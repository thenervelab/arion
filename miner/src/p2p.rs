//! P2P protocol handler for the miner.

use crate::constants::{
    DEFAULT_READ_TIMEOUT_SECS, MAX_CLUSTER_MAP_JSON_SIZE, MAX_CONCURRENT_HANDLERS, MAX_EPOCH_JUMP,
    MAX_FETCH_RESPONSE_SIZE, MAX_MESSAGE_SIZE, MAX_PEER_CACHE_ENTRIES, MAX_V2_DATA_SIZE,
};
use crate::helpers::truncate_for_log;
use crate::state::{
    get_blob_cache, get_blobs_dir, get_cluster_map, get_current_epoch, get_peer_cache,
    get_warden_node_ids,
};
use anyhow::Result;
use futures::StreamExt;
use iroh::endpoint::Endpoint;
use iroh_blobs::BlobFormat;
use iroh_blobs::store::fs::FsStore;
use pos_circuits::commitment::CommitmentWithTree;
use pos_circuits::prover::generate_proof;
use pos_circuits::types::Challenge as PosChallenge;
use std::str::FromStr;
use std::sync::Arc;
use std::sync::OnceLock;
use std::time::Instant;
use tracing::{debug, error, trace, warn};

/// Global semaphore to limit concurrent P2P stream handlers
/// Prevents OOM from connection flood attacks spawning unbounded tasks
static HANDLER_SEMAPHORE: OnceLock<Arc<tokio::sync::Semaphore>> = OnceLock::new();

fn get_handler_semaphore() -> &'static Arc<tokio::sync::Semaphore> {
    HANDLER_SEMAPHORE.get_or_init(|| Arc::new(tokio::sync::Semaphore::new(MAX_CONCURRENT_HANDLERS)))
}

/// Helper to finish a send stream and wait for remote acknowledgment
async fn finish_stream(send: &mut iroh::endpoint::SendStream) -> Result<()> {
    send.finish()?;
    let _ = send.stopped().await;
    Ok(())
}

/// Helper to send a response and finish the stream
async fn send_response(send: &mut iroh::endpoint::SendStream, data: &[u8]) -> Result<()> {
    send.write_all(data).await?;
    finish_stream(send).await
}

/// Check if the remote node is authorized (must be the validator)
fn is_authorized(
    remote_node_id: &iroh::PublicKey,
    validator_node_id: Option<&iroh::PublicKey>,
) -> bool {
    validator_node_id.is_none_or(|v| remote_node_id == v)
}

/// Check if the remote node is authorized for PoS challenges (validator or warden)
async fn is_authorized_for_pos(
    remote_node_id: &iroh::PublicKey,
    validator_node_id: Option<&iroh::PublicKey>,
) -> bool {
    // Allow if: no validator configured (dev mode), or sender is validator
    if validator_node_id.is_none() {
        return true;
    }
    if validator_node_id.is_some_and(|v| remote_node_id == v) {
        return true;
    }
    // Check dynamic warden node IDs (auto-distributed by validator)
    let warden_ids = get_warden_node_ids().read().await;
    warden_ids.iter().any(|w| remote_node_id == w)
}

/// Result of attempting to acquire a semaphore permit with timeout
enum PermitResult {
    Acquired(tokio::sync::OwnedSemaphorePermit),
    Closed,
    Timeout,
}

/// Acquire a semaphore permit with timeout, handling common error cases
async fn acquire_permit_with_timeout(
    sem: Arc<tokio::sync::Semaphore>,
    timeout_secs: u64,
) -> PermitResult {
    match tokio::time::timeout(
        std::time::Duration::from_secs(timeout_secs),
        sem.acquire_owned(),
    )
    .await
    {
        Ok(Ok(p)) => PermitResult::Acquired(p),
        Ok(Err(_)) => PermitResult::Closed,
        Err(_) => PermitResult::Timeout,
    }
}

/// P2P protocol handler for miner control messages
#[derive(Debug)]
pub struct MinerControlHandler {
    pub store: FsStore,
    pub endpoint: Endpoint,
    pub store_sem: Arc<tokio::sync::Semaphore>,
    pub pull_sem: Arc<tokio::sync::Semaphore>,
    pub fetch_sem: Arc<tokio::sync::Semaphore>,
    pub pos_sem: Arc<tokio::sync::Semaphore>,
    pub validator_node_id: Option<iroh::PublicKey>,
}

impl iroh::protocol::ProtocolHandler for MinerControlHandler {
    fn accept(
        &self,
        conn: iroh::endpoint::Connection,
    ) -> impl futures::Future<Output = Result<(), iroh::protocol::AcceptError>> + Send {
        trace!(remote = %conn.remote_id(), "MinerControlHandler::accept called");
        let store = self.store.clone();
        let endpoint = self.endpoint.clone();
        let store_sem = self.store_sem.clone();
        let pull_sem = self.pull_sem.clone();
        let fetch_sem = self.fetch_sem.clone();
        let pos_sem = self.pos_sem.clone();
        let validator_node_id = self.validator_node_id;
        async move {
            handle_miner_control(
                conn,
                store,
                endpoint,
                store_sem,
                pull_sem,
                fetch_sem,
                pos_sem,
                validator_node_id,
            )
            .await
            .map_err(|e| iroh::protocol::AcceptError::from_err(std::io::Error::other(e)))
        }
    }
}

/// Handle incoming miner control messages
///
/// This function loops accepting multiple bidirectional streams on the connection,
/// spawning each as a concurrent task. This allows QUIC multiplexing so the gateway
/// can reuse a single connection for multiple parallel shard fetches.
#[allow(clippy::too_many_arguments)]
pub async fn handle_miner_control(
    connection: iroh::endpoint::Connection,
    store: FsStore,
    endpoint: Endpoint,
    store_sem: Arc<tokio::sync::Semaphore>,
    pull_sem: Arc<tokio::sync::Semaphore>,
    fetch_sem: Arc<tokio::sync::Semaphore>,
    pos_sem: Arc<tokio::sync::Semaphore>,
    validator_node_id: Option<iroh::PublicKey>,
) -> Result<()> {
    let remote_node_id = connection.remote_id();
    trace!(remote = %remote_node_id, "Accepted MinerControl connection");

    // Loop accepting streams until connection is closed
    loop {
        let (send, recv) = match connection.accept_bi().await {
            Ok(streams) => streams,
            Err(e) => {
                // Connection closed by peer or error - this is expected
                trace!(remote = %remote_node_id, error = %e, "Connection closed");
                break;
            }
        };

        // Backpressure: Limit total concurrent handlers to prevent OOM from connection floods
        let handler_permit = match get_handler_semaphore().clone().try_acquire_owned() {
            Ok(permit) => permit,
            Err(_) => {
                warn!(
                    remote = %remote_node_id,
                    limit = MAX_CONCURRENT_HANDLERS,
                    "Handler limit reached, dropping stream"
                );
                // Close the stream gracefully by dropping send/recv
                continue;
            }
        };

        // Clone state for the spawned task
        let store = store.clone();
        let endpoint = endpoint.clone();
        let store_sem = store_sem.clone();
        let pull_sem = pull_sem.clone();
        let fetch_sem = fetch_sem.clone();
        let pos_sem = pos_sem.clone();

        // Spawn handler for this stream so multiple streams can be processed concurrently
        tokio::spawn(async move {
            // Hold permit until handler completes
            let _permit = handler_permit;

            if let Err(e) = handle_single_stream(
                send,
                recv,
                &remote_node_id,
                validator_node_id.as_ref(),
                &store,
                &endpoint,
                &store_sem,
                &pull_sem,
                &fetch_sem,
                &pos_sem,
            )
            .await
            {
                warn!(remote = %remote_node_id, error = %e, "Stream handler error");
            }
        });
    }

    Ok(())
}

/// Handle a single bidirectional stream (one request-response)
#[allow(clippy::too_many_arguments)]
async fn handle_single_stream(
    mut send: iroh::endpoint::SendStream,
    mut recv: iroh::endpoint::RecvStream,
    remote_node_id: &iroh::PublicKey,
    validator_node_id: Option<&iroh::PublicKey>,
    store: &FsStore,
    endpoint: &Endpoint,
    store_sem: &Arc<tokio::sync::Semaphore>,
    pull_sem: &Arc<tokio::sync::Semaphore>,
    fetch_sem: &Arc<tokio::sync::Semaphore>,
    pos_sem: &Arc<tokio::sync::Semaphore>,
) -> Result<()> {
    // Read the first byte to detect V1 (JSON) vs V2 (binary framing) protocol.
    // SAFETY: JSON-encoded MinerControlMessage always starts with '{' (0x7B),
    // so 0x02 is an unambiguous V2 discriminant that can never appear in V1.
    // Data timeout (55s) is slightly shorter than the validator's write timeout (default 60s)
    // to ensure the miner times out before the validator, producing a clean error.
    // DEFAULT_READ_TIMEOUT_SECS (30s) is used for header/first-byte reads (small payloads).
    let header_timeout = std::time::Duration::from_secs(DEFAULT_READ_TIMEOUT_SECS);
    let data_timeout = std::time::Duration::from_secs(55);

    let mut first_byte = [0u8; 1];
    tokio::time::timeout(header_timeout, recv.read_exact(&mut first_byte))
        .await
        .map_err(|_| anyhow::anyhow!("First byte read timed out"))?
        .map_err(|e| anyhow::anyhow!("First byte read failed: {}", e))?;

    let message = if first_byte[0] == common::STORE_V2_MAGIC {
        // V2 binary framing: [0x02][4-byte LE header_len][JSON header][raw blob bytes]
        let mut header_len_bytes = [0u8; 4];
        tokio::time::timeout(header_timeout, recv.read_exact(&mut header_len_bytes))
            .await
            .map_err(|_| anyhow::anyhow!("StoreV2 header_len read timed out"))?
            .map_err(|e| anyhow::anyhow!("StoreV2 header_len read failed: {}", e))?;
        let header_len = u32::from_le_bytes(header_len_bytes) as usize;

        if header_len > MAX_MESSAGE_SIZE {
            anyhow::bail!("StoreV2 header too large: {} bytes", header_len);
        }

        let mut header_bytes = vec![0u8; header_len];
        tokio::time::timeout(header_timeout, recv.read_exact(&mut header_bytes))
            .await
            .map_err(|_| anyhow::anyhow!("StoreV2 header read timed out"))?
            .map_err(|e| anyhow::anyhow!("StoreV2 header read failed: {}", e))?;
        let header: common::MinerControlMessage = serde_json::from_slice(&header_bytes)?;

        match header {
            common::MinerControlMessage::StoreV2 { hash, data_len } => {
                if data_len > MAX_V2_DATA_SIZE {
                    anyhow::bail!(
                        "StoreV2 data too large: {} bytes (max {})",
                        data_len,
                        MAX_V2_DATA_SIZE
                    );
                }
                let data_len = data_len as usize;
                let mut data = vec![0u8; data_len];
                tokio::time::timeout(data_timeout, recv.read_exact(&mut data))
                    .await
                    .map_err(|_| anyhow::anyhow!("StoreV2 data read timed out after 55s"))?
                    .map_err(|e| anyhow::anyhow!("StoreV2 data read failed: {}", e))?;
                // Convert to Store variant for unified handling
                common::MinerControlMessage::Store {
                    hash,
                    data: Some(data),
                    source_miner: None,
                }
            }
            other => {
                // V2 framing only valid for StoreV2; other variants would leave raw data
                // unconsumed on the stream, causing protocol corruption.
                anyhow::bail!(
                    "V2 framing used with non-StoreV2 header: {:?}",
                    std::mem::discriminant(&other)
                );
            }
        }
    } else {
        // V1: prepend the first byte back and read rest as JSON.
        // Use io::Read chain to avoid allocating a Vec just to prepend one byte.
        // Use MAX_MESSAGE_SIZE - 1 since we already consumed the first byte.
        let remaining = tokio::time::timeout(data_timeout, recv.read_to_end(MAX_MESSAGE_SIZE - 1))
            .await
            .map_err(|_| anyhow::anyhow!("V1 message read timed out after 55s"))?
            .map_err(|e| anyhow::anyhow!("V1 message read failed: {}", e))?;
        let reader = std::io::Read::chain(
            std::io::Cursor::new(&first_byte[..]),
            std::io::Cursor::new(&remaining),
        );
        serde_json::from_reader(reader)?
    };

    match message {
        common::MinerControlMessage::Store {
            hash,
            data,
            source_miner,
        } => {
            handle_store(
                remote_node_id,
                validator_node_id,
                &mut send,
                store,
                endpoint,
                store_sem,
                pull_sem,
                hash,
                data,
                source_miner,
            )
            .await?;
        }
        common::MinerControlMessage::Delete { hash } => {
            handle_delete(remote_node_id, validator_node_id, &mut send, store, hash).await?;
        }
        common::MinerControlMessage::FetchBlob { hash } => {
            handle_fetch_blob(&mut send, store, fetch_sem, hash).await?;
        }
        common::MinerControlMessage::ClusterMapUpdate {
            epoch,
            peers,
            cluster_map_json,
            warden_node_ids,
        } => {
            handle_cluster_map_update(
                remote_node_id,
                validator_node_id,
                &mut send,
                epoch,
                peers,
                cluster_map_json,
                warden_node_ids,
            )
            .await?;
        }
        common::MinerControlMessage::PullFromPeer {
            hash,
            peer_endpoint,
        } => {
            // Parse peer_endpoint string to EndpointAddr
            let peer_addr = match serde_json::from_str::<iroh::EndpointAddr>(&peer_endpoint) {
                Ok(addr) => addr,
                Err(e) => {
                    error!(error = %e, "PullFromPeer: Invalid peer_endpoint format");
                    return send_response(&mut send, b"ERROR: Invalid peer_endpoint").await;
                }
            };
            handle_pull_from_peer(
                remote_node_id,
                validator_node_id,
                &mut send,
                store,
                endpoint,
                pull_sem,
                hash,
                peer_addr,
            )
            .await?;
        }
        common::MinerControlMessage::QueryPgFiles { .. }
        | common::MinerControlMessage::PgFilesResponse { .. } => {
            warn!("Received validator-only message, ignoring");
            send_response(&mut send, b"ERROR: Not supported").await?;
        }
        common::MinerControlMessage::PosChallenge {
            shard_hash,
            chunk_indices,
            nonce,
            expected_root,
            expires_at,
        } => {
            // Authorization: Only allow PoS challenges from validator or warden
            // This prevents DoS attacks and information disclosure from arbitrary peers
            if !is_authorized_for_pos(remote_node_id, validator_node_id).await {
                debug!(remote = %remote_node_id, "PosChallenge rejected: unauthorized sender");
                return send_response(&mut send, b"ERROR: UNAUTHORIZED").await;
            }

            // Backpressure: Proof generation is CPU-intensive
            let _permit = match pos_sem.clone().try_acquire_owned() {
                Ok(p) => p,
                Err(_) => {
                    debug!(shard = %truncate_for_log(&shard_hash, 16), "PosChallenge rate limited");
                    return send_response(&mut send, b"RATE_LIMITED").await;
                }
            };

            handle_pos_challenge(
                &mut send,
                store,
                shard_hash,
                chunk_indices,
                nonce,
                expected_root,
                expires_at,
            )
            .await?;
        }
        common::MinerControlMessage::StoreV2 { .. } => {
            // V1 JSON path: a raw JSON StoreV2 message (without V2 binary framing) is invalid.
            // V2 framing always converts StoreV2 → Store above, so this is only reachable
            // if someone sends {"StoreV2":...} as plain JSON — reject it.
            warn!("Received raw JSON StoreV2 message (not V2-framed), rejecting");
            send_response(&mut send, b"ERROR: StoreV2 requires binary framing").await?;
        }
    }

    Ok(())
}

#[allow(clippy::too_many_arguments)]
async fn handle_store(
    remote_node_id: &iroh::PublicKey,
    validator_node_id: Option<&iroh::PublicKey>,
    send: &mut iroh::endpoint::SendStream,
    store: &FsStore,
    endpoint: &Endpoint,
    store_sem: &Arc<tokio::sync::Semaphore>,
    pull_sem: &Arc<tokio::sync::Semaphore>,
    hash: String,
    data: Option<Vec<u8>>,
    source_miner: Option<String>,
) -> Result<()> {
    // Only validator should be allowed to issue Store commands
    if !is_authorized(remote_node_id, validator_node_id) {
        error!(remote = %remote_node_id, "Store rejected: non-validator controller");
        return send_response(send, b"ERROR: UNAUTHORIZED").await;
    }

    trace!(hash = %hash, "Received Store command");

    match (data, source_miner) {
        // CASE 1: Push from validator (initial upload)
        (Some(blob_data), None) => {
            // Backpressure: bound concurrent Store ops
            let _permit = match acquire_permit_with_timeout(store_sem.clone(), 30).await {
                PermitResult::Acquired(p) => p,
                PermitResult::Closed => {
                    error!("Store semaphore closed unexpectedly");
                    return send_response(send, b"ERROR: Internal error").await;
                }
                PermitResult::Timeout => {
                    debug!(hash = %hash, "Store command timed out waiting for permit");
                    return send_response(send, b"RATE_LIMITED").await;
                }
            };

            trace!(hash = %hash, size = blob_data.len(), "Receiving blob from validator");

            // Verify requested hash parses and matches what we actually store
            let requested = match iroh_blobs::Hash::from_str(&hash) {
                Ok(h) => h,
                Err(e) => {
                    error!(hash = %hash, error = %e, "Store: Invalid hash");
                    return send_response(send, b"ERROR: Invalid hash").await;
                }
            };

            // Store blob (persistent with FsStore)
            let outcome = match store.add_bytes(blob_data).await {
                Ok(o) => o,
                Err(e) => {
                    error!(hash = %hash, error = %e, "Failed to store blob");
                    return send_response(send, b"ERROR: Storage failed").await;
                }
            };

            // Invalidate blob cache entry to ensure fresh data on next read
            get_blob_cache().remove(&requested);

            if outcome.hash != requested {
                error!(requested = %requested, stored = %outcome.hash, "Store hash mismatch");
                return send_response(send, b"ERROR: Hash mismatch").await;
            }

            trace!(hash = %outcome.hash, "Stored blob");

            // Send ACK and wait for remote to receive it
            send_response(send, b"OK").await?;
        }

        // CASE 2: Pull from another miner (rebalancing)
        (None, Some(miner_id)) => {
            // Backpressure: bound concurrent peer pulls
            let permit = match acquire_permit_with_timeout(pull_sem.clone(), 30).await {
                PermitResult::Acquired(p) => p,
                PermitResult::Closed => {
                    error!("Pull semaphore closed unexpectedly");
                    return send_response(send, b"ERROR: Internal error").await;
                }
                PermitResult::Timeout => {
                    debug!(hash = %hash, miner_id = %miner_id, "Pull command timed out waiting for permit");
                    return send_response(send, b"RATE_LIMITED").await;
                }
            };

            trace!(hash = %hash, miner_id = %miner_id, "Downloading blob from miner");

            // Await download completion BEFORE sending ACK
            let result = tokio::time::timeout(
                std::time::Duration::from_secs(30),
                download_from_peer_miner(
                    miner_id.clone(),
                    hash.clone(),
                    store.clone(),
                    endpoint.clone(),
                ),
            )
            .await;

            // Release permit after download completes
            drop(permit);

            // Send ACK based on actual result
            let response: &[u8] = match &result {
                Ok(Ok(())) => {
                    trace!(hash = %hash, "Downloaded blob from peer miner");
                    b"OK"
                }
                Ok(Err(e)) => {
                    error!(hash = %hash, error = %e, "Failed to download blob from peer");
                    b"ERROR: Peer download failed"
                }
                Err(_) => {
                    error!(hash = %hash, miner_id = %miner_id, "Timeout downloading blob from peer");
                    b"TIMEOUT"
                }
            };
            send_response(send, response).await?;
        }

        // CASE 3: Invalid (both or neither specified)
        _ => {
            error!("Invalid Store command: must have either data OR source_miner (not both)");
            send_response(send, b"ERROR: Invalid parameters").await?;
        }
    }

    Ok(())
}

async fn handle_delete(
    remote_node_id: &iroh::PublicKey,
    validator_node_id: Option<&iroh::PublicKey>,
    send: &mut iroh::endpoint::SendStream,
    store: &FsStore,
    hash: String,
) -> Result<()> {
    // Only validator should be allowed to issue Delete commands
    if !is_authorized(remote_node_id, validator_node_id) {
        error!(remote = %remote_node_id, "Delete rejected: non-validator controller");
        return send_response(send, b"ERROR: UNAUTHORIZED").await;
    }

    trace!(hash = %hash, "Received Delete command");

    // Parse hash
    let hash_parsed = match iroh_blobs::Hash::from_str(&hash) {
        Ok(h) => h,
        Err(e) => {
            error!(hash = %hash, error = %e, "Delete: Invalid hash");
            return send_response(send, b"ERROR: Invalid hash").await;
        }
    };

    let canonical_hash = hash_parsed.to_string();

    // Step 1: Delete any tags associated with this blob hash
    // This unprotects the blob from GC, allowing it to be cleaned up.
    // Note: Tags are auto-generated by add_bytes(), so we need to find them by hash.
    let mut tags_deleted = 0u64;
    match store.tags().list().await {
        Ok(mut tag_stream) => {
            while let Some(tag_result) = tag_stream.next().await {
                match tag_result {
                    Ok(tag_info) => {
                        // Check if this tag references our blob hash (Raw format for shards)
                        if tag_info.hash == hash_parsed && tag_info.format == BlobFormat::Raw {
                            match store.tags().delete(&tag_info.name).await {
                                Ok(count) => {
                                    tags_deleted += count;
                                    trace!(
                                        hash = %truncate_for_log(&canonical_hash, 32),
                                        tag = ?tag_info.name,
                                        "Deleted tag for blob"
                                    );
                                }
                                Err(e) => {
                                    warn!(
                                        hash = %truncate_for_log(&canonical_hash, 32),
                                        tag = ?tag_info.name,
                                        error = %e,
                                        "Failed to delete tag"
                                    );
                                }
                            }
                        }
                    }
                    Err(e) => {
                        warn!(error = %e, "Error reading tag during delete");
                    }
                }
            }
        }
        Err(e) => {
            warn!(
                hash = %truncate_for_log(&canonical_hash, 32),
                error = %e,
                "Failed to list tags for deletion"
            );
        }
    }

    if tags_deleted > 0 {
        trace!(
            hash = %truncate_for_log(&canonical_hash, 32),
            tags_deleted,
            "Deleted tags, blob now eligible for GC"
        );
    }

    // Step 2: Best-effort physically remove blob bytes from disk
    // For large blobs (> 16KB), data is stored in files. For small blobs, data is
    // inlined in the database and will be cleaned up by GC after tag removal.
    let blobs_path = {
        let bd = get_blobs_dir().read().await;
        bd.clone()
    };

    let mut removed_file = false;
    if let Some(blobs_dir) = blobs_path {
        let data_dir = blobs_dir.join("data");

        // Try both filename formats: with and without .data extension
        let p1 = data_dir.join(format!("{}.data", canonical_hash));
        let p2 = data_dir.join(&canonical_hash);

        for p in [p1, p2] {
            match tokio::fs::remove_file(&p).await {
                Ok(()) => {
                    trace!(
                        hash = %truncate_for_log(&canonical_hash, 32),
                        file = %p.display(),
                        "Deleted blob file"
                    );
                    removed_file = true;
                }
                Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
                Err(e) => {
                    error!(
                        hash = %truncate_for_log(&canonical_hash, 32),
                        file = %p.display(),
                        error = %e,
                        "Delete: failed to remove file"
                    );
                }
            }
        }
    } else {
        error!("Delete: blobs_dir not initialized; cannot delete on disk");
    }

    // Log outcome
    if removed_file {
        trace!(
            hash = %truncate_for_log(&canonical_hash, 32),
            "Delete complete: removed file"
        );
    } else if tags_deleted > 0 {
        // Small/inlined blob - tags removed, GC will clean up
        trace!(
            hash = %truncate_for_log(&canonical_hash, 32),
            "Delete complete: tags removed, GC will clean up inlined blob"
        );
    } else {
        // Neither file nor tags found - blob may already be deleted or never existed
        trace!(
            hash = %truncate_for_log(&canonical_hash, 32),
            "Delete: no file or tags found, blob may already be deleted"
        );
    }

    // Step 3: Invalidate blob cache entry to prevent serving stale data
    get_blob_cache().remove(&hash_parsed);

    // Send ACK
    send_response(send, b"OK").await
}

async fn handle_fetch_blob(
    send: &mut iroh::endpoint::SendStream,
    store: &FsStore,
    fetch_sem: &Arc<tokio::sync::Semaphore>,
    hash: String,
) -> Result<()> {
    trace!(hash = %truncate_for_log(&hash, 32), "FetchBlob request");

    // Backpressure: bound concurrent FetchBlob serving ops
    let _permit = match fetch_sem.clone().try_acquire_owned() {
        Ok(p) => p,
        Err(_) => return send_response(send, b"ERROR: RATE_LIMITED").await,
    };

    // Parse hash
    let hash_parsed = match iroh_blobs::Hash::from_str(&hash) {
        Ok(h) => h,
        Err(e) => {
            error!(hash = %hash, error = %e, "FetchBlob: Invalid hash");
            return send_response(send, b"ERROR: Invalid hash").await;
        }
    };

    // Helper to send blob data with DATA: prefix
    async fn send_blob_data(send: &mut iroh::endpoint::SendStream, data: &[u8]) -> Result<()> {
        send.write_all(b"DATA:").await?;
        send.write_all(data).await?;
        finish_stream(send).await
    }

    // Check blob cache first (key is Hash — 32-byte Copy type, no heap alloc)
    let blob_cache = get_blob_cache();
    if let Some(cached) = blob_cache.get(&hash_parsed) {
        trace!(
            hash = %truncate_for_log(&hash, 16),
            size = cached.len(),
            "FetchBlob: Cache HIT"
        );
        return send_blob_data(send, &cached).await;
    }

    // Read blob data from store (returns bytes::Bytes — already refcounted)
    match store.get_bytes(hash_parsed).await {
        Ok(data) if !data.is_empty() => {
            trace!(
                hash = %truncate_for_log(&hash, 16),
                size = data.len(),
                "FetchBlob: Read bytes"
            );

            // Cache the Bytes directly — clone is just a refcount bump, no data copy
            blob_cache.insert(hash_parsed, data.clone());

            send_blob_data(send, &data).await
        }
        Ok(_) => {
            // Empty data means blob not found
            debug!(hash = %truncate_for_log(&hash, 16), "FetchBlob: Blob not found (empty)");
            send_response(send, b"ERROR: Not found").await
        }
        Err(e) => {
            debug!(
                hash = %truncate_for_log(&hash, 16),
                error = %e,
                "FetchBlob: Failed to read blob"
            );
            send_response(send, b"ERROR: Not found").await
        }
    }
}

async fn handle_cluster_map_update(
    remote_node_id: &iroh::PublicKey,
    validator_node_id: Option<&iroh::PublicKey>,
    send: &mut iroh::endpoint::SendStream,
    epoch: u64,
    peers: Vec<(String, String)>, // (public_key, endpoint_json)
    cluster_map_json: Option<String>,
    warden_node_ids: Option<Vec<String>>,
) -> Result<()> {
    // Only validator should broadcast map updates
    if !is_authorized(remote_node_id, validator_node_id) {
        error!(remote = %remote_node_id, "ClusterMapUpdate rejected: non-validator controller");
        return send_response(send, b"ERROR: UNAUTHORIZED").await;
    }

    debug!(
        epoch = epoch,
        peer_count = peers.len(),
        "Received cluster map update"
    );

    // Atomic read-modify-write for epoch
    let (old_epoch, epoch_changed, epoch_jump_rejected) = {
        let mut current = get_current_epoch().write().await;
        let old = *current;

        // Validate epoch jump to prevent malformed updates
        if epoch > old + MAX_EPOCH_JUMP && old > 0 {
            debug!(
                old_epoch = old,
                new_epoch = epoch,
                "Epoch jump too large, ignoring update"
            );
            (old, false, true)
        } else {
            let changed = epoch > old;
            if changed {
                *current = epoch;
            }
            (old, changed, false)
        }
    };

    // Handle rejection outside the lock
    if epoch_jump_rejected {
        return send_response(send, b"ERROR: Epoch jump too large").await;
    }

    if epoch_changed {
        debug!(old_epoch = old_epoch, new_epoch = epoch, "Epoch updated");
    }

    // Update peer cache (lock-free DashMap)
    // Parse addr strings to EndpointAddr and cache them
    let peer_cache = get_peer_cache();

    // On epoch change, clear stale entries to prevent unbounded growth
    if epoch_changed {
        peer_cache.clear();
        trace!("Cleared peer cache on epoch change");
    }

    for (node_id, addr_json) in peers {
        // Enforce cache size limit
        if peer_cache.len() >= MAX_PEER_CACHE_ENTRIES {
            warn!(
                capacity = MAX_PEER_CACHE_ENTRIES,
                "Peer cache at capacity, skipping remaining entries"
            );
            break;
        }

        if let Ok(addr) = serde_json::from_str::<iroh::EndpointAddr>(&addr_json) {
            peer_cache.insert(node_id, addr);
        } else {
            debug!(node_id = %node_id, "Failed to parse peer endpoint address");
        }
    }

    // Store the cluster map for CRUSH calculations
    // Validate size before parsing to prevent OOM from malicious large payloads
    if let Some(json) = cluster_map_json {
        if json.len() > MAX_CLUSTER_MAP_JSON_SIZE {
            debug!(
                size = json.len(),
                max = MAX_CLUSTER_MAP_JSON_SIZE,
                "cluster_map_json exceeds size limit, ignoring"
            );
        } else {
            match serde_json::from_str::<common::ClusterMap>(&json) {
                Ok(map) => {
                    let mut map_guard = get_cluster_map().write().await;
                    *map_guard = Some(Arc::new(map));
                }
                Err(e) => {
                    debug!(error = %e, "Failed to parse cluster_map_json");
                }
            }
        }
    }

    // Update warden node IDs if provided by validator
    if let Some(ids) = warden_node_ids {
        let mut new_ids = Vec::new();
        for id_str in &ids {
            if let Ok(pk) = iroh::PublicKey::from_str(id_str) {
                new_ids.push(pk);
            }
        }
        if !new_ids.is_empty() {
            // Sort for deterministic comparison (validator sends from HashSet)
            new_ids.sort();
            let warden_ids = get_warden_node_ids().read().await;
            if *warden_ids != new_ids {
                drop(warden_ids);
                let mut warden_ids = get_warden_node_ids().write().await;
                if *warden_ids != new_ids {
                    debug!(
                        count = new_ids.len(),
                        "Updated warden node IDs from ClusterMapUpdate"
                    );
                    *warden_ids = new_ids;
                }
            }
        }
    }

    // Send ACK
    send_response(send, b"OK").await
}

#[allow(clippy::too_many_arguments)]
async fn handle_pull_from_peer(
    remote_node_id: &iroh::PublicKey,
    validator_node_id: Option<&iroh::PublicKey>,
    send: &mut iroh::endpoint::SendStream,
    store: &FsStore,
    endpoint: &Endpoint,
    pull_sem: &Arc<tokio::sync::Semaphore>,
    hash: String,
    peer_endpoint: iroh::EndpointAddr,
) -> Result<()> {
    // Only validator should be allowed to issue PullFromPeer commands
    if !is_authorized(remote_node_id, validator_node_id) {
        error!(remote = %remote_node_id, "PullFromPeer rejected: non-validator controller");
        return send_response(send, b"ERROR: UNAUTHORIZED").await;
    }

    trace!(hash = %truncate_for_log(&hash, 32), "Received PullFromPeer command");

    // Backpressure: bound concurrent peer pulls
    let permit = match acquire_permit_with_timeout(pull_sem.clone(), 30).await {
        PermitResult::Acquired(p) => p,
        PermitResult::Closed => {
            error!("Pull semaphore closed unexpectedly");
            return send_response(send, b"ERROR: Internal error").await;
        }
        PermitResult::Timeout => {
            debug!(hash = %truncate_for_log(&hash, 32), "PullFromPeer command timed out waiting for permit");
            return send_response(send, b"RATE_LIMITED").await;
        }
    };

    // Await download completion BEFORE sending ACK
    let result = tokio::time::timeout(
        std::time::Duration::from_secs(30),
        pull_blob_from_peer(store.clone(), endpoint.clone(), peer_endpoint, hash.clone()),
    )
    .await;

    // Release permit after download completes
    drop(permit);

    // Send ACK based on actual result
    let response: &[u8] = match &result {
        Ok(Ok(())) => {
            trace!(hash = %truncate_for_log(&hash, 16), "Downloaded blob from peer");
            b"OK"
        }
        Ok(Err(e)) => {
            error!(hash = %truncate_for_log(&hash, 16), error = %e, "Failed to download blob from peer");
            b"ERROR: Peer download failed"
        }
        Err(_) => {
            error!(hash = %truncate_for_log(&hash, 16), "Timeout downloading blob from peer");
            b"TIMEOUT"
        }
    };
    send_response(send, response).await
}

/// Pull blob from peer using endpoint address
pub async fn pull_blob_from_peer(
    store: FsStore,
    endpoint: Endpoint,
    peer_addr: iroh::EndpointAddr,
    hash: String,
) -> Result<()> {
    trace!(hash = %truncate_for_log(&hash, 16), "Pulling blob from peer");

    // Use connection pool to avoid QUIC handshake on repeated pulls to the same peer
    let conn = crate::state::get_pooled_connection(&endpoint, &peer_addr, b"hippius/miner-control")
        .await?;

    let (mut send, mut recv) = conn.open_bi().await?;

    // Send FetchBlob request
    let request = common::MinerControlMessage::FetchBlob { hash: hash.clone() };
    let request_bytes = serde_json::to_vec(&request)?;
    send.write_all(&request_bytes).await?;
    send.finish()?;
    let _ = send.stopped().await;

    // Read response with timeout
    let response = tokio::time::timeout(
        std::time::Duration::from_secs(30),
        recv.read_to_end(MAX_FETCH_RESPONSE_SIZE),
    )
    .await
    .map_err(|_| anyhow::anyhow!("Timeout reading FetchBlob response"))??;

    if !response.starts_with(b"DATA:") {
        return Err(anyhow::anyhow!(
            "Peer did not return DATA for {}",
            truncate_for_log(&hash, 16)
        ));
    }

    // Zero-copy slice: Bytes::from(Vec) takes ownership, .slice() is a refcount bump
    let data = bytes::Bytes::from(response).slice(5..);
    if data.is_empty() {
        return Err(anyhow::anyhow!("Empty DATA payload from peer"));
    }

    // Store blob and verify hash matches (add_bytes accepts impl Into<Bytes>)
    let outcome = store
        .add_bytes(data)
        .await
        .map_err(|e| anyhow::anyhow!("Failed to store blob: {}", e))?;
    let stored_hash = outcome.hash.to_string();
    if stored_hash != hash {
        return Err(anyhow::anyhow!(
            "Hash mismatch: requested {} stored {}",
            truncate_for_log(&hash, 16),
            truncate_for_log(&stored_hash, 16)
        ));
    }

    trace!(hash = %truncate_for_log(&hash, 16), "Pulled and stored blob from peer");
    Ok(())
}

/// Download blob from peer miner using node ID (looks up EndpointAddr from cache)
pub async fn download_from_peer_miner(
    miner_id: String,
    hash: String,
    store: FsStore,
    endpoint: Endpoint,
) -> Result<()> {
    trace!(
        hash = %truncate_for_log(&hash, 16),
        miner_id = %truncate_for_log(&miner_id, 16),
        "Downloading blob from peer miner"
    );

    // Look up peer address from cache
    let peer_cache = get_peer_cache();
    let peer_addr = peer_cache
        .get(&miner_id)
        .map(|r| r.value().clone())
        .ok_or_else(|| anyhow::anyhow!("Peer {} not in cache", truncate_for_log(&miner_id, 16)))?;

    // Delegate to pull_blob_from_peer which does the actual work
    pull_blob_from_peer(store, endpoint, peer_addr, hash).await
}

/// Handle a proof-of-storage challenge from a Warden.
///
/// Generates a ZK proof demonstrating possession of the challenged chunks.
#[allow(clippy::too_many_arguments)]
async fn handle_pos_challenge(
    send: &mut iroh::endpoint::SendStream,
    store: &FsStore,
    shard_hash: String,
    chunk_indices: Vec<u32>,
    nonce: [u8; 32],
    expected_root: [u32; 8],
    expires_at: u64,
) -> Result<()> {
    debug!(
        shard = %truncate_for_log(&shard_hash, 16),
        chunks = ?chunk_indices,
        "Received PosChallenge"
    );

    // Check if challenge has expired
    let now = common::now_secs();
    if now > expires_at {
        warn!(
            shard = %truncate_for_log(&shard_hash, 16),
            now = now,
            expires_at = expires_at,
            "PosChallenge expired"
        );
        return send_response(send, b"ERROR: Challenge expired").await;
    }

    // Parse shard hash and read from store
    let hash_parsed = match iroh_blobs::Hash::from_str(&shard_hash) {
        Ok(h) => h,
        Err(e) => {
            error!(shard = %truncate_for_log(&shard_hash, 16), error = %e, "Invalid shard hash");
            return send_response(send, b"ERROR: Invalid shard hash").await;
        }
    };

    // Read shard data from blob store (keep as Bytes — Deref<Target=[u8]> for proof APIs)
    let shard_data = match store.get_bytes(hash_parsed).await {
        Ok(data) if !data.is_empty() => data,
        Ok(_) => {
            warn!(shard = %truncate_for_log(&shard_hash, 16), "Shard not found (empty)");
            return send_response(send, b"ERROR: Shard not found").await;
        }
        Err(e) => {
            warn!(shard = %truncate_for_log(&shard_hash, 16), error = %e, "Failed to read shard");
            return send_response(send, b"ERROR: Shard not found").await;
        }
    };

    trace!(
        shard = %truncate_for_log(&shard_hash, 16),
        size = shard_data.len(),
        "Read shard data for proof generation"
    );

    // Generate commitment with Merkle tree
    let commitment =
        match CommitmentWithTree::generate(&shard_data, pos_circuits::DEFAULT_CHUNK_SIZE) {
            Ok(c) => c,
            Err(e) => {
                error!(error = %e, "Failed to generate commitment");
                return send_response(send, b"ERROR: Commitment generation failed").await;
            }
        };

    // Verify expected root matches our computed root
    if commitment.commitment.merkle_root != expected_root {
        warn!(
            expected = ?expected_root,
            actual = ?commitment.commitment.merkle_root,
            "Merkle root mismatch"
        );
        return send_response(send, b"ERROR: Merkle root mismatch").await;
    }

    // Create challenge for proof generation
    let challenge = PosChallenge {
        shard_hash: commitment.commitment.shard_hash.clone(),
        chunk_indices: chunk_indices.clone(),
        nonce,
        expected_root,
        expires_at,
    };

    // Generate proof on blocking thread pool to avoid starving the async executor.
    // With pos_sem=2, this can block 2 executor threads for 500ms+ — spawn_blocking
    // moves the work to a dedicated thread pool.
    let start = Instant::now();
    let proof = match tokio::task::spawn_blocking(move || {
        generate_proof(&shard_data, &commitment, &challenge)
    })
    .await
    {
        Ok(Ok(p)) => p,
        Ok(Err(e)) => {
            error!(shard = %truncate_for_log(&shard_hash, 16), error = %e, "Failed to generate proof");
            return send_response(send, b"ERROR: Proof generation failed").await;
        }
        Err(e) => {
            error!(shard = %truncate_for_log(&shard_hash, 16), error = %e, "Proof generation task panicked");
            return send_response(send, b"ERROR: Proof generation failed").await;
        }
    };
    let proving_time_ms = start.elapsed().as_millis() as u64;

    // Serialize proof
    let proof_bytes = match proof.to_bytes() {
        Ok(b) => b,
        Err(e) => {
            error!(error = %e, "Failed to serialize proof");
            return send_response(send, b"ERROR: Proof serialization failed").await;
        }
    };

    // Build response
    let response = common::ValidatorControlMessage::PosProofResponse {
        nonce,
        proof_bytes,
        public_inputs: proof.public_inputs.to_vec(),
        proving_time_ms,
    };

    // Send response as JSON
    let response_json = serde_json::to_vec(&response)?;
    send_response(send, &response_json).await?;

    debug!(
        shard = %truncate_for_log(&shard_hash, 16),
        chunks = chunk_indices.len(),
        proving_time_ms = proving_time_ms,
        "PosProofResponse sent"
    );

    Ok(())
}

//! P2P protocol handler for the miner.
//!
//! Handles all inbound messages on the miner's quinn endpoint, including
//! shard storage, deletion, serving, peer pulls, cluster map updates, and
//! proof-of-storage challenges.
//!
//! # Protocol Framing
//!
//! Two framing modes share a single stream, disambiguated by the first byte:
//!
//! - **Binary store:** First byte is `0x02` ([`STORE_V2_MAGIC`]). Followed by
//!   4-byte LE header length, a JSON header, and raw blob bytes. Used for
//!   shard storage — the only supported store path.
//! - **JSON control:** First byte is `{` (0x7B). The entire message is a
//!   JSON-encoded [`MinerControlMessage`]. Used for all other control messages
//!   (Delete, FetchBlob, ClusterMapUpdate, PullFromPeer, PosChallenge, CheckBlob).
//!
//! # Backpressure
//!
//! Semaphores bound concurrent work per category:
//! - `store_sem` — validator-pushed Store operations
//! - `pull_sem` — peer-to-peer shard downloads
//! - `fetch_sem` — FetchBlob responses to gateways/miners
//! - `pos_sem` — CPU-intensive proof-of-storage generation
//! - `HANDLER_SEMAPHORE` — global cap on spawned stream handlers (2048)
//!
//! # Connection Model
//!
//! Each inbound connection loops accepting bidirectional QUIC streams,
//! spawning a task per stream for concurrent request handling.

use crate::constants::{
    DATA_FRAME_READ_TIMEOUT_SECS, DEFAULT_READ_TIMEOUT_SECS, LOG_STRING_TRUNCATE_LEN,
    MAX_CLUSTER_MAP_JSON_SIZE, MAX_CONCURRENT_HANDLERS, MAX_EPOCH_JUMP, MAX_FETCH_RESPONSE_SIZE,
    MAX_MESSAGE_SIZE, MAX_PEER_CACHE_ENTRIES, MAX_V2_DATA_SIZE, PEER_BLOB_DOWNLOAD_TIMEOUT_SECS,
    PEER_DATA_RECEPTION_TIMEOUT_SECS, PULL_PERMIT_TIMEOUT_SECS,
    STORE_PERMIT_TIMEOUT_SECS,
};
use crate::flat_store::FlatBlobStore;
use crate::helpers::{truncate_for_log, verify_signature};
use crate::state::{
    get_blob_cache, get_cluster_map, get_current_epoch, get_gateway_endpoints,
    get_last_epoch_change, get_peer_cache, get_warden_node_ids,
};
use anyhow::Result;
use pos_circuits::commitment::CommitmentWithTree;
use pos_circuits::prover::generate_proof;
use pos_circuits::types::Challenge as PosChallenge;
use std::str::FromStr;
use std::sync::Arc;
use std::sync::OnceLock;
use std::time::Instant;
use tracing::{debug, error, info, trace, warn};

/// Global semaphore to limit concurrent P2P stream handlers
/// Prevents OOM from connection flood attacks spawning unbounded tasks
static HANDLER_SEMAPHORE: OnceLock<Arc<tokio::sync::Semaphore>> = OnceLock::new();

fn get_handler_semaphore() -> &'static Arc<tokio::sync::Semaphore> {
    HANDLER_SEMAPHORE.get_or_init(|| Arc::new(tokio::sync::Semaphore::new(MAX_CONCURRENT_HANDLERS)))
}

/// Helper to finish a send stream and wait for remote acknowledgment
async fn finish_stream(send: &mut quinn::SendStream) -> Result<()> {
    send.finish()?;
    Ok(())
}

/// Helper to send a response and finish the stream
async fn send_response(send: &mut quinn::SendStream, data: &[u8]) -> Result<()> {
    send.write_all(data).await?;
    finish_stream(send).await
}

/// Check if the remote node is authorized (must be the validator).
///
/// SAFETY: When `validator_node_id` is `None` (no validator configured),
/// this returns `true` for ANY peer. This is intentional for local/dev
/// testing but means an unconfigured miner accepts Store/Delete from
/// anyone. Production deployments MUST set `VALIDATOR_NODE_ID`.
fn is_authorized(
    remote_node_id: &str,
    validator_node_id: Option<&str>,
) -> bool {
    validator_node_id.is_none_or(|v| remote_node_id == v)
}

/// Check if the remote node is authorized for PoS challenges (validator or warden)
async fn is_authorized_for_pos(
    remote_node_id: &str,
    validator_node_id: Option<&str>,
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
    warden_ids.iter().any(|w| w == remote_node_id)
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

/// P2P handler for miner control messages.
///
/// All fields are cheaply cloneable (Arc internals) so the handler can be
/// cloned per-connection without data duplication.
#[derive(Debug, Clone)]
pub struct MinerControlHandler {
    pub store: Arc<FlatBlobStore>,
    pub endpoint: quinn::Endpoint,
    pub store_sem: Arc<tokio::sync::Semaphore>,
    pub pull_sem: Arc<tokio::sync::Semaphore>,
    pub fetch_sem: Arc<tokio::sync::Semaphore>,
    pub pos_sem: Arc<tokio::sync::Semaphore>,
    pub validator_node_id: Option<String>,
}

/// Handle incoming miner control messages on a quinn connection.
///
/// Loops accepting bidirectional streams on the connection, spawning each as a
/// concurrent task. This allows QUIC multiplexing so the gateway can reuse a
/// single connection for multiple parallel shard fetches.
pub async fn handle_miner_control(
    connection: quinn::Connection,
    handler: MinerControlHandler,
) -> Result<()> {
    let remote_node_id = common::transport::remote_node_id(&connection)
        .unwrap_or_else(|| "unknown".to_string());
    let remote_short = truncate_for_log(&remote_node_id, 8);
    info!("[P2P] Inbound connection from {}", remote_short);

    // Loop accepting streams until connection is closed
    loop {
        let (mut send, recv) = match connection.accept_bi().await {
            Ok(streams) => streams,
            Err(e) => {
                // Connection closed by peer or error - this is expected
                trace!(remote = %remote_short, error = %e, "Connection closed");
                break;
            }
        };

        // Backpressure: Limit total concurrent handlers to prevent OOM from connection floods
        let handler_permit = match get_handler_semaphore().clone().try_acquire_owned() {
            Ok(permit) => permit,
            Err(_) => {
                warn!(
                    remote = %remote_short,
                    limit = MAX_CONCURRENT_HANDLERS,
                    "Handler limit reached, rejecting stream"
                );
                let _ = send_response(&mut send, b"ERROR: RATE_LIMITED").await;
                continue;
            }
        };

        let handler = handler.clone();
        let remote_id = remote_node_id.clone();
        let conn = connection.clone();

        // Spawn handler for this stream so multiple streams can be processed concurrently
        tokio::spawn(async move {
            // Hold permit until handler completes
            let _permit = handler_permit;

            if let Err(e) =
                handle_single_stream(send, recv, &remote_id, &handler, &conn).await
            {
                let err_str = e.to_string();
                // "sending stopped by peer: error 0" = clean close by remote, not an error
                // "connection lost" / "connection closed" = expected during reconnects
                if err_str.contains("error 0")
                    || err_str.contains("connection lost")
                    || err_str.contains("connection closed")
                {
                    trace!(
                        remote = %truncate_for_log(&remote_id, 8),
                        "Stream closed by peer (normal)"
                    );
                } else {
                    warn!(
                        remote = %truncate_for_log(&remote_id, 8),
                        error = %e,
                        "[P2P] Stream error"
                    );
                }
            }
        });
    }

    Ok(())
}

/// Handle a single bidirectional stream (one request-response)
async fn handle_single_stream(
    mut send: quinn::SendStream,
    mut recv: quinn::RecvStream,
    remote_node_id: &str,
    handler: &MinerControlHandler,
    _connection: &quinn::Connection,
) -> Result<()> {
    // Read the first byte to detect binary store (0x02) vs JSON control (0x7B).
    let header_timeout = std::time::Duration::from_secs(DEFAULT_READ_TIMEOUT_SECS);
    let data_timeout = std::time::Duration::from_secs(DATA_FRAME_READ_TIMEOUT_SECS);

    let mut first_byte = [0u8; 1];
    match tokio::time::timeout(header_timeout, recv.read_exact(&mut first_byte)).await {
        Ok(Ok(())) => {} // Got a byte, continue processing
        Ok(Err(e)) if e.to_string().contains("finished") => {
            // Stream closed immediately with 0 bytes — this is a health-check ping
            trace!(
                remote = %truncate_for_log(remote_node_id, 8),
                "Health-check ping received (0-byte stream), ignoring"
            );
            return Ok(());
        }
        Ok(Err(e)) => {
            return Err(anyhow::anyhow!("First byte read failed: {}", e));
        }
        Err(_) => {
            return Err(anyhow::anyhow!("First byte read timed out"));
        }
    }

    // V2 binary store path: parse header, read data, handle, return.
    if first_byte[0] == common::STORE_V2_MAGIC {
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

        let (hash, data_len, validator_signature) = match header {
            common::MinerControlMessage::StoreV2 {
                hash,
                data_len,
                validator_signature,
            } => (hash, data_len, validator_signature),
            other => {
                anyhow::bail!(
                    "V2 framing used with non-StoreV2 header: {:?}",
                    std::mem::discriminant(&other)
                );
            }
        };

        if data_len > MAX_V2_DATA_SIZE {
            anyhow::bail!(
                "StoreV2 data too large: {} bytes (max {})",
                data_len,
                MAX_V2_DATA_SIZE
            );
        }

        return handle_store(
            remote_node_id,
            handler,
            &mut send,
            &mut recv,
            hash,
            data_len as usize,
            validator_signature,
        )
        .await;
    }

    // JSON control path: prepend the first byte back and parse.
    let remaining = tokio::time::timeout(data_timeout, recv.read_to_end(MAX_MESSAGE_SIZE - 1))
        .await
        .map_err(|_| anyhow::anyhow!("JSON message read timed out after 55s"))?
        .map_err(|e| anyhow::anyhow!("JSON message read failed: {}", e))?;
    let mut full = Vec::with_capacity(1 + remaining.len());
    full.push(first_byte[0]);
    full.extend_from_slice(&remaining);
    let message: common::MinerControlMessage = serde_json::from_slice(&full)?;

    match message {
        common::MinerControlMessage::Delete {
            hash,
            validator_signature,
        } => {
            handle_delete(
                remote_node_id,
                handler.validator_node_id.as_deref(),
                &mut send,
                &handler.store,
                hash,
                validator_signature,
            )
            .await?;
        }
        common::MinerControlMessage::FetchBlob { hash } => {
            handle_fetch_blob(&mut send, &handler.store, &handler.fetch_sem, hash).await?;
        }
        common::MinerControlMessage::ClusterMapUpdate {
            epoch,
            peers,
            cluster_map_json,
            warden_node_ids,
            gateway_endpoints,
        } => {
            handle_cluster_map_update(
                remote_node_id,
                handler.validator_node_id.as_deref(),
                &mut send,
                epoch,
                peers,
                cluster_map_json,
                warden_node_ids,
                gateway_endpoints,
            )
            .await?;
        }
        common::MinerControlMessage::PullFromPeer {
            hash,
            peer_endpoint,
            ..
        } => {
            // Parse peer_endpoint string to EndpointAddr
            let peer_addr = match serde_json::from_str::<iroh::EndpointAddr>(&peer_endpoint) {
                Ok(addr) => addr,
                Err(e) => {
                    error!(error = %e, "PullFromPeer: Invalid peer_endpoint format");
                    return send_response(&mut send, b"ERROR: Invalid peer_endpoint").await;
                }
            };
            handle_pull_from_peer(remote_node_id, handler, &mut send, hash, peer_addr).await?;
        }
        common::MinerControlMessage::PosChallenge {
            shard_hash,
            chunk_indices,
            nonce,
            expected_root,
            expires_at,
        } => {
            // Authorization: Only allow PoS challenges from validator or warden
            if !is_authorized_for_pos(remote_node_id, handler.validator_node_id.as_deref()).await {
                debug!(remote = %remote_node_id, "PosChallenge rejected: unauthorized sender");
                return send_response(&mut send, b"ERROR: UNAUTHORIZED").await;
            }

            // Backpressure: Proof generation is CPU-intensive
            let _permit = match handler.pos_sem.clone().try_acquire_owned() {
                Ok(p) => p,
                Err(_) => {
                    debug!(shard = %truncate_for_log(&shard_hash, 16), "PosChallenge rate limited");
                    return send_response(&mut send, b"RATE_LIMITED").await;
                }
            };

            handle_pos_challenge(
                &mut send,
                &handler.store,
                shard_hash,
                chunk_indices,
                nonce,
                expected_root,
                expires_at,
            )
            .await?;
        }
        common::MinerControlMessage::CheckBlob { hash } => {
            handle_check_blob(&mut send, &handler.store, hash).await?;
        }
        common::MinerControlMessage::StoreV2 { .. } => {
            warn!("Received raw JSON StoreV2 message (not V2-framed), rejecting");
            send_response(&mut send, b"ERROR: StoreV2 requires binary framing").await?;
        }
    }

    Ok(())
}

async fn handle_store(
    remote_node_id: &str,
    handler: &MinerControlHandler,
    send: &mut quinn::SendStream,
    recv: &mut quinn::RecvStream,
    hash: String,
    data_len: usize,
    validator_signature: Vec<u8>,
) -> Result<()> {
    // Authenticate: Verify the Ed25519 signature from the validator
    let is_authorized = if let Some(ref val_node_id) = handler.validator_node_id {
        let message_to_sign = format!("UPLOAD:{}", hash);
        let sig_array = <[u8; 64]>::try_from(validator_signature.as_slice()).unwrap_or([0; 64]);
        verify_signature(val_node_id, message_to_sign.as_bytes(), &sig_array)
    } else {
        false // If no validator configured, nothing is authorized
    };

    if !is_authorized {
        error!(remote = %remote_node_id, "Store rejected: invalid validator signature");
        return send_response(send, b"ERROR: UNAUTHORIZED").await;
    }

    trace!(hash = %hash, "Received Store command");

    // Verify requested hash parses and matches what we actually store early
    let requested = match iroh_blobs::Hash::from_str(&hash) {
        Ok(h) => h,
        Err(e) => {
            error!(hash = %hash, error = %e, "Store: Invalid hash");
            return send_response(send, b"ERROR: Invalid hash").await;
        }
    };

    // Backpressure: bound concurrent Store ops
    let _permit =
        match acquire_permit_with_timeout(handler.store_sem.clone(), STORE_PERMIT_TIMEOUT_SECS)
            .await
        {
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

    trace!(hash = %hash, size = data_len, "Receiving blob from validator/gateway");

    let mut data = vec![0u8; data_len];
    let data_timeout = std::time::Duration::from_secs(DATA_FRAME_READ_TIMEOUT_SECS);
    tokio::time::timeout(data_timeout, recv.read_exact(&mut data))
        .await
        .map_err(|_| anyhow::anyhow!("StoreV2 data read timed out after 55s"))?
        .map_err(|e| anyhow::anyhow!("StoreV2 data read failed: {}", e))?;

    // Verify blake3 hash matches expected before writing to disk
    let computed = blake3::hash(&data);
    let computed_hex = computed.to_hex();
    if computed_hex.as_str() != hash {
        error!(requested = %hash, computed = %computed_hex, "Store hash mismatch");
        return send_response(send, b"ERROR: Hash mismatch").await;
    }

    // Store blob as flat file
    if let Err(e) = handler.store.store(&hash, &data).await {
        error!(hash = %hash, error = %e, "Failed to store blob");
        return send_response(send, b"ERROR: Storage failed").await;
    }

    // Invalidate blob cache entry to ensure fresh data on next read
    get_blob_cache().remove(&requested);

    // Invalidate PoS commitment cache (shard data changed)
    crate::state::get_pos_commitment_cache().remove(&requested);

    trace!(hash = %hash, "Stored blob");

    let size_human = if data_len >= 1_048_576 {
        format!("{:.1} MiB", data_len as f64 / 1_048_576.0)
    } else {
        format!("{:.1} KiB", data_len as f64 / 1024.0)
    };
    info!(
        "[SHARD] Stored shard {} ({}) from {}",
        truncate_for_log(&hash, 12),
        size_human,
        truncate_for_log(remote_node_id, 12),
    );

    // Send ACK and wait for remote to receive it
    send_response(send, b"OK").await
}

async fn handle_delete(
    remote_node_id: &str,
    validator_node_id: Option<&str>,
    send: &mut quinn::SendStream,
    store: &FlatBlobStore,
    hash: String,
    validator_signature: Vec<u8>,
) -> Result<()> {
    // Authenticate: Verify the Ed25519 signature from the validator
    let is_authorized = if let Some(val_node_id) = validator_node_id {
        let message_to_sign = format!("DELETE:{}", hash);
        let sig_array = <[u8; 64]>::try_from(validator_signature.as_slice()).unwrap_or([0; 64]);
        verify_signature(val_node_id, message_to_sign.as_bytes(), &sig_array)
    } else {
        false // If no validator configured, nothing is authorized
    };

    if !is_authorized {
        error!(remote = %remote_node_id, "Delete rejected: invalid validator signature");
        return send_response(send, b"ERROR: UNAUTHORIZED").await;
    }

    trace!(hash = %hash, "Received Delete command");

    // Parse hash to validate format
    let hash_parsed = match iroh_blobs::Hash::from_str(&hash) {
        Ok(h) => h,
        Err(e) => {
            error!(hash = %hash, error = %e, "Delete: Invalid hash");
            return send_response(send, b"ERROR: Invalid hash").await;
        }
    };

    // Delete the blob file directly
    match store.delete(&hash).await {
        Ok(()) => {
            trace!(
                hash = %truncate_for_log(&hash, 32),
                "Delete complete: removed blob file"
            );
        }
        Err(e) => {
            error!(
                hash = %truncate_for_log(&hash, 32),
                error = %e,
                "Delete: failed to remove file"
            );
        }
    }

    // Invalidate caches to prevent serving stale data
    get_blob_cache().remove(&hash_parsed);
    crate::state::get_pos_commitment_cache().remove(&hash_parsed);

    // Send ACK
    send_response(send, b"OK").await
}

async fn handle_check_blob(
    send: &mut quinn::SendStream,
    store: &FlatBlobStore,
    hash: String,
) -> Result<()> {
    trace!(hash = %truncate_for_log(&hash, 32), "CheckBlob request");

    if store.has(&hash) {
        send_response(send, b"HAS:true").await
    } else {
        send_response(send, b"HAS:false").await
    }
}

async fn handle_fetch_blob(
    send: &mut quinn::SendStream,
    store: &FlatBlobStore,
    fetch_sem: &Arc<tokio::sync::Semaphore>,
    hash: String,
) -> Result<()> {
    trace!(hash = %truncate_for_log(&hash, 32), "FetchBlob request");

    // Backpressure: bound concurrent FetchBlob serving ops
    let _permit = match fetch_sem.clone().try_acquire_owned() {
        Ok(p) => p,
        Err(_) => return send_response(send, b"ERROR: RATE_LIMITED").await,
    };

    // Parse hash for cache key
    let hash_parsed = match iroh_blobs::Hash::from_str(&hash) {
        Ok(h) => h,
        Err(e) => {
            error!(hash = %hash, error = %e, "FetchBlob: Invalid hash");
            return send_response(send, b"ERROR: Invalid hash").await;
        }
    };

    // Helper to send blob data with DATA: prefix
    async fn send_blob_data(send: &mut quinn::SendStream, data: &[u8]) -> Result<()> {
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

    // Read blob data from flat file store
    match store.read(&hash).await {
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
    remote_node_id: &str,
    validator_node_id: Option<&str>,
    send: &mut quinn::SendStream,
    epoch: u64,
    peers: Vec<(String, String)>, // (public_key, endpoint_json)
    cluster_map_json: Option<String>,
    warden_node_ids: Option<Vec<String>>,
    gateway_endpoints: Vec<common::GatewayEndpoint>,
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
        // Record when this epoch change happened for rebalance stability window
        let mut last_change = get_last_epoch_change().write().await;
        *last_change = (epoch, tokio::time::Instant::now());
    }

    // Update peer cache (lock-free DashMap)
    let peer_cache = get_peer_cache();

    // On epoch change, clear stale entries to prevent unbounded growth
    if epoch_changed {
        peer_cache.clear();
        trace!("Cleared peer cache on epoch change");
    }

    let mut peers_cached = 0u32;
    let mut peers_parse_failed = 0u32;

    for (node_id, addr_json) in &peers {
        // Enforce cache size limit
        if peer_cache.len() >= MAX_PEER_CACHE_ENTRIES {
            warn!(
                capacity = MAX_PEER_CACHE_ENTRIES,
                "Peer cache at capacity, skipping remaining entries"
            );
            break;
        }

        if let Ok(addr) = serde_json::from_str::<iroh::EndpointAddr>(addr_json) {
            peer_cache.insert(node_id.clone(), addr);
            peers_cached += 1;
        } else {
            peers_parse_failed += 1;
        }
    }

    if peers_parse_failed > 0 {
        debug!(
            peers_cached,
            peers_parse_failed, "Peer cache update had parse failures"
        );
    }

    // Store the cluster map for CRUSH calculations
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
                    crate::rebalance::persist_cluster_map(&map).await;
                    let mut map_guard = get_cluster_map().write().await;
                    // Save old map to history before replacing (for epoch lookback)
                    if let Some(old_map) = map_guard.as_ref() {
                        let history_lock = crate::state::get_cluster_map_history();
                        let mut history = history_lock.write().await;
                        if history.len() >= crate::constants::MAX_CLUSTER_MAP_HISTORY {
                            history.pop_front();
                        }
                        history.push_back(Arc::clone(old_map));
                    }
                    *map_guard = Some(Arc::new(map));
                }
                Err(e) => {
                    warn!(error = %e, "Failed to parse cluster_map_json");
                }
            }
        }
    }

    // Update gateway endpoints for keepalive connections
    if !gateway_endpoints.is_empty() {
        let gw_map = get_gateway_endpoints();
        gw_map.clear();
        let mut stored = 0u32;
        for ep in &gateway_endpoints {
            if stored as usize >= crate::constants::MAX_GATEWAY_ENDPOINTS {
                break;
            }
            gw_map.insert(ep.node_id.clone(), ep.clone());
            stored += 1;
        }
        debug!(
            count = stored,
            "Updated gateway endpoints from ClusterMapUpdate"
        );
    }

    // Update warden node IDs if provided by validator
    if let Some(ids) = warden_node_ids {
        let mut new_ids: Vec<String> = ids.into_iter().filter(|s| !s.is_empty()).collect();
        if !new_ids.is_empty() {
            new_ids.sort();
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

    // Send ACK
    send_response(send, b"OK").await
}

async fn handle_pull_from_peer(
    remote_node_id: &str,
    handler: &MinerControlHandler,
    send: &mut quinn::SendStream,
    hash: String,
    peer_endpoint: iroh::EndpointAddr,
) -> Result<()> {
    // Only validator should be allowed to issue PullFromPeer commands
    if !is_authorized(remote_node_id, handler.validator_node_id.as_deref()) {
        error!(remote = %remote_node_id, "PullFromPeer rejected: non-validator controller");
        return send_response(send, b"ERROR: UNAUTHORIZED").await;
    }

    trace!(hash = %truncate_for_log(&hash, 32), "Received PullFromPeer command");

    // Backpressure: bound concurrent peer pulls
    let permit = match acquire_permit_with_timeout(
        handler.pull_sem.clone(),
        PULL_PERMIT_TIMEOUT_SECS,
    )
    .await
    {
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
        std::time::Duration::from_secs(PEER_BLOB_DOWNLOAD_TIMEOUT_SECS),
        pull_blob_from_peer(
            Arc::clone(&handler.store),
            handler.endpoint.clone(),
            peer_endpoint,
            hash.clone(),
        ),
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

/// Pull blob from peer using endpoint address.
/// Extracts SocketAddr from the EndpointAddr and connects via quinn.
pub async fn pull_blob_from_peer(
    store: Arc<FlatBlobStore>,
    endpoint: quinn::Endpoint,
    peer_addr: iroh::EndpointAddr,
    hash: String,
) -> Result<()> {
    trace!(hash = %truncate_for_log(&hash, 16), "Pulling blob from peer");

    let peer_node_id = peer_addr.id.to_string();
    let id_prefix = truncate_for_log(&peer_node_id, 8);

    // Extract socket address from EndpointAddr
    let socket_addr = crate::state::socket_addr_from_endpoint(&peer_addr).ok_or_else(|| {
        anyhow::anyhow!("Peer {} has no direct IP address", id_prefix)
    })?;

    // Quick connectivity check: fail fast if peer is unreachable (3s timeout)
    let conn = match tokio::time::timeout(
        std::time::Duration::from_secs(crate::constants::REBALANCE_PEER_CONNECT_TIMEOUT_SECS),
        crate::state::get_pooled_connection(&endpoint, &peer_node_id, socket_addr),
    )
    .await
    {
        Ok(Ok(c)) => c,
        Ok(Err(e)) => {
            warn!(
                "[REBALANCE] Peer {} unreachable, skipping (connect error: {})",
                id_prefix, e
            );
            return Err(anyhow::anyhow!("Peer {} unreachable: {}", id_prefix, e));
        }
        Err(_) => {
            warn!(
                "[REBALANCE] Peer {} unreachable, skipping (connect timeout {}s)",
                id_prefix,
                crate::constants::REBALANCE_PEER_CONNECT_TIMEOUT_SECS,
            );
            return Err(anyhow::anyhow!(
                "Peer {} unreachable: connect timeout",
                id_prefix
            ));
        }
    };

    let (mut send, mut recv) = conn.open_bi().await?;

    // Send FetchBlob request
    let request = common::MinerControlMessage::FetchBlob { hash: hash.clone() };
    let request_bytes = serde_json::to_vec(&request)?;
    send.write_all(&request_bytes).await?;
    send.finish()?;

    // Read response with timeout
    let response = tokio::time::timeout(
        std::time::Duration::from_secs(PEER_DATA_RECEPTION_TIMEOUT_SECS),
        recv.read_to_end(MAX_FETCH_RESPONSE_SIZE),
    )
    .await
    .map_err(|_| {
        anyhow::anyhow!(
            "Timeout reading FetchBlob response for {} from peer {}",
            truncate_for_log(&hash, 16),
            id_prefix
        )
    })??;

    if !response.starts_with(b"DATA:") {
        let peer_msg = std::str::from_utf8(&response)
            .unwrap_or("<non-utf8>")
            .chars()
            .take(LOG_STRING_TRUNCATE_LEN)
            .collect::<String>();
        return Err(anyhow::anyhow!(
            "Peer did not return DATA for {} (response: {})",
            truncate_for_log(&hash, 16),
            peer_msg
        ));
    }

    // Skip the "DATA:" prefix (5 bytes)
    let data = &response[5..];
    if data.is_empty() {
        return Err(anyhow::anyhow!("Empty DATA payload from peer"));
    }

    let pull_size = data.len();

    // Verify blake3 hash before storing
    let computed = blake3::hash(data);
    let computed_hex = computed.to_hex();
    if computed_hex.as_str() != hash {
        return Err(anyhow::anyhow!(
            "Hash mismatch: requested {} stored {}",
            truncate_for_log(&hash, 16),
            truncate_for_log(computed_hex.as_str(), 16)
        ));
    }

    // Store blob as flat file
    store
        .store(&hash, data)
        .await
        .map_err(|e| anyhow::anyhow!("Failed to store blob: {}", e))?;
    let pull_size_human = if pull_size >= 1_048_576 {
        format!("{:.1} MiB", pull_size as f64 / 1_048_576.0)
    } else {
        format!("{:.1} KiB", pull_size as f64 / 1024.0)
    };
    info!(
        "[SHARD] Stored shard {} ({}) from peer {}",
        truncate_for_log(&hash, 12),
        pull_size_human,
        id_prefix,
    );
    Ok(())
}

/// Handle a proof-of-storage challenge from a Warden.
///
/// Generates a ZK proof demonstrating possession of the challenged chunks.
async fn handle_pos_challenge(
    send: &mut quinn::SendStream,
    store: &FlatBlobStore,
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

    // Parse shard hash for cache key
    let hash_parsed = match iroh_blobs::Hash::from_str(&shard_hash) {
        Ok(h) => h,
        Err(e) => {
            error!(shard = %truncate_for_log(&shard_hash, 16), error = %e, "Invalid shard hash");
            return send_response(send, b"ERROR: Invalid shard hash").await;
        }
    };

    // Read shard data from flat file store
    let shard_data = match store.read(&shard_hash).await {
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

    // Get or generate commitment with Merkle tree (cached to avoid rebuilding ~200KB tree)
    let pos_cache = crate::state::get_pos_commitment_cache();
    let commitment: Arc<CommitmentWithTree> = if let Some(cached) = pos_cache.get(&hash_parsed) {
        trace!(shard = %truncate_for_log(&shard_hash, 16), "PoS commitment cache HIT");
        cached
    } else {
        match CommitmentWithTree::generate(&shard_data, pos_circuits::DEFAULT_CHUNK_SIZE) {
            Ok(c) => {
                let arc = Arc::new(c);
                pos_cache.insert(hash_parsed, arc.clone());
                arc
            }
            Err(e) => {
                error!(error = %e, "Failed to generate commitment");
                return send_response(send, b"ERROR: Commitment generation failed").await;
            }
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

    // Arc clone for the blocking task (cheap refcount bump, not a deep copy)
    let commitment_for_proof = commitment.clone();

    // Generate proof on blocking thread pool to avoid starving the async executor.
    let start = Instant::now();
    let proof = match tokio::task::spawn_blocking(move || {
        generate_proof(&shard_data, &commitment_for_proof, &challenge)
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

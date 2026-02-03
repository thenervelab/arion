//! Chain-Submitter Control Protocol Handler
//!
//! Handles P2P messages from chain-submitters for:
//! - Fetching cluster maps for on-chain submission
//! - Fetching network stats for rewards calculation

use super::{MAX_MESSAGE_SIZE, P2pAuthConfig, send_response};
use crate::state::{AppState, ValidatorReadyState};
use common::{FileManifest, SubmitterControlMessage, calculate_stripe_placement};
use futures_lite::StreamExt;
use std::collections::HashMap;
use std::sync::Arc;
use tracing::{debug, warn};

/// P2P protocol handler for chain-submitter → validator communication.
///
/// Implements `ProtocolHandler` for Iroh's protocol router.
pub struct SubmitterControlHandler {
    pub state: Arc<AppState>,
    pub auth_config: Arc<P2pAuthConfig>,
}

impl std::fmt::Debug for SubmitterControlHandler {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SubmitterControlHandler").finish()
    }
}

impl iroh::protocol::ProtocolHandler for SubmitterControlHandler {
    fn accept(
        &self,
        conn: iroh::endpoint::Connection,
    ) -> impl futures::Future<Output = Result<(), iroh::protocol::AcceptError>> + Send {
        let state = self.state.clone();
        let auth_config = self.auth_config.clone();
        async move {
            handle_submitter_control(conn, state, auth_config)
                .await
                .map_err(|e| iroh::protocol::AcceptError::from_err(std::io::Error::other(e)))
        }
    }
}

/// Handle an incoming P2P connection from a chain-submitter.
///
/// This handler loops to accept multiple streams on the same connection,
/// allowing the client to reuse the connection for multiple requests.
/// The connection stays open until the client disconnects or an error occurs.
async fn handle_submitter_control(
    conn: iroh::endpoint::Connection,
    state: Arc<AppState>,
    auth_config: Arc<P2pAuthConfig>,
) -> anyhow::Result<()> {
    let remote_node_id = conn.remote_id();
    debug!(remote = %remote_node_id, "Submitter control connection accepted");

    // Authorization check ONCE per connection (not per stream)
    if !auth_config.is_authorized_submitter(&remote_node_id).await {
        warn!(remote = %remote_node_id, "Unauthorized submitter connection rejected");
        // Try to accept a stream to send error response
        if let Ok((mut send, _recv)) = conn.accept_bi().await {
            let response = SubmitterControlMessage::ClusterMapResponse {
                map: None,
                error: Some("Unauthorized: node ID not in allowed list".to_string()),
            };
            if let Ok(response_bytes) = serde_json::to_vec(&response) {
                let _ = send_response(&mut send, &response_bytes).await;
            }
        }
        return Ok(());
    }

    // Loop to handle multiple streams on the same connection
    loop {
        // Accept next bidirectional stream (blocks until client opens one or disconnects)
        let (mut send, mut recv) = match conn.accept_bi().await {
            Ok(stream) => stream,
            Err(e) => {
                // Connection closed by client or network error - this is normal
                debug!(remote = %remote_node_id, error = %e, "Submitter connection closed");
                break;
            }
        };

        // Handle this stream's message
        if let Err(e) =
            handle_single_submitter_message(&mut send, &mut recv, &state, &remote_node_id).await
        {
            warn!(remote = %remote_node_id, error = %e, "Error handling submitter message");
            // Continue loop - don't close connection on single message error
            // The client can retry on a new stream
        }
    }

    Ok(())
}

/// Handle a single message on a submitter stream.
async fn handle_single_submitter_message(
    send: &mut iroh::endpoint::SendStream,
    recv: &mut iroh::endpoint::RecvStream,
    state: &AppState,
    remote_node_id: &iroh::PublicKey,
) -> anyhow::Result<()> {
    // Read message
    let buf = recv.read_to_end(MAX_MESSAGE_SIZE).await?;
    let message: SubmitterControlMessage = serde_json::from_slice(&buf)?;

    // Record metric for this request
    let message_type = submitter_message_type(&message);
    state
        .metrics
        .p2p_requests_total
        .get_or_create(&[
            ("protocol".to_string(), "submitter-control".to_string()),
            ("message_type".to_string(), message_type.to_string()),
        ])
        .inc();

    // Check ready state for operations that require full readiness
    let ready_state = state.get_ready_state();

    match message {
        // GetClusterMap is always allowed - cluster_map is in-memory
        SubmitterControlMessage::GetClusterMap => {
            handle_get_cluster_map(send, state).await?;
        }
        // GetNetworkStats requires manifest_hashes which may not be loaded yet
        SubmitterControlMessage::GetNetworkStats => {
            if !ready_state.is_ready() {
                return send_warming_up_stats_error(send, ready_state).await;
            }
            handle_get_network_stats(send, state).await?;
        }
        // Response messages should not be received by the validator
        SubmitterControlMessage::ClusterMapResponse { .. }
        | SubmitterControlMessage::NetworkStatsResponse { .. }
        | SubmitterControlMessage::AttestationCommitmentReady { .. }
        | SubmitterControlMessage::AttestationCommitmentAck { .. } => {
            warn!(
                remote = %remote_node_id,
                "Received unexpected response message from submitter"
            );
        }
    }

    Ok(())
}

/// Extract message type name for metrics.
fn submitter_message_type(message: &SubmitterControlMessage) -> &'static str {
    match message {
        SubmitterControlMessage::GetClusterMap => "GetClusterMap",
        SubmitterControlMessage::GetNetworkStats => "GetNetworkStats",
        SubmitterControlMessage::ClusterMapResponse { .. } => "ClusterMapResponse",
        SubmitterControlMessage::NetworkStatsResponse { .. } => "NetworkStatsResponse",
        SubmitterControlMessage::AttestationCommitmentReady { .. } => "AttestationCommitmentReady",
        SubmitterControlMessage::AttestationCommitmentAck { .. } => "AttestationCommitmentAck",
    }
}

/// Handle GetClusterMap request from chain-submitter.
async fn handle_get_cluster_map(
    send: &mut iroh::endpoint::SendStream,
    state: &AppState,
) -> anyhow::Result<()> {
    debug!("GetClusterMap request from chain-submitter");

    let map = state.cluster_map.read().await.clone();

    let response = SubmitterControlMessage::ClusterMapResponse {
        map: Some(map),
        error: None,
    };
    let response_bytes = serde_json::to_vec(&response)?;
    send_response(send, &response_bytes).await
}

/// Handle GetNetworkStats request from chain-submitter.
async fn handle_get_network_stats(
    send: &mut iroh::endpoint::SendStream,
    state: &AppState,
) -> anyhow::Result<()> {
    debug!("GetNetworkStats request from chain-submitter");

    // Get file hashes and cluster map
    let manifest_hashes = state.manifest_hashes.lock().await;
    let file_hashes: Vec<String> = manifest_hashes.iter().map(|f| f.hash.clone()).collect();
    drop(manifest_hashes);

    let total_files = file_hashes.len();
    let cluster_map = state.cluster_map.read().await.clone();

    // Calculate per-miner stats by iterating through manifests and using CRUSH placement
    let mut miner_stats: HashMap<String, [u64; 2]> = HashMap::new();
    let mut bandwidth_stats: HashMap<String, u64> = HashMap::new();

    // Initialize all miners with zero stats
    for miner in &cluster_map.miners {
        let uid_str = miner.uid.to_string();
        miner_stats.insert(uid_str.clone(), [0, 0]);
        bandwidth_stats.insert(uid_str, miner.bandwidth_total);
    }

    // Process each file manifest to count shards per miner
    for file_hash in &file_hashes {
        let manifest = match get_manifest_from_cache_or_docs(state, file_hash).await {
            Some(m) => m,
            None => continue,
        };

        let k = manifest.stripe_config.k;
        let m = manifest.stripe_config.m;
        let shards_per_stripe = k + m;
        let num_shards = manifest.shards.len() as u64;
        let shard_size = if num_shards > 0 {
            manifest.size / num_shards
        } else {
            0
        };

        // Use CRUSH to calculate which miner should have each shard
        for shard in &manifest.shards {
            let stripe_idx = shard.index / shards_per_stripe;
            let local_idx = shard.index % shards_per_stripe;

            if let Ok(stripe_miners) = calculate_stripe_placement(
                &manifest.file_hash,
                stripe_idx as u64,
                shards_per_stripe,
                &cluster_map,
                manifest.placement_version,
            ) {
                if let Some(miner) = stripe_miners.get(local_idx) {
                    let uid_str = miner.uid.to_string();
                    if let Some(stats) = miner_stats.get_mut(&uid_str) {
                        stats[0] += shard_size; // stored_bytes
                        stats[1] += 1; // shard_count
                    }
                }
            }
        }
    }

    let response = SubmitterControlMessage::NetworkStatsResponse {
        total_files,
        miner_stats,
        bandwidth_stats,
    };
    let response_bytes = serde_json::to_vec(&response)?;
    send_response(send, &response_bytes).await
}

/// Helper to get a manifest from cache or iroh-docs.
async fn get_manifest_from_cache_or_docs(
    state: &AppState,
    file_hash: &str,
) -> Option<FileManifest> {
    use common::now_secs;
    use tokio::io::AsyncReadExt;

    // Try cache first
    if let Some((json, cached_at)) = state.manifest_cache.get(file_hash) {
        // Check for tombstone (deleted file)
        if json == common::MANIFEST_TOMBSTONE {
            return None;
        }
        // Check if cache entry is fresh (within TTL)
        let now = now_secs();
        if now.saturating_sub(cached_at) < state.manifest_cache_tombstone_ttl_secs {
            if let Ok(manifest) = serde_json::from_str::<FileManifest>(&json) {
                return Some(manifest);
            }
        }
    }

    // Fall back to iroh-docs
    let query = iroh_docs::store::Query::single_latest_per_key().key_exact(file_hash.as_bytes());
    let stream_result = state.doc.get_many(query).await.ok()?;
    let mut stream = Box::pin(stream_result);

    if let Some(Ok(entry)) = stream.next().await {
        let content_hash = entry.content_hash();
        let mut reader = state.blobs_store.reader(content_hash);
        let mut content = Vec::new();
        if reader.read_to_end(&mut content).await.is_ok() {
            if let Ok(manifest) = serde_json::from_slice::<FileManifest>(&content) {
                return Some(manifest);
            }
        }
    }

    None
}

/// Send a warming up error response for network stats.
async fn send_warming_up_stats_error(
    send: &mut iroh::endpoint::SendStream,
    ready_state: ValidatorReadyState,
) -> anyhow::Result<()> {
    debug!(state = ?ready_state, "Rejected GetNetworkStats during warmup");
    let response = SubmitterControlMessage::NetworkStatsResponse {
        total_files: 0,
        miner_stats: HashMap::new(),
        bandwidth_stats: HashMap::new(),
    };
    // Note: The response format doesn't have an error field, so we return empty stats
    // The chain-submitter should detect this and retry later
    let response_bytes = serde_json::to_vec(&response)?;
    send_response(send, &response_bytes).await
}

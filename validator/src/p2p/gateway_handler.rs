//! Gateway Control Protocol Handler
//!
//! Handles P2P messages from gateways for:
//! - Cluster map synchronization
//! - File manifest retrieval
//! - Upload/delete coordination
//! - Bandwidth/failure reporting
//! - Repair hints

use super::{MAX_MESSAGE_SIZE, MAX_UPLOAD_SIZE, P2pAuthConfig, send_response};
use crate::state::{AppState, ValidatorReadyState};
use common::{
    BandwidthReport, ClusterMap, FileManifest, GatewayControlMessage, MinerFailureReport,
    validate_file_hash,
};
use std::sync::Arc;
use tracing::{debug, info, warn};

/// Suggested retry delay for clients when validator is warming up
const WARMUP_RETRY_SECS: u64 = 30;

/// P2P protocol handler for gateway → validator communication.
///
/// Implements `ProtocolHandler` for Iroh's protocol router.
pub struct GatewayControlHandler {
    pub state: Arc<AppState>,
    pub auth_config: Arc<P2pAuthConfig>,
}

impl std::fmt::Debug for GatewayControlHandler {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("GatewayControlHandler").finish()
    }
}

impl iroh::protocol::ProtocolHandler for GatewayControlHandler {
    fn accept(
        &self,
        conn: iroh::endpoint::Connection,
    ) -> impl futures::Future<Output = Result<(), iroh::protocol::AcceptError>> + Send {
        let state = self.state.clone();
        let auth_config = self.auth_config.clone();
        async move {
            handle_gateway_control(conn, state, auth_config)
                .await
                .map_err(|e| iroh::protocol::AcceptError::from_err(std::io::Error::other(e)))
        }
    }
}

/// Handle an incoming P2P connection from a gateway.
///
/// This handler loops to accept multiple streams on the same connection,
/// allowing the client to reuse the connection for multiple requests.
/// The connection stays open until the client disconnects or an error occurs.
async fn handle_gateway_control(
    conn: iroh::endpoint::Connection,
    state: Arc<AppState>,
    auth_config: Arc<P2pAuthConfig>,
) -> anyhow::Result<()> {
    let remote_node_id = conn.remote_id();
    debug!(remote = %remote_node_id, "Gateway control connection accepted");

    // Authorization check ONCE per connection (not per stream)
    if !auth_config.is_authorized_gateway(&remote_node_id).await {
        warn!(remote = %remote_node_id, "Unauthorized gateway connection rejected");
        // Try to accept a stream to send error response
        if let Ok((mut send, _recv)) = conn.accept_bi().await {
            let response = GatewayControlMessage::Ack {
                success: false,
                message: Some("Unauthorized: node ID not in allowed list".to_string()),
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
                debug!(remote = %remote_node_id, error = %e, "Gateway connection closed");
                break;
            }
        };

        // Handle this stream's message
        if let Err(e) =
            handle_single_gateway_message(&mut send, &mut recv, &state, &remote_node_id).await
        {
            warn!(remote = %remote_node_id, error = %e, "Error handling gateway message");
            // Continue loop - don't close connection on single message error
            // The client can retry on a new stream
        }
    }

    Ok(())
}

/// Handle a single message on a gateway stream.
async fn handle_single_gateway_message(
    send: &mut iroh::endpoint::SendStream,
    recv: &mut iroh::endpoint::RecvStream,
    state: &AppState,
    remote_node_id: &iroh::PublicKey,
) -> anyhow::Result<()> {
    // Read message
    let buf = recv.read_to_end(MAX_MESSAGE_SIZE + MAX_UPLOAD_SIZE).await?;
    let message: GatewayControlMessage = serde_json::from_slice(&buf)?;

    // Record metric for this request
    let message_type = gateway_message_type(&message);
    state
        .metrics
        .p2p_requests_total
        .get_or_create(&[
            ("protocol".to_string(), "gateway-control".to_string()),
            ("message_type".to_string(), message_type.to_string()),
        ])
        .inc();

    // Check ready state for operations that require full readiness
    let ready_state = state.get_ready_state();

    match message {
        // GetClusterMap is always allowed - cluster_map is in-memory
        GatewayControlMessage::GetClusterMap => {
            handle_get_cluster_map(send, state).await?;
        }
        // GetClusterMapEpoch may need storage access but cluster map is critical for gateways
        GatewayControlMessage::GetClusterMapEpoch { epoch } => {
            handle_get_cluster_map_epoch(send, state, epoch).await?;
        }
        // GetManifest requires storage access - check ready state
        GatewayControlMessage::GetManifest { file_hash } => {
            if !ready_state.is_ready() {
                return send_warming_up_error(send, ready_state, "GetManifest").await;
            }
            handle_get_manifest(send, state, &file_hash).await?;
        }
        // GetRebalanceStatus is in-memory - always allowed
        GatewayControlMessage::GetRebalanceStatus { epoch, pg_id } => {
            handle_get_rebalance_status(send, state, epoch, pg_id).await?;
        }
        // UploadFile requires full readiness
        GatewayControlMessage::UploadFile {
            filename,
            size,
            data,
            content_type,
        } => {
            if !ready_state.is_ready() {
                return send_warming_up_upload_error(send, ready_state).await;
            }
            handle_upload_file(send, state, filename, size, data, content_type).await?;
        }
        // DeleteFile requires full readiness
        GatewayControlMessage::DeleteFile { file_hash } => {
            if !ready_state.is_ready() {
                return send_warming_up_error(send, ready_state, "DeleteFile").await;
            }
            handle_delete_file(send, state, &file_hash).await?;
        }
        // Bandwidth reporting is always allowed - updates in-memory state
        GatewayControlMessage::ReportBandwidth { reports } => {
            handle_report_bandwidth(send, state, reports).await?;
        }
        // Failure reporting is always allowed - updates in-memory state
        GatewayControlMessage::ReportFailures { reports } => {
            handle_report_failures(send, state, reports).await?;
        }
        // RepairHint requires full readiness
        GatewayControlMessage::RepairHint {
            file_hash,
            stripe_idx,
            count,
        } => {
            if !ready_state.is_ready() {
                return send_warming_up_error(send, ready_state, "RepairHint").await;
            }
            handle_repair_hint(send, state, &file_hash, stripe_idx, count).await?;
        }
        // Response messages should not be received by the validator
        GatewayControlMessage::ClusterMapResponse { .. }
        | GatewayControlMessage::ManifestResponse { .. }
        | GatewayControlMessage::RebalanceStatusResponse { .. }
        | GatewayControlMessage::UploadResponse { .. }
        | GatewayControlMessage::Ack { .. } => {
            warn!(remote = %remote_node_id, "Received unexpected response message from gateway");
        }
    }

    Ok(())
}

/// Extract message type name for metrics.
fn gateway_message_type(message: &GatewayControlMessage) -> &'static str {
    match message {
        GatewayControlMessage::GetClusterMap => "GetClusterMap",
        GatewayControlMessage::GetClusterMapEpoch { .. } => "GetClusterMapEpoch",
        GatewayControlMessage::GetManifest { .. } => "GetManifest",
        GatewayControlMessage::GetRebalanceStatus { .. } => "GetRebalanceStatus",
        GatewayControlMessage::UploadFile { .. } => "UploadFile",
        GatewayControlMessage::DeleteFile { .. } => "DeleteFile",
        GatewayControlMessage::ReportBandwidth { .. } => "ReportBandwidth",
        GatewayControlMessage::ReportFailures { .. } => "ReportFailures",
        GatewayControlMessage::RepairHint { .. } => "RepairHint",
        GatewayControlMessage::ClusterMapResponse { .. } => "ClusterMapResponse",
        GatewayControlMessage::ManifestResponse { .. } => "ManifestResponse",
        GatewayControlMessage::RebalanceStatusResponse { .. } => "RebalanceStatusResponse",
        GatewayControlMessage::UploadResponse { .. } => "UploadResponse",
        GatewayControlMessage::Ack { .. } => "Ack",
    }
}

/// Handle GetClusterMap request - returns current cluster map.
async fn handle_get_cluster_map(
    send: &mut iroh::endpoint::SendStream,
    state: &AppState,
) -> anyhow::Result<()> {
    debug!("GetClusterMap request");

    let map = state.cluster_map.read().await.clone();

    let response = GatewayControlMessage::ClusterMapResponse {
        map: Some(map),
        error: None,
    };
    let response_bytes = serde_json::to_vec(&response)?;
    send_response(send, &response_bytes).await
}

/// Handle GetClusterMapEpoch request - returns cluster map at specific epoch.
async fn handle_get_cluster_map_epoch(
    send: &mut iroh::endpoint::SendStream,
    state: &AppState,
    epoch: u64,
) -> anyhow::Result<()> {
    debug!(epoch = epoch, "GetClusterMapEpoch request");

    // Check current epoch first
    let current_map = state.cluster_map.read().await;
    if current_map.epoch == epoch {
        let response = GatewayControlMessage::ClusterMapResponse {
            map: Some(current_map.clone()),
            error: None,
        };
        drop(current_map);
        return send_cluster_map_response(send, response).await;
    }
    drop(current_map);

    // Load from iroh-docs
    let response = load_cluster_map_from_docs(state, epoch).await;
    send_cluster_map_response(send, response).await
}

/// Load a cluster map from iroh-docs storage.
async fn load_cluster_map_from_docs(state: &AppState, epoch: u64) -> GatewayControlMessage {
    use futures::StreamExt;
    use tokio::io::AsyncReadExt;

    let key = format!("cluster_map:{}", epoch).into_bytes();
    let query = iroh_docs::store::Query::single_latest_per_key().key_exact(&key);
    let mut stream = match state.doc.get_many(query).await {
        Ok(s) => Box::pin(s),
        Err(e) => {
            return GatewayControlMessage::ClusterMapResponse {
                map: None,
                error: Some(format!("Failed to query cluster map: {}", e)),
            };
        }
    };

    let Some(Ok(entry)) = stream.next().await else {
        return GatewayControlMessage::ClusterMapResponse {
            map: None,
            error: Some(format!("Cluster map epoch {} not found", epoch)),
        };
    };

    let mut reader = state.blobs_store.reader(entry.content_hash());
    let mut content = Vec::new();
    if reader.read_to_end(&mut content).await.is_err() {
        return GatewayControlMessage::ClusterMapResponse {
            map: None,
            error: Some(format!("Failed to read cluster map: {}", epoch)),
        };
    }

    match serde_json::from_slice::<ClusterMap>(&content) {
        Ok(map) => GatewayControlMessage::ClusterMapResponse {
            map: Some(map),
            error: None,
        },
        Err(e) => GatewayControlMessage::ClusterMapResponse {
            map: None,
            error: Some(format!("Failed to parse cluster map: {}", e)),
        },
    }
}

/// Helper to serialize and send a cluster map response.
async fn send_cluster_map_response(
    send: &mut iroh::endpoint::SendStream,
    response: GatewayControlMessage,
) -> anyhow::Result<()> {
    let response_bytes = serde_json::to_vec(&response)?;
    send_response(send, &response_bytes).await
}

/// Handle GetManifest request - returns file manifest.
async fn handle_get_manifest(
    send: &mut iroh::endpoint::SendStream,
    state: &AppState,
    file_hash: &str,
) -> anyhow::Result<()> {
    debug!(file_hash = %file_hash, "GetManifest request");

    // Validate file hash format
    if let Err(e) = validate_file_hash(file_hash) {
        return send_manifest_response(send, None, Some(e)).await;
    }

    // Check cache first
    if let Some(response) = check_manifest_cache(state, file_hash) {
        return send_manifest_response(send, response.0, response.1).await;
    }

    // Load from iroh-docs
    let (manifest, error) = load_manifest_from_docs(state, file_hash).await;
    send_manifest_response(send, manifest, error).await
}

/// Check manifest cache, returning (manifest, error) if cache hit.
fn check_manifest_cache(
    state: &AppState,
    file_hash: &str,
) -> Option<(Option<FileManifest>, Option<String>)> {
    let (cached_json, cached_at) = state.manifest_cache.get(file_hash)?;
    let now = common::now_secs();

    // Handle tombstone (deleted file)
    if cached_json == common::MANIFEST_TOMBSTONE {
        let tombstone_age = now.saturating_sub(cached_at);
        if tombstone_age < state.manifest_cache_tombstone_ttl_secs {
            return Some((None, Some("File has been deleted".to_string())));
        }
        // Tombstone expired, fall through to storage
        return None;
    }

    // Try to parse cached manifest
    match serde_json::from_str::<FileManifest>(&cached_json) {
        Ok(manifest) => Some((Some(manifest), None)),
        Err(_) => None, // Invalid cache entry, fall through
    }
}

/// Load manifest from iroh-docs storage.
async fn load_manifest_from_docs(
    state: &AppState,
    file_hash: &str,
) -> (Option<FileManifest>, Option<String>) {
    use futures::StreamExt;
    use tokio::io::AsyncReadExt;

    let key = format!("manifest:{}", file_hash).into_bytes();
    let query = iroh_docs::store::Query::single_latest_per_key().key_exact(&key);

    let stream = match state.doc.get_many(query).await {
        Ok(s) => s,
        Err(e) => return (None, Some(format!("Failed to query manifest: {}", e))),
    };
    let mut stream = Box::pin(stream);

    let Some(Ok(entry)) = stream.next().await else {
        return (None, Some(format!("Manifest not found for {}", file_hash)));
    };

    let mut reader = state.blobs_store.reader(entry.content_hash());
    let mut content = Vec::new();
    if reader.read_to_end(&mut content).await.is_err() {
        return (
            None,
            Some(format!("Failed to read manifest for {}", file_hash)),
        );
    }

    match serde_json::from_slice::<FileManifest>(&content) {
        Ok(manifest) => {
            // Update cache
            if let Ok(json) = serde_json::to_string(&manifest) {
                state
                    .manifest_cache
                    .insert(file_hash.to_string(), (json, common::now_secs()));
            }
            (Some(manifest), None)
        }
        Err(e) => (None, Some(format!("Failed to parse manifest: {}", e))),
    }
}

/// Helper to serialize and send a manifest response.
async fn send_manifest_response(
    send: &mut iroh::endpoint::SendStream,
    manifest: Option<FileManifest>,
    error: Option<String>,
) -> anyhow::Result<()> {
    let response = GatewayControlMessage::ManifestResponse { manifest, error };
    let response_bytes = serde_json::to_vec(&response)?;
    send_response(send, &response_bytes).await
}

/// Handle GetRebalanceStatus request.
async fn handle_get_rebalance_status(
    send: &mut iroh::endpoint::SendStream,
    state: &AppState,
    epoch: u64,
    pg_id: u32,
) -> anyhow::Result<()> {
    debug!(epoch = epoch, pg_id = pg_id, "GetRebalanceStatus request");

    let settled = state
        .rebalance_status
        .get(&(epoch, pg_id))
        .map(|status| status.is_settled())
        .unwrap_or(true); // If no status exists, assume settled

    let response = GatewayControlMessage::RebalanceStatusResponse { settled };
    let response_bytes = serde_json::to_vec(&response)?;
    send_response(send, &response_bytes).await
}

/// Handle UploadFile request.
///
/// This is a simplified upload path for smaller files that fit in memory.
/// For larger files, use streaming HTTP endpoint.
#[allow(unused_variables)]
async fn handle_upload_file(
    send: &mut iroh::endpoint::SendStream,
    state: &AppState,
    filename: String,
    size: u64,
    data: Vec<u8>,
    content_type: Option<String>,
) -> anyhow::Result<()> {
    info!(filename = %filename, size = size, "UploadFile request via P2P");

    if data.len() > MAX_UPLOAD_SIZE {
        let response = GatewayControlMessage::UploadResponse {
            file_hash: None,
            error: Some(format!(
                "File too large for P2P upload: {} bytes (max {})",
                data.len(),
                MAX_UPLOAD_SIZE
            )),
        };
        let response_bytes = serde_json::to_vec(&response)?;
        return send_response(send, &response_bytes).await;
    }

    // TODO: Implement the actual upload logic by calling the existing upload handler.
    // For now, return an error indicating this is not yet implemented.
    // The full implementation would:
    // 1. Compute file hash
    // 2. Split into stripes
    // 3. RS encode each stripe
    // 4. CRUSH place shards
    // 5. Push to miners via P2P
    // 6. Create and save manifest

    let response = GatewayControlMessage::UploadResponse {
        file_hash: None,
        error: Some("P2P upload not yet implemented - use HTTP endpoint".to_string()),
    };
    let response_bytes = serde_json::to_vec(&response)?;
    send_response(send, &response_bytes).await
}

/// Handle DeleteFile request.
async fn handle_delete_file(
    send: &mut iroh::endpoint::SendStream,
    state: &AppState,
    file_hash: &str,
) -> anyhow::Result<()> {
    info!(file_hash = %file_hash, "DeleteFile request via P2P");

    // Validate file hash format
    if let Err(e) = validate_file_hash(file_hash) {
        return send_ack(send, false, e).await;
    }

    // 1. Get manifest to find shards
    let manifest = load_manifest_for_delete(state, file_hash).await;

    // Collect shard hashes for Warden notification
    let shard_hashes_for_warden: Vec<String> = manifest
        .as_ref()
        .map(|m| m.shards.iter().map(|s| s.blob_hash.clone()).collect())
        .unwrap_or_default();

    // 2. Notify miners to delete shards
    if let Some(m) = &manifest {
        notify_miners_to_delete(state, m, file_hash).await;
    }

    // 3. Remove from manifest list
    {
        let mut hashes = state.manifest_hashes.lock().await;
        if let Some(pos) = hashes.iter().position(|f| f.hash == file_hash) {
            hashes.remove(pos);
        }
    }

    // 4. Tombstone the manifest in doc
    let _ = state
        .doc
        .set_bytes(
            state.author_id,
            bytes::Bytes::from(file_hash.to_string()),
            bytes::Bytes::from(common::MANIFEST_TOMBSTONE),
        )
        .await;

    // 5. Update manifest cache with tombstone
    state.manifest_cache.insert(
        file_hash.to_string(),
        (common::MANIFEST_TOMBSTONE.to_string(), common::now_secs()),
    );

    // 6. Remove from PG index
    let pg_count = state.cluster_map.read().await.pg_count;
    let pg_id = common::calculate_pg(file_hash, pg_count);
    state.pg_index.entry(pg_id).and_modify(|files| {
        files.retain(|h| h != file_hash);
    });

    // 7. Notify Warden of shard deletions (fire-and-forget)
    if let Some(warden) = &state.warden_client {
        if !shard_hashes_for_warden.is_empty() {
            let warden = warden.clone();
            tokio::spawn(async move {
                let deleted = warden.delete_shards_batch(&shard_hashes_for_warden).await;
                debug!(
                    total = shard_hashes_for_warden.len(),
                    deleted = deleted,
                    "Notified Warden of shard deletions"
                );
            });
        }
    }

    send_ack(send, true, "File deleted".to_string()).await
}

/// Load manifest for deletion (simplified - just need shards for notification).
async fn load_manifest_for_delete(state: &AppState, file_hash: &str) -> Option<FileManifest> {
    use futures::StreamExt;
    use tokio::io::AsyncReadExt;

    let query = iroh_docs::store::Query::single_latest_per_key().key_exact(file_hash.as_bytes());
    let stream = state.doc.get_many(query).await.ok()?;
    let mut stream = Box::pin(stream);

    let entry = stream.next().await?.ok()?;
    let mut reader = state.blobs_store.reader(entry.content_hash());
    let mut content = Vec::new();
    reader.read_to_end(&mut content).await.ok()?;

    let json_str = String::from_utf8_lossy(&content);
    serde_json::from_str(&json_str).ok()
}

/// Timeout for miner delete operations.
const MINER_DELETE_TIMEOUT_SECS: u64 = 5;

/// Notify miners to delete shards for a file.
async fn notify_miners_to_delete(state: &AppState, manifest: &FileManifest, file_hash: &str) {
    let cluster_map = state.cluster_map.read().await.clone();
    let miner_shards = collect_miner_shards_for_manifest(manifest, &cluster_map);

    debug!(
        miners = miner_shards.len(),
        shards = manifest.shards.len(),
        file_hash = %file_hash,
        "Notifying miners to delete shards"
    );

    for (uid, blob_hashes) in miner_shards {
        let Some(miner) = cluster_map.miners.iter().find(|m| m.uid == uid) else {
            continue;
        };
        for blob_hash in blob_hashes {
            spawn_miner_delete_task(state.endpoint.clone(), miner.endpoint.clone(), blob_hash);
        }
    }
}

/// Collect miner UID -> shard blob_hashes mapping for a manifest.
fn collect_miner_shards_for_manifest(
    manifest: &FileManifest,
    cluster_map: &common::ClusterMap,
) -> std::collections::HashMap<u32, Vec<String>> {
    let shards_per_stripe = manifest.stripe_config.k + manifest.stripe_config.m;
    let mut miner_shards: std::collections::HashMap<u32, Vec<String>> =
        std::collections::HashMap::new();

    for shard in &manifest.shards {
        let stripe_idx = shard.index / shards_per_stripe;
        let shard_pos = shard.index % shards_per_stripe;

        if let Ok(miners) = common::calculate_stripe_placement(
            &manifest.file_hash,
            stripe_idx as u64,
            shards_per_stripe,
            cluster_map,
            manifest.placement_version,
        ) && let Some(target) = miners.get(shard_pos)
        {
            miner_shards
                .entry(target.uid)
                .or_default()
                .push(shard.blob_hash.clone());
        }
    }
    miner_shards
}

/// Spawn a fire-and-forget task to send delete command to a miner.
fn spawn_miner_delete_task(
    endpoint: iroh::Endpoint,
    miner_endpoint: iroh::EndpointAddr,
    blob_hash: String,
) {
    tokio::spawn(async move {
        if let Err(e) = send_delete_to_miner(&endpoint, miner_endpoint, &blob_hash).await {
            debug!(error = %e, blob_hash = %blob_hash, "Failed to send delete to miner");
        }
    });
}

/// Send delete command to a single miner.
async fn send_delete_to_miner(
    endpoint: &iroh::Endpoint,
    miner_endpoint: iroh::EndpointAddr,
    blob_hash: &str,
) -> anyhow::Result<()> {
    let conn = tokio::time::timeout(
        std::time::Duration::from_secs(MINER_DELETE_TIMEOUT_SECS),
        endpoint.connect(miner_endpoint, b"hippius/miner-control"),
    )
    .await
    .map_err(|_| anyhow::anyhow!("Connect timeout"))??;

    let message = common::MinerControlMessage::Delete {
        hash: blob_hash.to_string(),
    };
    let msg_bytes = serde_json::to_vec(&message)?;

    let (mut send, mut recv) = conn.open_bi().await?;
    send.write_all(&msg_bytes).await?;
    send.finish()?;

    // Wait briefly for ack
    let _ = tokio::time::timeout(
        std::time::Duration::from_secs(MINER_DELETE_TIMEOUT_SECS),
        recv.read_to_end(64),
    )
    .await;

    Ok(())
}

/// Handle ReportBandwidth request.
async fn handle_report_bandwidth(
    send: &mut iroh::endpoint::SendStream,
    state: &AppState,
    reports: Vec<BandwidthReport>,
) -> anyhow::Result<()> {
    debug!(count = reports.len(), "ReportBandwidth request");

    // Update bandwidth stats on miner nodes
    let mut map = state.cluster_map.write().await;
    for report in &reports {
        if let Ok(uid) = report.miner_uid.parse::<u32>() {
            if let Some(miner) = map.miners.iter_mut().find(|m| m.uid == uid) {
                miner.bandwidth_total = miner.bandwidth_total.saturating_add(report.bytes);
            }
        }
    }
    drop(map);

    let response = GatewayControlMessage::Ack {
        success: true,
        message: Some(format!("Processed {} bandwidth reports", reports.len())),
    };
    let response_bytes = serde_json::to_vec(&response)?;
    send_response(send, &response_bytes).await
}

/// Handle ReportFailures request.
async fn handle_report_failures(
    send: &mut iroh::endpoint::SendStream,
    state: &AppState,
    reports: Vec<MinerFailureReport>,
) -> anyhow::Result<()> {
    debug!(count = reports.len(), "ReportFailures request");

    // Log failures and potentially trigger strikes
    for report in &reports {
        warn!(
            miner_uid = report.miner_uid,
            file_hash = %report.file_hash,
            shard_index = report.shard_index,
            failure_type = %report.failure_type,
            "Miner failure reported by gateway"
        );

        // Update latency tracking (mark as slow/failed)
        state.miner_latency.insert(report.miner_uid, f64::INFINITY);
    }

    let response = GatewayControlMessage::Ack {
        success: true,
        message: Some(format!("Processed {} failure reports", reports.len())),
    };
    let response_bytes = serde_json::to_vec(&response)?;
    send_response(send, &response_bytes).await
}

/// Handle RepairHint request.
async fn handle_repair_hint(
    send: &mut iroh::endpoint::SendStream,
    state: &AppState,
    file_hash: &str,
    stripe_idx: Option<u64>,
    count: Option<usize>,
) -> anyhow::Result<()> {
    debug!(file_hash = %file_hash, stripe_idx = ?stripe_idx, count = ?count, "RepairHint request");

    // Validate file hash format
    if let Err(e) = validate_file_hash(file_hash) {
        return send_ack(send, false, e).await;
    }

    if !state.repair_hint_enabled {
        return send_ack(send, false, "Repair hints disabled".to_string()).await;
    }

    let start = stripe_idx.unwrap_or(0) as usize;
    let count = count.unwrap_or(state.repair_hint_default_count);
    let allow_scan = false;
    let dedupe_key = format!("{}:{}", file_hash, start);
    let now = common::now_secs();

    // Deduplicate recent hints
    if let Some((last_seen, _, _)) = state.repair_hint_dedupe.get(&dedupe_key) {
        let is_recent = now.saturating_sub(last_seen) < state.repair_hint_dedupe_ttl_secs;
        if is_recent {
            return send_ack(send, true, "Repair hint deduplicated".to_string()).await;
        }
    }

    state
        .repair_hint_dedupe
        .insert(dedupe_key, (now, allow_scan, count));

    // Try to queue the hint
    let mut queue = state.repair_hint_queue.lock().await;
    let queued = queue.len() < state.repair_hint_queue_max;
    if queued {
        queue.push_back((file_hash.to_string(), start, count, allow_scan));
    }
    drop(queue);

    let message = if queued {
        "Repair hint queued"
    } else {
        "Repair hint queue full"
    };
    send_ack(send, queued, message.to_string()).await
}

/// Helper to send an Ack response.
async fn send_ack(
    send: &mut iroh::endpoint::SendStream,
    success: bool,
    message: String,
) -> anyhow::Result<()> {
    let response = GatewayControlMessage::Ack {
        success,
        message: Some(message),
    };
    let response_bytes = serde_json::to_vec(&response)?;
    send_response(send, &response_bytes).await
}

/// Send a warming up error response for general operations.
async fn send_warming_up_error(
    send: &mut iroh::endpoint::SendStream,
    ready_state: ValidatorReadyState,
    operation: &str,
) -> anyhow::Result<()> {
    let message = format!(
        "Validator is {}: {} unavailable. Retry in {} seconds.",
        ready_state.status_str(),
        operation,
        WARMUP_RETRY_SECS
    );
    debug!(operation = operation, state = ?ready_state, "Rejected request during warmup");
    send_ack(send, false, message).await
}

/// Send a warming up error response for upload operations.
async fn send_warming_up_upload_error(
    send: &mut iroh::endpoint::SendStream,
    ready_state: ValidatorReadyState,
) -> anyhow::Result<()> {
    let error_msg = format!(
        "Validator is {}: uploads unavailable. Retry in {} seconds.",
        ready_state.status_str(),
        WARMUP_RETRY_SECS
    );
    debug!(state = ?ready_state, "Rejected upload during warmup");
    let response = GatewayControlMessage::UploadResponse {
        file_hash: None,
        error: Some(error_msg),
    };
    let response_bytes = serde_json::to_vec(&response)?;
    send_response(send, &response_bytes).await
}

//! HTTP request handlers for the gateway.

use crate::config::{
    LATENCY_DEFAULT, LATENCY_EMA_NEW_WEIGHT, LATENCY_EMA_OLD_WEIGHT, LATENCY_FAILURE_DECAY,
    LATENCY_FAILURE_PENALTY, MAX_FAILURE_REPORTS, MAX_FETCH_RESPONSE_SIZE,
    MAX_MINER_BLACKLIST_ENTRIES, MAX_REPAIR_HINT_ENTRIES, MINER_BLACKLIST_DURATION_SECS,
    RepairHintRequest, UPLOAD_MAX_RETRIES, UPLOAD_RETRY_BASE_DELAY_MS, UPLOAD_TIMEOUT_SECS,
};
use crate::helpers::{
    ByteRange, bad_gateway_error, detect_content_type, get_pooled_connection, internal_error,
    is_pg_settled, parse_range_header, sanitize_filename,
};
use crate::state::AppState;
use axum::Json;
use axum::body::Body;
use axum::extract::{Multipart, Path, State};
use axum::http::{HeaderMap, StatusCode};
use axum::response::IntoResponse;
use common::{FileManifest, MinerFailureReport, decode_stripe, now_secs};
use std::collections::HashMap;
use std::sync::Arc;
use tracing::{debug, error, info, warn};

// ============================================================================
// Manifest Fetching
// ============================================================================

/// Result of fetching and parsing a file manifest
pub struct ManifestResult {
    pub manifest: Arc<FileManifest>,
    /// Whether placement_version was explicitly present in the manifest JSON
    pub placement_version_present: bool,
    /// Pre-built shard index for O(1) lookups: global_index -> blob_hash
    pub shard_index: HashMap<usize, String>,
}

/// Fetch and parse a file manifest from doc replica, P2P, or validator HTTP
async fn fetch_manifest(
    state: &Arc<AppState>,
    hash: &str,
) -> Result<ManifestResult, (StatusCode, String)> {
    use tokio::io::AsyncReadExt;

    // 1. First try doc replica if configured (fastest - local reads)
    let mut manifest_bytes_opt: Option<Vec<u8>> = None;
    if let (Some(doc), Some(blobs)) = (state.doc_replica.as_ref(), state.doc_replica_blobs.as_ref())
    {
        let query = iroh_docs::store::Query::single_latest_per_key().key_exact(hash.as_bytes());
        if let Ok(Some(entry)) = doc.get_one(query).await {
            let mut reader = blobs.reader(entry.content_hash());
            let mut content = Vec::new();
            // Timeout blob read to prevent hanging (5 seconds should be plenty for manifest)
            let read_result = tokio::time::timeout(
                std::time::Duration::from_secs(5),
                reader.read_to_end(&mut content),
            )
            .await;
            if matches!(read_result, Ok(Ok(_))) {
                manifest_bytes_opt = Some(content);
            }
        }
    }

    // 2. If not in doc replica, try P2P if enabled
    if manifest_bytes_opt.is_none() && state.use_p2p {
        if let Some(ref p2p_client) = state.validator_p2p_client {
            match p2p_client.get_manifest(hash).await {
                Ok(Some(manifest)) => {
                    debug!(hash = %hash, source = "p2p", "Fetched manifest via P2P");
                    // Serialize to bytes for consistent parsing flow
                    if let Ok(bytes) = serde_json::to_vec(&manifest) {
                        manifest_bytes_opt = Some(bytes);
                    }
                }
                Ok(None) => {
                    debug!(hash = %hash, "Manifest not found via P2P");
                    // Fall through to HTTP fallback
                }
                Err(e) => {
                    if state.http_fallback {
                        debug!(error = %e, "P2P manifest fetch failed, falling back to HTTP");
                    } else {
                        return Err((StatusCode::NOT_FOUND, "File not found".to_string()));
                    }
                }
            }
        }
    }

    // 3. HTTP fallback (or primary if P2P disabled)
    let manifest_url = format!("{}/manifest/{}", state.validator_url, hash);
    let manifest_res_result = if manifest_bytes_opt.is_some() {
        None // Skip HTTP; we already have bytes from doc replica or P2P
    } else {
        Some(state.http_client.get(&manifest_url).send().await)
    };

    // Get manifest bytes from doc replica, P2P, or HTTP
    let manifest_bytes: bytes::Bytes = if let Some(v) = manifest_bytes_opt {
        bytes::Bytes::from(v)
    } else {
        let manifest_res = match manifest_res_result.unwrap() {
            Ok(res) => res,
            Err(e) => {
                return Err(bad_gateway_error("fetch_manifest", e));
            }
        };
        if !manifest_res.status().is_success() {
            let status = manifest_res.status();
            let status_u16 = status.as_u16();
            // Log the actual error body for debugging
            let body = manifest_res
                .text()
                .await
                .unwrap_or_else(|_| "Manifest fetch failed".to_string());
            debug!(status = %status, body = %body, "Manifest fetch non-success");
            // Return appropriate status but generic message for client errors
            let axum_status = StatusCode::from_u16(status_u16).unwrap_or(StatusCode::BAD_GATEWAY);
            if axum_status == StatusCode::NOT_FOUND {
                return Err((axum_status, "File not found".to_string()));
            }
            return Err((axum_status, "Failed to retrieve file metadata".to_string()));
        }
        match manifest_res.bytes().await {
            Ok(b) => b,
            Err(e) => {
                return Err(bad_gateway_error("read_manifest_body", e));
            }
        }
    };

    // Parse manifest JSON
    let manifest_value: serde_json::Value = match serde_json::from_slice(&manifest_bytes) {
        Ok(v) => v,
        Err(e) => {
            return Err(internal_error("parse_manifest_json", e));
        }
    };

    let placement_version_present = manifest_value.get("placement_version").is_some();

    let manifest: FileManifest = match serde_json::from_value(manifest_value) {
        Ok(m) => m,
        Err(e) => {
            return Err(internal_error("deserialize_manifest", e));
        }
    };

    debug!(size = manifest.size, "Manifest found");

    // Build shard index for O(1) lookup
    let shard_index: HashMap<usize, String> = manifest
        .shards
        .iter()
        .map(|s| (s.index, s.blob_hash.clone()))
        .collect();

    Ok(ManifestResult {
        manifest: Arc::new(manifest),
        placement_version_present,
        shard_index,
    })
}

// ============================================================================
// Shard Fetching Helpers
// ============================================================================
// NOTE: These helpers abstract the shard fetching logic for cleaner code.
// The current download_file implementation uses inline code within the async
// stream closure. These can be integrated when the stream logic is refactored.

/// Context for fetching a shard from candidate miners
#[allow(dead_code)]
struct ShardFetchContext {
    pub blob_hash: String,
    pub local_idx: usize,
    pub miner_uid_primary: u32,
    pub connect_timeout: std::time::Duration,
    pub read_timeout: std::time::Duration,
}

/// Result of attempting to fetch a shard
#[allow(dead_code)]
pub enum ShardFetchResult {
    /// Successfully fetched shard data
    Success(Vec<u8>, u32), // (data, miner_uid that served it)
    /// All candidates failed
    Failed,
}

/// Try to fetch a shard from a list of candidate miners (current epoch + lookback epochs)
///
/// Returns the shard data if successful, or None if all candidates failed.
/// Updates latency tracking and miner blacklist as side effects.
#[allow(dead_code)]
async fn fetch_shard_from_candidates(
    ctx: &ShardFetchContext,
    candidates: Vec<(u64, common::MinerNode)>,
    state: &Arc<AppState>,
) -> ShardFetchResult {
    for (epoch_used, miner_try) in candidates {
        let miner_uid_try = miner_try.uid;
        let endpoint_addr_try = miner_try.endpoint.clone();

        // Check blacklist: skip miners that recently served corrupted data for this blob
        let blacklist_key = (miner_uid_try, ctx.blob_hash.clone());
        if let Some(blacklist_ts) = state.miner_blacklist.get(&blacklist_key) {
            let blacklist_now = now_secs();
            // Skip if blacklist entry is still valid
            if blacklist_now == 0
                || *blacklist_ts > blacklist_now
                || blacklist_now.saturating_sub(*blacklist_ts) < MINER_BLACKLIST_DURATION_SECS
            {
                debug!(
                    miner_uid = miner_uid_try,
                    blob = %&ctx.blob_hash[..std::cmp::min(16, ctx.blob_hash.len())],
                    "Skipping blacklisted miner for this blob"
                );
                continue;
            } else {
                // Blacklist expired, remove entry
                drop(blacklist_ts);
                state.miner_blacklist.remove(&blacklist_key);
            }
        }

        // Use connection pool for P2P connections
        let connection = match get_pooled_connection(
            &state.connection_pool,
            miner_uid_try,
            &state.endpoint,
            &endpoint_addr_try,
            ctx.connect_timeout,
        )
        .await
        {
            Some(conn) => conn,
            None => continue,
        };

        let (mut send, mut recv) = match connection.open_bi().await {
            Ok(s) => s,
            Err(_) => continue,
        };

        let request = common::MinerControlMessage::FetchBlob {
            hash: ctx.blob_hash.clone(),
        };
        let request_bytes = match serde_json::to_vec(&request) {
            Ok(b) => b,
            Err(_) => continue,
        };
        if send.write_all(&request_bytes).await.is_err() {
            continue;
        }
        let _ = send.finish();

        let response =
            match tokio::time::timeout(ctx.read_timeout, recv.read_to_end(MAX_FETCH_RESPONSE_SIZE))
                .await
            {
                Ok(Ok(bytes)) => bytes,
                _ => continue,
            };

        // Parse response: DATA:<bytes> or ERROR:<message>
        if response.starts_with(b"DATA:") {
            let data = response[5..].to_vec();

            // Verify integrity
            let computed_hash = blake3::hash(&data);
            let hash_matches = computed_hash.to_hex().as_str() == ctx.blob_hash;
            if !hash_matches {
                warn!(
                    miner_uid = miner_uid_try,
                    shard = ctx.local_idx,
                    epoch_try = epoch_used,
                    "Integrity fail: miner served corrupted shard"
                );
                // Blacklist this miner for this specific blob (Byzantine protection)
                // Only insert if under max capacity to prevent memory exhaustion
                if state.miner_blacklist.len() < MAX_MINER_BLACKLIST_ENTRIES {
                    state
                        .miner_blacklist
                        .insert((miner_uid_try, ctx.blob_hash.clone()), now_secs());
                }
                continue;
            }

            // Success: cache and return
            state
                .blob_cache
                .insert(ctx.blob_hash.clone(), Arc::new(data.clone()));
            return ShardFetchResult::Success(data, miner_uid_try);
        } else if response.starts_with(b"ERROR:") {
            let err_msg = String::from_utf8_lossy(&response[6..]);
            error!(
                miner_uid = miner_uid_try,
                error = %err_msg,
                shard = ctx.local_idx,
                blob = %&ctx.blob_hash[..std::cmp::min(16, ctx.blob_hash.len())],
                epoch_try = epoch_used,
                "FetchBlob error from miner"
            );
            continue;
        }
        // Unknown response format, try next candidate
    }

    // All candidates failed
    ShardFetchResult::Failed
}

/// Build list of candidate miners for a shard (current epoch + lookback epochs)
#[allow(dead_code, clippy::too_many_arguments)]
async fn build_shard_candidates(
    miner: common::MinerNode,
    current_epoch: u64,
    epoch_lookback: u64,
    file_hash: &str,
    stripe_idx: u64,
    local_idx: usize,
    shards_per_stripe: usize,
    placement_version: u8,
    state: &Arc<AppState>,
) -> Vec<(u64, common::MinerNode)> {
    let mut candidates: Vec<(u64, common::MinerNode)> = Vec::new();
    candidates.push((current_epoch, miner));

    if epoch_lookback == 0 {
        return candidates;
    }

    let min_epoch = current_epoch.saturating_sub(epoch_lookback);

    // First check local history cache (fast, no HTTP)
    {
        let history = state.cluster_map_history.lock().await;
        for map in history
            .iter()
            .filter(|m| m.epoch >= min_epoch && m.epoch < current_epoch)
        {
            if let Ok(miners_e) = common::calculate_stripe_placement(
                file_hash,
                stripe_idx,
                shards_per_stripe,
                map,
                placement_version,
            ) && let Some(m) = miners_e.get(local_idx).cloned()
                && !candidates.iter().any(|(_, x)| x.uid == m.uid)
            {
                candidates.push((map.epoch, m));
            }
        }
    }

    // Fall back to HTTP for epochs not in local history
    for e in (min_epoch..current_epoch).rev() {
        // Skip if we already have a candidate from this epoch
        if candidates.iter().any(|(epoch, _)| *epoch == e) {
            continue;
        }

        // Fetch cluster map for this epoch
        let url = format!("{}/map/epoch/{}", state.validator_url, e);
        let Ok(res) = state.http_client.get(&url).send().await else {
            continue;
        };
        if !res.status().is_success() {
            continue;
        }

        let Ok(map) = res.json::<common::ClusterMap>().await else {
            continue;
        };
        let Ok(miners_e) = common::calculate_stripe_placement(
            file_hash,
            stripe_idx,
            shards_per_stripe,
            &map,
            placement_version,
        ) else {
            continue;
        };

        // Add miner if not already a candidate
        if let Some(m) = miners_e.get(local_idx).cloned()
            && !candidates.iter().any(|(_, x)| x.uid == m.uid)
        {
            candidates.push((e, m));
        }
    }

    candidates
}

// ============================================================================
// Download Metric Guard
// ============================================================================

/// Guard to ensure active_downloads metric is decremented even on panics within the stream.
/// NOTE: For streaming responses, this guard must be held within the stream closure itself,
/// not the outer function, because the function returns before the stream is consumed.
struct DownloadMetricGuard(Arc<AppState>);
impl Drop for DownloadMetricGuard {
    fn drop(&mut self) {
        self.0.metrics.active_downloads.dec();
    }
}

/// Download a file by hash
pub async fn download_file(
    State(state): State<Arc<AppState>>,
    Path(hash): Path<String>,
    headers: HeaderMap,
) -> impl IntoResponse {
    let request_start = std::time::Instant::now();

    // Validate hash format before any processing
    if let Err(e) = common::validate_file_hash(&hash) {
        return (StatusCode::BAD_REQUEST, e).into_response();
    }

    state
        .metrics
        .http_requests
        .get_or_create(&[
            ("method".to_string(), "download_file".to_string()),
            ("status".to_string(), "started".to_string()),
        ])
        .inc();
    state.metrics.active_downloads.inc();

    info!(hash = %hash, "Download started");

    // Fetch and parse manifest
    let ManifestResult {
        manifest,
        placement_version_present,
        shard_index,
    } = match fetch_manifest(&state, &hash).await {
        Ok(result) => result,
        Err((status, msg)) => {
            let duration_ms = request_start.elapsed().as_millis();
            error!(
                hash = %hash,
                status = %status,
                error = %msg,
                duration_ms = duration_ms,
                "Download failed: manifest not found"
            );
            state.metrics.active_downloads.dec();
            return (status, msg).into_response();
        }
    };

    info!(
        hash = %hash,
        size_bytes = manifest.size,
        filename = %manifest.filename.as_deref().unwrap_or("unknown"),
        "Download manifest fetched"
    );

    // Snapshot current cluster map for the whole request (avoid mid-stream epoch drift)
    let cluster_map_snapshot = state.cluster_map.lock().await.clone();
    debug!(
        epoch = cluster_map_snapshot.epoch,
        shards = manifest.shards.len(),
        "Download map snapshot"
    );

    // Placement version handling:
    // - If manifest explicitly carries placement_version, use it.
    // - If manifest is legacy (no placement_version field), probe v2 then v1 for backward compatibility.
    let placement_versions_to_try: Vec<u8> = if placement_version_present {
        vec![manifest.placement_version]
    } else {
        vec![2, 1]
    };

    // Calculate PG for this file (used for rebalance status check)
    let pg_id = common::calculate_pg(&manifest.file_hash, cluster_map_snapshot.pg_count);
    let current_epoch = cluster_map_snapshot.epoch;

    // Check if PG is settled at current epoch (rebalance complete)
    // If settled, we can use current epoch CRUSH directly (no lookback needed)
    // If not settled, we need epoch lookback during rebalance window
    let pg_settled = is_pg_settled(
        &state.validator_url,
        &state.http_client,
        &state.rebalance_status_cache,
        current_epoch,
        pg_id,
    )
    .await;

    // Epoch lookback for transitional reads while rebalance converges
    // Only use lookback if PG is still rebalancing
    let epoch_lookback: u64 = if pg_settled {
        0 // PG is settled, no lookback needed - use current epoch only
    } else {
        std::env::var("EPOCH_LOOKBACK")
            .ok()
            .and_then(|s| s.parse::<u64>().ok())
            .unwrap_or(3)
    };

    debug!(
        pg_id = pg_id,
        epoch_lookback = epoch_lookback,
        pg_settled = pg_settled,
        placement_versions = ?placement_versions_to_try,
        "CRUSH placement"
    );

    // 2. Parse Range Header
    let file_size = manifest.size;
    let range = parse_range_header(&headers, file_size);
    let ByteRange {
        start,
        end,
        is_range_request,
    } = range;

    if start > end {
        state.metrics.active_downloads.dec();
        return (StatusCode::RANGE_NOT_SATISFIABLE, "Invalid range").into_response();
    }

    let content_length = end - start + 1;
    let stripe_size = manifest.stripe_config.size;
    let start_stripe = start / stripe_size;
    let end_stripe = end / stripe_size;

    // 3. Stream Response
    let manifest_content_type = manifest.content_type.clone();
    let manifest_filename = manifest.filename.clone();
    let placement_versions_to_try_stream = placement_versions_to_try.clone();
    // Move state clone into stream for guard - stream outlives the function
    let state_for_stream = state.clone();
    // Capture for logging in stream
    let stream_hash = hash.clone();
    let stream_file_size = manifest.size;
    let stream_content_length = content_length;
    let stream_start_time = request_start;
    let stream = async_stream::stream! {
        use rand::seq::SliceRandom;

        // Guard ensures metric is decremented when stream completes (success, error, or panic)
        let _stream_metric_guard = DownloadMetricGuard(state_for_stream.clone());
        let mut bytes_streamed: u64 = 0;
        let mut stream_failed = false;

        for stripe_idx in start_stripe..=end_stripe {
            let k = manifest.stripe_config.k;
            let m = manifest.stripe_config.m;
            let shards_per_stripe = k + m;
            let base_shard_index = (stripe_idx as usize) * shards_per_stripe;

            // Try placement versions in order (helps with legacy manifests created before placement_version existed).
            let mut stripe_recovered = false;
            for placement_version in &placement_versions_to_try_stream {
            let mut shards_data: Vec<Option<Vec<u8>>> = vec![None; k + m];
            let mut downloaded_count = 0;

                let stripe_miners = match common::calculate_stripe_placement(
                &manifest.file_hash,
                stripe_idx,
                shards_per_stripe,
                    &cluster_map_snapshot,
                    *placement_version,
            ) {
                    Ok(m) => m,
                Err(e) => {
                        error!(placement_version = placement_version, error = %e, "CRUSH stripe placement failed");
                    continue;
                }
            };

            // Build list of (shard_index, miner, blob_hash) tuples using O(1) index lookup
            // Pure CRUSH: miner location is always calculated from CRUSH, never from manifest
            let mut shard_targets: Vec<(usize, common::MinerNode, String)> = Vec::new();
            #[allow(clippy::needless_range_loop)] // local_idx used for multiple purposes beyond indexing
            for local_idx in 0..shards_per_stripe {
                let global_idx = base_shard_index + local_idx;

                // O(1) lookup instead of O(n) linear search
                if let Some(blob_hash) = shard_index.get(&global_idx) {
                    // Pure CRUSH placement - no manifest-based fallback
                    let miner = stripe_miners.get(local_idx).cloned();

                    if let Some(miner) = miner {
                        shard_targets.push((local_idx, miner.clone(), blob_hash.clone()));

                        // Check cache first (LRU cache access)
                        if let Some(data) = state.blob_cache.get(blob_hash) {
                            // quick_cache returns Arc<Vec<u8>> directly, deref to get Vec
                            shards_data[local_idx] = Some((*data).clone());
                            downloaded_count += 1;
                            shard_targets.pop();
                            state.metrics.cache_hits.inc();
                        } else {
                            state.metrics.cache_misses.inc();
                        }
                    }
                }
            }

            // Sort by latency (prefer miners with lower known latency) - lock-free DashMap access
            let get_latency = |uid: u32| -> f64 {
                state.miner_latency.get(&uid).map(|v| *v).unwrap_or(LATENCY_DEFAULT)
            };

            let all_unknown = shard_targets.iter().all(|(_, m, _)| !state.miner_latency.contains_key(&m.uid));
            if all_unknown {
                // No latency data - shuffle randomly for fair distribution
                shard_targets.shuffle(&mut rand::rng());
            } else {
                // Sort by known latency (lower is better)
                shard_targets.sort_by(|(_, a, _), (_, b, _)| {
                    get_latency(a.uid).total_cmp(&get_latency(b.uid))
                });
            }

                // Backpressure: bounded in-flight shard fetches per-request + globally across all downloads.
                let request_parallelism = std::cmp::max(1, state.download_request_parallelism);
                let global_sem = state.download_global_semaphore.clone();
                let permit_timeout_ms = state.download_permit_timeout_ms;
                let connect_timeout = std::time::Duration::from_secs(state.fetch_connect_timeout_secs);
                let read_timeout = std::time::Duration::from_secs(state.fetch_read_timeout_secs);

                let (result_tx, mut result_rx) = tokio::sync::mpsc::channel::<
                    (usize, Option<Vec<u8>>, u32, f64),
                >(request_parallelism * 2);

                use std::sync::atomic::{AtomicUsize, Ordering};
                let next_target_idx = AtomicUsize::new(0usize);
                let in_flight = AtomicUsize::new(0usize);

                let spawn_next = |state: Arc<AppState>,
                                  manifest: Arc<common::FileManifest>,
                                  stripe_idx: u64,
                                  shards_per_stripe_for_pg: usize,
                                  epoch_lookback_local: u64,
                                  current_epoch: u64,
                                  placement_version: u8,
                                  tx: tokio::sync::mpsc::Sender<(usize, Option<Vec<u8>>, u32, f64)>|
                 -> Option<()> {
                // Atomically claim the next shard index to avoid race conditions
                let idx = next_target_idx.fetch_add(1, Ordering::AcqRel);
                if idx >= shard_targets.len() {
                    return None;
                }
                let (local_idx, miner, blob_hash) = shard_targets[idx].clone();
                in_flight.fetch_add(1, Ordering::Release);

                let endpoint = state.endpoint.clone();
                let miner_uid_primary = miner.uid;
                let miner_latency = state.miner_latency.clone();
                let miner_failures = state.miner_failures.clone();
                let file_hash_log = manifest.file_hash.clone();
                let blob_cache = state.blob_cache.clone();
                let validator_url = state.validator_url.clone();
                let file_hash_for_pg = manifest.file_hash.clone();
                let blob_hash_for_log = blob_hash.clone();
                let global_sem = global_sem.clone();
                let http_client = state.http_client.clone();
                let cluster_map_history = state.cluster_map_history.clone();
                let connection_pool = state.connection_pool.clone();
                let miner_blacklist = state.miner_blacklist.clone();

                tokio::spawn(async move {
                    use std::time::Instant;
                    let start_time = Instant::now();

                    // Acquire global permit (bounded). Optionally timeout to avoid unbounded queuing under load.
                    // IMPORTANT: if permit wait is too short, reads can fail even though shards exist.
                    let _permit = if permit_timeout_ms == 0 {
                        match global_sem.acquire_owned().await {
                            Ok(p) => p,
                            Err(_) => {
                                let elapsed = start_time.elapsed().as_secs_f64() * 1000.0;
                                let _ = tx.send((local_idx, None, miner_uid_primary, elapsed)).await;
                                return;
                            }
                        }
                    } else {
                        let permit_timeout = std::time::Duration::from_millis(permit_timeout_ms);
                        match tokio::time::timeout(permit_timeout, global_sem.acquire_owned()).await {
                            Ok(Ok(p)) => p,
                            _ => {
                                let elapsed = start_time.elapsed().as_secs_f64() * 1000.0;
                                let _ = tx.send((local_idx, None, miner_uid_primary, elapsed)).await;
                                return;
                            }
                        }
                    };

                    // Candidate miners: placement_epoch FIRST (where file was actually stored),
                    // then current epoch and lookback for rebalancing fallback.
                    //
                    // CRITICAL: The manifest.placement_epoch tells us which cluster map epoch
                    // was used when the file was uploaded. We MUST try that epoch first,
                    // because that's where the shards were actually placed.
                    let mut candidates: Vec<(u64, common::MinerNode)> = Vec::new();
                    let placement_epoch = manifest.placement_epoch;

                    // 1. Try placement_epoch first (where file was actually stored)
                    if placement_epoch != current_epoch {
                        // First check local history cache for placement_epoch (fast, no HTTP)
                        let mut found_in_cache = false;
                        {
                            let history = cluster_map_history.lock().await;
                            if let Some(map) = history.iter().find(|m| m.epoch == placement_epoch)
                                && let Ok(miners_e) = common::calculate_stripe_placement(
                                    &file_hash_for_pg,
                                    stripe_idx,
                                    shards_per_stripe_for_pg,
                                    map,
                                    placement_version,
                                )
                                && let Some(m) = miners_e.get(local_idx).cloned()
                            {
                                candidates.push((placement_epoch, m));
                                found_in_cache = true;
                            }
                        }

                        // Fall back to HTTP if not in local cache
                        if !found_in_cache {
                            let url = format!("{}/map/epoch/{}", validator_url, placement_epoch);
                            if let Ok(res) = http_client.get(&url).send().await
                                && res.status().is_success()
                                && let Ok(map) = res.json::<common::ClusterMap>().await
                                && let Ok(miners_e) = common::calculate_stripe_placement(
                                    &file_hash_for_pg,
                                    stripe_idx,
                                    shards_per_stripe_for_pg,
                                    &map,
                                    placement_version,
                                )
                                && let Some(m) = miners_e.get(local_idx).cloned()
                            {
                                candidates.push((placement_epoch, m));
                            }
                        }
                    }

                    // 2. Add current epoch as fallback (for rebalanced files or same-epoch uploads)
                    if !candidates.iter().any(|(_, x)| x.uid == miner.uid) {
                        candidates.push((current_epoch, miner.clone()));
                    }

                    // 3. Add lookback epochs for transitional reads
                    if epoch_lookback_local > 0 {
                        let min_epoch = current_epoch.saturating_sub(epoch_lookback_local);

                        // First check local history cache (fast, no HTTP)
                        {
                            let history = cluster_map_history.lock().await;
                            for map in history.iter().filter(|m| m.epoch >= min_epoch && m.epoch < current_epoch) {
                                if let Ok(miners_e) = common::calculate_stripe_placement(
                                    &file_hash_for_pg,
                                    stripe_idx,
                                    shards_per_stripe_for_pg,
                                    map,
                                    placement_version,
                                )
                                    && let Some(m) = miners_e.get(local_idx).cloned()
                                    && !candidates.iter().any(|(_, x)| x.uid == m.uid)
                                {
                                    candidates.push((map.epoch, m));
                                }
                            }
                        }

                        // Fall back to HTTP for epochs not in local history
                        for e in (min_epoch..current_epoch).rev() {
                            // Skip if we already have a candidate from this epoch
                            let already_have_epoch = candidates.iter().any(|(epoch, _)| *epoch == e);
                            if already_have_epoch {
                                continue;
                            }

                            // Fetch cluster map for this epoch
                            let url = format!("{}/map/epoch/{}", validator_url, e);
                            let Ok(res) = http_client.get(&url).send().await else { continue };
                            if !res.status().is_success() { continue }

                            let Ok(map) = res.json::<common::ClusterMap>().await else { continue };
                            let Ok(miners_e) = common::calculate_stripe_placement(
                                &file_hash_for_pg,
                                stripe_idx,
                                shards_per_stripe_for_pg,
                                &map,
                                placement_version,
                            ) else { continue };

                            // Add miner if not already a candidate
                            if let Some(m) = miners_e.get(local_idx).cloned() {
                                let is_new_candidate = !candidates.iter().any(|(_, x)| x.uid == m.uid);
                                if is_new_candidate {
                                    candidates.push((e, m));
                                }
                            }
                        }
                    }

                    // Try candidates sequentially until DATA is received.
                    for (epoch_used, miner_try) in candidates {
                        let miner_uid_try = miner_try.uid;
                        let endpoint_addr_try = miner_try.endpoint.clone();

                        // Check blacklist: skip miners that recently served corrupted data for this blob
                        let blacklist_key = (miner_uid_try, blob_hash.clone());
                        if let Some(blacklist_ts) = miner_blacklist.get(&blacklist_key) {
                            let blacklist_now = now_secs();
                            // Skip if blacklist entry is still valid (within MINER_BLACKLIST_DURATION_SECS)
                            // Also handle clock skew: if blacklist_now is 0 or < blacklist_ts, skip anyway
                            if blacklist_now == 0
                                || *blacklist_ts > blacklist_now
                                || blacklist_now.saturating_sub(*blacklist_ts)
                                    < MINER_BLACKLIST_DURATION_SECS
                            {
                                debug!(
                                    miner_uid = miner_uid_try,
                                    blob = %&blob_hash[..std::cmp::min(16, blob_hash.len())],
                                    "Skipping blacklisted miner for this blob"
                                );
                                continue;
                            } else {
                                // Blacklist expired, remove entry
                                drop(blacklist_ts);
                                miner_blacklist.remove(&blacklist_key);
                            }
                        }

                        // Use connection pool for P2P connections
                        let connection = match get_pooled_connection(
                            &connection_pool,
                            miner_uid_try,
                            &endpoint,
                            &endpoint_addr_try,
                            connect_timeout,
                        )
                        .await
                        {
                            Some(conn) => conn,
                            None => continue,
                        };

                        let (mut send, mut recv) = match connection.open_bi().await {
                            Ok(s) => s,
                            Err(_) => continue,
                        };

                        let request = common::MinerControlMessage::FetchBlob { hash: blob_hash.clone() };
                        // use tokio::io::{AsyncReadExt, AsyncWriteExt};
                        let request_bytes = match serde_json::to_vec(&request) {
                            Ok(b) => b,
                            Err(_) => continue,
                        };
                        if send.write_all(&request_bytes).await.is_err() {
                            continue;
                        }
                        let _ = send.finish();

                        let response = match tokio::time::timeout(read_timeout, recv.read_to_end(MAX_FETCH_RESPONSE_SIZE)).await {
                            Ok(Ok(bytes)) => bytes,
                            _ => continue,
                        };

                        // Parse response: DATA:<bytes> or ERROR:<message>
                        if response.starts_with(b"DATA:") {
                            let data = response[5..].to_vec();

                            // Verify integrity
                            let computed_hash = blake3::hash(&data);
                            let hash_matches = computed_hash.to_hex().as_str() == blob_hash;
                            if !hash_matches {
                                warn!(
                                    miner_uid = miner_uid_try,
                                    shard = local_idx,
                                    epoch_try = epoch_used,
                                    "Integrity fail: miner served corrupted shard"
                                );
                                // Blacklist this miner for this specific blob (Byzantine protection)
                                // Only insert if under max capacity to prevent memory exhaustion
                                if miner_blacklist.len() < MAX_MINER_BLACKLIST_ENTRIES {
                                    let blacklist_key = (miner_uid_try, blob_hash.clone());
                                    miner_blacklist.insert(blacklist_key, now_secs());
                                }
                                continue;
                            }

                            // Success: cache and return
                            blob_cache.insert(blob_hash.clone(), Arc::new(data.clone()));
                            let elapsed = start_time.elapsed().as_secs_f64() * 1000.0;
                            let _ = tx.send((local_idx, Some(data), miner_uid_try, elapsed)).await;
                            return;
                        } else if response.starts_with(b"ERROR:") {
                            let err_msg = String::from_utf8_lossy(&response[6..]);
                            error!(
                                miner_uid = miner_uid_try,
                                error = %err_msg,
                                file_hash = %file_hash_log,
                                stripe = stripe_idx,
                                shard = local_idx,
                                blob = %&blob_hash_for_log[..std::cmp::min(16, blob_hash_for_log.len())],
                                epoch_try = epoch_used,
                                "FetchBlob error from miner"
                            );
                            continue;
                        }
                        // Unknown response format, try next candidate
                    }

                    // Record failure if all candidates failed (lock-free DashMap access)
                    miner_latency.entry(miner_uid_primary).and_modify(|v| {
                        *v = (*v * LATENCY_FAILURE_DECAY) + LATENCY_FAILURE_PENALTY;
                    }).or_insert(LATENCY_DEFAULT);
                    let mut failures = miner_failures.lock().await;
                    // Bounded queue - drop oldest failures when full
                    if failures.len() >= MAX_FAILURE_REPORTS {
                        failures.pop_front();
                    }
                    failures.push_back(MinerFailureReport {
                        miner_uid: miner_uid_primary,
                        file_hash: file_hash_log.clone(),
                        shard_index: local_idx,
                        failure_type: "fetch_failed_all_epochs".to_string(),
                        timestamp: now_secs(),
                    });

                    let elapsed = start_time.elapsed().as_secs_f64() * 1000.0;
                    let _ = tx.send((local_idx, None, miner_uid_primary, elapsed)).await;
                });

                Some(())
            };

            // Kick off initial wave
            while in_flight.load(Ordering::Acquire) < request_parallelism
                && next_target_idx.load(Ordering::Acquire) < shard_targets.len()
            {
                let _ = spawn_next(
                    state.clone(),
                    manifest.clone(),
                    stripe_idx,
                    shards_per_stripe,
                    epoch_lookback,
                    cluster_map_snapshot.epoch,
                    *placement_version,
                    result_tx.clone(),
                );
            }

            // Collect outcomes until we have k shards or we've exhausted candidates.
            while downloaded_count < k {
                if in_flight.load(Ordering::Acquire) == 0
                    && next_target_idx.load(Ordering::Acquire) >= shard_targets.len()
                {
                    break;
                }
                let Some((local_idx, maybe_data, miner_uid, elapsed_ms)) = result_rx.recv().await else {
                    break;
                };
                let _ = in_flight.fetch_update(Ordering::AcqRel, Ordering::Acquire, |v| {
                    Some(v.saturating_sub(1))
                });

                if let Some(data) = maybe_data {
                 let len = data.len() as u64;
                 if local_idx < shards_data.len() {
                     shards_data[local_idx] = Some(data);
                 } else {
                     warn!(local_idx, shards_data_len = shards_data.len(), "Shard index out of bounds");
                     continue;
                 }
                 downloaded_count += 1;

                 debug!(shard = local_idx, miner_uid = miner_uid, elapsed_ms = format!("{:.2}", elapsed_ms), "Shard streamed from miner");

                 // Update latency tracking (lock-free DashMap access, exponential moving average)
                 state.miner_latency.entry(miner_uid).and_modify(|v| {
                     *v = *v * LATENCY_EMA_OLD_WEIGHT + elapsed_ms * LATENCY_EMA_NEW_WEIGHT;
                 }).or_insert(elapsed_ms);

                 // Track Bandwidth (lock-free DashMap access)
                 // NOTE: This intentionally counts total bytes transferred, not unique bytes.
                 // The same shard may be fetched multiple times during retries or epoch fallback,
                 // and we want to track actual bandwidth consumed, not deduplicated file bytes.
                 state.bandwidth_stats.entry(miner_uid.to_string()).and_modify(|v| *v += len).or_insert(len);
                }

                // Spawn more if we still need shards
                while downloaded_count < k
                    && in_flight.load(Ordering::Acquire) < request_parallelism
                    && next_target_idx.load(Ordering::Acquire) < shard_targets.len()
                {
                    let _ = spawn_next(
                        state.clone(),
                        manifest.clone(),
                        stripe_idx,
                        shards_per_stripe,
                        epoch_lookback,
                        cluster_map_snapshot.epoch,
                        *placement_version,
                        result_tx.clone(),
                    );
                }
            }

            if downloaded_count >= k {
                // Decode
                let this_stripe_len = common::calculate_stripe_data_len(manifest.size, stripe_idx, stripe_size);

                if let Ok(decoded) = decode_stripe(&mut shards_data, &manifest.stripe_config, this_stripe_len) {
                    // Handle empty decoded data (edge case: zero-length stripe)
                    if decoded.is_empty() {
                        stripe_recovered = true;
                        break;
                    }

                    let stripe_start_offset = stripe_idx * stripe_size;
                    // Use saturating_sub to prevent underflow when decoded.len() is 0
                    let stripe_end_offset = stripe_start_offset + (decoded.len() as u64).saturating_sub(1);

                    let intersect_start = std::cmp::max(start, stripe_start_offset);
                    let intersect_end = std::cmp::min(end, stripe_end_offset);

                    if intersect_start <= intersect_end {
                        let rel_start = (intersect_start - stripe_start_offset) as usize;
                        let rel_end = (intersect_end - stripe_start_offset) as usize;

                        if rel_start < decoded.len() && rel_end < decoded.len() {
                             let chunk = decoded[rel_start..=rel_end].to_vec();
                             // Prometheus: count bytes successfully streamed to the client.
                             state.metrics.download_bytes.inc_by(chunk.len() as u64);
                             bytes_streamed += chunk.len() as u64;
                             yield Ok::<_, anyhow::Error>(axum::body::Bytes::from(chunk));
                        }
                    }
                }
                stripe_recovered = true;
                break;
            }
            }

            if !stripe_recovered {
                // Fail fast: otherwise the client will hang waiting for Content-Length bytes.
                let msg = format!(
                    "Failed to reconstruct stripe {} for file {} (got 0..{} shards across placements, need {})",
                    stripe_idx,
                    manifest.file_hash,
                    k + m,
                    k
                );
                error!(stripe = stripe_idx, file_hash = %manifest.file_hash, shards_needed = k, "Failed to reconstruct stripe");
                // Best-effort: ask validator to repair this stripe window (keeps miner-control privileged).
                maybe_send_repair_hint(state.clone(), manifest.file_hash.clone(), stripe_idx as usize).await;
                stream_failed = true;
                // _stream_metric_guard will decrement on drop
                let duration_ms = stream_start_time.elapsed().as_millis();
                error!(
                    hash = %stream_hash,
                    bytes_streamed = bytes_streamed,
                    duration_ms = duration_ms,
                    stripe = stripe_idx,
                    "Download failed: stripe reconstruction error"
                );
                yield Err(anyhow::anyhow!(msg));
                break;
            }
        }

        // Stream completed successfully
        if !stream_failed {
            let duration_ms = stream_start_time.elapsed().as_millis();
            info!(
                hash = %stream_hash,
                size_bytes = stream_file_size,
                bytes_served = bytes_streamed,
                content_length = stream_content_length,
                duration_ms = duration_ms,
                "Download completed"
            );
        }
        // _stream_metric_guard will decrement on drop
    };

    let body = Body::from_stream(stream);

    // Use content type from manifest, or detect from filename, or default
    let content_type =
        manifest_content_type.unwrap_or_else(|| detect_content_type(manifest_filename.as_deref()));

    // Sanitize filename for safe use in Content-Disposition header
    // This prevents header injection attacks via malicious filenames
    let raw_filename = manifest_filename.unwrap_or_else(|| format!("{}.bin", hash));
    let filename = sanitize_filename(&raw_filename);

    // Return 200 OK for full file, 206 Partial Content for range requests
    if is_range_request {
        (
            StatusCode::PARTIAL_CONTENT,
            [
                ("Content-Type", content_type.as_str()),
                (
                    "Content-Range",
                    &format!("bytes {}-{}/{}", start, end, file_size),
                ),
                ("Content-Length", &content_length.to_string()),
                ("Accept-Ranges", "bytes"),
                (
                    "Content-Disposition",
                    &format!("inline; filename=\"{}\"", filename),
                ),
            ],
            body,
        )
            .into_response()
    } else {
        (
            StatusCode::OK,
            [
                ("Content-Type", content_type.as_str()),
                ("Content-Length", &file_size.to_string()),
                ("Accept-Ranges", "bytes"),
                (
                    "Content-Disposition",
                    &format!("inline; filename=\"{}\"", filename),
                ),
            ],
            body,
        )
            .into_response()
    }
}

/// Send repair hint to validator when stripe reconstruction fails
async fn maybe_send_repair_hint(state: Arc<AppState>, file_hash: String, stripe_idx: usize) {
    if !state.auto_repair_hint_enabled {
        return;
    }

    let now = now_secs();
    // Guard: if clock skew detected, skip repair hints entirely (can't rate-limit properly)
    if now == 0 {
        return;
    }

    let key = format!("{}:{}", file_hash, stripe_idx);

    // Check rate limit and insert in a single critical section, but keep eviction logic minimal
    let needs_eviction = {
        let mut m = state.repair_hint_last_sent.lock().await;
        if let Some(ts) = m.get(&key) {
            // Guard: if stored timestamp is in the future (clock skew), treat as recent
            if *ts > now || now.saturating_sub(*ts) < state.repair_hint_min_interval_secs {
                return;
            }
        }
        m.insert(key, now);
        // Check if eviction is needed, but don't do the O(n) scan while holding lock
        m.len() >= MAX_REPAIR_HINT_ENTRIES
    };

    // Eviction outside the critical path - only when needed
    if needs_eviction {
        let mut m = state.repair_hint_last_sent.lock().await;
        // Re-check size (another task may have evicted)
        if m.len() >= MAX_REPAIR_HINT_ENTRIES {
            // Keep only entries within the min_interval window (still valid for deduplication)
            let cutoff = now.saturating_sub(state.repair_hint_min_interval_secs);
            m.retain(|_, ts| *ts > cutoff);
            // If retain didn't free enough space (all entries are recent), remove oldest
            if m.len() >= MAX_REPAIR_HINT_ENTRIES
                && let Some(oldest_key) = m.iter().min_by_key(|(_, ts)| *ts).map(|(k, _)| k.clone())
            {
                m.remove(&oldest_key);
            }
        }
    }

    let repair_hint_count = state.repair_hint_count;
    let repair_hint_allow_scan = state.repair_hint_allow_scan;
    let file_hash_clone = file_hash.clone();

    // Try P2P first if enabled
    if state.use_p2p {
        if let Some(ref p2p_client) = state.validator_p2p_client {
            let p2p_client = p2p_client.clone();
            let http_fallback = state.http_fallback;
            let validator_url = state.validator_url.clone();
            let http_client = state.http_client.clone();
            let api_key = state.validator_gateway_key.clone();

            tokio::spawn(async move {
                match p2p_client
                    .repair_hint(
                        &file_hash_clone,
                        Some(stripe_idx as u64),
                        Some(repair_hint_count.clamp(1, 50)),
                    )
                    .await
                {
                    Ok(true) => {
                        debug!(file_hash = %file_hash_clone, stripe_idx = stripe_idx, "Repair hint sent via P2P");
                    }
                    Ok(false) => {
                        debug!(file_hash = %file_hash_clone, "Repair hint not accepted via P2P");
                    }
                    Err(e) => {
                        if http_fallback {
                            debug!(error = %e, "P2P repair hint failed, falling back to HTTP");
                            // HTTP fallback
                            if let Some(api_key) = api_key {
                                let url =
                                    format!("{}/repair_hint", validator_url.trim_end_matches('/'));
                                let body = RepairHintRequest {
                                    file_hash: file_hash_clone,
                                    stripe_idx: stripe_idx as u64,
                                    count: Some(repair_hint_count.clamp(1, 50)),
                                    allow_scan: Some(repair_hint_allow_scan),
                                };
                                let _ = http_client
                                    .post(url)
                                    .header("Authorization", format!("Bearer {}", api_key))
                                    .json(&body)
                                    .timeout(std::time::Duration::from_secs(5))
                                    .send()
                                    .await;
                            }
                        } else {
                            warn!(error = %e, "P2P repair hint failed");
                        }
                    }
                }
            });
            return;
        }
    }

    // HTTP-only path (P2P disabled or no client)
    let Some(api_key) = state.validator_gateway_key.clone() else {
        return;
    };

    let url = format!("{}/repair_hint", state.validator_url.trim_end_matches('/'));
    let body = RepairHintRequest {
        file_hash,
        stripe_idx: stripe_idx as u64,
        count: Some(repair_hint_count.clamp(1, 50)),
        allow_scan: Some(repair_hint_allow_scan),
    };

    let http_client = state.http_client.clone();
    tokio::spawn(async move {
        let _ = http_client
            .post(url)
            .header("Authorization", format!("Bearer {}", api_key))
            .json(&body)
            .timeout(std::time::Duration::from_secs(5))
            .send()
            .await;
    });
}

/// Get gateway stats: miner latency rankings and bandwidth
pub async fn get_gateway_stats(State(state): State<Arc<AppState>>) -> impl IntoResponse {
    // Lock-free DashMap iteration
    let mut latency_vec: Vec<(u32, f64)> = state
        .miner_latency
        .iter()
        .map(|entry| (*entry.key(), *entry.value()))
        .collect();
    latency_vec.sort_by(|(_, a), (_, b)| a.total_cmp(b));

    let bandwidth_vec: Vec<(String, u64)> = state
        .bandwidth_stats
        .iter()
        .map(|entry| (entry.key().clone(), *entry.value()))
        .collect();

    // Build response
    let response = serde_json::json!({
        "miner_latency": latency_vec.iter()
            .map(|(uid, lat)| serde_json::json!({
                "miner_uid": uid,
                "latency_ms": format!("{:.1}", lat),
            }))
            .collect::<Vec<_>>(),
        "bandwidth": bandwidth_vec.iter()
            .map(|(uid, bytes)| serde_json::json!({
                "miner_uid": uid,
                "bytes": bytes,
            }))
            .collect::<Vec<_>>(),
        "total_miners_tracked": latency_vec.len(),
    });

    Json(response)
}

/// Upload a file through the gateway
pub async fn upload_file(
    State(state): State<Arc<AppState>>,
    mut multipart: Multipart,
) -> Result<impl IntoResponse, (StatusCode, String)> {
    let request_start = std::time::Instant::now();

    // 1. Acquire Permit (Throttling)
    let _permit = state.upload_semaphore.try_acquire().map_err(|_| {
        warn!("Upload rejected: too many concurrent uploads");
        (
            StatusCode::TOO_MANY_REQUESTS,
            "Server busy: too many concurrent uploads".to_string(),
        )
    })?;

    state.metrics.active_uploads.inc();

    // Guards for cleanup on drop (even if panic/error)
    struct MetricGuard(Arc<AppState>);
    impl Drop for MetricGuard {
        fn drop(&mut self) {
            self.0.metrics.active_uploads.dec();
        }
    }
    let _metric_guard = MetricGuard(state.clone());

    debug!("Streaming file upload to temp file");

    // 2. Stream to Disk using tempfile for atomic creation (prevents TOCTOU race)
    // NamedTempFile creates file with O_EXCL and auto-deletes on drop
    let temp_file =
        tempfile::NamedTempFile::new().map_err(|e| internal_error("create_temp_file", e))?;
    // Convert std::fs::File to tokio::fs::File for async I/O
    // Call keep() to get the path and file handle; we manage cleanup ourselves
    let (std_file, temp_path) = temp_file
        .keep()
        .map_err(|e| internal_error("persist_temp_file", e.error))?;
    let mut file = tokio::fs::File::from_std(std_file);

    // Guard to clean up temp file on exit (since we called keep())
    struct TempFileGuard(std::path::PathBuf);
    impl Drop for TempFileGuard {
        fn drop(&mut self) {
            let _ = std::fs::remove_file(&self.0);
        }
    }
    let _temp_guard = TempFileGuard(temp_path.clone());

    // Process Multipart Stream
    let field = match multipart.next_field().await {
        Ok(Some(f)) => f,
        Ok(None) => {
            return Err((
                StatusCode::BAD_REQUEST,
                "No file field in multipart request".to_string(),
            ));
        }
        Err(e) => {
            error!(error = %e, "Failed to parse multipart request");
            return Err((
                StatusCode::BAD_REQUEST,
                "Invalid multipart request format".to_string(),
            ));
        }
    };

    let file_name_final = field
        .file_name()
        .map(|s| s.to_string())
        .unwrap_or_else(|| "upload.bin".to_string());

    let mut file_size = 0u64;
    let mut field = field;
    loop {
        match field.chunk().await {
            Ok(Some(chunk)) => {
                tokio::io::AsyncWriteExt::write_all(&mut file, &chunk)
                    .await
                    .map_err(|e| internal_error("write_upload_chunk", e))?;
                file_size += chunk.len() as u64;
            }
            Ok(None) => break, // End of field data
            Err(e) => {
                error!(error = %e, "Failed to read upload chunk");
                return Err((
                    StatusCode::BAD_REQUEST,
                    "Failed to read upload data".to_string(),
                ));
            }
        }
    }

    tokio::io::AsyncWriteExt::flush(&mut file)
        .await
        .map_err(|e| internal_error("flush_upload_file", e))?;

    if file_size == 0 {
        return Err((StatusCode::BAD_REQUEST, "No file provided".to_string()));
    }

    info!(
        filename = %file_name_final,
        size_bytes = file_size,
        "Upload started"
    );

    // 3. Forward to Validator (Streaming from Disk) with Retries
    let upload_timeout = std::time::Duration::from_secs(UPLOAD_TIMEOUT_SECS);
    let url = format!("{}/upload", state.validator_url);

    let mut attempt = 0u32;

    loop {
        attempt += 1;

        // Open file for reading
        let file = match tokio::fs::File::open(&temp_path).await {
            Ok(f) => f,
            Err(e) => {
                break Err(internal_error("open_temp_file_for_upload", e));
            }
        };

        // Create streaming body
        let stream = tokio_util::io::ReaderStream::new(file);
        let body = reqwest::Body::wrap_stream(stream);

        let part = reqwest::multipart::Part::stream(body).file_name(file_name_final.clone());

        let form = reqwest::multipart::Form::new().part("file", part);

        let res_result = state
            .http_client
            .post(&url)
            .timeout(upload_timeout)
            .multipart(form)
            .send()
            .await;

        match res_result {
            Ok(res) => {
                if res.status().is_success() {
                    let _status_u16 = res.status().as_u16();
                    let response_text = res.text().await.unwrap_or_default();
                    let upload_hash = serde_json::from_str::<serde_json::Value>(&response_text)
                        .ok()
                        .and_then(|v| {
                            v.get("hash")
                                .and_then(|h| h.as_str())
                                .map(|s| s.to_string())
                        });
                    let duration_ms = request_start.elapsed().as_millis();
                    info!(
                        filename = %file_name_final,
                        size_bytes = file_size,
                        hash = %upload_hash.as_deref().unwrap_or("unknown"),
                        duration_ms = duration_ms,
                        "Upload completed"
                    );
                    state.metrics.upload_bytes.inc_by(file_size);
                    break Ok((StatusCode::OK, response_text).into_response());
                } else if res.status() == reqwest::StatusCode::TOO_MANY_REQUESTS
                    || res.status().is_server_error()
                {
                    // Retryable error (429 or 5xx)
                    if attempt >= UPLOAD_MAX_RETRIES {
                        let status_u16 = res.status().as_u16();
                        let status = StatusCode::from_u16(status_u16)
                            .unwrap_or(StatusCode::INTERNAL_SERVER_ERROR);
                        let text = res.text().await.unwrap_or_default();
                        let duration_ms = request_start.elapsed().as_millis();
                        error!(
                            filename = %file_name_final,
                            size_bytes = file_size,
                            status = %status,
                            duration_ms = duration_ms,
                            "Upload failed: max retries exceeded"
                        );
                        break Err((
                            status,
                            format!(
                                "Validator error after {} retries: {}",
                                UPLOAD_MAX_RETRIES, text
                            ),
                        ));
                    }

                    warn!(
                        status = res.status().as_u16(),
                        attempt = attempt,
                        max_retries = UPLOAD_MAX_RETRIES,
                        "Validator error, retrying"
                    );
                    // Note: Backoff sleep happens at end of loop for all retry cases
                } else {
                    // Client error (400, etc) - do not retry
                    let status_u16 = res.status().as_u16();
                    let status = StatusCode::from_u16(status_u16)
                        .unwrap_or(StatusCode::INTERNAL_SERVER_ERROR);
                    let text = res.text().await.unwrap_or_default();
                    let duration_ms = request_start.elapsed().as_millis();
                    error!(
                        filename = %file_name_final,
                        size_bytes = file_size,
                        status = %status,
                        error = %text,
                        duration_ms = duration_ms,
                        "Upload failed: validator error"
                    );
                    // Return status but with generic message (actual error logged above)
                    break Err((status, "Upload processing failed".to_string()));
                }
            }
            Err(e) => {
                // Network error - retry with backoff
                if attempt >= UPLOAD_MAX_RETRIES {
                    let duration_ms = request_start.elapsed().as_millis();
                    error!(
                        filename = %file_name_final,
                        size_bytes = file_size,
                        error = %e,
                        duration_ms = duration_ms,
                        "Upload failed: network error after retries"
                    );
                    // Generic message - actual error logged above
                    break Err((
                        StatusCode::BAD_GATEWAY,
                        "Failed to process upload. Please try again.".to_string(),
                    ));
                }
                warn!(
                    error = %e,
                    attempt = attempt,
                    max_retries = UPLOAD_MAX_RETRIES,
                    "Forwarding failed, retrying"
                );
            }
        }

        // Exponential backoff between retries (use saturating_mul to prevent overflow)
        let backoff_ms =
            UPLOAD_RETRY_BASE_DELAY_MS.saturating_mul(2u64.saturating_pow(attempt - 1));
        tokio::time::sleep(std::time::Duration::from_millis(backoff_ms)).await;
    }
    // TempFileGuard cleans up temp file on drop
}

/// Middleware to require admin API key for protected endpoints
pub async fn require_admin_key(
    req: axum::extract::Request,
    next: axum::middleware::Next,
) -> Result<axum::response::Response, StatusCode> {
    use common::middleware::{API_KEY_HEADER, constant_time_eq, get_expected_api_key};

    let provided_key = req
        .headers()
        .get(API_KEY_HEADER)
        .and_then(|h| h.to_str().ok());

    // Use cached API key from common (avoids re-reading env var on each request)
    let expected_key = get_expected_api_key();

    match provided_key {
        // Constant-time comparison to prevent timing side-channel attacks
        Some(key) if constant_time_eq(key, expected_key) => Ok(next.run(req).await),
        _ => Err(StatusCode::UNAUTHORIZED),
    }
}

/// Handler for Prometheus metrics endpoint
pub async fn metrics_handler(State(state): State<Arc<AppState>>) -> impl IntoResponse {
    let output = state.metrics.encode();
    (
        StatusCode::OK,
        [("content-type", "text/plain; version=0.0.4")],
        output,
    )
}

/// Delete a file by hash (proxied to validator via P2P or HTTP)
pub async fn delete_file(
    State(state): State<Arc<AppState>>,
    Path(hash): Path<String>,
    headers: HeaderMap,
) -> impl IntoResponse {
    // Validate hash format before forwarding to validator
    if let Err(e) = common::validate_file_hash(&hash) {
        return (StatusCode::BAD_REQUEST, e).into_response();
    }

    debug!(hash = %hash, "Received delete request");

    // Try P2P first if enabled
    if state.use_p2p {
        if let Some(ref p2p_client) = state.validator_p2p_client {
            match p2p_client.delete_file(&hash).await {
                Ok(true) => {
                    info!(hash = %hash, source = "p2p", "File deleted via P2P");
                    return (
                        StatusCode::OK,
                        serde_json::json!({"status": "deleted", "hash": hash}).to_string(),
                    )
                        .into_response();
                }
                Ok(false) => {
                    // File not found or deletion failed
                    debug!(hash = %hash, "P2P delete returned false");
                    if !state.http_fallback {
                        return (StatusCode::NOT_FOUND, "File not found".to_string())
                            .into_response();
                    }
                }
                Err(e) => {
                    if state.http_fallback {
                        debug!(error = %e, "P2P delete failed, falling back to HTTP");
                    } else {
                        error!(error = %e, hash = %hash, "P2P delete failed");
                        return (
                            StatusCode::BAD_GATEWAY,
                            "Failed to process delete request".to_string(),
                        )
                            .into_response();
                    }
                }
            }
        }
    }

    // HTTP fallback (or primary if P2P disabled)
    let url = format!("{}/blobs/{}", state.validator_url, hash);
    let mut request_builder = state.http_client.delete(url);

    // Forward Authorization header if present
    if let Some(auth_header) = headers.get("Authorization")
        && let Ok(val) = reqwest::header::HeaderValue::from_bytes(auth_header.as_bytes())
    {
        request_builder = request_builder.header("Authorization", val);
    }

    let response = match request_builder.send().await {
        Ok(r) => r,
        Err(e) => {
            error!(error = %e, hash = %hash, "Failed to contact validator for delete");
            return (
                StatusCode::BAD_GATEWAY,
                "Failed to process delete request".to_string(),
            )
                .into_response();
        }
    };

    let status = StatusCode::from_u16(response.status().as_u16())
        .unwrap_or(StatusCode::INTERNAL_SERVER_ERROR);

    // Convert reqwest headers to axum headers
    let axum_headers: HeaderMap = response
        .headers()
        .iter()
        .filter_map(|(k, v)| {
            let name = axum::http::HeaderName::from_bytes(k.as_str().as_bytes()).ok()?;
            let val = axum::http::HeaderValue::from_bytes(v.as_bytes()).ok()?;
            Some((name, val))
        })
        .collect();

    match response.text().await {
        Ok(body) => (status, axum_headers, body).into_response(),
        Err(e) => {
            error!(error = %e, hash = %hash, "Failed to read validator response");
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                "Failed to process response".to_string(),
            )
                .into_response()
        }
    }
}

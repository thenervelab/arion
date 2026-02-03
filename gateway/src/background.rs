//! Background task loops for the gateway.

use crate::config::MAX_CLUSTER_MAP_HISTORY;
use crate::state::AppState;
use common::{BandwidthReport, BandwidthStats, ClusterMap, MinerFailureReport, MinerFailureStats};
use std::sync::Arc;
use tracing::{debug, error, info, warn};

/// Get gateway key or log warning and return None
fn get_gateway_key(state: &AppState, operation: &str) -> Option<String> {
    state.validator_gateway_key.clone().or_else(|| {
        warn!(
            "VALIDATOR_GATEWAY_KEY not configured; skipping {}",
            operation
        );
        None
    })
}

/// Sync cluster map from validator periodically.
/// Prefers P2P when available, falls back to HTTP.
pub async fn sync_map_loop(state: Arc<AppState>, validator_url: String) {
    use tokio::io::AsyncReadExt;

    loop {
        // Prefer doc replica (fast local reads) but ALSO refresh from validator when available.
        // Doc replication can lag; validator keeps the gateway converged quickly.
        if let (Some(doc), Some(blobs)) =
            (state.doc_replica.as_ref(), state.doc_replica_blobs.as_ref())
        {
            let query = iroh_docs::store::Query::single_latest_per_key().key_exact(b"cluster_map");
            if let Ok(Some(entry)) = doc.get_one(query).await {
                let mut reader = blobs.reader(entry.content_hash());
                let mut content = Vec::new();
                // Timeout blob read to prevent hanging (5 seconds should be plenty for cluster map)
                let read_result = tokio::time::timeout(
                    std::time::Duration::from_secs(5),
                    reader.read_to_end(&mut content),
                )
                .await;
                if matches!(read_result, Ok(Ok(_)))
                    && let Ok(new_map) = serde_json::from_slice::<ClusterMap>(&content)
                {
                    let mut current_map = state.cluster_map.lock().await;
                    // Never regress epoch: doc replica may lag behind validator.
                    // If doc is behind, keep current and allow P2P/HTTP to refresh.
                    if new_map.epoch >= current_map.epoch {
                        if new_map.epoch != current_map.epoch {
                            info!(epoch = new_map.epoch, source = "doc", "Updating ClusterMap");
                        }
                        *current_map = new_map;
                    } else {
                        debug!(
                            doc_epoch = new_map.epoch,
                            current_epoch = current_map.epoch,
                            "Doc replica map behind current; will refresh via P2P/HTTP"
                        );
                    }
                }
            }
        }

        // Fetch map from Validator (authoritative when reachable). Never regress epoch.
        // Try P2P first if available, fall back to HTTP
        let fetch_result = fetch_cluster_map_with_fallback(&state, &validator_url).await;

        match fetch_result {
            Ok((new_map, source)) => {
                let mut current_map = state.cluster_map.lock().await;
                if new_map.epoch >= current_map.epoch {
                    if new_map.epoch != current_map.epoch {
                        info!(
                            epoch = new_map.epoch,
                            source = source,
                            "Updating ClusterMap"
                        );
                        // Save old map to history before updating (for epoch lookback)
                        let mut history = state.cluster_map_history.lock().await;
                        if history.len() >= MAX_CLUSTER_MAP_HISTORY {
                            history.remove(0); // Remove oldest first
                        }
                        history.push(current_map.clone());
                    }
                    *current_map = new_map;
                }
            }
            Err(e) => {
                debug!(error = %e, "Failed to sync map from validator");
            }
        }

        // Update connection pool size metric
        {
            let pool = state.connection_pool.read().await;
            state.metrics.connection_pool_size.set(pool.len() as i64);
        }

        // Periodic cleanup of expired blacklist entries (every sync cycle)
        // This prevents unbounded growth of the blacklist DashMap
        {
            let now = common::now_secs();
            // Guard: skip cleanup if clock skew detected
            if now > 0 && !state.miner_blacklist.is_empty() {
                state.miner_blacklist.retain(|_, ts| {
                    // Keep entries that are still within blacklist duration
                    // Guard: if ts > now (clock skew), keep the entry
                    *ts > now
                        || now.saturating_sub(*ts) < crate::config::MINER_BLACKLIST_DURATION_SECS
                });
            }
        }

        // Periodic cleanup of expired rebalance status cache entries
        {
            let now = common::now_secs();
            if now > 0 && !state.rebalance_status_cache.is_empty() {
                state.rebalance_status_cache.retain(|_, (_, cached_at)| {
                    *cached_at > now
                        || now.saturating_sub(*cached_at)
                            < crate::config::REBALANCE_STATUS_CACHE_TTL_SECS
                });
            }
        }

        // Sync every 2 seconds for faster convergence
        tokio::time::sleep(std::time::Duration::from_secs(2)).await;
    }
}

/// Fetch cluster map using P2P (preferred) with HTTP fallback.
/// Returns (ClusterMap, source) where source is "p2p" or "http".
async fn fetch_cluster_map_with_fallback(
    state: &AppState,
    validator_url: &str,
) -> Result<(ClusterMap, &'static str), String> {
    // Try P2P first if enabled and client is available
    if state.use_p2p {
        if let Some(ref p2p_client) = state.validator_p2p_client {
            match p2p_client.get_cluster_map().await {
                Ok(map) => {
                    debug!("Fetched cluster map via P2P");
                    return Ok((map, "p2p"));
                }
                Err(e) => {
                    if state.http_fallback {
                        debug!(error = %e, "P2P cluster map fetch failed, falling back to HTTP");
                    } else {
                        return Err(format!("P2P cluster map fetch failed: {}", e));
                    }
                }
            }
        }
    }

    // HTTP fallback (or primary if P2P disabled)
    match state
        .http_client
        .get(format!("{}/map", validator_url))
        .send()
        .await
    {
        Ok(res) if res.status().is_success() => {
            if let Ok(map_json) = res.text().await {
                if let Ok(map) = serde_json::from_str::<ClusterMap>(&map_json) {
                    return Ok((map, "http"));
                }
            }
            Err("Failed to parse cluster map from HTTP response".to_string())
        }
        Ok(res) => Err(format!("HTTP request failed with status: {}", res.status())),
        Err(e) => Err(format!("HTTP request failed: {}", e)),
    }
}

/// Report bandwidth statistics to validator periodically.
/// Uses P2P when available, falls back to HTTP.
pub async fn report_bandwidth_loop(state: Arc<AppState>, validator_url: String) {
    loop {
        tokio::time::sleep(tokio::time::Duration::from_secs(30)).await;

        // Lock-free DashMap iteration - skip if empty
        if state.bandwidth_stats.is_empty() {
            continue;
        }

        // Collect keys first to avoid race between iteration and clear
        let keys_to_report: Vec<String> = state
            .bandwidth_stats
            .iter()
            .map(|entry| entry.key().clone())
            .collect();

        if keys_to_report.is_empty() {
            continue;
        }

        // Build reports from the collected keys
        let reports: Vec<BandwidthReport> = keys_to_report
            .iter()
            .filter_map(|key| {
                state.bandwidth_stats.get(key).map(|v| BandwidthReport {
                    miner_uid: key.clone(),
                    bytes: *v,
                })
            })
            .collect();

        if reports.is_empty() {
            continue;
        }

        // Try P2P first, then HTTP fallback
        let success = report_bandwidth_with_fallback(&state, &validator_url, reports.clone()).await;

        if success {
            info!(
                count = reports.len(),
                "Reported bandwidth stats to validator"
            );
            // Clear only the keys we reported (not new entries added during send)
            for key in keys_to_report {
                state.bandwidth_stats.remove(&key);
            }
        }
    }
}

/// Report bandwidth using P2P (preferred) with HTTP fallback.
async fn report_bandwidth_with_fallback(
    state: &AppState,
    validator_url: &str,
    reports: Vec<BandwidthReport>,
) -> bool {
    // Try P2P first if enabled
    if state.use_p2p {
        if let Some(ref p2p_client) = state.validator_p2p_client {
            match p2p_client.report_bandwidth(reports.clone()).await {
                Ok(()) => {
                    debug!("Reported bandwidth stats via P2P");
                    return true;
                }
                Err(e) => {
                    if state.http_fallback {
                        debug!(error = %e, "P2P bandwidth report failed, falling back to HTTP");
                    } else {
                        error!(error = %e, "P2P bandwidth report failed");
                        return false;
                    }
                }
            }
        }
    }

    // HTTP fallback
    let Some(gateway_key) = get_gateway_key(state, "bandwidth reports") else {
        return false;
    };

    let payload = BandwidthStats { reports };
    match state
        .http_client
        .post(format!("{}/stats/bandwidth", validator_url))
        .header("Authorization", format!("Bearer {}", gateway_key))
        .json(&payload)
        .send()
        .await
    {
        Ok(res) if res.status().is_success() => true,
        Ok(res) => {
            error!(status = %res.status(), "Failed to report bandwidth stats via HTTP");
            false
        }
        Err(e) => {
            error!(error = %e, "Failed to report bandwidth stats via HTTP");
            false
        }
    }
}

/// Report miner failures to validator for tracking.
/// Uses P2P when available, falls back to HTTP.
pub async fn report_failures_loop(state: Arc<AppState>, validator_url: String) {
    loop {
        tokio::time::sleep(tokio::time::Duration::from_secs(30)).await;

        // Convert VecDeque to Vec under lock; only clear after successful submit.
        let reports: Vec<MinerFailureReport> = {
            let failures = state.miner_failures.lock().await;
            if failures.is_empty() {
                continue;
            }
            failures.iter().cloned().collect()
        };

        warn!(
            count = reports.len(),
            "Reporting miner failures to validator"
        );

        // Try P2P first, then HTTP fallback
        let success = report_failures_with_fallback(&state, &validator_url, reports).await;

        if success {
            state.miner_failures.lock().await.clear();
        }
    }
}

/// Report failures using P2P (preferred) with HTTP fallback.
async fn report_failures_with_fallback(
    state: &AppState,
    validator_url: &str,
    reports: Vec<MinerFailureReport>,
) -> bool {
    // Try P2P first if enabled
    if state.use_p2p {
        if let Some(ref p2p_client) = state.validator_p2p_client {
            match p2p_client.report_failures(reports.clone()).await {
                Ok(()) => {
                    debug!("Reported failures via P2P");
                    return true;
                }
                Err(e) => {
                    if state.http_fallback {
                        debug!(error = %e, "P2P failure report failed, falling back to HTTP");
                    } else {
                        error!(error = %e, "P2P failure report failed");
                        return false;
                    }
                }
            }
        }
    }

    // HTTP fallback
    let Some(gateway_key) = get_gateway_key(state, "failure reports") else {
        return false;
    };

    let payload = MinerFailureStats { reports };
    match state
        .http_client
        .post(format!("{}/stats/failures", validator_url))
        .header("Authorization", format!("Bearer {}", gateway_key))
        .json(&payload)
        .send()
        .await
    {
        Ok(res) if res.status().is_success() => true,
        Ok(res) => {
            error!(status = %res.status(), "Failed to report miner failures via HTTP");
            false
        }
        Err(e) => {
            error!(error = %e, "Failed to report miner failures via HTTP");
            false
        }
    }
}

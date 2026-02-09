//! Self-rebalancing logic for the miner.
//!
//! Miners periodically check which PGs they are responsible for,
//! query the validator for files in those PGs, and pull any missing shards.

use crate::constants::{
    DEFAULT_CONNECT_TIMEOUT_SECS, MAX_BATCH_PG_RESPONSE_SIZE, MAX_ORPHAN_ENTRIES,
    ORPHAN_GRACE_PERIOD_SECS, REBALANCE_MAX_FILES_PER_CYCLE, REBALANCE_MAX_PULL_ATTEMPTS,
};
use crate::helpers::truncate_for_log;
use crate::p2p::download_from_peer_miner;
use crate::state::{get_blobs_dir, get_cluster_map, get_orphan_shards, get_validator_endpoint};
use anyhow::Result;
use common::now_secs;
use iroh::endpoint::Endpoint;
use iroh_blobs::store::fs::FsStore;
use std::str::FromStr;
use std::sync::Arc;
use tracing::{debug, error, info, trace, warn};

/// PG-based self-rebalancing: Calculate which PGs this miner is responsible for,
/// query validator for files in each PG, and pull any missing shards
pub async fn self_rebalance_pg(store: FsStore, endpoint: Endpoint) -> Result<()> {
    info!("Starting PG-based self-rebalance");

    // Get my miner UID (same calculation as in heartbeat)
    let mut hasher = std::collections::hash_map::DefaultHasher::new();
    use std::hash::{Hash, Hasher};
    endpoint.secret_key().public().to_string().hash(&mut hasher);
    let my_uid = (hasher.finish() as u32) & 0x7FFFFFFF;

    trace!(miner_uid = my_uid, "My miner UID");

    // Epoch lookback for locating shards during transitions
    let epoch_lookback: u64 = std::env::var("EPOCH_LOOKBACK")
        .ok()
        .and_then(|s| s.parse::<u64>().ok())
        .unwrap_or(3);

    // Get cluster map for CRUSH calculations
    let cluster_map: Arc<common::ClusterMap> = {
        let map_guard = get_cluster_map().read().await;
        match map_guard.as_ref() {
            Some(map) => map.clone(),
            None => {
                warn!("No cluster map available, skipping rebalance");
                return Ok(());
            }
        }
    };

    // Pre-compute uid -> public_key mapping ONCE (not per-shard!)
    let uid_to_pk: std::collections::HashMap<u32, String> = cluster_map
        .miners
        .iter()
        .map(|m| (m.uid, m.public_key.clone()))
        .collect();

    // Get validator endpoint for P2P queries
    let validator_addr = {
        let val_ep = get_validator_endpoint().read().await;
        match val_ep.as_ref() {
            Some(addr) => addr.clone(),
            None => {
                warn!("No validator endpoint stored, skipping PG queries");
                return Ok(());
            }
        }
    };

    // Calculate which PGs we are responsible for
    let my_pgs = common::calculate_my_pgs(my_uid, &cluster_map);
    trace!(
        pg_count = my_pgs.len(),
        total_pgs = cluster_map.pg_count,
        "Responsible for PGs"
    );

    if my_pgs.is_empty() {
        warn!("No PGs assigned to this miner");
        return Ok(());
    }

    trace!(pgs = ?my_pgs.iter().take(10).collect::<Vec<_>>(), "My PG assignments (first 10)");

    // Query validator for files in ALL our PGs in a single batch request
    let mut total_files = 0;
    let mut files_processed = 0;
    let mut shards_pulled = 0;
    let mut pull_attempts = 0;
    let mut expected_shards: std::collections::HashSet<String> = std::collections::HashSet::new();

    // Build batch query message with all our PGs
    let query_msg = common::ValidatorControlMessage::QueryPgFilesBatch {
        pg_ids: my_pgs.clone(),
    };

    // Connect to validator via P2P with timeout
    let connect_timeout = std::time::Duration::from_secs(DEFAULT_CONNECT_TIMEOUT_SECS);
    let read_timeout = std::time::Duration::from_secs(60); // Longer timeout for batch response

    debug!(
        pg_count = my_pgs.len(),
        "Querying validator for files in assigned PGs (batch)"
    );

    // Single connection for all PG queries
    let pg_files_map: std::collections::HashMap<u32, Vec<String>> = match tokio::time::timeout(
        connect_timeout,
        endpoint.connect(validator_addr.clone(), b"hippius/validator-control"),
    )
    .await
    {
        Ok(Ok(conn)) => {
            let result: Result<std::collections::HashMap<u32, Vec<String>>> = async {
                let (mut send, mut recv) = conn.open_bi().await?;
                let msg_bytes = serde_json::to_vec(&query_msg)?;
                send.write_all(&msg_bytes).await?;
                send.finish()?;
                let _ = send.stopped().await;

                // Buffer for batch response (bounded to prevent OOM)
                let response_bytes = tokio::time::timeout(
                    read_timeout,
                    recv.read_to_end(MAX_BATCH_PG_RESPONSE_SIZE),
                )
                .await
                .map_err(|_| anyhow::anyhow!("QueryPgFilesBatch read timeout"))??;

                let files: std::collections::HashMap<u32, Vec<String>> =
                    serde_json::from_slice(&response_bytes)?;
                Ok(files)
            }
            .await;

            match result {
                Ok(f) => f,
                Err(e) => {
                    error!(error = %e, "Batch PG query failed");
                    return Ok(());
                }
            }
        }
        Ok(Err(e)) => {
            error!(error = %e, "Failed to connect for batch PG query");
            return Ok(());
        }
        Err(_) => {
            error!("Connection timeout for batch PG query");
            return Ok(());
        }
    };

    debug!(
        pgs_with_files = pg_files_map.len(),
        "Received batch PG query response"
    );

    // Process all files from the batch response (with limits to prevent memory exhaustion)
    'pg_loop: for (pg_id, files) in pg_files_map.iter() {
        trace!(pg_id = pg_id, file_count = files.len(), "Processing PG");
        total_files += files.len();

        // For each file, fetch manifest and check which shards we should have
        for file_hash in files.iter() {
            // Check file processing limit
            if files_processed >= REBALANCE_MAX_FILES_PER_CYCLE {
                debug!(
                    limit = REBALANCE_MAX_FILES_PER_CYCLE,
                    processed = files_processed,
                    "Hit file processing limit, continuing in next cycle"
                );
                break 'pg_loop;
            }
            files_processed += 1;

            // Fetch manifest from validator
            let manifest = match fetch_manifest_from_validator(
                &endpoint,
                &validator_addr,
                file_hash,
            )
            .await
            {
                Ok(m) => m,
                Err(e) => {
                    error!(file_hash = %truncate_for_log(file_hash, 16), error = %e, "Failed to fetch manifest");
                    continue;
                }
            };

            let shards_per_stripe = manifest.stripe_config.k + manifest.stripe_config.m;
            let num_stripes = manifest.shards.len().div_ceil(shards_per_stripe);

            // For each shard, check if this miner should have it
            for stripe_idx in 0..num_stripes {
                for local_idx in 0..shards_per_stripe {
                    let global_idx = stripe_idx * shards_per_stripe + local_idx;
                    if global_idx >= manifest.shards.len() {
                        continue;
                    }

                    // FULL CRUSH (PG-based, per paper): PG placement + rotate by stripe_index
                    let target = common::calculate_pg_placement_for_stripe(
                        file_hash,
                        stripe_idx as u64,
                        shards_per_stripe,
                        &cluster_map,
                    )
                    .ok()
                    .and_then(|miners| miners.get(local_idx).cloned());

                    if let Some(target_miner) = target
                        && target_miner.uid == my_uid
                    {
                        let shard = &manifest.shards[global_idx];

                        // Track this as an expected shard
                        expected_shards.insert(shard.blob_hash.clone());

                        // Check if we have this shard locally
                        let has_shard =
                            if let Ok(hash) = iroh_blobs::Hash::from_str(&shard.blob_hash) {
                                store.has(hash).await.unwrap_or(false)
                            } else {
                                false
                            };

                        if !has_shard {
                            // Skip pull logic if we've hit the limit (but still track expected shards above)
                            if pull_attempts >= REBALANCE_MAX_PULL_ATTEMPTS {
                                continue;
                            }

                            // Need to pull this shard from the most likely source(s)
                            let cur_epoch = cluster_map.epoch;
                            let min_epoch = cur_epoch.saturating_sub(epoch_lookback);
                            let mut tried: std::collections::HashSet<String> =
                                std::collections::HashSet::new();

                            let mut pulled = false;
                            let mut e = cur_epoch;
                            while e >= min_epoch {
                                // Get map for epoch e
                                let map_e: Option<Arc<common::ClusterMap>> = if e == cur_epoch {
                                    Some(cluster_map.clone())
                                } else {
                                    fetch_map_epoch_http(e).await.map(Arc::new)
                                };
                                let Some(map_e) = map_e else {
                                    if e == 0 {
                                        break;
                                    }
                                    e = e.saturating_sub(1);
                                    continue;
                                };

                                if let Ok(miners_e) = common::calculate_pg_placement_for_stripe(
                                    file_hash,
                                    stripe_idx as u64,
                                    shards_per_stripe,
                                    &map_e,
                                ) && let Some(src) = miners_e.get(local_idx)
                                    && src.uid != my_uid
                                    && let Some(pk) = uid_to_pk.get(&src.uid).cloned()
                                    && tried.insert(pk.clone())
                                {
                                    // Check pull attempts limit before attempting
                                    if pull_attempts >= REBALANCE_MAX_PULL_ATTEMPTS {
                                        debug!(
                                            limit = REBALANCE_MAX_PULL_ATTEMPTS,
                                            "Hit pull attempts limit, skipping remaining pulls"
                                        );
                                        break;
                                    }
                                    pull_attempts += 1;

                                    // Attempt P2P pull
                                    match download_from_peer_miner(
                                        pk.clone(),
                                        shard.blob_hash.clone(),
                                        store.clone(),
                                        endpoint.clone(),
                                    )
                                    .await
                                    {
                                        Ok(()) => {
                                            shards_pulled += 1;
                                            pulled = true;
                                            break;
                                        }
                                        Err(e) => {
                                            trace!(error = %e, peer = %pk, "Pull attempt failed");
                                        }
                                    }
                                }

                                if e == 0 {
                                    break;
                                }
                                e = e.saturating_sub(1);
                            }

                            if !pulled {
                                warn!(
                                    shard_idx = local_idx,
                                    blob_hash = %truncate_for_log(&shard.blob_hash, 16),
                                    file_hash = %truncate_for_log(file_hash, 16),
                                    epoch_lookback = epoch_lookback,
                                    "Could not pull shard after epoch-lookback"
                                );
                            }
                        }
                    }
                }
            }
        }
    }

    debug!(
        files_total = total_files,
        files_processed = files_processed,
        expected_shards = expected_shards.len(),
        pull_attempts = pull_attempts,
        pulled = shards_pulled,
        "Self-rebalance summary"
    );

    // GC: Walk blobs directory, identify orphans, delete after grace period
    gc_orphan_shards(&expected_shards).await;

    info!("PG-based self-rebalance complete");
    Ok(())
}

/// Garbage collect orphan shards
async fn gc_orphan_shards(expected_shards: &std::collections::HashSet<String>) {
    let now = now_secs();

    // Guard: if clock skew detected, skip GC entirely
    if now == 0 {
        warn!("Clock skew detected (now_secs=0), skipping orphan GC");
        return;
    }

    // Get blobs directory for file system walking
    let blobs_path = {
        let bd = get_blobs_dir().read().await;
        bd.clone()
    };

    if let Some(blobs_dir) = blobs_path {
        let data_dir = blobs_dir.join("data");

        if data_dir.exists() {
            let mut orphan_count = 0;
            let mut deleted_count = 0;
            let mut kept_count = 0;

            // Use DashMap for lock-free orphan tracking
            let orphan_map = get_orphan_shards();

            // Walk the data directory looking for blob entries
            if let Ok(mut entries) = tokio::fs::read_dir(&data_dir).await {
                while let Ok(Some(dir_entry)) = entries.next_entry().await {
                    let path = dir_entry.path();

                    // Try to extract hash from filename
                    if let Some(filename) = path.file_name().and_then(|n| n.to_str()) {
                        // iroh-blobs stores files as {hash}.data
                        let hash_str = if filename.ends_with(".data") {
                            filename.trim_end_matches(".data").to_string()
                        } else {
                            filename.to_string()
                        };

                        if expected_shards.contains(&hash_str) {
                            // This is expected - remove from orphan tracking
                            orphan_map.remove(&hash_str);
                            kept_count += 1;
                        } else if hash_str.len() > 20 {
                            // Looks like a blob hash - potential orphan
                            orphan_count += 1;

                            if let Some(orphan_entry) = orphan_map.get(&hash_str) {
                                let first_seen = *orphan_entry;
                                drop(orphan_entry);

                                // Guard: if now < first_seen, entry is corrupted
                                if now < first_seen {
                                    warn!(
                                        hash = %truncate_for_log(&hash_str, 16),
                                        "Clock skew detected: removing corrupted orphan entry"
                                    );
                                    orphan_map.remove(&hash_str);
                                    continue;
                                }

                                // Check if grace period expired
                                if now - first_seen > ORPHAN_GRACE_PERIOD_SECS {
                                    // Delete this orphan
                                    trace!(
                                        hash = %truncate_for_log(&hash_str, 16),
                                        age_secs = now - first_seen,
                                        "GC: Deleting orphan"
                                    );
                                    if let Err(e) = tokio::fs::remove_file(&path).await {
                                        error!(
                                            hash = %truncate_for_log(&hash_str, 16),
                                            error = %e,
                                            "Failed to delete orphan"
                                        );
                                    } else {
                                        deleted_count += 1;
                                        orphan_map.remove(&hash_str);
                                    }
                                }
                                // else: still in grace period, keep tracking
                            } else {
                                // New orphan - start tracking with timestamp
                                // Bound orphan map size to prevent unbounded memory growth
                                if orphan_map.len() < MAX_ORPHAN_ENTRIES {
                                    orphan_map.insert(hash_str, now);
                                } else {
                                    warn!(
                                        capacity = MAX_ORPHAN_ENTRIES,
                                        hash = %truncate_for_log(&hash_str, 16),
                                        "Orphan map at capacity, skipping tracking"
                                    );
                                }
                            }
                        }
                    }
                }
            }

            if orphan_count > 0 || deleted_count > 0 {
                debug!(
                    expected = kept_count,
                    orphans_tracked = orphan_count,
                    deleted = deleted_count,
                    grace_period_secs = ORPHAN_GRACE_PERIOD_SECS,
                    "GC complete"
                );
            }
        }
    }
}

/// Shared HTTP client for rebalance operations (created once, reused)
fn get_http_client() -> &'static reqwest::Client {
    use std::sync::OnceLock;
    static CLIENT: OnceLock<reqwest::Client> = OnceLock::new();
    CLIENT.get_or_init(|| {
        reqwest::Client::builder()
            .timeout(std::time::Duration::from_secs(30))
            .pool_max_idle_per_host(2)
            .build()
            .expect("Failed to create HTTP client")
    })
}

/// Helper: fetch a historical cluster map from validator HTTP
async fn fetch_map_epoch_http(epoch: u64) -> Option<common::ClusterMap> {
    let base = std::env::var("VALIDATOR_URL").ok()?;
    let url = format!("{}/map/epoch/{}", base.trim_end_matches('/'), epoch);
    let client = get_http_client();
    let res = client.get(&url).send().await.ok()?;
    if !res.status().is_success() {
        return None;
    }
    res.json::<common::ClusterMap>().await.ok()
}

/// Fetch manifest from validator via P2P
pub async fn fetch_manifest_from_validator(
    endpoint: &Endpoint,
    validator_addr: &iroh::EndpointAddr,
    file_hash: &str,
) -> Result<common::FileManifest> {
    let query_msg = common::ValidatorControlMessage::QueryManifest {
        file_hash: file_hash.to_string(),
    };

    let conn = tokio::time::timeout(
        std::time::Duration::from_secs(DEFAULT_CONNECT_TIMEOUT_SECS),
        endpoint.connect(validator_addr.clone(), b"hippius/validator-control"),
    )
    .await
    .map_err(|_| anyhow::anyhow!("Connection timeout fetching manifest"))??;

    let (mut send, mut recv) =
        tokio::time::timeout(std::time::Duration::from_secs(10), conn.open_bi())
            .await
            .map_err(|_| anyhow::anyhow!("Stream open timeout fetching manifest"))??;

    let msg_bytes = serde_json::to_vec(&query_msg)?;
    send.write_all(&msg_bytes).await?;
    send.finish()?;
    let _ = send.stopped().await;

    let response_bytes = tokio::time::timeout(
        std::time::Duration::from_secs(30),
        recv.read_to_end(1024 * 1024),
    )
    .await
    .map_err(|_| anyhow::anyhow!("Read timeout fetching manifest"))??; // Max 1MB manifest

    if response_bytes == b"NOT_FOUND" {
        return Err(anyhow::anyhow!("Manifest not found"));
    }

    let manifest: common::FileManifest = serde_json::from_slice(&response_bytes)?;
    Ok(manifest)
}

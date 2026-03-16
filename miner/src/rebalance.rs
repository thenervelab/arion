//! Self-rebalancing logic for the miner.
//!
//! Runs on a configurable tick (default 300s) with startup jitter to
//! desynchronize miners. Each cycle:
//!
//! 1. **PG calculation**: Compute which Placement Groups this miner is
//!    responsible for using CRUSH over the current cluster map (cached by epoch).
//! 2. **Manifest fetch**: Query the validator for all files in those PGs
//!    via chunked `QueryPgFilesBatch` requests (500 PGs per chunk).
//!    Falls back to local iroh-doc replica if validator is unreachable.
//! 3. **Shard verification**: For each file, fetch the manifest and walk
//!    stripes to identify shards this miner should hold (CRUSH placement
//!    with stripe rotation). Compare against a pre-built set of locally
//!    present blobs (directory walk, O(1) lookups).
//! 4. **Orphan GC**: Any local blob not in the expected set is tracked as
//!    an orphan. After a 1-hour grace period, orphans are deleted from disk.
//!
//! Missing shards are fetched concurrently from peer miners with adaptive
//! throttling (see `fetch_missing_shards`). The validator also handles
//! migration via `PullFromPeer` commands as a fallback.

use crate::constants::{
    BATCH_RESPONSE_TIMEOUT_SECS, CONCURRENT_MANIFEST_FETCH_STREAMS, EPOCH_LOOKBACK,
    MANIFEST_READ_TIMEOUT_SECS, MANIFEST_RESPONSE_MAX_SIZE, MANIFEST_STREAM_OPEN_TIMEOUT_SECS,
    MAX_BATCH_PG_RESPONSE_SIZE, MAX_CONSECUTIVE_MANIFEST_FAILURES, MAX_ORPHAN_ENTRIES,
    MAX_PG_BATCH_FILE_ENTRIES, ORPHAN_GRACE_PERIOD_SECS, PG_BATCH_CHUNK_SIZE,
    REBALANCE_FETCH_CONCURRENCY, REBALANCE_FETCH_MAX_CONCURRENCY, REBALANCE_FETCH_MIN_CONCURRENCY,
    REBALANCE_FETCH_SCALEUP_THRESHOLD, REBALANCE_MAX_FILES_PER_CYCLE,
};
use crate::state::{
    get_blobs_dir, get_cluster_map, get_orphan_shards, get_validator_endpoint,
    get_validator_reachable,
};
use anyhow::Result;
use common::now_secs;
use iroh::endpoint::Endpoint;
use iroh_blobs::store::fs::FsStore;
use std::str::FromStr;
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use tokio::io::AsyncWriteExt;
use tokio::sync::Semaphore;
use tracing::{debug, error, info, trace, warn};

/// Timeout for reading doc replica blob content (seconds).
const DOC_BLOB_READ_TIMEOUT_SECS: u64 = 5;

/// PG-based self-rebalancing: Calculate which PGs this miner is responsible for,
/// query validator for files in each PG, and pull any missing shards.
///
/// Uses validator P2P as primary source. Falls back to local iroh-doc replica
/// when validator is unreachable, enabling fully offline self-healing.
pub async fn self_rebalance_pg(store: FsStore, endpoint: Endpoint) -> Result<()> {
    // Stability window: defer rebalance if the cluster map epoch changed recently.
    // This prevents acting on a stale or rapidly-changing topology.
    {
        let last_change = crate::state::get_last_epoch_change().read().await;
        let (change_epoch, change_time) = &*last_change;
        if *change_epoch > 0
            && change_time.elapsed()
                < std::time::Duration::from_secs(crate::constants::REBALANCE_STABLE_WINDOW_SECS)
        {
            info!(
                "[REBALANCE] Deferred — epoch {} changed {}s ago, waiting for {}s stability window",
                change_epoch,
                change_time.elapsed().as_secs(),
                crate::constants::REBALANCE_STABLE_WINDOW_SECS,
            );
            return Ok(());
        }
    }

    let validator_reachable = get_validator_reachable().load(std::sync::atomic::Ordering::Relaxed);
    let doc_available = crate::state::get_doc_joined().load(std::sync::atomic::Ordering::Acquire);

    if !validator_reachable && !doc_available {
        debug!("Skipping rebalance: validator not reachable and no doc replica");
        return Ok(());
    }

    if validator_reachable {
        info!("[REBALANCE] Starting — checking shards across assigned PGs");
    } else {
        info!(
            "[REBALANCE] Starting in offline mode — using local doc replica (validator unreachable)"
        );
    }

    // Get miner UID from global (computed once at startup)
    let my_uid = crate::state::get_miner_uid();

    trace!(miner_uid = my_uid, "My miner UID");

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

    // Get validator endpoint for P2P queries (optional when doc replica available)
    let validator_addr = {
        let val_ep = get_validator_endpoint().read().await;
        val_ep.as_ref().cloned()
    };

    if validator_addr.is_none() && !doc_available {
        warn!("No validator endpoint stored and no doc replica, skipping rebalance");
        return Ok(());
    }

    // Snapshot cluster map history for epoch lookback (prevents premature orphan GC).
    // Only keep maps within the EPOCH_LOOKBACK window.
    let history_maps: Vec<Arc<common::ClusterMap>> = {
        let history = crate::state::get_cluster_map_history().read().await;
        let min_epoch = cluster_map.epoch.saturating_sub(EPOCH_LOOKBACK);
        history
            .iter()
            .filter(|m| m.epoch >= min_epoch)
            .cloned()
            .collect()
    };

    // Calculate which PGs we are responsible for (cached by epoch).
    // calculate_my_pgs is CPU-bound (CRUSH over 16,384 PGs) so it
    // runs on spawn_blocking to avoid starving the async runtime.
    let current_epoch = cluster_map.epoch;
    let my_pgs = {
        let cache = crate::state::get_my_pgs_cache();
        let cached = cache.read().await;
        if cached.0 == current_epoch && !cached.1.is_empty() {
            trace!(epoch = current_epoch, "Reusing cached PG assignments");
            cached.1.clone()
        } else {
            drop(cached);
            let map_for_pgs = cluster_map.clone();
            let pgs =
                tokio::task::spawn_blocking(move || common::calculate_my_pgs(my_uid, &map_for_pgs))
                    .await
                    .unwrap_or_else(|e| {
                        error!(error = %e, "PG calculation panicked");
                        Vec::new()
                    });
            let mut cached = cache.write().await;
            *cached = (current_epoch, pgs.clone());
            pgs
        }
    };
    trace!(
        pg_count = my_pgs.len(),
        total_pgs = cluster_map.pg_count,
        "Responsible for PGs"
    );

    // Retry loop: after re-registration the cluster map broadcast may not have
    // arrived yet, so give it up to 60s before skipping this rebalance cycle.
    let my_pgs = if !my_pgs.is_empty() {
        my_pgs
    } else {
        const MAX_WAIT_SECS: u64 = 60;
        const POLL_INTERVAL_SECS: u64 = 5;
        const MAX_ATTEMPTS: u64 = MAX_WAIT_SECS / POLL_INTERVAL_SECS;
        let mut found_pgs = Vec::new();
        for attempt in 1..=MAX_ATTEMPTS {
            warn!(
                attempt,
                max_attempts = MAX_ATTEMPTS,
                "No PGs assigned yet — waiting for cluster map broadcast..."
            );
            tokio::time::sleep(std::time::Duration::from_secs(POLL_INTERVAL_SECS)).await;
            // Re-read cluster map (may have been updated by validator broadcast)
            let updated_map: Arc<common::ClusterMap> = {
                let map_guard = get_cluster_map().read().await;
                match map_guard.as_ref() {
                    Some(map) => map.clone(),
                    None => continue,
                }
            };
            let map_for_pgs = updated_map.clone();
            let pgs =
                tokio::task::spawn_blocking(move || common::calculate_my_pgs(my_uid, &map_for_pgs))
                    .await
                    .unwrap_or_else(|e| {
                        error!(error = %e, "PG calculation panicked during retry");
                        Vec::new()
                    });
            if !pgs.is_empty() {
                // Update cache with fresh result
                let cache = crate::state::get_my_pgs_cache();
                let mut cached = cache.write().await;
                *cached = (updated_map.epoch, pgs.clone());
                found_pgs = pgs;
                break;
            }
        }
        if found_pgs.is_empty() {
            warn!(
                waited_secs = MAX_WAIT_SECS,
                "No PGs assigned after waiting, skipping this rebalance cycle"
            );
            return Ok(());
        }
        found_pgs
    };

    trace!(pgs = ?my_pgs.iter().take(10).collect::<Vec<_>>(), "My PG assignments (first 10)");

    // Pre-build map of locally present hashes and their tags via FsStore API.
    // This is authoritative (unlike directory walks which can miss inlined blobs)
    // and also provides tags for gc_orphan_shards to delete properly.
    let local_hash_tags: std::collections::HashMap<iroh_blobs::Hash, iroh_blobs::api::Tag> = {
        use futures::StreamExt;
        let mut map = std::collections::HashMap::new();
        match store.tags().list().await {
            Ok(mut tag_stream) => {
                while let Some(Ok(tag_info)) = tag_stream.next().await {
                    map.insert(tag_info.hash, tag_info.name);
                }
            }
            Err(e) => {
                error!(error = %e, "Failed to list tags from store");
            }
        }
        trace!(
            local_blobs = map.len(),
            "Built local hash set from FsStore tags"
        );
        map
    };
    let local_hashes: std::collections::HashSet<iroh_blobs::Hash> =
        local_hash_tags.keys().copied().collect();

    let mut missing_shards: usize = 0;
    let mut expected_shards: std::collections::HashSet<iroh_blobs::Hash> =
        std::collections::HashSet::new();
    let mut missing_shard_list: Vec<MissingShard> = Vec::new();
    let mut total_manifest_failures: u32 = 0;
    let mut aborted = false;

    // Try validator path first, fall back to doc replica
    let used_doc_fallback = if validator_reachable && validator_addr.is_some() {
        let validator_addr = validator_addr.as_ref().unwrap();

        let validator_conn = match crate::state::get_pooled_connection(
            &endpoint,
            validator_addr,
            common::VALIDATOR_CONTROL_ALPN,
        )
        .await
        {
            Ok(conn) => Some(conn),
            Err(e) => {
                warn!(error = %e, "Failed to connect to validator for rebalance, trying doc fallback");
                None
            }
        };

        if let Some(validator_conn) = validator_conn {
            // ---- Validator path: query PGs then fetch manifests ----
            let mut pg_files_map: std::collections::HashMap<u32, Vec<String>> =
                std::collections::HashMap::with_capacity(my_pgs.len());
            let read_timeout = std::time::Duration::from_secs(BATCH_RESPONSE_TIMEOUT_SECS);

            debug!(
                pg_count = my_pgs.len(),
                "Querying validator for files in assigned PGs (chunked batch)"
            );

            for chunk in my_pgs.chunks(PG_BATCH_CHUNK_SIZE) {
                let query_msg = common::ValidatorControlMessage::QueryPgFilesBatch {
                    pg_ids: chunk.to_vec(),
                };

                let result: Result<std::collections::HashMap<u32, Vec<String>>> = async {
                    let (mut send, mut recv) = validator_conn.open_bi().await?;
                    let msg_bytes = serde_json::to_vec(&query_msg)?;
                    send.write_all(&msg_bytes).await?;
                    send.flush().await?;
                    send.finish()?;

                    let response_bytes = tokio::time::timeout(
                        read_timeout,
                        recv.read_to_end(MAX_BATCH_PG_RESPONSE_SIZE),
                    )
                    .await
                    .map_err(|_| anyhow::anyhow!("QueryPgFilesBatch read timeout"))??;

                    let files: std::collections::HashMap<u32, Vec<String>> =
                        serde_json::from_slice(&response_bytes)?;

                    let total_entries: usize = files.values().map(|v| v.len()).sum();
                    if total_entries > MAX_PG_BATCH_FILE_ENTRIES {
                        anyhow::bail!(
                            "PG batch response too large: {} file entries (max {})",
                            total_entries,
                            MAX_PG_BATCH_FILE_ENTRIES,
                        );
                    }

                    Ok(files)
                }
                .await;

                match result {
                    Ok(f) => {
                        for (k, v) in f {
                            pg_files_map.insert(k, v);
                        }
                    }
                    Err(e) => {
                        error!(error = %e, "Batch PG chunk query failed");
                    }
                }
            }

            debug!(
                pgs_with_files = pg_files_map.len(),
                "Received batch PG query response"
            );

            let file_entries: Vec<String> = pg_files_map
                .values()
                .flat_map(|files| files.iter().cloned())
                .take(REBALANCE_MAX_FILES_PER_CYCLE)
                .collect();

            // Fetch manifests concurrently (16 parallel QUIC streams on one connection)
            {
                use futures::stream::StreamExt;
                let mut manifest_stream = futures::stream::iter(file_entries.into_iter())
                    .map(|file_hash| {
                        let conn = validator_conn.clone();
                        async move {
                            let result = fetch_manifest_on_conn(&conn, &file_hash).await;
                            (file_hash, result)
                        }
                    })
                    .buffer_unordered(CONCURRENT_MANIFEST_FETCH_STREAMS);

                let mut consecutive_failures: u32 = 0;

                while let Some((file_hash, result)) = manifest_stream.next().await {
                    match result {
                        Ok(Some(manifest)) => {
                            consecutive_failures = 0;
                            tally_manifest_shards(
                                &file_hash,
                                &manifest,
                                my_uid,
                                &cluster_map,
                                &history_maps,
                                &store,
                                &local_hashes,
                                &mut expected_shards,
                                &mut missing_shards,
                                &mut missing_shard_list,
                            )
                            .await;
                        }
                        Ok(None) => {
                            consecutive_failures = 0;
                        }
                        Err(_) => {
                            total_manifest_failures += 1;
                            consecutive_failures += 1;
                            if consecutive_failures >= MAX_CONSECUTIVE_MANIFEST_FAILURES {
                                aborted = true;
                                break;
                            }
                        }
                    }
                }
            }

            // If too many failures, try doc fallback for remaining work
            aborted && doc_available
        } else {
            // Connection failed, try doc fallback
            doc_available
        }
    } else {
        // Validator not reachable, use doc
        doc_available
    };

    // ---- Doc replica fallback / offline mode ----
    if used_doc_fallback {
        info!(
            "[REBALANCE] Using local doc replica for manifest discovery (validator unreachable or too many failures)"
        );
        let my_pgs_set: std::collections::HashSet<u32> = my_pgs.iter().copied().collect();

        match fetch_file_hashes_from_doc(&cluster_map, &my_pgs_set).await {
            Ok(file_hashes) => {
                debug!(
                    file_count = file_hashes.len(),
                    "Discovered files from doc replica for our PGs"
                );

                let file_hashes: Vec<String> = file_hashes
                    .into_iter()
                    .take(REBALANCE_MAX_FILES_PER_CYCLE)
                    .collect();

                for file_hash in &file_hashes {
                    match fetch_manifest_from_doc(file_hash).await {
                        Some(manifest) => {
                            tally_manifest_shards(
                                file_hash,
                                &manifest,
                                my_uid,
                                &cluster_map,
                                &history_maps,
                                &store,
                                &local_hashes,
                                &mut expected_shards,
                                &mut missing_shards,
                                &mut missing_shard_list,
                            )
                            .await;
                        }
                        None => {
                            total_manifest_failures += 1;
                        }
                    }
                }
            }
            Err(e) => {
                error!(error = %e, "Failed to fetch file hashes from doc replica");
            }
        }
    }

    if total_manifest_failures > 0 {
        warn!(
            manifest_failures = total_manifest_failures,
            aborted = aborted,
            "Manifest fetch failures during rebalance"
        );
    }

    // Concurrently fetch missing shards from peers
    let shards_fetched = if !missing_shard_list.is_empty() {
        fetch_missing_shards(missing_shard_list, &store, &endpoint).await
    } else {
        0
    };

    // Adjust counts: fetched shards are no longer missing
    missing_shards = missing_shards.saturating_sub(shards_fetched);

    let verified = expected_shards.len().saturating_sub(missing_shards);
    if missing_shards > 0 {
        let pct = if expected_shards.is_empty() {
            0
        } else {
            verified * 100 / expected_shards.len()
        };
        info!(
            "[REBALANCE] {}/{} shards present ({}%) — {} missing, reported to validator for recovery",
            verified,
            expected_shards.len(),
            pct,
            missing_shards,
        );
    } else {
        info!(
            "[REBALANCE] Complete — all {} shards verified ✓",
            expected_shards.len(),
        );
    }

    // GC: Identify orphan shards, delete tags and files after grace period
    gc_orphan_shards(&expected_shards, &local_hash_tags, &store).await;
    Ok(())
}

/// Info about a shard that is missing locally and should be fetched from a peer.
struct MissingShard {
    /// Hash of the missing shard blob.
    shard_hash: iroh_blobs::Hash,
    /// Hex string blob hash for FetchBlob P2P requests.
    blob_hash_str: String,
    /// Peers that may hold this shard (from current and historical placements).
    peer_endpoints: Vec<iroh::EndpointAddr>,
}

/// Walk a manifest and tally which shards this miner should hold,
/// tracking expected and missing shards.
///
/// Uses epoch lookback: shards assigned to this miner under any historical
/// cluster map (within EPOCH_LOOKBACK window) are added to `expected_shards`
/// to prevent premature orphan GC during rebalancing transitions.
///
/// Uses loopback: before counting a shard as missing, checks if the blob
/// exists in the local iroh_blobs store (it may be present without a tag).
///
/// Missing shards are collected into `missing_shard_list` for concurrent fetching.
async fn tally_manifest_shards(
    file_hash: &str,
    manifest: &common::FileManifest,
    my_uid: u32,
    cluster_map: &common::ClusterMap,
    history_maps: &[Arc<common::ClusterMap>],
    store: &FsStore,
    local_hashes: &std::collections::HashSet<iroh_blobs::Hash>,
    expected_shards: &mut std::collections::HashSet<iroh_blobs::Hash>,
    missing_shards: &mut usize,
    missing_shard_list: &mut Vec<MissingShard>,
) {
    let shards_per_stripe = manifest.stripe_config.k + manifest.stripe_config.m;
    let num_stripes = manifest.shards.len().div_ceil(shards_per_stripe);

    for stripe_idx in 0..num_stripes {
        let stripe_miners = match common::calculate_stripe_placement(
            file_hash,
            stripe_idx as u64,
            shards_per_stripe,
            cluster_map,
            manifest.placement_version,
        ) {
            Ok(m) => m,
            Err(_) => continue,
        };

        for local_idx in 0..shards_per_stripe {
            let global_idx = stripe_idx * shards_per_stripe + local_idx;
            if global_idx >= manifest.shards.len() {
                continue;
            }

            let shard = &manifest.shards[global_idx];
            let shard_hash = if let Ok(h) = iroh_blobs::Hash::from_str(&shard.blob_hash) {
                h
            } else {
                continue;
            };

            // Check current epoch placement
            let mine_current = stripe_miners
                .get(local_idx)
                .is_some_and(|m| m.uid == my_uid);

            // Check historical epoch placements (epoch lookback)
            let mine_historical = if !mine_current {
                history_maps.iter().any(|hist_map| {
                    common::calculate_stripe_placement(
                        file_hash,
                        stripe_idx as u64,
                        shards_per_stripe,
                        hist_map,
                        manifest.placement_version,
                    )
                    .ok()
                    .and_then(|miners| miners.get(local_idx).cloned())
                    .is_some_and(|m| m.uid == my_uid)
                })
            } else {
                false
            };

            if mine_current || mine_historical {
                expected_shards.insert(shard_hash);

                // Only count missing shards for current-epoch placement
                if mine_current && !local_hashes.contains(&shard_hash) {
                    // Loopback: check if blob exists in store without a tag
                    if store.blobs().has(shard_hash).await.unwrap_or(false) {
                        let hash_str = shard_hash.to_string();
                        info!(
                            "[REBALANCE] Shard {} found locally (loopback)",
                            &hash_str[..8.min(hash_str.len())]
                        );
                    } else {
                        *missing_shards += 1;

                        // Collect peers that might hold this shard:
                        // other miners in the same stripe position from current
                        // and historical epochs (the previous holder likely
                        // still has it during the orphan grace period).
                        let mut peers = Vec::new();
                        // Historical placements: the miner that held this
                        // position in a previous epoch likely still has it.
                        for hist_map in history_maps {
                            if let Ok(hist_miners) = common::calculate_stripe_placement(
                                file_hash,
                                stripe_idx as u64,
                                shards_per_stripe,
                                hist_map,
                                manifest.placement_version,
                            ) {
                                if let Some(m) = hist_miners.get(local_idx) {
                                    if m.uid != my_uid && common::has_direct_addr(&m.endpoint) {
                                        peers.push(m.endpoint.clone());
                                    }
                                }
                            }
                        }
                        // Current placement peers at the SAME stripe position
                        // in other stripes won't help (different shard), but
                        // other miners in the SAME stripe might have a copy
                        // if they held this position before.
                        // Also try all other stripe miners as FetchBlob sources
                        // (they may have the blob from a previous assignment).
                        for (i, m) in stripe_miners.iter().enumerate() {
                            if i != local_idx
                                && m.uid != my_uid
                                && common::has_direct_addr(&m.endpoint)
                            {
                                peers.push(m.endpoint.clone());
                            }
                        }
                        // Deduplicate by node_id
                        peers.dedup_by(|a, b| a.id == b.id);

                        missing_shard_list.push(MissingShard {
                            shard_hash,
                            blob_hash_str: shard.blob_hash.clone(),
                            peer_endpoints: peers,
                        });
                    }
                }
            }
        }
    }
}

/// Concurrently fetch missing shards from peer miners with adaptive throttling.
///
/// Uses a local semaphore (separate from `fetch_sem` used for inbound FetchBlob)
/// to bound concurrency. Starts at `REBALANCE_FETCH_CONCURRENCY` and adapts:
/// - On timeout/failure: reduce concurrency by 1 (floor: `REBALANCE_FETCH_MIN_CONCURRENCY`)
/// - On `REBALANCE_FETCH_SCALEUP_THRESHOLD` consecutive successes: increase by 1
///   (ceiling: `REBALANCE_FETCH_MAX_CONCURRENCY`)
///
/// Returns the number of shards successfully fetched.
async fn fetch_missing_shards(
    missing: Vec<MissingShard>,
    store: &FsStore,
    endpoint: &Endpoint,
) -> usize {
    if missing.is_empty() {
        return 0;
    }

    let total = missing.len();
    let concurrency = Arc::new(AtomicUsize::new(REBALANCE_FETCH_CONCURRENCY));
    let consecutive_ok = Arc::new(AtomicUsize::new(0));
    let fetched = Arc::new(AtomicUsize::new(0));

    // Local semaphore — separate from the inbound fetch_sem
    let sem = Arc::new(Semaphore::new(REBALANCE_FETCH_CONCURRENCY));

    let connect_timeout =
        std::time::Duration::from_secs(crate::constants::REBALANCE_PEER_CONNECT_TIMEOUT_SECS);
    let read_timeout = std::time::Duration::from_secs(crate::constants::DEFAULT_READ_TIMEOUT_SECS);

    info!(
        "[REBALANCE] Fetching {total} missing shards (concurrency={})",
        REBALANCE_FETCH_CONCURRENCY,
    );

    let mut join_set = tokio::task::JoinSet::new();

    for shard in missing {
        let sem = sem.clone();
        let concurrency = concurrency.clone();
        let consecutive_ok = consecutive_ok.clone();
        let fetched = fetched.clone();
        let store = store.clone();
        let endpoint = endpoint.clone();

        join_set.spawn(async move {
            // Acquire permit from the local rebalance semaphore
            let _permit = sem.acquire().await.expect("semaphore closed");

            let hash_short = &shard.shard_hash.to_string()[..12];

            // Try each peer until one succeeds
            let mut success = false;
            for peer_addr in &shard.peer_endpoints {
                if !common::has_direct_addr(peer_addr) {
                    continue;
                }

                let conn = match tokio::time::timeout(
                    connect_timeout,
                    crate::state::get_pooled_connection(
                        &endpoint,
                        peer_addr,
                        common::MINER_CONTROL_ALPN,
                    ),
                )
                .await
                {
                    Ok(Ok(c)) => c,
                    _ => continue,
                };

                let request = common::MinerControlMessage::FetchBlob {
                    hash: shard.blob_hash_str.clone(),
                };
                let request_bytes = match serde_json::to_vec(&request) {
                    Ok(b) => b,
                    Err(_) => continue,
                };

                let fetch_result: Result<Option<Vec<u8>>> = async {
                    let (mut send, mut recv) = conn.open_bi().await?;
                    send.write_all(&request_bytes).await?;
                    send.finish()?;
                    let response = tokio::time::timeout(
                        read_timeout,
                        recv.read_to_end(crate::constants::MAX_FETCH_RESPONSE_SIZE),
                    )
                    .await
                    .map_err(|_| anyhow::anyhow!("Read timeout"))??;

                    if response.starts_with(b"DATA:") {
                        Ok(Some(response[5..].to_vec()))
                    } else {
                        Ok(None)
                    }
                }
                .await;

                match fetch_result {
                    Ok(Some(data)) => {
                        // Store the fetched shard
                        match store.add_bytes(bytes::Bytes::from(data)).await {
                            Ok(outcome) => {
                                if outcome.hash == shard.shard_hash {
                                    crate::state::tag_map_insert(outcome.hash, outcome.name);
                                    success = true;
                                    debug!(
                                        shard = hash_short,
                                        "[REBALANCE] Fetched shard from peer"
                                    );
                                    break;
                                } else {
                                    // Hash mismatch — delete and try next peer
                                    let _ = store.tags().delete(&outcome.name).await;
                                    warn!(
                                        shard = hash_short,
                                        "[REBALANCE] Shard hash mismatch from peer"
                                    );
                                }
                            }
                            Err(e) => {
                                warn!(
                                    error = %e,
                                    shard = hash_short,
                                    "[REBALANCE] Failed to store fetched shard"
                                );
                            }
                        }
                    }
                    Ok(None) => {
                        // Peer doesn't have it, try next
                        continue;
                    }
                    Err(_) => {
                        // Timeout or error — adaptive: reduce concurrency
                        let cur = concurrency.load(Ordering::Relaxed);
                        if cur > REBALANCE_FETCH_MIN_CONCURRENCY {
                            let new = cur.saturating_sub(1).max(REBALANCE_FETCH_MIN_CONCURRENCY);
                            concurrency.store(new, Ordering::Relaxed);
                            // Shrink the semaphore by forgetting a permit
                            if let Ok(p) = sem.try_acquire() {
                                p.forget();
                                debug!(
                                    new_concurrency = new,
                                    "[REBALANCE] Reduced fetch concurrency (timeout)"
                                );
                            }
                        }
                        consecutive_ok.store(0, Ordering::Relaxed);
                        continue;
                    }
                }
            }

            if success {
                fetched.fetch_add(1, Ordering::Relaxed);
                let streak = consecutive_ok.fetch_add(1, Ordering::Relaxed) + 1;
                // Adaptive scale-up after consecutive successes
                if streak >= REBALANCE_FETCH_SCALEUP_THRESHOLD {
                    consecutive_ok.store(0, Ordering::Relaxed);
                    let cur = concurrency.load(Ordering::Relaxed);
                    if cur < REBALANCE_FETCH_MAX_CONCURRENCY {
                        let new = (cur + 1).min(REBALANCE_FETCH_MAX_CONCURRENCY);
                        concurrency.store(new, Ordering::Relaxed);
                        // Grow the semaphore by adding a permit
                        sem.add_permits(1);
                        debug!(
                            new_concurrency = new,
                            "[REBALANCE] Increased fetch concurrency (streak)"
                        );
                    }
                }
            } else {
                consecutive_ok.store(0, Ordering::Relaxed);
            }
        });
    }

    // Await all tasks
    while let Some(result) = join_set.join_next().await {
        if let Err(e) = result {
            warn!(error = %e, "[REBALANCE] Fetch task panicked");
        }
    }

    let total_fetched = fetched.load(Ordering::Relaxed);
    let final_concurrency = concurrency.load(Ordering::Relaxed);
    info!(
        "[REBALANCE] Fetched {total_fetched}/{total} missing shards (final concurrency={final_concurrency})",
    );
    total_fetched
}

/// Fetch a single manifest from the local iroh-doc replica.
///
/// The doc stores manifests with key = file_hash bytes (hex string),
/// value = bincode-serialized DocManifest.
async fn fetch_manifest_from_doc(file_hash: &str) -> Option<common::FileManifest> {
    use tokio::io::AsyncReadExt;

    let doc_guard = crate::state::get_doc_replica().read().await;
    let doc = doc_guard.as_ref()?;

    let blobs_guard = crate::state::get_doc_replica_blobs().read().await;
    let blobs = blobs_guard.as_ref()?;

    let query = iroh_docs::store::Query::single_latest_per_key().key_exact(file_hash.as_bytes());
    let entry = match doc.get_one(query).await {
        Ok(Some(entry)) => entry,
        Ok(None) => return None,
        Err(e) => {
            debug!(error = %e, hash = %&file_hash[..8.min(file_hash.len())], "Doc replica query failed");
            return None;
        }
    };

    let mut reader = blobs.reader(entry.content_hash());
    let mut content = Vec::new();
    let read_result = tokio::time::timeout(
        std::time::Duration::from_secs(DOC_BLOB_READ_TIMEOUT_SECS),
        reader.read_to_end(&mut content),
    )
    .await;

    if !matches!(read_result, Ok(Ok(_))) {
        debug!(hash = %&file_hash[..8.min(file_hash.len())], "Doc replica blob read failed or timed out");
        return None;
    }

    let doc_manifest = match common::doc_manifest_from_bytes(&content) {
        Ok(m) => m,
        Err(e) => {
            debug!(error = %e, hash = %&file_hash[..8.min(file_hash.len())], "Doc replica manifest deserialization failed");
            return None;
        }
    };

    // Detect accumulated manifests (multiple re-uploads appended rather than replaced)
    let sps = doc_manifest.stripe_config.k + doc_manifest.stripe_config.m;
    let expected_stripes = if doc_manifest.size == 0 {
        1usize
    } else {
        let stripe_data = doc_manifest.stripe_config.size as usize * doc_manifest.stripe_config.k;
        doc_manifest.size.div_ceil(stripe_data as u64) as usize
    };
    if doc_manifest.shards.len() > expected_stripes * sps {
        warn!(
            hash = %&file_hash[..8.min(file_hash.len())],
            "Doc replica has accumulated manifest — skipping"
        );
        return None;
    }

    Some(common::FileManifest::from(doc_manifest))
}

/// Discover all file hashes from the doc replica that belong to our PGs.
///
/// Iterates all manifest entries in the doc, computes PG for each file hash,
/// and returns those matching the miner's assigned PGs.
async fn fetch_file_hashes_from_doc(
    cluster_map: &common::ClusterMap,
    my_pgs: &std::collections::HashSet<u32>,
) -> Result<Vec<String>> {
    use futures::StreamExt;

    let doc_guard = crate::state::get_doc_replica().read().await;
    let doc = doc_guard
        .as_ref()
        .ok_or_else(|| anyhow::anyhow!("Doc replica not available"))?;

    let query = iroh_docs::store::Query::single_latest_per_key();
    let stream = doc.get_many(query).await?;
    tokio::pin!(stream);

    let mut file_hashes = Vec::new();
    while let Some(Ok(entry)) = stream.next().await {
        let key = entry.key();
        // Skip non-manifest keys (e.g. "map:{epoch}" for cluster maps)
        // Manifest keys are 64-char hex file hashes
        if key.len() != 64 || key.iter().any(|b| !b.is_ascii_hexdigit()) {
            continue;
        }

        let file_hash = match std::str::from_utf8(key) {
            Ok(s) => s.to_string(),
            Err(_) => continue,
        };

        // Check if this file's PG is one we're responsible for
        let pg = match common::calculate_pg(&file_hash, cluster_map.pg_count) {
            Ok(pg) => pg,
            Err(_) => continue,
        };
        if my_pgs.contains(&pg) {
            file_hashes.push(file_hash);
        }
    }

    Ok(file_hashes)
}

/// Garbage collect orphan shards.
///
/// Uses the pre-built `local_hash_tags` map from the rebalance tag listing.
/// Deletes orphans by removing both the FsStore tag (so the blob becomes
/// eligible for store-level GC) and the on-disk data file.
async fn gc_orphan_shards(
    expected_shards: &std::collections::HashSet<iroh_blobs::Hash>,
    local_hash_tags: &std::collections::HashMap<iroh_blobs::Hash, iroh_blobs::api::Tag>,
    store: &FsStore,
) {
    let now = now_secs();

    // Guard: if clock skew detected, skip GC entirely
    if now == 0 {
        warn!("Clock skew detected (now_secs=0), skipping orphan GC");
        return;
    }

    // Get blobs directory for file deletion paths
    let blobs_path = {
        let bd = get_blobs_dir().read().await;
        bd.clone()
    };

    let Some(blobs_dir) = blobs_path else {
        return;
    };
    let data_dir = blobs_dir.join("data");

    let mut orphan_count = 0;
    let mut deleted_count = 0;
    let mut kept_count = 0;
    let mut skipped_at_capacity = 0u64;
    let mut tag_delete_failures = 0u32;
    let mut file_delete_failures = 0u32;

    // Use DashMap for lock-free orphan tracking
    let orphan_map = get_orphan_shards();

    // Iterate over pre-built local hash/tag map (no directory walk needed)
    for (blob_hash, tag) in local_hash_tags {
        if expected_shards.contains(blob_hash) {
            // This is expected - remove from orphan tracking
            orphan_map.remove(blob_hash);
            kept_count += 1;
        } else {
            // Potential orphan
            orphan_count += 1;
            let hash_str = blob_hash.to_string();

            if let Some(orphan_entry) = orphan_map.get(blob_hash) {
                let first_seen = *orphan_entry;
                drop(orphan_entry);

                // Guard: if now < first_seen, entry is corrupted
                if now < first_seen {
                    orphan_map.remove(blob_hash);
                    continue;
                }

                // Check if grace period expired
                if now - first_seen > ORPHAN_GRACE_PERIOD_SECS {
                    let mut removed = false;

                    // Delete the tag first so the blob becomes eligible for store-level GC
                    match store.tags().delete(tag).await {
                        Ok(_) => {
                            removed = true;
                            // Also remove from TAG_MAP cache
                            crate::state::get_tag_map().remove(blob_hash);
                        }
                        Err(_) => {
                            tag_delete_failures += 1;
                        }
                    }

                    // Best-effort remove data file from disk
                    let p1 = data_dir.join(format!("{}.data", hash_str));
                    let p2 = data_dir.join(&hash_str);
                    for p in [p1, p2] {
                        match tokio::fs::remove_file(&p).await {
                            Ok(()) => {
                                removed = true;
                                break;
                            }
                            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
                            Err(_) => {
                                file_delete_failures += 1;
                            }
                        }
                    }

                    if removed {
                        deleted_count += 1;
                        orphan_map.remove(blob_hash);
                    }
                }
                // else: still in grace period, keep tracking
            } else {
                // New orphan - start tracking with timestamp
                // Bound orphan map size to prevent unbounded memory growth
                if orphan_map.len() < MAX_ORPHAN_ENTRIES {
                    orphan_map.insert(*blob_hash, now);
                } else {
                    skipped_at_capacity += 1;
                }
            }
        }
    }

    if skipped_at_capacity > 0 {
        warn!(
            capacity = MAX_ORPHAN_ENTRIES,
            skipped = skipped_at_capacity,
            "Orphan map at capacity, skipped tracking new orphans"
        );
    }

    if tag_delete_failures > 0 || file_delete_failures > 0 {
        warn!(
            tag_delete_failures,
            file_delete_failures, "Orphan GC encountered delete errors"
        );
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

/// Fetch manifest using an existing P2P connection (opens a new bidi stream).
///
/// Reuses the connection instead of creating one per file, avoiding
/// connection storms that overwhelm the validator.
async fn fetch_manifest_on_conn(
    conn: &iroh::endpoint::Connection,
    file_hash: &str,
) -> Result<Option<common::FileManifest>> {
    let query_msg = common::ValidatorControlMessage::QueryManifest {
        file_hash: file_hash.to_string(),
    };

    let (mut send, mut recv) = tokio::time::timeout(
        std::time::Duration::from_secs(MANIFEST_STREAM_OPEN_TIMEOUT_SECS),
        conn.open_bi(),
    )
    .await
    .map_err(|_| anyhow::anyhow!("Stream open timeout"))??;

    let msg_bytes = serde_json::to_vec(&query_msg)?;
    send.write_all(&msg_bytes).await?;
    send.finish()?;

    let response_bytes = tokio::time::timeout(
        std::time::Duration::from_secs(MANIFEST_READ_TIMEOUT_SECS),
        recv.read_to_end(MANIFEST_RESPONSE_MAX_SIZE),
    )
    .await
    .map_err(|_| anyhow::anyhow!("Read timeout fetching manifest"))??;

    if response_bytes == b"NOT_FOUND" {
        return Ok(None);
    }
    if response_bytes == b"WARMING_UP" {
        return Err(anyhow::anyhow!("Validator still warming up"));
    }

    let manifest: common::FileManifest = serde_json::from_slice(&response_bytes)?;
    Ok(Some(manifest))
}

/// File name for the persisted cluster map cache.
const CLUSTER_MAP_CACHE_FILE: &str = "cluster_map_cache.json";

/// Persist the cluster map to `{data_dir}/cluster_map_cache.json` so it survives restarts.
pub async fn persist_cluster_map(map: &common::ClusterMap) {
    let Some(data_dir) = crate::state::get_data_dir() else {
        return;
    };
    let path = data_dir.join(CLUSTER_MAP_CACHE_FILE);
    match serde_json::to_string(map) {
        Ok(json) => {
            if let Err(e) = tokio::fs::write(&path, json.as_bytes()).await {
                warn!(error = %e, "Failed to persist cluster map cache to disk");
            } else {
                debug!(epoch = map.epoch, path = %path.display(), "Persisted cluster map cache");
            }
        }
        Err(e) => {
            warn!(error = %e, "Failed to serialize cluster map for disk cache");
        }
    }
}

/// Load cluster map from `{data_dir}/cluster_map_cache.json` if it exists.
/// Returns `None` if the file doesn't exist or fails to parse.
pub async fn load_cluster_map_cache(data_dir: &std::path::Path) -> Option<common::ClusterMap> {
    let path = data_dir.join(CLUSTER_MAP_CACHE_FILE);
    let bytes = match tokio::fs::read(&path).await {
        Ok(b) => b,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return None,
        Err(e) => {
            warn!(error = %e, "Failed to read cluster map cache from disk");
            return None;
        }
    };
    match serde_json::from_slice::<common::ClusterMap>(&bytes) {
        Ok(map) => Some(map),
        Err(e) => {
            warn!(error = %e, "Failed to parse cluster map cache from disk");
            None
        }
    }
}

/// Attempt to reconstruct a missing shard using erasure coding.
///
/// Fetches sibling shards from other miners in the same stripe and uses
/// Reed-Solomon decoding to reconstruct all shards, then stores the target.
///
/// Returns `Ok(true)` if the shard was successfully reconstructed and stored,
/// `Ok(false)` if not enough sibling shards were available (< k).
#[allow(dead_code)]
pub async fn reconstruct_shard(
    shard_hash: iroh_blobs::Hash,
    shard_index: usize,
    stripe_index: u64,
    manifest: &common::FileManifest,
    store: &FsStore,
    endpoint: &Endpoint,
    fetch_sem: &Arc<Semaphore>,
) -> Result<bool> {
    let shards_per_stripe = manifest.stripe_config.k + manifest.stripe_config.m;
    let k = manifest.stripe_config.k;

    // 1. Get all shard hashes for this stripe from the manifest (30 shards per stripe)
    let stripe_start = stripe_index as usize * shards_per_stripe;
    let stripe_end = (stripe_start + shards_per_stripe).min(manifest.shards.len());
    if stripe_end - stripe_start != shards_per_stripe {
        warn!(
            stripe = stripe_index,
            expected = shards_per_stripe,
            got = stripe_end - stripe_start,
            "[REBALANCE] Incomplete stripe in manifest, cannot reconstruct"
        );
        return Ok(false);
    }
    let stripe_shards = &manifest.shards[stripe_start..stripe_end];

    // 2. Check which ones are stored locally first (loopback)
    let mut shard_data: Vec<Option<Vec<u8>>> = vec![None; shards_per_stripe];
    let mut available_count: usize = 0;

    for (i, shard_info) in stripe_shards.iter().enumerate() {
        let hash = match iroh_blobs::Hash::from_str(&shard_info.blob_hash) {
            Ok(h) => h,
            Err(_) => continue,
        };
        match store.get_bytes(hash).await {
            Ok(data) if !data.is_empty() => {
                shard_data[i] = Some(data.to_vec());
                available_count += 1;
            }
            _ => {}
        }
    }

    // Early exit if we already have the target shard locally
    if shard_data[shard_index].is_some() {
        debug!(
            shard = %&shard_hash.to_string()[..12],
            "[REBALANCE] Target shard already present locally"
        );
        return Ok(true);
    }

    // 3. Fetch missing ones from peers until we have k=10
    if available_count < k {
        let cluster_map: Arc<common::ClusterMap> = {
            let map_guard = crate::state::get_cluster_map().read().await;
            match map_guard.as_ref() {
                Some(map) => map.clone(),
                None => return Ok(false),
            }
        };

        let stripe_miners = match common::calculate_stripe_placement(
            &manifest.file_hash,
            stripe_index,
            shards_per_stripe,
            &cluster_map,
            manifest.placement_version,
        ) {
            Ok(m) => m,
            Err(e) => {
                warn!(error = %e, "[REBALANCE] Failed to calculate stripe placement for reconstruction");
                return Ok(false);
            }
        };

        let connect_timeout =
            std::time::Duration::from_secs(crate::constants::RECONSTRUCT_PEER_CONNECT_TIMEOUT_SECS);
        let read_timeout =
            std::time::Duration::from_secs(crate::constants::RECONSTRUCT_PEER_READ_TIMEOUT_SECS);

        for (i, shard_info) in stripe_shards.iter().enumerate() {
            if available_count >= k {
                break;
            }
            if shard_data[i].is_some() {
                continue;
            }

            // Get the miner assigned to this shard via CRUSH
            let miner = match stripe_miners.get(i) {
                Some(m) => m,
                None => continue,
            };

            // Skip relay-only miners
            if !common::has_direct_addr(&miner.endpoint) {
                continue;
            }

            // Acquire fetch semaphore permit (bounds concurrency)
            let _permit = match fetch_sem.clone().try_acquire_owned() {
                Ok(p) => p,
                Err(_) => continue,
            };

            // Connect and fetch via FetchBlob P2P protocol
            let conn = match tokio::time::timeout(
                connect_timeout,
                crate::state::get_pooled_connection(
                    endpoint,
                    &miner.endpoint,
                    common::MINER_CONTROL_ALPN,
                ),
            )
            .await
            {
                Ok(Ok(c)) => c,
                _ => continue,
            };

            let request = common::MinerControlMessage::FetchBlob {
                hash: shard_info.blob_hash.clone(),
            };
            let request_bytes = match serde_json::to_vec(&request) {
                Ok(b) => b,
                Err(_) => continue,
            };

            let fetch_result: Result<Option<Vec<u8>>> = async {
                let (mut send, mut recv) = conn.open_bi().await?;
                send.write_all(&request_bytes).await?;
                send.finish()?;
                let response = tokio::time::timeout(
                    read_timeout,
                    recv.read_to_end(crate::constants::MAX_FETCH_RESPONSE_SIZE),
                )
                .await
                .map_err(|_| anyhow::anyhow!("Read timeout"))??;

                if response.starts_with(b"DATA:") {
                    Ok(Some(response[5..].to_vec()))
                } else {
                    Ok(None)
                }
            }
            .await;

            if let Ok(Some(data)) = fetch_result {
                shard_data[i] = Some(data);
                available_count += 1;
            }
        }
    }

    if available_count < k {
        warn!(
            available = available_count,
            needed = k,
            stripe = stripe_index,
            shard = %&shard_hash.to_string()[..12],
            "[REBALANCE] Not enough shards for erasure reconstruction"
        );
        return Ok(false);
    }

    // 4. Call decode_stripe() to reconstruct all shards
    let stripe_data_len =
        common::calculate_stripe_data_len(manifest.size, stripe_index, manifest.stripe_config.size);

    if let Err(e) = common::decode_stripe(&mut shard_data, &manifest.stripe_config, stripe_data_len)
    {
        warn!(
            error = %e,
            stripe = stripe_index,
            "[REBALANCE] Erasure decode failed"
        );
        return Ok(false);
    }

    // 5. Store the reconstructed target shard via store.add_bytes()
    let reconstructed = match &shard_data[shard_index] {
        Some(data) => data.clone(),
        None => {
            warn!(
                shard_index,
                "[REBALANCE] Target shard still None after reconstruction"
            );
            return Ok(false);
        }
    };

    let outcome = store
        .add_bytes(bytes::Bytes::from(reconstructed))
        .await
        .map_err(|e| anyhow::anyhow!("Failed to store reconstructed shard: {}", e))?;

    // Verify stored hash matches expected
    if outcome.hash != shard_hash {
        warn!(
            expected = %&shard_hash.to_string()[..12],
            stored = %&outcome.hash.to_string()[..12],
            "[REBALANCE] Reconstructed shard hash mismatch"
        );
        let _ = store.tags().delete(&outcome.name).await;
        return Ok(false);
    }

    // Track tag for O(1) delete lookup
    crate::state::tag_map_insert(outcome.hash, outcome.name);

    // 6. Return Ok(true) if successful
    info!(
        shard = %&shard_hash.to_string()[..12],
        stripe = stripe_index,
        peers_used = available_count,
        "[REBALANCE] Reconstructed shard via erasure (used {} peers)",
        available_count,
    );

    Ok(true)
}

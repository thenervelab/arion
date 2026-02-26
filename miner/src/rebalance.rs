//! Self-rebalancing logic for the miner.
//!
//! Runs on a configurable tick (default 300s) with startup jitter to
//! desynchronize miners. Each cycle:
//!
//! 1. **PG calculation**: Compute which Placement Groups this miner is
//!    responsible for using CRUSH over the current cluster map (cached by epoch).
//! 2. **Manifest fetch**: Query the validator for all files in those PGs
//!    via chunked `QueryPgFilesBatch` requests (500 PGs per chunk).
//! 3. **Shard verification**: For each file, fetch the manifest and walk
//!    stripes to identify shards this miner should hold (CRUSH placement
//!    with stripe rotation). Compare against a pre-built set of locally
//!    present blobs (directory walk, O(1) lookups).
//! 4. **Orphan GC**: Any local blob not in the expected set is tracked as
//!    an orphan. After a 1-hour grace period, orphans are deleted from disk.
//!
//! Missing shards are only logged — the validator handles migration via
//! `PullFromPeer` commands. The miner does not self-heal.

use crate::constants::{
    MAX_BATCH_PG_RESPONSE_SIZE, MAX_ORPHAN_ENTRIES, ORPHAN_GRACE_PERIOD_SECS,
    REBALANCE_MAX_FILES_PER_CYCLE,
};
use crate::helpers::truncate_for_log;
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
use tracing::{debug, error, info, trace, warn};

/// PG-based self-rebalancing: Calculate which PGs this miner is responsible for,
/// query validator for files in each PG, and pull any missing shards
pub async fn self_rebalance_pg(store: FsStore, endpoint: Endpoint) -> Result<()> {
    if !get_validator_reachable().load(std::sync::atomic::Ordering::Relaxed) {
        debug!("Skipping rebalance: validator not reachable");
        return Ok(());
    }

    info!("Starting PG-based self-rebalance");

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

    // Calculate which PGs we are responsible for (cached by epoch)
    let current_epoch = cluster_map.epoch;
    let my_pgs = {
        let cache = crate::state::get_my_pgs_cache();
        let cached = cache.read().await;
        if cached.0 == current_epoch && !cached.1.is_empty() {
            trace!(epoch = current_epoch, "Reusing cached PG assignments");
            cached.1.clone()
        } else {
            drop(cached);
            let pgs = common::calculate_my_pgs(my_uid, &cluster_map);
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

    if my_pgs.is_empty() {
        warn!("No PGs assigned to this miner");
        return Ok(());
    }

    trace!(pgs = ?my_pgs.iter().take(10).collect::<Vec<_>>(), "My PG assignments (first 10)");

    // Query validator for files in ALL our PGs in a single batch request
    let mut missing_shards = 0;
    let mut expected_shards: std::collections::HashSet<iroh_blobs::Hash> =
        std::collections::HashSet::new();

    // Build overall map for the file responses
    let mut pg_files_map: std::collections::HashMap<u32, Vec<String>> =
        std::collections::HashMap::with_capacity(my_pgs.len());

    // Single P2P connection for both PG queries and manifest fetches.
    // QUIC natively multiplexes streams on one connection.
    // Reuses the pooled validator connection to avoid extra QUIC handshakes.
    let read_timeout = std::time::Duration::from_secs(60); // Longer timeout for batch response

    let validator_conn = match crate::state::get_pooled_connection(
        &endpoint,
        &validator_addr,
        b"hippius/validator-control",
    )
    .await
    {
        Ok(conn) => conn,
        Err(e) => {
            error!(error = %e, "Failed to connect to validator for rebalance");
            return Ok(());
        }
    };

    debug!(
        pg_count = my_pgs.len(),
        "Querying validator for files in assigned PGs (chunked batch)"
    );

    // Process PGs in chunks to prevent validator OOM
    // 500 PGs * ~17 files/PG * 64 bytes/hash ≈ 544 KB per chunk (very safe)
    for chunk in my_pgs.chunks(500) {
        let query_msg = common::ValidatorControlMessage::QueryPgFilesBatch {
            pg_ids: chunk.to_vec(),
        };

        let result: Result<std::collections::HashMap<u32, Vec<String>>> = async {
            let (mut send, mut recv) = validator_conn.open_bi().await?;
            let msg_bytes = serde_json::to_vec(&query_msg)?;
            send.write_all(&msg_bytes).await?;
            send.finish()?;

            // Buffer for batch response
            let response_bytes =
                tokio::time::timeout(read_timeout, recv.read_to_end(MAX_BATCH_PG_RESPONSE_SIZE))
                    .await
                    .map_err(|_| anyhow::anyhow!("QueryPgFilesBatch read timeout"))??;

            let files: std::collections::HashMap<u32, Vec<String>> =
                serde_json::from_slice(&response_bytes)?;

            // Validate deserialized size to prevent memory exhaustion
            let total_entries: usize = files.values().map(|v| v.len()).sum();
            if total_entries > 100_000 {
                anyhow::bail!(
                    "PG batch response too large: {} file entries (max 100000)",
                    total_entries
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

    // Reuse the same validator connection for manifest fetches.
    let total_files: usize = pg_files_map.values().map(|v| v.len()).sum();
    let file_entries: Vec<String> = pg_files_map
        .values()
        .flat_map(|files| files.iter().cloned())
        .take(REBALANCE_MAX_FILES_PER_CYCLE)
        .collect();
    let files_processed = file_entries.len();
    {
        // Fetch manifests concurrently (16 parallel QUIC streams on one connection)
        use futures::stream::StreamExt;
        let mut manifest_stream = futures::stream::iter(file_entries.into_iter())
            .map(|file_hash| {
                let conn = validator_conn.clone();
                async move {
                    let result = fetch_manifest_on_conn(&conn, &file_hash).await;
                    (file_hash, result)
                }
            })
            .buffer_unordered(16);

        let mut consecutive_failures: u32 = 0;
        const MAX_CONSECUTIVE_FAILURES: u32 = 10;

        while let Some((file_hash, result)) = manifest_stream.next().await {
            match result {
                Ok(manifest) => {
                    consecutive_failures = 0;

                    let shards_per_stripe = manifest.stripe_config.k + manifest.stripe_config.m;
                    let num_stripes = manifest.shards.len().div_ceil(shards_per_stripe);

                    // Compute PG and base CRUSH placement once per file
                    let pg_id = common::calculate_pg(&file_hash, cluster_map.pg_count);
                    let base_miners = match common::calculate_pg_placement(
                        pg_id,
                        shards_per_stripe,
                        &cluster_map,
                    ) {
                        Ok(m) => m,
                        Err(_) => continue,
                    };
                    let base_len = base_miners.len();

                    for stripe_idx in 0..num_stripes {
                        let mut stripe_miners = base_miners.clone();
                        if base_len > 0 {
                            stripe_miners.rotate_left(stripe_idx % base_len);
                        }

                        for local_idx in 0..shards_per_stripe {
                            let global_idx = stripe_idx * shards_per_stripe + local_idx;
                            if global_idx >= manifest.shards.len() {
                                continue;
                            }

                            let target = stripe_miners.get(local_idx);

                            if let Some(target_miner) = target
                                && target_miner.uid == my_uid
                            {
                                let shard = &manifest.shards[global_idx];

                                let shard_hash =
                                    if let Ok(h) = iroh_blobs::Hash::from_str(&shard.blob_hash) {
                                        h
                                    } else {
                                        continue;
                                    };

                                expected_shards.insert(shard_hash);

                                if !local_hashes.contains(&shard_hash) {
                                    missing_shards += 1;
                                    trace!(
                                        shard_idx = local_idx,
                                        blob_hash = %truncate_for_log(&shard.blob_hash, 16),
                                        file_hash = %truncate_for_log(&file_hash, 16),
                                        "Missing shard (validator handles migration via PullFromPeer)"
                                    );
                                }
                            }
                        }
                    }
                }
                Err(e) => {
                    error!(
                        file_hash = %truncate_for_log(&file_hash, 16),
                        error = %e,
                        "Failed to fetch manifest"
                    );
                    consecutive_failures += 1;
                    if consecutive_failures >= MAX_CONSECUTIVE_FAILURES {
                        error!(
                            failures = consecutive_failures,
                            "Too many consecutive manifest failures, aborting rebalance"
                        );
                        break;
                    }
                }
            }
        }
    }

    debug!(
        files_total = total_files,
        files_processed = files_processed,
        expected_shards = expected_shards.len(),
        missing_shards = missing_shards,
        "Self-rebalance summary"
    );

    // GC: Identify orphan shards, delete tags and files after grace period
    gc_orphan_shards(&expected_shards, &local_hash_tags, &store).await;

    info!("PG-based self-rebalance complete");
    Ok(())
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
                    warn!(
                        hash = %truncate_for_log(&hash_str, 16),
                        "Clock skew detected: removing corrupted orphan entry"
                    );
                    orphan_map.remove(blob_hash);
                    continue;
                }

                // Check if grace period expired
                if now - first_seen > ORPHAN_GRACE_PERIOD_SECS {
                    trace!(
                        hash = %truncate_for_log(&hash_str, 16),
                        age_secs = now - first_seen,
                        "GC: Deleting orphan"
                    );

                    let mut removed = false;

                    // Delete the tag first so the blob becomes eligible for store-level GC
                    match store.tags().delete(tag).await {
                        Ok(_) => {
                            removed = true;
                            // Also remove from TAG_MAP cache
                            crate::state::get_tag_map().remove(blob_hash);
                        }
                        Err(e) => {
                            warn!(
                                hash = %truncate_for_log(&hash_str, 16),
                                error = %e,
                                "Failed to delete tag for orphan"
                            );
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
                            Err(e) => {
                                error!(
                                    hash = %truncate_for_log(&hash_str, 16),
                                    error = %e,
                                    "Failed to delete orphan file"
                                );
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
) -> Result<common::FileManifest> {
    let query_msg = common::ValidatorControlMessage::QueryManifest {
        file_hash: file_hash.to_string(),
    };

    let (mut send, mut recv) =
        tokio::time::timeout(std::time::Duration::from_secs(10), conn.open_bi())
            .await
            .map_err(|_| anyhow::anyhow!("Stream open timeout"))??;

    let msg_bytes = serde_json::to_vec(&query_msg)?;
    send.write_all(&msg_bytes).await?;
    send.finish()?;

    let response_bytes = tokio::time::timeout(
        std::time::Duration::from_secs(30),
        recv.read_to_end(1024 * 1024),
    )
    .await
    .map_err(|_| anyhow::anyhow!("Read timeout fetching manifest"))??;

    if response_bytes == b"NOT_FOUND" {
        return Err(anyhow::anyhow!("Manifest not found"));
    }
    if response_bytes == b"WARMING_UP" {
        return Err(anyhow::anyhow!("Validator still warming up"));
    }

    let manifest: common::FileManifest = serde_json::from_slice(&response_bytes)?;
    Ok(manifest)
}

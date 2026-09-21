//! Obligation-list backfill loop: fetch listed blobs this miner lacks.
//!
//! Mirror of `pg_purge`. Every `BACKFILL_PASS_INTERVAL_SECS` a pass walks
//! the owned PGs of the current signed generation from the persisted
//! cursor, streams one PG list at a time, and collects the listed blobs
//! whose hash is absent from the SQLite inventory (a point lookup per
//! record; the filesystem is never scanned). When `BACKFILL_MAX_PENDING`
//! candidates are collected or the walk reaches the end, the pass fetches
//! them from up to `BACKFILL_PEERS_PER_BLOB` peers placed on the same PG,
//! verifies blake3 and the listed length, and stores under the per-hash
//! write lock. The cursor advances past every fully scanned PG so the
//! next pass resumes there; a PG cut by the cap is rescanned (its fetched
//! blobs are then in the inventory and no longer candidates).
//!
//! Interaction with the purge: none on data (the purge only deletes
//! unlisted blobs, the backfill only stores listed ones, both from the
//! same generation), but the backfill waits while a purge pass runs and
//! while the blob volume has less than `BACKFILL_MIN_FREE_BYTES` free.

use std::sync::Arc;
use std::sync::atomic::Ordering;
use std::time::Duration;

use anyhow::Result;
use tracing::{debug, error, info, warn};

use miner::backfill::{
    BackfillConfig, BackfillMetrics, Candidate, Cursor, FetchError, PauseReason, Peer,
    holders_for_pg, verify_payload,
};
use miner::pg_lists::{self, ListExpectation, ListSource, MAX_LIST_BYTES, Manifest};
use miner::purge::{PurgeConfig, RateLimiter, generation_is_fresh};
use miner::store::BlobStore;

use crate::inventory;
use crate::state;

/// Process-wide counters of the backfill loop.
pub fn metrics() -> &'static BackfillMetrics {
    static METRICS: std::sync::OnceLock<BackfillMetrics> = std::sync::OnceLock::new();
    METRICS.get_or_init(BackfillMetrics::default)
}

/// What a pass needs from the host process. The live implementation
/// reads the globals and dials peers; tests substitute in-memory
/// inventory, fixed holders and a scripted fetch.
#[async_trait::async_trait]
pub trait PassEnv: Send + Sync {
    /// The inventory holds `hash_hex` as a live (not trashed) shard.
    fn has_live(&self, hash_hex: &str) -> Result<bool>;
    /// Peers placed on `pg_id` to try, at most `max`, best first.
    async fn holders(&self, pg_id: u32, max: usize) -> Vec<Peer>;
    /// This miner's uid: the listed records whose `holder_uid` is this
    /// are its own.
    fn my_uid(&self) -> u32;
    /// One FetchBlob round trip; the bytes are blake3-verified already.
    async fn fetch(&self, peer: &Peer, hash_hex: &str) -> Result<Vec<u8>, FetchError>;
    /// Exclusive on the hash while the blob lands (writers: Store,
    /// PullFromPeer, backfill; the purge skips a locked hash).
    async fn lock_write(&self, hash_hex: &str) -> state::HashWriteLock;
    /// The blob is in the store: record its inventory row.
    fn record_stored(&self, hash_hex: &str);
    /// Free bytes on the blob volume.
    fn free_bytes(&self) -> u64;
    /// A purge pass is deleting right now.
    fn purge_active(&self) -> bool;
    /// Current cluster-map epoch; a change mid-pass aborts the pass.
    async fn current_epoch(&self) -> u64;
}

/// The real miner: SQLite inventory, cluster map, peer cache, QUIC.
pub struct LiveEnv {
    pub endpoint: quinn::Endpoint,
    pub blobs_dir: std::path::PathBuf,
}

#[async_trait::async_trait]
impl PassEnv for LiveEnv {
    fn has_live(&self, hash_hex: &str) -> Result<bool> {
        Ok(inventory::live_stored_at(hash_hex)?.is_some())
    }
    async fn holders(&self, pg_id: u32, max: usize) -> Vec<Peer> {
        let Some(map) = state::get_cluster_map().read().await.clone() else {
            return Vec::new();
        };
        let me = state::get_miner_uid();
        let cache = state::get_peer_cache();
        tokio::task::spawn_blocking(move || {
            holders_for_pg(
                &map,
                pg_id,
                me,
                |node_id| {
                    cache
                        .get(node_id)
                        .and_then(|addr| state::socket_addr_from_endpoint(&addr))
                },
                max,
            )
        })
        .await
        .unwrap_or_default()
    }
    fn my_uid(&self) -> u32 {
        state::get_miner_uid()
    }
    async fn fetch(&self, peer: &Peer, hash_hex: &str) -> Result<Vec<u8>, FetchError> {
        crate::p2p::fetch_blob_from_peer(&self.endpoint, &peer.node_id, peer.addr, hash_hex).await
    }
    async fn lock_write(&self, hash_hex: &str) -> state::HashWriteLock {
        state::lock_hash_write(hash_hex).await
    }
    fn record_stored(&self, hash_hex: &str) {
        if let Err(e) = inventory::insert_shard(hash_hex) {
            warn!(hash = %hash_hex, error = %e, "backfill: inventory insert failed");
        }
    }
    fn free_bytes(&self) -> u64 {
        fs2::available_space(&self.blobs_dir).unwrap_or(0)
    }
    fn purge_active(&self) -> bool {
        state::purge_pass_active()
    }
    async fn current_epoch(&self) -> u64 {
        *state::get_current_epoch().read().await
    }
}

/// Outcome of one pass.
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct PassSummary {
    /// Owned PGs whose list was scanned to the end.
    pub scanned_pgs: u64,
    /// Owned PGs the generation does not cover (skipped, cursor advances).
    pub uncovered_pgs: u64,
    /// Lists that failed to fetch or verify (skipped this pass).
    pub list_errors: u64,
    /// Listed records whose holder is another miner of the PG: not this
    /// miner's obligation, never fetched.
    pub other_holder: u64,
    pub candidates: u64,
    pub fetched: u64,
    pub fetched_bytes: u64,
    pub no_peer: u64,
    pub bad_peer: u64,
    pub already_present: u64,
    pub store_errors: u64,
    /// The scan stopped at `BACKFILL_MAX_PENDING` before the last PG.
    pub truncated: bool,
    /// The walk reached the last owned PG: the next pass starts over.
    pub walk_complete: bool,
    /// The epoch moved while scanning: stopped before fetching.
    pub aborted_epoch_change: bool,
    /// Where the next pass resumes.
    pub next_cursor: Cursor,
}

/// One pass: discovery from `cursor` over `owned` (sorted), then fetch.
/// `epoch_at_start` is the epoch the owned set was computed on.
#[allow(clippy::too_many_arguments)]
pub async fn run_pass(
    store: Arc<dyn BlobStore>,
    env: Arc<dyn PassEnv>,
    source: &dyn ListSource,
    manifest: &Manifest,
    owned: &[u32],
    cursor: Cursor,
    cfg: &BackfillConfig,
    epoch_at_start: u64,
    metrics: &'static BackfillMetrics,
) -> PassSummary {
    let mut summary = PassSummary::default();
    let generation = manifest.generation;
    let mut idx = cursor.start_index(generation, owned.len());
    let mut candidates: Vec<Candidate> = Vec::new();

    // Phase 1: discovery, one list in memory at a time.
    while idx < owned.len() && candidates.len() < cfg.max_pending {
        if env.current_epoch().await != epoch_at_start {
            summary.aborted_epoch_change = true;
            break;
        }
        let pg_id = owned[idx];
        let Some(obj) = manifest.object_for_pg(pg_id) else {
            summary.uncovered_pgs += 1;
            idx += 1;
            continue;
        };
        let mut skips = ScanSkips::default();
        let scanned = scan_pg_list(
            source,
            manifest,
            pg_id,
            obj,
            env.as_ref(),
            cfg.max_pending - candidates.len(),
            &mut candidates,
            &mut skips,
        )
        .await;
        summary.other_holder += skips.other_holder;
        match scanned {
            Ok(ScanOutcome::Complete) => {
                summary.scanned_pgs += 1;
                idx += 1;
            }
            Ok(ScanOutcome::Truncated) => {
                // Rescanned next pass: what this pass fetches is then in
                // the inventory, the remainder becomes the new candidates.
                summary.truncated = true;
                break;
            }
            Err(e) => {
                warn!(pg_id, generation, error = %format!("{e:#}"), "backfill: list skipped");
                summary.list_errors += 1;
                metrics.list_errors.fetch_add(1, Ordering::Relaxed);
                idx += 1;
            }
        }
    }
    summary.candidates = candidates.len() as u64;
    metrics
        .candidates
        .fetch_add(summary.candidates, Ordering::Relaxed);
    summary.walk_complete = !summary.aborted_epoch_change && idx >= owned.len();
    summary.next_cursor = Cursor {
        generation,
        next_index: if summary.walk_complete { 0 } else { idx },
    };
    if summary.aborted_epoch_change {
        info!(
            generation,
            epoch_at_start,
            candidates = summary.candidates,
            "backfill: epoch changed during discovery, pass aborted before fetching"
        );
        return summary;
    }

    // Phase 2: fetch, at most `max_concurrent` in flight, paced by the
    // byte budget (charged with the listed length) and paused while a
    // purge pass runs or free space is below the floor.
    // Only the byte budget bounds the backfill; the operation bucket is
    // left effectively unbounded.
    const UNBOUNDED_OPS_PER_SEC: u64 = 1 << 40;
    let limiter = Arc::new(tokio::sync::Mutex::new(RateLimiter::new(
        UNBOUNDED_OPS_PER_SEC,
        cfg.max_bytes_per_sec,
    )));
    let sem = Arc::new(tokio::sync::Semaphore::new(cfg.max_concurrent));
    let mut tasks = tokio::task::JoinSet::new();
    let total = candidates.len();
    metrics.pending.store(total as u64, Ordering::Relaxed);
    for (n, candidate) in candidates.into_iter().enumerate() {
        wait_while_paused(env.as_ref(), cfg, metrics).await;
        limiter.lock().await.acquire(candidate.shard_length).await;
        let permit = Arc::clone(&sem)
            .acquire_owned()
            .await
            .expect("semaphore open");
        let (store, env) = (Arc::clone(&store), Arc::clone(&env));
        let peers_per_blob = cfg.peers_per_blob;
        tasks.spawn(async move {
            let outcome = fetch_one(
                store.as_ref(),
                env.as_ref(),
                &candidate,
                peers_per_blob,
                metrics,
            )
            .await;
            drop(permit);
            outcome
        });
        while let Some(joined) = tasks.try_join_next() {
            fold_outcome(&mut summary, joined, metrics);
        }
        if (n + 1) % 1_000 == 0 {
            info!(
                generation,
                dispatched = n + 1,
                total,
                fetched = summary.fetched,
                no_peer = summary.no_peer,
                "backfill: progress"
            );
        }
    }
    while let Some(joined) = tasks.join_next().await {
        fold_outcome(&mut summary, joined, metrics);
    }
    metrics.pending.store(0, Ordering::Relaxed);
    summary
}

fn fold_outcome(
    summary: &mut PassSummary,
    joined: Result<FetchOutcome, tokio::task::JoinError>,
    metrics: &BackfillMetrics,
) {
    metrics.pending.fetch_sub(1, Ordering::Relaxed);
    match joined {
        Ok(o) => {
            summary.fetched += o.fetched;
            summary.fetched_bytes += o.fetched_bytes;
            summary.no_peer += o.no_peer;
            summary.bad_peer += o.bad_peer;
            summary.already_present += o.already_present;
            summary.store_errors += o.store_errors;
        }
        Err(e) => {
            error!(error = %e, "backfill: fetch task panicked");
            summary.store_errors += 1;
            metrics.store_errors.fetch_add(1, Ordering::Relaxed);
        }
    }
}

enum ScanOutcome {
    Complete,
    Truncated,
}

/// Records of one list scan that were not candidates.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
struct ScanSkips {
    other_holder: u64,
}

/// Fetch, verify and decode one PG list, appending to `out` the blobs
/// this miner holds according to the list (records whose `holder_uid` is
/// this miner) but that are absent from the inventory, at most `room` of
/// them. The whole list is still decoded (its digest is checked as one
/// body); only the collection stops at `room`. Records of other holders
/// are counted, not fetched.
#[allow(clippy::too_many_arguments)]
async fn scan_pg_list(
    source: &dyn ListSource,
    manifest: &Manifest,
    pg_id: u32,
    obj: &pg_lists::ObjectEntry,
    env: &dyn PassEnv,
    room: usize,
    out: &mut Vec<Candidate>,
    skips: &mut ScanSkips,
) -> Result<ScanOutcome> {
    if obj.size > MAX_LIST_BYTES {
        anyhow::bail!(
            "list declares {} bytes, above the {MAX_LIST_BYTES} byte limit",
            obj.size
        );
    }
    let path = format!("gen/{}/{}", manifest.generation, Manifest::list_path(pg_id));
    let bytes = source.fetch(&path, obj.size).await?;
    if bytes.len() as u64 != obj.size {
        anyhow::bail!(
            "manifest size {} but body is {} bytes",
            obj.size,
            bytes.len()
        );
    }
    let expect = ListExpectation {
        pg_id,
        generation: manifest.generation,
        ec_k: manifest.ec_k,
        ec_m: manifest.ec_m,
        sha256_hex: &obj.sha256,
    };
    let my_uid = env.my_uid();
    let mut truncated = false;
    let mut lookup_error: Option<anyhow::Error> = None;
    let mut found = 0usize;
    let mut other_holder = 0u64;
    let header = pg_lists::decode_list(&bytes, expect, &mut |record| {
        if truncated || lookup_error.is_some() {
            return;
        }
        if !record.is_held_by(my_uid) {
            other_holder += 1;
            return;
        }
        match env.has_live(&hex::encode(record.blob_hash)) {
            Ok(true) => {}
            Ok(false) => {
                if found >= room {
                    truncated = true;
                    return;
                }
                found += 1;
                out.push(Candidate {
                    pg_id,
                    hash: record.blob_hash,
                    shard_length: u64::from(record.shard_length),
                });
            }
            Err(e) => lookup_error = Some(e),
        }
    })?;
    skips.other_holder += other_holder;
    if let Some(e) = lookup_error {
        // A failed inventory read leaves the PG's candidates unknown:
        // drop what this list contributed and skip it.
        out.truncate(out.len() - found);
        return Err(e.context("inventory lookup"));
    }
    debug!(
        pg_id,
        listed = header.count,
        other_holder,
        missing = found,
        truncated,
        "backfill: list scanned"
    );
    Ok(if truncated {
        ScanOutcome::Truncated
    } else {
        ScanOutcome::Complete
    })
}

/// Block while a pause condition holds, re-checking every
/// `pause_poll_secs`; gauges reflect the reason.
async fn wait_while_paused(env: &dyn PassEnv, cfg: &BackfillConfig, metrics: &BackfillMetrics) {
    let mut logged: Option<PauseReason> = None;
    loop {
        let reason = if env.purge_active() {
            Some(PauseReason::PurgeRunning)
        } else if env.free_bytes() < cfg.min_free_bytes {
            Some(PauseReason::LowFreeSpace)
        } else {
            None
        };
        metrics.set_paused(
            PauseReason::PurgeRunning,
            reason == Some(PauseReason::PurgeRunning),
        );
        metrics.set_paused(
            PauseReason::LowFreeSpace,
            reason == Some(PauseReason::LowFreeSpace),
        );
        let Some(reason) = reason else {
            if let Some(r) = logged {
                info!(reason = r.label(), "backfill: resumed");
            }
            return;
        };
        if logged != Some(reason) {
            info!(
                reason = reason.label(),
                free_bytes = env.free_bytes(),
                min_free_bytes = cfg.min_free_bytes,
                "backfill: paused"
            );
            logged = Some(reason);
        }
        tokio::time::sleep(Duration::from_secs(cfg.pause_poll_secs)).await;
    }
}

#[derive(Debug, Default)]
struct FetchOutcome {
    fetched: u64,
    fetched_bytes: u64,
    no_peer: u64,
    bad_peer: u64,
    already_present: u64,
    store_errors: u64,
}

/// Try the holders of the candidate's PG in order until one payload
/// verifies, then store it under the write lock unless it landed
/// meanwhile.
async fn fetch_one(
    store: &dyn BlobStore,
    env: &dyn PassEnv,
    candidate: &Candidate,
    peers_per_blob: usize,
    metrics: &BackfillMetrics,
) -> FetchOutcome {
    let mut out = FetchOutcome::default();
    let hash_hex = candidate.hash_hex();
    let peers = env.holders(candidate.pg_id, peers_per_blob).await;
    if peers.is_empty() {
        debug!(hash = %hash_hex, pg_id = candidate.pg_id, "backfill: no eligible peer");
        out.no_peer += 1;
        metrics.no_peer.fetch_add(1, Ordering::Relaxed);
        return out;
    }
    let mut data = None;
    for peer in &peers {
        let result = env.fetch(peer, &hash_hex).await.and_then(|bytes| {
            verify_payload(&bytes, &candidate.hash, candidate.shard_length).map(|()| bytes)
        });
        match result {
            Ok(bytes) => {
                data = Some(bytes);
                break;
            }
            Err(e) => {
                debug!(
                    hash = %hash_hex,
                    peer_uid = peer.uid,
                    reason = e.reason(),
                    error = %e,
                    "backfill: peer did not yield the blob"
                );
                out.bad_peer += 1;
                metrics.record_bad_peer(&e);
            }
        }
    }
    let Some(data) = data else {
        out.no_peer += 1;
        metrics.no_peer.fetch_add(1, Ordering::Relaxed);
        return out;
    };

    let _lock = env.lock_write(&hash_hex).await;
    if store.has(&hash_hex) {
        out.already_present += 1;
        metrics.already_present.fetch_add(1, Ordering::Relaxed);
        return out;
    }
    match store.store(&hash_hex, &data).await {
        Ok(()) => {
            env.record_stored(&hash_hex);
            out.fetched += 1;
            out.fetched_bytes += data.len() as u64;
            metrics.fetched.fetch_add(1, Ordering::Relaxed);
            metrics
                .fetched_bytes
                .fetch_add(data.len() as u64, Ordering::Relaxed);
        }
        Err(e) => {
            warn!(hash = %hash_hex, error = %e, "backfill: store failed");
            out.store_errors += 1;
            metrics.store_errors.fetch_add(1, Ordering::Relaxed);
        }
    }
    out
}

// ============================================================================
// Loop
// ============================================================================

/// Background task. Returns immediately when the backfill is disabled or
/// the purge has no bucket URL (the two share `PG_LISTS_BASE_URL`).
pub async fn run_loop(
    store: Arc<dyn BlobStore>,
    validator_node_id: String,
    purge_cfg: PurgeConfig,
    cfg: BackfillConfig,
    endpoint: quinn::Endpoint,
    blobs_dir: std::path::PathBuf,
) {
    if !cfg.enabled {
        info!("backfill: disabled (BACKFILL_ENABLED=false)");
        return;
    }
    let Some(base_url) = purge_cfg.base_url.clone() else {
        error!(
            "backfill: BACKFILL_ENABLED=true but PG_LISTS_BASE_URL is unset, backfill stays off"
        );
        return;
    };
    let source = match crate::pg_purge::build_source(&base_url) {
        Ok(s) => s,
        Err(e) => {
            error!(error = %e, "backfill: cannot build HTTP source, backfill stays off");
            return;
        }
    };
    let Some(data_dir) = state::get_data_dir().cloned() else {
        error!("backfill: data dir unknown, backfill stays off");
        return;
    };
    info!(
        base_url = %base_url,
        max_pending = cfg.max_pending,
        max_bytes_per_sec = cfg.max_bytes_per_sec,
        max_concurrent = cfg.max_concurrent,
        pass_interval_secs = cfg.pass_interval_secs,
        min_free_bytes = cfg.min_free_bytes,
        peers_per_blob = cfg.peers_per_blob,
        "backfill: enabled"
    );

    let metrics = metrics();
    let env: Arc<dyn PassEnv> = Arc::new(LiveEnv {
        endpoint,
        blobs_dir,
    });
    let mut cursor = Cursor::load_from(&data_dir);
    if cursor != Cursor::default() {
        info!(
            generation = cursor.generation,
            next_index = cursor.next_index,
            "backfill: cursor restored"
        );
    }
    let mut manifest: Option<Manifest> = None;
    let mut last_poll_at: Option<tokio::time::Instant> = None;
    let mut last_pass_at: Option<tokio::time::Instant> = None;
    let mut last_logged_wait: Option<&'static str> = None;
    // Generation the empty-ownership refusal was last logged for.
    let mut last_logged_empty: Option<u64> = None;

    loop {
        tokio::time::sleep(Duration::from_secs(purge_cfg.poll_secs.min(60))).await;

        let Some(crate::pg_purge::Ownership {
            epoch,
            pgs: owned,
            weight,
        }) = crate::pg_purge::owned_pgs().await
        else {
            debug!("backfill: no cluster map yet");
            continue;
        };
        if !miner::purge::ownership_nonempty(&owned) {
            // Same clause 0 as the purge: a weight-0 miner owns no PG.
            // There is nothing to fetch, and the manifest is not even
            // polled on its behalf.
            metrics
                .refused_empty_ownership
                .fetch_add(1, Ordering::Relaxed);
            let generation = manifest.as_ref().map(|m| m.generation).unwrap_or(0);
            if last_logged_empty != Some(generation) {
                warn!(
                    epoch,
                    weight = ?weight,
                    generation,
                    "backfill: this miner owns no PG under the current map (weight 0?), nothing to fetch"
                );
                last_logged_empty = Some(generation);
            }
            continue;
        }
        last_logged_empty = None;
        let poll_due = last_poll_at.is_none_or(|t| t.elapsed().as_secs() >= purge_cfg.poll_secs);
        if manifest.is_none() || poll_due {
            refresh_manifest(source.as_ref(), &validator_node_id, &mut manifest).await;
            last_poll_at = Some(tokio::time::Instant::now());
        }
        let Some(current) = manifest.as_ref() else {
            continue;
        };
        metrics
            .generation
            .store(current.generation, Ordering::Relaxed);

        let now = common::now_secs();
        let fresh = current
            .created_at_secs()
            .is_some_and(|c| generation_is_fresh(c, now, purge_cfg.generation_max_age_secs));
        let wait = if !fresh {
            Some("generation is stale")
        } else if !inventory::is_ready() {
            Some("inventory not reconciled yet")
        } else if inventory::had_write_failure() {
            Some("an inventory write failed since startup")
        } else {
            None
        };
        if let Some(reason) = wait {
            if last_logged_wait != Some(reason) {
                warn!(
                    generation = current.generation,
                    "backfill: waiting: {reason}"
                );
                last_logged_wait = Some(reason);
            }
            continue;
        }
        last_logged_wait = None;
        if last_pass_at.is_some_and(|t| t.elapsed().as_secs() < cfg.pass_interval_secs) {
            continue;
        }

        info!(
            generation = current.generation,
            epoch,
            owned_pgs = owned.len(),
            start_index = cursor.start_index(current.generation, owned.len()),
            "backfill: pass starting"
        );
        let started = tokio::time::Instant::now();
        let summary = run_pass(
            Arc::clone(&store),
            Arc::clone(&env),
            source.as_ref(),
            current,
            &owned,
            cursor,
            &cfg,
            epoch,
            metrics,
        )
        .await;
        cursor = summary.next_cursor;
        if let Err(e) = cursor.persist_to(&data_dir) {
            warn!(error = %e, "backfill: cursor not persisted");
        }
        if !summary.aborted_epoch_change {
            metrics.passes.fetch_add(1, Ordering::Relaxed);
            last_pass_at = Some(tokio::time::Instant::now());
        }
        info!(
            generation = current.generation,
            elapsed_secs = started.elapsed().as_secs(),
            aborted = summary.aborted_epoch_change,
            scanned_pgs = summary.scanned_pgs,
            uncovered_pgs = summary.uncovered_pgs,
            list_errors = summary.list_errors,
            other_holder = summary.other_holder,
            candidates = summary.candidates,
            fetched = summary.fetched,
            fetched_bytes = summary.fetched_bytes,
            no_peer = summary.no_peer,
            bad_peer = summary.bad_peer,
            already_present = summary.already_present,
            store_errors = summary.store_errors,
            truncated = summary.truncated,
            walk_complete = summary.walk_complete,
            next_index = cursor.next_index,
            "backfill: pass finished"
        );
    }
}

/// Load the manifest `current.json` points at, keeping the previous one
/// on any failure. Unlike the purge, an older pointer is not refused
/// here: fetching blobs listed by an older generation is harmless, and
/// the purge's watermark already guards the deletion side.
async fn refresh_manifest(
    source: &dyn ListSource,
    validator_node_id: &str,
    current: &mut Option<Manifest>,
) {
    let pointer = match pg_lists::fetch_current(source).await {
        Ok(p) => p,
        Err(e) => {
            warn!(error = %format!("{e:#}"), "backfill: current.json unavailable");
            return;
        }
    };
    let latest = pointer.generation;
    if current.as_ref().is_some_and(|m| m.generation == latest) {
        return;
    }
    match pg_lists::fetch_manifest_at(source, &pointer, validator_node_id).await {
        Ok(m) => {
            info!(
                generation = m.generation,
                listed_pgs = m.pgs.len(),
                "backfill: manifest loaded"
            );
            *current = Some(m);
        }
        Err(e) => {
            warn!(generation = latest, error = %format!("{e:#}"), "backfill: manifest rejected");
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use miner::flat_store::FlatBlobStore;
    use miner::pg_lists::Record;
    use miner::pg_lists::test_fixtures::{
        CREATED_AT, MY_UID, deterministic_key, encode_list, sign_manifest,
    };
    use miner::pg_lists::{DirListSource, fetch_manifest};
    use sha2::{Digest, Sha256};
    use std::collections::{HashMap, HashSet};
    use std::sync::Mutex;
    use std::sync::atomic::{AtomicBool, AtomicU64};

    const GENERATION: u64 = 9;

    /// A listed blob: the payload the honest peer serves, hashed for
    /// real so the hash check can pass.
    fn blob(pg: u32, i: u32) -> (Vec<u8>, [u8; 32]) {
        let data = format!("pg{pg}-blob{i}-")
            .repeat(i as usize + 1)
            .into_bytes();
        let hash = *blake3::hash(&data).as_bytes();
        (data, hash)
    }

    /// Record `i` of pg `pg`: the true length of the blob (the shared
    /// fixture uses synthetic lengths), held by `holder_uid`.
    fn record_held_by(pg: u32, i: u32, holder_uid: u32) -> Record {
        let (data, hash) = blob(pg, i);
        Record {
            blob_hash: hash,
            shard_length: data.len() as u32,
            holder_uid,
        }
    }

    /// Record `i` of pg `pg`, held by this miner (`MY_UID`).
    fn record(pg: u32, i: u32) -> Record {
        record_held_by(pg, i, MY_UID)
    }

    /// Write a generation whose PG lists declare the true length of
    /// each blob, the holder of record `i` of pg `pg` given by
    /// `holder_of(pg, i)` (`rig` names this miner on every record).
    fn write_generation_held(
        root: &std::path::Path,
        pgs: &[(u32, u32)],
        holder_of: &dyn Fn(u32, u32) -> u32,
    ) -> String {
        let key = deterministic_key(3);
        let gen_dir = root.join(format!("gen/{GENERATION}"));
        std::fs::create_dir_all(gen_dir.join("pg")).unwrap();
        let mut objects = serde_json::Map::new();
        for &(pg, count) in pgs {
            let records: Vec<Record> = (0..count)
                .map(|i| record_held_by(pg, i, holder_of(pg, i)))
                .collect();
            let body = encode_list(pg, GENERATION, 10, 20, &records);
            std::fs::write(gen_dir.join(Manifest::list_path(pg)), &body).unwrap();
            objects.insert(
                Manifest::list_path(pg),
                serde_json::json!({
                    "sha256": hex::encode(Sha256::digest(&body)),
                    "size": body.len(),
                }),
            );
        }
        let unsigned = serde_json::json!({
            "generation": GENERATION,
            "created_at": CREATED_AT,
            "pg_count": 16384,
            "ec_k": 10,
            "ec_m": 20,
            "pgs": pgs.iter().map(|(pg, _)| *pg).collect::<Vec<_>>(),
            "objects": objects,
        });
        let signed = sign_manifest(&key, &unsigned);
        std::fs::write(
            gen_dir.join("manifest.json"),
            serde_json::to_vec_pretty(&signed).unwrap(),
        )
        .unwrap();
        std::fs::write(
            root.join("current.json"),
            serde_json::json!({ "generation": GENERATION }).to_string(),
        )
        .unwrap();
        hex::encode(key.verifying_key().to_bytes())
    }

    fn peer(uid: u32) -> Peer {
        Peer {
            uid,
            node_id: format!("peer-{uid}"),
            addr: format!("10.0.0.{uid}:4001").parse().unwrap(),
        }
    }

    /// What a scripted peer returns for any hash.
    #[derive(Clone)]
    enum Serve {
        /// The true payload of the requested hash.
        Honest,
        /// A blake3-correct payload with a byte appended: impossible for
        /// a real blob, but the closest stand-in for "hash ok, length
        /// wrong" is the honest bytes truncated — so serve those and let
        /// the hash check fail first; the length case is exercised with
        /// a list that lies instead (see `list_length_disagreement`).
        Garbage,
        NotFound,
        Unreachable,
    }

    struct FakeEnv {
        live: Mutex<HashSet<String>>,
        holders: Vec<Peer>,
        serve: HashMap<u32, Serve>,
        /// Payloads by hex hash, for `Serve::Honest`.
        payloads: HashMap<String, Vec<u8>>,
        fetches: Mutex<Vec<(u32, String)>>,
        free_bytes: AtomicU64,
        purge_active: AtomicBool,
        epoch: AtomicU64,
        /// Epoch bump fired on the first `current_epoch` call after the
        /// first PG (tests the abort path).
        bump_epoch_after_calls: Mutex<Option<u32>>,
        /// This miner's uid (default `MY_UID`, the holder of every
        /// record of `write_generation`).
        my_uid: u32,
    }

    impl FakeEnv {
        fn new(holders: Vec<Peer>, serve: HashMap<u32, Serve>, pgs: &[(u32, u32)]) -> Self {
            let mut payloads = HashMap::new();
            for &(pg, count) in pgs {
                for i in 0..count {
                    let (data, hash) = blob(pg, i);
                    payloads.insert(hex::encode(hash), data);
                }
            }
            Self {
                live: Mutex::new(HashSet::new()),
                holders,
                serve,
                payloads,
                fetches: Mutex::new(Vec::new()),
                free_bytes: AtomicU64::new(u64::MAX),
                purge_active: AtomicBool::new(false),
                epoch: AtomicU64::new(5),
                bump_epoch_after_calls: Mutex::new(None),
                my_uid: MY_UID,
            }
        }
    }

    #[async_trait::async_trait]
    impl PassEnv for FakeEnv {
        fn has_live(&self, hash_hex: &str) -> Result<bool> {
            Ok(self.live.lock().unwrap().contains(hash_hex))
        }
        async fn holders(&self, _pg_id: u32, max: usize) -> Vec<Peer> {
            self.holders.iter().take(max).cloned().collect()
        }
        fn my_uid(&self) -> u32 {
            self.my_uid
        }
        async fn fetch(&self, peer: &Peer, hash_hex: &str) -> Result<Vec<u8>, FetchError> {
            self.fetches
                .lock()
                .unwrap()
                .push((peer.uid, hash_hex.to_string()));
            match self
                .serve
                .get(&peer.uid)
                .cloned()
                .unwrap_or(Serve::NotFound)
            {
                Serve::Honest => Ok(self.payloads[hash_hex].clone()),
                Serve::Garbage => Ok(b"definitely not the blob".to_vec()),
                Serve::NotFound => Err(FetchError::NotFound),
                Serve::Unreachable => Err(FetchError::Unreachable("refused".into())),
            }
        }
        async fn lock_write(&self, hash_hex: &str) -> state::HashWriteLock {
            state::lock_hash_write(hash_hex).await
        }
        fn record_stored(&self, hash_hex: &str) {
            self.live.lock().unwrap().insert(hash_hex.to_string());
        }
        fn free_bytes(&self) -> u64 {
            self.free_bytes.load(Ordering::Relaxed)
        }
        fn purge_active(&self) -> bool {
            self.purge_active.load(Ordering::Relaxed)
        }
        async fn current_epoch(&self) -> u64 {
            let mut pending = self.bump_epoch_after_calls.lock().unwrap();
            if let Some(n) = pending.as_mut() {
                if *n == 0 {
                    self.epoch.fetch_add(1, Ordering::Relaxed);
                    *pending = None;
                } else {
                    *n -= 1;
                }
            }
            self.epoch.load(Ordering::Relaxed)
        }
    }

    fn fast_cfg() -> BackfillConfig {
        BackfillConfig {
            enabled: true,
            max_pending: 100_000,
            max_bytes_per_sec: 1 << 30,
            max_concurrent: 4,
            pass_interval_secs: 0,
            min_free_bytes: 0,
            peers_per_blob: 3,
            pause_poll_secs: 1,
        }
    }

    struct Rig {
        _bucket: tempfile::TempDir,
        _store_dir: tempfile::TempDir,
        source: DirListSource,
        manifest: Manifest,
        store: Arc<FlatBlobStore>,
        /// Per-test counters: the process-wide ones are shared by the
        /// tests running in parallel.
        metrics: &'static BackfillMetrics,
    }

    fn fresh_metrics() -> &'static BackfillMetrics {
        Box::leak(Box::default())
    }

    async fn rig(pgs: &[(u32, u32)]) -> Rig {
        rig_held(pgs, &|_, _| MY_UID).await
    }

    async fn rig_held(pgs: &[(u32, u32)], holder_of: &dyn Fn(u32, u32) -> u32) -> Rig {
        let bucket = tempfile::tempdir().unwrap();
        let validator_hex = write_generation_held(bucket.path(), pgs, holder_of);
        let source = DirListSource::new(bucket.path());
        let manifest = fetch_manifest(&source, GENERATION, &validator_hex)
            .await
            .unwrap();
        let store_dir = tempfile::tempdir().unwrap();
        let store = Arc::new(FlatBlobStore::new(store_dir.path()).unwrap());
        Rig {
            _bucket: bucket,
            _store_dir: store_dir,
            source,
            manifest,
            store,
            metrics: fresh_metrics(),
        }
    }

    async fn run(
        rig: &Rig,
        env: &Arc<FakeEnv>,
        owned: &[u32],
        cursor: Cursor,
        cfg: &BackfillConfig,
    ) -> PassSummary {
        let env_dyn: Arc<dyn PassEnv> = Arc::clone(env) as Arc<dyn PassEnv>;
        run_pass(
            rig.store.clone() as Arc<dyn BlobStore>,
            env_dyn,
            &rig.source,
            &rig.manifest,
            owned,
            cursor,
            cfg,
            5,
            rig.metrics,
        )
        .await
    }

    /// Only the records naming THIS miner as holder are candidates: with
    /// 60 records over two stripes and thirty distinct holders rotating
    /// per stripe, exactly two are its own (one per stripe) and the 58
    /// others are never fetched nor dialled.
    #[tokio::test]
    async fn discovery_fetches_only_this_holders_records() {
        let pgs = [(1u32, 60u32)];
        // Record i: shard i % 30 of stripe i / 30, held by position
        // (shard + stripe) % 30 of a placement of uids MY_UID..MY_UID+30.
        let rig = rig_held(&pgs, &|_, i| MY_UID + (i % 30 + i / 30) % 30).await;
        let mut env = FakeEnv::new(vec![peer(11)], HashMap::from([(11, Serve::Honest)]), &pgs);
        // Position 4: shard 4 of stripe 0, shard 3 of stripe 1.
        env.my_uid = MY_UID + 4;
        let env = Arc::new(env);
        let s = run(&rig, &env, &[1], Cursor::default(), &fast_cfg()).await;
        assert_eq!(s.candidates, 2, "one shard per stripe is mine");
        assert_eq!(s.fetched, 2);
        assert_eq!(s.other_holder, 58);
        assert!(s.walk_complete);
        for i in [4u32, 33] {
            let (data, hash) = blob(1, i);
            assert_eq!(rig.store.read(&hex::encode(hash)).await.unwrap(), data);
        }
        assert_eq!(
            env.fetches.lock().unwrap().len(),
            2,
            "no other record dialled"
        );

        // A miner no record names fetches nothing from the same list.
        let mut env = FakeEnv::new(vec![peer(11)], HashMap::from([(11, Serve::Honest)]), &pgs);
        env.my_uid = MY_UID + 30;
        let env = Arc::new(env);
        let s = run(&rig, &env, &[1], Cursor::default(), &fast_cfg()).await;
        assert_eq!(s.candidates, 0);
        assert_eq!(s.other_holder, 60);
        assert!(env.fetches.lock().unwrap().is_empty());
    }

    /// Listed-and-absent blobs are the candidates; listed-and-held are
    /// not; the cap stops the collection and the cursor stays on the cut
    /// PG; the next pass resumes there and completes the walk.
    #[tokio::test]
    async fn discovery_skips_held_blobs_and_bounds_pending() {
        let pgs = [(1u32, 3u32), (2, 2), (3, 1)];
        let rig = rig(&pgs).await;
        let env = Arc::new(FakeEnv::new(
            vec![peer(11)],
            HashMap::from([(11, Serve::Honest)]),
            &pgs,
        ));
        // Two blobs of pg 1 are already held.
        for i in 0..2 {
            let (data, hash) = blob(1, i);
            rig.store.store(&hex::encode(hash), &data).await.unwrap();
            env.record_stored(&hex::encode(hash));
        }
        let owned = [1u32, 2, 3, 4];
        let mut cfg = fast_cfg();
        cfg.max_pending = 2;

        let first = run(&rig, &env, &owned, Cursor::default(), &cfg).await;
        assert_eq!(first.candidates, 2, "1 missing in pg 1 + first of pg 2");
        assert_eq!(first.fetched, 2);
        assert!(first.truncated);
        assert!(!first.walk_complete);
        assert_eq!(first.scanned_pgs, 1, "pg 1 complete, pg 2 cut");
        assert_eq!(
            first.next_cursor,
            Cursor {
                generation: GENERATION,
                next_index: 1
            },
            "resume at pg 2, which is rescanned"
        );

        let second = run(&rig, &env, &owned, first.next_cursor, &cfg).await;
        assert_eq!(
            second.candidates, 2,
            "remaining blob of pg 2 + the one of pg 3"
        );
        assert_eq!(second.fetched, 2);
        assert!(!second.truncated, "pg 3 was scanned to its end");
        assert!(!second.walk_complete, "the cap was reached before pg 4");
        assert_eq!(second.next_cursor.next_index, 3);

        let third = run(&rig, &env, &owned, second.next_cursor, &cfg).await;
        assert_eq!(third.candidates, 0);
        assert_eq!(third.uncovered_pgs, 1, "pg 4 is owned but not listed");
        assert!(third.walk_complete);
        assert_eq!(third.next_cursor.next_index, 0);

        // Every listed blob is now in the store with the exact payload.
        for &(pg, count) in &pgs {
            for i in 0..count {
                let (data, hash) = blob(pg, i);
                assert_eq!(rig.store.read(&hex::encode(hash)).await.unwrap(), data);
            }
        }
        let again = run(&rig, &env, &owned, third.next_cursor, &cfg).await;
        assert_eq!(again.candidates, 0, "nothing left to fetch");
        assert!(again.walk_complete);
    }

    /// A peer serving wrong bytes or nothing is counted and the next
    /// holder is tried; the payload that verifies is the one stored.
    #[tokio::test]
    async fn bad_peers_are_skipped_until_one_verifies() {
        let pgs = [(7u32, 2u32)];
        let rig = rig(&pgs).await;
        let env = Arc::new(FakeEnv::new(
            vec![peer(1), peer(2), peer(3), peer(4)],
            HashMap::from([
                (1, Serve::Unreachable),
                (2, Serve::Garbage),
                (3, Serve::Honest),
                (4, Serve::Honest),
            ]),
            &pgs,
        ));
        let s = run(&rig, &env, &[7], Cursor::default(), &fast_cfg()).await;
        assert_eq!(s.candidates, 2);
        assert_eq!(s.fetched, 2);
        assert_eq!(s.bad_peer, 4, "unreachable + garbage, per blob");
        assert_eq!(s.no_peer, 0);
        assert_eq!(rig.metrics.bad_peer_total(), 4);
        assert_eq!(rig.metrics.bad_peer_unreachable.load(Ordering::Relaxed), 2);
        assert_eq!(
            rig.metrics.bad_peer_hash_mismatch.load(Ordering::Relaxed),
            2
        );
        assert_eq!(rig.metrics.fetched.load(Ordering::Relaxed), 2);
        assert!(
            env.fetches.lock().unwrap().iter().all(|(uid, _)| *uid != 4),
            "the fourth holder is beyond peers_per_blob=3"
        );
        for i in 0..2 {
            let (data, hash) = blob(7, i);
            assert_eq!(rig.store.read(&hex::encode(hash)).await.unwrap(), data);
        }
    }

    /// No holder yields the blob: counted as no_peer, nothing stored,
    /// and the blob stays a candidate for the next pass.
    #[tokio::test]
    async fn no_verifying_peer_stores_nothing() {
        let pgs = [(8u32, 1u32)];
        let rig = rig(&pgs).await;
        let env = Arc::new(FakeEnv::new(
            vec![peer(1), peer(2)],
            HashMap::from([(1, Serve::Garbage), (2, Serve::NotFound)]),
            &pgs,
        ));
        let s = run(&rig, &env, &[8], Cursor::default(), &fast_cfg()).await;
        assert_eq!(s.candidates, 1);
        assert_eq!(s.fetched, 0);
        assert_eq!(s.no_peer, 1);
        assert_eq!(s.bad_peer, 2);
        let (_, hash) = blob(8, 0);
        assert!(!rig.store.has(&hex::encode(hash)));

        let empty = Arc::new(FakeEnv::new(vec![], HashMap::new(), &pgs));
        let s = run(&rig, &empty, &[8], Cursor::default(), &fast_cfg()).await;
        assert_eq!(s.no_peer, 1, "no eligible holder at all");
        assert_eq!(s.fetched, 0);
    }

    /// A list whose declared length disagrees with the real blob: the
    /// hash verifies, the length does not, nothing is stored.
    #[tokio::test]
    async fn list_length_disagreement_rejects_the_payload() {
        let bucket = tempfile::tempdir().unwrap();
        let key = deterministic_key(4);
        let (_, hash) = blob(5, 0);
        let gen_dir = bucket.path().join(format!("gen/{GENERATION}"));
        std::fs::create_dir_all(gen_dir.join("pg")).unwrap();
        let mut lying = record(5, 0);
        lying.shard_length += 1;
        let body = encode_list(5, GENERATION, 10, 20, &[lying]);
        std::fs::write(gen_dir.join(Manifest::list_path(5)), &body).unwrap();
        let unsigned = serde_json::json!({
            "generation": GENERATION, "created_at": CREATED_AT, "pg_count": 16384,
            "ec_k": 10, "ec_m": 20, "pgs": [5],
            "objects": { Manifest::list_path(5): {
                "sha256": hex::encode(Sha256::digest(&body)), "size": body.len() } },
        });
        std::fs::write(
            gen_dir.join("manifest.json"),
            serde_json::to_vec(&sign_manifest(&key, &unsigned)).unwrap(),
        )
        .unwrap();
        let source = DirListSource::new(bucket.path());
        let manifest = fetch_manifest(
            &source,
            GENERATION,
            &hex::encode(key.verifying_key().to_bytes()),
        )
        .await
        .unwrap();
        let store_dir = tempfile::tempdir().unwrap();
        let store = Arc::new(FlatBlobStore::new(store_dir.path()).unwrap());
        let env = Arc::new(FakeEnv::new(
            vec![peer(1)],
            HashMap::from([(1, Serve::Honest)]),
            &[(5, 1)],
        ));
        let metrics = fresh_metrics();
        let s = run_pass(
            store.clone() as Arc<dyn BlobStore>,
            Arc::clone(&env) as Arc<dyn PassEnv>,
            &source,
            &manifest,
            &[5],
            Cursor::default(),
            &fast_cfg(),
            5,
            metrics,
        )
        .await;
        assert_eq!(s.fetched, 0);
        assert_eq!(s.no_peer, 1);
        assert_eq!(s.bad_peer, 1);
        assert_eq!(metrics.bad_peer_length_mismatch.load(Ordering::Relaxed), 1);
        assert!(!store.has(&hex::encode(hash)));
    }

    /// A blob that lands through another writer between discovery and
    /// the store is left alone (counted, not overwritten).
    #[tokio::test]
    async fn blob_stored_meanwhile_is_not_rewritten() {
        let pgs = [(6u32, 1u32)];
        let rig = rig(&pgs).await;
        let env = Arc::new(FakeEnv::new(
            vec![peer(1)],
            HashMap::from([(1, Serve::Honest)]),
            &pgs,
        ));
        // Present in the store but not (yet) in the inventory: the
        // inventory row is what discovery reads, so it is a candidate.
        let (data, hash) = blob(6, 0);
        rig.store.store(&hex::encode(hash), &data).await.unwrap();
        let s = run(&rig, &env, &[6], Cursor::default(), &fast_cfg()).await;
        assert_eq!(s.candidates, 1);
        assert_eq!(s.already_present, 1);
        assert_eq!(s.fetched, 0);
    }

    /// The pass waits while a purge pass runs or free space is below the
    /// floor, and resumes when the condition clears.
    #[tokio::test]
    async fn pauses_for_purge_and_low_free_space() {
        let pgs = [(9u32, 1u32)];
        let rig = rig(&pgs).await;
        let env = Arc::new(FakeEnv::new(
            vec![peer(1)],
            HashMap::from([(1, Serve::Honest)]),
            &pgs,
        ));
        env.purge_active.store(true, Ordering::Relaxed);
        let mut cfg = fast_cfg();
        cfg.min_free_bytes = 1_000;
        env.free_bytes.store(10, Ordering::Relaxed);

        let metrics = rig.metrics;
        let env2 = Arc::clone(&env);
        let pass = tokio::spawn(async move {
            let rig = rig;
            let s = run(&rig, &env2, &[9], Cursor::default(), &cfg).await;
            (s, rig)
        });
        tokio::time::sleep(Duration::from_millis(300)).await;
        assert_eq!(metrics.paused_purge_running.load(Ordering::Relaxed), 1);
        assert!(
            env.fetches.lock().unwrap().is_empty(),
            "nothing fetched while paused"
        );

        env.purge_active.store(false, Ordering::Relaxed);
        tokio::time::sleep(Duration::from_millis(1_300)).await;
        assert_eq!(metrics.paused_purge_running.load(Ordering::Relaxed), 0);
        assert_eq!(metrics.paused_low_free_space.load(Ordering::Relaxed), 1);
        assert!(env.fetches.lock().unwrap().is_empty());

        env.free_bytes.store(u64::MAX, Ordering::Relaxed);
        let (s, _rig) = tokio::time::timeout(Duration::from_secs(10), pass)
            .await
            .expect("pass resumes once the floor is cleared")
            .unwrap();
        assert_eq!(s.fetched, 1);
        assert_eq!(metrics.paused_low_free_space.load(Ordering::Relaxed), 0);
    }

    /// The epoch moving during discovery aborts before any fetch; the
    /// cursor keeps the PGs already scanned.
    #[tokio::test]
    async fn epoch_change_aborts_before_fetching() {
        let pgs = [(1u32, 1u32), (2, 1), (3, 1)];
        let rig = rig(&pgs).await;
        let env = Arc::new(FakeEnv::new(
            vec![peer(1)],
            HashMap::from([(1, Serve::Honest)]),
            &pgs,
        ));
        // First check passes (pg 1), second check (before pg 2) bumps.
        *env.bump_epoch_after_calls.lock().unwrap() = Some(1);
        let s = run(&rig, &env, &[1, 2, 3], Cursor::default(), &fast_cfg()).await;
        assert!(s.aborted_epoch_change);
        assert_eq!(s.scanned_pgs, 1);
        assert_eq!(s.fetched, 0);
        assert!(env.fetches.lock().unwrap().is_empty());
        assert_eq!(s.next_cursor.next_index, 1);
        assert!(!s.walk_complete);
    }
}

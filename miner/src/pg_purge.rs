//! Obligation-list purge loop: keeps the store down to what the published
//! per-PG lists oblige this miner to hold.
//!
//! Every `PG_LISTS_POLL_SECS` the loop (1) derives the PGs this miner owns
//! from the current cluster map (CRUSH, cached by epoch), (2) follows
//! `current.json` to the latest generation and, when it changed or the
//! owned set changed, loads the verified lists of the owned PGs into a
//! membership filter ([`miner::pg_lists`]), and (3) when the gate is open
//! runs one rate-bounded pass over the inventory, deleting through the
//! store's own two-phase delete every blob the rule in [`miner::purge`]
//! declares purgeable. The pass never walks the store: it pages the
//! SQLite inventory in hash order (`inventory::live_shards_page`), which
//! also carries the age of each blob.
//!
//! Off by default (`PURGE_ENABLED=false`); dry-run by default when enabled.

use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;

use anyhow::Result;
use miner::pg_lists::{
    self, CurrentPointer, DirListSource, HttpListSource, ListSource, LoadedGeneration,
};
use miner::purge::{
    self, Candidate, Mode, OwnershipDecision, OwnershipHysteresis, OwnershipStability, PurgeConfig,
    PurgeGate, PurgeMetrics, RateLimiter, StabilityObservation, Verdict, classify, decide,
    generation_is_fresh,
};
use miner::store::BlobStore;
use tracing::{debug, error, info, warn};

use crate::inventory;
use crate::state;

/// Inventory rows fetched per blocking query.
const PAGE_SIZE: usize = 1_000;
/// Progress line cadence (blobs purged, or would-be purged in dry-run).
const SUMMARY_EVERY: u64 = 1_000;

/// Process-wide counters of the purge loop.
pub fn metrics() -> &'static PurgeMetrics {
    static METRICS: std::sync::OnceLock<PurgeMetrics> = std::sync::OnceLock::new();
    METRICS.get_or_init(PurgeMetrics::default)
}

/// What a pass needs from the host process. The live implementation
/// reads the globals; tests substitute an in-memory inventory.
#[async_trait::async_trait]
pub trait PassEnv: Send + Sync {
    /// `(hash, stored_at)` rows strictly after `after`, in hash order.
    fn live_shards_page(&self, after: Option<&str>, limit: usize) -> Result<Vec<(String, i64)>>;
    /// A Store/PullFromPeer of `hash_hex` is in progress.
    fn is_write_inflight(&self, hash_hex: &str) -> bool;
    /// Take the per-hash write lock if free; `None` while a writer holds
    /// it. Held by the pass across the delete so no write can interleave.
    fn try_lock_write(&self, hash_hex: &str) -> Option<state::HashWriteLock>;
    /// Current `stored_at` of a live row, re-read under the lock.
    fn live_stored_at(&self, hash_hex: &str) -> Result<Option<i64>>;
    /// The blob left the live store through `BlobStore::delete`.
    #[cfg(feature = "purge-enforce")]
    fn record_trashed(&self, hash_hex: &str);
    /// The blob left the store for good through `BlobStore::remove`.
    #[cfg(feature = "purge-enforce")]
    fn record_removed(&self, hash_hex: &str);
    /// Current cluster-map epoch; a change mid-pass aborts the pass.
    async fn current_epoch(&self) -> u64;
    /// Unix seconds.
    fn now_secs(&self) -> u64;
}

/// The real miner: SQLite inventory, in-flight registry, epoch global.
pub struct LiveEnv;

#[async_trait::async_trait]
impl PassEnv for LiveEnv {
    fn live_shards_page(&self, after: Option<&str>, limit: usize) -> Result<Vec<(String, i64)>> {
        inventory::live_shards_page(after, limit)
    }
    fn is_write_inflight(&self, hash_hex: &str) -> bool {
        state::is_write_inflight(hash_hex)
    }
    fn try_lock_write(&self, hash_hex: &str) -> Option<state::HashWriteLock> {
        state::try_lock_hash_write(hash_hex)
    }
    fn live_stored_at(&self, hash_hex: &str) -> Result<Option<i64>> {
        inventory::live_stored_at(hash_hex)
    }
    #[cfg(feature = "purge-enforce")]
    fn record_trashed(&self, hash_hex: &str) {
        if let Err(e) = inventory::trash_shard(hash_hex) {
            warn!(hash = %hash_hex, error = %e, "purge: inventory trash mark failed");
        }
        invalidate_caches(hash_hex);
    }
    #[cfg(feature = "purge-enforce")]
    fn record_removed(&self, hash_hex: &str) {
        if let Err(e) = inventory::delete_shard(hash_hex) {
            warn!(hash = %hash_hex, error = %e, "purge: inventory delete failed");
        }
        invalidate_caches(hash_hex);
    }
    async fn current_epoch(&self) -> u64 {
        *state::get_current_epoch().read().await
    }
    fn now_secs(&self) -> u64 {
        common::now_secs()
    }
}

#[cfg(feature = "purge-enforce")]
fn invalidate_caches(hash_hex: &str) {
    use std::str::FromStr;
    if let Ok(parsed) = iroh_blobs::Hash::from_str(hash_hex) {
        state::get_blob_cache().remove(&parsed);
        state::get_pos_commitment_cache().remove(&parsed);
    }
}

/// Outcome of one pass over the inventory.
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct PassSummary {
    pub examined: u64,
    pub purged: u64,
    pub purged_bytes: u64,
    pub would_purge: u64,
    pub would_purge_bytes: u64,
    /// Blobs whose verdict was the tombstone class (writer saw the file
    /// deleted): candidates, then those deleted (subset of `purged`) or
    /// that would be (subset of `would_purge`), and their bytes.
    pub tombstone_candidates: u64,
    pub tombstone_deleted: u64,
    pub tombstone_deleted_bytes: u64,
    pub tombstone_would_purge: u64,
    /// Tombstoned blobs retained because their last write is at or after
    /// the generation's snapshot bound (a reference the writer could not
    /// have seen; a re-upload of the same content refreshes `stored_at`).
    pub tombstone_retained_fresh_store: u64,
    pub kept_by_filter: u64,
    /// Blobs whose verdict was the moved class (listed in an owned PG
    /// under another holder): retained.
    pub kept_moved: u64,
    pub skipped_young: u64,
    pub skipped_inflight: u64,
    pub skipped_invalid: u64,
    pub delete_errors: u64,
    /// Distance between the heartbeat epoch and the map epoch when the
    /// pass started (0 when they agreed).
    pub epoch_skew: u64,
    /// The pass stopped early: the heartbeat epoch and the map epoch
    /// disagreed by more than [`EPOCH_SKEW_TOLERANCE`] at the start, or
    /// the heartbeat epoch moved while the pass ran.
    pub aborted_epoch_change: bool,
    /// The pass was refused before its first page because the filter
    /// was not built from the enforced generation's lists
    /// ([`LoadedGeneration::filter_matches_generation`]). A filter miss
    /// is a deletion; a filter from another generation must never decide
    /// one.
    pub refused_filter_generation: bool,
}

/// Largest distance tolerated between the heartbeat epoch and the epoch
/// of the map the owned set was computed on. The validator's heartbeat
/// ack moves `CURRENT_EPOCH` on its own, while the map only arrives with
/// a `ClusterMapUpdate`; one epoch of lag between the two is the normal
/// order of delivery, not an ownership change, and refusing it made every
/// pass abort at page one whenever the two disagreed.
pub const EPOCH_SKEW_TOLERANCE: u64 = 1;

/// One rate-bounded pass over the live inventory.
///
/// `gate` was evaluated by the caller for `loaded`. `epoch_at_start` is
/// the epoch of the map the owned set was computed on; the heartbeat
/// epoch (`env.current_epoch`) may run ahead of it by up to
/// [`EPOCH_SKEW_TOLERANCE`] (logged and counted, the pass runs), a larger
/// distance aborts the pass before the first page (the map this miner
/// holds is not the one the validator places on), and any move of the
/// heartbeat epoch while the pass runs aborts it, since the owned-PG set
/// the filter was built for is then stale. Deletion goes
/// through `store.delete` (two-phase trash) unless `hard_delete`, which
/// mirrors `TRASH_ENABLED=false` on the validator's Delete path.
#[allow(clippy::too_many_arguments)]
pub async fn run_pass(
    store: &dyn BlobStore,
    env: &dyn PassEnv,
    loaded: &LoadedGeneration,
    gate: PurgeGate,
    cfg: &PurgeConfig,
    hard_delete: bool,
    epoch_at_start: u64,
    metrics: &PurgeMetrics,
) -> PassSummary {
    // Only the enforcing arm reads it; a census build has no such arm.
    #[cfg(not(feature = "purge-enforce"))]
    let _ = hard_delete;
    let mut summary = PassSummary::default();
    if !gate.open() {
        return summary;
    }
    if !loaded.filter_matches_generation() {
        error!(
            generation = loaded.generation,
            filter_generation = loaded.filter.generation(),
            "purge: filter was not built from the enforced generation: pass not run, generation dropped for rebuild"
        );
        metrics
            .filter_generation_refusals
            .fetch_add(1, Ordering::Relaxed);
        summary.refused_filter_generation = true;
        return summary;
    }
    // The heartbeat epoch as the pass starts is the baseline every
    // mid-pass check compares against; its distance to the map epoch is
    // the skew.
    let epoch_baseline = env.current_epoch().await;
    summary.epoch_skew = epoch_baseline.abs_diff(epoch_at_start);
    if summary.epoch_skew > EPOCH_SKEW_TOLERANCE {
        warn!(
            map_epoch = epoch_at_start,
            heartbeat_epoch = epoch_baseline,
            skew = summary.epoch_skew,
            tolerated = EPOCH_SKEW_TOLERANCE,
            "purge: heartbeat epoch and cluster map epoch disagree, the map is not current: pass not run"
        );
        metrics.epoch_skew_aborts.fetch_add(1, Ordering::Relaxed);
        summary.aborted_epoch_change = true;
        return summary;
    }
    if summary.epoch_skew > 0 {
        warn!(
            map_epoch = epoch_at_start,
            heartbeat_epoch = epoch_baseline,
            skew = summary.epoch_skew,
            "purge: heartbeat epoch ahead of the cluster map epoch, within tolerance: pass runs on the map's ownership"
        );
        metrics.epoch_skew_tolerated.fetch_add(1, Ordering::Relaxed);
    }
    let mut limiter = RateLimiter::new(cfg.rate_per_sec, cfg.max_bytes_per_sec);
    let mut after: Option<String> = None;
    let mut since_summary = 0u64;
    // The moved class needs both the switch and a built others filter;
    // without either, a blob held for another holder is an orphan (the
    // pre-moved-class rule).
    let moved_class = cfg.moved_class && loaded.has_others_filter();

    'pages: loop {
        let epoch_now = env.current_epoch().await;
        if epoch_now != epoch_baseline {
            warn!(
                map_epoch = epoch_at_start,
                epoch_at_start = epoch_baseline,
                now = epoch_now,
                "purge: cluster epoch changed mid-pass, stopping"
            );
            summary.aborted_epoch_change = true;
            break;
        }
        let page = match env.live_shards_page(after.as_deref(), PAGE_SIZE) {
            Ok(p) => p,
            Err(e) => {
                error!(error = %e, "purge: inventory page failed, stopping pass");
                break;
            }
        };
        let Some((last, _)) = page.last() else {
            break;
        };
        after = Some(last.clone());
        // Age is measured from the earlier of now and the generation's
        // snapshot bound (scan start when published, else creation): a
        // blob written after it may be unlisted and must never look "old
        // enough".
        let reference = env.now_secs().min(loaded.snapshot_secs);

        for (hash_hex, stored_at) in &page {
            summary.examined += 1;
            metrics.candidates.fetch_add(1, Ordering::Relaxed);

            let Some(hash) = parse_hash(hash_hex) else {
                summary.skipped_invalid += 1;
                metrics.skipped_invalid.fetch_add(1, Ordering::Relaxed);
                continue;
            };
            let in_filter = loaded.may_be_obliged(&hash);
            // The others filter and the exact tombstone set are only
            // consulted for a filter miss: a listed hash wins over both,
            // and the lookups are spared on the common (obliged) case.
            let moved = !in_filter && moved_class && loaded.may_be_held_by_other(&hash);
            // The tombstone set was already stripped, at load time, of
            // every hash a record of the enforced lists names (see
            // `LoadedGeneration::tombstones_retained_live_ref`); the
            // filter checks here are the cheap first line, not the rule.
            let stored_at = (*stored_at).max(0) as u64;
            let candidate = Candidate {
                age_secs: reference.saturating_sub(stored_at),
                in_filter,
                moved,
                tombstoned: !in_filter && !moved && loaded.is_tombstoned(&hash),
                stored_after_snapshot: stored_at >= reference,
                inflight: env.is_write_inflight(hash_hex),
            };
            let tombstoned = match decide(gate, candidate, cfg.min_age_secs) {
                Verdict::Purge => false,
                Verdict::PurgeTombstoned => {
                    summary.tombstone_candidates += 1;
                    metrics.tombstone_candidates.fetch_add(1, Ordering::Relaxed);
                    true
                }
                Verdict::KeepInList => {
                    summary.kept_by_filter += 1;
                    metrics.kept_by_filter.fetch_add(1, Ordering::Relaxed);
                    continue;
                }
                Verdict::KeepMoved => {
                    summary.kept_moved += 1;
                    metrics.kept_moved.fetch_add(1, Ordering::Relaxed);
                    continue;
                }
                Verdict::KeepYoung => {
                    summary.skipped_young += 1;
                    metrics.skipped_young.fetch_add(1, Ordering::Relaxed);
                    continue;
                }
                Verdict::KeepStoredAfterSnapshot => {
                    summary.tombstone_retained_fresh_store += 1;
                    metrics
                        .tombstone_retained_fresh_store
                        .fetch_add(1, Ordering::Relaxed);
                    continue;
                }
                Verdict::KeepInflight => {
                    summary.skipped_inflight += 1;
                    metrics.skipped_inflight.fetch_add(1, Ordering::Relaxed);
                    continue;
                }
                // The gate was open at the top of the pass; these cannot
                // fire, but if they ever do the only safe answer is stop.
                Verdict::KeepEmptyOwnership
                | Verdict::KeepNoGeneration
                | Verdict::KeepGenerationStale
                | Verdict::KeepCoverageIncomplete
                | Verdict::KeepOwnershipUnstable => break 'pages,
            };

            // Absent from the store already (inventory ahead of disk): a
            // delete would be a no-op, do not spend budget or count it.
            let Some(len) = store.blob_len(hash_hex) else {
                summary.skipped_invalid += 1;
                metrics.skipped_invalid.fetch_add(1, Ordering::Relaxed);
                continue;
            };
            limiter.acquire(len).await;

            // The limiter may have waited: the map may have moved, and a
            // write of this hash may have started (a content-addressed
            // re-upload lands under the old hash). Re-check the epoch and
            // take the per-hash write lock before touching the store; a
            // writer arriving now waits for the delete to finish and then
            // re-stores, a writer already there makes us skip.
            if env.current_epoch().await != epoch_baseline {
                summary.aborted_epoch_change = true;
                break 'pages;
            }
            let Some(_write_lock) = env.try_lock_write(hash_hex) else {
                summary.skipped_inflight += 1;
                metrics.skipped_inflight.fetch_add(1, Ordering::Relaxed);
                continue;
            };
            // A write may have completed during the wait and refreshed the
            // row: the age decided on above is stale. Re-read under the
            // lock and re-apply the age clause before deleting.
            let fresh_stored_at = match env.live_stored_at(hash_hex) {
                Ok(Some(at)) => at.max(0) as u64,
                Ok(None) => {
                    summary.skipped_invalid += 1;
                    metrics.skipped_invalid.fetch_add(1, Ordering::Relaxed);
                    continue;
                }
                Err(e) => {
                    error!(error = %e, "purge: inventory re-read failed, stopping pass");
                    break 'pages;
                }
            };
            let fresh_age = reference.saturating_sub(fresh_stored_at);
            // The age clause is the orphan class's; a tombstone is proof
            // of the deletion, but not of a write the writer never saw:
            // a re-store at or after the snapshot bound keeps it.
            if tombstoned {
                if fresh_stored_at >= reference {
                    summary.tombstone_retained_fresh_store += 1;
                    metrics
                        .tombstone_retained_fresh_store
                        .fetch_add(1, Ordering::Relaxed);
                    continue;
                }
            } else if fresh_age < cfg.min_age_secs {
                summary.skipped_young += 1;
                metrics.skipped_young.fetch_add(1, Ordering::Relaxed);
                continue;
            }

            match cfg.mode {
                Mode::Census => {
                    debug!(
                        hash = %hash_hex,
                        bytes = len,
                        age_secs = candidate.age_secs,
                        tombstoned,
                        "purge[census]: would delete"
                    );
                    summary.would_purge += 1;
                    summary.would_purge_bytes += len;
                    metrics.would_purge.fetch_add(1, Ordering::Relaxed);
                    metrics.would_purge_bytes.fetch_add(len, Ordering::Relaxed);
                    if tombstoned {
                        summary.tombstone_would_purge += 1;
                        metrics
                            .tombstone_would_purge
                            .fetch_add(1, Ordering::Relaxed);
                    }
                }
                #[cfg(feature = "purge-enforce")]
                Mode::Enforce => {
                    let result = if hard_delete {
                        store.remove(hash_hex).await
                    } else {
                        store.delete(hash_hex).await
                    };
                    match result {
                        Ok(()) => {
                            if hard_delete {
                                env.record_removed(hash_hex);
                            } else {
                                env.record_trashed(hash_hex);
                            }
                            debug!(
                                hash = %hash_hex,
                                bytes = len,
                                age_secs = candidate.age_secs,
                                tombstoned,
                                "purge: deleted"
                            );
                            summary.purged += 1;
                            summary.purged_bytes += len;
                            metrics.purged.fetch_add(1, Ordering::Relaxed);
                            metrics.purged_bytes.fetch_add(len, Ordering::Relaxed);
                            if tombstoned {
                                summary.tombstone_deleted += 1;
                                summary.tombstone_deleted_bytes += len;
                                metrics.tombstone_deleted.fetch_add(1, Ordering::Relaxed);
                                metrics
                                    .tombstone_deleted_bytes
                                    .fetch_add(len, Ordering::Relaxed);
                            }
                        }
                        Err(e) => {
                            warn!(hash = %hash_hex, error = %e, "purge: delete failed");
                            summary.delete_errors += 1;
                            metrics.delete_errors.fetch_add(1, Ordering::Relaxed);
                        }
                    }
                }
            }
            since_summary += 1;
            if since_summary >= SUMMARY_EVERY {
                since_summary = 0;
                log_progress(cfg.mode, &summary);
            }
        }
        // Let the runtime breathe between blocking page queries.
        tokio::task::yield_now().await;
    }
    summary
}

fn parse_hash(hash_hex: &str) -> Option<[u8; 32]> {
    if hash_hex.len() != 64 {
        return None;
    }
    let mut out = [0u8; 32];
    hex::decode_to_slice(hash_hex, &mut out).ok()?;
    Some(out)
}

fn log_progress(mode: Mode, s: &PassSummary) {
    info!(
        mode = ?mode,
        examined = s.examined,
        purged = s.purged,
        purged_bytes = s.purged_bytes,
        would_purge = s.would_purge,
        would_purge_bytes = s.would_purge_bytes,
        tombstone_candidates = s.tombstone_candidates,
        tombstone_deleted = s.tombstone_deleted,
        tombstone_would_purge = s.tombstone_would_purge,
        tombstone_retained_fresh_store = s.tombstone_retained_fresh_store,
        kept_by_filter = s.kept_by_filter,
        kept_moved = s.kept_moved,
        skipped_young = s.skipped_young,
        skipped_inflight = s.skipped_inflight,
        skipped_invalid = s.skipped_invalid,
        delete_errors = s.delete_errors,
        "purge: progress"
    );
}

// ============================================================================
// Census on incomplete coverage (dry-run only)
// ============================================================================

/// What one dry-run census over the inventory found under a generation
/// that does not cover every owned PG. Every blob is classified with the
/// purge rule ([`classify`]) against the lists that ARE loaded; nothing
/// is deleted, locked or marked.
///
/// The miner cannot tell which PG a blob belongs to (the inventory and
/// the store know the shard hash only; the PG is a function of the file
/// hash, which no list record carries), so a filter miss is either an
/// orphan or a blob of an uncovered PG. The `protected`, `moved` and
/// `tombstone` classes are positive (a loaded list names the hash); the
/// `orphan_*` classes are an upper bound that shrinks as coverage grows.
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct Census {
    pub generation: u64,
    /// Owned PGs whose list is folded in / owned PGs the generation
    /// does not cover.
    pub covered_pgs: usize,
    pub missing_pgs: usize,
    pub chain_broken_at: Option<u64>,
    pub examined: u64,
    /// In the membership filter: this miner's obligation in a covered
    /// PG. Blobs only, the store is not `stat`ed for the common case.
    pub protected: u64,
    /// In the others filter: listed in a covered PG under another
    /// holder. Blobs only.
    pub moved: u64,
    /// Tombstoned by a covered PG (whatever the fresh-store or in-flight
    /// clause says), with bytes.
    pub tombstone: u64,
    pub tombstone_bytes: u64,
    /// Unlisted, past the age clause and not in flight: what a
    /// full-coverage pass would delete now, if the blob is an orphan.
    pub orphan_gated: u64,
    pub orphan_gated_bytes: u64,
    /// Unlisted but too young or in flight: kept for now under any
    /// coverage.
    pub orphan_pending: u64,
    pub orphan_pending_bytes: u64,
    /// Malformed rows and rows whose blob is gone from the store.
    pub skipped_invalid: u64,
    /// Heartbeat epoch moves seen between the first and the last page
    /// (sum of the distances). A census deletes nothing and counts
    /// under the generation's pinned lists, so unlike [`run_pass`] it
    /// does NOT stop on an epoch change: on a live network the epoch moves
    /// every ~15 min and a full inventory walk takes hours, so an abort
    /// meant the census never finished on a large store. Non-zero tells that
    /// the owned set may have moved under the counts.
    pub epochs_crossed: u32,
    /// The census did not start: the map epoch and the heartbeat epoch
    /// disagreed beyond [`EPOCH_SKEW_TOLERANCE`] at the start (the held
    /// map is not current). Never set mid-pass, see `epochs_crossed`.
    pub aborted_epoch_change: bool,
    /// The filter was not built from the enforced generation's lists:
    /// nothing counted.
    pub refused_filter_generation: bool,
}

impl Census {
    /// Whether every inventory page was read.
    pub fn complete(&self) -> bool {
        !self.aborted_epoch_change && !self.refused_filter_generation
    }

    /// Publish this census as the `purge_census_*` gauges. `complete` is
    /// what the caller says: 0 for a progress snapshot, the census's own
    /// [`Census::complete`] once it returned.
    pub fn publish(&self, metrics: &PurgeMetrics, complete: bool) {
        let g = &metrics.census;
        let set = |gauge: &AtomicU64, v: u64| gauge.store(v, Ordering::Relaxed);
        set(&g.generation, self.generation);
        set(&g.covered_pgs, self.covered_pgs as u64);
        set(&g.missing_pgs, self.missing_pgs as u64);
        set(&g.examined, self.examined);
        set(&g.protected_blobs, self.protected);
        set(&g.moved_blobs, self.moved);
        set(&g.tombstone_blobs, self.tombstone);
        set(&g.tombstone_bytes, self.tombstone_bytes);
        set(&g.orphan_gated_blobs, self.orphan_gated);
        set(&g.orphan_gated_bytes, self.orphan_gated_bytes);
        set(&g.orphan_pending_blobs, self.orphan_pending);
        set(&g.orphan_pending_bytes, self.orphan_pending_bytes);
        set(&g.skipped_invalid, self.skipped_invalid);
        g.complete.store(complete, Ordering::Relaxed);
    }
}

/// One rate-bounded, read-only census over the live inventory for a
/// generation with incomplete coverage, in dry-run only. Same paging,
/// same start-of-pass skew check and same per-blob rule as [`run_pass`],
/// but the coverage gate is not consulted, and an epoch change mid-pass
/// is counted (`epochs_crossed`) instead of aborting: nothing is
/// deleted, so no decision straddles two maps. The point is to show
/// what the loaded lists say about the store while the writer is still
/// publishing. The
/// byte size is read (`BlobStore::blob_len`, a `stat`) only for the
/// classes a full-coverage dry-run would `stat` too (tombstone, orphan),
/// paced by the pass's operation budget (`PURGE_RATE_PER_SEC`): the I/O
/// profile is that of the existing dry-run, not a walk of the store.
pub async fn run_census(
    store: &dyn BlobStore,
    env: &dyn PassEnv,
    loaded: &LoadedGeneration,
    cfg: &PurgeConfig,
    epoch_at_start: u64,
) -> Census {
    let mut census = Census {
        generation: loaded.generation,
        covered_pgs: loaded.listed_pgs,
        missing_pgs: loaded.missing_pgs.len(),
        chain_broken_at: loaded.chain_broken_at,
        ..Census::default()
    };
    if !loaded.filter_matches_generation() {
        census.refused_filter_generation = true;
        return census;
    }
    let epoch_baseline = env.current_epoch().await;
    if epoch_baseline.abs_diff(epoch_at_start) > EPOCH_SKEW_TOLERANCE {
        census.aborted_epoch_change = true;
        return census;
    }
    let mut limiter = RateLimiter::new(cfg.rate_per_sec, cfg.max_bytes_per_sec);
    let mut after: Option<String> = None;
    let mut since_summary = 0u64;
    let moved_class = cfg.moved_class && loaded.has_others_filter();
    let mut epoch_last_seen = epoch_baseline;

    'pages: loop {
        // A census deletes nothing: an epoch move is recorded, not an
        // abort (the real pass, `run_pass`, keeps its abort).
        let epoch_now = env.current_epoch().await;
        if epoch_now != epoch_last_seen {
            let crossed = u32::try_from(epoch_now.abs_diff(epoch_last_seen)).unwrap_or(u32::MAX);
            census.epochs_crossed = census.epochs_crossed.saturating_add(crossed);
            info!(
                map_epoch = epoch_at_start,
                epoch_at_start = epoch_baseline,
                now = epoch_now,
                epochs_crossed = census.epochs_crossed,
                examined = census.examined,
                "purge[census]: cluster epoch changed mid-pass, continuing (read-only count under the generation's lists)"
            );
            epoch_last_seen = epoch_now;
        }
        let page = match env.live_shards_page(after.as_deref(), PAGE_SIZE) {
            Ok(p) => p,
            Err(e) => {
                error!(error = %e, "purge[census]: inventory page failed, stopping");
                break;
            }
        };
        let Some((last, _)) = page.last() else {
            break;
        };
        after = Some(last.clone());
        let reference = env.now_secs().min(loaded.snapshot_secs);

        for (hash_hex, stored_at) in &page {
            census.examined += 1;
            let Some(hash) = parse_hash(hash_hex) else {
                census.skipped_invalid += 1;
                continue;
            };
            let in_filter = loaded.may_be_obliged(&hash);
            let moved = !in_filter && moved_class && loaded.may_be_held_by_other(&hash);
            let stored_at = (*stored_at).max(0) as u64;
            let candidate = Candidate {
                age_secs: reference.saturating_sub(stored_at),
                in_filter,
                moved,
                tombstoned: !in_filter && !moved && loaded.is_tombstoned(&hash),
                stored_after_snapshot: stored_at >= reference,
                inflight: env.is_write_inflight(hash_hex),
            };
            let verdict = classify(candidate, cfg.min_age_secs);
            match verdict {
                Verdict::KeepInList => {
                    census.protected += 1;
                    continue;
                }
                Verdict::KeepMoved => {
                    census.moved += 1;
                    continue;
                }
                // The gates were not consulted: these cannot come out of
                // `classify`; stopping is the only safe reading if they do.
                Verdict::KeepEmptyOwnership
                | Verdict::KeepNoGeneration
                | Verdict::KeepGenerationStale
                | Verdict::KeepCoverageIncomplete
                | Verdict::KeepOwnershipUnstable => break 'pages,
                Verdict::Purge
                | Verdict::PurgeTombstoned
                | Verdict::KeepYoung
                | Verdict::KeepStoredAfterSnapshot
                | Verdict::KeepInflight => {}
            }
            // One `stat` per unlisted blob, paced like a dry-run deletion
            // (operation budget only: nothing is written).
            limiter.acquire(0).await;
            let Some(len) = store.blob_len(hash_hex) else {
                census.skipped_invalid += 1;
                continue;
            };
            if candidate.tombstoned {
                census.tombstone += 1;
                census.tombstone_bytes += len;
            } else if verdict == Verdict::Purge {
                census.orphan_gated += 1;
                census.orphan_gated_bytes += len;
            } else {
                census.orphan_pending += 1;
                census.orphan_pending_bytes += len;
            }
            since_summary += 1;
            if since_summary >= SUMMARY_EVERY {
                since_summary = 0;
                log_census(&census, "purge[dry-run]: census progress");
                census.publish(metrics(), false);
            }
        }
        tokio::task::yield_now().await;
    }
    census
}

fn log_census(c: &Census, message: &'static str) {
    info!(
        generation = c.generation,
        covered_pgs = c.covered_pgs,
        missing_pgs = c.missing_pgs,
        chain_broken_at = c.chain_broken_at,
        examined = c.examined,
        protected = c.protected,
        moved = c.moved,
        tombstone = c.tombstone,
        tombstone_bytes = c.tombstone_bytes,
        orphan_gated = c.orphan_gated,
        orphan_gated_bytes = c.orphan_gated_bytes,
        orphan_pending = c.orphan_pending,
        orphan_pending_bytes = c.orphan_pending_bytes,
        skipped_invalid = c.skipped_invalid,
        epochs_crossed = c.epochs_crossed,
        aborted_epoch_change = c.aborted_epoch_change,
        "{message} (orphan classes are an upper bound: a blob of an uncovered PG is indistinguishable from an orphan; nothing deleted)"
    );
}

// ============================================================================
// Ownership
// ============================================================================

/// This miner's ownership under one cluster map.
pub(crate) struct Ownership {
    pub epoch: u64,
    /// Sorted owned PGs. EMPTY for a miner the map gives no weight
    /// (quarantine, declared full, duplicate address, absence): the
    /// callers refuse to purge or backfill on it (clause 0 of the purge
    /// rule), they never treat it as "owns nothing, so nothing is
    /// obliged".
    pub pgs: Vec<u32>,
    /// This miner's CRUSH weight in that map (`None` when the map does
    /// not list this uid), for the refusal log.
    pub weight: Option<u32>,
}

/// PGs this miner owns under the current cluster map, from the shared
/// epoch-keyed cache (recomputed here on a miss so the purge does not
/// depend on the rebalance loop being enabled). `None` only when no map
/// has arrived yet; an empty owned set is returned as such.
pub(crate) async fn owned_pgs() -> Option<Ownership> {
    let map = state::get_cluster_map().read().await.clone()?;
    let epoch = map.epoch;
    let uid = state::get_miner_uid();
    let weight = map.miners.iter().find(|m| m.uid == uid).map(|m| m.weight);
    {
        let cached = state::get_my_pgs_cache().read().await;
        if cached.0 == epoch && !cached.1.is_empty() {
            let mut pgs = cached.1.clone();
            pgs.sort_unstable();
            return Some(Ownership { epoch, pgs, weight });
        }
    }
    let map_for_pgs = if map.miners.iter().any(|m| m.draining) {
        Arc::new(common::filter_map_for_placement(&map))
    } else {
        Arc::clone(&map)
    };
    // CRUSH over every PG is CPU-bound: off the runtime.
    let mut pgs = tokio::task::spawn_blocking(move || common::calculate_my_pgs(uid, &map_for_pgs))
        .await
        .unwrap_or_else(|e| {
            error!(error = %e, "purge: PG ownership calculation panicked");
            Vec::new()
        });
    pgs.sort_unstable();
    if pgs.is_empty() {
        // Not cached: the shared cache's "empty" means "not computed for
        // this epoch" to the rebalance loop. Recomputed at the next tick.
        return Some(Ownership { epoch, pgs, weight });
    }
    *state::get_my_pgs_cache().write().await = (epoch, pgs.clone());
    info!(epoch, owned_pgs = pgs.len(), "purge: PG ownership computed");
    Some(Ownership { epoch, pgs, weight })
}

// ============================================================================
// Generation refresh
// ============================================================================

/// Bring `current` up to date with the bucket for `owned`. A failure at
/// any step keeps the previous generation (logged), so a bad publication
/// never widens what may be purged; a previous generation loaded for a
/// different owned set is dropped, since its coverage no longer means
/// anything.
#[allow(clippy::too_many_arguments)]
async fn refresh_generation(
    source: &dyn ListSource,
    validator_node_id: &str,
    owned: &[u32],
    my_uid: u32,
    cfg: &PurgeConfig,
    now_secs: u64,
    current: &mut Option<LoadedGeneration>,
    highest_seen: &mut u64,
) {
    let pointer = match pg_lists::fetch_current(source).await {
        Ok(p) => p,
        Err(e) => {
            warn!(error = %format!("{e:#}"), "purge: current.json unavailable, keeping previous generation");
            return;
        }
    };
    let latest = pointer.generation;
    // A pointer that goes backwards is a replayed or corrupted bucket:
    // never step down to older lists. The watermark only advances once
    // the generation has verified and loaded, so a bogus pointer cannot
    // poison it.
    if latest < *highest_seen {
        warn!(
            latest,
            highest_seen = *highest_seen,
            "purge: current.json points at an older generation, ignoring"
        );
        drop_if_owned_set_changed(current, owned);
        return;
    }
    if let Some(loaded) = current.as_mut()
        && loaded.generation == latest
        && loaded.owned_pgs == owned
    {
        // Same generation, same PGs: only the delta chain can have grown.
        // Nothing to do while the pointer's hint is not ahead of what is
        // folded in and the chain is whole; otherwise re-fetch the base
        // manifest (its `deltas` grew) and fold the new deltas without
        // downloading the base lists again.
        if loaded.delta_seq >= pointer.delta_hint() && loaded.chain_broken_at.is_none() {
            return;
        }
        extend_generation(source, validator_node_id, my_uid, cfg, loaded, &pointer).await;
        return;
    }
    // A v2 pointer digests the base manifest it names: bytes that do not
    // match are a bucket mid-publication or a tampered object, refused
    // before parsing.
    let manifest = match pg_lists::fetch_manifest_at(source, &pointer, validator_node_id).await {
        Ok(m) => m,
        Err(e) => {
            warn!(
                generation = latest,
                error = %format!("{e:#}"),
                "purge: manifest rejected, keeping previous generation"
            );
            drop_if_owned_set_changed(current, owned);
            return;
        }
    };
    // A generation past its maximum age is not even downloaded: it could
    // not open the gate, and the previous one (older still) neither.
    match manifest.created_at_secs() {
        Some(created_at)
            if generation_is_fresh(created_at, now_secs, cfg.generation_max_age_secs) => {}
        Some(created_at) => {
            warn!(
                generation = latest,
                created_at,
                age_secs = now_secs.saturating_sub(created_at),
                max_age_secs = cfg.generation_max_age_secs,
                "purge: generation is stale (PURGE_GENERATION_MAX_AGE_SECS), not loading it"
            );
            drop_if_owned_set_changed(current, owned);
            return;
        }
        None => {
            warn!(
                generation = latest,
                "purge: manifest has no usable created_at, not loading it"
            );
            drop_if_owned_set_changed(current, owned);
            return;
        }
    }
    // Keep the previous filters only if both generations fit under the
    // caps together (main and others filters each against their own cap;
    // `PURGE_MOVED_CLASS=false` builds no others filter at all).
    let shards_per_stripe = usize::from(manifest.ec_k) + usize::from(manifest.ec_m);
    let others_cap = if cfg.moved_class {
        cfg.others_filter_max_bytes
    } else {
        0
    };
    let (new_my, new_all) = owned
        .iter()
        .filter_map(|pg| manifest.object_for_pg(*pg))
        .fold((0u64, 0u64), |(my, all), o| {
            (
                my + pg_lists::expected_my_records(o.size, shards_per_stripe, 1),
                all + pg_lists::records_in_list(o.size),
            )
        });
    let new_filter_bytes = pg_lists::HashFilter::bytes_for(new_my, cfg.filter_fp);
    let new_others_bytes = if others_cap == 0 {
        0
    } else {
        pg_lists::HashFilter::bytes_for(new_all.saturating_sub(new_my), cfg.filter_fp)
    };
    if current.as_ref().is_some_and(|c| {
        c.filter.memory_bytes() + new_filter_bytes > cfg.filter_max_bytes
            || c.others
                .as_ref()
                .map_or(0, pg_lists::HashFilter::memory_bytes)
                + new_others_bytes.min(others_cap)
                > others_cap
    }) {
        warn!("purge: dropping the previous filters to make room for the new generation");
        *current = None;
    }
    match pg_lists::load_generation(
        source,
        &manifest,
        owned,
        my_uid,
        cfg.filter_fp,
        cfg.fetch_concurrency,
        cfg.filter_max_bytes,
        others_cap,
    )
    .await
    {
        Ok(loaded) => {
            info!(
                generation = loaded.generation,
                owned_pgs = loaded.owned_pgs.len(),
                listed_pgs = loaded.listed_pgs,
                missing_pgs = loaded.missing_pgs.len(),
                records = loaded.total_records,
                hashes = loaded.total_hashes,
                shard_bytes = loaded.total_shard_bytes,
                filter_bytes = loaded.filter.memory_bytes(),
                moved_class = cfg.moved_class && loaded.has_others_filter(),
                other_hashes = loaded.total_other_hashes,
                others_filter_bytes = loaded
                    .others
                    .as_ref()
                    .map_or(0, pg_lists::HashFilter::memory_bytes),
                tombstone_pgs = loaded.tombstone_pgs,
                tombstones = loaded.tombstones.len(),
                tombstone_bytes = loaded.tombstones.len() * 32,
                tombstones_retained_live_ref = loaded.tombstones_retained_live_ref,
                delta_seq = loaded.delta_seq,
                delta_records = loaded.delta_records,
                delta_hashes = loaded.delta_hashes,
                chain_broken_at = loaded.chain_broken_at,
                snapshot_secs = loaded.snapshot_secs,
                "purge: generation loaded"
            );
            if loaded.generation > *highest_seen {
                *highest_seen = loaded.generation;
                persist_watermark(*highest_seen);
            }
            *current = Some(loaded);
        }
        Err(e) => {
            if let Some(refusal) = e.downcast_ref::<pg_lists::OthersFilterOverCap>() {
                // The moved class cannot be enforced for this generation:
                // it is refused whole, counted, and the previous one is
                // kept. Raise PURGE_OTHERS_FILTER_MAX_BYTES (or the
                // filter fp) to load it; PURGE_MOVED_CLASS=false is the
                // only way to run without the class.
                metrics()
                    .others_filter_cap_refusals
                    .fetch_add(1, Ordering::Relaxed);
                warn!(
                    generation = refusal.generation,
                    expected_others = refusal.expected_others,
                    needed_bytes = refusal.needed_bytes,
                    cap_bytes = refusal.cap_bytes,
                    "purge: generation refused, others filter over PURGE_OTHERS_FILTER_MAX_BYTES: nothing loaded from it, keeping previous generation"
                );
            } else {
                warn!(
                    generation = latest,
                    error = %format!("{e:#}"),
                    "purge: generation load failed, keeping previous generation"
                );
            }
            drop_if_owned_set_changed(current, owned);
        }
    }
}

/// Fold the deltas appended to the loaded generation since it was loaded
/// (or since the chain last broke). The base manifest is re-fetched
/// through the pointer (`pg_lists::fetch_manifest_at`: digest-checked
/// when the pointer carries one; the chain is the signed base's, or the
/// v2 pointer's when the base declares none), the already-verified delta
/// manifests are reused, and only the new `.added` bodies of the owned
/// PGs are downloaded. Any
/// failure leaves the load as it was: a broken chain is coverage
/// incomplete (the purge waits), retried at the next poll.
async fn extend_generation(
    source: &dyn ListSource,
    validator_node_id: &str,
    my_uid: u32,
    cfg: &PurgeConfig,
    loaded: &mut LoadedGeneration,
    pointer: &CurrentPointer,
) {
    let manifest = match pg_lists::fetch_manifest_at(source, pointer, validator_node_id).await {
        Ok(m) => m,
        Err(e) => {
            warn!(
                generation = loaded.generation,
                error = %format!("{e:#}"),
                "purge: manifest re-fetch for deltas failed, keeping the loaded view"
            );
            return;
        }
    };
    match loaded
        .extend(source, &manifest, my_uid, cfg.fetch_concurrency)
        .await
    {
        Ok(applied) => {
            if applied > 0 || loaded.chain_broken_at.is_some() {
                info!(
                    generation = loaded.generation,
                    applied,
                    delta_seq = loaded.delta_seq,
                    declared = manifest.declared_delta_seq(),
                    chain_broken_at = loaded.chain_broken_at,
                    delta_records = loaded.delta_records,
                    delta_hashes = loaded.delta_hashes,
                    filter_hashes = loaded.filter.inserted(),
                    snapshot_secs = loaded.snapshot_secs,
                    "purge: generation extended with deltas"
                );
            }
        }
        Err(e) => {
            warn!(
                generation = loaded.generation,
                error = %format!("{e:#}"),
                "purge: delta extension refused, keeping the loaded view"
            );
        }
    }
}

/// Bucket source for `PG_LISTS_BASE_URL`: a `file://` directory mirror
/// or an HTTP bucket.
pub(crate) fn build_source(base_url: &str) -> Result<Box<dyn ListSource>> {
    Ok(if let Some(dir) = base_url.strip_prefix("file://") {
        Box::new(DirListSource::new(dir))
    } else {
        Box::new(HttpListSource::new(base_url)?)
    })
}

/// The highest verified generation survives restarts in `data_dir` so a
/// replayed older bucket is refused after a restart too.
const WATERMARK_FILE: &str = "purge_generation";

fn load_watermark() -> u64 {
    state::get_data_dir()
        .map(|d| load_watermark_from(d))
        .unwrap_or(0)
}

pub(crate) fn load_watermark_from(data_dir: &std::path::Path) -> u64 {
    std::fs::read_to_string(data_dir.join(WATERMARK_FILE))
        .ok()
        .and_then(|s| s.trim().parse::<u64>().ok())
        .unwrap_or(0)
}

fn persist_watermark(generation: u64) {
    if let Some(data_dir) = state::get_data_dir() {
        persist_watermark_to(data_dir, generation);
    }
}

pub(crate) fn persist_watermark_to(data_dir: &std::path::Path, generation: u64) {
    let path = data_dir.join(WATERMARK_FILE);
    let tmp = path.with_extension("tmp");
    let result =
        std::fs::write(&tmp, generation.to_string()).and_then(|_| std::fs::rename(&tmp, &path));
    if let Err(e) = result {
        warn!(error = %e, path = %path.display(), "purge: cannot persist generation watermark");
    }
}

/// The owned PG set and the time it last changed survive restarts in
/// `data_dir`, next to the watermark: a restart must not reset the
/// stability clock (clause 4), or a node restarted every few hours would
/// never purge.
const OWNERSHIP_FILE: &str = "purge_ownership";

fn load_ownership() -> Option<OwnershipStability> {
    state::get_data_dir().and_then(|d| load_ownership_from(d))
}

pub(crate) fn load_ownership_from(data_dir: &std::path::Path) -> Option<OwnershipStability> {
    let text = std::fs::read_to_string(data_dir.join(OWNERSHIP_FILE)).ok()?;
    let parsed = OwnershipStability::decode(&text);
    if parsed.is_none() {
        warn!(
            path = %data_dir.join(OWNERSHIP_FILE).display(),
            "purge: persisted ownership state unreadable, stability clock starts now"
        );
    }
    parsed
}

fn persist_ownership(st: &OwnershipStability) {
    if let Some(data_dir) = state::get_data_dir() {
        persist_ownership_to(data_dir, st);
    }
}

pub(crate) fn persist_ownership_to(data_dir: &std::path::Path, st: &OwnershipStability) {
    let path = data_dir.join(OWNERSHIP_FILE);
    let tmp = path.with_extension("tmp");
    let result = std::fs::write(&tmp, st.encode()).and_then(|_| std::fs::rename(&tmp, &path));
    if let Err(e) = result {
        warn!(error = %e, path = %path.display(), "purge: cannot persist ownership state");
    }
}

/// One poll of clause 4: fold `observed` into the persisted tracker,
/// log the outcome, persist on change. Returns the tracker.
pub(crate) fn observe_ownership(
    stability: &mut Option<OwnershipStability>,
    observed: &[u32],
    now_secs: u64,
    required_secs: u64,
    persist: &dyn Fn(&OwnershipStability),
) -> bool {
    let st = match stability.as_mut() {
        None => {
            let st = OwnershipStability::first(observed, now_secs);
            info!(
                owned_pgs = st.owned().len(),
                required = required_secs,
                "purge: owned set first observed, stability clock started"
            );
            persist(&st);
            *stability = Some(st);
            return false;
        }
        Some(st) => st,
    };
    match st.observe(observed, now_secs) {
        StabilityObservation::Changed { added, removed } => {
            warn!(
                added,
                removed,
                owned_pgs = st.owned().len(),
                required = required_secs,
                "purge: owned set changed (added={added} removed={removed}), stability clock reset"
            );
            persist(st);
            false
        }
        StabilityObservation::Unchanged { stable_for_secs } => {
            info!(
                stable_secs = stable_for_secs,
                required = required_secs,
                owned_pgs = st.owned().len(),
                "purge: owned set stable for {stable_for_secs}s (required {required_secs})"
            );
            st.is_stable(now_secs, required_secs)
        }
    }
}

fn drop_if_owned_set_changed(current: &mut Option<LoadedGeneration>, owned: &[u32]) {
    if current.as_ref().is_some_and(|c| c.owned_pgs != owned) {
        warn!("purge: owned PG set changed and reload failed, dropping previous generation");
        *current = None;
    }
}

fn publish_generation_metrics(
    loaded: Option<&LoadedGeneration>,
    owned: usize,
    moved_class: bool,
    metrics: &PurgeMetrics,
) {
    match loaded {
        Some(l) => {
            metrics.generation.store(l.generation, Ordering::Relaxed);
            metrics
                .filter_hashes
                .store(l.total_hashes, Ordering::Relaxed);
            metrics
                .filter_bytes
                .store(l.filter.memory_bytes(), Ordering::Relaxed);
            metrics
                .moved_class_enforced
                .store(moved_class && l.has_others_filter(), Ordering::Relaxed);
            metrics
                .others_filter_hashes
                .store(l.total_other_hashes, Ordering::Relaxed);
            metrics.others_filter_bytes.store(
                l.others
                    .as_ref()
                    .map_or(0, pg_lists::HashFilter::memory_bytes),
                Ordering::Relaxed,
            );
            metrics
                .tombstone_retained_live_ref
                .store(l.tombstones_retained_live_ref, Ordering::Relaxed);
            metrics.set_coverage(owned as u64, l.listed_pgs as u64);
            if l.chain_broken_at.is_some() {
                // Every PG listed, but the delta chain is not whole: the
                // gate is closed, the gauge says so.
                metrics.coverage_complete.store(false, Ordering::Relaxed);
            }
            metrics.delta_seq.store(l.delta_seq, Ordering::Relaxed);
            metrics
                .delta_chain_broken
                .store(l.chain_broken_at.is_some(), Ordering::Relaxed);
        }
        None => {
            metrics.generation.store(0, Ordering::Relaxed);
            metrics.filter_hashes.store(0, Ordering::Relaxed);
            metrics.filter_bytes.store(0, Ordering::Relaxed);
            metrics.moved_class_enforced.store(false, Ordering::Relaxed);
            metrics.others_filter_hashes.store(0, Ordering::Relaxed);
            metrics.others_filter_bytes.store(0, Ordering::Relaxed);
            metrics
                .tombstone_retained_live_ref
                .store(0, Ordering::Relaxed);
            metrics.set_coverage(owned as u64, 0);
            metrics.delta_seq.store(0, Ordering::Relaxed);
            metrics.delta_chain_broken.store(false, Ordering::Relaxed);
        }
    }
}

// ============================================================================
// Loop
// ============================================================================

/// Background task. Returns immediately when the purge is disabled or has
/// no bucket URL.
pub async fn run_loop(
    store: Arc<dyn BlobStore>,
    validator_node_id: String,
    cfg: PurgeConfig,
    trash_enabled: bool,
) {
    if !cfg.enabled {
        info!("purge: disabled (PURGE_ENABLED=false)");
        return;
    }
    let Some(base_url) = cfg.base_url.clone() else {
        error!("purge: PURGE_ENABLED=true but PG_LISTS_BASE_URL is unset, purge stays off");
        return;
    };
    let source = match build_source(&base_url) {
        Ok(s) => s,
        Err(e) => {
            error!(error = %e, "purge: cannot build HTTP source, purge stays off");
            return;
        }
    };
    info!(
        base_url = %base_url,
        mode = ?cfg.mode,
        enforcement_compiled = purge::ENFORCEMENT_COMPILED,
        min_age_secs = cfg.min_age_secs,
        rate_per_sec = cfg.rate_per_sec,
        max_bytes_per_sec = cfg.max_bytes_per_sec,
        ownership_stable_secs = cfg.ownership_stable_secs,
        hard_delete = !trash_enabled,
        "purge: enabled"
    );

    let metrics = metrics();
    let env = LiveEnv;
    let mut current: Option<LoadedGeneration> = None;
    let mut last_pass_at: Option<tokio::time::Instant> = None;
    let mut last_census_at: Option<tokio::time::Instant> = None;
    let mut last_poll_at: Option<tokio::time::Instant> = None;
    let mut highest_generation_seen = load_watermark();
    if highest_generation_seen > 0 {
        info!(
            generation = highest_generation_seen,
            "purge: generation watermark restored"
        );
    }
    // Clause 4: the owned set as last observed and when it last changed,
    // restored from disk so a restart does not reset the clock.
    let mut stability = load_ownership();
    if let Some(st) = stability.as_ref() {
        info!(
            owned_pgs = st.owned().len(),
            changed_at = st.changed_at_secs(),
            stable_secs = st.stable_for_secs(common::now_secs()),
            "purge: ownership state restored"
        );
    }
    let mut last_logged_owned: Option<(u64, usize)> = None;
    let mut last_logged_coverage: Option<(u64, usize, usize)> = None;
    let mut last_logged_stale: Option<u64> = None;
    // Clause 4 applied to the owned set: a shrink by more than half is
    // not adopted before it has held for `ownership_stable_secs`.
    let mut hysteresis = OwnershipHysteresis::default();
    let mut last_logged_held: Option<(usize, usize)> = None;
    // Clause 0: generation the empty-ownership refusal was last logged for.
    let mut last_logged_empty: Option<u64> = None;

    loop {
        // Tick often enough to notice epoch changes and pass timing; the
        // bucket itself is only polled every `poll_secs`.
        tokio::time::sleep(Duration::from_secs(cfg.poll_secs.min(60))).await;

        let Some(Ownership {
            epoch: observed_epoch,
            pgs: observed,
            weight,
        }) = owned_pgs().await
        else {
            debug!("purge: no cluster map yet");
            continue;
        };
        // Clause 4 is timed on the set the map says, not on the held
        // one: when the hysteresis adopts a shrunken set after the quiet
        // period, that set has by then been stable for the same period.
        let ownership_stable = observe_ownership(
            &mut stability,
            &observed,
            common::now_secs(),
            cfg.ownership_stable_secs,
            &persist_ownership,
        );
        let decision = hysteresis.observe(
            observed_epoch,
            observed.clone(),
            tokio::time::Instant::now(),
            cfg.ownership_stable_secs,
        );
        let Some((epoch, held)) = hysteresis.held() else {
            continue;
        };
        let owned: Vec<u32> = held.to_vec();
        if let OwnershipDecision::Held { pending_for_secs } = decision {
            metrics
                .ownership_shrink_held
                .fetch_add(1, Ordering::Relaxed);
            let key = (owned.len(), observed.len());
            if last_logged_held != Some(key) {
                warn!(
                    held_epoch = epoch,
                    held_owned_pgs = owned.len(),
                    observed_epoch,
                    observed_owned_pgs = observed.len(),
                    weight = ?weight,
                    pending_for_secs,
                    required_secs = cfg.ownership_stable_secs,
                    "purge: owned PG set shrank by more than half, keeping the previous set for purge decisions until the new one is stable"
                );
                last_logged_held = Some(key);
            }
        } else {
            last_logged_held = None;
        }
        if !purge::ownership_nonempty(&owned) {
            // Clause 0: a weight-0 miner owns nothing; an empty owned set
            // would make coverage trivially complete and every blob a
            // filter miss. Nothing is refreshed, gated or purged on it.
            metrics
                .refused_empty_ownership
                .fetch_add(1, Ordering::Relaxed);
            let generation = current
                .as_ref()
                .map(|c| c.generation)
                .unwrap_or(highest_generation_seen);
            if last_logged_empty != Some(generation) {
                warn!(
                    epoch,
                    weight = ?weight,
                    generation,
                    "purge: this miner owns no PG under the current map (weight 0?), refusing to purge anything"
                );
                last_logged_empty = Some(generation);
            }
            continue;
        }
        last_logged_empty = None;
        if last_logged_owned != Some((epoch, owned.len())) {
            info!(epoch, owned_pgs = owned.len(), "purge: owned PGs");
            last_logged_owned = Some((epoch, owned.len()));
        }
        let owned_changed = current.as_ref().is_none_or(|c| c.owned_pgs != owned);
        let poll_due = last_poll_at.is_none_or(|t| t.elapsed().as_secs() >= cfg.poll_secs);
        if owned_changed || poll_due {
            refresh_generation(
                source.as_ref(),
                &validator_node_id,
                &owned,
                state::get_miner_uid(),
                &cfg,
                common::now_secs(),
                &mut current,
                &mut highest_generation_seen,
            )
            .await;
            last_poll_at = Some(tokio::time::Instant::now());
        }
        publish_generation_metrics(current.as_ref(), owned.len(), cfg.moved_class, metrics);

        let now = common::now_secs();
        let gate = PurgeGate {
            ownership_nonempty: purge::ownership_nonempty(&owned),
            generation_loaded: current.is_some(),
            // A generation ages while loaded: re-evaluated every tick.
            generation_fresh: current.as_ref().is_some_and(|c| {
                generation_is_fresh(c.created_at_secs, now, cfg.generation_max_age_secs)
            }),
            coverage_complete: current
                .as_ref()
                .is_some_and(|c| c.coverage_complete() && c.owned_pgs == owned),
            ownership_stable,
        };
        let Some(loaded) = current.as_ref() else {
            debug!("purge: no generation loaded");
            continue;
        };
        if !gate.generation_fresh {
            if last_logged_stale != Some(loaded.generation) {
                warn!(
                    generation = loaded.generation,
                    created_at = loaded.created_at_secs,
                    age_secs = now.saturating_sub(loaded.created_at_secs),
                    max_age_secs = cfg.generation_max_age_secs,
                    "purge: loaded generation is stale, purging nothing until a newer one is published"
                );
                last_logged_stale = Some(loaded.generation);
            }
            continue;
        }
        last_logged_stale = None;
        if !gate.coverage_complete {
            let key = (loaded.generation, loaded.listed_pgs, owned.len());
            if last_logged_coverage != Some(key) {
                warn!(
                    generation = loaded.generation,
                    listed = loaded.listed_pgs,
                    owned = owned.len(),
                    delta_seq = loaded.delta_seq,
                    chain_broken_at = loaded.chain_broken_at,
                    "purge: coverage incomplete: {} of {} PGs listed, delta chain {}, purging nothing",
                    loaded.listed_pgs,
                    owned.len(),
                    match loaded.chain_broken_at {
                        Some(seq) => format!("broken at seq {seq}"),
                        None => "whole".to_string(),
                    }
                );
                last_logged_coverage = Some(key);
            }
            // Dry-run only: count what the loaded lists say about the
            // store while the writer is still publishing. Read-only, at
            // the pass cadence, never on a filter built for another
            // owned set. The real purge keeps refusing above.
            if cfg.mode.is_census()
                && loaded.listed_pgs > 0
                && loaded.owned_pgs == owned
                && inventory::is_ready()
                && last_census_at.is_none_or(|t| t.elapsed().as_secs() >= cfg.pass_interval_secs)
            {
                info!(
                    generation = loaded.generation,
                    epoch,
                    covered_pgs = loaded.listed_pgs,
                    missing_pgs = loaded.missing_pgs.len(),
                    "purge[dry-run]: census starting on incomplete coverage"
                );
                let started = tokio::time::Instant::now();
                let census = run_census(store.as_ref(), &env, loaded, &cfg, epoch).await;
                // A census that read nothing is retried at the next tick.
                let refused = census.refused_filter_generation
                    || (census.aborted_epoch_change && census.examined == 0);
                if !refused {
                    last_census_at = Some(tokio::time::Instant::now());
                }
                info!(
                    elapsed_secs = started.elapsed().as_secs(),
                    "purge[dry-run]: census finished"
                );
                log_census(&census, "purge[dry-run]: census");
                census.publish(metrics, census.complete());
            }
            continue;
        }
        last_logged_coverage = None;
        if !gate.ownership_stable {
            // The per-poll `owned set stable for` / `changed` line above
            // already carries the numbers.
            debug!("purge: owned set not stable long enough, waiting");
            continue;
        }
        if !inventory::is_ready() {
            info!("purge: inventory not reconciled yet, waiting");
            continue;
        }
        if inventory::had_write_failure() {
            warn!("purge: an inventory write failed since startup, purge closed until restart");
            continue;
        }
        if last_pass_at.is_some_and(|t| t.elapsed().as_secs() < cfg.pass_interval_secs) {
            continue;
        }

        info!(
            generation = loaded.generation,
            epoch,
            owned_pgs = owned.len(),
            mode = ?cfg.mode,
            "purge: pass starting"
        );
        let started = tokio::time::Instant::now();
        // Published for the backfill, which waits while a pass deletes.
        let pass_active = state::mark_purge_pass_active();
        let summary = run_pass(
            store.as_ref(),
            &env,
            loaded,
            gate,
            &cfg,
            !trash_enabled,
            epoch,
            metrics,
        )
        .await;
        drop(pass_active);
        // A pass refused before its first page (epoch skew beyond the
        // tolerance, or a filter that does not belong to the enforced
        // generation) read nothing: it is not a pass, and the next tick
        // retries it as soon as the map catches up instead of waiting a
        // whole pass interval.
        let refused = summary.refused_filter_generation
            || (summary.aborted_epoch_change && summary.examined == 0);
        if !refused {
            metrics.passes.fetch_add(1, Ordering::Relaxed);
            last_pass_at = Some(tokio::time::Instant::now());
        }
        let generation = loaded.generation;
        if summary.refused_filter_generation {
            // Forget the generation: the next tick's refresh rebuilds the
            // filter from the lists (owned set differs from `current`).
            current = None;
            last_poll_at = None;
        }
        info!(
            generation,
            elapsed_secs = started.elapsed().as_secs(),
            aborted = summary.aborted_epoch_change,
            refused,
            refused_filter_generation = summary.refused_filter_generation,
            epoch_skew = summary.epoch_skew,
            examined = summary.examined,
            purged = summary.purged,
            purged_bytes = summary.purged_bytes,
            would_purge = summary.would_purge,
            would_purge_bytes = summary.would_purge_bytes,
            tombstone_candidates = summary.tombstone_candidates,
            tombstone_deleted = summary.tombstone_deleted,
            tombstone_deleted_bytes = summary.tombstone_deleted_bytes,
            tombstone_would_purge = summary.tombstone_would_purge,
            tombstone_retained_fresh_store = summary.tombstone_retained_fresh_store,
            kept_by_filter = summary.kept_by_filter,
            kept_moved = summary.kept_moved,
            skipped_young = summary.skipped_young,
            skipped_inflight = summary.skipped_inflight,
            skipped_invalid = summary.skipped_invalid,
            delete_errors = summary.delete_errors,
            "purge: pass finished"
        );
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use miner::flat_store::FlatBlobStore;
    #[cfg(feature = "purge-enforce")]
    use miner::pg_lists::test_fixtures::write_generation_stamped;
    use miner::pg_lists::test_fixtures::{
        CREATED_AT_SECS, MY_UID, OTHER_UID, Stamps, deterministic_key, hash_for, record_for,
        record_held_by, sorted_records, write_generation, write_generation_with_tombstones,
    };
    use std::collections::HashSet;
    use std::sync::Mutex;

    /// What a writer does to a hash at the moment the pass tries to take
    /// its lock (i.e. after the limiter wait, before the delete).
    #[derive(Clone, Copy)]
    enum WriterAtLock {
        /// A Store has just started: the hash is now in flight.
        Starts,
        /// A Store has just completed: the row carries a fresh `stored_at`.
        Completed,
    }

    /// In-memory inventory + in-flight set standing in for the globals.
    struct FakeEnv {
        rows: Mutex<Vec<(String, i64)>>,
        inflight: Mutex<HashSet<String>>,
        trashed: Mutex<Vec<String>>,
        removed: Mutex<Vec<String>>,
        epoch: std::sync::atomic::AtomicU64,
        now: u64,
        /// One-shot writer interference, applied when `try_lock_write`
        /// is first called for that hash. Deterministic stand-in for a
        /// writer racing the limiter wait (a paused clock racing real
        /// file I/O made the timed version flaky under load).
        writer_at_lock: Mutex<Option<(String, WriterAtLock)>>,
        /// One-shot: the heartbeat moves the epoch by one while the pass
        /// evaluates this hash (before its limiter wait).
        epoch_bump_at_inflight_check: Mutex<Option<String>>,
    }

    impl FakeEnv {
        fn new(rows: Vec<(String, i64)>, now: u64) -> Self {
            let mut rows = rows;
            rows.sort();
            Self {
                rows: Mutex::new(rows),
                inflight: Mutex::new(HashSet::new()),
                trashed: Mutex::new(Vec::new()),
                removed: Mutex::new(Vec::new()),
                epoch: std::sync::atomic::AtomicU64::new(5),
                now,
                writer_at_lock: Mutex::new(None),
                epoch_bump_at_inflight_check: Mutex::new(None),
            }
        }
    }

    #[async_trait::async_trait]
    impl PassEnv for FakeEnv {
        fn live_shards_page(
            &self,
            after: Option<&str>,
            limit: usize,
        ) -> Result<Vec<(String, i64)>> {
            let rows = self.rows.lock().unwrap();
            Ok(rows
                .iter()
                .filter(|(h, _)| after.is_none_or(|a| h.as_str() > a))
                .take(limit)
                .cloned()
                .collect())
        }
        fn is_write_inflight(&self, hash_hex: &str) -> bool {
            if self
                .epoch_bump_at_inflight_check
                .lock()
                .unwrap()
                .take_if(|h| h == hash_hex)
                .is_some()
            {
                self.epoch.fetch_add(1, Ordering::Relaxed);
            }
            self.inflight.lock().unwrap().contains(hash_hex)
        }
        fn try_lock_write(&self, hash_hex: &str) -> Option<state::HashWriteLock> {
            let pending = self
                .writer_at_lock
                .lock()
                .unwrap()
                .take_if(|(h, _)| h == hash_hex);
            match pending {
                Some((_, WriterAtLock::Starts)) => {
                    self.inflight.lock().unwrap().insert(hash_hex.to_string());
                }
                Some((_, WriterAtLock::Completed)) => {
                    for row in self.rows.lock().unwrap().iter_mut() {
                        if row.0 == hash_hex {
                            row.1 = self.now as i64;
                        }
                    }
                }
                None => {}
            }
            if self.inflight.lock().unwrap().contains(hash_hex) {
                return None;
            }
            state::try_lock_hash_write(hash_hex)
        }
        fn live_stored_at(&self, hash_hex: &str) -> Result<Option<i64>> {
            Ok(self
                .rows
                .lock()
                .unwrap()
                .iter()
                .find(|(h, _)| h == hash_hex)
                .map(|(_, at)| *at))
        }
        #[cfg(feature = "purge-enforce")]
        fn record_trashed(&self, hash_hex: &str) {
            self.trashed.lock().unwrap().push(hash_hex.to_string());
        }
        #[cfg(feature = "purge-enforce")]
        fn record_removed(&self, hash_hex: &str) {
            self.removed.lock().unwrap().push(hash_hex.to_string());
        }
        async fn current_epoch(&self) -> u64 {
            self.epoch.load(Ordering::Relaxed)
        }
        fn now_secs(&self) -> u64 {
            self.now
        }
    }

    const OPEN: PurgeGate = PurgeGate {
        ownership_nonempty: true,
        generation_loaded: true,
        generation_fresh: true,
        coverage_complete: true,
        ownership_stable: true,
    };

    /// The mode a real run would take in this build: `Enforce` with the
    /// `purge-enforce` feature, else the only mode there is. Tests that
    /// assert a refusal use it so the refusal is exercised against the
    /// strongest mode compiled; tests that assert an actual deletion are
    /// gated on the feature.
    fn strongest() -> Mode {
        Mode::from_dry_run(false)
    }

    fn fast_cfg(mode: Mode) -> PurgeConfig {
        PurgeConfig {
            mode,
            min_age_secs: 3600,
            rate_per_sec: 1_000_000,
            max_bytes_per_sec: u64::MAX / 4,
            ..PurgeConfig::default()
        }
    }

    /// A store with: 3 obliged blobs (in PG 10/11 lists), 2 stray old
    /// blobs, 1 stray young blob, 1 stray old blob in flight; a loaded
    /// generation for PGs 10 and 11.
    async fn scenario(
        dir: &std::path::Path,
    ) -> (
        FlatBlobStore,
        LoadedGeneration,
        FakeEnv,
        Vec<String>,
        Vec<String>,
    ) {
        let key = deterministic_key(3);
        let fx = write_generation(&dir.join("bucket"), &key, 9, &[10, 11], 20);
        let source = DirListSource::new(dir.join("bucket"));
        let manifest = pg_lists::fetch_manifest(&source, 9, &fx.validator_hex())
            .await
            .unwrap();
        let loaded =
            pg_lists::load_generation(&source, &manifest, &[10, 11], MY_UID, 0.01, 2, 1 << 30, 0)
                .await
                .unwrap();
        assert!(loaded.coverage_complete());

        let store = FlatBlobStore::new(dir.join("blobs")).unwrap();
        let now = 1_000_000u64;
        let mut rows = Vec::new();
        let mut obliged = Vec::new();
        for (pg, i) in [(10u32, 0u32), (10, 7), (11, 19)] {
            let h = hex::encode(hash_for(pg, i));
            store.store(&h, b"obliged").await.unwrap();
            rows.push((h.clone(), (now - 86_400) as i64));
            obliged.push(h);
        }
        // Per-test hashes: the per-hash write lock is process-wide, so two
        // tests sharing a stray hash would see each other's lock. A stray
        // must also miss the Bloom filter (1 % false positives = keep):
        // walk the tag until it does.
        let stray = |tag: &str| {
            (0u32..)
                .map(|i| {
                    *blake3::hash(format!("{}/{tag}/{i}", dir.display()).as_bytes()).as_bytes()
                })
                .find(|h| !loaded.may_be_obliged(h))
                .map(hex::encode)
                .unwrap()
        };
        let old_a = stray("stray-old-a");
        let old_b = stray("stray-old-b");
        let young = stray("stray-young");
        let inflight = stray("stray-inflight");
        for h in [&old_a, &old_b, &young, &inflight] {
            store.store(h, b"stray-bytes").await.unwrap();
        }
        rows.push((old_a.clone(), (now - 7200) as i64));
        rows.push((old_b.clone(), (now - 3600) as i64)); // exactly min_age: purgeable
        rows.push((young.clone(), (now - 3599) as i64));
        rows.push((inflight.clone(), (now - 7200) as i64));
        // A row whose blob is gone from disk, and a malformed row.
        rows.push((stray("ghost"), (now - 7200) as i64));
        rows.push(("not-a-hash".to_string(), (now - 7200) as i64));

        let env = FakeEnv::new(rows, now);
        env.inflight.lock().unwrap().insert(inflight.clone());
        let mut keep = obliged.clone();
        keep.push(young);
        keep.push(inflight);
        (store, loaded, env, vec![old_a, old_b], keep)
    }

    #[tokio::test]
    async fn dry_run_deletes_nothing_but_counts() {
        let dir = tempfile::tempdir().unwrap();
        let (store, loaded, env, stray_old, keep) = scenario(dir.path()).await;
        let metrics = PurgeMetrics::default();
        let s = run_pass(
            &store,
            &env,
            &loaded,
            OPEN,
            &fast_cfg(Mode::Census),
            false,
            5,
            &metrics,
        )
        .await;
        assert_eq!(s.examined, 9);
        assert_eq!(s.would_purge, 2);
        assert_eq!(s.would_purge_bytes, 2 * "stray-bytes".len() as u64);
        assert_eq!(s.purged, 0, "{s:?}");
        assert_eq!(s.kept_by_filter, 3);
        assert_eq!(s.skipped_young, 1);
        assert_eq!(s.skipped_inflight, 1);
        assert_eq!(s.skipped_invalid, 2, "ghost row + malformed row");
        for h in stray_old.iter().chain(keep.iter()) {
            assert!(store.has(h), "dry-run must keep {h}");
        }
        assert!(env.trashed.lock().unwrap().is_empty());
        assert_eq!(metrics.would_purge.load(Ordering::Relaxed), 2);
        assert_eq!(metrics.purged.load(Ordering::Relaxed), 0);
    }

    /// The release guard: `PURGE_ENABLED=true PURGE_DRY_RUN=false` on a
    /// build without the `purge-enforce` feature resolves to the census
    /// mode, and a pass over a complete, valid generation — the exact
    /// situation in which an enforcing build would delete — unlinks and
    /// trashes nothing while the census counters are populated.
    #[cfg(not(feature = "purge-enforce"))]
    #[tokio::test]
    async fn enforcement_requested_by_env_is_a_census_in_this_build() {
        let cfg = PurgeConfig::from_lookup(|n| match n {
            "PURGE_ENABLED" => Some("true".into()),
            "PURGE_DRY_RUN" => Some("false".into()),
            _ => None,
        })
        .unwrap();
        assert!(cfg.enabled);
        assert_eq!(cfg.mode, Mode::Census, "the only mode compiled");
        assert!(!purge::ENFORCEMENT_COMPILED);

        let dir = tempfile::tempdir().unwrap();
        let (store, loaded, env, stray_old, keep) = scenario(dir.path()).await;
        // Same pacing as the other tests; the mode is the one under test.
        let cfg = PurgeConfig {
            mode: cfg.mode,
            enabled: cfg.enabled,
            ..fast_cfg(Mode::Census)
        };
        let metrics = PurgeMetrics::default();
        for hard_delete in [false, true] {
            let s = run_pass(&store, &env, &loaded, OPEN, &cfg, hard_delete, 5, &metrics).await;
            assert_eq!(s.examined, 9, "hard_delete={hard_delete}");
            assert_eq!(s.would_purge, 2, "hard_delete={hard_delete} {s:?}");
            assert_eq!(s.purged, 0);
            assert_eq!(s.purged_bytes, 0);
            assert_eq!(s.delete_errors, 0);
        }
        for h in stray_old.iter().chain(keep.iter()) {
            assert!(store.has(h), "{h} must still be live");
            assert!(!store.has_trashed(h), "{h} must not be trashed");
        }
        assert!(env.trashed.lock().unwrap().is_empty());
        assert!(env.removed.lock().unwrap().is_empty());
        assert_eq!(metrics.would_purge.load(Ordering::Relaxed), 4);
        assert_eq!(metrics.purged.load(Ordering::Relaxed), 0);
        assert!(
            metrics
                .render_prometheus()
                .contains("purge_purged_total 0\n")
        );
    }

    /// Partial coverage: the miner owns PGs 10..=13, the generation lists
    /// 10 and 11 only. The census classifies with the loaded lists: the
    /// blobs those lists name are protected / moved / tombstone, every
    /// other blob (strays AND the shards of the uncovered PGs, which the
    /// miner cannot tell apart) is an orphan upper bound split by the age
    /// clause. Nothing is deleted, and the real pass keeps refusing the
    /// closed coverage gate.
    #[tokio::test]
    async fn census_on_partial_coverage_counts_with_the_loaded_lists_and_deletes_nothing() {
        let dir = tempfile::tempdir().unwrap();
        let key = deterministic_key(11);
        let now = 1_000_000u64;
        let named = |tag: &str| *blake3::hash(format!("census-test/{tag}").as_bytes()).as_bytes();
        let tombstoned = named("deleted");
        let stones: &dyn Fn(u32) -> Vec<[u8; 32]> = &|pg| match pg {
            10 => vec![tombstoned],
            _ => vec![],
        };
        // PG 10: records 0..20 mine except record 5, held by another
        // holder of the PG (the moved class).
        let fx = write_generation_with_tombstones(
            &dir.path().join("bucket"),
            &key,
            9,
            &[10, 11],
            &Stamps::default(),
            &|pg| {
                (0..20)
                    .map(|i| {
                        if pg == 10 && i == 5 {
                            record_held_by(pg, i, OTHER_UID)
                        } else {
                            record_for(pg, i)
                        }
                    })
                    .collect()
            },
            Some(stones),
        );
        let source = DirListSource::new(dir.path().join("bucket"));
        let manifest = pg_lists::fetch_manifest(&source, 9, &fx.validator_hex())
            .await
            .unwrap();
        let owned = [10u32, 11, 12, 13];
        let loaded = pg_lists::load_generation(
            &source,
            &manifest,
            &owned,
            MY_UID,
            0.01,
            2,
            1 << 30,
            1 << 30,
        )
        .await
        .unwrap();
        assert_eq!(loaded.missing_pgs, vec![12, 13]);
        assert_eq!(loaded.listed_pgs, 2);
        assert!(!loaded.coverage_complete());
        assert!(loaded.has_others_filter());

        let store = FlatBlobStore::new(dir.path().join("blobs")).unwrap();
        let inflight = named("stray-inflight");
        let blobs: [([u8; 32], u64); 7] = [
            // Protected: two of my records in covered PGs.
            (hash_for(10, 0), 86_400),
            (hash_for(11, 19), 86_400),
            // Moved: PG 10 record 5, another holder's.
            (hash_for(10, 5), 86_400),
            // Tombstoned by PG 10, one hour old (no age clause).
            (tombstoned, 3600),
            // Shards of the uncovered PGs 12 and 13: filter misses. Old:
            // orphan upper bound, gated; young: pending.
            (hash_for(12, 1), 86_400),
            (hash_for(13, 2), 600),
            // A true stray, old, in flight: pending.
            (inflight, 86_400),
        ];
        let mut rows = Vec::new();
        for (h, age) in blobs {
            let hex = hex::encode(h);
            store.store(&hex, b"shard-bytes").await.unwrap();
            rows.push((hex, (now - age) as i64));
        }
        for h in [hash_for(12, 1), hash_for(13, 2), inflight] {
            assert!(!loaded.may_be_obliged(&h), "fixture hash hit the filter");
            assert!(
                !loaded.may_be_held_by_other(&h),
                "fixture hash hit the others filter"
            );
        }
        // A row whose blob is gone, and a malformed row.
        rows.push((hex::encode(named("ghost")), (now - 86_400) as i64));
        rows.push(("not-a-hash".to_string(), (now - 86_400) as i64));
        let env = FakeEnv::new(rows, now);
        env.inflight.lock().unwrap().insert(hex::encode(inflight));
        let cfg = fast_cfg(Mode::Census);
        let shard = "shard-bytes".len() as u64;

        let c = run_census(&store, &env, &loaded, &cfg, 5).await;
        assert_eq!((c.covered_pgs, c.missing_pgs), (2, 2));
        assert_eq!(c.examined, 9);
        assert_eq!(c.protected, 2, "{c:?}");
        assert_eq!(c.moved, 1);
        assert_eq!((c.tombstone, c.tombstone_bytes), (1, shard));
        assert_eq!((c.orphan_gated, c.orphan_gated_bytes), (1, shard));
        assert_eq!((c.orphan_pending, c.orphan_pending_bytes), (2, 2 * shard));
        assert_eq!(c.skipped_invalid, 2, "ghost + malformed");
        assert!(!c.aborted_epoch_change && !c.refused_filter_generation);
        assert!(c.complete());
        // Published as gauges, exposed under `purge_census_*`.
        let m = PurgeMetrics::default();
        c.publish(&m, false);
        assert!(
            !m.census.complete.load(Ordering::Relaxed),
            "progress snapshot"
        );
        c.publish(&m, c.complete());
        let text = m.render_prometheus();
        for line in [
            "purge_census_generation 9".to_string(),
            "purge_census_covered_pgs 2".into(),
            "purge_census_missing_pgs 2".into(),
            "purge_census_examined 9".into(),
            "purge_census_protected_blobs 2".into(),
            "purge_census_moved_blobs 1".into(),
            "purge_census_tombstone_blobs 1".into(),
            format!("purge_census_tombstone_bytes {shard}"),
            "purge_census_orphan_gated_blobs 1".into(),
            format!("purge_census_orphan_gated_bytes {shard}"),
            "purge_census_orphan_pending_blobs 2".into(),
            format!("purge_census_orphan_pending_bytes {}", 2 * shard),
            "purge_census_skipped_invalid 2".into(),
            "purge_census_complete 1".into(),
        ] {
            assert!(
                text.contains(&format!("{line}\n")),
                "missing `{line}` in\n{text}"
            );
        }
        // Read-only: every blob is still there, nothing trashed or removed.
        for (h, _) in env.rows.lock().unwrap().iter() {
            if h.len() == 64 && !h.starts_with(&hex::encode(named("ghost"))[..8]) {
                assert!(store.has(h), "census must keep {h}");
            }
        }
        assert!(env.trashed.lock().unwrap().is_empty());
        assert!(env.removed.lock().unwrap().is_empty());

        // The same generation through the real pass, coverage gate closed:
        // refused before the first page, in dry-run and for real.
        let closed = PurgeGate {
            coverage_complete: false,
            ..OPEN
        };
        for mode in [Mode::Census, strongest()] {
            let metrics = PurgeMetrics::default();
            let s = run_pass(
                &store,
                &env,
                &loaded,
                closed,
                &fast_cfg(mode),
                false,
                5,
                &metrics,
            )
            .await;
            assert_eq!(s, PassSummary::default(), "mode={mode:?}");
        }
        assert!(env.trashed.lock().unwrap().is_empty());

        // A heartbeat epoch ahead by more than the tolerance counts nothing.
        let c = run_census(&store, &env, &loaded, &cfg, 5 + EPOCH_SKEW_TOLERANCE + 1).await;
        assert!(c.aborted_epoch_change);
        assert_eq!(c.examined, 0);
    }

    /// Tombstone class, dry-run then real: a blob held one hour, far
    /// younger than `min_age_secs` (14 days here), is purged when the
    /// generation's `.deleted` names it and retained when it does not;
    /// a tombstoned hash the list still obliges is kept; a tombstoned
    /// hash with a write in flight is skipped. The counters split the
    /// class out of the totals.
    #[tokio::test]
    async fn tombstoned_young_blob_is_purged_without_the_age_gate() {
        let dir = tempfile::tempdir().unwrap();
        let key = deterministic_key(4);
        let now = 1_000_000u64;
        // Deterministic hashes, distinct per test (process-wide write locks).
        let named =
            |tag: &str| *blake3::hash(format!("tombstone-test/{tag}").as_bytes()).as_bytes();
        let (tomb_young, tomb_inflight, plain_young) = (
            named("deleted-young"),
            named("deleted-inflight"),
            named("not-deleted-young"),
        );
        let listed_and_tombstoned = hash_for(10, 3); // record 3 of PG 10 is MY_UID's
        let write = |tombstones: bool| {
            let bucket = dir.path().join(if tombstones { "with" } else { "without" });
            let stones: &dyn Fn(u32) -> Vec<[u8; 32]> = &|pg| match pg {
                10 => vec![tomb_young, listed_and_tombstoned],
                11 => vec![tomb_inflight],
                _ => vec![],
            };
            write_generation_with_tombstones(
                &bucket,
                &key,
                9,
                &[10, 11],
                &Stamps::default(),
                &|pg| sorted_records(pg, 20),
                if tombstones { Some(stones) } else { None },
            )
        };
        let mut loaded_with = None;
        let mut loaded_without = None;
        for tombstones in [true, false] {
            let fx = write(tombstones);
            let bucket = dir.path().join(if tombstones { "with" } else { "without" });
            let source = DirListSource::new(&bucket);
            let manifest = pg_lists::fetch_manifest(&source, 9, &fx.validator_hex())
                .await
                .unwrap();
            let loaded = pg_lists::load_generation(
                &source,
                &manifest,
                &[10, 11],
                MY_UID,
                0.01,
                2,
                1 << 30,
                0,
            )
            .await
            .unwrap();
            if tombstones {
                loaded_with = Some(loaded);
            } else {
                loaded_without = Some(loaded);
            }
        }
        let (loaded_with, loaded_without) = (loaded_with.unwrap(), loaded_without.unwrap());
        // The listed hash's tombstone is withdrawn at load time (exact),
        // the two unlisted ones stay.
        assert_eq!(loaded_with.tombstones.len(), 2);
        assert_eq!(loaded_with.tombstones_retained_live_ref, 1);
        assert!(!loaded_with.is_tombstoned(&listed_and_tombstoned));
        assert!(loaded_without.tombstones.is_empty());
        // The Bloom filter must miss the three unlisted hashes for the test
        // to mean anything (1 % FP): assert rather than search.
        for h in [&tomb_young, &tomb_inflight, &plain_young] {
            assert!(
                !loaded_with.may_be_obliged(h),
                "fixture hash hit the filter"
            );
        }

        let store = FlatBlobStore::new(dir.path().join("blobs")).unwrap();
        let mut rows = Vec::new();
        for h in [
            &tomb_young,
            &tomb_inflight,
            &plain_young,
            &listed_and_tombstoned,
        ] {
            let hex = hex::encode(h);
            store.store(&hex, b"shard").await.unwrap();
            rows.push((hex, (now - 3600) as i64)); // one hour old
        }
        let env = FakeEnv::new(rows, now);
        env.inflight
            .lock()
            .unwrap()
            .insert(hex::encode(tomb_inflight));
        let cfg = PurgeConfig {
            min_age_secs: 14 * 86_400,
            ..fast_cfg(Mode::Census)
        };

        // Dry-run with tombstones: exactly the young tombstoned blob.
        let metrics = PurgeMetrics::default();
        let s = run_pass(&store, &env, &loaded_with, OPEN, &cfg, false, 5, &metrics).await;
        assert_eq!(s.examined, 4);
        assert_eq!(s.tombstone_candidates, 1, "{s:?}");
        assert_eq!(s.would_purge, 1);
        assert_eq!(s.tombstone_would_purge, 1);
        assert_eq!(s.purged, 0);
        assert_eq!(s.kept_by_filter, 1, "listed wins over its tombstone");
        assert_eq!(
            s.skipped_young, 1,
            "the untombstoned young blob keeps the age gate"
        );
        assert_eq!(s.skipped_inflight, 1);
        assert_eq!(metrics.tombstone_would_purge.load(Ordering::Relaxed), 1);
        assert_eq!(metrics.tombstone_deleted.load(Ordering::Relaxed), 0);
        assert!(store.has(&hex::encode(tomb_young)), "dry-run keeps it");

        // Same store, same blob, generation without tombstones: retained.
        let metrics = PurgeMetrics::default();
        let s = run_pass(
            &store,
            &env,
            &loaded_without,
            OPEN,
            &cfg,
            false,
            5,
            &metrics,
        )
        .await;
        assert_eq!(s.tombstone_candidates, 0);
        assert_eq!(s.would_purge, 0, "{s:?}");
        // Orphan order is age before in-flight: all three unlisted young
        // blobs are kept by the age clause.
        assert_eq!(s.skipped_young, 3);
        assert_eq!(s.skipped_inflight, 0);
        assert_eq!(s.kept_by_filter, 1);

        #[cfg(feature = "purge-enforce")]
        {
            // Real run with tombstones: trashed, counted in both totals.
            let cfg = PurgeConfig {
                mode: Mode::Enforce,
                ..cfg
            };
            let metrics = PurgeMetrics::default();
            let s = run_pass(&store, &env, &loaded_with, OPEN, &cfg, false, 5, &metrics).await;
            assert_eq!(s.purged, 1, "{s:?}");
            assert_eq!(s.tombstone_deleted, 1);
            assert_eq!(s.tombstone_deleted_bytes, "shard".len() as u64);
            assert_eq!(s.purged_bytes, s.tombstone_deleted_bytes);
            assert_eq!(metrics.tombstone_deleted.load(Ordering::Relaxed), 1);
            assert!(
                metrics
                    .render_prometheus()
                    .contains("purge_tombstone_deleted_total 1\n")
            );
            assert!(!store.has(&hex::encode(tomb_young)));
            assert!(store.has_trashed(&hex::encode(tomb_young)));
            for h in [&tomb_inflight, &plain_young, &listed_and_tombstoned] {
                assert!(store.has(&hex::encode(h)), "must survive");
            }
        }
    }

    /// A tombstone proves the deletion the writer saw, not the absence
    /// of a write it could not see: a blob whose `stored_at` is at or
    /// after the generation's snapshot bound (a re-upload of the same
    /// content lands on the same hash and refreshes the row) is retained,
    /// both at the decision and when a writer completes during the
    /// limiter wait (re-read under the lock). The plain old tombstoned
    /// blob still goes.
    #[cfg(feature = "purge-enforce")]
    #[tokio::test]
    async fn tombstoned_blob_stored_at_or_after_the_snapshot_is_kept() {
        let dir = tempfile::tempdir().unwrap();
        let key = deterministic_key(6);
        // now > snapshot: the reference is the fixture's CREATED_AT.
        let now = CREATED_AT_SECS + 86_400;
        let named =
            |tag: &str| *blake3::hash(format!("tombstone-fresh-test/{tag}").as_bytes()).as_bytes();
        let (at_snapshot, after_snapshot, during_wait, old) = (
            named("at-snapshot"),
            named("after-snapshot"),
            named("during-wait"),
            named("old"),
        );
        let stones: &dyn Fn(u32) -> Vec<[u8; 32]> = &|pg| match pg {
            10 => vec![at_snapshot, after_snapshot, during_wait, old],
            _ => vec![],
        };
        let fx = write_generation_with_tombstones(
            dir.path(),
            &key,
            9,
            &[10, 11],
            &Stamps::default(),
            &|pg| sorted_records(pg, 20),
            Some(stones),
        );
        let source = DirListSource::new(dir.path());
        let manifest = pg_lists::fetch_manifest(&source, 9, &fx.validator_hex())
            .await
            .unwrap();
        let loaded =
            pg_lists::load_generation(&source, &manifest, &[10, 11], MY_UID, 0.01, 2, 1 << 30, 0)
                .await
                .unwrap();
        assert_eq!(loaded.snapshot_secs, CREATED_AT_SECS);
        assert_eq!(loaded.tombstones.len(), 4);
        for h in [&at_snapshot, &after_snapshot, &during_wait, &old] {
            assert!(!loaded.may_be_obliged(h), "fixture hash hit the filter");
        }

        let store = FlatBlobStore::new(dir.path().join("blobs")).unwrap();
        let mut rows = Vec::new();
        for (h, stored_at) in [
            (&at_snapshot, CREATED_AT_SECS),
            (&after_snapshot, CREATED_AT_SECS + 10),
            (&during_wait, CREATED_AT_SECS - 3600),
            (&old, CREATED_AT_SECS - 3600),
        ] {
            let hex = hex::encode(h);
            store.store(&hex, b"shard").await.unwrap();
            rows.push((hex, stored_at as i64));
        }
        let env = FakeEnv::new(rows, now);
        // A writer completes on `during_wait` while it sits in the
        // limiter: the row is refreshed to `now` before the lock is taken.
        *env.writer_at_lock.lock().unwrap() =
            Some((hex::encode(during_wait), WriterAtLock::Completed));
        let cfg = PurgeConfig {
            min_age_secs: 14 * 86_400,
            ..fast_cfg(strongest())
        };
        let metrics = PurgeMetrics::default();
        let s = run_pass(&store, &env, &loaded, OPEN, &cfg, false, 5, &metrics).await;
        assert_eq!(s.examined, 4);
        assert_eq!(s.purged, 1, "{s:?}");
        assert_eq!(s.tombstone_deleted, 1);
        assert_eq!(
            s.tombstone_retained_fresh_store, 3,
            "two at the decision, one under the lock: {s:?}"
        );
        assert_eq!(s.skipped_young, 0, "the age clause is not what kept them");
        assert_eq!(
            metrics
                .tombstone_retained_fresh_store
                .load(Ordering::Relaxed),
            3
        );
        assert!(
            metrics
                .render_prometheus()
                .contains("purge_tombstone_retained_fresh_store_total 3\n")
        );
        assert!(!store.has(&hex::encode(old)));
        for h in [&at_snapshot, &after_snapshot, &during_wait] {
            assert!(store.has(&hex::encode(h)), "kept: {}", hex::encode(h));
        }
    }

    /// Moved class: an old blob listed in an owned PG under ANOTHER
    /// holder is retained (not even a candidate for the age or tombstone
    /// clauses), whether the list also tombstones it or not. With
    /// `PURGE_MOVED_CLASS=false`, or with an others filter refused for
    /// its cap, the same blob is an orphan again and goes — as an orphan,
    /// never as a tombstone: the live record withdrew the tombstone at
    /// load time, independently of the others filter.
    #[tokio::test]
    async fn moved_blob_is_retained_unless_the_class_is_off() {
        let dir = tempfile::tempdir().unwrap();
        let key = deterministic_key(5);
        // Age is measured from the earlier of now and the snapshot: a
        // `now` well past CREATED_AT keeps the fixture stamp the bound.
        let now = CREATED_AT_SECS + 86_400;
        let named = |tag: &str| *blake3::hash(format!("moved-test/{tag}").as_bytes()).as_bytes();
        let (moved, moved_and_tombstoned, orphan) =
            (named("moved"), named("moved-tombstoned"), named("orphan"));
        // PG 10: this miner's records 0..20, plus two records held by
        // OTHER_UID whose hashes are `moved` and `moved_and_tombstoned`;
        // the latter is also in PG 10's `.deleted` (a live file and a
        // deleted file sharing the shard bytes).
        let records: &dyn Fn(u32) -> Vec<pg_lists::Record> = &|pg| {
            let mut r = sorted_records(pg, 20);
            if pg == 10 {
                let mut a = record_held_by(10, 900, OTHER_UID);
                a.blob_hash = moved;
                let mut b = record_held_by(10, 901, OTHER_UID);
                b.blob_hash = moved_and_tombstoned;
                r.push(a);
                r.push(b);
            }
            r
        };
        let stones: &dyn Fn(u32) -> Vec<[u8; 32]> = &|pg| match pg {
            10 => vec![moved_and_tombstoned],
            _ => vec![],
        };
        let fx = write_generation_with_tombstones(
            dir.path(),
            &key,
            9,
            &[10, 11],
            &Stamps::default(),
            records,
            Some(stones),
        );
        let source = DirListSource::new(dir.path());
        let manifest = pg_lists::fetch_manifest(&source, 9, &fx.validator_hex())
            .await
            .unwrap();
        let load = |others_cap: u64| {
            pg_lists::load_generation(
                &source,
                &manifest,
                &[10, 11],
                MY_UID,
                0.01,
                2,
                1 << 30,
                others_cap,
            )
        };
        let with_others = load(256 << 20).await.unwrap();
        assert!(with_others.has_others_filter());
        assert_eq!(with_others.total_other_hashes, 2);
        assert_eq!(with_others.total_hashes, 40);
        assert!(with_others.may_be_held_by_other(&moved));
        assert!(with_others.may_be_held_by_other(&moved_and_tombstoned));
        assert!(
            !with_others.is_tombstoned(&moved_and_tombstoned),
            "a hash a live record names is withdrawn from the tombstone set"
        );
        assert_eq!(with_others.tombstones_retained_live_ref, 1);
        for h in [&moved, &moved_and_tombstoned, &orphan] {
            assert!(
                !with_others.may_be_obliged(h),
                "fixture hash hit the filter"
            );
        }
        assert!(!with_others.may_be_held_by_other(&orphan));
        // Over the cap: the generation is refused, there is nothing to
        // run a pass on (the class is never silently off).
        let refusal = load(1)
            .await
            .expect_err("over the cap refuses the generation");
        let refusal = refusal
            .downcast_ref::<pg_lists::OthersFilterOverCap>()
            .expect("typed refusal");
        assert_eq!(refusal.cap_bytes, 1);
        assert!(refusal.needed_bytes > 1);
        assert!(
            refusal.expected_others > 0,
            "sized from the manifest before any list is read"
        );
        // Cap 0: the caller asked for none, not an over-cap.
        let none = load(0).await.unwrap();
        assert!(!none.has_others_filter());

        let store = FlatBlobStore::new(dir.path().join("blobs")).unwrap();
        let mut rows = Vec::new();
        for h in [&moved, &moved_and_tombstoned, &orphan] {
            let hex = hex::encode(h);
            store.store(&hex, b"shard").await.unwrap();
            rows.push((hex, (CREATED_AT_SECS - 30 * 86_400) as i64)); // 30 days before the snapshot
        }
        let env = FakeEnv::new(rows, now);
        let cfg = PurgeConfig {
            min_age_secs: 14 * 86_400,
            ..fast_cfg(Mode::Census)
        };
        assert!(cfg.moved_class, "default on");

        // Dry-run, class on: only the orphan would go.
        let metrics = PurgeMetrics::default();
        let s = run_pass(&store, &env, &with_others, OPEN, &cfg, false, 5, &metrics).await;
        assert_eq!(s.examined, 3);
        assert_eq!(s.kept_moved, 2, "{s:?}");
        assert_eq!(s.would_purge, 1);
        assert_eq!(
            s.tombstone_candidates, 0,
            "a hash with a live record is never in the tombstone class"
        );
        assert_eq!(metrics.kept_moved.load(Ordering::Relaxed), 2);
        assert!(
            metrics
                .render_prometheus()
                .contains("miner_purge_kept_moved_total 2\n")
        );

        // Rollback flag: same load, the class is off, both go as old
        // orphans (30 days > min age); none as a tombstone.
        let off = PurgeConfig {
            moved_class: false,
            ..cfg.clone()
        };
        let metrics = PurgeMetrics::default();
        let s = run_pass(&store, &env, &with_others, OPEN, &off, false, 5, &metrics).await;
        assert_eq!(s.kept_moved, 0);
        assert_eq!(s.would_purge, 3, "{s:?}");
        assert_eq!(
            s.tombstone_candidates, 0,
            "withdrawn at load: the class being off never revives a tombstone"
        );

        #[cfg(feature = "purge-enforce")]
        {
            // Real run, class on: the two moved blobs survive.
            let real = PurgeConfig {
                mode: Mode::Enforce,
                ..cfg
            };
            let metrics = PurgeMetrics::default();
            let s = run_pass(&store, &env, &with_others, OPEN, &real, false, 5, &metrics).await;
            assert_eq!(s.purged, 1, "{s:?}");
            assert_eq!(s.kept_moved, 2);
            assert!(!store.has(&hex::encode(orphan)));
            assert!(store.has(&hex::encode(moved)));
            assert!(store.has(&hex::encode(moved_and_tombstoned)));
        }
    }

    #[cfg(feature = "purge-enforce")]
    #[tokio::test]
    async fn real_run_trashes_only_old_stray_blobs() {
        let dir = tempfile::tempdir().unwrap();
        let (store, loaded, env, stray_old, keep) = scenario(dir.path()).await;
        let metrics = PurgeMetrics::default();
        let s = run_pass(
            &store,
            &env,
            &loaded,
            OPEN,
            &fast_cfg(strongest()),
            false,
            5,
            &metrics,
        )
        .await;
        assert_eq!(s.purged, 2, "{s:?}");
        assert_eq!(s.purged_bytes, 2 * "stray-bytes".len() as u64);
        assert_eq!(s.would_purge, 0);
        assert_eq!(s.delete_errors, 0);
        for h in &stray_old {
            assert!(!store.has(h), "{h} must be gone from the live store");
            assert!(
                store.has_trashed(h),
                "{h} must be restorable from the trash"
            );
        }
        for h in &keep {
            assert!(store.has(h), "{h} must survive");
        }
        let mut trashed = env.trashed.lock().unwrap().clone();
        trashed.sort();
        let mut expected = stray_old.clone();
        expected.sort();
        assert_eq!(trashed, expected);
        assert!(env.removed.lock().unwrap().is_empty());
    }

    #[cfg(feature = "purge-enforce")]
    #[tokio::test]
    async fn hard_delete_removes_without_trash() {
        let dir = tempfile::tempdir().unwrap();
        let (store, loaded, env, stray_old, _) = scenario(dir.path()).await;
        let metrics = PurgeMetrics::default();
        let s = run_pass(
            &store,
            &env,
            &loaded,
            OPEN,
            &fast_cfg(strongest()),
            true,
            5,
            &metrics,
        )
        .await;
        assert_eq!(s.purged, 2, "{s:?}");
        for h in &stray_old {
            assert!(!store.has(h) && !store.has_trashed(h));
        }
        assert_eq!(env.removed.lock().unwrap().len(), 2);
    }

    /// The weight-0 trap: a generation loaded for an EMPTY owned set has
    /// complete coverage (0 of 0 PGs listed) and an empty filter, so every
    /// blob on disk is an old, unlisted orphan. Clause 0 must be the only
    /// thing standing between that and an emptied store: with the gate
    /// built from the owned set exactly as the loop builds it, the
    /// strongest mode deletes nothing and the summary is empty.
    #[tokio::test]
    async fn empty_ownership_purges_nothing_even_with_a_loaded_generation() {
        let tmp = tempfile::tempdir().unwrap();
        let dir = tmp.path();
        let key = deterministic_key(3);
        let fx = write_generation(&dir.join("bucket"), &key, 9, &[10, 11], 20);
        let source = DirListSource::new(dir.join("bucket"));
        let manifest = pg_lists::fetch_manifest(&source, 9, &fx.validator_hex())
            .await
            .unwrap();
        let owned: Vec<u32> = Vec::new();
        let loaded =
            pg_lists::load_generation(&source, &manifest, &owned, MY_UID, 0.01, 2, 1 << 30, 0)
                .await
                .unwrap();
        // The trap, spelled out: nothing is missing, nothing is listed.
        assert!(loaded.coverage_complete());
        assert_eq!(loaded.listed_pgs, 0);
        assert_eq!(loaded.total_hashes, 0);

        let store = FlatBlobStore::new(dir.join("blobs")).unwrap();
        // Stored well before both `now` and the generation's snapshot:
        // old enough for the orphan clause by any measure.
        let now = 1_000_000u64;
        let mut rows = Vec::new();
        let mut hashes = Vec::new();
        for (pg, i) in [(10u32, 0u32), (10, 7), (11, 19)] {
            let h = hex::encode(hash_for(pg, i));
            store.store(&h, b"was-obliged-yesterday").await.unwrap();
            assert!(!loaded.may_be_obliged(&hash_for(pg, i)), "empty filter");
            rows.push((h.clone(), 1_000i64));
            hashes.push(h);
        }
        let env = FakeEnv::new(rows, now);
        let metrics = PurgeMetrics::default();
        let gate = PurgeGate {
            ownership_nonempty: purge::ownership_nonempty(&loaded.owned_pgs),
            ..OPEN
        };
        assert!(!gate.open());
        let s = run_pass(
            &store,
            &env,
            &loaded,
            gate,
            &fast_cfg(strongest()),
            false,
            5,
            &metrics,
        )
        .await;
        assert_eq!(s, PassSummary::default(), "{s:?}");
        assert_eq!(s.purged, 0);
        for h in &hashes {
            assert!(store.has(h), "{h} must survive an empty ownership");
            assert!(!store.has_trashed(h));
        }
        assert!(env.trashed.lock().unwrap().is_empty());
        assert!(env.removed.lock().unwrap().is_empty());
        // Control: with the clause removed the same pass would empty the
        // store, which is exactly what the gate exists to prevent.
        let s = run_pass(
            &store,
            &env,
            &loaded,
            OPEN,
            &fast_cfg(Mode::Census),
            false,
            5,
            &metrics,
        )
        .await;
        assert_eq!(s.would_purge, hashes.len() as u64, "{s:?}");
        assert_eq!(s.purged, 0);
    }

    /// Ownership flaps 9000 → 0 → 9000 inside the quiet period. The set
    /// purge decisions run on stays the held one at every step (never the
    /// empty one), and a pass over blobs the held lists oblige deletes
    /// none of them; the observed empty set would have closed the gate
    /// through clause 0, but it is never what the gate sees.
    #[tokio::test]
    async fn ownership_flap_to_zero_and_back_purges_nothing() {
        let tmp = tempfile::tempdir().unwrap();
        let dir = tmp.path();
        let key = deterministic_key(3);
        let fx = write_generation(&dir.join("bucket"), &key, 9, &[10, 11], 20);
        let source = DirListSource::new(dir.join("bucket"));
        let manifest = pg_lists::fetch_manifest(&source, 9, &fx.validator_hex())
            .await
            .unwrap();
        let loaded =
            pg_lists::load_generation(&source, &manifest, &[10, 11], MY_UID, 0.01, 2, 1 << 30, 0)
                .await
                .unwrap();
        let store = FlatBlobStore::new(dir.join("blobs")).unwrap();
        let mut rows = Vec::new();
        let mut obliged = Vec::new();
        for (pg, i) in [(10u32, 0u32), (10, 7), (11, 19)] {
            let h = hex::encode(hash_for(pg, i));
            store.store(&h, b"obliged").await.unwrap();
            rows.push((h.clone(), 1_000i64));
            obliged.push(h);
        }
        let env = FakeEnv::new(rows, 1_000_000);
        let metrics = PurgeMetrics::default();
        let cfg = fast_cfg(strongest());

        let mut h = OwnershipHysteresis::default();
        let t0 = tokio::time::Instant::now();
        let big: Vec<u32> = (0..9000).collect();
        let steps: [(u64, Vec<u32>, u64); 3] = [
            (1, big.clone(), 0),
            (2, Vec::new(), 30),
            (3, big.clone(), 60),
        ];
        for (epoch, observed, at) in steps {
            let decision = h.observe(
                epoch,
                observed.clone(),
                t0 + Duration::from_secs(at),
                cfg.ownership_stable_secs.max(3600),
            );
            let (held_epoch, held) = h.held().unwrap();
            assert_eq!(held, big.as_slice(), "step at {at}s: {decision:?}");
            if observed.is_empty() {
                assert_eq!(
                    decision,
                    OwnershipDecision::Held {
                        pending_for_secs: 0
                    }
                );
                assert_eq!(held_epoch, 1, "the held set keeps its own epoch");
                metrics
                    .ownership_shrink_held
                    .fetch_add(1, Ordering::Relaxed);
            } else {
                assert_eq!(decision, OwnershipDecision::Adopted);
            }
            let gate = PurgeGate {
                ownership_nonempty: purge::ownership_nonempty(held),
                ..OPEN
            };
            assert!(gate.open());
            // The heartbeat epoch follows the observed map; the pass runs
            // on the held set's epoch and must stay within the skew
            // tolerance here so that the filter, not a refusal, is what
            // keeps the blobs.
            env.epoch.store(epoch, Ordering::Relaxed);
            let s = run_pass(
                &store, &env, &loaded, gate, &cfg, false, held_epoch, &metrics,
            )
            .await;
            assert!(!s.aborted_epoch_change, "step at {at}s: {s:?}");
            assert_eq!(s.purged, 0, "step at {at}s: {s:?}");
            assert_eq!(s.kept_by_filter, 3);
        }
        assert_eq!(h.pending(), None);
        for hash in &obliged {
            assert!(store.has(hash));
        }
        assert!(env.trashed.lock().unwrap().is_empty());
        assert!(
            metrics
                .render_prometheus()
                .contains("purge_ownership_shrink_held_total 1\n")
        );
    }

    #[tokio::test]
    async fn closed_gate_examines_nothing() {
        let dir = tempfile::tempdir().unwrap();
        let (store, loaded, env, stray_old, _) = scenario(dir.path()).await;
        let metrics = PurgeMetrics::default();
        for gate in [
            PurgeGate {
                generation_loaded: false,
                ..OPEN
            },
            PurgeGate {
                generation_fresh: false,
                ..OPEN
            },
            PurgeGate {
                coverage_complete: false,
                ..OPEN
            },
            PurgeGate {
                ownership_stable: false,
                ..OPEN
            },
            PurgeGate {
                ownership_nonempty: false,
                ..OPEN
            },
        ] {
            let s = run_pass(
                &store,
                &env,
                &loaded,
                gate,
                &fast_cfg(strongest()),
                false,
                5,
                &metrics,
            )
            .await;
            assert_eq!(s, PassSummary::default(), "{gate:?}");
        }
        for h in &stray_old {
            assert!(store.has(h));
        }
    }

    /// Heartbeat epoch 5, map epoch 3: the map this miner holds is two
    /// epochs behind what the validator places on. The pass is refused
    /// before its first page, both epochs are in the summary, the abort
    /// is counted.
    #[tokio::test]
    async fn epoch_skew_beyond_tolerance_refuses_the_pass() {
        let dir = tempfile::tempdir().unwrap();
        let (store, loaded, env, stray_old, _) = scenario(dir.path()).await;
        let metrics = PurgeMetrics::default();
        let s = run_pass(
            &store,
            &env,
            &loaded,
            OPEN,
            &fast_cfg(strongest()),
            false,
            3,
            &metrics,
        )
        .await;
        assert!(s.aborted_epoch_change);
        assert_eq!(s.epoch_skew, 2);
        assert_eq!(s.examined, 0);
        assert_eq!(metrics.epoch_skew_aborts.load(Ordering::Relaxed), 1);
        assert_eq!(metrics.epoch_skew_tolerated.load(Ordering::Relaxed), 0);
        for h in &stray_old {
            assert!(store.has(h));
        }
        assert!(
            metrics
                .render_prometheus()
                .contains("miner_purge_epoch_skew_aborts_total 1\n")
        );
    }

    /// The filter carries generation 8 while the enforced generation is
    /// 9 (a stale filter kept across a generation change, or a filter
    /// built from another manifest). A filter miss would delete, so the
    /// pass is refused before its first page, nothing is read or
    /// deleted, and the refusal is counted; the filter's own tag is what
    /// decides, not the caller's word.
    #[tokio::test]
    async fn filter_from_another_generation_refuses_the_pass() {
        let dir = tempfile::tempdir().unwrap();
        let (store, mut loaded, env, stray_old, _) = scenario(dir.path()).await;
        assert!(loaded.filter_matches_generation());
        let filter = std::mem::replace(&mut loaded.filter, pg_lists::HashFilter::new(1, 0.01));
        loaded.filter = filter.for_generation(loaded.generation - 1);
        assert!(!loaded.filter_matches_generation());

        let metrics = PurgeMetrics::default();
        let s = run_pass(
            &store,
            &env,
            &loaded,
            OPEN,
            &fast_cfg(strongest()),
            false,
            5,
            &metrics,
        )
        .await;
        assert!(s.refused_filter_generation);
        assert!(!s.aborted_epoch_change);
        assert_eq!(s.examined, 0);
        assert_eq!(s.purged, 0);
        assert_eq!(
            metrics.filter_generation_refusals.load(Ordering::Relaxed),
            1
        );
        assert_eq!(metrics.candidates.load(Ordering::Relaxed), 0);
        for h in &stray_old {
            assert!(store.has(h));
        }
        assert!(
            metrics
                .render_prometheus()
                .contains("miner_purge_filter_generation_refusals_total 1\n")
        );

        // The same filter tagged with the enforced generation runs.
        let filter = std::mem::replace(&mut loaded.filter, pg_lists::HashFilter::new(1, 0.01));
        loaded.filter = filter.for_generation(loaded.generation);
        let s = run_pass(
            &store,
            &env,
            &loaded,
            OPEN,
            &fast_cfg(strongest()),
            false,
            5,
            &metrics,
        )
        .await;
        assert!(!s.refused_filter_generation);
        assert!(s.examined > 0);
    }

    /// Heartbeat epoch 5, map epoch 4: the heartbeat ack moved
    /// `CURRENT_EPOCH` before the `ClusterMapUpdate` arrived. One epoch
    /// of lead is the normal delivery order, not an ownership change:
    /// the pass runs on the map's ownership, the skew is logged and
    /// counted, the strays go.
    #[cfg(feature = "purge-enforce")]
    #[tokio::test]
    async fn one_epoch_of_heartbeat_lead_is_tolerated() {
        let dir = tempfile::tempdir().unwrap();
        let (store, loaded, env, stray_old, keep) = scenario(dir.path()).await;
        let metrics = PurgeMetrics::default();
        let s = run_pass(
            &store,
            &env,
            &loaded,
            OPEN,
            &fast_cfg(strongest()),
            false,
            4,
            &metrics,
        )
        .await;
        assert!(!s.aborted_epoch_change, "{s:?}");
        assert_eq!(s.epoch_skew, 1);
        assert_eq!(s.purged, 2, "{s:?}");
        assert_eq!(metrics.epoch_skew_tolerated.load(Ordering::Relaxed), 1);
        assert_eq!(metrics.epoch_skew_aborts.load(Ordering::Relaxed), 0);
        for h in &stray_old {
            assert!(!store.has(h), "{h} purged despite the one-epoch lead");
        }
        for h in &keep {
            assert!(store.has(h));
        }
        assert!(
            metrics
                .render_prometheus()
                .contains("miner_purge_epoch_skew_tolerated_total 1\n")
        );
    }

    /// Epochs agree at the start; the heartbeat moves the epoch while the
    /// pass evaluates the first stray. The post-limiter re-check sees the
    /// move and the pass stops before deleting anything: tolerance
    /// applies to the skew at the start, never to a change during the
    /// pass.
    #[tokio::test]
    async fn epoch_change_mid_pass_aborts_before_any_delete() {
        let dir = tempfile::tempdir().unwrap();
        let (store, loaded, env, stray_old, _) = scenario(dir.path()).await;
        let metrics = PurgeMetrics::default();
        let first_stray = stray_old.iter().min().unwrap().clone();
        *env.epoch_bump_at_inflight_check.lock().unwrap() = Some(first_stray);
        let s = run_pass(
            &store,
            &env,
            &loaded,
            OPEN,
            &fast_cfg(strongest()),
            false,
            5,
            &metrics,
        )
        .await;
        assert!(s.aborted_epoch_change, "{s:?}");
        assert_eq!(s.epoch_skew, 0);
        assert_eq!(s.purged, 0, "{s:?}");
        assert!(s.examined > 0, "the pass did start");
        assert_eq!(metrics.epoch_skew_aborts.load(Ordering::Relaxed), 0);
        for h in &stray_old {
            assert!(store.has(h));
        }
    }

    /// Clause 4 across a restart: the owned set and the time it last
    /// changed are persisted next to the watermark, so a second process
    /// observing the same set inherits the clock instead of waiting a
    /// full period again; a different set after the restart starts a new
    /// one. Also the loop's per-poll contract: closed while the set moves,
    /// open once the same set has held for the required time.
    #[test]
    fn ownership_clock_survives_restart_and_resets_on_change() {
        let dir = tempfile::tempdir().unwrap();
        let required = 21_600u64;
        let persist = |st: &OwnershipStability| persist_ownership_to(dir.path(), st);
        assert!(
            load_ownership_from(dir.path()).is_none(),
            "nothing persisted yet"
        );

        // Process 1: first observation starts the clock at t0; polls with
        // the same set keep it closed until t0 + required.
        let t0 = 1_700_000_000u64;
        let mut st: Option<OwnershipStability> = None;
        assert!(!observe_ownership(
            &mut st,
            &[10, 11],
            t0,
            required,
            &persist
        ));
        assert!(!observe_ownership(
            &mut st,
            &[11, 10],
            t0 + required / 2,
            required,
            &persist
        ));
        // A PG lost mid-way resets the clock; gained back, reset again.
        assert!(!observe_ownership(
            &mut st,
            &[10],
            t0 + required / 2 + 60,
            required,
            &persist
        ));
        assert!(!observe_ownership(
            &mut st,
            &[10, 11],
            t0 + required / 2 + 120,
            required,
            &persist
        ));
        let changed_at = t0 + required / 2 + 120;
        assert_eq!(st.as_ref().unwrap().changed_at_secs(), changed_at);

        // Process 2 (restart) a while later: the persisted state carries
        // the clock, the same set is stable from `changed_at`, not from
        // the restart.
        let mut st2 = load_ownership_from(dir.path());
        assert_eq!(st2.as_ref().unwrap().owned(), &[10, 11]);
        assert_eq!(st2.as_ref().unwrap().changed_at_secs(), changed_at);
        assert!(!observe_ownership(
            &mut st2,
            &[10, 11],
            changed_at + required - 1,
            required,
            &persist
        ));
        assert!(observe_ownership(
            &mut st2,
            &[10, 11],
            changed_at + required,
            required,
            &persist
        ));
        let gate = PurgeGate {
            ownership_stable: st2
                .as_ref()
                .unwrap()
                .is_stable(changed_at + required, required),
            ..OPEN
        };
        assert!(gate.open());

        // Process 3: restarted with a different owned set (weight change
        // while down): the clock starts at the first observation.
        let mut st3 = load_ownership_from(dir.path());
        let t3 = changed_at + required + 5_000;
        assert!(!observe_ownership(
            &mut st3,
            &[10, 11, 12],
            t3,
            required,
            &persist
        ));
        assert_eq!(st3.as_ref().unwrap().changed_at_secs(), t3);
        assert_eq!(
            load_ownership_from(dir.path()).unwrap().changed_at_secs(),
            t3,
            "the reset is persisted"
        );

        // Garbage on disk: the clock starts at first observation.
        std::fs::write(dir.path().join(OWNERSHIP_FILE), "not a state").unwrap();
        assert!(load_ownership_from(dir.path()).is_none());
    }

    /// Same mid-pass epoch move through the census: it deletes nothing
    /// and counts under the generation's pinned lists, so it walks every
    /// page to the end and reports the move as `epochs_crossed` instead
    /// of aborting (on a live network the epoch moves every ~15 min; an abort meant a
    /// large store never got a full census). The start-of-pass skew
    /// refusal is unchanged.
    #[tokio::test]
    async fn epoch_change_mid_census_is_counted_not_an_abort() {
        let dir = tempfile::tempdir().unwrap();
        let (store, loaded, env, stray_old, keep) = scenario(dir.path()).await;
        let first_stray = stray_old.iter().min().unwrap().clone();
        *env.epoch_bump_at_inflight_check.lock().unwrap() = Some(first_stray);
        let cfg = fast_cfg(Mode::Census);

        let c = run_census(&store, &env, &loaded, &cfg, 5).await;
        assert_eq!(c.epochs_crossed, 1, "{c:?}");
        assert!(!c.aborted_epoch_change, "{c:?}");
        assert!(c.complete(), "{c:?}");
        assert_eq!(c.examined, 9, "every row read past the epoch move: {c:?}");
        assert_eq!(c.protected, 3);
        assert_eq!(c.orphan_gated, 2, "both strays counted: {c:?}");
        assert_eq!(c.orphan_pending, 2, "young + in flight: {c:?}");
        assert_eq!(c.skipped_invalid, 2, "ghost + malformed");
        assert_eq!(env.epoch.load(Ordering::Relaxed), 6, "the bump fired");
        // Read-only regardless of the move.
        for h in stray_old.iter().chain(keep.iter()) {
            assert!(store.has(h));
        }
        assert!(env.trashed.lock().unwrap().is_empty());
        assert!(env.removed.lock().unwrap().is_empty());

        // A skew beyond tolerance at the start still refuses the census
        // before its first page, with `epochs_crossed` untouched.
        let c = run_census(&store, &env, &loaded, &cfg, 6 + EPOCH_SKEW_TOLERANCE + 1).await;
        assert!(c.aborted_epoch_change);
        assert_eq!((c.examined, c.epochs_crossed), (0, 0));
    }

    #[tokio::test(start_paused = true)]
    async fn pass_respects_rate_limit() {
        let dir = tempfile::tempdir().unwrap();
        let (store, loaded, env, _, _) = scenario(dir.path()).await;
        let metrics = PurgeMetrics::default();
        // 1 deletion/s: 2 stray blobs, the first is free, the second waits ~1 s.
        let cfg = PurgeConfig {
            rate_per_sec: 1,
            ..fast_cfg(Mode::Census)
        };
        let t0 = tokio::time::Instant::now();
        let s = run_pass(&store, &env, &loaded, OPEN, &cfg, false, 5, &metrics).await;
        assert_eq!(s.would_purge, 2);
        let elapsed = t0.elapsed().as_secs_f64();
        assert!((0.9..=1.2).contains(&elapsed), "{elapsed}s");
    }

    #[cfg(feature = "purge-enforce")]
    #[tokio::test]
    async fn write_starting_during_the_limiter_wait_is_not_deleted() {
        let dir = tempfile::tempdir().unwrap();
        let (store, loaded, env, stray_old, _) = scenario(dir.path()).await;
        let metrics = PurgeMetrics::default();
        // The second stray passed `decide` (not in flight) but a Store for
        // it starts before the pass takes its lock.
        let mut sorted = stray_old.clone();
        sorted.sort();
        let second = sorted[1].clone();
        *env.writer_at_lock.lock().unwrap() = Some((second.clone(), WriterAtLock::Starts));
        let s = run_pass(
            &store,
            &env,
            &loaded,
            OPEN,
            &fast_cfg(strongest()),
            false,
            5,
            &metrics,
        )
        .await;
        assert_eq!(s.purged, 1, "{s:?}");
        assert_eq!(s.skipped_inflight, 2, "scenario in-flight + the late one");
        assert!(!store.has(&sorted[0]));
        assert!(store.has(&second), "a write that started mid-wait must win");
    }

    /// The writer stamps `scan_started_at` days before `created_at`: a
    /// blob stored between the two is old by the creation stamp yet may
    /// be unlisted (its manifest was committed behind the scan cursor),
    /// so the age bound is the scan start.
    #[cfg(feature = "purge-enforce")]
    #[tokio::test]
    async fn blob_written_after_the_scan_start_is_kept() {
        let dir = tempfile::tempdir().unwrap();
        let key = deterministic_key(7);
        let scan_started = CREATED_AT_SECS - 4 * 86_400;
        let stamps = Stamps {
            created_at: serde_json::json!(CREATED_AT_SECS),
            scan_started_at: Some(serde_json::json!(scan_started)),
        };
        let fx = write_generation_stamped(&dir.path().join("bucket"), &key, 9, &[10], 20, &stamps);
        let source = DirListSource::new(dir.path().join("bucket"));
        let manifest = pg_lists::fetch_manifest(&source, 9, &fx.validator_hex())
            .await
            .unwrap();
        let loaded =
            pg_lists::load_generation(&source, &manifest, &[10], MY_UID, 0.01, 1, 1 << 30, 0)
                .await
                .unwrap();
        assert_eq!(loaded.snapshot_secs, scan_started);
        let store = FlatBlobStore::new(dir.path().join("blobs")).unwrap();
        let stray = |tag: &str| {
            (0u32..)
                .map(|i| *blake3::hash(format!("{tag}/{i}").as_bytes()).as_bytes())
                .find(|h| !loaded.may_be_obliged(h))
                .map(hex::encode)
                .unwrap()
        };
        let during_scan = stray("scan-start-during");
        let before_scan = stray("scan-start-before");
        for h in [&during_scan, &before_scan] {
            store.store(h, b"stray-bytes").await.unwrap();
        }
        // Two days into the scan: 2 days before created_at (old by that
        // stamp, min age is an hour) but after the scan start.
        let rows = vec![
            (during_scan.clone(), (scan_started + 2 * 86_400) as i64),
            (before_scan.clone(), (scan_started - 7200) as i64),
        ];
        let env = FakeEnv::new(rows, CREATED_AT_SECS + 86_400);
        let metrics = PurgeMetrics::default();
        let s = run_pass(
            &store,
            &env,
            &loaded,
            OPEN,
            &fast_cfg(strongest()),
            false,
            5,
            &metrics,
        )
        .await;
        assert_eq!(s.purged, 1, "{s:?}");
        assert_eq!(s.skipped_young, 1);
        assert!(store.has(&during_scan), "stored after the scan start: kept");
        assert!(
            !store.has(&before_scan),
            "stored before the scan start: purged"
        );
    }

    /// A generation older than PURGE_GENERATION_MAX_AGE_SECS is not even
    /// loaded, and one that ages past it while loaded closes the gate.
    #[tokio::test]
    async fn stale_generation_is_refused() {
        let dir = tempfile::tempdir().unwrap();
        let key = deterministic_key(8);
        let fx = write_generation(dir.path(), &key, 3, &[1], 5);
        let source = DirListSource::new(dir.path());
        let cfg = PurgeConfig::default();
        let mut current = None;
        let mut highest = 0;
        // Eight days after creation: refused, the watermark untouched.
        refresh_generation(
            &source,
            &fx.validator_hex(),
            &[1],
            MY_UID,
            &cfg,
            CREATED_AT_SECS + 8 * 86_400,
            &mut current,
            &mut highest,
        )
        .await;
        assert!(current.is_none(), "stale generation must not be loaded");
        assert_eq!(highest, 0);
        // Exactly seven days: accepted.
        refresh_generation(
            &source,
            &fx.validator_hex(),
            &[1],
            MY_UID,
            &cfg,
            CREATED_AT_SECS + 7 * 86_400,
            &mut current,
            &mut highest,
        )
        .await;
        let loaded = current.as_ref().expect("fresh generation loads");
        assert_eq!(highest, 3);
        // The gate closes once it ages out, with nothing else wrong.
        let fresh = miner::purge::generation_is_fresh(
            loaded.created_at_secs,
            CREATED_AT_SECS + 7 * 86_400 + 1,
            cfg.generation_max_age_secs,
        );
        assert!(!fresh);
        assert!(
            !PurgeGate {
                generation_fresh: fresh,
                ..OPEN
            }
            .open()
        );
    }

    #[cfg(feature = "purge-enforce")]
    #[tokio::test]
    async fn blob_written_after_the_generation_snapshot_is_kept() {
        let dir = tempfile::tempdir().unwrap();
        let (store, loaded, env, stray_old, _) = scenario(dir.path()).await;
        assert_eq!(loaded.created_at_secs, CREATED_AT_SECS);
        assert_eq!(
            loaded.snapshot_secs, CREATED_AT_SECS,
            "no scan_started_at: creation is the bound"
        );
        // Now is ten days after the snapshot. One stray was written an
        // hour after the snapshot (nine days ago: old by wall clock), the
        // other a day before the snapshot.
        let now = CREATED_AT_SECS + 10 * 86_400;
        let mut sorted = stray_old.clone();
        sorted.sort();
        let (after_snapshot, before_snapshot) = (sorted[0].clone(), sorted[1].clone());
        let rows = vec![
            (after_snapshot.clone(), (CREATED_AT_SECS + 3600) as i64),
            (before_snapshot.clone(), (CREATED_AT_SECS - 86_400) as i64),
        ];
        let env2 = FakeEnv::new(rows, now);
        drop(env);
        let metrics = PurgeMetrics::default();
        let s = run_pass(
            &store,
            &env2,
            &loaded,
            OPEN,
            &fast_cfg(strongest()),
            false,
            5,
            &metrics,
        )
        .await;
        assert_eq!(s.purged, 1, "{s:?}");
        assert_eq!(s.skipped_young, 1);
        assert!(
            store.has(&after_snapshot),
            "written after the snapshot: kept"
        );
        assert!(!store.has(&before_snapshot));
    }

    #[cfg(feature = "purge-enforce")]
    #[tokio::test]
    async fn hash_held_by_a_writer_lock_is_skipped() {
        let dir = tempfile::tempdir().unwrap();
        let (store, loaded, env, stray_old, _) = scenario(dir.path()).await;
        let mut sorted = stray_old.clone();
        sorted.sort();
        // A writer (Store handler) holds the real per-hash lock.
        let held = state::lock_hash_write(&sorted[0]).await;
        let metrics = PurgeMetrics::default();
        let s = run_pass(
            &store,
            &env,
            &loaded,
            OPEN,
            &fast_cfg(strongest()),
            false,
            5,
            &metrics,
        )
        .await;
        assert_eq!(s.purged, 1, "{s:?}");
        assert!(store.has(&sorted[0]), "locked by a writer: untouched");
        assert!(!store.has(&sorted[1]));
        drop(held);
        // Released: the entry is gone and the hash is free again.
        assert!(!state::is_write_inflight(&sorted[0]));
        assert!(state::try_lock_hash_write(&sorted[0]).is_some());
    }

    /// Same generation, delta chain grown: the refresh extends the loaded
    /// view (base lists not downloaded again, new records enforced, gate
    /// open). A broken link closes the coverage gate and the gauges say
    /// so; the writer fixing the chain reopens it at the next poll.
    #[tokio::test]
    async fn refresh_extends_with_deltas_and_gates_on_a_broken_chain() {
        use miner::pg_lists::test_fixtures::{
            append_delta, deterministic_key, hash_for, record_for, rewrite_base_manifest,
            set_base_cut, write_generation,
        };
        let dir = tempfile::tempdir().unwrap();
        let key = deterministic_key(4);
        let cut = CREATED_AT_SECS - 300;
        let fx = write_generation(dir.path(), &key, 9, &[1, 2], 5);
        set_base_cut(dir.path(), &key, 9, cut);
        let source = DirListSource::new(dir.path());
        let cfg = PurgeConfig::default();
        let mut current = None;
        let mut highest = 0;
        let hex = fx.validator_hex();
        macro_rules! refresh {
            () => {
                refresh_generation(
                    &source,
                    &hex,
                    &[1, 2],
                    MY_UID,
                    &cfg,
                    CREATED_AT_SECS + 60,
                    &mut current,
                    &mut highest,
                )
                .await
            };
        }
        refresh!();
        let loaded = current.as_ref().unwrap();
        assert_eq!((loaded.generation, loaded.delta_seq), (9, 0));
        assert!(loaded.coverage_complete());

        append_delta(dir.path(), &key, 9, 1, cut, cut + 600, &[1, 2], &|pg| {
            vec![record_for(pg, 50)]
        });
        refresh!();
        let loaded = current.as_ref().unwrap();
        assert_eq!((loaded.generation, loaded.delta_seq), (9, 1));
        assert!(loaded.coverage_complete());
        assert!(loaded.may_be_obliged(&hash_for(1, 50)));
        assert_eq!(loaded.snapshot_secs, cut + 600);
        let metrics = metrics();
        publish_generation_metrics(current.as_ref(), 2, true, metrics);
        assert!(metrics.coverage_complete.load(Ordering::Relaxed));
        assert_eq!(metrics.delta_seq.load(Ordering::Relaxed), 1);
        assert!(!metrics.delta_chain_broken.load(Ordering::Relaxed));

        // Seq 3 without seq 2: chain broken, view kept, gate closed.
        append_delta(
            dir.path(),
            &key,
            9,
            3,
            cut + 1200,
            cut + 1800,
            &[1, 2],
            &|pg| vec![record_for(pg, 60)],
        );
        refresh!();
        let loaded = current.as_ref().unwrap();
        assert_eq!((loaded.delta_seq, loaded.chain_broken_at), (1, Some(3)));
        assert!(!loaded.coverage_complete());
        assert!(
            loaded.may_be_obliged(&hash_for(1, 50)),
            "seq 1 still enforced"
        );
        assert!(!loaded.may_be_obliged(&hash_for(1, 60)));
        publish_generation_metrics(current.as_ref(), 2, true, metrics);
        assert!(!metrics.coverage_complete.load(Ordering::Relaxed));
        assert!(metrics.delta_chain_broken.load(Ordering::Relaxed));

        // The writer repairs the chain: seq 2 inserted before 3 (re-signed
        // base), the next poll folds 2 then 3 and reopens the gate.
        rewrite_base_manifest(dir.path(), &key, 9, &|v| {
            v["deltas"].as_array_mut().unwrap().pop();
        });
        append_delta(
            dir.path(),
            &key,
            9,
            2,
            cut + 600,
            cut + 1200,
            &[1, 2],
            &|pg| vec![record_for(pg, 55)],
        );
        // Re-append the ref to the already written seq 3 body.
        let body = std::fs::read(
            dir.path()
                .join(miner::pg_lists::DeltaManifest::manifest_path(9, 3)),
        )
        .unwrap();
        let sha = hex::encode(<sha2::Sha256 as sha2::Digest>::digest(&body));
        rewrite_base_manifest(dir.path(), &key, 9, &|v| {
            v["deltas"].as_array_mut().unwrap().push(serde_json::json!({
                "seq": 3, "since": cut + 1200, "until": cut + 1800,
                "sha256": sha, "size": body.len(),
            }));
        });
        std::fs::write(
            dir.path().join("current.json"),
            serde_json::json!({ "generation": 9, "delta_seq": 3 }).to_string(),
        )
        .unwrap();
        refresh!();
        let loaded = current.as_ref().unwrap();
        assert_eq!((loaded.delta_seq, loaded.chain_broken_at), (3, None));
        assert!(loaded.coverage_complete());
        assert!(loaded.may_be_obliged(&hash_for(2, 55)));
        assert!(loaded.may_be_obliged(&hash_for(2, 60)));
        assert_eq!(loaded.snapshot_secs, cut + 1800);
    }

    #[tokio::test]
    async fn refresh_rejects_generation_rollback_and_keeps_previous_on_failure() {
        use miner::pg_lists::test_fixtures::{deterministic_key, write_generation};
        let dir = tempfile::tempdir().unwrap();
        let key = deterministic_key(4);
        let fx = write_generation(dir.path(), &key, 9, &[1, 2], 5);
        let source = DirListSource::new(dir.path());
        let cfg = PurgeConfig::default();
        let mut current = None;
        let mut highest = 0;
        refresh_generation(
            &source,
            &fx.validator_hex(),
            &[1, 2],
            MY_UID,
            &cfg,
            CREATED_AT_SECS + 60,
            &mut current,
            &mut highest,
        )
        .await;
        assert_eq!(current.as_ref().map(|c| c.generation), Some(9));
        assert_eq!(highest, 9);

        // current.json rolled back to a generation that even exists.
        write_generation(dir.path(), &key, 8, &[1, 2], 5);
        refresh_generation(
            &source,
            &fx.validator_hex(),
            &[1, 2],
            MY_UID,
            &cfg,
            CREATED_AT_SECS + 60,
            &mut current,
            &mut highest,
        )
        .await;
        assert_eq!(
            current.as_ref().map(|c| c.generation),
            Some(9),
            "rollback ignored"
        );

        // A newer generation with a bad signature keeps the previous one.
        write_generation(dir.path(), &deterministic_key(5), 10, &[1, 2], 5);
        refresh_generation(
            &source,
            &fx.validator_hex(),
            &[1, 2],
            MY_UID,
            &cfg,
            CREATED_AT_SECS + 60,
            &mut current,
            &mut highest,
        )
        .await;
        assert_eq!(current.as_ref().map(|c| c.generation), Some(9));

        // ...unless the owned set changed: then the stale one is dropped.
        refresh_generation(
            &source,
            &fx.validator_hex(),
            &[1, 2, 3],
            MY_UID,
            &cfg,
            CREATED_AT_SECS + 60,
            &mut current,
            &mut highest,
        )
        .await;
        assert!(current.is_none());
    }

    /// A v2 `current.json` digests the base manifest: a pointer whose
    /// digest does not match the published bytes loads nothing (previous
    /// view kept), the matching one loads, and its `deltas` chain is the
    /// hint that makes the next poll re-fetch the manifest and extend.
    #[tokio::test]
    async fn refresh_honours_a_v2_pointer_digest_and_delta_hint() {
        use miner::pg_lists::test_fixtures::{
            append_delta, deterministic_key, hash_for, record_for, set_base_cut, write_generation,
        };
        let dir = tempfile::tempdir().unwrap();
        let key = deterministic_key(4);
        let cut = CREATED_AT_SECS - 300;
        let fx = write_generation(dir.path(), &key, 9, &[1, 2], 5);
        set_base_cut(dir.path(), &key, 9, cut);
        let source = DirListSource::new(dir.path());
        let cfg = PurgeConfig::default();
        let mut current = None;
        let mut highest = 0;
        let hex = fx.validator_hex();
        macro_rules! refresh {
            () => {
                refresh_generation(
                    &source,
                    &hex,
                    &[1, 2],
                    MY_UID,
                    &cfg,
                    CREATED_AT_SECS + 60,
                    &mut current,
                    &mut highest,
                )
                .await
            };
        }
        let manifest_sha = |root: &std::path::Path| {
            hex::encode(<sha2::Sha256 as sha2::Digest>::digest(
                std::fs::read(root.join("gen/9/manifest.json")).unwrap(),
            ))
        };
        let write_pointer = |sha: &str, deltas: serde_json::Value| {
            std::fs::write(
                dir.path().join("current.json"),
                serde_json::json!({
                    "generation": 9, "base_cut": cut, "manifest_sha": sha, "deltas": deltas,
                })
                .to_string(),
            )
            .unwrap();
        };

        // Wrong digest: the manifest is refused, nothing is loaded, the
        // watermark does not move.
        write_pointer(&"cd".repeat(32), serde_json::json!([]));
        refresh!();
        assert!(
            current.is_none(),
            "a manifest the pointer does not digest is refused"
        );
        assert_eq!(highest, 0);

        // Right digest: loads.
        write_pointer(&manifest_sha(dir.path()), serde_json::json!([]));
        refresh!();
        let loaded = current.as_ref().unwrap();
        assert_eq!((loaded.generation, loaded.delta_seq), (9, 0));
        assert!(loaded.coverage_complete());
        assert_eq!(highest, 9);

        // The writer appends a delta (base re-signed, so its digest moves)
        // and the pointer's chain says seq 1 exists: the next poll
        // re-fetches the manifest (checked against the new digest) and
        // extends the loaded view.
        append_delta(dir.path(), &key, 9, 1, cut, cut + 600, &[1, 2], &|pg| {
            vec![record_for(pg, 50)]
        });
        let new_sha = manifest_sha(dir.path());
        write_pointer(
            &new_sha,
            serde_json::json!([{ "seq": 1, "cut": cut + 600, "manifest_sha": "ef".repeat(32) }]),
        );
        refresh!();
        let loaded = current.as_ref().unwrap();
        assert_eq!((loaded.generation, loaded.delta_seq), (9, 1));
        assert!(loaded.may_be_obliged(&hash_for(1, 50)));

        // Same hint, stale digest (bucket mid-publication): the loaded
        // view is kept as is, nothing breaks.
        write_pointer(
            &"cd".repeat(32),
            serde_json::json!([{ "seq": 2, "cut": cut + 1200, "manifest_sha": "ef".repeat(32) }]),
        );
        refresh!();
        let loaded = current.as_ref().unwrap();
        assert_eq!((loaded.delta_seq, loaded.chain_broken_at), (1, None));
        assert!(loaded.coverage_complete());
    }

    /// v2 layout end to end in the refresh: write-once base, the chain
    /// only in `current.json`. First poll loads base + delta 1; the
    /// pointer growing to seq 2 extends the view without touching the
    /// base.
    #[tokio::test]
    async fn refresh_applies_the_chain_a_v2_pointer_carries() {
        use miner::pg_lists::test_fixtures::{
            deterministic_key, hash_for, record_for, write_current_v2, write_delta,
            write_generation,
        };
        let dir = tempfile::tempdir().unwrap();
        let key = deterministic_key(4);
        let cut = CREATED_AT_SECS - 300;
        let fx = write_generation(dir.path(), &key, 9, &[1, 2], 5);
        let source = DirListSource::new(dir.path());
        let cfg = PurgeConfig::default();
        let mut current = None;
        let mut highest = 0;
        let hex = fx.validator_hex();
        macro_rules! refresh {
            () => {
                refresh_generation(
                    &source,
                    &hex,
                    &[1, 2],
                    MY_UID,
                    &cfg,
                    CREATED_AT_SECS + 60,
                    &mut current,
                    &mut highest,
                )
                .await
            };
        }
        let (sha1, _) = write_delta(dir.path(), &key, 9, 1, cut, cut + 600, &[1, 2], &|pg| {
            vec![record_for(pg, 50)]
        });
        write_current_v2(dir.path(), 9, cut, &[(1, cut + 600, sha1)]);
        refresh!();
        let loaded = current.as_ref().unwrap();
        assert_eq!((loaded.generation, loaded.delta_seq), (9, 1));
        assert!(loaded.coverage_complete());
        assert!(loaded.may_be_obliged(&hash_for(1, 50)));
        assert_eq!(loaded.snapshot_secs, cut + 600);

        let (sha2, _) = write_delta(
            dir.path(),
            &key,
            9,
            2,
            cut + 600,
            cut + 1200,
            &[1, 2],
            &|pg| vec![record_for(pg, 55)],
        );
        write_current_v2(
            dir.path(),
            9,
            cut,
            &[(1, cut + 600, sha1), (2, cut + 1200, sha2)],
        );
        refresh!();
        let loaded = current.as_ref().unwrap();
        assert_eq!((loaded.delta_seq, loaded.chain_broken_at), (2, None));
        assert!(loaded.may_be_obliged(&hash_for(2, 55)));
        assert_eq!(loaded.snapshot_secs, cut + 1200);
        // Same pointer again: nothing to do.
        refresh!();
        assert_eq!(current.as_ref().unwrap().delta_seq, 2);
    }

    #[cfg(feature = "purge-enforce")]
    #[tokio::test]
    async fn write_completing_during_the_limiter_wait_refreshes_the_age() {
        let dir = tempfile::tempdir().unwrap();
        let (store, loaded, env, stray_old, _) = scenario(dir.path()).await;
        let metrics = PurgeMetrics::default();
        let mut sorted = stray_old.clone();
        sorted.sort();
        let second = sorted[1].clone();
        // A writer completed while the second stray waited in the limiter:
        // by the time the pass takes the lock, the row carries a fresh
        // stored_at and the lock is free again.
        *env.writer_at_lock.lock().unwrap() = Some((second.clone(), WriterAtLock::Completed));
        let s = run_pass(
            &store,
            &env,
            &loaded,
            OPEN,
            &fast_cfg(strongest()),
            false,
            5,
            &metrics,
        )
        .await;
        assert_eq!(s.purged, 1, "{s:?}");
        assert_eq!(s.skipped_young, 2, "scenario young + the refreshed row");
        assert!(store.has(&second), "re-stored during the wait: kept");
    }

    #[tokio::test]
    async fn bogus_current_pointer_does_not_poison_the_watermark() {
        use miner::pg_lists::test_fixtures::{deterministic_key, write_generation};
        let dir = tempfile::tempdir().unwrap();
        let key = deterministic_key(6);
        let fx = write_generation(dir.path(), &key, 3, &[1], 5);
        let source = DirListSource::new(dir.path());
        let cfg = PurgeConfig::default();
        let mut current = None;
        let mut highest = 0;
        // current.json says 999 but no such generation exists.
        std::fs::write(dir.path().join("current.json"), r#"{"generation": 999}"#).unwrap();
        refresh_generation(
            &source,
            &fx.validator_hex(),
            &[1],
            MY_UID,
            &cfg,
            CREATED_AT_SECS + 60,
            &mut current,
            &mut highest,
        )
        .await;
        assert!(current.is_none());
        assert_eq!(
            highest, 0,
            "unverified pointer must not advance the watermark"
        );
        // The real generation 3 is then still accepted.
        std::fs::write(dir.path().join("current.json"), r#"{"generation": 3}"#).unwrap();
        refresh_generation(
            &source,
            &fx.validator_hex(),
            &[1],
            MY_UID,
            &cfg,
            CREATED_AT_SECS + 60,
            &mut current,
            &mut highest,
        )
        .await;
        assert_eq!(current.as_ref().map(|c| c.generation), Some(3));
        assert_eq!(highest, 3);
    }

    #[test]
    fn parse_hash_accepts_only_32_hex_bytes() {
        assert!(parse_hash(&"ab".repeat(32)).is_some());
        assert!(parse_hash(&"ab".repeat(31)).is_none());
        assert!(parse_hash(&"zz".repeat(32)).is_none());
    }
}

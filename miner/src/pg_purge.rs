//! Obligation-list purge loop: keeps the store down to what the published
//! per-PG lists oblige this miner to hold.
//!
//! Every tick the loop (1) derives the PGs this miner owns for the purge
//! from the current cluster map (v3 straw2 placement only,
//! [`purge::calculate_purge_pgs`], cached by epoch) and folds them into
//! the per-PG ownership window ([`OwnershipWindow`]): the **protected
//! set** is every PG owned now or within `PURGE_OWNERSHIP_STABLE_SECS`;
//! (2) every `PG_LISTS_POLL_SECS`, or sooner with backoff while the
//! protected set is not covered (a PG gained, a delta chain broken),
//! follows `current.json` and brings the verified lists of the protected
//! PGs into the membership filters ([`miner::pg_lists`]); and (3) when the
//! gate is open, runs one rate-bounded pass over the inventory in a
//! background task, deleting through the store's own two-phase delete
//! every blob the rule in [`miner::purge`] declares purgeable. The pass
//! (and the dry-run census on incomplete coverage) never blocks the loop:
//! they share the lists through [`SharedView`], re-read before every
//! decision, and a pass stops as soon as the loaded lists no longer cover
//! the protected set. The pass never walks the store: it pages the SQLite
//! inventory in hash order (`inventory::live_shards_page`), which also
//! carries the age of each blob.
//!
//! On by default as a census (`PURGE_ENABLED=true`, `PURGE_DRY_RUN=true`):
//! nothing is deleted unless the operator sets `PURGE_DRY_RUN=false`.

use std::collections::HashSet;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::time::Duration;

use anyhow::Result;
use miner::pg_lists::{
    self, CurrentPointer, DirListSource, HttpListSource, ListSource, LoadedGeneration, Manifest,
};
use miner::purge::{
    self, Candidate, Mode, OwnershipWindow, PurgeConfig, PurgeGate, PurgeMetrics, RateLimiter,
    Verdict, WindowDecoded, classify, decide, generation_is_fresh,
};
use miner::store::BlobStore;
use tokio::sync::RwLock;
use tracing::{debug, error, info, warn};

use crate::inventory;
use crate::state;

/// Inventory rows fetched per blocking query.
const PAGE_SIZE: usize = 1_000;
/// Progress line cadence (blobs purged, or would-be purged in dry-run).
const SUMMARY_EVERY: u64 = 1_000;
/// Longest tick of the loop: ownership, window and gate are re-evaluated
/// at least this often (the bucket itself only every `poll_secs`), so the
/// shared view follows a new map within seconds.
const MAX_TICK_SECS: u64 = 10;
/// How long a pass waits, before a delete, for the view's ownership to
/// come back within [`EPOCH_SKEW_TOLERANCE`] of the heartbeat epoch and
/// the held map (the map to arrive, the loop to publish it) before it
/// stops.
const VIEW_CATCHUP_MAX_WAIT: Duration = Duration::from_secs(180);
/// Longest a pass waits for the view's read lock while it holds a hash
/// write lock (a Store of that hash waits on it); past it the blob is
/// kept and the lock released.
const VIEW_READ_TIMEOUT: Duration = Duration::from_secs(5);
/// First retry delay of a refresh that left the protected set uncovered;
/// doubles up to `poll_secs`.
const REFRESH_RETRY_BASE_SECS: u64 = 30;
/// Delay before a pass that stopped early (coverage lost, inventory
/// error, view behind the map) is resumed from its cursor.
const PASS_RESUME_DELAY_SECS: u64 = 60;

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
    /// Drop the live row of a blob the store does not hold, if still live
    /// with this `stored_at`. Returns whether a row was dropped.
    fn drop_live_row(&self, hash_hex: &str, stored_at: i64) -> Result<bool>;
    /// The blob left the live store through `BlobStore::delete`.
    #[cfg(feature = "purge-enforce")]
    fn record_trashed(&self, hash_hex: &str);
    /// The blob left the store for good through `BlobStore::remove`.
    #[cfg(feature = "purge-enforce")]
    fn record_removed(&self, hash_hex: &str);
    /// Current heartbeat epoch (moved by the validator's heartbeat ack).
    async fn current_epoch(&self) -> u64;
    /// Epoch of the cluster map this miner holds (0 before the first).
    async fn map_epoch(&self) -> u64;
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
    fn drop_live_row(&self, hash_hex: &str, stored_at: i64) -> Result<bool> {
        inventory::drop_live_row(hash_hex, stored_at)
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
    async fn map_epoch(&self) -> u64 {
        state::get_cluster_map()
            .read()
            .await
            .as_ref()
            .map_or(0, |m| m.epoch)
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

// ============================================================================
// Shared view
// ============================================================================

/// What a pass or census decides on, shared with the loop that keeps it
/// current: the loaded lists and the protected set they must cover. The
/// loop takes the write lock to publish a new ownership or to refresh the
/// lists; a pass takes the read lock to classify one inventory page and,
/// again, around each delete (never across a rate-limiter wait), so a
/// refresh waits at most for one page's classification or one delete.
#[derive(Debug, Default)]
pub struct PurgeView {
    /// Verified lists of the protected PGs (possibly of more PGs: a PG
    /// that left the window stays loaded until the next reload).
    pub loaded: Option<LoadedGeneration>,
    /// Protected PGs (sorted): owned now or within the ownership window.
    pub protected: Vec<u32>,
    /// This miner's uid is listed in the map of `map_epoch`, not draining
    /// and not under a placement hold (clause 0);
    /// its owned and protected sets may be empty (weight 0).
    pub miner_eligible: bool,
    /// Epoch of the map `protected` was computed on.
    pub map_epoch: u64,
    /// The purge state on disk (generation watermark, ownership window)
    /// could not be read back or written: no deletion is decided.
    pub state_fault: bool,
    /// The ownership window has been tracked for a full window at the
    /// last observation (`OwnershipWindow::is_tracked`). Cleared by a
    /// gap restart, so a pass running at that moment stops deleting at
    /// once instead of at its next start.
    pub ownership_tracked: bool,
}

/// The view behind its lock.
pub type SharedView = RwLock<PurgeView>;

/// Why a view may not decide a deletion.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ViewRefusal {
    /// The miner's uid is absent from the view's map, or draining or
    /// under a placement hold there (clause 0).
    MinerNotEligible,
    NoGeneration,
    GenerationStale,
    /// The filter's bits do not come from the loaded generation.
    FilterGeneration,
    /// The loaded lists do not cover every protected PG, or a delta
    /// chain is broken.
    CoverageIncomplete,
    /// The newest signed cut of the view is older than
    /// `PURGE_VIEW_MAX_LAG_SECS`.
    ViewStale,
    /// The purge state could not be persisted or read back.
    StateFault,
    /// The ownership window has not been tracked for a full window (first
    /// start, or tracking restarted after a gap).
    OwnershipUntracked,
}

/// Whether every PG of `protected` is in `loaded` (owned set sorted or
/// not).
fn loaded_holds_all(loaded: &LoadedGeneration, protected: &[u32]) -> bool {
    let held: HashSet<u32> = loaded.owned_pgs.iter().copied().collect();
    protected.iter().all(|pg| held.contains(pg))
}

/// Coverage for the protected set: the generation carries a holder index
/// and holder sets with a live filter, every protected PG and every PG the
/// holder index names this miner in was asked for, the manifest listed all
/// of them, and the delta chain is whole. A generation without a holder
/// index placed holders on the current map only, one without sets cannot
/// tell this miner's blobs from orphans: neither decides a deletion.
pub fn covers_protected(loaded: &LoadedGeneration, protected: &[u32]) -> bool {
    if loaded.held_pgs.is_none() || loaded.sets.is_none() {
        return false;
    }
    let required = loaded.required_pgs(protected);
    let missing: HashSet<u32> = loaded.missing_pgs.iter().copied().collect();
    loaded.chain_broken_at.is_none()
        && loaded_holds_all(loaded, &required)
        && required.iter().all(|pg| !missing.contains(pg))
}

/// The loaded set holds more than twice what the view needs (the
/// protected set plus the holder index): reload for exactly that.
fn loaded_is_bloated(loaded: &LoadedGeneration, protected: &[u32]) -> bool {
    loaded.owned_pgs.len()
        > loaded
            .required_pgs(protected)
            .len()
            .max(1)
            .saturating_mul(2)
}

impl PurgeView {
    /// The loaded generation if a deletion may be decided on it at
    /// `now_secs`: ownership non-empty, generation loaded and fresh, its
    /// filter built from it, and its lists covering the protected set.
    pub fn enforceable(
        &self,
        now_secs: u64,
        cfg: &PurgeConfig,
    ) -> Result<&LoadedGeneration, ViewRefusal> {
        if self.state_fault {
            return Err(ViewRefusal::StateFault);
        }
        if !self.ownership_tracked {
            return Err(ViewRefusal::OwnershipUntracked);
        }
        if !self.miner_eligible {
            return Err(ViewRefusal::MinerNotEligible);
        }
        let Some(loaded) = self.loaded.as_ref() else {
            return Err(ViewRefusal::NoGeneration);
        };
        if !generation_is_fresh(
            loaded.created_at_secs,
            now_secs,
            cfg.generation_max_age_secs,
        ) {
            return Err(ViewRefusal::GenerationStale);
        }
        if !loaded.filter_matches_generation() {
            return Err(ViewRefusal::FilterGeneration);
        }
        if !covers_protected(loaded, &self.protected) {
            return Err(ViewRefusal::CoverageIncomplete);
        }
        if !view_is_fresh(loaded, now_secs, cfg) {
            return Err(ViewRefusal::ViewStale);
        }
        Ok(loaded)
    }
}

/// Whether the newest signed cut folded into `loaded` is at most
/// `PURGE_VIEW_MAX_LAG_SECS` old at `now_secs` (a cut ahead of the clock
/// counts as lag zero).
pub fn view_is_fresh(loaded: &LoadedGeneration, now_secs: u64, cfg: &PurgeConfig) -> bool {
    now_secs.saturating_sub(loaded.view_cut_secs) <= cfg.view_max_lag_secs
}

/// Distance between the epoch an ownership was computed on and the
/// farther of the heartbeat epoch and the held map's epoch.
fn epoch_skew(ownership_epoch: u64, heartbeat_epoch: u64, held_map_epoch: u64) -> u64 {
    heartbeat_epoch
        .abs_diff(ownership_epoch)
        .max(held_map_epoch.abs_diff(ownership_epoch))
}

/// The per-delete epoch gate: a delete is decided only when the held map
/// is the one the view's ownership was computed on (the loop published
/// it) AND the heartbeat epoch is not ahead of it. A held map newer than
/// the heartbeat (a late heartbeat reply) is accepted: this miner holds
/// the newest map it has heard of.
///
/// Why no lead at all, while the pass START tolerates
/// [`EPOCH_SKEW_TOLERANCE`]: ownership comes from the map, but the
/// validator acts on its own current epoch at once. If an epoch the
/// miner has not received gives it back a PG it lost more than the
/// ownership window ago, the validator's rebalance may see the old bytes
/// still on this disk (`CheckBlob` answers `HAS:true`), skip the copy and
/// release the interim holder, while this miner's view neither protects
/// that PG nor requires its list; the old bytes are an orphan on the
/// view, and with the trash off (or its TTL past) their deletion is
/// final. One epoch of lead is enough for that, and any time bound on a
/// lead needs a clock that a restart or a flapping heartbeat resets. So
/// the delete waits for the map; every class alike (tombstones, exempt
/// from the age clause, included).
async fn delete_gate_open(view: &PurgeView, env: &dyn PassEnv) -> bool {
    let held = env.map_epoch().await;
    let heartbeat = env.current_epoch().await;
    held == view.map_epoch && heartbeat <= held
}

// ============================================================================
// Pass
// ============================================================================

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
    /// Blobs whose verdict was the moved class (listed in a protected PG
    /// under another holder): retained.
    pub kept_moved: u64,
    pub skipped_young: u64,
    pub skipped_inflight: u64,
    /// Blobs left for the next pass because the view stayed
    /// write-locked (a refresh downloading) past `VIEW_READ_TIMEOUT` while
    /// the pass held the hash lock.
    pub skipped_view_busy: u64,
    /// Rows whose hash is not 64 hex characters.
    pub invalid_hash: u64,
    /// Live rows whose blob the store does not hold (inventory ahead of
    /// the disk): nothing to delete.
    pub absent_from_store: u64,
    /// Of `absent_from_store`, rows dropped from the inventory because the
    /// store confirmed the blob absent ([`drop_absent_row`]).
    pub absent_rows_dropped: u64,
    /// Rows gone or trashed between the page read and the delete (a
    /// Delete or a trash purge ran meanwhile).
    pub vanished: u64,
    pub delete_errors: u64,
    /// Blobs left for the next pass because the per-delete epoch gate
    /// ([`delete_gate_open`]) closed between the wait and the store call.
    pub deferred_epoch_gate: u64,
    /// Distance between the ownership's map epoch and the farther of
    /// the heartbeat epoch and the held map when the pass started (0
    /// when they agreed).
    pub epoch_skew: u64,
    /// The pass stopped on epochs: the ownership's map was more than
    /// [`EPOCH_SKEW_TOLERANCE`] epochs away from the heartbeat epoch or
    /// the held map at the start, or the per-delete gate
    /// ([`delete_gate_open`]) stayed closed for [`VIEW_CATCHUP_MAX_WAIT`].
    pub aborted_epoch_change: bool,
    /// The pass stopped because the view could no longer decide a
    /// deletion: the lists stopped covering the protected set (a PG
    /// gained, a delta chain broken, a generation dropped), the
    /// generation aged out, or the miner lost every PG.
    pub aborted_coverage_lost: bool,
    /// The pass stopped (or never started) because the newest signed cut
    /// of the view was older than `PURGE_VIEW_MAX_LAG_SECS`.
    pub aborted_view_stale: bool,
    /// The pass was refused before its first page because the filter
    /// was not built from the enforced generation's lists
    /// ([`LoadedGeneration::filter_matches_generation`]). A filter miss
    /// is a deletion; a filter from another generation must never decide
    /// one.
    pub refused_filter_generation: bool,
    /// Every inventory page was read.
    pub completed: bool,
    /// Where a pass that stopped early resumes: the last hash of the last
    /// page fully handled (`None` = from the start). Deciding a blob is
    /// independent of every other, so resuming is equivalent to a pass
    /// that re-read the pages before.
    pub resume_after: Option<String>,
}

/// Largest distance, in epochs, tolerated at the START of a pass or a
/// census between the map the view's ownership was computed on and the
/// farther of the heartbeat epoch and the held map. Beyond it the pass is
/// refused before its first page.
///
/// This bound decides only whether a pass starts walking the inventory
/// (and whether a census counts). It never lets a delete through: every
/// delete goes through [`delete_gate_open`] (held map == view map, the
/// heartbeat not ahead of it) and waits ([`VIEW_CATCHUP_MAX_WAIT`])
/// otherwise. Measured on a test bench (an 11 TB node, epochs every 10-15
/// min): the held map routinely trailed the heartbeat by 2 epochs, and a
/// start bound of 1 refused 28 of 38 passes before their first page; with
/// 3 the pass starts, classifies, and its deletes proceed as soon as the
/// map arrives and is published.
pub const EPOCH_SKEW_TOLERANCE: u64 = 3;

/// A filter miss of one page that the first classification sent to the
/// delete path.
/// Drop the live inventory row of a blob the store does not hold, so the
/// inventory reported to the validator stops claiming it. The row goes
/// only under the per-hash write lock (no Store, PullFromPeer or Delete of
/// the hash can interleave), once the store positively confirms that no
/// copy exists, live or trashed ([`BlobStore::confirmed_absent`]: an I/O
/// error is not absence), and only while the row is still live with the
/// `stored_at` paged. No blob is touched: done in every mode, census
/// included. Returns whether a row was dropped.
fn drop_absent_row(
    store: &dyn BlobStore,
    env: &dyn PassEnv,
    hash_hex: &str,
    stored_at: i64,
) -> bool {
    let Some(_write_lock) = env.try_lock_write(hash_hex) else {
        return false;
    };
    if !store.confirmed_absent(hash_hex) {
        return false;
    }
    match env.drop_live_row(hash_hex, stored_at) {
        Ok(dropped) => {
            if dropped {
                debug!(hash = %hash_hex, "purge: blob absent from the store, inventory row dropped");
            }
            dropped
        }
        Err(e) => {
            warn!(hash = %hash_hex, error = %e, "purge: dropping the inventory row of an absent blob failed");
            false
        }
    }
}

struct PageCandidate {
    hash_hex: String,
    hash: [u8; 32],
    /// The row's `stored_at` as paged (guards [`drop_absent_row`]).
    stored_at: i64,
    age_secs: u64,
    tombstoned: bool,
}

fn count_refusal(refusal: ViewRefusal, summary: &mut PassSummary, metrics: &PurgeMetrics) {
    match refusal {
        ViewRefusal::FilterGeneration => {
            metrics
                .filter_generation_refusals
                .fetch_add(1, Ordering::Relaxed);
            summary.refused_filter_generation = true;
        }
        ViewRefusal::ViewStale => {
            metrics.view_stale_refusals.fetch_add(1, Ordering::Relaxed);
            summary.aborted_view_stale = true;
        }
        ViewRefusal::MinerNotEligible
        | ViewRefusal::NoGeneration
        | ViewRefusal::GenerationStale
        | ViewRefusal::CoverageIncomplete
        | ViewRefusal::StateFault
        | ViewRefusal::OwnershipUntracked => {
            metrics.coverage_lost_aborts.fetch_add(1, Ordering::Relaxed);
            summary.aborted_coverage_lost = true;
        }
    }
}

/// One rate-bounded pass over the live inventory, deciding every blob on
/// `view` (see [`run_pass_on`]); test entry point over a fixed load.
#[cfg(test)]
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
    let view = RwLock::new(PurgeView {
        protected: loaded.owned_pgs.clone(),
        miner_eligible: gate.miner_eligible,
        map_epoch: env.map_epoch().await,
        state_fault: false,
        ownership_tracked: gate.ownership_window_tracked,
        loaded: Some(loaded.clone()),
    });
    run_pass_on(
        store,
        env,
        &view,
        gate,
        cfg,
        hard_delete,
        epoch_at_start,
        None,
        metrics,
    )
    .await
}

/// One rate-bounded pass over the live inventory, starting after
/// `start_after` (a resumed pass) or at the first hash.
///
/// `gate` was evaluated by the caller. `epoch_at_start` is the epoch of
/// the map the protected set was computed on; the heartbeat epoch
/// (`env.current_epoch`) and the held map (`env.map_epoch`) may be up to
/// [`EPOCH_SKEW_TOLERANCE`] epochs away from it (logged and counted, the
/// pass runs on that ownership), a larger distance refuses the pass
/// before the first page (the map this miner holds is not the one the
/// validator places on).
///
/// Every page is classified under one read of `view`, and every blob sent
/// to the delete path is decided again, after the rate-limiter wait and
/// under its per-hash write lock, on a fresh read of the view held across
/// the delete: the lists must still cover the protected set (else the
/// pass stops, `aborted_coverage_lost`), the view's ownership must be
/// within [`EPOCH_SKEW_TOLERANCE`] epochs of the heartbeat epoch and of
/// the held map (else the pass waits for the map and for the loop to
/// publish it, up to [`VIEW_CATCHUP_MAX_WAIT`]), and the blob must still
/// be a filter miss of the lists loaded at that moment. An epoch
/// change does not stop the pass: the protected set keeps every PG owned
/// within the window, so a PG lost stays covered and a PG gained closes
/// coverage until its list is loaded. Deletion goes through
/// `store.delete` (two-phase trash) unless `hard_delete`, which mirrors
/// `TRASH_ENABLED=false` on the validator's Delete path.
#[allow(clippy::too_many_arguments)]
pub async fn run_pass_on(
    store: &dyn BlobStore,
    env: &dyn PassEnv,
    view: &SharedView,
    gate: PurgeGate,
    cfg: &PurgeConfig,
    hard_delete: bool,
    epoch_at_start: u64,
    start_after: Option<String>,
    metrics: &PurgeMetrics,
) -> PassSummary {
    // Only the enforcing arm reads it; a census build has no such arm.
    #[cfg(not(feature = "purge-enforce"))]
    let _ = hard_delete;
    let mut summary = PassSummary::default();
    if !gate.open() {
        return summary;
    }
    {
        let v = view.read().await;
        if let Some(loaded) = v.loaded.as_ref()
            && !loaded.filter_matches_generation()
        {
            error!(
                generation = loaded.generation,
                sets_generation = loaded.sets.as_ref().map(|sets| sets.generation()),
                "purge: filter was not built from the enforced generation: pass not run, generation dropped for rebuild"
            );
            count_refusal(ViewRefusal::FilterGeneration, &mut summary, metrics);
            return summary;
        }
    }
    // The heartbeat epoch and the held map as the pass starts, against
    // the map the ownership was computed on.
    let epoch_baseline = env.current_epoch().await;
    let held_map_epoch = env.map_epoch().await;
    summary.epoch_skew = epoch_skew(epoch_at_start, epoch_baseline, held_map_epoch);
    if summary.epoch_skew > EPOCH_SKEW_TOLERANCE {
        warn!(
            map_epoch = epoch_at_start,
            held_map_epoch,
            heartbeat_epoch = epoch_baseline,
            skew = summary.epoch_skew,
            tolerated = EPOCH_SKEW_TOLERANCE,
            "purge: heartbeat epoch and cluster map epoch disagree, the map is not current: pass not run"
        );
        metrics.epoch_skew_aborts.fetch_add(1, Ordering::Relaxed);
        summary.aborted_epoch_change = true;
        summary.resume_after = start_after;
        return summary;
    }
    if summary.epoch_skew > 0 {
        warn!(
            map_epoch = epoch_at_start,
            held_map_epoch,
            heartbeat_epoch = epoch_baseline,
            skew = summary.epoch_skew,
            tolerated = EPOCH_SKEW_TOLERANCE,
            "purge: heartbeat epoch ahead of the cluster map epoch, within tolerance: pass runs on the map's ownership"
        );
        metrics.epoch_skew_tolerated.fetch_add(1, Ordering::Relaxed);
    }
    let mut limiter = RateLimiter::new(cfg.rate_per_sec, cfg.max_bytes_per_sec);
    let mut after: Option<String> = start_after;
    let mut since_summary = 0u64;

    loop {
        let page = match env.live_shards_page(after.as_deref(), PAGE_SIZE) {
            Ok(p) => p,
            Err(e) => {
                error!(error = %e, "purge: inventory page failed, stopping pass");
                summary.resume_after = after;
                return summary;
            }
        };
        let Some((last, _)) = page.last() else {
            summary.completed = true;
            break;
        };
        let last = last.clone();
        // First classification of the page, under one read of the view.
        let candidates: Option<Vec<PageCandidate>> = {
            let v = view.read().await;
            let loaded = match v.enforceable(env.now_secs(), cfg) {
                Ok(l) => l,
                Err(refusal) => {
                    warn!(
                        ?refusal,
                        examined = summary.examined,
                        "purge: the loaded lists no longer decide a deletion, stopping pass"
                    );
                    count_refusal(refusal, &mut summary, metrics);
                    summary.resume_after = after;
                    return summary;
                }
            };
            // Without the switch a blob held for another holder is an
            // orphan (the pre-moved-class rule).
            let moved_class = cfg.moved_class;
            // Age is measured from the earlier of now and the generation's
            // snapshot bound (scan start when published, else creation): a
            // blob written after it may be unlisted and must never look
            // "old enough".
            let reference = env.now_secs().min(loaded.snapshot_secs);
            // The lookups fault pages of the mapped sets in from disk,
            // one per hash: the whole page is classified in one blocking
            // section so a cold cache never holds a runtime worker.
            crate::helpers::blocking(|| {
                let mut out = Vec::new();
                for (hash_hex, stored_at) in &page {
                    summary.examined += 1;
                    metrics.candidates.fetch_add(1, Ordering::Relaxed);
                    let Some(hash) = parse_hash(hash_hex) else {
                        summary.invalid_hash += 1;
                        metrics.invalid_hash.fetch_add(1, Ordering::Relaxed);
                        continue;
                    };
                    let in_filter = loaded.may_be_obliged(&hash);
                    // The others filter and the exact tombstone set are only
                    // consulted for a filter miss: a listed hash wins over
                    // both, and the lookups are spared on the common case.
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
                        // The gate was open at the top of the pass; these
                        // cannot fire, but if they ever do the only safe
                        // answer is stop.
                        Verdict::KeepMinerNotEligible
                        | Verdict::KeepNoGeneration
                        | Verdict::KeepGenerationStale
                        | Verdict::KeepCoverageIncomplete
                        | Verdict::KeepOwnershipWindowUntracked => {
                            return None;
                        }
                    };
                    out.push(PageCandidate {
                        hash_hex: hash_hex.clone(),
                        hash,
                        stored_at: stored_at as i64,
                        age_secs: candidate.age_secs,
                        tombstoned,
                    });
                }
                Some(out)
            })
        };
        let Some(candidates) = candidates else {
            summary.resume_after = after;
            return summary;
        };

        'candidates: for c in candidates {
            // Absent from the store already (inventory ahead of disk): a
            // delete would be a no-op, do not spend budget on it.
            let Some(len) = store.blob_len(&c.hash_hex) else {
                summary.absent_from_store += 1;
                metrics.absent_from_store.fetch_add(1, Ordering::Relaxed);
                if drop_absent_row(store, env, &c.hash_hex, c.stored_at) {
                    summary.absent_rows_dropped += 1;
                    metrics.absent_rows_dropped.fetch_add(1, Ordering::Relaxed);
                }
                continue;
            };
            limiter.acquire(len).await;

            // The limiter may have waited: the map may have moved, the
            // lists may have changed, and a write of this hash may have
            // started (a content-addressed re-upload lands under the old
            // hash). Take the per-hash write lock (a writer already there
            // makes us skip, a writer arriving now waits for the delete
            // and then re-stores) and a fresh read of the view, which
            // must carry the ownership of the map held now.
            let deadline = tokio::time::Instant::now() + VIEW_CATCHUP_MAX_WAIT;
            let (_write_lock, v) = loop {
                let Some(lock) = env.try_lock_write(&c.hash_hex) else {
                    summary.skipped_inflight += 1;
                    metrics.skipped_inflight.fetch_add(1, Ordering::Relaxed);
                    continue 'candidates;
                };
                // Bounded: while holding the hash lock the pass never
                // waits long for the view (a refresh may hold its write
                // lock across downloads). A Store of this hash waiting on
                // the lock gets it back; the blob is kept for the next
                // pass.
                let v = match tokio::time::timeout(VIEW_READ_TIMEOUT, view.read()).await {
                    Ok(v) => v,
                    Err(_) => {
                        drop(lock);
                        debug!(hash = %c.hash_hex, "purge: view busy (refresh in progress), blob left for the next pass");
                        summary.skipped_view_busy += 1;
                        metrics.skipped_view_busy.fetch_add(1, Ordering::Relaxed);
                        continue 'candidates;
                    }
                };
                if delete_gate_open(&v, env).await {
                    break (lock, v);
                }
                let view_epoch = v.map_epoch;
                drop(v);
                drop(lock);
                if tokio::time::Instant::now() >= deadline {
                    let heartbeat_epoch = env.current_epoch().await;
                    let held_map_epoch = env.map_epoch().await;
                    warn!(
                        waited_secs = VIEW_CATCHUP_MAX_WAIT.as_secs(),
                        view_map_epoch = view_epoch,
                        heartbeat_epoch,
                        held_map_epoch,
                        "purge: no delete on this ownership (held map not published into the view, or the heartbeat ahead of it), stopping pass"
                    );
                    summary.aborted_epoch_change = true;
                    summary.resume_after = after;
                    return summary;
                }
                tokio::time::sleep(Duration::from_secs(1)).await;
            };
            let now = env.now_secs();
            let loaded = match v.enforceable(now, cfg) {
                Ok(l) => l,
                Err(refusal) => {
                    warn!(
                        ?refusal,
                        examined = summary.examined,
                        "purge: the loaded lists no longer decide a deletion, stopping pass before the delete"
                    );
                    count_refusal(refusal, &mut summary, metrics);
                    summary.resume_after = after;
                    return summary;
                }
            };
            // A write may have completed during the wait and refreshed
            // the row: re-read it under the lock.
            let fresh_stored_at = match env.live_stored_at(&c.hash_hex) {
                Ok(Some(at)) => at.max(0) as u64,
                Ok(None) => {
                    summary.vanished += 1;
                    metrics.vanished.fetch_add(1, Ordering::Relaxed);
                    continue;
                }
                Err(e) => {
                    error!(error = %e, "purge: inventory re-read failed, stopping pass");
                    summary.resume_after = after;
                    return summary;
                }
            };
            // Decide again on the lists loaded now: a refresh may have
            // listed the hash (a keep) since the page was classified.
            let reference = now.min(loaded.snapshot_secs);
            let (in_filter, moved, tombstoned) = crate::helpers::blocking(|| {
                let in_filter = loaded.may_be_obliged(&c.hash);
                let moved = !in_filter && cfg.moved_class && loaded.may_be_held_by_other(&c.hash);
                let tombstoned = !in_filter && !moved && loaded.is_tombstoned(&c.hash);
                (in_filter, moved, tombstoned)
            });
            let recheck = Candidate {
                age_secs: reference.saturating_sub(fresh_stored_at),
                in_filter,
                moved,
                tombstoned,
                stored_after_snapshot: fresh_stored_at >= reference,
                // This pass holds the hash's write lock: no write is in
                // flight (`is_write_inflight` would see our own lock).
                inflight: false,
            };
            let tombstoned = match decide(gate, recheck, cfg.min_age_secs) {
                Verdict::Purge => false,
                Verdict::PurgeTombstoned => true,
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
                Verdict::KeepMinerNotEligible
                | Verdict::KeepNoGeneration
                | Verdict::KeepGenerationStale
                | Verdict::KeepCoverageIncomplete
                | Verdict::KeepOwnershipWindowUntracked => {
                    summary.resume_after = after;
                    return summary;
                }
            };
            if tombstoned && !c.tombstoned {
                summary.tombstone_candidates += 1;
                metrics.tombstone_candidates.fetch_add(1, Ordering::Relaxed);
            }
            // Last check before the store call: the epoch gate is still
            // open. This is the decision's linearization point: a map arriving during
            // the delete call itself makes it a delete decided just before
            // that map, on lists that covered every PG protected at that
            // moment. The blob is left for the next pass otherwise.
            if !delete_gate_open(&v, env).await {
                debug!(hash = %c.hash_hex, tombstoned, "purge: epoch gate closed during the checks, blob left for the next pass");
                summary.deferred_epoch_gate += 1;
                continue;
            }

            match cfg.mode {
                Mode::Census => {
                    debug!(
                        hash = %c.hash_hex,
                        bytes = len,
                        age_secs = c.age_secs,
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
                    // The view's read lock is held across the delete: the
                    // lists it was decided on cannot change under it.
                    let result = if hard_delete {
                        store.remove(&c.hash_hex).await
                    } else {
                        store.delete(&c.hash_hex).await
                    };
                    match result {
                        Ok(()) => {
                            if hard_delete {
                                env.record_removed(&c.hash_hex);
                            } else {
                                env.record_trashed(&c.hash_hex);
                            }
                            debug!(
                                hash = %c.hash_hex,
                                bytes = len,
                                age_secs = c.age_secs,
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
                            warn!(hash = %c.hash_hex, error = %e, "purge: delete failed");
                            summary.delete_errors += 1;
                            metrics.delete_errors.fetch_add(1, Ordering::Relaxed);
                        }
                    }
                }
            }
            drop(v);
            since_summary += 1;
            if since_summary >= SUMMARY_EVERY {
                since_summary = 0;
                log_progress(cfg.mode, &summary);
            }
        }
        after = Some(last);
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
        skipped_view_busy = s.skipped_view_busy,
        invalid_hash = s.invalid_hash,
        absent_from_store = s.absent_from_store,
        absent_rows_dropped = s.absent_rows_dropped,
        vanished = s.vanished,
        delete_errors = s.delete_errors,
        "purge: progress"
    );
}

// ============================================================================
// Census on incomplete coverage (dry-run only)
// ============================================================================

/// What one dry-run census over the inventory found under a generation
/// that does not cover every protected PG. Every blob is classified with
/// the purge rule ([`classify`]) against the lists that ARE loaded;
/// no blob is deleted, locked or marked. Only the inventory row of a blob
/// the store confirms absent is dropped ([`drop_absent_row`]), as in a
/// pass: the row lies, whatever the mode.
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
    /// Protected PGs whose list is folded in / PGs the generation does
    /// not cover.
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
    /// Rows whose hash is not 64 hex characters.
    pub invalid_hash: u64,
    /// Unlisted rows whose blob the store does not hold.
    pub absent_from_store: u64,
    /// Of `absent_from_store`, rows dropped from the inventory because the
    /// store confirmed the blob absent ([`drop_absent_row`]).
    pub absent_rows_dropped: u64,
    /// Heartbeat epoch moves seen between the first and the last page
    /// (sum of the distances). A census deletes nothing and counts
    /// under the lists loaded at each page, so it does NOT stop on an
    /// epoch change: on a live network the epoch moves every ~15 min and a
    /// full inventory walk takes hours. Non-zero tells that the owned set
    /// may have moved under the counts.
    pub epochs_crossed: u32,
    /// The census did not start: the ownership's map epoch was more than
    /// [`EPOCH_SKEW_TOLERANCE`] epochs away from the heartbeat epoch or
    /// the held map at the start (the held map is not current). Never set mid-pass, see `epochs_crossed`.
    pub aborted_epoch_change: bool,
    /// The filter was not built from the enforced generation's lists:
    /// nothing counted.
    pub refused_filter_generation: bool,
    /// The census stopped before the last page: cancelled by the loop
    /// (coverage became complete, a real pass is due) or the view lost
    /// its generation.
    pub stopped: bool,
}

impl Census {
    /// Whether every inventory page was read.
    pub fn complete(&self) -> bool {
        !self.aborted_epoch_change && !self.refused_filter_generation && !self.stopped
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
        set(&g.invalid_hash, self.invalid_hash);
        set(&g.absent_from_store, self.absent_from_store);
        set(&g.absent_rows_dropped, self.absent_rows_dropped);
        g.complete.store(complete, Ordering::Relaxed);
    }
}

/// [`run_census_on`] over a fixed load, never cancelled; test entry point.
#[cfg(test)]
pub async fn run_census(
    store: &dyn BlobStore,
    env: &dyn PassEnv,
    loaded: &LoadedGeneration,
    cfg: &PurgeConfig,
    epoch_at_start: u64,
) -> Census {
    let view = RwLock::new(PurgeView {
        protected: loaded.owned_pgs.clone(),
        miner_eligible: true,
        map_epoch: epoch_at_start,
        state_fault: false,
        ownership_tracked: true,
        loaded: Some(loaded.clone()),
    });
    run_census_on(
        store,
        env,
        &view,
        cfg,
        epoch_at_start,
        &AtomicBool::new(false),
    )
    .await
}

/// An unlisted blob of one census page, classified under the view.
struct CensusRow {
    hash_hex: String,
    stored_at: i64,
    tombstoned: bool,
    verdict: Verdict,
}

/// One rate-bounded, read-only census over the live inventory for a
/// generation with incomplete coverage, in dry-run only. Same paging,
/// same start-of-pass skew check and same per-blob rule as
/// [`run_pass_on`], but the coverage gate is not consulted, and an epoch
/// change mid-pass is counted (`epochs_crossed`) instead of stopping:
/// nothing is deleted. Each page is classified under one read of `view`
/// (the lists loaded at that moment, so a delta or a PG added meanwhile
/// is counted from the next page on) and the lock is released before the
/// paced `stat`s, so the census never holds the loop's refresh back for
/// longer than one page's in-memory classification. `cancel` stops it at
/// the next row. The byte size is read (`BlobStore::blob_len`, a `stat`)
/// only for the classes a full-coverage dry-run would `stat` too
/// (tombstone, orphan), paced by the pass's operation budget
/// (`PURGE_RATE_PER_SEC`): the I/O profile is that of the existing
/// dry-run, not a walk of the store.
pub async fn run_census_on(
    store: &dyn BlobStore,
    env: &dyn PassEnv,
    view: &SharedView,
    cfg: &PurgeConfig,
    epoch_at_start: u64,
    cancel: &AtomicBool,
) -> Census {
    let mut census = Census::default();
    {
        let v = view.read().await;
        let Some(loaded) = v.loaded.as_ref() else {
            census.stopped = true;
            return census;
        };
        census.generation = loaded.generation;
        census.covered_pgs = loaded.listed_pgs;
        census.missing_pgs = loaded.missing_pgs.len();
        census.chain_broken_at = loaded.chain_broken_at;
        if !loaded.filter_matches_generation() {
            census.refused_filter_generation = true;
            return census;
        }
    }
    let epoch_baseline = env.current_epoch().await;
    if epoch_skew(epoch_at_start, epoch_baseline, env.map_epoch().await) > EPOCH_SKEW_TOLERANCE {
        census.aborted_epoch_change = true;
        return census;
    }
    let mut limiter = RateLimiter::new(cfg.rate_per_sec, cfg.max_bytes_per_sec);
    let mut after: Option<String> = None;
    let mut since_summary = 0u64;
    let mut epoch_last_seen = epoch_baseline;

    'pages: loop {
        if cancel.load(Ordering::Relaxed) {
            census.stopped = true;
            break;
        }
        // A census deletes nothing: an epoch move is recorded, not an
        // abort (the real pass keeps deciding on a current view).
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
                "purge[census]: cluster epoch changed mid-pass, continuing (read-only count under the loaded lists)"
            );
            epoch_last_seen = epoch_now;
        }
        let page = match env.live_shards_page(after.as_deref(), PAGE_SIZE) {
            Ok(p) => p,
            Err(e) => {
                error!(error = %e, "purge[census]: inventory page failed, stopping");
                census.stopped = true;
                break;
            }
        };
        let Some((last, _)) = page.last() else {
            break;
        };
        after = Some(last.clone());

        let unlisted: Option<Vec<CensusRow>> = {
            let v = view.read().await;
            let Some(loaded) = v.loaded.as_ref() else {
                census.stopped = true;
                break 'pages;
            };
            census.generation = loaded.generation;
            census.covered_pgs = loaded.listed_pgs;
            census.missing_pgs = loaded.missing_pgs.len();
            census.chain_broken_at = loaded.chain_broken_at;
            let moved_class = cfg.moved_class;
            let reference = env.now_secs().min(loaded.snapshot_secs);
            // One blocking section per page, as in the pass.
            crate::helpers::blocking(|| {
                let mut out = Vec::new();
                for (hash_hex, stored_at) in &page {
                    census.examined += 1;
                    let Some(hash) = parse_hash(hash_hex) else {
                        census.invalid_hash += 1;
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
                        Verdict::KeepInList => census.protected += 1,
                        Verdict::KeepMoved => census.moved += 1,
                        // The gates were not consulted: these cannot come out
                        // of `classify`; stopping is the only safe reading.
                        Verdict::KeepMinerNotEligible
                        | Verdict::KeepNoGeneration
                        | Verdict::KeepGenerationStale
                        | Verdict::KeepCoverageIncomplete
                        | Verdict::KeepOwnershipWindowUntracked => {
                            return None;
                        }
                        Verdict::Purge
                        | Verdict::PurgeTombstoned
                        | Verdict::KeepYoung
                        | Verdict::KeepStoredAfterSnapshot
                        | Verdict::KeepInflight => out.push(CensusRow {
                            hash_hex: hash_hex.clone(),
                            stored_at: stored_at as i64,
                            tombstoned: candidate.tombstoned,
                            verdict,
                        }),
                    }
                }
                Some(out)
            })
        };
        let Some(unlisted) = unlisted else {
            census.stopped = true;
            break 'pages;
        };
        for row in unlisted {
            if cancel.load(Ordering::Relaxed) {
                census.stopped = true;
                break 'pages;
            }
            // One `stat` per unlisted blob, paced like a dry-run deletion
            // (operation budget only: no blob is touched; a row whose blob
            // is confirmed gone is dropped).
            limiter.acquire(0).await;
            let Some(len) = store.blob_len(&row.hash_hex) else {
                census.absent_from_store += 1;
                if drop_absent_row(store, env, &row.hash_hex, row.stored_at) {
                    census.absent_rows_dropped += 1;
                }
                continue;
            };
            if row.tombstoned {
                census.tombstone += 1;
                census.tombstone_bytes += len;
            } else if row.verdict == Verdict::Purge {
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
        invalid_hash = c.invalid_hash,
        absent_from_store = c.absent_from_store,
        absent_rows_dropped = c.absent_rows_dropped,
        epochs_crossed = c.epochs_crossed,
        aborted_epoch_change = c.aborted_epoch_change,
        stopped = c.stopped,
        "{message} (orphan classes are an upper bound: a blob of an uncovered PG is indistinguishable from an orphan; nothing deleted)"
    );
}

// ============================================================================
// Ownership
// ============================================================================

/// Why clause 0 refuses a map.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Ineligible {
    /// The map does not list this uid.
    NotInMap,
    /// The map lists it as draining or under a placement hold.
    NotPlaceable,
}

/// Clause 0 of the purge rule on this miner's entry in the held map:
/// listed (`weight` is `Some`, any value, 0 included) and placeable (not
/// draining, no placement hold: what `common::filter_map_for_placement`
/// keeps).
pub(crate) fn purge_eligibility(weight: Option<u32>, unplaceable: bool) -> Result<(), Ineligible> {
    match (weight, unplaceable) {
        (None, _) => Err(Ineligible::NotInMap),
        (Some(_), true) => Err(Ineligible::NotPlaceable),
        (Some(_), false) => Ok(()),
    }
}

/// This miner's ownership under one cluster map.
pub(crate) struct Ownership {
    pub epoch: u64,
    /// Sorted owned PGs. EMPTY for a miner the map gives no weight
    /// (quarantine, declared full, duplicate address) or does not list.
    /// The purge keeps the PGs lost within the ownership window
    /// protected either way; the backfill has nothing to fetch.
    pub pgs: Vec<u32>,
    /// This miner's CRUSH weight in that map; `None` when the map does
    /// not list this uid (the purge's clause 0 then refuses).
    pub weight: Option<u32>,
    /// The map lists this uid as draining or under a placement hold
    /// (what `common::filter_map_for_placement` removes): the purge's
    /// clause 0 refuses.
    pub unplaceable: bool,
}

/// PGs this miner owns under the current cluster map for the backfill
/// (v2 ∪ v3, `common::calculate_my_pgs`), from the shared epoch-keyed
/// cache (recomputed here on a miss so the backfill does not depend on
/// the rebalance loop being enabled). `None` only when no map has arrived
/// yet; an empty owned set is returned as such. The purge uses
/// [`purge_owned_pgs`] (v3 only) instead.
#[cfg_attr(not(feature = "backfill"), allow(dead_code))]
pub(crate) async fn owned_pgs() -> Option<Ownership> {
    let map = state::get_cluster_map().read().await.clone()?;
    let epoch = map.epoch;
    let uid = state::get_miner_uid();
    let me = map.miners.iter().find(|m| m.uid == uid);
    let weight = me.map(|m| m.weight);
    let unplaceable = me.is_some_and(|m| m.draining || m.placement_hold);
    {
        let cached = state::get_my_pgs_cache().read().await;
        if cached.0 == epoch && !cached.1.is_empty() {
            let mut pgs = cached.1.clone();
            pgs.sort_unstable();
            return Some(Ownership {
                epoch,
                pgs,
                weight,
                unplaceable,
            });
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
        return Some(Ownership {
            epoch,
            pgs,
            weight,
            unplaceable,
        });
    }
    *state::get_my_pgs_cache().write().await = (epoch, pgs.clone());
    info!(epoch, owned_pgs = pgs.len(), "purge: PG ownership computed");
    Some(Ownership {
        epoch,
        pgs,
        weight,
        unplaceable,
    })
}

/// PGs this miner owns for the purge under the current cluster map: the
/// v3 (straw2) placement only ([`purge::calculate_purge_pgs`]), cached in
/// `cache` by epoch. `None` only when no map has arrived yet, or when the
/// computation panicked (the tick is skipped; never an empty set).
async fn purge_owned_pgs(
    cache: &mut Option<(Arc<common::ClusterMap>, Vec<u32>)>,
) -> Option<Ownership> {
    let map = state::get_cluster_map().read().await.clone()?;
    let epoch = map.epoch;
    let uid = state::get_miner_uid();
    let me = map.miners.iter().find(|m| m.uid == uid);
    let weight = me.map(|m| m.weight);
    let unplaceable = me.is_some_and(|m| m.draining || m.placement_hold);
    // Keyed by the map object itself, not only its epoch: a map replaced
    // under the same epoch is recomputed (the validator bumps the epoch on
    // every map mutation, so this is belt and braces).
    if let Some((cached_map, pgs)) = cache.as_ref()
        && Arc::ptr_eq(cached_map, &map)
    {
        return Some(Ownership {
            epoch,
            pgs: pgs.clone(),
            weight,
            unplaceable,
        });
    }
    // CRUSH over every PG is CPU-bound: off the runtime.
    let for_crush = Arc::clone(&map);
    let pgs = match tokio::task::spawn_blocking(move || purge::calculate_purge_pgs(uid, &for_crush))
        .await
    {
        Ok(pgs) => pgs,
        Err(e) => {
            error!(error = %e, "purge: PG ownership calculation panicked, skipping this tick");
            return None;
        }
    };
    info!(
        epoch,
        owned_pgs = pgs.len(),
        "purge: v3 PG ownership computed"
    );
    *cache = Some((map, pgs.clone()));
    Some(Ownership {
        epoch,
        pgs,
        weight,
        unplaceable,
    })
}

// ============================================================================
// Generation refresh
// ============================================================================

/// Bring `current` up to date with the bucket for the `protected` PGs. A
/// failure at any step keeps the previous generation (logged): a bad
/// publication never widens what may be purged, and a previous generation
/// that does not cover the protected set closes the gate by itself
/// ([`covers_protected`]).
///
/// Same generation: PGs of `protected` it does not hold are added in
/// place ([`LoadedGeneration::add_pgs`]: no base list is fetched, the
/// holder set and live filter cover every PG), and new deltas are folded in; PGs that left the protected
/// set stay loaded (a keep) until the loaded set is more than twice the
/// protected one, then the generation is reloaded for exactly the
/// protected set. New generation: loaded whole for `protected`.
#[allow(clippy::too_many_arguments)]
async fn refresh_generation(
    source: &dyn ListSource,
    validator_node_id: &str,
    protected: &[u32],
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
    refresh_generation_at(
        source,
        validator_node_id,
        &pointer,
        protected,
        my_uid,
        cfg,
        now_secs,
        current,
        highest_seen,
    )
    .await;
}

/// Whether a refresh for `pointer` would change nothing: the pointer is
/// behind the watermark or stale, or it names the loaded generation, the
/// loaded view holds every protected PG without bloat, has folded every
/// announced delta and its chain is whole. Decided under a read lock so
/// the common poll never takes the view's write lock.
fn refresh_is_noop(
    loaded: Option<&LoadedGeneration>,
    pointer: &CurrentPointer,
    protected: &[u32],
    highest_seen: u64,
) -> bool {
    if pointer.generation < highest_seen {
        return true;
    }
    let Some(l) = loaded else {
        return false;
    };
    if l.generation != pointer.generation {
        return false;
    }
    if pointer_is_stale(l, pointer.delta_hint()) {
        return true;
    }
    loaded_holds_all(l, protected)
        && !loaded_is_bloated(l, protected)
        && l.delta_seq >= pointer.delta_hint()
        && l.chain_broken_at.is_none()
}

/// [`refresh_generation`] for an already fetched `current.json`.
#[allow(clippy::too_many_arguments)]
async fn refresh_generation_at(
    source: &dyn ListSource,
    validator_node_id: &str,
    pointer: &CurrentPointer,
    protected: &[u32],
    my_uid: u32,
    cfg: &PurgeConfig,
    now_secs: u64,
    current: &mut Option<LoadedGeneration>,
    highest_seen: &mut u64,
) {
    let pointer = pointer.clone();
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
        return;
    }
    let mut prefetched: Option<Manifest> = None;
    if let Some(loaded) = current.as_mut()
        && loaded.generation == latest
    {
        // Within a generation the announced delta sequence only grows: a
        // pointer announcing fewer deltas than already announced is stale
        // or replayed. Nothing is done on it (in particular it can never
        // make a broken chain whole again).
        if pointer_is_stale(loaded, pointer.delta_hint()) {
            warn!(
                generation = latest,
                pointer_delta_seq = pointer.delta_hint(),
                announced_delta_seq = loaded.announced_delta_seq,
                delta_seq = loaded.delta_seq,
                "purge: current.json announces fewer deltas than already announced for this generation (stale or replayed pointer), ignoring it"
            );
            return;
        }
        // Whatever branch follows and however it fails, a view behind the
        // deltas the pointer announces is incomplete; only folding them
        // clears the mark.
        mark_behind_pointer(loaded, pointer.delta_hint());
        let held: HashSet<u32> = loaded.owned_pgs.iter().copied().collect();
        let to_add: Vec<u32> = protected
            .iter()
            .copied()
            .filter(|pg| !held.contains(pg))
            .collect();
        let bloated = loaded_is_bloated(loaded, protected);
        if to_add.is_empty() && !bloated {
            // Same generation, protected set held: only the delta chain
            // can have grown. Nothing to do while the pointer's hint is
            // not ahead of what is folded in and the chain is whole;
            // otherwise re-fetch the base manifest (its `deltas` grew)
            // and fold the new deltas without downloading the base lists
            // again.
            if loaded.delta_seq >= pointer.delta_hint() && loaded.chain_broken_at.is_none() {
                return;
            }
            extend_generation(source, validator_node_id, my_uid, cfg, loaded, &pointer).await;
            return;
        }
        let manifest = match pg_lists::fetch_manifest_at(source, &pointer, validator_node_id).await
        {
            Ok(m) => m,
            Err(e) => {
                warn!(
                    generation = latest,
                    error = %format!("{e:#}"),
                    "purge: manifest rejected, keeping previous generation"
                );
                return;
            }
        };
        if !bloated {
            match loaded
                .add_pgs(source, &manifest, &to_add, my_uid, cfg.fetch_concurrency)
                .await
            {
                Ok(added) => info!(
                    generation = latest,
                    added,
                    protected = protected.len(),
                    loaded_pgs = loaded.owned_pgs.len(),
                    "purge: protected PGs added to the loaded generation"
                ),
                Err(e) => {
                    warn!(
                        generation = latest,
                        pgs = to_add.len(),
                        error = %format!("{e:#}"),
                        "purge: adding protected PGs failed, coverage incomplete until a retry succeeds"
                    );
                    return;
                }
            }
            extend_with(source, &manifest, pointer.delta_hint(), my_uid, cfg, loaded).await;
            return;
        }
        info!(
            generation = latest,
            protected = protected.len(),
            loaded_pgs = loaded.owned_pgs.len(),
            to_add = to_add.len(),
            "purge: loaded lists no longer fit the protected set, reloading the generation for it"
        );
        prefetched = Some(manifest);
    }
    let manifest = match prefetched {
        Some(m) => m,
        None => match pg_lists::fetch_manifest_at(source, &pointer, validator_node_id).await {
            Ok(m) => m,
            Err(e) => {
                // A v2 pointer digests the base manifest it names: bytes
                // that do not match are a bucket mid-publication or a
                // tampered object, refused before parsing.
                warn!(
                    generation = latest,
                    error = %format!("{e:#}"),
                    "purge: manifest rejected, keeping previous generation"
                );
                return;
            }
        },
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
            return;
        }
        None => {
            warn!(
                generation = latest,
                "purge: manifest has no usable created_at, not loading it"
            );
            return;
        }
    }
    let prev_announced = current
        .as_ref()
        .filter(|c| c.generation == latest)
        .map_or(0, |c| c.announced_delta_seq);
    let Some(cache_root) = lists_cache_root(cfg) else {
        warn!(
            generation = latest,
            "purge: no data directory for the holder set cache, not loading the generation"
        );
        return;
    };
    match pg_lists::load_generation(
        source,
        &manifest,
        protected,
        my_uid,
        cfg.fetch_concurrency,
        &cache_root,
    )
    .await
    {
        Ok(mut loaded) => {
            // A reload of the same generation keeps what was already
            // announced for it: the new view is behind it until folded.
            loaded.note_announced(prev_announced);
            mark_behind_pointer(&mut loaded, pointer.delta_hint());
            info!(
                generation = loaded.generation,
                protected_pgs = loaded.owned_pgs.len(),
                listed_pgs = loaded.listed_pgs,
                missing_pgs = loaded.missing_pgs.len(),
                hashes = loaded.total_hashes,
                sets = loaded.sets.is_some(),
                mapped_bytes = loaded.sets.as_ref().map_or(0, |sets| sets.mapped_bytes()),
                fetched_objects = loaded.sets.as_ref().map_or(0, |sets| sets.fetched_objects),
                reused_objects = loaded.sets.as_ref().map_or(0, |sets| sets.reused_objects),
                moved_class = cfg.moved_class,
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
                crate::helpers::blocking(|| persist_watermark(*highest_seen));
            }
            *current = Some(loaded);
        }
        Err(e) => {
            warn!(
                generation = latest,
                error = %format!("{e:#}"),
                "purge: generation load failed, keeping previous generation"
            );
        }
    }
}

/// Where the holder sets and live filter shards are cached:
/// `PurgeConfig::lists_cache_dir`, else `<data_dir>/pg-lists-cache`.
fn lists_cache_root(cfg: &PurgeConfig) -> Option<std::path::PathBuf> {
    cfg.lists_cache_dir
        .clone()
        .or_else(|| state::get_data_dir().map(|dir| dir.join("pg-lists-cache")))
}

/// Fold the deltas appended to the loaded generation since it was loaded
/// (or since the chain last broke). The base manifest is re-fetched
/// through the pointer (`pg_lists::fetch_manifest_at`: digest-checked
/// when the pointer carries one; the chain is the signed base's, or the
/// v2 pointer's when the base declares none), the already-verified delta
/// manifests are reused, and only the new deltas' bundles holding loaded
/// PGs are downloaded. Any failure leaves the load as it was: a broken
/// chain is coverage incomplete (the purge waits) and the loop retries
/// with backoff ([`RefreshBackoff`]), independently of any running pass
/// or census.
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
            mark_behind_pointer(loaded, pointer.delta_hint());
            return;
        }
    };
    extend_with(source, &manifest, pointer.delta_hint(), my_uid, cfg, loaded).await;
}

/// `current.json` announces deltas up to `hint` and the loaded view has
/// not folded them: the view is known to be incomplete, so its chain is
/// marked broken (coverage incomplete, no pass deletes on it) until an
/// extension catches up.
fn mark_behind_pointer(loaded: &mut LoadedGeneration, hint: u64) {
    let was_broken = loaded.chain_broken_at.is_some();
    if loaded.note_announced(hint) && !was_broken {
        warn!(
            generation = loaded.generation,
            delta_seq = loaded.delta_seq,
            announced = loaded.announced_delta_seq,
            "purge: deltas were announced that the loaded view does not hold: coverage incomplete until they are folded in"
        );
    }
}

/// A pointer for the loaded generation that announces fewer deltas than
/// were already announced (by an earlier pointer or a verified manifest)
/// is a stale or replayed publication: within a generation the delta
/// sequence only grows. `hint == 0` is a pointer that carries no delta
/// information (v0), not a rollback.
fn pointer_is_stale(loaded: &LoadedGeneration, hint: u64) -> bool {
    hint > 0 && hint < loaded.announced_delta_seq
}

/// [`extend_generation`] with the manifest already fetched and verified;
/// `hint` is the delta seq `current.json` announces.
async fn extend_with(
    source: &dyn ListSource,
    manifest: &Manifest,
    hint: u64,
    my_uid: u32,
    cfg: &PurgeConfig,
    loaded: &mut LoadedGeneration,
) {
    if loaded.delta_seq == manifest.declared_delta_seq() && loaded.chain_broken_at.is_none() {
        mark_behind_pointer(loaded, hint);
        return;
    }
    match loaded
        .extend(source, manifest, my_uid, cfg.fetch_concurrency)
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
                    hashes = loaded.total_hashes,
                    snapshot_secs = loaded.snapshot_secs,
                    "purge: generation extended with deltas"
                );
            }
            mark_behind_pointer(loaded, hint);
        }
        Err(e) => {
            warn!(
                generation = loaded.generation,
                error = %format!("{e:#}"),
                "purge: delta extension refused, keeping the loaded view (coverage incomplete)"
            );
            if loaded.chain_broken_at.is_none() {
                loaded.chain_broken_at = Some(loaded.delta_seq + 1);
            }
        }
    }
}

/// Retry pacing of a refresh that left the protected set uncovered (a PG
/// gained whose list failed to load, a delta chain broken by a transient
/// GET failure): first retry after [`REFRESH_RETRY_BASE_SECS`], doubling
/// up to the poll interval, reset once coverage is whole again. The
/// regular poll keeps its own cadence.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RefreshBackoff {
    delay_secs: u64,
    max_secs: u64,
    next_at: Option<tokio::time::Instant>,
}

impl RefreshBackoff {
    pub fn new(max_secs: u64) -> Self {
        Self {
            delay_secs: REFRESH_RETRY_BASE_SECS.min(max_secs.max(1)),
            max_secs: max_secs.max(1),
            next_at: None,
        }
    }

    /// A retry may run at `now` (no failure pending, or its delay spent).
    pub fn due(&self, now: tokio::time::Instant) -> bool {
        self.next_at.is_none_or(|t| now >= t)
    }

    /// The refresh left coverage incomplete: schedule the next retry.
    pub fn failed(&mut self, now: tokio::time::Instant) {
        self.next_at = Some(now + Duration::from_secs(self.delay_secs));
        self.delay_secs = self.delay_secs.saturating_mul(2).min(self.max_secs);
    }

    /// Coverage is whole: forget the failures.
    pub fn reset(&mut self) {
        *self = Self::new(self.max_secs);
    }

    /// Delay the next failure will schedule.
    pub fn next_delay_secs(&self) -> u64 {
        self.delay_secs
    }
}

/// Whether the loop refreshes the lists at this tick: the regular poll is
/// due, or the protected set is not covered (a PG to add, a delta chain
/// broken, no generation) and the backoff allows a retry.
pub fn refresh_due(
    poll_due: bool,
    uncovered: bool,
    backoff: &RefreshBackoff,
    now: tokio::time::Instant,
) -> bool {
    poll_due || (uncovered && backoff.due(now))
}

/// Longest the loop waits for the view's write lock. Readers hold it for
/// one page's in-memory classification or one delete; a delete stuck on
/// the filesystem must not stall the loop, which then skips this step and
/// tries again at the next tick (a pass stuck that way decides nothing
/// else meanwhile, and one resuming re-checks the view it waited for).
const VIEW_WRITE_TIMEOUT: Duration = Duration::from_secs(30);

/// The view's write lock, or `None` (logged) after [`VIEW_WRITE_TIMEOUT`].
async fn write_view(view: &SharedView) -> Option<tokio::sync::RwLockWriteGuard<'_, PurgeView>> {
    match tokio::time::timeout(VIEW_WRITE_TIMEOUT, view.write()).await {
        Ok(guard) => Some(guard),
        Err(_) => {
            warn!(
                waited_secs = VIEW_WRITE_TIMEOUT.as_secs(),
                "purge: the shared view stayed read-locked (a delete stuck on the store?), skipping this step"
            );
            None
        }
    }
}

/// Re-hash the mapped holder set and live filter of the loaded generation
/// against their signed digests (off the runtime, no lock held while
/// hashing). `true` when they match or nothing is mapped. On a mismatch
/// (a cache file modified or truncated after the load) the error is
/// logged and the loaded generation is dropped from the view, if it still
/// holds those sets: coverage is gone until the next refresh reloads it,
/// which finds the damaged cache file, removes it and fetches it again.
/// `false` = no pass now.
async fn verify_mapped_sets(view: &SharedView) -> bool {
    let sets = view
        .read()
        .await
        .loaded
        .as_ref()
        .and_then(|l| l.sets.clone());
    let Some(sets) = sets else {
        return true;
    };
    let hashed = Arc::clone(&sets);
    let outcome = tokio::task::spawn_blocking(move || hashed.verify())
        .await
        .map_err(anyhow::Error::from)
        .and_then(|verified| verified);
    let Err(e) = outcome else {
        return true;
    };
    error!(
        generation = sets.generation(),
        error = %format!("{e:#}"),
        "purge: mapped holder set or live filter no longer matches the signed manifest, coverage dropped until the generation is reloaded"
    );
    if let Some(mut v) = write_view(view).await
        && v.loaded
            .as_ref()
            .and_then(|l| l.sets.as_ref())
            .is_some_and(|current| Arc::ptr_eq(current, &sets))
    {
        v.loaded = None;
    }
    false
}

/// One refresh of the shared view for `protected`, under its write lock
/// (a running pass or census waits between pages; the loop never waits
/// for them longer than [`VIEW_WRITE_TIMEOUT`]). Returns whether the
/// loaded lists cover the protected set.
#[allow(clippy::too_many_arguments)]
async fn refresh_view(
    source: &dyn ListSource,
    validator_node_id: &str,
    view: &SharedView,
    protected: &[u32],
    my_uid: u32,
    cfg: &PurgeConfig,
    now_secs: u64,
    highest_seen: &mut u64,
) -> bool {
    // `current.json` is fetched without any lock, and the common case
    // (nothing new) is decided under a read lock: the write lock is only
    // taken when there is something to fold or load.
    let pointer = match pg_lists::fetch_current(source).await {
        Ok(p) => p,
        Err(e) => {
            warn!(error = %format!("{e:#}"), "purge: current.json unavailable, keeping previous generation");
            let v = view.read().await;
            return v
                .loaded
                .as_ref()
                .is_some_and(|l| covers_protected(l, protected));
        }
    };
    {
        let v = view.read().await;
        if refresh_is_noop(v.loaded.as_ref(), &pointer, protected, *highest_seen) {
            if pointer.generation < *highest_seen {
                warn!(
                    latest = pointer.generation,
                    highest_seen = *highest_seen,
                    "purge: current.json points at an older generation, ignoring"
                );
            }
            return v
                .loaded
                .as_ref()
                .is_some_and(|l| covers_protected(l, protected));
        }
    }
    // Folding deltas or adding PGs mutates the loaded filters in place
    // (they can weigh gigabytes, a copy is not an option), so this holds
    // the write lock across the downloads it needs. A pass waiting on it
    // with a hash lock gives up after `VIEW_READ_TIMEOUT` (blob kept).
    let Some(mut v) = write_view(view).await else {
        return false;
    };
    refresh_generation_at(
        source,
        validator_node_id,
        &pointer,
        protected,
        my_uid,
        cfg,
        now_secs,
        &mut v.loaded,
        highest_seen,
    )
    .await;
    // A watermark write that just failed closes the purge under the same
    // lock the new lists were published under: no pass can decide on
    // them before the fault is visible.
    if WATERMARK_FAULT.load(Ordering::Relaxed) {
        v.state_fault = true;
    }
    v.loaded
        .as_ref()
        .is_some_and(|l| covers_protected(l, protected))
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

/// Left over by an earlier build of this branch (a persisted delta
/// watermark, replaced by the signed freshness gate): removed at start.
const LEFTOVER_DELTA_WATERMARK_FILE: &str = "purge_delta_watermark";

/// Set while the generation watermark could not be read back or written:
/// the purge state on disk is not what the process believes, so no pass
/// deletes ([`PurgeView::state_fault`]) until a write of it succeeds.
static WATERMARK_FAULT: AtomicBool = AtomicBool::new(false);

/// The persisted generation watermark. Missing: 0 (first start). Present
/// but unreadable or malformed: 0 as a starting point, and the fault flag
/// is raised, so the purge stays closed until the watermark is written
/// back successfully (the next generation load).
fn load_watermark() -> u64 {
    let Some(dir) = state::get_data_dir() else {
        return 0;
    };
    match load_watermark_from(dir) {
        Ok(generation) => generation,
        Err(e) => {
            error!(error = %format!("{e:#}"), "purge: generation watermark unreadable, purge closed until it is rewritten");
            WATERMARK_FAULT.store(true, Ordering::Relaxed);
            0
        }
    }
}

/// `Ok(0)` when no watermark was ever written; an error when one exists
/// but cannot be read or parsed (never silently zero).
pub(crate) fn load_watermark_from(data_dir: &std::path::Path) -> Result<u64> {
    let path = data_dir.join(WATERMARK_FILE);
    match std::fs::read_to_string(&path) {
        Ok(text) => text
            .trim()
            .parse::<u64>()
            .map_err(|e| anyhow::anyhow!("{}: {e}", path.display())),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(0),
        Err(e) => Err(anyhow::anyhow!("{}: {e}", path.display())),
    }
}

fn persist_watermark(generation: u64) {
    if let Some(data_dir) = state::get_data_dir() {
        let ok = persist_watermark_to(data_dir, generation);
        WATERMARK_FAULT.store(!ok, Ordering::Relaxed);
    }
}

/// Write the watermark (temp file + rename). `false` on failure (logged
/// at error): the caller closes the purge.
pub(crate) fn persist_watermark_to(data_dir: &std::path::Path, generation: u64) -> bool {
    let path = data_dir.join(WATERMARK_FILE);
    let tmp = path.with_extension("tmp");
    let result =
        std::fs::write(&tmp, generation.to_string()).and_then(|_| std::fs::rename(&tmp, &path));
    match result {
        Ok(()) => true,
        Err(e) => {
            error!(error = %e, path = %path.display(), "purge: cannot persist generation watermark, purge closed until a write succeeds");
            false
        }
    }
}

/// The per-PG ownership window survives restarts in `data_dir`, next to
/// the watermark: a restart must not forget a PG lost an hour ago
/// (clause 4). Same file name as the former whole-set stability state,
/// which is migrated on read ([`OwnershipWindow::decode`]); a binary that
/// predates the window reads the new format as unreadable and restarts
/// its own clock, the safe side.
const OWNERSHIP_FILE: &str = "purge_ownership";

/// The persisted window, or a fresh one tracking from `now_secs` when
/// nothing (readable) is persisted.
pub(crate) fn load_window_from(
    data_dir: Option<&std::path::Path>,
    now_secs: u64,
) -> OwnershipWindow {
    let Some(dir) = data_dir else {
        return OwnershipWindow::new(now_secs);
    };
    let path = dir.join(OWNERSHIP_FILE);
    let text = match std::fs::read_to_string(&path) {
        Ok(t) => t,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            info!("purge: no persisted ownership window, tracking starts now");
            return OwnershipWindow::new(now_secs);
        }
        Err(e) => {
            warn!(error = %e, path = %path.display(), "purge: persisted ownership window unreadable, tracking starts now (a pass waits a full window)");
            return OwnershipWindow::new(now_secs);
        }
    };
    match OwnershipWindow::decode(&text, now_secs) {
        Some((mut w, WindowDecoded::Current)) => {
            if w.has_gap_until(now_secs) {
                warn!(
                    window_pgs = w.len(),
                    last_observed = w.last_observed(),
                    now = now_secs,
                    max_gap_secs = purge::OWNERSHIP_OBSERVATION_GAP_SECS,
                    "purge: ownership window not observed since the last run (downtime or clock step): every PG in it is protected a full window from now, and tracking restarts (no pass for a full window)"
                );
                w.restart_after_gap(now_secs);
            } else {
                info!(
                    window_pgs = w.len(),
                    tracking_since = w.tracking_since(),
                    "purge: ownership window restored"
                );
            }
            w
        }
        Some((w, WindowDecoded::MigratedFromV2)) => {
            warn!(
                window_pgs = w.len(),
                "purge: ownership window of the previous format (no observation time) migrated: its PGs are protected for a full window from now, and a pass waits a full window"
            );
            w
        }
        Some((w, WindowDecoded::MigratedFromV1)) => {
            warn!(
                window_pgs = w.len(),
                "purge: former whole-set ownership state migrated to the per-PG window: its PGs are protected for a full window from now, and a pass waits a full window"
            );
            w
        }
        None => {
            warn!(path = %path.display(), "purge: persisted ownership window malformed, tracking starts now (a pass waits a full window)");
            OwnershipWindow::new(now_secs)
        }
    }
}

/// Write the window (temp file + rename). `false` on failure (logged at
/// error): the caller closes the purge until a write succeeds, since a
/// restart would otherwise forget PGs lost since the last good write.
pub(crate) fn persist_window_to(data_dir: &std::path::Path, w: &OwnershipWindow) -> bool {
    let path = data_dir.join(OWNERSHIP_FILE);
    let tmp = path.with_extension("tmp");
    let result = std::fs::write(&tmp, w.encode()).and_then(|_| std::fs::rename(&tmp, &path));
    match result {
        Ok(()) => true,
        Err(e) => {
            error!(error = %e, path = %path.display(), "purge: cannot persist ownership window, purge closed until a write succeeds");
            false
        }
    }
}

fn publish_generation_metrics(
    loaded: Option<&LoadedGeneration>,
    protected: &[u32],
    moved_class: bool,
    metrics: &PurgeMetrics,
) {
    metrics
        .protected_pgs
        .store(protected.len() as u64, Ordering::Relaxed);
    match loaded {
        Some(l) => {
            metrics.generation.store(l.generation, Ordering::Relaxed);
            metrics
                .filter_hashes
                .store(l.total_hashes, Ordering::Relaxed);
            metrics.filter_bytes.store(
                l.sets.as_ref().map_or(0, |sets| sets.mapped_bytes()),
                Ordering::Relaxed,
            );
            metrics
                .moved_class_enforced
                .store(moved_class && l.sets.is_some(), Ordering::Relaxed);
            metrics
                .tombstone_retained_live_ref
                .store(l.tombstones_retained_live_ref, Ordering::Relaxed);
            let held: HashSet<u32> = l.owned_pgs.iter().copied().collect();
            let missing: HashSet<u32> = l.missing_pgs.iter().copied().collect();
            let required = l.required_pgs(protected);
            let listed = required
                .iter()
                .filter(|pg| held.contains(pg) && !missing.contains(pg))
                .count();
            metrics.set_coverage(required.len() as u64, listed as u64);
            // Every protected PG listed, but the delta chain may not be
            // whole: the gauge is the gate's own reading.
            metrics
                .coverage_complete
                .store(covers_protected(l, protected), Ordering::Relaxed);
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
            metrics
                .tombstone_retained_live_ref
                .store(0, Ordering::Relaxed);
            metrics.set_coverage(protected.len() as u64, 0);
            metrics.coverage_complete.store(false, Ordering::Relaxed);
            metrics.delta_seq.store(0, Ordering::Relaxed);
            metrics.delta_chain_broken.store(false, Ordering::Relaxed);
        }
    }
}

// ============================================================================
// Background work
// ============================================================================

/// What the background task returns.
#[derive(Debug)]
pub enum BackgroundOutcome {
    Pass(PassSummary),
    Census(Census),
}

/// A pass or census running in its own task, so the loop keeps polling
/// the bucket, extending the delta chain and publishing ownership while
/// it runs (a census over an 11 TB store at ~46 blobs/s takes hours).
pub struct Background {
    pub handle: tokio::task::JoinHandle<BackgroundOutcome>,
    /// Asks a census to stop at its next row (a pass stops by itself on a
    /// view that no longer covers the protected set).
    pub cancel: Arc<AtomicBool>,
    pub is_census: bool,
    pub started: tokio::time::Instant,
}

/// Start a dry-run census over `view` in its own task.
pub fn spawn_census(
    store: Arc<dyn BlobStore>,
    env: Arc<dyn PassEnv>,
    view: Arc<SharedView>,
    cfg: PurgeConfig,
    epoch_at_start: u64,
) -> Background {
    let cancel = Arc::new(AtomicBool::new(false));
    let flag = Arc::clone(&cancel);
    let handle = tokio::spawn(async move {
        BackgroundOutcome::Census(
            run_census_on(
                store.as_ref(),
                env.as_ref(),
                &view,
                &cfg,
                epoch_at_start,
                &flag,
            )
            .await,
        )
    });
    Background {
        handle,
        cancel,
        is_census: true,
        started: tokio::time::Instant::now(),
    }
}

/// Start a pass over `view` in its own task, resuming after
/// `start_after` when set.
#[allow(clippy::too_many_arguments)]
pub fn spawn_pass(
    store: Arc<dyn BlobStore>,
    env: Arc<dyn PassEnv>,
    view: Arc<SharedView>,
    gate: PurgeGate,
    cfg: PurgeConfig,
    hard_delete: bool,
    epoch_at_start: u64,
    start_after: Option<String>,
) -> Background {
    let handle = tokio::spawn(async move {
        // Published for the backfill, which waits while a pass deletes.
        let _pass_active = state::mark_purge_pass_active();
        BackgroundOutcome::Pass(
            run_pass_on(
                store.as_ref(),
                env.as_ref(),
                &view,
                gate,
                &cfg,
                hard_delete,
                epoch_at_start,
                start_after,
                metrics(),
            )
            .await,
        )
    });
    Background {
        handle,
        cancel: Arc::new(AtomicBool::new(false)),
        is_census: false,
        started: tokio::time::Instant::now(),
    }
}

fn log_pass(summary: &PassSummary, elapsed_secs: u64) {
    info!(
        elapsed_secs,
        completed = summary.completed,
        aborted = summary.aborted_epoch_change,
        aborted_coverage_lost = summary.aborted_coverage_lost,
        aborted_view_stale = summary.aborted_view_stale,
        refused_filter_generation = summary.refused_filter_generation,
        resume_after = summary.resume_after.as_deref(),
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
        skipped_view_busy = summary.skipped_view_busy,
        invalid_hash = summary.invalid_hash,
        absent_from_store = summary.absent_from_store,
        absent_rows_dropped = summary.absent_rows_dropped,
        vanished = summary.vanished,
        delete_errors = summary.delete_errors,
        deferred_epoch_gate = summary.deferred_epoch_gate,
        "purge: pass finished"
    );
}

// ============================================================================
// Loop
// ============================================================================

/// Why the ownership window was not observed continuously up to a tick.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ObservationBreak {
    /// The wall clock moved differently from the monotonic clock
    /// (`purge::wall_clock_jumped`).
    WallClockJump,
    /// Both clocks moved alike, but the previous observation is older than
    /// `purge::OWNERSHIP_OBSERVATION_GAP_SECS` (a stalled loop). PGs lost
    /// during the stall were last seen owned before it: observed as is,
    /// their window would be shortened by the length of the stall.
    Stall,
}

/// One tick of clause 4: fold `owned` into the window at `now`. If the
/// observation was not continuous since the previous one (a wall-clock
/// jump since `prev_wall`, measured against `mono_elapsed_secs`, or a gap
/// longer than the bound, `OwnershipWindow::has_gap_until`), every PG of
/// the window is first owned until `now` and tracking restarts
/// (`OwnershipWindow::restart_after_gap`), the rule applied at load.
fn observe_ownership(
    window: &mut OwnershipWindow,
    owned: &[u32],
    prev_wall: u64,
    now: u64,
    mono_elapsed_secs: u64,
    window_secs: u64,
) -> (purge::WindowObservation, Option<ObservationBreak>) {
    let observation_break = if purge::wall_clock_jumped(prev_wall, now, mono_elapsed_secs) {
        Some(ObservationBreak::WallClockJump)
    } else if window.has_gap_until(now) {
        Some(ObservationBreak::Stall)
    } else {
        None
    };
    if observation_break.is_some() {
        window.restart_after_gap(now);
    }
    (window.observe(owned, now, window_secs), observation_break)
}

/// The last map the purge ownership was computed on, and that ownership.
type OwnershipCache = Option<(Arc<common::ClusterMap>, Vec<u32>)>;

/// What the ownership observer last published into the view.
#[derive(Debug, Clone, PartialEq, Eq)]
struct OwnershipSnapshot {
    /// Epoch of the map the ownership was computed on.
    epoch: u64,
    /// Number of PGs owned under that map.
    owned_pgs: usize,
    /// Protected set (owned now or within the window), sorted.
    protected: Vec<u32>,
    /// Clause 0 on that map.
    miner_eligible: Result<(), Ineligible>,
    /// The window has been tracked for a full window.
    tracked: bool,
    tracked_for_secs: u64,
}

/// Clause 4 state: the ownership window, its persistence and the clocks
/// of the last observation.
struct OwnershipObserver {
    window: OwnershipWindow,
    window_secs: u64,
    data_dir: Option<std::path::PathBuf>,
    /// Wall and monotonic clocks at the last observation: a wall clock
    /// that moves differently from the monotonic one between two ticks
    /// jumped (`purge::wall_clock_jumped`).
    last_clocks: Option<(u64, tokio::time::Instant)>,
    last_persist_at: u64,
    /// A window write that failed closes the purge until one succeeds.
    window_fault: bool,
    last_logged_owned: Option<(u64, usize, usize)>,
}

impl OwnershipObserver {
    fn new(
        window: OwnershipWindow,
        window_secs: u64,
        data_dir: Option<std::path::PathBuf>,
    ) -> Self {
        Self {
            window,
            window_secs,
            data_dir,
            last_clocks: None,
            last_persist_at: 0,
            window_fault: false,
            last_logged_owned: None,
        }
    }

    /// Fold `ownership` at wall time `now` (monotonic `mono_now`), persist
    /// the window when due, and return what to publish.
    fn observe(
        &mut self,
        ownership: &Ownership,
        now: u64,
        mono_now: tokio::time::Instant,
    ) -> OwnershipSnapshot {
        let window_secs = self.window_secs;
        let (prev_wall, prev_mono) = self.last_clocks.unwrap_or((now, mono_now));
        let mono_elapsed = mono_now.saturating_duration_since(prev_mono).as_secs();
        let previous_observation = self.window.last_observed();
        let (obs, observation_break) = observe_ownership(
            &mut self.window,
            &ownership.pgs,
            prev_wall,
            now,
            mono_elapsed,
            window_secs,
        );
        match observation_break {
            Some(ObservationBreak::WallClockJump) => warn!(
                previous_wall = prev_wall,
                now,
                monotonic_elapsed_secs = mono_elapsed,
                "purge: wall clock jumped between two observations: every PG in the ownership window is protected a full window from now, and tracking restarts"
            ),
            Some(ObservationBreak::Stall) => warn!(
                previous_observation,
                now,
                gap_bound_secs = purge::OWNERSHIP_OBSERVATION_GAP_SECS,
                "purge: ownership not observed for longer than the gap bound (process stalled): every PG in the ownership window is protected a full window from now, and tracking restarts"
            ),
            None => {}
        }
        self.last_clocks = Some((now, mono_now));
        if obs.membership_changed()
            || now.saturating_sub(self.last_persist_at) >= purge::OWNERSHIP_PERSIST_INTERVAL_SECS
        {
            if let Some(dir) = self.data_dir.as_deref() {
                // A write and a rename on the data disk: never on a
                // runtime worker (a saturated disk would stall the timers
                // this observer's own gap rule measures).
                self.window_fault =
                    !crate::helpers::blocking(|| persist_window_to(dir, &self.window));
            }
            self.last_persist_at = now;
        }
        let protected = self.window.protected(now, window_secs);
        let tracked = self.window.is_tracked(now, window_secs);
        metrics()
            .ownership_window_tracked
            .store(tracked, Ordering::Relaxed);
        let epoch = ownership.epoch;
        let owned_pgs = ownership.pgs.len();
        if obs.membership_changed()
            || self.last_logged_owned != Some((epoch, owned_pgs, protected.len()))
        {
            info!(
                epoch,
                owned_pgs,
                protected_pgs = protected.len(),
                gained = obs.gained,
                lost_in_window = obs.lost,
                expired = obs.expired,
                window_secs,
                tracked_secs = self.window.tracked_for_secs(now),
                "purge: owned PGs (v3) and protected set (owned within the window)"
            );
            self.last_logged_owned = Some((epoch, owned_pgs, protected.len()));
        }
        OwnershipSnapshot {
            epoch,
            owned_pgs,
            protected,
            miner_eligible: purge_eligibility(ownership.weight, ownership.unplaceable),
            tracked,
            tracked_for_secs: self.window.tracked_for_secs(now),
        }
    }
}

/// Clause 4 on its own task: every `tick`, compute the ownership, fold it
/// into the window and publish the protected set into the view, then hand
/// the snapshot to the loop. Separate from the loop so that a list refresh
/// (a generation load, a slow delta fold) never delays an observation: the
/// gap rule then only fires when the process itself did not run. Publishing
/// waits for the view's write lock (bounded, `write_view`), the
/// observation and its persistence never do. Ends when the loop is gone.
async fn run_ownership_observer<F, Fut, W>(
    mut observer: OwnershipObserver,
    mut ownership: F,
    wall_now: W,
    view: Arc<SharedView>,
    tick: Duration,
    tx: tokio::sync::watch::Sender<Option<OwnershipSnapshot>>,
) where
    F: FnMut() -> Fut + Send,
    Fut: std::future::Future<Output = Option<Ownership>> + Send,
    W: Fn() -> u64 + Send,
{
    loop {
        tokio::time::sleep(tick).await;
        if tx.is_closed() {
            return;
        }
        let Some(current) = ownership().await else {
            continue;
        };
        let snapshot = observer.observe(&current, wall_now(), tokio::time::Instant::now());
        // Publish before the loop sees it: a running pass must see a PG
        // just gained (coverage then incomplete: it stops) or its uid gone
        // from the map (clause 0: it stops). Until this lands, a pass
        // decides no delete (`delete_gate_open` requires held map ==
        // view). A listed miner with weight 0 owns nothing now and keeps
        // the PGs it lost within the window protected, like any miner.
        {
            let Some(mut v) = write_view(&view).await else {
                continue;
            };
            v.protected = snapshot.protected.clone();
            v.miner_eligible = snapshot.miner_eligible.is_ok();
            v.map_epoch = snapshot.epoch;
            v.state_fault = observer.window_fault || WATERMARK_FAULT.load(Ordering::Relaxed);
            v.ownership_tracked = snapshot.tracked;
        }
        tx.send_replace(Some(snapshot));
    }
}

/// Watches the ownership observer task. Once it has ended (a panic, or a
/// return that should never happen), the protected set it publishes is
/// frozen: the purge fails closed explicitly (view `state_fault`, window
/// untracked, gauge `purge_ownership_observer_down`), logged once at error.
struct ObserverSupervisor {
    task: Option<tokio::task::JoinHandle<()>>,
}

impl ObserverSupervisor {
    fn new(task: tokio::task::JoinHandle<()>) -> Self {
        Self { task: Some(task) }
    }

    /// Whether the observer is still running. When it is not, re-asserts
    /// the fault on the view (a write-lock timeout is retried next tick).
    async fn check(&mut self, view: &SharedView, metrics: &PurgeMetrics) -> bool {
        if let Some(task) = self.task.as_ref() {
            if !task.is_finished() {
                return true;
            }
            let task = self.task.take().expect("checked above");
            match task.await {
                Ok(()) => {
                    error!("purge: the ownership observer task ended, purge closed until restart")
                }
                Err(e) => error!(
                    error = %e,
                    "purge: the ownership observer task failed, purge closed until restart"
                ),
            }
            metrics
                .ownership_observer_down
                .store(true, Ordering::Relaxed);
            metrics
                .ownership_window_tracked
                .store(false, Ordering::Relaxed);
        }
        if let Some(mut v) = write_view(view).await {
            v.state_fault = true;
            v.ownership_tracked = false;
        }
        false
    }
}

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
        error!("purge: PURGE_ENABLED=true but PG_LISTS_BASE_URL is empty, purge stays off");
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
        ownership_window_secs = cfg.ownership_stable_secs,
        moved_class = cfg.moved_class,
        hard_delete = !trash_enabled,
        "purge: enabled"
    );

    let metrics = metrics();
    let env: Arc<dyn PassEnv> = Arc::new(LiveEnv);
    let view: Arc<SharedView> = Arc::new(RwLock::new(PurgeView::default()));
    let window_secs = cfg.ownership_stable_secs;
    let tick = Duration::from_secs(cfg.poll_secs.clamp(1, MAX_TICK_SECS));
    let mut last_pass_at: Option<tokio::time::Instant> = None;
    let mut last_census_at: Option<tokio::time::Instant> = None;
    let mut last_poll_at: Option<tokio::time::Instant> = None;
    let mut backoff = RefreshBackoff::new(cfg.poll_secs);
    let mut background: Option<Background> = None;
    // A pass that stopped early resumes from here, not before this.
    let mut pass_cursor: Option<String> = None;
    let mut pass_resume: Option<tokio::time::Instant> = None;
    let mut highest_generation_seen = crate::helpers::blocking(load_watermark);
    if highest_generation_seen > 0 {
        info!(
            generation = highest_generation_seen,
            "purge: generation watermark restored"
        );
    }
    // Clause 4: per-PG first/last ownership, restored from disk so a
    // restart does not forget a PG lost within the window, observed on
    // its own task.
    let data_dir = state::get_data_dir().map(|d| d.as_path());
    let observer = OwnershipObserver::new(
        crate::helpers::blocking(|| load_window_from(data_dir, common::now_secs())),
        window_secs,
        data_dir.map(std::path::Path::to_path_buf),
    );
    let (ownership_tx, mut ownership_rx) = tokio::sync::watch::channel(None);
    // Ownership computed on the last map seen (recomputed on a new map).
    let ownership_cache: Arc<tokio::sync::Mutex<OwnershipCache>> =
        Arc::new(tokio::sync::Mutex::new(None));
    let mut observer_task = ObserverSupervisor::new(tokio::spawn(run_ownership_observer(
        observer,
        move || {
            let cache = Arc::clone(&ownership_cache);
            async move { purge_owned_pgs(&mut *cache.lock().await).await }
        },
        common::now_secs,
        Arc::clone(&view),
        tick,
        ownership_tx,
    )));
    if let Some(dir) = data_dir {
        match crate::helpers::blocking(|| {
            std::fs::remove_file(dir.join(LEFTOVER_DELTA_WATERMARK_FILE))
        }) {
            Ok(()) => info!("purge: removed the obsolete persisted delta watermark"),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
            Err(e) => {
                warn!(error = %e, "purge: cannot remove the obsolete delta watermark (ignored, never read)")
            }
        }
    }
    let mut last_logged_coverage: Option<(u64, usize, usize, Option<u64>)> = None;
    let mut last_logged_stale: Option<u64> = None;
    let mut last_logged_untracked = false;
    let mut last_logged_view_stale: Option<u64> = None;
    // Clause 0: generation the not-in-map refusal was last logged for.
    let mut last_logged_absent: Option<(u64, Ineligible)> = None;

    loop {
        tokio::time::sleep(tick).await;

        // 1. Collect a finished pass or census.
        if background.as_ref().is_some_and(|b| b.handle.is_finished()) {
            let bg = background.take().expect("checked above");
            let elapsed = bg.started.elapsed().as_secs();
            match bg.handle.await {
                Ok(BackgroundOutcome::Pass(summary)) => {
                    log_pass(&summary, elapsed);
                    if summary.completed {
                        metrics.passes.fetch_add(1, Ordering::Relaxed);
                        last_pass_at = Some(tokio::time::Instant::now());
                        pass_cursor = None;
                        pass_resume = None;
                    } else {
                        // Stopped early: resume from its cursor once the
                        // gate reopens, not after a whole pass interval.
                        pass_cursor = summary.resume_after.clone();
                        pass_resume = Some(
                            tokio::time::Instant::now()
                                + Duration::from_secs(PASS_RESUME_DELAY_SECS),
                        );
                    }
                    if summary.refused_filter_generation {
                        // Forget the generation: the next refresh rebuilds
                        // the filter from the lists.
                        if let Some(mut v) = write_view(&view).await {
                            v.loaded = None;
                        }
                        last_poll_at = None;
                    }
                }
                Ok(BackgroundOutcome::Census(census)) => {
                    // A census that read nothing is retried at the next
                    // tick.
                    let refused = census.refused_filter_generation
                        || (census.aborted_epoch_change && census.examined == 0);
                    if !refused {
                        last_census_at = Some(tokio::time::Instant::now());
                    }
                    info!(elapsed_secs = elapsed, "purge[dry-run]: census finished");
                    log_census(&census, "purge[dry-run]: census");
                    census.publish(metrics, census.complete());
                }
                Err(e) => {
                    error!(error = %e, "purge: background pass or census task failed");
                    pass_resume = Some(
                        tokio::time::Instant::now() + Duration::from_secs(PASS_RESUME_DELAY_SECS),
                    );
                }
            }
        }

        // The observer never ends in normal operation; if it did, the
        // protected set would freeze: the purge is closed for good.
        if !observer_task.check(&view, metrics).await {
            continue;
        }

        // 2. Ownership, as last observed and published into the view by
        // the observer task (`run_ownership_observer`), which ticks on its
        // own so the observation never waits for a list refresh.
        let Some(OwnershipSnapshot {
            epoch,
            owned_pgs,
            protected,
            miner_eligible,
            tracked,
            tracked_for_secs,
        }) = ownership_rx.borrow_and_update().clone()
        else {
            debug!("purge: no cluster map yet");
            continue;
        };
        if let Err(why) = miner_eligible {
            // Clause 0: nothing is refreshed, gated or purged on a map
            // that does not list this uid, or lists it as draining or
            // under a placement hold (a state that lasts until an
            // operator undrains it, not a weight the network assigns).
            match why {
                Ineligible::NotInMap => metrics.refused_not_in_map.fetch_add(1, Ordering::Relaxed),
                Ineligible::NotPlaceable => metrics
                    .refused_not_placeable
                    .fetch_add(1, Ordering::Relaxed),
            };
            let generation = view
                .read()
                .await
                .loaded
                .as_ref()
                .map_or(highest_generation_seen, |c| c.generation);
            if last_logged_absent != Some((generation, why)) {
                warn!(
                    epoch,
                    generation,
                    reason = ?why,
                    "purge: this miner is not in the held map, or is draining or under a placement hold there, refusing to purge anything"
                );
                last_logged_absent = Some((generation, why));
            }
            continue;
        }
        last_logged_absent = None;

        // 3. Lists: regular poll, or a retry with backoff while the
        // protected set is not covered. Never blocked by a pass/census.
        let uncovered = view
            .read()
            .await
            .loaded
            .as_ref()
            .is_none_or(|l| !covers_protected(l, &protected));
        let instant = tokio::time::Instant::now();
        let poll_due = last_poll_at.is_none_or(|t| t.elapsed().as_secs() >= cfg.poll_secs);
        if refresh_due(poll_due, uncovered, &backoff, instant) {
            let covered = refresh_view(
                source.as_ref(),
                &validator_node_id,
                &view,
                &protected,
                state::get_miner_uid(),
                &cfg,
                common::now_secs(),
                &mut highest_generation_seen,
            )
            .await;
            last_poll_at = Some(tokio::time::Instant::now());
            if covered {
                backoff.reset();
            } else {
                backoff.failed(tokio::time::Instant::now());
                debug!(
                    next_retry_secs = backoff.next_delay_secs(),
                    "purge: protected set not covered after refresh, retrying with backoff"
                );
            }
        }

        // 4. Gate.
        let v = view.read().await;
        publish_generation_metrics(v.loaded.as_ref(), &protected, cfg.moved_class, metrics);
        let now = common::now_secs();
        let gate = PurgeGate {
            miner_eligible: miner_eligible.is_ok(),
            generation_loaded: v.loaded.is_some(),
            // A generation ages while loaded: re-evaluated every tick.
            generation_fresh: v.loaded.as_ref().is_some_and(|c| {
                generation_is_fresh(c.created_at_secs, now, cfg.generation_max_age_secs)
            }),
            coverage_complete: v
                .loaded
                .as_ref()
                .is_some_and(|c| covers_protected(c, &protected)),
            ownership_window_tracked: tracked,
        };
        let Some(loaded) = v.loaded.as_ref() else {
            debug!("purge: no generation loaded");
            continue;
        };
        let generation = loaded.generation;
        if !gate.generation_fresh {
            if last_logged_stale != Some(generation) {
                warn!(
                    generation,
                    created_at = loaded.created_at_secs,
                    age_secs = now.saturating_sub(loaded.created_at_secs),
                    max_age_secs = cfg.generation_max_age_secs,
                    "purge: loaded generation is stale, purging nothing until a newer one is published"
                );
                last_logged_stale = Some(generation);
            }
            continue;
        }
        last_logged_stale = None;
        if !gate.coverage_complete {
            let listed = loaded.listed_pgs;
            let key = (generation, listed, protected.len(), loaded.chain_broken_at);
            if last_logged_coverage != Some(key) {
                warn!(
                    generation,
                    listed,
                    protected = protected.len(),
                    loaded_pgs = loaded.owned_pgs.len(),
                    delta_seq = loaded.delta_seq,
                    chain_broken_at = loaded.chain_broken_at,
                    "purge: coverage incomplete for the protected set ({} protected PGs, {} lists loaded), delta chain {}, purging nothing",
                    protected.len(),
                    listed,
                    match loaded.chain_broken_at {
                        Some(seq) => format!("broken at seq {seq}"),
                        None => "whole".to_string(),
                    }
                );
                last_logged_coverage = Some(key);
            }
            // Dry-run only: count what the loaded lists say about the
            // store while the writer is still publishing. Read-only, at
            // the pass cadence, in the background. The real purge keeps
            // refusing above.
            let census_due = cfg.mode.is_census()
                && background.is_none()
                && loaded.listed_pgs > 0
                && inventory::is_ready()
                && last_census_at.is_none_or(|t| t.elapsed().as_secs() >= cfg.pass_interval_secs);
            let covered_pgs = loaded.listed_pgs;
            let missing_pgs = loaded.missing_pgs.len();
            drop(v);
            if census_due {
                info!(
                    generation,
                    epoch,
                    covered_pgs,
                    missing_pgs,
                    "purge[dry-run]: census starting on incomplete coverage (background)"
                );
                background = Some(spawn_census(
                    Arc::clone(&store),
                    Arc::clone(&env),
                    Arc::clone(&view),
                    cfg.clone(),
                    epoch,
                ));
            }
            continue;
        }
        last_logged_coverage = None;
        drop(v);
        // Coverage is complete: a census still running is obsolete, the
        // pass (census-mode in dry-run) takes over.
        if let Some(bg) = background.as_ref()
            && bg.is_census
        {
            bg.cancel.store(true, Ordering::Relaxed);
        }
        if !gate.ownership_window_tracked {
            if !last_logged_untracked {
                info!(
                    tracked_secs = tracked_for_secs,
                    required_secs = window_secs,
                    "purge: ownership window not tracked long enough yet (first start or unreadable state), waiting"
                );
                last_logged_untracked = true;
            }
            continue;
        }
        last_logged_untracked = false;
        if background.is_some() {
            continue;
        }
        {
            let v = view.read().await;
            let now = common::now_secs();
            if v.state_fault || WATERMARK_FAULT.load(Ordering::Relaxed) {
                warn!(
                    "purge: purge state could not be persisted or read back, no pass until a write succeeds"
                );
                continue;
            }
            if let Some(l) = v.loaded.as_ref()
                && !view_is_fresh(l, now, &cfg)
            {
                if last_logged_view_stale != Some(l.view_cut_secs) {
                    warn!(
                        generation = l.generation,
                        view_cut_secs = l.view_cut_secs,
                        lag_secs = now.saturating_sub(l.view_cut_secs),
                        max_lag_secs = cfg.view_max_lag_secs,
                        "purge: the newest signed cut of the loaded lists is older than PURGE_VIEW_MAX_LAG_SECS, no pass until a fresher delta or generation is folded in"
                    );
                    last_logged_view_stale = Some(l.view_cut_secs);
                }
                continue;
            }
        }
        last_logged_view_stale = None;
        if !inventory::is_ready() {
            info!("purge: inventory not reconciled yet, waiting");
            continue;
        }
        if inventory::had_write_failure() {
            warn!("purge: an inventory write failed since startup, purge closed until restart");
            continue;
        }
        let instant = tokio::time::Instant::now();
        if pass_resume.is_some_and(|t| instant < t) {
            continue;
        }
        let resuming = pass_cursor.is_some() || pass_resume.is_some();
        if !resuming && last_pass_at.is_some_and(|t| t.elapsed().as_secs() < cfg.pass_interval_secs)
        {
            continue;
        }
        if !verify_mapped_sets(&view).await {
            continue;
        }
        info!(
            generation,
            epoch,
            owned_pgs,
            protected_pgs = protected.len(),
            mode = ?cfg.mode,
            resume_after = pass_cursor.as_deref(),
            "purge: pass starting (background)"
        );
        background = Some(spawn_pass(
            Arc::clone(&store),
            Arc::clone(&env),
            Arc::clone(&view),
            gate,
            cfg.clone(),
            !trash_enabled,
            epoch,
            pass_cursor.take(),
        ));
        pass_resume = None;
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
        record_held_by, sorted_records, write_generation, write_generation_held,
        write_generation_with_tombstones,
    };
    use std::collections::HashSet;
    use std::sync::Mutex;

    /// The default configuration with a holder set cache of its own (a
    /// test process has no data directory). The directories live under
    /// one process-wide temporary root, removed with the process's tmp.
    fn test_default() -> PurgeConfig {
        static ROOT: std::sync::OnceLock<tempfile::TempDir> = std::sync::OnceLock::new();
        static NEXT: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
        let root = ROOT.get_or_init(|| tempfile::tempdir().unwrap());
        let n = NEXT.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        PurgeConfig {
            lists_cache_dir: Some(root.path().join(format!("cfg-{n}"))),
            ..PurgeConfig::default()
        }
    }

    /// A fresh holder set cache for one load. The directory goes with the
    /// guard (at the end of the calling statement); the mappings made from
    /// it stay valid.
    fn cache_dir() -> tempfile::TempDir {
        tempfile::tempdir().unwrap()
    }

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
        /// One-shot: the heartbeat moves the epoch by this many while the
        /// pass evaluates this hash (before its limiter wait); with the
        /// flag set a `ClusterMapUpdate` moves the held map along with it.
        epoch_bump_at_inflight_check: Mutex<Option<(String, u64, bool)>>,
        /// Epoch of the map the miner holds (moved only by a test).
        map_epoch: std::sync::atomic::AtomicU64,
        /// One-shot: when the pass takes this hash's write lock, the loop
        /// publishes these PGs as protected into this view (a PG gained
        /// while the pass waited on the limiter).
        protect_at_lock: Mutex<Option<ProtectAtLock>>,
        /// Sleep before each inventory page (a slow census).
        page_delay: Option<Duration>,
        /// One-shot: when the pass takes this hash's write lock, a refresh
        /// takes the view's write lock and holds it this long.
        busy_view_at_lock: Mutex<Option<(String, Arc<SharedView>, Duration)>>,
        /// One-shot: when the pass takes this hash's write lock, the view's
        /// newest signed cut becomes ancient (a view gone stale mid-pass).
        age_view_at_lock: Mutex<Option<(String, Arc<SharedView>)>>,
    }

    type ProtectAtLock = (String, Arc<SharedView>, Vec<u32>);

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
                map_epoch: std::sync::atomic::AtomicU64::new(5),
                protect_at_lock: Mutex::new(None),
                page_delay: None,
                busy_view_at_lock: Mutex::new(None),
                age_view_at_lock: Mutex::new(None),
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
            if let Some(delay) = self.page_delay {
                std::thread::sleep(delay);
            }
            let rows = self.rows.lock().unwrap();
            Ok(rows
                .iter()
                .filter(|(h, _)| after.is_none_or(|a| h.as_str() > a))
                .take(limit)
                .cloned()
                .collect())
        }
        fn is_write_inflight(&self, hash_hex: &str) -> bool {
            if let Some((_, by, with_map)) = self
                .epoch_bump_at_inflight_check
                .lock()
                .unwrap()
                .take_if(|(h, _, _)| h == hash_hex)
            {
                let epoch = self.epoch.fetch_add(by, Ordering::Relaxed) + by;
                if with_map {
                    self.map_epoch.store(epoch, Ordering::Relaxed);
                }
            }
            self.inflight.lock().unwrap().contains(hash_hex)
        }
        fn try_lock_write(&self, hash_hex: &str) -> Option<state::HashWriteLock> {
            let protect = self
                .protect_at_lock
                .lock()
                .unwrap()
                .take_if(|(h, _, _)| h == hash_hex);
            let age = self
                .age_view_at_lock
                .lock()
                .unwrap()
                .take_if(|(h, _)| h == hash_hex);
            if let Some((_, view)) = age {
                let mut v = view
                    .try_write()
                    .expect("no view lock is held at try_lock_write");
                if let Some(l) = v.loaded.as_mut() {
                    l.view_cut_secs = 0;
                }
            }
            let busy = self
                .busy_view_at_lock
                .lock()
                .unwrap()
                .take_if(|(h, _, _)| h == hash_hex);
            if let Some((_, view, hold)) = busy {
                let guard = view
                    .try_write_owned()
                    .expect("no view lock is held at try_lock_write");
                tokio::spawn(async move {
                    tokio::time::sleep(hold).await;
                    drop(guard);
                });
            }
            if let Some((_, view, pgs)) = protect {
                let mut v = view
                    .try_write()
                    .expect("no view lock is held at try_lock_write");
                v.protected.extend(pgs);
                v.protected.sort_unstable();
                v.protected.dedup();
            }
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
        fn drop_live_row(&self, hash_hex: &str, stored_at: i64) -> Result<bool> {
            let mut rows = self.rows.lock().unwrap();
            let before = rows.len();
            rows.retain(|(h, at)| !(h == hash_hex && *at == stored_at));
            Ok(rows.len() < before)
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
        async fn map_epoch(&self) -> u64 {
            self.map_epoch.load(Ordering::Relaxed)
        }
        fn now_secs(&self) -> u64 {
            self.now
        }
    }

    const OPEN: PurgeGate = PurgeGate {
        miner_eligible: true,
        generation_loaded: true,
        generation_fresh: true,
        coverage_complete: true,
        ownership_window_tracked: true,
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
            // Fixtures are stamped at a fixed date; the freshness gate has
            // its own tests.
            view_max_lag_secs: u64::MAX,
            ..test_default()
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
            pg_lists::load_generation(&source, &manifest, &[10, 11], MY_UID, 2, cache_dir().path())
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
        // must also miss the holder set and the live filter (a Bloom false
        // positive is a keep): walk the tag until it does.
        let stray = |tag: &str| {
            (0u32..)
                .map(|i| {
                    *blake3::hash(format!("{}/{tag}/{i}", dir.display()).as_bytes()).as_bytes()
                })
                .find(|h| !loaded.may_be_obliged(h) && !loaded.may_be_held_by_other(h))
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

    /// A row whose blob is missing is dropped only on proof of absence,
    /// under the hash lock, and only while unchanged: a trashed copy, a
    /// write in flight, or a write that completed at the lock keep it.
    #[tokio::test]
    async fn absent_blob_row_is_dropped_only_when_provably_gone() {
        let dir = tempfile::tempdir().unwrap();
        let (store, loaded, env, _, _) = scenario(dir.path()).await;
        let now = env.now;
        // Unlisted hashes (a filter hit is a keep and never reaches the
        // store probe), per test as in `scenario`.
        let ghost_of = |tag: &str| {
            (0u32..)
                .map(|i| {
                    *blake3::hash(format!("{}/absent/{tag}/{i}", dir.path().display()).as_bytes())
                        .as_bytes()
                })
                .find(|h| !loaded.may_be_obliged(h) && !loaded.may_be_held_by_other(h))
                .map(hex::encode)
                .unwrap()
        };
        let in_trash = ghost_of("in-trash");
        store.store(&in_trash, b"stray-bytes").await.unwrap();
        store.delete(&in_trash).await.unwrap();
        let starts = ghost_of("writer-starts");
        let completes = ghost_of("writer-completes");
        {
            let mut rows = env.rows.lock().unwrap();
            for h in [&in_trash, &starts, &completes] {
                rows.push((h.clone(), (now - 7200) as i64));
            }
            rows.sort();
        }
        *env.writer_at_lock.lock().unwrap() = Some((starts.clone(), WriterAtLock::Starts));

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
        // Absent: the scenario's ghost and the three here. Dropped: the
        // scenario's ghost and `completes` (nothing armed for it yet).
        assert_eq!(s.absent_from_store, 4, "{s:?}");
        assert_eq!(s.absent_rows_dropped, 2, "{s:?}");
        let has_row = |h: &str| env.rows.lock().unwrap().iter().any(|(r, _)| r == h);
        assert!(has_row(&in_trash), "a trashed copy is not absence");
        assert!(has_row(&starts), "a writer in flight keeps the row");
        assert!(!has_row(&completes));
        assert_eq!(
            metrics.absent_rows_dropped.load(Ordering::Relaxed),
            2,
            "counted in the metrics too"
        );

        // A write that completes as the lock is taken refreshes the row:
        // the paged `stored_at` no longer matches, the row stays.
        env.inflight.lock().unwrap().remove(&starts);
        env.rows
            .lock()
            .unwrap()
            .push((completes.clone(), (now - 7200) as i64));
        env.rows.lock().unwrap().sort();
        *env.writer_at_lock.lock().unwrap() = Some((completes.clone(), WriterAtLock::Completed));
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
        assert!(has_row(&completes), "a refreshed row is kept: {s:?}");
        assert!(!has_row(&starts), "the writer is gone, its absent row goes");
        assert!(has_row(&in_trash));
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
        assert_eq!(s.invalid_hash, 1, "malformed row");
        assert_eq!(s.absent_from_store, 1, "ghost row");
        assert_eq!(
            s.absent_rows_dropped, 1,
            "the ghost's row goes, even in dry-run"
        );
        assert_eq!(s.vanished, 0);
        {
            let rows = env.rows.lock().unwrap();
            assert_eq!(rows.len(), 8, "only the ghost's row goes");
            assert!(
                rows.iter().all(|(h, _)| h.len() != 64 || store.has(h)),
                "every remaining hash row has its blob"
            );
        }
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
        let loaded =
            pg_lists::load_generation(&source, &manifest, &owned, MY_UID, 2, cache_dir().path())
                .await
                .unwrap();
        assert_eq!(loaded.missing_pgs, vec![12, 13]);
        assert_eq!(loaded.listed_pgs, 2);
        assert!(!loaded.coverage_complete());
        assert!(loaded.sets.is_some());

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
        assert_eq!(c.invalid_hash, 1, "malformed");
        assert_eq!(
            (c.absent_from_store, c.absent_rows_dropped),
            (1, 1),
            "ghost"
        );
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
            "purge_census_invalid_hash 1".into(),
            "purge_census_absent_from_store 1".into(),
            "purge_census_absent_rows_dropped 1".into(),
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
                2,
                cache_dir().path(),
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

        // Heartbeat one epoch ahead of the held map, within the grace:
        // orphans could go, the tombstone waits for full agreement (it is
        // exempt from the age clause) and is decided once the map lands.
        let lead_env = Arc::new(FakeEnv::new(env.rows.lock().unwrap().clone(), now));
        lead_env
            .inflight
            .lock()
            .unwrap()
            .insert(hex::encode(tomb_inflight));
        lead_env.epoch.store(6, Ordering::Relaxed);
        let view = view_of(&loaded_with, &loaded_with.owned_pgs);
        let metrics = Arc::new(PurgeMetrics::default());
        let tombstone_before_map = Arc::new(AtomicU64::new(u64::MAX));
        let publisher = {
            let (env, view, metrics, seen) = (
                Arc::clone(&lead_env),
                Arc::clone(&view),
                Arc::clone(&metrics),
                Arc::clone(&tombstone_before_map),
            );
            tokio::spawn(async move {
                tokio::time::sleep(Duration::from_millis(1500)).await;
                seen.store(
                    metrics.tombstone_would_purge.load(Ordering::Relaxed),
                    Ordering::Relaxed,
                );
                env.map_epoch.store(6, Ordering::Relaxed);
                view.write().await.map_epoch = 6;
            })
        };
        let s = run_pass_on(
            &store,
            lead_env.as_ref(),
            &view,
            OPEN,
            &cfg,
            false,
            5,
            None,
            &metrics,
        )
        .await;
        publisher.await.unwrap();
        assert_eq!(
            tombstone_before_map.load(Ordering::Relaxed),
            0,
            "no tombstone applied while the heartbeat led the map"
        );
        assert_eq!(s.tombstone_would_purge, 1, "{s:?}");

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
            pg_lists::load_generation(&source, &manifest, &[10, 11], MY_UID, 2, cache_dir().path())
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
    /// `PURGE_MOVED_CLASS=false` the same blob is an orphan again and goes
    /// — as an orphan, never as a tombstone: the live filter withdrew the
    /// tombstone at load time, independently of the switch.
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
        let with_others =
            pg_lists::load_generation(&source, &manifest, &[10, 11], MY_UID, 2, cache_dir().path())
                .await
                .unwrap();
        assert!(with_others.sets.is_some());
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
                "fixture hash hit the holder set"
            );
        }
        assert!(!with_others.may_be_held_by_other(&orphan));

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

    /// Weight 0 for longer than the ownership window: the miner is in
    /// the map, owns no PG, and every PG it owned has left the window, so
    /// its protected set is empty; the lists name other holders for the
    /// shards it held (the validator moved them), so the holder index
    /// names it nowhere. The loop's refresh loads the generation for zero
    /// PGs (no list downloaded, empty filters, coverage complete) and the
    /// pass follows the same rule as for any miner: old unlisted blobs are
    /// orphans and go, a young blob is kept by the age clause. Fail closed
    /// stays for a uid absent from the map, an untracked window and a
    /// stale signed cut.
    #[tokio::test]
    async fn weight_zero_past_the_window_purges_old_blobs_and_keeps_young_ones() {
        let tmp = tempfile::tempdir().unwrap();
        let dir = tmp.path();
        let key = deterministic_key(3);
        let fx = write_generation_held(&dir.join("bucket"), &key, 9, &[10, 11], 20, &[]);
        let source = DirListSource::new(dir.join("bucket"));
        let cfg = fast_cfg(strongest());
        let now = CREATED_AT_SECS + 3600;
        let view: Arc<SharedView> = Arc::new(RwLock::new(PurgeView {
            protected: Vec::new(),
            miner_eligible: true,
            map_epoch: 5,
            ownership_tracked: true,
            ..PurgeView::default()
        }));
        let mut highest = 0;
        assert!(
            refresh_view(
                &source,
                &fx.validator_hex(),
                &view,
                &[],
                MY_UID,
                &cfg,
                now,
                &mut highest
            )
            .await,
            "an empty protected set is covered by a generation loaded for zero PGs"
        );
        {
            let v = view.read().await;
            let loaded = v.loaded.as_ref().expect("generation kept");
            assert!(loaded.owned_pgs.is_empty());
            assert_eq!((loaded.listed_pgs, loaded.total_hashes), (0, 0));
            assert!(v.enforceable(now, &cfg).is_ok());
        }

        let store = FlatBlobStore::new(dir.join("blobs")).unwrap();
        let mut rows = Vec::new();
        let mut old = Vec::new();
        // Still listed (under another holder): the moved class keeps them,
        // weight 0 or not, since the live filter spans the partition.
        for (pg, i) in [(10u32, 0u32), (10, 7), (11, 19)] {
            let h = hex::encode(hash_for(pg, i));
            store.store(&h, b"was-obliged-long-ago").await.unwrap();
            rows.push((h, 1_000i64));
        }
        // Listed nowhere: orphans.
        for i in 0..3 {
            let h = hex::encode(blake3::hash(format!("weight-zero/old-{i}").as_bytes()).as_bytes());
            store.store(&h, b"unlisted-and-old").await.unwrap();
            rows.push((h.clone(), 1_000i64));
            old.push(h);
        }
        let young = hex::encode(blake3::hash(b"weight-zero/young").as_bytes());
        store.store(&young, b"fresh").await.unwrap();
        rows.push((young.clone(), (now - 60) as i64));
        let metrics = PurgeMetrics::default();

        // Uid absent from the held map: nothing.
        let env = FakeEnv::new(rows.clone(), now);
        view.write().await.miner_eligible = false;
        let absent = PurgeGate {
            miner_eligible: false,
            ..OPEN
        };
        let s = run_pass_on(&store, &env, &view, absent, &cfg, false, 5, None, &metrics).await;
        assert_eq!(s, PassSummary::default(), "{s:?}");
        view.write().await.miner_eligible = true;

        // Window restarted (not tracked yet): nothing.
        let untracked = PurgeGate {
            ownership_window_tracked: false,
            ..OPEN
        };
        let s = run_pass_on(
            &store, &env, &view, untracked, &cfg, false, 5, None, &metrics,
        )
        .await;
        assert_eq!(s, PassSummary::default(), "{s:?}");

        // Signed cut too old: refused even with no list to cover.
        let strict = PurgeConfig {
            view_max_lag_secs: 60,
            ..cfg.clone()
        };
        let late_env = FakeEnv::new(rows.clone(), now + 86_400);
        let s = run_pass_on(
            &store, &late_env, &view, OPEN, &strict, false, 5, None, &metrics,
        )
        .await;
        assert!(s.aborted_view_stale, "{s:?}");
        assert_eq!(s.purged + s.would_purge, 0);

        // Same rule as any miner: the old orphans go, the listed blobs are
        // moved, the young blob stays.
        let s = run_pass_on(&store, &env, &view, OPEN, &cfg, false, 5, None, &metrics).await;
        assert!(s.completed, "{s:?}");
        assert_eq!(s.purged + s.would_purge, 3, "{s:?}");
        assert_eq!(s.kept_moved, 3, "{s:?}");
        assert_eq!(s.skipped_young, 1, "{s:?}");
        #[cfg(feature = "purge-enforce")]
        for h in &old {
            assert!(!store.has(h), "{h} purged");
        }
        let _ = &old;
        assert!(store.has(&young));
    }

    /// A view over `loaded` with the given protected set, current for the
    /// FakeEnv map (epoch 5).
    fn view_of(loaded: &LoadedGeneration, protected: &[u32]) -> Arc<SharedView> {
        Arc::new(RwLock::new(PurgeView {
            loaded: Some(loaded.clone()),
            protected: protected.to_vec(),
            miner_eligible: true,
            map_epoch: 5,
            state_fault: false,
            ownership_tracked: true,
        }))
    }

    /// Ownership flaps 9000 → 0 → 9000 (weight 0 for less than the
    /// window). The miner stays in the map, so the gate stays open, and
    /// the PGs owned before the drop stay in the protected set
    /// throughout: every pass keeps the blobs their lists oblige.
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
            pg_lists::load_generation(&source, &manifest, &[10, 11], MY_UID, 2, cache_dir().path())
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
        let window_secs = cfg.ownership_stable_secs;

        let t0 = 1_000_000u64;
        let mut w = OwnershipWindow::new(t0 - window_secs);
        for (at, observed) in [
            (t0, vec![10u32, 11]),
            (t0 + 30, Vec::new()),
            (t0 + 60, vec![10, 11]),
        ] {
            w.observe(&observed, at, window_secs);
            let protected = w.protected(at, window_secs);
            assert_eq!(protected, vec![10, 11], "at {at}: protected throughout");
            let gate = PurgeGate {
                ownership_window_tracked: w.is_tracked(at, window_secs),
                ..OPEN
            };
            let view = view_of(&loaded, &protected);
            let s = run_pass_on(&store, &env, &view, gate, &cfg, false, 5, None, &metrics).await;
            assert_eq!(s.purged + s.would_purge, 0, "at {at}: {s:?}");
            assert!(s.completed, "at {at} ({} owned): {s:?}", observed.len());
            assert_eq!(s.kept_by_filter, 3);
        }
        for hash in &obliged {
            assert!(store.has(hash));
        }
        assert!(env.trashed.lock().unwrap().is_empty());
    }

    /// A blob of a PG lost five hours ago is still protected: the window
    /// keeps the PG, its list is loaded, the blob is a filter hit. Seven
    /// hours after the loss the PG left the protected set; the loaded
    /// superset still keeps it (a keep; the generation's holder index also
    /// still names this miner there: the shard was not moved yet). Once a
    /// generation names another holder for the PG (the validator moved the
    /// shard) and is loaded for exactly the protected set, the blob is an
    /// orphan like any other.
    #[tokio::test]
    async fn pg_lost_within_the_window_is_protected_and_after_it_is_not() {
        let dir = tempfile::tempdir().unwrap();
        let bucket = dir.path().join("bucket");
        let key = deterministic_key(21);
        let fx = write_generation(&bucket, &key, 9, &[10, 11], 20);
        let source = DirListSource::new(&bucket);
        let cfg = fast_cfg(strongest());
        let window_secs = cfg.ownership_stable_secs;
        assert_eq!(window_secs, 6 * 3600);
        let now = CREATED_AT_SECS + 3600;

        // Owned [10, 11] for a day, PG 11 lost five hours ago.
        let mut w = OwnershipWindow::new(now - 86_400);
        w.observe(&[10, 11], now - 86_400, window_secs);
        w.observe(&[10, 11], now - 5 * 3600, window_secs);
        w.observe(&[10], now - 5 * 3600 + 60, window_secs);
        w.observe(&[10], now, window_secs);
        let protected = w.protected(now, window_secs);
        assert_eq!(protected, vec![10, 11]);
        assert!(w.is_tracked(now, window_secs));

        let view: Arc<SharedView> = Arc::new(RwLock::new(PurgeView {
            protected: protected.clone(),
            miner_eligible: true,
            map_epoch: 5,
            ownership_tracked: true,
            ..PurgeView::default()
        }));
        let mut highest = 0;
        assert!(
            refresh_view(
                &source,
                &fx.validator_hex(),
                &view,
                &protected,
                MY_UID,
                &cfg,
                now,
                &mut highest
            )
            .await,
            "the lists of the lost PG are loaded too"
        );

        let store = FlatBlobStore::new(dir.path().join("blobs")).unwrap();
        let lost_pg_blob = hex::encode(hash_for(11, 3));
        let stray = hex::encode(blake3::hash(b"window-test/stray").as_bytes());
        for h in [&lost_pg_blob, &stray] {
            store.store(h, b"old-bytes").await.unwrap();
        }
        let rows = vec![(lost_pg_blob.clone(), 1_000i64), (stray.clone(), 1_000i64)];
        let metrics = PurgeMetrics::default();
        let env = FakeEnv::new(rows.clone(), now);
        let s = run_pass_on(&store, &env, &view, OPEN, &cfg, false, 5, None, &metrics).await;
        assert!(s.completed, "{s:?}");
        assert_eq!(s.kept_by_filter, 1, "the lost PG's blob is kept: {s:?}");
        #[cfg(feature = "purge-enforce")]
        {
            assert_eq!(s.purged, 1, "{s:?}");
            assert!(!store.has(&stray));
        }
        assert!(store.has(&lost_pg_blob));

        // Seven hours after the loss: out of the window.
        let later = now + 2 * 3600;
        w.observe(&[10], later, window_secs);
        let protected = w.protected(later, window_secs);
        assert_eq!(protected, vec![10]);
        view.write().await.protected = protected.clone();
        let env = FakeEnv::new(rows.clone(), later);
        let s = run_pass_on(&store, &env, &view, OPEN, &cfg, false, 5, None, &metrics).await;
        assert_eq!(
            s.kept_by_filter, 1,
            "the loaded superset still keeps it: {s:?}"
        );
        assert!(store.has(&lost_pg_blob));

        // The next generation names another holder in PG 11 and is loaded
        // for the protected set only.
        write_generation_held(&bucket, &key, 10, &[10, 11], 20, &[10]);
        assert!(
            refresh_view(
                &source,
                &fx.validator_hex(),
                &view,
                &protected,
                MY_UID,
                &cfg,
                later,
                &mut highest
            )
            .await
        );
        assert_eq!(
            view.read().await.loaded.as_ref().unwrap().owned_pgs,
            vec![10]
        );
        let s = run_pass_on(&store, &env, &view, OPEN, &cfg, false, 5, None, &metrics).await;
        assert!(s.completed, "{s:?}");
        assert_eq!(s.kept_by_filter, 0, "{s:?}");
        // The PG left the window, but its blob is still listed under the
        // new holder: the live filter makes it moved, never an orphan.
        assert_eq!(s.kept_moved, 1, "{s:?}");
        assert!(store.has(&lost_pg_blob));
        #[cfg(feature = "purge-enforce")]
        assert_eq!(s.purged, 0, "{s:?}");
        // A census deletes nothing: the stray of the first pass is still
        // there and counted again.
        #[cfg(not(feature = "purge-enforce"))]
        assert_eq!(s.would_purge, 1, "{s:?}");
    }

    /// Observed on a test bench: lists whose holders followed the current
    /// map made placement-epoch holders purge the only copy the gateway
    /// reads first. Miner A holds shard X of PG 11 at the file's placement
    /// epoch; the current map gave PG 11 to miner B. A protects PG 10
    /// only, yet the holder index requires PG 11 and X is A's obligation:
    /// kept, while an old stray blob goes. B protects PG 11: X is listed
    /// there for A, so a copy B already holds is kept by the moved class,
    /// never counted as B's own.
    #[tokio::test]
    async fn placement_epoch_holder_keeps_a_shard_of_a_pg_it_no_longer_owns() {
        const A: u32 = MY_UID;
        const B: u32 = OTHER_UID;
        let dir = tempfile::tempdir().unwrap();
        let bucket = dir.path().join("bucket");
        let key = deterministic_key(40);
        let x = hash_for(11, 2);
        let fx = miner::pg_lists::test_fixtures::write_generation_with(
            &bucket,
            &key,
            9,
            &[10, 11],
            &Stamps::default(),
            &|pg| {
                (0..20)
                    .map(|i| {
                        let holder = if pg == 10 || hash_for(pg, i) == x {
                            A
                        } else {
                            B
                        };
                        record_held_by(pg, i, holder)
                    })
                    .collect()
            },
        );
        let source = DirListSource::new(&bucket);
        let cfg = fast_cfg(strongest());
        let now = CREATED_AT_SECS + 3600;
        let x_hex = hex::encode(x);
        let stray = hex::encode(blake3::hash(b"placement-epoch/stray").as_bytes());

        for (uid, protected, kept_by_filter, kept_moved) in
            [(A, vec![10u32], 1u64, 0u64), (B, vec![11], 0, 1)]
        {
            let view: Arc<SharedView> = Arc::new(RwLock::new(PurgeView {
                protected: protected.clone(),
                miner_eligible: true,
                map_epoch: 5,
                ownership_tracked: true,
                ..PurgeView::default()
            }));
            let mut highest = 0;
            assert!(
                refresh_view(
                    &source,
                    &fx.validator_hex(),
                    &view,
                    &protected,
                    uid,
                    &cfg,
                    now,
                    &mut highest
                )
                .await,
                "uid {uid}: covered, holder index included"
            );
            assert!(view.read().await.enforceable(now, &cfg).is_ok());
            let store = FlatBlobStore::new(dir.path().join(format!("blobs-{uid}"))).unwrap();
            for h in [&x_hex, &stray] {
                store.store(h, b"old-bytes").await.unwrap();
            }
            let env = FakeEnv::new(vec![(x_hex.clone(), 1_000), (stray.clone(), 1_000)], now);
            let metrics = PurgeMetrics::default();
            let s = run_pass_on(&store, &env, &view, OPEN, &cfg, false, 5, None, &metrics).await;
            assert!(s.completed, "uid {uid}: {s:?}");
            assert_eq!(
                (s.kept_by_filter, s.kept_moved),
                (kept_by_filter, kept_moved),
                "uid {uid}: {s:?}"
            );
            assert!(store.has(&x_hex), "uid {uid}: the listed shard is kept");
            #[cfg(feature = "purge-enforce")]
            {
                assert_eq!(s.purged, 1, "uid {uid}: {s:?}");
                assert!(!store.has(&stray));
            }
        }
    }

    /// A generation without a holder index was written by a writer that
    /// placed holders on the current map only: it loads, but it never
    /// covers the protected set, so no pass deletes anything on it.
    #[tokio::test]
    async fn generation_without_holder_index_never_opens_the_gate() {
        let dir = tempfile::tempdir().unwrap();
        let bucket = dir.path().join("bucket");
        let key = deterministic_key(41);
        let fx = miner::pg_lists::test_fixtures::write_generation_stamped(
            &bucket,
            &key,
            9,
            &[10],
            20,
            &miner::pg_lists::test_fixtures::unindexed(),
        );
        let source = DirListSource::new(&bucket);
        let cfg = fast_cfg(strongest());
        let now = CREATED_AT_SECS + 3600;
        let view: Arc<SharedView> = Arc::new(RwLock::new(PurgeView {
            protected: vec![10],
            miner_eligible: true,
            map_epoch: 5,
            ownership_tracked: true,
            ..PurgeView::default()
        }));
        let mut highest = 0;
        assert!(
            !refresh_view(
                &source,
                &fx.validator_hex(),
                &view,
                &[10],
                MY_UID,
                &cfg,
                now,
                &mut highest
            )
            .await
        );
        {
            let v = view.read().await;
            let loaded = v.loaded.as_ref().expect("loaded");
            assert_eq!(loaded.held_pgs, None);
            assert!(!covers_protected(loaded, &[10]));
            assert_eq!(
                v.enforceable(now, &cfg).unwrap_err(),
                ViewRefusal::CoverageIncomplete
            );
        }
        let store = FlatBlobStore::new(dir.path().join("blobs")).unwrap();
        let stray = hex::encode(blake3::hash(b"unindexed/stray").as_bytes());
        store.store(&stray, b"old-bytes").await.unwrap();
        let env = FakeEnv::new(vec![(stray.clone(), 1_000)], now);
        let metrics = PurgeMetrics::default();
        let s = run_pass_on(&store, &env, &view, OPEN, &cfg, false, 5, None, &metrics).await;
        assert!(s.aborted_coverage_lost, "{s:?}");
        assert_eq!((s.examined, s.purged, s.would_purge), (0, 0, 0), "{s:?}");
        assert!(store.has(&stray));
    }

    /// A PG gained is protected at once: until its list is loaded, the
    /// pass refuses before its first page (an old blob of that PG is not
    /// touched); the next refresh adds the PG to the loaded generation in
    /// place. Its list still names the previous holder (files placed at
    /// older epochs), so the blob is then kept by the moved class.
    #[tokio::test]
    async fn pg_gained_is_protected_before_its_list_is_loaded() {
        let dir = tempfile::tempdir().unwrap();
        let bucket = dir.path().join("bucket");
        let key = deterministic_key(22);
        let fx = write_generation_held(&bucket, &key, 9, &[10, 11, 12], 20, &[10, 11]);
        let source = DirListSource::new(&bucket);
        let cfg = fast_cfg(strongest());
        let now = CREATED_AT_SECS + 3600;
        let view: Arc<SharedView> = Arc::new(RwLock::new(PurgeView {
            protected: vec![10, 11],
            miner_eligible: true,
            map_epoch: 5,
            ownership_tracked: true,
            ..PurgeView::default()
        }));
        let mut highest = 0;
        assert!(
            refresh_view(
                &source,
                &fx.validator_hex(),
                &view,
                &[10, 11],
                MY_UID,
                &cfg,
                now,
                &mut highest
            )
            .await
        );
        let store = FlatBlobStore::new(dir.path().join("blobs")).unwrap();
        let gained_blob = hex::encode(hash_for(12, 4));
        let stray = hex::encode(blake3::hash(b"gained-test/stray").as_bytes());
        for h in [&gained_blob, &stray] {
            store.store(h, b"old-bytes").await.unwrap();
        }
        let env = FakeEnv::new(
            vec![(gained_blob.clone(), 1_000), (stray.clone(), 1_000)],
            now,
        );
        let metrics = PurgeMetrics::default();

        // The map moved: PG 12 is owned, protected at once.
        view.write().await.protected = vec![10, 11, 12];
        let s = run_pass_on(&store, &env, &view, OPEN, &cfg, false, 5, None, &metrics).await;
        assert!(s.aborted_coverage_lost, "{s:?}");
        assert_eq!((s.examined, s.purged, s.would_purge), (0, 0, 0), "{s:?}");
        assert!(!s.completed);
        assert!(store.has(&gained_blob) && store.has(&stray));

        // The loop's next refresh adds PG 12 in place.
        assert!(
            refresh_view(
                &source,
                &fx.validator_hex(),
                &view,
                &[10, 11, 12],
                MY_UID,
                &cfg,
                now,
                &mut highest
            )
            .await
        );
        {
            let v = view.read().await;
            let loaded = v.loaded.as_ref().unwrap();
            assert_eq!(loaded.owned_pgs, vec![10, 11, 12]);
            assert_eq!(loaded.listed_pgs, 3);
            let manifest = pg_lists::fetch_manifest(&source, 9, &fx.validator_hex())
                .await
                .unwrap();
            assert!(
                loaded.covers(&manifest, &[10, 11, 12]),
                "same identity as a load of the three PGs"
            );
        }
        let s = run_pass_on(&store, &env, &view, OPEN, &cfg, false, 5, None, &metrics).await;
        assert!(s.completed, "{s:?}");
        assert_eq!((s.kept_by_filter, s.kept_moved), (0, 1), "{s:?}");
        assert!(store.has(&gained_blob));
        #[cfg(feature = "purge-enforce")]
        assert_eq!(s.purged, 1, "{s:?}");
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
                ownership_window_tracked: false,
                ..OPEN
            },
            PurgeGate {
                miner_eligible: false,
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

    /// Heartbeat epoch 5, ownership computed on a map one epoch beyond
    /// the tolerance behind it: the map this miner decides on is not the
    /// one the validator places on. The pass is refused before its first
    /// page, the skew is in the summary, the abort is counted.
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
            5 - (EPOCH_SKEW_TOLERANCE + 1),
            &metrics,
        )
        .await;
        assert!(s.aborted_epoch_change);
        assert_eq!(s.epoch_skew, EPOCH_SKEW_TOLERANCE + 1);
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

    /// The mapped sets carry generation 8 while the enforced generation
    /// is 9 (sets kept across a generation change, or mapped from another
    /// manifest). A miss would delete, so the pass is refused before its
    /// first page, nothing is read or deleted, and the refusal is counted;
    /// the sets' own tag is what decides, not the caller's word.
    #[tokio::test]
    async fn filter_from_another_generation_refuses_the_pass() {
        let dir = tempfile::tempdir().unwrap();
        let (store, mut loaded, env, stray_old, _) = scenario(dir.path()).await;
        assert!(loaded.filter_matches_generation());
        let bucket = dir.path().join("bucket-8");
        let fx = write_generation(&bucket, &deterministic_key(3), 8, &[10, 11], 20);
        let source = DirListSource::new(&bucket);
        let manifest = pg_lists::fetch_manifest(&source, 8, &fx.validator_hex())
            .await
            .unwrap();
        let older =
            pg_lists::load_generation(&source, &manifest, &[10, 11], MY_UID, 2, cache_dir().path())
                .await
                .unwrap();
        let own = std::mem::replace(&mut loaded.sets, older.sets.clone());
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

        // The enforced generation's own sets run.
        loaded.sets = own;
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

    /// Held map (and the view's ownership) at `5 - EPOCH_SKEW_TOLERANCE`,
    /// heartbeat at 5: the case measured on a test bench, pushed maps
    /// trailing the heartbeat ack. The START admits the pass (skew counted
    /// as tolerated), but no delete is decided on that ownership: every
    /// delete waits until the map arrives and the loop publishes it, then
    /// the strays go.
    #[tokio::test]
    async fn start_admits_a_lagging_map_but_deletes_wait_for_it() {
        let dir = tempfile::tempdir().unwrap();
        let (store, loaded, env, stray_old, keep) = scenario(dir.path()).await;
        let lagging = 5 - EPOCH_SKEW_TOLERANCE;
        env.map_epoch.store(lagging, Ordering::Relaxed);
        let view = view_of(&loaded, &loaded.owned_pgs);
        view.write().await.map_epoch = lagging;
        let env = Arc::new(env);
        let metrics = Arc::new(PurgeMetrics::default());
        let decided_before_map = Arc::new(AtomicBool::new(false));
        let publisher = {
            let (env, view, metrics, flag) = (
                Arc::clone(&env),
                Arc::clone(&view),
                Arc::clone(&metrics),
                Arc::clone(&decided_before_map),
            );
            tokio::spawn(async move {
                tokio::time::sleep(Duration::from_millis(1500)).await;
                flag.store(
                    !env.trashed.lock().unwrap().is_empty()
                        || metrics.would_purge.load(Ordering::Relaxed) > 0,
                    Ordering::Relaxed,
                );
                // The map arrives, the loop publishes its ownership.
                env.map_epoch.store(5, Ordering::Relaxed);
                view.write().await.map_epoch = 5;
            })
        };
        let s = run_pass_on(
            &store,
            env.as_ref(),
            &view,
            OPEN,
            &fast_cfg(strongest()),
            false,
            lagging,
            None,
            &metrics,
        )
        .await;
        publisher.await.unwrap();
        assert!(!s.aborted_epoch_change, "{s:?}");
        assert!(s.completed, "{s:?}");
        assert_eq!(s.epoch_skew, EPOCH_SKEW_TOLERANCE);
        assert_eq!(metrics.epoch_skew_tolerated.load(Ordering::Relaxed), 1);
        assert_eq!(metrics.epoch_skew_aborts.load(Ordering::Relaxed), 0);
        assert!(
            !decided_before_map.load(Ordering::Relaxed),
            "no delete decided on a map behind the heartbeat"
        );
        assert_eq!(s.purged + s.would_purge, 2, "{s:?}");
        #[cfg(feature = "purge-enforce")]
        for h in &stray_old {
            assert!(!store.has(h));
        }
        let _ = &stray_old;
        for h in &keep {
            assert!(store.has(h));
        }
    }

    /// THE HAZARD. The heartbeat is two epochs ahead of the held map and
    /// the view; in those epochs this miner was given back PG 12, lost
    /// long ago, whose old bytes are still on its disk (the "strays":
    /// unlisted in the loaded PGs 10/11, older than the age clause). The
    /// validator may already count on them. No delete happens while the
    /// map lags; when it arrives and the loop publishes PG 12 as
    /// protected, coverage is incomplete (its list is not loaded) and the
    /// pass stops: the old bytes survive.
    #[tokio::test]
    async fn pg_regained_during_the_lag_keeps_its_old_bytes() {
        let dir = tempfile::tempdir().unwrap();
        let (store, loaded, env, stray_old, _keep) = scenario(dir.path()).await;
        env.epoch.store(7, Ordering::Relaxed);
        let view = view_of(&loaded, &loaded.owned_pgs);
        let env = Arc::new(env);
        let metrics = Arc::new(PurgeMetrics::default());
        let publisher = {
            let (env, view) = (Arc::clone(&env), Arc::clone(&view));
            tokio::spawn(async move {
                tokio::time::sleep(Duration::from_millis(1500)).await;
                env.map_epoch.store(7, Ordering::Relaxed);
                let mut v = view.write().await;
                v.map_epoch = 7;
                v.protected = vec![10, 11, 12];
            })
        };
        let s = run_pass_on(
            &store,
            env.as_ref(),
            &view,
            OPEN,
            &fast_cfg(strongest()),
            false,
            5,
            None,
            &metrics,
        )
        .await;
        publisher.await.unwrap();
        assert!(s.aborted_coverage_lost, "{s:?}");
        assert_eq!(s.purged + s.would_purge, 0, "{s:?}");
        assert!(env.trashed.lock().unwrap().is_empty());
        for h in &stray_old {
            assert!(store.has(h), "old bytes of the regained PG survive");
        }
    }

    /// One epoch of heartbeat lead is enough for the hazard: in epoch 6,
    /// not yet received, this miner was given back PG 12, whose old bytes
    /// (the strays) are on its disk. Nothing is deleted while the held map
    /// is 5; when map 6 lands with PG 12 protected, the pass stops on
    /// coverage and the old bytes survive.
    #[tokio::test]
    async fn one_epoch_lead_with_a_regained_pg_deletes_nothing() {
        let dir = tempfile::tempdir().unwrap();
        let (store, loaded, env, stray_old, _keep) = scenario(dir.path()).await;
        env.epoch.store(6, Ordering::Relaxed);
        let view = view_of(&loaded, &loaded.owned_pgs);
        let env = Arc::new(env);
        let metrics = Arc::new(PurgeMetrics::default());
        let decided_before_map = Arc::new(AtomicBool::new(false));
        let publisher = {
            let (env, view, metrics, flag) = (
                Arc::clone(&env),
                Arc::clone(&view),
                Arc::clone(&metrics),
                Arc::clone(&decided_before_map),
            );
            tokio::spawn(async move {
                tokio::time::sleep(Duration::from_millis(1500)).await;
                flag.store(
                    !env.trashed.lock().unwrap().is_empty()
                        || metrics.would_purge.load(Ordering::Relaxed) > 0,
                    Ordering::Relaxed,
                );
                env.map_epoch.store(6, Ordering::Relaxed);
                let mut v = view.write().await;
                v.map_epoch = 6;
                v.protected = vec![10, 11, 12];
            })
        };
        let s = run_pass_on(
            &store,
            env.as_ref(),
            &view,
            OPEN,
            &fast_cfg(strongest()),
            false,
            5,
            None,
            &metrics,
        )
        .await;
        publisher.await.unwrap();
        assert!(!decided_before_map.load(Ordering::Relaxed));
        assert!(s.aborted_coverage_lost, "{s:?}");
        assert_eq!(s.purged + s.would_purge, 0, "{s:?}");
        for h in &stray_old {
            assert!(store.has(h), "old bytes of the regained PG survive");
        }
    }

    /// One epoch of heartbeat lead and no ownership change: nothing is
    /// decided until the map lands; then the deletes resume.
    #[tokio::test]
    async fn one_epoch_lead_waits_and_deletes_resume_when_the_map_lands() {
        let dir = tempfile::tempdir().unwrap();
        let (store, loaded, env, stray_old, keep) = scenario(dir.path()).await;
        let first_stray = stray_old.iter().min().unwrap().clone();
        *env.epoch_bump_at_inflight_check.lock().unwrap() = Some((first_stray, 1, false));
        let view = view_of(&loaded, &loaded.owned_pgs);
        let env = Arc::new(env);
        let metrics = Arc::new(PurgeMetrics::default());
        let decided_before_map = Arc::new(AtomicBool::new(false));
        let publisher = {
            let (env, view, metrics, flag) = (
                Arc::clone(&env),
                Arc::clone(&view),
                Arc::clone(&metrics),
                Arc::clone(&decided_before_map),
            );
            tokio::spawn(async move {
                while env.epoch.load(Ordering::Relaxed) != 6 {
                    tokio::time::sleep(Duration::from_millis(20)).await;
                }
                tokio::time::sleep(Duration::from_millis(1500)).await;
                flag.store(
                    !env.trashed.lock().unwrap().is_empty()
                        || metrics.would_purge.load(Ordering::Relaxed) > 0,
                    Ordering::Relaxed,
                );
                env.map_epoch.store(6, Ordering::Relaxed);
                view.write().await.map_epoch = 6;
            })
        };
        let s = run_pass_on(
            &store,
            env.as_ref(),
            &view,
            OPEN,
            &fast_cfg(strongest()),
            false,
            5,
            None,
            &metrics,
        )
        .await;
        publisher.await.unwrap();
        assert!(s.completed, "{s:?}");
        assert!(!decided_before_map.load(Ordering::Relaxed));
        assert_eq!(s.purged + s.would_purge, 2, "{s:?}");
        for h in &keep {
            assert!(store.has(h));
        }
    }

    /// Epochs agree at the start; the heartbeat moves the epoch past the
    /// tolerance while the pass evaluates the first stray (the validator
    /// is several epochs ahead and no map has arrived). An epoch change
    /// does not stop a pass (the protected set keeps every PG owned
    /// within the window), but no delete is decided until a map within
    /// the tolerance is held and its ownership published into the view;
    /// then the strays are decided as usual.
    #[tokio::test]
    async fn epoch_change_mid_pass_is_not_an_abort() {
        let dir = tempfile::tempdir().unwrap();
        let (store, loaded, env, stray_old, keep) = scenario(dir.path()).await;
        let env = Arc::new(env);
        let view = view_of(&loaded, &loaded.owned_pgs);
        let metrics = PurgeMetrics::default();
        let first_stray = stray_old.iter().min().unwrap().clone();
        let bumped = 5 + EPOCH_SKEW_TOLERANCE + 1;
        *env.epoch_bump_at_inflight_check.lock().unwrap() =
            Some((first_stray, EPOCH_SKEW_TOLERANCE + 1, false));
        let deleted_before_publish = Arc::new(AtomicBool::new(false));
        let publisher = {
            let (env, view, flag) = (
                Arc::clone(&env),
                Arc::clone(&view),
                Arc::clone(&deleted_before_publish),
            );
            tokio::spawn(async move {
                while env.epoch.load(Ordering::Relaxed) != bumped {
                    tokio::time::sleep(Duration::from_millis(20)).await;
                }
                tokio::time::sleep(Duration::from_millis(1200)).await;
                flag.store(!env.trashed.lock().unwrap().is_empty(), Ordering::Relaxed);
                // The map arrives, the loop publishes its ownership.
                env.map_epoch.store(bumped, Ordering::Relaxed);
                view.write().await.map_epoch = bumped;
            })
        };
        let s = run_pass_on(
            &store,
            env.as_ref(),
            &view,
            OPEN,
            &fast_cfg(strongest()),
            false,
            5,
            None,
            &metrics,
        )
        .await;
        publisher.await.unwrap();
        assert!(!s.aborted_epoch_change, "{s:?}");
        assert!(!s.aborted_coverage_lost, "{s:?}");
        assert!(s.completed, "{s:?}");
        assert_eq!(env.epoch.load(Ordering::Relaxed), bumped, "the bump fired");
        assert!(
            !deleted_before_publish.load(Ordering::Relaxed),
            "nothing deleted while the view lagged the heartbeat beyond the tolerance"
        );
        assert_eq!(s.purged + s.would_purge, 2, "{s:?}");
        for h in &keep {
            assert!(store.has(h));
        }
    }

    /// Mid-pass, a map beyond the tolerance arrives (the miner jumps
    /// `EPOCH_SKEW_TOLERANCE + 1` epochs) and the loop has not published
    /// its ownership yet (view at 5): the pass waits before deleting, and
    /// proceeds once the view carries the new map.
    #[tokio::test]
    async fn pass_waits_for_the_view_of_a_new_map_before_deleting() {
        let dir = tempfile::tempdir().unwrap();
        let (store, loaded, env, stray_old, _keep) = scenario(dir.path()).await;
        let view = view_of(&loaded, &loaded.owned_pgs);
        // A ClusterMapUpdate moves both the held map and the heartbeat
        // epoch while the pass evaluates the first stray.
        let jumped = 5 + EPOCH_SKEW_TOLERANCE + 1;
        let first_stray = stray_old.iter().min().unwrap().clone();
        *env.epoch_bump_at_inflight_check.lock().unwrap() =
            Some((first_stray, EPOCH_SKEW_TOLERANCE + 1, true));
        let env = Arc::new(env);
        let publisher = {
            let (env, view) = (Arc::clone(&env), Arc::clone(&view));
            tokio::spawn(async move {
                while env.map_epoch.load(Ordering::Relaxed) != jumped {
                    tokio::time::sleep(Duration::from_millis(20)).await;
                }
                tokio::time::sleep(Duration::from_millis(1500)).await;
                view.write().await.map_epoch = jumped;
            })
        };
        let metrics = PurgeMetrics::default();
        let started = tokio::time::Instant::now();
        let s = run_pass_on(
            &store,
            env.as_ref(),
            &view,
            OPEN,
            &fast_cfg(Mode::Census),
            false,
            5,
            None,
            &metrics,
        )
        .await;
        publisher.await.unwrap();
        assert!(s.completed, "{s:?}");
        assert_eq!(s.would_purge, 2, "{s:?}");
        assert!(
            started.elapsed() >= Duration::from_millis(1000),
            "the first delete waited for the view"
        );
    }

    /// The per-delete gate: held map == view map and the heartbeat not
    /// ahead of it; a held map newer than the heartbeat is accepted.
    #[tokio::test]
    async fn delete_gate_table() {
        let env = FakeEnv::new(Vec::new(), 1_000_000);
        let view = PurgeView {
            map_epoch: 5,
            ..PurgeView::default()
        };
        let gate = |held: u64, heartbeat: u64| {
            env.map_epoch.store(held, Ordering::Relaxed);
            env.epoch.store(heartbeat, Ordering::Relaxed);
            delete_gate_open(&view, &env)
        };
        assert!(gate(5, 5).await);
        assert!(gate(5, 4).await, "late heartbeat reply");
        assert!(!gate(5, 6).await, "one epoch of lead");
        assert!(!gate(6, 6).await, "not published");
        assert!(!gate(4, 5).await, "view ahead of the map");
    }

    /// The protected set grows while the pass waits on the limiter (the
    /// loop published a PG gained): the re-check under the lock sees the
    /// coverage gap and the pass stops before any delete, with a resume
    /// cursor, counted.
    #[tokio::test]
    async fn coverage_lost_mid_pass_stops_before_any_delete() {
        let dir = tempfile::tempdir().unwrap();
        let (store, loaded, env, stray_old, keep) = scenario(dir.path()).await;
        let view = view_of(&loaded, &loaded.owned_pgs);
        let first_stray = stray_old.iter().min().unwrap().clone();
        *env.protect_at_lock.lock().unwrap() = Some((first_stray, Arc::clone(&view), vec![12]));
        let metrics = PurgeMetrics::default();
        let s = run_pass_on(
            &store,
            &env,
            &view,
            OPEN,
            &fast_cfg(strongest()),
            false,
            5,
            None,
            &metrics,
        )
        .await;
        assert!(s.aborted_coverage_lost, "{s:?}");
        assert!(!s.completed);
        assert_eq!((s.purged, s.would_purge), (0, 0), "{s:?}");
        assert!(s.examined > 0, "the pass did start");
        assert_eq!(s.resume_after, None, "resume from the first page");
        assert_eq!(metrics.coverage_lost_aborts.load(Ordering::Relaxed), 1);
        assert!(
            metrics
                .render_prometheus()
                .contains("purge_coverage_lost_aborts_total 1\n")
        );
        for h in stray_old.iter().chain(keep.iter()) {
            assert!(store.has(h), "{h} must survive");
        }
        assert!(env.trashed.lock().unwrap().is_empty());
    }

    /// Clause 4 across a restart: the per-PG window is persisted next to
    /// the watermark, so a PG lost before the restart stays protected
    /// after it, and the tracking is not restarted. The former whole-set
    /// state (`v1`) written by an older binary is migrated: its PGs are
    /// protected for a full window from the load and the tracking
    /// restarts, so no pass runs on a window the file cannot vouch for.
    /// A missing or malformed file starts a fresh window, tracked from
    /// the load.
    #[test]
    fn ownership_window_survives_restart_and_migrates_the_old_state() {
        let dir = tempfile::tempdir().unwrap();
        let window = 21_600u64;
        let t0 = 1_700_000_000u64;

        // Nothing persisted: fresh, tracked from now.
        let w = load_window_from(Some(dir.path()), t0);
        assert!(w.is_empty());
        assert_eq!(w.tracking_since(), t0);
        assert_eq!(load_window_from(None, t0).tracking_since(), t0);

        // Process 1 owns [10, 11] then loses 11.
        let mut w = OwnershipWindow::new(t0);
        w.observe(&[10, 11], t0, window);
        w.observe(&[10, 11], t0 + window, window);
        w.observe(&[10], t0 + window + 60, window);
        persist_window_to(dir.path(), &w);

        // Process 2, restarted 30 s later: state kept as is.
        let t2 = t0 + window + 90;
        let mut w2 = load_window_from(Some(dir.path()), t2);
        assert_eq!(w2, w);
        w2.observe(&[10], t2, window);
        assert_eq!(w2.protected(t2, window), vec![10, 11]);
        assert!(w2.is_tracked(t2, window));
        assert_eq!(w2.entry(11), Some((t0, t0 + window)));

        // The old binary's state file.
        std::fs::write(
            dir.path().join(OWNERSHIP_FILE),
            format!("v1 {t0}\n10 11 12\n"),
        )
        .unwrap();
        let t3 = t0 + 10 * window;
        let m = load_window_from(Some(dir.path()), t3);
        assert_eq!(m.owned(), &[10, 11, 12]);
        assert_eq!(m.tracking_since(), t3, "tracking restarts at the migration");
        assert!(!m.is_tracked(t3 + window - 1, window));
        assert_eq!(m.protected(t3 + window, window), vec![10, 11, 12]);
        // Written back in the new format, which the old decoder refuses
        // (an older binary then restarts its own clock: the safe side).
        persist_window_to(dir.path(), &m);
        let text = std::fs::read_to_string(dir.path().join(OWNERSHIP_FILE)).unwrap();
        assert!(text.starts_with("v3 "));
        assert_eq!(load_window_from(Some(dir.path()), t3 + 5), m);

        // Garbage: a fresh window, tracked from the load.
        std::fs::write(dir.path().join(OWNERSHIP_FILE), "not a state").unwrap();
        let g = load_window_from(Some(dir.path()), t3 + 9);
        assert!(g.is_empty());
        assert_eq!(g.tracking_since(), t3 + 9);
    }

    /// Clause 0 on the map entry: listed at any weight (0 included) and
    /// placeable is eligible; absent, draining or under a placement hold
    /// is refused, with its own reason and counter.
    #[test]
    fn clause_zero_refuses_absent_draining_and_held_miners() {
        assert_eq!(purge_eligibility(Some(0), false), Ok(()));
        assert_eq!(purge_eligibility(Some(900), false), Ok(()));
        assert_eq!(purge_eligibility(None, false), Err(Ineligible::NotInMap));
        assert_eq!(
            purge_eligibility(Some(0), true),
            Err(Ineligible::NotPlaceable)
        );
        assert_eq!(
            purge_eligibility(Some(900), true),
            Err(Ineligible::NotPlaceable)
        );
        let m = PurgeMetrics::default();
        m.refused_not_placeable.fetch_add(2, Ordering::Relaxed);
        assert!(
            m.render_prometheus()
                .contains("purge_refused_not_placeable_total 2\n")
        );
    }

    /// Through the real persisted file: a node down 7 h (longer than the
    /// window) comes back with a weight-0 map. Without the gap rule every
    /// PG would have expired and the tracking would already be old enough:
    /// the first pass would purge the whole old store. With it, every PG of
    /// the record is protected a full window from the restart and no pass
    /// runs before a full window of observation. A wall clock that jumps
    /// forward at load is the same case; one that went back restarts the
    /// tracking too; a clean restart 30 s later keeps everything.
    #[tokio::test]
    async fn ownership_window_survives_downtime_and_clock_steps() {
        let window = 21_600u64;
        let t0 = 1_700_000_000u64;
        let persisted = |dir: &std::path::Path| {
            let mut w = OwnershipWindow::new(t0 - 2 * window);
            w.observe(&[10, 11], t0 - 2 * window, window);
            w.observe(&[10, 11], t0, window);
            assert!(persist_window_to(dir, &w));
            w
        };

        // Down 7 h, back at weight 0 (owns nothing).
        let dir = tempfile::tempdir().unwrap();
        persisted(dir.path());
        let back = t0 + 7 * 3600;
        let mut w = load_window_from(Some(dir.path()), back);
        assert_eq!(w.tracking_since(), back, "tracking restarted");
        w.observe(&[], back, window);
        assert_eq!(w.protected(back, window), vec![10, 11]);
        assert_eq!(w.protected(back + window - 1, window), vec![10, 11]);
        assert!(!w.is_tracked(back + window - 1, window));
        // A pass on that state deletes nothing: the gate is closed by the
        // untracked window, whatever the lists say.
        let bucket_dir = tempfile::tempdir().unwrap();
        let (store, loaded, env, stray_old, _) = scenario(bucket_dir.path()).await;
        let gate = PurgeGate {
            ownership_window_tracked: w.is_tracked(back, window),
            ..OPEN
        };
        let view = view_of(&loaded, &w.protected(back, window));
        let metrics = PurgeMetrics::default();
        let s = run_pass_on(
            &store,
            &env,
            &view,
            gate,
            &fast_cfg(strongest()),
            false,
            5,
            None,
            &metrics,
        )
        .await;
        assert_eq!(s, PassSummary::default(), "{s:?}");
        for h in &stray_old {
            assert!(store.has(h));
        }

        // Wall clock jumped forward by 7 h at load: same outcome.
        let dir = tempfile::tempdir().unwrap();
        persisted(dir.path());
        let w = load_window_from(Some(dir.path()), t0 + 7 * 3600);
        assert_eq!(w.tracking_since(), t0 + 7 * 3600);
        assert_eq!(
            w.protected(t0 + 7 * 3600 + window - 1, window),
            vec![10, 11]
        );

        // Wall clock went back an hour: tracking restarts.
        let dir = tempfile::tempdir().unwrap();
        persisted(dir.path());
        let w = load_window_from(Some(dir.path()), t0 - 3600);
        assert_eq!(w.tracking_since(), t0 - 3600);
        assert!(!w.is_tracked(t0 - 3600 + window - 1, window));

        // Clean restart 30 s later: state kept.
        let dir = tempfile::tempdir().unwrap();
        let before = persisted(dir.path());
        let w = load_window_from(Some(dir.path()), t0 + 30);
        assert_eq!(w, before);
        assert!(w.is_tracked(t0 + 30, window));

        // At runtime, only a wall clock moving differently from the
        // monotonic one is a jump; a stalled loop is not.
        assert!(!purge::wall_clock_jumped(t0, t0 + 600, 600));
        assert!(purge::wall_clock_jumped(t0, t0 + 7 * 3600, 10));
        assert!(purge::wall_clock_jumped(t0, t0 - 60, 10));
        assert!(!purge::wall_clock_jumped(t0, t0 + 8, 10));
    }

    /// A loop stalled longer than the gap bound is not a clock jump (both
    /// clocks moved alike), but it is a period in which ownership was not
    /// observed: a PG lost during the stall was last seen owned before it,
    /// and observing it as is would shorten its window by the stall. The
    /// tick applies the load-time gap rule instead: every PG of the window
    /// is owned until now and tracking restarts.
    #[test]
    fn stalled_loop_keeps_pgs_lost_during_the_stall_a_full_window() {
        let window = 21_600u64;
        let t0 = 1_700_000_000u64;
        let start = t0 - 2 * window;
        let mut w = OwnershipWindow::new(start);
        let mut at = start;
        while at <= t0 {
            let (_, brk) =
                observe_ownership(&mut w, &[10, 11], at.saturating_sub(10), at, 10, window);
            assert_eq!(brk, None, "continuous observation at {at}");
            at += 10;
        }
        let last = at - 10;
        assert!(w.is_tracked(last, window));

        // A tick within the bound is continuous.
        let mut quick = w.clone();
        let (_, brk) = observe_ownership(&mut quick, &[10, 11], last, last + 60, 60, window);
        assert_eq!(brk, None);
        assert!(quick.is_tracked(last + 60, window));

        // The loop stalls for longer than the window; PG 11 is lost
        // during the stall. Both clocks moved alike: no jump.
        let stall = window + 1_000;
        let now = last + stall;
        assert!(!purge::wall_clock_jumped(last, now, stall));

        // Observed without the gap rule, PG 11 would already be expired.
        let mut unguarded = w.clone();
        unguarded.observe(&[10], now, window);
        assert_eq!(unguarded.protected(now, window), vec![10]);

        let (_, brk) = observe_ownership(&mut w, &[10], last, now, stall, window);
        assert_eq!(brk, Some(ObservationBreak::Stall));
        assert_eq!(w.protected(now, window), vec![10, 11]);
        assert_eq!(w.protected(now + window - 1, window), vec![10, 11]);
        assert_eq!(w.tracking_since(), now, "tracking restarted");
        assert!(!w.is_tracked(now + window - 1, window));
        assert!(w.is_tracked(now + window, window));

        // A wall-clock jump is still reported as such (not as a stall).
        let mut jumped = quick.clone();
        let (_, brk) = observe_ownership(
            &mut jumped,
            &[10],
            last + 60,
            last + 60 + 7 * 3600,
            10,
            window,
        );
        assert_eq!(brk, Some(ObservationBreak::WallClockJump));
        assert_eq!(jumped.protected(last + 60 + 7 * 3600, window), vec![10, 11]);
    }

    /// A list refresh holds the view's write lock far longer than the gap
    /// bound (a generation load, a slow delta fold). The ownership keeps
    /// being observed on its own task meanwhile: tracking is not
    /// restarted, and a PG lost during the refresh keeps its real
    /// `last_owned_at` (protected the window from then, not from later).
    #[tokio::test(start_paused = true)]
    async fn slow_refresh_does_not_stall_the_ownership_observation() {
        let window_secs = 21_600u64;
        let t0 = 1_700_000_000u64;
        let start = tokio::time::Instant::now();
        let mut window = OwnershipWindow::new(t0 - 2 * window_secs);
        window.observe(&[10, 11], t0, window_secs);
        let observer = OwnershipObserver::new(window, window_secs, None);
        let view: Arc<SharedView> = Arc::new(RwLock::new(PurgeView::default()));
        let (tx, rx) = tokio::sync::watch::channel(None);
        // PG 11 is lost 100 s in, while the refresh holds the view.
        let ownership = move || async move {
            let pgs = if start.elapsed().as_secs() < 100 {
                vec![10, 11]
            } else {
                vec![10]
            };
            Some(Ownership {
                epoch: 7,
                pgs,
                weight: Some(1),
                unplaceable: false,
            })
        };
        let refresh = view.write().await;
        let task = tokio::spawn(run_ownership_observer(
            observer,
            ownership,
            move || t0 + start.elapsed().as_secs(),
            Arc::clone(&view),
            Duration::from_secs(10),
            tx,
        ));
        let bound = purge::OWNERSHIP_OBSERVATION_GAP_SECS;
        tokio::time::sleep(Duration::from_secs(3 * bound)).await;
        drop(refresh);
        tokio::time::sleep(Duration::from_secs(60)).await;

        let now = t0 + start.elapsed().as_secs();
        let snap = rx.borrow().clone().expect("published after the refresh");
        assert!(snap.tracked, "tracking restarted: {snap:?}");
        assert!(
            snap.tracked_for_secs >= 2 * window_secs + 3 * bound,
            "{snap:?}"
        );
        assert_eq!(snap.protected, vec![10, 11]);
        assert_eq!(view.read().await.protected, vec![10, 11]);
        assert_eq!(view.read().await.map_epoch, 7);
        assert!(view.read().await.ownership_tracked);
        assert!(now > t0 + 3 * bound);
        drop(rx);
        tokio::time::sleep(Duration::from_secs(20)).await;
        assert!(task.is_finished(), "the observer ends with the loop");
    }

    /// The observer task dies (panic): the supervisor logs it, raises the
    /// gauge and closes the view explicitly, and keeps it closed.
    #[tokio::test]
    async fn dead_observer_closes_the_purge() {
        let view: SharedView = RwLock::new(PurgeView {
            miner_eligible: true,
            map_epoch: 5,
            ownership_tracked: true,
            ..PurgeView::default()
        });
        let metrics = PurgeMetrics::default();

        let (release, wait) = tokio::sync::oneshot::channel::<()>();
        let task = tokio::spawn(async move {
            let _ = wait.await;
            panic!("observer bug");
        });
        let mut supervisor = ObserverSupervisor::new(task);
        assert!(supervisor.check(&view, &metrics).await, "running");
        assert!(!view.read().await.state_fault);

        release.send(()).unwrap();
        while supervisor.task.as_ref().is_some_and(|t| !t.is_finished()) {
            tokio::task::yield_now().await;
        }
        assert!(!supervisor.check(&view, &metrics).await);
        {
            let v = view.read().await;
            assert!(v.state_fault && !v.ownership_tracked);
            assert_eq!(
                v.enforceable(CREATED_AT_SECS, &fast_cfg(Mode::Census))
                    .err(),
                Some(ViewRefusal::StateFault)
            );
        }
        assert!(metrics.ownership_observer_down.load(Ordering::Relaxed));
        assert!(
            metrics
                .render_prometheus()
                .contains("purge_ownership_observer_down 1\n")
        );
        // Stays closed: a later write clearing the fault is re-asserted.
        view.write().await.state_fault = false;
        assert!(!supervisor.check(&view, &metrics).await);
        assert!(view.read().await.state_fault);
    }

    /// A gap restart while a pass runs: the observer publishes the window
    /// as untracked, and the next delete decision is refused at once.
    #[test]
    fn untracked_window_refuses_every_delete() {
        let view = PurgeView {
            miner_eligible: true,
            map_epoch: 5,
            ownership_tracked: false,
            ..PurgeView::default()
        };
        assert_eq!(
            view.enforceable(CREATED_AT_SECS, &fast_cfg(Mode::Census))
                .err(),
            Some(ViewRefusal::OwnershipUntracked)
        );
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
        *env.epoch_bump_at_inflight_check.lock().unwrap() = Some((first_stray, 1, false));
        let cfg = fast_cfg(Mode::Census);

        let c = run_census(&store, &env, &loaded, &cfg, 5).await;
        assert_eq!(c.epochs_crossed, 1, "{c:?}");
        assert!(!c.aborted_epoch_change, "{c:?}");
        assert!(c.complete(), "{c:?}");
        assert_eq!(c.examined, 9, "every row read past the epoch move: {c:?}");
        assert_eq!(c.protected, 3);
        assert_eq!(c.orphan_gated, 2, "both strays counted: {c:?}");
        assert_eq!(c.orphan_pending, 2, "young + in flight: {c:?}");
        assert_eq!(c.invalid_hash, 1, "malformed");
        assert_eq!(c.absent_from_store, 1, "ghost");
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
            ..Stamps::default()
        };
        let fx = write_generation_stamped(&dir.path().join("bucket"), &key, 9, &[10], 20, &stamps);
        let source = DirListSource::new(dir.path().join("bucket"));
        let manifest = pg_lists::fetch_manifest(&source, 9, &fx.validator_hex())
            .await
            .unwrap();
        let loaded =
            pg_lists::load_generation(&source, &manifest, &[10], MY_UID, 1, cache_dir().path())
                .await
                .unwrap();
        assert_eq!(loaded.snapshot_secs, scan_started);
        let store = FlatBlobStore::new(dir.path().join("blobs")).unwrap();
        let stray = |tag: &str| {
            (0u32..)
                .map(|i| *blake3::hash(format!("{tag}/{i}").as_bytes()).as_bytes())
                .find(|h| !loaded.may_be_obliged(h) && !loaded.may_be_held_by_other(h))
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
        let cfg = test_default();
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
        // Ten days old: fresh only under a longer maximum age (the pass
        // re-checks freshness on the view itself).
        let cfg = PurgeConfig {
            generation_max_age_secs: 30 * 86_400,
            ..fast_cfg(strongest())
        };
        let s = run_pass(&store, &env2, &loaded, OPEN, &cfg, false, 5, &metrics).await;
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
        let cfg = test_default();
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
        publish_generation_metrics(current.as_ref(), &[1, 2], true, metrics);
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
        publish_generation_metrics(current.as_ref(), &[1, 2], true, metrics);
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
        let cfg = test_default();
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

        // The protected set grew (PG 3 gained) and the newer generation
        // is still refused: the previous one is kept, and it does not
        // cover the protected set, so no pass may decide on it.
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
        let kept = current.as_ref().expect("previous generation kept");
        assert_eq!(kept.generation, 9);
        assert!(covers_protected(kept, &[1, 2]));
        assert!(!covers_protected(kept, &[1, 2, 3]));
    }

    /// A cache file damaged after the load (modified in place: the mapping
    /// reads the new bytes) fails the pre-pass verification: the loaded
    /// generation leaves the view (no coverage, no pass) and the next
    /// refresh reloads it, refetching the damaged object.
    #[tokio::test]
    async fn a_cache_file_damaged_after_the_load_drops_coverage_until_reloaded() {
        use miner::pg_lists::test_fixtures::{deterministic_key, write_generation};
        use std::io::{Seek, SeekFrom, Write};
        let dir = tempfile::tempdir().unwrap();
        let key = deterministic_key(4);
        let fx = write_generation(dir.path(), &key, 9, &[1, 2], 5);
        let source = DirListSource::new(dir.path());
        let cfg = test_default();
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
        let loaded = current.take().expect("generation 9 loaded");
        assert!(covers_protected(&loaded, &[1, 2]));
        let view: SharedView = RwLock::new(PurgeView {
            loaded: Some(loaded),
            ..PurgeView::default()
        });
        assert!(verify_mapped_sets(&view).await, "an intact cache verifies");
        assert!(view.read().await.loaded.is_some());

        // One live filter shard and this miner's holder set part damaged
        // in place (same size).
        let gen_dir = cfg.lists_cache_dir.as_ref().unwrap().join("gen-9");
        let holder_part = gen_dir.join(common::hash_set_files::holder_set_path(MY_UID, 0));
        for damaged in [gen_dir.join("live/000.bloom"), holder_part] {
            let mut file = std::fs::OpenOptions::new()
                .write(true)
                .open(&damaged)
                .unwrap();
            let len = file.metadata().unwrap().len();
            file.seek(SeekFrom::Start(len - 1)).unwrap();
            file.write_all(&[0xA5]).unwrap();
            file.sync_all().unwrap();
        }
        assert!(!verify_mapped_sets(&view).await, "the damage is detected");
        let mut current = view.write().await.loaded.take();
        assert!(current.is_none(), "coverage dropped");

        // The next refresh reloads the generation and refetches the
        // damaged objects instead of trusting the cache.
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
        let reloaded = current.expect("generation 9 reloaded");
        assert!(covers_protected(&reloaded, &[1, 2]));
        let sets = reloaded.sets.as_ref().expect("sets mapped again");
        assert_eq!(sets.fetched_objects, 2, "the two damaged objects refetched");
        sets.verify().unwrap();
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
        let cfg = test_default();
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
        assert_eq!(loaded.delta_seq, 1, "the loaded view is kept as is");
        assert_eq!(
            loaded.chain_broken_at,
            Some(2),
            "but a delta it cannot fold is announced: coverage incomplete"
        );
        assert!(!loaded.coverage_complete());
        // A stale or replayed pointer ending at seq 1 again: within a
        // generation the announced sequence only grows, so it is ignored
        // and the view stays incomplete (seq 2 is still owed).
        write_pointer(
            &new_sha,
            serde_json::json!([{ "seq": 1, "cut": cut + 600, "manifest_sha": "ef".repeat(32) }]),
        );
        refresh!();
        let loaded = current.as_ref().unwrap();
        assert_eq!((loaded.delta_seq, loaded.chain_broken_at), (1, Some(2)));
        assert_eq!(loaded.announced_delta_seq, 2);
        assert!(!loaded.coverage_complete());
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
        let cfg = test_default();
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
        let cfg = test_default();
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

    /// A bucket mirror that fails the first fetch of one object (a
    /// transient GET failure), then serves it.
    struct FlakySource {
        inner: DirListSource,
        fail_once: Mutex<Option<String>>,
        failures: AtomicU64,
    }

    #[async_trait::async_trait]
    impl ListSource for FlakySource {
        async fn fetch(&self, rel_path: &str, max_len: u64) -> Result<bytes::Bytes> {
            let fail = self
                .fail_once
                .lock()
                .unwrap()
                .take_if(|p| rel_path == p.as_str())
                .is_some();
            if fail {
                self.failures.fetch_add(1, Ordering::Relaxed);
                anyhow::bail!("{rel_path}: transient GET failure");
            }
            self.inner.fetch(rel_path, max_len).await
        }
    }

    /// One transient GET failure of a delta bundle breaks the chain;
    /// the loop's retry is not tied to the regular poll: it is due after
    /// the backoff delay, and the next refresh folds the delta and
    /// restores coverage (the case observed on a test bench, where the
    /// chain stayed broken for hours because the census blocked the loop).
    #[tokio::test]
    async fn broken_delta_chain_is_retried_with_backoff_and_recovers() {
        use miner::pg_lists::test_fixtures::{append_delta, set_base_cut};
        let dir = tempfile::tempdir().unwrap();
        let key = deterministic_key(31);
        let cut = CREATED_AT_SECS - 300;
        let fx = write_generation(dir.path(), &key, 9, &[1, 2], 5);
        set_base_cut(dir.path(), &key, 9, cut);
        let source = FlakySource {
            inner: DirListSource::new(dir.path()),
            fail_once: Mutex::new(None),
            failures: AtomicU64::new(0),
        };
        let cfg = test_default();
        let view: SharedView = RwLock::new(PurgeView::default());
        let mut highest = 0;
        let now = CREATED_AT_SECS + 60;
        let hex = fx.validator_hex();
        assert!(
            refresh_view(
                &source,
                &hex,
                &view,
                &[1, 2],
                MY_UID,
                &cfg,
                now,
                &mut highest
            )
            .await
        );

        append_delta(dir.path(), &key, 9, 1, cut, cut + 600, &[1, 2], &|pg| {
            vec![record_for(pg, 50)]
        });
        *source.fail_once.lock().unwrap() = Some("delta/9/1/bundle/000.added".to_string());
        let mut backoff = RefreshBackoff::new(cfg.poll_secs);
        let t0 = tokio::time::Instant::now();
        let covered = refresh_view(
            &source,
            &hex,
            &view,
            &[1, 2],
            MY_UID,
            &cfg,
            now,
            &mut highest,
        )
        .await;
        assert!(!covered);
        assert_eq!(source.failures.load(Ordering::Relaxed), 1);
        assert_eq!(
            view.read().await.loaded.as_ref().unwrap().chain_broken_at,
            Some(1)
        );
        backoff.failed(t0);
        // Not before the delay, even though the chain is broken; due after
        // it without waiting for the regular poll.
        assert!(!refresh_due(
            false,
            true,
            &backoff,
            t0 + Duration::from_secs(10)
        ));
        assert!(refresh_due(
            false,
            true,
            &backoff,
            t0 + Duration::from_secs(REFRESH_RETRY_BASE_SECS)
        ));
        assert!(
            refresh_due(true, false, &backoff, t0),
            "the poll keeps its cadence"
        );
        assert!(
            refresh_view(
                &source,
                &hex,
                &view,
                &[1, 2],
                MY_UID,
                &cfg,
                now,
                &mut highest
            )
            .await
        );
        let v = view.read().await;
        let loaded = v.loaded.as_ref().unwrap();
        assert_eq!((loaded.delta_seq, loaded.chain_broken_at), (1, None));
        assert!(loaded.may_be_obliged(&hash_for(1, 50)));
        backoff.reset();
        assert!(backoff.due(t0));
    }

    #[test]
    fn refresh_backoff_doubles_up_to_the_poll_interval() {
        let t0 = tokio::time::Instant::now();
        let mut b = RefreshBackoff::new(600);
        assert!(b.due(t0));
        let mut delays = Vec::new();
        for _ in 0..7 {
            delays.push(b.next_delay_secs());
            b.failed(t0);
        }
        assert_eq!(delays, vec![30, 60, 120, 240, 480, 600, 600]);
        assert!(!b.due(t0 + Duration::from_secs(599)));
        assert!(b.due(t0 + Duration::from_secs(600)));
        b.reset();
        assert_eq!(b.next_delay_secs(), 30);
        // A poll interval below the base caps the first delay too.
        assert_eq!(RefreshBackoff::new(10).next_delay_secs(), 10);
    }

    /// A census running in the background over a slow inventory does not
    /// hold the loop back: while it runs, a delta appended to the bucket
    /// is applied by the loop's refresh (the write lock is taken between
    /// census pages), and the census stops on the loop's cancel.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn census_does_not_starve_list_refresh() {
        use miner::pg_lists::test_fixtures::{append_delta, set_base_cut};
        let dir = tempfile::tempdir().unwrap();
        let bucket = dir.path().join("bucket");
        let key = deterministic_key(32);
        let cut = CREATED_AT_SECS - 300;
        let fx = write_generation(&bucket, &key, 9, &[1, 2], 5);
        set_base_cut(&bucket, &key, 9, cut);
        let source = DirListSource::new(&bucket);
        // PG 3 is protected but not published: coverage incomplete, the
        // dry-run census is what runs.
        let protected = [1u32, 2, 3];
        let cfg = PurgeConfig {
            rate_per_sec: 2,
            ..fast_cfg(Mode::Census)
        };
        let view: Arc<SharedView> = Arc::new(RwLock::new(PurgeView {
            protected: protected.to_vec(),
            miner_eligible: true,
            map_epoch: 5,
            ownership_tracked: true,
            ..PurgeView::default()
        }));
        let now = CREATED_AT_SECS + 60;
        let mut highest = 0;
        let hex = fx.validator_hex();
        assert!(
            !refresh_view(
                &source,
                &hex,
                &view,
                &protected,
                MY_UID,
                &cfg,
                now,
                &mut highest
            )
            .await,
            "PG 3 is not covered"
        );

        let store = Arc::new(FlatBlobStore::new(dir.path().join("blobs")).unwrap());
        let mut rows = Vec::new();
        for i in 0..40u32 {
            let h = hex::encode(blake3::hash(format!("slow-census/{i}").as_bytes()).as_bytes());
            store.store(&h, b"stray").await.unwrap();
            rows.push((h, 1_000i64));
        }
        let mut env = FakeEnv::new(rows, now);
        env.page_delay = Some(Duration::from_millis(50));
        let env: Arc<FakeEnv> = Arc::new(env);
        let bg = spawn_census(
            store.clone() as Arc<dyn BlobStore>,
            env.clone() as Arc<dyn PassEnv>,
            Arc::clone(&view),
            cfg.clone(),
            5,
        );
        tokio::time::sleep(Duration::from_millis(300)).await;
        assert!(
            !bg.handle.is_finished(),
            "40 stats at 2/s: the census runs for ~20 s"
        );

        append_delta(&bucket, &key, 9, 1, cut, cut + 600, &[1, 2], &|pg| {
            vec![record_for(pg, 50)]
        });
        let refreshed = tokio::time::timeout(
            Duration::from_secs(5),
            refresh_view(
                &source,
                &hex,
                &view,
                &protected,
                MY_UID,
                &cfg,
                now,
                &mut highest,
            ),
        )
        .await
        .expect("the refresh is not blocked by the census");
        assert!(!refreshed, "PG 3 is still missing");
        assert_eq!(view.read().await.loaded.as_ref().unwrap().delta_seq, 1);
        assert!(
            !bg.handle.is_finished(),
            "the delta landed while the census ran"
        );

        bg.cancel.store(true, Ordering::Relaxed);
        let outcome = tokio::time::timeout(Duration::from_secs(5), bg.handle)
            .await
            .expect("the census honours the cancel")
            .unwrap();
        match outcome {
            BackgroundOutcome::Census(c) => {
                assert!(c.stopped, "{c:?}");
                assert!(!c.complete());
                assert!(c.examined > 0);
            }
            BackgroundOutcome::Pass(_) => panic!("a census was spawned"),
        }
        for (h, _) in env.rows.lock().unwrap().iter() {
            assert!(store.has(h), "a census deletes nothing");
        }
    }

    /// Adding a gained PG in place fails on a transient GET (the applied
    /// delta's bundle, re-read for the new PG's section; no base list is
    /// fetched any more): nothing is recorded as covered (a pass stays
    /// refused), and the retry adds it without reloading the generation.
    #[tokio::test]
    async fn failed_add_of_a_gained_pg_leaves_it_uncovered_until_the_retry() {
        use miner::pg_lists::test_fixtures::{append_delta, set_base_cut};
        let dir = tempfile::tempdir().unwrap();
        let key = deterministic_key(34);
        let fx = write_generation_held(dir.path(), &key, 9, &[10, 11, 12], 20, &[10, 11]);
        let cut = CREATED_AT_SECS - 300;
        set_base_cut(dir.path(), &key, 9, cut);
        // PG 12's delta record names another holder: the delta's index
        // does not pull PG 12 in, only the gain does.
        append_delta(
            dir.path(),
            &key,
            9,
            1,
            cut,
            cut + 60,
            &[10, 11, 12],
            &|pg| vec![record_held_by(pg, 100, OTHER_UID)],
        );
        let source = FlakySource {
            inner: DirListSource::new(dir.path()),
            fail_once: Mutex::new(None),
            failures: AtomicU64::new(0),
        };
        let cfg = test_default();
        let view: SharedView = RwLock::new(PurgeView::default());
        let now = CREATED_AT_SECS + 60;
        let mut highest = 0;
        let hex = fx.validator_hex();
        assert!(
            refresh_view(
                &source,
                &hex,
                &view,
                &[10, 11],
                MY_UID,
                &cfg,
                now,
                &mut highest
            )
            .await
        );
        {
            let v = view.read().await;
            let loaded = v.loaded.as_ref().unwrap();
            assert_eq!(
                (loaded.owned_pgs.clone(), loaded.delta_seq),
                (vec![10, 11], 1)
            );
            assert!(!loaded.may_be_held_by_other(&hash_for(12, 100)));
        }
        *source.fail_once.lock().unwrap() = Some("delta/9/1/bundle/000.added".to_string());
        assert!(
            !refresh_view(
                &source,
                &hex,
                &view,
                &[10, 11, 12],
                MY_UID,
                &cfg,
                now,
                &mut highest
            )
            .await
        );
        assert_eq!(source.failures.load(Ordering::Relaxed), 1);
        {
            let v = view.read().await;
            let loaded = v.loaded.as_ref().unwrap();
            assert_eq!(
                loaded.owned_pgs,
                vec![10, 11],
                "the failed PG is not recorded"
            );
            assert!(!covers_protected(loaded, &[10, 11, 12]));
        }
        assert!(
            refresh_view(
                &source,
                &hex,
                &view,
                &[10, 11, 12],
                MY_UID,
                &cfg,
                now,
                &mut highest
            )
            .await
        );
        let v = view.read().await;
        let loaded = v.loaded.as_ref().unwrap();
        assert_eq!(loaded.owned_pgs, vec![10, 11, 12]);
        assert!(loaded.may_be_held_by_other(&hash_for(12, 3)), "live filter");
        assert!(
            loaded.may_be_held_by_other(&hash_for(12, 100)),
            "PG 12's delta section folded"
        );
    }

    /// `current.json` announces a delta the loaded view cannot fold (the
    /// manifest re-fetch fails, or the manifest does not chain it yet):
    /// the view is known to be incomplete, so coverage is closed until a
    /// refresh folds the delta.
    #[tokio::test]
    async fn announced_delta_not_folded_closes_coverage() {
        use miner::pg_lists::test_fixtures::{append_delta, set_base_cut};
        let dir = tempfile::tempdir().unwrap();
        let key = deterministic_key(35);
        let cut = CREATED_AT_SECS - 300;
        let fx = write_generation(dir.path(), &key, 9, &[1, 2], 5);
        set_base_cut(dir.path(), &key, 9, cut);
        let source = FlakySource {
            inner: DirListSource::new(dir.path()),
            fail_once: Mutex::new(None),
            failures: AtomicU64::new(0),
        };
        let cfg = test_default();
        let view: SharedView = RwLock::new(PurgeView::default());
        let now = CREATED_AT_SECS + 60;
        let mut highest = 0;
        let hex = fx.validator_hex();
        assert!(
            refresh_view(
                &source,
                &hex,
                &view,
                &[1, 2],
                MY_UID,
                &cfg,
                now,
                &mut highest
            )
            .await
        );

        // The pointer runs ahead of the signed chain.
        std::fs::write(
            dir.path().join("current.json"),
            serde_json::json!({ "generation": 9, "delta_seq": 1 }).to_string(),
        )
        .unwrap();
        assert!(
            !refresh_view(
                &source,
                &hex,
                &view,
                &[1, 2],
                MY_UID,
                &cfg,
                now,
                &mut highest
            )
            .await
        );
        assert_eq!(
            view.read().await.loaded.as_ref().unwrap().chain_broken_at,
            Some(1)
        );

        // The delta is published, but the manifest re-fetch fails once.
        append_delta(dir.path(), &key, 9, 1, cut, cut + 600, &[1, 2], &|pg| {
            vec![record_for(pg, 50)]
        });
        *source.fail_once.lock().unwrap() = Some("gen/9/manifest.json".to_string());
        assert!(
            !refresh_view(
                &source,
                &hex,
                &view,
                &[1, 2],
                MY_UID,
                &cfg,
                now,
                &mut highest
            )
            .await
        );
        assert_eq!(source.failures.load(Ordering::Relaxed), 1);
        // Retry: folded, coverage back.
        assert!(
            refresh_view(
                &source,
                &hex,
                &view,
                &[1, 2],
                MY_UID,
                &cfg,
                now,
                &mut highest
            )
            .await
        );
        let v = view.read().await;
        let loaded = v.loaded.as_ref().unwrap();
        assert_eq!((loaded.delta_seq, loaded.chain_broken_at), (1, None));
    }

    /// Same with a loaded set more than twice the protected one (the
    /// reload branch): a failed reload leaves the announced delta
    /// unfolded, and the view is not enforceable; the retry reloads for
    /// exactly the protected set, delta included.
    #[tokio::test]
    async fn announced_delta_not_folded_on_the_reload_branch_closes_coverage() {
        use miner::pg_lists::test_fixtures::{append_delta, set_base_cut};
        let dir = tempfile::tempdir().unwrap();
        let key = deterministic_key(36);
        let cut = CREATED_AT_SECS - 300;
        let fx = write_generation_held(dir.path(), &key, 9, &[1, 2, 3, 4], 5, &[1]);
        set_base_cut(dir.path(), &key, 9, cut);
        let source = FlakySource {
            inner: DirListSource::new(dir.path()),
            fail_once: Mutex::new(None),
            failures: AtomicU64::new(0),
        };
        let cfg = test_default();
        let view: SharedView = RwLock::new(PurgeView::default());
        let now = CREATED_AT_SECS + 60;
        let mut highest = 0;
        let hex = fx.validator_hex();
        assert!(
            refresh_view(
                &source,
                &hex,
                &view,
                &[1, 2, 3, 4],
                MY_UID,
                &cfg,
                now,
                &mut highest
            )
            .await
        );
        append_delta(
            dir.path(),
            &key,
            9,
            1,
            cut,
            cut + 600,
            &[1, 2, 3, 4],
            &|pg| {
                if pg == 1 {
                    vec![record_for(pg, 50)]
                } else {
                    vec![record_held_by(pg, 50, OTHER_UID)]
                }
            },
        );
        *source.fail_once.lock().unwrap() = Some("gen/9/manifest.json".to_string());
        assert!(!refresh_view(&source, &hex, &view, &[1], MY_UID, &cfg, now, &mut highest).await);
        {
            let v = view.read().await;
            let loaded = v.loaded.as_ref().unwrap();
            assert_eq!(loaded.owned_pgs, vec![1, 2, 3, 4], "previous view kept");
            assert_eq!(loaded.chain_broken_at, Some(1));
            assert!(!covers_protected(loaded, &[1]));
        }
        assert!(refresh_view(&source, &hex, &view, &[1], MY_UID, &cfg, now, &mut highest).await);
        let v = view.read().await;
        let loaded = v.loaded.as_ref().unwrap();
        assert_eq!(loaded.owned_pgs, vec![1]);
        assert_eq!((loaded.delta_seq, loaded.chain_broken_at), (1, None));
        assert!(loaded.may_be_obliged(&hash_for(1, 50)));
    }

    /// Within one generation the announced delta sequence only grows.
    /// Seq 2 is announced but cannot be fetched; a replayed base manifest
    /// that stops at seq 1 (with a pointer carrying no delta information)
    /// or a replayed pointer ending at seq 1 never makes the view whole:
    /// coverage stays closed until seq 2 is folded.
    #[tokio::test]
    async fn same_generation_delta_rollback_never_restores_coverage() {
        use miner::pg_lists::test_fixtures::{append_delta, rewrite_base_manifest, set_base_cut};
        let dir = tempfile::tempdir().unwrap();
        let key = deterministic_key(37);
        let cut = CREATED_AT_SECS - 300;
        let fx = write_generation(dir.path(), &key, 9, &[1, 2], 5);
        set_base_cut(dir.path(), &key, 9, cut);
        let source = FlakySource {
            inner: DirListSource::new(dir.path()),
            fail_once: Mutex::new(None),
            failures: AtomicU64::new(0),
        };
        let cfg = test_default();
        let view: SharedView = RwLock::new(PurgeView::default());
        let now = CREATED_AT_SECS + 60;
        let mut highest = 0;
        let hex = fx.validator_hex();
        assert!(
            refresh_view(
                &source,
                &hex,
                &view,
                &[1, 2],
                MY_UID,
                &cfg,
                now,
                &mut highest
            )
            .await
        );
        append_delta(dir.path(), &key, 9, 1, cut, cut + 600, &[1, 2], &|pg| {
            vec![record_for(pg, 50)]
        });
        append_delta(
            dir.path(),
            &key,
            9,
            2,
            cut + 600,
            cut + 1200,
            &[1, 2],
            &|pg| vec![record_for(pg, 60)],
        );
        *source.fail_once.lock().unwrap() = Some("delta/9/2/manifest.json".to_string());
        assert!(
            !refresh_view(
                &source,
                &hex,
                &view,
                &[1, 2],
                MY_UID,
                &cfg,
                now,
                &mut highest
            )
            .await
        );
        {
            let v = view.read().await;
            let l = v.loaded.as_ref().unwrap();
            assert_eq!(
                (l.delta_seq, l.chain_broken_at, l.announced_delta_seq),
                (1, Some(2), 2)
            );
        }

        // Replayed base manifest (seq 2 dropped from the chain) behind a
        // pointer without delta information.
        let body = std::fs::read(
            dir.path()
                .join(miner::pg_lists::DeltaManifest::manifest_path(9, 2)),
        )
        .unwrap();
        rewrite_base_manifest(dir.path(), &key, 9, &|v| {
            v["deltas"].as_array_mut().unwrap().pop();
        });
        std::fs::write(
            dir.path().join("current.json"),
            serde_json::json!({ "generation": 9 }).to_string(),
        )
        .unwrap();
        assert!(
            !refresh_view(
                &source,
                &hex,
                &view,
                &[1, 2],
                MY_UID,
                &cfg,
                now,
                &mut highest
            )
            .await
        );
        assert_eq!(
            view.read().await.loaded.as_ref().unwrap().chain_broken_at,
            Some(2),
            "a manifest declaring fewer deltas than announced is stale"
        );
        // Replayed pointer ending at seq 1: ignored.
        std::fs::write(
            dir.path().join("current.json"),
            serde_json::json!({ "generation": 9, "delta_seq": 1 }).to_string(),
        )
        .unwrap();
        assert!(
            !refresh_view(
                &source,
                &hex,
                &view,
                &[1, 2],
                MY_UID,
                &cfg,
                now,
                &mut highest
            )
            .await
        );
        {
            let v = view.read().await;
            let l = v.loaded.as_ref().unwrap();
            assert_eq!((l.delta_seq, l.chain_broken_at), (1, Some(2)));
            assert!(!covers_protected(l, &[1, 2]));
        }

        // The real chain is back: seq 2 folds, coverage returns.
        let sha = hex::encode(<sha2::Sha256 as sha2::Digest>::digest(&body));
        rewrite_base_manifest(dir.path(), &key, 9, &|v| {
            v["deltas"].as_array_mut().unwrap().push(serde_json::json!({
                "seq": 2, "since": cut + 600, "until": cut + 1200,
                "sha256": sha, "size": body.len(),
            }));
        });
        std::fs::write(
            dir.path().join("current.json"),
            serde_json::json!({ "generation": 9, "delta_seq": 2 }).to_string(),
        )
        .unwrap();
        assert!(
            refresh_view(
                &source,
                &hex,
                &view,
                &[1, 2],
                MY_UID,
                &cfg,
                now,
                &mut highest
            )
            .await
        );
        let v = view.read().await;
        let l = v.loaded.as_ref().unwrap();
        assert_eq!((l.delta_seq, l.chain_broken_at), (2, None));
        assert!(l.may_be_obliged(&hash_for(2, 60)));
    }

    /// A refresh holds the view's write lock across downloads while the
    /// pass holds a blob's hash lock: the pass waits at most
    /// `VIEW_READ_TIMEOUT` for the view, then keeps the blob and releases
    /// the hash lock, so a Store of that hash waiting on it proceeds.
    #[tokio::test]
    async fn pass_gives_up_on_a_busy_view_and_releases_the_hash_lock() {
        let dir = tempfile::tempdir().unwrap();
        let (store, loaded, env, stray_old, keep) = scenario(dir.path()).await;
        let view = view_of(&loaded, &loaded.owned_pgs);
        let first_stray = stray_old.iter().min().unwrap().clone();
        *env.busy_view_at_lock.lock().unwrap() = Some((
            first_stray.clone(),
            Arc::clone(&view),
            VIEW_READ_TIMEOUT * 2 + Duration::from_secs(2),
        ));
        // A Store of the first stray arrives while the pass holds its lock.
        let writer = {
            let hash = first_stray.clone();
            tokio::spawn(async move {
                while !state::is_write_inflight(&hash) {
                    tokio::time::sleep(Duration::from_millis(5)).await;
                }
                let started = tokio::time::Instant::now();
                let lock = tokio::time::timeout(
                    VIEW_READ_TIMEOUT + Duration::from_secs(3),
                    state::lock_hash_write(&hash),
                )
                .await
                .expect("the writer gets the hash lock once the pass gives up");
                drop(lock);
                started.elapsed()
            })
        };
        let metrics = PurgeMetrics::default();
        let s = run_pass_on(
            &store,
            &env,
            &view,
            OPEN,
            &fast_cfg(strongest()),
            false,
            5,
            None,
            &metrics,
        )
        .await;
        let waited = writer.await.unwrap();
        assert!(
            waited <= VIEW_READ_TIMEOUT + Duration::from_secs(1),
            "{waited:?}"
        );
        assert!(s.completed, "{s:?}");
        assert_eq!(s.skipped_view_busy, 2, "both strays kept: {s:?}");
        assert_eq!((s.purged, s.would_purge), (0, 0), "{s:?}");
        assert_eq!(metrics.skipped_view_busy.load(Ordering::Relaxed), 2);
        for h in stray_old.iter().chain(keep.iter()) {
            assert!(store.has(h), "{h} kept");
        }
        assert!(state::try_lock_hash_write(&first_stray).is_some());
    }

    /// A view whose newest signed cut is older than
    /// `PURGE_VIEW_MAX_LAG_SECS` deletes nothing (refused at the start);
    /// exactly at the bound it runs.
    #[tokio::test]
    async fn stale_view_is_refused_and_fresh_view_runs() {
        let dir = tempfile::tempdir().unwrap();
        let (store, loaded, env, stray_old, _keep) = scenario(dir.path()).await;
        assert_eq!(
            loaded.view_cut_secs, CREATED_AT_SECS,
            "no base_cut: the snapshot"
        );
        let rows = env.rows.lock().unwrap().clone();
        let inflight = env.inflight.lock().unwrap().clone();
        let cfg = PurgeConfig {
            view_max_lag_secs: 7_200,
            ..fast_cfg(strongest())
        };
        let at = |now: u64| {
            let e = FakeEnv::new(rows.clone(), now);
            *e.inflight.lock().unwrap() = inflight.clone();
            e
        };
        let metrics = PurgeMetrics::default();
        let stale = at(CREATED_AT_SECS + 7_201);
        let s = run_pass(&store, &stale, &loaded, OPEN, &cfg, false, 5, &metrics).await;
        assert!(s.aborted_view_stale, "{s:?}");
        assert_eq!((s.examined, s.purged, s.would_purge), (0, 0, 0));
        assert_eq!(metrics.view_stale_refusals.load(Ordering::Relaxed), 1);
        assert!(
            metrics
                .render_prometheus()
                .contains("purge_view_stale_refusals_total 1\n")
        );
        for h in &stray_old {
            assert!(store.has(h));
        }
        let fresh = at(CREATED_AT_SECS + 7_200);
        let s = run_pass(&store, &fresh, &loaded, OPEN, &cfg, false, 5, &metrics).await;
        assert!(!s.aborted_view_stale && s.completed, "{s:?}");
        // The scenario's "young" stray is old at this clock: three strays.
        assert_eq!(s.purged + s.would_purge, 3, "{s:?}");
    }

    /// The view goes stale while the pass waits on the limiter: the
    /// re-check before the delete refuses it, nothing is deleted.
    #[tokio::test]
    async fn view_going_stale_mid_pass_stops_before_any_delete() {
        let dir = tempfile::tempdir().unwrap();
        let (store, loaded, env, stray_old, keep) = scenario(dir.path()).await;
        let view = view_of(&loaded, &loaded.owned_pgs);
        let first_stray = stray_old.iter().min().unwrap().clone();
        *env.age_view_at_lock.lock().unwrap() = Some((first_stray, Arc::clone(&view)));
        let cfg = PurgeConfig {
            view_max_lag_secs: 7_200,
            ..fast_cfg(strongest())
        };
        let metrics = PurgeMetrics::default();
        let s = run_pass_on(&store, &env, &view, OPEN, &cfg, false, 5, None, &metrics).await;
        assert!(s.aborted_view_stale, "{s:?}");
        assert!(s.examined > 0, "the pass did start");
        assert_eq!((s.purged, s.would_purge), (0, 0), "{s:?}");
        for h in stray_old.iter().chain(keep.iter()) {
            assert!(store.has(h));
        }
    }

    /// After a restart the in-memory delta high-water is gone. A replayed
    /// pointer and manifest that stop at an old delta load as a complete
    /// view, but its newest signed cut is old: the freshness gate refuses
    /// it, while the same view within the lag bound would run. The cut is
    /// the signed delta's `until`, not anything from `current.json`.
    #[tokio::test]
    async fn restart_with_a_replayed_stale_pointer_is_refused_by_freshness() {
        use miner::pg_lists::test_fixtures::{append_delta, set_base_cut};
        let dir = tempfile::tempdir().unwrap();
        let bucket = dir.path().join("bucket");
        let key = deterministic_key(39);
        let cut = CREATED_AT_SECS - 300;
        let fx = write_generation(&bucket, &key, 9, &[10, 11], 20);
        set_base_cut(&bucket, &key, 9, cut);
        append_delta(&bucket, &key, 9, 1, cut, cut + 600, &[10, 11], &|pg| {
            vec![record_for(pg, 50)]
        });
        // A fresh process: nothing in memory, the bucket replays seq 1.
        let cfg = PurgeConfig {
            view_max_lag_secs: 7_200,
            ..fast_cfg(strongest())
        };
        let view: Arc<SharedView> = Arc::new(RwLock::new(PurgeView {
            protected: vec![10, 11],
            miner_eligible: true,
            map_epoch: 5,
            ownership_tracked: true,
            ..PurgeView::default()
        }));
        let mut highest = 0;
        let late = cut + 600 + 7_201;
        assert!(
            refresh_view(
                &DirListSource::new(&bucket),
                &fx.validator_hex(),
                &view,
                &[10, 11],
                MY_UID,
                &cfg,
                late,
                &mut highest
            )
            .await,
            "the replayed chain looks complete"
        );
        assert_eq!(
            view.read().await.loaded.as_ref().unwrap().view_cut_secs,
            cut + 600
        );
        let store = FlatBlobStore::new(dir.path().join("blobs")).unwrap();
        let stray = hex::encode(blake3::hash(b"replay-test/stray").as_bytes());
        store.store(&stray, b"old").await.unwrap();
        let rows = vec![(stray.clone(), 1_000i64)];
        let metrics = PurgeMetrics::default();
        let s = run_pass_on(
            &store,
            &FakeEnv::new(rows.clone(), late),
            &view,
            OPEN,
            &cfg,
            false,
            5,
            None,
            &metrics,
        )
        .await;
        assert!(s.aborted_view_stale, "{s:?}");
        assert!(store.has(&stray));
        // The same view within the bound is an ordinary (lagging) view.
        let s = run_pass_on(
            &store,
            &FakeEnv::new(rows, cut + 600 + 3_600),
            &view,
            OPEN,
            &cfg,
            false,
            5,
            None,
            &metrics,
        )
        .await;
        assert!(s.completed, "{s:?}");
        assert_eq!(s.purged + s.would_purge, 1, "{s:?}");
    }

    /// Purge state that cannot be read back or written closes the purge:
    /// a malformed watermark is an error (never a silent zero), a failed
    /// write reports failure, and a view carrying the fault deletes
    /// nothing.
    #[tokio::test]
    async fn purge_state_faults_fail_closed() {
        let dir = tempfile::tempdir().unwrap();
        assert_eq!(load_watermark_from(dir.path()).unwrap(), 0, "never written");
        std::fs::write(dir.path().join(WATERMARK_FILE), "not-a-number").unwrap();
        assert!(load_watermark_from(dir.path()).is_err());
        assert!(persist_watermark_to(dir.path(), 12));
        assert_eq!(load_watermark_from(dir.path()).unwrap(), 12);
        let missing = dir.path().join("does/not/exist");
        assert!(!persist_watermark_to(&missing, 13));
        assert!(!persist_window_to(&missing, &OwnershipWindow::new(1)));

        let (store, loaded, env, stray_old, _) = scenario(&dir.path().join("s")).await;
        let view = view_of(&loaded, &loaded.owned_pgs);
        view.write().await.state_fault = true;
        let metrics = PurgeMetrics::default();
        let s = run_pass_on(
            &store,
            &env,
            &view,
            OPEN,
            &fast_cfg(strongest()),
            false,
            5,
            None,
            &metrics,
        )
        .await;
        assert!(s.aborted_coverage_lost, "{s:?}");
        assert_eq!((s.examined, s.purged, s.would_purge), (0, 0, 0));
        for h in &stray_old {
            assert!(store.has(h));
        }
    }

    /// v2 layout: the signed base carries no `base_cut` (the pointer
    /// does, unsigned) and its snapshot is later than the end of the old
    /// delta the pointer chains. The view's cut is that delta's signed
    /// end, not the later snapshot and not the pointer's `base_cut`: the
    /// view is stale.
    #[tokio::test]
    async fn view_cut_is_the_last_signed_delta_end_not_a_later_snapshot() {
        use miner::pg_lists::test_fixtures::{write_current_v2, write_delta};
        let dir = tempfile::tempdir().unwrap();
        let key = deterministic_key(40);
        let cut = CREATED_AT_SECS - 20_000;
        let fx = write_generation(dir.path(), &key, 9, &[1, 2], 5);
        let (sha1, _) = write_delta(dir.path(), &key, 9, 1, cut, cut + 600, &[1, 2], &|pg| {
            vec![record_for(pg, 50)]
        });
        write_current_v2(dir.path(), 9, cut, &[(1, cut + 600, sha1)]);
        let cfg = PurgeConfig {
            view_max_lag_secs: 7_200,
            ..test_default()
        };
        let mut current = None;
        let mut highest = 0;
        refresh_generation(
            &DirListSource::new(dir.path()),
            &fx.validator_hex(),
            &[1, 2],
            MY_UID,
            &cfg,
            CREATED_AT_SECS + 60,
            &mut current,
            &mut highest,
        )
        .await;
        let loaded = current.as_ref().unwrap();
        assert_eq!(loaded.delta_seq, 1);
        assert_eq!(
            loaded.snapshot_secs, CREATED_AT_SECS,
            "the base snapshot is later"
        );
        assert_eq!(loaded.view_cut_secs, cut + 600, "the signed delta end");
        assert!(!view_is_fresh(loaded, CREATED_AT_SECS + 60, &cfg));
    }
}

//! Obligation-list purge policy: what may be deleted, how fast, and the
//! counters that describe it. Pure logic — the background loop that walks
//! the inventory and drives the store lives in the binary (`pg_purge`).
//!
//! ## Purge rule
//!
//! A live blob is purgeable iff, in this order:
//! 0. this miner's uid is listed in the map it holds, and not as
//!    draining nor under a placement hold ([`PurgeGate::miner_eligible`]):
//!    a map that does not list it says nothing about what it owns, and a
//!    draining or held miner is in a state that lasts until an operator
//!    lifts it, not a weight the network assigns; nothing is decided
//!    (logged once per generation, counted in
//!    `purge_refused_not_in_map_total` / `purge_refused_not_placeable_total`).
//!    A miner
//!    that IS listed with CRUSH weight 0 (connectivity quarantine,
//!    declared full, duplicate address) owns no PG now and follows the
//!    same rule as every other miner: the PGs it lost stay protected for
//!    `ownership_stable_secs` (clause 4), and once they have left the
//!    window its protected set may be empty, so every clause applies to
//!    nothing listed and its old, unlisted blobs are orphans. Refusing it
//!    instead left nodes declared full with weight 0 forever: no weight,
//!    no PG, no purge, still full. The other guards stay: the window must
//!    have been tracked for `ownership_stable_secs` (a restarted or
//!    unreadable window state purges nothing for one window), the signed
//!    cut of the view must be fresh even with no list loaded, the age
//!    clause keeps every blob written less than `min_age_secs` before the
//!    snapshot bound, and the per-delete epoch gate applies,
//! 1. a valid generation is loaded ([`PurgeGate::generation_loaded`]),
//! 2. that generation is not stale ([`PurgeGate::generation_fresh`]): its
//!    `created_at` is at most `generation_max_age_secs` in the past — a
//!    bucket nobody publishes to any more must not drive deletions,
//! 3. that generation covers EVERY PG of the protected set (clause 4)
//!    ([`PurgeGate::coverage_complete`], its delta chain whole) — an
//!    unknown PG means nothing is purged, because its blobs cannot be
//!    told apart from stray ones; a pass re-checks this before every
//!    delete and stops as soon as it no longer holds,
//! 4. the ownership window is tracked
//!    ([`PurgeGate::ownership_window_tracked`], [`OwnershipWindow`],
//!    persisted across restarts): this miner has recorded, per PG, when it
//!    first and last owned it for at least `ownership_stable_secs`, so the
//!    **protected set** — the PGs owned now plus every PG owned at any time
//!    within the last `ownership_stable_secs` — is known. Ownership here is
//!    the v3 (straw2) placement only ([`calculate_purge_pgs`]): v2 data is
//!    no longer readable network-wide and v2 placement reshuffles most of a
//!    node's PGs at every epoch, so it neither protects nor gates anything.
//!    The lists of every protected PG are loaded and clause 3 applies to the
//!    protected set: a blob listed (this miner's or another holder's) in a
//!    PG this miner lost within the window is kept, and a PG just gained is
//!    protected at once (its list must be loaded before any pass deletes;
//!    its incoming blobs are also young and in flight). An owned-set change
//!    never resets a clock and never aborts a pass; only a loss of coverage
//!    for the protected set does. The window replaces the former
//!    whole-set stability clock, which never opened on a live network: the
//!    validator publishes an epoch about every 15 minutes and every epoch
//!    changes some PGs of a node's owned set,
//! 5. the blob hash is not this miner's: its key is in neither this
//!    miner's holder set of the generation nor a delta record naming it
//!    (a hit is a keep even when it is a 64-bit prefix collision),
//! 6. **moved class**: if the hash may be listed under ANOTHER holder (the
//!    generation's live filter, a Bloom over every hash of every list plus
//!    the shards the base withholds from the lists, or the key of a delta
//!    record naming another holder in an enforced PG; a false positive is
//!    a keep) the blob is a live shard of a live file that some other
//!    miner is obliged to hold, and this copy is RETAINED: nothing in the lists
//!    proves the other holder actually has it, and the only proof source
//!    this rule may ever take is the storage-proof observation stream
//!    (not wired in this release). The class exists so the
//!    tombstone and orphan classes never apply to such a blob; it is
//!    switched off by `PURGE_MOVED_CLASS=false` only (back to clause 7/8
//!    behaviour: a listed blob of another holder, or a withheld one,
//!    is then an orphan),
//! 7. **tombstone class**: if the hash is in a protected PG's `.deleted`
//!    (the writer saw its file deleted inside the generation's window;
//!    exact set, no false positive) AND the live filter does not name it
//!    and no delta record of the enforced PGs does (the load removes such
//!    hashes from the tombstone set, see
//!    `pg_lists::LoadedGeneration::tombstones_retained_live_ref`; a live
//!    filter false positive only sends the blob back to clause 8) AND
//!    the blob's last write is before the generation's snapshot bound
//!    ([`Candidate::stored_after_snapshot`] false: a Store after the
//!    scan start is a live reference the writer could not have seen —
//!    a re-upload of the same content lands on the same hash and only
//!    refreshes `stored_at`), it is purgeable now, without the
//!    `min_age_secs` clause — the deletion is proven, not inferred from
//!    absence — but still subject to clause 9 and to the same dry-run,
//!    write lock and in-flight checks as any other delete,
//! 8. otherwise (**orphan class**: neither listed, moved nor tombstoned)
//!    the blob was stored at least `min_age_secs` before BOTH now and the
//!    generation's snapshot bound (`scan_started_at` when published,
//!    else `created_at`; `Candidate::age_secs` is measured from the
//!    earlier of the two): a blob the scan could not have listed is never
//!    a candidate, however old the generation is,
//! 9. the blob is not the target of a Store/PullFromPeer in progress
//!    (checked again under the per-hash write lock right before the
//!    delete).
//!
//! Moved is checked before tombstoned on purpose: a hash with ANY live
//! record in an owned PG (this miner's or another holder's — identical
//! shard bytes are shared by several files, padding shards in
//! particular) is never in the tombstone class, exactly as a hash this
//! miner's own list still names wins over its tombstone. The Bloom
//! filters make that cheap on the common path; the exact removal at load
//! time makes it independent of the filters (the others filter may be
//! off or over its cap, a tombstone is still never enforced against a
//! listed hash). The rule behind both: a blob referenced by any live
//! manifest, in any PG, is never tombstoned or purged as tombstoned.
//!
//! ## Kill switches
//!
//! `PURGE_ENABLED` defaults to true. Since 0.1.36 `PURGE_DRY_RUN` defaults
//! to false: a build with the `purge-enforce` feature deletes (two-phase
//! trash) once every gate below opens; `PURGE_DRY_RUN=true` keeps the
//! census, which only logs what would be deleted. `PURGE_ENABLED=false`
//! turns the loop off.
//!
//! ## Mode
//!
//! What a pass may do is a type, [`Mode`], not a boolean. A build without
//! the `purge-enforce` Cargo feature has exactly one variant, `Census`:
//! the pass counts and logs, the store calls that delete are not
//! compiled, and an explicit `PURGE_DRY_RUN=false` is answered with a warning
//! and the census (the unset default is the census, silently). Only a build
//! with the feature carries `Enforce`.

use std::collections::BTreeMap;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::time::Duration;

use anyhow::{Result, anyhow};
use tokio::time::Instant;

/// The one boolean syntax of every `PURGE_*` switch: exactly `1`, `true`,
/// `yes`, `on` or `0`, `false`, `no`, `off`, case-insensitive, surrounding
/// whitespace ignored. Anything else is `None`: a deletion knob never
/// falls back to a silent default, the caller must refuse to run.
pub fn parse_bool(raw: &str) -> Option<bool> {
    match raw.trim().to_ascii_lowercase().as_str() {
        "1" | "true" | "yes" | "on" => Some(true),
        "0" | "false" | "no" | "off" => Some(false),
        _ => None,
    }
}

/// Read a boolean switch through `lookup`: `Ok(None)` when unset, an error
/// naming the variable and its value when set to anything [`parse_bool`]
/// rejects.
pub fn lookup_bool(lookup: &impl Fn(&str) -> Option<String>, name: &str) -> Result<Option<bool>> {
    match lookup(name) {
        None => Ok(None),
        Some(raw) => parse_bool(&raw).map(Some).ok_or_else(|| {
            anyhow!(
                "{name}={raw:?} is not a boolean: use 1/true/yes/on or 0/false/no/off (refusing to run rather than guess a deletion switch)"
            )
        }),
    }
}

/// True when this binary was built with the `purge-enforce` feature, i.e.
/// when [`Mode::Enforce`] exists and a pass can delete.
pub const ENFORCEMENT_COMPILED: bool = cfg!(feature = "purge-enforce");

/// What a purge pass may do to the store.
///
/// Without the `purge-enforce` feature this enum has one variant: a
/// release built that way cannot delete through the purge, whatever the
/// environment says. The variant set is the guard, not a flag.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Mode {
    /// Count and log what the rule would delete; touch nothing.
    Census,
    /// Delete for real (two-phase trash, or unlink with
    /// `TRASH_ENABLED=false`). Compiled only with `purge-enforce`.
    #[cfg(feature = "purge-enforce")]
    Enforce,
}

impl Mode {
    /// The mode a `PURGE_DRY_RUN` value asks for. `false` asks for
    /// enforcement; a build that does not carry it warns once and
    /// answers with the census.
    pub fn from_dry_run(dry_run: bool) -> Self {
        if dry_run {
            return Mode::Census;
        }
        #[cfg(feature = "purge-enforce")]
        {
            Mode::Enforce
        }
        #[cfg(not(feature = "purge-enforce"))]
        {
            tracing::warn!(
                "PURGE_DRY_RUN=false: enforcement not compiled into this build, running the census"
            );
            Mode::Census
        }
    }

    /// The mode when `PURGE_DRY_RUN` is unset: `Enforce` in a build that
    /// carries it, else `Census`. Unlike [`Mode::from_dry_run`] it never
    /// warns: nobody asked for enforcement.
    pub fn default_for_build() -> Self {
        #[cfg(feature = "purge-enforce")]
        {
            Mode::Enforce
        }
        #[cfg(not(feature = "purge-enforce"))]
        {
            Mode::Census
        }
    }

    /// True when the pass only counts.
    pub fn is_census(self) -> bool {
        matches!(self, Mode::Census)
    }

    /// True when the pass deletes.
    pub fn enforces(self) -> bool {
        !self.is_census()
    }
}

/// Public bucket root of the obligation lists, used when
/// `PG_LISTS_BASE_URL` is not set.
pub const DEFAULT_PG_LISTS_BASE_URL: &str = "https://s3.hippius.com/pg-inventory";

/// Purge knobs, all environment-driven (`PURGE_*`, `PG_LISTS_*`).
#[derive(Debug, Clone, PartialEq)]
pub struct PurgeConfig {
    /// `PG_LISTS_BASE_URL`: public bucket root, [`DEFAULT_PG_LISTS_BASE_URL`]
    /// when unset; set but empty, there is no source and the purge stays off.
    pub base_url: Option<String>,
    /// `PURGE_ENABLED` (default true). With the default `PURGE_DRY_RUN=false`
    /// a `purge-enforce` build deletes (two-phase trash) once every gate
    /// opens; `PURGE_DRY_RUN=true` runs the census only.
    pub enabled: bool,
    /// `PURGE_DRY_RUN` (default false since 0.1.36) as a [`Mode`]: `Census`
    /// logs candidates and deletes nothing; `Enforce` only exists in a
    /// build with the `purge-enforce` feature, see
    /// [`Mode::default_for_build`].
    pub mode: Mode,
    /// `PURGE_MIN_AGE_SECS` (default 1 209 600 = 14 days): a blob must
    /// have been stored this long before the earlier of now and the
    /// generation snapshot. Day-scale on purpose: the writer's scan spans
    /// days, and a manifest committed after the scan cursor passed its
    /// hash is unlisted but old by the time the generation is published.
    pub min_age_secs: u64,
    /// `PURGE_RATE_PER_SEC` (default 50 deletions per second).
    pub rate_per_sec: u64,
    /// `PURGE_MAX_BYTES_PER_SEC` (default 50 MiB per second).
    pub max_bytes_per_sec: u64,
    /// `PG_LISTS_POLL_SECS` (default 600): `current.json` poll cadence.
    pub poll_secs: u64,
    /// `PURGE_OWNERSHIP_STABLE_SECS` (default 21 600 = 6 h): the per-PG
    /// ownership window ([`OwnershipWindow`]). A PG owned at any time in
    /// the last `ownership_stable_secs` stays protected: its list is
    /// loaded and a blob it names (under this holder or another) is kept.
    /// A PG this miner just lost is "not owned" under the new map, yet
    /// gateways still read it through the placement_epoch map and the
    /// rebalance may not have copied it to the new owners: a weight drop
    /// must not turn into a mass delete half an hour later. The window is
    /// per PG, not a clock on the whole owned set: the validator publishes
    /// an epoch about every 15 minutes and each one moves some PGs of every
    /// node, so a whole-set clock never ran out. A pass also waits until
    /// the window has been tracked for this long (after a first start or
    /// an unreadable state file). `PURGE_EPOCH_STABLE_SECS` is accepted,
    /// warned about and ignored.
    pub ownership_stable_secs: u64,
    /// `PG_LISTS_FETCH_CONCURRENCY` (default 4, at most 8: each list body
    /// is buffered whole, up to 256 MiB).
    pub fetch_concurrency: usize,
    /// `PURGE_PASS_INTERVAL_SECS` (default 3600): pause between full
    /// passes over the inventory.
    pub pass_interval_secs: u64,
    /// `PURGE_GENERATION_MAX_AGE_SECS` (default 604 800 = 7 days): a
    /// generation whose `created_at` is older than this is refused
    /// (nothing purged) until a newer one is published.
    pub generation_max_age_secs: u64,
    /// `PURGE_VIEW_MAX_LAG_SECS` (default 7 200 = 2 h): a pass deletes only
    /// while the newest signed cut folded into the view (the last applied
    /// delta's `until`, else the base's signed `base_cut`, never a
    /// `current.json` field) is at most this old. Deltas are published
    /// hourly, so a healthy view lags by up to about an hour plus the
    /// publication delay; the purge is built to tolerate that (14-day age
    /// clause, moved class, trash). A stale or replayed pointer is just an
    /// older view: past this bound it deletes nothing.
    pub view_max_lag_secs: u64,
    /// `PURGE_MOVED_CLASS` (default true): classify blobs listed in an
    /// owned PG under another holder as moved and retain them. `false` is
    /// the rollback to the two-class rule (such a blob is an orphan).
    pub moved_class: bool,
    /// Where the holder sets and live filter shards of the loaded
    /// generation are cached (`gen-<g>/` below it). `None` (the default):
    /// `<data_dir>/pg-lists-cache`. Not read from the environment.
    pub lists_cache_dir: Option<std::path::PathBuf>,
}

impl Default for PurgeConfig {
    fn default() -> Self {
        Self {
            base_url: Some(DEFAULT_PG_LISTS_BASE_URL.to_string()),
            enabled: true,
            mode: Mode::default_for_build(),
            min_age_secs: 14 * 86_400,
            rate_per_sec: 50,
            max_bytes_per_sec: 50 * 1024 * 1024,
            poll_secs: 600,
            ownership_stable_secs: 21_600,
            fetch_concurrency: 4,
            pass_interval_secs: 3600,
            generation_max_age_secs: 7 * 86_400,
            view_max_lag_secs: 7_200,
            moved_class: true,
            lists_cache_dir: None,
        }
    }
}

/// Whether a generation finalized at `created_at_secs` may still drive
/// deletions at `now_secs`: at most `max_age_secs` old. A clock behind
/// the manifest counts as age zero.
pub fn generation_is_fresh(created_at_secs: u64, now_secs: u64, max_age_secs: u64) -> bool {
    now_secs.saturating_sub(created_at_secs) <= max_age_secs
}

impl PurgeConfig {
    /// Read the process environment.
    pub fn from_env() -> Result<Self> {
        Self::from_lookup(|name| std::env::var(name).ok())
    }

    /// Build from any name -> value lookup (tests pass a map). An
    /// unparseable NUMERIC value keeps the default (logged at warn); an
    /// unparseable BOOLEAN (`PURGE_ENABLED`, `PURGE_DRY_RUN`) is an error,
    /// see [`parse_bool`].
    pub fn from_lookup(lookup: impl Fn(&str) -> Option<String>) -> Result<Self> {
        let mut cfg = Self::default();
        fn parse<T: std::str::FromStr>(
            lookup: &impl Fn(&str) -> Option<String>,
            name: &str,
            target: &mut T,
        ) {
            if let Some(raw) = lookup(name) {
                match raw.trim().parse::<T>() {
                    Ok(v) => *target = v,
                    Err(_) => tracing::warn!(
                        env = name,
                        value = %raw,
                        "purge: invalid value, keeping default"
                    ),
                }
            }
        }
        if let Some(raw) = lookup("PG_LISTS_BASE_URL") {
            cfg.base_url = Some(raw.trim().to_string()).filter(|s| !s.is_empty());
        }
        if let Some(v) = lookup_bool(&lookup, "PURGE_ENABLED")? {
            cfg.enabled = v;
        }
        if let Some(v) = lookup_bool(&lookup, "PURGE_DRY_RUN")? {
            cfg.mode = Mode::from_dry_run(v);
        }
        parse(&lookup, "PURGE_MIN_AGE_SECS", &mut cfg.min_age_secs);
        parse(&lookup, "PURGE_RATE_PER_SEC", &mut cfg.rate_per_sec);
        parse(
            &lookup,
            "PURGE_MAX_BYTES_PER_SEC",
            &mut cfg.max_bytes_per_sec,
        );
        parse(&lookup, "PG_LISTS_POLL_SECS", &mut cfg.poll_secs);
        parse(
            &lookup,
            "PURGE_OWNERSHIP_STABLE_SECS",
            &mut cfg.ownership_stable_secs,
        );
        if let Some(raw) = lookup("PURGE_EPOCH_STABLE_SECS") {
            tracing::warn!(
                value = %raw,
                "purge: PURGE_EPOCH_STABLE_SECS is deprecated and ignored (an epoch changes every few minutes on a live network, the gate never opened); PURGE_OWNERSHIP_STABLE_SECS is the per-PG ownership window"
            );
        }
        for removed in [
            "PURGE_FILTER_FP",
            "PURGE_FILTER_MAX_BYTES",
            "PURGE_OTHERS_FILTER_MAX_BYTES",
        ] {
            if let Some(raw) = lookup(removed) {
                tracing::warn!(
                    knob = removed,
                    value = %raw,
                    "purge: knob removed and ignored (membership comes from the published holder sets and live filter, no filter is built locally)"
                );
            }
        }
        parse(
            &lookup,
            "PG_LISTS_FETCH_CONCURRENCY",
            &mut cfg.fetch_concurrency,
        );
        parse(
            &lookup,
            "PURGE_PASS_INTERVAL_SECS",
            &mut cfg.pass_interval_secs,
        );
        parse(
            &lookup,
            "PURGE_GENERATION_MAX_AGE_SECS",
            &mut cfg.generation_max_age_secs,
        );
        parse(
            &lookup,
            "PURGE_VIEW_MAX_LAG_SECS",
            &mut cfg.view_max_lag_secs,
        );
        if let Some(v) = lookup_bool(&lookup, "PURGE_MOVED_CLASS")? {
            cfg.moved_class = v;
        }
        cfg.rate_per_sec = cfg.rate_per_sec.max(1);
        cfg.max_bytes_per_sec = cfg.max_bytes_per_sec.max(1);
        cfg.poll_secs = cfg.poll_secs.max(10);
        cfg.fetch_concurrency = cfg.fetch_concurrency.clamp(1, 8);
        Ok(cfg)
    }
}

// ============================================================================
// Decision
// ============================================================================

/// Global preconditions, evaluated once per pass.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PurgeGate {
    /// This miner's uid is listed in the map the pass runs on, not
    /// draining and not under a placement hold (clause 0).
    /// A listed miner with weight 0 and an empty protected set passes:
    /// it follows the same window rule as every other miner.
    pub miner_eligible: bool,
    pub generation_loaded: bool,
    /// The loaded generation is at most `generation_max_age_secs` old.
    pub generation_fresh: bool,
    pub coverage_complete: bool,
    /// The per-PG ownership window has been tracked for at least
    /// `ownership_stable_secs`, so the protected set is complete.
    pub ownership_window_tracked: bool,
}

impl PurgeGate {
    pub fn open(&self) -> bool {
        self.miner_eligible
            && self.generation_loaded
            && self.generation_fresh
            && self.coverage_complete
            && self.ownership_window_tracked
    }
}

/// PGs this miner owns for the purge under `map`: those whose v3 (straw2)
/// placement, on the placement-filtered map (draining and held miners
/// removed, like the write path), includes `miner_uid`. v2 placement is
/// deliberately left out: v2 data is no longer readable network-wide, new
/// uploads are v3, and the v2 placement moves about 90 % of a node's v2
/// PGs at every epoch (measured on two consecutive live-network epochs,
/// against 3-8 % for straw2), so a union with it made a node's owned set
/// change by roughly half at every epoch. `common::calculate_my_pgs` (the
/// v2 ∪ v3 union) stays what rebalance and backfill use. Sorted.
pub fn calculate_purge_pgs(miner_uid: u32, map: &common::ClusterMap) -> Vec<u32> {
    let filtered;
    let map_ref = if map.miners.iter().any(|m| m.draining || m.placement_hold) {
        filtered = common::filter_map_for_placement(map);
        &filtered
    } else {
        map
    };
    let shards_per_file = map.ec_k + map.ec_m;
    (0..map_ref.pg_count)
        .filter(|&pg_id| {
            common::calculate_pg_placement_straw2(pg_id, shards_per_file, map_ref)
                .map(|miners| miners.iter().any(|m| m.uid == miner_uid))
                .unwrap_or(false)
        })
        .collect()
}

/// Slack added to the ownership window when deciding whether a PG is
/// still protected: the window state is persisted at most this often
/// while membership does not change, so after a crash a `last_owned_at`
/// read back may be up to this much older than the truth.
pub const OWNERSHIP_PERSIST_INTERVAL_SECS: u64 = 60;

/// Longest gap between two observations of the ownership window that is
/// still continuous observation: the state is persisted at least every
/// [`OWNERSHIP_PERSIST_INTERVAL_SECS`] and the loop ticks every 10 s, so
/// three persist intervals plus slack cover a normal restart. A longer
/// gap (downtime, a wall clock jumping forward) is a period in which PGs
/// were owned or lost unseen: [`OwnershipWindow::restart_after_gap`].
pub const OWNERSHIP_OBSERVATION_GAP_SECS: u64 = 3 * OWNERSHIP_PERSIST_INTERVAL_SECS + 30;

/// A wall-clock step backwards larger than this between two loop ticks
/// (measured against the monotonic clock) restarts the tracking.
pub const WALL_CLOCK_BACKWARD_TOLERANCE_SECS: u64 = 5;

/// Whether the wall clock jumped between two loop ticks: the wall-clock
/// delta minus the monotonic delta is above
/// [`OWNERSHIP_OBSERVATION_GAP_SECS`] (forward) or below
/// `-WALL_CLOCK_BACKWARD_TOLERANCE_SECS` (backwards). A loop stalled for
/// minutes moves both clocks alike and is not a jump.
pub fn wall_clock_jumped(prev_wall_secs: u64, now_wall_secs: u64, mono_elapsed_secs: u64) -> bool {
    let skew = now_wall_secs as i128 - prev_wall_secs as i128 - mono_elapsed_secs as i128;
    skew > OWNERSHIP_OBSERVATION_GAP_SECS as i128
        || skew < -(WALL_CLOCK_BACKWARD_TOLERANCE_SECS as i128)
}

/// What one [`OwnershipWindow::observe`] changed.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct WindowObservation {
    /// PGs owned now that the window did not hold (newly owned, or owned
    /// again after they expired).
    pub gained: usize,
    /// PGs held by the window but not owned now (still protected while
    /// inside the window).
    pub lost: usize,
    /// PGs dropped from the window: not owned for longer than the window.
    pub expired: usize,
}

impl WindowObservation {
    /// The window's membership changed (a PG entered or left it).
    pub fn membership_changed(&self) -> bool {
        self.gained > 0 || self.expired > 0
    }
}

/// Clause 4 of the purge rule: per PG, the wall-clock time (Unix seconds)
/// this miner first and last owned it, plus the time since which the
/// record is complete (`tracking_since`: the first observation of a fresh
/// or unreadable state). Persisted next to the generation watermark so a
/// restart keeps the window; a missing or unreadable file restarts the
/// tracking, and a pass then waits a full window (a PG lost just before
/// would otherwise be forgotten).
///
/// The protected set at `now` is every PG owned at the last observation
/// plus every PG whose `last_owned_at` is at most `window_secs`
/// (+ [`OWNERSHIP_PERSIST_INTERVAL_SECS`]) old.
///
/// The record is only as good as the observation was continuous: the
/// time of the last observation is persisted too, and a gap (downtime
/// longer than [`OWNERSHIP_OBSERVATION_GAP_SECS`], a wall clock that
/// jumped forward or went back) makes every PG of the record owned until
/// now and restarts the tracking ([`Self::restart_after_gap`]): nothing
/// the window held can expire during the unseen period, and no pass runs
/// before a full window of observation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OwnershipWindow {
    /// `pg -> (first_owned_at, last_owned_at)`.
    pgs: BTreeMap<u32, (u64, u64)>,
    /// PGs owned at the last observation (sorted).
    owned: Vec<u32>,
    tracking_since: u64,
    /// Wall-clock time of the last observation (or of the creation).
    last_observed: u64,
}

/// How [`OwnershipWindow::decode`] read a persisted state.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WindowDecoded {
    /// The current format (`v3`).
    Current,
    /// The previous per-PG format (`v2`, no observation time): every PG
    /// of it is owned until the load, and tracking restarts at the load.
    MigratedFromV2,
    /// The former whole-set stability state (`v1 <changed_at>` + the set):
    /// its PGs are imported as owned from `changed_at` until the load, and
    /// tracking restarts at the load (the v1 file does not say which PGs
    /// were lost before `changed_at`).
    MigratedFromV1,
}

impl OwnershipWindow {
    /// Empty window whose tracking starts at `now_secs`.
    pub fn new(now_secs: u64) -> Self {
        Self {
            pgs: BTreeMap::new(),
            owned: Vec::new(),
            tracking_since: now_secs,
            last_observed: now_secs,
        }
    }

    /// Wall-clock time of the last observation.
    pub fn last_observed(&self) -> u64 {
        self.last_observed
    }

    /// Whether the record was not observed continuously up to `now_secs`:
    /// the last observation is more than [`OWNERSHIP_OBSERVATION_GAP_SECS`]
    /// old, or in the future (the clock went back).
    pub fn has_gap_until(&self, now_secs: u64) -> bool {
        now_secs
            > self
                .last_observed
                .saturating_add(OWNERSHIP_OBSERVATION_GAP_SECS)
            || now_secs < self.last_observed
    }

    /// After a period this record did not see: every PG it holds is owned
    /// until `now_secs` (so each stays protected a full window from now),
    /// and tracking restarts at `now_secs` (no pass for a full window).
    pub fn restart_after_gap(&mut self, now_secs: u64) {
        for (_, last) in self.pgs.values_mut() {
            *last = (*last).max(now_secs);
        }
        self.tracking_since = now_secs;
        self.last_observed = now_secs;
    }

    /// Unix seconds since which the record is complete.
    pub fn tracking_since(&self) -> u64 {
        self.tracking_since
    }

    /// Seconds the window has been tracked at `now_secs`.
    pub fn tracked_for_secs(&self, now_secs: u64) -> u64 {
        now_secs.saturating_sub(self.tracking_since)
    }

    /// Tracked for at least `window_secs`: every PG owned within the
    /// window is in the record.
    pub fn is_tracked(&self, now_secs: u64, window_secs: u64) -> bool {
        self.tracked_for_secs(now_secs) >= window_secs
    }

    /// PGs owned at the last observation.
    pub fn owned(&self) -> &[u32] {
        &self.owned
    }

    /// `(first_owned_at, last_owned_at)` of `pg`, if in the window.
    pub fn entry(&self, pg: u32) -> Option<(u64, u64)> {
        self.pgs.get(&pg).copied()
    }

    /// Number of PGs in the window (owned now or within it).
    pub fn len(&self) -> usize {
        self.pgs.len()
    }

    /// Whether the window holds no PG.
    pub fn is_empty(&self) -> bool {
        self.pgs.is_empty()
    }

    fn inside(last_owned_at: u64, now_secs: u64, window_secs: u64) -> bool {
        now_secs.saturating_sub(last_owned_at)
            <= window_secs.saturating_add(OWNERSHIP_PERSIST_INTERVAL_SECS)
    }

    /// Fold the owned set computed from the current map at `now_secs`:
    /// every owned PG gets `last_owned_at = now` (and `first_owned_at =
    /// now` if new), PGs not owned for longer than the window are dropped.
    /// A clock step backwards never shortens a PG's protection.
    pub fn observe(&mut self, owned: &[u32], now_secs: u64, window_secs: u64) -> WindowObservation {
        let mut owned = owned.to_vec();
        owned.sort_unstable();
        owned.dedup();
        let mut obs = WindowObservation::default();
        for pg in &owned {
            match self.pgs.get_mut(pg) {
                Some((_, last)) => *last = (*last).max(now_secs),
                None => {
                    self.pgs.insert(*pg, (now_secs, now_secs));
                    obs.gained += 1;
                }
            }
        }
        let before = self.pgs.len();
        self.pgs.retain(|pg, (_, last)| {
            owned.binary_search(pg).is_ok() || Self::inside(*last, now_secs, window_secs)
        });
        obs.expired = before - self.pgs.len();
        obs.lost = self.pgs.len() - owned.len();
        self.owned = owned;
        self.last_observed = now_secs;
        obs
    }

    /// The protected set at `now_secs` (sorted): owned at the last
    /// observation, or owned at any time within the window.
    pub fn protected(&self, now_secs: u64, window_secs: u64) -> Vec<u32> {
        self.pgs
            .iter()
            .filter(|(pg, (_, last))| {
                self.owned.binary_search(pg).is_ok() || Self::inside(*last, now_secs, window_secs)
            })
            .map(|(pg, _)| *pg)
            .collect()
    }

    /// Persisted form: `v3 <tracking_since> <last_observed>`, then one
    /// `<pg> <first> <last>` line per PG in the window, then `owned`
    /// followed by the PGs owned at the last observation. A binary that
    /// predates `v3` reads it as unreadable and restarts its own tracking
    /// (the safe side).
    pub fn encode(&self) -> String {
        let mut out = format!("v3 {} {}\n", self.tracking_since, self.last_observed);
        for (pg, (first, last)) in &self.pgs {
            out.push_str(&format!("{pg} {first} {last}\n"));
        }
        let owned: Vec<String> = self.owned.iter().map(u32::to_string).collect();
        out.push_str(&format!("owned {}\n", owned.join(" ")));
        out
    }

    /// Inverse of [`encode`](Self::encode), also accepting the former
    /// `v2` per-PG and `v1` whole-set states (migrated, see
    /// [`WindowDecoded`]); `None` on anything malformed (the caller then
    /// starts a fresh window at `now_secs`, and a pass waits a full
    /// window). A `v3` state is returned as persisted: the caller checks
    /// [`Self::has_gap_until`].
    pub fn decode(text: &str, now_secs: u64) -> Option<(Self, WindowDecoded)> {
        let mut lines = text.lines();
        let header = lines.next()?;
        let mut parts = header.split_whitespace();
        match parts.next()? {
            version @ ("v3" | "v2") => {
                let tracking_since = parts.next()?.parse::<u64>().ok()?;
                let last_observed = if version == "v3" {
                    parts.next()?.parse::<u64>().ok()?
                } else {
                    now_secs
                };
                if parts.next().is_some() {
                    return None;
                }
                let mut pgs = BTreeMap::new();
                let mut owned: Option<Vec<u32>> = None;
                for line in lines {
                    if line.trim().is_empty() {
                        continue;
                    }
                    if owned.is_some() {
                        return None;
                    }
                    let mut fields = line.split_whitespace();
                    let first_tok = fields.next()?;
                    if first_tok == "owned" {
                        let mut set = Vec::new();
                        for tok in fields {
                            set.push(tok.parse::<u32>().ok()?);
                        }
                        set.sort_unstable();
                        set.dedup();
                        owned = Some(set);
                        continue;
                    }
                    let pg = first_tok.parse::<u32>().ok()?;
                    let first = fields.next()?.parse::<u64>().ok()?;
                    let last = fields.next()?.parse::<u64>().ok()?;
                    if fields.next().is_some()
                        || first > last
                        || pgs.insert(pg, (first, last)).is_some()
                    {
                        return None;
                    }
                }
                let owned = owned?;
                if owned.iter().any(|pg| !pgs.contains_key(pg)) {
                    return None;
                }
                let mut w = Self {
                    pgs,
                    owned,
                    tracking_since,
                    last_observed,
                };
                if version == "v2" {
                    // No observation time: the downtime before this load
                    // is unknown, so the gap rule applies.
                    w.restart_after_gap(now_secs);
                    return Some((w, WindowDecoded::MigratedFromV2));
                }
                Some((w, WindowDecoded::Current))
            }
            "v1" => {
                let changed_at = parts.next()?.parse::<u64>().ok()?;
                if parts.next().is_some() {
                    return None;
                }
                let mut owned = Vec::new();
                for tok in lines.next().unwrap_or("").split_whitespace() {
                    owned.push(tok.parse::<u32>().ok()?);
                }
                if lines.next().is_some_and(|l| !l.trim().is_empty()) {
                    return None;
                }
                owned.sort_unstable();
                owned.dedup();
                let first = changed_at.min(now_secs);
                let pgs = owned.iter().map(|pg| (*pg, (first, now_secs))).collect();
                Some((
                    Self {
                        pgs,
                        owned,
                        tracking_since: now_secs,
                        last_observed: now_secs,
                    },
                    WindowDecoded::MigratedFromV1,
                ))
            }
            _ => None,
        }
    }
}

/// Per-blob facts.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Candidate {
    /// Seconds between the blob's last write and the earlier of now and
    /// the generation snapshot.
    pub age_secs: u64,
    /// Membership filter answer (true = possibly obliged).
    pub in_filter: bool,
    /// Others filter answer (true = possibly a live shard some other
    /// holder of an owned PG is obliged to hold). Always `false` when the
    /// moved class is off or its filter was not built.
    pub moved: bool,
    /// Exact tombstone-set answer: the writer saw this shard's file
    /// deleted inside the generation's window and no enforced list
    /// names the hash.
    pub tombstoned: bool,
    /// The blob's last write (`stored_at`, refreshed by every Store) is
    /// at or after the generation's snapshot bound: a live reference the
    /// writer's scan could not have seen. Keeps a tombstoned blob.
    pub stored_after_snapshot: bool,
    /// A Store/PullFromPeer for this hash is in progress.
    pub inflight: bool,
}

/// Outcome of [`decide`]; every `Keep*` names the clause that kept it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Verdict {
    /// Orphan: unlisted, old enough, not in flight.
    Purge,
    /// Tombstoned: unlisted and the writer saw its file deleted; the age
    /// clause does not apply.
    PurgeTombstoned,
    /// Absent from the held map, draining or held: clause 0.
    KeepMinerNotEligible,
    KeepNoGeneration,
    KeepGenerationStale,
    KeepCoverageIncomplete,
    /// The ownership window has not been tracked long enough yet.
    KeepOwnershipWindowUntracked,
    KeepInList,
    /// Moved: listed in an owned PG under another holder; retained until
    /// a proof source other than the lists exists (module docs, clause 6).
    KeepMoved,
    KeepYoung,
    /// Tombstoned, but written at or after the generation's snapshot
    /// bound: the writer could not have seen that reference.
    KeepStoredAfterSnapshot,
    KeepInflight,
}

/// The purge rule (see module docs). Clauses are checked in order so the
/// cheapest global gates short-circuit before per-blob facts matter.
pub fn decide(gate: PurgeGate, candidate: Candidate, min_age_secs: u64) -> Verdict {
    if !gate.miner_eligible {
        return Verdict::KeepMinerNotEligible;
    }
    if !gate.generation_loaded {
        return Verdict::KeepNoGeneration;
    }
    if !gate.generation_fresh {
        return Verdict::KeepGenerationStale;
    }
    if !gate.coverage_complete {
        return Verdict::KeepCoverageIncomplete;
    }
    if !gate.ownership_window_tracked {
        return Verdict::KeepOwnershipWindowUntracked;
    }
    classify(candidate, min_age_secs)
}

/// The per-blob part of [`decide`], after the global gates: the class a
/// blob falls in under the loaded lists (in list, moved, tombstoned,
/// orphan) and the clause that keeps or purges it. The dry-run census on
/// a generation with incomplete coverage applies exactly this rule to
/// count what a full-coverage pass would do; it never deletes.
pub fn classify(candidate: Candidate, min_age_secs: u64) -> Verdict {
    if candidate.in_filter {
        return Verdict::KeepInList;
    }
    if candidate.moved {
        return Verdict::KeepMoved;
    }
    if candidate.tombstoned {
        return if candidate.stored_after_snapshot {
            Verdict::KeepStoredAfterSnapshot
        } else if candidate.inflight {
            Verdict::KeepInflight
        } else {
            Verdict::PurgeTombstoned
        };
    }
    if candidate.age_secs < min_age_secs {
        return Verdict::KeepYoung;
    }
    if candidate.inflight {
        return Verdict::KeepInflight;
    }
    Verdict::Purge
}

// ============================================================================
// Rate limiting
// ============================================================================

/// Two token buckets (operations and bytes) refilled continuously. A
/// deletion waits until both have room; a single blob larger than one
/// second of byte budget is admitted once the bucket is full (it just
/// drains it further into debt, spacing the next ones out).
#[derive(Debug)]
pub struct RateLimiter {
    ops_per_sec: f64,
    bytes_per_sec: f64,
    ops_tokens: f64,
    bytes_tokens: f64,
    last: Instant,
}

impl RateLimiter {
    pub fn new(ops_per_sec: u64, bytes_per_sec: u64) -> Self {
        let ops_per_sec = ops_per_sec.max(1) as f64;
        let bytes_per_sec = bytes_per_sec.max(1) as f64;
        Self {
            ops_per_sec,
            bytes_per_sec,
            // Start full: the first second of work is not delayed.
            ops_tokens: ops_per_sec,
            bytes_tokens: bytes_per_sec,
            last: Instant::now(),
        }
    }

    fn refill(&mut self) {
        let now = Instant::now();
        let elapsed = now.duration_since(self.last).as_secs_f64();
        self.last = now;
        self.ops_tokens = (self.ops_tokens + elapsed * self.ops_per_sec).min(self.ops_per_sec);
        self.bytes_tokens =
            (self.bytes_tokens + elapsed * self.bytes_per_sec).min(self.bytes_per_sec);
    }

    /// Wait until one deletion of `bytes` fits the budget, then consume it.
    pub async fn acquire(&mut self, bytes: u64) {
        loop {
            self.refill();
            let need_bytes = (bytes as f64).min(self.bytes_per_sec);
            if self.ops_tokens >= 1.0 && self.bytes_tokens >= need_bytes {
                self.ops_tokens -= 1.0;
                // Charge the real size: an oversized blob drives the bucket
                // negative and the refill pays it back before the next one.
                self.bytes_tokens -= bytes as f64;
                return;
            }
            let wait_ops = ((1.0 - self.ops_tokens).max(0.0)) / self.ops_per_sec;
            let wait_bytes = ((need_bytes - self.bytes_tokens).max(0.0)) / self.bytes_per_sec;
            let wait = wait_ops.max(wait_bytes).max(0.001);
            tokio::time::sleep(Duration::from_secs_f64(wait)).await;
        }
    }
}

// ============================================================================
// Metrics
// ============================================================================

/// Counters of the purge loop. Cumulative since process start except the
/// coverage gauges, which describe the loaded generation.
#[derive(Debug, Default)]
pub struct PurgeMetrics {
    /// Inventory rows examined.
    pub candidates: AtomicU64,
    /// Blobs actually deleted (never incremented in dry-run).
    pub purged: AtomicU64,
    pub purged_bytes: AtomicU64,
    /// Blobs a real run would have deleted while in dry-run.
    pub would_purge: AtomicU64,
    pub would_purge_bytes: AtomicU64,
    /// Blobs whose verdict was the tombstone class (subset of
    /// `candidates`; counted in dry-run too).
    pub tombstone_candidates: AtomicU64,
    /// Tombstoned blobs actually deleted (subset of `purged`; never
    /// incremented in dry-run). Exposed as `purge_tombstone_deleted_total`.
    pub tombstone_deleted: AtomicU64,
    pub tombstone_deleted_bytes: AtomicU64,
    /// Tombstoned blobs a real run would have deleted while in dry-run
    /// (subset of `would_purge`).
    pub tombstone_would_purge: AtomicU64,
    /// Tombstoned blobs retained because their last write is at or after
    /// the generation's snapshot bound. Exposed as
    /// `purge_tombstone_retained_fresh_store_total`.
    pub tombstone_retained_fresh_store: AtomicU64,
    /// Gauge: tombstone hashes of the loaded generation the load removed
    /// because a record of an enforced list names them. Exposed as
    /// `purge_tombstone_retained_live_ref`.
    pub tombstone_retained_live_ref: AtomicU64,
    pub kept_by_filter: AtomicU64,
    /// Blobs whose verdict was the moved class: retained. Exposed as
    /// `miner_purge_kept_moved_total`.
    pub kept_moved: AtomicU64,
    pub skipped_young: AtomicU64,
    pub skipped_inflight: AtomicU64,
    /// Blobs a pass left because the view stayed write-locked while it
    /// held their hash lock. Exposed as `purge_skipped_view_busy_total`.
    pub skipped_view_busy: AtomicU64,
    /// Rows whose hash is not 64 hex characters. Exposed as
    /// `miner_purge_invalid_hash_total`.
    pub invalid_hash: AtomicU64,
    /// Live rows whose blob the store does not hold. Exposed as
    /// `miner_purge_absent_from_store_total`.
    pub absent_from_store: AtomicU64,
    /// Of those, rows dropped because the store confirmed the blob absent.
    /// Exposed as `miner_purge_absent_rows_dropped_total`.
    pub absent_rows_dropped: AtomicU64,
    /// Rows gone or trashed between the page read and the delete. Exposed
    /// as `miner_purge_vanished_total`.
    pub vanished: AtomicU64,
    pub delete_errors: AtomicU64,
    /// Gauge: protected PGs listed by the loaded generation.
    pub coverage_pgs_listed: AtomicU64,
    /// Gauge: PGs in the protected set (owned now or within the window).
    pub coverage_pgs_owned: AtomicU64,
    /// Gauge: 1 when the loaded lists cover every protected PG (delta
    /// chain whole).
    pub coverage_complete: AtomicBool,
    /// Gauge: loaded generation (0 = none).
    pub generation: AtomicU64,
    /// Gauge: keys in this miner's holder set plus its delta records.
    pub filter_hashes: AtomicU64,
    /// Gauge: bytes mapped from the local cache (this miner's holder set
    /// parts and the 256 live filter shards).
    pub filter_bytes: AtomicU64,
    /// Gauge: 1 when the loaded generation carries a live filter and
    /// `PURGE_MOVED_CLASS` is on, i.e. the moved class is enforced.
    pub moved_class_enforced: AtomicBool,
    /// Full passes completed.
    pub passes: AtomicU64,
    /// Passes that ran with the heartbeat epoch ahead of the map epoch by
    /// at most the tolerance (`pg_purge::EPOCH_SKEW_TOLERANCE`).
    pub epoch_skew_tolerated: AtomicU64,
    /// Passes refused before their first page because the heartbeat epoch
    /// and the map epoch disagreed by more than the tolerance.
    pub epoch_skew_aborts: AtomicU64,
    /// Passes refused before their first page because the filter was not
    /// built from the enforced generation's lists.
    pub filter_generation_refusals: AtomicU64,
    /// Loop ticks refused because this miner's uid is not in the held
    /// map: clause 0 of the purge rule. Exposed as
    /// `purge_refused_not_in_map_total`.
    pub refused_not_in_map: AtomicU64,
    /// Loop ticks refused because the held map lists this miner as
    /// draining or under a placement hold: clause 0. Exposed as
    /// `purge_refused_not_placeable_total`.
    pub refused_not_placeable: AtomicU64,
    /// Passes stopped because the loaded lists no longer covered the
    /// protected set (a PG gained, a generation dropped, a delta chain
    /// broken). Exposed as `purge_coverage_lost_aborts_total`.
    pub coverage_lost_aborts: AtomicU64,
    /// Passes refused or stopped because the view's newest signed cut was
    /// older than `PURGE_VIEW_MAX_LAG_SECS`. Exposed as
    /// `purge_view_stale_refusals_total`.
    pub view_stale_refusals: AtomicU64,
    /// Gauge: PGs in the protected set (owned now or within the ownership
    /// window). Exposed as `purge_protected_pgs`.
    pub protected_pgs: AtomicU64,
    /// Gauge: 1 once the ownership window has been tracked for
    /// `PURGE_OWNERSHIP_STABLE_SECS`. Exposed as
    /// `purge_ownership_window_tracked`.
    pub ownership_window_tracked: AtomicBool,
    /// Gauge: 1 once the ownership observer task has ended (it never ends
    /// in normal operation: a panic or a bug). The purge is then closed.
    /// Exposed as `purge_ownership_observer_down`.
    pub ownership_observer_down: AtomicBool,
    /// Highest delta seq folded into the loaded generation (0 = base only).
    pub delta_seq: AtomicU64,
    /// 1 while the loaded generation's delta chain has a link that failed
    /// to chain, fetch, verify or apply (coverage incomplete, gate closed).
    pub delta_chain_broken: AtomicBool,
    /// Gauges of the last dry-run census over an incompletely covered
    /// generation (`pg_purge::run_census`), published as
    /// `purge_census_*`. Zero until a census ran; refreshed while one is
    /// running. The orphan classes are an upper bound: a blob of an
    /// uncovered PG is indistinguishable from an orphan.
    pub census: CensusGauges,
}

/// Snapshot of one census (see [`PurgeMetrics::census`]).
#[derive(Debug, Default)]
pub struct CensusGauges {
    /// Generation the census read (0 = none yet).
    pub generation: AtomicU64,
    pub covered_pgs: AtomicU64,
    pub missing_pgs: AtomicU64,
    pub examined: AtomicU64,
    pub protected_blobs: AtomicU64,
    pub moved_blobs: AtomicU64,
    pub tombstone_blobs: AtomicU64,
    pub tombstone_bytes: AtomicU64,
    pub orphan_gated_blobs: AtomicU64,
    pub orphan_gated_bytes: AtomicU64,
    pub orphan_pending_blobs: AtomicU64,
    pub orphan_pending_bytes: AtomicU64,
    pub invalid_hash: AtomicU64,
    pub absent_from_store: AtomicU64,
    pub absent_rows_dropped: AtomicU64,
    /// 1 when the last census read every inventory page (no epoch abort,
    /// no filter refusal); 0 while running or when it stopped early.
    pub complete: AtomicBool,
}

impl PurgeMetrics {
    pub fn set_coverage(&self, owned: u64, listed: u64) {
        self.coverage_pgs_owned.store(owned, Ordering::Relaxed);
        self.coverage_pgs_listed.store(listed, Ordering::Relaxed);
        self.coverage_complete
            .store(listed == owned, Ordering::Relaxed);
    }

    /// One `name value` line per counter, Prometheus text format, for
    /// whichever exposition the host wires up.
    pub fn render_prometheus(&self) -> String {
        let g = |v: &AtomicU64| v.load(Ordering::Relaxed);
        format!(
            "miner_purge_candidates_total {}\n\
             miner_purge_purged_total {}\n\
             miner_purge_purged_bytes_total {}\n\
             miner_purge_would_purge_total {}\n\
             miner_purge_would_purge_bytes_total {}\n\
             purge_tombstone_candidates_total {}\n\
             purge_tombstone_deleted_total {}\n\
             purge_tombstone_deleted_bytes_total {}\n\
             purge_tombstone_would_purge_total {}\n\
             purge_tombstone_retained_fresh_store_total {}\n\
             purge_tombstone_retained_live_ref {}\n\
             miner_purge_kept_by_filter_total {}\n\
             miner_purge_kept_moved_total {}\n\
             miner_purge_skipped_young_total {}\n\
             miner_purge_skipped_inflight_total {}\n\
             purge_skipped_view_busy_total {}\n\
             miner_purge_invalid_hash_total {}\n\
             miner_purge_absent_from_store_total {}\n\
             miner_purge_absent_rows_dropped_total {}\n\
             miner_purge_vanished_total {}\n\
             miner_purge_delete_errors_total {}\n\
             miner_purge_coverage_pgs_listed {}\n\
             miner_purge_coverage_pgs_owned {}\n\
             miner_purge_coverage_complete {}\n\
             miner_purge_generation {}\n\
             miner_purge_filter_hashes {}\n\
             miner_purge_filter_bytes {}\n\
             miner_purge_moved_class_enforced {}\n\
             miner_purge_passes_total {}\n\
             miner_purge_epoch_skew_tolerated_total {}\n\
             miner_purge_epoch_skew_aborts_total {}\n\
             miner_purge_filter_generation_refusals_total {}\n\
             purge_refused_not_in_map_total {}\n\
             purge_refused_not_placeable_total {}\n\
             purge_coverage_lost_aborts_total {}\n\
             purge_view_stale_refusals_total {}\n\
             purge_protected_pgs {}\n\
             purge_ownership_window_tracked {}\n\
             purge_ownership_observer_down {}\n\
             miner_purge_delta_seq {}\n\
             miner_purge_delta_chain_broken {}\n\
             purge_census_generation {}\n\
             purge_census_covered_pgs {}\n\
             purge_census_missing_pgs {}\n\
             purge_census_examined {}\n\
             purge_census_protected_blobs {}\n\
             purge_census_moved_blobs {}\n\
             purge_census_tombstone_blobs {}\n\
             purge_census_tombstone_bytes {}\n\
             purge_census_orphan_gated_blobs {}\n\
             purge_census_orphan_gated_bytes {}\n\
             purge_census_orphan_pending_blobs {}\n\
             purge_census_orphan_pending_bytes {}\n\
             purge_census_invalid_hash {}\n\
             purge_census_absent_from_store {}\n\
             purge_census_absent_rows_dropped {}\n\
             purge_census_complete {}\n",
            g(&self.candidates),
            g(&self.purged),
            g(&self.purged_bytes),
            g(&self.would_purge),
            g(&self.would_purge_bytes),
            g(&self.tombstone_candidates),
            g(&self.tombstone_deleted),
            g(&self.tombstone_deleted_bytes),
            g(&self.tombstone_would_purge),
            g(&self.tombstone_retained_fresh_store),
            g(&self.tombstone_retained_live_ref),
            g(&self.kept_by_filter),
            g(&self.kept_moved),
            g(&self.skipped_young),
            g(&self.skipped_inflight),
            g(&self.skipped_view_busy),
            g(&self.invalid_hash),
            g(&self.absent_from_store),
            g(&self.absent_rows_dropped),
            g(&self.vanished),
            g(&self.delete_errors),
            g(&self.coverage_pgs_listed),
            g(&self.coverage_pgs_owned),
            u8::from(self.coverage_complete.load(Ordering::Relaxed)),
            g(&self.generation),
            g(&self.filter_hashes),
            g(&self.filter_bytes),
            u8::from(self.moved_class_enforced.load(Ordering::Relaxed)),
            g(&self.passes),
            g(&self.epoch_skew_tolerated),
            g(&self.epoch_skew_aborts),
            g(&self.filter_generation_refusals),
            g(&self.refused_not_in_map),
            g(&self.refused_not_placeable),
            g(&self.coverage_lost_aborts),
            g(&self.view_stale_refusals),
            g(&self.protected_pgs),
            u8::from(self.ownership_window_tracked.load(Ordering::Relaxed)),
            u8::from(self.ownership_observer_down.load(Ordering::Relaxed)),
            g(&self.delta_seq),
            u8::from(self.delta_chain_broken.load(Ordering::Relaxed)),
            g(&self.census.generation),
            g(&self.census.covered_pgs),
            g(&self.census.missing_pgs),
            g(&self.census.examined),
            g(&self.census.protected_blobs),
            g(&self.census.moved_blobs),
            g(&self.census.tombstone_blobs),
            g(&self.census.tombstone_bytes),
            g(&self.census.orphan_gated_blobs),
            g(&self.census.orphan_gated_bytes),
            g(&self.census.orphan_pending_blobs),
            g(&self.census.orphan_pending_bytes),
            g(&self.census.invalid_hash),
            g(&self.census.absent_from_store),
            g(&self.census.absent_rows_dropped),
            u8::from(self.census.complete.load(Ordering::Relaxed)),
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;

    const OPEN: PurgeGate = PurgeGate {
        miner_eligible: true,
        generation_loaded: true,
        generation_fresh: true,
        coverage_complete: true,
        ownership_window_tracked: true,
    };

    /// Clause 0: a miner absent from the held map closes the gate before
    /// any other clause is consulted, and an otherwise obviously stray
    /// blob is kept.
    #[test]
    fn miner_absent_from_the_map_closes_the_gate_before_every_other_clause() {
        let stray = Candidate {
            age_secs: 86_400 * 30,
            in_filter: false,
            tombstoned: false,
            moved: false,
            stored_after_snapshot: false,
            inflight: false,
        };
        let empty = PurgeGate {
            miner_eligible: false,
            ..OPEN
        };
        assert!(!empty.open());
        assert_eq!(decide(empty, stray, 3600), Verdict::KeepMinerNotEligible);
        // Wins over every other closed clause too.
        assert_eq!(
            decide(
                PurgeGate {
                    miner_eligible: false,
                    generation_loaded: false,
                    generation_fresh: false,
                    coverage_complete: false,
                    ownership_window_tracked: false,
                },
                stray,
                3600
            ),
            Verdict::KeepMinerNotEligible
        );
        let m = PurgeMetrics::default();
        m.refused_not_in_map.fetch_add(1, Ordering::Relaxed);
        assert!(
            m.render_prometheus()
                .contains("purge_refused_not_in_map_total 1\n")
        );
    }

    #[test]
    fn stale_generation_is_kept_before_coverage_is_even_looked_at() {
        let c = Candidate {
            age_secs: 86_400 * 30,
            in_filter: false,
            tombstoned: false,
            moved: false,
            stored_after_snapshot: false,
            inflight: false,
        };
        let stale = PurgeGate {
            generation_fresh: false,
            coverage_complete: false,
            ownership_window_tracked: false,
            ..OPEN
        };
        assert_eq!(decide(stale, c, 3600), Verdict::KeepGenerationStale);
        assert_eq!(
            decide(
                PurgeGate {
                    generation_loaded: false,
                    ..stale
                },
                c,
                3600
            ),
            Verdict::KeepNoGeneration
        );
        assert!(!stale.open());
        // Exactly max age is fresh, one second more is stale; a clock
        // behind the manifest is age zero.
        assert!(generation_is_fresh(1_000, 1_000 + 7 * 86_400, 7 * 86_400));
        assert!(!generation_is_fresh(1_000, 1_001 + 7 * 86_400, 7 * 86_400));
        assert!(generation_is_fresh(2_000, 1_000, 0));
    }

    #[test]
    fn purge_decision_table() {
        // (generation_loaded, coverage_complete, ownership_stable, in_filter,
        //  age_secs, inflight) -> verdict, with min_age = 3600 and a
        //  fresh generation.
        let table: &[(bool, bool, bool, bool, u64, bool, Verdict)] = &[
            // Every clause satisfied.
            (true, true, true, false, 3600, false, Verdict::Purge),
            (true, true, true, false, 86_400, false, Verdict::Purge),
            // Global gates, in precedence order.
            (
                false,
                true,
                true,
                false,
                86_400,
                false,
                Verdict::KeepNoGeneration,
            ),
            (
                false,
                false,
                false,
                false,
                86_400,
                false,
                Verdict::KeepNoGeneration,
            ),
            (
                true,
                false,
                true,
                false,
                86_400,
                false,
                Verdict::KeepCoverageIncomplete,
            ),
            (
                true,
                false,
                false,
                false,
                86_400,
                false,
                Verdict::KeepCoverageIncomplete,
            ),
            (
                true,
                true,
                false,
                false,
                86_400,
                false,
                Verdict::KeepOwnershipWindowUntracked,
            ),
            // Per-blob clauses.
            (true, true, true, true, 86_400, false, Verdict::KeepInList),
            (true, true, true, true, 0, true, Verdict::KeepInList),
            (true, true, true, false, 3599, false, Verdict::KeepYoung),
            (true, true, true, false, 0, false, Verdict::KeepYoung),
            (true, true, true, false, 3599, true, Verdict::KeepYoung),
            (true, true, true, false, 86_400, true, Verdict::KeepInflight),
            // A closed gate wins over a blob that is otherwise obviously stray.
            (
                false,
                true,
                true,
                false,
                86_400,
                true,
                Verdict::KeepNoGeneration,
            ),
            (
                true,
                false,
                true,
                true,
                0,
                true,
                Verdict::KeepCoverageIncomplete,
            ),
        ];
        for &(loaded, covered, stable, in_filter, age, inflight, want) in table {
            let gate = PurgeGate {
                miner_eligible: true,
                generation_loaded: loaded,
                generation_fresh: true,
                coverage_complete: covered,
                ownership_window_tracked: stable,
            };
            let candidate = Candidate {
                age_secs: age,
                in_filter,
                tombstoned: false,
                moved: false,
                stored_after_snapshot: false,
                inflight,
            };
            assert_eq!(
                decide(gate, candidate, 3600),
                want,
                "gate={gate:?} candidate={candidate:?}"
            );
        }
    }

    #[test]
    fn min_age_zero_purges_fresh_blobs() {
        let c = Candidate {
            age_secs: 0,
            in_filter: false,
            tombstoned: false,
            moved: false,
            stored_after_snapshot: false,
            inflight: false,
        };
        assert_eq!(decide(OPEN, c, 0), Verdict::Purge);
    }

    /// Tombstoned: no age clause, but the list (even a false positive)
    /// and an in-flight write still keep; the global gates still apply.
    #[test]
    fn tombstoned_blob_skips_age_but_not_list_inflight_or_gates() {
        let young_tombstoned = Candidate {
            age_secs: 0,
            in_filter: false,
            tombstoned: true,
            moved: false,
            stored_after_snapshot: false,
            inflight: false,
        };
        assert_eq!(
            decide(OPEN, young_tombstoned, 14 * 86_400),
            Verdict::PurgeTombstoned
        );
        let same_without_tombstone = Candidate {
            tombstoned: false,
            moved: false,
            ..young_tombstoned
        };
        assert_eq!(
            decide(OPEN, same_without_tombstone, 14 * 86_400),
            Verdict::KeepYoung
        );
        assert_eq!(
            decide(
                OPEN,
                Candidate {
                    in_filter: true,
                    ..young_tombstoned
                },
                14 * 86_400
            ),
            Verdict::KeepInList
        );
        assert_eq!(
            decide(
                OPEN,
                Candidate {
                    inflight: true,
                    ..young_tombstoned
                },
                14 * 86_400
            ),
            Verdict::KeepInflight
        );
        // Written at or after the scan start: a reference the writer
        // could not have seen (a re-upload of the same content refreshes
        // stored_at on the same hash). Kept, before the in-flight clause,
        // whatever min_age says (even 0).
        for inflight in [false, true] {
            assert_eq!(
                decide(
                    OPEN,
                    Candidate {
                        stored_after_snapshot: true,
                        inflight,
                        ..young_tombstoned
                    },
                    0
                ),
                Verdict::KeepStoredAfterSnapshot
            );
        }
        // Without the tombstone the same fact is just a young orphan.
        assert_eq!(
            decide(
                OPEN,
                Candidate {
                    stored_after_snapshot: true,
                    ..same_without_tombstone
                },
                14 * 86_400
            ),
            Verdict::KeepYoung
        );
        let closed = PurgeGate {
            ownership_window_tracked: false,
            ..OPEN
        };
        assert_eq!(
            decide(closed, young_tombstoned, 14 * 86_400),
            Verdict::KeepOwnershipWindowUntracked
        );
    }

    /// Moved: retained whatever its age, tombstone or in-flight state
    /// (nothing is deleted, so there is nothing for those clauses to
    /// guard); a list hit still names the list; the global gates still
    /// answer first.
    #[test]
    fn moved_blob_is_retained_before_tombstone_and_age() {
        let moved = Candidate {
            age_secs: 365 * 86_400,
            in_filter: false,
            tombstoned: false,
            moved: true,
            stored_after_snapshot: false,
            inflight: false,
        };
        assert_eq!(decide(OPEN, moved, 0), Verdict::KeepMoved);
        assert_eq!(
            decide(
                OPEN,
                Candidate {
                    tombstoned: true,
                    ..moved
                },
                0
            ),
            Verdict::KeepMoved,
            "a hash with a live record in an owned PG is never in the tombstone class"
        );
        assert_eq!(
            decide(
                OPEN,
                Candidate {
                    inflight: true,
                    ..moved
                },
                0
            ),
            Verdict::KeepMoved
        );
        assert_eq!(
            decide(
                OPEN,
                Candidate {
                    in_filter: true,
                    ..moved
                },
                0
            ),
            Verdict::KeepInList
        );
        assert_eq!(
            decide(
                PurgeGate {
                    coverage_complete: false,
                    ..OPEN
                },
                moved,
                0
            ),
            Verdict::KeepCoverageIncomplete
        );
        // The rollback: with the class off the caller passes `moved:
        // false` and the same blob is an orphan again.
        assert_eq!(
            decide(
                OPEN,
                Candidate {
                    moved: false,
                    ..moved
                },
                0
            ),
            Verdict::Purge
        );
    }

    #[test]
    fn moved_class_config_flag() {
        let cfg = PurgeConfig::from_lookup(|_| None).unwrap();
        assert!(cfg.moved_class, "on by default: retaining is the safe side");
        assert_eq!(cfg.lists_cache_dir, None, "not read from the environment");
        let mut env = HashMap::new();
        env.insert("PURGE_MOVED_CLASS", "off");
        // A removed knob is warned about and ignored, never an error.
        env.insert("PURGE_OTHERS_FILTER_MAX_BYTES", "0");
        let cfg = PurgeConfig::from_lookup(|k| env.get(k).map(|v| v.to_string())).unwrap();
        assert!(!cfg.moved_class);
        env.insert("PURGE_MOVED_CLASS", "on");
        assert!(
            PurgeConfig::from_lookup(|k| env.get(k).map(|v| v.to_string()))
                .unwrap()
                .moved_class
        );
        env.insert("PURGE_MOVED_CLASS", "maybe");
        assert!(
            PurgeConfig::from_lookup(|k| env.get(k).map(|v| v.to_string())).is_err(),
            "a class switch takes the strict boolean syntax"
        );
    }

    #[test]
    fn config_defaults_enforce_on_the_public_bucket() {
        let cfg = PurgeConfig::from_lookup(|_| None).unwrap();
        assert_eq!(cfg, PurgeConfig::default());
        assert!(cfg.enabled);
        assert_eq!(cfg.mode, Mode::default_for_build());
        assert_eq!(
            cfg.mode.enforces(),
            ENFORCEMENT_COMPILED,
            "unset PURGE_DRY_RUN deletes exactly when the build can"
        );
        let census =
            PurgeConfig::from_lookup(|n| (n == "PURGE_DRY_RUN").then(|| "true".into())).unwrap();
        assert!(
            census.mode.is_census(),
            "PURGE_DRY_RUN=true keeps the census"
        );
        assert_eq!(cfg.base_url.as_deref(), Some(DEFAULT_PG_LISTS_BASE_URL));
        assert_eq!(
            cfg.min_age_secs,
            14 * 86_400,
            "14 days: the writer's scan spans days"
        );
        assert_eq!(
            cfg.ownership_stable_secs, 21_600,
            "6 h per-PG ownership window"
        );
        assert_eq!(cfg.rate_per_sec, 50);
        assert_eq!(cfg.max_bytes_per_sec, 50 * 1024 * 1024);
        assert_eq!(cfg.generation_max_age_secs, 7 * 86_400);
    }

    #[test]
    fn config_empty_base_url_or_disabled_turns_the_purge_off() {
        let cfg =
            PurgeConfig::from_lookup(|n| (n == "PG_LISTS_BASE_URL").then(|| " ".into())).unwrap();
        assert_eq!(cfg.base_url, None, "an empty URL leaves no source");
        let cfg =
            PurgeConfig::from_lookup(|n| (n == "PURGE_ENABLED").then(|| "false".into())).unwrap();
        assert!(!cfg.enabled);
    }

    #[test]
    fn config_reads_every_variable_and_ignores_garbage() {
        let vars: HashMap<&str, &str> = HashMap::from([
            (
                "PG_LISTS_BASE_URL",
                " https://bucket.example/pg-inventory/ ",
            ),
            ("PURGE_ENABLED", "true"),
            ("PURGE_DRY_RUN", "false"),
            ("PURGE_MIN_AGE_SECS", "120"),
            ("PURGE_RATE_PER_SEC", "0"),
            ("PURGE_MAX_BYTES_PER_SEC", "1048576"),
            ("PG_LISTS_POLL_SECS", "1"),
            ("PURGE_OWNERSHIP_STABLE_SECS", "notanumber"),
            ("PURGE_EPOCH_STABLE_SECS", "86400"),
            ("PURGE_FILTER_FP", "0.001"),
            ("PG_LISTS_FETCH_CONCURRENCY", "999"),
            ("PURGE_FILTER_MAX_BYTES", "4096"),
            ("PURGE_PASS_INTERVAL_SECS", "30"),
            ("PURGE_GENERATION_MAX_AGE_SECS", "600"),
        ]);
        let cfg = PurgeConfig::from_lookup(|n| vars.get(n).map(|v| v.to_string())).unwrap();
        assert_eq!(
            cfg.base_url.as_deref(),
            Some("https://bucket.example/pg-inventory/")
        );
        assert!(cfg.enabled);
        assert_eq!(cfg.mode, Mode::from_dry_run(false));
        assert_eq!(cfg.mode.enforces(), ENFORCEMENT_COMPILED);
        assert_eq!(cfg.min_age_secs, 120);
        assert_eq!(cfg.rate_per_sec, 1, "zero rate is clamped to 1");
        assert_eq!(cfg.max_bytes_per_sec, 1_048_576);
        assert_eq!(cfg.poll_secs, 10, "poll floor");
        assert_eq!(
            cfg.ownership_stable_secs, 21_600,
            "garbage keeps the default; the deprecated epoch knob is ignored"
        );
        assert_eq!(cfg.fetch_concurrency, 8, "concurrency ceiling");
        assert_eq!(cfg.pass_interval_secs, 30);
        assert_eq!(cfg.generation_max_age_secs, 600);
    }

    #[test]
    fn booleans_accept_exactly_the_documented_spellings() {
        for raw in ["1", "true", "TRUE", " True ", "yes", "YES", "on", "On"] {
            assert_eq!(parse_bool(raw), Some(true), "{raw:?}");
        }
        for raw in ["0", "false", "FALSE", " False ", "no", "NO", "off", "Off"] {
            assert_eq!(parse_bool(raw), Some(false), "{raw:?}");
        }
        for raw in ["", " ", "2", "t", "y", "enabled", "maybe", "1.0", "on off"] {
            assert_eq!(parse_bool(raw), None, "{raw:?}");
        }
    }

    #[test]
    fn config_refuses_unparseable_booleans_and_accepts_every_spelling() {
        // Every spelling works for both switches.
        let cfg = PurgeConfig::from_lookup(|n| match n {
            "PURGE_ENABLED" => Some("1".into()),
            "PURGE_DRY_RUN" => Some("off".into()),
            _ => None,
        })
        .unwrap();
        assert!(cfg.enabled, "PURGE_ENABLED=1 must enable");
        assert_eq!(
            cfg.mode.enforces(),
            ENFORCEMENT_COMPILED,
            "PURGE_DRY_RUN=off asks for enforcement; only a purge-enforce build grants it"
        );
        let cfg = PurgeConfig::from_lookup(|n| match n {
            "PURGE_ENABLED" => Some("yes".into()),
            "PURGE_DRY_RUN" => Some("0".into()),
            _ => None,
        })
        .unwrap();
        assert!(cfg.enabled);
        assert_eq!(cfg.mode.enforces(), ENFORCEMENT_COMPILED);
        // A value outside the syntax is an error, never a default, for
        // either switch, even when the other one is valid.
        for (name, raw) in [
            ("PURGE_ENABLED", "enabled"),
            ("PURGE_ENABLED", "2"),
            ("PURGE_DRY_RUN", "maybe"),
            ("PURGE_DRY_RUN", ""),
        ] {
            let err = PurgeConfig::from_lookup(|n| {
                if n == name {
                    Some(raw.to_string())
                } else {
                    Some("true".to_string()).filter(|_| n == "PURGE_ENABLED")
                }
            })
            .unwrap_err();
            let text = err.to_string();
            assert!(text.contains(name) && text.contains(raw), "{text}");
        }
    }

    #[tokio::test(start_paused = true)]
    async fn rate_limiter_bounds_operations_per_second() {
        let mut limiter = RateLimiter::new(10, u64::MAX / 4);
        let start = Instant::now();
        // The bucket starts full: 10 immediate, then 10/s.
        for _ in 0..30 {
            limiter.acquire(1).await;
        }
        let elapsed = start.elapsed().as_secs_f64();
        assert!(
            (1.9..=2.2).contains(&elapsed),
            "30 ops at 10/s took {elapsed}s"
        );
    }

    #[tokio::test(start_paused = true)]
    async fn rate_limiter_bounds_bytes_per_second() {
        let mut limiter = RateLimiter::new(1_000_000, 1000);
        let start = Instant::now();
        // 1000 B budget/s, first second free: 5 × 500 B = 2500 B -> ~1.5 s.
        for _ in 0..5 {
            limiter.acquire(500).await;
        }
        let elapsed = start.elapsed().as_secs_f64();
        assert!(
            (1.4..=1.7).contains(&elapsed),
            "2500 B at 1000 B/s took {elapsed}s"
        );
    }

    #[tokio::test(start_paused = true)]
    async fn rate_limiter_admits_oversized_blob_then_pays_it_back() {
        let mut limiter = RateLimiter::new(1_000_000, 1000);
        let start = Instant::now();
        limiter.acquire(5000).await; // admitted immediately on a full bucket
        assert!(start.elapsed().as_secs_f64() < 0.01);
        limiter.acquire(1).await; // must wait for the 4000 B of debt + 1
        let elapsed = start.elapsed().as_secs_f64();
        assert!(
            (3.9..=4.2).contains(&elapsed),
            "debt repayment took {elapsed}s"
        );
    }

    #[test]
    fn metrics_render_and_coverage_gauge() {
        let m = PurgeMetrics::default();
        m.set_coverage(1600, 1599);
        assert!(!m.coverage_complete.load(Ordering::Relaxed));
        m.set_coverage(1600, 1600);
        assert!(m.coverage_complete.load(Ordering::Relaxed));
        m.purged.fetch_add(3, Ordering::Relaxed);
        let text = m.render_prometheus();
        assert!(text.contains("miner_purge_purged_total 3\n"));
        assert!(text.contains("miner_purge_coverage_pgs_owned 1600\n"));
        assert!(text.contains("miner_purge_coverage_complete 1\n"));
        m.kept_moved.fetch_add(2, Ordering::Relaxed);
        m.moved_class_enforced.store(true, Ordering::Relaxed);
        let text = m.render_prometheus();
        assert!(text.contains("miner_purge_kept_moved_total 2\n"));
        assert!(text.contains("miner_purge_moved_class_enforced 1\n"));
        assert!(!text.contains("others_filter"), "series removed");
    }

    #[test]
    fn ownership_window_protects_lost_pgs_for_the_window_only() {
        let window = 6 * 3600;
        let t0 = 1_700_000_000u64;
        let mut w = OwnershipWindow::new(t0);
        assert!(!w.is_tracked(t0, window), "a fresh window is not tracked");
        let obs = w.observe(&[3, 1, 2, 2], t0, window);
        assert_eq!(
            obs,
            WindowObservation {
                gained: 3,
                lost: 0,
                expired: 0
            }
        );
        assert_eq!(w.owned(), &[1, 2, 3]);
        assert_eq!(w.protected(t0, window), vec![1, 2, 3]);

        // PG 2 lost at t0 + 60 (last owned at t0).
        let obs = w.observe(&[1, 3], t0 + 60, window);
        assert_eq!((obs.gained, obs.lost, obs.expired), (0, 1, 0));
        assert!(!obs.membership_changed(), "a loss inside the window");
        assert_eq!(w.entry(2), Some((t0, t0)));
        // Five hours later: still protected, though not owned.
        let t5h = t0 + 5 * 3600;
        w.observe(&[1, 3], t5h, window);
        assert_eq!(w.protected(t5h, window), vec![1, 2, 3]);
        // Seven hours later: out of the window, dropped.
        let t7h = t0 + 7 * 3600;
        let obs = w.observe(&[1, 3], t7h, window);
        assert_eq!(obs.expired, 1);
        assert!(obs.membership_changed());
        assert_eq!(w.protected(t7h, window), vec![1, 3]);
        assert_eq!(w.entry(2), None);

        // A PG gained is protected at once, with its own first_owned_at.
        let obs = w.observe(&[1, 3, 9], t7h + 10, window);
        assert_eq!(obs.gained, 1);
        assert_eq!(w.protected(t7h + 10, window), vec![1, 3, 9]);
        assert_eq!(w.entry(9), Some((t7h + 10, t7h + 10)));
        assert_eq!(w.entry(1), Some((t0, t7h + 10)), "first kept, last moves");

        // The window is a set of per-PG clocks: churn at every observation
        // never resets the tracking, which opened after one window.
        assert!(w.is_tracked(t0 + window, window));
        for i in 0..50u32 {
            w.observe(&[1, 3, 100 + i], t7h + 100 + u64::from(i) * 900, window);
        }
        assert!(w.is_tracked(t7h + 100 + 49 * 900, window));
        assert_eq!(w.tracking_since(), t0);

        // A clock step backwards does not shorten a PG's protection.
        let before = w.entry(1).unwrap().1;
        w.observe(&[1], before - 3600, window);
        assert_eq!(w.entry(1).unwrap().1, before);
    }

    #[test]
    fn ownership_window_round_trips_migrates_v1_and_refuses_garbage() {
        let window = 21_600;
        let t0 = 1_700_000_000u64;
        let mut w = OwnershipWindow::new(t0);
        w.observe(&[5, 7, 9], t0, window);
        w.observe(&[5, 9], t0 + 100, window);
        let text = w.encode();
        assert_eq!(
            text,
            format!(
                "v3 {t0} {}\n5 {t0} {}\n7 {t0} {t0}\n9 {t0} {}\nowned 5 9\n",
                t0 + 100,
                t0 + 100,
                t0 + 100
            )
        );
        let (back, how) = OwnershipWindow::decode(&text, t0 + 200).unwrap();
        assert_eq!(how, WindowDecoded::Current);
        assert_eq!(back, w);
        // Restart: the lost PG keeps its clock, it is not re-timed.
        assert_eq!(back.protected(t0 + window, window), vec![5, 7, 9]);
        assert_eq!(back.protected(t0 + window + 3600, window), vec![5, 9]);

        // The former whole-set state: every PG is protected for a full
        // window from the load, and the tracking restarts (the file does
        // not say what was lost before `changed_at`).
        let load_at = t0 + 50_000;
        let (m, how) = OwnershipWindow::decode(&format!("v1 {t0}\n1 2 3\n"), load_at).unwrap();
        assert_eq!(how, WindowDecoded::MigratedFromV1);
        assert_eq!(m.owned(), &[1, 2, 3]);
        assert_eq!(m.entry(2), Some((t0, load_at)));
        assert_eq!(m.tracking_since(), load_at);
        assert!(!m.is_tracked(load_at + window - 1, window));
        assert!(m.is_tracked(load_at + window, window));
        // The migrated PGs stay protected for the window after the load
        // even when the next observation owns none of them.
        let mut m2 = m.clone();
        m2.observe(&[4], load_at + 60, window);
        assert_eq!(m2.protected(load_at + 60, window), vec![1, 2, 3, 4]);
        // An empty v1 set migrates too.
        let (e, _) = OwnershipWindow::decode(&format!("v1 {t0}\n\n"), load_at).unwrap();
        assert!(e.is_empty());

        let empty = OwnershipWindow::new(5);
        assert_eq!(
            OwnershipWindow::decode(&empty.encode(), 5).unwrap().0,
            empty
        );
        // The previous per-PG format: owned until the load, tracking
        // restarted there.
        let v2 = format!("v2 {t0}\n5 {t0} {}\n7 {t0} {t0}\nowned 5\n", t0 + 100);
        let (m, how) = OwnershipWindow::decode(&v2, load_at).unwrap();
        assert_eq!(how, WindowDecoded::MigratedFromV2);
        assert_eq!(m.entry(7), Some((t0, load_at)));
        assert_eq!(m.tracking_since(), load_at);
        assert_eq!(m.protected(load_at + window, window), vec![5, 7]);

        for bad in [
            "",
            "v3 1\nowned\n",
            "v3 1 x\nowned\n",
            "v3 1 2 3\nowned\n",
            "v4 1 2\nowned\n",
            "v2\nowned\n",
            "v2 x\nowned\n",
            "v2 1\n1 2\nowned 1\n",
            "v2 1\n1 5 4\nowned 1\n",
            "v2 1\n1 2 3\n1 2 3\nowned 1\n",
            "v2 1\n1 2 3\n",
            "v2 1\n1 2 3\nowned 2\n",
            "v2 1\n1 2 3\nowned 1\n2 3 4\n",
            "v1 x\n1\n",
            "v1 1 2\n1\n",
            "v1 1\n1 two\n",
            "v1 1\n1\nextra\n",
        ] {
            assert!(
                OwnershipWindow::decode(bad, 10).is_none(),
                "{bad:?} must not decode"
            );
        }
    }

    /// Purge ownership is the straw2 placement alone; the union
    /// `calculate_my_pgs` also counts the v2 placement.
    #[test]
    fn purge_ownership_is_v3_only() {
        let map = crate::backfill::tests::test_map(40);
        let shards = map.ec_k + map.ec_m;
        for uid in [0u32, 7, 39] {
            let purge_pgs = calculate_purge_pgs(uid, &map);
            let union = common::calculate_my_pgs(uid, &map);
            let v3: Vec<u32> = (0..map.pg_count)
                .filter(|pg| {
                    common::calculate_pg_placement_straw2(*pg, shards, &map)
                        .unwrap()
                        .iter()
                        .any(|m| m.uid == uid)
                })
                .collect();
            let v2_only: Vec<u32> = union
                .iter()
                .copied()
                .filter(|pg| v3.binary_search(pg).is_err())
                .collect();
            assert_eq!(purge_pgs, v3, "uid {uid}");
            assert!(!purge_pgs.is_empty());
            assert!(
                !v2_only.is_empty(),
                "uid {uid}: the fixture must own some PG under v2 alone"
            );
            assert!(purge_pgs.iter().all(|pg| union.contains(pg)));
            assert!(purge_pgs.len() < union.len());
        }
        // A draining miner is filtered out like on the write path.
        let mut draining = map.clone();
        draining.miners[7].draining = true;
        assert!(calculate_purge_pgs(7, &draining).is_empty());
    }
}

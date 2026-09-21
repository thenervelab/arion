//! Obligation-list purge policy: what may be deleted, how fast, and the
//! counters that describe it. Pure logic — the background loop that walks
//! the inventory and drives the store lives in the binary (`pg_purge`).
//!
//! ## Purge rule
//!
//! A live blob is purgeable iff, in this order:
//! 0. this miner owns at least one PG ([`PurgeGate::ownership_nonempty`]).
//!    A miner with CRUSH weight 0 (connectivity quarantine, declared
//!    full, duplicate address, absence) owns NO PG, and an empty owned
//!    set makes every later clause vacuous: coverage is trivially
//!    complete, the filter is empty, every blob is a filter miss. Such a
//!    pass would empty the store of a node that gets its weight back an
//!    hour later. The pass is refused, logged once per generation with
//!    the map epoch and this miner's weight, and counted
//!    (`purge_refused_empty_ownership_total`),
//! 1. a valid generation is loaded ([`PurgeGate::generation_loaded`]),
//! 2. that generation is not stale ([`PurgeGate::generation_fresh`]): its
//!    `created_at` is at most `generation_max_age_secs` in the past — a
//!    bucket nobody publishes to any more must not drive deletions,
//! 3. that generation covers EVERY PG this miner owns
//!    ([`PurgeGate::coverage_complete`]) — an unknown PG means nothing is
//!    purged, because its blobs cannot be told apart from stray ones,
//! 4. the set of PGs this miner owns has been IDENTICAL for
//!    `ownership_stable_secs` ([`PurgeGate::ownership_stable`], tracked by
//!    [`OwnershipStability`], persisted across restarts) — what the gate
//!    protects is a PG this miner just lost or just gained (its
//!    obligations changed), which is a property of its own owned set,
//!    not of the global epoch counter (on a live network an epoch moves
//!    every few minutes without touching most miners' ownership; a gate
//!    on epoch quiet never opened there). The same period applies to
//!    the owned set's adoption ([`OwnershipHysteresis`]): an ownership
//!    that SHRINKS by more than half between two consecutive polls (9000
//!    → 0, 9000 → 3000) is not adopted for purge decisions until it has
//!    held for `ownership_stable_secs`; the previous owned set stays in
//!    force meanwhile, so a flap (9000 → 0 → 9000) never widens what may
//!    be purged,
//! 5. the blob hash is in none of the owned PGs' lists (filter miss; a
//!    filter hit is a keep even when it is a false positive),
//! 6. **moved class**: if the hash is listed in an owned PG under
//!    ANOTHER holder (the "others" filter, a second Bloom over the
//!    records that are not this miner's; a false positive is a keep) the
//!    blob is a live shard of a live file that some other miner is
//!    obliged to hold, and this copy is RETAINED: nothing in the lists
//!    proves the other holder actually has it, and the only proof source
//!    this rule may ever take is the storage-proof observation stream
//!    (not wired in this release). The class exists so the
//!    tombstone and orphan classes never apply to such a blob; it is
//!    switched off by `PURGE_MOVED_CLASS=false` only (back to clause 7/8
//!    behaviour); a generation whose others filter would exceed
//!    `PURGE_OTHERS_FILTER_MAX_BYTES` is REFUSED at load (logged,
//!    counted in `miner_purge_others_filter_cap_refusals_total`), never
//!    enforced with the class silently off,
//! 7. **tombstone class**: if the hash is in an owned PG's `.deleted`
//!    (the writer saw its file deleted inside the generation's window;
//!    exact set, no false positive) AND no record of the enforced lists
//!    names it (this miner's or another holder's, any owned PG: the
//!    load removes such hashes from the tombstone set exactly, see
//!    `pg_lists::LoadedGeneration::tombstones_retained_live_ref`) AND
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
//! `PURGE_ENABLED` defaults to false; when enabled, `PURGE_DRY_RUN`
//! defaults to true and only logs what would be deleted.
//!
//! ## Mode
//!
//! What a pass may do is a type, [`Mode`], not a boolean. A build without
//! the `purge-enforce` Cargo feature has exactly one variant, `Census`:
//! the pass counts and logs, the store calls that delete are not
//! compiled, and `PURGE_DRY_RUN=false` is answered with a warning and the
//! census. Only a build with the feature carries `Enforce`.

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

    /// True when the pass only counts.
    pub fn is_census(self) -> bool {
        matches!(self, Mode::Census)
    }

    /// True when the pass deletes.
    pub fn enforces(self) -> bool {
        !self.is_census()
    }
}

/// Purge knobs, all environment-driven (`PURGE_*`, `PG_LISTS_*`).
#[derive(Debug, Clone, PartialEq)]
pub struct PurgeConfig {
    /// `PG_LISTS_BASE_URL`: public bucket root; purge stays off without it.
    pub base_url: Option<String>,
    /// `PURGE_ENABLED` (default false).
    pub enabled: bool,
    /// `PURGE_DRY_RUN` (default true) as a [`Mode`]: `Census` logs
    /// candidates and deletes nothing; `Enforce` only exists in a build
    /// with the `purge-enforce` feature.
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
    /// `PURGE_OWNERSHIP_STABLE_SECS` (default 21 600 = 6 h): how long the
    /// set of PGs this miner owns must have been IDENTICAL before a pass
    /// may run. A PG this miner just lost is "not owned" under the new
    /// map and its blobs are filter misses, yet gateways still read them
    /// through the placement_epoch map and the rebalance may not have
    /// copied them to the new owners: a weight drop must not turn into a
    /// mass delete half an hour later. The clock is this miner's own
    /// obligations, not the global epoch counter: on a live network an epoch
    /// changes every ~15 min (quarantines, heartbeats) while most miners'
    /// owned set does not move, so a gate on epoch quiet never opened.
    /// `PURGE_EPOCH_STABLE_SECS` is accepted, warned about and ignored.
    pub ownership_stable_secs: u64,
    /// `PURGE_FILTER_FP` (default 0.01): Bloom false-positive target.
    pub filter_fp: f64,
    /// `PG_LISTS_FETCH_CONCURRENCY` (default 4, at most 8: each list body
    /// is buffered whole, up to 256 MiB).
    pub fetch_concurrency: usize,
    /// `PURGE_FILTER_MAX_BYTES` (default 1 GiB): a generation whose
    /// filter would be larger is refused (nothing purged).
    pub filter_max_bytes: u64,
    /// `PURGE_PASS_INTERVAL_SECS` (default 3600): pause between full
    /// passes over the inventory.
    pub pass_interval_secs: u64,
    /// `PURGE_GENERATION_MAX_AGE_SECS` (default 604 800 = 7 days): a
    /// generation whose `created_at` is older than this is refused
    /// (nothing purged) until a newer one is published.
    pub generation_max_age_secs: u64,
    /// `PURGE_MOVED_CLASS` (default true): classify blobs listed in an
    /// owned PG under another holder as moved and retain them. `false` is
    /// the rollback to the two-class rule (such a blob is an orphan).
    pub moved_class: bool,
    /// `PURGE_OTHERS_FILTER_MAX_BYTES` (default 256 MiB): cap on the
    /// Bloom filter over the other holders' records that backs the moved
    /// class. A generation whose others filter would be larger loads
    /// without it: the class is disabled for that generation (logged,
    /// gauge `miner_purge_moved_class_enforced`=0), the load itself
    /// never fails on it.
    pub others_filter_max_bytes: u64,
}

impl Default for PurgeConfig {
    fn default() -> Self {
        Self {
            base_url: None,
            enabled: false,
            mode: Mode::Census,
            min_age_secs: 14 * 86_400,
            rate_per_sec: 50,
            max_bytes_per_sec: 50 * 1024 * 1024,
            poll_secs: 600,
            ownership_stable_secs: 21_600,
            filter_fp: 0.01,
            fetch_concurrency: 4,
            filter_max_bytes: 1 << 30,
            pass_interval_secs: 3600,
            generation_max_age_secs: 7 * 86_400,
            moved_class: true,
            others_filter_max_bytes: 256 << 20,
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
        cfg.base_url = lookup("PG_LISTS_BASE_URL")
            .map(|s| s.trim().to_string())
            .filter(|s| !s.is_empty());
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
                "purge: PURGE_EPOCH_STABLE_SECS is deprecated and ignored (an epoch changes every few minutes on a live network, the gate never opened); the pass is gated on PURGE_OWNERSHIP_STABLE_SECS, the time this miner's owned PG set has been unchanged"
            );
        }
        parse(&lookup, "PURGE_FILTER_FP", &mut cfg.filter_fp);
        parse(
            &lookup,
            "PG_LISTS_FETCH_CONCURRENCY",
            &mut cfg.fetch_concurrency,
        );
        parse(&lookup, "PURGE_FILTER_MAX_BYTES", &mut cfg.filter_max_bytes);
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
        if let Some(v) = lookup_bool(&lookup, "PURGE_MOVED_CLASS")? {
            cfg.moved_class = v;
        }
        parse(
            &lookup,
            "PURGE_OTHERS_FILTER_MAX_BYTES",
            &mut cfg.others_filter_max_bytes,
        );
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
    /// This miner owns at least one PG under the map the pass runs on.
    /// False for a weight-0 miner: an empty owned set makes every other
    /// clause vacuous (coverage trivially complete, filter empty, every
    /// blob a miss), so it is checked first and closes the gate alone.
    pub ownership_nonempty: bool,
    pub generation_loaded: bool,
    /// The loaded generation is at most `generation_max_age_secs` old.
    pub generation_fresh: bool,
    pub coverage_complete: bool,
    /// The owned PG set has been identical for `ownership_stable_secs`.
    pub ownership_stable: bool,
}

impl PurgeGate {
    pub fn open(&self) -> bool {
        self.ownership_nonempty
            && self.generation_loaded
            && self.generation_fresh
            && self.coverage_complete
            && self.ownership_stable
    }
}

/// Whether an owned set of `owned` PGs may drive purge decisions at all:
/// the clause 0 of the purge rule. Pure, so the gate cannot be computed
/// any other way by a caller.
pub fn ownership_nonempty(owned: &[u32]) -> bool {
    !owned.is_empty()
}

/// Whether `next` is a shrink of more than half against `held` (strictly
/// fewer than half the PGs remain). An empty `held` never shrinks.
pub fn ownership_shrank_by_half(held: usize, next: usize) -> bool {
    next * 2 < held
}

/// Outcome of one [`OwnershipHysteresis::observe`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum OwnershipDecision {
    /// The observed set is the one purge decisions run on (adopted now,
    /// or already held).
    Adopted,
    /// The observed set shrank by more than half against the held one and
    /// has not been stable for `stable_secs` yet: decisions keep running
    /// on the held set. `pending_for_secs` is how long the shrunken set
    /// has been observed unchanged.
    Held { pending_for_secs: u64 },
}

/// Clause 4 of the purge rule applied to the owned set itself: a set that
/// shrinks by more than half between two consecutive observations is
/// only adopted for purge decisions once it has held unchanged for
/// `stable_secs`. Growth, and shrinks of at most half, are adopted at
/// once (the map-epoch quiet period covers those). Feed it every poll;
/// read [`OwnershipHysteresis::held`] for the set to decide on.
#[derive(Debug, Default)]
pub struct OwnershipHysteresis {
    /// `(epoch, owned)` purge decisions run on.
    held: Option<(u64, Vec<u32>)>,
    /// A shrunken set waiting out its quiet period: `(epoch, owned,
    /// first observed at)`.
    pending: Option<(u64, Vec<u32>, Instant)>,
}

impl OwnershipHysteresis {
    /// Observe the owned set computed on the map of `epoch` at `now`.
    pub fn observe(
        &mut self,
        epoch: u64,
        owned: Vec<u32>,
        now: Instant,
        stable_secs: u64,
    ) -> OwnershipDecision {
        let Some((_, held)) = self.held.as_ref() else {
            self.held = Some((epoch, owned));
            return OwnershipDecision::Adopted;
        };
        if !ownership_shrank_by_half(held.len(), owned.len()) {
            self.pending = None;
            self.held = Some((epoch, owned));
            return OwnershipDecision::Adopted;
        }
        match self.pending.as_mut() {
            Some((pending_epoch, pending, since)) if *pending == owned => {
                *pending_epoch = epoch;
                let pending_for = now.saturating_duration_since(*since).as_secs();
                if pending_for >= stable_secs {
                    self.pending = None;
                    self.held = Some((epoch, owned));
                    OwnershipDecision::Adopted
                } else {
                    OwnershipDecision::Held {
                        pending_for_secs: pending_for,
                    }
                }
            }
            _ => {
                self.pending = Some((epoch, owned, now));
                OwnershipDecision::Held {
                    pending_for_secs: 0,
                }
            }
        }
    }

    /// `(epoch, owned)` purge decisions run on; `None` before the first
    /// observation.
    pub fn held(&self) -> Option<(u64, &[u32])> {
        self.held.as_ref().map(|(e, o)| (*e, o.as_slice()))
    }

    /// The shrunken set waiting out its quiet period, if any.
    pub fn pending(&self) -> Option<&[u32]> {
        self.pending.as_ref().map(|(_, o, _)| o.as_slice())
    }
}

/// Outcome of one [`OwnershipStability::observe`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum StabilityObservation {
    /// Same set as last time; `stable_for_secs` since it last changed.
    Unchanged { stable_for_secs: u64 },
    /// The set differs from the last observation: the clock is reset.
    Changed { added: usize, removed: usize },
}

/// Clause 4 of the purge rule: the owned PG set and the wall-clock time
/// it last changed. Wall clock (Unix seconds) on purpose: the state is
/// persisted next to the generation watermark so a restart does not
/// reset the clock; when nothing is persisted the clock starts at the
/// first observation. Sets compare as sorted, deduplicated lists.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OwnershipStability {
    owned: Vec<u32>,
    changed_at_secs: u64,
}

impl OwnershipStability {
    /// First observation: the clock starts now.
    pub fn first(owned: &[u32], now_secs: u64) -> Self {
        Self {
            owned: Self::normalize(owned),
            changed_at_secs: now_secs,
        }
    }

    fn normalize(owned: &[u32]) -> Vec<u32> {
        let mut v = owned.to_vec();
        v.sort_unstable();
        v.dedup();
        v
    }

    /// The set purge decisions are timed against.
    pub fn owned(&self) -> &[u32] {
        &self.owned
    }

    /// Unix seconds of the last change (or of the first observation).
    pub fn changed_at_secs(&self) -> u64 {
        self.changed_at_secs
    }

    /// Feed the owned set computed from the current map. An identical set
    /// leaves the clock alone; a different one resets it to `now_secs`.
    pub fn observe(&mut self, observed: &[u32], now_secs: u64) -> StabilityObservation {
        let observed = Self::normalize(observed);
        if observed == self.owned {
            return StabilityObservation::Unchanged {
                stable_for_secs: self.stable_for_secs(now_secs),
            };
        }
        let added = observed
            .iter()
            .filter(|pg| self.owned.binary_search(pg).is_err())
            .count();
        let removed = self
            .owned
            .iter()
            .filter(|pg| observed.binary_search(pg).is_err())
            .count();
        self.owned = observed;
        self.changed_at_secs = now_secs;
        StabilityObservation::Changed { added, removed }
    }

    /// Seconds the current set has been unchanged at `now_secs` (0 when
    /// the clock is ahead of `now_secs`).
    pub fn stable_for_secs(&self, now_secs: u64) -> u64 {
        now_secs.saturating_sub(self.changed_at_secs)
    }

    /// Clause 4: unchanged for at least `required_secs`.
    pub fn is_stable(&self, now_secs: u64, required_secs: u64) -> bool {
        self.stable_for_secs(now_secs) >= required_secs
    }

    /// Persisted form: `v1 <changed_at_secs>` then the sorted PG ids,
    /// space-separated, on the second line.
    pub fn encode(&self) -> String {
        let pgs: Vec<String> = self.owned.iter().map(u32::to_string).collect();
        format!("v1 {}\n{}\n", self.changed_at_secs, pgs.join(" "))
    }

    /// Inverse of [`encode`](Self::encode); `None` on any malformed
    /// input (the caller then starts the clock at first observation).
    pub fn decode(text: &str) -> Option<Self> {
        let mut lines = text.lines();
        let header = lines.next()?;
        let mut parts = header.split_whitespace();
        if parts.next()? != "v1" {
            return None;
        }
        let changed_at_secs = parts.next()?.parse::<u64>().ok()?;
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
        Some(Self {
            owned: Self::normalize(&owned),
            changed_at_secs,
        })
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
    /// This miner owns no PG under the current map (weight 0): clause 0.
    KeepEmptyOwnership,
    KeepNoGeneration,
    KeepGenerationStale,
    KeepCoverageIncomplete,
    KeepOwnershipUnstable,
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
    if !gate.ownership_nonempty {
        return Verdict::KeepEmptyOwnership;
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
    if !gate.ownership_stable {
        return Verdict::KeepOwnershipUnstable;
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
    /// Rows whose hash is not 32 hex bytes, or whose delete failed.
    pub skipped_invalid: AtomicU64,
    pub delete_errors: AtomicU64,
    /// Gauge: owned PGs listed by the loaded generation.
    pub coverage_pgs_listed: AtomicU64,
    /// Gauge: PGs this miner owns.
    pub coverage_pgs_owned: AtomicU64,
    /// Gauge: 1 when every owned PG is listed.
    pub coverage_complete: AtomicBool,
    /// Gauge: loaded generation (0 = none).
    pub generation: AtomicU64,
    /// Gauge: hashes folded into the filter.
    pub filter_hashes: AtomicU64,
    pub filter_bytes: AtomicU64,
    /// Gauge: 1 when the loaded generation carries an others filter and
    /// `PURGE_MOVED_CLASS` is on, i.e. the moved class is enforced.
    pub moved_class_enforced: AtomicBool,
    /// Gauge: hashes folded into the others filter (0 when not built).
    pub others_filter_hashes: AtomicU64,
    pub others_filter_bytes: AtomicU64,
    /// Gauge: 1 when the loaded generation was loaded without an others
    /// filter because it would have exceeded
    /// `PURGE_OTHERS_FILTER_MAX_BYTES` (the moved class is then off for
    /// it whatever `PURGE_MOVED_CLASS` says).
    pub others_filter_cap_refusals: AtomicU64,
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
    /// Passes refused because this miner owns no PG under the current map
    /// (weight 0): clause 0 of the purge rule. Exposed as
    /// `purge_refused_empty_ownership_total`.
    pub refused_empty_ownership: AtomicU64,
    /// Polls at which the owned set had shrunk by more than half and the
    /// previous set was kept for purge decisions
    /// ([`OwnershipHysteresis`]). Exposed as
    /// `purge_ownership_shrink_held_total`.
    pub ownership_shrink_held: AtomicU64,
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
    pub skipped_invalid: AtomicU64,
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
             miner_purge_skipped_invalid_total {}\n\
             miner_purge_delete_errors_total {}\n\
             miner_purge_coverage_pgs_listed {}\n\
             miner_purge_coverage_pgs_owned {}\n\
             miner_purge_coverage_complete {}\n\
             miner_purge_generation {}\n\
             miner_purge_filter_hashes {}\n\
             miner_purge_filter_bytes {}\n\
             miner_purge_moved_class_enforced {}\n\
             miner_purge_others_filter_hashes {}\n\
             miner_purge_others_filter_bytes {}\n\
             miner_purge_others_filter_cap_refusals_total {}\n\
             miner_purge_passes_total {}\n\
             miner_purge_epoch_skew_tolerated_total {}\n\
             miner_purge_epoch_skew_aborts_total {}\n\
             miner_purge_filter_generation_refusals_total {}\n\
             purge_refused_empty_ownership_total {}\n\
             purge_ownership_shrink_held_total {}\n\
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
             purge_census_skipped_invalid {}\n\
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
            g(&self.skipped_invalid),
            g(&self.delete_errors),
            g(&self.coverage_pgs_listed),
            g(&self.coverage_pgs_owned),
            u8::from(self.coverage_complete.load(Ordering::Relaxed)),
            g(&self.generation),
            g(&self.filter_hashes),
            g(&self.filter_bytes),
            u8::from(self.moved_class_enforced.load(Ordering::Relaxed)),
            g(&self.others_filter_hashes),
            g(&self.others_filter_bytes),
            g(&self.others_filter_cap_refusals),
            g(&self.passes),
            g(&self.epoch_skew_tolerated),
            g(&self.epoch_skew_aborts),
            g(&self.filter_generation_refusals),
            g(&self.refused_empty_ownership),
            g(&self.ownership_shrink_held),
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
            g(&self.census.skipped_invalid),
            u8::from(self.census.complete.load(Ordering::Relaxed)),
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;

    const OPEN: PurgeGate = PurgeGate {
        ownership_nonempty: true,
        generation_loaded: true,
        generation_fresh: true,
        coverage_complete: true,
        ownership_stable: true,
    };

    /// Clause 0: a weight-0 miner owns no PG; the gate is closed before any
    /// other clause is consulted, and an otherwise obviously stray blob is
    /// kept.
    #[test]
    fn empty_ownership_closes_the_gate_before_every_other_clause() {
        assert!(!ownership_nonempty(&[]));
        assert!(ownership_nonempty(&[7]));
        let stray = Candidate {
            age_secs: 86_400 * 30,
            in_filter: false,
            tombstoned: false,
            moved: false,
            stored_after_snapshot: false,
            inflight: false,
        };
        let empty = PurgeGate {
            ownership_nonempty: false,
            ..OPEN
        };
        assert!(!empty.open());
        assert_eq!(decide(empty, stray, 3600), Verdict::KeepEmptyOwnership);
        // Wins over every other closed clause too.
        assert_eq!(
            decide(
                PurgeGate {
                    ownership_nonempty: false,
                    generation_loaded: false,
                    generation_fresh: false,
                    coverage_complete: false,
                    ownership_stable: false,
                },
                stray,
                3600
            ),
            Verdict::KeepEmptyOwnership
        );
        let m = PurgeMetrics::default();
        m.refused_empty_ownership.fetch_add(1, Ordering::Relaxed);
        assert!(
            m.render_prometheus()
                .contains("purge_refused_empty_ownership_total 1\n")
        );
    }

    /// 9000 → 0 → 9000 inside the quiet period: the held set is 9000 at
    /// every step, the empty set is never adopted, and a shrink that does
    /// hold for the whole period is adopted at its end.
    #[test]
    fn ownership_shrink_is_held_until_stable() {
        let big: Vec<u32> = (0..9000).collect();
        let small: Vec<u32> = (0..3000).collect();
        let mut h = OwnershipHysteresis::default();
        let t0 = Instant::now();
        assert_eq!(
            h.observe(1, big.clone(), t0, 100),
            OwnershipDecision::Adopted
        );
        assert_eq!(h.held(), Some((1, big.as_slice())));
        // 9000 -> 0: held.
        assert_eq!(
            h.observe(2, Vec::new(), t0 + Duration::from_secs(10), 100),
            OwnershipDecision::Held {
                pending_for_secs: 0
            }
        );
        assert_eq!(h.held(), Some((1, big.as_slice())));
        assert_eq!(h.pending(), Some(&[][..]));
        assert_eq!(
            h.observe(2, Vec::new(), t0 + Duration::from_secs(50), 100),
            OwnershipDecision::Held {
                pending_for_secs: 40
            }
        );
        // 0 -> 9000 before the period elapsed: back to the held set, no
        // pending left.
        assert_eq!(
            h.observe(3, big.clone(), t0 + Duration::from_secs(60), 100),
            OwnershipDecision::Adopted
        );
        assert_eq!(h.held(), Some((3, big.as_slice())));
        assert_eq!(h.pending(), None);
        // 9000 -> 3000 (more than half lost): held, then adopted once it
        // has held for the period. 9000 -> 4500 (exactly half) is adopted
        // at once.
        assert_eq!(
            h.observe(4, small.clone(), t0 + Duration::from_secs(70), 100),
            OwnershipDecision::Held {
                pending_for_secs: 0
            }
        );
        assert_eq!(h.held(), Some((3, big.as_slice())));
        assert_eq!(
            h.observe(4, small.clone(), t0 + Duration::from_secs(170), 100),
            OwnershipDecision::Adopted
        );
        assert_eq!(h.held(), Some((4, small.as_slice())));
        let half: Vec<u32> = (0..1500).collect();
        assert_eq!(
            h.observe(5, half.clone(), t0 + Duration::from_secs(171), 100),
            OwnershipDecision::Adopted
        );
        assert_eq!(h.held(), Some((5, half.as_slice())));
        // A different shrunken set restarts the period.
        let mut h2 = OwnershipHysteresis::default();
        h2.observe(1, big.clone(), t0, 100);
        h2.observe(2, small.clone(), t0 + Duration::from_secs(10), 100);
        assert_eq!(
            h2.observe(3, Vec::new(), t0 + Duration::from_secs(120), 100),
            OwnershipDecision::Held {
                pending_for_secs: 0
            }
        );
        assert_eq!(h2.held(), Some((1, big.as_slice())));
        assert!(!ownership_shrank_by_half(0, 0));
        assert!(ownership_shrank_by_half(9000, 4499));
        assert!(!ownership_shrank_by_half(9000, 4500));
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
            ownership_stable: false,
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
                Verdict::KeepOwnershipUnstable,
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
                ownership_nonempty: true,
                generation_loaded: loaded,
                generation_fresh: true,
                coverage_complete: covered,
                ownership_stable: stable,
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
            ownership_stable: false,
            ..OPEN
        };
        assert_eq!(
            decide(closed, young_tombstoned, 14 * 86_400),
            Verdict::KeepOwnershipUnstable
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
    fn moved_class_config_flag_and_cap() {
        let cfg = PurgeConfig::from_lookup(|_| None).unwrap();
        assert!(cfg.moved_class, "on by default: retaining is the safe side");
        assert_eq!(cfg.others_filter_max_bytes, 256 << 20);
        let mut env = HashMap::new();
        env.insert("PURGE_MOVED_CLASS", "off");
        env.insert("PURGE_OTHERS_FILTER_MAX_BYTES", "1048576");
        let cfg = PurgeConfig::from_lookup(|k| env.get(k).map(|v| v.to_string())).unwrap();
        assert!(!cfg.moved_class);
        assert_eq!(cfg.others_filter_max_bytes, 1 << 20);
        env.insert("PURGE_MOVED_CLASS", "maybe");
        assert!(
            PurgeConfig::from_lookup(|k| env.get(k).map(|v| v.to_string())).is_err(),
            "a class switch takes the strict boolean syntax"
        );
    }

    #[test]
    fn config_defaults_are_off_and_dry() {
        let cfg = PurgeConfig::from_lookup(|_| None).unwrap();
        assert_eq!(cfg, PurgeConfig::default());
        assert!(!cfg.enabled);
        assert!(cfg.mode.is_census());
        assert_eq!(cfg.base_url, None);
        assert_eq!(
            cfg.min_age_secs,
            14 * 86_400,
            "14 days: the writer's scan spans days"
        );
        assert_eq!(
            cfg.ownership_stable_secs, 21_600,
            "6 h of identical owned set before a pass"
        );
        assert_eq!(cfg.rate_per_sec, 50);
        assert_eq!(cfg.max_bytes_per_sec, 50 * 1024 * 1024);
        assert_eq!(cfg.generation_max_age_secs, 7 * 86_400);
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
        assert_eq!(cfg.filter_fp, 0.001);
        assert_eq!(cfg.fetch_concurrency, 8, "concurrency ceiling");
        assert_eq!(cfg.filter_max_bytes, 4096);
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
        m.others_filter_cap_refusals.store(1, Ordering::Relaxed);
        let text = m.render_prometheus();
        assert!(text.contains("miner_purge_kept_moved_total 2\n"));
        assert!(text.contains("miner_purge_moved_class_enforced 1\n"));
        assert!(text.contains("miner_purge_others_filter_cap_refusals_total 1\n"));
    }

    #[test]
    fn ownership_stability_gate_closed_while_set_changes_opens_after_required() {
        let required = 21_600;
        let mut st = OwnershipStability::first(&[3, 1, 2], 1_000);
        assert_eq!(st.owned(), &[1, 2, 3], "sets are sorted");
        assert!(!st.is_stable(1_000, required), "clock starts at zero");
        // Identical set (any order): the clock runs.
        assert_eq!(
            st.observe(&[2, 3, 1], 1_000 + 3_600),
            StabilityObservation::Unchanged {
                stable_for_secs: 3_600
            }
        );
        assert!(!st.is_stable(1_000 + 3_600, required));
        // A lost PG and a gained one reset the clock.
        assert_eq!(
            st.observe(&[1, 2, 4], 1_000 + 7_200),
            StabilityObservation::Changed {
                added: 1,
                removed: 1
            }
        );
        assert_eq!(st.changed_at_secs(), 8_200);
        assert!(!st.is_stable(8_200 + required - 1, required));
        assert_eq!(
            st.observe(&[1, 2, 4], 8_200 + required - 1),
            StabilityObservation::Unchanged {
                stable_for_secs: required - 1
            }
        );
        assert!(!st.is_stable(8_200 + required - 1, required));
        assert!(st.is_stable(8_200 + required, required), "opens at M");
        // Any further change closes it again for a full period.
        assert_eq!(
            st.observe(&[], 8_200 + required),
            StabilityObservation::Changed {
                added: 0,
                removed: 3
            }
        );
        assert!(!st.is_stable(8_200 + required, required));
    }

    #[test]
    fn ownership_stability_round_trips_and_refuses_garbage() {
        let st = OwnershipStability::first(&[7, 5, 5, 9], 1_700_000_000);
        let text = st.encode();
        assert_eq!(text, "v1 1700000000\n5 7 9\n");
        let back = OwnershipStability::decode(&text).unwrap();
        assert_eq!(back, st);
        // Restart-shaped use: the same set observed later keeps the old
        // clock; a different set starts a new one.
        let mut back2 = back.clone();
        assert_eq!(
            back2.observe(&[5, 7, 9], 1_700_000_000 + 21_600),
            StabilityObservation::Unchanged {
                stable_for_secs: 21_600
            }
        );
        assert!(back2.is_stable(1_700_000_000 + 21_600, 21_600));
        // Empty set encodes and decodes.
        let empty = OwnershipStability::first(&[], 5);
        assert_eq!(OwnershipStability::decode(&empty.encode()).unwrap(), empty);
        for bad in [
            "",
            "v2 1\n1 2\n",
            "v1\n1\n",
            "v1 x\n1\n",
            "v1 1 2\n1\n",
            "v1 1\n1 two\n",
            "v1 1\n1\nextra\n",
        ] {
            assert!(
                OwnershipStability::decode(bad).is_none(),
                "{bad:?} must not decode"
            );
        }
    }
}

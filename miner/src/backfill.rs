//! Obligation-list backfill: the other half of the purge.
//!
//! The purge deletes blobs this miner holds that are absent from the
//! published lists of its PGs. The backfill fetches blobs that are present
//! in those lists but absent from the local inventory, from peer miners
//! placed on the same PG. Both read the same signed generation
//! (`pg_lists`) and the same SQLite inventory; neither touches the other's
//! data (the purge only deletes unlisted blobs, the backfill only stores
//! listed ones), and the backfill pauses while a purge pass runs so the
//! two never compete for the disk.
//!
//! This module holds the pure parts: configuration, metrics, the on-disk
//! cursor, peer selection over a cluster map, and payload verification.
//! The loop that streams lists, talks to peers and writes the store lives
//! in the binary (`pg_backfill`).

use std::collections::HashSet;
use std::net::SocketAddr;
use std::path::Path;
use std::sync::atomic::{AtomicU64, Ordering};

use anyhow::{Context, Result};

use crate::purge::lookup_bool;

/// Backfill knobs, all environment-driven (`BACKFILL_*`). The generation
/// source (`PG_LISTS_BASE_URL`, `PG_LISTS_POLL_SECS`) is shared with the
/// purge and read from [`crate::purge::PurgeConfig`].
#[derive(Debug, Clone, PartialEq)]
pub struct BackfillConfig {
    /// `BACKFILL_ENABLED` (default false).
    pub enabled: bool,
    /// `BACKFILL_MAX_PENDING` (default 100 000): candidates collected per
    /// pass before the pass stops scanning and fetches what it has. The
    /// cursor resumes the scan at the next PG on the following pass.
    pub max_pending: usize,
    /// `BACKFILL_MAX_BYTES_PER_SEC` (default 20 MiB): fetch byte budget,
    /// charged with the declared shard length before the fetch.
    pub max_bytes_per_sec: u64,
    /// `BACKFILL_MAX_CONCURRENT` (default 4): fetches in flight.
    pub max_concurrent: usize,
    /// `BACKFILL_PASS_INTERVAL_SECS` (default 3600): pause between passes.
    pub pass_interval_secs: u64,
    /// `BACKFILL_MIN_FREE_BYTES` (default 50 GiB): the pass pauses while
    /// the blob volume has less free space than this.
    pub min_free_bytes: u64,
    /// `BACKFILL_PEERS_PER_BLOB` (default 3): holders tried per blob.
    pub peers_per_blob: usize,
    /// `BACKFILL_PAUSE_POLL_SECS` (default 30): re-check cadence while
    /// paused (purge pass running, low free space).
    pub pause_poll_secs: u64,
}

impl Default for BackfillConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            max_pending: 100_000,
            max_bytes_per_sec: 20 << 20,
            max_concurrent: 4,
            pass_interval_secs: 3600,
            min_free_bytes: 50 << 30,
            peers_per_blob: 3,
            pause_poll_secs: 30,
        }
    }
}

impl BackfillConfig {
    pub fn from_env() -> Result<Self> {
        Self::from_lookup(|name| std::env::var(name).ok())
    }

    /// Build from any name -> value lookup. An unparseable NUMERIC value
    /// keeps the default (logged at warn); an unparseable
    /// `BACKFILL_ENABLED` is an error, as for the purge switches.
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
                        "backfill: invalid value, keeping default"
                    ),
                }
            }
        }
        if let Some(v) = lookup_bool(&lookup, "BACKFILL_ENABLED")? {
            cfg.enabled = v;
        }
        parse(&lookup, "BACKFILL_MAX_PENDING", &mut cfg.max_pending);
        parse(
            &lookup,
            "BACKFILL_MAX_BYTES_PER_SEC",
            &mut cfg.max_bytes_per_sec,
        );
        parse(&lookup, "BACKFILL_MAX_CONCURRENT", &mut cfg.max_concurrent);
        parse(
            &lookup,
            "BACKFILL_PASS_INTERVAL_SECS",
            &mut cfg.pass_interval_secs,
        );
        parse(&lookup, "BACKFILL_MIN_FREE_BYTES", &mut cfg.min_free_bytes);
        parse(&lookup, "BACKFILL_PEERS_PER_BLOB", &mut cfg.peers_per_blob);
        parse(
            &lookup,
            "BACKFILL_PAUSE_POLL_SECS",
            &mut cfg.pause_poll_secs,
        );
        cfg.max_pending = cfg.max_pending.max(1);
        cfg.max_concurrent = cfg.max_concurrent.clamp(1, 64);
        cfg.peers_per_blob = cfg.peers_per_blob.max(1);
        cfg.pause_poll_secs = cfg.pause_poll_secs.max(1);
        Ok(cfg)
    }
}

// ============================================================================
// Candidates and cursor
// ============================================================================

/// A listed blob absent from the local inventory.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Candidate {
    pub pg_id: u32,
    pub hash: [u8; 32],
    /// Length declared by the list; the payload must match it exactly.
    pub shard_length: u64,
}

impl Candidate {
    pub fn hash_hex(&self) -> String {
        hex::encode(self.hash)
    }
}

/// Where the PG walk resumes: the first PG (in owned order) of
/// `generation` that has not been fully scanned. A different generation
/// restarts the walk at the first owned PG.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct Cursor {
    pub generation: u64,
    /// Index into the sorted owned-PG list of the next PG to scan.
    pub next_index: usize,
}

const CURSOR_FILE: &str = "backfill_cursor";

impl Cursor {
    /// `Cursor::default()` when absent or malformed.
    pub fn load_from(data_dir: &Path) -> Self {
        std::fs::read_to_string(data_dir.join(CURSOR_FILE))
            .ok()
            .and_then(|s| {
                let mut parts = s.split_whitespace();
                let generation = parts.next()?.parse().ok()?;
                let next_index = parts.next()?.parse().ok()?;
                Some(Self {
                    generation,
                    next_index,
                })
            })
            .unwrap_or_default()
    }

    /// Atomic write (temp + rename), errors reported to the caller.
    pub fn persist_to(&self, data_dir: &Path) -> Result<()> {
        let path = data_dir.join(CURSOR_FILE);
        let tmp = path.with_extension("tmp");
        std::fs::write(&tmp, format!("{} {}\n", self.generation, self.next_index))
            .and_then(|_| std::fs::rename(&tmp, &path))
            .with_context(|| format!("persist backfill cursor to {}", path.display()))
    }

    /// Position to start scanning `owned` for `generation`: the persisted
    /// index when it belongs to this generation and is still in range,
    /// zero otherwise.
    pub fn start_index(&self, generation: u64, owned_len: usize) -> usize {
        if self.generation == generation && self.next_index < owned_len {
            self.next_index
        } else {
            0
        }
    }
}

// ============================================================================
// Peer selection
// ============================================================================

/// A miner to fetch a blob from.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Peer {
    pub uid: u32,
    /// Hex node id (the key of the connection pool and peer cache).
    pub node_id: String,
    pub addr: SocketAddr,
}

/// Peers placed on `pg_id` that may hold its blobs, at most `max`, in
/// CRUSH order. Excludes this miner, draining and offline miners, and
/// miners without any direct address. The address comes from
/// `known_addr` (the peer cache, refreshed by live connections) when it
/// has one, else from the map.
///
/// Ownership unions the v2 and straw2 placements (as `calculate_my_pgs`
/// does), so a holder under either placement is a candidate source. The
/// map is filtered for placement first: a draining miner changes the
/// CRUSH input for everyone.
pub fn holders_for_pg(
    map: &common::ClusterMap,
    pg_id: u32,
    self_uid: u32,
    known_addr: impl Fn(&str) -> Option<SocketAddr>,
    max: usize,
) -> Vec<Peer> {
    let filtered;
    let map_ref = if map.miners.iter().any(|m| m.draining || m.placement_hold) {
        filtered = common::filter_map_for_placement(map);
        &filtered
    } else {
        map
    };
    let shards_per_file = map.ec_k + map.ec_m;
    let mut ordered: Vec<common::MinerNode> = Vec::new();
    let mut seen = HashSet::new();
    for placement in [
        common::calculate_pg_placement(pg_id, shards_per_file, map_ref).ok(),
        common::calculate_pg_placement_straw2(pg_id, shards_per_file, map_ref).ok(),
    ]
    .into_iter()
    .flatten()
    {
        for node in placement {
            if seen.insert(node.uid) {
                ordered.push(node);
            }
        }
    }
    ordered
        .into_iter()
        .filter(|m| m.uid != self_uid && !m.draining && !m.drained_for_offline)
        .filter_map(|m| {
            let node_id = m.endpoint.id.to_string();
            let addr =
                known_addr(&node_id).or_else(|| common::socket_addr_from_endpoint(&m.endpoint))?;
            Some(Peer {
                uid: m.uid,
                node_id,
                addr,
            })
        })
        .take(max)
        .collect()
}

// ============================================================================
// Verification
// ============================================================================

/// Why a peer did not yield the blob. `reason()` is the metric label.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum FetchError {
    /// Connect failure or timeout.
    Unreachable(String),
    /// The peer answered without DATA (it does not hold the blob).
    NotFound,
    /// Transport error or timeout after connecting.
    Transport(String),
    /// The payload's blake3 is not the requested hash.
    HashMismatch,
    /// The payload verifies but its length is not the listed shard length.
    LengthMismatch { expected: u64, got: u64 },
}

impl FetchError {
    pub fn reason(&self) -> &'static str {
        match self {
            FetchError::Unreachable(_) => "unreachable",
            FetchError::NotFound => "not_found",
            FetchError::Transport(_) => "transport",
            FetchError::HashMismatch => "hash_mismatch",
            FetchError::LengthMismatch { .. } => "length_mismatch",
        }
    }
}

impl std::fmt::Display for FetchError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            FetchError::Unreachable(e) => write!(f, "unreachable: {e}"),
            FetchError::NotFound => write!(f, "not found on peer"),
            FetchError::Transport(e) => write!(f, "transport: {e}"),
            FetchError::HashMismatch => write!(f, "blake3 mismatch"),
            FetchError::LengthMismatch { expected, got } => {
                write!(f, "length mismatch: listed {expected}, got {got}")
            }
        }
    }
}

/// The payload is the listed blob: blake3 equals `hash` and the length
/// equals `shard_length`. Hash first (a wrong blob is the stronger
/// signal), length second (the list is the authority on what the blob
/// must be; a hash-correct payload of the wrong length means the list and
/// the peer disagree, and nothing is stored either way).
pub fn verify_payload(data: &[u8], hash: &[u8; 32], shard_length: u64) -> Result<(), FetchError> {
    if blake3::hash(data).as_bytes() != hash {
        return Err(FetchError::HashMismatch);
    }
    if data.len() as u64 != shard_length {
        return Err(FetchError::LengthMismatch {
            expected: shard_length,
            got: data.len() as u64,
        });
    }
    Ok(())
}

// ============================================================================
// Metrics
// ============================================================================

/// Counters of the backfill loop, cumulative since process start except
/// the `paused_*` gauges and `pending`, which describe the current pass.
#[derive(Debug, Default)]
pub struct BackfillMetrics {
    /// Listed blobs found absent from the inventory.
    pub candidates: AtomicU64,
    /// Blobs fetched, verified and stored.
    pub fetched: AtomicU64,
    pub fetched_bytes: AtomicU64,
    /// Peer attempts that did not yield the blob, by reason.
    pub bad_peer_unreachable: AtomicU64,
    pub bad_peer_not_found: AtomicU64,
    pub bad_peer_transport: AtomicU64,
    pub bad_peer_hash_mismatch: AtomicU64,
    pub bad_peer_length_mismatch: AtomicU64,
    /// Candidates given up: no eligible peer, or every tried peer failed.
    pub no_peer: AtomicU64,
    /// Candidates found already present under the write lock (a Store or
    /// PullFromPeer landed the blob first).
    pub already_present: AtomicU64,
    pub store_errors: AtomicU64,
    /// PG lists that failed to fetch or verify (the PG is skipped this
    /// pass, the cursor does not advance past it).
    pub list_errors: AtomicU64,
    pub passes: AtomicU64,
    /// 0/1: the loop is waiting for the named condition to clear.
    pub paused_purge_running: AtomicU64,
    pub paused_low_free_space: AtomicU64,
    /// Candidates of the current pass not yet resolved.
    pub pending: AtomicU64,
    pub generation: AtomicU64,
    /// Polls refused because this miner owns no PG under the current map
    /// (weight 0): nothing to fetch, and an empty owned set is never read
    /// as "nothing obliged". Exposed as
    /// `miner_backfill_refused_empty_ownership_total`.
    pub refused_empty_ownership: AtomicU64,
}

impl BackfillMetrics {
    pub fn record_bad_peer(&self, err: &FetchError) {
        let counter = match err {
            FetchError::Unreachable(_) => &self.bad_peer_unreachable,
            FetchError::NotFound => &self.bad_peer_not_found,
            FetchError::Transport(_) => &self.bad_peer_transport,
            FetchError::HashMismatch => &self.bad_peer_hash_mismatch,
            FetchError::LengthMismatch { .. } => &self.bad_peer_length_mismatch,
        };
        counter.fetch_add(1, Ordering::Relaxed);
    }

    pub fn bad_peer_total(&self) -> u64 {
        [
            &self.bad_peer_unreachable,
            &self.bad_peer_not_found,
            &self.bad_peer_transport,
            &self.bad_peer_hash_mismatch,
            &self.bad_peer_length_mismatch,
        ]
        .iter()
        .map(|c| c.load(Ordering::Relaxed))
        .sum()
    }

    pub fn set_paused(&self, reason: PauseReason, on: bool) {
        let gauge = match reason {
            PauseReason::PurgeRunning => &self.paused_purge_running,
            PauseReason::LowFreeSpace => &self.paused_low_free_space,
        };
        gauge.store(u64::from(on), Ordering::Relaxed);
    }

    pub fn render_prometheus(&self) -> String {
        let g = |v: &AtomicU64| v.load(Ordering::Relaxed);
        format!(
            "miner_backfill_candidates_total {}\n\
             miner_backfill_fetched_total {}\n\
             miner_backfill_fetched_bytes_total {}\n\
             miner_backfill_bad_peer_total{{reason=\"unreachable\"}} {}\n\
             miner_backfill_bad_peer_total{{reason=\"not_found\"}} {}\n\
             miner_backfill_bad_peer_total{{reason=\"transport\"}} {}\n\
             miner_backfill_bad_peer_total{{reason=\"hash_mismatch\"}} {}\n\
             miner_backfill_bad_peer_total{{reason=\"length_mismatch\"}} {}\n\
             miner_backfill_no_peer_total {}\n\
             miner_backfill_already_present_total {}\n\
             miner_backfill_store_errors_total {}\n\
             miner_backfill_list_errors_total {}\n\
             miner_backfill_passes_total {}\n\
             miner_backfill_paused{{reason=\"purge_running\"}} {}\n\
             miner_backfill_paused{{reason=\"low_free_space\"}} {}\n\
             miner_backfill_pending {}\n\
             miner_backfill_generation {}\n\
             miner_backfill_refused_empty_ownership_total {}\n",
            g(&self.candidates),
            g(&self.fetched),
            g(&self.fetched_bytes),
            g(&self.bad_peer_unreachable),
            g(&self.bad_peer_not_found),
            g(&self.bad_peer_transport),
            g(&self.bad_peer_hash_mismatch),
            g(&self.bad_peer_length_mismatch),
            g(&self.no_peer),
            g(&self.already_present),
            g(&self.store_errors),
            g(&self.list_errors),
            g(&self.passes),
            g(&self.paused_purge_running),
            g(&self.paused_low_free_space),
            g(&self.pending),
            g(&self.generation),
            g(&self.refused_empty_ownership),
        )
    }
}

/// Why the loop is waiting instead of fetching.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PauseReason {
    PurgeRunning,
    LowFreeSpace,
}

impl PauseReason {
    pub fn label(self) -> &'static str {
        match self {
            PauseReason::PurgeRunning => "purge_running",
            PauseReason::LowFreeSpace => "low_free_space",
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn lookup_of<'a>(pairs: &'a [(&'a str, &'a str)]) -> impl Fn(&str) -> Option<String> + 'a {
        move |name| {
            pairs
                .iter()
                .find(|(n, _)| *n == name)
                .map(|(_, v)| v.to_string())
        }
    }

    #[test]
    fn config_defaults_are_off_and_bounded() {
        let cfg = BackfillConfig::from_lookup(|_| None).unwrap();
        assert!(!cfg.enabled);
        assert_eq!(cfg.max_pending, 100_000);
        assert_eq!(cfg.max_bytes_per_sec, 20 << 20);
        assert_eq!(cfg.max_concurrent, 4);
        assert_eq!(cfg.pass_interval_secs, 3600);
        assert_eq!(cfg.min_free_bytes, 50 << 30);
        assert_eq!(cfg.peers_per_blob, 3);
    }

    #[test]
    fn config_reads_env_and_refuses_bad_switch() {
        let cfg = BackfillConfig::from_lookup(lookup_of(&[
            ("BACKFILL_ENABLED", "true"),
            ("BACKFILL_MAX_PENDING", "0"),
            ("BACKFILL_MAX_CONCURRENT", "999"),
            ("BACKFILL_MAX_BYTES_PER_SEC", "not-a-number"),
            ("BACKFILL_MIN_FREE_BYTES", "1024"),
        ]))
        .unwrap();
        assert!(cfg.enabled);
        assert_eq!(cfg.max_pending, 1, "zero is clamped to one");
        assert_eq!(cfg.max_concurrent, 64, "clamped");
        assert_eq!(cfg.max_bytes_per_sec, 20 << 20, "invalid keeps default");
        assert_eq!(cfg.min_free_bytes, 1024);
        let err = BackfillConfig::from_lookup(lookup_of(&[("BACKFILL_ENABLED", "yes please")]))
            .unwrap_err()
            .to_string();
        assert!(err.contains("BACKFILL_ENABLED"), "{err}");
    }

    #[test]
    fn cursor_round_trips_and_resets_on_new_generation() {
        let dir = tempfile::tempdir().unwrap();
        assert_eq!(Cursor::load_from(dir.path()), Cursor::default());
        let c = Cursor {
            generation: 7,
            next_index: 42,
        };
        c.persist_to(dir.path()).unwrap();
        assert_eq!(Cursor::load_from(dir.path()), c);
        assert_eq!(c.start_index(7, 100), 42);
        assert_eq!(c.start_index(8, 100), 0, "new generation restarts");
        assert_eq!(c.start_index(7, 42), 0, "index past the owned set restarts");
        std::fs::write(dir.path().join(CURSOR_FILE), "garbage").unwrap();
        assert_eq!(Cursor::load_from(dir.path()), Cursor::default());
    }

    #[test]
    fn verify_checks_hash_then_length() {
        let data = b"hello backfill".to_vec();
        let hash = *blake3::hash(&data).as_bytes();
        assert_eq!(verify_payload(&data, &hash, data.len() as u64), Ok(()));
        assert_eq!(
            verify_payload(&data, &hash, 3),
            Err(FetchError::LengthMismatch {
                expected: 3,
                got: data.len() as u64
            })
        );
        assert_eq!(
            verify_payload(b"other", &hash, 5),
            Err(FetchError::HashMismatch),
            "a wrong blob is a hash mismatch even when the length matches"
        );
    }

    /// A cluster map of `n` miners in `n` families, weight 100, over 256
    /// PGs; miner `i` has direct address 10.0.0.i:4001.
    fn test_map(n: u32) -> common::ClusterMap {
        let mut map = common::ClusterMap::new();
        map.epoch = 42;
        map.pg_count = 256;
        map.miners = (0..n)
            .map(|i| {
                let sk = iroh::SecretKey::from_bytes(&[i as u8 + 1; 32]);
                let addr: SocketAddr = format!("10.0.0.{i}:4001").parse().unwrap();
                let mut endpoint = iroh::EndpointAddr::from(sk.public());
                endpoint.addrs.insert(iroh::TransportAddr::Ip(addr));
                common::MinerNode {
                    uid: i,
                    weight: 100,
                    balancer_reweight: 1.0,
                    family_id: format!("family-{i}"),
                    endpoint,
                    ip_subnet: String::new(),
                    ip_address: None,
                    http_addr: String::new(),
                    public_key: format!("{i:064x}"),
                    total_storage: 1 << 40,
                    available_storage: 1 << 39,
                    strikes: 0,
                    last_seen: 0,
                    heartbeat_count: 0,
                    registration_time: 0,
                    bandwidth_total: 0,
                    bandwidth_window_start: 0,
                    weight_manual_override: false,
                    reputation: 0.0,
                    consecutive_audit_passes: 0,
                    integrity_fails: 0,
                    version: String::new(),
                    base_weight: 0,
                    warden_challenges_total: 0,
                    warden_challenges_passed: 0,
                    fetch_timeout_count: 0,
                    expected_shards: 0,
                    actual_shards: 0,
                    trust_score: 0.0,
                    earned_capacity_bytes: 0,
                    incarnation: None,
                    draining: false,
                    drained_for_offline: false,
                    placement_hold: false,
                    placement_hold_base_hb: 0,
                    p2p_reliability_score: 1.0,
                    is_historical_seeder: false,
                }
            })
            .collect();
        map
    }

    #[test]
    fn holders_exclude_self_draining_offline_and_prefer_known_addr() {
        let mut map = test_map(40);
        let me = 7u32;
        let owned = common::calculate_my_pgs(me, &map);
        let pg = owned[0];
        let all = holders_for_pg(&map, pg, me, |_| None, usize::MAX);
        assert!(!all.is_empty());
        assert!(all.iter().all(|p| p.uid != me), "self excluded");
        assert!(all.len() >= 3, "a 30-wide placement has other holders");
        let capped = holders_for_pg(&map, pg, me, |_| None, 3);
        assert_eq!(capped.len(), 3);
        assert_eq!(capped, all[..3].to_vec(), "CRUSH order preserved");
        assert_eq!(
            capped[0].addr,
            format!("10.0.0.{}:4001", capped[0].uid).parse().unwrap(),
            "map address when nothing better is known"
        );

        // The peer cache knows a fresher address for the first holder.
        let cached: SocketAddr = "192.0.2.9:5000".parse().unwrap();
        let first = capped[0].node_id.clone();
        let with_cache = holders_for_pg(&map, pg, me, |id| (id == first).then_some(cached), 3);
        assert_eq!(with_cache[0].addr, cached);

        // A holder marked offline by the validator is skipped; a draining
        // holder is filtered out of the placement input.
        let offline = capped[1].uid;
        map.miners[offline as usize].drained_for_offline = true;
        let without = holders_for_pg(&map, pg, me, |_| None, usize::MAX);
        assert!(without.iter().all(|p| p.uid != offline));
        let draining = capped[2].uid;
        map.miners[draining as usize].draining = true;
        let without2 = holders_for_pg(&map, pg, me, |_| None, usize::MAX);
        assert!(without2.iter().all(|p| p.uid != draining));

        // A holder with no direct address cannot be dialled.
        let mut relay_only = test_map(40);
        for m in &mut relay_only.miners {
            m.endpoint.addrs.clear();
        }
        assert!(holders_for_pg(&relay_only, pg, me, |_| None, 3).is_empty());
        assert_eq!(
            holders_for_pg(&relay_only, pg, me, |_| Some(cached), 3).len(),
            3,
            "the peer cache alone is enough"
        );
    }

    #[test]
    fn metrics_render_every_series() {
        let m = BackfillMetrics::default();
        m.record_bad_peer(&FetchError::HashMismatch);
        m.record_bad_peer(&FetchError::NotFound);
        m.set_paused(PauseReason::PurgeRunning, true);
        assert_eq!(m.bad_peer_total(), 2);
        let text = m.render_prometheus();
        assert!(text.contains("miner_backfill_bad_peer_total{reason=\"hash_mismatch\"} 1\n"));
        assert!(text.contains("miner_backfill_bad_peer_total{reason=\"not_found\"} 1\n"));
        assert!(text.contains("miner_backfill_paused{reason=\"purge_running\"} 1\n"));
        assert!(text.contains("miner_backfill_paused{reason=\"low_free_space\"} 0\n"));
        assert!(text.contains("miner_backfill_fetched_bytes_total 0\n"));
        m.refused_empty_ownership.fetch_add(3, Ordering::Relaxed);
        assert!(
            m.render_prometheus()
                .contains("miner_backfill_refused_empty_ownership_total 3\n")
        );
    }
}

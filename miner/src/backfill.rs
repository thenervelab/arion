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
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};

use anyhow::{Context, Result};

use crate::flat_store::{FileId, FlatBlobStore};
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
    /// `BACKFILL_LOCAL_SOURCE_DIRS` (default none): comma-separated
    /// absolute paths of flat store roots set aside on this node (an
    /// operator who resets a node to the packed store can import the
    /// shards it still holds from the set-aside directory). Each candidate
    /// is looked up there by direct path before any peer is asked.
    pub local_source_dirs: Vec<PathBuf>,
    /// `BACKFILL_LOCAL_SOURCE_DELETE` (default false, strict boolean):
    /// move instead of copy. A source file is unlinked once its bytes are
    /// durably in the live store, readable there and recorded in the
    /// inventory (or were already held by the live store), so the import
    /// does not double the disk usage. Honoured only on a live store whose
    /// `store` is durable ([`crate::store::BlobStore::store_is_durable`]).
    pub local_source_delete: bool,
    /// `BACKFILL_LOCAL_CONCURRENCY` (default 64, 1..256): local lookups in
    /// flight. Disk-bound, not charged to the network byte budget.
    pub local_concurrency: usize,
    /// `BACKFILL_DISCOVERY_CONCURRENCY` (default 8, 1..64): PG lists
    /// fetched, decoded and looked up in the inventory at once during
    /// discovery. Results are still consumed in PG order (cursor).
    pub discovery_concurrency: usize,
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
            local_source_dirs: Vec::new(),
            local_source_delete: false,
            local_concurrency: 64,
            discovery_concurrency: 8,
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
        if let Some(v) = lookup_bool(&lookup, "BACKFILL_LOCAL_SOURCE_DELETE")? {
            cfg.local_source_delete = v;
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
        parse(
            &lookup,
            "BACKFILL_LOCAL_CONCURRENCY",
            &mut cfg.local_concurrency,
        );
        parse(
            &lookup,
            "BACKFILL_DISCOVERY_CONCURRENCY",
            &mut cfg.discovery_concurrency,
        );
        if let Some(raw) = lookup("BACKFILL_LOCAL_SOURCE_DIRS") {
            cfg.local_source_dirs = parse_local_source_dirs(&raw);
        }
        cfg.local_concurrency = cfg.local_concurrency.clamp(1, 256);
        cfg.discovery_concurrency = cfg.discovery_concurrency.clamp(1, 64);
        cfg.max_pending = cfg.max_pending.max(1);
        cfg.max_concurrent = cfg.max_concurrent.clamp(1, 64);
        cfg.peers_per_blob = cfg.peers_per_blob.max(1);
        cfg.pause_poll_secs = cfg.pause_poll_secs.max(1);
        Ok(cfg)
    }
}

/// The absolute paths of a comma-separated list, in order, without
/// duplicates; empty items are skipped and relative ones are refused
/// (logged at warn): a relative path would resolve against the service's
/// working directory, not the operator's intent.
fn parse_local_source_dirs(raw: &str) -> Vec<PathBuf> {
    let mut out: Vec<PathBuf> = Vec::new();
    for item in raw.split(',').map(str::trim).filter(|s| !s.is_empty()) {
        let path = PathBuf::from(item);
        if !path.is_absolute() {
            tracing::warn!(
                path = item,
                "backfill: BACKFILL_LOCAL_SOURCE_DIRS entry is not absolute, ignored"
            );
            continue;
        }
        if !out.contains(&path) {
            out.push(path);
        }
    }
    out
}

// ============================================================================
// Local sources
// ============================================================================

/// Set-aside flat store roots read before the peers. Lookups are direct
/// path probes through [`FlatBlobStore::read_at_most_located`]: the
/// sharded path `ab/cd/<hash>.bin`, then the legacy root path
/// `<hash>.bin`; a directory is never listed (such roots hold millions of
/// entries, often behind a FUSE union mount). Nothing is ever created or
/// written in them. In [`SourceMode::ReadOnly`] nothing is removed either;
/// in [`SourceMode::Move`] the exact file a verified copy was read from
/// may be unlinked ([`remove_copy`](Self::remove_copy)), never a
/// directory, never a path outside the root.
#[derive(Debug, Default)]
pub struct LocalSources {
    roots: Vec<SourceRoot>,
}

#[derive(Debug)]
struct SourceRoot {
    store: FlatBlobStore,
    /// The root's canonical path at open, when its files may be unlinked
    /// after a move (`None`: read-only).
    removable: Option<PathBuf>,
}

/// How the set-aside roots are opened.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SourceMode {
    /// Copy: the roots are only read.
    ReadOnly,
    /// Move (`BACKFILL_LOCAL_SOURCE_DELETE=true` on a durable live store):
    /// a source file may be unlinked once its blob is in the live store.
    /// A root that overlaps `live_root` (the live store's directory: same,
    /// inside or containing it) stays read-only, since its files may be
    /// the live copies themselves.
    Move { live_root: PathBuf },
}

/// Where a verified local copy was read: root index, exact path, and the
/// identity of the file whose bytes were verified.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LocalCopy {
    pub root: usize,
    pub path: PathBuf,
    pub file: FileId,
}

/// Result of one local lookup over every source root.
#[derive(Debug, PartialEq, Eq)]
pub enum LocalLookup {
    /// A copy that verifies (blake3, then the listed length), and where
    /// it was read.
    Hit { data: bytes::Bytes, copy: LocalCopy },
    /// No source root has a file for the hash.
    Miss,
    /// Some root has a file for it, but none verifies or reads (wrong
    /// hash, wrong length, I/O error); the reason of the last one.
    Bad(String),
}

/// Outcome of [`LocalSources::remove_copy`].
#[derive(Debug, PartialEq, Eq)]
pub enum RemoveOutcome {
    /// The source file was unlinked.
    Removed,
    /// It was already gone (another candidate of the same hash moved it).
    Gone,
    /// Not removed: refused (read-only root, path not the blob's path in
    /// that root, path resolving elsewhere, not the file that was read,
    /// not a regular file) or the unlink failed.
    Failed(String),
}

/// The canonical form of `root` if it overlaps neither way with
/// `live_root` (equal, or one inside the other); `None` when they overlap
/// or either cannot be canonicalized (the safe answer for a deletion
/// guard).
fn removable_root(root: &Path, live_root: &Path) -> Option<PathBuf> {
    let root = std::fs::canonicalize(root).ok()?;
    let live = std::fs::canonicalize(live_root).ok()?;
    (!root.starts_with(&live) && !live.starts_with(&root)).then_some(root)
}

impl LocalSources {
    /// The roots of `dirs` that are existing directories (one `stat`
    /// each); the others are logged at warn and left out. Blocking
    /// (`stat`, `canonicalize`): call it off the runtime workers.
    pub fn open(dirs: &[PathBuf], mode: &SourceMode) -> Self {
        let roots = dirs
            .iter()
            .filter_map(|dir| match FlatBlobStore::open_read_only(dir) {
                Ok(store) => {
                    let removable = match mode {
                        SourceMode::ReadOnly => None,
                        SourceMode::Move { live_root } => {
                            let canonical = removable_root(dir, live_root);
                            if canonical.is_none() {
                                tracing::warn!(
                                    path = %dir.display(),
                                    live_root = %live_root.display(),
                                    "backfill: local source overlaps the live store (or cannot be resolved), its files are never removed"
                                );
                            }
                            canonical
                        }
                    };
                    Some(SourceRoot { store, removable })
                }
                Err(e) => {
                    tracing::warn!(
                        path = %dir.display(),
                        error = %e,
                        "backfill: local source unusable, ignored"
                    );
                    None
                }
            })
            .collect();
        Self { roots }
    }

    pub fn is_empty(&self) -> bool {
        self.roots.is_empty()
    }

    pub fn len(&self) -> usize {
        self.roots.len()
    }

    /// Roots whose files may be unlinked after a move.
    pub fn removable_roots(&self) -> usize {
        self.roots.iter().filter(|r| r.removable.is_some()).count()
    }

    /// Whether a file read from `copy` may be unlinked (its root is in
    /// move mode).
    pub fn is_removable(&self, copy: &LocalCopy) -> bool {
        self.roots
            .get(copy.root)
            .is_some_and(|r| r.removable.is_some())
    }

    /// Look `hash` up in every root, in order, reading at most
    /// `shard_length` bytes (a longer file is refused before it is
    /// buffered) and verifying with [`verify_payload`]. The first copy that
    /// verifies wins; a bad copy in one root does not hide a good one in
    /// the next.
    pub async fn lookup(&self, hash: &[u8; 32], shard_length: u64) -> LocalLookup {
        let hash_hex = hex::encode(hash);
        let mut bad: Option<String> = None;
        for (idx, root) in self.roots.iter().enumerate() {
            let dir = root.store.data_dir();
            match root
                .store
                .read_at_most_located(&hash_hex, shard_length)
                .await
            {
                Ok((data, path, file)) => match verify_payload(&data, hash, shard_length) {
                    Ok(()) => {
                        return LocalLookup::Hit {
                            data,
                            copy: LocalCopy {
                                root: idx,
                                path,
                                file,
                            },
                        };
                    }
                    Err(e) => bad = Some(format!("{}: {e}", dir.display())),
                },
                Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
                Err(e) => bad = Some(format!("{}: {e}", dir.display())),
            }
        }
        match bad {
            Some(reason) => LocalLookup::Bad(reason),
            None => LocalLookup::Miss,
        }
    }

    /// Unlink the source file a verified copy of `hash` was read from.
    /// Refused unless all of these hold, checked in the blocking pool right
    /// before the unlink:
    /// - the copy's root is removable (move mode, no overlap with the live
    ///   store) and still resolves to the canonical path it had at open
    ///   (a root symlink retargeted since is refused);
    /// - `copy.path` is exactly one of the two paths that root stores
    ///   `hash` at, and its directory resolves to the root itself (legacy)
    ///   or to the root's own `ab/cd` (sharded): a symlinked shard
    ///   directory pointing elsewhere is refused;
    /// - the entry is a regular file (`symlink_metadata`: no directory, no
    ///   symlink) and is still the file whose bytes were verified (same
    ///   device and inode).
    ///
    /// The unlink goes through the resolved path. The caller decides WHEN
    /// (after the live copy is durable, readable and recorded).
    pub async fn remove_copy(&self, hash: &[u8; 32], copy: &LocalCopy) -> RemoveOutcome {
        let hash_hex = hex::encode(hash);
        let Some(root) = self.roots.get(copy.root) else {
            return RemoveOutcome::Failed(format!("no source root #{}", copy.root));
        };
        let Some(canonical_root) = root.removable.clone() else {
            return RemoveOutcome::Failed(format!(
                "{} is read-only",
                root.store.data_dir().display()
            ));
        };
        if !root.store.is_blob_path(&hash_hex, &copy.path) {
            return RemoveOutcome::Failed(format!(
                "{} is not the path of {hash_hex} under {}",
                copy.path.display(),
                root.store.data_dir().display()
            ));
        }
        let legacy = copy.path.parent() == Some(root.store.data_dir());
        let expected_dir = if legacy {
            canonical_root.clone()
        } else {
            canonical_root.join(&hash_hex[0..2]).join(&hash_hex[2..4])
        };
        let root_dir = root.store.data_dir().to_path_buf();
        let path = copy.path.clone();
        let file = copy.file;
        let file_name = format!("{hash_hex}.bin");
        let unlink = move || -> std::io::Result<RemoveOutcome> {
            if std::fs::canonicalize(&root_dir)? != canonical_root {
                return Ok(RemoveOutcome::Failed(format!(
                    "{} no longer resolves to {}",
                    root_dir.display(),
                    canonical_root.display()
                )));
            }
            let dir = match path.parent().map(std::fs::canonicalize) {
                Some(Ok(dir)) => dir,
                Some(Err(e)) if e.kind() == std::io::ErrorKind::NotFound => {
                    return Ok(RemoveOutcome::Gone);
                }
                Some(Err(e)) => return Err(e),
                None => return Ok(RemoveOutcome::Failed("no parent directory".into())),
            };
            if dir != expected_dir {
                return Ok(RemoveOutcome::Failed(format!(
                    "{} resolves to {}, outside {}",
                    path.display(),
                    dir.display(),
                    expected_dir.display()
                )));
            }
            let target = dir.join(&file_name);
            match std::fs::symlink_metadata(&target) {
                Ok(m) if !m.file_type().is_file() => {
                    return Ok(RemoveOutcome::Failed(format!(
                        "{} is not a regular file",
                        target.display()
                    )));
                }
                Ok(m) if FileId::of(&m) != file => {
                    return Ok(RemoveOutcome::Failed(format!(
                        "{} is no longer the file that was read",
                        target.display()
                    )));
                }
                Ok(_) => {}
                Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                    return Ok(RemoveOutcome::Gone);
                }
                Err(e) => return Err(e),
            }
            match std::fs::remove_file(&target) {
                Ok(()) => Ok(RemoveOutcome::Removed),
                Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(RemoveOutcome::Gone),
                Err(e) => Err(e),
            }
        };
        match tokio::task::spawn_blocking(unlink).await {
            Ok(Ok(outcome)) => outcome,
            Ok(Err(e)) => RemoveOutcome::Failed(format!("{}: {e}", copy.path.display())),
            Err(e) => RemoveOutcome::Failed(format!("unlink task failed: {e}")),
        }
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
    /// The other holders the same list names for this blob (identical
    /// shard bytes in several files or stripes), ascending: tried before
    /// the PG's current placement, since the list says they hold it.
    pub listed_holders: Vec<u32>,
}

impl Candidate {
    pub fn hash_hex(&self) -> String {
        hex::encode(self.hash)
    }
}

/// Where the PG walk resumes: the first PG of `generation` that has not
/// been fully scanned, by PG id (the walk is in ascending PG order). An
/// id, not a position: the owned set changes with the epoch, and a
/// position into a list that gained or lost a PG below it would skip or
/// rescan PGs until the walk wraps. A different generation restarts the
/// walk at the first owned PG.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct Cursor {
    pub generation: u64,
    /// The next PG to scan: the walk resumes at the first owned PG at or
    /// above it.
    pub next_pg: u32,
}

const CURSOR_FILE: &str = "backfill_cursor";
/// Format tag of the cursor file (`v2 <generation> <next_pg>`). The
/// former `<generation> <index>` file is read as absent: the walk restarts,
/// which only rescans lists.
const CURSOR_FORMAT: &str = "v2";

impl Cursor {
    /// `Cursor::default()` when absent, malformed or of the former format.
    pub fn load_from(data_dir: &Path) -> Self {
        std::fs::read_to_string(data_dir.join(CURSOR_FILE))
            .ok()
            .and_then(|s| {
                let mut parts = s.split_whitespace();
                if parts.next()? != CURSOR_FORMAT {
                    return None;
                }
                let generation = parts.next()?.parse().ok()?;
                let next_pg = parts.next()?.parse().ok()?;
                Some(Self {
                    generation,
                    next_pg,
                })
            })
            .unwrap_or_default()
    }

    /// Atomic write (temp + rename), errors reported to the caller.
    pub fn persist_to(&self, data_dir: &Path) -> Result<()> {
        let path = data_dir.join(CURSOR_FILE);
        let tmp = path.with_extension("tmp");
        std::fs::write(
            &tmp,
            format!("{CURSOR_FORMAT} {} {}\n", self.generation, self.next_pg),
        )
        .and_then(|_| std::fs::rename(&tmp, &path))
        .with_context(|| format!("persist backfill cursor to {}", path.display()))
    }

    /// Position to start scanning `owned` (sorted ascending) for
    /// `generation`: the first PG at or above `next_pg` when the cursor
    /// belongs to this generation and such a PG is owned, zero otherwise.
    pub fn start_index(&self, generation: u64, owned: &[u32]) -> usize {
        if self.generation != generation {
            return 0;
        }
        let idx = owned.partition_point(|pg| *pg < self.next_pg);
        if idx < owned.len() { idx } else { 0 }
    }

    /// The cursor resuming at `owned[idx]`, or at the start when the walk
    /// is complete.
    pub fn at(generation: u64, owned: &[u32], idx: usize, walk_complete: bool) -> Self {
        let next_pg = if walk_complete {
            0
        } else {
            owned.get(idx).copied().unwrap_or(0)
        };
        Self {
            generation,
            next_pg,
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

/// The miners of `uids` (in that order) that can be dialled: this miner,
/// draining and offline miners and miners without any direct address are
/// skipped, as in [`holders_for_pg`]. A uid absent from the map is
/// skipped. The address comes from `known_addr` first, else from the map.
pub fn peers_for_uids(
    map: &common::ClusterMap,
    uids: &[u32],
    self_uid: u32,
    known_addr: impl Fn(&str) -> Option<SocketAddr>,
) -> Vec<Peer> {
    uids.iter()
        .filter(|uid| **uid != self_uid)
        .filter_map(|uid| map.miners.iter().find(|m| m.uid == *uid))
        .filter(|m| !m.draining && !m.drained_for_offline)
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
        .collect()
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
    /// Local source lookups (`BACKFILL_LOCAL_SOURCE_DIRS`): a copy that
    /// verified (then stored, or found already present), none in any
    /// root, or only copies that failed verification or the read.
    pub local_hit: AtomicU64,
    pub local_miss: AtomicU64,
    pub local_bad: AtomicU64,
    /// Bytes stored from a local source (not in `fetched_bytes`).
    pub local_bytes: AtomicU64,
    /// `BACKFILL_LOCAL_SOURCE_DELETE`: source files unlinked once their
    /// blob was confirmed in the live store, and source files kept because
    /// the confirmation or the unlink failed.
    pub local_deleted: AtomicU64,
    pub local_delete_errors: AtomicU64,
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
    /// (weight 0) and the holder index names it in none: nothing to fetch.
    /// Exposed as
    /// `miner_backfill_refused_empty_ownership_total`.
    pub refused_empty_ownership: AtomicU64,
    /// PG lists scanned to the end by discovery, and the records they
    /// held: their rate is the discovery rate.
    pub discovery_pgs: AtomicU64,
    pub discovery_records: AtomicU64,
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
             miner_backfill_local_total{{outcome=\"hit\"}} {}\n\
             miner_backfill_local_total{{outcome=\"miss\"}} {}\n\
             miner_backfill_local_total{{outcome=\"bad\"}} {}\n\
             miner_backfill_local_bytes_total {}\n\
             miner_backfill_local_source_deleted_total {}\n\
             miner_backfill_local_source_delete_errors_total {}\n\
             miner_backfill_already_present_total {}\n\
             miner_backfill_store_errors_total {}\n\
             miner_backfill_list_errors_total {}\n\
             miner_backfill_passes_total {}\n\
             miner_backfill_paused{{reason=\"purge_running\"}} {}\n\
             miner_backfill_paused{{reason=\"low_free_space\"}} {}\n\
             miner_backfill_pending {}\n\
             miner_backfill_generation {}\n\
             miner_backfill_refused_empty_ownership_total {}\n\
             miner_backfill_discovery_pgs_total {}\n\
             miner_backfill_discovery_records_total {}\n",
            g(&self.candidates),
            g(&self.fetched),
            g(&self.fetched_bytes),
            g(&self.bad_peer_unreachable),
            g(&self.bad_peer_not_found),
            g(&self.bad_peer_transport),
            g(&self.bad_peer_hash_mismatch),
            g(&self.bad_peer_length_mismatch),
            g(&self.no_peer),
            g(&self.local_hit),
            g(&self.local_miss),
            g(&self.local_bad),
            g(&self.local_bytes),
            g(&self.local_deleted),
            g(&self.local_delete_errors),
            g(&self.already_present),
            g(&self.store_errors),
            g(&self.list_errors),
            g(&self.passes),
            g(&self.paused_purge_running),
            g(&self.paused_low_free_space),
            g(&self.pending),
            g(&self.generation),
            g(&self.refused_empty_ownership),
            g(&self.discovery_pgs),
            g(&self.discovery_records),
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
pub(crate) mod tests {
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
            next_pg: 42,
        };
        c.persist_to(dir.path()).unwrap();
        assert_eq!(Cursor::load_from(dir.path()), c);
        let owned = [3u32, 10, 42, 50, 99];
        assert_eq!(c.start_index(7, &owned), 2);
        assert_eq!(c.start_index(8, &owned), 0, "new generation restarts");
        // The owned set changed: PG 42 is no longer owned, 20 and 41 were
        // gained below it. The walk resumes at the first PG at or above 42.
        assert_eq!(c.start_index(7, &[3, 20, 41, 50, 99]), 3);
        assert_eq!(
            c.start_index(7, &[3, 10, 41]),
            0,
            "nothing left above: restart"
        );
        assert_eq!(Cursor::at(7, &owned, 3, false).next_pg, 50);
        assert_eq!(Cursor::at(7, &owned, 5, true).next_pg, 0);
        std::fs::write(dir.path().join(CURSOR_FILE), "garbage").unwrap();
        assert_eq!(Cursor::load_from(dir.path()), Cursor::default());
        std::fs::write(dir.path().join(CURSOR_FILE), "7 42\n").unwrap();
        assert_eq!(
            Cursor::load_from(dir.path()),
            Cursor::default(),
            "the former index format restarts the walk"
        );
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
    pub(crate) fn test_map(n: u32) -> common::ClusterMap {
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
    fn listed_peers_keep_their_order_and_skip_the_undialable() {
        let mut map = test_map(40);
        map.miners[4].draining = true;
        map.miners[5].drained_for_offline = true;
        map.miners[6].endpoint.addrs.clear();
        let peers = peers_for_uids(&map, &[9, 7, 4, 5, 6, 3, 999], 7, |_| None);
        assert_eq!(
            peers.iter().map(|p| p.uid).collect::<Vec<_>>(),
            vec![9, 3],
            "self, draining, offline, address-less and unknown uids skipped"
        );
        let cached: SocketAddr = "192.0.2.9:5000".parse().unwrap();
        let with_cache = peers_for_uids(&map, &[6], 7, |_| Some(cached));
        assert_eq!(with_cache.len(), 1, "the peer cache alone is enough");
        assert_eq!(with_cache[0].addr, cached);
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
        m.discovery_pgs.fetch_add(2, Ordering::Relaxed);
        m.discovery_records.fetch_add(440_000, Ordering::Relaxed);
        let text = m.render_prometheus();
        assert!(text.contains("miner_backfill_discovery_pgs_total 2\n"));
        assert!(text.contains("miner_backfill_discovery_records_total 440000\n"));
    }

    #[tokio::test]
    async fn local_sources_probe_both_layouts_and_verify() {
        let a = tempfile::tempdir().unwrap();
        let b = tempfile::tempdir().unwrap();
        let blob = |tag: &str| {
            let data = format!("local-{tag}").repeat(7).into_bytes();
            let hash = *blake3::hash(&data).as_bytes();
            (data, hash)
        };
        let write_sharded = |root: &Path, hash: &[u8; 32], data: &[u8]| {
            let h = hex::encode(hash);
            let dir = root.join(&h[0..2]).join(&h[2..4]);
            std::fs::create_dir_all(&dir).unwrap();
            std::fs::write(dir.join(format!("{h}.bin")), data).unwrap();
        };
        let write_legacy = |root: &Path, hash: &[u8; 32], data: &[u8]| {
            std::fs::write(root.join(format!("{}.bin", hex::encode(hash))), data).unwrap();
        };
        let (sharded, sharded_h) = blob("sharded");
        let (legacy, legacy_h) = blob("legacy");
        let (rotten, rotten_h) = blob("rotten");
        let (healed, healed_h) = blob("healed");
        let (_, absent_h) = blob("absent");
        write_sharded(a.path(), &sharded_h, &sharded);
        write_legacy(a.path(), &legacy_h, &legacy);
        write_sharded(a.path(), &rotten_h, b"rotten bytes");
        // A bad copy in the first root does not hide a good one in the next.
        write_legacy(a.path(), &healed_h, b"bad copy");
        write_sharded(b.path(), &healed_h, &healed);

        let sharded_path = |root: &Path, hash: &[u8; 32]| {
            let h = hex::encode(hash);
            root.join(&h[0..2]).join(&h[2..4]).join(format!("{h}.bin"))
        };
        let hit = |data: &[u8], root: usize, path: PathBuf| LocalLookup::Hit {
            data: data.to_vec().into(),
            copy: LocalCopy {
                root,
                file: FileId::of(&std::fs::metadata(&path).unwrap()),
                path,
            },
        };
        let missing = a.path().join("does-not-exist");
        let local = LocalSources::open(
            &[a.path().to_path_buf(), missing, b.path().to_path_buf()],
            &SourceMode::ReadOnly,
        );
        assert_eq!(local.len(), 2, "a missing root is left out");
        let len = |d: &[u8]| d.len() as u64;
        assert_eq!(
            local.lookup(&sharded_h, len(&sharded)).await,
            hit(&sharded, 0, sharded_path(a.path(), &sharded_h))
        );
        assert_eq!(
            local.lookup(&legacy_h, len(&legacy)).await,
            hit(
                &legacy,
                0,
                a.path().join(format!("{}.bin", hex::encode(legacy_h)))
            )
        );
        assert_eq!(local.lookup(&absent_h, 10).await, LocalLookup::Miss);
        assert!(matches!(
            local.lookup(&rotten_h, len(&rotten)).await,
            LocalLookup::Bad(_)
        ));
        assert_eq!(
            local.lookup(&healed_h, len(&healed)).await,
            hit(&healed, 1, sharded_path(b.path(), &healed_h))
        );
        // A listed length shorter than the file: refused before buffering.
        assert!(matches!(
            local.lookup(&sharded_h, len(&sharded) - 1).await,
            LocalLookup::Bad(_)
        ));
        // Longer than the file: the bytes verify by hash, not by length.
        assert!(matches!(
            local.lookup(&sharded_h, len(&sharded) + 1).await,
            LocalLookup::Bad(_)
        ));
        assert!(
            !a.path().join("trash").exists() && !a.path().join(".tmp").exists(),
            "opened read-only"
        );
        assert!(LocalSources::default().is_empty());
    }

    /// `remove_copy` unlinks only the exact file of the hash under a
    /// removable root: never a path outside the roots, another hash's
    /// file, a directory, a file of a read-only root or of a root that
    /// overlaps the live store.
    #[tokio::test]
    async fn remove_copy_is_confined_to_the_blob_file_of_a_removable_root() {
        let root = tempfile::tempdir().unwrap();
        let live = tempfile::tempdir().unwrap();
        let outside = tempfile::tempdir().unwrap();
        let data = b"moved blob".to_vec();
        let hash = *blake3::hash(&data).as_bytes();
        let h = hex::encode(hash);
        let other = *blake3::hash(b"other").as_bytes();
        let sharded = root
            .path()
            .join(&h[0..2])
            .join(&h[2..4])
            .join(format!("{h}.bin"));
        std::fs::create_dir_all(sharded.parent().unwrap()).unwrap();
        std::fs::write(&sharded, &data).unwrap();
        let legacy = root.path().join(format!("{h}.bin"));
        std::fs::write(&legacy, &data).unwrap();
        let foreign = outside.path().join(format!("{h}.bin"));
        std::fs::write(&foreign, &data).unwrap();
        let move_mode = SourceMode::Move {
            live_root: live.path().to_path_buf(),
        };
        let local = LocalSources::open(&[root.path().to_path_buf()], &move_mode);
        assert_eq!(local.removable_roots(), 1);
        // The identity of whatever the path names now (a placeholder when
        // nothing does).
        let copy = |path: PathBuf| LocalCopy {
            root: 0,
            file: std::fs::symlink_metadata(&path)
                .map(|m| FileId::of(&m))
                .unwrap_or(FileId { dev: 0, ino: 0 }),
            path,
        };
        let failed = |o: RemoveOutcome| matches!(o, RemoveOutcome::Failed(_));

        // Outside the root, a sibling dir, another hash, a bad root index.
        assert!(failed(
            local.remove_copy(&hash, &copy(foreign.clone())).await
        ));
        assert!(failed(
            local
                .remove_copy(
                    &hash,
                    &copy(root.path().join("..").join(format!("{h}.bin")))
                )
                .await
        ));
        assert!(failed(
            local.remove_copy(&other, &copy(sharded.clone())).await
        ));
        assert!(failed(
            local
                .remove_copy(
                    &hash,
                    &LocalCopy {
                        root: 7,
                        ..copy(sharded.clone())
                    }
                )
                .await
        ));
        assert!(foreign.exists() && sharded.exists());

        // A directory at the blob's path is never removed.
        let dir_hash = *blake3::hash(b"dir").as_bytes();
        let dh = hex::encode(dir_hash);
        let as_dir = root.path().join(format!("{dh}.bin"));
        std::fs::create_dir(&as_dir).unwrap();
        assert!(failed(
            local.remove_copy(&dir_hash, &copy(as_dir.clone())).await
        ));
        assert!(as_dir.is_dir());

        // A shard directory that is a symlink to elsewhere: the path is
        // lexically the blob's, but resolves outside the root.
        let linked_data = b"linked".to_vec();
        let linked_hash = *blake3::hash(&linked_data).as_bytes();
        let lh = hex::encode(linked_hash);
        let away = outside.path().join("away");
        std::fs::create_dir(&away).unwrap();
        std::fs::write(away.join(format!("{lh}.bin")), &linked_data).unwrap();
        std::fs::create_dir_all(root.path().join(&lh[0..2])).unwrap();
        std::os::unix::fs::symlink(&away, root.path().join(&lh[0..2]).join(&lh[2..4])).unwrap();
        let linked = root
            .path()
            .join(&lh[0..2])
            .join(&lh[2..4])
            .join(format!("{lh}.bin"));
        assert!(failed(
            local.remove_copy(&linked_hash, &copy(linked.clone())).await
        ));
        assert!(away.join(format!("{lh}.bin")).exists());

        // The file at the path was replaced after it was read.
        let read_then = copy(sharded.clone());
        let tmp = root.path().join("replacement");
        std::fs::write(&tmp, &data).unwrap();
        std::fs::rename(&tmp, &sharded).unwrap();
        assert!(failed(local.remove_copy(&hash, &read_then).await));
        assert!(sharded.exists());

        // The real files go, a second removal reports them gone.
        assert_eq!(
            local.remove_copy(&hash, &copy(sharded.clone())).await,
            RemoveOutcome::Removed
        );
        assert_eq!(
            local.remove_copy(&hash, &copy(legacy.clone())).await,
            RemoveOutcome::Removed
        );
        assert_eq!(
            local.remove_copy(&hash, &copy(sharded.clone())).await,
            RemoveOutcome::Gone
        );
        assert!(sharded.parent().unwrap().is_dir(), "directories stay");

        // Read-only mode, and a root overlapping the live store.
        std::fs::write(&legacy, &data).unwrap();
        let ro = LocalSources::open(&[root.path().to_path_buf()], &SourceMode::ReadOnly);
        assert!(!ro.is_removable(&copy(legacy.clone())));
        assert!(failed(ro.remove_copy(&hash, &copy(legacy.clone())).await));
        for live_root in [
            root.path().to_path_buf(),
            root.path().join(&h[0..2]),
            outside.path().join("missing"),
        ] {
            let overlapping = LocalSources::open(
                &[root.path().to_path_buf()],
                &SourceMode::Move { live_root },
            );
            assert_eq!(overlapping.removable_roots(), 0);
            assert!(failed(
                overlapping.remove_copy(&hash, &copy(legacy.clone())).await
            ));
        }
        let parent = root.path().parent().unwrap().to_path_buf();
        let containing = LocalSources::open(
            &[root.path().to_path_buf()],
            &SourceMode::Move { live_root: parent },
        );
        assert_eq!(
            containing.removable_roots(),
            0,
            "a live root containing the source"
        );
        assert!(legacy.exists());
    }

    #[test]
    fn local_source_delete_is_a_strict_boolean() {
        assert!(
            !BackfillConfig::from_lookup(|_| None)
                .unwrap()
                .local_source_delete
        );
        let on =
            BackfillConfig::from_lookup(lookup_of(&[("BACKFILL_LOCAL_SOURCE_DELETE", " Yes ")]));
        assert!(on.unwrap().local_source_delete);
        let off = BackfillConfig::from_lookup(lookup_of(&[("BACKFILL_LOCAL_SOURCE_DELETE", "0")]));
        assert!(!off.unwrap().local_source_delete);
        assert!(
            BackfillConfig::from_lookup(lookup_of(&[("BACKFILL_LOCAL_SOURCE_DELETE", "maybe")]))
                .is_err(),
            "a deletion switch is never defaulted silently"
        );
    }

    #[test]
    fn local_source_dirs_parse_absolute_unique_paths() {
        let cfg = BackfillConfig::from_lookup(lookup_of(&[
            (
                "BACKFILL_LOCAL_SOURCE_DIRS",
                " /a/storage.flat-old-1 , relative/dir,,/b/x,/a/storage.flat-old-1 ",
            ),
            ("BACKFILL_LOCAL_CONCURRENCY", "0"),
        ]))
        .unwrap();
        assert_eq!(
            cfg.local_source_dirs,
            vec![
                PathBuf::from("/a/storage.flat-old-1"),
                PathBuf::from("/b/x")
            ]
        );
        assert_eq!(cfg.local_concurrency, 1, "clamped");
        let d = BackfillConfig::from_lookup(|_| None).unwrap();
        assert!(d.local_source_dirs.is_empty());
        assert_eq!(d.local_concurrency, 64);
        assert_eq!(d.discovery_concurrency, 8);
        for (raw, want) in [("0", 1), ("16", 16), ("999", 64), ("x", 8)] {
            let c =
                BackfillConfig::from_lookup(lookup_of(&[("BACKFILL_DISCOVERY_CONCURRENCY", raw)]))
                    .unwrap();
            assert_eq!(c.discovery_concurrency, want, "{raw}");
        }
    }
}

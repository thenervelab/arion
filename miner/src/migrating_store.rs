//! Flat → packed migration: hybrid read path + throttled background mover.
//!
//! When the packed backend is selected on a data dir that still holds
//! per-file blobs, the node runs a [`MigratingStore`]: reads hit the packed
//! index first and fall back to the flat layout, writes go straight to the
//! packed volumes, and a background task drains the flat layout into the
//! volumes. No read can fail because of the migration, and the node serves
//! traffic the whole time.
//!
//! Mover contract, per blob:
//!
//! 1. read the flat file;
//! 2. verify `blake3(payload) == name` — the store protocol enforces this
//!    invariant on every write, so a mismatch means local corruption: the
//!    file is left in place (repair will re-place the shard) and only
//!    logged, never deleted;
//! 3. `store()` into the packed backend — returns only after the volume
//!    append is fsync'd (group commit);
//! 4. only then unlink the flat file.
//!
//! A crash between 3 and 4 leaves a duplicate (flat + packed), which the
//! next pass resolves by unlinking the flat copy: the mover is idempotent
//! and resumable — the cursor is the existence of the flat files
//! themselves. Trashed flat blobs move to packed tombstones (the trash TTL
//! clock lives in the inventory DB, so nothing about purge timing changes).
//!
//! Enumeration never materializes a directory listing, and never
//! `read_dir`s a root just to discover its shard subdirectories — the
//! legacy flat root can still hold tens of millions of `.bin` entries
//! (nodes where the 0.1.28 sharding migration never finished), and a
//! listing of it blocks for the node's whole uptime before the first blob
//! moves. Instead:
//!
//! - shard leaf directories (`ab/cd/`, ~1/65536 of the population each)
//!   are discovered by probing the 256 possible names per level (one
//!   `stat` each) and drained FIRST — progress is immediate and
//!   measurable;
//! - the legacy flat roots are drained LAST, streamed in bounded pages
//!   from a single held readdir cursor, moving blobs as they are
//!   enumerated;
//! - progress is logged every 60 s (`migration: progress`), and each phase
//!   announces itself when it starts.
//!
//! Within a page, up to `PACKED_MIGRATE_CONCURRENCY` blobs (default 16)
//! are moved concurrently. This matters more than any throttle: the packed
//! writer group-commits — it drains every pending store into one append +
//! one `fdatasync` — so N concurrent movers share a single flush where a
//! sequential mover pays cold-read latency plus a full fsync **per blob**
//! (measured ~15-25 blobs/s on a latency-bound spindle pool, i.e. weeks
//! for a 70M-blob node, with the disks mostly idle). Concurrent moves also
//! overlap the cold flat-store reads, which is where the remaining time
//! goes.
//!
//! Throttle knobs: `PACKED_MIGRATE_BATCH` blobs per page (default 1000)
//! and `PACKED_MIGRATE_PAUSE_MS` between pages (default 100), capping the
//! mover at ~10k blobs/s; the filesystem is the real limiter on I/O-bound
//! nodes. Emptied leaf directories are removed at the end of the pass.

use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, Instant};

use bytes::Bytes;

use crate::flat_store::FlatBlobStore;
use crate::packed_store::PackedStore;
use crate::store::BlobStore;

fn env_u64(name: &str, default: u64) -> u64 {
    std::env::var(name)
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(default)
}

/// Hybrid store used while a flat layout is being drained into packed
/// volumes: packed is authoritative for new data, flat is the fallback.
#[derive(Debug)]
pub struct MigratingStore {
    pub flat: Arc<FlatBlobStore>,
    pub packed: Arc<PackedStore>,
}

#[async_trait::async_trait]
impl BlobStore for MigratingStore {
    /// New data always lands in the packed volumes.
    async fn store(&self, hash_hex: &str, data: &[u8]) -> std::io::Result<()> {
        self.packed.store(hash_hex, data).await?;
        // A flat copy from before the migration is superseded.
        if self.flat.has(hash_hex) {
            self.flat.remove(hash_hex).await.ok();
        }
        Ok(())
    }

    async fn read(&self, hash_hex: &str) -> std::io::Result<Bytes> {
        match self.packed.read(hash_hex).await {
            Ok(b) => Ok(b),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => self.flat.read(hash_hex).await,
            Err(e) => Err(e),
        }
    }

    fn has(&self, hash_hex: &str) -> bool {
        self.packed.has(hash_hex) || self.flat.has(hash_hex)
    }

    async fn delete(&self, hash_hex: &str) -> std::io::Result<()> {
        // The blob may exist on either side (or both, mid-migration): trash
        // every copy so none keeps serving.
        if self.packed.has(hash_hex) {
            self.packed.delete(hash_hex).await?;
        }
        if self.flat.has(hash_hex) {
            self.flat.delete(hash_hex).await?;
        }
        Ok(())
    }

    async fn remove(&self, hash_hex: &str) -> std::io::Result<()> {
        self.packed.remove(hash_hex).await?;
        self.flat.remove(hash_hex).await
    }

    async fn restore(&self, hash_hex: &str) -> std::io::Result<bool> {
        let a = self.packed.restore(hash_hex).await?;
        let b = self.flat.restore(hash_hex).await?;
        Ok(a || b)
    }

    async fn purge_trashed(&self, hash_hex: &str) -> std::io::Result<()> {
        self.packed.purge_trashed(hash_hex).await?;
        self.flat.purge_trashed(hash_hex).await
    }

    fn list_hashes(&self) -> Vec<String> {
        // Union, packed first (authoritative), flat entries not yet moved.
        let mut out = self.packed.list_hashes();
        let mut seen: std::collections::HashSet<String> = out.iter().cloned().collect();
        for h in self.flat.list_hashes() {
            if seen.insert(h.clone()) {
                out.push(h);
            }
        }
        out
    }

    fn list_trashed_hashes(&self) -> Vec<String> {
        let mut out = self.packed.list_trashed_hashes();
        let mut seen: std::collections::HashSet<String> = out.iter().cloned().collect();
        for h in self.flat.list_trashed_hashes() {
            if seen.insert(h.clone()) {
                out.push(h);
            }
        }
        out
    }

    fn has_trashed(&self, hash_hex: &str) -> bool {
        self.packed.has_trashed(hash_hex) || self.flat.has_trashed(hash_hex)
    }

    fn used_bytes(&self) -> u64 {
        self.packed.used_bytes() + self.flat.used_bytes()
    }

    fn trash_bytes(&self) -> u64 {
        self.packed.trash_bytes() + self.flat.trash_bytes()
    }

    fn recompute_usage(&self) {
        self.packed.recompute_usage();
        self.flat.recompute_usage();
    }

    fn cleanup_stale_tmp(&self) -> usize {
        self.packed.cleanup_stale_tmp() + self.flat.cleanup_stale_tmp()
    }

    /// The 0.1.28 flat-root → sharded-dirs migration is superseded by the
    /// flat → packed mover; running both would double the I/O for nothing.
    async fn migrate_legacy_layout(&self, _batch: usize, _pause: Duration) -> u64 {
        0
    }
}

/// Counters published by the mover (for logs). `skipped` counts skip
/// EVENTS (corrupt blob re-seen on a later pass, raced delete), not unique
/// blobs.
#[derive(Debug, Default)]
pub struct MigrationProgress {
    pub migrated: AtomicU64,
    pub bytes: AtomicU64,
    pub skipped: AtomicU64,
    pub done: std::sync::atomic::AtomicBool,
}

/// How often the mover reports progress while it works.
const PROGRESS_LOG_INTERVAL: Duration = Duration::from_secs(60);

/// All existing two-hex-digit subdirectories of `base`, found by PROBING
/// the 256 possible names directly (one `stat` each). Never `read_dir`s
/// `base`: filtering a giant flat root for its shard dirs is exactly the
/// stall that kept the 0.1.29 mover from ever starting on nodes still
/// mid-way through the 0.1.28 sharding migration.
fn probe_hex_subdirs(base: &Path) -> Vec<PathBuf> {
    (0u16..=255)
        .map(|i| base.join(format!("{i:02x}")))
        .filter(|p| p.is_dir())
        .collect()
}

/// Streaming pager over the `*.bin` entries of one directory. Holds the
/// readdir cursor across pages so a directory of any size is enumerated at
/// most once per pass, in bounded chunks, off the async runtime — the full
/// listing is never collected.
struct BinPager {
    dir: PathBuf,
    cursor: Option<std::fs::ReadDir>,
    exhausted: bool,
}

impl BinPager {
    fn new(dir: &Path) -> Self {
        Self {
            dir: dir.to_path_buf(),
            cursor: None,
            exhausted: false,
        }
    }

    /// Next page of up to `batch` blob names. Empty page = directory
    /// exhausted for this pass.
    async fn next_page(&mut self, batch: usize) -> Vec<String> {
        if self.exhausted {
            return Vec::new();
        }
        let cursor = self.cursor.take();
        let dir = self.dir.clone();
        let (cursor, page) = tokio::task::spawn_blocking(move || {
            let mut cursor = match cursor {
                Some(c) => c,
                None => match std::fs::read_dir(&dir) {
                    Ok(c) => c,
                    Err(_) => return (None, Vec::new()),
                },
            };
            let mut page = Vec::with_capacity(batch.min(4096));
            for e in cursor.by_ref().flatten() {
                let Ok(name) = e.file_name().into_string() else {
                    continue;
                };
                let Some(h) = name.strip_suffix(".bin") else {
                    continue;
                };
                if !e.file_type().map(|t| t.is_file()).unwrap_or(false) {
                    continue;
                }
                page.push(h.to_string());
                if page.len() >= batch {
                    // Cursor survives to the next call: the next page
                    // resumes here instead of re-reading from the start.
                    return (Some(cursor), page);
                }
            }
            (None, page)
        })
        .await
        .unwrap_or((None, Vec::new()));
        self.cursor = cursor;
        self.exhausted = self.cursor.is_none();
        page
    }
}

/// Move one live flat blob into the packed store. Returns payload size, or
/// `None` when the blob was skipped (gone already, or left in place because
/// its content no longer matches its name).
async fn move_one(flat: &FlatBlobStore, packed: &PackedStore, hash: &str) -> Option<u64> {
    if packed.has(hash) {
        // Already migrated (crash between store and unlink): just unlink.
        flat.remove(hash).await.ok();
        return Some(0);
    }
    let data = match flat.read(hash).await {
        Ok(d) => d,
        Err(_) => return None, // deleted/trashed since enumeration
    };
    // The store protocol guarantees name == blake3(payload); a mismatch
    // here means the flat copy rotted locally. Leave it for repair to
    // re-place — never carry corruption forward, never delete evidence.
    if blake3::hash(&data).to_hex().as_str() != hash {
        tracing::warn!(
            hash,
            "migration: flat blob fails hash check, leaving in place"
        );
        return None;
    }
    if let Err(e) = packed.store(hash, &data).await {
        tracing::warn!(hash, error = %e, "migration: packed store failed, will retry");
        return None;
    }
    // Durable in the volume (acked after fsync): the flat copy can go.
    flat.remove(hash).await.ok();
    Some(data.len() as u64)
}

/// Which space a directory being drained belongs to.
#[derive(Clone, Copy, PartialEq)]
enum Space {
    Live,
    Trash,
}

/// The mover's working state: stores, throttle, counters, progress log.
struct Mover {
    flat: Arc<FlatBlobStore>,
    packed: Arc<PackedStore>,
    progress: Arc<MigrationProgress>,
    limit: Option<u64>,
    batch: usize,
    pause: Duration,
    concurrency: usize,
    moved_total: u64,
    phase: &'static str,
    dirs_left: usize,
    last_log: Instant,
    last_logged_moved: u64,
}

impl Mover {
    fn limit_hit(&self) -> bool {
        self.limit.is_some_and(|l| self.moved_total >= l)
    }

    /// Periodic INFO so an operator can see the drain is alive — the
    /// 0.1.29 startup stall was invisible precisely because the mover
    /// logged nothing between its init line and its completion line.
    fn maybe_log(&mut self) {
        let elapsed = self.last_log.elapsed();
        if elapsed < PROGRESS_LOG_INTERVAL {
            return;
        }
        let moved = self.progress.migrated.load(Ordering::Relaxed);
        let rate = (moved.saturating_sub(self.last_logged_moved)) / elapsed.as_secs().max(1);
        tracing::info!(
            phase = self.phase,
            moved,
            bytes = self.progress.bytes.load(Ordering::Relaxed),
            skipped = self.progress.skipped.load(Ordering::Relaxed),
            dirs_left = self.dirs_left,
            blobs_per_s = rate,
            "migration: progress"
        );
        self.last_log = Instant::now();
        self.last_logged_moved = moved;
    }

    /// Trashed blobs: restore → pack → tombstone → drop the flat copy. The
    /// trash TTL clock lives in the inventory DB and is untouched.
    async fn move_trashed(&self, hash: &str) -> Option<u64> {
        if !self.flat.restore(hash).await.unwrap_or(false) {
            return None; // purged/restored since enumeration
        }
        match move_one(&self.flat, &self.packed, hash).await {
            Some(n) => {
                self.packed.delete(hash).await.ok(); // back to (packed) trash
                Some(n)
            }
            None => {
                // Could not pack it: put it back in the flat trash so the
                // TTL semantics stay intact.
                self.flat.delete(hash).await.ok();
                None
            }
        }
    }

    /// Move one page of blobs with bounded concurrency. Sequential moves
    /// pay cold-read latency plus one full `fdatasync` per blob; with N in
    /// flight the packed writer group-commits them into shared flushes and
    /// the cold reads overlap. Blobs within a page are independent (moves
    /// are per-hash and idempotent), so ordering inside the page does not
    /// matter. Counters are applied after the page so `limit` stays exact
    /// at page granularity — callers truncate the page to the remaining
    /// budget first.
    async fn move_page(&mut self, page: Vec<String>, space: Space) {
        use futures::StreamExt;
        let take = match self.limit {
            Some(l) => (l.saturating_sub(self.moved_total) as usize).min(page.len()),
            None => page.len(),
        };
        let results: Vec<Option<u64>> = {
            let this: &Mover = self;
            futures::stream::iter(page.into_iter().take(take).map(|hash| async move {
                match space {
                    Space::Live => move_one(&this.flat, &this.packed, &hash).await,
                    Space::Trash => this.move_trashed(&hash).await,
                }
            }))
            .buffer_unordered(this.concurrency)
            .collect()
            .await
        };
        for res in results {
            match res {
                Some(bytes) => {
                    self.moved_total += 1;
                    self.progress.migrated.fetch_add(1, Ordering::Relaxed);
                    self.progress.bytes.fetch_add(bytes, Ordering::Relaxed);
                }
                None => {
                    self.progress.skipped.fetch_add(1, Ordering::Relaxed);
                }
            }
        }
        self.maybe_log();
    }

    /// Drain every `*.bin` in `dir`: streamed, paged, throttled. Repeats
    /// until a full pass moves nothing — unlinking entries mid-readdir
    /// makes it unspecified whether later entries are surfaced, so the
    /// final (near-empty, cheap) pass is the proof of completion. Entries
    /// that can only be skipped (corrupt, raced) never trigger another
    /// pass, so the mover cannot spin.
    async fn drain_dir(&mut self, dir: &Path, space: Space) {
        loop {
            if self.limit_hit() {
                return;
            }
            let moved_before = self.moved_total;
            let mut pager = BinPager::new(dir);
            loop {
                let page = pager.next_page(self.batch).await;
                if page.is_empty() {
                    break;
                }
                let full_page = page.len() >= self.batch;
                self.move_page(page, space).await;
                if self.limit_hit() {
                    return;
                }
                // Throttle only under sustained flow. A partial page means
                // the directory is exhausted — sleeping there turns sparse
                // leaf dirs (a couple of blobs each) into one pause per
                // handful of blobs and caps the whole drain at ~10-20
                // blobs/s (measured: 65 536 near-empty leaves x 100 ms
                // ≈ 90 min of pure sleep for 100k blobs).
                if full_page {
                    tokio::time::sleep(self.pause).await;
                }
            }
            if self.moved_total == moved_before {
                return;
            }
        }
    }

    /// Drain the sharded tree under `base`: leaf dirs are discovered by
    /// name probing, never by listing `base`.
    async fn drain_sharded_tree(&mut self, base: &Path, space: Space) {
        let l1_dirs = {
            let b = base.to_path_buf();
            tokio::task::spawn_blocking(move || probe_hex_subdirs(&b))
                .await
                .unwrap_or_default()
        };
        tracing::info!(
            phase = self.phase,
            base = %base.display(),
            l1_dirs = l1_dirs.len(),
            "migration: draining sharded leaf directories"
        );
        self.dirs_left = l1_dirs.len();
        for l1 in l1_dirs {
            if self.limit_hit() {
                return;
            }
            let leaves = {
                let l1 = l1.clone();
                tokio::task::spawn_blocking(move || probe_hex_subdirs(&l1))
                    .await
                    .unwrap_or_default()
            };
            for leaf in leaves {
                if self.limit_hit() {
                    return;
                }
                self.drain_dir(&leaf, space).await;
            }
            self.dirs_left = self.dirs_left.saturating_sub(1);
        }
    }
}

/// Drain the flat layout (live + trash, both the sharded tree and the
/// legacy flat root) into the packed store. Resumable and idempotent; safe
/// to run while the node serves traffic through a [`MigratingStore`].
/// `limit` bounds the number of blobs moved in this call (tests; `None` in
/// production).
pub async fn run_migration(
    flat: Arc<FlatBlobStore>,
    packed: Arc<PackedStore>,
    data_dir: PathBuf,
    progress: Arc<MigrationProgress>,
    limit: Option<u64>,
) -> u64 {
    let batch = env_u64("PACKED_MIGRATE_BATCH", 1000).clamp(1, 100_000) as usize;
    let pause = Duration::from_millis(env_u64("PACKED_MIGRATE_PAUSE_MS", 100));
    let concurrency = env_u64("PACKED_MIGRATE_CONCURRENCY", 16).clamp(1, 256) as usize;
    let trash_dir = data_dir.join("trash");
    tracing::info!(
        batch,
        pause_ms = pause.as_millis() as u64,
        concurrency,
        "migration: mover starting"
    );

    let mut mover = Mover {
        flat,
        packed,
        progress: Arc::clone(&progress),
        limit,
        batch,
        pause,
        concurrency,
        moved_total: 0,
        phase: "",
        dirs_left: 0,
        last_log: Instant::now(),
        last_logged_moved: 0,
    };

    // Sharded leaf dirs first (small, immediate measurable progress), the
    // giant legacy roots last.
    mover.phase = "sharded-live";
    mover.drain_sharded_tree(&data_dir, Space::Live).await;
    mover.phase = "sharded-trash";
    mover.drain_sharded_tree(&trash_dir, Space::Trash).await;

    mover.phase = "legacy-root-live";
    mover.dirs_left = 0;
    tracing::info!("migration: draining legacy flat root");
    mover.drain_dir(&data_dir, Space::Live).await;
    mover.phase = "legacy-root-trash";
    mover.drain_dir(&trash_dir, Space::Trash).await;

    if mover.limit_hit() {
        return mover.moved_total; // partial run: no sweep, not done
    }
    let moved_total = mover.moved_total;

    // Sweep now-empty shard leaf directories (their dnodes are the point).
    let removed_dirs = {
        let data = data_dir.clone();
        let trash = trash_dir.clone();
        tokio::task::spawn_blocking(move || {
            let mut removed = 0usize;
            for base in [&data, &trash] {
                for l1 in probe_hex_subdirs(base) {
                    for l2 in probe_hex_subdirs(&l1) {
                        if std::fs::remove_dir(&l2).is_ok() {
                            removed += 1;
                        }
                    }
                    if std::fs::remove_dir(&l1).is_ok() {
                        removed += 1;
                    }
                }
            }
            removed
        })
        .await
        .unwrap_or(0)
    };

    progress.done.store(true, Ordering::Relaxed);
    tracing::info!(
        moved = moved_total,
        bytes = progress.bytes.load(Ordering::Relaxed),
        left_in_place = progress.skipped.load(Ordering::Relaxed),
        removed_dirs,
        "migration: flat layout drained into packed volumes"
    );
    moved_total
}

/// First `*.bin` found in `dir`, lazily — stops at the first hit.
fn has_any_bin(dir: &Path) -> bool {
    let Ok(entries) = std::fs::read_dir(dir) else {
        return false;
    };
    entries.flatten().any(|e| {
        e.file_name().to_string_lossy().ends_with(".bin")
            && e.file_type().map(|t| t.is_file()).unwrap_or(false)
    })
}

/// Whether a data dir still holds flat-layout blobs (live or trashed) that
/// need migrating. Bounded probe: shard dirs are found by name probing
/// (never by listing the roots), and each directory scan stops at the
/// first `.bin`.
pub fn flat_data_present(data_dir: &Path) -> bool {
    let trash = data_dir.join("trash");
    for base in [data_dir, trash.as_path()] {
        if has_any_bin(base) {
            return true;
        }
        for l1 in probe_hex_subdirs(base) {
            for l2 in probe_hex_subdirs(&l1) {
                if has_any_bin(&l2) {
                    return true;
                }
            }
        }
    }
    false
}

#[cfg(test)]
mod tests {
    use super::*;

    fn h(data: &[u8]) -> String {
        blake3::hash(data).to_hex().to_string()
    }

    async fn setup(dir: &Path) -> (Arc<FlatBlobStore>, Arc<PackedStore>) {
        let flat = Arc::new(FlatBlobStore::new(dir).unwrap());
        let packed = PackedStore::open(dir.join("packed")).unwrap();
        (flat, packed)
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn full_migration_drains_flat_and_preserves_reads() {
        let dir = tempfile::tempdir().unwrap();
        let (flat, packed) = setup(dir.path()).await;

        let live1 = b"alpha".to_vec();
        let live2 = b"beta-longer-payload".to_vec();
        let trashed = b"gamma".to_vec();
        flat.store(&h(&live1), &live1).await.unwrap();
        flat.store(&h(&live2), &live2).await.unwrap();
        flat.store(&h(&trashed), &trashed).await.unwrap();
        FlatBlobStore::delete(&flat, &h(&trashed)).await.unwrap();
        // A legacy (pre-sharding) file at the flat root as well.
        let legacy = b"legacy-root-blob".to_vec();
        std::fs::write(dir.path().join(format!("{}.bin", h(&legacy))), &legacy).unwrap();

        assert!(flat_data_present(dir.path()));

        let hybrid = MigratingStore {
            flat: Arc::clone(&flat),
            packed: Arc::clone(&packed),
        };
        // Reads work through the hybrid before migration.
        assert_eq!(hybrid.read(&h(&live1)).await.unwrap().as_ref(), &live1[..]);
        assert_eq!(
            hybrid.read(&h(&legacy)).await.unwrap().as_ref(),
            &legacy[..]
        );

        let progress = Arc::new(MigrationProgress::default());
        let moved = run_migration(
            Arc::clone(&flat),
            Arc::clone(&packed),
            dir.path().to_path_buf(),
            Arc::clone(&progress),
            None,
        )
        .await;
        assert_eq!(moved, 4); // 3 live (incl. legacy) + 1 trashed

        // Everything reads from packed alone now.
        assert_eq!(packed.read(&h(&live1)).await.unwrap().as_ref(), &live1[..]);
        assert_eq!(packed.read(&h(&live2)).await.unwrap().as_ref(), &live2[..]);
        assert_eq!(
            packed.read(&h(&legacy)).await.unwrap().as_ref(),
            &legacy[..]
        );
        assert!(packed.has_trashed(&h(&trashed)));
        assert!(!flat.has(&h(&live1)));
        assert!(!flat.has_trashed(&h(&trashed)));
        assert!(!flat_data_present(dir.path()));
        // Hybrid semantics unchanged after the drain.
        assert_eq!(hybrid.read(&h(&live2)).await.unwrap().as_ref(), &live2[..]);
        assert!(hybrid.has_trashed(&h(&trashed)));
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn migration_is_resumable() {
        let dir = tempfile::tempdir().unwrap();
        let (flat, packed) = setup(dir.path()).await;
        let payloads: Vec<Vec<u8>> = (0..5u8).map(|i| vec![i; 64]).collect();
        for p in &payloads {
            flat.store(&h(p), p).await.unwrap();
        }
        let progress = Arc::new(MigrationProgress::default());
        let first = run_migration(
            Arc::clone(&flat),
            Arc::clone(&packed),
            dir.path().to_path_buf(),
            Arc::clone(&progress),
            Some(2),
        )
        .await;
        assert_eq!(first, 2);
        assert!(flat_data_present(dir.path()));

        let rest = run_migration(
            Arc::clone(&flat),
            Arc::clone(&packed),
            dir.path().to_path_buf(),
            Arc::clone(&progress),
            None,
        )
        .await;
        assert_eq!(first + rest, 5);
        for p in &payloads {
            assert_eq!(packed.read(&h(p)).await.unwrap().as_ref(), &p[..]);
        }
        assert!(!flat_data_present(dir.path()));
    }

    /// Exercises the concurrent path (default concurrency 16, several full
    /// pages of parallel moves, live + trash mixed): every blob must land
    /// exactly once and the counters must add up.
    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn concurrent_migration_moves_every_blob_exactly_once() {
        let dir = tempfile::tempdir().unwrap();
        let (flat, packed) = setup(dir.path()).await;
        let mut live = Vec::new();
        let mut trashed = Vec::new();
        for i in 0..300u32 {
            let p = i.to_le_bytes().repeat(1 + (i as usize % 7)).to_vec();
            flat.store(&h(&p), &p).await.unwrap();
            if i % 5 == 0 {
                FlatBlobStore::delete(&flat, &h(&p)).await.unwrap();
                trashed.push(p);
            } else {
                live.push(p);
            }
        }

        let progress = Arc::new(MigrationProgress::default());
        let moved = run_migration(
            Arc::clone(&flat),
            Arc::clone(&packed),
            dir.path().to_path_buf(),
            Arc::clone(&progress),
            None,
        )
        .await;
        assert_eq!(moved, 300);
        assert_eq!(progress.migrated.load(Ordering::Relaxed), 300);
        assert_eq!(progress.skipped.load(Ordering::Relaxed), 0);
        for p in &live {
            assert_eq!(packed.read(&h(p)).await.unwrap().as_ref(), &p[..]);
        }
        for p in &trashed {
            assert!(packed.has_trashed(&h(p)));
        }
        assert!(!flat_data_present(dir.path()));
        // Exactly once: the packed index lists each hash a single time.
        assert_eq!(packed.list_hashes().len(), live.len());
        assert_eq!(packed.list_trashed_hashes().len(), trashed.len());
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn corrupt_flat_blob_is_left_in_place() {
        let dir = tempfile::tempdir().unwrap();
        let (flat, packed) = setup(dir.path()).await;
        let good = b"intact".to_vec();
        flat.store(&h(&good), &good).await.unwrap();
        // A blob whose content no longer matches its name (local rot).
        let rotten_name = h(b"original-content");
        flat.store(&rotten_name, b"bit-rotted!").await.unwrap();

        let progress = Arc::new(MigrationProgress::default());
        let moved = run_migration(
            Arc::clone(&flat),
            Arc::clone(&packed),
            dir.path().to_path_buf(),
            Arc::clone(&progress),
            None,
        )
        .await;
        assert_eq!(moved, 1);
        assert!(packed.has(&h(&good)));
        // The rotten copy is untouched: still served nowhere as valid data,
        // but preserved as evidence / for repair to overwrite.
        assert!(!packed.has(&rotten_name));
        assert!(flat.has(&rotten_name));
        assert_eq!(progress.skipped.load(Ordering::Relaxed), 1);
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn interrupted_between_pack_and_unlink_is_idempotent() {
        let dir = tempfile::tempdir().unwrap();
        let (flat, packed) = setup(dir.path()).await;
        let data = b"double-stored".to_vec();
        flat.store(&h(&data), &data).await.unwrap();
        // Simulate the crash window: already packed, flat copy still there.
        packed.store(&h(&data), &data).await.unwrap();

        let progress = Arc::new(MigrationProgress::default());
        run_migration(
            Arc::clone(&flat),
            Arc::clone(&packed),
            dir.path().to_path_buf(),
            Arc::clone(&progress),
            None,
        )
        .await;
        assert!(!flat.has(&h(&data)));
        assert_eq!(packed.read(&h(&data)).await.unwrap().as_ref(), &data[..]);
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn sharded_leaves_drain_before_legacy_root() {
        let dir = tempfile::tempdir().unwrap();
        let (flat, packed) = setup(dir.path()).await;
        // One blob in a shard leaf dir, one at the legacy flat root.
        let leaf_blob = b"sharded-first".to_vec();
        flat.store(&h(&leaf_blob), &leaf_blob).await.unwrap();
        let root_blob = b"legacy-later".to_vec();
        let root_path = dir.path().join(format!("{}.bin", h(&root_blob)));
        std::fs::write(&root_path, &root_blob).unwrap();

        let progress = Arc::new(MigrationProgress::default());
        let moved = run_migration(
            Arc::clone(&flat),
            Arc::clone(&packed),
            dir.path().to_path_buf(),
            Arc::clone(&progress),
            Some(1),
        )
        .await;
        assert_eq!(moved, 1);
        // The leaf blob moved; the legacy root was not touched yet.
        assert!(packed.has(&h(&leaf_blob)));
        assert!(!packed.has(&h(&root_blob)));
        assert!(root_path.exists());
    }

    /// Regression test for the 0.1.29 startup stall: the mover must land
    /// its first blob without enumerating (let alone materializing) a
    /// legacy root holding a huge number of entries.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn first_blob_moves_without_enumerating_a_huge_root() {
        const ROOT_ENTRIES: usize = 30_000;
        let dir = tempfile::tempdir().unwrap();
        let (flat, packed) = setup(dir.path()).await;
        // A root crowded with flat entries (contents never read: the run
        // is bounded to one move, which must come from the leaf dir).
        for i in 0..ROOT_ENTRIES {
            std::fs::write(dir.path().join(format!("{i:064x}.bin")), b"x").unwrap();
        }
        let leaf_blob = b"must-move-first".to_vec();
        flat.store(&h(&leaf_blob), &leaf_blob).await.unwrap();

        let progress = Arc::new(MigrationProgress::default());
        let started = Instant::now();
        let moved = run_migration(
            Arc::clone(&flat),
            Arc::clone(&packed),
            dir.path().to_path_buf(),
            Arc::clone(&progress),
            Some(1),
        )
        .await;
        let elapsed = started.elapsed();
        assert_eq!(moved, 1);
        assert!(packed.has(&h(&leaf_blob)));
        // Generous CI bound: probing 512 names + one leaf page is
        // milliseconds; a root enumeration at this scale would already
        // push past it on a slow runner, and on the real nodes (tens of
        // millions of entries) it never returned at all.
        assert!(
            elapsed < Duration::from_secs(10),
            "first move took {elapsed:?}"
        );
        // Every root entry is still in place: none were needed.
        let root_bins = std::fs::read_dir(dir.path())
            .unwrap()
            .flatten()
            .filter(|e| e.file_name().to_string_lossy().ends_with(".bin"))
            .count();
        assert_eq!(root_bins, ROOT_ENTRIES);
    }

    /// Heap probe (not a pass/fail test — run with `--ignored --nocapture`):
    /// reproduces the mover on a synthetic population with the production
    /// size mix (90% tiny, 10% ~90 KB) and reports the REAL marginal
    /// RssAnon per migrated blob, straight from /proc. Knobs:
    /// `RSS_PROBE_BLOBS` (default 100k), `PACKED_MIGRATE_CONCURRENCY`,
    /// `MALLOC_ARENA_MAX` (set on the test process).
    #[ignore]
    #[tokio::test(flavor = "multi_thread", worker_threads = 8)]
    async fn rss_probe_migration_marginal_heap() {
        fn rss_anon_kb() -> u64 {
            std::fs::read_to_string("/proc/self/status")
                .ok()
                .and_then(|s| {
                    s.lines()
                        .find(|l| l.starts_with("RssAnon:"))
                        .and_then(|l| l.split_whitespace().nth(1))
                        .and_then(|v| v.parse().ok())
                })
                .unwrap_or(0)
        }
        let n: usize = std::env::var("RSS_PROBE_BLOBS")
            .ok()
            .and_then(|v| v.parse().ok())
            .unwrap_or(100_000);
        let dir = tempfile::tempdir().unwrap();
        let (flat, packed) = setup(dir.path()).await;

        let mut total_bytes = 0u64;
        for i in 0..n {
            // Production mix: median ~100 B, ~10% around 90 KB.
            let size = if i % 10 == 0 {
                90_000 + i % 4096
            } else {
                100 + i % 64
            };
            let mut p = vec![0u8; size];
            p[..8].copy_from_slice(&(i as u64).to_le_bytes());
            total_bytes += size as u64;
            flat.store(&h(&p), &p).await.unwrap();
        }
        let rss_before = rss_anon_kb();
        println!(
            "probe: {} blobs ({} MB) staged, RssAnon before migration = {} MB",
            n,
            total_bytes >> 20,
            rss_before >> 10
        );

        let progress = Arc::new(MigrationProgress::default());
        let t0 = Instant::now();
        let moved = run_migration(
            Arc::clone(&flat),
            Arc::clone(&packed),
            dir.path().to_path_buf(),
            Arc::clone(&progress),
            None,
        )
        .await;
        let secs = t0.elapsed().as_secs_f64();
        let rss_after = rss_anon_kb();
        assert_eq!(moved as usize, n);
        let marginal = (rss_after.saturating_sub(rss_before) * 1024) / n as u64;
        println!(
            "probe: migrated {} blobs in {:.1}s ({:.0} blobs/s), RssAnon after = {} MB, marginal = {} B/blob",
            moved,
            secs,
            moved as f64 / secs,
            rss_after >> 10,
            marginal
        );
        // Give the allocator a chance to return freed memory, then re-read.
        drop(packed);
        tokio::time::sleep(Duration::from_secs(2)).await;
        unsafe { libc::malloc_trim(0) };
        println!(
            "probe: RssAnon after malloc_trim = {} MB",
            rss_anon_kb() >> 10
        );
    }

    /// Leaf discovery must not depend on listing the root at all: with the
    /// root's read permission removed (execute kept), probing still finds
    /// and drains the shard dirs.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn leaf_drain_needs_no_root_readdir() {
        use std::os::unix::fs::PermissionsExt;
        let dir = tempfile::tempdir().unwrap();
        let (flat, packed) = setup(dir.path()).await;
        let leaf_blob = b"reachable-by-probe".to_vec();
        flat.store(&h(&leaf_blob), &leaf_blob).await.unwrap();

        std::fs::set_permissions(dir.path(), std::fs::Permissions::from_mode(0o311)).unwrap();
        let progress = Arc::new(MigrationProgress::default());
        let moved = run_migration(
            Arc::clone(&flat),
            Arc::clone(&packed),
            dir.path().to_path_buf(),
            Arc::clone(&progress),
            Some(1),
        )
        .await;
        // Restore before asserting so the tempdir can always be cleaned.
        std::fs::set_permissions(dir.path(), std::fs::Permissions::from_mode(0o755)).unwrap();
        assert_eq!(moved, 1);
        assert!(packed.has(&h(&leaf_blob)));
    }
}

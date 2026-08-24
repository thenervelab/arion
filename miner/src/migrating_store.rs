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
//! Enumeration is paged by shard leaf directory (`ab/cd/`, ~1/65536 of the
//! population each) plus a bounded page of the legacy flat root, so the
//! mover never materializes the full blob list in memory. Throttle knobs:
//! `PACKED_MIGRATE_BATCH` blobs per page (default 500) and
//! `PACKED_MIGRATE_PAUSE_MS` between pages (default 250) — start slow on
//! drowning nodes; the node gets lighter as the migration progresses.
//! Emptied leaf directories are removed at the end of the pass.

use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;

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

/// Counters published by the mover (for logs and the metrics endpoint).
#[derive(Debug, Default)]
pub struct MigrationProgress {
    pub migrated: AtomicU64,
    pub bytes: AtomicU64,
    pub corrupt_left: AtomicU64,
    pub done: std::sync::atomic::AtomicBool,
}

/// One bounded page of `*.bin` names from a single directory (never
/// recursive — leaf dirs are enumerated one at a time by the caller).
fn page_of_bins(dir: &Path, batch: usize) -> Vec<String> {
    let Ok(entries) = std::fs::read_dir(dir) else {
        return Vec::new();
    };
    entries
        .flatten()
        .filter_map(|e| {
            let n = e.file_name().into_string().ok()?;
            let h = n.strip_suffix(".bin")?;
            e.file_type().ok()?.is_file().then(|| h.to_string())
        })
        .take(batch)
        .collect()
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
    let batch = env_u64("PACKED_MIGRATE_BATCH", 500).clamp(1, 100_000) as usize;
    let pause = Duration::from_millis(env_u64("PACKED_MIGRATE_PAUSE_MS", 250));
    let trash_dir = data_dir.join("trash");
    let mut moved_total = 0u64;

    // Live blobs: legacy flat root first (bounded pages), then each shard
    // leaf directory in turn.
    let mut roots: Vec<PathBuf> = vec![data_dir.clone()];
    for l1 in list_two_hex_dirs(&data_dir) {
        for l2 in list_two_hex_dirs(&l1) {
            roots.push(l2);
        }
    }
    for root in roots {
        loop {
            if let Some(l) = limit
                && moved_total >= l
            {
                return moved_total;
            }
            let page = page_of_bins(&root, batch);
            if page.is_empty() {
                break;
            }
            let mut all_skipped = true;
            for hash in &page {
                if let Some(l) = limit
                    && moved_total >= l
                {
                    return moved_total;
                }
                if let Some(bytes) = move_one(&flat, &packed, hash).await {
                    moved_total += 1;
                    progress.migrated.fetch_add(1, Ordering::Relaxed);
                    progress.bytes.fetch_add(bytes, Ordering::Relaxed);
                    all_skipped = false;
                } else {
                    progress.corrupt_left.fetch_add(1, Ordering::Relaxed);
                }
            }
            if all_skipped {
                // Every entry in this page is unmovable (corrupt or raced):
                // stop paging this dir or we would spin on it forever.
                break;
            }
            tokio::time::sleep(pause).await;
        }
    }

    // Trashed blobs: restore → pack → tombstone → drop the flat copy. The
    // trash TTL clock lives in the inventory DB and is untouched.
    for hash in flat.list_trashed_hashes() {
        if let Some(l) = limit
            && moved_total >= l
        {
            return moved_total;
        }
        if !flat.restore(&hash).await.unwrap_or(false) {
            continue;
        }
        match move_one(&flat, &packed, &hash).await {
            Some(_) => {
                packed.delete(&hash).await.ok(); // back to (packed) trash
                moved_total += 1;
                progress.migrated.fetch_add(1, Ordering::Relaxed);
            }
            None => {
                // Could not pack it: put it back in the flat trash so the
                // TTL semantics stay intact.
                flat.delete(&hash).await.ok();
                progress.corrupt_left.fetch_add(1, Ordering::Relaxed);
            }
        }
        tokio::time::sleep(Duration::from_millis(5)).await;
    }

    // Sweep now-empty shard leaf directories (their dnodes are the point).
    let mut removed_dirs = 0usize;
    for base in [&data_dir, &trash_dir] {
        for l1 in list_two_hex_dirs(base) {
            for l2 in list_two_hex_dirs(&l1) {
                if std::fs::remove_dir(&l2).is_ok() {
                    removed_dirs += 1;
                }
            }
            if std::fs::remove_dir(&l1).is_ok() {
                removed_dirs += 1;
            }
        }
    }

    progress.done.store(true, Ordering::Relaxed);
    tracing::info!(
        moved = moved_total,
        bytes = progress.bytes.load(Ordering::Relaxed),
        left_in_place = progress.corrupt_left.load(Ordering::Relaxed),
        removed_dirs,
        "migration: flat layout drained into packed volumes"
    );
    moved_total
}

fn list_two_hex_dirs(base: &Path) -> Vec<PathBuf> {
    let Ok(entries) = std::fs::read_dir(base) else {
        return Vec::new();
    };
    let mut out: Vec<PathBuf> = entries
        .flatten()
        .filter_map(|e| {
            let n = e.file_name().into_string().ok()?;
            (n.len() == 2
                && n != "trash"
                && n.bytes().all(|b| b.is_ascii_hexdigit())
                && e.file_type().ok()?.is_dir())
            .then(|| e.path())
        })
        .collect();
    out.sort();
    out
}

/// Whether a data dir still holds flat-layout blobs (live or trashed) that
/// need migrating. Bounded probe: one readdir page per level, no full walk.
pub fn flat_data_present(data_dir: &Path) -> bool {
    fn has_any_bin(dir: &Path) -> bool {
        !page_of_bins(dir, 1).is_empty()
    }
    if has_any_bin(data_dir) {
        return true;
    }
    for l1 in list_two_hex_dirs(data_dir) {
        for l2 in list_two_hex_dirs(&l1) {
            if has_any_bin(&l2) {
                return true;
            }
        }
    }
    let trash = data_dir.join("trash");
    if has_any_bin(&trash) {
        return true;
    }
    for l1 in list_two_hex_dirs(&trash) {
        for l2 in list_two_hex_dirs(&l1) {
            if has_any_bin(&l2) {
                return true;
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
        assert_eq!(progress.corrupt_left.load(Ordering::Relaxed), 1);
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
}

//! Blob store for shard storage: sharded flat files.
//!
//! Blobs are stored as `{data_dir}/{h[0:2]}/{h[2:4]}/{hash}.bin` (65 536
//! leaf directories). The historical layout was one flat directory holding
//! every blob; at millions of entries that hit the ext4 `dir_index` limit
//! (ENOSPC on create with terabytes free) and made every enumeration a
//! dnode-read storm on ZFS. Reads fall back to the legacy flat path, writes
//! always go sharded, and a throttled background migrator renames legacy
//! entries into the sharded tree (same filesystem — pure metadata moves).
//!
//! Atomic writes via temp-file + rename prevent partial reads.
//!
//! Deletes are two-phase: `delete()` renames the blob into the sharded
//! trash (`{data_dir}/trash/{h[0:2]}/{h[2:4]}/{hash}.bin`) where it no
//! longer counts as stored (not listed, not served, quota freed) but can be
//! brought back by `restore()` until purged. Directory walks are bounded to
//! the expected shapes, so trash and live never leak into each other.

use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};

use bytes::Bytes;

/// Name of the trash subdirectory inside the data dir.
const TRASH_DIR: &str = "trash";

/// Directory for in-flight writes (crash leftovers are purged on startup).
const TMP_DIR: &str = ".tmp";

/// Simple sharded-file blob store.
#[derive(Debug)]
pub struct FlatBlobStore {
    data_dir: PathBuf,
    trash_dir: PathBuf,
    tmp_dir: PathBuf,
    used_bytes: AtomicU64,
    trash_bytes: AtomicU64,
}

/// `ab/cd/<hash>.bin` for a well-formed hex hash; `None` for anything that
/// cannot be sharded (defensive: such names only ever existed flat).
fn sharded_rel(hash_hex: &str) -> Option<PathBuf> {
    if hash_hex.len() < 4 || !hash_hex.as_bytes()[..4].iter().all(u8::is_ascii_hexdigit) {
        return None;
    }
    Some(
        PathBuf::from(&hash_hex[0..2])
            .join(&hash_hex[2..4])
            .join(format!("{hash_hex}.bin")),
    )
}

/// Stream every `*.bin` blob under a store root — the flat legacy level
/// plus the two-level sharded tree — to `visit(hash, entry)`. Never
/// descends anywhere else, so live, trash and tmp spaces stay disjoint.
///
/// STREAMING IS NOT OPTIONAL: a node can hold tens of millions of blobs,
/// and collecting their names is gigabytes of anonymous heap (~104 B per
/// name once String and allocator overhead are counted) that glibc never
/// returns to the kernel — measured 7+ GB of permanent RSS plus swap on
/// 31 GB nodes. Any walk over a blob space must go through a visitor.
pub(crate) fn for_each_bin(root: &Path, visit: &mut dyn FnMut(&str, &std::fs::DirEntry)) {
    let Ok(top) = std::fs::read_dir(root) else {
        return;
    };
    for entry in top.flatten() {
        let name = match entry.file_name().into_string() {
            Ok(n) => n,
            Err(_) => continue,
        };
        let ft = match entry.file_type() {
            Ok(t) => t,
            Err(_) => continue,
        };
        if ft.is_file() {
            if let Some(h) = name.strip_suffix(".bin") {
                visit(h, &entry);
            }
        } else if ft.is_dir() && name.len() == 2 && name != TRASH_DIR {
            let Ok(mid) = std::fs::read_dir(entry.path()) else {
                continue;
            };
            for sub in mid.flatten() {
                if !sub.file_type().map(|t| t.is_dir()).unwrap_or(false) {
                    continue;
                }
                let Ok(leaves) = std::fs::read_dir(sub.path()) else {
                    continue;
                };
                for leaf in leaves.flatten() {
                    if let Ok(n) = leaf.file_name().into_string()
                        && let Some(h) = n.strip_suffix(".bin")
                    {
                        visit(h, &leaf);
                    }
                }
            }
        }
    }
}

/// Materialized listing — ONLY for spaces known to be small (trash) or
/// explicit rebuild paths. Steady-state code must use [`for_each_bin`].
pub(crate) fn walk_bin_names(root: &Path) -> Vec<String> {
    let mut out = Vec::new();
    for_each_bin(root, &mut |h, _| out.push(h.to_string()));
    out
}

/// Sum file sizes under a store root (flat level + sharded tree).
/// One `stat` per file, zero allocation per blob — background use only.
fn walk_usage(root: &Path) -> (u64, u64) {
    let (mut bytes, mut files) = (0u64, 0u64);
    for_each_bin(root, &mut |_, entry| {
        if let Ok(m) = entry.metadata() {
            bytes += m.len();
            files += 1;
        }
    });
    (bytes, files)
}

impl FlatBlobStore {
    /// Create the store, ensuring the data, trash and tmp directories exist.
    ///
    /// Returns immediately: usage counters start at zero and are filled in
    /// by [`recompute_usage`](Self::recompute_usage) off the startup path
    /// (sizing walks cost one `stat` per blob — hours on large ZFS nodes).
    pub fn new(data_dir: impl AsRef<Path>) -> std::io::Result<Self> {
        let data_dir = data_dir.as_ref().to_path_buf();
        let trash_dir = data_dir.join(TRASH_DIR);
        let tmp_dir = data_dir.join(TMP_DIR);
        std::fs::create_dir_all(&data_dir)?;
        std::fs::create_dir_all(&trash_dir)?;
        std::fs::create_dir_all(&tmp_dir)?;

        Ok(Self {
            data_dir,
            trash_dir,
            tmp_dir,
            used_bytes: AtomicU64::new(0),
            trash_bytes: AtomicU64::new(0),
        })
    }

    /// Walk both spaces and set the usage counters. EXPENSIVE and blocking —
    /// run from `spawn_blocking` once the miner is registered and serving.
    pub fn recompute_usage(&self) {
        let (bytes, files) = walk_usage(&self.data_dir);
        let (trash_bytes, _) = walk_usage(&self.trash_dir);
        self.used_bytes.store(bytes, Ordering::Relaxed);
        self.trash_bytes.store(trash_bytes, Ordering::Relaxed);
        tracing::info!(
            blobs = files,
            used_bytes = bytes,
            trash_bytes,
            "storage: usage recomputed"
        );
    }

    /// Saturating decrement for the usage counters.
    ///
    /// The counters start at 0 on process start and only become authoritative
    /// once `recompute_usage` finishes -- tens of minutes on a large store. A
    /// delete processed before that would wrap the raw `fetch_sub` to
    /// ~u64::MAX, making the heartbeat report available_storage=0 and the
    /// validator zero this node's weight. Saturate
    /// instead: after the recompute the counter always covers the decrement,
    /// so steady-state behavior is unchanged.
    fn sub_used(&self, n: u64) {
        let _ = self
            .used_bytes
            .fetch_update(Ordering::Relaxed, Ordering::Relaxed, |v| {
                Some(v.saturating_sub(n))
            });
    }

    fn sub_trash(&self, n: u64) {
        let _ = self
            .trash_bytes
            .fetch_update(Ordering::Relaxed, Ordering::Relaxed, |v| {
                Some(v.saturating_sub(n))
            });
    }

    /// Preferred (sharded) path for a blob.
    fn blob_path(&self, hash_hex: &str) -> PathBuf {
        match sharded_rel(hash_hex) {
            Some(rel) => self.data_dir.join(rel),
            None => self.data_dir.join(format!("{hash_hex}.bin")),
        }
    }

    /// Legacy flat path (pre-sharding layout).
    fn blob_path_flat(&self, hash_hex: &str) -> PathBuf {
        self.data_dir.join(format!("{hash_hex}.bin"))
    }

    /// Where the blob actually lives right now, if anywhere.
    ///
    /// Re-checks the sharded path after a flat miss for the same reason `read`
    /// does: a concurrent `migrate_legacy_layout` rename between the two
    /// `exists` calls would otherwise report a present blob as absent, and
    /// `has()` feeds "do you hold this shard?" answers.
    fn locate(&self, hash_hex: &str) -> Option<PathBuf> {
        let sharded = self.blob_path(hash_hex);
        if sharded.exists() {
            return Some(sharded);
        }
        let flat = self.blob_path_flat(hash_hex);
        if flat != sharded && flat.exists() {
            return Some(flat);
        }
        if sharded.exists() {
            return Some(sharded);
        }
        None
    }

    /// Preferred (sharded) trash path.
    fn trash_path(&self, hash_hex: &str) -> PathBuf {
        match sharded_rel(hash_hex) {
            Some(rel) => self.trash_dir.join(rel),
            None => self.trash_dir.join(format!("{hash_hex}.bin")),
        }
    }

    fn trash_path_flat(&self, hash_hex: &str) -> PathBuf {
        self.trash_dir.join(format!("{hash_hex}.bin"))
    }

    fn locate_trashed(&self, hash_hex: &str) -> Option<PathBuf> {
        let sharded = self.trash_path(hash_hex);
        if sharded.exists() {
            return Some(sharded);
        }
        let flat = self.trash_path_flat(hash_hex);
        if flat != sharded && flat.exists() {
            return Some(flat);
        }
        // `migrate_legacy_layout` walks the trash root too — same race as `locate`.
        if sharded.exists() {
            return Some(sharded);
        }
        None
    }

    /// Store blob data. Atomic via temp-file + rename into the sharded tree.
    pub async fn store(&self, hash_hex: &str, data: &[u8]) -> std::io::Result<()> {
        let target = self.blob_path(hash_hex);
        if let Some(parent) = target.parent() {
            tokio::fs::create_dir_all(parent).await?;
        }
        let tmp = self.tmp_dir.join(format!("{hash_hex}.part"));

        let existing_size = match self.locate(hash_hex) {
            Some(p) => tokio::fs::metadata(&p).await.map(|m| m.len()).unwrap_or(0),
            None => 0,
        };

        tokio::fs::write(&tmp, data).await?;
        tokio::fs::rename(&tmp, &target).await?;

        // A legacy flat copy is superseded by the sharded write.
        let flat = self.blob_path_flat(hash_hex);
        if flat != target && flat.exists() {
            tokio::fs::remove_file(&flat).await.ok();
        }

        let new_size = data.len() as u64;
        if existing_size > 0 {
            if new_size > existing_size {
                self.used_bytes
                    .fetch_add(new_size - existing_size, Ordering::Relaxed);
            } else if existing_size > new_size {
                self.sub_used(existing_size - new_size);
            }
        } else {
            self.used_bytes.fetch_add(new_size, Ordering::Relaxed);
        }
        Ok(())
    }

    /// Read blob data (sharded first, legacy flat fallback).
    ///
    /// The flat miss is retried against the sharded path once. Without that,
    /// `migrate_legacy_layout` renaming this very blob in the window between the
    /// two lookups makes a permanently-present blob read as absent — which on the
    /// PoS challenge path (`p2p.rs`) answers "Shard not found" and costs a
    /// reputation penalty that never decays. A blob that moved mid-check is by
    /// then definitively sharded, so one retry closes the race completely.
    pub async fn read(&self, hash_hex: &str) -> std::io::Result<Bytes> {
        match tokio::fs::read(self.blob_path(hash_hex)).await {
            Ok(data) => Ok(Bytes::from(data)),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                match tokio::fs::read(self.blob_path_flat(hash_hex)).await {
                    Ok(data) => Ok(Bytes::from(data)),
                    Err(e2) if e2.kind() == std::io::ErrorKind::NotFound => {
                        // Migrated out from under us between the two lookups.
                        let data = tokio::fs::read(self.blob_path(hash_hex)).await?;
                        Ok(Bytes::from(data))
                    }
                    Err(e2) => Err(e2),
                }
            }
            Err(e) => Err(e),
        }
    }

    /// Check if a blob exists in either layout.
    pub fn has(&self, hash_hex: &str) -> bool {
        self.locate(hash_hex).is_some()
    }

    /// Two-phase delete: move the blob (wherever it lives) into the sharded
    /// trash, freeing its quota while staying restorable.
    pub async fn delete(&self, hash_hex: &str) -> std::io::Result<()> {
        let Some(path) = self.locate(hash_hex) else {
            return Ok(());
        };
        let size = tokio::fs::metadata(&path)
            .await
            .map(|m| m.len())
            .unwrap_or(0);
        let target = self.trash_path(hash_hex);

        // A full disk traps the node: parking a blob in the trash needs a new
        // directory entry, which needs the space that only a delete can free.
        // Every delete then fails, nothing is ever reclaimed, and the node can
        // never recover on its own. When -- and only when -- the filesystem is
        // out of room, give up the restore window rather than the ability to
        // delete at all: an unlink needs no extra space.
        //
        // Both steps can hit ENOSPC, so both feed the same fallback. Any other
        // error still propagates: silently destroying a blob because of a
        // permission or I/O fault would throw away recoverable data.
        // Both steps can hit ENOSPC, so both must be able to fall back. They are
        // kept separate because only a missing blob at `rename` time means "already
        // gone": an ENOENT while creating the trash directory (renamed ancestor,
        // dangling symlink, concurrent unmount) leaves the blob very much alive and
        // must not be reported as a successful delete.
        if let Some(parent) = target.parent() {
            if let Err(e) = tokio::fs::create_dir_all(parent).await {
                if !is_out_of_space(&e) {
                    return Err(e);
                }
                return self.remove_for_lack_of_space(hash_hex).await;
            }
        }

        match tokio::fs::rename(&path, &target).await {
            Ok(()) => {
                self.sub_used(size);
                self.trash_bytes.fetch_add(size, Ordering::Relaxed);
                Ok(())
            }
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(()),
            Err(e) if is_out_of_space(&e) => self.remove_for_lack_of_space(hash_hex).await,
            Err(e) => Err(e),
        }
    }

    /// Permanently drop a blob because the filesystem has no room to park it.
    ///
    /// A full disk traps the node: parking a blob in the trash needs a new directory
    /// entry, which needs the space that only a delete can free. Every delete then
    /// fails, nothing is ever reclaimed, and the node cannot recover on its own. We
    /// give up the restore window rather than the ability to delete at all -- an
    /// unlink needs no extra space.
    async fn remove_for_lack_of_space(&self, hash_hex: &str) -> std::io::Result<()> {
        tracing::warn!(
            hash = %&hash_hex[..hash_hex.len().min(32)],
            "Delete: no space to move blob to trash, removing permanently"
        );
        self.remove(hash_hex).await
    }

    /// Permanently delete a live blob, bypassing the trash.
    pub async fn remove(&self, hash_hex: &str) -> std::io::Result<()> {
        let Some(path) = self.locate(hash_hex) else {
            return Ok(());
        };
        let size = tokio::fs::metadata(&path)
            .await
            .map(|m| m.len())
            .unwrap_or(0);
        match tokio::fs::remove_file(path).await {
            Ok(()) => {
                self.sub_used(size);
                Ok(())
            }
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(()),
            Err(e) => Err(e),
        }
    }

    /// Bring a trashed blob back into the live (sharded) store.
    pub async fn restore(&self, hash_hex: &str) -> std::io::Result<bool> {
        let Some(trashed) = self.locate_trashed(hash_hex) else {
            return Ok(false);
        };
        let size = tokio::fs::metadata(&trashed)
            .await
            .map(|m| m.len())
            .unwrap_or(0);
        let target = self.blob_path(hash_hex);
        if let Some(parent) = target.parent() {
            tokio::fs::create_dir_all(parent).await?;
        }
        match tokio::fs::rename(&trashed, &target).await {
            Ok(()) => {
                self.sub_trash(size);
                self.used_bytes.fetch_add(size, Ordering::Relaxed);
                Ok(true)
            }
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(false),
            Err(e) => Err(e),
        }
    }

    /// Permanently remove one blob from the trash. No-op if absent.
    pub async fn purge_trashed(&self, hash_hex: &str) -> std::io::Result<()> {
        let Some(path) = self.locate_trashed(hash_hex) else {
            return Ok(());
        };
        let size = tokio::fs::metadata(&path)
            .await
            .map(|m| m.len())
            .unwrap_or(0);
        match tokio::fs::remove_file(path).await {
            Ok(()) => {
                self.sub_trash(size);
                Ok(())
            }
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(()),
            Err(e) => Err(e),
        }
    }

    /// Hashes currently in the trash (both layouts).
    pub fn list_trashed_hashes(&self) -> Vec<String> {
        walk_bin_names(&self.trash_dir)
    }

    /// Whether a blob is currently in the trash.
    pub fn has_trashed(&self, hash_hex: &str) -> bool {
        self.locate_trashed(hash_hex).is_some()
    }

    /// Total size of trashed blobs in bytes.
    pub fn trash_bytes(&self) -> u64 {
        self.trash_bytes.load(Ordering::Relaxed)
    }

    /// List all stored blob hashes (both layouts).
    pub fn list_hashes(&self) -> Vec<String> {
        walk_bin_names(&self.data_dir)
    }

    /// Return the total size of all stored blobs in bytes.
    pub fn used_bytes(&self) -> u64 {
        self.used_bytes.load(Ordering::Relaxed)
    }

    /// Remove stale write artifacts: `.tmp/*.part` older than a day and
    /// legacy `.tmp.<hash>` files at the store root (pre-0.1.28 in-flight
    /// writes that a crash left behind — never valid blobs).
    pub fn cleanup_stale_tmp(&self) -> usize {
        let mut removed = 0usize;
        let day = std::time::Duration::from_secs(86_400);
        if let Ok(entries) = std::fs::read_dir(&self.tmp_dir) {
            for e in entries.flatten() {
                let old = e
                    .metadata()
                    .and_then(|m| m.modified())
                    .map(|t| t.elapsed().unwrap_or_default() > day)
                    .unwrap_or(true);
                if old && std::fs::remove_file(e.path()).is_ok() {
                    removed += 1;
                }
            }
        }
        if let Ok(entries) = std::fs::read_dir(&self.data_dir) {
            for e in entries.flatten() {
                if let Ok(name) = e.file_name().into_string()
                    && name.starts_with(".tmp.")
                    && e.file_type().map(|t| t.is_file()).unwrap_or(false)
                    && std::fs::remove_file(e.path()).is_ok()
                {
                    removed += 1;
                }
            }
        }
        if removed > 0 {
            tracing::info!(removed, "storage: stale tmp artifacts cleaned");
        }
        removed
    }

    /// Migrate legacy flat-layout entries (live and trash) into the sharded
    /// tree. Pure `rename(2)` on the same filesystem — metadata-only moves.
    /// Throttled and resumable: the flat directory only ever shrinks.
    /// Returns the number of entries moved.
    pub async fn migrate_legacy_layout(&self, batch: usize, pause: std::time::Duration) -> u64 {
        let mut moved = 0u64;
        for (root, is_trash) in [(&self.data_dir, false), (&self.trash_dir, true)] {
            loop {
                // One bounded readdir page of flat *.bin entries: names only,
                // no stat — cheap even on the ZFS nodes.
                let names: Vec<String> = {
                    let Ok(entries) = std::fs::read_dir(root) else {
                        break;
                    };
                    entries
                        .flatten()
                        .filter_map(|e| {
                            let n = e.file_name().into_string().ok()?;
                            let h = n.strip_suffix(".bin")?;
                            sharded_rel(h)?; // shardable names only
                            e.file_type().ok()?.is_file().then(|| h.to_string())
                        })
                        .take(batch)
                        .collect()
                };
                if names.is_empty() {
                    break;
                }
                for h in &names {
                    let rel = match sharded_rel(h) {
                        Some(r) => r,
                        None => continue,
                    };
                    let from = root.join(format!("{h}.bin"));
                    let to = root.join(rel);
                    if let Some(parent) = to.parent()
                        && tokio::fs::create_dir_all(parent).await.is_err()
                    {
                        continue;
                    }
                    if to.exists() {
                        // Sharded copy already present (re-store since):
                        // the flat one is a stale duplicate.
                        tokio::fs::remove_file(&from).await.ok();
                        continue;
                    }
                    if tokio::fs::rename(&from, &to).await.is_ok() {
                        moved += 1;
                    }
                }
                tracing::info!(
                    moved,
                    trash = is_trash,
                    "storage: legacy layout migration progress"
                );
                tokio::time::sleep(pause).await;
            }
        }
        if moved > 0 {
            tracing::info!(moved, "storage: legacy layout migration complete");
        }
        moved
    }
}

/// [`BlobStore`](crate::store::BlobStore) implementation: pure delegation to
/// the inherent methods above.
#[async_trait::async_trait]
impl crate::store::BlobStore for FlatBlobStore {
    async fn store(&self, hash_hex: &str, data: &[u8]) -> std::io::Result<()> {
        FlatBlobStore::store(self, hash_hex, data).await
    }

    async fn read(&self, hash_hex: &str) -> std::io::Result<Bytes> {
        FlatBlobStore::read(self, hash_hex).await
    }

    fn has(&self, hash_hex: &str) -> bool {
        FlatBlobStore::has(self, hash_hex)
    }

    async fn delete(&self, hash_hex: &str) -> std::io::Result<()> {
        FlatBlobStore::delete(self, hash_hex).await
    }

    async fn remove(&self, hash_hex: &str) -> std::io::Result<()> {
        FlatBlobStore::remove(self, hash_hex).await
    }

    async fn restore(&self, hash_hex: &str) -> std::io::Result<bool> {
        FlatBlobStore::restore(self, hash_hex).await
    }

    async fn purge_trashed(&self, hash_hex: &str) -> std::io::Result<()> {
        FlatBlobStore::purge_trashed(self, hash_hex).await
    }

    fn list_hashes(&self) -> Vec<String> {
        FlatBlobStore::list_hashes(self)
    }

    fn list_trashed_hashes(&self) -> Vec<String> {
        FlatBlobStore::list_trashed_hashes(self)
    }

    fn has_trashed(&self, hash_hex: &str) -> bool {
        FlatBlobStore::has_trashed(self, hash_hex)
    }

    fn used_bytes(&self) -> u64 {
        FlatBlobStore::used_bytes(self)
    }

    fn trash_bytes(&self) -> u64 {
        FlatBlobStore::trash_bytes(self)
    }

    fn recompute_usage(&self) {
        FlatBlobStore::recompute_usage(self)
    }

    fn cleanup_stale_tmp(&self) -> usize {
        FlatBlobStore::cleanup_stale_tmp(self)
    }

    async fn migrate_legacy_layout(&self, batch: usize, pause: std::time::Duration) -> u64 {
        FlatBlobStore::migrate_legacy_layout(self, batch, pause).await
    }
}

/// True when an I/O error means the filesystem is out of room.
///
/// `ENOSPC` is the disk-full case; `EDQUOT` is the same situation under a user
/// quota. In both, creating the trash entry is impossible while unlinking still
/// works, so the caller falls back to a permanent removal.
fn is_out_of_space(e: &std::io::Error) -> bool {
    matches!(e.raw_os_error(), Some(libc::ENOSPC) | Some(libc::EDQUOT))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn out_of_space_matches_enospc_and_edquot_only() {
        let enospc = std::io::Error::from_raw_os_error(libc::ENOSPC);
        let edquot = std::io::Error::from_raw_os_error(libc::EDQUOT);
        assert!(is_out_of_space(&enospc));
        assert!(is_out_of_space(&edquot));
        // Everything else must keep bubbling up. Unlinking a blob because of a
        // permission, I/O or layout fault would destroy recoverable data.
        for code in [libc::EACCES, libc::EIO, libc::ENOTDIR, libc::EPERM] {
            assert!(
                !is_out_of_space(&std::io::Error::from_raw_os_error(code)),
                "errno {code} must not be treated as a full disk"
            );
        }
    }

    #[tokio::test]
    async fn delete_keeps_the_blob_when_the_failure_is_not_a_full_disk() {
        let dir = tempfile::tempdir().unwrap();
        let store = FlatBlobStore::new(dir.path().to_path_buf()).unwrap();
        store.store(HASH, b"payload").await.unwrap();

        // A file where the trash tree must go: create_dir_all fails with
        // ENOTDIR, which is NOT an out-of-space condition.
        let trash = dir.path().join("trash");
        std::fs::remove_dir_all(&trash).ok();
        std::fs::write(&trash, b"not a directory").unwrap();

        let err = store.delete(HASH).await.expect_err("delete should fail");
        assert!(!is_out_of_space(&err));
        assert!(
            store.locate(HASH).is_some(),
            "a non-space failure must leave the blob in place, not destroy it"
        );
    }

    #[tokio::test]
    async fn remove_reclaims_space_without_touching_the_trash() {
        let dir = tempfile::tempdir().unwrap();
        let store = FlatBlobStore::new(dir.path().to_path_buf()).unwrap();
        store.store(HASH, b"payload").await.unwrap();
        let before = store.used_bytes.load(Ordering::Relaxed);
        assert!(before > 0);

        // This is the path the ENOSPC fallback takes: a plain unlink, needing no
        // new directory entry and therefore no free space.
        store.remove(HASH).await.unwrap();

        assert!(store.locate(HASH).is_none(), "blob must be gone");
        assert!(
            store.used_bytes.load(Ordering::Relaxed) < before,
            "used_bytes must drop so the node reports reclaimed space"
        );
        let trash_entries = std::fs::read_dir(dir.path().join("trash"))
            .map(|d| d.count())
            .unwrap_or(0);
        assert_eq!(trash_entries, 0, "fallback must not park anything in trash");
    }

    const HASH: &str = "aa11bb22cc33";

    #[tokio::test]
    async fn store_read_trash_restore_sharded() {
        let dir = tempfile::tempdir().unwrap();
        let store = FlatBlobStore::new(dir.path()).unwrap();

        store.store(HASH, b"hello").await.unwrap();
        assert!(
            dir.path()
                .join("aa/11")
                .join(format!("{HASH}.bin"))
                .exists()
        );
        assert_eq!(store.used_bytes(), 5);
        assert!(store.has(HASH));

        store.delete(HASH).await.unwrap();
        assert!(!store.has(HASH));
        assert!(store.has_trashed(HASH));
        assert_eq!(store.used_bytes(), 0);
        assert_eq!(store.trash_bytes(), 5);
        assert_eq!(store.list_trashed_hashes(), vec![HASH.to_string()]);
        assert!(!store.list_hashes().contains(&HASH.to_string()));

        assert!(store.restore(HASH).await.unwrap());
        assert!(store.has(HASH));
        assert_eq!(store.read(HASH).await.unwrap().as_ref(), b"hello");

        store.delete(HASH).await.unwrap();
        store.purge_trashed(HASH).await.unwrap();
        assert!(!store.has_trashed(HASH));
        assert_eq!(store.trash_bytes(), 0);
    }

    #[tokio::test]
    async fn legacy_flat_blobs_are_readable_and_migrated() {
        let dir = tempfile::tempdir().unwrap();
        let store = FlatBlobStore::new(dir.path()).unwrap();

        // Simulate a pre-0.1.28 blob at the flat root.
        std::fs::write(dir.path().join(format!("{HASH}.bin")), b"legacy").unwrap();
        assert!(store.has(HASH));
        assert_eq!(store.read(HASH).await.unwrap().as_ref(), b"legacy");
        assert!(store.list_hashes().contains(&HASH.to_string()));

        // Migration renames it into the sharded tree; content unchanged.
        let moved = store
            .migrate_legacy_layout(100, std::time::Duration::from_millis(1))
            .await;
        assert_eq!(moved, 1);
        assert!(!dir.path().join(format!("{HASH}.bin")).exists());
        assert!(
            dir.path()
                .join("aa/11")
                .join(format!("{HASH}.bin"))
                .exists()
        );
        assert_eq!(store.read(HASH).await.unwrap().as_ref(), b"legacy");

        // Trash a legacy-placed blob: it lands in the sharded trash.
        std::fs::write(dir.path().join("ff00aa.bin"), b"x").unwrap();
        store.delete("ff00aa").await.unwrap();
        assert!(dir.path().join("trash/ff/00/ff00aa.bin").exists());
    }

    #[tokio::test]
    async fn stale_tmp_artifacts_are_cleaned() {
        let dir = tempfile::tempdir().unwrap();
        let store = FlatBlobStore::new(dir.path()).unwrap();

        // Legacy crash leftover at the root + an old .part in tmp.
        std::fs::write(dir.path().join(".tmp.deadbeef"), b"junk").unwrap();
        std::fs::write(dir.path().join(".tmp/old.part"), b"junk").unwrap();
        // Note: fresh .part files are kept (mtime now > cutoff only for old
        // ones); the root legacy pattern is always removed.
        let removed = store.cleanup_stale_tmp();
        assert!(removed >= 1);
        assert!(!dir.path().join(".tmp.deadbeef").exists());

        // Usage recompute sees only real blobs.
        store.store(HASH, b"data").await.unwrap();
        store.recompute_usage();
        assert_eq!(store.used_bytes(), 4);
    }

    #[tokio::test]
    async fn delete_before_recompute_saturates_instead_of_wrapping() {
        // Simulates the post-restart window: counters still 0 (recompute_usage
        // has not run) while validator deletes arrive. The decrement must
        // clamp at 0 -- a wrapped counter makes the heartbeat report
        // available_storage=0 and the validator zero the node's weight.
        let dir = tempfile::tempdir().unwrap();
        let store = FlatBlobStore::new(dir.path().to_path_buf()).unwrap();
        store.store(HASH, b"payload").await.unwrap();
        store.used_bytes.store(0, Ordering::Relaxed);
        store.delete(HASH).await.unwrap();
        assert_eq!(store.used_bytes(), 0, "must saturate, not wrap");
    }
}

//! Flat-file blob store for shard storage.
//!
//! Replaces iroh-blobs `FsStore` with simple flat files: `{hash_hex}.bin`
//! in a single directory. No tags, no redb — just files.
//!
//! Atomic writes via temp-file + rename prevent partial reads.
//!
//! Deletes are two-phase: `trash()` renames the blob into `{data_dir}/trash/`
//! where it no longer counts as stored (not listed, not served, quota freed)
//! but can be brought back instantly by `restore()` until `purge_trash()`
//! removes it for good. Both directory scans are non-recursive, so trashed
//! blobs are invisible to `list_hashes()` and the `used_bytes` accounting by
//! construction.

use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};

use bytes::Bytes;

/// Name of the trash subdirectory inside the data dir.
const TRASH_DIR: &str = "trash";

/// Simple flat-file blob store.
///
/// Each blob is stored as `{data_dir}/{hash_hex}.bin` where `hash_hex`
/// is the lowercase hex encoding of the blob's blake3 hash.
#[derive(Debug)]
pub struct FlatBlobStore {
    data_dir: PathBuf,
    trash_dir: PathBuf,
    used_bytes: AtomicU64,
    trash_bytes: AtomicU64,
}

impl FlatBlobStore {
    /// Create a new flat blob store, ensuring the data and trash
    /// directories exist.
    pub fn new(data_dir: impl AsRef<Path>) -> std::io::Result<Self> {
        let data_dir = data_dir.as_ref().to_path_buf();
        let trash_dir = data_dir.join(TRASH_DIR);
        std::fs::create_dir_all(&data_dir)?;
        std::fs::create_dir_all(&trash_dir)?;

        let scan_dir = |dir: &Path| -> u64 {
            let mut size = 0;
            if let Ok(entries) = std::fs::read_dir(dir) {
                for entry in entries.flatten() {
                    if let Ok(metadata) = entry.metadata()
                        && metadata.is_file()
                    {
                        size += metadata.len();
                    }
                }
            }
            size
        };
        let initial_size = scan_dir(&data_dir);
        let initial_trash = scan_dir(&trash_dir);

        Ok(Self {
            data_dir,
            trash_dir,
            used_bytes: AtomicU64::new(initial_size),
            trash_bytes: AtomicU64::new(initial_trash),
        })
    }

    /// Path to the blob file for a given hash hex string.
    fn blob_path(&self, hash_hex: &str) -> PathBuf {
        self.data_dir.join(format!("{}.bin", hash_hex))
    }

    /// Path to the trashed blob file for a given hash hex string.
    fn trash_path(&self, hash_hex: &str) -> PathBuf {
        self.trash_dir.join(format!("{}.bin", hash_hex))
    }

    /// Store blob data at the given hash. Atomic via temp-file + rename.
    pub async fn store(&self, hash_hex: &str, data: &[u8]) -> std::io::Result<()> {
        let target = self.blob_path(hash_hex);
        let tmp = self.data_dir.join(format!(".tmp.{}", hash_hex));

        let existing_size = match tokio::fs::metadata(&target).await {
            Ok(m) => m.len(),
            Err(_) => 0,
        };

        tokio::fs::write(&tmp, data).await?;
        tokio::fs::rename(&tmp, &target).await?;

        let new_size = data.len() as u64;
        if existing_size > 0 {
            // Overwrite
            if new_size > existing_size {
                self.used_bytes
                    .fetch_add(new_size - existing_size, Ordering::Relaxed);
            } else if existing_size > new_size {
                self.used_bytes
                    .fetch_sub(existing_size - new_size, Ordering::Relaxed);
            }
        } else {
            // New file
            self.used_bytes.fetch_add(new_size, Ordering::Relaxed);
        }

        Ok(())
    }

    /// Read blob data by hash hex string.
    pub async fn read(&self, hash_hex: &str) -> std::io::Result<Bytes> {
        let data = tokio::fs::read(self.blob_path(hash_hex)).await?;
        Ok(Bytes::from(data))
    }

    /// Check if a blob exists (synchronous filesystem check).
    pub fn has(&self, hash_hex: &str) -> bool {
        self.blob_path(hash_hex).exists()
    }

    /// Delete a blob by hash hex string. No-op if it doesn't exist.
    ///
    /// Two-phase: the blob is renamed into the trash directory, freeing
    /// its quota immediately while staying recoverable via [`restore`]
    /// until [`purge_trash`] removes it permanently.
    pub async fn delete(&self, hash_hex: &str) -> std::io::Result<()> {
        let path = self.blob_path(hash_hex);
        let size = match tokio::fs::metadata(&path).await {
            Ok(m) => m.len(),
            Err(_) => return Ok(()), // Doesn't exist
        };

        match tokio::fs::rename(&path, self.trash_path(hash_hex)).await {
            Ok(()) => {
                self.used_bytes.fetch_sub(size, Ordering::Relaxed);
                self.trash_bytes.fetch_add(size, Ordering::Relaxed);
                Ok(())
            }
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(()),
            Err(e) => Err(e),
        }
    }

    /// Permanently delete a live blob, bypassing the trash (used when the
    /// trash is disabled). No-op if it doesn't exist.
    pub async fn remove(&self, hash_hex: &str) -> std::io::Result<()> {
        let path = self.blob_path(hash_hex);
        let size = match tokio::fs::metadata(&path).await {
            Ok(m) => m.len(),
            Err(_) => return Ok(()),
        };
        match tokio::fs::remove_file(path).await {
            Ok(()) => {
                self.used_bytes.fetch_sub(size, Ordering::Relaxed);
                Ok(())
            }
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(()),
            Err(e) => Err(e),
        }
    }

    /// Bring a trashed blob back into the live store. Returns `Ok(true)` if
    /// it was restored, `Ok(false)` if it is not in the trash.
    pub async fn restore(&self, hash_hex: &str) -> std::io::Result<bool> {
        let trashed = self.trash_path(hash_hex);
        let size = match tokio::fs::metadata(&trashed).await {
            Ok(m) => m.len(),
            Err(_) => return Ok(false),
        };

        match tokio::fs::rename(&trashed, self.blob_path(hash_hex)).await {
            Ok(()) => {
                self.trash_bytes.fetch_sub(size, Ordering::Relaxed);
                self.used_bytes.fetch_add(size, Ordering::Relaxed);
                Ok(true)
            }
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(false),
            Err(e) => Err(e),
        }
    }

    /// Permanently remove one blob from the trash (used once its retention
    /// clock has elapsed). No-op if it is not in the trash.
    pub async fn purge_trashed(&self, hash_hex: &str) -> std::io::Result<()> {
        let path = self.trash_path(hash_hex);
        let size = match tokio::fs::metadata(&path).await {
            Ok(m) => m.len(),
            Err(_) => return Ok(()),
        };
        match tokio::fs::remove_file(path).await {
            Ok(()) => {
                self.trash_bytes.fetch_sub(size, Ordering::Relaxed);
                Ok(())
            }
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(()),
            Err(e) => Err(e),
        }
    }

    /// Hashes currently sitting in the trash directory.
    pub fn list_trashed_hashes(&self) -> Vec<String> {
        std::fs::read_dir(&self.trash_dir)
            .into_iter()
            .flatten()
            .filter_map(|e| {
                let e = e.ok()?;
                let name = e.file_name().to_str()?.to_string();
                name.strip_suffix(".bin").map(|h| h.to_string())
            })
            .collect()
    }

    /// Whether a blob is currently in the trash.
    pub fn has_trashed(&self, hash_hex: &str) -> bool {
        self.trash_path(hash_hex).exists()
    }

    /// Total size of trashed blobs in bytes.
    pub fn trash_bytes(&self) -> u64 {
        self.trash_bytes.load(Ordering::Relaxed)
    }

    /// List all stored blob hash hex strings.
    pub fn list_hashes(&self) -> Vec<String> {
        std::fs::read_dir(&self.data_dir)
            .into_iter()
            .flatten()
            .filter_map(|e| {
                let e = e.ok()?;
                let name = e.file_name().to_str()?.to_string();
                name.strip_suffix(".bin").map(|h| h.to_string())
            })
            .collect()
    }

    /// Return the data directory path.
    #[allow(dead_code)]
    pub fn data_dir(&self) -> &Path {
        &self.data_dir
    }

    /// Return the total size of all stored blobs in bytes.
    pub fn used_bytes(&self) -> u64 {
        self.used_bytes.load(Ordering::Relaxed)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const HASH: &str = "aa11";

    #[tokio::test]
    async fn delete_moves_to_trash_and_restore_brings_back() {
        let dir = tempfile::tempdir().unwrap();
        let store = FlatBlobStore::new(dir.path()).unwrap();

        store.store(HASH, b"hello").await.unwrap();
        assert_eq!(store.used_bytes(), 5);
        assert!(store.has(HASH));

        store.delete(HASH).await.unwrap();
        assert!(!store.has(HASH), "trashed blob must not be servable");
        assert!(store.has_trashed(HASH));
        assert_eq!(store.used_bytes(), 0, "trash frees the quota");
        assert_eq!(store.trash_bytes(), 5);
        assert!(
            !store.list_hashes().contains(&HASH.to_string()),
            "trashed blob must not be listed"
        );
        assert_eq!(store.list_trashed_hashes(), vec![HASH.to_string()]);

        assert!(store.restore(HASH).await.unwrap());
        assert!(store.has(HASH));
        assert!(!store.has_trashed(HASH));
        assert_eq!(store.used_bytes(), 5);
        assert_eq!(store.trash_bytes(), 0);
        assert_eq!(store.read(HASH).await.unwrap().as_ref(), b"hello");

        // Restoring again is a no-op signal, not an error.
        assert!(!store.restore(HASH).await.unwrap());
    }

    #[tokio::test]
    async fn purge_is_permanent_and_remove_bypasses_trash() {
        let dir = tempfile::tempdir().unwrap();
        let store = FlatBlobStore::new(dir.path()).unwrap();

        store.store(HASH, b"data").await.unwrap();
        store.delete(HASH).await.unwrap();
        store.purge_trashed(HASH).await.unwrap();
        assert!(!store.has_trashed(HASH));
        assert_eq!(store.trash_bytes(), 0);
        assert!(!store.restore(HASH).await.unwrap(), "purged = gone");

        store.store(HASH, b"data").await.unwrap();
        store.remove(HASH).await.unwrap();
        assert!(!store.has(HASH));
        assert!(!store.has_trashed(HASH), "remove never goes through trash");
        assert_eq!(store.used_bytes(), 0);
    }

    #[tokio::test]
    async fn startup_scan_accounts_both_directories() {
        let dir = tempfile::tempdir().unwrap();
        {
            let store = FlatBlobStore::new(dir.path()).unwrap();
            store.store("live", b"12345").await.unwrap();
            store.store("gone", b"1234567").await.unwrap();
            store.delete("gone").await.unwrap();
        }
        let reopened = FlatBlobStore::new(dir.path()).unwrap();
        assert_eq!(reopened.used_bytes(), 5);
        assert_eq!(reopened.trash_bytes(), 7);
        assert!(reopened.has("live"));
        assert!(reopened.has_trashed("gone"));
    }
}

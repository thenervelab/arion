//! Flat-file blob store for shard storage.
//!
//! Replaces iroh-blobs `FsStore` with simple flat files: `{hash_hex}.bin`
//! in a single directory. No GC, no tags, no redb — just files.
//!
//! Atomic writes via temp-file + rename prevent partial reads.

use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};

use bytes::Bytes;

/// Simple flat-file blob store.
///
/// Each blob is stored as `{data_dir}/{hash_hex}.bin` where `hash_hex`
/// is the lowercase hex encoding of the blob's blake3 hash.
#[derive(Debug)]
pub struct FlatBlobStore {
    data_dir: PathBuf,
    used_bytes: AtomicU64,
}

impl FlatBlobStore {
    /// Create a new flat blob store, ensuring the data directory exists.
    pub fn new(data_dir: impl AsRef<Path>) -> std::io::Result<Self> {
        let data_dir = data_dir.as_ref().to_path_buf();
        std::fs::create_dir_all(&data_dir)?;

        let mut initial_size = 0;
        if let Ok(entries) = std::fs::read_dir(&data_dir) {
            for entry in entries.flatten() {
                if let Ok(metadata) = entry.metadata()
                    && metadata.is_file() {
                        initial_size += metadata.len();
                    }
            }
        }

        Ok(Self {
            data_dir,
            used_bytes: AtomicU64::new(initial_size),
        })
    }

    /// Path to the blob file for a given hash hex string.
    fn blob_path(&self, hash_hex: &str) -> PathBuf {
        self.data_dir.join(format!("{}.bin", hash_hex))
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
    pub async fn delete(&self, hash_hex: &str) -> std::io::Result<()> {
        let path = self.blob_path(hash_hex);
        let size = match tokio::fs::metadata(&path).await {
            Ok(m) => m.len(),
            Err(_) => return Ok(()), // Doesn't exist
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

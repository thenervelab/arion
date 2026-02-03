//! Index Cache Module
//!
//! Provides persistent caching of the validator's sync index and PG index to accelerate
//! startup times. Instead of rebuilding indexes from iroh-docs on every restart,
//! this module saves indexes to disk and validates them on load.
//!
//! # Cache Invalidation
//!
//! The cache is invalidated when:
//! - The epoch changes (cluster map topology changed)
//! - The cache version doesn't match (format change)
//! - The cache file is corrupted or missing
//!
//! # Cache Format
//!
//! The cache uses bincode serialization for efficiency:
//! - Header: version (u32), epoch (u64), created_at (u64)
//! - Body: manifest_hashes (Vec<FileSummary>), pg_index (HashMap<u32, Vec<String>>)
//! - Footer: checksum (BLAKE3 hash of the body)

use common::FileSummary;
use dashmap::DashMap;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::path::Path;
use std::sync::Arc;
use tokio::fs;
use tracing::{debug, info, warn};

/// Current cache format version. Increment when changing the serialization format.
const CACHE_VERSION: u32 = 1;

/// Cache file name
const CACHE_FILENAME: &str = "index_cache.bin";

/// Index cache containing pre-computed indexes for fast startup.
#[derive(Debug, Serialize, Deserialize)]
pub struct IndexCache {
    /// Cache format version
    pub version: u32,
    /// Epoch when this cache was created
    pub epoch: u64,
    /// Timestamp when cache was created (Unix seconds)
    pub created_at: u64,
    /// List of file summaries (file_hash, size)
    pub manifest_hashes: Vec<FileSummary>,
    /// PG index: pg_id -> list of file hashes
    pub pg_index: HashMap<u32, Vec<String>>,
    /// BLAKE3 checksum of the serialized body (excluding this field)
    /// Reserved for future use (e.g., in-memory verification)
    #[serde(skip)]
    _checksum: Option<[u8; 32]>,
}

impl IndexCache {
    /// Create a new index cache from current state.
    pub fn new(
        epoch: u64,
        manifest_hashes: Vec<FileSummary>,
        pg_index: &Arc<DashMap<u32, Vec<String>>>,
    ) -> Self {
        // Convert DashMap to HashMap for serialization
        let pg_index_map: HashMap<u32, Vec<String>> = pg_index
            .iter()
            .map(|entry| (*entry.key(), entry.value().clone()))
            .collect();

        Self {
            version: CACHE_VERSION,
            epoch,
            created_at: common::now_secs(),
            manifest_hashes,
            pg_index: pg_index_map,
            _checksum: None,
        }
    }

    /// Load cache from disk if valid.
    ///
    /// Returns `Some(cache)` if the cache exists, is valid, and matches the current epoch.
    /// Returns `None` if the cache is missing, corrupted, or stale.
    pub async fn load(data_dir: &Path, current_epoch: u64) -> Option<Self> {
        let cache_path = data_dir.join(CACHE_FILENAME);

        // Check if cache file exists
        if !cache_path.exists() {
            debug!("Index cache file not found");
            return None;
        }

        // Read cache file
        let bytes = match fs::read(&cache_path).await {
            Ok(b) => b,
            Err(e) => {
                warn!(error = %e, "Failed to read index cache file");
                return None;
            }
        };

        // Need at least header + checksum
        if bytes.len() < 48 {
            warn!("Index cache file too small");
            return None;
        }

        // Extract checksum (last 32 bytes)
        let (body_bytes, checksum_bytes) = bytes.split_at(bytes.len() - 32);
        let stored_checksum: [u8; 32] = checksum_bytes.try_into().ok()?;

        // Verify checksum
        let computed_checksum = common::blake3_hash(body_bytes);
        if stored_checksum != computed_checksum {
            warn!("Index cache checksum mismatch - cache corrupted");
            return None;
        }

        // Deserialize cache
        let cache: Self = match bincode::deserialize(body_bytes) {
            Ok(c) => c,
            Err(e) => {
                warn!(error = %e, "Failed to deserialize index cache");
                return None;
            }
        };

        // Validate version
        if cache.version != CACHE_VERSION {
            info!(
                cached_version = cache.version,
                current_version = CACHE_VERSION,
                "Index cache version mismatch"
            );
            return None;
        }

        // Validate epoch
        if cache.epoch != current_epoch {
            info!(
                cached_epoch = cache.epoch,
                current_epoch = current_epoch,
                "Index cache epoch mismatch - cluster topology changed"
            );
            return None;
        }

        info!(
            epoch = cache.epoch,
            files = cache.manifest_hashes.len(),
            pgs = cache.pg_index.len(),
            age_secs = common::now_secs().saturating_sub(cache.created_at),
            "Loaded index cache from disk"
        );

        Some(cache)
    }

    /// Save cache to disk.
    ///
    /// Serializes the cache with a trailing BLAKE3 checksum for integrity verification.
    pub async fn save(&self, data_dir: &Path) -> anyhow::Result<()> {
        let cache_path = data_dir.join(CACHE_FILENAME);

        // Serialize body
        let body_bytes = bincode::serialize(self)?;

        // Compute checksum
        let checksum = common::blake3_hash(&body_bytes);

        // Write body + checksum atomically
        let mut full_bytes = body_bytes;
        full_bytes.extend_from_slice(&checksum);

        // Write to temp file then rename for atomic operation
        let temp_path = cache_path.with_extension("tmp");
        fs::write(&temp_path, &full_bytes).await?;
        fs::rename(&temp_path, &cache_path).await?;

        info!(
            epoch = self.epoch,
            files = self.manifest_hashes.len(),
            pgs = self.pg_index.len(),
            size_bytes = full_bytes.len(),
            "Saved index cache to disk"
        );

        Ok(())
    }

    /// Delete the cache file (for invalidation on epoch change).
    #[allow(dead_code)]
    pub async fn delete(data_dir: &Path) -> anyhow::Result<()> {
        let cache_path = data_dir.join(CACHE_FILENAME);
        if cache_path.exists() {
            fs::remove_file(&cache_path).await?;
            info!("Deleted stale index cache");
        }
        Ok(())
    }

    /// Apply this cache to the application state.
    ///
    /// Populates the manifest_hashes and pg_index from the cached values.
    /// This should only be called during early startup when no other tasks are accessing state.
    pub fn apply_to_state(
        self,
        manifest_hashes: &tokio::sync::Mutex<Vec<FileSummary>>,
        pg_index: &Arc<DashMap<u32, Vec<String>>>,
    ) {
        // Populate manifest_hashes - use try_lock since we're in async context
        // but this is called early in startup before other tasks are running
        match manifest_hashes.try_lock() {
            Ok(mut hashes) => {
                *hashes = self.manifest_hashes;
            }
            Err(_) => {
                // This should not happen during early startup - log a warning
                warn!(
                    "Failed to acquire manifest_hashes lock during cache apply - \
                     this is unexpected during startup and may indicate a race condition"
                );
            }
        }

        // Populate pg_index
        pg_index.clear();
        for (pg_id, files) in self.pg_index {
            pg_index.insert(pg_id, files);
        }
    }

    /// Get the number of files in the cache
    pub fn file_count(&self) -> usize {
        self.manifest_hashes.len()
    }

    /// Get the number of PGs in the cache
    pub fn pg_count(&self) -> usize {
        self.pg_index.len()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    #[tokio::test]
    async fn test_cache_roundtrip() {
        let dir = tempdir().unwrap();
        let pg_index = Arc::new(DashMap::new());
        pg_index.insert(0, vec!["hash1".to_string(), "hash2".to_string()]);
        pg_index.insert(1, vec!["hash3".to_string()]);

        let manifest_hashes = vec![
            FileSummary {
                hash: "hash1".to_string(),
                size: 1000,
            },
            FileSummary {
                hash: "hash2".to_string(),
                size: 2000,
            },
            FileSummary {
                hash: "hash3".to_string(),
                size: 3000,
            },
        ];

        let cache = IndexCache::new(42, manifest_hashes.clone(), &pg_index);

        // Save
        cache.save(dir.path()).await.unwrap();

        // Load with correct epoch
        let loaded = IndexCache::load(dir.path(), 42).await;
        assert!(loaded.is_some());
        let loaded = loaded.unwrap();
        assert_eq!(loaded.epoch, 42);
        assert_eq!(loaded.manifest_hashes.len(), 3);
        assert_eq!(loaded.pg_index.len(), 2);

        // Load with wrong epoch should fail
        let stale = IndexCache::load(dir.path(), 43).await;
        assert!(stale.is_none());
    }

    #[tokio::test]
    async fn test_cache_corruption_detection() {
        let dir = tempdir().unwrap();
        let pg_index = Arc::new(DashMap::new());
        let cache = IndexCache::new(1, vec![], &pg_index);
        cache.save(dir.path()).await.unwrap();

        // Corrupt the cache file
        let cache_path = dir.path().join(CACHE_FILENAME);
        let mut bytes = fs::read(&cache_path).await.unwrap();
        if !bytes.is_empty() {
            bytes[0] ^= 0xFF; // Flip bits
        }
        fs::write(&cache_path, bytes).await.unwrap();

        // Load should fail due to checksum mismatch
        let loaded = IndexCache::load(dir.path(), 1).await;
        assert!(loaded.is_none());
    }
}

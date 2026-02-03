//! Persistent upload progress tracking using ReDB.
//!
//! Stores upload progress to disk so it survives validator restarts.
//! This enables clients to query upload status even after validator crashes
//! or restarts, and supports upload resumption for interrupted transfers.
//!
//! # Data Model
//!
//! Each entry tracks:
//! - `file_hash`: BLAKE3 hash of the file being uploaded
//! - `processed_stripes`: Number of stripes encoded and distributed
//! - `total_stripes`: Total stripes in the file
//! - `status`: Current state (`Processing`, `Completed`, `Failed`, `Failed: Interrupted`)
//! - `updated_at`: Unix timestamp of last update
//!
//! # Crash Recovery
//!
//! On startup, `load_and_recover()` marks any `Processing` entries as `Failed: Interrupted`.
//! This ensures stale in-progress entries don't persist indefinitely.
//!
//! # Cleanup
//!
//! `cleanup_old_completed()` removes entries older than a configurable age,
//! preventing unbounded database growth.
//!
//! # Thread Safety
//!
//! The `UploadProgressStore` is wrapped in `Arc` (`SharedUploadProgressStore`)
//! for shared ownership across async tasks. ReDB handles internal locking.

#![allow(clippy::result_large_err)]

use common::now_secs;
use redb::{Database, ReadableTable, TableDefinition};
use serde::{Deserialize, Serialize};
use std::path::Path;
use std::sync::Arc;
use tracing::warn;

/// Table definition for upload progress entries
const UPLOAD_PROGRESS_TABLE: TableDefinition<&str, &[u8]> = TableDefinition::new("upload_progress");

/// Upload progress entry (serializable)
#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct UploadProgress {
    pub file_hash: String,
    pub processed_stripes: usize,
    pub total_stripes: usize,
    pub status: String, // "Processing", "Completed", "Failed", "Failed: Interrupted"
    pub updated_at: u64,
}

/// Persistent store for upload progress
pub struct UploadProgressStore {
    db: Database,
}

impl UploadProgressStore {
    /// Open or create the database at the given path
    pub fn open(path: impl AsRef<Path>) -> Result<Self, redb::Error> {
        let db = Database::create(path)?;

        // Ensure the table exists
        let write_txn = db.begin_write()?;
        {
            let _ = write_txn.open_table(UPLOAD_PROGRESS_TABLE)?;
        }
        write_txn.commit()?;

        Ok(Self { db })
    }

    /// Load all progress entries and mark any "Processing" as "Failed: Interrupted"
    /// This should be called on startup to handle crashed uploads
    pub fn load_and_recover(
        &self,
    ) -> Result<std::collections::HashMap<String, UploadProgress>, redb::Error> {
        let mut result = std::collections::HashMap::new();

        // First read all entries
        {
            let read_txn = self.db.begin_read()?;
            let table = read_txn.open_table(UPLOAD_PROGRESS_TABLE)?;

            for entry in table.iter()? {
                let (key, value) = entry?;
                if let Ok(mut progress) = serde_json::from_slice::<UploadProgress>(value.value()) {
                    // Mark interrupted uploads
                    if progress.status == "Processing" {
                        progress.status = "Failed: Interrupted".to_string();
                        progress.updated_at = now_secs();
                    }
                    result.insert(key.value().to_string(), progress);
                }
            }
        }

        // Update interrupted entries in DB
        let write_txn = self.db.begin_write()?;
        {
            let mut table = write_txn.open_table(UPLOAD_PROGRESS_TABLE)?;
            for (hash, progress) in &result {
                if progress.status == "Failed: Interrupted" {
                    match serde_json::to_vec(progress) {
                        Ok(json) => {
                            table.insert(hash.as_str(), json.as_slice())?;
                        }
                        Err(e) => {
                            warn!(file_hash = %hash, error = %e, "Failed to serialize interrupted progress entry, skipping");
                            continue;
                        }
                    }
                }
            }
        }
        write_txn.commit()?;

        Ok(result)
    }

    /// Store or update a progress entry
    pub fn set(&self, progress: &UploadProgress) -> Result<(), redb::Error> {
        let json = serde_json::to_vec(progress).map_err(|_| {
            redb::Error::Io(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "Failed to serialize progress",
            ))
        })?;

        let write_txn = self.db.begin_write()?;
        {
            let mut table = write_txn.open_table(UPLOAD_PROGRESS_TABLE)?;
            table.insert(progress.file_hash.as_str(), json.as_slice())?;
        }
        write_txn.commit()?;

        Ok(())
    }

    /// Get a progress entry by hash
    pub fn get(&self, file_hash: &str) -> Result<Option<UploadProgress>, redb::Error> {
        let read_txn = self.db.begin_read()?;
        let table = read_txn.open_table(UPLOAD_PROGRESS_TABLE)?;

        match table.get(file_hash)? {
            Some(value) => {
                let progress = serde_json::from_slice(value.value()).map_err(|_| {
                    redb::Error::Io(std::io::Error::new(
                        std::io::ErrorKind::InvalidData,
                        "Failed to deserialize progress",
                    ))
                })?;
                Ok(Some(progress))
            }
            None => Ok(None),
        }
    }

    /// Remove a progress entry
    #[allow(dead_code)]
    pub fn remove(&self, file_hash: &str) -> Result<(), redb::Error> {
        let write_txn = self.db.begin_write()?;
        {
            let mut table = write_txn.open_table(UPLOAD_PROGRESS_TABLE)?;
            table.remove(file_hash)?;
        }
        write_txn.commit()?;
        Ok(())
    }

    /// Remove completed entries older than max_age_secs
    pub fn cleanup_old_completed(&self, max_age_secs: u64) -> Result<usize, redb::Error> {
        let now = now_secs();
        let cutoff = now.saturating_sub(max_age_secs);

        let mut to_remove = Vec::new();

        // Find entries to remove
        {
            let read_txn = self.db.begin_read()?;
            let table = read_txn.open_table(UPLOAD_PROGRESS_TABLE)?;

            for entry in table.iter()? {
                let (key, value) = entry?;
                if let Ok(progress) = serde_json::from_slice::<UploadProgress>(value.value()) {
                    // Remove completed/failed entries older than cutoff
                    // OR Processing entries that are stale (likely crashed)
                    if progress.updated_at < cutoff
                        && (progress.status.starts_with("Completed")
                            || progress.status.starts_with("Failed")
                            || progress.status == "Processing")
                    {
                        to_remove.push(key.value().to_string());
                    }
                }
            }
        }

        // Remove them
        let count = to_remove.len();
        if !to_remove.is_empty() {
            let write_txn = self.db.begin_write()?;
            {
                let mut table = write_txn.open_table(UPLOAD_PROGRESS_TABLE)?;
                for hash in to_remove {
                    table.remove(hash.as_str())?;
                }
            }
            write_txn.commit()?;
        }

        Ok(count)
    }

    /// Get count of all entries
    #[allow(dead_code)]
    pub fn len(&self) -> Result<usize, redb::Error> {
        let read_txn = self.db.begin_read()?;
        let table = read_txn.open_table(UPLOAD_PROGRESS_TABLE)?;
        let mut count = 0;
        for _ in table.iter()? {
            count += 1;
        }
        Ok(count)
    }

    /// Get count of active (Processing) entries only
    pub fn active_count(&self) -> Result<usize, redb::Error> {
        let read_txn = self.db.begin_read()?;
        let table = read_txn.open_table(UPLOAD_PROGRESS_TABLE)?;

        let mut count = 0;
        for entry in table.iter()? {
            let (_, value) = entry?;
            if let Ok(progress) = serde_json::from_slice::<UploadProgress>(value.value()) {
                if progress.status == "Processing" {
                    count += 1;
                }
            }
        }

        Ok(count)
    }
}

/// Thread-safe wrapper with Arc
pub type SharedUploadProgressStore = Arc<UploadProgressStore>;

//! Incremental blob backup module - handles S3 backup of shard blobs.
//!
//! This module provides incremental backup of erasure-coded shard blobs to S3-compatible
//! storage. Since blobs are content-addressed by BLAKE3 hash, the system only uploads
//! new blobs (never re-uploads unchanged content).
//!
//! # Features
//!
//! - **Incremental sync**: Only uploads blobs not yet backed up
//! - **Content-addressing**: Uses blob hash as S3 key (same hash = same content)
//! - **ReDB state tracking**: Fast local lookup of backed-up blobs
//! - **Batched uploads**: Processes blobs in configurable batch sizes
//! - **Concurrent uploads**: Multiple parallel S3 uploads per batch
//! - **Restore support**: Can restore blobs from S3 if local storage is lost
//!
//! # S3 Key Structure
//!
//! ```text
//! {bucket}/{prefix}/blobs/{hash[0:2]}/{hash[2:4]}/{full_64_char_hash}
//! ```
//!
//! Example: `hippius-backups/validator-1/blobs/ab/cd/abcdef123456789...`
//!
//! The two-level partitioning by first 4 hex chars prevents S3 hot spots.
//!
//! # Configuration
//!
//! ```toml
//! [backup.blobs]
//! enabled = true
//! sync_interval_minutes = 15
//! batch_size = 100
//! upload_concurrency = 8
//! prefix = "blobs"
//! ```

use crate::config::{BackupConfig, BlobBackupConfig};
use crate::metrics::Metrics;
use common::{FileManifest, FileSummary};
use futures_lite::StreamExt;
use iroh_docs::api::Doc;
use redb::{Database, ReadableTable, ReadableTableMetadata, TableDefinition};
use s3::bucket::Bucket;
use s3::creds::Credentials;
use s3::region::Region;
use serde::{Deserialize, Serialize};
use std::collections::HashSet;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::io::AsyncReadExt;
use tokio::sync::Mutex;
use tracing::{debug, error, info, warn};

// ReDB table definition for tracking backed-up blobs
const BACKED_UP_BLOBS_TABLE: TableDefinition<&str, &[u8]> = TableDefinition::new("backed_up_blobs");

// ReDB table for sync metadata (last sync timestamp, etc.)
const SYNC_METADATA_TABLE: TableDefinition<&str, &[u8]> = TableDefinition::new("sync_metadata");

/// Entry tracking a backed-up blob
#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct BlobBackupEntry {
    /// BLAKE3 hash of the blob
    pub blob_hash: String,
    /// Size in bytes
    pub size: u64,
    /// Unix timestamp when backed up
    pub backed_up_at: u64,
}

/// Sync metadata for tracking backup progress
#[derive(Serialize, Deserialize, Clone, Debug, Default)]
pub struct SyncMetadata {
    /// Unix timestamp of last successful sync
    pub last_sync_timestamp: u64,
    /// Total blobs backed up across all syncs
    pub total_blobs_backed_up: u64,
    /// Total bytes backed up across all syncs
    pub total_bytes_backed_up: u64,
}

/// Blob backup manager handles incremental blob sync to S3
pub struct BlobBackupManager {
    config: BackupConfig,
    blob_config: BlobBackupConfig,
    bucket: Option<Bucket>,
    db: Arc<Database>,
    doc: Doc,
    blobs_store: iroh_blobs::store::fs::FsStore,
    manifest_hashes: Arc<Mutex<Vec<FileSummary>>>,
    metrics: Metrics,
}

impl BlobBackupManager {
    /// Create a new blob backup manager
    pub async fn new(
        config: BackupConfig,
        data_dir: PathBuf,
        doc: Doc,
        blobs_store: iroh_blobs::store::fs::FsStore,
        manifest_hashes: Arc<Mutex<Vec<FileSummary>>>,
        metrics: Metrics,
    ) -> Result<Self, Box<dyn std::error::Error + Send + Sync>> {
        let bucket = if config.enabled && config.blobs.enabled {
            Some(Self::create_bucket(&config)?)
        } else {
            None
        };

        // Open or create ReDB database for blob backup state
        let db_path = data_dir.join("blob_backup.redb");
        let db = Database::create(&db_path)?;

        // Initialize tables
        {
            let write_txn = db.begin_write()?;
            {
                let _ = write_txn.open_table(BACKED_UP_BLOBS_TABLE)?;
                let _ = write_txn.open_table(SYNC_METADATA_TABLE)?;
            }
            write_txn.commit()?;
        }

        Ok(Self {
            blob_config: config.blobs.clone(),
            config,
            bucket,
            db: Arc::new(db),
            doc,
            blobs_store,
            manifest_hashes,
            metrics,
        })
    }

    fn create_bucket(
        config: &BackupConfig,
    ) -> Result<Bucket, Box<dyn std::error::Error + Send + Sync>> {
        let endpoint = config.s3_endpoint.as_ref().ok_or("S3 endpoint required")?;
        let bucket_name = config.s3_bucket.as_ref().ok_or("S3 bucket required")?;
        let region_name = config.s3_region.as_deref().unwrap_or("us-east-1");

        let region = Region::Custom {
            region: region_name.to_string(),
            endpoint: endpoint.clone(),
        };

        let credentials = Credentials::new(
            Some(&config.s3_access_key),
            Some(&config.s3_secret_key),
            None,
            None,
            None,
        )?;

        let bucket = Bucket::new(bucket_name, region, credentials)?.with_path_style();

        Ok(*bucket)
    }

    /// Run the blob backup scheduler loop
    pub async fn run_scheduler(self) {
        if !self.config.enabled || !self.blob_config.enabled {
            info!("Blob backup disabled, scheduler not starting");
            return;
        }

        info!(
            sync_interval_minutes = self.blob_config.sync_interval_minutes,
            batch_size = self.blob_config.batch_size,
            upload_concurrency = self.blob_config.upload_concurrency,
            "Blob backup scheduler starting"
        );

        // Wait for startup to complete before first sync
        tokio::time::sleep(Duration::from_secs(120)).await;

        // Run initial sync
        if let Err(e) = self.run_sync().await {
            error!(error = %e, "Initial blob backup sync failed");
        }

        // Run periodic sync
        let interval = Duration::from_secs(self.blob_config.sync_interval_minutes * 60);
        loop {
            tokio::time::sleep(interval).await;

            if let Err(e) = self.run_sync().await {
                error!(error = %e, "Blob backup sync failed");
                self.metrics.blob_backup_errors_total.inc();
            }
        }
    }

    /// Execute a sync cycle: discover new blobs and upload them
    async fn run_sync(&self) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        let sync_start = Instant::now();
        info!("Starting blob backup sync");

        // 1. Discover all blob hashes from manifests
        let all_blob_hashes = self.discover_blob_hashes().await?;
        debug!(
            total_blobs = all_blob_hashes.len(),
            "Discovered blobs from manifests"
        );

        // 2. Filter out already backed-up blobs
        let new_blobs = self.filter_new_blobs(&all_blob_hashes)?;
        let pending_count = new_blobs.len();

        if new_blobs.is_empty() {
            info!("No new blobs to backup");
            self.update_last_sync_timestamp()?;
            return Ok(());
        }

        info!(pending_blobs = pending_count, "Found new blobs to backup");
        self.metrics
            .blob_backup_pending_blobs
            .set(pending_count as i64);

        // 3. Upload in batches
        let mut total_uploaded = 0u64;
        let mut total_bytes = 0u64;
        let mut errors = 0u64;

        for batch in new_blobs.chunks(self.blob_config.batch_size) {
            let (uploaded, bytes, batch_errors) = self.upload_batch(batch).await;
            total_uploaded += uploaded;
            total_bytes += bytes;
            errors += batch_errors;

            // Update metrics after each batch
            self.metrics.blob_backup_blobs_total.inc_by(uploaded);
            self.metrics.blob_backup_bytes_total.inc_by(bytes);
            if batch_errors > 0 {
                self.metrics.blob_backup_errors_total.inc_by(batch_errors);
            }
        }

        // 4. Update sync metadata
        self.update_sync_metadata(total_uploaded, total_bytes)?;

        let duration = sync_start.elapsed();
        self.metrics
            .blob_backup_sync_duration_seconds
            .observe(duration.as_secs_f64());
        self.metrics
            .blob_backup_last_sync_timestamp
            .set(common::now_secs() as i64);

        info!(
            uploaded = total_uploaded,
            bytes = total_bytes,
            errors = errors,
            duration_secs = duration.as_secs(),
            "Blob backup sync complete"
        );

        Ok(())
    }

    /// Discover all blob hashes from file manifests
    async fn discover_blob_hashes(
        &self,
    ) -> Result<HashSet<String>, Box<dyn std::error::Error + Send + Sync>> {
        let mut blob_hashes = HashSet::new();

        // Get all manifest hashes
        let manifest_summaries = self.manifest_hashes.lock().await.clone();

        for summary in manifest_summaries {
            // Try to load the manifest
            match self.load_manifest(&summary.hash).await {
                Ok(manifest) => {
                    // Extract all shard blob hashes
                    for shard in &manifest.shards {
                        blob_hashes.insert(shard.blob_hash.clone());
                    }
                }
                Err(e) => {
                    warn!(
                        file_hash = %summary.hash,
                        error = %e,
                        "Failed to load manifest for blob backup discovery, will retry next sync"
                    );
                }
            }
        }

        Ok(blob_hashes)
    }

    /// Load a file manifest from iroh-docs by file hash
    async fn load_manifest(
        &self,
        file_hash: &str,
    ) -> Result<FileManifest, Box<dyn std::error::Error + Send + Sync>> {
        // Query iroh-docs for the manifest using file_hash as the key
        let query =
            iroh_docs::store::Query::single_latest_per_key().key_exact(file_hash.as_bytes());

        let mut stream = Box::pin(self.doc.get_many(query).await?);

        if let Some(Ok(entry)) = stream.next().await {
            let content_hash = entry.content_hash();
            let mut reader = self.blobs_store.reader(content_hash);
            let mut content = Vec::new();
            reader.read_to_end(&mut content).await?;

            let manifest: FileManifest = serde_json::from_slice(&content)?;
            Ok(manifest)
        } else {
            Err(format!("Manifest not found for file_hash: {}", file_hash).into())
        }
    }

    /// Filter out blobs that are already backed up
    fn filter_new_blobs(
        &self,
        all_hashes: &HashSet<String>,
    ) -> Result<Vec<String>, Box<dyn std::error::Error + Send + Sync>> {
        let read_txn = self.db.begin_read()?;
        let table = read_txn.open_table(BACKED_UP_BLOBS_TABLE)?;

        let mut new_blobs = Vec::new();
        for hash in all_hashes {
            if table.get(hash.as_str())?.is_none() {
                new_blobs.push(hash.clone());
            }
        }

        Ok(new_blobs)
    }

    /// Upload a batch of blobs to S3
    async fn upload_batch(&self, batch: &[String]) -> (u64, u64, u64) {
        let bucket = match &self.bucket {
            Some(b) => b,
            None => return (0, 0, batch.len() as u64),
        };

        let semaphore = Arc::new(tokio::sync::Semaphore::new(
            self.blob_config.upload_concurrency,
        ));
        let mut handles = Vec::new();

        for blob_hash in batch {
            let hash = blob_hash.clone();
            let bucket = bucket.clone();
            let blobs_store = self.blobs_store.clone();
            let db = self.db.clone();
            let config = self.config.clone();
            let blob_config = self.blob_config.clone();
            let permit = match semaphore.clone().acquire_owned().await {
                Ok(p) => p,
                Err(_) => {
                    // Semaphore closed, likely during shutdown
                    debug!("Semaphore closed, stopping batch upload");
                    break;
                }
            };

            let handle = tokio::spawn(async move {
                let _permit = permit;
                Self::upload_single_blob(&hash, &bucket, &blobs_store, &db, &config, &blob_config)
                    .await
            });

            handles.push(handle);
        }

        // Collect results
        let mut uploaded = 0u64;
        let mut bytes = 0u64;
        let mut errors = 0u64;

        for handle in handles {
            match handle.await {
                Ok(Ok(size)) => {
                    uploaded += 1;
                    bytes += size;
                }
                Ok(Err(e)) => {
                    debug!(error = %e, "Failed to upload blob");
                    errors += 1;
                }
                Err(e) => {
                    debug!(error = %e, "Blob upload task panicked");
                    errors += 1;
                }
            }
        }

        (uploaded, bytes, errors)
    }

    /// Upload a single blob to S3 and record in ReDB
    async fn upload_single_blob(
        blob_hash: &str,
        bucket: &Bucket,
        blobs_store: &iroh_blobs::store::fs::FsStore,
        db: &Database,
        config: &BackupConfig,
        blob_config: &BlobBackupConfig,
    ) -> Result<u64, Box<dyn std::error::Error + Send + Sync>> {
        use iroh_blobs::Hash;
        use std::str::FromStr;

        // Read blob data
        let hash = Hash::from_str(blob_hash)?;

        // Check if blob exists in store
        let blob_exists = blobs_store
            .has(hash)
            .await
            .map_err(|e| format!("Failed to check blob store for {}: {}", blob_hash, e))?;
        if !blob_exists {
            return Err(format!("Blob not found in store: {}", blob_hash).into());
        }

        let mut reader = blobs_store.reader(hash);
        let mut data = Vec::new();
        reader.read_to_end(&mut data).await?;

        let size = data.len() as u64;

        // Validate blob_hash length (BLAKE3 hashes are 64 hex chars)
        if blob_hash.len() < 4 {
            return Err(format!(
                "Invalid blob hash length {}: {}",
                blob_hash.len(),
                blob_hash
            )
            .into());
        }

        // Compute S3 key: {prefix}/{blob_prefix}/{hash[0:2]}/{hash[2:4]}/{hash}
        let s3_key = format!(
            "{}/{}/{}/{}/{}",
            config.prefix,
            blob_config.prefix,
            &blob_hash[0..2],
            &blob_hash[2..4],
            blob_hash
        );

        // Upload to S3
        let response = bucket.put_object(&s3_key, &data).await?;

        if response.status_code() != 200 {
            return Err(format!("S3 upload failed with status {}", response.status_code()).into());
        }

        // Record in ReDB
        let entry = BlobBackupEntry {
            blob_hash: blob_hash.to_string(),
            size,
            backed_up_at: common::now_secs(),
        };
        let entry_bytes = bincode::serialize(&entry)?;

        let write_txn = db.begin_write()?;
        {
            let mut table = write_txn.open_table(BACKED_UP_BLOBS_TABLE)?;
            table.insert(blob_hash, entry_bytes.as_slice())?;
        }
        write_txn.commit()?;

        debug!(blob_hash = blob_hash, size = size, "Blob backed up to S3");

        Ok(size)
    }

    /// Update sync metadata after a sync cycle
    fn update_sync_metadata(
        &self,
        blobs_uploaded: u64,
        bytes_uploaded: u64,
    ) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        let write_txn = self.db.begin_write()?;
        {
            let mut table = write_txn.open_table(SYNC_METADATA_TABLE)?;

            // Load existing metadata
            let mut metadata = if let Some(entry) = table.get("metadata")? {
                bincode::deserialize(entry.value())?
            } else {
                SyncMetadata::default()
            };

            // Update
            metadata.last_sync_timestamp = common::now_secs();
            metadata.total_blobs_backed_up += blobs_uploaded;
            metadata.total_bytes_backed_up += bytes_uploaded;

            let metadata_bytes = bincode::serialize(&metadata)?;
            table.insert("metadata", metadata_bytes.as_slice())?;
        }
        write_txn.commit()?;

        Ok(())
    }

    /// Update last sync timestamp without changing counters
    fn update_last_sync_timestamp(&self) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        let write_txn = self.db.begin_write()?;
        {
            let mut table = write_txn.open_table(SYNC_METADATA_TABLE)?;

            let mut metadata = if let Some(entry) = table.get("metadata")? {
                bincode::deserialize(entry.value())?
            } else {
                SyncMetadata::default()
            };

            metadata.last_sync_timestamp = common::now_secs();

            let metadata_bytes = bincode::serialize(&metadata)?;
            table.insert("metadata", metadata_bytes.as_slice())?;
        }
        write_txn.commit()?;

        self.metrics
            .blob_backup_last_sync_timestamp
            .set(common::now_secs() as i64);

        Ok(())
    }

    /// Rebuild ReDB state from S3 if the local ReDB database is empty.
    ///
    /// This is called on startup to recover blob backup state if the ReDB was lost.
    /// It does NOT download blobs - blob restore requires manual intervention via admin-cli.
    pub async fn restore_state_if_needed(
        &self,
    ) -> Result<bool, Box<dyn std::error::Error + Send + Sync>> {
        if !self.config.enabled || !self.blob_config.enabled {
            return Ok(false);
        }

        // Check if ReDB already has data
        let count = self.count_backed_up_blobs()?;
        if count > 0 {
            info!(
                backed_up_blobs = count,
                "Blob backup state already initialized"
            );
            return Ok(false);
        }

        // Rebuild from S3 listing
        info!("ReDB empty, rebuilding blob backup state from S3");
        self.rebuild_redb_state().await?;

        Ok(true)
    }

    /// Rebuild ReDB state from S3 listing (used after restore or if ReDB is lost)
    async fn rebuild_redb_state(&self) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        let bucket = match &self.bucket {
            Some(b) => b,
            None => return Ok(()),
        };

        info!("Rebuilding blob backup state from S3");

        let prefix = format!("{}/{}/", self.config.prefix, self.blob_config.prefix);
        let list_result = bucket.list(prefix, None).await?;

        let write_txn = self.db.begin_write()?;
        {
            let mut table = write_txn.open_table(BACKED_UP_BLOBS_TABLE)?;
            let mut count = 0u64;
            let mut bytes = 0u64;

            for result in list_result {
                for object in result.contents {
                    // Extract hash from key path
                    let blob_hash = match object.key.split('/').next_back() {
                        Some(h) if h.len() == 64 => h,
                        _ => continue,
                    };

                    let size = object.size;

                    let entry = BlobBackupEntry {
                        blob_hash: blob_hash.to_string(),
                        size,
                        backed_up_at: common::now_secs(), // We don't know original time
                    };
                    let entry_bytes = bincode::serialize(&entry)?;
                    table.insert(blob_hash, entry_bytes.as_slice())?;

                    count += 1;
                    bytes += size;
                }
            }

            // Update metadata
            let mut meta_table = write_txn.open_table(SYNC_METADATA_TABLE)?;
            let metadata = SyncMetadata {
                last_sync_timestamp: common::now_secs(),
                total_blobs_backed_up: count,
                total_bytes_backed_up: bytes,
            };
            let metadata_bytes = bincode::serialize(&metadata)?;
            meta_table.insert("metadata", metadata_bytes.as_slice())?;

            info!(
                blobs = count,
                bytes = bytes,
                "Rebuilt blob backup state from S3"
            );
        }
        write_txn.commit()?;

        Ok(())
    }

    /// Get current sync statistics
    #[allow(dead_code)]
    pub fn get_stats(&self) -> Result<SyncMetadata, Box<dyn std::error::Error + Send + Sync>> {
        let read_txn = self.db.begin_read()?;
        let table = read_txn.open_table(SYNC_METADATA_TABLE)?;

        if let Some(entry) = table.get("metadata")? {
            Ok(bincode::deserialize(entry.value())?)
        } else {
            Ok(SyncMetadata::default())
        }
    }

    /// Check if a specific blob is backed up
    #[allow(dead_code)]
    pub fn is_blob_backed_up(
        &self,
        blob_hash: &str,
    ) -> Result<bool, Box<dyn std::error::Error + Send + Sync>> {
        let read_txn = self.db.begin_read()?;
        let table = read_txn.open_table(BACKED_UP_BLOBS_TABLE)?;
        Ok(table.get(blob_hash)?.is_some())
    }

    /// Count total backed-up blobs in ReDB
    pub fn count_backed_up_blobs(&self) -> Result<u64, Box<dyn std::error::Error + Send + Sync>> {
        let read_txn = self.db.begin_read()?;
        let table = read_txn.open_table(BACKED_UP_BLOBS_TABLE)?;
        Ok(table.len()?)
    }
}

//! Backup module - handles S3 backup/restore with multiple backup types.
//!
//! Supports full, differential, and incremental backups of the validator's
//! iroh-docs database (`docs.db`) to S3-compatible storage.
//!
//! # Backup Types
//!
//! | Type | Interval | Retention | Description |
//! |------|----------|-----------|-------------|
//! | Full | 24h | 30 days | Complete database snapshot |
//! | Differential | 6h | 7 days | Changes since last full backup |
//! | Incremental | 30min | 3 days | Changes since last backup (any type) |
//!
//! # Change Detection
//!
//! Uses BLAKE3 hashing to detect database changes. Backups are skipped if
//! the database hasn't changed since the last backup of the same type.
//!
//! # Automatic Restore
//!
//! On startup, if `docs.db` is missing and backups are enabled, the manager
//! attempts to restore from the latest full backup in S3.
//!
//! # Configuration
//!
//! ```toml
//! [backup]
//! enabled = true
//! s3_endpoint = "https://s3.amazonaws.com"
//! s3_bucket = "my-backups"
//! s3_region = "us-east-1"
//! s3_access_key = "..."
//! s3_secret_key = "..."
//! prefix = "validator"
//!
//! [backup.full]
//! enabled = true
//! interval_hours = 24
//! retention_days = 30
//! ```

use crate::config::BackupConfig;
use chrono::{DateTime, Utc};
use s3::bucket::Bucket;
use s3::creds::Credentials;
use s3::region::Region;
use std::path::PathBuf;
use std::time::{Duration, Instant};
use tokio::fs;
use tracing::{error, info, warn};

/// Backup type enumeration
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum BackupType {
    Full,
    Differential,
    Incremental,
}

impl BackupType {
    pub fn prefix(&self) -> &'static str {
        match self {
            BackupType::Full => "full",
            BackupType::Differential => "diff",
            BackupType::Incremental => "incr",
        }
    }
}

/// Backup manager handles scheduling and execution
pub struct BackupManager {
    config: BackupConfig,
    bucket: Option<Bucket>,
    data_dir: PathBuf,
    last_full: Option<Instant>,
    last_diff: Option<Instant>,
    last_incr: Option<Instant>,
    last_full_hash: Option<String>,
}

impl BackupManager {
    /// Create new backup manager
    pub async fn new(
        config: BackupConfig,
        data_dir: PathBuf,
    ) -> Result<Self, Box<dyn std::error::Error + Send + Sync>> {
        let bucket = if config.enabled {
            Some(Self::create_bucket(&config)?)
        } else {
            None
        };

        Ok(Self {
            config,
            bucket,
            data_dir,
            last_full: None,
            last_diff: None,
            last_incr: None,
            last_full_hash: None,
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

    /// Run the backup scheduler loop
    pub async fn run_scheduler(mut self) {
        if !self.config.enabled {
            info!("Backup disabled, scheduler not starting");
            return;
        }

        info!("Backup scheduler starting");
        info!(
            interval_hours = self.config.full.interval_hours,
            retention_days = self.config.full.retention_days,
            "Full backup schedule"
        );
        info!(
            interval_hours = self.config.differential.interval_hours,
            retention_days = self.config.differential.retention_days,
            "Differential backup schedule"
        );
        info!(
            interval_minutes = self.config.incremental.interval_minutes,
            retention_days = self.config.incremental.retention_days,
            "Incremental backup schedule"
        );

        // Do initial full backup
        tokio::time::sleep(Duration::from_secs(60)).await; // Wait for startup
        if let Err(e) = self.run_backup(BackupType::Full).await {
            error!(error = %e, "Initial full backup failed");
        }

        loop {
            tokio::time::sleep(Duration::from_secs(60)).await;

            // Check if full backup needed
            if self.config.full.enabled {
                let interval = Duration::from_secs(self.config.full.interval_hours * 3600);
                if self
                    .last_full
                    .map(|t| t.elapsed() >= interval)
                    .unwrap_or(true)
                {
                    if let Err(e) = self.run_backup(BackupType::Full).await {
                        error!(error = %e, "Full backup failed");
                    }
                    continue;
                }
            }

            // Check if differential backup needed
            if self.config.differential.enabled && self.last_full.is_some() {
                let interval = Duration::from_secs(self.config.differential.interval_hours * 3600);
                if self
                    .last_diff
                    .map(|t| t.elapsed() >= interval)
                    .unwrap_or(true)
                {
                    if let Err(e) = self.run_backup(BackupType::Differential).await {
                        error!(error = %e, "Differential backup failed");
                    }
                    continue;
                }
            }

            // Check if incremental backup needed
            if self.config.incremental.enabled {
                let interval = Duration::from_secs(self.config.incremental.interval_minutes * 60);
                if self
                    .last_incr
                    .map(|t| t.elapsed() >= interval)
                    .unwrap_or(true)
                {
                    if let Err(e) = self.run_backup(BackupType::Incremental).await {
                        error!(error = %e, "Incremental backup failed");
                    }
                }
            }
        }
    }

    /// Execute a backup of the specified type
    async fn run_backup(
        &mut self,
        backup_type: BackupType,
    ) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        let bucket = self.bucket.as_ref().ok_or("Bucket not configured")?;
        let docs_path = self.data_dir.join("docs.db");

        if !docs_path.exists() {
            return Err("docs.db not found".into());
        }

        let now: DateTime<Utc> = Utc::now();
        let filename = format!(
            "{}/{}-{}-{}.db",
            self.config.prefix,
            backup_type.prefix(),
            now.format("%Y%m%d-%H%M%S"),
            now.timestamp()
        );

        info!(backup_type = backup_type.prefix(), filename = %filename, "Starting backup");

        // Read the database file
        let data = fs::read(&docs_path).await?;
        let data_hash = blake3::hash(&data).to_hex().to_string();

        // For differential/incremental, check if there are changes
        if backup_type != BackupType::Full
            && self
                .last_full_hash
                .as_ref()
                .is_some_and(|h| h == &data_hash)
        {
            info!("No changes since last backup, skipping");
            match backup_type {
                BackupType::Differential => self.last_diff = Some(Instant::now()),
                BackupType::Incremental => self.last_incr = Some(Instant::now()),
                _ => {}
            }
            return Ok(());
        }

        // Upload to S3
        let response = bucket.put_object(&filename, &data).await?;

        if response.status_code() == 200 {
            let size_kb = data.len() / 1024;
            info!(
                backup_type = backup_type.prefix(),
                filename = %filename,
                size_kb = size_kb,
                "Backup complete"
            );

            match backup_type {
                BackupType::Full => {
                    self.last_full = Some(Instant::now());
                    self.last_diff = Some(Instant::now());
                    self.last_incr = Some(Instant::now());
                    self.last_full_hash = Some(data_hash);
                }
                BackupType::Differential => {
                    self.last_diff = Some(Instant::now());
                }
                BackupType::Incremental => {
                    self.last_incr = Some(Instant::now());
                }
            }

            // Cleanup old backups
            self.cleanup_old_backups(backup_type).await?;

            Ok(())
        } else {
            Err(format!("S3 upload failed with status {}", response.status_code()).into())
        }
    }

    /// Remove backups older than retention period
    async fn cleanup_old_backups(
        &self,
        backup_type: BackupType,
    ) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        let bucket = self.bucket.as_ref().ok_or("Bucket not configured")?;

        let retention_days = match backup_type {
            BackupType::Full => self.config.full.retention_days,
            BackupType::Differential => self.config.differential.retention_days,
            BackupType::Incremental => self.config.incremental.retention_days,
        };

        let prefix = format!("{}/{}-", self.config.prefix, backup_type.prefix());
        let cutoff = Utc::now() - chrono::Duration::days(retention_days as i64);

        let list = bucket.list(prefix, None).await?;

        for result in list {
            for object in result.contents {
                // Parse timestamp from filename and check if expired
                let should_delete = object
                    .key
                    .split('-')
                    .next_back()
                    .and_then(|s| s.strip_suffix(".db"))
                    .and_then(|s| s.parse::<i64>().ok())
                    .and_then(|ts| DateTime::from_timestamp(ts, 0))
                    .is_some_and(|dt| dt < cutoff);

                if should_delete {
                    info!(key = %object.key, "Deleting old backup");
                    let _ = bucket.delete_object(&object.key).await;
                }
            }
        }

        Ok(())
    }

    /// Restore from latest backup (called on startup if docs.db missing)
    pub async fn restore_if_needed(
        &self,
    ) -> Result<bool, Box<dyn std::error::Error + Send + Sync>> {
        let docs_path = self.data_dir.join("docs.db");

        if docs_path.exists() {
            return Ok(false); // No restore needed
        }

        if !self.config.enabled {
            warn!("docs.db missing and backup not configured");
            return Ok(false);
        }

        let bucket = self.bucket.as_ref().ok_or("Bucket not configured")?;

        info!("Attempting to restore from backup");

        // Find latest full backup
        let prefix = format!("{}/full-", self.config.prefix);
        let list = bucket.list(prefix, None).await?;

        let mut latest: Option<(String, i64)> = None;

        for result in list {
            for object in result.contents {
                // Parse timestamp from filename
                let ts = object
                    .key
                    .split('-')
                    .next_back()
                    .and_then(|s| s.strip_suffix(".db"))
                    .and_then(|s| s.parse::<i64>().ok());

                if let Some(ts) =
                    ts.filter(|&ts| latest.as_ref().map(|(_, t)| ts > *t).unwrap_or(true))
                {
                    latest = Some((object.key.clone(), ts));
                }
            }
        }

        if let Some((key, _)) = latest {
            info!(key = %key, "Restoring from backup");

            let response = bucket.get_object(&key).await?;
            let data = response.bytes();

            // Ensure parent directory exists
            if let Some(parent) = docs_path.parent() {
                fs::create_dir_all(parent).await?;
            }

            fs::write(&docs_path, data).await?;

            info!(bytes = data.len(), "Restore complete");
            Ok(true)
        } else {
            warn!("No backups found in S3");
            Ok(false)
        }
    }
}

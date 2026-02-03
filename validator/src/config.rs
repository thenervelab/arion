//! Validator configuration module.
//!
//! Loads settings from `validator.toml` with environment variable overrides.
//!
//! # Configuration Hierarchy
//!
//! Configuration is loaded in this priority order (highest wins):
//! 1. Environment variables (e.g., `CHAIN_REGISTRY_ENABLED`, `REBUILD_TICK_SECS`)
//! 2. TOML file (`validator.toml` by default)
//! 3. Built-in defaults
//!
//! # Sections
//!
//! | Section | Purpose |
//! |---------|---------|
//! | `network` | HTTP port, relay URL, data directory |
//! | `backup` | S3 backup settings (full/differential/incremental) |
//! | `families` | API-based family whitelist verification |
//! | `chain_registry` | On-chain pallet-arion verification |
//! | `tuning` | Backpressure, rebuild agent, weight updates |
//!
//! # Example
//!
//! ```toml
//! [network]
//! port = 3002
//! data_dir = "data/validator"
//!
//! [chain_registry]
//! enabled = true
//! cache_path = "arion-registry-cache.json"
//!
//! [tuning]
//! rebuild_enabled = true
//! miner_out_threshold_secs = 600
//! ```

use serde::{Deserialize, Serialize};
use tracing::warn;
// use std::path::PathBuf;

/// Root configuration structure
#[derive(Debug, Clone, Deserialize, Serialize, Default)]
pub struct ValidatorConfig {
    #[serde(default)]
    pub network: NetworkConfig,
    #[serde(default)]
    pub backup: BackupConfig,
    #[serde(default)]
    pub families: FamiliesConfig,
    #[serde(default)]
    pub chain_registry: ChainRegistryConfig,
    #[serde(default)]
    pub warden: WardenConfig,
    #[serde(default)]
    pub reputation: ReputationConfig,
    #[serde(default)]
    pub tuning: TuningConfig,
    #[serde(default)]
    pub p2p: P2pConfig,
    #[serde(default)]
    pub chain_submitter: ChainSubmitterConfig,
}

/// Network configuration
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct NetworkConfig {
    #[serde(default = "default_port")]
    pub port: u16,
    pub relay_url: Option<String>,
    #[serde(default = "default_data_dir")]
    pub data_dir: String,
}

impl Default for NetworkConfig {
    fn default() -> Self {
        Self {
            port: default_port(),
            relay_url: None,
            data_dir: default_data_dir(),
        }
    }
}

fn default_port() -> u16 {
    3002
}
fn default_data_dir() -> String {
    "data/validator".to_string()
}

/// S3 backup configuration
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct BackupConfig {
    #[serde(default)]
    pub enabled: bool,
    pub s3_endpoint: Option<String>,
    pub s3_bucket: Option<String>,
    pub s3_region: Option<String>,
    #[serde(default)]
    pub s3_access_key: String,
    #[serde(default)]
    pub s3_secret_key: String,
    #[serde(default = "default_prefix")]
    pub prefix: String,
    #[serde(default)]
    pub full: FullBackupConfig,
    #[serde(default)]
    pub differential: DifferentialBackupConfig,
    #[serde(default)]
    pub incremental: IncrementalBackupConfig,
    /// Blob backup settings for incremental shard backup
    #[serde(default)]
    pub blobs: BlobBackupConfig,
}

impl Default for BackupConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            s3_endpoint: None,
            s3_bucket: None,
            s3_region: None,
            s3_access_key: String::new(),
            s3_secret_key: String::new(),
            prefix: default_prefix(),
            full: FullBackupConfig::default(),
            differential: DifferentialBackupConfig::default(),
            incremental: IncrementalBackupConfig::default(),
            blobs: BlobBackupConfig::default(),
        }
    }
}

fn default_prefix() -> String {
    "validator".to_string()
}

/// Full backup settings
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct FullBackupConfig {
    #[serde(default = "default_true")]
    pub enabled: bool,
    #[serde(default = "default_full_interval")]
    pub interval_hours: u64,
    #[serde(default = "default_full_retention")]
    pub retention_days: u64,
}

impl Default for FullBackupConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            interval_hours: 24,
            retention_days: 30,
        }
    }
}

fn default_true() -> bool {
    true
}
fn default_full_interval() -> u64 {
    24
}
fn default_full_retention() -> u64 {
    30
}

/// Differential backup settings
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct DifferentialBackupConfig {
    #[serde(default = "default_true")]
    pub enabled: bool,
    #[serde(default = "default_diff_interval")]
    pub interval_hours: u64,
    #[serde(default = "default_diff_retention")]
    pub retention_days: u64,
}

impl Default for DifferentialBackupConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            interval_hours: 6,
            retention_days: 7,
        }
    }
}

fn default_diff_interval() -> u64 {
    6
}
fn default_diff_retention() -> u64 {
    7
}

/// Incremental backup settings
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct IncrementalBackupConfig {
    #[serde(default = "default_true")]
    pub enabled: bool,
    #[serde(default = "default_incr_interval")]
    pub interval_minutes: u64,
    #[serde(default = "default_incr_retention")]
    pub retention_days: u64,
}

impl Default for IncrementalBackupConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            interval_minutes: 30,
            retention_days: 3,
        }
    }
}

fn default_incr_interval() -> u64 {
    30
}
fn default_incr_retention() -> u64 {
    3
}

/// Blob backup settings for incremental shard backup to S3.
///
/// When enabled, blob backup syncs all shard blobs (erasure-coded data)
/// to S3 on an interval. Since blobs are content-addressed by BLAKE3 hash,
/// only new blobs are uploaded (never re-uploads unchanged content).
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct BlobBackupConfig {
    /// Enable blob backup (default: false)
    #[serde(default)]
    pub enabled: bool,
    /// Sync interval in minutes (default: 15)
    #[serde(default = "default_blob_sync_interval")]
    pub sync_interval_minutes: u64,
    /// Number of blobs to upload in each batch (default: 100)
    #[serde(default = "default_blob_batch_size")]
    pub batch_size: usize,
    /// Concurrent S3 uploads per batch (default: 8)
    #[serde(default = "default_blob_upload_concurrency")]
    pub upload_concurrency: usize,
    /// S3 key prefix for blobs (default: "blobs")
    #[serde(default = "default_blob_prefix")]
    pub prefix: String,
}

impl Default for BlobBackupConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            sync_interval_minutes: default_blob_sync_interval(),
            batch_size: default_blob_batch_size(),
            upload_concurrency: default_blob_upload_concurrency(),
            prefix: default_blob_prefix(),
        }
    }
}

fn default_blob_sync_interval() -> u64 {
    15
}
fn default_blob_batch_size() -> usize {
    100
}
fn default_blob_upload_concurrency() -> usize {
    8
}
fn default_blob_prefix() -> String {
    "blobs".to_string()
}

/// Family verification configuration
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct FamiliesConfig {
    /// Enable family verification during miner registration
    #[serde(default)]
    pub enabled: bool,

    /// API URL to fetch family whitelist
    #[serde(default = "default_families_api_url")]
    pub api_url: String,

    /// How often to refresh the families list (seconds)
    #[serde(default = "default_families_refresh")]
    pub refresh_interval_secs: u64,
}

impl Default for FamiliesConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            api_url: default_families_api_url(),
            refresh_interval_secs: default_families_refresh(),
        }
    }
}

fn default_families_api_url() -> String {
    "https://api.hippius.com/api/miner/families/".to_string()
}
fn default_families_refresh() -> u64 {
    300
} // 5 minutes

/// On-chain registry verification configuration (reads local JSON snapshot from `chain-registry-cache`).
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct ChainRegistryConfig {
    /// Enable verifying miner registrations against on-chain `pallet-arion` registry data.
    #[serde(default)]
    pub enabled: bool,

    /// Path to the JSON snapshot produced by `chain-registry-cache`.
    #[serde(default = "default_chain_registry_cache_path")]
    pub cache_path: String,

    /// How often to reload the snapshot from disk (seconds).
    #[serde(default = "default_chain_registry_refresh")]
    pub refresh_interval_secs: u64,

    /// If true, allow miners to register even if the cache is missing/stale or a node isn't found.
    /// Recommended: false (fail-closed).
    #[serde(default)]
    pub fail_open: bool,
}

impl Default for ChainRegistryConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            cache_path: default_chain_registry_cache_path(),
            refresh_interval_secs: default_chain_registry_refresh(),
            fail_open: false,
        }
    }
}

fn default_chain_registry_cache_path() -> String {
    "arion-registry-cache.json".to_string()
}
fn default_chain_registry_refresh() -> u64 {
    30
}

/// Warden (proof-of-storage audit) configuration.
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct WardenConfig {
    /// Enable pushing shard commitments to Warden on upload.
    #[serde(default)]
    pub enabled: bool,

    /// Warden HTTP API base URL (e.g., "http://localhost:3003").
    #[serde(default = "default_warden_url")]
    pub url: String,

    /// Audit epoch duration in seconds (default: 3600 = 1 hour).
    /// Shards are sampled per epoch rather than pushing all shards.
    #[serde(default = "default_audit_epoch_secs")]
    pub audit_epoch_secs: u64,

    /// Number of shards to sample per miner per epoch.
    /// With 30 miners and 100 shards each, warden tracks ~3000 shards max per epoch.
    #[serde(default = "default_shards_per_miner_per_epoch")]
    pub shards_per_miner_per_epoch: usize,
}

impl Default for WardenConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            url: default_warden_url(),
            audit_epoch_secs: default_audit_epoch_secs(),
            shards_per_miner_per_epoch: default_shards_per_miner_per_epoch(),
        }
    }
}

fn default_warden_url() -> String {
    "http://localhost:3003".to_string()
}

fn default_audit_epoch_secs() -> u64 {
    common::DEFAULT_AUDIT_EPOCH_SECS
}

fn default_shards_per_miner_per_epoch() -> usize {
    common::DEFAULT_SHARDS_PER_MINER_PER_EPOCH
}

/// Reputation system configuration for warden audit integration.
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct ReputationConfig {
    /// Allowed warden public keys (hex-encoded). Empty = skip signature verification.
    #[serde(default)]
    pub allowed_wardens: Vec<String>,

    /// Reputation penalty for Failed audit result
    #[serde(default = "default_strike_weight_failed")]
    pub strike_weight_failed: f32,

    /// Reputation penalty for InvalidProof audit result
    #[serde(default = "default_strike_weight_invalid_proof")]
    pub strike_weight_invalid_proof: f32,

    /// Reputation penalty for Timeout audit result
    #[serde(default = "default_strike_weight_timeout")]
    pub strike_weight_timeout: f32,

    /// Reputation recovery rate per successful audit (after min_passes_for_recovery)
    #[serde(default = "default_recovery_rate")]
    pub recovery_rate: f32,

    /// Minimum consecutive passes required before recovery begins
    #[serde(default = "default_min_passes_for_recovery")]
    pub min_passes_for_recovery: u32,

    /// Reputation threshold for banning miner (reputation >= this = banned)
    #[serde(default = "default_ban_threshold")]
    pub ban_threshold: f32,
}

impl Default for ReputationConfig {
    fn default() -> Self {
        Self {
            allowed_wardens: Vec::new(),
            strike_weight_failed: default_strike_weight_failed(),
            strike_weight_invalid_proof: default_strike_weight_invalid_proof(),
            strike_weight_timeout: default_strike_weight_timeout(),
            recovery_rate: default_recovery_rate(),
            min_passes_for_recovery: default_min_passes_for_recovery(),
            ban_threshold: default_ban_threshold(),
        }
    }
}

fn default_strike_weight_failed() -> f32 {
    1.0
}
fn default_strike_weight_invalid_proof() -> f32 {
    1.0
}
fn default_strike_weight_timeout() -> f32 {
    0.3
}
fn default_recovery_rate() -> f32 {
    0.05
}
fn default_min_passes_for_recovery() -> u32 {
    10
}
fn default_ban_threshold() -> f32 {
    3.0
}

/// P2P protocol authorization configuration.
///
/// Controls which node IDs (Ed25519 public keys) are authorized to use each P2P protocol.
/// Empty lists mean allow all connections (development mode).
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct P2pConfig {
    /// Authorized gateway node IDs (hex-encoded Ed25519 public keys).
    /// Empty = allow all gateways (dev mode).
    #[serde(default)]
    pub authorized_gateways: Vec<String>,

    /// Authorized warden node IDs (hex-encoded Ed25519 public keys).
    /// Empty = allow all wardens (dev mode).
    #[serde(default)]
    pub authorized_wardens: Vec<String>,

    /// Authorized chain-submitter node IDs (hex-encoded Ed25519 public keys).
    /// Empty = allow all submitters (dev mode).
    #[serde(default)]
    pub authorized_submitters: Vec<String>,
}

/// Chain-submitter configuration for attestation commitment push.
///
/// When configured, the validator will push epoch attestation commitments
/// to the chain-submitter via P2P at epoch boundaries.
#[derive(Debug, Clone, Deserialize, Serialize, Default)]
pub struct ChainSubmitterConfig {
    /// Chain-submitter node ID (hex-encoded Ed25519 public key).
    /// When set, enables P2P push of attestation commitments.
    #[serde(default)]
    pub node_id: Option<String>,
}

impl Default for P2pConfig {
    fn default() -> Self {
        Self {
            authorized_gateways: Vec::new(),
            authorized_wardens: Vec::new(),
            authorized_submitters: Vec::new(),
        }
    }
}

/// Parse boolean from env var string (truthy unless "0", "false", or "FALSE")
fn parse_bool_env(val: &str) -> bool {
    !matches!(val, "0" | "false" | "FALSE")
}

/// Parse comma-separated node ID list from env var string.
fn parse_node_id_list(val: &str) -> Vec<String> {
    val.split(',')
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
        .collect()
}

impl ValidatorConfig {
    /// Load configuration from file with environment variable overrides
    pub fn load(path: Option<&str>) -> Result<Self, Box<dyn std::error::Error>> {
        let config_path = path.unwrap_or("validator.toml");

        let mut config = if std::path::Path::new(config_path).exists() {
            let content = std::fs::read_to_string(config_path)?;
            toml::from_str(&content)?
        } else {
            warn!(path = config_path, "No config file found, using defaults");
            ValidatorConfig::default()
        };

        // Environment variable overrides
        if let Ok(val) = std::env::var("PORT") {
            if let Ok(port) = val.parse() {
                config.network.port = port;
            }
        }

        if let Ok(val) = std::env::var("IROH_RELAY_URL") {
            config.network.relay_url = Some(val);
        }

        // Chain registry env overrides
        if let Ok(val) = std::env::var("CHAIN_REGISTRY_ENABLED") {
            config.chain_registry.enabled = parse_bool_env(&val);
        }
        if let Ok(val) = std::env::var("CHAIN_REGISTRY_CACHE_PATH") {
            if !val.trim().is_empty() {
                config.chain_registry.cache_path = val;
            }
        }
        if let Ok(val) = std::env::var("CHAIN_REGISTRY_REFRESH_SECS") {
            if let Ok(n) = val.parse() {
                config.chain_registry.refresh_interval_secs = n;
            }
        }
        if let Ok(val) = std::env::var("CHAIN_REGISTRY_FAIL_OPEN") {
            config.chain_registry.fail_open = parse_bool_env(&val);
        }

        if let Ok(val) = std::env::var("BACKUP_ENABLED") {
            config.backup.enabled = val.parse().unwrap_or(false);
        }

        if let Ok(val) = std::env::var("BACKUP_S3_ENDPOINT") {
            config.backup.s3_endpoint = Some(val);
        }

        if let Ok(val) = std::env::var("BACKUP_S3_BUCKET") {
            config.backup.s3_bucket = Some(val);
        }

        if let Ok(val) = std::env::var("BACKUP_S3_ACCESS_KEY") {
            config.backup.s3_access_key = val;
        }

        if let Ok(val) = std::env::var("BACKUP_S3_SECRET_KEY") {
            config.backup.s3_secret_key = val;
        }

        // Blob backup env overrides
        if let Ok(val) = std::env::var("BLOB_BACKUP_ENABLED") {
            config.backup.blobs.enabled = parse_bool_env(&val);
        }
        if let Ok(val) = std::env::var("BLOB_BACKUP_SYNC_INTERVAL_MINUTES") {
            if let Ok(n) = val.parse() {
                config.backup.blobs.sync_interval_minutes = n;
            }
        }
        if let Ok(val) = std::env::var("BLOB_BACKUP_BATCH_SIZE") {
            if let Ok(n) = val.parse() {
                config.backup.blobs.batch_size = n;
            }
        }
        if let Ok(val) = std::env::var("BLOB_BACKUP_UPLOAD_CONCURRENCY") {
            if let Ok(n) = val.parse() {
                config.backup.blobs.upload_concurrency = n;
            }
        }

        // Tuning env overrides (backpressure / rebuild loop)
        if let Ok(val) = std::env::var("REBUILD_ENABLED") {
            config.tuning.rebuild_enabled = parse_bool_env(&val);
        }
        if let Ok(val) = std::env::var("REBUILD_TICK_SECS") {
            if let Ok(n) = val.parse() {
                config.tuning.rebuild_tick_secs = n;
            }
        }
        if let Ok(val) = std::env::var("REBUILD_FILES_PER_TICK") {
            if let Ok(n) = val.parse() {
                config.tuning.rebuild_files_per_tick = n;
            }
        }
        if let Ok(val) = std::env::var("REBUILD_STRIPES_PER_FILE") {
            if let Ok(n) = val.parse() {
                config.tuning.rebuild_stripes_per_file = n;
            }
        }
        if let Ok(val) = std::env::var("REBUILD_CONCURRENCY") {
            if let Ok(n) = val.parse() {
                config.tuning.rebuild_concurrency = n;
            }
        }
        if let Ok(val) = std::env::var("MINER_OUT_THRESHOLD_SECS") {
            if let Ok(n) = val.parse() {
                config.tuning.miner_out_threshold_secs = n;
            }
        }
        if let Ok(val) = std::env::var("UPLOAD_MIN_REDUNDANCY_BUFFER") {
            if let Ok(n) = val.parse() {
                config.tuning.upload_min_redundancy_buffer = n;
            }
        }

        // Placement weight update env overrides
        if let Ok(val) = std::env::var("WEIGHT_UPDATE_ENABLED") {
            config.tuning.weight_update_enabled = parse_bool_env(&val);
        }
        if let Ok(val) = std::env::var("WEIGHT_UPDATE_TICK_SECS") {
            if let Ok(n) = val.parse() {
                config.tuning.weight_update_tick_secs = n;
            }
        }
        if let Ok(val) = std::env::var("WEIGHT_UPDATE_MIN_CHANGE_PCT") {
            if let Ok(n) = val.parse() {
                config.tuning.weight_update_min_change_pct = n;
            }
        }

        // Manifest cache tombstone TTL env override
        if let Ok(val) = std::env::var("MANIFEST_CACHE_TOMBSTONE_TTL_SECS") {
            if let Ok(n) = val.parse() {
                config.tuning.manifest_cache_tombstone_ttl_secs = n;
            }
        }

        // Warden (proof-of-storage) env overrides
        if let Ok(val) = std::env::var("WARDEN_ENABLED") {
            config.warden.enabled = parse_bool_env(&val);
        }
        if let Ok(val) = std::env::var("WARDEN_URL") {
            if !val.trim().is_empty() {
                config.warden.url = val;
            }
        }
        if let Ok(val) = std::env::var("AUDIT_EPOCH_SECS") {
            if let Ok(n) = val.parse() {
                config.warden.audit_epoch_secs = n;
            }
        }
        if let Ok(val) = std::env::var("SHARDS_PER_MINER_PER_EPOCH") {
            if let Ok(n) = val.parse() {
                config.warden.shards_per_miner_per_epoch = n;
            }
        }

        // Reputation system env overrides
        if let Ok(val) = std::env::var("REPUTATION_ALLOWED_WARDENS") {
            config.reputation.allowed_wardens = val
                .split(',')
                .map(|s| s.trim().to_string())
                .filter(|s| !s.is_empty())
                .collect();
        }
        if let Ok(val) = std::env::var("REPUTATION_STRIKE_WEIGHT_FAILED") {
            if let Ok(n) = val.parse() {
                config.reputation.strike_weight_failed = n;
            }
        }
        if let Ok(val) = std::env::var("REPUTATION_STRIKE_WEIGHT_TIMEOUT") {
            if let Ok(n) = val.parse() {
                config.reputation.strike_weight_timeout = n;
            }
        }
        if let Ok(val) = std::env::var("REPUTATION_RECOVERY_RATE") {
            if let Ok(n) = val.parse() {
                config.reputation.recovery_rate = n;
            }
        }
        if let Ok(val) = std::env::var("REPUTATION_MIN_PASSES_FOR_RECOVERY") {
            if let Ok(n) = val.parse() {
                config.reputation.min_passes_for_recovery = n;
            }
        }
        if let Ok(val) = std::env::var("REPUTATION_BAN_THRESHOLD") {
            if let Ok(n) = val.parse() {
                config.reputation.ban_threshold = n;
            }
        }

        // P2P authorization env overrides (comma-separated node IDs)
        if let Ok(val) = std::env::var("P2P_AUTHORIZED_GATEWAYS") {
            config.p2p.authorized_gateways = parse_node_id_list(&val);
        }
        if let Ok(val) = std::env::var("P2P_AUTHORIZED_WARDENS") {
            config.p2p.authorized_wardens = parse_node_id_list(&val);
        }
        if let Ok(val) = std::env::var("P2P_AUTHORIZED_SUBMITTERS") {
            config.p2p.authorized_submitters = parse_node_id_list(&val);
        }

        // Chain-submitter config for attestation commitment push
        if let Ok(val) = std::env::var("CHAIN_SUBMITTER_NODE_ID") {
            let trimmed = val.trim();
            if !trimmed.is_empty() {
                config.chain_submitter.node_id = Some(trimmed.to_string());
            }
        }

        Ok(config)
    }

    /// Validate backup configuration
    pub fn validate_backup(&self) -> Result<(), String> {
        if !self.backup.enabled {
            return Ok(());
        }

        if self.backup.s3_endpoint.is_none() {
            return Err("backup.s3_endpoint is required when backup is enabled".to_string());
        }

        if self.backup.s3_bucket.is_none() {
            return Err("backup.s3_bucket is required when backup is enabled".to_string());
        }

        if self.backup.s3_access_key.is_empty() {
            return Err(
                "backup.s3_access_key is required (or set BACKUP_S3_ACCESS_KEY env)".to_string(),
            );
        }

        if self.backup.s3_secret_key.is_empty() {
            return Err(
                "backup.s3_secret_key is required (or set BACKUP_S3_SECRET_KEY env)".to_string(),
            );
        }

        Ok(())
    }
}

/// Backpressure / operational tuning knobs
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct TuningConfig {
    /// Enable/disable automatic rebuild loop
    #[serde(default = "default_true")]
    pub rebuild_enabled: bool,
    /// Rebuild loop tick interval
    #[serde(default = "default_rebuild_tick_secs")]
    pub rebuild_tick_secs: u64,
    /// Max files to rebuild per tick
    #[serde(default = "default_rebuild_files_per_tick")]
    pub rebuild_files_per_tick: usize,
    /// Max stripes per file per tick (0 = unlimited)
    #[serde(default = "default_rebuild_stripes_per_file")]
    pub rebuild_stripes_per_file: usize,
    /// Max concurrent file rebuilds per tick
    #[serde(default = "default_rebuild_concurrency")]
    pub rebuild_concurrency: usize,
    /// How long a miner must be offline before being marked OUT (epoch bump)
    #[serde(default = "default_miner_out_threshold_secs")]
    pub miner_out_threshold_secs: u64,

    // ---- Upload redundancy requirements ----
    /// Minimum number of shards above k that must succeed for upload to complete.
    /// For k=10, m=20: buffer=10 means require 20 shards (k+buffer), providing
    /// tolerance for 10 miner failures during download.
    /// Set to 0 to accept minimum k shards (no fault tolerance).
    /// Set to m (20) to require full k+m success.
    /// Default: 10 (half of parity shards for 10+20 config)
    #[serde(default = "default_upload_min_redundancy_buffer")]
    pub upload_min_redundancy_buffer: usize,

    // ---- Placement weight update knobs (coarse, epoch-bumping) ----
    /// Enable periodic recomputation of miner weights (capacity/uptime/strikes) and bump epoch when weights change.
    /// Disabled by default to avoid constant remapping.
    #[serde(default)]
    pub weight_update_enabled: bool,
    /// How often to recompute weights (seconds).
    #[serde(default = "default_weight_update_tick_secs")]
    pub weight_update_tick_secs: u64,
    /// Minimum percentage change required (per-miner) to apply a new weight and bump epoch.
    #[serde(default = "default_weight_update_min_change_pct")]
    pub weight_update_min_change_pct: u32,

    // ---- Manifest cache TTL for tombstones ----
    /// TTL for "DELETED" tombstones in manifest cache (seconds).
    /// After this time, tombstones are expired allowing re-upload of the same file hash.
    /// Default: 3600 (1 hour)
    #[serde(default = "default_manifest_cache_tombstone_ttl_secs")]
    pub manifest_cache_tombstone_ttl_secs: u64,
}

impl Default for TuningConfig {
    fn default() -> Self {
        Self {
            rebuild_enabled: default_true(),
            rebuild_tick_secs: default_rebuild_tick_secs(),
            rebuild_files_per_tick: default_rebuild_files_per_tick(),
            rebuild_stripes_per_file: default_rebuild_stripes_per_file(),
            rebuild_concurrency: default_rebuild_concurrency(),
            miner_out_threshold_secs: default_miner_out_threshold_secs(),
            upload_min_redundancy_buffer: default_upload_min_redundancy_buffer(),
            weight_update_enabled: false,
            weight_update_tick_secs: default_weight_update_tick_secs(),
            weight_update_min_change_pct: default_weight_update_min_change_pct(),
            manifest_cache_tombstone_ttl_secs: default_manifest_cache_tombstone_ttl_secs(),
        }
    }
}

fn default_rebuild_tick_secs() -> u64 {
    10
}
fn default_rebuild_files_per_tick() -> usize {
    5
}
fn default_rebuild_stripes_per_file() -> usize {
    25
}
fn default_rebuild_concurrency() -> usize {
    2
}
fn default_miner_out_threshold_secs() -> u64 {
    600
}
fn default_upload_min_redundancy_buffer() -> usize {
    10
} // require k+10 shards minimum (for k=10, m=20: 20 shards, tolerates 10 failures)
fn default_weight_update_tick_secs() -> u64 {
    3600
} // 1 hour
fn default_weight_update_min_change_pct() -> u32 {
    20
} // 20%
fn default_manifest_cache_tombstone_ttl_secs() -> u64 {
    3600
} // 1 hour - tombstones expire after this, allowing re-upload

//! Miner configuration module.
//!
//! Loads settings from `miner.toml` with environment variable overrides.
//!
//! # Configuration Hierarchy
//!
//! Configuration is loaded in this priority order (highest wins):
//! 1. Environment variables (e.g., `VALIDATOR_NODE_ID`, `MINER_STORE_CONCURRENCY`)
//! 2. TOML file (`miner.toml` by default)
//! 3. Built-in defaults
//!
//! # Sections
//!
//! | Section | Purpose |
//! |---------|---------|
//! | `network` | HTTP port, P2P port, relay URL, family ID |
//! | `storage` | Blob storage path, max storage limit, data directory |
//! | `validator` | Validator node ID, heartbeat interval |
//! | `tuning` | Concurrency limits, timeouts, rebalance settings |
//!
//! # Example
//!
//! ```toml
//! [network]
//! port = 3001
//! p2p_port = 11230
//! family_id = "my-datacenter"
//!
//! [storage]
//! path = "data/miner/blobs"
//! max_storage_gb = 1000
//!
//! [validator]
//! node_id = "abc123..."
//!
//! [tuning]
//! store_concurrency = 64
//! fetch_concurrency = 256
//! ```

use anyhow::Result;
use serde::{Deserialize, Serialize};
use std::path::Path;
use tracing::warn;

/// Root configuration structure
#[derive(Debug, Clone, Deserialize, Serialize, Default)]
pub struct MinerConfig {
    #[serde(default)]
    pub network: NetworkConfig,
    #[serde(default)]
    pub storage: StorageConfig,
    #[serde(default)]
    pub validator: ValidatorConfig,
    #[serde(default)]
    pub tuning: TuningConfig,
}

/// Network configuration
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct NetworkConfig {
    /// HTTP API port
    #[serde(default = "default_port")]
    pub port: u16,

    /// Public hostname/IP for other nodes to reach this miner
    pub hostname: Option<String>,

    /// Iroh relay URL for P2P connectivity
    pub relay_url: Option<String>,

    /// P2P bind port (UDP)
    #[serde(default = "default_p2p_port")]
    pub p2p_port: u16,

    /// Family ID for CRUSH placement grouping
    #[serde(default = "default_family_id")]
    pub family_id: String,
}

impl Default for NetworkConfig {
    fn default() -> Self {
        Self {
            port: default_port(),
            hostname: None,
            relay_url: None,
            p2p_port: default_p2p_port(),
            family_id: default_family_id(),
        }
    }
}

fn default_port() -> u16 {
    3001
}
fn default_p2p_port() -> u16 {
    11230
}
fn default_family_id() -> String {
    "default".to_string()
}

/// Storage configuration
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct StorageConfig {
    /// Directory for blob storage
    #[serde(default = "default_storage_path")]
    pub path: String,

    /// Maximum storage to use in GB (0 = unlimited)
    #[serde(default)]
    pub max_storage_gb: u64,

    /// Data directory for keypair and state
    #[serde(default = "default_data_dir")]
    pub data_dir: String,
}

impl Default for StorageConfig {
    fn default() -> Self {
        Self {
            path: default_storage_path(),
            max_storage_gb: 0,
            data_dir: default_data_dir(),
        }
    }
}

fn default_storage_path() -> String {
    "data/miner/blobs".to_string()
}
fn default_data_dir() -> String {
    "data/miner".to_string()
}

/// Validator connection configuration
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct ValidatorConfig {
    /// Validator Node ID (Ed25519 public key) for P2P
    pub node_id: Option<String>,

    /// Warden Node ID (Ed25519 public key) for PoS challenges
    pub warden_node_id: Option<String>,

    /// Heartbeat interval in seconds
    #[serde(default = "default_heartbeat_interval")]
    pub heartbeat_interval_secs: u64,

    /// Registration retry delay in seconds
    #[serde(default = "default_registration_retry")]
    pub registration_retry_secs: u64,
}

impl Default for ValidatorConfig {
    fn default() -> Self {
        Self {
            node_id: None,
            warden_node_id: None,
            heartbeat_interval_secs: default_heartbeat_interval(),
            registration_retry_secs: default_registration_retry(),
        }
    }
}

fn default_heartbeat_interval() -> u64 {
    30
}
fn default_registration_retry() -> u64 {
    60
}

impl MinerConfig {
    /// Load configuration from file with environment variable overrides
    pub fn load(path: Option<&str>) -> Result<Self> {
        let config_path = path.unwrap_or("miner.toml");

        let mut config = if Path::new(config_path).exists() {
            let content = std::fs::read_to_string(config_path)?;
            toml::from_str(&content)?
        } else {
            warn!(config_path = %config_path, "No config file found, using defaults/env vars");
            MinerConfig::default()
        };

        // Environment variable overrides
        if let Ok(val) = std::env::var("PORT") {
            match val.parse() {
                Ok(port) => config.network.port = port,
                Err(_) => warn!(value = %val, "Invalid PORT value, using default"),
            }
        }

        if let Ok(val) = std::env::var("P2P_PORT") {
            match val.parse() {
                Ok(port) => config.network.p2p_port = port,
                Err(_) => warn!(value = %val, "Invalid P2P_PORT value, using default"),
            }
        }

        if let Ok(val) = std::env::var("HOSTNAME") {
            config.network.hostname = Some(val);
        }

        if let Ok(val) = std::env::var("IROH_RELAY_URL") {
            config.network.relay_url = Some(val);
        }

        if let Ok(val) = std::env::var("FAMILY_ID") {
            config.network.family_id = val;
        }

        if let Ok(val) = std::env::var("STORAGE_PATH") {
            config.storage.path = val;
        }

        if let Ok(val) = std::env::var("MAX_STORAGE_GB") {
            match val.parse() {
                Ok(gb) => config.storage.max_storage_gb = gb,
                Err(_) => warn!(value = %val, "Invalid MAX_STORAGE_GB value, using default"),
            }
        }

        if let Ok(val) = std::env::var("VALIDATOR_NODE_ID") {
            config.validator.node_id = Some(val);
        }

        if let Ok(val) = std::env::var("WARDEN_NODE_ID") {
            config.validator.warden_node_id = Some(val);
        }

        // Tuning env overrides
        if let Ok(val) = std::env::var("MINER_STORE_CONCURRENCY") {
            match val.parse() {
                Ok(n) => config.tuning.store_concurrency = n,
                Err(_) => {
                    warn!(value = %val, "Invalid MINER_STORE_CONCURRENCY value, using default")
                }
            }
        }
        if let Ok(val) = std::env::var("MINER_PULL_CONCURRENCY") {
            match val.parse() {
                Ok(n) => config.tuning.pull_concurrency = n,
                Err(_) => {
                    warn!(value = %val, "Invalid MINER_PULL_CONCURRENCY value, using default")
                }
            }
        }
        if let Ok(val) = std::env::var("MINER_FETCH_CONCURRENCY") {
            match val.parse() {
                Ok(n) => config.tuning.fetch_concurrency = n,
                Err(_) => {
                    warn!(value = %val, "Invalid MINER_FETCH_CONCURRENCY value, using default")
                }
            }
        }
        if let Ok(val) = std::env::var("MINER_REBALANCE_ENABLED") {
            config.tuning.rebalance_enabled = val != "0" && val.to_lowercase() != "false";
        }
        if let Ok(val) = std::env::var("MINER_REBALANCE_TICK_SECS") {
            match val.parse() {
                Ok(n) => config.tuning.rebalance_tick_secs = n,
                Err(_) => {
                    warn!(value = %val, "Invalid MINER_REBALANCE_TICK_SECS value, using default")
                }
            }
        }

        Ok(config)
    }

    /// Validate required configuration
    #[allow(dead_code)]
    pub fn validate(&self) -> Result<(), String> {
        if self.validator.node_id.is_none() {
            return Err("validator.node_id is required (or set VALIDATOR_NODE_ID env)".to_string());
        }

        Ok(())
    }

    /// Get the full HTTP address for this miner
    #[allow(dead_code)]
    pub fn http_addr(&self) -> String {
        let host = self
            .network
            .hostname
            .clone()
            .unwrap_or_else(|| "localhost".to_string());
        format!("http://{}:{}", host, self.network.port)
    }
}

/// Backpressure and concurrency tuning knobs
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct TuningConfig {
    /// Max concurrent Store operations (validator pushes / internal pulls)
    #[serde(default = "default_store_concurrency")]
    pub store_concurrency: usize,
    /// Max concurrent PullFromPeer / download-from-peer tasks
    #[serde(default = "default_pull_concurrency")]
    pub pull_concurrency: usize,
    /// Max concurrent FetchBlob serving operations
    #[serde(default = "default_fetch_concurrency")]
    pub fetch_concurrency: usize,
    /// Connection timeout in seconds
    #[serde(default = "default_connect_timeout")]
    pub connect_timeout_secs: u64,
    /// Read timeout in seconds
    #[serde(default = "default_read_timeout")]
    pub read_timeout_secs: u64,
    /// Initial backoff for retries in seconds
    #[serde(default = "default_initial_backoff")]
    pub initial_backoff_secs: u64,
    /// Maximum backoff for retries in seconds
    #[serde(default = "default_max_backoff")]
    pub max_backoff_secs: u64,
    /// Enable periodic self-rebalancing (miner pulls missing shards)
    #[serde(default = "default_rebalance_enabled")]
    pub rebalance_enabled: bool,
    /// Self-rebalance check interval in seconds
    #[serde(default = "default_rebalance_tick_secs")]
    pub rebalance_tick_secs: u64,
    /// Max concurrent PoS proof generation operations (CPU-intensive, default 2)
    #[serde(default)]
    pub pos_concurrency: Option<usize>,
}

impl Default for TuningConfig {
    fn default() -> Self {
        Self {
            store_concurrency: default_store_concurrency(),
            pull_concurrency: default_pull_concurrency(),
            fetch_concurrency: default_fetch_concurrency(),
            connect_timeout_secs: default_connect_timeout(),
            read_timeout_secs: default_read_timeout(),
            initial_backoff_secs: default_initial_backoff(),
            max_backoff_secs: default_max_backoff(),
            rebalance_enabled: default_rebalance_enabled(),
            rebalance_tick_secs: default_rebalance_tick_secs(),
            pos_concurrency: None, // defaults to 2 in main.rs
        }
    }
}

fn default_store_concurrency() -> usize {
    1024
}
fn default_pull_concurrency() -> usize {
    32
}
fn default_fetch_concurrency() -> usize {
    256
}
fn default_connect_timeout() -> u64 {
    20
}
fn default_read_timeout() -> u64 {
    30
}
fn default_initial_backoff() -> u64 {
    5
}
fn default_max_backoff() -> u64 {
    60
}
fn default_rebalance_enabled() -> bool {
    true
}
fn default_rebalance_tick_secs() -> u64 {
    300
}

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
//! | `network` | P2P port, relay URL, family ID |
//! | `storage` | Blob storage path, max storage limit, data directory |
//! | `validator` | Validator node ID, heartbeat interval |
//! | `tuning` | Concurrency limits, timeouts, rebalance settings |
//!
//! # Example
//!
//! ```toml
//! [network]
//! p2p_port = 11220
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

/// Read an env var, parse it, and apply it to `target`. Logs a warning on parse failure.
fn env_parse<T: std::str::FromStr>(var: &str, target: &mut T) {
    if let Ok(val) = std::env::var(var) {
        match val.parse() {
            Ok(parsed) => *target = parsed,
            Err(_) => warn!(
                env = var,
                value = %val,
                expected_type = std::any::type_name::<T>(),
                "Invalid env var value, using default"
            ),
        }
    }
}

/// Read an env var as a string and set an `Option<String>` field.
fn env_string_opt(var: &str, target: &mut Option<String>) {
    if let Ok(val) = std::env::var(var) {
        *target = Some(val);
    }
}

/// Read an env var, trim whitespace, and set an `Option<String>` field (skips empty values).
fn env_trimmed_opt(var: &str, target: &mut Option<String>) {
    if let Ok(val) = std::env::var(var) {
        let trimmed = val.trim();
        if !trimmed.is_empty() {
            *target = Some(trimmed.to_string());
        }
    }
}

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
    /// Public hostname/IP for other nodes to reach this miner
    pub hostname: Option<String>,

    /// Iroh relay URL for P2P connectivity
    pub relay_url: Option<String>,

    /// P2P bind port (UDP)
    #[serde(default = "default_p2p_port")]
    pub p2p_port: u16,

    /// Specific IPv4 address to bind the P2P endpoint to.
    /// When set, iroh only advertises this address instead of scanning all
    /// interfaces. Required when Docker is installed on the host (to avoid
    /// advertising the docker0 bridge IP).
    ///
    /// Override: `P2P_BIND_IPV4` env var.
    pub bind_ipv4: Option<String>,

    /// Specific IPv6 address to bind the P2P endpoint to.
    ///
    /// Override: `P2P_BIND_IPV6` env var.
    pub bind_ipv6: Option<String>,

    /// Family ID for CRUSH placement grouping
    #[serde(default = "default_family_id")]
    pub family_id: String,

    /// Automatically detect public IP via STUN for hostname and bind
    /// address configuration. When enabled, the miner queries STUN
    /// servers at startup to discover its public IP. The detected IP
    /// is used as a fallback when hostname/bind_ipv4/bind_ipv6 are
    /// not explicitly configured. Manual overrides always win.
    ///
    /// Override: `STUN_ENABLED` env var (`true`/`false`/`0`/`1`).
    #[serde(default = "default_auto_detect_ip")]
    pub auto_detect_ip: bool,
}

impl Default for NetworkConfig {
    fn default() -> Self {
        Self {
            hostname: None,
            relay_url: None,
            p2p_port: default_p2p_port(),
            bind_ipv4: None,
            bind_ipv6: None,
            family_id: default_family_id(),
            auto_detect_ip: default_auto_detect_ip(),
        }
    }
}

fn default_p2p_port() -> u16 {
    11220
}
fn default_family_id() -> String {
    "default".to_string()
}
fn default_auto_detect_ip() -> bool {
    true
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

        // Environment variable overrides (network)
        env_parse("P2P_PORT", &mut config.network.p2p_port);
        env_string_opt("HOSTNAME", &mut config.network.hostname);
        env_string_opt("IROH_RELAY_URL", &mut config.network.relay_url);
        env_trimmed_opt("P2P_BIND_IPV4", &mut config.network.bind_ipv4);
        env_trimmed_opt("P2P_BIND_IPV6", &mut config.network.bind_ipv6);
        if let Ok(val) = std::env::var("FAMILY_ID") {
            config.network.family_id = val;
        }
        if let Ok(val) = std::env::var("STUN_ENABLED") {
            config.network.auto_detect_ip = val != "0" && val.to_lowercase() != "false";
        }

        // Storage overrides
        if let Ok(val) = std::env::var("STORAGE_PATH") {
            config.storage.path = val;
        }
        env_parse("MAX_STORAGE_GB", &mut config.storage.max_storage_gb);

        // Validator overrides
        env_string_opt("VALIDATOR_NODE_ID", &mut config.validator.node_id);
        env_string_opt("WARDEN_NODE_ID", &mut config.validator.warden_node_id);

        // Tuning overrides
        env_parse(
            "MINER_STORE_CONCURRENCY",
            &mut config.tuning.store_concurrency,
        );
        env_parse(
            "MINER_PULL_CONCURRENCY",
            &mut config.tuning.pull_concurrency,
        );
        env_parse(
            "MINER_FETCH_CONCURRENCY",
            &mut config.tuning.fetch_concurrency,
        );
        env_parse(
            "MINER_REBALANCE_TICK_SECS",
            &mut config.tuning.rebalance_tick_secs,
        );
        env_parse(
            "P2P_DIRECT_WAIT_SECS",
            &mut config.tuning.p2p_direct_wait_secs,
        );
        if let Ok(val) = std::env::var("MINER_REBALANCE_ENABLED") {
            config.tuning.rebalance_enabled = val != "0" && val.to_lowercase() != "false";
        }

        Ok(config)
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
    /// Max seconds to wait for a direct P2P connection to the validator
    /// before each registration attempt. Iroh hole-punches during this
    /// window. If direct is not achieved, registration is skipped and
    /// retried with backoff. Default: 30.
    /// Override: P2P_DIRECT_WAIT_SECS env var.
    #[serde(default = "default_p2p_direct_wait_secs")]
    pub p2p_direct_wait_secs: u64,
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
            p2p_direct_wait_secs: default_p2p_direct_wait_secs(),
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
fn default_p2p_direct_wait_secs() -> u64 {
    30
}

#[cfg(test)]
mod tests {
    use super::*;

    // SAFETY: `set_var`/`remove_var` are unsafe in Rust 2024 edition because
    // concurrent env modification is UB. Each test uses a unique prefixed
    // name (`_MTEST_*`) so no two tests touch the same variable, making
    // concurrent execution safe regardless of thread count.

    #[test]
    fn env_parse_valid_u16() {
        let mut val: u16 = 0;
        unsafe { std::env::set_var("_MTEST_PARSE_U16", "8080") };
        env_parse("_MTEST_PARSE_U16", &mut val);
        assert_eq!(val, 8080);
        unsafe { std::env::remove_var("_MTEST_PARSE_U16") };
    }

    #[test]
    fn env_parse_invalid_leaves_default() {
        let mut val: u16 = 42;
        unsafe { std::env::set_var("_MTEST_PARSE_INV", "not_a_number") };
        env_parse("_MTEST_PARSE_INV", &mut val);
        assert_eq!(val, 42);
        unsafe { std::env::remove_var("_MTEST_PARSE_INV") };
    }

    #[test]
    fn env_parse_missing_leaves_default() {
        let mut val: u16 = 42;
        unsafe { std::env::remove_var("_MTEST_PARSE_MISS") };
        env_parse("_MTEST_PARSE_MISS", &mut val);
        assert_eq!(val, 42);
    }

    #[test]
    fn env_string_opt_sets_value() {
        let mut val: Option<String> = None;
        unsafe { std::env::set_var("_MTEST_STRING_OPT", "hello") };
        env_string_opt("_MTEST_STRING_OPT", &mut val);
        assert_eq!(val.as_deref(), Some("hello"));
        unsafe { std::env::remove_var("_MTEST_STRING_OPT") };
    }

    #[test]
    fn env_trimmed_opt_trims_and_skips_empty() {
        let mut val: Option<String> = None;

        unsafe { std::env::set_var("_MTEST_TRIM", "  10.0.0.1  ") };
        env_trimmed_opt("_MTEST_TRIM", &mut val);
        assert_eq!(val.as_deref(), Some("10.0.0.1"));

        val = None;
        unsafe { std::env::set_var("_MTEST_TRIM", "   ") };
        env_trimmed_opt("_MTEST_TRIM", &mut val);
        assert_eq!(val, None);

        unsafe { std::env::remove_var("_MTEST_TRIM") };
    }

    #[test]
    fn default_config_has_sane_values() {
        let config = MinerConfig::default();
        assert_eq!(config.network.p2p_port, 11220);
        assert_eq!(config.network.family_id, "default");
        assert_eq!(config.tuning.store_concurrency, 1024);
        assert_eq!(config.tuning.fetch_concurrency, 256);
        assert_eq!(config.tuning.rebalance_tick_secs, 300);
        assert!(config.tuning.rebalance_enabled);
    }
}

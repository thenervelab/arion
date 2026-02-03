//! Configuration loading for the Warden service.

use serde::Deserialize;
use std::net::SocketAddr;
use std::path::PathBuf;

/// Warden configuration loaded from TOML + environment overrides.
#[derive(Debug, Clone, Deserialize)]
pub struct WardenConfig {
    /// Data directory for warden state (keypairs, node_id, etc.)
    #[serde(default = "default_data_dir")]
    pub data_dir: PathBuf,

    /// Ed25519 keypair path for signing attestations
    #[serde(default = "default_keypair_path")]
    pub keypair_path: PathBuf,

    /// Sled database path for persistent shard storage
    #[serde(default = "default_db_path")]
    pub db_path: PathBuf,

    /// HTTP listen address for API (validator push, health, metrics)
    #[serde(default = "default_listen_addr")]
    pub listen_addr: SocketAddr,

    /// Chain submitter endpoint for attestation submission
    #[serde(default = "default_chain_submitter_url")]
    pub chain_submitter_url: String,

    /// Whether to skip TLS certificate verification for chain-submitter
    /// Set to true only in development with self-signed certificates
    #[serde(default)]
    pub chain_submitter_insecure_tls: bool,

    /// Audit interval in seconds
    #[serde(default = "default_audit_interval_secs")]
    pub audit_interval_secs: u64,

    /// Number of shards to audit per interval
    #[serde(default = "default_shards_per_audit")]
    pub shards_per_audit: usize,

    /// Challenge timeout in seconds
    #[serde(default = "default_challenge_timeout_secs")]
    pub challenge_timeout_secs: u64,

    /// Number of chunk indices per challenge
    #[serde(default = "default_chunks_per_challenge")]
    pub chunks_per_challenge: usize,

    /// Maximum number of shards to track (prevents memory exhaustion)
    /// Reduced from 100k to 5k for epoch-based sampling model
    #[serde(default = "default_max_shards")]
    pub max_shards: usize,

    /// Maximum number of pending challenges (prevents memory exhaustion)
    #[serde(default = "default_max_pending_challenges")]
    pub max_pending_challenges: usize,

    /// Audit epoch duration in seconds (default: 3600 = 1 hour).
    /// Shards are cleared and re-sampled at epoch boundaries.
    #[serde(default = "default_audit_epoch_secs")]
    pub audit_epoch_secs: u64,

    /// Optional validator URL for pushing audit results (reputation system)
    #[serde(default)]
    pub validator_url: Option<String>,

    /// Optional API key for validator authentication
    #[serde(default)]
    pub validator_api_key: Option<String>,

    /// Whether to skip TLS certificate verification for validator
    /// Set to true only in development with self-signed certificates
    #[serde(default)]
    pub validator_insecure_tls: bool,

    /// Validator's Iroh node ID for P2P authorization
    /// Only connections from this node ID will be accepted for shard commitments
    #[serde(default)]
    pub validator_node_id: Option<String>,
}

fn default_data_dir() -> PathBuf {
    PathBuf::from("data/warden")
}

fn default_keypair_path() -> PathBuf {
    PathBuf::from("data/warden/keypair.bin")
}

fn default_db_path() -> PathBuf {
    PathBuf::from("data/warden/shards.db")
}

fn default_listen_addr() -> SocketAddr {
    "0.0.0.0:3003".parse().unwrap()
}

fn default_chain_submitter_url() -> String {
    "http://localhost:3004".to_string()
}

fn default_audit_interval_secs() -> u64 {
    30
}

fn default_shards_per_audit() -> usize {
    10
}

fn default_challenge_timeout_secs() -> u64 {
    60
}

fn default_chunks_per_challenge() -> usize {
    4
}

fn default_max_shards() -> usize {
    5_000 // Reduced for epoch-based sampling (100 shards * ~50 miners = 5000 max per epoch)
}

fn default_audit_epoch_secs() -> u64 {
    common::DEFAULT_AUDIT_EPOCH_SECS
}

fn default_max_pending_challenges() -> usize {
    10_000
}

impl Default for WardenConfig {
    fn default() -> Self {
        Self {
            data_dir: default_data_dir(),
            keypair_path: default_keypair_path(),
            db_path: default_db_path(),
            listen_addr: default_listen_addr(),
            chain_submitter_url: default_chain_submitter_url(),
            chain_submitter_insecure_tls: false,
            audit_interval_secs: default_audit_interval_secs(),
            shards_per_audit: default_shards_per_audit(),
            challenge_timeout_secs: default_challenge_timeout_secs(),
            chunks_per_challenge: default_chunks_per_challenge(),
            max_shards: default_max_shards(),
            max_pending_challenges: default_max_pending_challenges(),
            audit_epoch_secs: default_audit_epoch_secs(),
            validator_url: None,
            validator_api_key: None,
            validator_insecure_tls: false,
            validator_node_id: None,
        }
    }
}

/// Load configuration from TOML file with environment variable overrides.
pub fn load_config(path: Option<&str>) -> anyhow::Result<WardenConfig> {
    let config_path = path.map(std::path::Path::new).or_else(|| {
        let default = std::path::Path::new("warden.toml");
        default.exists().then_some(default)
    });

    let config = match config_path {
        Some(p) => toml::from_str(&std::fs::read_to_string(p)?)?,
        None => WardenConfig::default(),
    };

    Ok(apply_env_overrides(config))
}

/// Read an env var and parse it, returning None if missing or parse fails.
fn env_parse<T: std::str::FromStr>(key: &str) -> Option<T> {
    std::env::var(key).ok().and_then(|v| v.parse().ok())
}

fn apply_env_overrides(mut config: WardenConfig) -> WardenConfig {
    if let Ok(val) = std::env::var("WARDEN_DATA_DIR") {
        config.data_dir = PathBuf::from(val);
    }
    if let Ok(val) = std::env::var("WARDEN_KEYPAIR_PATH") {
        config.keypair_path = PathBuf::from(val);
    }
    if let Ok(val) = std::env::var("WARDEN_DB_PATH") {
        config.db_path = PathBuf::from(val);
    }
    if let Some(addr) = env_parse("WARDEN_LISTEN_ADDR") {
        config.listen_addr = addr;
    }
    if let Ok(val) = std::env::var("CHAIN_SUBMITTER_URL") {
        config.chain_submitter_url = val;
    }
    if let Ok(val) = std::env::var("CHAIN_SUBMITTER_INSECURE_TLS") {
        config.chain_submitter_insecure_tls = val == "true" || val == "1";
    }
    if let Some(v) = env_parse("WARDEN_AUDIT_INTERVAL_SECS") {
        config.audit_interval_secs = v;
    }
    if let Some(v) = env_parse("WARDEN_SHARDS_PER_AUDIT") {
        config.shards_per_audit = v;
    }
    if let Some(v) = env_parse("WARDEN_CHALLENGE_TIMEOUT_SECS") {
        config.challenge_timeout_secs = v;
    }
    if let Some(v) = env_parse("WARDEN_CHUNKS_PER_CHALLENGE") {
        config.chunks_per_challenge = v;
    }
    if let Some(v) = env_parse("WARDEN_MAX_SHARDS") {
        config.max_shards = v;
    }
    if let Some(v) = env_parse("WARDEN_MAX_PENDING_CHALLENGES") {
        config.max_pending_challenges = v;
    }
    if let Some(v) = env_parse("AUDIT_EPOCH_SECS") {
        config.audit_epoch_secs = v;
    }
    if let Ok(val) = std::env::var("WARDEN_VALIDATOR_URL") {
        if !val.trim().is_empty() {
            config.validator_url = Some(val);
        }
    }
    if let Ok(val) = std::env::var("WARDEN_VALIDATOR_API_KEY") {
        if !val.trim().is_empty() {
            config.validator_api_key = Some(val);
        }
    }
    if let Ok(val) = std::env::var("WARDEN_VALIDATOR_INSECURE_TLS") {
        config.validator_insecure_tls = val == "true" || val == "1";
    }
    if let Ok(val) = std::env::var("WARDEN_VALIDATOR_NODE_ID") {
        if !val.trim().is_empty() {
            config.validator_node_id = Some(val);
        }
    }
    config
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_default_config() {
        let config = WardenConfig::default();
        assert_eq!(config.audit_interval_secs, 30);
        assert_eq!(config.shards_per_audit, 10);
        assert_eq!(config.challenge_timeout_secs, 60);
    }
}

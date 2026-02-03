//! Chain Submitter - bridges off-chain validator state to the Hippius blockchain.
//!
//! This daemon polls the validator's HTTP API and submits four types of transactions
//! to the `pallet-arion` runtime:
//!
//! 1. **CRUSH Map** (`submit_crush_map`): Cluster topology with miner endpoints and weights
//! 2. **Miner Stats** (`submit_miner_stats`): Per-miner shard counts and bandwidth
//! 3. **Node Quality** (`submit_node_quality`): Uptime and reliability metrics for rewards
//! 4. **Attestations** (`submit_attestations`): Warden proof-of-storage verification results
//!
//! # Architecture
//!
//! ```text
//! Validator HTTP API ──► Chain Submitter ──► Substrate RPC ──► pallet-arion
//!      /map                   │                  │
//!      /network-stats         │                  ▼
//!                             │            On-chain state:
//! Warden ─────────────────────┤            - CurrentEpoch
//!   POST /attestations        │            - CrushMap
//!                             │            - MinerStats
//!                             └────────────► NodeIdToChild lookup
//! ```
//!
//! # Bucket System
//!
//! Miner stats and node quality are grouped into "buckets" based on block height:
//! `bucket = best_block / bucket_blocks` (default: 300 blocks per bucket).
//! This aggregates metrics over time windows and prevents duplicate submissions.
//!
//! # HTTP Server
//!
//! The chain-submitter runs an HTTP server (default port 3004) to receive attestations
//! from the warden service:
//! - `POST /attestations` - Queue a signed attestation for on-chain submission
//! - `GET /health` - Health check with queue status
//!
//! # Required Permissions
//!
//! The submitter account needs:
//! - `MapAuthorityOrigin`: For `submit_crush_map` calls
//! - `StatsAuthorityOrigin`: For `submit_miner_stats` and `submit_node_quality` calls
//! - `AttestationAuthorityOrigin`: For `submit_attestations` calls (when pallet ready)
//! - Sufficient balance for transaction fees

mod attestation;
mod p2p_server;
mod validator_p2p;

use anyhow::{Context, Result, anyhow};
use attestation::SignedAttestation;
use axum::{
    Router,
    extract::Json,
    http::{HeaderMap, StatusCode},
    response::IntoResponse,
    routing::{get, post},
};
use clap::Parser;
use common::{ClusterMap, EpochAttestationCommitment, now_secs};
use dashmap::DashMap;
use serde::{Deserialize, Serialize};
use std::net::SocketAddr;
use std::str::FromStr;
use std::sync::atomic::AtomicU64;
use std::sync::{Arc, OnceLock};
use std::time::Duration;
use subxt::{OnlineClient, config::PolkadotConfig, dynamic};
use subxt_signer::sr25519::Keypair;
use tokio::net::TcpListener;
use tokio::sync::RwLock;
use tokio::time::timeout;
use tracing::{debug, error, info, warn};
use validator_p2p::ValidatorP2pClient;

/// Cached validator API key (loaded once from VALIDATOR_ADMIN_API_KEY env var).
static VALIDATOR_API_KEY: OnceLock<Option<String>> = OnceLock::new();

/// Cached Arion API key (loaded once from ARION_API_KEY env var).
static ARION_API_KEY: OnceLock<String> = OnceLock::new();

/// Attestation queue (lock-free, shared between HTTP handler and main loop).
/// Key: dedup_key (shard_hash:challenge_seed_hex)
/// Value: (SignedAttestation, retry_count)
static ATTESTATION_QUEUE: OnceLock<DashMap<String, (SignedAttestation, u8)>> = OnceLock::new();

/// Last successful attestation submission timestamp.
static LAST_ATTESTATION_SUBMISSION: OnceLock<AtomicU64> = OnceLock::new();

/// Default API key (logs warning if used in production).
const DEFAULT_API_KEY: &str = "Hippius-Arion-Dev-01";

/// Maximum retries for failed attestation submissions.
const MAX_ATTESTATION_RETRIES: u8 = 3;

/// Maximum size of the attestation queue to prevent memory exhaustion.
/// When the queue is full, new attestations are rejected with "queue_full" status.
const MAX_ATTESTATION_QUEUE_SIZE: usize = 10_000;

/// Cached cluster map to avoid redundant fetches when epoch hasn't changed.
/// The cluster map only changes on epoch boundaries, so we can cache it.
static CACHED_CLUSTER_MAP: OnceLock<RwLock<Option<ClusterMap>>> = OnceLock::new();

/// Get the cluster map cache, initializing if needed.
fn cluster_map_cache() -> &'static RwLock<Option<ClusterMap>> {
    CACHED_CLUSTER_MAP.get_or_init(|| RwLock::new(None))
}

/// Get the attestation queue, initializing if needed.
fn attestation_queue() -> &'static DashMap<String, (SignedAttestation, u8)> {
    ATTESTATION_QUEUE.get_or_init(DashMap::new)
}

/// Get the Arion API key, loading from env var on first call.
fn get_arion_api_key() -> &'static str {
    ARION_API_KEY.get_or_init(|| {
        std::env::var("ARION_API_KEY")
            .ok()
            .filter(|k| !k.trim().is_empty())
            .map(|k| k.trim().to_string())
            .unwrap_or_else(|| {
                warn!(
                    "ARION_API_KEY not set, using default '{}' - this is insecure for production!",
                    DEFAULT_API_KEY
                );
                DEFAULT_API_KEY.to_string()
            })
    })
}

/// Get the last attestation submission timestamp.
fn last_attestation_submission() -> &'static AtomicU64 {
    LAST_ATTESTATION_SUBMISSION.get_or_init(|| AtomicU64::new(0))
}

/// Keywords indicating a connection error that requires reconnection.
const CONNECTION_ERROR_KEYWORDS: &[&str] = &[
    "connection",
    "websocket",
    "transport",
    "disconnected",
    "closed",
    "rpc error",
];

/// Checks if an error message indicates a connection issue requiring reconnection.
fn is_connection_error(err: &anyhow::Error) -> bool {
    let err_str = err.to_string().to_lowercase();
    CONNECTION_ERROR_KEYWORDS
        .iter()
        .any(|kw| err_str.contains(kw))
}

/// Attempts to reconnect to the blockchain with a 30-second timeout.
/// Returns the new client and optionally a re-detected pallet name.
async fn try_reconnect(
    chain_ws_url: &str,
    explicit_pallet_name: &str,
) -> Option<(OnlineClient<PolkadotConfig>, Option<String>)> {
    const RECONNECT_TIMEOUT: Duration = Duration::from_secs(30);

    match timeout(
        RECONNECT_TIMEOUT,
        OnlineClient::<PolkadotConfig>::from_url(chain_ws_url),
    )
    .await
    {
        Ok(Ok(new_client)) => {
            info!("Reconnected to blockchain");
            let new_pallet = if explicit_pallet_name.trim().is_empty() {
                match detect_arion_pallet_name(&new_client) {
                    Ok(name) => {
                        info!("Re-detected arion pallet name: {}", name);
                        Some(name)
                    }
                    Err(e) => {
                        error!(error = %e, "Failed to re-detect pallet name after reconnect");
                        None
                    }
                }
            } else {
                None
            };
            Some((new_client, new_pallet))
        }
        Ok(Err(e)) => {
            error!(error = %e, "Failed to reconnect to blockchain");
            None
        }
        Err(_) => {
            error!(
                "Reconnection attempt timed out after {}s",
                RECONNECT_TIMEOUT.as_secs()
            );
            None
        }
    }
}

// ============================================================================
// Constants
// ============================================================================

/// Timeout for blockchain transaction submission and finalization.
/// Set to 2 minutes to account for block production delays and network latency.
const TX_TIMEOUT: Duration = Duration::from_secs(120);

// ============================================================================
// Transaction Submission Helper
// ============================================================================

/// Signs, submits, and waits for a transaction to be finalized.
///
/// This helper encapsulates the common pattern of:
/// 1. Submit transaction with timeout
/// 2. Wait for finalization with timeout
/// 3. Return appropriate errors with context
async fn submit_and_finalize(
    client: &OnlineClient<PolkadotConfig>,
    signer: &Keypair,
    tx: subxt::tx::DynamicPayload,
    tx_name: &str,
) -> Result<()> {
    let tx_progress = match timeout(
        TX_TIMEOUT,
        client.tx().sign_and_submit_then_watch_default(&tx, signer),
    )
    .await
    {
        Ok(Ok(progress)) => progress,
        Ok(Err(e)) => return Err(anyhow!("{} transaction rejected: {}", tx_name, e)),
        Err(_) => return Err(anyhow!("{} transaction submission timed out", tx_name)),
    };

    match timeout(TX_TIMEOUT, tx_progress.wait_for_finalized_success()).await {
        Ok(Ok(_)) => Ok(()),
        Ok(Err(e)) => Err(anyhow!("{} extrinsic failed: {}", tx_name, e)),
        Err(_) => Err(anyhow!("{} transaction finalization timed out", tx_name)),
    }
}

// ============================================================================
// CLI Configuration
// ============================================================================

/// Command-line arguments and environment variables for the chain submitter.
#[derive(Parser, Debug, Clone)]
#[command(author, version, about)]
struct Args {
    /// Substrate WS URL (required)
    #[arg(long, env = "CHAIN_WS_URL")]
    chain_ws_url: String,

    /// Validator HTTP URL (e.g. http://127.0.0.1:3002)
    #[arg(long, env = "VALIDATOR_HTTP_URL")]
    validator_http_url: String,

    /// Mnemonic phrase for the whitelisted submitter account (prefer env var SUBMITTER_MNEMONIC)
    #[arg(long, env = "SUBMITTER_MNEMONIC", hide_env_values = true)]
    submitter_mnemonic: String,

    /// Optional: override pallet name if auto-detect fails
    #[arg(long, env = "ARION_PALLET_NAME", default_value = "")]
    arion_pallet_name: String,

    /// Poll interval seconds
    #[arg(long, env = "SUBMITTER_POLL_SECS", default_value_t = 6)]
    poll_secs: u64,

    /// Bucket size in blocks (bucket = best_block / bucket_blocks)
    #[arg(long, env = "SUBMITTER_BUCKET_BLOCKS", default_value_t = 300)]
    bucket_blocks: u32,

    /// Miner is considered offline if last_seen is older than this (seconds)
    #[arg(long, env = "SUBMITTER_UPTIME_OFFLINE_SECS", default_value_t = 120)]
    uptime_offline_secs: u64,

    #[arg(long, env = "SUBMITTER_ENABLE_CRUSH_MAP", default_value_t = true)]
    enable_crush_map: bool,

    #[arg(long, env = "SUBMITTER_ENABLE_MINER_STATS", default_value_t = true)]
    enable_miner_stats: bool,

    #[arg(long, env = "SUBMITTER_ENABLE_NODE_QUALITY", default_value_t = true)]
    enable_node_quality: bool,

    #[arg(long, env = "SUBMITTER_MAX_ENDPOINT_BYTES", default_value_t = 256)]
    max_endpoint_bytes: usize,

    #[arg(long, env = "SUBMITTER_MAX_HTTP_ADDR_BYTES", default_value_t = 128)]
    max_http_addr_bytes: usize,

    // --- Attestation submission settings ---
    /// HTTP server port for receiving attestations from warden
    #[arg(long, env = "SUBMITTER_HTTP_PORT", default_value_t = 3004)]
    http_port: u16,

    /// Enable attestation submission from warden
    #[arg(long, env = "SUBMITTER_ENABLE_ATTESTATIONS", default_value_t = true)]
    enable_attestations: bool,

    /// Maximum attestations to submit per extrinsic
    #[arg(long, env = "SUBMITTER_ATTESTATION_BATCH_SIZE", default_value_t = 100)]
    attestation_batch_size: usize,

    /// Log attestations instead of submitting (until pallet ready)
    #[arg(long, env = "SUBMITTER_ATTESTATION_DRY_RUN", default_value_t = false)]
    attestation_dry_run: bool,

    // --- P2P Configuration ---
    /// Validator's Iroh node ID for P2P communication (preferred over HTTP)
    #[arg(long, env = "VALIDATOR_NODE_ID")]
    validator_node_id: Option<String>,

    /// Enable P2P communication with validator
    #[arg(long, env = "USE_P2P", default_value_t = true)]
    use_p2p: bool,

    /// Fall back to HTTP if P2P fails
    #[arg(long, env = "HTTP_FALLBACK", default_value_t = true)]
    http_fallback: bool,

    // --- P2P Server Configuration ---
    /// Enable P2P server for receiving attestation commitments from validator
    #[arg(long, env = "SUBMITTER_P2P_SERVER_ENABLED", default_value_t = true)]
    p2p_server_enabled: bool,

    /// Authorized validator node IDs for P2P server (comma-separated, empty = allow all)
    #[arg(long, env = "P2P_AUTHORIZED_VALIDATORS")]
    p2p_authorized_validators: Option<String>,

    // --- Attestation Commitment Settings ---
    /// Enable attestation commitment submission (separate from individual attestations)
    #[arg(
        long,
        env = "SUBMITTER_ENABLE_ATTESTATION_COMMITMENTS",
        default_value_t = true
    )]
    enable_attestation_commitments: bool,

    /// Log attestation commitments instead of submitting (until pallet ready)
    #[arg(
        long,
        env = "SUBMITTER_ATTESTATION_COMMITMENT_DRY_RUN",
        default_value_t = false
    )]
    attestation_commitment_dry_run: bool,
}

// ============================================================================
// API Response Types
// ============================================================================

/// Response from the validator's `/network-stats` endpoint.
///
/// Contains aggregated network statistics and per-miner metrics for on-chain submission.
#[derive(Debug, Deserialize)]
struct NetworkStatsResponse {
    /// Total files stored across all miners
    total_files: usize,
    /// Total shard blobs stored (files × shards per file)
    total_blobs: usize,
    /// Total bytes stored across all shards
    total_storage: u64,
    /// Per-miner stats: uid (string) → [shard_count, shard_bytes]
    miner_stats: std::collections::HashMap<String, [u64; 2]>,
    /// Per-miner bandwidth: uid (string) → bytes served
    bandwidth_stats: std::collections::HashMap<String, u64>,
}

// ============================================================================
// HTTP Server (Attestation Endpoint)
// ============================================================================

/// Response for attestation endpoint.
#[derive(Serialize)]
struct AttestationResponse {
    status: &'static str,
    #[serde(skip_serializing_if = "Option::is_none")]
    message: Option<String>,
}

/// Response for health endpoint.
#[derive(Serialize)]
struct HealthResponse {
    status: &'static str,
    version: &'static str,
    queue_size: usize,
    last_submission: u64,
}

/// Starts the HTTP server for receiving attestations from warden.
///
/// The server runs on the specified port and provides:
/// - `POST /attestations` - Queue a signed attestation
/// - `GET /health` - Health check with queue status
fn start_http_server(port: u16) -> tokio::task::JoinHandle<()> {
    let app = Router::new()
        .route("/attestations", post(handle_post_attestation))
        .route("/health", get(handle_health));

    tokio::spawn(async move {
        let addr = SocketAddr::from(([0, 0, 0, 0], port));
        info!("Starting HTTP server on {}", addr);

        match TcpListener::bind(addr).await {
            Ok(listener) => {
                if let Err(e) = axum::serve(listener, app).await {
                    error!(error = %e, "HTTP server error");
                }
            }
            Err(e) => {
                error!(error = %e, port = port, "Failed to bind HTTP server");
            }
        }
    })
}

/// Handler for POST /attestations endpoint.
///
/// Accepts a SignedAttestation from warden, verifies the signature,
/// and queues it for on-chain submission.
///
/// # Authentication
/// Requires `X-API-Key` header matching `ARION_API_KEY` env var.
///
/// # Returns
/// - 200 OK: Attestation queued successfully
/// - 400 Bad Request: Invalid signature or malformed data
/// - 401 Unauthorized: Invalid or missing API key
async fn handle_post_attestation(
    headers: HeaderMap,
    Json(attestation): Json<SignedAttestation>,
) -> impl IntoResponse {
    // Check API key
    let expected_key = get_arion_api_key();
    let provided_key = headers
        .get("X-API-Key")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("");

    if provided_key != expected_key {
        warn!("Attestation rejected: invalid API key");
        return (
            StatusCode::UNAUTHORIZED,
            Json(AttestationResponse {
                status: "error",
                message: Some("Invalid API key".to_string()),
            }),
        );
    }

    // Verify signature
    if !attestation.verify() {
        warn!(
            shard_hash = %attestation.attestation.shard_hash,
            miner_uid = attestation.attestation.miner_uid,
            "Attestation rejected: invalid signature"
        );
        return (
            StatusCode::BAD_REQUEST,
            Json(AttestationResponse {
                status: "error",
                message: Some("Invalid signature".to_string()),
            }),
        );
    }

    // Queue attestation
    let dedup_key = attestation.dedup_key();
    let queue = attestation_queue();

    // Check if queue is full (prevent memory exhaustion)
    if queue.len() >= MAX_ATTESTATION_QUEUE_SIZE {
        warn!(
            queue_size = queue.len(),
            max_size = MAX_ATTESTATION_QUEUE_SIZE,
            "Attestation queue full, rejecting new attestation"
        );
        return (
            StatusCode::SERVICE_UNAVAILABLE,
            Json(AttestationResponse {
                status: "queue_full",
                message: Some(format!(
                    "Queue is full ({} attestations). Try again later.",
                    MAX_ATTESTATION_QUEUE_SIZE
                )),
            }),
        );
    }

    // Check if already queued (deduplication)
    if queue.contains_key(&dedup_key) {
        debug!(
            dedup_key = %dedup_key,
            "Attestation already queued, ignoring duplicate"
        );
        return (
            StatusCode::OK,
            Json(AttestationResponse {
                status: "already_queued",
                message: None,
            }),
        );
    }

    queue.insert(dedup_key.clone(), (attestation.clone(), 0));

    info!(
        shard_hash = %attestation.attestation.shard_hash,
        miner_uid = attestation.attestation.miner_uid,
        result = ?attestation.attestation.result,
        queue_size = queue.len(),
        "Attestation queued for submission"
    );

    (
        StatusCode::OK,
        Json(AttestationResponse {
            status: "queued",
            message: None,
        }),
    )
}

/// Handler for GET /health endpoint.
///
/// Returns health status including attestation queue size and last submission time.
async fn handle_health() -> impl IntoResponse {
    let queue_size = attestation_queue().len();
    let last_submission = last_attestation_submission().load(std::sync::atomic::Ordering::Relaxed);

    Json(HealthResponse {
        status: "ok",
        version: env!("CARGO_PKG_VERSION"),
        queue_size,
        last_submission,
    })
}

// ============================================================================
// Encoding Helpers
// ============================================================================

/// Converts a 32-byte array to a SCALE-compatible dynamic value.
/// Used for AccountId and NodeId encoding in transaction payloads.
fn bytes32_value(bytes: [u8; 32]) -> dynamic::Value {
    dynamic::Value::from_bytes(bytes)
}

/// Truncates a byte vector to the specified maximum length.
/// Used to respect on-chain BoundedVec limits for endpoints and addresses.
fn bytes_truncated(mut v: Vec<u8>, max_len: usize) -> Vec<u8> {
    v.truncate(max_len);
    v
}

// ============================================================================
// Validator API Fetching
// ============================================================================

/// Gets the cached validator API key, loading from env var on first call.
fn get_validator_api_key() -> Option<&'static str> {
    VALIDATOR_API_KEY
        .get_or_init(|| {
            std::env::var("VALIDATOR_ADMIN_API_KEY")
                .ok()
                .filter(|k| !k.trim().is_empty())
                .map(|k| k.trim().to_string())
        })
        .as_deref()
}

/// Adds authentication header if `VALIDATOR_ADMIN_API_KEY` environment variable is set.
fn add_auth_header(req: reqwest::RequestBuilder) -> reqwest::RequestBuilder {
    match get_validator_api_key() {
        Some(key) => req.header("Authorization", format!("Bearer {key}")),
        None => req,
    }
}

/// Fetches JSON from a validator endpoint with optional authentication.
async fn fetch_validator_json<T: serde::de::DeserializeOwned>(
    http: &reqwest::Client,
    base: &str,
    endpoint: &str,
) -> Result<T> {
    let url = format!("{}/{}", base.trim_end_matches('/'), endpoint);
    let req = add_auth_header(http.get(url));
    let res = req.send().await?.error_for_status()?;
    Ok(res.json::<T>().await?)
}

/// Fetches the current cluster map from the validator via P2P (preferred) or HTTP.
async fn fetch_cluster_map(
    http: &reqwest::Client,
    base: &str,
    p2p_client: &Option<std::sync::Arc<ValidatorP2pClient>>,
    http_fallback: bool,
) -> Result<ClusterMap> {
    // Try P2P first if available
    if let Some(p2p) = p2p_client {
        match p2p.get_cluster_map().await {
            Ok(map) => {
                debug!("Fetched cluster map via P2P");
                return Ok(map);
            }
            Err(e) => {
                if http_fallback {
                    debug!(error = %e, "P2P cluster map fetch failed, falling back to HTTP");
                } else {
                    return Err(e);
                }
            }
        }
    }

    // HTTP fallback
    fetch_validator_json(http, base, "map").await
}

/// Fetches network statistics from the validator via P2P (preferred) or HTTP.
async fn fetch_network_stats(
    http: &reqwest::Client,
    base: &str,
    p2p_client: &Option<std::sync::Arc<ValidatorP2pClient>>,
    http_fallback: bool,
) -> Result<NetworkStatsResponse> {
    // Try P2P first if available
    if let Some(p2p) = p2p_client {
        match p2p.get_network_stats().await {
            Ok(stats) => {
                debug!("Fetched network stats via P2P");
                // Compute totals from miner_stats: [blob_count, storage_bytes]
                let total_blobs: usize =
                    stats.miner_stats.values().map(|arr| arr[0] as usize).sum();
                let total_storage: u64 = stats.miner_stats.values().map(|arr| arr[1]).sum();
                // Convert P2P response to NetworkStatsResponse
                return Ok(NetworkStatsResponse {
                    total_files: stats.total_files,
                    total_blobs,
                    total_storage,
                    miner_stats: stats.miner_stats,
                    bandwidth_stats: stats.bandwidth_stats,
                });
            }
            Err(e) => {
                if http_fallback {
                    debug!(error = %e, "P2P network stats fetch failed, falling back to HTTP");
                } else {
                    return Err(e);
                }
            }
        }
    }

    // HTTP fallback
    fetch_validator_json(http, base, "network-stats").await
}

/// Create an Iroh endpoint for P2P communication.
async fn create_p2p_endpoint() -> Result<iroh::Endpoint> {
    let secret_key = iroh::SecretKey::generate(&mut rand::rng());

    let mut transport_config = iroh::endpoint::TransportConfig::default();
    transport_config.keep_alive_interval(Some(Duration::from_secs(15)));
    transport_config.max_idle_timeout(Some(
        Duration::from_secs(60)
            .try_into()
            .expect("valid idle timeout"),
    ));

    // Get relay URL from environment or use default
    let relay_url = common::get_relay_url(None);
    info!(relay_url = %relay_url, "Configuring relay");

    let endpoint = iroh::Endpoint::builder()
        .secret_key(secret_key)
        .transport_config(transport_config)
        .relay_mode(common::build_relay_mode(&relay_url))
        .bind()
        .await
        .context("Failed to bind Iroh endpoint")?;

    // Wait for relay connection
    info!(
        wait_secs = common::RELAY_CONNECTION_WAIT_SECS,
        "Waiting for relay connection"
    );
    tokio::time::sleep(Duration::from_secs(common::RELAY_CONNECTION_WAIT_SECS)).await;

    Ok(endpoint)
}

// ============================================================================
// Runtime Introspection
// ============================================================================

/// Auto-detects the arion pallet name from runtime metadata.
///
/// Searches for a pallet containing the `submit_node_quality` extrinsic.
/// Returns an error if zero or multiple pallets match (requires explicit config).
fn detect_arion_pallet_name(client: &OnlineClient<PolkadotConfig>) -> Result<String> {
    let candidates: Vec<_> = client
        .metadata()
        .pallets()
        .filter(|p| p.call_hash("submit_node_quality").is_some())
        .map(|p| p.name().to_string())
        .collect();

    match candidates.as_slice() {
        [] => Err(anyhow!(
            "No pallet with 'submit_node_quality' call found in runtime metadata"
        )),
        [single] => Ok(single.clone()),
        _ => Err(anyhow!(
            "Multiple pallets have 'submit_node_quality': {:?}. Specify pallet name explicitly via --arion-pallet-name or ARION_PALLET_NAME env var.",
            candidates
        )),
    }
}

#[tokio::main]
async fn main() -> Result<()> {
    dotenvy::dotenv().ok();
    tracing_subscriber::fmt()
        .with_env_filter(tracing_subscriber::EnvFilter::from_default_env())
        .init();

    let args = Args::parse();
    info!(
        version = env!("CARGO_PKG_VERSION"),
        "Starting chain-submitter"
    );

    let http = reqwest::Client::builder()
        .timeout(Duration::from_secs(30))
        .pool_max_idle_per_host(5)
        .pool_idle_timeout(Duration::from_secs(60))
        .build()?;

    info!("Connecting to chain WS: {}", args.chain_ws_url);
    let mut client = OnlineClient::<PolkadotConfig>::from_url(&args.chain_ws_url)
        .await
        .context("connect chain ws")?;

    let mut pallet_name = if args.arion_pallet_name.trim().is_empty() {
        detect_arion_pallet_name(&client)?
    } else {
        args.arion_pallet_name.clone()
    };
    info!("Using arion pallet name: {}", pallet_name);

    let mnemonic = bip39::Mnemonic::parse(&args.submitter_mnemonic)
        .map_err(|e| anyhow!("invalid mnemonic: {e}"))?;
    let signer =
        Keypair::from_phrase(&mnemonic, None).map_err(|e| anyhow!("invalid mnemonic: {e}"))?;

    let submitter_account = subxt::utils::AccountId32(signer.public_key().0);
    info!(account = ?submitter_account, "Submitter account configured");
    info!(
        "Account requirements: MapAuthorityOrigin, StatsAuthorityOrigin, sufficient balance for fees"
    );

    // Start HTTP server for attestation endpoint
    if args.enable_attestations {
        let _http_server = start_http_server(args.http_port);
        info!(
            port = args.http_port,
            batch_size = args.attestation_batch_size,
            dry_run = args.attestation_dry_run,
            "Attestation endpoint enabled"
        );
    }

    // Create shared storage for pending attestation commitments
    let pending_commitment_storage = Arc::new(RwLock::new(None::<EpochAttestationCommitment>));

    // Start P2P server for receiving attestation commitments from validator
    let _p2p_server_endpoint = if args.p2p_server_enabled && args.enable_attestation_commitments {
        // Parse authorized validators
        let authorized_validators: Vec<iroh::PublicKey> = args
            .p2p_authorized_validators
            .as_ref()
            .map(|s| {
                s.split(',')
                    .filter(|v| !v.trim().is_empty())
                    .filter_map(|v| {
                        v.trim().parse::<iroh::PublicKey>().ok().or_else(|| {
                            warn!(node_id = %v, "Failed to parse authorized validator node ID");
                            None
                        })
                    })
                    .collect()
            })
            .unwrap_or_default();

        match p2p_server::create_p2p_server(
            pending_commitment_storage.clone(),
            authorized_validators.clone(),
        )
        .await
        {
            Ok((endpoint, node_id)) => {
                info!(
                    node_id = %node_id,
                    authorized_count = authorized_validators.len(),
                    "P2P server started for attestation commitments"
                );
                Some(endpoint)
            }
            Err(e) => {
                warn!(error = %e, "Failed to start P2P server for attestation commitments");
                None
            }
        }
    } else {
        debug!("P2P server disabled or attestation commitments disabled");
        None
    };

    // Initialize P2P client for validator communication if configured
    let validator_p2p_client: Option<std::sync::Arc<ValidatorP2pClient>> = if args.use_p2p {
        if let Some(ref node_id_str) = args.validator_node_id {
            match node_id_str.parse::<iroh::PublicKey>() {
                Ok(node_id) => {
                    // Create an Iroh endpoint for P2P communication
                    match create_p2p_endpoint().await {
                        Ok(endpoint) => {
                            let client = ValidatorP2pClient::new(endpoint, node_id.clone());
                            info!(
                                validator_node_id = %node_id_str,
                                "Validator P2P client enabled"
                            );
                            Some(std::sync::Arc::new(client))
                        }
                        Err(e) => {
                            warn!(error = %e, "Failed to create P2P endpoint, using HTTP only");
                            None
                        }
                    }
                }
                Err(e) => {
                    warn!(error = %e, node_id = %node_id_str, "Failed to parse VALIDATOR_NODE_ID");
                    None
                }
            }
        } else {
            debug!("VALIDATOR_NODE_ID not set, using HTTP only");
            None
        }
    } else {
        debug!("P2P disabled, using HTTP only");
        None
    };

    let mut consecutive_failures = 0u32;
    loop {
        match tick(
            &args,
            &http,
            &client,
            &signer,
            &pallet_name,
            &validator_p2p_client,
            &pending_commitment_storage,
        )
        .await
        {
            Ok(()) => {
                consecutive_failures = 0;
            }
            Err(e) => {
                if is_connection_error(&e) {
                    warn!(error = %e, "Connection lost, attempting to reconnect...");
                    if let Some((new_client, new_pallet)) =
                        try_reconnect(&args.chain_ws_url, &args.arion_pallet_name).await
                    {
                        client = new_client;
                        if let Some(name) = new_pallet {
                            pallet_name = name;
                        }
                        // Reset failure count on successful reconnection
                        consecutive_failures = 0;
                        info!("Reconnection successful, resuming normal operation");
                        continue;
                    }
                }

                consecutive_failures = consecutive_failures.saturating_add(1);
                if consecutive_failures >= 10 {
                    error!(
                        consecutive_failures,
                        "CRITICAL: Chain submitter has failed {} consecutive times, check blockchain connection",
                        consecutive_failures
                    );
                }
                let backoff =
                    std::cmp::min(args.poll_secs * 2u64.pow(consecutive_failures.min(4)), 300);
                warn!(error = %e, backoff_secs = backoff, "tick failed, backing off");
                tokio::time::sleep(Duration::from_secs(backoff)).await;
                continue;
            }
        }
        tokio::time::sleep(Duration::from_secs(args.poll_secs)).await;
    }
}

// ============================================================================
// Main Polling Loop
// ============================================================================

/// Executes a single polling tick: fetch data from validator and submit to chain.
///
/// This function runs five independent submission flows:
/// 1. CRUSH map (if epoch changed)
/// 2. Attestation commitment (if pending and CRUSH map submitted)
/// 3. Miner stats (aggregated per-bucket)
/// 4. Node quality (uptime and reliability metrics)
/// 5. Attestations (proof-of-storage results from warden)
///
/// Each flow is executed independently - failures in one don't block others.
async fn tick(
    args: &Args,
    http: &reqwest::Client,
    client: &OnlineClient<PolkadotConfig>,
    signer: &Keypair,
    pallet_name: &str,
    p2p_client: &Option<std::sync::Arc<ValidatorP2pClient>>,
    pending_commitment: &Arc<RwLock<Option<EpochAttestationCommitment>>>,
) -> Result<()> {
    // Check on-chain epoch to determine if we need to fetch a fresh cluster map
    let onchain_epoch = fetch_storage_u64(client, pallet_name, "CurrentEpoch")
        .await
        .unwrap_or(0);

    // Check cached cluster map - only fetch if epoch might have changed
    let map = {
        let cache = cluster_map_cache();
        let cached = cache.read().await;

        if let Some(ref cached_map) = *cached {
            // Use cached map if epoch hasn't advanced (map.epoch > onchain means we have newer data)
            if cached_map.epoch >= onchain_epoch {
                debug!(
                    cached_epoch = cached_map.epoch,
                    onchain_epoch = onchain_epoch,
                    "Using cached cluster map"
                );
                cached_map.clone()
            } else {
                drop(cached); // Release read lock before acquiring write lock

                // Epoch advanced, fetch fresh map
                let fresh_map = fetch_cluster_map(
                    http,
                    &args.validator_http_url,
                    p2p_client,
                    args.http_fallback,
                )
                .await?;

                // Update cache
                *cache.write().await = Some(fresh_map.clone());
                info!(
                    old_epoch = onchain_epoch,
                    new_epoch = fresh_map.epoch,
                    "Fetched fresh cluster map (epoch changed)"
                );
                fresh_map
            }
        } else {
            drop(cached); // Release read lock

            // No cached map, fetch one
            let fresh_map = fetch_cluster_map(
                http,
                &args.validator_http_url,
                p2p_client,
                args.http_fallback,
            )
            .await?;

            // Update cache
            *cache.write().await = Some(fresh_map.clone());
            info!(epoch = fresh_map.epoch, "Cached initial cluster map");
            fresh_map
        }
    };

    // Stats are always fetched fresh as they change every bucket
    let stats = fetch_network_stats(
        http,
        &args.validator_http_url,
        p2p_client,
        args.http_fallback,
    )
    .await?;

    // Determine current bucket (best_block / bucket_blocks)
    let best_block: u32 = client.blocks().at_latest().await?.number();
    // Guard against division by zero if bucket_blocks is misconfigured to 0
    let bucket: u32 = if args.bucket_blocks > 0 {
        best_block / args.bucket_blocks
    } else {
        0
    };

    info!(
        "tick: chain_best_block={} bucket={} miners={} files={}",
        best_block,
        bucket,
        map.miners.len(),
        stats.total_files
    );

    // Try all submissions independently - don't fail early
    let mut errors = Vec::new();
    let mut crush_map_submitted = false;

    // 1. Submit CRUSH map if epoch changed
    if args.enable_crush_map {
        match submit_crush_map_if_needed(args, client, signer, pallet_name, &map).await {
            Ok(submitted) => {
                crush_map_submitted = submitted;
            }
            Err(e) => {
                errors.push(format!("submit_crush_map: {}", e));
            }
        }
    }

    // 2. Submit attestation commitment if pending and CRUSH map was submitted
    if args.enable_attestation_commitments && crush_map_submitted {
        // Take the pending commitment (if any)
        let commitment = { pending_commitment.write().await.take() };

        if let Some(commitment) = commitment {
            let commitment_epoch = commitment.epoch;
            if let Err(e) =
                submit_attestation_commitment(args, client, signer, pallet_name, &commitment).await
            {
                // Put the commitment back for retry, but only if no newer commitment arrived
                let mut guard = pending_commitment.write().await;
                if guard.is_none() {
                    // No new commitment arrived while we were trying to submit
                    *guard = Some(commitment);
                } else {
                    // A newer commitment arrived - drop the old failed one
                    warn!(
                        old_epoch = commitment_epoch,
                        "Dropping failed commitment - newer commitment already pending"
                    );
                }
                drop(guard);
                errors.push(format!("submit_attestation_commitment: {}", e));
            }
        }
    }

    // 3. Submit miner stats
    if args.enable_miner_stats {
        if let Err(e) =
            submit_miner_stats(args, client, signer, pallet_name, bucket, &map, &stats).await
        {
            errors.push(format!("submit_miner_stats: {}", e));
        }
    }

    // 4. Submit node quality
    if args.enable_node_quality {
        if let Err(e) =
            submit_node_quality(args, client, signer, pallet_name, bucket, &map, &stats).await
        {
            errors.push(format!("submit_node_quality: {}", e));
        }
    }

    // 5. Submit individual attestations from warden if enabled and queue has entries
    if args.enable_attestations {
        if let Err(e) =
            submit_attestations_if_ready(args, client, signer, pallet_name, bucket).await
        {
            errors.push(format!("submit_attestations: {}", e));
        }
    }

    if errors.is_empty() {
        Ok(())
    } else {
        Err(anyhow!("Some submissions failed: {}", errors.join("; ")))
    }
}

// ============================================================================
// Transaction Submission Functions
// ============================================================================

/// Submits the CRUSH cluster map to the blockchain if the epoch has advanced.
///
/// The CRUSH map contains:
/// - Epoch number (monotonically increasing)
/// - Placement parameters (pg_count, ec_k, ec_m)
/// - Full list of miners with UIDs, weights, family IDs, and endpoints
///
/// # Preconditions
/// - Submitter must have `MapAuthorityOrigin` permission
/// - New epoch must be greater than on-chain `CurrentEpoch`
///
/// # On-chain Effects
/// - Updates `CurrentEpoch` storage
/// - Replaces `CrushMap` with new miner topology
///
/// # Returns
/// - `Ok(true)` if the CRUSH map was successfully submitted
/// - `Ok(false)` if no submission was needed (epoch hasn't advanced)
/// - `Err(_)` if submission failed
async fn submit_crush_map_if_needed(
    args: &Args,
    client: &OnlineClient<PolkadotConfig>,
    signer: &Keypair,
    pallet_name: &str,
    map: &ClusterMap,
) -> Result<bool> {
    // We optimistically submit if epoch > onchain_current_epoch, but if we can't read it we still try.
    let should_submit = match fetch_storage_u64(client, pallet_name, "CurrentEpoch").await {
        Ok(cur) => map.epoch > cur,
        Err(_) => true,
    };
    if !should_submit {
        return Ok(false);
    }

    // params: { pg_count, ec_k, ec_m } from map
    let params = dynamic::Value::named_composite(vec![
        ("pg_count", dynamic::Value::u128(map.pg_count as u128)),
        ("ec_k", dynamic::Value::u128(map.ec_k as u128)),
        ("ec_m", dynamic::Value::u128(map.ec_m as u128)),
    ]);

    // miners: vec of MinerRecord (BoundedVec encodes like Vec)
    // IMPORTANT: Pallet requires miners to be sorted by uid
    let mut sorted_miners = map.miners.clone();
    sorted_miners.sort_by_key(|m| m.uid);

    let mut miner_vals = Vec::with_capacity(sorted_miners.len());
    for m in sorted_miners.iter() {
        let node_id = match parse_node_id32_bytes(&m.public_key) {
            Ok(b) => b,
            Err(e) => {
                warn!(miner_uid = m.uid, error = %e, "Skipping miner: failed to parse public_key");
                continue;
            }
        };

        // family_id is expected to be an AccountId on-chain.
        // Supports SS58, hex, or arbitrary strings (hashed to 32 bytes for development).
        let family_bytes = parse_account_id32_bytes(&m.family_id);

        let endpoint_bytes = bytes_truncated(
            serde_json::to_vec(&m.endpoint)
                .unwrap_or_else(|_| format!("{:?}", m.endpoint).into_bytes()),
            args.max_endpoint_bytes,
        );
        let http_bytes = bytes_truncated(m.http_addr.as_bytes().to_vec(), args.max_http_addr_bytes);

        let miner_val = dynamic::Value::named_composite(vec![
            ("uid", dynamic::Value::u128(m.uid as u128)),
            ("node_id", bytes32_value(node_id)),
            ("weight", dynamic::Value::u128(m.weight as u128)),
            ("family_id", dynamic::Value::from_bytes(family_bytes)),
            ("endpoint", dynamic::Value::from_bytes(endpoint_bytes)),
            ("http_addr", dynamic::Value::from_bytes(http_bytes)),
        ]);
        miner_vals.push(miner_val);
    }

    // Guard against submitting an empty miner list which could corrupt on-chain state
    if miner_vals.is_empty() && !map.miners.is_empty() {
        return Err(anyhow!(
            "All {} miners failed to parse - refusing to submit empty CRUSH map",
            map.miners.len()
        ));
    }

    let valid_miner_count = miner_vals.len();
    let miners = dynamic::Value::unnamed_composite(miner_vals);

    let tx = dynamic::tx(
        pallet_name,
        "submit_crush_map",
        vec![dynamic::Value::u128(map.epoch as u128), params, miners],
    );

    info!(
        epoch = map.epoch,
        valid_miners = valid_miner_count,
        total_miners = map.miners.len(),
        pg_count = map.pg_count,
        ec_k = map.ec_k,
        ec_m = map.ec_m,
        "Submitting CRUSH map (requires MapAuthorityOrigin)"
    );

    submit_and_finalize(client, signer, tx, "submit_crush_map")
        .await
        .inspect(|_| info!(epoch = map.epoch, "CRUSH map submitted successfully"))
        .inspect_err(|e| warn!(error = %e, "CRUSH map submission failed"))?;

    Ok(true)
}

/// Submits per-miner storage and bandwidth statistics to the blockchain.
///
/// Statistics are aggregated per "bucket" (time window based on block height).
/// Each miner gets an update with:
/// - Shard count and total shard bytes stored
/// - Bandwidth bytes served
/// - Strike count (reliability metric)
///
/// # Preconditions
/// - Submitter must have `StatsAuthorityOrigin` permission
///
/// # On-chain Effects
/// - Updates per-miner stats in the bucket storage
/// - Updates network totals (total_shards, total_bytes, total_bandwidth)
async fn submit_miner_stats(
    _args: &Args,
    client: &OnlineClient<PolkadotConfig>,
    signer: &Keypair,
    pallet_name: &str,
    bucket: u32,
    map: &ClusterMap,
    stats: &NetworkStatsResponse,
) -> Result<()> {
    // Build updates: Vec<{uid, stats}>
    let mut updates = Vec::new();
    for m in map.miners.iter() {
        let entry = stats
            .miner_stats
            .get(&m.uid.to_string())
            .copied()
            .unwrap_or([0, 0]);
        let shard_count = entry[0];
        let shard_bytes = entry[1];
        let bw = stats
            .bandwidth_stats
            .get(&m.uid.to_string())
            .copied()
            .unwrap_or(0);

        let ms = dynamic::Value::named_composite(vec![
            ("shard_count", dynamic::Value::u128(shard_count as u128)),
            (
                "shard_data_bytes",
                dynamic::Value::u128(shard_bytes as u128),
            ),
            ("strikes", dynamic::Value::u128(m.strikes as u128)),
            ("last_seen_bucket", dynamic::Value::u128(bucket as u128)),
            ("bandwidth_bytes", dynamic::Value::u128(bw as u128)),
            ("integrity_fails", dynamic::Value::u128(0)),
        ]);
        let upd = dynamic::Value::named_composite(vec![
            ("uid", dynamic::Value::u128(m.uid as u128)),
            ("stats", ms),
        ]);
        updates.push(upd);
    }

    let totals = dynamic::Value::named_composite(vec![
        (
            "total_shards",
            dynamic::Value::u128(stats.total_blobs as u128),
        ),
        (
            "total_shard_data_bytes",
            dynamic::Value::u128(stats.total_storage as u128),
        ),
        (
            "total_bandwidth_bytes",
            dynamic::Value::u128(
                stats
                    .bandwidth_stats
                    .values()
                    .map(|v| *v as u128)
                    .sum::<u128>(),
            ),
        ),
    ]);

    let tx = dynamic::tx(
        pallet_name,
        "submit_miner_stats",
        vec![
            dynamic::Value::u128(bucket as u128),
            dynamic::Value::unnamed_composite(updates),
            dynamic::Value::unnamed_variant("Some", vec![totals]),
        ],
    );
    info!(
        bucket = bucket,
        miner_updates = map.miners.len(),
        total_blobs = stats.total_blobs,
        total_storage_bytes = stats.total_storage,
        "Submitting miner stats (requires StatsAuthorityOrigin)"
    );

    submit_and_finalize(client, signer, tx, "submit_miner_stats")
        .await
        .inspect(|_| info!(bucket = bucket, "Miner stats submitted successfully"))
        .inspect_err(|e| warn!(bucket = bucket, error = %e, "Miner stats submission failed"))
}

/// Submits node quality metrics for reward calculations to the blockchain.
///
/// Unlike miner_stats (keyed by UID), node_quality is keyed by the child AccountId
/// registered on-chain. This requires looking up each miner's NodeId → Child mapping.
///
/// Quality metrics include:
/// - Shard data bytes stored
/// - Bandwidth bytes served
/// - Uptime (1000 permille if online, 0 if offline)
/// - Strike count
///
/// # Preconditions
/// - Submitter must have `StatsAuthorityOrigin` permission
/// - Miners must be registered in on-chain `NodeIdToChild` storage
///
/// # Rate Limiting
/// Includes 50ms delays between RPC reads to avoid overwhelming the blockchain node.
async fn submit_node_quality(
    args: &Args,
    client: &OnlineClient<PolkadotConfig>,
    signer: &Keypair,
    pallet_name: &str,
    bucket: u32,
    map: &ClusterMap,
    stats: &NetworkStatsResponse,
) -> Result<()> {
    let now = now_secs();

    // Build updates keyed by child AccountId, which we resolve from on-chain NodeIdToChild(node_id).
    let mut updates = Vec::new();
    for (idx, m) in map.miners.iter().enumerate() {
        // Rate limit RPC reads to avoid overwhelming the blockchain node
        // Add a small delay before subsequent reads (not before the first one)
        if idx > 0 {
            tokio::time::sleep(Duration::from_millis(50)).await;
        }

        let node_id_bytes: [u8; 32] = match parse_node_id32_bytes(&m.public_key) {
            Ok(b) => b,
            Err(e) => {
                warn!(miner_uid = m.uid, error = %e, "Skipping miner: failed to parse public_key");
                continue;
            }
        };

        // Resolve child account id from chain storage map NodeIdToChild(node_id)
        let child = match fetch_node_id_to_child(client, pallet_name, node_id_bytes).await {
            Ok(Some(v)) => v,
            Ok(None) => {
                warn!(
                    miner_uid = m.uid,
                    "Skipping miner: not found in on-chain NodeIdToChild registry"
                );
                continue;
            }
            Err(e) => {
                warn!(miner_uid = m.uid, error = %e, "Skipping miner: failed to fetch NodeIdToChild");
                continue;
            }
        };

        let entry = stats
            .miner_stats
            .get(&m.uid.to_string())
            .copied()
            .unwrap_or([0, 0]);
        let shard_bytes = entry[1] as u128;
        let bw = stats
            .bandwidth_stats
            .get(&m.uid.to_string())
            .copied()
            .unwrap_or(0) as u128;

        let uptime_permille = if now.saturating_sub(m.last_seen) <= args.uptime_offline_secs {
            1000u16
        } else {
            0u16
        };

        let q = dynamic::Value::named_composite(vec![
            ("shard_data_bytes", dynamic::Value::u128(shard_bytes)),
            ("bandwidth_bytes", dynamic::Value::u128(bw)),
            (
                "uptime_permille",
                dynamic::Value::u128(uptime_permille as u128),
            ),
            ("strikes", dynamic::Value::u128(m.strikes as u128)),
            ("integrity_fails", dynamic::Value::u128(0)),
        ]);

        // child AccountId32 is represented as bytes via `Value::from_bytes`.
        let upd = dynamic::Value::unnamed_composite(vec![dynamic::Value::from_bytes(child), q]);
        updates.push(upd);
    }

    info!(
        bucket = bucket,
        node_updates = updates.len(),
        total_miners = map.miners.len(),
        "Submitting node quality (requires StatsAuthorityOrigin)"
    );
    if updates.len() < map.miners.len() {
        warn!(
            missing = map.miners.len() - updates.len(),
            "Some miners not found in on-chain registry"
        );
    }

    let tx = dynamic::tx(
        pallet_name,
        "submit_node_quality",
        vec![
            dynamic::Value::u128(bucket as u128),
            dynamic::Value::unnamed_composite(updates),
        ],
    );

    submit_and_finalize(client, signer, tx, "submit_node_quality")
        .await
        .inspect(|_| info!(bucket = bucket, "Node quality submitted successfully"))
        .inspect_err(|e| warn!(bucket = bucket, error = %e, "Node quality submission failed"))
}

/// Submits an epoch attestation commitment to the blockchain.
///
/// The commitment is a compact summary of all warden attestations for an epoch,
/// including merkle roots for verification. The full bundle is stored in Arion.
///
/// # Timing
/// This is called after `submit_crush_map_if_needed` succeeds, ensuring the
/// on-chain epoch matches the commitment epoch.
///
/// # Preconditions
/// - Submitter must have `AttestationAuthorityOrigin` permission
/// - CRUSH map for this epoch must already be submitted
///
/// # On-chain Effects
/// - Stores `EpochAttestationCommitments[epoch] = commitment`
/// - Emits `AttestationCommitmentSubmitted` event
async fn submit_attestation_commitment(
    args: &Args,
    client: &OnlineClient<PolkadotConfig>,
    signer: &Keypair,
    pallet_name: &str,
    commitment: &EpochAttestationCommitment,
) -> Result<()> {
    info!(
        epoch = commitment.epoch,
        attestation_count = commitment.attestation_count,
        arion_hash = hex::encode(commitment.arion_content_hash),
        dry_run = args.attestation_commitment_dry_run,
        "Processing attestation commitment"
    );

    // In dry-run mode, just log the commitment
    if args.attestation_commitment_dry_run {
        info!(
            epoch = commitment.epoch,
            attestation_count = commitment.attestation_count,
            attestation_merkle_root = hex::encode(commitment.attestation_merkle_root),
            warden_pubkey_merkle_root = hex::encode(commitment.warden_pubkey_merkle_root),
            arion_content_hash = hex::encode(commitment.arion_content_hash),
            "[DRY RUN] Would submit attestation commitment"
        );
        return Ok(());
    }

    // Build the extrinsic
    let tx = dynamic::tx(
        pallet_name,
        "submit_attestation_commitment",
        vec![
            dynamic::Value::u128(commitment.epoch as u128),
            bytes32_value(commitment.arion_content_hash),
            bytes32_value(commitment.attestation_merkle_root),
            bytes32_value(commitment.warden_pubkey_merkle_root),
            dynamic::Value::u128(commitment.attestation_count as u128),
        ],
    );

    info!(
        epoch = commitment.epoch,
        attestation_count = commitment.attestation_count,
        "Submitting attestation commitment (requires AttestationAuthorityOrigin)"
    );

    submit_and_finalize(client, signer, tx, "submit_attestation_commitment")
        .await
        .inspect(|_| {
            info!(
                epoch = commitment.epoch,
                "Attestation commitment submitted successfully"
            )
        })
        .inspect_err(|e| {
            warn!(
                epoch = commitment.epoch,
                error = %e,
                "Attestation commitment submission failed"
            )
        })
}

/// Submits queued attestations from warden to the blockchain.
///
/// Attestations are proof-of-storage verification results signed by wardens.
/// They are used to:
/// - Credit miners for passed audits (reputation/rewards)
/// - Slash miners for failed audits, timeouts, or invalid proofs
///
/// # Behavior
/// - Drains up to `attestation_batch_size` attestations from the queue
/// - In dry-run mode, logs attestations instead of submitting
/// - Failed attestations are requeued with retry count (up to MAX_ATTESTATION_RETRIES)
///
/// # Preconditions
/// - Submitter must have `AttestationAuthorityOrigin` permission (when pallet ready)
///
/// # On-chain Effects (when pallet ready)
/// - Stores individual attestation records
/// - Updates aggregate audit scores per miner
async fn submit_attestations_if_ready(
    args: &Args,
    client: &OnlineClient<PolkadotConfig>,
    signer: &Keypair,
    pallet_name: &str,
    bucket: u32,
) -> Result<()> {
    let queue = attestation_queue();
    if queue.is_empty() {
        return Ok(());
    }

    // Drain up to batch_size attestations from queue
    let mut batch: Vec<(String, SignedAttestation, u8)> = Vec::new();
    let keys: Vec<String> = queue
        .iter()
        .take(args.attestation_batch_size)
        .map(|r| r.key().clone())
        .collect();

    for key in keys {
        if let Some((_, (attestation, retry_count))) = queue.remove(&key) {
            batch.push((key, attestation, retry_count));
        }
    }

    if batch.is_empty() {
        return Ok(());
    }

    let batch_len = batch.len();
    info!(
        batch_size = batch_len,
        queue_remaining = queue.len(),
        dry_run = args.attestation_dry_run,
        "Processing attestation batch"
    );

    // In dry-run mode, just log the attestations
    if args.attestation_dry_run {
        for (key, attestation, _) in &batch {
            info!(
                dedup_key = %key,
                shard_hash = %attestation.attestation.shard_hash,
                miner_uid = attestation.attestation.miner_uid,
                result = ?attestation.attestation.result,
                block_number = attestation.attestation.block_number,
                "[DRY RUN] Would submit attestation"
            );
        }
        // Update last submission timestamp even in dry-run
        last_attestation_submission().store(now_secs(), std::sync::atomic::Ordering::Relaxed);
        info!(
            count = batch_len,
            "[DRY RUN] Logged {} attestations (pallet not ready)", batch_len
        );
        return Ok(());
    }

    // Build attestation records for on-chain submission
    // Types must match pallet's AttestationRecord:
    // - miner_uid: u32
    // - result: AuditResult enum (unit variants)
    // - block_number: u64
    // - timestamp: u64
    // - Other fields: BoundedVec<u8, ...>
    let mut attestation_vals = Vec::with_capacity(batch.len());
    for (_, attestation, _) in &batch {
        let record = dynamic::Value::named_composite(vec![
            (
                "shard_hash",
                dynamic::Value::from_bytes(attestation.attestation.shard_hash.as_bytes()),
            ),
            (
                "miner_uid",
                dynamic::Value::u128(attestation.attestation.miner_uid as u128),
            ),
            (
                // AuditResult is an enum with unit variants - encode as variant, not integer
                "result",
                dynamic::Value::unnamed_variant(
                    attestation.attestation.result.variant_name(),
                    vec![],
                ),
            ),
            (
                "challenge_seed",
                dynamic::Value::from_bytes(attestation.attestation.challenge_seed),
            ),
            (
                "block_number",
                dynamic::Value::u128(attestation.attestation.block_number as u128),
            ),
            (
                "timestamp",
                dynamic::Value::u128(attestation.attestation.timestamp as u128),
            ),
            (
                "warden_pubkey",
                dynamic::Value::from_bytes(attestation.warden_pubkey.clone()),
            ),
            (
                "signature",
                dynamic::Value::from_bytes(attestation.signature.clone()),
            ),
            (
                "merkle_proof_sig_hash",
                dynamic::Value::from_bytes(attestation.attestation.merkle_proof_sig_hash.clone()),
            ),
            (
                "warden_id",
                dynamic::Value::from_bytes(attestation.attestation.warden_id.as_bytes()),
            ),
        ]);
        attestation_vals.push(record);
    }

    let tx = dynamic::tx(
        pallet_name,
        "submit_attestations",
        vec![
            dynamic::Value::u128(bucket as u128),
            dynamic::Value::unnamed_composite(attestation_vals),
        ],
    );

    match submit_and_finalize(client, signer, tx, "submit_attestations").await {
        Ok(()) => {
            last_attestation_submission().store(now_secs(), std::sync::atomic::Ordering::Relaxed);
            info!(
                bucket = bucket,
                count = batch_len,
                "Attestations submitted successfully"
            );
            Ok(())
        }
        Err(e) => {
            // Requeue failed attestations (up to max retries)
            let mut requeued = 0;
            for (key, attestation, retry_count) in batch {
                if retry_count < MAX_ATTESTATION_RETRIES {
                    queue.insert(key, (attestation, retry_count + 1));
                    requeued += 1;
                } else {
                    warn!(
                        shard_hash = %attestation.attestation.shard_hash,
                        miner_uid = attestation.attestation.miner_uid,
                        "Dropping attestation after {} retries",
                        MAX_ATTESTATION_RETRIES
                    );
                }
            }
            warn!(
                error = %e,
                requeued = requeued,
                dropped = batch_len - requeued,
                "Attestation submission failed"
            );
            Err(e)
        }
    }
}

// ============================================================================
// On-Chain Storage Helpers
// ============================================================================

/// Fetches a u64 storage value from the blockchain using dynamic queries.
///
/// Returns 0 if the storage key doesn't exist or decoding fails.
async fn fetch_storage_u64(
    client: &OnlineClient<PolkadotConfig>,
    pallet: &str,
    storage: &str,
) -> Result<u64> {
    let addr = dynamic::storage(pallet, storage, Vec::<dynamic::Value>::new());
    let maybe = client.storage().at_latest().await?.fetch(&addr).await?;
    let Some(v) = maybe else {
        return Ok(0);
    };
    // subxt dynamic value -> decode to u64 by re-encoding and decoding as u64 (best-effort)
    let bytes = v.encoded();
    let mut s = bytes;
    match parity_scale_codec::Decode::decode(&mut s) {
        Ok(v) => Ok(v),
        Err(e) => {
            warn!(storage = %storage, error = %e, "Failed to decode storage value, using default 0");
            Ok(0u64)
        }
    }
}

/// Looks up a miner's child AccountId from their NodeId in on-chain storage.
///
/// The `NodeIdToChild` storage map links a miner's P2P public key to their
/// registered child account, which is used for reward distribution.
///
/// # Returns
/// - `Ok(Some(bytes))` - SCALE-encoded AccountId32
/// - `Ok(None)` - NodeId not found in registry
/// - `Err` - RPC or decoding error
async fn fetch_node_id_to_child(
    client: &OnlineClient<PolkadotConfig>,
    pallet: &str,
    node_id: [u8; 32],
) -> Result<Option<Vec<u8>>> {
    let addr = dynamic::storage(pallet, "NodeIdToChild", vec![bytes32_value(node_id)]);
    let maybe = client.storage().at_latest().await?.fetch(&addr).await?;
    let Some(v) = maybe else {
        return Ok(None);
    };
    let bytes = v.encoded().to_vec();
    Ok(Some(bytes))
}

// ============================================================================
// ID Parsing Helpers
// ============================================================================

/// Parses a 32-byte hex string (with or without 0x prefix) into a byte array.
fn parse_hex32(s: &str, context: &str) -> Result<[u8; 32]> {
    let trimmed = s.trim_start_matches("0x");
    let bytes = hex::decode(trimmed).with_context(|| format!("{} is not valid hex", context))?;
    bytes
        .try_into()
        .map_err(|_| anyhow!("{} hex is not 32 bytes", context))
}

/// Parses an AccountId32 from SS58 string, 32-byte hex, or arbitrary string.
///
/// Used to convert validator's family_id strings to on-chain AccountId format.
///
/// Supports three formats (tried in order):
/// 1. SS58 address (e.g., `5GrwvaEF5zXb26Fz9rcQpDWS57CtERHpNehXCPcNoHGKutQY`)
/// 2. 32-byte hex with optional "0x" prefix
/// 3. Arbitrary string (hashed with BLAKE3 to produce deterministic 32 bytes)
///
/// The fallback to BLAKE3 hash allows development/testing with miners that use
/// simple family_id strings like "default" or "datacenter-1" without requiring
/// on-chain registration.
fn parse_account_id32_bytes(s: &str) -> [u8; 32] {
    // Try SS58 first
    if let Ok(a) = s.parse::<subxt::utils::AccountId32>() {
        return *a.as_ref();
    }
    // Try hex second
    if let Ok(bytes) = parse_hex32(s, "family_id") {
        return bytes;
    }
    // Fall back to BLAKE3 hash of the string for arbitrary family_id values
    // This produces a deterministic 32-byte value that can serve as an AccountId
    debug!(family_id = %s, "family_id is not SS58 or hex, using BLAKE3 hash as fallback");
    *blake3::hash(s.as_bytes()).as_bytes()
}

/// Parses a NodeId (Iroh public key) from base32 or 32-byte hex.
///
/// Supports two formats:
/// 1. Iroh base32 public key (e.g., from `PublicKey::to_string()`)
/// 2. 32-byte hex with optional "0x" prefix
fn parse_node_id32_bytes(s: &str) -> Result<[u8; 32]> {
    iroh_base::PublicKey::from_str(s)
        .map(|pk| *pk.as_bytes())
        .or_else(|_| parse_hex32(s, "node_id"))
}

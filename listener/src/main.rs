//! Listener - Read-only replica service for the Hippius Arion storage subnet.
//!
//! The listener connects to a validator via P2P (`hippius/gateway-control` protocol) and serves
//! read-only HTTP endpoints for cluster map and file manifests. It acts as a
//! lightweight proxy that doesn't require full validator privileges.
//!
//! # Architecture
//!
//! ```text
//! Validator                    Listener (reads)          Clients
//!      |                            |                       |
//!      |<-- P2P gateway-control ----|                       |
//!      |    (GetClusterMap,         |                       |
//!      |     GetManifest)           |<---- GET /map --------|
//!      |                            |<---- GET /manifest ---|
//! ```
//!
//! # Replication Model
//!
//! - Connects to validator using `VALIDATOR_NODE_ID`
//! - Periodically fetches cluster map via P2P (every 5 seconds)
//! - Fetches manifests on-demand via P2P
//! - All data is cached locally for fast read access
//!
//! # HTTP Endpoints
//!
//! - `GET /map` - Returns current cluster map JSON
//! - `GET /manifest/:hash` - Returns file manifest for the given hash
//! - `GET /health` - Health check
//!
//! # Example Usage
//!
//! ```bash
//! export VALIDATOR_NODE_ID="your-validator-node-id-hex"
//! export PORT=3005
//! cargo run --bin listener
//! ```

use anyhow::{Result, anyhow};
use axum::{
    extract::{Path, State},
    http::{StatusCode, header},
    middleware as axum_middleware,
    response::IntoResponse,
};
use axum_server::tls_openssl::OpenSSLConfig;
use clap::Parser;
use common::{
    ClusterMap, FileManifest, GATEWAY_CONTROL_ALPN, GatewayControlMessage,
    P2P_DEFAULT_TIMEOUT_SECS, P2P_MAX_RESPONSE_SIZE, P2pConnectionManager,
    middleware::validate_api_key, tls::TlsConfig,
};
use std::time::Duration;
use std::{net::SocketAddr, sync::Arc};
use tokio::signal;
use tokio::sync::RwLock;
use tracing::{debug, error, info, warn};
use tracing_subscriber::{layer::SubscriberExt, util::SubscriberInitExt};

// ============================================================================
// Constants
// ============================================================================

/// Interval between cluster map sync attempts (in seconds).
const CLUSTER_MAP_SYNC_INTERVAL_SECS: u64 = 5;

/// Maximum retry attempts for initial cluster map fetch.
const MAX_INITIAL_SYNC_RETRIES: u32 = 100;

/// Maximum backoff duration in seconds for sync retries.
const MAX_BACKOFF_SECS: u64 = 60;

/// Exponent cap to prevent overflow in backoff calculation.
/// 2^6 = 64 seconds, which is capped to MAX_BACKOFF_SECS (60).
const MAX_BACKOFF_EXPONENT: u32 = 6;

// ============================================================================
// CLI Configuration
// ============================================================================

/// Listener service for read-only cluster state access via P2P.
#[derive(Parser, Debug)]
#[command(author, version, about, long_about = None)]
struct Args {
    /// HTTP server port
    #[arg(long, env = "PORT", default_value = "3005")]
    port: u16,

    /// Validator's Iroh node ID (hex-encoded Ed25519 public key) for P2P communication.
    #[arg(long, env = "VALIDATOR_NODE_ID")]
    validator_node_id: String,
}

// ============================================================================
// Application State
// ============================================================================

/// Shared application state for HTTP handlers.
struct AppState {
    /// Cached cluster map from validator
    cluster_map: Arc<RwLock<Option<ClusterMap>>>,
    /// P2P client for validator communication
    validator_client: ValidatorP2pClient,
}

// ============================================================================
// P2P Client for Validator Communication
// ============================================================================

/// P2P client for communicating with the validator via gateway-control protocol.
#[derive(Clone)]
struct ValidatorP2pClient {
    conn_manager: P2pConnectionManager,
}

impl ValidatorP2pClient {
    /// Create a new P2P client for the validator.
    fn new(endpoint: iroh::Endpoint, validator_node_id: iroh::PublicKey) -> Self {
        Self {
            conn_manager: P2pConnectionManager::new(
                endpoint,
                validator_node_id,
                GATEWAY_CONTROL_ALPN,
            ),
        }
    }

    /// Send a message and receive a response.
    async fn send_request(&self, message: &GatewayControlMessage) -> Result<GatewayControlMessage> {
        let conn = self.conn_manager.get_connection().await?;

        let (mut send, mut recv) = conn.open_bi().await?;

        // Send message
        let message_bytes = serde_json::to_vec(message)?;
        send.write_all(&message_bytes).await?;
        send.finish()?;

        // Wait for response with timeout
        let response_bytes = tokio::time::timeout(
            Duration::from_secs(P2P_DEFAULT_TIMEOUT_SECS),
            recv.read_to_end(P2P_MAX_RESPONSE_SIZE),
        )
        .await
        .map_err(|_| anyhow!("Timeout waiting for validator response"))??;

        let response: GatewayControlMessage = serde_json::from_slice(&response_bytes)?;
        Ok(response)
    }

    /// Fetch the current cluster map from validator.
    async fn get_cluster_map(&self) -> Result<ClusterMap> {
        let response = self
            .send_request(&GatewayControlMessage::GetClusterMap)
            .await?;

        match response {
            GatewayControlMessage::ClusterMapResponse { map: Some(map), .. } => Ok(map),
            GatewayControlMessage::ClusterMapResponse { error: Some(e), .. } => {
                Err(anyhow!("Validator error: {}", e))
            }
            GatewayControlMessage::ClusterMapResponse {
                map: None,
                error: None,
            } => Err(anyhow!("Validator returned empty response")),
            _ => Err(anyhow!("Unexpected response type from validator")),
        }
    }

    /// Fetch file manifest from validator.
    async fn get_manifest(&self, file_hash: &str) -> Result<Option<FileManifest>> {
        let response = self
            .send_request(&GatewayControlMessage::GetManifest {
                file_hash: file_hash.to_string(),
            })
            .await?;

        match response {
            GatewayControlMessage::ManifestResponse {
                manifest,
                error: None,
            } => Ok(manifest),
            GatewayControlMessage::ManifestResponse { error: Some(e), .. } => {
                debug!(file_hash = %file_hash, error = %e, "Manifest not found");
                Ok(None)
            }
            _ => Err(anyhow!("Unexpected response type from validator")),
        }
    }
}

// ============================================================================
// Key Management
// ============================================================================

/// Loads or generates the listener's Ed25519 keypair.
///
/// The keypair is stored in `keypair.bin` within the data directory.
/// If no keypair exists, generates a new one with secure permissions (0600).
async fn load_keypair(data_dir: &std::path::Path) -> anyhow::Result<iroh::SecretKey> {
    let keypair_path = data_dir.join("keypair.bin");
    if keypair_path.exists() {
        let bytes = tokio::fs::read(&keypair_path).await?;
        return iroh::SecretKey::try_from(&bytes[..]).map_err(|e| {
            anyhow::anyhow!(
                "Existing keypair file is corrupted: {}. Delete {} to generate new key.",
                e,
                keypair_path.display()
            )
        });
    }

    // Use rand::rng() which provides a thread-local CSPRNG
    let secret_key = iroh::SecretKey::generate(&mut rand::rng());
    tokio::fs::write(&keypair_path, secret_key.to_bytes()).await?;

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        tokio::fs::set_permissions(&keypair_path, std::fs::Permissions::from_mode(0o600)).await?;
    }

    Ok(secret_key)
}

// ============================================================================
// Background Tasks
// ============================================================================

/// Background loop to periodically sync cluster map from validator.
async fn sync_cluster_map_loop(state: Arc<AppState>) {
    loop {
        match state.validator_client.get_cluster_map().await {
            Ok(map) => {
                let epoch = map.epoch;
                let miner_count = map.miners.len();
                *state.cluster_map.write().await = Some(map);
                debug!(epoch = epoch, miners = miner_count, "Cluster map synced");
            }
            Err(e) => {
                warn!(error = %e, "Failed to sync cluster map from validator");
            }
        }
        tokio::time::sleep(Duration::from_secs(CLUSTER_MAP_SYNC_INTERVAL_SECS)).await;
    }
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::registry()
        .with(tracing_subscriber::EnvFilter::new(
            std::env::var("RUST_LOG").unwrap_or_else(|_| "info".into()),
        ))
        .with(tracing_subscriber::fmt::layer())
        .init();

    let args = Args::parse();
    info!(version = env!("CARGO_PKG_VERSION"), "Listener starting");

    // 1. Initialize Iroh Endpoint
    let data_dir = std::env::var("LISTENER_DATA_DIR").map_or_else(
        |_| std::path::PathBuf::from("data/listener"),
        std::path::PathBuf::from,
    );
    tokio::fs::create_dir_all(&data_dir).await?;

    let secret_key = load_keypair(&data_dir).await?;

    // Get relay URL from environment or use default
    let relay_url = common::get_relay_url(None);
    info!(relay_url = %relay_url, "Configuring relay");

    let endpoint = iroh::Endpoint::builder()
        .secret_key(secret_key)
        .relay_mode(common::build_relay_mode(&relay_url))
        .bind()
        .await?;

    // Wait for relay connection
    info!(
        wait_secs = common::RELAY_CONNECTION_WAIT_SECS,
        "Waiting for relay connection"
    );
    tokio::time::sleep(std::time::Duration::from_secs(
        common::RELAY_CONNECTION_WAIT_SECS,
    ))
    .await;

    info!(iroh_address = %endpoint.secret_key().public(), "Listener Iroh endpoint bound");

    // 2. Parse validator node ID
    let validator_node_id: iroh::PublicKey = args.validator_node_id.parse().map_err(|e| {
        anyhow::anyhow!(
            "Invalid VALIDATOR_NODE_ID '{}': {}. Must be hex-encoded Ed25519 public key.",
            args.validator_node_id,
            e
        )
    })?;
    info!(validator_node_id = %validator_node_id, "Connecting to validator via P2P");

    // 3. Create P2P client for validator
    let validator_client = ValidatorP2pClient::new(endpoint.clone(), validator_node_id);

    // 4. Initial cluster map fetch with retries
    info!("Fetching initial cluster map from validator");
    let mut retry_count = 0u32;
    let initial_cluster_map = loop {
        match validator_client.get_cluster_map().await {
            Ok(map) => {
                info!(
                    epoch = map.epoch,
                    miners = map.miners.len(),
                    "Initial cluster map received"
                );
                break Some(map);
            }
            Err(e) => {
                retry_count += 1;
                if retry_count >= MAX_INITIAL_SYNC_RETRIES {
                    warn!(
                        error = %e,
                        "Failed to fetch initial cluster map after {} retries, starting without it",
                        MAX_INITIAL_SYNC_RETRIES
                    );
                    break None;
                }
                // Cap exponent to prevent overflow, then cap result to MAX_BACKOFF_SECS
                let exponent = retry_count.min(MAX_BACKOFF_EXPONENT);
                let backoff = std::cmp::min(MAX_BACKOFF_SECS, 2u64.saturating_pow(exponent));
                warn!(error = %e, retry = retry_count, backoff_secs = backoff, "Failed to fetch cluster map, retrying");
                tokio::time::sleep(Duration::from_secs(backoff)).await;
            }
        }
    };

    // 5. Build application state
    let state = Arc::new(AppState {
        cluster_map: Arc::new(RwLock::new(initial_cluster_map)),
        validator_client,
    });

    // 6. Spawn background cluster map sync task
    let state_clone = state.clone();
    tokio::spawn(async move {
        sync_cluster_map_loop(state_clone).await;
    });

    // 7. Start HTTP Server with API Key Authentication
    // Public health endpoint (no auth required)
    let public_routes = axum::Router::new().route("/health", axum::routing::get(health_check));

    // Protected routes require X-API-Key authentication
    let protected_routes = axum::Router::new()
        .route("/map", axum::routing::get(get_map))
        .route("/manifest/{hash}", axum::routing::get(get_manifest))
        .layer(axum_middleware::from_fn(validate_api_key));

    let app = public_routes
        .merge(protected_routes)
        .with_state(state.clone());

    // Load TLS configuration
    let tls_config = TlsConfig::new("listener")
        .map_err(|e| anyhow::anyhow!("Failed to initialize TLS config: {}", e))?;
    let rustls_config = OpenSSLConfig::from_pem_file(&tls_config.cert_path, &tls_config.key_path)
        .map_err(|e| anyhow::anyhow!("Failed to load TLS configuration: {}", e))?;

    let addr = SocketAddr::from(([0, 0, 0, 0], args.port));
    info!(address = %addr, "Listener server starting (HTTPS)");

    // Create shutdown signal handler
    let shutdown_signal = async {
        let ctrl_c = async {
            signal::ctrl_c()
                .await
                .expect("Failed to install Ctrl+C handler");
        };

        #[cfg(unix)]
        let terminate = async {
            signal::unix::signal(signal::unix::SignalKind::terminate())
                .expect("Failed to install signal handler")
                .recv()
                .await;
        };

        #[cfg(not(unix))]
        let terminate = std::future::pending::<()>();

        tokio::select! {
            _ = ctrl_c => {},
            _ = terminate => {},
        }

        info!("Shutdown signal received, initiating graceful shutdown");
    };

    // Create graceful shutdown handle
    let handle = axum_server::Handle::new();
    let shutdown_handle = handle.clone();

    // Spawn shutdown listener
    tokio::spawn(async move {
        shutdown_signal.await;
        // Give 30 seconds for graceful shutdown
        shutdown_handle.graceful_shutdown(Some(Duration::from_secs(30)));
    });

    // Run server with graceful shutdown support
    axum_server::bind_openssl(addr, rustls_config)
        .handle(handle)
        .serve(app.into_make_service())
        .await?;

    info!("Listener shutdown complete");
    Ok(())
}

// ============================================================================
// HTTP Handlers
// ============================================================================

/// Health check endpoint for load balancers and monitoring.
///
/// Returns 200 OK with version info when the service is running.
async fn health_check() -> impl IntoResponse {
    let response = serde_json::json!({
        "status": "ok",
        "version": env!("CARGO_PKG_VERSION"),
    });
    json_response(&response)
}

/// Creates a JSON response from a serializable value.
fn json_response<T: serde::Serialize>(value: &T) -> axum::response::Response {
    match serde_json::to_string(value) {
        Ok(json) => (
            StatusCode::OK,
            [(header::CONTENT_TYPE, "application/json")],
            json,
        )
            .into_response(),
        Err(e) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            format!("Failed to serialize response: {}", e),
        )
            .into_response(),
    }
}

/// Returns the current cluster map from the cached state.
///
/// The cluster map is periodically synced from the validator.
/// Returns 503 if the map hasn't been fetched yet.
async fn get_map(State(state): State<Arc<AppState>>) -> impl IntoResponse {
    debug!("get_map called");

    let map_guard = state.cluster_map.read().await;
    match map_guard.as_ref() {
        Some(map) => json_response(map),
        None => (
            StatusCode::SERVICE_UNAVAILABLE,
            "Cluster map not yet available, sync in progress",
        )
            .into_response(),
    }
}

/// Returns a file manifest from the validator.
///
/// Fetches the manifest on-demand via P2P.
///
/// # Path Parameters
/// - `hash`: 64-character hex file hash (BLAKE3)
///
/// # Responses
/// - 200: Manifest JSON
/// - 400: Invalid hash format
/// - 404: Manifest not found
/// - 500: Failed to fetch from validator
async fn get_manifest(
    State(state): State<Arc<AppState>>,
    Path(hash): Path<String>,
) -> impl IntoResponse {
    if !common::is_valid_file_hash(&hash) {
        return (
            StatusCode::BAD_REQUEST,
            "Invalid file hash: must be 64 hex characters",
        )
            .into_response();
    }

    match state.validator_client.get_manifest(&hash).await {
        Ok(Some(manifest)) => json_response(&manifest),
        Ok(None) => (StatusCode::NOT_FOUND, "Manifest not found").into_response(),
        Err(e) => {
            error!(error = %e, file_hash = %hash, "Failed to fetch manifest from validator");
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                format!("Failed to fetch manifest: {}", e),
            )
                .into_response()
        }
    }
}

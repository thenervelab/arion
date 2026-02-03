//! Gateway entry point for the Hippius Arion storage subnet.
//!
//! The gateway provides HTTP ingress for file uploads and downloads,
//! communicates with the validator for metadata, and fetches erasure-coded
//! shards from miners via Iroh P2P.

mod background;
mod config;
mod handlers;
mod helpers;
mod metrics;
mod state;
mod validator_p2p;

use anyhow::Result;
use axum::{Router as AxumRouter, routing::post};
use axum_server::tls_openssl::OpenSSLConfig;
use clap::Parser;
use common::ClusterMap;
use common::tls::TlsConfig;
use dashmap::DashMap;
use helpers::load_keypair;
use iroh::Endpoint;
use iroh::protocol::Router;
use iroh_blobs::{BlobsProtocol, store::mem::MemStore};
use iroh_docs::{
    DocTicket,
    api::DocsApi,
    engine::{DefaultAuthorStorage, Engine},
};
use iroh_gossip::net::Gossip;
use metrics::Metrics;
use quick_cache::sync::Cache;
use state::AppState;
use std::collections::{HashMap, VecDeque};
use std::ops::Deref;
use std::str::FromStr;
use std::sync::Arc;
use tokio::sync::Mutex;
use tracing::info;
use tracing_subscriber::EnvFilter;

#[derive(Parser, Debug, Clone)]
#[command(author, version, about, long_about = None)]
struct Args {
    /// URL of the Validator (HTTP fallback)
    #[arg(long, env = "VALIDATOR_URL", default_value = "http://validator:3002")]
    validator_url: String,

    /// Validator's Iroh node ID (hex-encoded Ed25519 public key) for P2P communication.
    /// Required when USE_P2P=true.
    #[arg(long, env = "VALIDATOR_NODE_ID")]
    validator_node_id: Option<String>,

    /// Enable P2P communication with validator (default: true if VALIDATOR_NODE_ID is set)
    #[arg(long, env = "USE_P2P")]
    use_p2p: Option<bool>,

    /// Fall back to HTTP when P2P fails (default: true)
    #[arg(long, env = "HTTP_FALLBACK")]
    http_fallback: Option<bool>,

    /// Optional doc ticket to replicate validator metadata over P2P (read-only).
    /// If set, gateway will prefer reading manifests+cluster_map from local doc replica.
    #[arg(long, env = "DOC_TICKET")]
    doc_ticket: Option<String>,

    /// Port to listen on
    #[arg(long, env = "PORT", default_value = "3000")]
    port: u16,
}

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(EnvFilter::from_default_env())
        .init();

    let args = Args::parse();
    info!(version = env!("CARGO_PKG_VERSION"), "Starting gateway");

    // Helper to parse env vars with defaults
    fn env_parse<T: std::str::FromStr>(name: &str, default: T) -> T {
        std::env::var(name)
            .ok()
            .and_then(|s| s.parse().ok())
            .unwrap_or(default)
    }
    fn env_bool(name: &str, default: bool) -> bool {
        std::env::var(name)
            .ok()
            .map(|v| v != "0" && v.to_lowercase() != "false")
            .unwrap_or(default)
    }

    // Backpressure / concurrency knobs (env-configurable)
    let download_global_concurrency: usize = env_parse("GATEWAY_GLOBAL_FETCH_CONCURRENCY", 512);
    let download_request_parallelism: usize = env_parse("GATEWAY_REQUEST_FETCH_CONCURRENCY", 64);
    let download_permit_timeout_ms: u64 = env_parse("GATEWAY_FETCH_PERMIT_TIMEOUT_MS", 20_000);
    let fetch_connect_timeout_secs: u64 = env_parse("GATEWAY_FETCH_CONNECT_TIMEOUT_SECS", 20);
    let fetch_read_timeout_secs: u64 = env_parse("GATEWAY_FETCH_READ_TIMEOUT_SECS", 15);

    // Automatic repair-hint (gateway -> validator) knobs
    let auto_repair_hint_enabled: bool = env_bool("GATEWAY_AUTO_REPAIR_HINT_ENABLED", true);
    let validator_gateway_key: Option<String> = std::env::var("VALIDATOR_GATEWAY_KEY").ok();
    let repair_hint_min_interval_secs: u64 =
        env_parse("GATEWAY_REPAIR_HINT_MIN_INTERVAL_SECS", 600);
    let repair_hint_count: usize = env_parse("GATEWAY_REPAIR_HINT_COUNT", 2);
    let repair_hint_allow_scan: bool = env_bool("GATEWAY_REPAIR_HINT_ALLOW_SCAN", false);

    // Initialize Iroh Endpoint
    let data_dir = std::path::PathBuf::from("data");
    tokio::fs::create_dir_all(&data_dir).await?;

    let secret_key = load_keypair(&data_dir).await?;

    // Get relay URL from environment or use default
    let relay_url = common::get_relay_url(None);
    info!(relay_url = %relay_url, "Configuring relay");

    let endpoint = Endpoint::builder()
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

    let node_id = endpoint.secret_key().public();
    info!(node_id = %node_id, "Gateway Iroh address");

    // Optional: start iroh-docs engine and join validator doc using DOC_TICKET
    let (doc_replica, doc_replica_blobs): (
        Option<iroh_docs::api::Doc>,
        Option<iroh_blobs::store::fs::FsStore>,
    ) = if let Some(ticket_str) = args.doc_ticket.clone() {
        info!("DOC_TICKET provided, starting iroh-docs replica");
        let data_dir = std::path::PathBuf::from("data");
        let blobs_dir = data_dir.join("docs_blobs");
        tokio::fs::create_dir_all(&blobs_dir).await?;

        // Use an FsStore for docs replication (separate from the in-memory blob store used for gateway blob caching)
        let blobs_store = iroh_blobs::store::fs::FsStore::load(&blobs_dir).await?;
        let docs_path = data_dir.join("docs.db");
        let docs_store = iroh_docs::store::fs::Store::persistent(&docs_path)?;
        let downloader = iroh_blobs::api::downloader::Downloader::new(&blobs_store, &endpoint);
        let gossip = Gossip::builder().spawn(endpoint.clone());
        let default_author_storage =
            DefaultAuthorStorage::Persistent(data_dir.join("default_author"));

        let engine = Engine::spawn(
            endpoint.clone(),
            gossip,
            docs_store,
            blobs_store.deref().clone(),
            downloader,
            default_author_storage,
            None,
        )
        .await?;
        let engine_arc = Arc::new(engine);
        let docs_api = DocsApi::spawn(engine_arc.clone());

        let ticket = DocTicket::from_str(&ticket_str)?;
        let doc = docs_api.import_namespace(ticket.capability.clone()).await?;
        info!(doc_id = %doc.id(), "Joined doc replica");
        engine_arc
            .start_sync(doc.id(), ticket.nodes.clone())
            .await?;
        (Some(doc), Some(blobs_store))
    } else {
        (None, None)
    };

    // Initialize Store
    let store = MemStore::default();

    // Initialize shared HTTP client with connection pooling
    // Accept self-signed certs since validator/other services use auto-generated TLS certs
    let accept_invalid_certs = std::env::var("ACCEPT_INVALID_CERTS")
        .map(|v| v != "0" && v.to_lowercase() != "false")
        .unwrap_or(true);

    let http_client = reqwest::Client::builder()
        .pool_max_idle_per_host(20)
        .pool_idle_timeout(std::time::Duration::from_secs(90))
        .timeout(std::time::Duration::from_secs(30))
        .danger_accept_invalid_certs(accept_invalid_certs)
        .build()
        .map_err(|e| anyhow::anyhow!("Failed to build HTTP client: {}", e))?;

    // Initialize Blobs Protocol
    let blobs = BlobsProtocol::new(&store, None);

    // Run Iroh Router
    let _router = Router::builder(endpoint.clone())
        .accept(iroh_blobs::ALPN, blobs.clone())
        .spawn();

    // Initialize P2P client for validator communication (if configured)
    let validator_p2p_client = if let Some(ref node_id_str) = args.validator_node_id {
        match node_id_str.parse::<iroh::PublicKey>() {
            Ok(validator_node_id) => {
                info!(
                    validator_node_id = %validator_node_id,
                    "P2P validator client enabled"
                );
                Some(validator_p2p::ValidatorP2pClient::new(
                    endpoint.clone(),
                    validator_node_id,
                ))
            }
            Err(e) => {
                tracing::warn!(
                    error = %e,
                    node_id = %node_id_str,
                    "Invalid VALIDATOR_NODE_ID, P2P disabled"
                );
                None
            }
        }
    } else {
        None
    };

    // Determine P2P mode: default to true if we have a P2P client
    let use_p2p = args.use_p2p.unwrap_or(validator_p2p_client.is_some());
    let http_fallback = args.http_fallback.unwrap_or(true);

    if use_p2p && validator_p2p_client.is_none() {
        tracing::warn!(
            "USE_P2P=true but no VALIDATOR_NODE_ID configured, falling back to HTTP only"
        );
    }
    if use_p2p {
        info!(
            http_fallback = http_fallback,
            "P2P mode enabled for validator communication"
        );
    } else {
        info!("HTTP mode only for validator communication");
    }

    // Build application state
    let app_state = Arc::new(AppState {
        endpoint: endpoint.clone(),
        _store: store.clone(),
        cluster_map: Arc::new(Mutex::new(ClusterMap::new())),
        cluster_map_history: Arc::new(Mutex::new(Vec::new())),
        bandwidth_stats: Arc::new(DashMap::new()),
        miner_latency: Arc::new(DashMap::new()),
        miner_failures: Arc::new(Mutex::new(VecDeque::new())),
        validator_url: args.validator_url.clone(),
        blob_cache: Arc::new(Cache::new(config::BLOB_CACHE_MAX_ENTRIES)),
        metrics: Metrics::new(),
        upload_semaphore: Arc::new(tokio::sync::Semaphore::new(config::MAX_CONCURRENT_UPLOADS)),
        download_global_semaphore: Arc::new(tokio::sync::Semaphore::new(
            download_global_concurrency,
        )),
        download_request_parallelism,
        download_permit_timeout_ms,
        fetch_connect_timeout_secs,
        fetch_read_timeout_secs,
        auto_repair_hint_enabled,
        validator_gateway_key,
        repair_hint_last_sent: Arc::new(Mutex::new(HashMap::new())),
        repair_hint_min_interval_secs,
        repair_hint_count,
        repair_hint_allow_scan,
        connection_pool: Arc::new(tokio::sync::RwLock::new(HashMap::new())),
        miner_blacklist: Arc::new(DashMap::new()),
        doc_replica,
        doc_replica_blobs,
        http_client,
        rebalance_status_cache: Arc::new(DashMap::new()),
        validator_p2p_client,
        use_p2p,
        http_fallback,
    });

    // Build HTTP router
    let app = AxumRouter::new()
        .route(
            "/upload",
            post(handlers::upload_file)
                .layer(axum::middleware::from_fn(handlers::require_admin_key)),
        )
        .route(
            "/download/:hash",
            axum::routing::get(handlers::download_file),
        )
        .route(
            "/blobs/:hash",
            axum::routing::get(handlers::download_file).delete(handlers::delete_file),
        )
        .route("/stats", axum::routing::get(handlers::get_gateway_stats))
        .route("/metrics", axum::routing::get(handlers::metrics_handler))
        .layer(axum::extract::DefaultBodyLimit::max(5 * 1024 * 1024 * 1024)) // 5GB limit
        .with_state(app_state.clone());

    // Load TLS configuration
    let tls_config = TlsConfig::new("gateway")
        .map_err(|e| anyhow::anyhow!("Failed to initialize TLS config: {}", e))?;
    let rustls_config = OpenSSLConfig::from_pem_file(&tls_config.cert_path, &tls_config.key_path)
        .map_err(|e| anyhow::anyhow!("Failed to load TLS config: {}", e))?;

    let addr = std::net::SocketAddr::from(([0, 0, 0, 0], args.port));
    info!(addr = %addr, "Gateway listening (HTTPS)");

    // Spawn background tasks
    let state_clone = app_state.clone();
    let validator_url_clone = args.validator_url.clone();
    tokio::spawn(async move {
        background::sync_map_loop(state_clone, validator_url_clone).await;
    });

    let state_clone_bw = app_state.clone();
    let validator_url_clone_bw = args.validator_url.clone();
    tokio::spawn(async move {
        background::report_bandwidth_loop(state_clone_bw, validator_url_clone_bw).await;
    });

    let state_clone_fail = app_state.clone();
    let validator_url_clone_fail = args.validator_url.clone();
    tokio::spawn(async move {
        background::report_failures_loop(state_clone_fail, validator_url_clone_fail).await;
    });

    // Start HTTPS server
    axum_server::bind_openssl(addr, rustls_config)
        .serve(app.into_make_service())
        .await
        .map_err(|e| anyhow::anyhow!("HTTPS server error: {}", e))?;

    Ok(())
}

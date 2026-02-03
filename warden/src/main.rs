//! Warden - Proof-of-Storage audit service for Hippius Arion.

mod api;
mod attestation;
mod audit;
mod config;
mod p2p;
mod state;
mod submitter;
mod validator_p2p;

use anyhow::Result;
use axum::{
    Router, middleware as axum_middleware,
    routing::{delete, get, post},
};
use axum_server::tls_openssl::OpenSSLConfig;
use clap::Parser;
use common::middleware::validate_api_key;
use common::tls::TlsConfig;
use std::sync::Arc;
use tracing::info;
use tracing_subscriber::EnvFilter;

#[derive(Parser, Debug)]
#[command(author, version, about = "Warden - Proof-of-Storage audit service")]
struct Cli {
    /// Path to configuration file
    #[arg(short, long)]
    config: Option<String>,
}

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(EnvFilter::from_default_env())
        .init();

    let cli = Cli::parse();
    let config = Arc::new(config::load_config(cli.config.as_deref())?);

    info!(
        version = env!("CARGO_PKG_VERSION"),
        listen_addr = %config.listen_addr,
        audit_interval = config.audit_interval_secs,
        shards_per_audit = config.shards_per_audit,
        "Warden starting"
    );

    // Load or generate signing keypair
    let signing_key = Arc::new(attestation::load_or_generate_keypair(&config.keypair_path)?);
    let warden_id = *signing_key.verifying_key().as_bytes();
    info!(warden_id = hex::encode(warden_id), "Warden identity loaded");

    // Initialize state with sled persistence
    let warden_state = Arc::new(
        state::WardenState::open(
            &config.db_path,
            config.max_shards,
            config.max_pending_challenges,
        )
        .map_err(|e| anyhow::anyhow!("Failed to open warden database: {}", e))?,
    );
    let shards_loaded = warden_state
        .load_and_recover()
        .map_err(|e| anyhow::anyhow!("Failed to load warden state: {}", e))?;
    info!(shards_loaded, db_path = %config.db_path.display(), "Warden state recovered from disk");
    let app_state = Arc::new(api::AppState {
        warden: warden_state.clone(),
    });

    // Start audit scheduler in background
    let scheduler_config = config.clone();
    let scheduler_state = warden_state.clone();
    let scheduler_key = signing_key.clone();
    tokio::spawn(async move {
        audit::run_audit_loop(scheduler_config, scheduler_state, scheduler_key, warden_id).await;
    });

    // Build router with protected and open routes
    // Protected routes require X-API-Key authentication
    let protected_routes = Router::new()
        .route("/shards", post(api::push_shard))
        .route("/shards/{shard_hash}", delete(api::delete_shard))
        .layer(axum_middleware::from_fn(validate_api_key));

    // Open routes (health check)
    let open_routes = Router::new().route("/health", get(api::health));

    let app = Router::new()
        .merge(protected_routes)
        .merge(open_routes)
        .with_state(app_state);

    // Load TLS configuration
    let tls_config = TlsConfig::new("warden")
        .map_err(|e| anyhow::anyhow!("Failed to initialize TLS config: {}", e))?;
    let rustls_config = OpenSSLConfig::from_pem_file(&tls_config.cert_path, &tls_config.key_path)
        .map_err(|e| anyhow::anyhow!("Failed to load TLS configuration: {}", e))?;

    info!(addr = %config.listen_addr, "Warden listening (HTTPS)");

    axum_server::bind_openssl(config.listen_addr, rustls_config)
        .serve(app.into_make_service())
        .await?;

    Ok(())
}

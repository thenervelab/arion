//! Miner entry point for the Hippius Arion storage subnet.
//!
//! The miner receives shards from validators via P2P, stores them in Iroh's
//! FsStore, and serves them back to gateways and other miners on request.

mod config;
mod constants;
mod handlers;
mod helpers;
mod p2p;
mod rebalance;
mod state;

use constants::MAX_HTTP_BODY_SIZE;

use anyhow::Result;
use axum::{
    Router as AxumRouter,
    extract::DefaultBodyLimit,
    routing::{get, post},
};
use axum_server::tls_openssl::OpenSSLConfig;
use clap::Parser;
use common::now_secs;
use common::tls::TlsConfig;
use fs2::free_space;
use helpers::{load_keypair, truncate_for_log};
use iroh::protocol::Router;
use iroh_blobs::BlobsProtocol;
use iroh_blobs::store::fs::FsStore;
use p2p::MinerControlHandler;
use state::{AppState, get_blobs_dir, get_needs_reregistration, get_validator_endpoint};
use std::str::FromStr;
use std::sync::Arc;
use tracing::{debug, error, info, warn};
use tracing_subscriber::EnvFilter;

#[derive(Parser, Debug)]
#[command(author, version, about, long_about = None)]
struct Cli {
    #[command(subcommand)]
    command: Option<Commands>,

    // Default run mode args (for backward compatibility)
    /// Port to listen on
    #[arg(long, env = "PORT")]
    port: Option<u16>,

    /// Hostname of this miner
    #[arg(long, env = "HOSTNAME")]
    hostname: Option<String>,

    /// Storage path
    #[arg(long, env = "STORAGE_PATH")]
    storage_path: Option<String>,

    /// Family ID (e.g. Substrate SS58)
    #[arg(long, env = "FAMILY_ID")]
    family_id: Option<String>,

    /// Validator Node ID for P2P registration
    #[arg(long, env = "VALIDATOR_NODE_ID")]
    validator_node_id: Option<String>,

    /// Warden Node ID for PoS challenge authorization
    #[arg(long, env = "WARDEN_NODE_ID")]
    warden_node_id: Option<String>,
}

#[derive(clap::Subcommand, Debug)]
enum Commands {
    /// Backup miner identity to archive
    Backup {
        /// Data directory (default: data/miner)
        #[arg(short, long, default_value = "data/miner")]
        data_dir: String,
        /// Output file path (default: miner-backup-{timestamp}.tar.gz)
        #[arg(short, long)]
        output: Option<String>,
    },
    /// Restore miner identity from archive
    Restore {
        /// Archive file to restore from
        file: String,
        /// Target data directory (default: data/miner)
        #[arg(short, long, default_value = "data/miner")]
        data_dir: String,
    },
}

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(EnvFilter::from_default_env())
        .init();

    let cli = Cli::parse();

    // Handle backup/restore subcommands
    if let Some(command) = cli.command {
        return handle_subcommand(command).await;
    }

    // Default: run miner service
    run_miner(cli).await
}

async fn handle_subcommand(command: Commands) -> Result<()> {
    use std::path::Path;

    match command {
        Commands::Backup { data_dir, output } => {
            let data_path = Path::new(&data_dir);

            if !data_path.exists() {
                anyhow::bail!("Data directory not found: {}", data_dir);
            }

            info!(data_dir = %data_dir, "Backing up miner node");

            // Generate filename with timestamp
            let now = chrono::Utc::now().format("%Y-%m-%dT%H-%M-%S");
            let filename = output.unwrap_or_else(|| format!("miner-backup-{}.tar.gz", now));

            // Create tar.gz archive
            let file = std::fs::File::create(&filename)?;
            let encoder = flate2::write::GzEncoder::new(file, flate2::Compression::default());
            let mut archive = tar::Builder::new(encoder);

            // Files to backup
            let files_to_backup = ["keypair.txt"];

            let mut backed_up = 0;
            for file_name in &files_to_backup {
                let file_path = data_path.join(file_name);
                if file_path.exists() {
                    archive.append_path_with_name(&file_path, file_name)?;
                    debug!(file = %file_name, "Backed up file");
                    backed_up += 1;
                } else {
                    warn!(file = %file_name, "File not found, skipping");
                }
            }

            archive.finish()?;

            info!(filename = %filename, files_backed_up = backed_up, "Backup complete");
            warn!("Keep this file secure - it contains your miner identity");

            Ok(())
        }
        Commands::Restore { file, data_dir } => {
            let archive_path = Path::new(&file);
            let data_path = Path::new(&data_dir);

            if !archive_path.exists() {
                anyhow::bail!("Backup file not found: {}", file);
            }

            // Create directory and get canonical path for path traversal validation
            std::fs::create_dir_all(data_path)?;
            let canonical_data_path = data_path.canonicalize()?;

            info!(data_dir = %data_dir, "Restoring miner node");

            // Warn if directory already has identity
            let keypair_path = canonical_data_path.join("keypair.txt");
            if keypair_path.exists() {
                warn!(data_dir = %data_dir, "Existing keypair.txt found - will OVERWRITE existing miner identity");
                warn!("Press Ctrl+C to cancel, or wait 5 seconds to continue...");
                std::thread::sleep(std::time::Duration::from_secs(5));
            }

            // Extract archive
            let file = std::fs::File::open(archive_path)?;
            let decoder = flate2::read::GzDecoder::new(file);
            let mut archive = tar::Archive::new(decoder);

            // Allowed file names for restore (whitelist approach)
            let allowed_files: std::collections::HashSet<&str> =
                ["keypair.txt"].iter().copied().collect();

            let mut restored = 0;
            for entry in archive.entries()? {
                let mut entry = entry?;
                let path = entry.path()?;

                // Security: Validate path to prevent directory traversal attacks
                let path_str = path.to_string_lossy();
                if path_str.contains("..") || path_str.starts_with('/') {
                    warn!(
                        path = %path_str,
                        "Skipping entry with suspicious path (potential path traversal)"
                    );
                    continue;
                }

                // Only allow whitelisted file names
                let file_name = path.file_name().and_then(|n| n.to_str()).unwrap_or("");
                if !allowed_files.contains(file_name) {
                    warn!(
                        path = %path_str,
                        "Skipping entry not in allowed file list"
                    );
                    continue;
                }

                // Construct destination and verify it's within data_path
                let dest = canonical_data_path.join(file_name);
                if !dest.starts_with(&canonical_data_path) {
                    warn!(
                        path = %path_str,
                        dest = %dest.display(),
                        "Skipping entry that would escape data directory"
                    );
                    continue;
                }

                debug!(path = %path.display(), "Restoring file");
                entry.unpack(&dest)?;
                restored += 1;
            }

            info!(files_restored = restored, "Restore complete");
            info!("Restart the miner service for changes to take effect");

            Ok(())
        }
    }
}

async fn run_miner(cli: Cli) -> Result<()> {
    info!(version = env!("CARGO_PKG_VERSION"), "Starting miner");

    // Load config from TOML file with env overrides
    let config = match config::MinerConfig::load(None) {
        Ok(c) => c,
        Err(e) => {
            warn!(error = %e, "Config load warning, using defaults");
            config::MinerConfig::default()
        }
    };

    // CLI args override config file values
    let port = cli.port.unwrap_or(config.network.port);
    let hostname = cli
        .hostname
        .or(config.network.hostname.clone())
        .unwrap_or_else(|| "miner-1".to_string());
    let family_id = cli
        .family_id
        .unwrap_or_else(|| config.network.family_id.clone());
    let data_dir = std::path::PathBuf::from(&config.storage.data_dir);
    let validator_node_id = cli.validator_node_id.or(config.validator.node_id.clone());
    let warden_node_id = cli
        .warden_node_id
        .or(config.validator.warden_node_id.clone());

    info!(
        port = port,
        hostname = %hostname,
        family_id = %family_id,
        data_dir = %data_dir.display(),
        validator_node_id = ?validator_node_id.as_ref().map(|n| truncate_for_log(n, 16)),
        "Configuration loaded"
    );

    // 1. Initialize Iroh Endpoint
    tokio::fs::create_dir_all(&data_dir).await?;

    let secret_key = load_keypair(&data_dir).await?;

    // Get relay URL from config, environment, or use default
    let relay_url_value = common::get_relay_url(config.network.relay_url.as_deref());
    info!(relay_url = %relay_url_value, "Configuring relay");
    // Wrap in Option for compatibility with existing function signatures
    let relay_url: Option<iroh_base::RelayUrl> = Some(relay_url_value.clone());

    let mut endpoint_builder = iroh::Endpoint::builder()
        .secret_key(secret_key)
        .bind_addr_v4(std::net::SocketAddrV4::new(
            std::net::Ipv4Addr::UNSPECIFIED,
            config.network.p2p_port,
        ));

    // Configure transport with keep-alive to maintain relay connections
    let mut transport_config = iroh::endpoint::TransportConfig::default();
    transport_config.keep_alive_interval(Some(std::time::Duration::from_secs(15)));
    if let Ok(idle_timeout) = std::time::Duration::from_secs(60).try_into() {
        transport_config.max_idle_timeout(Some(idle_timeout));
    }
    endpoint_builder = endpoint_builder.transport_config(transport_config);

    // Configure relay using consistent pattern from common crate
    endpoint_builder = endpoint_builder.relay_mode(common::build_relay_mode(&relay_url_value));

    let endpoint = endpoint_builder.bind().await?;

    let node_id = endpoint.secret_key().public();
    info!(node_id = %node_id, "Iroh endpoint bound");

    // Wait for relay connection to establish before attempting P2P
    info!(
        wait_secs = common::RELAY_CONNECTION_WAIT_SECS,
        "Waiting for relay connection"
    );
    tokio::time::sleep(tokio::time::Duration::from_secs(
        common::RELAY_CONNECTION_WAIT_SECS,
    ))
    .await;
    info!("Ready for P2P connections");

    // 2. Initialize FsStore for persistent blob storage
    let blobs_dir = data_dir.join("blobs");
    tokio::fs::create_dir_all(&blobs_dir).await?;
    let store = FsStore::load(blobs_dir.clone()).await?;
    info!(path = %blobs_dir.display(), "Initialized persistent blob storage");

    // Store blobs_dir globally for GC access
    {
        let mut bd = get_blobs_dir().write().await;
        *bd = Some(blobs_dir.clone());
    }

    // 3. Register with Validator via P2P
    let http_addr = format!("http://{}:{}", hostname, port);

    let validator_node_id_str = validator_node_id.ok_or_else(|| {
        anyhow::anyhow!(
            "VALIDATOR_NODE_ID is required for P2P registration (set via config or env)"
        )
    })?;

    let validator_pubkey = iroh::PublicKey::from_str(&validator_node_id_str)
        .map_err(|e| anyhow::anyhow!("Invalid VALIDATOR_NODE_ID format: {}", e))?;

    // Parse warden node ID if provided (optional)
    let warden_pubkey = warden_node_id
        .as_ref()
        .map(|id| {
            iroh::PublicKey::from_str(id)
                .map_err(|e| anyhow::anyhow!("Invalid WARDEN_NODE_ID format: {}", e))
        })
        .transpose()?;

    if let Some(ref warden_id) = warden_node_id {
        info!(warden = %truncate_for_log(warden_id, 16), "Warden PoS challenges authorized");
    }

    info!(validator = %truncate_for_log(&validator_node_id_str, 16), "Registering with validator via P2P");

    // P2P Registration Loop with exponential backoff
    register_with_validator(
        &endpoint,
        &validator_pubkey,
        &relay_url,
        &hostname,
        &http_addr,
        &family_id,
        &data_dir,
        &config,
    )
    .await?;

    // 4. Initialize Blobs Protocol and Router
    let blobs = BlobsProtocol::new(&store, None);

    let store_concurrency = std::cmp::max(1, config.tuning.store_concurrency);
    let pull_concurrency = std::cmp::max(1, config.tuning.pull_concurrency);
    let fetch_concurrency = std::cmp::max(1, config.tuning.fetch_concurrency);

    // PoS proof generation is CPU-intensive, limit concurrency
    let pos_concurrency = std::cmp::max(1, config.tuning.pos_concurrency.unwrap_or(2));

    let miner_control_handler = MinerControlHandler {
        store: store.clone(),
        endpoint: endpoint.clone(),
        store_sem: Arc::new(tokio::sync::Semaphore::new(store_concurrency)),
        pull_sem: Arc::new(tokio::sync::Semaphore::new(pull_concurrency)),
        fetch_sem: Arc::new(tokio::sync::Semaphore::new(fetch_concurrency)),
        pos_sem: Arc::new(tokio::sync::Semaphore::new(pos_concurrency)),
        validator_node_id: Some(validator_pubkey),
        warden_node_id: warden_pubkey,
    };
    let _router = Router::builder(endpoint.clone())
        .accept(iroh_blobs::ALPN, blobs.clone())
        .accept(b"hippius/miner-control", miner_control_handler)
        .spawn();

    // 5. Start P2P Heartbeat Loop
    spawn_heartbeat_loop(
        endpoint.clone(),
        validator_pubkey,
        relay_url.clone(),
        hostname.clone(),
        data_dir.clone(),
        config.storage.max_storage_gb,
        family_id.clone(),
        config.clone(),
    );

    // 6. Start Self-Rebalance Loop (if enabled)
    if config.tuning.rebalance_enabled {
        let store_rebalance = store.clone();
        let endpoint_rebalance = endpoint.clone();
        let tick_secs = config.tuning.rebalance_tick_secs;

        tokio::spawn(async move {
            // Initial delay to let the miner settle after startup
            tokio::time::sleep(std::time::Duration::from_secs(60)).await;

            loop {
                if let Err(e) = rebalance::self_rebalance_pg(
                    store_rebalance.clone(),
                    endpoint_rebalance.clone(),
                )
                .await
                {
                    error!(error = %e, "Self-rebalance failed");
                }

                tokio::time::sleep(std::time::Duration::from_secs(tick_secs)).await;
            }
        });

        info!(tick_secs = tick_secs, "Miner self-rebalance loop started");
    } else {
        info!("Miner self-rebalance disabled (set MINER_REBALANCE_ENABLED=true to enable)");
    }

    // 7. Miner HTTP server (DISABLED BY DEFAULT)
    let http_enabled = std::env::var("MINER_HTTP_ENABLED")
        .ok()
        .map(|v| v != "0" && v.to_lowercase() != "false")
        .unwrap_or(false);

    if http_enabled {
        let state = AppState {
            endpoint: endpoint.clone(),
            store: store.clone(),
        };
        let app = AxumRouter::new()
            .route("/blobs/add", post(handlers::add_blob))
            .route("/blobs/:hash", get(handlers::get_blob))
            .route("/status", get(handlers::status))
            .layer(DefaultBodyLimit::max(MAX_HTTP_BODY_SIZE)) // Bounded to prevent OOM attacks
            .layer(axum::middleware::from_fn(handlers::log_request))
            .fallback(handlers::fallback_handler)
            .with_state(state);

        let addr = std::net::SocketAddr::from(([0, 0, 0, 0], port));

        // Load TLS configuration
        let tls_config = TlsConfig::new("miner")
            .map_err(|e| anyhow::anyhow!("Failed to initialize TLS config: {}", e))?;
        let rustls_config =
            OpenSSLConfig::from_pem_file(&tls_config.cert_path, &tls_config.key_path)
                .map_err(|e| anyhow::anyhow!("Failed to load TLS configuration: {}", e))?;

        info!(addr = %addr, "Miner HTTP server listening (HTTPS)");
        axum_server::bind_openssl(addr, rustls_config)
            .serve(app.into_make_service())
            .await?;
        Ok(())
    } else {
        info!("Miner HTTP server disabled (set MINER_HTTP_ENABLED=true to enable for dev)");

        // Keep process alive: miner runs purely on P2P
        tokio::signal::ctrl_c().await?;
        Ok(())
    }
}

#[allow(clippy::too_many_arguments)]
async fn register_with_validator(
    endpoint: &iroh::Endpoint,
    validator_pubkey: &iroh::PublicKey,
    relay_url: &Option<iroh_base::RelayUrl>,
    hostname: &str,
    http_addr: &str,
    family_id: &str,
    data_dir: &std::path::Path,
    config: &config::MinerConfig,
) -> Result<()> {
    let initial_backoff = config.tuning.initial_backoff_secs;
    let max_backoff = config.tuning.max_backoff_secs;
    let mut retry_count: u32 = 0;

    loop {
        // Calculate storage stats
        let available = free_space(data_dir).unwrap_or(0);
        let total = fs2::total_space(data_dir).unwrap_or(0);

        // Respect max_storage config if set
        let reported_available = if config.storage.max_storage_gb > 0 {
            std::cmp::min(
                available,
                config
                    .storage
                    .max_storage_gb
                    .saturating_mul(1024 * 1024 * 1024),
            )
        } else {
            available
        };

        let register_msg = {
            let public_key_str = endpoint.secret_key().public().to_string();
            let timestamp = now_secs();

            // Sign "REGISTER:{public_key}:{timestamp}"
            let sign_data = format!("REGISTER:{}:{}", public_key_str, timestamp);
            let signature = endpoint.secret_key().sign(sign_data.as_bytes());

            // Construct our EndpointAddr with relay hints
            let node_id = endpoint.secret_key().public();
            let my_endpoint_addr = {
                let mut addr = iroh::EndpointAddr::new(node_id);
                if let Some(url) = relay_url {
                    debug!(node_id = %node_id, relay = %url, "My endpoint address");
                    addr = addr.with_relay_url(url.clone());
                } else {
                    debug!(node_id = %node_id, relay = "default", "My endpoint address");
                }

                // Add direct address hint from hostname
                let ip_opt = if hostname == "localhost" {
                    Some(std::net::IpAddr::V4(std::net::Ipv4Addr::LOCALHOST))
                } else {
                    hostname.parse::<std::net::IpAddr>().ok()
                };

                if let Some(ip) = ip_opt {
                    let direct_addr = std::net::SocketAddr::new(ip, config.network.p2p_port);
                    let transport_addr = iroh::TransportAddr::Ip(direct_addr);
                    addr = addr.with_addrs(vec![transport_addr]);
                    debug!(addr = %direct_addr, "Added direct address hint");
                }

                Some(addr)
            };

            common::ValidatorControlMessage::Register {
                public_key: public_key_str,
                http_addr: http_addr.to_string(),
                total_storage: total,
                available_storage: reported_available,
                family_id: family_id.to_string(),
                timestamp,
                signature: signature.to_bytes().to_vec(),
                endpoint_addr: my_endpoint_addr,
            }
        };

        // Connect to validator via P2P
        let mut validator_addr = iroh::EndpointAddr::new(*validator_pubkey);
        if let Some(url) = relay_url {
            validator_addr = validator_addr.with_relay_url(url.clone());
        }

        // Add direct address hint for localhost
        if hostname == "localhost" {
            let direct_addr =
                std::net::SocketAddr::new(std::net::Ipv4Addr::new(127, 0, 0, 1).into(), 11220);
            validator_addr = validator_addr.with_addrs(vec![iroh::TransportAddr::Ip(direct_addr)]);
            debug!(addr = %direct_addr, "Added direct validator address hint");
        }

        // Calculate exponential backoff with jitter
        let backoff_secs = std::cmp::min(
            max_backoff,
            initial_backoff.saturating_mul(2u64.saturating_pow(retry_count)),
        );

        match endpoint
            .connect(validator_addr.clone(), b"hippius/validator-control")
            .await
        {
            Ok(conn) => {
                match async {
                    let (mut send, mut recv) = conn.open_bi().await?;
                    let msg_bytes = serde_json::to_vec(&register_msg)?;
                    debug!("Sending registration message");
                    send.write_all(&msg_bytes).await?;
                    send.finish()?;
                    let _ = send.stopped().await;
                    debug!("Message sent, waiting for ACK");

                    // Wait for ACK
                    let ack = recv.read_to_end(4096).await?;
                    let ack_str = String::from_utf8_lossy(&ack);
                    debug!(ack = %ack_str, "Received ACK");

                    match ack_str.as_ref() {
                        "OK" => Ok::<_, anyhow::Error>(()),
                        "RATE_LIMITED" => Err(anyhow::anyhow!("RATE_LIMITED")),
                        _ if ack_str.starts_with("FAMILY_REJECTED:") => {
                            Err(anyhow::anyhow!("{ack_str}"))
                        }
                        _ => Err(anyhow::anyhow!("Registration failed: {ack_str}")),
                    }
                }
                .await
                {
                    Ok(()) => {
                        info!("Registered with validator via P2P");
                        // Store validator endpoint for later PG queries
                        {
                            let mut val_ep = get_validator_endpoint().write().await;
                            *val_ep = Some(validator_addr.clone());
                        }
                        return Ok(());
                    }
                    Err(e) => {
                        retry_count = retry_count.saturating_add(1);
                        error!(
                            error = %e,
                            backoff_secs = backoff_secs,
                            attempt = retry_count,
                            "P2P registration error, retrying"
                        );
                    }
                }
            }
            Err(e) => {
                retry_count = retry_count.saturating_add(1);
                error!(
                    error = %e,
                    backoff_secs = backoff_secs,
                    attempt = retry_count,
                    "Failed to connect to validator, retrying"
                );
            }
        }
        tokio::time::sleep(tokio::time::Duration::from_secs(backoff_secs)).await;
    }
}

/// Interval (in heartbeat cycles) at which to refresh validator address from environment
const VALIDATOR_ADDR_REFRESH_INTERVAL: u32 = 10;

#[allow(clippy::too_many_arguments)]
fn spawn_heartbeat_loop(
    endpoint: iroh::Endpoint,
    validator_pubkey: iroh::PublicKey,
    relay_url: Option<iroh_base::RelayUrl>,
    hostname: String,
    data_dir: std::path::PathBuf,
    max_storage_gb: u64,
    family_id: String,
    config: config::MinerConfig,
) {
    let mut hasher = std::collections::hash_map::DefaultHasher::new();
    use std::hash::{Hash, Hasher};
    endpoint.secret_key().public().to_string().hash(&mut hasher);
    let miner_uid = (hasher.finish() as u32) & 0x7FFFFFFF;

    tokio::spawn(async move {
        let mut heartbeat_count: u32 = 0;
        let mut current_validator_pubkey = validator_pubkey;

        // Build initial validator address
        let build_validator_addr = |pubkey: &iroh::PublicKey,
                                    relay: &Option<iroh_base::RelayUrl>,
                                    host: &str|
         -> iroh::EndpointAddr {
            let mut addr = iroh::EndpointAddr::new(*pubkey);
            if let Some(url) = relay {
                addr = addr.with_relay_url(url.clone());
            }
            // Add direct address hint for localhost
            if host == "localhost" {
                let direct_addr =
                    std::net::SocketAddr::new(std::net::Ipv4Addr::new(127, 0, 0, 1).into(), 11220);
                addr = addr.with_addrs(vec![iroh::TransportAddr::Ip(direct_addr)]);
            }
            addr
        };

        let mut heartbeat_validator_addr =
            build_validator_addr(&current_validator_pubkey, &relay_url, &hostname);

        loop {
            // Check if re-registration is needed
            if get_needs_reregistration().load(std::sync::atomic::Ordering::SeqCst) {
                info!("Re-registration flag set, performing re-registration");

                // Clear the flag first
                get_needs_reregistration().store(false, std::sync::atomic::Ordering::SeqCst);

                // Perform re-registration
                let http_addr = format!("http://{}:{}", hostname, config.network.port);
                match register_with_validator_once(
                    &endpoint,
                    &current_validator_pubkey,
                    &relay_url,
                    &hostname,
                    &http_addr,
                    &family_id,
                    &data_dir,
                    &config,
                )
                .await
                {
                    Ok(()) => {
                        info!("Re-registration successful");
                        // Update stored validator endpoint
                        let new_addr =
                            build_validator_addr(&current_validator_pubkey, &relay_url, &hostname);
                        {
                            let mut val_ep = get_validator_endpoint().write().await;
                            *val_ep = Some(new_addr.clone());
                        }
                        heartbeat_validator_addr = new_addr;
                    }
                    Err(e) => {
                        error!(error = %e, "Re-registration failed, will retry on next heartbeat");
                        // Set flag again to retry
                        get_needs_reregistration().store(true, std::sync::atomic::Ordering::SeqCst);
                        tokio::time::sleep(tokio::time::Duration::from_secs(5)).await;
                        continue;
                    }
                }
            }

            // Periodically refresh validator address from environment
            heartbeat_count = heartbeat_count.wrapping_add(1);
            if heartbeat_count % VALIDATOR_ADDR_REFRESH_INTERVAL == 0
                && let Ok(new_validator_id) = std::env::var("VALIDATOR_NODE_ID")
                && let Ok(new_pubkey) = iroh::PublicKey::from_str(&new_validator_id)
                && new_pubkey != current_validator_pubkey
            {
                info!(
                    old = %truncate_for_log(&current_validator_pubkey.to_string(), 16),
                    new = %truncate_for_log(&new_validator_id, 16),
                    "Validator address refreshed from environment"
                );
                current_validator_pubkey = new_pubkey;
                heartbeat_validator_addr =
                    build_validator_addr(&current_validator_pubkey, &relay_url, &hostname);

                // Update stored validator endpoint
                {
                    let mut val_ep = get_validator_endpoint().write().await;
                    *val_ep = Some(heartbeat_validator_addr.clone());
                }

                // Trigger re-registration with new validator
                get_needs_reregistration().store(true, std::sync::atomic::Ordering::SeqCst);
                continue;
            }

            let timestamp = now_secs();

            // Calculate available storage
            let available = free_space(&data_dir).unwrap_or(0);
            let reported_available = if max_storage_gb > 0 {
                std::cmp::min(available, max_storage_gb * 1024 * 1024 * 1024)
            } else {
                available
            };

            let heartbeat_msg = {
                let public_key_str = endpoint.secret_key().public().to_string();

                // Sign "HEARTBEAT:{public_key}:{timestamp}"
                let sign_data = format!("HEARTBEAT:{}:{}", public_key_str, timestamp);
                let signature = endpoint.secret_key().sign(sign_data.as_bytes());

                common::ValidatorControlMessage::Heartbeat {
                    miner_uid,
                    timestamp,
                    available_storage: reported_available,
                    public_key: public_key_str,
                    signature: signature.to_bytes().to_vec(),
                }
            };

            // Connect to validator via P2P for heartbeat with timeout
            let connect_result = tokio::time::timeout(
                std::time::Duration::from_secs(10),
                endpoint.connect(
                    heartbeat_validator_addr.clone(),
                    b"hippius/validator-control",
                ),
            )
            .await;

            match connect_result {
                Ok(Ok(conn)) => {
                    let result = async {
                        // Open stream with timeout
                        let (mut send, mut recv) =
                            tokio::time::timeout(std::time::Duration::from_secs(5), conn.open_bi())
                                .await??;

                        let msg_bytes = serde_json::to_vec(&heartbeat_msg)?;
                        send.write_all(&msg_bytes).await?;
                        send.finish()?;
                        let _ = send.stopped().await;

                        // Read ACK with timeout
                        let ack_bytes = tokio::time::timeout(
                            std::time::Duration::from_secs(5),
                            recv.read_to_end(1024),
                        )
                        .await??;

                        let ack_str = String::from_utf8_lossy(&ack_bytes);
                        if ack_str.starts_with("FAMILY_REJECTED:") {
                            error!(response = %ack_str, "Heartbeat rejected");
                            std::process::exit(1);
                        }
                        if ack_str == "UNKNOWN" {
                            warn!("Validator returned UNKNOWN - triggering re-registration");
                            // Signal that re-registration is needed
                            get_needs_reregistration()
                                .store(true, std::sync::atomic::Ordering::SeqCst);
                            return Err(anyhow::anyhow!("Re-registration needed"));
                        }

                        Ok::<_, anyhow::Error>(())
                    }
                    .await;

                    if let Err(e) = result {
                        warn!(error = %e, "Heartbeat error");
                    }
                }
                Ok(Err(e)) => {
                    warn!(error = %e, "Heartbeat connection failed");
                }
                Err(_) => {
                    warn!("Heartbeat connection timed out");
                }
            }

            tokio::time::sleep(tokio::time::Duration::from_secs(30)).await;
        }
    });
}

/// Perform a single registration attempt with the validator (for re-registration)
#[allow(clippy::too_many_arguments)]
async fn register_with_validator_once(
    endpoint: &iroh::Endpoint,
    validator_pubkey: &iroh::PublicKey,
    relay_url: &Option<iroh_base::RelayUrl>,
    hostname: &str,
    http_addr: &str,
    family_id: &str,
    data_dir: &std::path::Path,
    config: &config::MinerConfig,
) -> Result<()> {
    // Calculate storage stats
    let available = free_space(data_dir).unwrap_or(0);
    let total = fs2::total_space(data_dir).unwrap_or(0);

    // Respect max_storage config if set
    let reported_available = if config.storage.max_storage_gb > 0 {
        std::cmp::min(
            available,
            config
                .storage
                .max_storage_gb
                .saturating_mul(1024 * 1024 * 1024),
        )
    } else {
        available
    };

    let register_msg = {
        let public_key_str = endpoint.secret_key().public().to_string();
        let timestamp = now_secs();

        // Sign "REGISTER:{public_key}:{timestamp}"
        let sign_data = format!("REGISTER:{}:{}", public_key_str, timestamp);
        let signature = endpoint.secret_key().sign(sign_data.as_bytes());

        // Construct our EndpointAddr with relay hints
        let node_id = endpoint.secret_key().public();
        let my_endpoint_addr = {
            let mut addr = iroh::EndpointAddr::new(node_id);
            if let Some(url) = relay_url {
                addr = addr.with_relay_url(url.clone());
            }

            // Add direct address hint from hostname
            let ip_opt = if hostname == "localhost" {
                Some(std::net::IpAddr::V4(std::net::Ipv4Addr::LOCALHOST))
            } else {
                hostname.parse::<std::net::IpAddr>().ok()
            };

            if let Some(ip) = ip_opt {
                let direct_addr = std::net::SocketAddr::new(ip, config.network.p2p_port);
                let transport_addr = iroh::TransportAddr::Ip(direct_addr);
                addr = addr.with_addrs(vec![transport_addr]);
            }

            Some(addr)
        };

        common::ValidatorControlMessage::Register {
            public_key: public_key_str,
            http_addr: http_addr.to_string(),
            total_storage: total,
            available_storage: reported_available,
            family_id: family_id.to_string(),
            timestamp,
            signature: signature.to_bytes().to_vec(),
            endpoint_addr: my_endpoint_addr,
        }
    };

    // Connect to validator via P2P
    let mut validator_addr = iroh::EndpointAddr::new(*validator_pubkey);
    if let Some(url) = relay_url {
        validator_addr = validator_addr.with_relay_url(url.clone());
    }

    // Add direct address hint for localhost
    if hostname == "localhost" {
        let direct_addr =
            std::net::SocketAddr::new(std::net::Ipv4Addr::new(127, 0, 0, 1).into(), 11220);
        validator_addr = validator_addr.with_addrs(vec![iroh::TransportAddr::Ip(direct_addr)]);
    }

    let conn = tokio::time::timeout(
        std::time::Duration::from_secs(10),
        endpoint.connect(validator_addr.clone(), b"hippius/validator-control"),
    )
    .await
    .map_err(|_| anyhow::anyhow!("Connection timeout"))?
    .map_err(|e| anyhow::anyhow!("Connection failed: {}", e))?;

    let (mut send, mut recv) = conn.open_bi().await?;
    let msg_bytes = serde_json::to_vec(&register_msg)?;
    send.write_all(&msg_bytes).await?;
    send.finish()?;
    let _ = send.stopped().await;

    // Wait for ACK
    let ack = tokio::time::timeout(std::time::Duration::from_secs(10), recv.read_to_end(4096))
        .await
        .map_err(|_| anyhow::anyhow!("ACK timeout"))??;

    let ack_str = String::from_utf8_lossy(&ack);
    match ack_str.as_ref() {
        "OK" => Ok(()),
        "RATE_LIMITED" => Err(anyhow::anyhow!("RATE_LIMITED")),
        _ if ack_str.starts_with("FAMILY_REJECTED:") => Err(anyhow::anyhow!("{ack_str}")),
        _ => Err(anyhow::anyhow!("Registration failed: {ack_str}")),
    }
}

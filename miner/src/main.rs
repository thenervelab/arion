//! Miner entry point for the Hippius Arion storage subnet.
//!
//! The miner receives shards from validators via P2P (quinn QUIC), stores them
//! in a flat file store, and serves them back to gateways and other miners on request.

mod config;
mod constants;
mod doc_replica;
mod flat_store;
mod gateway_keepalive;
mod helpers;
mod p2p;
mod rebalance;
mod state;
mod version_check;

use anyhow::Result;
use clap::Parser;
use common::now_secs;
use flat_store::FlatBlobStore;
use fs2::free_space;
use helpers::{load_keypair, truncate_for_log};
use p2p::MinerControlHandler;
use rand::Rng as _;
use state::{
    get_blobs_dir, get_needs_reregistration,
    get_validator_reachable, get_warden_node_ids,
};
use std::net::SocketAddr;
use std::sync::Arc;
use tokio_util::sync::CancellationToken;
use tracing::{debug, error, info, warn};
use tracing_subscriber::EnvFilter;

#[derive(Parser, Debug)]
#[command(author, version, about, long_about = None)]
struct Cli {
    #[command(subcommand)]
    command: Option<Commands>,

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
    // Install rustls crypto provider for quinn/TLS
    rustls::crypto::ring::default_provider()
        .install_default()
        .expect("Failed to install rustls CryptoProvider");

    tracing_subscriber::fmt()
        .with_env_filter(
            EnvFilter::from_default_env()
                .add_directive("iroh_docs::engine::live=error".parse().unwrap())
                .add_directive("iroh_gossip=error".parse().unwrap()),
        )
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
            let files_to_backup = ["keypair.bin"];

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
            let keypair_path = canonical_data_path.join("keypair.bin");
            if keypair_path.exists() {
                warn!(data_dir = %data_dir, "Existing keypair.bin found - will OVERWRITE existing miner identity");
                warn!("Press Ctrl+C to cancel, or wait 5 seconds to continue...");
                tokio::time::sleep(std::time::Duration::from_secs(5)).await;
            }

            // Extract archive
            let file = std::fs::File::open(archive_path)?;
            let decoder = flate2::read::GzDecoder::new(file);
            let mut archive = tar::Archive::new(decoder);

            // Allowed file names for restore (whitelist approach)
            let allowed_files: std::collections::HashSet<&str> =
                ["keypair.bin"].iter().copied().collect();

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

/// Shared context for registration and heartbeat functions.
#[derive(Clone)]
struct MinerContext {
    endpoint: quinn::Endpoint,
    signing_key: Arc<ed25519_dalek::SigningKey>,
    node_id: String,
    validator_node_id: String,
    validator_socket_addr: SocketAddr,
    hostname: String,
    family_id: String,
    data_dir: std::path::PathBuf,
    config: config::MinerConfig,
    /// STUN-detected public IP, used as fallback when hostname resolves to
    /// a non-routable address (e.g. `--hostname 0.0.0.0`).
    stun_public_ip: Option<std::net::IpAddr>,
}

impl MinerContext {
    fn http_addr(&self) -> String {
        format!("http://{}:{}", self.hostname, self.config.network.p2p_port)
    }

    /// Resolve the configured hostname to an IP address.
    fn resolve_hostname_ip(&self) -> Option<std::net::IpAddr> {
        if self.hostname == "localhost" {
            Some(std::net::IpAddr::V4(std::net::Ipv4Addr::LOCALHOST))
        } else if let Ok(ip) = self.hostname.parse::<std::net::IpAddr>() {
            Some(ip)
        } else {
            use std::net::ToSocketAddrs;
            format!("{}:{}", self.hostname, self.config.network.p2p_port)
                .to_socket_addrs()
                .ok()
                .and_then(|mut addrs| addrs.find(|a| a.is_ipv4()))
                .map(|a| a.ip())
        }
    }

    /// Build our `EndpointAddr` for protocol messages to the validator.
    /// The validator still expects iroh::EndpointAddr format for backward compat.
    fn build_endpoint_addr(&self) -> iroh::EndpointAddr {
        // Convert our ed25519 public key to iroh PublicKey for EndpointAddr
        let iroh_pk = iroh::PublicKey::from_bytes(self.signing_key.verifying_key().as_bytes())
            .expect("valid ed25519 public key");
        let mut addr = iroh::EndpointAddr::new(iroh_pk);

        // Resolve direct address: hostname first, STUN fallback second
        let resolved_ip = self
            .resolve_hostname_ip()
            .filter(|ip| common::is_advertisable_ip(*ip))
            .or(self.stun_public_ip);
        if let Some(ip) = resolved_ip {
            let direct_addr = SocketAddr::new(ip, self.config.network.p2p_port);
            addr = addr.with_addrs(vec![iroh::TransportAddr::Ip(direct_addr)]);
        } else {
            warn!(
                hostname = %self.hostname,
                stun_ip = ?self.stun_public_ip,
                "No advertisable IP for endpoint: set --hostname to your public IP"
            );
        }
        addr
    }

    /// Sign a message with the miner's Ed25519 key.
    fn sign(&self, message: &[u8]) -> ed25519_dalek::Signature {
        use ed25519_dalek::Signer;
        self.signing_key.sign(message)
    }
}

async fn run_miner(cli: Cli) -> Result<()> {
    info!(version = env!("CARGO_PKG_VERSION"), "Starting miner");
    // Version check + auto-update spawned after data_dir is known (below).

    // Preflight: check firewall/conntrack settings that can silently kill QUIC
    check_network_health();

    // Load config from TOML file with env overrides
    let config = match config::MinerConfig::load(None) {
        Ok(c) => c,
        Err(e) => {
            warn!(error = %e, "Config load warning, using defaults");
            config::MinerConfig::default()
        }
    };

    // STUN-based public IP auto-detection (runs before hostname/bind resolution)
    let stun_ipv4 = if config.network.auto_detect_ip {
        info!("Running STUN public IP detection...");
        let stun_timeout = std::time::Duration::from_secs(constants::STUN_TIMEOUT_SECS);
        let result = common::stun::detect_public_ipv4(stun_timeout).await;
        if let Some(ref r) = result {
            info!(ip = %r.ip, "STUN detected public IPv4");
        } else {
            warn!(
                "STUN IPv4 detection returned no result — falling back to manual config or defaults"
            );
        }
        result
    } else {
        debug!("STUN auto-detection disabled");
        None
    };

    // CLI args override config file values.
    let hostname = cli
        .hostname
        .or(config.network.hostname.clone())
        .or_else(|| stun_ipv4.as_ref().map(|r| r.ip.to_string()))
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
        hostname = %hostname,
        family_id = %family_id,
        data_dir = %data_dir.display(),
        validator_node_id = ?validator_node_id.as_ref().map(|n| truncate_for_log(n, 16)),
        "Configuration loaded"
    );

    // Spawn auto-update loop (periodic version check + download + restart).
    tokio::spawn(version_check::auto_update_loop(data_dir.clone()));

    // 1. Initialize quinn endpoint
    tokio::fs::create_dir_all(&data_dir).await?;

    let signing_key = load_keypair(&data_dir).await?;
    let node_id = common::transport::node_id_from_public_key(&signing_key.verifying_key());

    // Determine bind address
    let bind_ipv4: std::net::Ipv4Addr = config
        .network
        .bind_ipv4
        .as_deref()
        .map(|ip| {
            ip.parse().unwrap_or_else(|e| {
                panic!("P2P_BIND_IPV4 '{ip}' is not a valid IPv4 address: {e}");
            })
        })
        .or_else(|| {
            stun_ipv4.as_ref().and_then(|r| match r.ip {
                std::net::IpAddr::V4(v4) if common::stun::is_local_interface_ip(r.ip) => {
                    info!(ip = %v4, "Using STUN-detected IPv4 as bind address (local interface)");
                    Some(v4)
                }
                std::net::IpAddr::V4(v4) => {
                    debug!(ip = %v4, "STUN IPv4 is not a local interface (behind NAT)");
                    None
                }
                _ => None,
            })
        })
        .or_else(|| {
            let ip = common::stun::detect_default_route_ipv4();
            if let Some(v4) = ip {
                info!(ip = %v4, "Using default-route interface as bind address");
            }
            ip
        })
        .unwrap_or(std::net::Ipv4Addr::UNSPECIFIED);

    if bind_ipv4.is_unspecified() {
        warn!(
            "P2P binding to 0.0.0.0:{} — set P2P_BIND_IPV4 to your server's primary IP.",
            config.network.p2p_port
        );
    } else {
        info!(bind_ip = %bind_ipv4, "P2P binding to specific IPv4 address");
    }

    let bind_addr = SocketAddr::new(
        std::net::IpAddr::V4(bind_ipv4),
        config.network.p2p_port,
    );
    let endpoint = common::transport::create_endpoint(bind_addr, &signing_key).await?;

    info!(node_id = %truncate_for_log(&node_id, 16), bind = %bind_addr, "Quinn endpoint bound");

    // Compute miner UID once (deterministic hash of public key)
    let miner_uid = common::compute_miner_uid(&node_id);
    state::set_miner_uid(miner_uid);

    // Store data_dir globally for cluster map persistence
    state::set_data_dir(data_dir.clone());

    // Load cached cluster map from disk (survives restarts)
    if let Some(map) = rebalance::load_cluster_map_cache(&data_dir).await {
        let epoch = map.epoch;
        let pgs = tokio::task::spawn_blocking({
            let map_clone = map.clone();
            move || common::calculate_my_pgs(miner_uid, &map_clone)
        })
        .await
        .unwrap_or_default();
        let pg_count = pgs.len();
        {
            let mut map_guard = state::get_cluster_map().write().await;
            *map_guard = Some(Arc::new(map));
        }
        {
            let mut cached = state::get_my_pgs_cache().write().await;
            *cached = (epoch, pgs);
        }
        info!(
            epoch = epoch,
            pgs = pg_count,
            "[STARTUP] Loaded cached cluster map from disk"
        );
    }

    info!("Ready for P2P connections");

    // 2. Initialize flat-file blob store for persistent shard storage
    let blobs_dir = data_dir.join("blobs");
    let store = Arc::new(
        FlatBlobStore::new(&blobs_dir)
            .map_err(|e| anyhow::anyhow!("Failed to initialize blob store: {}", e))?,
    );
    info!(path = %blobs_dir.display(), "Initialized flat-file blob storage");

    // Store blobs_dir globally
    {
        let mut bd = get_blobs_dir().write().await;
        *bd = Some(blobs_dir.clone());
    }

    // 3. Resolve validator address
    let validator_node_id_str = validator_node_id.ok_or_else(|| {
        anyhow::anyhow!(
            "VALIDATOR_NODE_ID is required for P2P registration (set via config or env)"
        )
    })?;

    // Resolve validator socket address: VALIDATOR_ADDR > first direct_addr
    let validator_socket_addr: SocketAddr = config
        .validator
        .addr
        .as_deref()
        .map(|s| {
            s.parse().unwrap_or_else(|e| {
                panic!("VALIDATOR_ADDR '{s}' is not a valid socket address: {e}");
            })
        })
        .or_else(|| {
            config::parse_direct_addrs(&config.validator.direct_addrs)
                .into_iter()
                .next()
        })
        .ok_or_else(|| {
            anyhow::anyhow!(
                "VALIDATOR_ADDR or VALIDATOR_DIRECT_ADDRS is required for quinn transport"
            )
        })?;

    info!(
        validator_addr = %validator_socket_addr,
        validator_node_id = %truncate_for_log(&validator_node_id_str, 16),
        "Validator address resolved"
    );

    // Parse warden node ID if provided (optional)
    if let Some(ref wid) = warden_node_id {
        let mut ids = get_warden_node_ids().write().await;
        ids.push(wid.clone());
        info!(warden = %truncate_for_log(wid, 16), "Warden PoS challenges authorized");
    }

    // Store validator info globally
    {
        let mut val_addr = state::get_validator_addr().write().await;
        *val_addr = Some(validator_socket_addr);
    }
    {
        let mut val_id = state::get_validator_node_id_global().write().await;
        *val_id = validator_node_id_str.clone();
    }

    // 4. Initialize handler and start accept loop BEFORE registration.
    let store_concurrency = std::cmp::max(1, config.tuning.store_concurrency);
    let pull_concurrency = std::cmp::max(1, config.tuning.pull_concurrency);
    let fetch_concurrency = std::cmp::max(1, config.tuning.fetch_concurrency);
    let pos_concurrency = std::cmp::max(1, config.tuning.pos_concurrency.unwrap_or(2));

    let miner_control_handler = MinerControlHandler {
        store: Arc::clone(&store),
        endpoint: endpoint.clone(),
        store_sem: Arc::new(tokio::sync::Semaphore::new(store_concurrency)),
        pull_sem: Arc::new(tokio::sync::Semaphore::new(pull_concurrency)),
        fetch_sem: Arc::new(tokio::sync::Semaphore::new(fetch_concurrency)),
        pos_sem: Arc::new(tokio::sync::Semaphore::new(pos_concurrency)),
        validator_node_id: Some(validator_node_id_str.clone()),
    };

    // Spawn quinn accept loop (replaces iroh Router)
    let accept_endpoint = endpoint.clone();
    let accept_handler = miner_control_handler.clone();
    let accept_token = CancellationToken::new();
    let accept_cancel = accept_token.clone();
    // Limit concurrent connections to prevent DoS (file descriptor exhaustion)
    let conn_semaphore = Arc::new(tokio::sync::Semaphore::new(256));
    tokio::spawn(async move {
        loop {
            tokio::select! {
                incoming = accept_endpoint.accept() => {
                    let Some(incoming) = incoming else {
                        info!("Accept loop: endpoint closed");
                        break;
                    };
                    let handler = accept_handler.clone();
                    let permit = match conn_semaphore.clone().try_acquire_owned() {
                        Ok(permit) => permit,
                        Err(_) => {
                            warn!("Connection limit reached (256), dropping incoming connection");
                            drop(incoming);
                            continue;
                        }
                    };
                    tokio::spawn(async move {
                        let _permit = permit; // held until task completes
                        match incoming.await {
                            Ok(conn) => {
                                if let Err(e) = p2p::handle_miner_control(conn, handler).await {
                                    let err_str = e.to_string();
                                    if !err_str.contains("connection closed")
                                        && !err_str.contains("error 0")
                                    {
                                        debug!(error = %e, "Connection handler error");
                                    }
                                }
                            }
                            Err(e) => {
                                debug!(error = %e, "Incoming connection handshake failed");
                            }
                        }
                    });
                }
                () = accept_cancel.cancelled() => {
                    info!("Accept loop shutting down");
                    break;
                }
            }
        }
    });

    let signing_key = Arc::new(signing_key);

    let ctx = MinerContext {
        endpoint: endpoint.clone(),
        signing_key: signing_key.clone(),
        node_id: node_id.clone(),
        validator_node_id: validator_node_id_str.clone(),
        validator_socket_addr,
        hostname,
        family_id,
        data_dir,
        config: config.clone(),
        stun_public_ip: stun_ipv4.map(|r| r.ip),
    };

    // 5. Register with Validator via P2P
    info!(validator = %truncate_for_log(&validator_node_id_str, 16), "Registering with validator via P2P");

    let reg_conn = register_with_validator(&ctx).await?;

    // 5b. Join iroh-doc if DOC_TICKET provided at startup
    // Note: iroh-docs still needs an iroh::Endpoint for gossip. We create a
    // lightweight one just for doc sync. This is temporary until #151 removes iroh-docs.
    if let Ok(ticket) = std::env::var("DOC_TICKET") {
        if !ticket.is_empty() {
            info!("DOC_TICKET provided — iroh-docs requires iroh::Endpoint (not yet migrated)");
            // doc_replica::join_doc needs an iroh::Endpoint — skip for now.
            // This feature will be removed in #151.
        }
    }

    // 6. Start P2P Heartbeat Loop (reuse registration connection)
    let shutdown_token = CancellationToken::new();
    let shutdown_notify = Arc::new(tokio::sync::Notify::new());
    spawn_heartbeat_loop(
        ctx.clone(),
        shutdown_notify.clone(),
        shutdown_token.clone(),
        Some(reg_conn),
    );

    // 7. Start gateway keepalive loop
    gateway_keepalive::spawn_gateway_keepalive(endpoint.clone(), shutdown_token.clone());

    // 8. Start Self-Rebalance Loop (if enabled)
    if config.tuning.rebalance_enabled {
        let store_rebalance = Arc::clone(&store);
        let endpoint_rebalance = endpoint.clone();
        let tick_secs = config.tuning.rebalance_tick_secs;
        let rebalance_token = shutdown_token.clone();

        tokio::spawn(async move {
            // Initial randomized jitter delay
            let jitter_secs = {
                use rand::Rng;
                let mut rng = rand::rng();
                let max_jitter = std::cmp::max(constants::MIN_REBALANCE_JITTER_SECS + 1, tick_secs);
                rng.random_range(constants::MIN_REBALANCE_JITTER_SECS..max_jitter)
            };

            info!(
                jitter_secs = jitter_secs,
                "Waiting for randomized jitter before first self-rebalance"
            );
            tokio::select! {
                () = tokio::time::sleep(std::time::Duration::from_secs(jitter_secs)) => {}
                () = rebalance_token.cancelled() => {
                    info!("Rebalance loop received shutdown signal during initial jitter");
                    return;
                }
            }

            loop {
                if let Err(e) = rebalance::self_rebalance_pg(
                    Arc::clone(&store_rebalance),
                    endpoint_rebalance.clone(),
                )
                .await
                {
                    error!(error = %e, "Self-rebalance failed");
                }

                tokio::select! {
                    () = tokio::time::sleep(std::time::Duration::from_secs(tick_secs)) => {}
                    () = rebalance_token.cancelled() => {
                        info!("Rebalance loop received shutdown signal");
                        break;
                    }
                }
                let loop_jitter_secs = {
                    use rand::Rng;
                    let mut rng = rand::rng();
                    rng.random_range(0..constants::MAX_REBALANCE_INITIAL_JITTER_SECS)
                };
                tokio::select! {
                    () = tokio::time::sleep(std::time::Duration::from_secs(loop_jitter_secs)) => {}
                    () = rebalance_token.cancelled() => {
                        info!("Rebalance loop received shutdown signal");
                        break;
                    }
                }
            }
        });

        info!(tick_secs = tick_secs, "Miner self-rebalance loop started");
    } else {
        info!("Miner self-rebalance disabled (set MINER_REBALANCE_ENABLED=true to enable)");
    }

    // Keep process alive until Ctrl+C, SIGTERM, or fatal shutdown signal
    let ctrl_c = async {
        tokio::signal::ctrl_c()
            .await
            .expect("Failed to install Ctrl+C handler");
    };
    #[cfg(unix)]
    let terminate = async {
        tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())
            .expect("Failed to install SIGTERM handler")
            .recv()
            .await;
    };
    #[cfg(not(unix))]
    let terminate = std::future::pending::<()>();

    tokio::select! {
        () = ctrl_c => info!("Received Ctrl+C, initiating graceful shutdown"),
        () = terminate => info!("Received SIGTERM, initiating graceful shutdown"),
        () = shutdown_notify.notified() => error!("Fatal shutdown signal received, shutting down"),
    }

    // 1. Signal all background loops to stop
    shutdown_token.cancel();
    accept_token.cancel();

    // 2. Grace period for in-flight operations
    tokio::time::sleep(std::time::Duration::from_millis(
        constants::SHUTDOWN_GRACE_PERIOD_MS,
    ))
    .await;

    // 3. Close quinn endpoint
    info!("Closing P2P endpoint...");
    endpoint.close(0u32.into(), b"shutdown");
    endpoint.wait_idle().await;
    info!("Shutdown complete");

    Ok(())
}

/// Preflight network health checks.
fn check_network_health() {
    for (path, label) in [
        (
            "/proc/sys/net/netfilter/nf_conntrack_udp_timeout",
            "nf_conntrack_udp_timeout",
        ),
        (
            "/proc/sys/net/netfilter/nf_conntrack_udp_timeout_stream",
            "nf_conntrack_udp_timeout_stream",
        ),
    ] {
        if let Ok(val) = std::fs::read_to_string(path) {
            if let Ok(timeout) = val.trim().parse::<u64>() {
                if timeout < 120 {
                    warn!(
                        param = label,
                        current_timeout = timeout,
                        required = 120,
                        "LOW CONNTRACK UDP TIMEOUT — QUIC connections may drop after {timeout}s. \
                         Run: sudo sysctl -w {label}=120"
                    );
                } else {
                    info!(param = label, timeout, "Conntrack UDP timeout OK");
                }
            }
        }
    }
}

async fn register_with_validator(ctx: &MinerContext) -> Result<quinn::Connection> {
    let initial_backoff = ctx.config.tuning.initial_backoff_secs;
    let max_backoff = ctx.config.tuning.max_backoff_secs;
    let mut retry_count: u32 = 0;

    loop {
        match register_with_validator_once(ctx).await {
            Ok(conn) => {
                info!("Registered with validator via P2P");
                {
                    let mut val_addr = state::get_validator_addr().write().await;
                    *val_addr = Some(ctx.validator_socket_addr);
                }
                return Ok(conn);
            }
            Err(e) => {
                let is_warming_up = e.to_string().contains("warming up");
                if is_warming_up {
                    info!(
                        "Validator is warming up, retrying in {}s",
                        constants::REGISTRATION_RETRY_SLEEP_SECS
                    );
                    let jitter_ms =
                        rand::rng().random_range(0..constants::MAX_REGISTRATION_RETRY_JITTER_MS);
                    tokio::time::sleep(
                        tokio::time::Duration::from_secs(constants::REGISTRATION_RETRY_SLEEP_SECS)
                            + tokio::time::Duration::from_millis(jitter_ms),
                    )
                    .await;
                } else {
                    retry_count = retry_count.saturating_add(1);
                    let backoff_secs = std::cmp::min(
                        max_backoff,
                        initial_backoff.saturating_mul(2u64.saturating_pow(retry_count)),
                    );
                    error!(
                        error = %e,
                        backoff_secs = backoff_secs,
                        attempt = retry_count,
                        "P2P registration failed, retrying"
                    );
                    tokio::time::sleep(tokio::time::Duration::from_secs(backoff_secs)).await;
                }
            }
        }
    }
}

fn spawn_heartbeat_loop(
    ctx: MinerContext,
    shutdown: Arc<tokio::sync::Notify>,
    cancel_token: CancellationToken,
    initial_conn: Option<quinn::Connection>,
) {
    let miner_uid = state::get_miner_uid();
    let mut cached_endpoint_addr = ctx.build_endpoint_addr();
    let mut endpoint_addr_refresh_counter: u32 = 0;

    tokio::spawn(async move {
        let mut heartbeat_count: u32 = 0;
        let mut consecutive_failures: u32 = 0;
        let mut current_validator_node_id = ctx.validator_node_id.clone();
        let mut current_validator_addr = ctx.validator_socket_addr;

        // Persistent connection: reuse a single QUIC connection across heartbeats
        let mut cached_conn: Option<quinn::Connection> = initial_conn;
        let mut consecutive_rereg_failures: u32 = 0;

        loop {
            // Check if re-registration is needed
            if get_needs_reregistration().load(std::sync::atomic::Ordering::SeqCst) {
                info!("Re-registration flag set, performing re-registration");
                get_needs_reregistration().store(false, std::sync::atomic::Ordering::SeqCst);

                let rereg_ctx = MinerContext {
                    validator_node_id: current_validator_node_id.clone(),
                    validator_socket_addr: current_validator_addr,
                    ..ctx.clone()
                };
                match register_with_validator_once(&rereg_ctx).await {
                    Ok(new_conn) => {
                        consecutive_rereg_failures = 0;
                        info!("Re-registration successful");
                        {
                            let mut val_addr = state::get_validator_addr().write().await;
                            *val_addr = Some(current_validator_addr);
                        }
                        if let Some(old) = cached_conn.take() {
                            old.close(0u32.into(), b"stale");
                        }
                        cached_conn = Some(new_conn);
                        let jitter_ms =
                            rand::rng().random_range(0..constants::MAX_HEARTBEAT_RETRY_JITTER_MS);
                        tokio::time::sleep(tokio::time::Duration::from_millis(jitter_ms)).await;
                    }
                    Err(e) => {
                        consecutive_rereg_failures = consecutive_rereg_failures.saturating_add(1);
                        error!(
                            error = %e,
                            attempt = consecutive_rereg_failures,
                            "Re-registration failed, will retry on next heartbeat"
                        );

                        if consecutive_rereg_failures
                            >= constants::MAX_REREGISTRATION_FAILURES_BEFORE_EXIT
                        {
                            error!(
                                consecutive_failures = consecutive_rereg_failures,
                                "Re-registration stuck — triggering clean exit for systemd restart"
                            );
                            if let Some(conn) = cached_conn.take() {
                                conn.close(0u32.into(), b"stale-rereg");
                            }
                            shutdown.notify_one();
                            return;
                        }

                        get_needs_reregistration().store(true, std::sync::atomic::Ordering::SeqCst);
                        let retry_jitter_ms =
                            rand::rng().random_range(0..constants::MAX_SOCKET_REFRESH_JITTER_MS);
                        tokio::time::sleep(
                            tokio::time::Duration::from_secs(
                                constants::RELAY_LOSS_RECOVERY_DELAY_SECS,
                            ) + tokio::time::Duration::from_millis(retry_jitter_ms),
                        )
                        .await;
                        continue;
                    }
                }
            }

            // Periodically refresh validator address from environment
            heartbeat_count = heartbeat_count.wrapping_add(1);
            if heartbeat_count.is_multiple_of(constants::VALIDATOR_ADDR_REFRESH_INTERVAL_CYCLES)
            {
                if let Ok(new_validator_id) = std::env::var("VALIDATOR_NODE_ID") {
                    if new_validator_id != current_validator_node_id {
                        debug!(
                            old = %truncate_for_log(&current_validator_node_id, 16),
                            new = %truncate_for_log(&new_validator_id, 16),
                            "Validator node ID refreshed from environment"
                        );
                        current_validator_node_id = new_validator_id;
                        {
                            let mut val_id = state::get_validator_node_id_global().write().await;
                            *val_id = current_validator_node_id.clone();
                        }

                        // Also check for VALIDATOR_ADDR update
                        if let Ok(new_addr_str) = std::env::var("VALIDATOR_ADDR") {
                            if let Ok(new_addr) = new_addr_str.parse::<SocketAddr>() {
                                current_validator_addr = new_addr;
                                let mut val_addr = state::get_validator_addr().write().await;
                                *val_addr = Some(current_validator_addr);
                            }
                        }

                        if let Some(old) = cached_conn.take() {
                            old.close(0u32.into(), b"stale");
                        }
                        get_needs_reregistration().store(true, std::sync::atomic::Ordering::SeqCst);
                        continue;
                    }
                }
            }

            let timestamp = now_secs();

            // Calculate available storage
            let max_storage_gb = ctx.config.storage.max_storage_gb;
            let available = free_space(&ctx.data_dir).unwrap_or(0);
            let reported_available = if max_storage_gb > 0 {
                std::cmp::min(available, max_storage_gb * 1024 * 1024 * 1024)
            } else {
                available
            };

            // Refresh endpoint addr periodically
            endpoint_addr_refresh_counter = endpoint_addr_refresh_counter.wrapping_add(1);
            if endpoint_addr_refresh_counter
                .is_multiple_of(constants::ENDPOINT_ADDR_REFRESH_INTERVAL_CYCLES)
            {
                cached_endpoint_addr = ctx.build_endpoint_addr();
            }

            let heartbeat_msg = {
                let public_key_str = ctx.node_id.clone();

                // Sign "HEARTBEAT:{public_key}:{timestamp}"
                let sign_data = format!("HEARTBEAT:{}:{}", public_key_str, timestamp);
                let signature = ctx.sign(sign_data.as_bytes());

                common::ValidatorControlMessage::Heartbeat {
                    miner_uid,
                    timestamp,
                    available_storage: reported_available,
                    public_key: public_key_str,
                    signature: signature.to_bytes().to_vec(),
                    endpoint_addr: Some(cached_endpoint_addr.clone()),
                    version: Some(env!("CARGO_PKG_VERSION").to_string()),
                }
            };

            // Reuse cached connection or establish a new one.
            let conn = match cached_conn.as_ref() {
                Some(c) if c.close_reason().is_none() => Ok(c.clone()),
                _ => {
                    if let Some(old) = cached_conn.take() {
                        old.close(0u32.into(), b"stale");
                    }
                    match tokio::time::timeout(
                        std::time::Duration::from_secs(constants::DEFAULT_CONNECT_TIMEOUT_SECS),
                        common::transport::connect(
                            &ctx.endpoint,
                            current_validator_addr,
                            &current_validator_node_id,
                        ),
                    )
                    .await
                    {
                        Ok(Ok(new_conn)) => {
                            cached_conn = Some(new_conn.clone());
                            Ok(new_conn)
                        }
                        Ok(Err(e)) => Err(format!("{e}")),
                        Err(_) => Err("connect timeout".to_string()),
                    }
                }
            };

            match conn {
                Ok(conn) => {
                    // Wrap entire heartbeat exchange in a single timeout
                    let result = tokio::time::timeout(std::time::Duration::from_secs(constants::HEARTBEAT_EXCHANGE_TIMEOUT_SECS), async {
                        let (mut send, mut recv) = conn.open_bi().await?;

                        let msg_bytes = serde_json::to_vec(&heartbeat_msg)?;
                        send.write_all(&msg_bytes).await?;
                        send.finish()?;

                        // Read ACK
                        let ack_bytes = recv.read_to_end(constants::HEARTBEAT_ACK_BUFFER_SIZE).await?;

                        let ack_str = String::from_utf8_lossy(&ack_bytes);
                        if ack_str.starts_with("FAMILY_REJECTED:") {
                            error!(response = %ack_str, "Heartbeat rejected — miner cannot operate, shutting down");
                            return Err(anyhow::anyhow!("FAMILY_REJECTED"));
                        }
                        if ack_str == "UNKNOWN" {
                            warn!("Validator returned UNKNOWN - triggering re-registration");
                            get_needs_reregistration()
                                .store(true, std::sync::atomic::Ordering::SeqCst);
                            return Err(anyhow::anyhow!("Re-registration needed"));
                        }
                        if ack_str == "WARMING_UP" {
                            debug!("Validator is warming up, will retry shortly");
                            return Ok(false);
                        }

                        // Try to parse JSON response for warden node IDs
                        if let Ok(response) = serde_json::from_str::<serde_json::Value>(&ack_str)
                        {
                            if let Some(ids) =
                                response.get("warden_node_ids").and_then(|v| v.as_array())
                            {
                                let mut new_ids: Vec<String> = ids
                                    .iter()
                                    .filter_map(|id| id.as_str().map(|s| s.to_string()))
                                    .filter(|s| !s.is_empty())
                                    .collect();
                                if !new_ids.is_empty() {
                                    new_ids.sort();
                                    let mut warden_ids = get_warden_node_ids().write().await;
                                    if *warden_ids != new_ids {
                                        debug!(
                                            count = new_ids.len(),
                                            "Updated warden node IDs from validator heartbeat"
                                        );
                                        *warden_ids = new_ids;
                                    }
                                }
                            }
                        }

                        Ok::<_, anyhow::Error>(true)
                    })
                    .await;

                    match result {
                        Ok(Ok(true)) => {
                            consecutive_failures = 0;
                            get_validator_reachable()
                                .store(true, std::sync::atomic::Ordering::Relaxed);
                            let hb_epoch = {
                                let e = crate::state::get_current_epoch().read().await;
                                *e
                            };
                            let hb_pgs = {
                                let c = crate::state::get_my_pgs_cache().read().await;
                                c.1.len()
                            };
                            info!(
                                "[HEARTBEAT] OK — epoch={} assigned_pgs={}",
                                hb_epoch, hb_pgs
                            );
                        }
                        Ok(Ok(false)) => {
                            // Validator is warming up
                            get_validator_reachable()
                                .store(true, std::sync::atomic::Ordering::Relaxed);
                            let jitter_ms =
                                rand::rng().random_range(0..constants::ERROR_RETRY_JITTER_MS);
                            tokio::time::sleep(
                                tokio::time::Duration::from_secs(
                                    constants::RETRY_BACKOFF_BASE_SECS,
                                ) + tokio::time::Duration::from_millis(jitter_ms),
                            )
                            .await;
                            continue;
                        }
                        Ok(Err(e)) if e.to_string() == "FAMILY_REJECTED" => {
                            info!(
                                "[DISCONNECTED] Validator rejected this miner's family, shutting down"
                            );
                            if let Some(conn) = cached_conn.take() {
                                conn.close(0u32.into(), b"shutdown");
                            }
                            shutdown.notify_one();
                            return;
                        }
                        Ok(Err(e)) => {
                            warn!(error = %e, "[DISCONNECTED] Lost connection to validator, will retry...");
                            if let Some(old) = cached_conn.take() {
                                old.close(0u32.into(), b"stale");
                            }
                            consecutive_failures = consecutive_failures.saturating_add(1);
                            get_validator_reachable()
                                .store(false, std::sync::atomic::Ordering::Relaxed);
                        }
                        Err(_) => {
                            warn!(
                                timeout_secs = constants::HEARTBEAT_EXCHANGE_TIMEOUT_SECS,
                                "[DISCONNECTED] Lost connection to validator, will retry..."
                            );
                            if let Some(old) = cached_conn.take() {
                                old.close(0u32.into(), b"stale");
                            }
                            consecutive_failures = consecutive_failures.saturating_add(1);
                            get_validator_reachable()
                                .store(false, std::sync::atomic::Ordering::Relaxed);
                        }
                    }
                }
                Err(e) => {
                    warn!(error = %e, "[DISCONNECTED] Lost connection to validator, will retry...");
                    consecutive_failures = consecutive_failures.saturating_add(1);
                    get_validator_reachable().store(false, std::sync::atomic::Ordering::Relaxed);
                }
            }

            // After 3 consecutive heartbeat failures, trigger re-registration.
            if consecutive_failures >= constants::HEARTBEAT_FAILURES_BEFORE_REREGISTRATION {
                warn!(
                    consecutive_failures,
                    "Too many consecutive heartbeat failures — triggering re-registration"
                );
                get_needs_reregistration().store(true, std::sync::atomic::Ordering::SeqCst);
                consecutive_failures = 0;
            }

            // Exponential backoff: 30s, 60s, 120s (capped) on consecutive failures
            let backoff_secs = if consecutive_failures == 0 {
                constants::FAILURE_BACKOFF_BASE_SECS
            } else {
                std::cmp::min(
                    constants::FAILURE_BACKOFF_MAX_SECS,
                    constants::FAILURE_BACKOFF_BASE_SECS << consecutive_failures.min(2),
                )
            };
            let jitter_ms = rand::rng().random_range(0..constants::FAILURE_BACKOFF_JITTER_MS);
            tokio::select! {
                () = tokio::time::sleep(
                    tokio::time::Duration::from_secs(backoff_secs)
                        + tokio::time::Duration::from_millis(jitter_ms),
                ) => {}
                () = cancel_token.cancelled() => {
                    info!("Heartbeat loop received shutdown signal");
                    if let Some(conn) = cached_conn.take() {
                        conn.close(0u32.into(), b"shutdown");
                    }
                    return;
                }
            }
        }
    });
}

/// Perform a single registration attempt with the validator.
async fn register_with_validator_once(ctx: &MinerContext) -> Result<quinn::Connection> {
    // Calculate storage stats
    let available = free_space(&ctx.data_dir).unwrap_or(0);
    let total = fs2::total_space(&ctx.data_dir).unwrap_or(0);

    let reported_available = if ctx.config.storage.max_storage_gb > 0 {
        std::cmp::min(
            available,
            ctx.config
                .storage
                .max_storage_gb
                .saturating_mul(1024 * 1024 * 1024),
        )
    } else {
        available
    };

    let http_addr = ctx.http_addr();

    let register_msg = {
        let public_key_str = ctx.node_id.clone();
        let timestamp = now_secs();

        // Sign "REGISTER:{public_key}:{timestamp}"
        let sign_data = format!("REGISTER:{}:{}", public_key_str, timestamp);
        let signature = ctx.sign(sign_data.as_bytes());

        let resolved_ip = ctx.resolve_hostname_ip();
        let my_endpoint_addr = ctx.build_endpoint_addr();

        if my_endpoint_addr.addrs.is_empty() {
            warn!(
                hostname = %ctx.hostname,
                "Could not resolve hostname to IP — registering with relay-only address"
            );
        } else {
            info!(
                direct_addrs = ?my_endpoint_addr.addrs,
                p2p_port = ctx.config.network.p2p_port,
                "Including direct address hint in registration"
            );
        }

        // Send the resolved IP in http_addr when available.
        let resolved_http_addr = match resolved_ip {
            Some(ip) if ip.is_loopback() => http_addr.clone(),
            Some(ip) if common::is_advertisable_ip(ip) => ip.to_string(),
            _ => ctx
                .stun_public_ip
                .map(|ip| ip.to_string())
                .unwrap_or(http_addr),
        };

        common::ValidatorControlMessage::Register {
            public_key: public_key_str,
            http_addr: resolved_http_addr,
            total_storage: total,
            available_storage: reported_available,
            family_id: ctx.family_id.clone(),
            timestamp,
            signature: signature.to_bytes().to_vec(),
            endpoint_addr: Some(my_endpoint_addr),
            version: Some(env!("CARGO_PKG_VERSION").to_string()),
        }
    };

    // Connect to validator via quinn
    let conn = tokio::time::timeout(
        std::time::Duration::from_secs(constants::DEFAULT_CONNECT_TIMEOUT_SECS),
        common::transport::connect(
            &ctx.endpoint,
            ctx.validator_socket_addr,
            &ctx.validator_node_id,
        ),
    )
    .await?
    .map_err(|e| anyhow::anyhow!("connect error: {}", e))?;

    info!("Registration: P2P connection to validator established");

    let result: anyhow::Result<()> = async {
        let (mut send, mut recv) = conn.open_bi().await?;
        let msg_bytes = serde_json::to_vec(&register_msg)?;
        send.write_all(&msg_bytes).await?;
        send.finish()?;

        // Wait for ACK
        let ack = tokio::time::timeout(
            std::time::Duration::from_secs(constants::REGISTER_COMPLETION_TIMEOUT_SECS),
            recv.read_to_end(constants::REGISTER_ACK_BUFFER_SIZE),
        )
        .await
        .map_err(|_| anyhow::anyhow!("ACK timeout"))??;

        let ack_str = String::from_utf8_lossy(&ack);
        match ack_str.as_ref() {
            "OK" => Ok(()),
            "RATE_LIMITED" => Err(anyhow::anyhow!("RATE_LIMITED")),
            "WARMING_UP" => Err(anyhow::anyhow!("Validator warming up")),
            _ if ack_str.starts_with("FAMILY_REJECTED:") => Err(anyhow::anyhow!("{ack_str}")),
            _ => Err(anyhow::anyhow!("Registration failed: {ack_str}")),
        }
    }
    .await;

    result?;
    Ok(conn)
}

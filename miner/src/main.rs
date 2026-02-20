//! Miner entry point for the Hippius Arion storage subnet.
//!
//! The miner receives shards from validators via P2P, stores them in Iroh's
//! FsStore, and serves them back to gateways and other miners on request.

mod config;
mod constants;
mod helpers;
mod p2p;
mod rebalance;
mod state;
mod version_check;

use anyhow::Result;
use clap::Parser;
use common::now_secs;
use fs2::free_space;
use helpers::{load_keypair, truncate_for_log};
use iroh::protocol::Router;
use iroh_blobs::BlobsProtocol;
use iroh_blobs::store::fs::FsStore;
use p2p::MinerControlHandler;
use state::{
    get_blobs_dir, get_needs_reregistration, get_validator_endpoint, get_validator_reachable,
    get_warden_node_ids,
};
use std::str::FromStr;
use std::sync::Arc;
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
                tokio::time::sleep(std::time::Duration::from_secs(5)).await;
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
    tokio::spawn(version_check::check_for_updates());

    // Load config from TOML file with env overrides
    let config = match config::MinerConfig::load(None) {
        Ok(c) => c,
        Err(e) => {
            warn!(error = %e, "Config load warning, using defaults");
            config::MinerConfig::default()
        }
    };

    // CLI args override config file values
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

    // Bind to specific IP if configured, otherwise UNSPECIFIED (all interfaces).
    // When bound to UNSPECIFIED, iroh scans all interfaces and advertises every
    // detected address — including unreachable private IPs (Docker bridge, K8s
    // internal). Binding to a specific public IP makes iroh advertise only that
    // address, which is required for direct P2P connections.
    let bind_ipv4: std::net::Ipv4Addr = config
        .network
        .bind_ipv4
        .as_deref()
        .map(|ip| {
            ip.parse().unwrap_or_else(|e| {
                panic!("P2P_BIND_IPV4 '{ip}' is not a valid IPv4 address: {e}");
            })
        })
        .unwrap_or(std::net::Ipv4Addr::UNSPECIFIED);

    let mut endpoint_builder = iroh::Endpoint::builder()
        .secret_key(secret_key)
        .bind_addr_v4(std::net::SocketAddrV4::new(
            bind_ipv4,
            config.network.p2p_port,
        ));

    if let Some(ref ipv6_str) = config.network.bind_ipv6 {
        let bind_ipv6: std::net::Ipv6Addr = ipv6_str.parse().unwrap_or_else(|e| {
            panic!("P2P_BIND_IPV6 '{ipv6_str}' is not a valid IPv6 address: {e}");
        });
        endpoint_builder =
            endpoint_builder.bind_addr_v6(std::net::SocketAddrV6::new(bind_ipv6, 11231, 0, 0));
    }

    if bind_ipv4.is_unspecified() {
        info!(
            "P2P binding to 0.0.0.0:{} (all interfaces — set P2P_BIND_IPV4 to restrict)",
            config.network.p2p_port
        );
    } else {
        info!(bind_ip = %bind_ipv4, "P2P binding to specific IPv4 address");
    }

    // Configure transport with keep-alive to maintain relay connections
    let mut transport_config = iroh::endpoint::TransportConfig::default();
    transport_config.keep_alive_interval(Some(std::time::Duration::from_secs(15)));
    if let Ok(idle_timeout) = std::time::Duration::from_secs(120).try_into() {
        transport_config.max_idle_timeout(Some(idle_timeout));
    }

    // Match validator's stream capacity for shard distribution.
    // Large uploads open ~256 streams/miner (524MB file); 16384 supports multi-GB files.
    transport_config.max_concurrent_bidi_streams(16384u32.into());
    transport_config.max_concurrent_uni_streams(1024u32.into());

    // Flow control for receiving shard data at scale.
    // 16MB send_window reduces per-connection memory and UDP buffer pressure.
    transport_config.send_window(16 * 1024 * 1024);
    transport_config.stream_receive_window((2u32 * 1024 * 1024).into());
    // 64MB receive_window bounds aggregate receive capacity per connection.
    transport_config.receive_window((64u32 * 1024 * 1024).into());

    endpoint_builder = endpoint_builder.transport_config(transport_config);

    // Configure relay using consistent pattern from common crate
    endpoint_builder = endpoint_builder.relay_mode(common::build_relay_mode(&relay_url_value));

    let endpoint = endpoint_builder.bind().await?;

    let node_id = endpoint.secret_key().public();
    info!(node_id = %node_id, "Iroh endpoint bound");

    // Compute miner UID once (deterministic hash of public key)
    let miner_uid = {
        let mut hasher = std::collections::hash_map::DefaultHasher::new();
        use std::hash::{Hash, Hasher};
        node_id.to_string().hash(&mut hasher);
        (hasher.finish() as u32) & 0x7FFFFFFF
    };
    state::set_miner_uid(miner_uid);

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

    // 3. Register with Validator via P2P (http_addr kept for backward compatibility)
    let http_addr = format!("http://{}:{}", hostname, config.network.p2p_port);

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

    // Parse validator direct addresses for P2P seeding
    let validator_direct_addrs: Vec<std::net::SocketAddr> = config
        .validator
        .validator_direct_addrs
        .as_deref()
        .unwrap_or("")
        .split(',')
        .filter(|s| !s.trim().is_empty())
        .filter_map(|s| {
            s.trim().parse().map_err(|e| {
                warn!(addr = %s.trim(), error = %e, "Ignoring invalid VALIDATOR_DIRECT_ADDRS entry");
                e
            }).ok()
        })
        .collect();

    if !validator_direct_addrs.is_empty() {
        info!(
            addrs = ?validator_direct_addrs,
            "Seeding validator direct addresses for P2P"
        );
    }

    // Initialize dynamic warden node IDs from config (will be updated by validator heartbeats)
    if let Some(wpk) = warden_pubkey {
        let mut ids = get_warden_node_ids().write().await;
        ids.push(wpk);
        info!(warden = %truncate_for_log(warden_node_id.as_deref().unwrap_or(""), 16), "Warden PoS challenges authorized");
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
        &validator_direct_addrs,
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
        validator_direct_addrs,
    );

    // 6. Start Self-Rebalance Loop (if enabled)
    if config.tuning.rebalance_enabled {
        let store_rebalance = store.clone();
        let endpoint_rebalance = endpoint.clone();
        let tick_secs = config.tuning.rebalance_tick_secs;

        tokio::spawn(async move {
            // Initial randomized jitter delay to let the miner settle after startup
            // and desynchronize miners so they don't all hammer the validator
            // at the exact same time with QueryPgFilesBatch requests.
            let jitter_secs = {
                use rand::Rng;
                let mut rng = rand::rng();
                // Wait anywhere from 10 seconds to the full tick length (usually 300s)
                let max_jitter = std::cmp::max(11, tick_secs);
                rng.random_range(10..max_jitter)
            };

            info!(
                jitter_secs = jitter_secs,
                "Waiting for randomized jitter before first self-rebalance"
            );
            tokio::time::sleep(std::time::Duration::from_secs(jitter_secs)).await;

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
                // Add a small randomized delay between ticks to prevent miners
                // that started close together from perfectly synchronizing over time.
                let loop_jitter_secs = {
                    use rand::Rng;
                    let mut rng = rand::rng();
                    rng.random_range(0..30)
                };
                tokio::time::sleep(std::time::Duration::from_secs(loop_jitter_secs)).await;
            }
        });

        info!(tick_secs = tick_secs, "Miner self-rebalance loop started");
    } else {
        info!("Miner self-rebalance disabled (set MINER_REBALANCE_ENABLED=true to enable)");
    }

    // Keep process alive: miner runs purely on P2P
    tokio::signal::ctrl_c().await?;
    Ok(())
}

/// Build a validator `EndpointAddr` seeded with direct socket addresses
/// and an optional relay URL so iroh can connect over UDP immediately
/// instead of discovering the validator via relay first.
fn build_validator_addr(
    pubkey: &iroh::PublicKey,
    direct_addrs: &[std::net::SocketAddr],
    relay_url: &Option<iroh_base::RelayUrl>,
) -> iroh::EndpointAddr {
    let mut addr = iroh::EndpointAddr::new(*pubkey);
    if !direct_addrs.is_empty() {
        addr = addr.with_addrs(direct_addrs.iter().map(|a| iroh::TransportAddr::Ip(*a)));
    }
    if let Some(url) = relay_url {
        addr = addr.with_relay_url(url.clone());
    }
    addr
}

/// Returns true if the miner has a direct UDP path to the validator.
/// Mixed (relay fallback), relay-only, and None are all rejected to
/// prevent any traffic from flowing through relay servers.
fn has_udp_path_to_validator(endpoint: &iroh::Endpoint, validator_id: iroh::PublicKey) -> bool {
    use iroh::Watcher as _;
    endpoint.conn_type(validator_id).is_some_and(|mut watcher| {
        matches!(watcher.get(), iroh::endpoint::ConnectionType::Direct(_))
    })
}

async fn wait_for_direct_connection(
    endpoint: &iroh::Endpoint,
    validator_pubkey: &iroh::PublicKey,
    timeout_secs: u64,
) -> bool {
    use iroh::Watcher as _;

    // Check if iroh already knows about this peer (e.g. from a previous
    // connection attempt). If conn_type returns None, iroh hasn't started
    // discovery for this node yet — the first registration attempt in the
    // retry loop will trigger hole-punching via connect(). In that case,
    // skip the polling loop and let the retry loop handle it.
    if endpoint.conn_type(*validator_pubkey).is_none() {
        debug!(
            "No existing connection to validator — \
             hole-punching will start on first registration attempt"
        );
        return false;
    }

    let deadline = tokio::time::Instant::now() + tokio::time::Duration::from_secs(timeout_secs);

    while tokio::time::Instant::now() < deadline {
        if has_udp_path_to_validator(endpoint, *validator_pubkey) {
            info!("UDP path to validator confirmed");
            return true;
        }

        let state = endpoint
            .conn_type(*validator_pubkey)
            .map(|mut w| format!("{:?}", w.get()))
            .unwrap_or_else(|| "None".to_string());
        debug!(conn_type = %state, "Waiting for UDP path to validator");

        tokio::time::sleep(tokio::time::Duration::from_secs(2)).await;
    }

    let port = endpoint.bound_sockets().first().map_or(0, |s| s.port());
    warn!(
        timeout_secs = timeout_secs,
        "Failed to establish UDP path to validator (relay-only). \
         Check: (1) UDP port {} is open inbound, \
         (2) P2P_BIND_IPV4 is set to your public IP if Docker is installed, \
         (3) firewall allows UDP traffic. \
         Will retry with backoff.",
        port
    );
    false
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
    validator_direct_addrs: &[std::net::SocketAddr],
) -> Result<()> {
    // Give iroh time to establish a direct connection via hole-punching.
    // The initial relay connection triggers STUN discovery; this polls
    // until Direct is confirmed or timeout.
    wait_for_direct_connection(
        endpoint,
        validator_pubkey,
        config.tuning.p2p_direct_wait_secs,
    )
    .await;
    // If wait timed out, proceed to the loop — the per-attempt check in
    // register_with_validator_once will reject relay connections, and
    // the backoff gives more time for hole-punching.

    let initial_backoff = config.tuning.initial_backoff_secs;
    let max_backoff = config.tuning.max_backoff_secs;
    let mut retry_count: u32 = 0;

    loop {
        match register_with_validator_once(
            endpoint,
            validator_pubkey,
            relay_url,
            hostname,
            http_addr,
            family_id,
            data_dir,
            config,
            validator_direct_addrs,
        )
        .await
        {
            Ok(()) => {
                info!("Registered with validator via P2P");
                let validator_addr =
                    build_validator_addr(validator_pubkey, validator_direct_addrs, relay_url);
                {
                    let mut val_ep = get_validator_endpoint().write().await;
                    *val_ep = Some(validator_addr);
                }
                return Ok(());
            }
            Err(e) => {
                let is_warming_up = e.to_string().contains("warming up");
                if is_warming_up {
                    // Validator reachable but not ready -- short fixed retry, no backoff
                    info!("Validator is warming up, retrying in 5s");
                    let jitter_ms = rand::random::<u64>() % 2000;
                    tokio::time::sleep(
                        tokio::time::Duration::from_secs(5)
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
    validator_direct_addrs: Vec<std::net::SocketAddr>,
) {
    let miner_uid = state::get_miner_uid();

    tokio::spawn(async move {
        let mut heartbeat_count: u32 = 0;
        let mut consecutive_failures: u32 = 0;
        let mut current_validator_pubkey = validator_pubkey;

        let mut heartbeat_validator_addr = build_validator_addr(
            &current_validator_pubkey,
            &validator_direct_addrs,
            &relay_url,
        );

        // Persistent connection: reuse a single QUIC connection across heartbeats
        // instead of creating a new one every 30s. Open a fresh bidi stream per
        // heartbeat on the existing connection; reconnect only when it drops.
        let mut cached_conn: Option<iroh::endpoint::Connection> = None;

        loop {
            // Check if re-registration is needed
            if get_needs_reregistration().load(std::sync::atomic::Ordering::SeqCst) {
                info!("Re-registration flag set, performing re-registration");

                // Clear the flag first
                get_needs_reregistration().store(false, std::sync::atomic::Ordering::SeqCst);

                // Perform re-registration
                let http_addr = format!("http://{}:{}", hostname, config.network.p2p_port);
                match register_with_validator_once(
                    &endpoint,
                    &current_validator_pubkey,
                    &relay_url,
                    &hostname,
                    &http_addr,
                    &family_id,
                    &data_dir,
                    &config,
                    &validator_direct_addrs,
                )
                .await
                {
                    Ok(()) => {
                        info!("Re-registration successful");
                        // Update stored validator endpoint
                        let new_addr = build_validator_addr(
                            &current_validator_pubkey,
                            &validator_direct_addrs,
                            &relay_url,
                        );
                        {
                            let mut val_ep = get_validator_endpoint().write().await;
                            *val_ep = Some(new_addr.clone());
                        }
                        heartbeat_validator_addr = new_addr;
                        // Invalidate cached connection after re-registration
                        cached_conn = None;
                        // Jitter before the next heartbeat to prevent thundering
                        // herd when many miners re-register simultaneously
                        // (e.g. after a validator restart).
                        let jitter_ms = rand::random::<u64>() % 5000;
                        tokio::time::sleep(tokio::time::Duration::from_millis(jitter_ms)).await;
                    }
                    Err(e) => {
                        error!(error = %e, "Re-registration failed, will retry on next heartbeat");
                        // Set flag again to retry
                        get_needs_reregistration().store(true, std::sync::atomic::Ordering::SeqCst);
                        // Jitter avoids all miners retrying registration simultaneously
                        let retry_jitter_ms = rand::random::<u64>() % 10_000;
                        tokio::time::sleep(
                            tokio::time::Duration::from_secs(5)
                                + tokio::time::Duration::from_millis(retry_jitter_ms),
                        )
                        .await;
                        continue;
                    }
                }
            }

            // Periodically refresh validator address from environment
            heartbeat_count = heartbeat_count.wrapping_add(1);
            if heartbeat_count.is_multiple_of(VALIDATOR_ADDR_REFRESH_INTERVAL)
                && let Ok(new_validator_id) = std::env::var("VALIDATOR_NODE_ID")
                && let Ok(new_pubkey) = iroh::PublicKey::from_str(&new_validator_id)
                && new_pubkey != current_validator_pubkey
            {
                debug!(
                    old = %truncate_for_log(&current_validator_pubkey.to_string(), 16),
                    new = %truncate_for_log(&new_validator_id, 16),
                    "Validator address refreshed from environment"
                );
                current_validator_pubkey = new_pubkey;
                heartbeat_validator_addr = build_validator_addr(
                    &current_validator_pubkey,
                    &validator_direct_addrs,
                    &relay_url,
                );

                // Update stored validator endpoint
                {
                    let mut val_ep = get_validator_endpoint().write().await;
                    *val_ep = Some(heartbeat_validator_addr.clone());
                }

                // Invalidate cached connection for old validator
                cached_conn = None;

                // Trigger re-registration with new validator
                get_needs_reregistration().store(true, std::sync::atomic::Ordering::SeqCst);
                continue;
            }

            // Skip heartbeat if no UDP path to the validator (relay-only or none).
            // This makes the validator's last_seen age out naturally, which
            // triggers offline detection and excludes the miner from placement.
            // Mixed (UDP + relay fallback) is accepted — the UDP path works.
            if !has_udp_path_to_validator(&endpoint, current_validator_pubkey) {
                use iroh::Watcher as _;
                let state = endpoint
                    .conn_type(current_validator_pubkey)
                    .map(|mut w| format!("{:?}", w.get()))
                    .unwrap_or_else(|| "None".to_string());
                warn!(
                    conn_type = %state,
                    "Skipping heartbeat: relay-only connection to validator. \
                     Miner will not receive shards until UDP connectivity is established."
                );
                get_validator_reachable().store(false, std::sync::atomic::Ordering::Relaxed);
                cached_conn = None;
                consecutive_failures = consecutive_failures.saturating_add(1);
                let backoff_secs = std::cmp::min(120, 30u64 << consecutive_failures.min(2));
                let jitter_ms = rand::random::<u64>() % 5000;
                tokio::time::sleep(
                    tokio::time::Duration::from_secs(backoff_secs)
                        + tokio::time::Duration::from_millis(jitter_ms),
                )
                .await;
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
                    version: Some(env!("CARGO_PKG_VERSION").to_string()),
                }
            };

            // Reuse cached connection or establish a new one
            let conn = match cached_conn.as_ref() {
                Some(c) if c.close_reason().is_none() => Ok(c.clone()),
                _ => {
                    cached_conn = None;
                    let connect_result = tokio::time::timeout(
                        std::time::Duration::from_secs(10),
                        endpoint.connect(
                            heartbeat_validator_addr.clone(),
                            b"hippius/validator-control",
                        ),
                    )
                    .await;
                    match connect_result {
                        Ok(Ok(new_conn)) => {
                            cached_conn = Some(new_conn.clone());
                            Ok(new_conn)
                        }
                        Ok(Err(e)) => Err(format!("Heartbeat connection failed: {e}")),
                        Err(_) => Err("Heartbeat connection timed out".to_string()),
                    }
                }
            };

            match conn {
                Ok(conn) => {
                    // Wrap entire heartbeat exchange in a single timeout to prevent
                    // stalling on write_all/stopped if the validator's receive buffer is full.
                    let result = tokio::time::timeout(std::time::Duration::from_secs(15), async {
                        let (mut send, mut recv) = conn.open_bi().await?;

                        let msg_bytes = serde_json::to_vec(&heartbeat_msg)?;
                        send.write_all(&msg_bytes).await?;
                        send.finish()?;

                        // Read ACK
                        let ack_bytes = recv.read_to_end(1024).await?;

                        let ack_str = String::from_utf8_lossy(&ack_bytes);
                        if ack_str.starts_with("FAMILY_REJECTED:") {
                            error!(response = %ack_str, "Heartbeat rejected — miner cannot operate, shutting down");
                            // Allow tracing subscriber to flush before hard exit
                            tokio::time::sleep(std::time::Duration::from_millis(100)).await;
                            std::process::exit(1);
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

                        // Try to parse JSON response for warden node IDs (new validator format)
                        if let Ok(response) = serde_json::from_str::<serde_json::Value>(&ack_str)
                            && let Some(ids) =
                                response.get("warden_node_ids").and_then(|v| v.as_array())
                        {
                            let mut new_ids = Vec::new();
                            for id in ids {
                                if let Some(s) = id.as_str()
                                    && let Ok(pk) = iroh::PublicKey::from_str(s)
                                {
                                    new_ids.push(pk);
                                }
                            }
                            if !new_ids.is_empty() {
                                // Sort for deterministic comparison (validator sends from HashSet)
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

                        Ok::<_, anyhow::Error>(true)
                    })
                    .await;

                    match result {
                        Ok(Ok(true)) => {
                            consecutive_failures = 0;
                            get_validator_reachable()
                                .store(true, std::sync::atomic::Ordering::Relaxed);
                        }
                        Ok(Ok(false)) => {
                            // Validator is warming up -- reachable but not ready.
                            // Don't increment failures; use short retry (5s).
                            get_validator_reachable()
                                .store(true, std::sync::atomic::Ordering::Relaxed);
                            let jitter_ms = rand::random::<u64>() % 2000;
                            tokio::time::sleep(
                                tokio::time::Duration::from_secs(5)
                                    + tokio::time::Duration::from_millis(jitter_ms),
                            )
                            .await;
                            continue;
                        }
                        Ok(Err(e)) => {
                            warn!(error = %e, "Heartbeat error");
                            cached_conn = None;
                            consecutive_failures = consecutive_failures.saturating_add(1);
                            get_validator_reachable()
                                .store(false, std::sync::atomic::Ordering::Relaxed);
                        }
                        Err(_) => {
                            warn!("Heartbeat exchange timed out (15s)");
                            cached_conn = None;
                            consecutive_failures = consecutive_failures.saturating_add(1);
                            get_validator_reachable()
                                .store(false, std::sync::atomic::Ordering::Relaxed);
                        }
                    }
                }
                Err(e) => {
                    warn!(error = %e, "Heartbeat connection unavailable");
                    consecutive_failures = consecutive_failures.saturating_add(1);
                    get_validator_reachable().store(false, std::sync::atomic::Ordering::Relaxed);
                }
            }

            // Exponential backoff: 30s, 60s, 120s (capped) on consecutive failures
            let backoff_secs = if consecutive_failures == 0 {
                30
            } else {
                std::cmp::min(120, 30u64 << consecutive_failures.min(2))
            };
            let jitter_ms = rand::random::<u64>() % 5000;
            tokio::time::sleep(
                tokio::time::Duration::from_secs(backoff_secs)
                    + tokio::time::Duration::from_millis(jitter_ms),
            )
            .await;
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
    validator_direct_addrs: &[std::net::SocketAddr],
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

        // Resolve hostname to IP once — reused for both endpoint_addr hints
        // and http_addr so the validator/chain-submitter gets a real IP,
        // not a K8s pod name.
        let resolved_ip = if hostname == "localhost" {
            Some(std::net::IpAddr::V4(std::net::Ipv4Addr::LOCALHOST))
        } else if let Ok(ip) = hostname.parse::<std::net::IpAddr>() {
            Some(ip)
        } else {
            use std::net::ToSocketAddrs;
            format!("{}:{}", hostname, config.network.p2p_port)
                .to_socket_addrs()
                .ok()
                .and_then(|mut addrs| addrs.find(|a| a.is_ipv4()))
                .map(|a| a.ip())
        };

        let my_endpoint_addr = {
            let mut addr = iroh::EndpointAddr::new(node_id);
            if let Some(url) = relay_url {
                addr = addr.with_relay_url(url.clone());
            }

            // Add direct address hint so the validator can reach us
            // without routing through the relay.
            if let Some(ip) = resolved_ip {
                let direct_addr = std::net::SocketAddr::new(ip, config.network.p2p_port);
                let transport_addr = iroh::TransportAddr::Ip(direct_addr);
                addr = addr.with_addrs(vec![transport_addr]);
                info!(%ip, p2p_port = config.network.p2p_port, "Including direct address hint in registration");
            } else {
                warn!(
                    hostname = hostname,
                    "Could not resolve hostname to IP — registering with relay-only address"
                );
            }

            Some(addr)
        };

        // Send the resolved IP in http_addr when available.
        // For localhost keep the original URL (validator uses it for local
        // testing hints). For everything else, send just the IP.
        let resolved_http_addr = match resolved_ip {
            Some(ip) if ip.is_loopback() => http_addr.to_string(),
            Some(ip) => ip.to_string(),
            None => http_addr.to_string(),
        };

        common::ValidatorControlMessage::Register {
            public_key: public_key_str,
            http_addr: resolved_http_addr,
            total_storage: total,
            available_storage: reported_available,
            family_id: family_id.to_string(),
            timestamp,
            signature: signature.to_bytes().to_vec(),
            endpoint_addr: my_endpoint_addr,
            version: Some(env!("CARGO_PKG_VERSION").to_string()),
        }
    };

    // Connect to validator via P2P with direct address hints
    let validator_addr = build_validator_addr(validator_pubkey, validator_direct_addrs, relay_url);

    let conn = tokio::time::timeout(
        std::time::Duration::from_secs(10),
        endpoint.connect(validator_addr, b"hippius/validator-control"),
    )
    .await
    .map_err(|_| anyhow::anyhow!("Connection timeout"))?
    .map_err(|e| anyhow::anyhow!("Connection failed: {}", e))?;

    // Verify UDP path exists — relay-only miners cannot receive shards.
    if !has_udp_path_to_validator(endpoint, *validator_pubkey) {
        return Err(anyhow::anyhow!(
            "Connection is relay-only, no UDP path to validator. \
             Waiting for hole-punching to complete."
        ));
    }

    let (mut send, mut recv) = conn.open_bi().await?;
    let msg_bytes = serde_json::to_vec(&register_msg)?;
    send.write_all(&msg_bytes).await?;
    send.finish()?;

    // Wait for ACK
    let ack = tokio::time::timeout(std::time::Duration::from_secs(10), recv.read_to_end(4096))
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

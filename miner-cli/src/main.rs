//! Miner CLI for on-chain registration with pallet-arion.
//!
//! This tool manages the lifecycle of miner registration on the Hippius blockchain.
//! Miners must be registered on-chain to participate in the storage network and
//! receive rewards.
//!
//! # Registration Model
//!
//! The pallet uses a family/child hierarchy:
//! - **Family**: Parent account that registers and manages miners
//! - **Child**: Delegate account that receives rewards for a specific miner
//! - **NodeId**: Ed25519 public key (Iroh identity) linking the P2P node to on-chain registration
//!
//! ```text
//! Family Account (signs transactions)
//!     └── Child Account (receives rewards)
//!             └── NodeId (miner P2P identity)
//! ```
//!
//! # Commands
//!
//! - `show-node-id`: Display miner's P2P identity (NodeId)
//! - `register-child`: Register a new miner under a family
//! - `deregister-child`: Begin unbonding process (starts cooldown)
//! - `claim-unbonded`: Reclaim deposit after cooldown expires
//!
//! # Security
//!
//! The family mnemonic is sensitive - it controls registration and deposits.
//! Prefer `--family-mnemonic-file` over CLI arguments to avoid shell history exposure.
//!
//! # Example Usage
//!
//! ```bash
//! # View miner's node ID
//! miner-cli --chain-ws-url ws://127.0.0.1:9944 \
//!     --family-mnemonic-file /secure/mnemonic.txt \
//!     show-node-id
//!
//! # Register a miner
//! miner-cli --chain-ws-url ws://127.0.0.1:9944 \
//!     --family-mnemonic-file /secure/mnemonic.txt \
//!     register-child --child-ss58 5GrwvaEF...
//! ```

use anyhow::{Context, Result, anyhow};
use clap::{Parser, Subcommand};
use parity_scale_codec::Encode;
use std::path::{Path, PathBuf};
use std::time::Duration;
use subxt::{OnlineClient, config::PolkadotConfig, dynamic};
use subxt_signer::sr25519::Keypair;
use tokio::time::timeout;
use tracing::{error, info};

// ============================================================================
// Constants
// ============================================================================

/// Timeout for transaction operations (submission + finalization).
/// Set to 2 minutes to account for block production delays.
const TX_TIMEOUT: Duration = Duration::from_secs(120);

// ============================================================================
// CLI Configuration
// ============================================================================

/// Miner CLI for on-chain registration and identity management.
#[derive(Parser, Clone)]
#[command(author, version, about)]
struct Args {
    /// Substrate WebSocket URL (e.g., ws://127.0.0.1:9944)
    #[arg(long, env = "CHAIN_WS_URL")]
    chain_ws_url: String,

    /// Override pallet name if auto-detection fails (usually "Arion" or "arion")
    #[arg(long, env = "ARION_PALLET_NAME", default_value = "")]
    arion_pallet_name: String,

    /// Mnemonic phrase for the family account (signs registration transactions).
    /// SECURITY: Prefer --family-mnemonic-file to avoid shell history exposure.
    #[arg(long, env = "FAMILY_MNEMONIC", conflicts_with = "family_mnemonic_file")]
    family_mnemonic: Option<String>,

    /// Path to file containing the mnemonic phrase (more secure than CLI argument).
    /// File should contain only the mnemonic with optional whitespace.
    #[arg(long, env = "FAMILY_MNEMONIC_FILE", conflicts_with = "family_mnemonic")]
    family_mnemonic_file: Option<std::path::PathBuf>,

    #[command(subcommand)]
    cmd: Command,
}

// Manual Debug implementation to redact sensitive mnemonic
impl std::fmt::Debug for Args {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Args")
            .field("chain_ws_url", &self.chain_ws_url)
            .field("arion_pallet_name", &self.arion_pallet_name)
            .field("family_mnemonic", &"[REDACTED]")
            .field("family_mnemonic_file", &self.family_mnemonic_file)
            .field("cmd", &self.cmd)
            .finish()
    }
}

// ============================================================================
// Mnemonic Handling
// ============================================================================

/// Loads mnemonic from a file with security checks.
///
/// # Security Checks
/// - Verifies file exists
/// - On Unix: warns if file permissions are not restrictive (should be 600)
/// - Validates mnemonic is not empty
///
/// # Arguments
/// * `path` - Path to the mnemonic file
///
/// # Returns
/// The trimmed mnemonic string, or an error if loading fails
fn load_mnemonic_from_file(path: &std::path::Path) -> Result<String> {
    // Check file exists
    if !path.exists() {
        return Err(anyhow!("Mnemonic file not found: {}", path.display()));
    }

    // Check file permissions on Unix (should be 600 or more restrictive)
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        let meta = std::fs::metadata(path).with_context(|| {
            format!("Failed to read mnemonic file metadata: {}", path.display())
        })?;
        let mode = meta.mode();
        if mode & 0o077 != 0 {
            tracing::warn!(
                "Mnemonic file {} has insecure permissions (mode {:o}). Should be 600. Run: chmod 600 {}",
                path.display(),
                mode & 0o777,
                path.display()
            );
        }
    }

    // Read and trim the mnemonic
    let content = std::fs::read_to_string(path)
        .with_context(|| format!("Failed to read mnemonic file: {}", path.display()))?;

    let mnemonic = content.trim().to_string();
    if mnemonic.is_empty() {
        return Err(anyhow!("Mnemonic file is empty: {}", path.display()));
    }

    Ok(mnemonic)
}

/// Retrieves mnemonic from available sources (CLI arg, file, or env var).
///
/// Priority order:
/// 1. `--family-mnemonic` CLI argument
/// 2. `--family-mnemonic-file` file path
/// 3. `FAMILY_MNEMONIC` environment variable (via clap)
fn get_mnemonic(args: &Args) -> Result<String> {
    if let Some(ref mnemonic) = args.family_mnemonic {
        return Ok(mnemonic.clone());
    }

    if let Some(ref file_path) = args.family_mnemonic_file {
        return load_mnemonic_from_file(file_path);
    }

    Err(anyhow!(
        "No mnemonic provided. Use --family-mnemonic, --family-mnemonic-file, or set FAMILY_MNEMONIC env var"
    ))
}

#[derive(Subcommand, Debug, Clone)]
enum Command {
    /// Print this machine's miner node_id (ed25519 pubkey) as hex and iroh string.
    ShowNodeId {
        /// Miner data dir that contains keypair.bin (default: data/miner)
        #[arg(long, env = "MINER_DATA_DIR", default_value = "data/miner")]
        miner_data_dir: PathBuf,
    },

    /// Register a miner child under this family in pallet-arion.
    ///
    /// Note: the pallet currently requires the **family account** to sign the extrinsic (origin == family).
    RegisterChild {
        /// Child account SS58 (delegate) to register.
        #[arg(long, env = "CHILD_SS58")]
        child_ss58: String,

        /// Miner data dir that contains keypair.bin (default: data/miner)
        #[arg(long, env = "MINER_DATA_DIR", default_value = "data/miner")]
        miner_data_dir: PathBuf,
    },

    /// Deregister a child (starts unbonding + cooldown; origin must be family).
    DeregisterChild {
        /// Child account SS58
        #[arg(long, env = "CHILD_SS58")]
        child_ss58: String,
    },

    /// Claim unbonded deposit for a child (origin must be family).
    ClaimUnbonded {
        /// Child account SS58
        #[arg(long, env = "CHILD_SS58")]
        child_ss58: String,
    },
}

// ============================================================================
// Runtime Introspection
// ============================================================================

/// Auto-detects the arion pallet name from runtime metadata.
///
/// Searches for a pallet containing the `register_child` extrinsic.
fn detect_arion_pallet_name(client: &OnlineClient<PolkadotConfig>) -> Result<String> {
    for p in client.metadata().pallets() {
        if p.call_hash("register_child").is_some() {
            return Ok(p.name().to_string());
        }
    }
    Err(anyhow!(
        "Could not auto-detect arion pallet name from metadata (no call named register_child)"
    ))
}

// ============================================================================
// Account and Key Helpers
// ============================================================================

/// Parses an SS58-encoded AccountId32 string.
fn parse_account_id32(s: &str) -> Result<subxt::utils::AccountId32> {
    s.parse::<subxt::utils::AccountId32>()
        .map_err(|e| anyhow!("invalid SS58 AccountId32: {e:?}"))
}

/// Loads the miner's Ed25519 secret key from the data directory.
///
/// The key is stored in `keypair.bin` within the miner's data directory.
/// On Unix, warns if file permissions are too permissive.
async fn load_miner_secret_key(data_dir: &Path) -> Result<iroh_base::SecretKey> {
    let keypair_path = data_dir.join("keypair.bin");

    // Check file permissions on Unix systems
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        if let Ok(meta) = tokio::fs::metadata(&keypair_path).await {
            let mode = meta.mode();
            if mode & 0o077 != 0 {
                tracing::warn!(
                    "Keypair file {} has insecure permissions (mode {:o}). Consider: chmod 600 {}",
                    keypair_path.display(),
                    mode & 0o777,
                    keypair_path.display()
                );
            }
        }
    }

    let bytes = tokio::fs::read(&keypair_path)
        .await
        .with_context(|| format!("read miner keypair: {}", keypair_path.display()))?;
    iroh_base::SecretKey::try_from(&bytes[..]).map_err(|e| anyhow!("invalid keypair.bin: {e:?}"))
}

// ============================================================================
// On-Chain Storage Helpers
// ============================================================================

/// Fetches the current nonce for a NodeId from on-chain storage.
///
/// The nonce is used for replay protection in registration messages.
/// Returns 0 if the NodeId has never been registered.
async fn fetch_node_id_nonce(
    client: &OnlineClient<PolkadotConfig>,
    pallet_name: &str,
    node_id: [u8; 32],
) -> Result<u64> {
    let key = dynamic::Value::from_bytes(node_id);
    let addr = dynamic::storage(pallet_name, "NodeIdNonce", vec![key]);
    let at = client.storage().at_latest().await?;
    let v = at.fetch(&addr).await?;
    if let Some(thunk) = v {
        Ok(thunk.as_type::<u64>()?)
    } else {
        Ok(0)
    }
}

/// Constructs the registration message that the miner signs.
///
/// The message format must match the pallet's verification:
/// `(b"ARION_NODE_REG_V1", family, child, node_id, nonce).encode()`
///
/// The nonce prevents replay attacks - each registration increments it.
fn registration_message(
    family: &subxt::utils::AccountId32,
    child: &subxt::utils::AccountId32,
    node_id: &[u8; 32],
    nonce: u64,
) -> Vec<u8> {
    const DOMAIN: &[u8; 17] = b"ARION_NODE_REG_V1";
    (DOMAIN, family, child, node_id, nonce).encode()
}

#[tokio::main]
async fn main() -> Result<()> {
    dotenvy::dotenv().ok();
    tracing_subscriber::fmt()
        .with_env_filter(tracing_subscriber::EnvFilter::from_default_env())
        .init();

    tracing::info!("");
    tracing::info!(" /$$   /$$ /$$$$$$ /$$$$$$$  /$$$$$$$  /$$$$$$ /$$   /$$  /$$$$$$ ");
    tracing::info!("| $$  | $$|_  $$_/| $$__  $$| $$__  $$|_  $$_/| $$  | $$ /$$__  $$");
    tracing::info!("| $$  | $$  | $$  | $$  \\ $$| $$  \\ $$  | $$  | $$  | $$| $$  \\__/");
    tracing::info!("| $$$$$$$$  | $$  | $$$$$$$/| $$$$$$$/  | $$  | $$  | $$|  $$$$$$ ");
    tracing::info!("| $$__  $$  | $$  | $$____/ | $$____/   | $$  | $$  | $$ \\____  $$");
    tracing::info!("| $$  | $$  | $$  | $$      | $$        | $$  | $$  | $$ /$$  \\ $$");
    tracing::info!("| $$  | $$ /$$$$$$| $$      | $$       /$$$$$$|  $$$$$$/|  $$$$$$/");
    tracing::info!("|__/  |__/|______/|__/      |__/      |______/ \\______/  \\______/ ");
    tracing::info!("");
    tracing::info!("=========================================================================");
    tracing::info!("                     Hippius Miner CLI Starting");
    tracing::info!("=========================================================================");

    let args = Args::parse();

    let mnemonic_str = get_mnemonic(&args)?;
    let mnemonic =
        bip39::Mnemonic::parse(&mnemonic_str).map_err(|e| anyhow!("invalid mnemonic: {e}"))?;
    let signer =
        Keypair::from_phrase(&mnemonic, None).map_err(|e| anyhow!("invalid mnemonic: {e}"))?;
    let family_pub = signer.public_key();
    let family = subxt::utils::AccountId32(family_pub.0);

    tracing::info!("Connecting to chain WS: {}", args.chain_ws_url);
    let mut retries = 3u32;
    let client = loop {
        match tokio::time::timeout(
            std::time::Duration::from_secs(30),
            OnlineClient::<PolkadotConfig>::from_url(&args.chain_ws_url),
        )
        .await
        {
            Ok(Ok(c)) => break c,
            Ok(Err(e)) if retries > 0 => {
                retries -= 1;
                tracing::warn!(
                    "Connection failed ({}), retrying ({} attempts left)",
                    e,
                    retries
                );
                tokio::time::sleep(std::time::Duration::from_secs(5)).await;
            }
            Ok(Err(e)) => anyhow::bail!("Failed to connect to blockchain: {}", e),
            Err(_) if retries > 0 => {
                retries -= 1;
                tracing::warn!("Connection timed out, retrying ({} attempts left)", retries);
                tokio::time::sleep(std::time::Duration::from_secs(5)).await;
            }
            Err(_) => anyhow::bail!("Connection to blockchain timed out"),
        }
    };

    let pallet_name = if args.arion_pallet_name.trim().is_empty() {
        detect_arion_pallet_name(&client)?
    } else {
        args.arion_pallet_name.clone()
    };
    tracing::info!("Using arion pallet name: {}", pallet_name);

    match args.cmd {
        Command::ShowNodeId { miner_data_dir } => {
            let sk = load_miner_secret_key(&miner_data_dir).await?;
            let pk = sk.public();
            println!("node_id (iroh string): {}", pk);
            println!("node_id (hex32): 0x{}", hex::encode(pk.as_bytes()));
            Ok(())
        }
        Command::RegisterChild {
            child_ss58,
            miner_data_dir,
        } => {
            let child = parse_account_id32(&child_ss58)?;
            let sk = load_miner_secret_key(&miner_data_dir).await?;
            let node_pk = sk.public();
            let node_id: [u8; 32] = *node_pk.as_bytes();

            info!("Pre-registration checks...");
            info!("   Family: 0x{}", hex::encode(family.0));
            info!("   Child:  0x{}", hex::encode(child.0));
            info!("   Node ID: 0x{}", hex::encode(node_id));

            // Check if child is already registered
            let child_addr = dynamic::storage(
                &pallet_name,
                "ChildRegistrations",
                vec![dynamic::Value::from_bytes(child.0)],
            );
            if let Some(_reg) = client
                .storage()
                .at_latest()
                .await?
                .fetch(&child_addr)
                .await?
            {
                error!("Child account is ALREADY REGISTERED");
                error!("   Child SS58: {}", child_ss58);
                error!("Solution: Deregister first, then wait for cooldown period");
                error!(
                    "   Command: cargo run --release -- --chain-ws-url ws://127.0.0.1:9944 --family-mnemonic \"YOUR_MNEMONIC\" deregister-child --child-ss58 {}",
                    child_ss58
                );
                return Err(anyhow!(
                    "Child account {} is already registered. Deregister first!",
                    child_ss58
                ));
            }
            info!("   Child account not registered");

            // Check if node_id is already mapped to a child
            let node_addr = dynamic::storage(
                &pallet_name,
                "NodeIdToChild",
                vec![dynamic::Value::from_bytes(node_id)],
            );
            if let Some(_existing_child) = client
                .storage()
                .at_latest()
                .await?
                .fetch(&node_addr)
                .await?
            {
                error!("Node ID is ALREADY MAPPED to another child");
                error!("   Node ID: 0x{}", hex::encode(node_id));
                error!(
                    "Solution: This node_id is still registered. Deregister the old child first, then wait for cooldown"
                );
                return Err(anyhow!(
                    "Node ID 0x{} is already mapped to another child account",
                    hex::encode(node_id)
                ));
            }
            info!("   Node ID not mapped");

            // Check for child cooldown
            let child_cooldown_addr = dynamic::storage(
                &pallet_name,
                "ChildCooldownUntil",
                vec![dynamic::Value::from_bytes(child.0)],
            );
            if let Some(cooldown_block) = client
                .storage()
                .at_latest()
                .await?
                .fetch(&child_cooldown_addr)
                .await?
            {
                let current_block = client.blocks().at_latest().await?.number();
                let cooldown_val: u32 = cooldown_block.as_type()?;
                if cooldown_val > current_block {
                    error!("Child account is in COOLDOWN period");
                    error!("   Current block: {}", current_block);
                    error!("   Cooldown until: {}", cooldown_val);
                    error!("   Blocks remaining: {}", cooldown_val - current_block);
                    error!(
                        "Solution: Wait {} more blocks before registering",
                        cooldown_val - current_block
                    );
                    return Err(anyhow!(
                        "Child account is in cooldown until block {}",
                        cooldown_val
                    ));
                }
            }
            info!("   No child cooldown");

            // Check for node_id cooldown
            let node_cooldown_addr = dynamic::storage(
                &pallet_name,
                "NodeIdCooldownUntil",
                vec![dynamic::Value::from_bytes(node_id)],
            );
            if let Some(cooldown_block) = client
                .storage()
                .at_latest()
                .await?
                .fetch(&node_cooldown_addr)
                .await?
            {
                let current_block = client.blocks().at_latest().await?.number();
                let cooldown_val: u32 = cooldown_block.as_type()?;
                if cooldown_val > current_block {
                    error!("Node ID is in COOLDOWN period");
                    error!("   Current block: {}", current_block);
                    error!("   Cooldown until: {}", cooldown_val);
                    error!("   Blocks remaining: {}", cooldown_val - current_block);
                    error!(
                        "Solution: Wait {} more blocks before registering",
                        cooldown_val - current_block
                    );
                    return Err(anyhow!(
                        "Node ID is in cooldown until block {}",
                        cooldown_val
                    ));
                }
            }
            info!("   No node_id cooldown");
            info!("All checks passed!");

            let nonce = fetch_node_id_nonce(&client, &pallet_name, node_id).await?;
            info!("Registration details:");
            info!("   Nonce: {}", nonce);

            let msg = registration_message(&family, &child, &node_id, nonce);
            let sig = sk.sign(&msg).to_bytes();
            info!("   Signature: 0x{}", hex::encode(sig));

            let tx = dynamic::tx(
                &pallet_name,
                "register_child",
                vec![
                    dynamic::Value::from_bytes(family.0),
                    dynamic::Value::from_bytes(child.0),
                    dynamic::Value::from_bytes(node_id),
                    dynamic::Value::from_bytes(sig),
                ],
            );

            info!("Submitting register_child transaction...");
            tracing::info!(
                "Submitting register_child family=0x{} child=0x{} node_id=0x{} nonce={}",
                hex::encode(family.0),
                hex::encode(child.0),
                hex::encode(node_id),
                nonce
            );

            let tx_progress = match timeout(
                TX_TIMEOUT,
                client.tx().sign_and_submit_then_watch_default(&tx, &signer),
            )
            .await
            {
                Ok(Ok(p)) => p,
                Ok(Err(e)) => {
                    error!("Transaction FAILED (could not be included)");
                    error!("Error details: {:?}", e);
                    error!("Common causes:");
                    error!("   - Insufficient balance for transaction fees");
                    error!("   - Invalid transaction");
                    return Err(anyhow!("register_child transaction failed: {}", e));
                }
                Err(_) => {
                    error!(
                        "Transaction submission timed out after {} seconds",
                        TX_TIMEOUT.as_secs()
                    );
                    return Err(anyhow!(
                        "Transaction submission timed out after {} seconds",
                        TX_TIMEOUT.as_secs()
                    ));
                }
            };

            info!("Transaction included in block");

            // Check if extrinsic succeeded
            match timeout(TX_TIMEOUT, tx_progress.wait_for_finalized_success()).await {
                Ok(Ok(_)) => {
                    info!("SUCCESS: Miner registered on-chain");
                    println!("Verify with:");
                    println!(
                        "   Polkadot.js Apps > Chain State > arion > childRegistrations({})",
                        child_ss58
                    );
                    Ok(())
                }
                Ok(Err(e)) => {
                    error!(
                        "EXTRINSIC FAILED (transaction was included but failed during execution)"
                    );
                    error!("Error: {:?}", e);
                    error!("Common causes:");
                    error!(
                        "   - Insufficient balance for deposit (family needs funds for ChildDepositBase)"
                    );
                    error!("   - Family account balance: Check on Polkadot.js Apps");
                    error!("   - Registration limit reached");
                    error!("   - Invalid signature or parameters");
                    Err(anyhow!("register_child extrinsic failed: {}", e))
                }
                Err(_) => {
                    error!(
                        "Transaction finalization timed out after {} seconds",
                        TX_TIMEOUT.as_secs()
                    );
                    Err(anyhow!(
                        "Transaction finalization timed out after {} seconds",
                        TX_TIMEOUT.as_secs()
                    ))
                }
            }
        }
        Command::DeregisterChild { child_ss58 } => {
            let child = parse_account_id32(&child_ss58)?;
            let tx = dynamic::tx(
                &pallet_name,
                "deregister_child",
                vec![dynamic::Value::from_bytes(child.0)],
            );
            tracing::info!(
                "Submitting deregister_child family=0x{} child=0x{}",
                hex::encode(family.0),
                hex::encode(child.0)
            );
            let tx_progress = match timeout(
                TX_TIMEOUT,
                client.tx().sign_and_submit_then_watch_default(&tx, &signer),
            )
            .await
            {
                Ok(Ok(p)) => p,
                Ok(Err(e)) => {
                    return Err(anyhow!("deregister_child transaction failed: {}", e));
                }
                Err(_) => {
                    return Err(anyhow!(
                        "Transaction submission timed out after {} seconds",
                        TX_TIMEOUT.as_secs()
                    ));
                }
            };

            match timeout(TX_TIMEOUT, tx_progress.wait_for_finalized_success()).await {
                Ok(Ok(_events)) => {
                    info!("Deregistration finalized successfully");
                }
                Ok(Err(e)) => {
                    error!(error = %e, "Deregistration failed");
                    return Err(anyhow!("Deregistration failed: {}", e));
                }
                Err(_) => {
                    return Err(anyhow!(
                        "Transaction finalization timed out after {} seconds",
                        TX_TIMEOUT.as_secs()
                    ));
                }
            }
            Ok(())
        }
        Command::ClaimUnbonded { child_ss58 } => {
            let child = parse_account_id32(&child_ss58)?;
            let tx = dynamic::tx(
                &pallet_name,
                "claim_unbonded",
                vec![dynamic::Value::from_bytes(child.0)],
            );
            tracing::info!(
                "Submitting claim_unbonded family=0x{} child=0x{}",
                hex::encode(family.0),
                hex::encode(child.0)
            );
            let tx_progress = match timeout(
                TX_TIMEOUT,
                client.tx().sign_and_submit_then_watch_default(&tx, &signer),
            )
            .await
            {
                Ok(Ok(p)) => p,
                Ok(Err(e)) => {
                    return Err(anyhow!("claim_unbonded transaction failed: {}", e));
                }
                Err(_) => {
                    return Err(anyhow!(
                        "Transaction submission timed out after {} seconds",
                        TX_TIMEOUT.as_secs()
                    ));
                }
            };

            match timeout(TX_TIMEOUT, tx_progress.wait_for_finalized_success()).await {
                Ok(Ok(_events)) => {
                    info!("Claim unbonded finalized successfully");
                }
                Ok(Err(e)) => {
                    error!(error = %e, "Claim unbonded failed");
                    return Err(anyhow!("Claim unbonded failed: {}", e));
                }
                Err(_) => {
                    return Err(anyhow!(
                        "Transaction finalization timed out after {} seconds",
                        TX_TIMEOUT.as_secs()
                    ));
                }
            }
            Ok(())
        }
    }
}

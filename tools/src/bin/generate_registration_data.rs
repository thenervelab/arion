//! Generate registration data for on-chain miner registration.
//!
//! This tool creates the signed registration message required by pallet-arion's
//! `register_child` extrinsic. It reads the miner's keypair and generates the
//! Ed25519 signature over the registration message.
//!
//! # Registration Message Format
//!
//! The message format is defined by pallet-arion:
//! ```text
//! (b"ARION_NODE_REG_V1", family_account, child_account, node_id, nonce).encode()
//! ```
//!
//! # Output
//!
//! Produces hex-encoded values for use in Polkadot.js Apps or miner-cli:
//! - `node_id`: Ed25519 public key (32 bytes)
//! - `node_sig`: Ed25519 signature (64 bytes)
//!
//! With `--output-json`, produces machine-readable JSON:
//! ```json
//! {"miner_id":1,"family":"5Grw...","child":"5FHn...","node_id":"0x...","node_sig":"0x..."}
//! ```
//!
//! # Example Usage
//!
//! ```bash
//! # Human-readable output
//! generate_registration_data \
//!     --family 5GrwvaEF... \
//!     --child 5FHneW46... \
//!     --miner-id 1 \
//!     --keypair data/miner-1/keypair.bin
//!
//! # Machine-readable JSON output
//! generate_registration_data \
//!     --family 5GrwvaEF... \
//!     --child 5FHneW46... \
//!     --miner-id 1 \
//!     --keypair data/miner-1/keypair.bin \
//!     --output-json
//! ```
//!
//! # Security
//!
//! The keypair file contains the miner's secret key - ensure restrictive permissions (600).
//! The generated signature should only be used once and not shared publicly.

use anyhow::{Context, Result, anyhow};
use clap::Parser;
use parity_scale_codec::Encode;
use std::path::PathBuf;
use tracing_subscriber::EnvFilter;

// ============================================================================
// CLI Configuration
// ============================================================================

/// Generate registration signatures for on-chain miner registration.
#[derive(Parser)]
#[command(about = "Generate registration signatures for miners")]
struct Args {
    /// Family account SS58 address (parent that manages the miner)
    #[arg(long)]
    family: String,

    /// Child account SS58 address (receives rewards for this miner)
    #[arg(long)]
    child: String,

    /// Miner ID for display purposes (e.g., 1 for miner-1)
    #[arg(long)]
    miner_id: usize,

    /// Path to miner keypair file (32-byte Ed25519 secret key)
    #[arg(long)]
    keypair: PathBuf,

    /// Node ID nonce for replay protection (usually 0 for first registration)
    #[arg(long, default_value = "0")]
    nonce: u64,

    /// Output as JSON instead of human-readable format (for scripted consumption)
    #[arg(long)]
    output_json: bool,
}

// ============================================================================
// Message Construction
// ============================================================================

/// Constructs the registration message that the miner must sign.
///
/// The message format matches pallet-arion's verification:
/// `(b"ARION_NODE_REG_V1", family, child, node_id, nonce).encode()`
fn registration_message(
    family: &subxt::utils::AccountId32,
    child: &subxt::utils::AccountId32,
    node_id: &[u8; 32],
    nonce: u64,
) -> Vec<u8> {
    const DOMAIN: &[u8; 17] = b"ARION_NODE_REG_V1";
    (DOMAIN, family, child, node_id, nonce).encode()
}

fn main() -> Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(EnvFilter::from_default_env())
        .init();

    let args = Args::parse();

    let family: subxt::utils::AccountId32 = args
        .family
        .parse()
        .map_err(|e| anyhow!("invalid family SS58: {:?}", e))?;

    let child: subxt::utils::AccountId32 = args
        .child
        .parse()
        .map_err(|e| anyhow!("invalid child SS58: {:?}", e))?;

    // Read keypair file (32 bytes - Ed25519 secret key)
    // Check size before reading to fail fast on wrong file
    let metadata = std::fs::metadata(&args.keypair)
        .with_context(|| format!("stat keypair: {}", args.keypair.display()))?;
    if metadata.len() != 32 {
        anyhow::bail!(
            "Keypair file must be exactly 32 bytes, got {} bytes",
            metadata.len()
        );
    }

    // Security: Check file permissions on Unix (should be 600 or more restrictive)
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        let mode = metadata.mode();
        if mode & 0o077 != 0 {
            tracing::warn!(
                "Keypair file {} has insecure permissions (mode {:o}). Consider: chmod 600 {}",
                args.keypair.display(),
                mode & 0o777,
                args.keypair.display()
            );
        }
    }

    let secret_bytes = std::fs::read(&args.keypair)
        .with_context(|| format!("read keypair: {}", args.keypair.display()))?;

    // Load as iroh SecretKey
    let secret = iroh_base::SecretKey::try_from(&secret_bytes[..])
        .map_err(|e| anyhow!("invalid keypair: {:?}", e))?;
    let public = secret.public();
    let node_id = public.as_bytes();

    // Build registration message
    let message = registration_message(&family, &child, node_id, args.nonce);

    // Sign the message using Ed25519
    let signature = secret.sign(&message);
    let sig_bytes = signature.to_bytes();

    let node_id_hex = format!("0x{}", hex::encode(node_id));
    let node_sig_hex = format!("0x{}", hex::encode(sig_bytes));

    if args.output_json {
        // Machine-readable JSON output for scripted consumption
        println!(
            r#"{{"miner_id":{},"family":"{}","child":"{}","node_id":"{}","node_sig":"{}"}}"#,
            args.miner_id, args.family, child, node_id_hex, node_sig_hex
        );
    } else {
        // Human-readable output for Polkadot.js Apps
        println!("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━");
        println!("MINER-{}", args.miner_id);
        println!("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━");
        println!("family:    {}", args.family);
        println!("child:     {}", child);
        println!();
        println!("node_id:   {}", node_id_hex);
        println!("node_sig:  {}", node_sig_hex);
        println!();
        println!("WARNING: These values are for one-time registration. Do not share publicly.");
    }

    Ok(())
}

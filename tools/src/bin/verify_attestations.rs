//! Attestation verification CLI tool.
//!
//! This tool verifies warden attestation bundles against on-chain commitments.
//!
//! # Verification Steps
//!
//! 1. Query chain for `EpochAttestationCommitments[epoch]`
//! 2. Download bundle from Arion gateway using `arion_content_hash`
//! 3. Verify `BLAKE3(bundle_bytes) == arion_content_hash`
//! 4. Recompute attestation merkle root and compare
//! 5. Recompute warden pubkey merkle root and compare
//! 6. Verify Ed25519 signature on each attestation
//!
//! # Usage
//!
//! ```bash
//! cargo run --bin verify_attestations -- \
//!     --epoch 42 \
//!     --chain-ws-url wss://node:9944 \
//!     --gateway-url http://gateway:3000
//! ```

use anyhow::{Context, Result, anyhow};
use clap::Parser;
use common::{AttestationBundle, AttestationLeaf, build_merkle_tree, verify_merkle_proof};
use ed25519_dalek::{Signature, Verifier, VerifyingKey};
use parity_scale_codec::Decode;
use subxt::{OnlineClient, PolkadotConfig};
use tracing::{debug, error, info, warn};

#[derive(Parser, Debug)]
#[command(
    name = "verify_attestations",
    about = "Verify warden attestation bundles against on-chain commitments"
)]
struct Args {
    /// Epoch to verify
    #[arg(long, env = "VERIFY_EPOCH")]
    epoch: u64,

    /// Substrate/Polkadot chain WebSocket URL
    #[arg(long, env = "CHAIN_WS_URL", default_value = "wss://127.0.0.1:9944")]
    chain_ws_url: String,

    /// Gateway URL for downloading bundles
    #[arg(long, env = "GATEWAY_URL", default_value = "http://127.0.0.1:3000")]
    gateway_url: String,

    /// Pallet name for storage queries
    #[arg(long, default_value = "Arion")]
    pallet_name: String,

    /// Skip signature verification (faster, less thorough)
    #[arg(long, default_value = "false")]
    skip_signatures: bool,

    /// Output detailed verification results as JSON
    #[arg(long, default_value = "false")]
    json_output: bool,

    /// API key for gateway authentication
    #[arg(long, env = "ARION_API_KEY")]
    api_key: Option<String>,
}

/// On-chain commitment structure (mirrors pallet's EpochAttestationCommitment)
#[derive(Debug, Clone, Decode)]
struct OnChainCommitment {
    /// Epoch this commitment covers
    epoch: u64,
    /// BLAKE3 hash of the SCALE-encoded AttestationBundle (BoundedVec decodes as Vec)
    arion_content_hash: Vec<u8>,
    /// Merkle root of all attestation leaves
    attestation_merkle_root: [u8; 32],
    /// Merkle root of unique warden public keys
    warden_pubkey_merkle_root: [u8; 32],
    /// Number of attestations in the bundle
    attestation_count: u32,
    /// Block number when commitment was submitted
    submitted_at_block: u64,
}

/// Verification result details
#[derive(Debug, serde::Serialize)]
struct VerificationResult {
    epoch: u64,
    success: bool,
    attestation_count: u32,
    verified_signatures: u32,
    failed_signatures: u32,
    content_hash_valid: bool,
    attestation_root_valid: bool,
    warden_root_valid: bool,
    errors: Vec<String>,
}

impl VerificationResult {
    fn new(epoch: u64) -> Self {
        Self {
            epoch,
            success: false,
            attestation_count: 0,
            verified_signatures: 0,
            failed_signatures: 0,
            content_hash_valid: false,
            attestation_root_valid: false,
            warden_root_valid: false,
            errors: Vec::new(),
        }
    }
}

#[tokio::main]
async fn main() -> Result<()> {
    // Initialize logging
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("info")),
        )
        .init();

    let args = Args::parse();

    info!(
        "Verifying attestations for epoch {} from chain {} via gateway {}",
        args.epoch, args.chain_ws_url, args.gateway_url
    );

    // Run verification
    let result = verify_epoch(&args).await;

    match result {
        Ok(verification) => {
            if args.json_output {
                println!("{}", serde_json::to_string_pretty(&verification)?);
            } else {
                print_verification_result(&verification);
            }

            if verification.success {
                std::process::exit(0);
            } else {
                std::process::exit(1);
            }
        }
        Err(e) => {
            error!("Verification failed: {}", e);
            if args.json_output {
                let result = VerificationResult {
                    epoch: args.epoch,
                    success: false,
                    attestation_count: 0,
                    verified_signatures: 0,
                    failed_signatures: 0,
                    content_hash_valid: false,
                    attestation_root_valid: false,
                    warden_root_valid: false,
                    errors: vec![e.to_string()],
                };
                println!("{}", serde_json::to_string_pretty(&result)?);
            }
            std::process::exit(1);
        }
    }
}

fn print_verification_result(result: &VerificationResult) {
    println!("\n=== Attestation Verification Result ===");
    println!("Epoch: {}", result.epoch);
    println!(
        "Status: {}",
        if result.success { "PASSED" } else { "FAILED" }
    );
    println!("Attestation count: {}", result.attestation_count);
    println!(
        "Content hash: {}",
        if result.content_hash_valid {
            "OK"
        } else {
            "MISMATCH"
        }
    );
    println!(
        "Attestation merkle root: {}",
        if result.attestation_root_valid {
            "OK"
        } else {
            "MISMATCH"
        }
    );
    println!(
        "Warden pubkey merkle root: {}",
        if result.warden_root_valid {
            "OK"
        } else {
            "MISMATCH"
        }
    );
    println!(
        "Signatures verified: {}/{}",
        result.verified_signatures,
        result.verified_signatures + result.failed_signatures
    );

    if !result.errors.is_empty() {
        println!("\nErrors:");
        for err in &result.errors {
            println!("  - {}", err);
        }
    }
    println!();
}

async fn verify_epoch(args: &Args) -> Result<VerificationResult> {
    let mut result = VerificationResult::new(args.epoch);

    // Fetch data
    info!("Step 1: Querying on-chain commitment...");
    let commitment = query_on_chain_commitment(args)
        .await
        .context("Failed to query on-chain commitment")?;
    info!(
        "Found commitment: epoch={}, {} attestations, arion_hash=0x{}...",
        commitment.epoch,
        commitment.attestation_count,
        hex::encode(
            &commitment
                .arion_content_hash
                .get(..8)
                .unwrap_or(&commitment.arion_content_hash)
        )
    );

    // Verify the epoch matches
    if commitment.epoch != args.epoch {
        return Err(anyhow!(
            "On-chain commitment epoch mismatch: expected {}, got {}",
            args.epoch,
            commitment.epoch
        ));
    }

    // Convert arion_content_hash Vec to [u8; 32]
    let content_hash: [u8; 32] = commitment
        .arion_content_hash
        .as_slice()
        .try_into()
        .context("arion_content_hash is not 32 bytes")?;

    info!("Step 2: Downloading bundle from gateway...");
    let bundle_bytes = download_bundle(args, &content_hash)
        .await
        .context("Failed to download bundle")?;
    info!("Downloaded {} bytes", bundle_bytes.len());

    // Verify content hash
    info!("Step 3: Verifying content hash...");
    verify_content_hash(&bundle_bytes, &content_hash, &mut result);

    // Decode and verify bundle
    info!("Step 4: Decoding bundle...");
    let bundle = AttestationBundle::decode(&mut &bundle_bytes[..])
        .context("Failed to decode AttestationBundle")?;
    result.attestation_count = bundle.attestation_count() as u32;
    info!(
        "Decoded bundle: epoch={}, {} attestations, {} wardens",
        bundle.epoch,
        bundle.attestation_count(),
        bundle.warden_pubkeys.len()
    );

    if bundle.epoch != args.epoch {
        result.errors.push(format!(
            "Bundle epoch mismatch: expected {}, got {}",
            args.epoch, bundle.epoch
        ));
    }

    // Verify merkle roots
    info!("Step 5: Verifying attestation merkle root...");
    verify_attestation_merkle_root(&bundle, &commitment, &mut result);

    info!("Step 6: Verifying warden pubkey merkle root...");
    verify_warden_merkle_root(&bundle, &commitment, &mut result);

    // Verify individual proofs
    info!("Step 7: Verifying attestation merkle proofs...");
    verify_merkle_proofs(&bundle, &commitment, &mut result);

    // Verify signatures (optional)
    if !args.skip_signatures {
        info!("Step 8: Verifying Ed25519 signatures...");
        verify_signatures(&bundle, &mut result);
        info!(
            "Signature verification: {}/{} valid",
            result.verified_signatures,
            result.verified_signatures + result.failed_signatures
        );
    } else {
        info!("Step 8: Skipping signature verification (--skip-signatures)");
    }

    result.success = result.content_hash_valid
        && result.attestation_root_valid
        && result.warden_root_valid
        && result.failed_signatures == 0
        && result.errors.is_empty();

    Ok(result)
}

fn verify_content_hash(
    bundle_bytes: &[u8],
    expected_hash: &[u8; 32],
    result: &mut VerificationResult,
) {
    let computed_hash = blake3::hash(bundle_bytes);
    result.content_hash_valid = computed_hash.as_bytes() == expected_hash;

    if result.content_hash_valid {
        info!("Content hash verified");
    } else {
        result.errors.push(format!(
            "Content hash mismatch: expected 0x{}, got 0x{}",
            hex::encode(expected_hash),
            hex::encode(computed_hash.as_bytes())
        ));
        warn!("Content hash mismatch!");
    }
}

fn verify_attestation_merkle_root(
    bundle: &AttestationBundle,
    commitment: &OnChainCommitment,
    result: &mut VerificationResult,
) {
    let attestation_leaves: Vec<AttestationLeaf> = bundle
        .attestations
        .iter()
        .map(|a| a.attestation.clone())
        .collect();

    let (computed_root, _) = build_merkle_tree(&attestation_leaves);
    result.attestation_root_valid = computed_root == commitment.attestation_merkle_root;

    if result.attestation_root_valid {
        info!("Attestation merkle root verified");
    } else {
        result.errors.push(format!(
            "Attestation merkle root mismatch: expected 0x{}, got 0x{}",
            hex::encode(&commitment.attestation_merkle_root),
            hex::encode(&computed_root)
        ));
        warn!("Attestation merkle root mismatch!");
    }
}

fn verify_warden_merkle_root(
    bundle: &AttestationBundle,
    commitment: &OnChainCommitment,
    result: &mut VerificationResult,
) {
    let mut sorted_pubkeys = bundle.warden_pubkeys.clone();
    sorted_pubkeys.sort();

    let (computed_root, _) = if sorted_pubkeys.is_empty() {
        ([0u8; 32], Vec::new())
    } else {
        build_merkle_tree(&sorted_pubkeys)
    };

    result.warden_root_valid = computed_root == commitment.warden_pubkey_merkle_root;

    if result.warden_root_valid {
        info!("Warden pubkey merkle root verified");
    } else {
        result.errors.push(format!(
            "Warden pubkey merkle root mismatch: expected 0x{}, got 0x{}",
            hex::encode(&commitment.warden_pubkey_merkle_root),
            hex::encode(&computed_root)
        ));
        warn!("Warden pubkey merkle root mismatch!");
    }
}

fn verify_merkle_proofs(
    bundle: &AttestationBundle,
    commitment: &OnChainCommitment,
    result: &mut VerificationResult,
) {
    for (i, attestation_with_proof) in bundle.attestations.iter().enumerate() {
        if !verify_merkle_proof(
            &attestation_with_proof.attestation,
            &attestation_with_proof.proof,
            &commitment.attestation_merkle_root,
        ) {
            result
                .errors
                .push(format!("Attestation {} has invalid merkle proof", i));
        }
    }
}

fn verify_signatures(bundle: &AttestationBundle, result: &mut VerificationResult) {
    for (i, attestation_with_proof) in bundle.attestations.iter().enumerate() {
        match verify_attestation_signature(&attestation_with_proof.attestation) {
            Ok(true) => {
                result.verified_signatures += 1;
                debug!("Attestation {} signature valid", i);
            }
            Ok(false) => {
                result.failed_signatures += 1;
                result
                    .errors
                    .push(format!("Attestation {} has invalid signature", i));
            }
            Err(e) => {
                result.failed_signatures += 1;
                result.errors.push(format!(
                    "Attestation {} signature verification error: {}",
                    i, e
                ));
            }
        }
    }
}

async fn query_on_chain_commitment(args: &Args) -> Result<OnChainCommitment> {
    let client = OnlineClient::<PolkadotConfig>::from_url(&args.chain_ws_url)
        .await
        .context("Failed to connect to chain")?;

    // Build storage query for EpochAttestationCommitments
    let storage_address = subxt::dynamic::storage(
        &args.pallet_name,
        "EpochAttestationCommitments",
        vec![subxt::dynamic::Value::u128(args.epoch as u128)],
    );

    let storage_value = client
        .storage()
        .at_latest()
        .await?
        .fetch(&storage_address)
        .await?;

    match storage_value {
        Some(value) => {
            // Decode the value
            let bytes = value.encoded();
            let commitment = OnChainCommitment::decode(&mut &bytes[..])
                .context("Failed to decode on-chain commitment")?;
            Ok(commitment)
        }
        None => Err(anyhow!(
            "No attestation commitment found for epoch {}",
            args.epoch
        )),
    }
}

async fn download_bundle(args: &Args, content_hash: &[u8; 32]) -> Result<Vec<u8>> {
    let hash_hex = hex::encode(content_hash);
    let url = format!("{}/download/{}", args.gateway_url, hash_hex);

    debug!("Downloading from: {}", url);

    let mut request = reqwest::Client::new().get(&url);

    // Add API key if provided
    if let Some(api_key) = &args.api_key {
        request = request.header("X-API-Key", api_key);
    }

    let response = request.send().await.context("HTTP request failed")?;

    if !response.status().is_success() {
        return Err(anyhow!(
            "Download failed with status {}: {}",
            response.status(),
            response.text().await.unwrap_or_default()
        ));
    }

    let bytes = response
        .bytes()
        .await
        .context("Failed to read response body")?;
    Ok(bytes.to_vec())
}

fn verify_attestation_signature(attestation: &AttestationLeaf) -> Result<bool> {
    // Use SCALE-encoded signing bytes with domain separator (matches warden/validator/pallet)
    // Format: SCALE("ARION_ATTESTATION_V1", shard_hash, miner_uid, result.as_u8(), ...)
    let message = attestation.to_signing_bytes();

    // Verify Ed25519 signature
    let verifying_key = VerifyingKey::from_bytes(&attestation.warden_pubkey)
        .context("Invalid warden public key")?;

    let signature = Signature::from_bytes(&attestation.signature);

    match verifying_key.verify(&message, &signature) {
        Ok(()) => Ok(true),
        Err(_) => Ok(false),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_verification_result_json() {
        let result = VerificationResult {
            epoch: 42,
            success: true,
            attestation_count: 100,
            verified_signatures: 100,
            failed_signatures: 0,
            content_hash_valid: true,
            attestation_root_valid: true,
            warden_root_valid: true,
            errors: vec![],
        };

        let json = serde_json::to_string(&result).unwrap();
        assert!(json.contains("\"epoch\":42"));
        assert!(json.contains("\"success\":true"));
    }
}

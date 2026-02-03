//! Audit scheduler - selects shards and orchestrates the audit loop.

use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::time::interval;
use tracing::{debug, error, info, warn};

use crate::attestation::{Attestation, AuditResult, SignedAttestation};
use crate::audit::challenger::generate_challenge;
use crate::audit::verifier::{VerifyResult, verify_pos_proof};
use crate::config::WardenConfig;
use crate::p2p::P2pClient;
use crate::state::{PendingChallenge, ShardInfo, WardenState};
use crate::submitter::{ChainSubmitter, ValidatorClient};
use crate::validator_p2p::ValidatorP2pClient;
use common::{AuditResultType, WardenAuditBatch, WardenAuditReport, now_secs};
use ed25519_dalek::SigningKey;

/// Convert a SignedAttestation to a WardenAuditReport for the validator.
fn attestation_to_report(attestation: &SignedAttestation) -> WardenAuditReport {
    let result = match attestation.attestation.result {
        AuditResult::Passed => AuditResultType::Passed,
        AuditResult::Failed => AuditResultType::Failed,
        AuditResult::Timeout => AuditResultType::Timeout,
        AuditResult::InvalidProof => AuditResultType::InvalidProof,
    };

    WardenAuditReport {
        audit_id: hex::encode(&attestation.attestation.challenge_seed),
        warden_pubkey: hex::encode(&attestation.warden_pubkey),
        miner_uid: attestation.attestation.miner_uid,
        shard_hash: attestation.attestation.shard_hash.clone(),
        result,
        timestamp: attestation.attestation.timestamp,
        signature: attestation.signature.clone(),
        // Fields needed for SCALE signature verification
        block_number: attestation.attestation.block_number,
        merkle_proof_sig_hash: attestation.attestation.merkle_proof_sig_hash.clone(),
        warden_id: attestation.attestation.warden_id.clone(),
    }
}

/// Push audit results to validator via P2P (preferred) with HTTP fallback.
/// Returns true if successful, false if both P2P and HTTP failed.
async fn push_audit_results_to_validator(
    batch: &WardenAuditBatch,
    p2p_client: &Option<Arc<ValidatorP2pClient>>,
    http_client: &Option<Arc<ValidatorClient>>,
) -> bool {
    if batch.reports.is_empty() {
        return true;
    }

    // Try P2P first if available
    if let Some(p2p) = p2p_client {
        match p2p.push_audit_results(batch).await {
            Ok(true) => {
                debug!(
                    reports = batch.reports.len(),
                    "Audit results pushed via P2P"
                );
                return true;
            }
            Ok(false) => {
                // Validator explicitly rejected - don't retry via HTTP
                // (rejection is a validation issue, not transport failure)
                warn!("Validator rejected audit results via P2P");
                return false;
            }
            Err(e) => {
                warn!(error = %e, "P2P audit result push failed, trying HTTP fallback");
                // Fall through to HTTP on transport error
            }
        }
    }

    // HTTP fallback (only on P2P transport failure, not rejection)
    if let Some(http) = http_client {
        match http.push_audit_results(batch).await {
            Ok(true) => {
                debug!(
                    reports = batch.reports.len(),
                    "Audit results pushed via HTTP"
                );
                return true;
            }
            Ok(false) => {
                warn!("Validator rejected audit results via HTTP");
                return false;
            }
            Err(e) => {
                error!(error = %e, "Failed to push audit results via HTTP");
            }
        }
    }

    // Both P2P and HTTP failed
    false
}

/// Queue failed attestations for retry.
fn queue_attestations_for_retry(state: &WardenState, reports: &[WardenAuditReport]) {
    for report in reports {
        if !state.queue_for_retry(report.clone()) {
            warn!(
                audit_id = %report.audit_id,
                miner_uid = report.miner_uid,
                "Failed to queue attestation for retry"
            );
        }
    }
}

/// Process the retry queue, attempting to resend failed attestations.
async fn process_retry_queue(
    state: &WardenState,
    p2p_client: &Option<Arc<ValidatorP2pClient>>,
    http_client: &Option<Arc<ValidatorClient>>,
) {
    // Get up to 50 attestations ready for retry
    let ready = state.get_retry_ready(50);
    if ready.is_empty() {
        return;
    }

    info!(count = ready.len(), "Processing retry queue");

    for (key, entry) in ready {
        let batch = WardenAuditBatch {
            reports: vec![entry.report.clone()],
        };

        if push_audit_results_to_validator(&batch, p2p_client, http_client).await {
            // Success - remove from retry queue
            state.remove_from_retry_queue(&key);
            debug!(
                audit_id = %entry.report.audit_id,
                miner_uid = entry.report.miner_uid,
                retry_count = entry.retry_count,
                "Retry succeeded"
            );
        } else {
            // Still failing - update retry count
            state.mark_retry_failed(&key, &entry);
            debug!(
                audit_id = %entry.report.audit_id,
                miner_uid = entry.report.miner_uid,
                retry_count = entry.retry_count + 1,
                "Retry failed, will retry later"
            );
        }
    }
}

/// Run the audit scheduler loop.
pub async fn run_audit_loop(
    config: Arc<WardenConfig>,
    state: Arc<WardenState>,
    signing_key: Arc<SigningKey>,
    warden_id: [u8; 32],
) {
    // Initialize P2P client for miner challenges with persistent node ID
    let p2p_client = match P2pClient::new(&config.data_dir).await {
        Ok(client) => Arc::new(client),
        Err(e) => {
            error!(error = %e, "Failed to initialize P2P client, audit loop disabled");
            return;
        }
    };

    // Initialize chain submitter (optional)
    let submitter = ChainSubmitter::new(
        &config.chain_submitter_url,
        config.chain_submitter_insecure_tls,
    );

    // Initialize validator P2P client for reputation system (preferred if node ID is set)
    let validator_p2p_client: Option<Arc<ValidatorP2pClient>> = config
        .validator_node_id
        .as_ref()
        .and_then(|node_id_str| match node_id_str.parse::<iroh::PublicKey>() {
            Ok(node_id) => {
                let client =
                    ValidatorP2pClient::new(p2p_client.endpoint().clone(), node_id.clone());
                info!(
                    validator_node_id = %node_id_str,
                    "Validator P2P client enabled for reputation system"
                );
                Some(Arc::new(client))
            }
            Err(e) => {
                error!(error = %e, node_id = %node_id_str, "Failed to parse VALIDATOR_NODE_ID");
                None
            }
        });

    // Initialize HTTP validator client for reputation system (fallback or primary if no P2P)
    let validator_http_client = config.validator_url.as_ref().map(|url| {
        info!(validator_url = %url, "Validator HTTP client enabled for reputation system");
        Arc::new(ValidatorClient::new(
            url,
            config.validator_api_key.clone(),
            config.validator_insecure_tls,
        ))
    });

    // Use P2P if available, otherwise HTTP
    let use_p2p = validator_p2p_client.is_some();
    let http_fallback = validator_http_client.is_some();

    let mut ticker = interval(Duration::from_secs(config.audit_interval_secs));

    // Initialize epoch tracking for shard cleanup
    let audit_epoch_secs = config.audit_epoch_secs;
    let initial_epoch = common::current_epoch(now_secs(), audit_epoch_secs);
    state.set_epoch(initial_epoch);

    info!(
        interval_secs = config.audit_interval_secs,
        shards_per_audit = config.shards_per_audit,
        audit_epoch_secs = audit_epoch_secs,
        current_epoch = initial_epoch,
        p2p_node_id = %p2p_client.node_id(),
        validator_p2p_enabled = use_p2p,
        validator_http_enabled = http_fallback,
        retry_queue_size = state.retry_queue_size(),
        "Audit scheduler started with P2P and epoch-based sampling"
    );

    loop {
        ticker.tick().await;

        // Process retry queue BEFORE epoch check (ensures pending attestations are submitted)
        process_retry_queue(&state, &validator_p2p_client, &validator_http_client).await;

        // Check for epoch transition and clear shards if new epoch started
        let current_epoch = common::current_epoch(now_secs(), audit_epoch_secs);
        let stored_epoch = state.get_epoch();
        if current_epoch > stored_epoch {
            // Drain retry queue completely before clearing (epoch transition grace)
            let retry_count = state.retry_queue_size();
            if retry_count > 0 {
                info!(
                    pending_retries = retry_count,
                    "Epoch transition pending - draining retry queue first"
                );
                // Process all remaining retries before clearing
                for _ in 0..retry_count {
                    process_retry_queue(&state, &validator_p2p_client, &validator_http_client)
                        .await;
                }
            }

            info!(
                old_epoch = stored_epoch,
                new_epoch = current_epoch,
                shards_before = state.shard_count(),
                "Epoch transition detected, clearing shards for new epoch"
            );
            let cleared = state.clear_all_shards();
            state.set_epoch(current_epoch);
            info!(
                epoch = current_epoch,
                shards_cleared = cleared,
                "New audit epoch started - waiting for validator to push sampled shards"
            );
        }

        // Cleanup expired challenges and create timeout attestations
        let warden_id_hex = hex::encode(warden_id);
        let expired = collect_expired_challenges(&state, now_secs());
        let mut timeout_reports = Vec::new();
        for pending in expired {
            let attestation = create_timeout_attestation(&pending, &signing_key, &warden_id_hex);
            warn!(
                miner = pending.miner_uid,
                shard = %pending.shard_hash,
                "Challenge timed out"
            );
            // Submit timeout attestation to chain
            if let Err(e) = submitter.submit_attestation(&attestation).await {
                error!(error = %e, "Failed to submit timeout attestation");
            }
            // Collect for validator push
            timeout_reports.push(attestation_to_report(&attestation));
        }

        // Push timeout attestations to validator (reputation system) via P2P or HTTP
        if !timeout_reports.is_empty() {
            let batch = WardenAuditBatch {
                reports: timeout_reports.clone(),
            };
            if !push_audit_results_to_validator(
                &batch,
                &validator_p2p_client,
                &validator_http_client,
            )
            .await
            {
                // Queue failed attestations for retry
                queue_attestations_for_retry(&state, &timeout_reports);
            }
        }

        // Select shards for this audit round
        let shards = state.select_shards_for_audit(config.shards_per_audit);
        if shards.is_empty() {
            debug!("No shards to audit");
            continue;
        }

        info!(
            count = shards.len(),
            pending = state.pending_count(),
            "Starting audit round"
        );

        // Process each shard - spawn concurrent tasks
        for shard in shards {
            // Skip shards without endpoint info
            let miner_endpoint = match &shard.miner_endpoint {
                Some(ep) => ep.clone(),
                None => {
                    debug!(
                        shard = %shard.shard_hash,
                        miner = shard.miner_uid,
                        "Skipping shard - no miner endpoint"
                    );
                    continue;
                }
            };

            let challenge = create_challenge_for_shard(&shard, &config, &warden_id);

            // Extract challenge details before moving
            let (nonce, chunk_indices, expires_at) =
                if let common::MinerControlMessage::PosChallenge {
                    nonce,
                    chunk_indices,
                    expires_at,
                    ..
                } = &challenge
                {
                    (*nonce, chunk_indices.clone(), *expires_at)
                } else {
                    continue;
                };

            // Record pending challenge
            state.add_pending(PendingChallenge {
                nonce,
                shard_hash: shard.shard_hash.clone(),
                chunk_indices: chunk_indices.clone(),
                expected_root: shard.merkle_root,
                miner_uid: shard.miner_uid,
                sent_at: Instant::now(),
                expires_at,
            });

            // Spawn task to send challenge and process response
            let p2p = p2p_client.clone();
            let state_clone = state.clone();
            let signing_key_clone = signing_key.clone();
            let submitter_clone = submitter.clone();
            let validator_p2p_clone = validator_p2p_client.clone();
            let validator_http_clone = validator_http_client.clone();
            let shard_hash = shard.shard_hash.clone();
            let miner_uid = shard.miner_uid;
            let expected_root = shard.merkle_root;
            let chunk_count = shard.chunk_count;
            let warden_id_hex_clone = warden_id_hex.clone();

            tokio::spawn(async move {
                match p2p.send_challenge(&miner_endpoint, challenge).await {
                    Ok(Some(response)) => {
                        // Process the proof response
                        if let Some(attestation) = process_proof_response(
                            &state_clone,
                            &signing_key_clone,
                            nonce,
                            response,
                            &shard_hash,
                            miner_uid,
                            expected_root,
                            chunk_count,
                            &chunk_indices,
                            expires_at,
                            &warden_id_hex_clone,
                        ) {
                            // Submit attestation to chain
                            if let Err(e) = submitter_clone.submit_attestation(&attestation).await {
                                error!(error = %e, "Failed to submit attestation");
                            }
                            // Push to validator (reputation system) via P2P or HTTP
                            let report = attestation_to_report(&attestation);
                            let batch = WardenAuditBatch {
                                reports: vec![report.clone()],
                            };
                            if !push_audit_results_to_validator(
                                &batch,
                                &validator_p2p_clone,
                                &validator_http_clone,
                            )
                            .await
                            {
                                // Queue for retry on failure
                                state_clone.queue_for_retry(report);
                            }
                        }
                    }
                    Ok(None) => {
                        // Miner returned error, create failed attestation
                        if let Some(pending) = state_clone.take_pending(&nonce) {
                            let attestation = create_failed_attestation(
                                &pending,
                                &signing_key_clone,
                                &warden_id_hex_clone,
                            );
                            warn!(
                                miner = miner_uid,
                                shard = %shard_hash,
                                "Miner returned error response"
                            );
                            if let Err(e) = submitter_clone.submit_attestation(&attestation).await {
                                error!(error = %e, "Failed to submit failed attestation");
                            }
                            // Push to validator (reputation system) via P2P or HTTP
                            let report = attestation_to_report(&attestation);
                            let batch = WardenAuditBatch {
                                reports: vec![report.clone()],
                            };
                            if !push_audit_results_to_validator(
                                &batch,
                                &validator_p2p_clone,
                                &validator_http_clone,
                            )
                            .await
                            {
                                // Queue for retry on failure
                                state_clone.queue_for_retry(report);
                            }
                        }
                    }
                    Err(e) => {
                        error!(
                            error = %e,
                            miner = miner_uid,
                            shard = %shard_hash,
                            "Failed to send challenge"
                        );
                        // Don't remove from pending - let it timeout
                    }
                }
            });
        }
    }
}

/// Create a challenge for a specific shard.
fn create_challenge_for_shard(
    shard: &ShardInfo,
    config: &WardenConfig,
    warden_id: &[u8; 32],
) -> common::MinerControlMessage {
    // Use current timestamp as "block hash" for now
    // In production, fetch recent finalized block hash
    let block_hash = {
        let ts = now_secs();
        let mut h = [0u8; 32];
        h[..8].copy_from_slice(&ts.to_le_bytes());
        h
    };

    let expires_at = now_secs() + config.challenge_timeout_secs;

    generate_challenge(
        &shard.shard_hash,
        shard.merkle_root,
        shard.chunk_count,
        config.chunks_per_challenge,
        &block_hash,
        warden_id,
        expires_at,
    )
}

/// Collect and remove expired pending challenges.
fn collect_expired_challenges(state: &WardenState, now_secs: u64) -> Vec<PendingChallenge> {
    let mut expired = Vec::new();
    state.pending.retain(|_, c| {
        if c.expires_at <= now_secs {
            expired.push(c.clone());
            false
        } else {
            true
        }
    });
    expired
}

/// Process a proof response from a miner.
fn process_proof_response(
    state: &WardenState,
    signing_key: &SigningKey,
    nonce: [u8; 32],
    response: common::ValidatorControlMessage,
    shard_hash: &str,
    miner_uid: u32,
    expected_root: [u32; 8],
    chunk_count: u32,
    chunk_indices: &[u32],
    expires_at: u64,
    warden_id_hex: &str,
) -> Option<SignedAttestation> {
    // Remove from pending
    let _pending = state.take_pending(&nonce)?;

    // Extract proof from response
    let (proof_bytes, _proving_time_ms) = match response {
        common::ValidatorControlMessage::PosProofResponse {
            nonce: resp_nonce,
            proof_bytes,
            proving_time_ms,
            ..
        } => {
            // Verify nonce matches
            if resp_nonce != nonce {
                warn!(
                    expected = hex::encode(nonce),
                    got = hex::encode(resp_nonce),
                    "Nonce mismatch in proof response"
                );
                return None;
            }
            (proof_bytes, proving_time_ms)
        }
        _ => {
            warn!("Unexpected response type from miner");
            return None;
        }
    };

    debug!(
        shard = %shard_hash,
        miner = miner_uid,
        proof_len = proof_bytes.len(),
        "Processing proof response"
    );

    // Verify the proof
    let verify_result = verify_pos_proof(
        &proof_bytes,
        expected_root,
        chunk_indices,
        chunk_count,
        shard_hash,
        expires_at,
    );

    let audit_result = match verify_result {
        VerifyResult::Passed => {
            info!(
                miner = miner_uid,
                shard = %shard_hash,
                "Proof verification PASSED"
            );
            AuditResult::Passed
        }
        VerifyResult::Failed => {
            warn!(
                miner = miner_uid,
                shard = %shard_hash,
                "Proof verification FAILED"
            );
            AuditResult::Failed
        }
        VerifyResult::InvalidProof => {
            warn!(
                miner = miner_uid,
                shard = %shard_hash,
                "Invalid proof format"
            );
            AuditResult::InvalidProof
        }
    };

    // Compute proof hash for attestation (used for on-chain verification)
    let merkle_proof_sig_hash = if !proof_bytes.is_empty() {
        blake3::hash(&proof_bytes).as_bytes().to_vec()
    } else {
        Vec::new()
    };

    // Create and sign attestation
    let timestamp = now_secs();
    let attestation = Attestation {
        shard_hash: shard_hash.to_string(),
        miner_uid,
        result: audit_result,
        challenge_seed: nonce,
        // Approximate block number based on timestamp (assuming 6-second blocks)
        // For precise block tracking, a chain client would be needed
        block_number: timestamp / 6,
        timestamp,
        merkle_proof_sig_hash,
        warden_id: warden_id_hex.to_string(),
    };

    let signed = attestation.sign(signing_key);

    info!(
        miner = miner_uid,
        result = ?audit_result,
        "Attestation created"
    );

    Some(signed)
}

/// Create a timeout attestation for an unanswered challenge.
fn create_timeout_attestation(
    pending: &PendingChallenge,
    signing_key: &SigningKey,
    warden_id_hex: &str,
) -> SignedAttestation {
    let timestamp = now_secs();
    let attestation = Attestation {
        shard_hash: pending.shard_hash.clone(),
        miner_uid: pending.miner_uid,
        result: AuditResult::Timeout,
        challenge_seed: pending.nonce,
        // Approximate block number based on timestamp (assuming 6-second blocks)
        block_number: timestamp / 6,
        timestamp,
        merkle_proof_sig_hash: Vec::new(), // No proof for timeout
        warden_id: warden_id_hex.to_string(),
    };

    attestation.sign(signing_key)
}

/// Create a failed attestation when miner returns an error.
fn create_failed_attestation(
    pending: &PendingChallenge,
    signing_key: &SigningKey,
    warden_id_hex: &str,
) -> SignedAttestation {
    let timestamp = now_secs();
    let attestation = Attestation {
        shard_hash: pending.shard_hash.clone(),
        miner_uid: pending.miner_uid,
        result: AuditResult::Failed,
        challenge_seed: pending.nonce,
        // Approximate block number based on timestamp (assuming 6-second blocks)
        block_number: timestamp / 6,
        timestamp,
        merkle_proof_sig_hash: Vec::new(), // No valid proof for failure
        warden_id: warden_id_hex.to_string(),
    };

    attestation.sign(signing_key)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_config() -> WardenConfig {
        WardenConfig {
            audit_interval_secs: 1,
            shards_per_audit: 2,
            challenge_timeout_secs: 60,
            chunks_per_challenge: 4,
            ..Default::default()
        }
    }

    fn test_shard() -> ShardInfo {
        ShardInfo {
            shard_hash: "test_shard".to_string(),
            merkle_root: [1, 2, 3, 4, 5, 6, 7, 8],
            chunk_count: 100,
            miner_uid: 42,
            miner_endpoint: None,
            last_audited: None,
        }
    }

    #[test]
    fn test_create_challenge_for_shard() {
        let config = test_config();
        let shard = test_shard();
        let warden_id = [99u8; 32];

        let challenge = create_challenge_for_shard(&shard, &config, &warden_id);

        match challenge {
            common::MinerControlMessage::PosChallenge {
                shard_hash,
                chunk_indices,
                ..
            } => {
                assert_eq!(shard_hash, "test_shard");
                assert_eq!(chunk_indices.len(), 4);
            }
            _ => panic!("Wrong message type"),
        }
    }

    #[test]
    fn test_create_timeout_attestation() {
        let signing_key = SigningKey::from_bytes(&[42u8; 32]);
        let warden_id_hex = hex::encode(signing_key.verifying_key().to_bytes());
        let pending = PendingChallenge {
            nonce: [1u8; 32],
            shard_hash: "test".to_string(),
            chunk_indices: vec![0, 1],
            expected_root: [0; 8],
            miner_uid: 5,
            sent_at: Instant::now(),
            expires_at: 0,
        };

        let signed = create_timeout_attestation(&pending, &signing_key, &warden_id_hex);

        assert!(signed.verify());
        assert_eq!(signed.attestation.result, AuditResult::Timeout);
        assert_eq!(signed.attestation.miner_uid, 5);
        assert_eq!(signed.attestation.warden_id, warden_id_hex);
    }
}

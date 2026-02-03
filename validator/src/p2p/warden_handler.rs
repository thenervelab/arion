//! Warden Control Protocol Handler
//!
//! Handles P2P messages for warden audit integration:
//! - Receiving audit results from wardens
//!
//! Note: Pushing shard commitments TO wardens is handled by the validator
//! as an outbound operation, not by this handler.

use super::{MAX_MESSAGE_SIZE, P2pAuthConfig, send_response};
use crate::state::{AppState, ValidatorReadyState};
use common::{WardenAuditBatch, WardenControlMessage};
use std::sync::Arc;
use tracing::{debug, info, warn};

/// Suggested retry delay for clients when validator is warming up
const WARMUP_RETRY_SECS: u64 = 30;

/// P2P protocol handler for warden → validator communication.
///
/// Implements `ProtocolHandler` for Iroh's protocol router.
pub struct WardenControlHandler {
    pub state: Arc<AppState>,
    pub auth_config: Arc<P2pAuthConfig>,
}

impl std::fmt::Debug for WardenControlHandler {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("WardenControlHandler").finish()
    }
}

impl iroh::protocol::ProtocolHandler for WardenControlHandler {
    fn accept(
        &self,
        conn: iroh::endpoint::Connection,
    ) -> impl futures::Future<Output = Result<(), iroh::protocol::AcceptError>> + Send {
        let state = self.state.clone();
        let auth_config = self.auth_config.clone();
        async move {
            handle_warden_control(conn, state, auth_config)
                .await
                .map_err(|e| iroh::protocol::AcceptError::from_err(std::io::Error::other(e)))
        }
    }
}

/// Handle an incoming P2P connection from a warden.
///
/// This handler loops to accept multiple streams on the same connection,
/// allowing the client to reuse the connection for multiple requests.
/// The connection stays open until the client disconnects or an error occurs.
async fn handle_warden_control(
    conn: iroh::endpoint::Connection,
    state: Arc<AppState>,
    auth_config: Arc<P2pAuthConfig>,
) -> anyhow::Result<()> {
    let remote_node_id = conn.remote_id();
    debug!(remote = %remote_node_id, "Warden control connection accepted");

    // Authorization check ONCE per connection (not per stream)
    if !auth_config.is_authorized_warden(&remote_node_id).await {
        warn!(remote = %remote_node_id, "Unauthorized warden connection rejected");
        // Try to accept a stream to send error response
        if let Ok((mut send, _recv)) = conn.accept_bi().await {
            let response = WardenControlMessage::Ack {
                success: false,
                message: Some("Unauthorized: node ID not in allowed list".to_string()),
            };
            if let Ok(response_bytes) = serde_json::to_vec(&response) {
                let _ = send_response(&mut send, &response_bytes).await;
            }
        }
        return Ok(());
    }

    // Loop to handle multiple streams on the same connection
    loop {
        // Accept next bidirectional stream (blocks until client opens one or disconnects)
        let (mut send, mut recv) = match conn.accept_bi().await {
            Ok(stream) => stream,
            Err(e) => {
                // Connection closed by client or network error - this is normal
                debug!(remote = %remote_node_id, error = %e, "Warden connection closed");
                break;
            }
        };

        // Handle this stream's message
        if let Err(e) =
            handle_single_warden_message(&mut send, &mut recv, &state, &remote_node_id).await
        {
            warn!(remote = %remote_node_id, error = %e, "Error handling warden message");
            // Continue loop - don't close connection on single message error
            // The client can retry on a new stream
        }
    }

    Ok(())
}

/// Handle a single message on a warden stream.
async fn handle_single_warden_message(
    send: &mut iroh::endpoint::SendStream,
    recv: &mut iroh::endpoint::RecvStream,
    state: &AppState,
    remote_node_id: &iroh::PublicKey,
) -> anyhow::Result<()> {
    // Read message
    let buf = recv.read_to_end(MAX_MESSAGE_SIZE).await?;
    let message: WardenControlMessage = serde_json::from_slice(&buf)?;

    // Record metric for this request
    let message_type = warden_message_type(&message);
    state
        .metrics
        .p2p_requests_total
        .get_or_create(&[
            ("protocol".to_string(), "warden-control".to_string()),
            ("message_type".to_string(), message_type.to_string()),
        ])
        .inc();

    // Check ready state for operations that require full readiness
    let ready_state = state.get_ready_state();

    match message {
        WardenControlMessage::PushAuditResults { batch } => {
            // Audit results require full readiness to persist cluster map changes
            if !ready_state.is_ready() {
                return send_warming_up_error(send, ready_state).await;
            }
            handle_push_audit_results(send, state, batch, remote_node_id).await?;
        }
        // These are outbound messages from validator, not received by this handler
        WardenControlMessage::PushShardCommitment { .. }
        | WardenControlMessage::DeleteShard { .. } => {
            warn!(
                remote = %remote_node_id,
                "Received outbound message type from warden (should not happen)"
            );
        }
        WardenControlMessage::Ack { .. } => {
            // Acks are responses, not requests - ignore
        }
    }

    Ok(())
}

/// Extract message type name for metrics.
fn warden_message_type(message: &WardenControlMessage) -> &'static str {
    match message {
        WardenControlMessage::PushAuditResults { .. } => "PushAuditResults",
        WardenControlMessage::PushShardCommitment { .. } => "PushShardCommitment",
        WardenControlMessage::DeleteShard { .. } => "DeleteShard",
        WardenControlMessage::Ack { .. } => "Ack",
    }
}

/// Handle PushAuditResults from warden.
///
/// Processes audit results and updates miner reputation scores.
/// Also adds attestations to the aggregator for epoch bundling.
/// Mirrors the logic in the HTTP handler (`post_audit_results`).
async fn handle_push_audit_results(
    send: &mut iroh::endpoint::SendStream,
    state: &AppState,
    batch: WardenAuditBatch,
    remote_node_id: &iroh::PublicKey,
) -> anyhow::Result<()> {
    info!(
        warden = %remote_node_id,
        count = batch.reports.len(),
        "Received audit results from warden via P2P"
    );

    // Filter to only signature-verified reports
    let signature_verified_reports: Vec<_> = batch
        .reports
        .iter()
        .filter(|report| verify_audit_report(report))
        .cloned()
        .collect();

    let verified_batch = WardenAuditBatch {
        reports: signature_verified_reports.clone(),
    };

    // Process through reputation system
    let mut map = state.cluster_map.write().await;
    let result = state
        .reputation_processor
        .process_batch(&verified_batch, &mut map.miners);

    info!(
        processed = result.processed,
        skipped_duplicate = result.skipped_duplicate,
        skipped_invalid = result.skipped_invalid,
        miners_updated = result.miners_updated.len(),
        "Processed audit batch via P2P"
    );

    // Add verified reports to attestation aggregator for epoch bundling
    let mut attestations_added = 0u32;
    for report in &signature_verified_reports {
        if state.attestation_aggregator.add_attestation(report) {
            attestations_added += 1;
        }
    }
    if attestations_added > 0 {
        debug!(
            added = attestations_added,
            total = state.attestation_aggregator.attestation_count(),
            "Added attestations to aggregator"
        );
    }

    // Remove miners that reached ban threshold (mirrors HTTP handler logic)
    let banned_uids: Vec<u32> = result
        .miners_updated
        .iter()
        .filter(|u| u.should_ban)
        .map(|u| u.miner_uid)
        .collect();

    if !banned_uids.is_empty() {
        for uid in &banned_uids {
            warn!(
                miner_uid = uid,
                "Removing miner due to ban threshold (via P2P)"
            );
        }
        map.miners.retain(|m| !banned_uids.contains(&m.uid));
        map.epoch += 1; // Bump epoch since topology changed
    }

    // Persist updated cluster map if any miners were updated or banned
    let miners_were_updated = !result.miners_updated.is_empty();
    let miners_were_banned = !banned_uids.is_empty();
    let should_persist_cluster_map = miners_were_updated || miners_were_banned;

    // Clone and drop the write lock BEFORE calling persist_cluster_map_to_doc
    // to avoid deadlock (persist_cluster_map_to_doc also acquires cluster_map locks)
    let map_clone = if should_persist_cluster_map {
        Some(map.clone())
    } else {
        None
    };
    drop(map);

    if let Some(map_to_persist) = map_clone {
        // Persist to iroh-docs (now safe - we don't hold the cluster_map lock)
        if let Err(e) = crate::persist_cluster_map_to_doc(state, &map_to_persist).await {
            warn!(error = %e, "Failed to persist cluster map after P2P reputation update");
            // Don't fail the request - changes are in memory and will be persisted eventually
        }
    }

    let response = WardenControlMessage::Ack {
        success: true,
        message: Some(format!(
            "Processed {} audit reports ({} skipped, {} banned)",
            result.processed,
            result.skipped_duplicate + result.skipped_invalid,
            banned_uids.len()
        )),
    };
    let response_bytes = serde_json::to_vec(&response)?;
    send_response(send, &response_bytes).await
}

/// Send a warming up error response.
async fn send_warming_up_error(
    send: &mut iroh::endpoint::SendStream,
    ready_state: ValidatorReadyState,
) -> anyhow::Result<()> {
    let message = format!(
        "Validator is {}: audit results unavailable. Retry in {} seconds.",
        ready_state.status_str(),
        WARMUP_RETRY_SECS
    );
    debug!(state = ?ready_state, "Rejected audit results during warmup");
    let response = WardenControlMessage::Ack {
        success: false,
        message: Some(message),
    };
    let response_bytes = serde_json::to_vec(&response)?;
    send_response(send, &response_bytes).await
}

/// Domain separator for attestation signing (must match warden and pallet)
const ATTESTATION_DOMAIN_SEPARATOR: &[u8] = b"ARION_ATTESTATION_V1";

/// Verify a single audit report's signature using SCALE encoding.
/// Returns true if valid, false otherwise (with warning logged).
pub fn verify_audit_report(report: &common::WardenAuditReport) -> bool {
    use parity_scale_codec::Encode;

    // Parse warden public key
    let warden_pubkey = match report.warden_pubkey.parse::<iroh::PublicKey>() {
        Ok(pk) => pk,
        Err(e) => {
            warn!(audit_id = %report.audit_id, error = %e, "Invalid warden public key");
            return false;
        }
    };

    // Parse signature bytes
    let sig_bytes: [u8; 64] = match report.signature.clone().try_into() {
        Ok(b) => b,
        Err(_) => {
            warn!(audit_id = %report.audit_id, "Invalid signature length");
            return false;
        }
    };

    // Parse challenge_seed from audit_id (hex-encoded)
    let challenge_seed: [u8; 32] = match hex::decode(&report.audit_id) {
        Ok(bytes) if bytes.len() == 32 => {
            let mut arr = [0u8; 32];
            arr.copy_from_slice(&bytes);
            arr
        }
        _ => {
            warn!(audit_id = %report.audit_id, "Invalid audit_id (expected 32-byte hex)");
            return false;
        }
    };

    // Convert result to u8 for SCALE encoding
    let result_u8 = match report.result {
        common::AuditResultType::Passed => 0u8,
        common::AuditResultType::Failed => 1u8,
        common::AuditResultType::Timeout => 2u8,
        common::AuditResultType::InvalidProof => 3u8,
    };

    // Reconstruct SCALE-encoded signing bytes (must match warden's to_signing_bytes)
    let sign_data = (
        ATTESTATION_DOMAIN_SEPARATOR,
        report.shard_hash.as_bytes(),
        report.miner_uid,
        result_u8,
        challenge_seed,
        report.block_number,
        report.timestamp,
        &report.merkle_proof_sig_hash,
        report.warden_id.as_bytes(),
    )
        .encode();

    let sig = iroh::Signature::from_bytes(&sig_bytes);

    if warden_pubkey.verify(&sign_data, &sig).is_err() {
        warn!(audit_id = %report.audit_id, warden = %report.warden_pubkey, "Signature verification failed");
        return false;
    }

    true
}

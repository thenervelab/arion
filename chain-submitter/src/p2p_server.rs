//! P2P server for receiving attestation commitments from the validator.
//!
//! The chain-submitter acts as a P2P server to receive `AttestationCommitmentReady`
//! messages from the validator. These messages contain epoch attestation commitments
//! that should be submitted on-chain after the CRUSH map submission succeeds.
//!
//! # Protocol
//!
//! Uses the `hippius/submitter-control` ALPN protocol, but in reverse direction:
//! - Validator sends `AttestationCommitmentReady` message
//! - Chain-submitter responds with `AttestationCommitmentAck`
//!
//! # Flow
//!
//! ```text
//! Validator ──P2P──▶ Chain-Submitter
//!    │                     │
//!    │  AttestationCommitmentReady
//!    │─────────────────────▶│
//!    │                     │ Store in pending_attestation_commitment
//!    │  AttestationCommitmentAck
//!    │◀─────────────────────│
//! ```

use anyhow::Result;
use common::{
    EpochAttestationCommitment, P2P_MAX_MESSAGE_SIZE, SUBMITTER_CONTROL_ALPN,
    SubmitterControlMessage, p2p_send_response,
};
use std::sync::Arc;
use tokio::sync::RwLock;
use tracing::{debug, info, warn};

/// P2P protocol handler for Validator → Chain-Submitter communication.
///
/// Receives attestation commitments from the validator and stores them
/// for on-chain submission after the CRUSH map is submitted.
pub struct SubmitterP2pHandler {
    /// Shared storage for pending attestation commitment
    pending_commitment: Arc<RwLock<Option<EpochAttestationCommitment>>>,
    /// Authorized validator node IDs (empty = allow all for dev mode)
    authorized_validators: Vec<iroh::PublicKey>,
}

impl std::fmt::Debug for SubmitterP2pHandler {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SubmitterP2pHandler")
            .field("authorized_validators", &self.authorized_validators.len())
            .finish()
    }
}

impl SubmitterP2pHandler {
    /// Create a new P2P handler.
    ///
    /// # Arguments
    /// * `pending_commitment` - Shared storage for pending commitments
    /// * `authorized_validators` - List of authorized validator node IDs (empty = allow all)
    pub fn new(
        pending_commitment: Arc<RwLock<Option<EpochAttestationCommitment>>>,
        authorized_validators: Vec<iroh::PublicKey>,
    ) -> Self {
        Self {
            pending_commitment,
            authorized_validators,
        }
    }

    /// Check if a node is authorized as a validator.
    #[allow(dead_code)]
    fn is_authorized(&self, node_id: &iroh::PublicKey) -> bool {
        self.authorized_validators.is_empty() || self.authorized_validators.contains(node_id)
    }
}

impl iroh::protocol::ProtocolHandler for SubmitterP2pHandler {
    fn accept(
        &self,
        conn: iroh::endpoint::Connection,
    ) -> impl futures::Future<Output = Result<(), iroh::protocol::AcceptError>> + Send {
        let pending = self.pending_commitment.clone();
        let authorized = self.authorized_validators.clone();
        async move {
            handle_validator_connection(conn, pending, authorized)
                .await
                .map_err(|e| iroh::protocol::AcceptError::from_err(std::io::Error::other(e)))
        }
    }
}

/// Handle an incoming P2P connection from a validator.
async fn handle_validator_connection(
    conn: iroh::endpoint::Connection,
    pending: Arc<RwLock<Option<EpochAttestationCommitment>>>,
    authorized_validators: Vec<iroh::PublicKey>,
) -> Result<()> {
    let remote_node_id = conn.remote_id();
    debug!(remote = %remote_node_id, "Validator P2P connection accepted");

    // Accept the bidirectional stream
    let (mut send, mut recv) = conn.accept_bi().await?;

    // Authorization check
    let is_authorized =
        authorized_validators.is_empty() || authorized_validators.contains(&remote_node_id);
    if !is_authorized {
        warn!(remote = %remote_node_id, "Unauthorized validator connection rejected");
        let response = SubmitterControlMessage::AttestationCommitmentAck {
            success: false,
            message: Some("Unauthorized: node ID not in allowed list".to_string()),
        };
        let response_bytes = serde_json::to_vec(&response)?;
        p2p_send_response(&mut send, &response_bytes).await?;
        return Ok(());
    }

    // Read message
    let buf = recv.read_to_end(P2P_MAX_MESSAGE_SIZE).await?;
    let message: SubmitterControlMessage = serde_json::from_slice(&buf)?;

    match message {
        SubmitterControlMessage::AttestationCommitmentReady { commitment } => {
            handle_attestation_commitment(&mut send, pending, commitment, &remote_node_id).await?;
        }
        // Other messages should not be sent by the validator to the chain-submitter
        other => {
            warn!(
                remote = %remote_node_id,
                message_type = ?other,
                "Received unexpected message type from validator"
            );
            let response = SubmitterControlMessage::AttestationCommitmentAck {
                success: false,
                message: Some("Unexpected message type".to_string()),
            };
            let response_bytes = serde_json::to_vec(&response)?;
            p2p_send_response(&mut send, &response_bytes).await?;
        }
    }

    Ok(())
}

/// Handle `AttestationCommitmentReady` message from validator.
async fn handle_attestation_commitment(
    send: &mut iroh::endpoint::SendStream,
    pending: Arc<RwLock<Option<EpochAttestationCommitment>>>,
    commitment: EpochAttestationCommitment,
    remote_node_id: &iroh::PublicKey,
) -> Result<()> {
    info!(
        remote = %remote_node_id,
        epoch = commitment.epoch,
        attestation_count = commitment.attestation_count,
        "Received attestation commitment from validator"
    );

    // Check if we should reject this commitment (older or same epoch)
    let mut guard = pending.write().await;
    if let Some(existing) = guard.as_ref() {
        if existing.epoch >= commitment.epoch {
            warn!(
                existing_epoch = existing.epoch,
                new_epoch = commitment.epoch,
                "Ignoring older or same-epoch commitment"
            );
            return send_ack(
                send,
                false,
                format!(
                    "Ignoring: existing epoch {} >= new epoch {}",
                    existing.epoch, commitment.epoch
                ),
            )
            .await;
        }
    }

    // Store and acknowledge
    let epoch = commitment.epoch;
    *guard = Some(commitment);
    drop(guard); // Release lock before I/O

    info!(
        epoch,
        "Attestation commitment queued for on-chain submission"
    );
    send_ack(
        send,
        true,
        format!("Commitment for epoch {} queued for submission", epoch),
    )
    .await
}

/// Send an attestation commitment acknowledgment.
async fn send_ack(
    send: &mut iroh::endpoint::SendStream,
    success: bool,
    message: String,
) -> Result<()> {
    let response = SubmitterControlMessage::AttestationCommitmentAck {
        success,
        message: Some(message),
    };
    let response_bytes = serde_json::to_vec(&response)?;
    p2p_send_response(send, &response_bytes).await
}

/// Create an Iroh endpoint for P2P server with protocol handler.
///
/// Returns the endpoint and its public node ID.
pub async fn create_p2p_server(
    pending_commitment: Arc<RwLock<Option<EpochAttestationCommitment>>>,
    authorized_validators: Vec<iroh::PublicKey>,
) -> Result<(iroh::Endpoint, iroh::PublicKey)> {
    use iroh::protocol::Router;

    let secret_key = iroh::SecretKey::generate(&mut rand::rng());

    let mut transport_config = iroh::endpoint::TransportConfig::default();
    transport_config.keep_alive_interval(Some(std::time::Duration::from_secs(15)));
    transport_config.max_idle_timeout(Some(
        std::time::Duration::from_secs(60)
            .try_into()
            .expect("valid idle timeout"),
    ));

    // Get relay URL from environment or use default
    let relay_url = common::get_relay_url(None);
    info!(relay_url = %relay_url, "Configuring relay for P2P server");

    // Create the endpoint with consistent relay configuration
    let endpoint = iroh::Endpoint::builder()
        .secret_key(secret_key.clone())
        .transport_config(transport_config)
        .relay_mode(common::build_relay_mode(&relay_url))
        .bind()
        .await?;

    // Create the protocol handler
    let handler = SubmitterP2pHandler::new(pending_commitment, authorized_validators);

    // Build the protocol router with our handler and spawn it
    let _router = Router::builder(endpoint.clone())
        .accept(SUBMITTER_CONTROL_ALPN, handler)
        .spawn();

    let node_id = secret_key.public();

    // Wait for relay connection
    info!(
        wait_secs = common::RELAY_CONNECTION_WAIT_SECS,
        "Waiting for relay connection"
    );
    tokio::time::sleep(std::time::Duration::from_secs(
        common::RELAY_CONNECTION_WAIT_SECS,
    ))
    .await;

    info!(
        node_id = %node_id,
        "P2P server started for receiving attestation commitments"
    );

    Ok((endpoint, node_id))
}

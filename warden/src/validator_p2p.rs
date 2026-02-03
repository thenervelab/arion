//! P2P client for Warden → Validator communication.
//!
//! This module provides a client for the `hippius/warden-control` P2P protocol,
//! replacing HTTP endpoints for pushing audit results to the validator.
//!
//! # Usage
//!
//! ```rust,ignore
//! let client = ValidatorP2pClient::new(endpoint, validator_node_id);
//!
//! // Push audit results
//! let success = client.push_audit_results(&batch).await?;
//! ```

use anyhow::{Result, anyhow};
use common::{
    P2P_DEFAULT_TIMEOUT_SECS, P2P_MAX_MESSAGE_SIZE, P2pConnectionManager, WARDEN_CONTROL_ALPN,
    WardenAuditBatch, WardenControlMessage, p2p_send_response,
};
use iroh::Endpoint;
use std::sync::Arc;
use std::time::Duration;
use tracing::{debug, error, info, warn};

/// P2P client for communicating with the validator.
#[derive(Clone)]
pub struct ValidatorP2pClient {
    conn_manager: P2pConnectionManager,
}

impl ValidatorP2pClient {
    /// Create a new P2P client for the validator.
    pub fn new(endpoint: Endpoint, validator_node_id: iroh::PublicKey) -> Self {
        Self {
            conn_manager: P2pConnectionManager::new(
                endpoint,
                validator_node_id,
                WARDEN_CONTROL_ALPN,
            ),
        }
    }

    /// Get the warden's node ID.
    pub fn node_id(&self) -> iroh::PublicKey {
        self.conn_manager.endpoint().secret_key().public()
    }

    /// Get the count of unhealthy connections detected (for metrics).
    pub fn unhealthy_connection_count(&self) -> u64 {
        self.conn_manager.unhealthy_connection_count()
    }

    /// Send a message and receive a response.
    async fn send_request(&self, message: &WardenControlMessage) -> Result<WardenControlMessage> {
        let conn = self.conn_manager.get_connection().await?;

        let (mut send, mut recv) = conn.open_bi().await?;

        // Send message
        let message_bytes = serde_json::to_vec(message)?;
        send.write_all(&message_bytes).await?;
        send.finish()?;

        // Wait for response with timeout
        let response_bytes = tokio::time::timeout(
            Duration::from_secs(P2P_DEFAULT_TIMEOUT_SECS),
            recv.read_to_end(P2P_MAX_MESSAGE_SIZE),
        )
        .await
        .map_err(|_| anyhow!("Timeout waiting for validator response"))??;

        let response: WardenControlMessage = serde_json::from_slice(&response_bytes)?;
        Ok(response)
    }

    /// Push audit results to the validator for reputation updates.
    ///
    /// Returns true if the validator accepted the batch.
    pub async fn push_audit_results(&self, batch: &WardenAuditBatch) -> Result<bool> {
        if batch.reports.is_empty() {
            return Ok(true);
        }

        info!(
            reports = batch.reports.len(),
            "Pushing audit results to validator via P2P"
        );

        let response = self
            .send_request(&WardenControlMessage::PushAuditResults {
                batch: batch.clone(),
            })
            .await?;

        match response {
            WardenControlMessage::Ack {
                success: true,
                message,
            } => {
                debug!(
                    message = %message.unwrap_or_default(),
                    "Audit results accepted by validator"
                );
                Ok(true)
            }
            WardenControlMessage::Ack {
                success: false,
                message,
            } => {
                warn!(
                    error = %message.unwrap_or_default(),
                    "Validator rejected audit results"
                );
                Ok(false)
            }
            _ => {
                error!("Unexpected response type from validator");
                Ok(false)
            }
        }
    }
}

/// Handler for receiving shard commitments from validator.
///
/// This is called when the validator pushes new shard commitments via P2P
/// (the `hippius/warden-control` protocol).
pub struct WardenControlHandler {
    state: Arc<crate::state::WardenState>,
    /// Authorized validator node ID (if None, all connections are allowed - dev mode only)
    authorized_validator: Option<iroh::PublicKey>,
}

impl WardenControlHandler {
    /// Create a new handler.
    pub fn new(state: Arc<crate::state::WardenState>) -> Self {
        Self {
            state,
            authorized_validator: None,
        }
    }

    /// Create a handler with an authorized validator.
    pub fn with_authorized_validator(
        state: Arc<crate::state::WardenState>,
        validator_node_id: iroh::PublicKey,
    ) -> Self {
        Self {
            state,
            authorized_validator: Some(validator_node_id),
        }
    }

    /// Check if a node is authorized to connect.
    fn is_authorized(&self, node_id: &iroh::PublicKey) -> bool {
        match &self.authorized_validator {
            Some(authorized) => authorized == node_id,
            None => {
                // No authorization configured - allow all (dev mode)
                // Log warning on first connection
                true
            }
        }
    }
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
    ) -> impl std::future::Future<Output = Result<(), iroh::protocol::AcceptError>> + Send {
        let state = self.state.clone();
        let authorized_validator = self.authorized_validator.clone();
        async move {
            handle_warden_control(conn, state, authorized_validator)
                .await
                .map_err(|e| iroh::protocol::AcceptError::from_err(std::io::Error::other(e)))
        }
    }
}

/// Handle an incoming P2P connection from the validator.
async fn handle_warden_control(
    conn: iroh::endpoint::Connection,
    state: Arc<crate::state::WardenState>,
    authorized_validator: Option<iroh::PublicKey>,
) -> anyhow::Result<()> {
    let remote_node_id = conn.remote_id();
    debug!(remote = %remote_node_id, "Warden control connection from validator");

    // Authorization check using guard clauses
    if let Some(authorized) = &authorized_validator {
        if authorized != &remote_node_id {
            warn!(
                remote = %remote_node_id,
                expected = %authorized,
                "Unauthorized validator connection rejected"
            );
            return Ok(());
        }
    } else {
        // No authorization configured - allow but warn (dev mode)
        warn!(
            remote = %remote_node_id,
            "Accepting connection without authorization - set WARDEN_VALIDATOR_NODE_ID in production"
        );
    }

    let (mut send, mut recv) = conn.accept_bi().await?;

    // Read message
    let buf = recv.read_to_end(P2P_MAX_MESSAGE_SIZE).await?;
    let message: WardenControlMessage = serde_json::from_slice(&buf)?;

    match message {
        WardenControlMessage::PushShardCommitment {
            shard_hash,
            merkle_root,
            chunk_count,
            miner_uid,
            miner_endpoint,
        } => {
            handle_push_shard_commitment(
                &mut send,
                &state,
                shard_hash,
                merkle_root,
                chunk_count,
                miner_uid,
                miner_endpoint,
            )
            .await?;
        }
        WardenControlMessage::DeleteShard { shard_hash } => {
            handle_delete_shard(&mut send, &state, shard_hash).await?;
        }
        // Response messages should not be received by the warden
        WardenControlMessage::PushAuditResults { .. } | WardenControlMessage::Ack { .. } => {
            warn!(
                remote = %remote_node_id,
                "Received unexpected message type from validator"
            );
        }
    }

    Ok(())
}

/// Handle PushShardCommitment from validator.
async fn handle_push_shard_commitment(
    send: &mut iroh::endpoint::SendStream,
    state: &crate::state::WardenState,
    shard_hash: String,
    merkle_root: [u32; 8],
    chunk_count: u32,
    miner_uid: u32,
    miner_endpoint: String,
) -> anyhow::Result<()> {
    debug!(
        shard = %shard_hash,
        miner_uid = miner_uid,
        "Received shard commitment via P2P"
    );

    // Parse miner endpoint
    let endpoint = match serde_json::from_str::<iroh::EndpointAddr>(&miner_endpoint) {
        Ok(e) => e,
        Err(e) => {
            let response = WardenControlMessage::Ack {
                success: false,
                message: Some(format!("Invalid miner endpoint: {}", e)),
            };
            let response_bytes = serde_json::to_vec(&response)?;
            p2p_send_response(send, &response_bytes).await?;
            return Ok(());
        }
    };

    // Create shard info (runtime type for upsert)
    let info = crate::state::ShardInfo {
        shard_hash: shard_hash.clone(),
        merkle_root,
        chunk_count,
        miner_uid,
        miner_endpoint: Some(endpoint),
        last_audited: None,
    };

    // Store shard
    let success = state.upsert_shard(info);

    let response = WardenControlMessage::Ack {
        success,
        message: if success {
            Some("Shard commitment stored".to_string())
        } else {
            Some("Failed to store shard commitment".to_string())
        },
    };
    let response_bytes = serde_json::to_vec(&response)?;
    p2p_send_response(send, &response_bytes).await
}

/// Handle DeleteShard from validator.
async fn handle_delete_shard(
    send: &mut iroh::endpoint::SendStream,
    state: &crate::state::WardenState,
    shard_hash: String,
) -> anyhow::Result<()> {
    debug!(shard = %shard_hash, "Received shard deletion via P2P");

    // Check if shard exists before deletion
    let existed = state.get_shard(&shard_hash).is_some();
    state.remove_shard(&shard_hash);

    let response = WardenControlMessage::Ack {
        success: true, // Deletion is always "successful" (idempotent)
        message: if existed {
            Some("Shard removed".to_string())
        } else {
            Some("Shard not found (already deleted)".to_string())
        },
    };
    let response_bytes = serde_json::to_vec(&response)?;
    p2p_send_response(send, &response_bytes).await
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_max_response_size() {
        assert_eq!(P2P_MAX_MESSAGE_SIZE, 1024 * 1024);
    }
}

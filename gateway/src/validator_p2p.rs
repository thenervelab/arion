//! P2P client for Gateway → Validator communication.
//!
//! This module provides a client for the `hippius/gateway-control` P2P protocol,
//! replacing HTTP endpoints for internal cluster communication.
//!
//! # Usage
//!
//! ```rust,ignore
//! let client = ValidatorP2pClient::new(endpoint, validator_node_id);
//!
//! // Fetch cluster map
//! let map = client.get_cluster_map().await?;
//!
//! // Fetch manifest
//! let manifest = client.get_manifest(&file_hash).await?;
//! ```

use anyhow::{Result, anyhow};
use common::{
    BandwidthReport, ClusterMap, FileManifest, GATEWAY_CONTROL_ALPN, GatewayControlMessage,
    MinerFailureReport, P2P_DEFAULT_TIMEOUT_SECS, P2P_MAX_RESPONSE_SIZE, P2pConnectionManager,
};
use iroh::Endpoint;
use std::time::Duration;
use tracing::{debug, error, warn};

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
                GATEWAY_CONTROL_ALPN,
            ),
        }
    }

    /// Get the count of unhealthy connections detected (for metrics).
    pub fn unhealthy_connection_count(&self) -> u64 {
        self.conn_manager.unhealthy_connection_count()
    }

    /// Send a message and receive a response.
    async fn send_request(&self, message: &GatewayControlMessage) -> Result<GatewayControlMessage> {
        let conn = self.conn_manager.get_connection().await?;

        let (mut send, mut recv) = conn.open_bi().await?;

        // Send message
        let message_bytes = serde_json::to_vec(message)?;
        send.write_all(&message_bytes).await?;
        send.finish()?;

        // Wait for response with timeout
        let response_bytes = tokio::time::timeout(
            Duration::from_secs(P2P_DEFAULT_TIMEOUT_SECS),
            recv.read_to_end(P2P_MAX_RESPONSE_SIZE),
        )
        .await
        .map_err(|_| anyhow!("Timeout waiting for validator response"))??;

        let response: GatewayControlMessage = serde_json::from_slice(&response_bytes)?;
        Ok(response)
    }

    /// Fetch the current cluster map from validator.
    pub async fn get_cluster_map(&self) -> Result<ClusterMap> {
        let response = self
            .send_request(&GatewayControlMessage::GetClusterMap)
            .await?;

        match response {
            GatewayControlMessage::ClusterMapResponse { map: Some(map), .. } => Ok(map),
            GatewayControlMessage::ClusterMapResponse { error: Some(e), .. } => {
                Err(anyhow!("Validator error: {}", e))
            }
            GatewayControlMessage::ClusterMapResponse {
                map: None,
                error: None,
            } => Err(anyhow!("Validator returned empty response")),
            _ => Err(anyhow!("Unexpected response type from validator")),
        }
    }

    /// Fetch cluster map at a specific epoch.
    pub async fn get_cluster_map_epoch(&self, epoch: u64) -> Result<Option<ClusterMap>> {
        let response = self
            .send_request(&GatewayControlMessage::GetClusterMapEpoch { epoch })
            .await?;

        match response {
            GatewayControlMessage::ClusterMapResponse { map, error: None } => Ok(map),
            GatewayControlMessage::ClusterMapResponse { error: Some(e), .. } => {
                warn!(epoch = epoch, error = %e, "Failed to get cluster map epoch");
                Ok(None)
            }
            _ => Err(anyhow!("Unexpected response type from validator")),
        }
    }

    /// Fetch file manifest from validator.
    pub async fn get_manifest(&self, file_hash: &str) -> Result<Option<FileManifest>> {
        let response = self
            .send_request(&GatewayControlMessage::GetManifest {
                file_hash: file_hash.to_string(),
            })
            .await?;

        match response {
            GatewayControlMessage::ManifestResponse {
                manifest,
                error: None,
            } => Ok(manifest),
            GatewayControlMessage::ManifestResponse { error: Some(e), .. } => {
                debug!(file_hash = %file_hash, error = %e, "Manifest not found");
                Ok(None)
            }
            _ => Err(anyhow!("Unexpected response type from validator")),
        }
    }

    /// Check if a placement group has settled (rebalancing complete).
    pub async fn get_rebalance_status(&self, epoch: u64, pg_id: u32) -> Result<bool> {
        let response = self
            .send_request(&GatewayControlMessage::GetRebalanceStatus { epoch, pg_id })
            .await?;

        match response {
            GatewayControlMessage::RebalanceStatusResponse { settled } => Ok(settled),
            _ => {
                warn!(
                    epoch = epoch,
                    pg_id = pg_id,
                    "Unexpected rebalance status response"
                );
                Ok(true) // Assume settled on error
            }
        }
    }

    /// Report bandwidth statistics to validator.
    pub async fn report_bandwidth(&self, reports: Vec<BandwidthReport>) -> Result<()> {
        if reports.is_empty() {
            return Ok(());
        }

        let response = self
            .send_request(&GatewayControlMessage::ReportBandwidth { reports })
            .await?;

        match response {
            GatewayControlMessage::Ack { success: true, .. } => Ok(()),
            GatewayControlMessage::Ack {
                success: false,
                message,
            } => {
                error!(
                    error = %message.unwrap_or_default(),
                    "Validator rejected bandwidth report"
                );
                Ok(()) // Don't propagate error - fire and forget
            }
            _ => Ok(()),
        }
    }

    /// Report miner failures to validator.
    pub async fn report_failures(&self, reports: Vec<MinerFailureReport>) -> Result<()> {
        if reports.is_empty() {
            return Ok(());
        }

        let response = self
            .send_request(&GatewayControlMessage::ReportFailures { reports })
            .await?;

        match response {
            GatewayControlMessage::Ack { success: true, .. } => Ok(()),
            GatewayControlMessage::Ack {
                success: false,
                message,
            } => {
                error!(
                    error = %message.unwrap_or_default(),
                    "Validator rejected failure report"
                );
                Ok(()) // Don't propagate error
            }
            _ => Ok(()),
        }
    }

    /// Send repair hint to validator.
    pub async fn repair_hint(
        &self,
        file_hash: &str,
        stripe_idx: Option<u64>,
        count: Option<usize>,
    ) -> Result<bool> {
        let response = self
            .send_request(&GatewayControlMessage::RepairHint {
                file_hash: file_hash.to_string(),
                stripe_idx,
                count,
            })
            .await?;

        match response {
            GatewayControlMessage::Ack { success, message } => {
                if !success {
                    debug!(
                        file_hash = %file_hash,
                        message = %message.unwrap_or_default(),
                        "Repair hint not accepted"
                    );
                }
                Ok(success)
            }
            _ => {
                warn!(file_hash = %file_hash, "Unexpected repair hint response");
                Ok(false)
            }
        }
    }

    /// Delete a file via P2P.
    pub async fn delete_file(&self, file_hash: &str) -> Result<bool> {
        let response = self
            .send_request(&GatewayControlMessage::DeleteFile {
                file_hash: file_hash.to_string(),
            })
            .await?;

        match response {
            GatewayControlMessage::Ack { success, message } => {
                if !success {
                    warn!(
                        file_hash = %file_hash,
                        error = %message.unwrap_or_default(),
                        "File deletion failed"
                    );
                }
                Ok(success)
            }
            _ => Err(anyhow!("Unexpected delete response")),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_max_response_size() {
        // 10 MiB should be enough for large manifests
        assert_eq!(P2P_MAX_RESPONSE_SIZE, 10 * 1024 * 1024);
    }
}

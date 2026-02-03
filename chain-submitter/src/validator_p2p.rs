//! P2P client for Chain-Submitter → Validator communication.
//!
//! This module provides a client for the `hippius/submitter-control` P2P protocol,
//! replacing HTTP endpoints for fetching cluster map and network stats.
//!
//! # Usage
//!
//! ```rust,ignore
//! let client = ValidatorP2pClient::new(endpoint, validator_node_id);
//!
//! // Fetch cluster map
//! let map = client.get_cluster_map().await?;
//!
//! // Fetch network stats
//! let stats = client.get_network_stats().await?;
//! ```

use anyhow::{Result, anyhow};
use common::{
    ClusterMap, P2P_DEFAULT_TIMEOUT_SECS, P2P_MAX_RESPONSE_SIZE, P2pConnectionManager,
    SUBMITTER_CONTROL_ALPN, SubmitterControlMessage,
};
use iroh::Endpoint;
use std::collections::HashMap;
use std::time::Duration;
use tracing::{debug, error, warn};

/// Network statistics from validator (matches NetworkStatsResponse fields).
#[derive(Debug, Clone)]
pub struct NetworkStats {
    /// Total number of files stored
    pub total_files: usize,
    /// Per-miner storage stats: miner_uid -> [stored_bytes, shard_count]
    pub miner_stats: HashMap<String, [u64; 2]>,
    /// Per-miner bandwidth stats: miner_uid -> bytes_served
    pub bandwidth_stats: HashMap<String, u64>,
}

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
                SUBMITTER_CONTROL_ALPN,
            ),
        }
    }

    /// Get the count of unhealthy connections detected (for metrics).
    #[allow(dead_code)]
    pub fn unhealthy_connection_count(&self) -> u64 {
        self.conn_manager.unhealthy_connection_count()
    }

    /// Send a message and receive a response.
    async fn send_request(
        &self,
        message: &SubmitterControlMessage,
    ) -> Result<SubmitterControlMessage> {
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

        let response: SubmitterControlMessage = serde_json::from_slice(&response_bytes)?;
        Ok(response)
    }

    /// Fetch the current cluster map from validator.
    pub async fn get_cluster_map(&self) -> Result<ClusterMap> {
        debug!("Fetching cluster map via P2P");

        let response = self
            .send_request(&SubmitterControlMessage::GetClusterMap)
            .await?;

        match response {
            SubmitterControlMessage::ClusterMapResponse { map: Some(map), .. } => Ok(map),
            SubmitterControlMessage::ClusterMapResponse { error: Some(e), .. } => {
                error!(error = %e, "Validator returned error for GetClusterMap");
                Err(anyhow!("Validator error: {}", e))
            }
            SubmitterControlMessage::ClusterMapResponse {
                map: None,
                error: None,
            } => Err(anyhow!("Validator returned empty response")),
            _ => {
                error!("Unexpected response type from validator for GetClusterMap");
                Err(anyhow!("Unexpected response type from validator"))
            }
        }
    }

    /// Fetch network statistics from validator.
    pub async fn get_network_stats(&self) -> Result<NetworkStats> {
        debug!("Fetching network stats via P2P");

        let response = self
            .send_request(&SubmitterControlMessage::GetNetworkStats)
            .await?;

        match response {
            SubmitterControlMessage::NetworkStatsResponse {
                total_files,
                miner_stats,
                bandwidth_stats,
            } => Ok(NetworkStats {
                total_files,
                miner_stats,
                bandwidth_stats,
            }),
            _ => {
                warn!("Unexpected response type from validator for GetNetworkStats");
                Err(anyhow!("Unexpected response type from validator"))
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_max_response_size() {
        // 10 MiB should be enough for large cluster maps
        assert_eq!(P2P_MAX_RESPONSE_SIZE, 10 * 1024 * 1024);
    }
}

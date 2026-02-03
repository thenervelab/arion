//! HTTP client for communicating with the Warden service.
//!
//! The Warden audits miners' proof-of-storage. The validator:
//! - Pushes shard commitments when files are uploaded
//! - Notifies deletions when files are removed

use anyhow::Result;
use serde::Serialize;
use tracing::{debug, error, info, warn};

/// Request body for POST /shards on the Warden.
#[derive(Debug, Serialize)]
pub struct PushShardRequest {
    /// BLAKE3 hash of the shard (or iroh hash for identification)
    pub shard_hash: String,
    /// Poseidon2 Merkle root commitment
    pub merkle_root: [u32; 8],
    /// Number of chunks in this shard
    pub chunk_count: u32,
    /// Miner UID holding this shard
    pub miner_uid: u32,
    /// Miner's Iroh node ID (hex) - deprecated, use miner_endpoint
    pub miner_node_id: String,
    /// Miner's full EndpointAddr (JSON serialized) for P2P connections
    #[serde(skip_serializing_if = "Option::is_none")]
    pub miner_endpoint: Option<String>,
}

/// Client for the Warden proof-of-storage audit service.
pub struct WardenClient {
    base_url: String,
    client: reqwest::Client,
    api_key: String,
}

/// Default timeout for Warden HTTP requests (10 seconds).
const WARDEN_REQUEST_TIMEOUT_SECS: u64 = 10;

impl WardenClient {
    /// Create a new Warden client.
    ///
    /// # Arguments
    /// * `base_url` - Warden HTTP API base URL (e.g., "http://localhost:3003")
    pub fn new(base_url: &str) -> Self {
        // Accept self-signed certs since warden uses auto-generated TLS certs
        let client = reqwest::Client::builder()
            .timeout(std::time::Duration::from_secs(WARDEN_REQUEST_TIMEOUT_SECS))
            .danger_accept_invalid_certs(true)
            .build()
            .unwrap_or_else(|_| reqwest::Client::new());

        // Get API key from environment
        let api_key = std::env::var("ARION_API_KEY").unwrap_or_else(|_| "Arion".to_string());

        Self {
            base_url: base_url.trim_end_matches('/').to_string(),
            client,
            api_key,
        }
    }

    /// Push a shard commitment to the Warden.
    ///
    /// Called after successfully storing a shard on a miner.
    /// The Warden will periodically challenge the miner to prove possession.
    ///
    /// # Arguments
    /// * `shard_hash` - Hash identifying the shard
    /// * `merkle_root` - Poseidon2 Merkle root from commitment
    /// * `chunk_count` - Number of chunks in the shard
    /// * `miner_uid` - UID of the miner storing this shard
    /// * `miner_endpoint` - Full Iroh EndpointAddr for P2P connections
    pub async fn push_shard_commitment(
        &self,
        shard_hash: &str,
        merkle_root: [u32; 8],
        chunk_count: u32,
        miner_uid: u32,
        miner_endpoint: &iroh::EndpointAddr,
    ) -> Result<bool> {
        let url = format!("{}/shards", self.base_url);

        // Serialize the endpoint to JSON for the warden
        let endpoint_json = serde_json::to_string(miner_endpoint)?;

        let request = PushShardRequest {
            shard_hash: shard_hash.to_string(),
            merkle_root,
            chunk_count,
            miner_uid,
            miner_node_id: miner_endpoint.id.to_string(),
            miner_endpoint: Some(endpoint_json),
        };

        debug!(
            shard = %shard_hash,
            miner = miner_uid,
            "Pushing shard commitment to Warden"
        );

        let response = self
            .client
            .post(&url)
            .header("X-API-Key", &self.api_key)
            .json(&request)
            .send()
            .await;

        match response {
            Ok(resp) if resp.status().is_success() => {
                info!(
                    shard = %shard_hash,
                    miner = miner_uid,
                    "Shard commitment pushed to Warden"
                );
                Ok(true)
            }
            Ok(resp) => {
                warn!(
                    status = %resp.status(),
                    shard = %shard_hash,
                    "Failed to push shard commitment to Warden"
                );
                Ok(false)
            }
            Err(e) => {
                error!(error = %e, "Failed to connect to Warden");
                Err(e.into())
            }
        }
    }

    /// Notify Warden that a shard has been deleted.
    ///
    /// Called when a file is deleted from the system.
    /// The Warden will stop auditing this shard.
    ///
    /// # Arguments
    /// * `shard_hash` - Hash of the deleted shard
    pub async fn delete_shard(&self, shard_hash: &str) -> Result<bool> {
        let url = format!("{}/shards/{}", self.base_url, shard_hash);

        debug!(shard = %shard_hash, "Notifying Warden of shard deletion");

        let response = self
            .client
            .delete(&url)
            .header("X-API-Key", &self.api_key)
            .send()
            .await;

        match response {
            Ok(resp) if resp.status().is_success() => {
                info!(shard = %shard_hash, "Warden notified of shard deletion");
                Ok(true)
            }
            Ok(resp) => {
                warn!(
                    status = %resp.status(),
                    shard = %shard_hash,
                    "Failed to notify Warden of deletion"
                );
                Ok(false)
            }
            Err(e) => {
                error!(error = %e, "Failed to connect to Warden");
                Err(e.into())
            }
        }
    }

    /// Push multiple shard commitments in batch.
    ///
    /// Convenience method for pushing all shards from an upload.
    /// Returns the number of successfully pushed commitments.
    /// Tuple: (hash, root, chunks, miner_uid, endpoint)
    pub async fn push_shard_commitments_batch(
        &self,
        shards: &[(String, [u32; 8], u32, u32, iroh::EndpointAddr)],
    ) -> usize {
        let mut success_count = 0;
        for (hash, root, chunks, miner_uid, endpoint) in shards {
            if self
                .push_shard_commitment(hash, *root, *chunks, *miner_uid, endpoint)
                .await
                .unwrap_or(false)
            {
                success_count += 1;
            }
        }
        success_count
    }

    /// Delete multiple shards in batch.
    ///
    /// Convenience method for deleting all shards when a file is removed.
    /// Returns the number of successfully deleted notifications.
    pub async fn delete_shards_batch(&self, shard_hashes: &[String]) -> usize {
        let mut success_count = 0;
        for hash in shard_hashes {
            if self.delete_shard(hash).await.unwrap_or(false) {
                success_count += 1;
            }
        }
        success_count
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_warden_client_creation() {
        let client = WardenClient::new("http://localhost:3003");
        assert_eq!(client.base_url, "http://localhost:3003");

        // Should strip trailing slash
        let client2 = WardenClient::new("http://localhost:3003/");
        assert_eq!(client2.base_url, "http://localhost:3003");
    }

    #[test]
    fn test_push_shard_request_serialization() {
        let request = PushShardRequest {
            shard_hash: "abc123".to_string(),
            merkle_root: [1, 2, 3, 4, 5, 6, 7, 8],
            chunk_count: 64,
            miner_uid: 42,
            miner_node_id: "node123".to_string(),
            miner_endpoint: Some("{\"node_id\":\"abc\"}".to_string()),
        };

        let json = serde_json::to_string(&request).unwrap();
        assert!(json.contains("\"shard_hash\":\"abc123\""));
        assert!(json.contains("\"miner_uid\":42"));
        assert!(json.contains("\"miner_endpoint\""));
    }
}

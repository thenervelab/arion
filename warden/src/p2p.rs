//! P2P communication with miners via Iroh.
//!
//! This module handles sending challenges and receiving proof responses
//! using the `hippius/miner-control` protocol.

use anyhow::{Context, Result};
use common::MinerControlMessage;
use iroh::{Endpoint, SecretKey};
use std::path::Path;
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::Semaphore;
use tracing::{debug, info, warn};

/// ALPN protocol identifier for miner control messages.
const MINER_CONTROL_ALPN: &[u8] = b"hippius/miner-control";

/// Default timeout for P2P operations.
const P2P_TIMEOUT_SECS: u64 = 30;

/// Maximum concurrent P2P connections.
const MAX_CONCURRENT_CHALLENGES: usize = 10;

/// P2P client for communicating with miners.
pub struct P2pClient {
    endpoint: Endpoint,
    /// Semaphore to limit concurrent challenge sends
    challenge_sem: Arc<Semaphore>,
}

impl P2pClient {
    /// Create a new P2P client with an Iroh endpoint.
    ///
    /// The secret key is persisted to `data_dir/p2p_keypair.bin` to ensure the node ID
    /// remains stable across restarts. The node ID is also saved to `data_dir/node_id.txt`
    /// for easy reference by operators.
    pub async fn new(data_dir: &Path) -> Result<Self> {
        info!("Initializing P2P client for warden");

        // Ensure data directory exists
        tokio::fs::create_dir_all(data_dir)
            .await
            .context("Failed to create warden data directory")?;

        // Load or generate the secret key for persistent node ID
        let secret_key = load_p2p_keypair(data_dir).await?;

        // Configure transport with reasonable timeouts
        let mut transport_config = iroh::endpoint::TransportConfig::default();
        transport_config.keep_alive_interval(Some(Duration::from_secs(15)));
        transport_config.max_idle_timeout(Some(
            Duration::from_secs(60)
                .try_into()
                .expect("valid idle timeout"),
        ));

        // Get relay URL from environment or use default
        let relay_url = common::get_relay_url(None);
        info!(relay_url = %relay_url, "Configuring relay");

        // Build the endpoint with consistent relay configuration
        let endpoint = Endpoint::builder()
            .secret_key(secret_key.clone())
            .transport_config(transport_config)
            .relay_mode(common::build_relay_mode(&relay_url))
            .bind()
            .await
            .context("Failed to bind Iroh endpoint")?;

        let node_id = secret_key.public();
        info!(node_id = %node_id, "Warden Iroh Node ID");

        // Save Node ID to file for easy ansible/deployment reference
        let node_id_str = node_id.to_string();
        let node_id_path = data_dir.join("node_id.txt");
        if let Err(e) = tokio::fs::write(&node_id_path, &node_id_str).await {
            warn!(error = %e, "Failed to write node_id.txt");
        } else {
            info!(path = ?node_id_path, "Node ID saved to file");
        }

        // Wait for relay connection
        info!(
            wait_secs = common::RELAY_CONNECTION_WAIT_SECS,
            "Waiting for relay connection"
        );
        tokio::time::sleep(Duration::from_secs(common::RELAY_CONNECTION_WAIT_SECS)).await;
        info!("P2P ready");

        Ok(Self {
            endpoint,
            challenge_sem: Arc::new(Semaphore::new(MAX_CONCURRENT_CHALLENGES)),
        })
    }

    /// Send a challenge to a miner and wait for the proof response.
    ///
    /// Returns the proof response if successful, or None on failure.
    pub async fn send_challenge(
        &self,
        miner_endpoint: &iroh::EndpointAddr,
        challenge: MinerControlMessage,
    ) -> Result<Option<common::ValidatorControlMessage>> {
        // Acquire semaphore permit to limit concurrent connections
        let _permit = self
            .challenge_sem
            .acquire()
            .await
            .context("Failed to acquire challenge semaphore")?;

        let miner_node_id = miner_endpoint.id;

        debug!(
            miner = %miner_node_id,
            "Sending PoS challenge to miner"
        );

        // Connect to the miner with timeout
        let conn = tokio::time::timeout(
            Duration::from_secs(P2P_TIMEOUT_SECS),
            self.endpoint
                .connect(miner_endpoint.clone(), MINER_CONTROL_ALPN),
        )
        .await
        .context("Connection timeout")?
        .context("Failed to connect to miner")?;

        // Open bidirectional stream
        let (mut send, mut recv) = conn
            .open_bi()
            .await
            .context("Failed to open bidirectional stream")?;

        // Serialize and send the challenge
        let msg_bytes = serde_json::to_vec(&challenge).context("Failed to serialize challenge")?;

        send.write_all(&msg_bytes)
            .await
            .context("Failed to write challenge")?;
        send.finish().context("Failed to finish send stream")?;

        debug!(
            miner = %miner_node_id,
            bytes = msg_bytes.len(),
            "Challenge sent, waiting for response"
        );

        // Read the response (proof can be large, allow up to 1MB)
        let response_bytes = tokio::time::timeout(
            Duration::from_secs(P2P_TIMEOUT_SECS),
            recv.read_to_end(1024 * 1024),
        )
        .await
        .context("Response timeout")?
        .context("Failed to read response")?;

        // Check for error responses
        if response_bytes.starts_with(b"ERROR:") {
            let error_msg = String::from_utf8_lossy(&response_bytes);
            warn!(
                miner = %miner_node_id,
                error = %error_msg,
                "Miner returned error"
            );
            return Ok(None);
        }

        // Deserialize the response
        let response: common::ValidatorControlMessage =
            serde_json::from_slice(&response_bytes).context("Failed to deserialize response")?;

        debug!(
            miner = %miner_node_id,
            "Received proof response"
        );

        Ok(Some(response))
    }

    /// Get the warden's node ID.
    pub fn node_id(&self) -> iroh::PublicKey {
        self.endpoint.secret_key().public()
    }

    /// Get a reference to the underlying Iroh endpoint.
    /// Used for creating validator P2P clients that share the same transport.
    pub fn endpoint(&self) -> &Endpoint {
        &self.endpoint
    }
}

/// Load or generate a persistent P2P keypair.
///
/// If `data_dir/p2p_keypair.bin` exists, loads the secret key from it.
/// Otherwise, generates a new key and saves it.
async fn load_p2p_keypair(data_dir: &Path) -> Result<SecretKey> {
    let keypair_path = data_dir.join("p2p_keypair.bin");

    if keypair_path.exists() {
        let bytes = tokio::fs::read(&keypair_path)
            .await
            .context("Failed to read P2P keypair file")?;

        if let Ok(key) = SecretKey::try_from(&bytes[..]) {
            info!(path = ?keypair_path, "Loaded existing P2P keypair");
            return Ok(key);
        } else {
            warn!(path = ?keypair_path, "Invalid P2P keypair file, generating new one");
        }
    }

    // Generate new keypair - ensure RNG doesn't span across await
    let (secret_key, key_bytes) = {
        let mut rng = rand::rng();
        let key = SecretKey::generate(&mut rng);
        let bytes = key.to_bytes();
        (key, bytes)
    };

    // Save to file
    tokio::fs::write(&keypair_path, key_bytes)
        .await
        .context("Failed to save P2P keypair")?;

    info!(path = ?keypair_path, "Generated and saved new P2P keypair");
    Ok(secret_key)
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    #[tokio::test]
    async fn test_p2p_client_creation() {
        // This test requires network access, skip in CI if needed
        let temp_dir = TempDir::new().expect("Failed to create temp dir");
        let client = P2pClient::new(temp_dir.path()).await;
        assert!(
            client.is_ok(),
            "P2P client creation failed: {:?}",
            client.err()
        );
    }

    #[tokio::test]
    async fn test_p2p_keypair_persistence() {
        let temp_dir = TempDir::new().expect("Failed to create temp dir");

        // Create client - should generate and save keypair
        let client1 = P2pClient::new(temp_dir.path())
            .await
            .expect("Failed to create first P2P client");
        let node_id1 = client1.node_id();

        // Drop the client and create a new one - should load the same keypair
        drop(client1);
        let client2 = P2pClient::new(temp_dir.path())
            .await
            .expect("Failed to create second P2P client");
        let node_id2 = client2.node_id();

        assert_eq!(
            node_id1, node_id2,
            "Node ID should be the same after restart"
        );

        // Verify node_id.txt was written
        let node_id_path = temp_dir.path().join("node_id.txt");
        assert!(node_id_path.exists(), "node_id.txt should exist");

        let saved_node_id = tokio::fs::read_to_string(&node_id_path)
            .await
            .expect("Failed to read node_id.txt");
        assert_eq!(
            saved_node_id,
            node_id2.to_string(),
            "Saved node ID should match"
        );
    }
}

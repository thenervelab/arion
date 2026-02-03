//! Family verification module.
//!
//! Fetches and caches a family whitelist from an external API, then verifies
//! that miners belong to their claimed families during registration.
//!
//! # Architecture
//!
//! ```text
//! ┌─────────────┐     ┌─────────────┐     ┌─────────────┐
//! │ Hippius API │────▶│ FamilyRegistry │◀────│ Validator   │
//! │ /families/  │     │ (in-memory)  │     │ registration │
//! └─────────────┘     └─────────────┘     └─────────────┘
//! ```
//!
//! # Verification Flow
//!
//! 1. Miner registers with `(node_id, family_id)`
//! 2. Validator calls `verify_membership(node_id, family_id)`
//! 3. Registry checks cached whitelist from API
//! 4. Returns `(true, None)` if valid, or `(false, error_message)` if invalid
//!
//! # Configuration
//!
//! Enabled via `[families]` section in `validator.toml`:
//! ```toml
//! [families]
//! enabled = true
//! api_url = "https://api.hippius.com/api/miner/families/"
//! refresh_interval_secs = 300
//! ```

use crate::config::FamiliesConfig;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::RwLock;
use tracing::{error, info, warn};

/// Represents a family from the API
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct Family {
    /// SS58 address of the family
    pub family: String,
    /// Main node ID (Ed25519 public key)
    pub main_node: String,
    /// Child node IDs
    #[serde(default)]
    pub child_nodes: Vec<String>,
}

/// API response structure (paginated)
#[derive(Debug, Clone, Deserialize)]
#[allow(dead_code)]
pub struct FamiliesApiResponse {
    pub count: u32,
    pub next: Option<String>,
    pub previous: Option<String>,
    pub results: Vec<Family>,
}

/// Family registry - caches families and provides verification
pub struct FamilyRegistry {
    config: FamiliesConfig,
    /// Map of node_id -> family_id for quick lookup
    node_to_family: Arc<RwLock<HashMap<String, String>>>,
    /// Map of family_id -> Family for full details
    families: Arc<RwLock<HashMap<String, Family>>>,
    /// HTTP client for API requests
    client: reqwest::Client,
}

impl FamilyRegistry {
    /// Create a new family registry
    pub fn new(config: FamiliesConfig) -> Self {
        // Accept self-signed certs for API connections
        let client = reqwest::Client::builder()
            .danger_accept_invalid_certs(true)
            .build()
            .unwrap_or_else(|_| reqwest::Client::new());

        Self {
            config,
            node_to_family: Arc::new(RwLock::new(HashMap::new())),
            families: Arc::new(RwLock::new(HashMap::new())),
            client,
        }
    }

    /// Fetch families from API and update cache
    pub async fn refresh(&self) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        if !self.config.enabled {
            return Ok(());
        }

        info!("Refreshing family whitelist from API");

        let mut url = self.config.api_url.clone();
        let mut all_families: Vec<Family> = Vec::new();

        // Handle pagination
        loop {
            let response: FamiliesApiResponse = self.client.get(&url).send().await?.json().await?;

            all_families.extend(response.results);

            match response.next {
                Some(next_url) => url = next_url,
                None => break,
            }
        }

        // Build lookup maps
        let mut node_map = HashMap::new();
        let mut family_map = HashMap::new();

        for family in all_families {
            // Add main node -> family mapping
            node_map.insert(family.main_node.clone(), family.family.clone());

            // Add child nodes -> family mapping
            for child in &family.child_nodes {
                node_map.insert(child.clone(), family.family.clone());
            }

            family_map.insert(family.family.clone(), family);
        }

        // Update cache
        *self.node_to_family.write().await = node_map;
        *self.families.write().await = family_map;

        let count = self.families.read().await.len();
        info!(count = count, "Loaded families");

        Ok(())
    }

    /// Verify that a node_id belongs to the given family_id
    /// Returns (is_valid, error_message)
    pub async fn verify_membership(
        &self,
        node_id: &str,
        claimed_family_id: &str,
    ) -> (bool, Option<String>) {
        if !self.config.enabled {
            return (true, None); // Verification disabled, allow all
        }

        fn truncate(s: &str) -> &str {
            &s[..16.min(s.len())]
        }

        let node_map = self.node_to_family.read().await;
        match node_map.get(node_id) {
            Some(actual_family) if actual_family == claimed_family_id => (true, None),
            Some(actual_family) => (
                false,
                Some(format!(
                    "Node {} belongs to family {} but claimed {}",
                    truncate(node_id),
                    truncate(actual_family),
                    truncate(claimed_family_id)
                )),
            ),
            None => (
                false,
                Some(format!(
                    "Node {} not found in any registered family",
                    truncate(node_id)
                )),
            ),
        }
    }

    /// Check if a node_id is registered in any family
    #[allow(dead_code)]
    pub async fn is_node_registered(&self, node_id: &str) -> bool {
        if !self.config.enabled {
            return true; // Verification disabled, allow all
        }

        self.node_to_family.read().await.contains_key(node_id)
    }

    /// Run periodic refresh loop
    pub async fn run_refresh_loop(self: Arc<Self>) {
        use std::time::{Duration, Instant};

        if !self.config.enabled {
            info!("Family verification disabled, not starting refresh loop");
            return;
        }

        info!(
            interval_secs = self.config.refresh_interval_secs,
            "Family verification enabled, starting refresh loop"
        );

        // Track last successful refresh for staleness detection
        let mut last_success = Instant::now();

        // Initial load
        if let Err(e) = self.refresh().await {
            error!(error = %e, "Initial family load failed");
        } else {
            last_success = Instant::now();
        }

        // Periodic refresh
        loop {
            tokio::time::sleep(Duration::from_secs(self.config.refresh_interval_secs)).await;

            match self.refresh().await {
                Ok(()) => {
                    last_success = Instant::now();
                }
                Err(e) => {
                    warn!(error = %e, "Family refresh failed");
                    if last_success.elapsed() > Duration::from_secs(3600) {
                        error!("Family list is stale (no successful refresh in over 1 hour)");
                    }
                }
            }
        }
    }
}

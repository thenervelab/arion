//! Chain registry cache reader (sourced from `pallet-arion` storage snapshots).
//!
//! This module is designed to consume the JSON snapshot produced by the `chain-registry-cache`
//! binary (in `chain-submitter/src/bin/chain-registry-cache.rs`), and provide fast in-memory
//! lookups:
//! - node_id (iroh public key) -> family_id (hex32 AccountId)
//!
//! We use this to derive a miner's `family_id` in the validator's CRUSH map from on-chain truth,
//! instead of trusting miner-provided family strings.

use crate::config::ChainRegistryConfig;
use anyhow::{Context, Result, anyhow};
use serde::Deserialize;
use std::collections::{BTreeMap, HashMap};
use std::path::Path;
use std::str::FromStr;
use std::sync::Arc;
use tokio::sync::RwLock;
use tracing::{info, warn};

#[derive(Debug, Clone, Deserialize)]
struct RegistrySnapshot {
    #[allow(dead_code)]
    at_block: u32,
    #[allow(dead_code)]
    pallet: String,

    #[allow(dead_code)]
    family_children: BTreeMap<String, Vec<String>>,
    child_registrations: BTreeMap<String, ChildRegistrationView>,
    node_id_to_child: BTreeMap<String, String>,
}

#[derive(Debug, Clone, Deserialize)]
struct ChildRegistrationView {
    family_id: String, // hex32
    #[allow(dead_code)]
    node_id: String, // hex32
    status: String,    // "Active" | "Unbonding" | "Unknown"
    #[allow(dead_code)]
    deposit: String, // u128 as string
    #[allow(dead_code)]
    unbonding_end: u32,
}

#[derive(Debug, Clone)]
pub struct ChainRegistry {
    cfg: ChainRegistryConfig,
    /// node_id_hex32 (0x...) -> family_id_hex32 (0x...)
    node_to_family: Arc<RwLock<HashMap<String, String>>>,
    /// last snapshot block (best-effort)
    last_at_block: Arc<RwLock<Option<u32>>>,
}

impl ChainRegistry {
    pub fn new(cfg: ChainRegistryConfig) -> Self {
        Self {
            cfg,
            node_to_family: Arc::new(RwLock::new(HashMap::new())),
            last_at_block: Arc::new(RwLock::new(None)),
        }
    }

    pub fn enabled(&self) -> bool {
        self.cfg.enabled
    }

    #[allow(dead_code)]
    pub fn cache_path(&self) -> &str {
        &self.cfg.cache_path
    }

    fn node_hex_from_iroh_str(public_key: &str) -> Result<String> {
        let pk = iroh::PublicKey::from_str(public_key)
            .map_err(|e| anyhow!("invalid iroh public_key: {e}"))?;
        Ok(format!("0x{}", hex::encode(pk.as_bytes())))
    }

    async fn set_snapshot(&self, snap: &RegistrySnapshot) {
        let m: HashMap<String, String> = snap
            .node_id_to_child
            .iter()
            .filter_map(|(node_hex, child_hex)| {
                snap.child_registrations
                    .get(child_hex)
                    .filter(|reg| reg.status == "Active")
                    .map(|reg| (node_hex.clone(), reg.family_id.clone()))
            })
            .collect();

        *self.node_to_family.write().await = m;
        *self.last_at_block.write().await = Some(snap.at_block);
    }

    pub async fn refresh_from_disk(&self) -> Result<()> {
        if !self.cfg.enabled {
            return Ok(());
        }

        let path = Path::new(&self.cfg.cache_path);
        let bytes = tokio::fs::read(path)
            .await
            .with_context(|| format!("read chain registry cache {}", path.display()))?;
        let snap: RegistrySnapshot =
            serde_json::from_slice(&bytes).context("parse chain registry cache json")?;
        self.set_snapshot(&snap).await;
        Ok(())
    }

    /// Resolve the on-chain family id (hex32) for a miner node id (iroh public key string).
    ///
    /// - If `enabled=false`, this returns `Ok(None)` (caller decides policy).
    /// - If `enabled=true` and cache is missing/stale, behavior depends on `fail_open`.
    pub async fn resolve_family_hex(&self, public_key: &str) -> Result<Option<String>> {
        if !self.cfg.enabled {
            return Ok(None);
        }
        let node_hex = Self::node_hex_from_iroh_str(public_key)?;

        // Check cache first
        if let Some(f) = self.node_to_family.read().await.get(&node_hex).cloned() {
            return Ok(Some(f));
        }

        // Best-effort: if we're enabled and missing, try a single refresh before failing.
        if let Err(e) = self.refresh_from_disk().await {
            return if self.cfg.fail_open { Ok(None) } else { Err(e) };
        }

        // Check again after refresh
        if let Some(f) = self.node_to_family.read().await.get(&node_hex).cloned() {
            return Ok(Some(f));
        }

        if self.cfg.fail_open {
            Ok(None)
        } else {
            Err(anyhow!(
                "node_id not registered on-chain (node_hex={})",
                node_hex
            ))
        }
    }

    pub async fn run_refresh_loop(self: Arc<Self>) {
        if !self.cfg.enabled {
            info!("Chain registry verification disabled, not starting refresh loop");
            return;
        }
        info!(
            cache_path = %self.cfg.cache_path,
            interval_secs = self.cfg.refresh_interval_secs,
            fail_open = self.cfg.fail_open,
            "Chain registry verification enabled"
        );

        if let Err(e) = self.refresh_from_disk().await {
            warn!(error = %e, "Initial chain registry load failed");
        }

        loop {
            tokio::time::sleep(std::time::Duration::from_secs(
                self.cfg.refresh_interval_secs,
            ))
            .await;
            if let Err(e) = self.refresh_from_disk().await {
                warn!(error = %e, "Chain registry refresh failed");
            }
        }
    }

    #[allow(dead_code)]
    pub async fn debug_last_at_block(&self) -> Option<u32> {
        *self.last_at_block.read().await
    }
}

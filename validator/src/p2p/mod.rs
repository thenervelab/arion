//! P2P protocol handlers for the validator.
//!
//! This module implements handlers for the three new ALPN protocols:
//!
//! - `hippius/gateway-control`: Gateway ↔ Validator communication
//! - `hippius/warden-control`: Warden ↔ Validator communication
//! - `hippius/submitter-control`: Chain-Submitter → Validator communication
//!
//! These protocols replace HTTP endpoints for internal cluster communication,
//! providing unified identity (Ed25519), no TLS certificate management, and
//! built-in NAT traversal via Iroh relays.

mod gateway_handler;
mod submitter_handler;
mod warden_handler;

pub use gateway_handler::GatewayControlHandler;
pub use submitter_handler::SubmitterControlHandler;
pub use warden_handler::{WardenControlHandler, verify_audit_report};

use std::collections::HashSet;
use std::sync::Arc;
use tokio::sync::RwLock;

// Re-export size constants from common crate
pub(crate) use common::P2P_MAX_MESSAGE_SIZE as MAX_MESSAGE_SIZE;
pub(crate) use common::P2P_MAX_UPLOAD_SIZE as MAX_UPLOAD_SIZE;

// Re-export the shared send_response helper
pub(crate) use common::p2p_send_response as send_response;

/// Configuration for P2P protocol authorization.
///
/// Defines which remote nodes are authorized to use each protocol.
/// Empty sets mean allow all (for development mode).
#[derive(Clone, Debug)]
pub struct P2pAuthConfig {
    /// Authorized gateway node IDs (Ed25519 public keys).
    /// Empty = allow all gateways.
    pub authorized_gateways: Arc<RwLock<HashSet<iroh::PublicKey>>>,

    /// Authorized warden node IDs.
    /// Empty = allow all wardens.
    pub authorized_wardens: Arc<RwLock<HashSet<iroh::PublicKey>>>,

    /// Authorized chain-submitter node IDs.
    /// Empty = allow all submitters.
    pub authorized_submitters: Arc<RwLock<HashSet<iroh::PublicKey>>>,
}

impl Default for P2pAuthConfig {
    fn default() -> Self {
        Self {
            authorized_gateways: Arc::new(RwLock::new(HashSet::new())),
            authorized_wardens: Arc::new(RwLock::new(HashSet::new())),
            authorized_submitters: Arc::new(RwLock::new(HashSet::new())),
        }
    }
}

impl P2pAuthConfig {
    /// Create a new P2pAuthConfig from optional lists of authorized node IDs.
    ///
    /// If any list is empty, that protocol allows all connections (dev mode).
    pub fn new(
        gateways: Vec<iroh::PublicKey>,
        wardens: Vec<iroh::PublicKey>,
        submitters: Vec<iroh::PublicKey>,
    ) -> Self {
        Self {
            authorized_gateways: Arc::new(RwLock::new(gateways.into_iter().collect())),
            authorized_wardens: Arc::new(RwLock::new(wardens.into_iter().collect())),
            authorized_submitters: Arc::new(RwLock::new(submitters.into_iter().collect())),
        }
    }

    /// Create from string node IDs (hex-encoded Ed25519 public keys).
    ///
    /// Invalid node IDs are logged and skipped.
    pub fn from_strings(gateways: &[String], wardens: &[String], submitters: &[String]) -> Self {
        use tracing::warn;

        let parse_node_ids = |ids: &[String], role: &str| -> Vec<iroh::PublicKey> {
            ids.iter()
                .filter_map(|s| {
                    match s.parse::<iroh::PublicKey>() {
                        Ok(pk) => Some(pk),
                        Err(e) => {
                            warn!(node_id = %s, error = %e, role = role, "Invalid P2P node ID in config, skipping");
                            None
                        }
                    }
                })
                .collect()
        };

        let gateways = parse_node_ids(gateways, "gateway");
        let wardens = parse_node_ids(wardens, "warden");
        let submitters = parse_node_ids(submitters, "submitter");

        Self::new(gateways, wardens, submitters)
    }

    /// Check if a node is authorized as a gateway.
    pub async fn is_authorized_gateway(&self, node_id: &iroh::PublicKey) -> bool {
        let gateways = self.authorized_gateways.read().await;
        gateways.is_empty() || gateways.contains(node_id)
    }

    /// Check if a node is authorized as a warden.
    pub async fn is_authorized_warden(&self, node_id: &iroh::PublicKey) -> bool {
        let wardens = self.authorized_wardens.read().await;
        wardens.is_empty() || wardens.contains(node_id)
    }

    /// Check if a node is authorized as a chain-submitter.
    pub async fn is_authorized_submitter(&self, node_id: &iroh::PublicKey) -> bool {
        let submitters = self.authorized_submitters.read().await;
        submitters.is_empty() || submitters.contains(node_id)
    }
}

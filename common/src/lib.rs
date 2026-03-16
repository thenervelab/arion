//! Common types and algorithms for the Hippius Arion storage subnet.
//!
//! This crate provides shared functionality used across all Arion components:
//! - **CRUSH placement algorithm**: Deterministic shard distribution with family diversity
//! - **Reed-Solomon codec**: Erasure coding for fault tolerance (10+20 default = 66% fault tolerance)
//! - **Protocol messages**: P2P communication between validators, miners, and gateways
//! - **Placement Groups (PGs)**: File-to-miner mapping for efficient rebalancing
//! - **TLS configuration**: Certificate loading with self-signed fallback for development
//! - **Attestation bundles**: Verifiable merkle tree proofs for warden audit results
//!
//! # Placement Algorithm Overview
//!
//! Arion supports three placement versions (controlled by `FileManifest.placement_version`):
//!
//! - **Version 1 (legacy)**: Per-stripe CRUSH with seed = `hash(file_hash + stripe_index)`
//! - **Version 2 (PG-based)**: File → PG mapping, then CRUSH on PG ID with stripe rotation
//! - **Version 3 (PG+straw2)**: Same as v2 but uses Ceph-style straw2 selection for
//!   minimal data movement on topology changes
//!
//! Both versions use CRUSH (Controlled Replication Under Scalable Hashing) for:
//! - Deterministic placement (no coordination needed between nodes)
//! - Family diversity (maximize spread across failure domains)
//! - Weighted distribution (respect miner storage capacity)
//!
//! # Key Design Principles
//!
//! - **Stable placement**: All miners included in CRUSH input (no filtering by online/space)
//!   to ensure Validator (write) and Gateway (read) calculate identical placements
//! - **Family diversity**: Shards spread across different family IDs for fault tolerance
//! - **Deterministic ordering**: Miners sorted by UID before placement to avoid HashMap shuffle

pub mod attestation_bundle;
pub mod merkle;
pub mod middleware;
#[cfg(feature = "redb")]
pub mod redb_utils;
pub mod stun;
pub mod telemetry;
pub mod tls;

// Re-export attestation bundle types at crate root for convenience
pub use attestation_bundle::{
    AttestationAuditResult, AttestationBundle, AttestationLeaf, AttestationWithProof,
    EpochAttestationCommitment, MerkleProof,
};

// Re-export merkle functions
pub use merkle::{blake3_hash, build_merkle_tree, verify_merkle_proof};

use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::hash::Hasher;
use std::path::PathBuf;
use tracing::debug;
use xxhash_rust::xxh3;

// ============================================================================
// Core Types
// ============================================================================

/// A storage miner node in the Arion network.
///
/// Miners store erasure-coded shards and serve them to gateways on demand.
/// Each miner belongs to a family (failure domain) and has a weight that
/// influences CRUSH placement probability.
#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct MinerNode {
    /// Unique identifier assigned by the validator upon registration
    pub uid: u32,
    /// Iroh P2P endpoint address including relay hints for NAT traversal
    pub endpoint: iroh::EndpointAddr,
    /// CRUSH weight - higher weight = more shards assigned (typically 1-100)
    pub weight: u32,
    /// IP subnet for network locality awareness (e.g., "192.168.1.0/24")
    pub ip_subnet: String,
    /// IP address extracted from EndpointAddr or http_addr at registration
    #[serde(default)]
    pub ip_address: Option<String>,
    /// HTTP address for legacy API calls (e.g., "http://127.0.0.1:3001")
    pub http_addr: String,
    /// Ed25519 public key (hex-encoded) for authentication
    pub public_key: String,
    /// Total storage capacity in bytes
    pub total_storage: u64,
    /// Available storage capacity in bytes
    pub available_storage: u64,
    /// Family ID for CRUSH failure domain grouping (e.g., "datacenter-1", "rack-a")
    pub family_id: String,
    /// Strike counter for reliability tracking (derived from floor(reputation))
    pub strikes: u8,
    /// Unix timestamp of last successful heartbeat
    pub last_seen: u64,

    // Performance tracking for auto weight adjustment
    /// Total successful heartbeats since registration
    #[serde(default)]
    pub heartbeat_count: u32,
    /// Unix timestamp when miner first registered
    #[serde(default)]
    pub registration_time: u64,
    /// Total bytes served across all requests
    #[serde(default)]
    pub bandwidth_total: u64,
    /// Window start timestamp for bandwidth rate calculation
    #[serde(default)]
    pub bandwidth_window_start: u64,
    /// If true, operator has locked weight and auto-adjustment is disabled
    #[serde(default)]
    pub weight_manual_override: bool,

    // Reputation tracking for warden audit integration
    /// Fractional reputation score (0.0 = perfect, 3.0+ = ban threshold)
    #[serde(default)]
    pub reputation: f32,
    /// Consecutive successful audit passes (for recovery calculation)
    #[serde(default)]
    pub consecutive_audit_passes: u32,
    /// Count of audit failures due to invalid/failed proofs (for on-chain penalty)
    #[serde(default)]
    pub integrity_fails: u32,
    /// Software version reported by the miner (e.g., "0.1.1")
    #[serde(default)]
    pub version: String,

    /// Pre-reputation base weight computed by `adjust_miner_weight()`.
    /// Stored to avoid reverse-computing from the reputation-penalized weight.
    /// Zero means not yet computed (backward compat with old serialized maps).
    #[serde(default)]
    pub base_weight: u32,

    // Trust score tracking for earned capacity
    /// Total warden challenges received
    #[serde(default)]
    pub warden_challenges_total: u32,
    /// Warden challenges that passed successfully
    #[serde(default)]
    pub warden_challenges_passed: u32,
    /// Fetch timeout count reported by peers (rolling 24h window)
    #[serde(default)]
    pub fetch_timeout_count: u32,
    /// Expected shard count based on CRUSH placement
    #[serde(default)]
    pub expected_shards: u32,
    /// Actual shard count confirmed on miner
    #[serde(default)]
    pub actual_shards: u32,
    /// Computed trust score in range [0.0, 1.0]
    #[serde(default)]
    pub trust_score: f32,
    /// Computed earned capacity in bytes
    #[serde(default)]
    pub earned_capacity_bytes: u64,
    /// When true, miner is deregistered and draining — read-only source,
    /// invisible as a destination for new shard placement.
    #[serde(default)]
    pub draining: bool,

    /// P2P reliability score in range [0.0, 1.0].
    /// Used to modulate CRUSH weight — miners with low scores get fewer shards.
    /// Updated by the validator's P2P connectivity probe and FetchBlob outcomes.
    #[serde(default = "default_reliability_score")]
    pub p2p_reliability_score: f64,
}

fn default_reliability_score() -> f64 {
    1.0
}

/// Result of auditing a single shard's availability and integrity.
///
/// Used by the validator's rebuild agent to track shard health and trigger recovery.
#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct ShardAuditReport {
    /// Global shard index within the file (stripe_idx * shards_per_stripe + shard_idx)
    pub shard_index: usize,
    /// BLAKE3 hash of the shard data
    pub hash: String,
    /// UID of the miner holding this shard (None if placement failed)
    pub miner_uid: Option<u32>,
    /// HTTP address of the miner (for debugging)
    pub miner_addr: Option<String>,
    /// Audit result: "PASS", "FAIL", "RECOVERED", or "OFFLINE"
    pub status: String,
    /// Round-trip latency in milliseconds
    pub latency_ms: u64,
    /// Unix timestamp when audit was performed
    pub timestamp: u64,
}

/// Summary of a stored file (hash and size only).
///
/// Used in sync indexes and file listings where full manifest data is not needed.
#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct FileSummary {
    /// BLAKE3 hash of the original file (64 hex characters)
    pub hash: String,
    /// File size in bytes
    pub size: u64,
}

/// Index for synchronizing file metadata between components.
///
/// Contains a snapshot of all files at a given cluster map version.
#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct SyncIndex {
    /// Hash of the cluster map at sync time (for version tracking)
    pub map_hash: String,
    /// List of all files in the system
    pub files: Vec<FileSummary>,
    /// Unix timestamp when index was generated
    pub timestamp: u64,
}

// ============================================================================
// Cluster Topology
// ============================================================================

/// The cluster map containing all active miners and placement parameters.
///
/// This is the authoritative view of the storage network used for CRUSH placement.
/// The validator broadcasts epoch updates; all components must agree on the same
/// map to calculate identical shard placements.
///
/// # Epoch Management
///
/// The epoch increments when:
/// - A miner joins or leaves the cluster
/// - Miner weights change significantly
/// - Manual rebalancing is triggered
///
/// A gateway endpoint registered with the validator for client discovery.
/// Included in `ClusterMapUpdate` broadcasts so miners and other nodes know
/// which gateways are available for HTTP ingress.
#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct GatewayEndpoint {
    /// Unique identifier for this gateway (typically the Iroh node ID hex string)
    pub node_id: String,
    /// Public HTTP address (e.g. "https://gateway.example.com:3000")
    pub public_addr: String,
    /// Direct P2P address for iroh QUIC connections (e.g. "51.91.196.88:11205")
    /// Miners use this to establish keepalive connections to gateways.
    #[serde(default)]
    pub direct_addr: Option<String>,
    /// Unix timestamp of last heartbeat (for TTL-based cleanup)
    pub last_seen: u64,
}

/// Files store their `placement_epoch` in the manifest to support epoch-fallback
/// reads during cluster transitions.
#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct ClusterMap {
    /// Monotonically increasing version number (increments on topology changes)
    pub epoch: u64,
    /// All registered miners (online and offline - filtering happens at write time)
    pub miners: Vec<MinerNode>,
    /// Number of Placement Groups for CRUSH distribution.
    /// Default: 16384 (suitable for 400+ miners at ~40 PGs per miner)
    #[serde(default = "default_pg_count")]
    pub pg_count: u32,
    /// Data shards per stripe (k in k+m erasure coding).
    /// Must be consistent across the cluster for deterministic PG ownership.
    #[serde(default = "default_ec_k")]
    pub ec_k: usize,
    /// Parity shards per stripe (m in k+m erasure coding).
    /// Default 20 provides 66% fault tolerance with k=10.
    #[serde(default = "default_ec_m")]
    pub ec_m: usize,
}

fn default_pg_count() -> u32 {
    16384
}

fn default_ec_k() -> usize {
    10
}
fn default_ec_m() -> usize {
    20
}

impl Default for ClusterMap {
    fn default() -> Self {
        Self::new()
    }
}

impl ClusterMap {
    /// Creates a new empty cluster map with default parameters.
    ///
    /// Default values: epoch=0, pg_count=16384, ec_k=10, ec_m=20
    pub fn new() -> Self {
        let empty = Self {
            epoch: 0,
            miners: Vec::new(),
            pg_count: default_pg_count(),
            ec_k: default_ec_k(),
            ec_m: default_ec_m(),
        };

        let backup_data_path = PathBuf::from("data/validator/cluster_map_backup.json");
        if !backup_data_path.exists() {
            return empty;
        }

        match std::fs::read_to_string(&backup_data_path) {
            Ok(json) => serde_json::from_str(&json).unwrap_or_else(|e| {
                tracing::warn!(
                    error = %e,
                    path = %backup_data_path.display(),
                    "Corrupt cluster_map backup, using empty default"
                );
                empty
            }),
            Err(e) => {
                tracing::warn!(
                    error = %e,
                    path = %backup_data_path.display(),
                    "Failed to read cluster_map backup, using empty default"
                );
                empty
            }
        }
    }

    /// Ensure critical placement parameters are valid.
    /// Call after deserialization from untrusted sources.
    ///
    /// - Replaces zero values with defaults
    /// - Rounds pg_count up to the next power of 2 (CRUSH distribution
    ///   uniformity requires power-of-2 PG counts)
    pub fn ensure_defaults(&mut self) {
        if self.pg_count == 0 {
            self.pg_count = default_pg_count();
        } else if !self.pg_count.is_power_of_two() {
            let rounded = self.pg_count.next_power_of_two();
            tracing::warn!(
                original = self.pg_count,
                rounded,
                "pg_count must be a power of 2, rounding up"
            );
            self.pg_count = rounded;
        }
        if self.ec_k == 0 {
            self.ec_k = default_ec_k();
        }
        if self.ec_m == 0 {
            self.ec_m = default_ec_m();
        }
    }

    /// Adds a miner node to the cluster (does not increment epoch).
    pub fn add_node(&mut self, node: MinerNode) {
        self.miners.push(node);
    }

    /// Removes a miner by UID from the cluster (does not increment epoch).
    pub fn remove_node(&mut self, uid: u32) {
        self.miners.retain(|m| m.uid != uid);
    }
}

// ============================================================================
// File Manifest Types
// ============================================================================

/// Information about a single erasure-coded shard.
///
/// Shards are the atomic storage unit - each stripe produces k+m shards.
/// The miner location is calculated via CRUSH at read time, not stored.
#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct ShardInfo {
    /// Global shard index across the file (stripe_idx * (k+m) + shard_idx_within_stripe)
    pub index: usize,
    /// BLAKE3 hash of the shard data (used for content addressing and verification)
    pub blob_hash: String,
}

/// Manifest describing a stored file and its erasure-coded shards.
///
/// The manifest is the source of truth for file reconstruction. It contains:
/// - Original file metadata (hash, size, content type)
/// - Erasure coding parameters (stripe config)
/// - All shard hashes (grouped by stripe)
///
/// Miner locations are NOT stored - they're calculated via CRUSH at read time
/// using the `placement_version` algorithm and current cluster map.
///
/// # Storage Layout
///
/// Shards are stored contiguously by stripe:
/// ```text
/// [stripe_0_shard_0, stripe_0_shard_1, ..., stripe_0_shard_{k+m-1},
///  stripe_1_shard_0, stripe_1_shard_1, ..., stripe_1_shard_{k+m-1},
///  ...]
/// ```
/// Warden PoS Commitment (shard_hash, poseidon_tree_root, miner_uid, size, address)
pub type ShardCommitment = (String, [u32; 8], u32, u32, iroh::EndpointAddr);

/// Payload sent from the Gateway to the Validator upon successful upload distribution.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UploadFinalizeRequest {
    pub manifest: FileManifest,
    pub warden_commitments: Vec<ShardCommitment>,
}

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct FileManifest {
    /// BLAKE3 hash of the original file (64 hex characters)
    pub file_hash: String,
    /// Placement algorithm version for shard location calculation:
    /// - 1: legacy per-stripe CRUSH (seed = hash(file_hash + stripe_index))
    /// - 2: PG-based placement (file → PG → CRUSH with stripe rotation)
    /// - 3: PG-based placement with straw2 selection (minimal data movement)
    #[serde(default = "default_manifest_placement_version")]
    pub placement_version: u8,
    /// Cluster map epoch when file was originally distributed.
    /// Used for debugging and epoch-fallback reads during rebalancing.
    #[serde(default)]
    pub placement_epoch: u64,
    /// Original file size in bytes
    pub size: u64,
    /// Erasure coding configuration (stripe size, k, m)
    pub stripe_config: StripeConfig,
    /// All shard hashes, grouped by stripe (see Storage Layout above)
    pub shards: Vec<ShardInfo>,
    /// Original filename (optional, for content disposition)
    #[serde(default)]
    pub filename: Option<String>,
    /// MIME content type (optional, for HTTP Content-Type header)
    #[serde(default)]
    pub content_type: Option<String>,
}

fn default_manifest_placement_version() -> u8 {
    1
}

/// Lightweight manifest for iroh-docs gossip distribution.
///
/// Contains only the fields needed for shard verification and CRUSH placement
/// recalculation. Miner assignments are intentionally excluded — they are
/// recalculated from CRUSH + the cluster map epoch at read time.
#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct DocManifest {
    /// BLAKE3 hash of the original file (64 hex characters)
    pub file_hash: String,
    /// Placement algorithm version (1, 2, or 3)
    pub placement_version: u8,
    /// Cluster map epoch when file was originally distributed
    pub placement_epoch: u64,
    /// Original file size in bytes
    pub size: u64,
    /// Erasure coding configuration (stripe size, k, m)
    pub stripe_config: StripeConfig,
    /// Shard hashes (index + blob_hash only, no miner info)
    pub shards: Vec<ShardInfo>,
}

impl From<&FileManifest> for DocManifest {
    fn from(m: &FileManifest) -> Self {
        Self {
            file_hash: m.file_hash.clone(),
            placement_version: m.placement_version,
            placement_epoch: m.placement_epoch,
            size: m.size,
            stripe_config: m.stripe_config.clone(),
            shards: m.shards.clone(),
        }
    }
}

impl From<DocManifest> for FileManifest {
    fn from(d: DocManifest) -> Self {
        Self {
            file_hash: d.file_hash,
            placement_version: d.placement_version,
            placement_epoch: d.placement_epoch,
            size: d.size,
            stripe_config: d.stripe_config,
            shards: d.shards,
            filename: None,
            content_type: None,
        }
    }
}

impl FileManifest {
    /// Serializes the manifest to a JSON string.
    ///
    /// Used for storing manifests in iroh-docs and transmitting over HTTP.
    pub fn to_json(&self) -> Result<String, serde_json::Error> {
        serde_json::to_string(self)
    }

    /// Deserializes a manifest from a JSON string.
    ///
    /// # Errors
    /// Returns an error if the JSON is malformed or missing required fields.
    pub fn from_json(json: &str) -> Result<Self, serde_json::Error> {
        serde_json::from_str(json)
    }
}

/// Serialize a [`DocManifest`] to bincode bytes for iroh-doc storage.
pub fn doc_manifest_to_bytes(m: &DocManifest) -> anyhow::Result<Vec<u8>> {
    bincode::serialize(m).map_err(|e| anyhow::anyhow!(e))
}

/// Deserialize a [`DocManifest`] from bincode bytes.
pub fn doc_manifest_from_bytes(b: &[u8]) -> anyhow::Result<DocManifest> {
    bincode::deserialize(b).map_err(|e| anyhow::anyhow!(e))
}

/// Serialize a [`ClusterMap`] to bincode bytes for iroh-doc storage.
pub fn cluster_map_to_bytes(m: &ClusterMap) -> anyhow::Result<Vec<u8>> {
    bincode::serialize(m).map_err(|e| anyhow::anyhow!(e))
}

/// Deserialize a [`ClusterMap`] from bincode bytes.
pub fn cluster_map_from_bytes(b: &[u8]) -> anyhow::Result<ClusterMap> {
    bincode::deserialize(b).map_err(|e| anyhow::anyhow!(e))
}

/// Configuration for Reed-Solomon erasure coding stripes.
///
/// Files are split into fixed-size stripes, each independently erasure-coded
/// into k data shards + m parity shards. Any k shards can reconstruct the stripe.
///
/// # Default Configuration
///
/// - `size`: 8 MiB per stripe
/// - `k`: 10 data shards
/// - `m`: 20 parity shards
///
/// This provides 66% fault tolerance (can lose 20 of 30 shards and still reconstruct).
///
/// StripeConfig is intentionally hardcoded (k=10, m=20, stripe_size=8MiB).
/// The manifest records the actual config used at upload time, enabling
/// future changes without breaking existing files.
#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct StripeConfig {
    /// Stripe size in bytes (default: 8 MiB)
    pub size: u64,
    /// Number of data shards (minimum shards needed for reconstruction)
    pub k: usize,
    /// Number of parity shards (redundancy for fault tolerance)
    pub m: usize,
}

impl Default for StripeConfig {
    fn default() -> Self {
        Self {
            size: 8 * 1024 * 1024,
            k: 10,
            m: 20,
        }
    }
}

impl StripeConfig {
    /// Validates the stripe configuration.
    ///
    /// # Errors
    /// Returns an error if:
    /// - k (data shards) is 0
    /// - m (parity shards) is 0
    /// - k + m exceeds 256 (GF(2^8) Reed-Solomon limit)
    /// - stripe size is 0
    pub fn validate(&self) -> Result<(), String> {
        if self.k == 0 {
            return Err("k (data shards) must be at least 1".to_string());
        }
        if self.m == 0 {
            return Err("m (parity shards) must be at least 1".to_string());
        }
        if self.k + self.m > 256 {
            return Err(format!(
                "k + m ({}) cannot exceed 256 for GF(2^8) Reed-Solomon",
                self.k + self.m
            ));
        }
        if self.size == 0 {
            return Err("stripe size must be positive".to_string());
        }
        Ok(())
    }
}

// ============================================================================
// P2P Protocol Messages
// ============================================================================

/// Messages sent via the `hippius/miner-control` P2P protocol.
///
/// Used for Validator → Miner and Gateway → Miner communication.
/// Sent over Iroh QUIC connections with JSON serialization (serde_json).
#[derive(Serialize, Deserialize, Debug, Clone)]
pub enum MinerControlMessage {
    /// Delete a shard by hash
    Delete {
        /// BLAKE3 hash of the shard to delete
        hash: String,
        /// Ed25519 signature from the Validator (or authorized Gateway) over `"DELETE:{hash}"`
        validator_signature: Vec<u8>,
    },
    /// Fetch a blob by hash (Gateway → Miner)
    FetchBlob {
        /// BLAKE3 hash of the requested shard
        hash: String,
    },
    /// Cluster map update for peer discovery and self-rebalancing
    ClusterMapUpdate {
        /// Current cluster map epoch
        epoch: u64,
        /// List of (public_key, endpoint_json) for all active miners
        peers: Vec<(String, String)>,
        /// Full cluster map JSON for CRUSH calculations (enables self-rebalancing)
        cluster_map_json: Option<String>,
        /// Authorized warden node IDs for PoS challenge authorization (auto-distributed by validator)
        #[serde(default)]
        warden_node_ids: Option<Vec<String>>,
        /// Known gateway endpoints for client discovery (optional, empty for old miners)
        #[serde(default)]
        gateway_endpoints: Vec<GatewayEndpoint>,
    },
    /// Instruct miner to pull a blob from a peer via Iroh P2P
    PullFromPeer {
        /// BLAKE3 hash of the blob to pull
        hash: String,
        /// Peer's EndpointAddr as JSON string
        peer_endpoint: String,
        /// Ed25519 signature over "PULL:{hash}" bytes, signed by the validator's iroh key.
        /// Verified by the miner to authenticate the command.
        #[serde(default)]
        validator_signature: Vec<u8>,
    },
    /// Proof-of-storage challenge from Warden
    PosChallenge {
        /// BLAKE3 hash of the shard to prove
        shard_hash: String,
        /// Random chunk indices to prove possession of
        chunk_indices: Vec<u32>,
        /// Random nonce for freshness (prevents replay)
        nonce: [u8; 32],
        /// Expected Merkle root from commitment
        expected_root: [u32; 8],
        /// Challenge expiry timestamp (Unix seconds)
        expires_at: u64,
    },
    /// Binary-framed Store (V2): header-only, data follows as raw bytes on the wire.
    /// Used for efficient shard distribution — avoids JSON encoding of binary data.
    /// The actual blob data is NOT in this variant; it is read separately from the stream.
    StoreV2 {
        /// BLAKE3 hash of the shard data
        hash: String,
        /// Length of raw blob data that follows this header on the stream.
        /// Uses u64 for platform-independent wire format.
        data_len: u64,
        /// Ed25519 signature from the Validator (or authorized Gateway) over `"UPLOAD:{hash}"`
        validator_signature: Vec<u8>,
    },
    /// Lightweight metadata-only existence check for a shard.
    /// Returns `HAS:true` or `HAS:false` without reading blob data.
    /// Used by the validator before PullFromPeer/FetchBlob to avoid
    /// wasting P2P round-trips on miners that lost a shard.
    CheckBlob { hash: String },
}

/// Magic byte for StoreV2 binary framing protocol.
/// When a miner receives a message starting with this byte, it uses V2 binary parsing.
pub const STORE_V2_MAGIC: u8 = 0x02;

/// Magic byte for gateway streaming upload framing protocol.
/// When the validator receives a message starting with this byte on the gateway-control
/// protocol, it uses binary streaming upload parsing instead of JSON deserialization.
pub const GATEWAY_UPLOAD_V1_MAGIC: u8 = 0x03;

/// Header for streaming upload over P2P (gateway → validator).
///
/// Sent as length-prefixed JSON after the magic byte. The raw file bytes follow
/// immediately after the header until the sender calls `finish()` on the stream.
#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct GatewayUploadHeader {
    pub filename: String,
    /// Advisory file size — validator streams until EOF and does not rely on this value.
    pub size_hint: u64,
    pub content_type: Option<String>,
}

/// Messages sent via the `hippius/validator-control` P2P protocol (Miner → Validator).
///
/// Used for miner registration, heartbeats, and self-rebalancing queries.
/// All messages requiring authentication include Ed25519 signatures.
#[derive(Serialize, Deserialize, Debug, Clone)]
pub enum ValidatorControlMessage {
    /// Initial miner registration request.
    /// Validator assigns a UID and adds miner to the cluster map.
    Register {
        /// Ed25519 public key (hex-encoded)
        public_key: String,
        /// HTTP API address (e.g., "http://127.0.0.1:3001")
        http_addr: String,
        /// Total storage capacity in bytes
        total_storage: u64,
        /// Available storage capacity in bytes
        available_storage: u64,
        /// Family ID for CRUSH failure domain grouping
        family_id: String,
        /// Unix timestamp for replay protection (rejects if >5min old)
        timestamp: u64,
        /// Ed25519 signature of "REGISTER:{public_key}:{timestamp}"
        signature: Vec<u8>,
        /// Miner's full EndpointAddr including relay hints for NAT traversal
        #[serde(default)]
        endpoint_addr: Option<iroh::EndpointAddr>,
        /// Miner software version
        #[serde(default)]
        version: Option<String>,
    },
    /// Periodic heartbeat to maintain online status (sent every 30 seconds).
    /// Miners are marked offline after 2 minutes without heartbeat.
    Heartbeat {
        /// Miner UID assigned during registration
        miner_uid: u32,
        /// Unix timestamp for replay protection
        timestamp: u64,
        /// Current available storage in bytes
        available_storage: u64,
        /// Ed25519 public key for signature verification
        public_key: String,
        /// Ed25519 signature of "HEARTBEAT:{public_key}:{timestamp}"
        signature: Vec<u8>,
        /// Miner's full EndpointAddr including relay hints for NAT traversal
        #[serde(default)]
        endpoint_addr: Option<iroh::EndpointAddr>,
        /// Miner software version
        #[serde(default)]
        version: Option<String>,
    },
    /// P2P health check - validator responds with Pong
    Ping {
        /// Unix timestamp for latency measurement
        timestamp: u64,
    },
    /// Query files in a single Placement Group (for self-rebalancing)
    QueryPgFiles {
        /// Placement Group ID to query
        pg_id: u32,
    },
    /// Batch query for files in multiple Placement Groups (more efficient)
    QueryPgFilesBatch {
        /// List of PG IDs to query
        pg_ids: Vec<u32>,
    },
    /// Query manifest for a specific file (for shard pulling during rebalancing)
    QueryManifest {
        /// File hash to get manifest for
        file_hash: String,
    },
    /// Proof-of-storage response from Miner to Warden
    PosProofResponse {
        /// Nonce from the challenge (for correlation)
        nonce: [u8; 32],
        /// Serialized proof bytes
        proof_bytes: Vec<u8>,
        /// Public inputs as u32 values
        public_inputs: Vec<u32>,
        /// Time taken to generate proof (milliseconds)
        proving_time_ms: u64,
    },
}

// ============================================================================
// CRUSH Placement Algorithm
// ============================================================================

/// Calculate which miner should hold a specific shard using CRUSH.
///
/// This is a convenience wrapper that returns a single miner for a specific
/// shard index. For efficiency when placing all shards in a stripe, use
/// `calculate_placement_for_stripe` directly.
///
/// # Arguments
/// * `file_hash` - BLAKE3 hash of the file (used as CRUSH input)
/// * `stripe_index` - Zero-based stripe index within the file
/// * `shard_index` - Zero-based shard index within the stripe (0 to k+m-1)
/// * `map` - Current cluster map
///
/// # Returns
/// - `Some(MinerNode)` with the target miner for this shard
/// - `None` if placement fails (insufficient miners)
pub fn calculate_shard_placement(
    file_hash: &str,
    stripe_index: u64,
    shard_index: usize,
    map: &ClusterMap,
) -> Option<MinerNode> {
    // Get all miners for this stripe
    let total_shards = map.ec_k + map.ec_m;
    match calculate_placement_for_stripe(file_hash, stripe_index, total_shards, map) {
        Ok(miners) => miners.get(shard_index).cloned(),
        Err(_) => None,
    }
}

/// Calculate miner placement for all shards in a stripe using CRUSH.
///
/// This is the core CRUSH implementation with family diversity optimization.
/// The algorithm:
/// 1. Groups miners by family ID (failure domain)
/// 2. Selects families using weighted random (deterministic from seed)
/// 3. Selects miners within each family using weighted random
/// 4. Maximizes family diversity: if N families ≥ count, each shard goes to different family
///
/// # Arguments
/// * `file_hash` - BLAKE3 hash of the file (combined with stripe_index for seed)
/// * `stripe_index` - Zero-based stripe index (varies the seed per stripe)
/// * `count` - Number of miners to select (typically k + m)
/// * `map` - Current cluster map
///
/// # Returns
/// - `Ok(Vec<MinerNode>)` with exactly `count` miners for shard placement
/// - `Err(String)` if insufficient miners or families available
///
/// # Stability Guarantee
///
/// This function uses ALL miners in the cluster map (no filtering by online/space).
/// Filtering happens at write time when the validator attempts connections.
/// This ensures Validator (write) and Gateway (read) calculate identical placements.
pub fn calculate_placement_for_stripe(
    file_hash: &str,
    stripe_index: u64,
    count: usize,
    map: &ClusterMap,
) -> Result<Vec<MinerNode>, String> {
    // Step 1: Use ALL miners to ensure Stable CRUSH placement
    // We do NOT filter by online/space here because that creates a transient map view
    // which causes Validator (Write) and Gateway (Read) to diverge.

    // Check if we have enough miners for placement
    if map.miners.len() < count {
        debug!(
            needed = count,
            available = map.miners.len(),
            "Insufficient miners for placement"
        );
        return Err(format!(
            "Insufficient cluster capacity: need {} miners with space, have {}",
            count,
            map.miners.len()
        ));
    }

    // CRUSH-inspired placement with MAXIMUM FAMILY DIVERSITY
    // For fault tolerance: distribute shards across DIFFERENT families
    // Goal: If a family goes down, we can still reconstruct (need 10 of 30 for 10+20 EC)

    // Generate deterministic placement seed from file_hash and stripe_index
    let mut hasher = xxh3::Xxh3::new();
    hasher.write(file_hash.as_bytes());
    hasher.write_u64(stripe_index);
    let input = hasher.finish();

    // Step 2: Group miners by family for diversity-aware placement
    // Include ALL miners (filtering happens at write-time when validator attempts connection)
    // Borrow family_id from the ClusterMap to avoid per-miner String clones.
    let mut families: HashMap<&str, Vec<(usize, &MinerNode)>> = HashMap::new();

    for (idx, miner) in map.miners.iter().enumerate() {
        families
            .entry(miner.family_id.as_str())
            .or_default()
            .push((idx, miner));
    }

    // Sort miners within each family by UID for deterministic ordering
    // This ensures consistent placement regardless of HashMap iteration order
    for miners in families.values_mut() {
        miners.sort_by_key(|(_, m)| m.uid);
    }

    // Strategy: Select DIFFERENT families for each shard (when possible)
    // If we have 15 shards and 16 miners across N families:
    // - If N >= 15: 1 shard per family (ideal)
    // - If N < 15: distribute evenly, but spread across all families

    let num_families = families.len();

    if num_families >= count {
        // IDEAL CASE: Enough families to put each shard in a different family
        // Select 'count' different families, then pick one miner from each
        let selected_families = select_weighted_families(&families, count, input)?;

        let mut selected_miners = Vec::new();
        for (idx, family_id) in selected_families.iter().enumerate() {
            let miners_in_family = &families[family_id];

            // Select ONE miner from this family
            let family_input = input.wrapping_add(idx as u64);
            let miner_from_family = select_weighted_miners_from_family(
                miners_in_family,
                1, // Only 1 miner per family
                family_input,
                map,
            )?;

            selected_miners.extend(miner_from_family);
        }

        // Safety check: ensure we got exactly the right number of miners
        if selected_miners.len() != count {
            return Err(format!(
                "Placement failed: needed {} miners but selected {} (zero-weight families?)",
                count,
                selected_miners.len()
            ));
        }

        Ok(selected_miners)
    } else {
        // FALLBACK: Fewer families than shards needed
        // Distribute as evenly as possible across all families
        // Example: 15 shards, 3 families → 5 shards per family

        let selected_families = select_weighted_families(&families, num_families, input)?;
        let mut selected_miners = Vec::new();

        // Calculate base amount and remainder
        let base_per_family = count / num_families;
        let remainder = count % num_families;

        // Track how many miners were taken from each family
        let mut taken_per_family = vec![0usize; num_families];

        for (idx, family_id) in selected_families.iter().enumerate() {
            let miners_in_family = &families[family_id];

            // First 'remainder' families get one extra shard
            let to_take = if idx < remainder {
                base_per_family + 1
            } else {
                base_per_family
            }
            .min(miners_in_family.len());

            let family_input = input.wrapping_add(idx as u64);
            let miners_from_family =
                select_weighted_miners_from_family(miners_in_family, to_take, family_input, map)?;

            taken_per_family[idx] = miners_from_family.len();
            selected_miners.extend(miners_from_family);
        }

        // Second pass: redistribute unfilled slots to families
        // with remaining capacity.
        if selected_miners.len() < count {
            let mut shortfall = count - selected_miners.len();
            let pass_seed = input.wrapping_add(num_families as u64);

            for (idx, family_id) in selected_families.iter().enumerate() {
                if shortfall == 0 {
                    break;
                }
                let miners_in_family = &families[family_id];
                let remaining = miners_in_family.len() - taken_per_family[idx];
                if remaining == 0 {
                    continue;
                }
                let extra = remaining.min(shortfall);

                let taken_uids: std::collections::HashSet<u32> =
                    selected_miners.iter().map(|m| m.uid).collect();
                let available: Vec<(usize, &MinerNode)> = miners_in_family
                    .iter()
                    .filter(|(i, _)| !taken_uids.contains(&map.miners[*i].uid))
                    .copied()
                    .collect();

                let family_input = pass_seed.wrapping_add(idx as u64);
                let extra_miners =
                    select_weighted_miners_from_family(&available, extra, family_input, map)?;
                taken_per_family[idx] += extra_miners.len();
                shortfall -= extra_miners.len();
                selected_miners.extend(extra_miners);
            }
        }

        selected_miners.truncate(count);

        // Safety check: ensure we got enough miners
        if selected_miners.len() < count {
            return Err(format!(
                "Placement failed: needed {} miners but only selected {} (family distribution issue)",
                count,
                selected_miners.len()
            ));
        }

        Ok(selected_miners)
    }
}

/// Advances LCG PRNG state and returns weighted selection index.
///
/// Uses Knuth multiplier for deterministic pseudo-random selection.
/// Lower bits have shorter period but sufficient for placement purposes.
/// Changing this would break placement compatibility.
fn weighted_select(
    weights: &[(usize, u64)],
    rng_seed: &mut u64,
    context: &str,
) -> Result<usize, String> {
    let total_weight: u64 = weights.iter().map(|(_, w)| *w).sum();
    if total_weight == 0 {
        return Err(format!("{}: total weight is zero", context));
    }

    *rng_seed = rng_seed.wrapping_mul(6364136223846793005).wrapping_add(1);
    let target = *rng_seed % total_weight;

    let mut cumulative = 0u64;
    for (idx, (_, weight)) in weights.iter().enumerate() {
        cumulative += *weight;
        if cumulative > target {
            return Ok(idx);
        }
    }

    Err(format!(
        "{}: selection failed - target={}, total_weight={}, cumulative={}",
        context, target, total_weight, cumulative
    ))
}

/// Selects families using weighted random distribution (CRUSH helper).
///
/// Family weight = sum of all miner weights in that family.
/// Uses deterministic LCG PRNG seeded from placement input.
fn select_weighted_families<'a>(
    families: &'a HashMap<&'a str, Vec<(usize, &MinerNode)>>,
    count: usize,
    seed: u64,
) -> Result<Vec<&'a str>, String> {
    // Build indexed weights once: (original_index, family_id, weight)
    // Use u64 for weights to prevent overflow when summing many miner weights
    let mut indexed_weights: Vec<(usize, &str, u64)> = families
        .iter()
        .enumerate()
        .map(|(i, (fid, miners))| {
            let total_weight: u64 = miners.iter().map(|(_, m)| m.weight as u64).sum();
            (i, *fid, total_weight)
        })
        .collect();

    // Sort for determinism by family_id
    indexed_weights.sort_by(|a, b| a.1.cmp(b.1));

    let mut selected = Vec::with_capacity(count);
    let mut rng_seed = seed;
    let iterations = count.min(indexed_weights.len());

    for _ in 0..iterations {
        // Build weights slice for selection
        let weights: Vec<(usize, u64)> = indexed_weights.iter().map(|(i, _, w)| (*i, *w)).collect();

        // Check if all remaining weights are zero
        if weights.iter().all(|(_, w)| *w == 0) {
            break;
        }

        let selected_idx = weighted_select(&weights, &mut rng_seed, "Weighted family selection")?;

        // Use remove (not swap_remove) to preserve deterministic ordering —
        // weighted_select depends on cumulative weight order across iterations.
        let (_, family_id, _) = indexed_weights.remove(selected_idx);
        selected.push(family_id);
    }

    Ok(selected)
}

/// Selects miners from a single family using weighted random distribution (CRUSH helper).
///
/// Miner selection respects weight values for load balancing.
/// Uses deterministic LCG PRNG for reproducible placement.
fn select_weighted_miners_from_family(
    miners_in_family: &[(usize, &MinerNode)],
    count: usize,
    seed: u64,
    map: &ClusterMap,
) -> Result<Vec<MinerNode>, String> {
    // Use u64 for weights to prevent overflow when summing many miner weights
    let mut available: Vec<(usize, u64)> = miners_in_family
        .iter()
        .map(|(idx, m)| (*idx, m.weight as u64))
        .collect();

    // Validate all indices before sorting to ensure bounds safety
    if available.iter().any(|(idx, _)| *idx >= map.miners.len()) {
        return Err("Invalid miner index in family".to_string());
    }

    // Sort for determinism by UID (using idx to lookup in map)
    // Safety: indices were validated above
    available.sort_by_key(|(idx, _)| map.miners[*idx].uid);

    let mut selected = Vec::new();
    let mut rng_seed = seed;

    for _ in 0..count.min(available.len()) {
        if available.iter().all(|(_, w)| *w == 0) {
            break;
        }

        let selected_idx = weighted_select(&available, &mut rng_seed, "Weighted miner selection")?;

        // Use remove (not swap_remove) to preserve deterministic ordering —
        // weighted_select depends on cumulative weight order across iterations.
        let (miner_idx, _) = available.remove(selected_idx);
        // Safety: miner_idx was validated above
        selected.push(map.miners[miner_idx].clone());
    }

    Ok(selected)
}

// ============================================================================
// Straw2 Selection (placement_version=3)
// ============================================================================
//
// Ceph-style straw2 selection for minimal data movement on topology changes.
// Each candidate computes an independent "draw" value; the max draw wins.
// Adding or removing a candidate only affects selections where that
// candidate would have won — all other placements remain stable.

/// Compute a straw2 draw for a single candidate.
///
/// Uses the Ceph straw2 formula: `ln(hash / 65536) / weight`.
/// Higher weight → less negative draw → more likely to win.
/// Zero-weight candidates get `-INFINITY` (never selected).
fn straw2_draw(seed: u64, id: u32, weight: u64) -> f64 {
    if weight == 0 {
        return f64::NEG_INFINITY;
    }
    let mut hasher = xxh3::Xxh3::new();
    hasher.write_u64(seed);
    hasher.write_u32(id);
    let hash = hasher.finish();
    // Map to (0, 1) range — +1 avoids ln(0), +1 in denominator keeps range < 1
    let u = ((hash & 0xFFFF) as f64 + 1.0) / 65537.0;
    // Use libm::log for cross-platform determinism (f64::ln() is
    // platform-dependent and may produce different results on different
    // CPU architectures).
    libm::log(u) / (weight as f64)
}

/// Select one item from candidates using straw2 (max-draw-wins).
///
/// Returns the index into `candidates` of the winner.
/// Each candidate's draw is independent of all other candidates.
fn straw2_select_one(candidates: &[(u32, u64)], seed: u64) -> Result<usize, String> {
    if candidates.is_empty() {
        return Err("straw2: empty candidate list".to_string());
    }
    if candidates.iter().all(|(_, w)| *w == 0) {
        return Err("straw2: all candidates have zero weight".to_string());
    }

    let mut best_idx = 0;
    let mut best_draw = f64::NEG_INFINITY;
    for (idx, (id, weight)) in candidates.iter().enumerate() {
        let draw = straw2_draw(seed, *id, *weight);
        if draw > best_draw {
            best_draw = draw;
            best_idx = idx;
        }
    }
    Ok(best_idx)
}

/// Selects families using straw2 for minimal data movement.
///
/// Each family's "id" for straw2 is a hash of its family_id string,
/// ensuring deterministic draws regardless of HashMap iteration order.
fn select_straw2_families<'a>(
    families: &'a HashMap<&'a str, Vec<(usize, &MinerNode)>>,
    count: usize,
    seed: u64,
) -> Result<Vec<&'a str>, String> {
    // Build sorted candidate list: (family_hash_id, family_id_str, weight)
    let mut candidates: Vec<(u32, &str, u64)> = families
        .iter()
        .map(|(fid, miners)| {
            let total_weight: u64 = miners.iter().map(|(_, m)| m.weight as u64).sum();
            // Hash family_id to a stable u32 for straw2_draw
            let mut h = xxh3::Xxh3::new();
            h.write(fid.as_bytes());
            let fid_hash = h.finish() as u32;
            (fid_hash, *fid, total_weight)
        })
        .collect();

    // Sort by family_id for determinism
    candidates.sort_by(|a, b| a.1.cmp(b.1));

    let mut selected = Vec::with_capacity(count);
    let iterations = count.min(candidates.len());

    for round in 0..iterations {
        if candidates.iter().all(|(_, _, w)| *w == 0) {
            break;
        }

        // Each round uses a different seed
        let round_seed = seed.wrapping_add(round as u64);
        let draw_candidates: Vec<(u32, u64)> =
            candidates.iter().map(|(id, _, w)| (*id, *w)).collect();

        let winner = straw2_select_one(&draw_candidates, round_seed)?;

        let (_, family_id, _) = candidates.remove(winner);
        selected.push(family_id);
    }

    Ok(selected)
}

/// Selects miners from a single family using straw2.
fn select_straw2_miners_from_family(
    miners_in_family: &[(usize, &MinerNode)],
    count: usize,
    seed: u64,
    map: &ClusterMap,
) -> Result<Vec<MinerNode>, String> {
    let mut available: Vec<(usize, u32, u64)> = miners_in_family
        .iter()
        .map(|(idx, m)| (*idx, m.uid, m.weight as u64))
        .collect();

    if available.iter().any(|(idx, _, _)| *idx >= map.miners.len()) {
        return Err("Invalid miner index in family".to_string());
    }

    // Sort by UID for determinism
    available.sort_by_key(|(_, uid, _)| *uid);

    let mut selected = Vec::new();

    for round in 0..count.min(available.len()) {
        if available.iter().all(|(_, _, w)| *w == 0) {
            break;
        }

        let round_seed = seed.wrapping_add(round as u64);
        let draw_candidates: Vec<(u32, u64)> =
            available.iter().map(|(_, uid, w)| (*uid, *w)).collect();

        let winner = straw2_select_one(&draw_candidates, round_seed)?;

        let (miner_idx, _, _) = available.remove(winner);
        selected.push(map.miners[miner_idx].clone());
    }

    Ok(selected)
}

/// UID-only straw2 miner selection (no MinerNode cloning).
fn select_straw2_miner_uids(
    miners_in_family: &[(usize, &MinerNode)],
    count: usize,
    seed: u64,
    map: &ClusterMap,
) -> Result<Vec<u32>, String> {
    let mut available: Vec<(usize, u32, u64)> = miners_in_family
        .iter()
        .map(|(idx, m)| (*idx, m.uid, m.weight as u64))
        .collect();

    if available.iter().any(|(idx, _, _)| *idx >= map.miners.len()) {
        return Err("Invalid miner index in family".to_string());
    }

    available.sort_by_key(|(_, uid, _)| *uid);

    let mut selected = Vec::with_capacity(count);

    for round in 0..count.min(available.len()) {
        if available.iter().all(|(_, _, w)| *w == 0) {
            break;
        }

        let round_seed = seed.wrapping_add(round as u64);
        let draw_candidates: Vec<(u32, u64)> =
            available.iter().map(|(_, uid, w)| (*uid, *w)).collect();

        let winner = straw2_select_one(&draw_candidates, round_seed)?;

        let (miner_idx, _, _) = available.remove(winner);
        selected.push(map.miners[miner_idx].uid);
    }

    Ok(selected)
}

/// CRUSH placement with straw2 selection (placement_version=3).
///
/// Same family-diversity logic as v1/v2, but uses straw2 max-draw selection
/// instead of cumulative-weight selection. This minimizes data movement
/// when miners join or leave the cluster.
pub fn calculate_placement_for_stripe_straw2(
    file_hash: &str,
    stripe_index: u64,
    count: usize,
    map: &ClusterMap,
) -> Result<Vec<MinerNode>, String> {
    if map.miners.len() < count {
        return Err(format!(
            "Insufficient cluster capacity: need {} miners with space, have {}",
            count,
            map.miners.len()
        ));
    }

    let mut hasher = xxh3::Xxh3::new();
    hasher.write(file_hash.as_bytes());
    hasher.write_u64(stripe_index);
    let input = hasher.finish();

    let mut families: HashMap<&str, Vec<(usize, &MinerNode)>> = HashMap::new();
    for (idx, miner) in map.miners.iter().enumerate() {
        families
            .entry(miner.family_id.as_str())
            .or_default()
            .push((idx, miner));
    }
    for miners in families.values_mut() {
        miners.sort_by_key(|(_, m)| m.uid);
    }

    let num_families = families.len();

    if num_families >= count {
        let selected_families = select_straw2_families(&families, count, input)?;
        let mut selected_miners = Vec::new();

        for (idx, family_id) in selected_families.iter().enumerate() {
            let miners_in_family = &families[family_id];
            let family_input = input.wrapping_add(idx as u64);
            let miners = select_straw2_miners_from_family(miners_in_family, 1, family_input, map)?;
            selected_miners.extend(miners);
        }

        if selected_miners.len() != count {
            return Err(format!(
                "Placement failed: needed {} miners but selected {} (zero-weight families?)",
                count,
                selected_miners.len()
            ));
        }
        Ok(selected_miners)
    } else {
        let selected_families = select_straw2_families(&families, num_families, input)?;
        let mut selected_miners = Vec::new();
        let base_per_family = count / num_families;
        let remainder = count % num_families;

        let mut taken_per_family = vec![0usize; num_families];

        for (idx, family_id) in selected_families.iter().enumerate() {
            let miners_in_family = &families[family_id];
            let to_take = if idx < remainder {
                base_per_family + 1
            } else {
                base_per_family
            }
            .min(miners_in_family.len());

            let family_input = input.wrapping_add(idx as u64);
            let miners =
                select_straw2_miners_from_family(miners_in_family, to_take, family_input, map)?;
            taken_per_family[idx] = miners.len();
            selected_miners.extend(miners);
        }

        // Second pass: redistribute unfilled slots to families
        // with remaining capacity.
        if selected_miners.len() < count {
            let mut shortfall = count - selected_miners.len();
            let pass_seed = input.wrapping_add(num_families as u64);

            for (idx, family_id) in selected_families.iter().enumerate() {
                if shortfall == 0 {
                    break;
                }
                let miners_in_family = &families[family_id];
                let remaining = miners_in_family.len() - taken_per_family[idx];
                if remaining == 0 {
                    continue;
                }
                let extra = remaining.min(shortfall);

                let taken_uids: std::collections::HashSet<u32> =
                    selected_miners.iter().map(|m| m.uid).collect();
                let available: Vec<(usize, &MinerNode)> = miners_in_family
                    .iter()
                    .filter(|(i, _)| !taken_uids.contains(&map.miners[*i].uid))
                    .copied()
                    .collect();

                let family_input = pass_seed.wrapping_add(idx as u64);
                let extra_miners =
                    select_straw2_miners_from_family(&available, extra, family_input, map)?;
                taken_per_family[idx] += extra_miners.len();
                shortfall -= extra_miners.len();
                selected_miners.extend(extra_miners);
            }
        }

        selected_miners.truncate(count);

        if selected_miners.len() < count {
            return Err(format!(
                "Placement failed: needed {} miners but only selected {}",
                count,
                selected_miners.len()
            ));
        }
        Ok(selected_miners)
    }
}

/// UID-only straw2 placement (no MinerNode cloning).
fn placement_uids_for_stripe_straw2(
    file_hash: &str,
    stripe_index: u64,
    count: usize,
    map: &ClusterMap,
) -> Result<Vec<u32>, String> {
    if map.miners.len() < count {
        return Err(format!(
            "Insufficient cluster capacity: need {} miners, have {}",
            count,
            map.miners.len()
        ));
    }

    let mut hasher = xxh3::Xxh3::new();
    hasher.write(file_hash.as_bytes());
    hasher.write_u64(stripe_index);
    let input = hasher.finish();

    let mut families: HashMap<&str, Vec<(usize, &MinerNode)>> = HashMap::new();
    for (idx, miner) in map.miners.iter().enumerate() {
        families
            .entry(miner.family_id.as_str())
            .or_default()
            .push((idx, miner));
    }
    for miners in families.values_mut() {
        miners.sort_by_key(|(_, m)| m.uid);
    }

    let num_families = families.len();

    if num_families >= count {
        let selected_families = select_straw2_families(&families, count, input)?;
        let mut uids = Vec::with_capacity(count);
        for (idx, family_id) in selected_families.iter().enumerate() {
            let miners_in_family = &families[family_id];
            let family_input = input.wrapping_add(idx as u64);
            let miner_uids = select_straw2_miner_uids(miners_in_family, 1, family_input, map)?;
            uids.extend(miner_uids);
        }
        if uids.len() != count {
            return Err(format!(
                "Placement failed: needed {} miners but selected {}",
                count,
                uids.len()
            ));
        }
        Ok(uids)
    } else {
        let selected_families = select_straw2_families(&families, num_families, input)?;
        let mut uids = Vec::with_capacity(count);
        let base_per_family = count / num_families;
        let remainder = count % num_families;

        let mut taken_per_family = vec![0usize; num_families];

        for (idx, family_id) in selected_families.iter().enumerate() {
            let miners_in_family = &families[family_id];
            let to_take = if idx < remainder {
                base_per_family + 1
            } else {
                base_per_family
            }
            .min(miners_in_family.len());

            let family_input = input.wrapping_add(idx as u64);
            let miner_uids =
                select_straw2_miner_uids(miners_in_family, to_take, family_input, map)?;
            taken_per_family[idx] = miner_uids.len();
            uids.extend(miner_uids);
        }

        // Second pass: redistribute unfilled slots to families
        // with remaining capacity.
        if uids.len() < count {
            let mut shortfall = count - uids.len();
            let pass_seed = input.wrapping_add(num_families as u64);

            for (idx, family_id) in selected_families.iter().enumerate() {
                if shortfall == 0 {
                    break;
                }
                let miners_in_family = &families[family_id];
                let remaining = miners_in_family.len() - taken_per_family[idx];
                if remaining == 0 {
                    continue;
                }
                let extra = remaining.min(shortfall);

                let taken_uids: std::collections::HashSet<u32> = uids.iter().copied().collect();
                let available: Vec<(usize, &MinerNode)> = miners_in_family
                    .iter()
                    .filter(|(i, _)| !taken_uids.contains(&map.miners[*i].uid))
                    .copied()
                    .collect();

                let family_input = pass_seed.wrapping_add(idx as u64);
                let extra_uids = select_straw2_miner_uids(&available, extra, family_input, map)?;
                taken_per_family[idx] += extra_uids.len();
                shortfall -= extra_uids.len();
                uids.extend(extra_uids);
            }
        }

        uids.truncate(count);
        if uids.len() < count {
            return Err(format!(
                "Placement failed: needed {} miners but only selected {}",
                count,
                uids.len()
            ));
        }
        Ok(uids)
    }
}

// ============================================================================
// Reed-Solomon Erasure Coding
// ============================================================================

use reed_solomon_erasure::galois_8::ReedSolomon;

/// Cached RS(10, 20) instance — the default stripe config.
/// Building `ReedSolomon` constructs GF(2^8) multiplication tables (~65 KB);
/// caching avoids repeating this work on every stripe.
static RS_10_20: std::sync::LazyLock<ReedSolomon> =
    std::sync::LazyLock::new(|| ReedSolomon::new(10, 20).expect("RS(10,20) is valid"));

/// Encodes a data stripe into k data shards + m parity shards.
///
/// Uses Reed-Solomon erasure coding over GF(2^8) (galois_8).
/// The resulting shards can tolerate loss of any m shards while still
/// allowing reconstruction of the original data.
///
/// # Arguments
/// * `data` - Raw data to encode (must be ≤ stripe_config.size bytes)
/// * `config` - Stripe configuration with k, m, and size parameters
///
/// # Returns
/// - `Ok(Vec<Vec<u8>>)` with k+m shards of equal size
/// - `Err(String)` if data is empty, too large, or RS encoding fails
///
/// # Shard Size Calculation
///
/// Shard size = ceil(data_len / k), ensuring all data fits in k shards.
/// Maximum shard size is 256 MiB to prevent memory issues.
pub fn encode_stripe(data: &[u8], config: &StripeConfig) -> Result<Vec<Vec<u8>>, String> {
    if data.is_empty() {
        return Err("Cannot encode empty data stripe".to_string());
    }
    if data.len() > config.size as usize {
        return Err("Data exceeds stripe size".to_string());
    }
    // Validate k > 0 before div_ceil to avoid divide-by-zero panic
    if config.k == 0 {
        return Err("k (data shards) must be at least 1".to_string());
    }

    // Reuse cached RS instance for the default (10, 20) config to avoid
    // rebuilding GF(2^8) multiplication tables on every stripe.
    let owned_rs;
    let rs: &ReedSolomon = if config.k == 10 && config.m == 20 {
        &RS_10_20
    } else {
        owned_rs = ReedSolomon::new(config.k, config.m).map_err(|e| e.to_string())?;
        &owned_rs
    };

    // Dynamic shard size calculation: ceil(data_len / k), minimum 1
    // (div_ceil always returns >= 1 for non-empty data, but .max(1) is defensive)
    const MAX_SHARD_SIZE: usize = 256 * 1024 * 1024; // 256MB max per shard
    let shard_size = data.len().div_ceil(config.k).max(1);

    if shard_size > MAX_SHARD_SIZE {
        return Err(format!(
            "Shard size {} exceeds maximum {}",
            shard_size, MAX_SHARD_SIZE
        ));
    }

    let mut shards: Vec<Vec<u8>> = vec![vec![0; shard_size]; config.k + config.m];

    // Copy data into data shards
    for (i, shard) in shards.iter_mut().take(config.k).enumerate() {
        let offset = i * shard_size;
        let len = shard_size.min(data.len().saturating_sub(offset));
        if len > 0 {
            shard[..len].copy_from_slice(&data[offset..offset + len]);
        }
    }

    rs.encode(&mut shards).map_err(|e| e.to_string())?;

    Ok(shards)
}

/// Calculate the data length for a specific stripe.
///
/// For most stripes this equals `stripe_size`, but for the last stripe it's the remainder.
/// This helper ensures consistent calculation across gateway and validator.
///
/// # Arguments
/// * `file_size` - Total file size in bytes
/// * `stripe_index` - Zero-based stripe index
/// * `stripe_size` - Size of each stripe in bytes
///
/// # Returns
/// The actual data length for the specified stripe, capped at `usize::MAX`
pub fn calculate_stripe_data_len(file_size: u64, stripe_index: u64, stripe_size: u64) -> usize {
    // Guard against zero stripe_size which would make stripe_start calculation meaningless
    if stripe_size == 0 {
        return 0;
    }
    let stripe_start = stripe_index.saturating_mul(stripe_size);
    if stripe_start >= file_size {
        return 0; // Stripe is beyond file end
    }
    let remaining = file_size - stripe_start;
    // Use try_into to safely convert to usize, capping at usize::MAX on 32-bit platforms
    std::cmp::min(remaining, stripe_size)
        .try_into()
        .unwrap_or(usize::MAX)
}

/// Calculate the actual byte size of a single shard in a given stripe.
///
/// After Reed-Solomon encoding, all `k + m` shards in a stripe have identical size:
/// `ceil(stripe_data_len / k)`.  This helper provides a single source of truth for
/// that computation, used by both HTTP and P2P network-stats endpoints.
///
/// Returns 0 when `k == 0` or the stripe is beyond the file end.
pub fn calculate_shard_size(file_size: u64, stripe_index: u64, stripe_size: u64, k: usize) -> u64 {
    if k == 0 {
        return 0;
    }
    let stripe_data_len = calculate_stripe_data_len(file_size, stripe_index, stripe_size);
    if stripe_data_len == 0 {
        return 0;
    }
    stripe_data_len.div_ceil(k) as u64
}

/// Decode a stripe from Reed-Solomon encoded shards.
///
/// # Arguments
/// * `shards` - Mutable slice of optional shard data (Some for available, None for missing)
/// * `config` - Stripe configuration with k (data) and m (parity) shard counts
/// * `stripe_data_len` - The actual data length for THIS stripe (not the total file size).
///   Use `calculate_stripe_data_len()` to compute this value.
///
/// # Returns
/// The reconstructed data for this stripe, or an error if reconstruction fails
pub fn decode_stripe(
    shards: &mut [Option<Vec<u8>>],
    config: &StripeConfig,
    stripe_data_len: usize,
) -> Result<Vec<u8>, String> {
    // Handle zero-length stripe data early - nothing to decode
    if stripe_data_len == 0 {
        return Ok(Vec::new());
    }
    // Validate k > 0 before div_ceil to avoid divide-by-zero panic
    if config.k == 0 {
        return Err("k (data shards) must be at least 1".to_string());
    }
    // Validate shards slice length matches expected k+m
    let expected_shards = config.k + config.m;
    if shards.len() != expected_shards {
        return Err(format!(
            "Shard count mismatch: expected {} (k={} + m={}), got {}",
            expected_shards,
            config.k,
            config.m,
            shards.len()
        ));
    }

    let owned_rs;
    let rs: &ReedSolomon = if config.k == 10 && config.m == 20 {
        &RS_10_20
    } else {
        owned_rs = ReedSolomon::new(config.k, config.m).map_err(|e| e.to_string())?;
        &owned_rs
    };

    rs.reconstruct(shards).map_err(|e| e.to_string())?;

    // Calculate expected shard size once (div_ceil always returns >= 1 for non-zero input)
    let shard_size = stripe_data_len.div_ceil(config.k).max(1);

    // Verify shard size consistency and reconstruct data in a single pass
    let mut data = Vec::with_capacity(stripe_data_len);

    for (idx, shard_opt) in shards.iter().take(config.k).enumerate() {
        let shard = shard_opt.as_ref().ok_or_else(|| {
            format!(
                "Internal error: data shard {} is None after successful RS reconstruction",
                idx
            )
        })?;

        if shard.len() != shard_size {
            return Err(format!(
                "Shard {} has inconsistent size after reconstruction: expected {}, got {}",
                idx,
                shard_size,
                shard.len()
            ));
        }

        let remaining = stripe_data_len.saturating_sub(data.len());
        let len = shard_size.min(shard.len()).min(remaining);
        data.extend_from_slice(&shard[..len]);
    }

    Ok(data)
}

// ============================================================================
// Telemetry and Reporting Types
// ============================================================================

/// Bandwidth report for a single miner (used for reward calculations).
#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct BandwidthReport {
    /// Miner UID as string (for JSON compatibility)
    pub miner_uid: String,
    /// Total bytes served in the reporting period
    pub bytes: u64,
}

/// Aggregated bandwidth statistics from the gateway.
#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct BandwidthStats {
    /// List of per-miner bandwidth reports
    pub reports: Vec<BandwidthReport>,
}

/// Report of a miner failure during shard retrieval.
///
/// Used by the validator to track miner reliability and trigger rebuild.
#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct MinerFailureReport {
    /// UID of the miner that failed
    pub miner_uid: u32,
    /// File hash where failure occurred
    pub file_hash: String,
    /// Shard index that failed
    pub shard_index: usize,
    /// Type of failure: "timeout", "http_error", "integrity_fail", "decode_fail"
    pub failure_type: String,
    /// Unix timestamp when failure was recorded
    pub timestamp: u64,
}

/// Aggregated miner failure statistics.
#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct MinerFailureStats {
    /// List of failure reports
    pub reports: Vec<MinerFailureReport>,
}

// ============================================================================
// Warden Audit Types (Reputation System)
// ============================================================================

/// Result type for warden proof-of-storage audits.
#[derive(Serialize, Deserialize, Clone, Copy, Debug, PartialEq, Eq)]
pub enum AuditResultType {
    /// Proof verified successfully
    Passed,
    /// Proof verification failed
    Failed,
    /// No response within deadline
    Timeout,
    /// Malformed proof data
    InvalidProof,
}

/// A single audit report from the warden.
#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct WardenAuditReport {
    /// Unique audit identifier (hex-encoded challenge_seed)
    pub audit_id: String,
    /// Warden's Ed25519 public key (hex-encoded)
    pub warden_pubkey: String,
    /// UID of the miner that was audited
    pub miner_uid: u32,
    /// BLAKE3 hash of the shard that was audited
    pub shard_hash: String,
    /// Audit result
    pub result: AuditResultType,
    /// Unix timestamp when audit was performed
    pub timestamp: u64,
    /// Ed25519 signature of the audit data (SCALE-encoded)
    pub signature: Vec<u8>,
    /// Block number when challenge was issued (for SCALE signature verification)
    #[serde(default)]
    pub block_number: u64,
    /// BLAKE3 hash of the proof bytes (for SCALE signature verification)
    /// Empty Vec for timeout/invalid cases
    #[serde(default)]
    pub merkle_proof_sig_hash: Vec<u8>,
    /// Hex-encoded warden Ed25519 public key (used in signing, for SCALE verification)
    #[serde(default)]
    pub warden_id: String,
}

/// Batch of audit reports from a warden.
#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct WardenAuditBatch {
    /// List of audit reports in this batch
    pub reports: Vec<WardenAuditReport>,
}

/// A single shard commitment for batched push to warden.
#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct WardenShardCommitment {
    /// BLAKE3 hash of the shard
    pub shard_hash: String,
    /// Merkle root of the shard's chunk tree (8 x u32 = 256 bits)
    pub merkle_root: [u32; 8],
    /// Number of chunks in the shard
    pub chunk_count: u32,
    /// UID of the miner holding this shard
    pub miner_uid: u32,
    /// Miner's Iroh endpoint address (JSON-serialized)
    pub miner_endpoint: String,
}

// ============================================================================
// P2P Protocol Constants (Hybrid Migration)
// ============================================================================

/// ALPN protocol identifier for Validator/Gateway/Warden → Miner P2P communication.
///
/// Used for:
/// - Shard storage (StoreV2), deletion, and existence checks
/// - Blob fetching (FetchBlob) by gateways and peer miners
/// - Peer-to-peer shard migration (PullFromPeer)
/// - Cluster map broadcasts
/// - Proof-of-storage challenges from wardens
pub const MINER_CONTROL_ALPN: &[u8] = b"hippius/miner-control";

/// ALPN protocol identifier for Miner → Gateway inbound connections.
///
/// Used for miner-initiated connections to the gateway. The miner connects
/// and sends its UID; the gateway adds the connection to its pool, preferring
/// inbound connections over outbound ones.
pub const GATEWAY_INBOUND_ALPN: &[u8] = b"hippius/gateway-inbound";

/// ALPN protocol identifier for Miner → Validator P2P communication.
///
/// Used for:
/// - Miner registration and heartbeats
/// - Placement group file queries
/// - Manifest retrieval
/// - Ping/health checks
pub const VALIDATOR_CONTROL_ALPN: &[u8] = b"hippius/validator-control";

/// ALPN protocol identifier for Gateway ↔ Validator P2P communication.
///
/// Used for internal cluster communication including:
/// - Cluster map synchronization
/// - File manifest retrieval
/// - Upload/download coordination
/// - Bandwidth/failure reporting
pub const GATEWAY_CONTROL_ALPN: &[u8] = b"hippius/gateway-control";

/// ALPN protocol identifier for Warden ↔ Validator P2P communication.
///
/// Used for:
/// - Pushing shard commitments from validator to warden
/// - Receiving audit results from warden to validator
pub const WARDEN_CONTROL_ALPN: &[u8] = b"hippius/warden-control";

/// ALPN protocol identifier for Chain-Submitter → Validator P2P communication.
///
/// Used for:
/// - Fetching cluster map for on-chain submission
/// - Fetching network stats for rewards calculation
pub const SUBMITTER_CONTROL_ALPN: &[u8] = b"hippius/submitter-control";

// ============================================================================
// Gateway Control Protocol Messages
// ============================================================================

/// Messages for Gateway ↔ Validator P2P communication.
///
/// Replaces HTTP endpoints for internal cluster communication:
/// - GET /map → `GetClusterMap` / `GetClusterMapEpoch`
/// - GET /manifest/{hash} → `GetManifest`
/// - POST /upload → `UploadFile`
/// - DELETE /blobs/{hash} → `DeleteFile` (passing validator signature)
/// - POST /stats/bandwidth → `ReportBandwidth`
/// - POST /stats/failures → `ReportFailures`
/// - POST /repair_hint → `RepairHint`
#[derive(Serialize, Deserialize, Debug, Clone)]
pub enum GatewayControlMessage {
    // ========================================
    // Requests (Gateway → Validator)
    // ========================================
    /// Request the current cluster map
    GetClusterMap,

    /// Request cluster map at specific epoch (for backwards compatibility during rebalancing)
    GetClusterMapEpoch {
        /// Target epoch to retrieve
        epoch: u64,
    },

    /// Request file manifest by hash
    GetManifest {
        /// BLAKE3 hash of the file
        file_hash: String,
    },

    /// Check if PG rebalancing has settled for an epoch
    GetRebalanceStatus {
        /// Epoch to check
        epoch: u64,
        /// Placement Group ID
        pg_id: u32,
    },

    /// Upload a new file (for smaller files that fit in memory)
    UploadFile {
        /// Original filename
        filename: String,
        /// File size in bytes
        size: u64,
        /// File content
        data: Vec<u8>,
        /// Optional content type
        content_type: Option<String>,
    },

    /// Delete a file from the cluster
    DeleteFile {
        /// BLAKE3 hash of the file to delete
        file_hash: String,
        /// Ed25519 signature from the Validator (or authorized Gateway) over `"DELETE:{hash}"`
        validator_signature: Vec<u8>,
    },

    /// Report bandwidth statistics from gateway
    ReportBandwidth {
        /// Per-miner bandwidth reports
        reports: Vec<BandwidthReport>,
    },

    /// Report miner failures encountered during downloads
    ReportFailures {
        /// Failure reports
        reports: Vec<MinerFailureReport>,
    },

    /// Hint to the validator that a file needs repair
    RepairHint {
        /// File hash needing repair
        file_hash: String,
        /// Starting stripe index (optional windowed repair)
        stripe_idx: Option<u64>,
        /// Number of stripes to repair (optional)
        count: Option<usize>,
    },

    // ========================================
    // Responses (Validator → Gateway)
    // ========================================
    /// Response containing cluster map
    ClusterMapResponse {
        /// The cluster map (None if not found for requested epoch)
        map: Option<ClusterMap>,
        /// Error message if request failed
        error: Option<String>,
    },

    /// Response containing file manifest
    ManifestResponse {
        /// The file manifest (None if file not found)
        manifest: Option<FileManifest>,
        /// Error message if request failed
        error: Option<String>,
    },

    /// Response for rebalance status check
    RebalanceStatusResponse {
        /// True if PG has settled (all shards in correct locations)
        settled: bool,
    },

    /// Response for file upload
    UploadResponse {
        /// File hash if upload succeeded
        file_hash: Option<String>,
        /// Error message if upload failed
        error: Option<String>,
    },

    /// Generic acknowledgment for fire-and-forget operations
    Ack {
        /// True if operation succeeded
        success: bool,
        /// Optional message (error details or confirmation)
        message: Option<String>,
    },
}

// ============================================================================
// Warden Control Protocol Messages
// ============================================================================

/// Messages for Warden ↔ Validator P2P communication.
///
/// Replaces HTTP endpoints:
/// - POST /shards (validator → warden) → `PushShardCommitment`
/// - DELETE /shards/{hash} (validator → warden) → `DeleteShard`
/// - POST /audit-results (warden → validator) → `PushAuditResults`
#[derive(Serialize, Deserialize, Debug, Clone)]
pub enum WardenControlMessage {
    // ========================================
    // Validator → Warden
    // ========================================
    /// Push shard commitment data to warden for future auditing
    PushShardCommitment {
        /// BLAKE3 hash of the shard
        shard_hash: String,
        /// Merkle root of the shard's chunk tree (8 x u32 = 256 bits)
        merkle_root: [u32; 8],
        /// Number of chunks in the shard
        chunk_count: u32,
        /// UID of the miner holding this shard
        miner_uid: u32,
        /// Miner's Iroh endpoint address (JSON-serialized)
        miner_endpoint: String,
    },

    /// Notify warden that a shard has been deleted (file removal or rebalancing)
    DeleteShard {
        /// BLAKE3 hash of the shard to remove from audit queue
        shard_hash: String,
    },

    /// Push a batch of shard commitments in a single message (replaces per-shard streams)
    PushShardCommitmentsBatch {
        /// List of shard commitments to store
        commitments: Vec<WardenShardCommitment>,
    },

    /// Delete multiple shards in a single message (replaces per-shard streams)
    DeleteShardsBatch {
        /// List of shard hashes to remove from audit queue
        shard_hashes: Vec<String>,
    },

    // ========================================
    // Warden → Validator
    // ========================================
    /// Push batch of audit results from warden to validator
    PushAuditResults {
        /// Batch of audit reports
        batch: WardenAuditBatch,
    },

    // ========================================
    // Response (bidirectional)
    // ========================================
    /// Generic acknowledgment
    Ack {
        /// True if operation succeeded
        success: bool,
        /// Optional message (error details or confirmation)
        message: Option<String>,
    },
}

// ============================================================================
// Submitter Control Protocol Messages
// ============================================================================

/// Messages for Chain-Submitter → Validator P2P communication.
///
/// Replaces HTTP endpoints:
/// - GET /map → `GetClusterMap`
/// - GET /stats → `GetNetworkStats`
#[derive(Serialize, Deserialize, Debug, Clone)]
pub enum SubmitterControlMessage {
    // ========================================
    // Requests (Chain-Submitter → Validator)
    // ========================================
    /// Request the current cluster map for on-chain submission
    GetClusterMap,

    /// Request network statistics for rewards calculation
    GetNetworkStats,

    /// Request the validator to sync its epoch to the on-chain value.
    ///
    /// Sent when the chain-submitter detects that the validator's epoch is
    /// behind the on-chain `CurrentEpoch` (e.g. after a PVC recreation).
    /// The validator bumps its epoch to `on_chain_epoch + 1` so that the
    /// next CRUSH map submission can proceed.
    SyncEpoch { on_chain_epoch: u64 },

    // ========================================
    // Responses (Validator → Chain-Submitter)
    // ========================================
    /// Response containing cluster map
    ClusterMapResponse {
        /// The current cluster map (None if error)
        map: Option<ClusterMap>,
        /// Error message if request failed
        error: Option<String>,
    },

    /// Response containing network statistics
    NetworkStatsResponse {
        /// Total number of files stored
        total_files: usize,
        /// Per-miner storage stats: miner_uid -> [shard_count, stored_bytes]
        miner_stats: HashMap<String, [u64; 2]>,
        /// Per-miner bandwidth stats: miner_uid -> bytes_served
        bandwidth_stats: HashMap<String, u64>,
        /// Whether the stats cache has been populated at least once.
        /// `false` when the validator is still warming up and the
        /// response contains default zeros rather than real data.
        #[serde(default)]
        is_ready: bool,
    },

    // ========================================
    // Notifications (Validator → Chain-Submitter)
    // ========================================
    /// Attestation commitment ready for on-chain submission.
    ///
    /// Sent by the validator when an epoch's attestation bundle has been
    /// finalized and uploaded to Arion storage.
    AttestationCommitmentReady {
        /// The commitment to submit on-chain
        commitment: EpochAttestationCommitment,
    },

    /// Acknowledgment for commitment notification
    AttestationCommitmentAck {
        /// True if the commitment was received and queued
        success: bool,
        /// Optional message
        message: Option<String>,
    },

    /// Response to a `SyncEpoch` request.
    SyncEpochResponse {
        /// Whether the epoch sync succeeded
        success: bool,
        /// The validator's epoch after the operation
        new_epoch: u64,
        /// Error description on failure
        error: Option<String>,
    },

    // ========================================
    // Warden → Chain-Submitter
    // ========================================
    /// Push a signed attestation for on-chain submission.
    ///
    /// The attestation is JSON-serialized to avoid coupling both crates
    /// through a shared type in common. The chain-submitter already
    /// deserializes from JSON via its HTTP endpoint — same format.
    PushAttestation {
        /// JSON-serialized SignedAttestation
        attestation_json: String,
    },

    /// Acknowledge attestation receipt.
    PushAttestationAck {
        /// Whether the attestation was accepted and queued
        success: bool,
        /// Optional status message
        message: Option<String>,
    },
}

/// Compute a deterministic miner UID from a public key string.
///
/// Uses `DefaultHasher` with the `Hash` trait, matching the UID
/// computation in deployed miners. Truncated to 31 bits to fit
/// in i32 range.
///
/// STABILITY: `DefaultHasher` is `SipHash-1-3` with keys `(0,0)`,
/// stable since Rust 1.36 (2019). UIDs are persisted in redb,
/// on-chain, attestation signatures, and warden state. DO NOT
/// change this hash function without a coordinated cluster-wide
/// migration. All nodes must use the same Rust toolchain to
/// guarantee identical UIDs.
pub fn compute_miner_uid(public_key: &str) -> u32 {
    use std::hash::{Hash, Hasher};
    let mut hasher = std::collections::hash_map::DefaultHasher::new();
    public_key.hash(&mut hasher);
    (hasher.finish() as u32) & 0x7FFF_FFFF
}

// ============================================================================
// Placement Group (PG) Functions
// ============================================================================

/// Calculate which Placement Group a file belongs to.
///
/// PGs provide an indirection layer for efficient rebalancing:
/// - Files are assigned to PGs (stable mapping)
/// - PGs are assigned to miners via CRUSH
/// - Rebalancing only moves PGs, not individual files
///
/// # Arguments
/// * `file_hash` - BLAKE3 hash of the file
/// * `pg_count` - Total number of placement groups (default: 16384)
///
/// # Returns
/// - `Ok(pg_id)` — PG ID in range [0, pg_count)
/// - `Err` if pg_count is 0
pub fn calculate_pg(file_hash: &str, pg_count: u32) -> Result<u32, String> {
    if pg_count == 0 {
        return Err("calculate_pg: pg_count must be > 0".to_string());
    }
    let mut hasher = xxh3::Xxh3::new();
    hasher.write(file_hash.as_bytes());
    // Perform modulo before truncation to preserve full 64-bit entropy
    Ok((hasher.finish() % (pg_count as u64)) as u32)
}

/// Calculate which miners are responsible for a Placement Group.
///
/// Uses CRUSH algorithm with family diversity to select miners.
/// All files in the same PG are stored on the same set of miners.
///
/// # Arguments
/// * `pg_id` - Placement Group ID
/// * `shards_per_file` - Number of miners needed (typically k + m = 30)
/// * `map` - Current cluster map
///
/// # Returns
/// - `Ok(Vec<MinerNode>)` with miners responsible for this PG
/// - `Err(String)` if insufficient miners
pub fn calculate_pg_placement(
    pg_id: u32,
    shards_per_file: usize,
    map: &ClusterMap,
) -> Result<Vec<MinerNode>, String> {
    // Use PG ID as the placement seed (like using file_hash + stripe_index)
    // This gives each PG a consistent, deterministic set of miners
    let pg_seed = format!("pg:{}", pg_id);
    calculate_placement_for_stripe(&pg_seed, 0, shards_per_file, map)
}

/// PG-based stripe placement (placement_version=2).
///
/// Algorithm:
/// 1. Map file_hash → PG_ID via xxhash
/// 2. Calculate PG's miner set via CRUSH
/// 3. Rotate miner list by stripe_index for per-stripe spreading
///
/// The rotation ensures that shards from different stripes of the same file
/// are distributed across different starting points in the miner set, improving
/// parallel fetch performance.
///
/// # Arguments
/// * `file_hash` - BLAKE3 hash of the file
/// * `stripe_index` - Zero-based stripe index
/// * `shards_per_stripe` - Number of shards per stripe (k + m)
/// * `map` - Current cluster map
///
/// # Returns
/// - `Ok(Vec<MinerNode>)` with miners for this stripe (rotated by stripe_index)
/// - `Err(String)` if insufficient miners
pub fn calculate_pg_placement_for_stripe(
    file_hash: &str,
    stripe_index: u64,
    shards_per_stripe: usize,
    map: &ClusterMap,
) -> Result<Vec<MinerNode>, String> {
    let pg_id = calculate_pg(file_hash, map.pg_count)?;
    let mut miners = calculate_pg_placement(pg_id, shards_per_stripe, map)?;

    if miners.is_empty() {
        return Err("No miners available for stripe placement".to_string());
    }

    // Rotate miner list by stripe_index for per-stripe spreading
    let len = miners.len();
    miners.rotate_left((stripe_index as usize) % len);
    Ok(miners)
}

/// PG placement using straw2 selection (placement_version=3).
pub fn calculate_pg_placement_straw2(
    pg_id: u32,
    shards_per_file: usize,
    map: &ClusterMap,
) -> Result<Vec<MinerNode>, String> {
    let pg_seed = format!("pg:{}", pg_id);
    calculate_placement_for_stripe_straw2(&pg_seed, 0, shards_per_file, map)
}

/// PG-based stripe placement with straw2 selection (placement_version=3).
///
/// Same PG mapping and stripe rotation as v2, but uses straw2 selection
/// for minimal data movement on topology changes.
pub fn calculate_pg_placement_for_stripe_straw2(
    file_hash: &str,
    stripe_index: u64,
    shards_per_stripe: usize,
    map: &ClusterMap,
) -> Result<Vec<MinerNode>, String> {
    let pg_id = calculate_pg(file_hash, map.pg_count)?;
    let mut miners = calculate_pg_placement_straw2(pg_id, shards_per_stripe, map)?;

    if miners.is_empty() {
        return Err("No miners available for stripe placement".to_string());
    }

    let len = miners.len();
    miners.rotate_left((stripe_index as usize) % len);
    Ok(miners)
}

/// Calculate stripe placement using the specified placement version.
///
/// This is the main entry point for placement calculations, dispatching to
/// the appropriate algorithm based on the manifest's placement_version.
///
/// # Arguments
/// * `file_hash` - BLAKE3 hash of the file
/// * `stripe_index` - Zero-based stripe index
/// * `shards_per_stripe` - Number of shards per stripe (k + m)
/// * `map` - Current cluster map
/// * `placement_version` - Algorithm version (1=legacy, 2=PG-based, 3=PG+straw2)
///
/// # Returns
/// - `Ok(Vec<MinerNode>)` with miners for this stripe
/// - `Err(String)` if placement fails
pub fn calculate_stripe_placement(
    file_hash: &str,
    stripe_index: u64,
    shards_per_stripe: usize,
    map: &ClusterMap,
    placement_version: u8,
) -> Result<Vec<MinerNode>, String> {
    match placement_version {
        3 => calculate_pg_placement_for_stripe_straw2(
            file_hash,
            stripe_index,
            shards_per_stripe,
            map,
        ),
        2 => calculate_pg_placement_for_stripe(file_hash, stripe_index, shards_per_stripe, map),
        _ => calculate_placement_for_stripe(file_hash, stripe_index, shards_per_stripe, map),
    }
}

/// Reliability-aware variant of `calculate_stripe_placement`.
///
/// Multiplies each miner's CRUSH weight by its P2P reliability score,
/// and skips miners whose score is below 0.2. Reliability scores are
/// passed externally to preserve CRUSH determinism (ClusterMap is shared
/// and snapshotted — embedding mutable scores would break consistency).
///
/// Gateway continues to use `calculate_stripe_placement` (no scores).
/// Validator recovery uses this variant for smarter shard placement.
pub fn calculate_stripe_placement_with_reliability(
    file_hash: &str,
    stripe_index: u64,
    shards_per_stripe: usize,
    map: &ClusterMap,
    placement_version: u8,
    reliability_scores: &std::collections::HashMap<u32, f64>,
) -> Result<Vec<MinerNode>, String> {
    // Build a filtered ClusterMap with adjusted weights
    let mut adjusted_map = map.clone();
    adjusted_map.miners.retain(|m| {
        let score = reliability_scores.get(&m.uid).copied().unwrap_or(1.0);
        score >= 0.2
    });
    for miner in &mut adjusted_map.miners {
        let score = reliability_scores
            .get(&miner.uid)
            .copied()
            .unwrap_or(1.0)
            .clamp(0.0, 1.0);
        miner.weight = std::cmp::max(1, (miner.weight as f64 * score) as u32);
    }

    // Fall back to original map if too few miners remain after filtering
    if adjusted_map.miners.len() < shards_per_stripe {
        return calculate_stripe_placement(
            file_hash,
            stripe_index,
            shards_per_stripe,
            map,
            placement_version,
        );
    }

    calculate_stripe_placement(
        file_hash,
        stripe_index,
        shards_per_stripe,
        &adjusted_map,
        placement_version,
    )
}

// ============================================================================
// Lightweight UID-only placement (avoids MinerNode cloning)
// ============================================================================

/// Like `calculate_placement_for_stripe` but returns only miner UIDs.
///
/// Avoids cloning MinerNode structs (6+ heap Strings each), reducing
/// allocation pressure from ~28 KB/call to ~240 bytes/call. Use this
/// for read-only statistics where only UIDs are needed.
fn placement_uids_for_stripe(
    file_hash: &str,
    stripe_index: u64,
    count: usize,
    map: &ClusterMap,
) -> Result<Vec<u32>, String> {
    if map.miners.len() < count {
        return Err(format!(
            "Insufficient cluster capacity: need {} miners, have {}",
            count,
            map.miners.len()
        ));
    }

    let mut hasher = xxh3::Xxh3::new();
    hasher.write(file_hash.as_bytes());
    hasher.write_u64(stripe_index);
    let input = hasher.finish();

    let mut families: HashMap<&str, Vec<(usize, &MinerNode)>> = HashMap::new();
    for (idx, miner) in map.miners.iter().enumerate() {
        families
            .entry(miner.family_id.as_str())
            .or_default()
            .push((idx, miner));
    }
    for miners in families.values_mut() {
        miners.sort_by_key(|(_, m)| m.uid);
    }

    let num_families = families.len();

    if num_families >= count {
        let selected_families = select_weighted_families(&families, count, input)?;
        let mut uids = Vec::with_capacity(count);
        for (idx, family_id) in selected_families.iter().enumerate() {
            let miners_in_family = &families[family_id];
            let family_input = input.wrapping_add(idx as u64);
            let miner_uids = select_weighted_miner_uids(miners_in_family, 1, family_input, map)?;
            uids.extend(miner_uids);
        }
        if uids.len() != count {
            return Err(format!(
                "Placement failed: needed {} miners but selected {}",
                count,
                uids.len()
            ));
        }
        Ok(uids)
    } else {
        let selected_families = select_weighted_families(&families, num_families, input)?;
        let mut uids = Vec::with_capacity(count);
        let base_per_family = count / num_families;
        let remainder = count % num_families;

        // Track how many miners were taken from each family
        let mut taken_per_family = vec![0usize; num_families];

        for (idx, family_id) in selected_families.iter().enumerate() {
            let miners_in_family = &families[family_id];
            let to_take = if idx < remainder {
                base_per_family + 1
            } else {
                base_per_family
            }
            .min(miners_in_family.len());

            let family_input = input.wrapping_add(idx as u64);
            let miner_uids =
                select_weighted_miner_uids(miners_in_family, to_take, family_input, map)?;
            taken_per_family[idx] = miner_uids.len();
            uids.extend(miner_uids);
        }

        // Second pass: redistribute unfilled slots to families
        // with remaining capacity.
        if uids.len() < count {
            let mut shortfall = count - uids.len();
            // Use a different seed offset to avoid repeating
            // the same selection pattern.
            let pass_seed = input.wrapping_add(num_families as u64);

            for (idx, family_id) in selected_families.iter().enumerate() {
                if shortfall == 0 {
                    break;
                }
                let miners_in_family = &families[family_id];
                let remaining = miners_in_family.len() - taken_per_family[idx];
                if remaining == 0 {
                    continue;
                }
                let extra = remaining.min(shortfall);

                // Build available list excluding already-taken miners
                let taken_uids: std::collections::HashSet<u32> = uids.iter().copied().collect();
                let available: Vec<(usize, &MinerNode)> = miners_in_family
                    .iter()
                    .filter(|(i, _)| !taken_uids.contains(&map.miners[*i].uid))
                    .copied()
                    .collect();

                let family_input = pass_seed.wrapping_add(idx as u64);
                let extra_uids = select_weighted_miner_uids(&available, extra, family_input, map)?;
                taken_per_family[idx] += extra_uids.len();
                shortfall -= extra_uids.len();
                uids.extend(extra_uids);
            }
        }

        uids.truncate(count);
        if uids.len() < count {
            return Err(format!(
                "Placement failed: needed {} miners but only selected {}",
                count,
                uids.len()
            ));
        }
        Ok(uids)
    }
}

/// Like `select_weighted_miners_from_family` but returns only UIDs (no clone).
fn select_weighted_miner_uids(
    miners_in_family: &[(usize, &MinerNode)],
    count: usize,
    seed: u64,
    map: &ClusterMap,
) -> Result<Vec<u32>, String> {
    let mut available: Vec<(usize, u64)> = miners_in_family
        .iter()
        .map(|(idx, m)| (*idx, m.weight as u64))
        .collect();

    if available.iter().any(|(idx, _)| *idx >= map.miners.len()) {
        return Err("Invalid miner index in family".to_string());
    }

    available.sort_by_key(|(idx, _)| map.miners[*idx].uid);

    let mut selected = Vec::with_capacity(count);
    let mut rng_seed = seed;

    for _ in 0..count.min(available.len()) {
        if available.iter().all(|(_, w)| *w == 0) {
            break;
        }
        let selected_idx = weighted_select(&available, &mut rng_seed, "Weighted miner selection")?;
        let (miner_idx, _) = available.remove(selected_idx);
        selected.push(map.miners[miner_idx].uid);
    }

    Ok(selected)
}

/// PG-based placement returning only UIDs (no MinerNode cloning).
///
/// Used by `compute_shard_stats` and other read-only statistics paths.
///
/// # Performance
///
/// This function performs CRUSH calculations and is CPU-bound when called
/// in a loop over all PGs (`pg_count`, typically 16,384). Callers in async
/// contexts **must** wrap bulk invocations in `tokio::task::spawn_blocking`
/// to avoid starving the tokio runtime.
pub fn calculate_pg_placement_uids(
    pg_id: u32,
    shards_per_file: usize,
    map: &ClusterMap,
) -> Result<Vec<u32>, String> {
    let pg_seed = format!("pg:{}", pg_id);
    placement_uids_for_stripe(&pg_seed, 0, shards_per_file, map)
}

/// PG-based UID-only placement using straw2 selection (placement_version=3).
pub fn calculate_pg_placement_uids_straw2(
    pg_id: u32,
    shards_per_file: usize,
    map: &ClusterMap,
) -> Result<Vec<u32>, String> {
    let pg_seed = format!("pg:{}", pg_id);
    placement_uids_for_stripe_straw2(&pg_seed, 0, shards_per_file, map)
}

/// Calculate which Placement Groups a miner is responsible for.
///
/// Used by miners during self-rebalancing to discover their workload.
/// This is an expensive operation (O(pg_count * placement_cost)) - cache results.
///
/// # Performance
///
/// This function is CPU-bound (iterates all `pg_count` PGs with CRUSH
/// calculations, typically 16,384). Callers in async contexts **must**
/// wrap this in `tokio::task::spawn_blocking` to avoid starving the
/// tokio runtime.
///
/// # Arguments
/// * `miner_uid` - UID of the miner to check
/// * `map` - Current cluster map
///
/// # Returns
/// List of PG IDs where this miner appears in the CRUSH placement
pub fn calculate_my_pgs(miner_uid: u32, map: &ClusterMap) -> Vec<u32> {
    let shards_per_file = map.ec_k + map.ec_m;

    (0..map.pg_count)
        .filter(|&pg_id| {
            let v2_match = calculate_pg_placement(pg_id, shards_per_file, map)
                .map(|miners| miners.iter().any(|m| m.uid == miner_uid))
                .unwrap_or(false);
            let v3_match = calculate_pg_placement_straw2(pg_id, shards_per_file, map)
                .map(|miners| miners.iter().any(|m| m.uid == miner_uid))
                .unwrap_or(false);
            v2_match || v3_match
        })
        .collect()
}

// ============================================================================
// Shared Utility Functions
// ============================================================================

/// Safe timestamp helper - returns current Unix timestamp in seconds.
/// Returns 0 on clock skew or system time errors (safe for timestamp comparisons).
///
/// Use this instead of `SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs()`
/// to avoid panics on systems with clock issues.
#[inline]
pub fn now_secs() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

// ============================================================================
// IP Routability Helpers
// ============================================================================

/// Returns true if the IP address is publicly routable.
///
/// Rejects loopback, link-local, private (RFC 1918), CGNAT (RFC 6598),
/// multicast, reserved, and Docker/K8s internal addresses.
pub fn is_routable_ip(ip: std::net::IpAddr) -> bool {
    match ip {
        std::net::IpAddr::V4(v4) => {
            !v4.is_loopback()
                && !v4.is_link_local()
                && !v4.is_broadcast()
                && !v4.is_unspecified()
                && !v4.is_multicast()
                && !is_non_routable_v4(v4)
        }
        std::net::IpAddr::V6(v6) => {
            !v6.is_loopback()
                && !v6.is_unspecified()
                && !v6.is_multicast()
                && !is_non_routable_v6(v6)
        }
    }
}

/// Non-routable IPv4 ranges:
/// - 10.0.0.0/8       RFC 1918 (K8s pod CIDRs)
/// - 172.16.0.0/12    RFC 1918 (Docker bridge 172.17.x.x)
/// - 192.168.0.0/16   RFC 1918 (home LANs)
/// - 100.64.0.0/10    RFC 6598 CGNAT (also Nebula VPN)
/// - 240.0.0.0/4      Reserved/experimental
fn is_non_routable_v4(ip: std::net::Ipv4Addr) -> bool {
    let o = ip.octets();
    o[0] == 10
        || (o[0] == 172 && (o[1] & 0xf0) == 16)
        || (o[0] == 192 && o[1] == 168)
        || (o[0] == 100 && (o[1] & 0xc0) == 64)
        || (o[0] & 0xf0) == 240
}

/// Non-routable IPv6 ranges:
/// - fc00::/7   Unique Local Addresses (ULA)
/// - fe80::/10  Link-local
fn is_non_routable_v6(ip: std::net::Ipv6Addr) -> bool {
    let s = ip.segments();
    (s[0] & 0xfe00) == 0xfc00 || (s[0] & 0xffc0) == 0xfe80
}

/// Returns true if the IP address is suitable for self-advertisement.
///
/// Rejects loopback, unspecified, link-local, broadcast, and multicast.
/// Allows private (RFC 1918), CGNAT (RFC 6598), and ULA IPv6 — Iroh
/// handles path selection and hole-punching for these ranges.
pub fn is_advertisable_ip(ip: std::net::IpAddr) -> bool {
    match ip {
        std::net::IpAddr::V4(v4) => {
            !v4.is_loopback()
                && !v4.is_link_local()
                && !v4.is_broadcast()
                && !v4.is_unspecified()
                && !v4.is_multicast()
                && !is_reserved_v4(v4)
        }
        std::net::IpAddr::V6(v6) => {
            !v6.is_loopback() && !v6.is_unspecified() && !v6.is_multicast() && !is_link_local_v6(v6)
        }
    }
}

/// Link-local IPv6: fe80::/10
fn is_link_local_v6(ip: std::net::Ipv6Addr) -> bool {
    (ip.segments()[0] & 0xffc0) == 0xfe80
}

/// Reserved/experimental IPv4: 240.0.0.0/4
fn is_reserved_v4(ip: std::net::Ipv4Addr) -> bool {
    (ip.octets()[0] & 0xf0) == 240
}

/// Returns true if the endpoint has at least one direct IP address
/// (not relay-only). Iroh handles path selection for all IP ranges.
pub fn has_direct_addr(addr: &iroh::EndpointAddr) -> bool {
    addr.addrs
        .iter()
        .any(|a| matches!(a, iroh::TransportAddr::Ip(_)))
}

/// Returns true if a path is a direct IP path (not relay).
fn is_direct_path(p: &iroh::endpoint::PathInfo) -> bool {
    matches!(p.remote_addr(), iroh::TransportAddr::Ip(_))
}

/// Returns true if the connection has a direct IP path (not relay-only).
///
/// Checks `Connection::paths()` for actual live transport paths, not just
/// the address book (discovery metadata). Any `TransportAddr::Ip` path
/// counts — Iroh handles path selection for all IP ranges including
/// private and CGNAT.
pub fn has_direct_ip_path(conn: &iroh::endpoint::Connection) -> bool {
    use iroh::Watcher as _;
    conn.paths().get().iter().any(is_direct_path)
}

/// Wait for a connection to establish a direct IP path within `timeout`.
///
/// Uses `Watcher::updated()` to wake on path changes (no polling).
/// Returns `true` if a direct IP path is found within the timeout,
/// `false` otherwise.
pub async fn wait_for_direct_ip_path(
    conn: &iroh::endpoint::Connection,
    timeout: std::time::Duration,
) -> bool {
    if has_direct_ip_path(conn) {
        return true;
    }

    let mut watcher = conn.paths();
    tokio::time::timeout(timeout, async {
        loop {
            use iroh::Watcher;
            if watcher.updated().await.is_err() {
                return false;
            }
            if watcher.get().iter().any(is_direct_path) {
                return true;
            }
        }
    })
    .await
    .unwrap_or(false)
}

/// Connect to a peer and ensure a direct IP path.
///
/// Returns `Err` if the connection is relay-only after the
/// `direct_path_timeout` expires. Callers already set
/// `max_tls_tickets(0)` to disable 0-RTT, so a single connect
/// attempt is sufficient.
pub async fn connect_with_direct_path(
    endpoint: &iroh::Endpoint,
    addr: iroh::EndpointAddr,
    alpn: &[u8],
    connect_timeout: std::time::Duration,
    direct_path_timeout: std::time::Duration,
) -> anyhow::Result<iroh::endpoint::Connection> {
    let conn = tokio::time::timeout(connect_timeout, endpoint.connect(addr, alpn))
        .await
        .map_err(|_| anyhow::anyhow!("connect timeout"))?
        .map_err(|e| anyhow::anyhow!("connect error: {e}"))?;

    if wait_for_direct_ip_path(&conn, direct_path_timeout).await {
        return Ok(conn);
    }

    conn.close(0u32.into(), b"no_direct_path");
    Err(anyhow::anyhow!("no direct IP path after timeout"))
}

/// Extract miner IP from EndpointAddr direct addresses
/// or fall back to parsing the http_addr URL hostname.
pub fn extract_miner_ip(
    endpoint_addr: Option<&iroh::EndpointAddr>,
    http_addr: &str,
) -> Option<String> {
    // Try EndpointAddr direct addresses first
    if let Some(addr) = endpoint_addr {
        for transport_addr in &addr.addrs {
            if let iroh::TransportAddr::Ip(sock) = transport_addr {
                let ip = sock.ip();
                if !ip.is_loopback() {
                    return Some(ip.to_string());
                }
            }
        }
    }
    // Fall back to parsing http_addr URL
    // Expected format: "http://203.0.113.5:3001" or "http://[::1]:3001"
    let host = http_addr
        .strip_prefix("https://")
        .or_else(|| http_addr.strip_prefix("http://"))
        .unwrap_or(http_addr);
    // Strip path suffix if any
    let host = host.split('/').next().unwrap_or(host);
    // Strip port: handle IPv6 bracket notation [::1]:3001
    let host = if host.starts_with('[') {
        // IPv6 bracket notation: [addr]:port or [addr]
        host.trim_start_matches('[')
            .split(']')
            .next()
            .unwrap_or(host)
    } else {
        // IPv4 or hostname: addr:port or addr
        host.rsplit_once(':').map_or(host, |(h, _)| h)
    };
    if let Ok(ip) = host.parse::<std::net::IpAddr>()
        && !ip.is_loopback()
    {
        return Some(ip.to_string());
    }
    None
}

/// Default EMA alpha for latency smoothing (20% new, 80% old).
/// This provides good smoothing while still being responsive to changes.
pub const LATENCY_EMA_ALPHA: f64 = 0.2;

/// Expected heartbeat interval in seconds (shared between validator and chain-submitter).
pub const HEARTBEAT_INTERVAL_SECS: u64 = 30;

/// Calculate uptime score based on heartbeat count and time since registration.
/// Returns a value in [0.0, 1.0]. New miners (< 60s) get 1.0.
pub fn calculate_uptime_score(
    heartbeat_count: u32,
    registration_time: u64,
    current_time: u64,
) -> f32 {
    let elapsed = current_time.saturating_sub(registration_time);
    let expected_heartbeats = elapsed / HEARTBEAT_INTERVAL_SECS;

    // New miners or very short elapsed time get benefit of doubt
    let is_newly_registered = elapsed < 60;
    let insufficient_data = expected_heartbeats == 0;
    if is_newly_registered || insufficient_data {
        return 1.0;
    }

    (heartbeat_count as f32 / expected_heartbeats as f32).clamp(0.0, 1.0)
}

// ============================================================================
// Epoch-Based Audit Sampling
// ============================================================================

/// Default audit epoch duration in seconds (1 hour).
/// Shards are sampled per epoch and cleared when the epoch advances.
pub const DEFAULT_AUDIT_EPOCH_SECS: u64 = 3600;

/// Default number of shards to sample per miner per epoch.
/// With 100 shards per miner and max_shards=1,000,000, a 100-miner cluster
/// gets ~1% audit coverage per hour. Higher value = better per-miner coverage.
pub const DEFAULT_SHARDS_PER_MINER_PER_EPOCH: usize = 100;

/// Calculate the current epoch number from a timestamp.
///
/// # Arguments
/// * `now_secs` - Current Unix timestamp in seconds
/// * `epoch_duration_secs` - Duration of each epoch in seconds
///
/// # Returns
/// The epoch number (timestamp / duration), or 0 if duration is 0.
///
/// # Example
/// ```
/// use common::current_epoch;
/// let epoch = current_epoch(7200, 3600); // 2 hours / 1 hour = epoch 2
/// assert_eq!(epoch, 2);
/// ```
#[inline]
pub fn current_epoch(now_secs: u64, epoch_duration_secs: u64) -> u64 {
    if epoch_duration_secs == 0 {
        return 0;
    }
    now_secs / epoch_duration_secs
}

/// Generate a deterministic sampling seed for an epoch.
///
/// The seed is derived from the epoch number and validator node ID using BLAKE3.
/// This ensures consistent sampling across restarts and multiple validators
/// (if they use the same node ID).
///
/// # Arguments
/// * `epoch` - The epoch number
/// * `validator_node_id` - Validator's node ID string (hex-encoded public key)
///
/// # Returns
/// A 32-byte deterministic seed for random sampling.
///
/// # Example
/// ```
/// use common::epoch_sampling_seed;
/// let seed = epoch_sampling_seed(42, "abc123def456");
/// assert_eq!(seed.len(), 32);
/// // Same inputs always produce same output
/// assert_eq!(seed, epoch_sampling_seed(42, "abc123def456"));
/// ```
pub fn epoch_sampling_seed(epoch: u64, validator_node_id: &str) -> [u8; 32] {
    let mut hasher = blake3::Hasher::new();
    hasher.update(b"ARION_EPOCH_SAMPLING_V1");
    hasher.update(&epoch.to_le_bytes());
    hasher.update(validator_node_id.as_bytes());
    *hasher.finalize().as_bytes()
}

/// Select N random indices from a range using a deterministic seed.
///
/// This function implements reservoir sampling with a deterministic PRNG
/// seeded by the provided 32-byte seed. The result is always the same
/// for the same inputs.
///
/// # Arguments
/// * `seed` - 32-byte deterministic seed (from `epoch_sampling_seed`)
/// * `total` - Total number of items to sample from (exclusive upper bound)
/// * `sample_size` - Number of indices to select
///
/// # Returns
/// A vector of unique indices in range [0, total), sorted in ascending order.
/// If `sample_size >= total`, returns all indices [0, total).
///
/// # Example
/// ```
/// use common::sample_indices;
/// let seed = [42u8; 32];
/// let indices = sample_indices(&seed, 1000, 10);
/// assert_eq!(indices.len(), 10);
/// // All indices are unique and in range
/// for &idx in &indices {
///     assert!(idx < 1000);
/// }
/// // Same seed produces same result
/// assert_eq!(indices, sample_indices(&seed, 1000, 10));
/// ```
pub fn sample_indices(seed: &[u8; 32], total: usize, sample_size: usize) -> Vec<usize> {
    if total == 0 {
        return Vec::new();
    }
    if sample_size >= total {
        return (0..total).collect();
    }

    // Knuth's LCG multiplier from MMIX
    const LCG_MULTIPLIER: u64 = 6364136223846793005;

    // Use a simple LCG PRNG seeded from the BLAKE3 hash
    // Seed the RNG with the first 8 bytes of the seed
    let mut rng_state = u64::from_le_bytes(seed[0..8].try_into().unwrap());

    // Fisher-Yates partial shuffle using reservoir sampling approach
    let mut result = Vec::with_capacity(sample_size);
    let mut selected = std::collections::HashSet::with_capacity(sample_size);

    while result.len() < sample_size {
        // Advance PRNG
        rng_state = rng_state.wrapping_mul(LCG_MULTIPLIER).wrapping_add(1);

        // Generate index in range [0, total)
        let idx = (rng_state % total as u64) as usize;

        // Only add if not already selected
        if selected.insert(idx) {
            result.push(idx);
        }
    }

    // Sort for consistent ordering (helps with debugging and determinism verification)
    result.sort_unstable();
    result
}

// ============================================================================
// PoS Commitment Selection
// ============================================================================

/// Minimum number of shards to generate PoS commitments for per file.
pub const MIN_COMMITMENTS_PER_FILE: usize = 3;

/// Target number of commitments for a 1 GB file (3840 shards at 8 MiB stripes).
pub const COMMITMENT_TARGET_PER_GB_SHARDS: usize = 100;

/// Number of shards in a 1 GB file (128 stripes * 30 shards/stripe).
pub const SHARDS_PER_GB: usize = 3840;

/// Calculate how many shards should have PoS commitments generated for a file.
///
/// Uses a linear scaling formula: `min(total_shards, max(3, ceil(total * 100 / 3840)))`.
/// This gives ~3 for tiny files, ~100 for 1 GB, and scales proportionally beyond.
pub fn calculate_commitment_count(total_shards: usize) -> usize {
    if total_shards == 0 {
        return 0;
    }
    let scaled = total_shards
        .saturating_mul(COMMITMENT_TARGET_PER_GB_SHARDS)
        .div_ceil(SHARDS_PER_GB);
    total_shards.min(scaled.max(MIN_COMMITMENTS_PER_FILE))
}

/// Produce a deterministic 32-byte seed for commitment shard selection.
///
/// Uses BLAKE3 with a distinct domain separator so the same file always
/// selects the same shards, independent of epoch or validator identity.
pub fn commitment_selection_seed(file_hash: &str) -> [u8; 32] {
    let mut hasher = blake3::Hasher::new();
    hasher.update(b"ARION_COMMITMENT_SELECTION_V1");
    hasher.update(file_hash.as_bytes());
    *hasher.finalize().as_bytes()
}

/// Select which shard indices should have PoS commitments generated.
///
/// Returns a `HashSet` for O(1) lookup in the hot path. The selection is
/// deterministic: the same file hash and total shard count always produce
/// the same set of indices.
pub fn select_commitment_indices(
    file_hash: &str,
    total_shards: usize,
) -> std::collections::HashSet<usize> {
    let count = calculate_commitment_count(total_shards);
    if count == 0 {
        return std::collections::HashSet::new();
    }
    let seed = commitment_selection_seed(file_hash);
    sample_indices(&seed, total_shards, count)
        .into_iter()
        .collect()
}

// ============================================================================
// P2P Message Size Constants
// ============================================================================

/// Maximum size for standard P2P control messages (1 MiB).
/// Used for protocol messages like cluster map requests, manifest lookups, etc.
pub const P2P_MAX_MESSAGE_SIZE: usize = 1024 * 1024;

/// Maximum size for P2P responses (10 MiB).
/// Larger to accommodate cluster maps with many miners and file manifests.
pub const P2P_MAX_RESPONSE_SIZE: usize = 10 * 1024 * 1024;

/// Maximum size for P2P file uploads (100 MiB).
/// Files larger than this should use streaming HTTP endpoint.
pub const P2P_MAX_UPLOAD_SIZE: usize = 100 * 1024 * 1024;

/// Default timeout for P2P operations in seconds.
pub const P2P_DEFAULT_TIMEOUT_SECS: u64 = 30;

/// Default connection TTL for P2P connection pooling in seconds.
pub const P2P_CONNECTION_TTL_SECS: u64 = 120;

/// Timeout for the write+flush phase of `p2p_send_response` in seconds.
/// 30s matches the QUIC idle timeout default and is generous enough for large
/// responses (~10 MB at modest bandwidth) while preventing indefinite stalls
/// when the remote stops reading mid-response (QUIC flow control).
pub const P2P_RESPONSE_WRITE_TIMEOUT_SECS: u64 = 30;

/// Timeout for waiting on stream finish acknowledgment in seconds.
/// Short timeout to allow graceful stream termination without blocking.
pub const P2P_RESPONSE_FINISH_TIMEOUT_SECS: u64 = 1;

/// Helper to send a P2P response and finish the stream gracefully.
///
/// This function writes the response data, flushes the stream, and waits briefly
/// for the remote peer to receive the data before closing the stream.
///
/// # Arguments
/// * `send` - The Iroh send stream to write to
/// * `data` - The response data bytes to send
///
/// # Returns
/// `Ok(())` on success, or an error if writing/flushing fails.
pub async fn p2p_send_response(
    send: &mut iroh::endpoint::SendStream,
    data: &[u8],
) -> anyhow::Result<()> {
    use tokio::io::AsyncWriteExt;
    tokio::time::timeout(
        std::time::Duration::from_secs(P2P_RESPONSE_WRITE_TIMEOUT_SECS),
        async {
            send.write_all(data).await?;
            send.flush().await?;
            Ok::<(), std::io::Error>(())
        },
    )
    .await
    .map_err(|_| {
        anyhow::anyhow!(
            "P2P response write timed out after \
             {P2P_RESPONSE_WRITE_TIMEOUT_SECS}s"
        )
    })??;
    send.finish()?;
    // Wait briefly for remote to receive before closing
    let _ = tokio::time::timeout(
        std::time::Duration::from_secs(P2P_RESPONSE_FINISH_TIMEOUT_SECS),
        send.stopped(),
    )
    .await;
    Ok(())
}

// Dead V2 helpers (encode_store_v2, decode_miner_control_message) were removed:
// they used big-endian framing and the legacy `Store` variant, which is incompatible
// with the production V2 protocol (little-endian, `StoreV2` variant).
// The canonical encoder is `validator::serialize_store_message` and the decoder
// lives in `miner::p2p::handle_single_stream`.

/// Validates that a string is a valid 64-character hex file hash.
///
/// # Returns
/// - `Ok(())` if the hash is valid
/// - `Err(String)` with a descriptive error message if invalid
///
/// # Example
/// ```
/// use common::validate_file_hash;
/// assert!(validate_file_hash("abc123").is_err()); // too short
/// assert!(validate_file_hash("0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef").is_ok());
/// ```
pub fn validate_file_hash(hash: &str) -> Result<(), String> {
    match hash.len() {
        64 if hash.chars().all(|c| c.is_ascii_hexdigit()) => Ok(()),
        64 => {
            Err("Invalid file hash: must contain only hex characters (0-9, a-f, A-F)".to_string())
        }
        len => Err(format!(
            "Invalid file hash: expected 64 characters, got {}",
            len
        )),
    }
}

/// Checks if a string is a valid 64-character hex file hash.
///
/// # Returns
/// `true` if the hash is valid, `false` otherwise.
#[inline]
pub fn is_valid_file_hash(hash: &str) -> bool {
    hash.len() == 64 && hash.chars().all(|c| c.is_ascii_hexdigit())
}

/// Updates a latency value using exponential moving average (EMA).
/// Returns the new smoothed latency value.
///
/// # Arguments
/// * `current` - Current EMA value (or initial sample if first measurement)
/// * `new_sample` - New latency measurement
/// * `alpha` - EMA alpha (weight for new sample, typically 0.1-0.3)
///
/// # Example
/// ```
/// use common::{update_ema_latency, LATENCY_EMA_ALPHA};
/// let current = 100.0;
/// let new_sample = 150.0;
/// let updated = update_ema_latency(current, new_sample, LATENCY_EMA_ALPHA);
/// // updated = 0.2 * 150 + 0.8 * 100 = 110
/// ```
#[inline]
pub fn update_ema_latency(current: f64, new_sample: f64, alpha: f64) -> f64 {
    let result = alpha.mul_add(new_sample - current, current);
    // Handle edge cases: NaN or Infinity from bad inputs
    if result.is_finite() {
        result
    } else {
        new_sample
    }
}

// ============================================================================
// Manifest Constants
// ============================================================================

/// Tombstone marker for deleted manifests in cache.
/// Used to indicate a file has been deleted without removing the cache entry.
pub const MANIFEST_TOMBSTONE: &str = "DELETED";

// ============================================================================
// P2P Connection Management
// ============================================================================

/// Maximum retries for P2P connection with exponential backoff.
pub const P2P_MAX_CONNECT_RETRIES: u32 = 3;

/// Initial backoff delay in milliseconds for P2P connection retries.
pub const P2P_INITIAL_BACKOFF_MS: u64 = 100;

/// Maximum backoff delay in milliseconds for P2P connection retries.
pub const P2P_MAX_BACKOFF_MS: u64 = 5000;

// ============================================================================
// Relay Configuration
// ============================================================================

/// Default Hippius relay URLs - used when IROH_RELAY_URL is not set.
pub const DEFAULT_RELAY_URLS: &[&str] =
    &["https://relay.hippius.com", "https://relay2.hippius.com"];

/// Maximum retries for initial endpoint binding.
pub const ENDPOINT_BIND_MAX_RETRIES: u32 = 3;

/// Initial backoff for endpoint bind retry (milliseconds).
pub const ENDPOINT_BIND_INITIAL_BACKOFF_MS: u64 = 500;

/// Time to wait for relay connection after successful bind (seconds).
pub const RELAY_CONNECTION_WAIT_SECS: u64 = 5;

/// Load primary relay URL from environment variable or config, falling back
/// to the first default. Use this when a single URL is needed (e.g.
/// `EndpointAddr::with_relay_url`).
///
/// Priority: config value > IROH_RELAY_URL env var > first DEFAULT_RELAY_URLS
pub fn get_relay_url(config_url: Option<&str>) -> iroh_base::RelayUrl {
    config_url
        .and_then(|s| s.parse().ok())
        .or_else(|| {
            std::env::var("IROH_RELAY_URL")
                .ok()
                .and_then(|s| s.parse().ok())
        })
        .unwrap_or_else(|| {
            DEFAULT_RELAY_URLS[0]
                .parse()
                .expect("valid default relay URL")
        })
}

/// Load all relay URLs. If a config/env override is set, returns only that
/// URL. Otherwise returns all `DEFAULT_RELAY_URLS`.
pub fn get_relay_urls(config_url: Option<&str>) -> Vec<iroh_base::RelayUrl> {
    if let Some(url_str) = config_url {
        if url_str.eq_ignore_ascii_case("default") {
            return vec![]; // Signal to use Iroh Default
        }
        if let Ok(url) = url_str.parse() {
            return vec![url];
        }
    }
    if let Ok(val) = std::env::var("IROH_RELAY_URL") {
        if val.eq_ignore_ascii_case("default") {
            return vec![]; // Signal to use Iroh Default
        }
        if let Ok(url) = val.parse() {
            return vec![url];
        }
    }
    DEFAULT_RELAY_URLS
        .iter()
        .map(|s| s.parse().expect("valid default relay URL"))
        .collect()
}

/// Build `RelayMode::Custom` from one or more relay URLs, or `RelayMode::Default` if empty.
pub fn build_relay_mode(urls: &[iroh_base::RelayUrl]) -> iroh::endpoint::RelayMode {
    if urls.is_empty() {
        return iroh::endpoint::RelayMode::Default;
    }
    let configs: Vec<_> = urls
        .iter()
        .map(|url| iroh::RelayConfig::from(url.clone()))
        .collect();
    iroh::endpoint::RelayMode::Custom(iroh::RelayMap::from_iter(configs))
}

/// Reusable P2P connection manager with connection pooling and retry logic.
///
/// Handles connection caching, health checking, and exponential backoff retries.
/// This is a generic building block for P2P clients.
///
/// # Example
/// ```rust,ignore
/// let manager = P2pConnectionManager::new(endpoint, target_node_id, ALPN);
/// let conn = manager.get_connection().await?;
/// ```
pub struct P2pConnectionManager {
    endpoint: iroh::Endpoint,
    target_node_id: iroh::PublicKey,
    alpn: &'static [u8],
    /// Cached connection: (connection, last_used_timestamp)
    connection: std::sync::Arc<tokio::sync::RwLock<Option<(iroh::endpoint::Connection, u64)>>>,
    /// Serializes reconnect attempts so only one caller retries at a time,
    /// without holding the `connection` RwLock during sleep/connect.
    reconnect_mutex: std::sync::Arc<tokio::sync::Mutex<()>>,
    /// Connection TTL in seconds
    connection_ttl_secs: u64,
    /// Counter for unhealthy connections detected (for metrics)
    unhealthy_connections: std::sync::Arc<std::sync::atomic::AtomicU64>,
    /// Known direct socket addresses for the target node (P2P address seeding)
    known_addrs: Vec<std::net::SocketAddr>,
    /// Relay URL hint for the target node (speeds up failover when direct
    /// addresses are unreachable — skips relay discovery via DNS)
    relay_url: Option<iroh_base::RelayUrl>,
}

impl Clone for P2pConnectionManager {
    fn clone(&self) -> Self {
        Self {
            endpoint: self.endpoint.clone(),
            target_node_id: self.target_node_id,
            alpn: self.alpn,
            connection: self.connection.clone(),
            reconnect_mutex: self.reconnect_mutex.clone(),
            connection_ttl_secs: self.connection_ttl_secs,
            unhealthy_connections: self.unhealthy_connections.clone(),
            known_addrs: self.known_addrs.clone(),
            relay_url: self.relay_url.clone(),
        }
    }
}

impl P2pConnectionManager {
    /// Create a new connection manager.
    pub fn new(
        endpoint: iroh::Endpoint,
        target_node_id: iroh::PublicKey,
        alpn: &'static [u8],
    ) -> Self {
        Self {
            endpoint,
            target_node_id,
            alpn,
            connection: std::sync::Arc::new(tokio::sync::RwLock::new(None)),
            reconnect_mutex: std::sync::Arc::new(tokio::sync::Mutex::new(())),
            connection_ttl_secs: P2P_CONNECTION_TTL_SECS,
            unhealthy_connections: std::sync::Arc::new(std::sync::atomic::AtomicU64::new(0)),
            known_addrs: vec![],
            relay_url: None,
        }
    }

    /// Override the connection TTL (default: `P2P_CONNECTION_TTL_SECS`).
    pub fn with_connection_ttl(mut self, secs: u64) -> Self {
        self.connection_ttl_secs = secs;
        self
    }

    /// Seed known direct socket addresses for the target node.
    ///
    /// When set, `get_connection()` builds an `EndpointAddr` with these
    /// addresses so iroh can connect directly without relay discovery.
    pub fn with_known_addrs(mut self, addrs: Vec<std::net::SocketAddr>) -> Self {
        self.known_addrs = addrs;
        self
    }

    /// Set the relay URL hint for the target node.
    ///
    /// When set, `get_connection()` includes this relay URL in the
    /// `EndpointAddr` so iroh can fall back to relay without a DNS
    /// discovery roundtrip if direct addresses are unreachable.
    pub fn with_relay_url(mut self, url: iroh_base::RelayUrl) -> Self {
        self.relay_url = Some(url);
        self
    }

    /// Get the target node ID.
    pub fn target_node_id(&self) -> &iroh::PublicKey {
        &self.target_node_id
    }

    /// Get the underlying endpoint.
    pub fn endpoint(&self) -> &iroh::Endpoint {
        &self.endpoint
    }

    /// Get the count of unhealthy connections detected (for metrics).
    pub fn unhealthy_connection_count(&self) -> u64 {
        self.unhealthy_connections
            .load(std::sync::atomic::Ordering::Relaxed)
    }

    /// Get or create a connection to the target node.
    ///
    /// Reuses cached connections within TTL, with health checking.
    /// On failure, retries with exponential backoff.
    ///
    /// The `connection` RwLock is only held for microseconds (cache
    /// read/write). The `reconnect_mutex` serializes concurrent reconnect
    /// attempts so only one caller drives the retry loop — other callers
    /// wait on the mutex and then re-check the cache.
    pub async fn get_connection(&self) -> anyhow::Result<iroh::endpoint::Connection> {
        use std::sync::atomic::Ordering;
        use tracing::{debug, warn};

        let now = now_secs();

        // Fast path: check cache under read-lock (microseconds)
        {
            let conn_guard = self.connection.read().await;
            if let Some((conn, last_used)) = conn_guard.as_ref()
                && now.saturating_sub(*last_used) < self.connection_ttl_secs
            {
                if conn.close_reason().is_none() {
                    debug!(
                        target = %self.target_node_id,
                        conn_id = conn.stable_id(),
                        "Reusing cached P2P connection"
                    );
                    return Ok(conn.clone());
                }
                self.unhealthy_connections.fetch_add(1, Ordering::Relaxed);
                warn!(
                    target = %self.target_node_id,
                    conn_id = conn.stable_id(),
                    reason = ?conn.close_reason(),
                    "Cached P2P connection is unhealthy, will reconnect"
                );
            }
        }
        // read-lock dropped

        // Serialize reconnect attempts — only one caller retries at a time.
        // Other callers wait here and re-check the cache when the mutex is
        // released. No I/O happens under the connection RwLock.
        let _reconnect_guard = self.reconnect_mutex.lock().await;

        // Re-check cache: another caller may have connected while we waited
        {
            let conn_guard = self.connection.read().await;
            if let Some((conn, last_used)) = conn_guard.as_ref()
                && now_secs().saturating_sub(*last_used) < self.connection_ttl_secs
                && conn.close_reason().is_none()
            {
                debug!(
                    target = %self.target_node_id,
                    conn_id = conn.stable_id(),
                    "Reusing cached P2P connection (after reconnect lock)"
                );
                return Ok(conn.clone());
            }
        }
        // read-lock dropped

        // Retry loop — no lock on `connection` during sleep or connect
        let mut last_error = None;
        for attempt in 0..=P2P_MAX_CONNECT_RETRIES {
            if attempt > 0 {
                let backoff_ms = std::cmp::min(
                    P2P_INITIAL_BACKOFF_MS * (1 << (attempt - 1)),
                    P2P_MAX_BACKOFF_MS,
                );
                debug!(
                    target = %self.target_node_id,
                    attempt = attempt,
                    backoff_ms = backoff_ms,
                    "Retrying P2P connection after backoff"
                );
                tokio::time::sleep(std::time::Duration::from_millis(backoff_ms)).await;
            }

            debug!(
                target = %self.target_node_id,
                attempt = attempt,
                "Connecting via P2P"
            );

            let mut connect_target = iroh::EndpointAddr::new(self.target_node_id);
            if let Some(ref url) = self.relay_url {
                connect_target = connect_target.with_relay_url(url.clone());
            }
            if !self.known_addrs.is_empty() {
                connect_target = connect_target
                    .with_addrs(self.known_addrs.iter().map(|a| iroh::TransportAddr::Ip(*a)));
            }

            // Uses connect_with_direct_path to ensure a direct IP path
            // before use — closes the connection if relay-only after
            // timeout.
            match connect_with_direct_path(
                &self.endpoint,
                connect_target,
                self.alpn,
                std::time::Duration::from_secs(P2P_DEFAULT_TIMEOUT_SECS),
                std::time::Duration::from_secs(5),
            )
            .await
            {
                Ok(conn) => {
                    debug!(
                        target = %self.target_node_id,
                        conn_id = conn.stable_id(),
                        "P2P connection established"
                    );
                    // Write-lock only to store the new connection (microseconds).
                    // Close any stale predecessor to free its Iroh path IDs.
                    let mut conn_guard = self.connection.write().await;
                    if let Some((old_conn, _)) = conn_guard.take() {
                        old_conn.close(0u32.into(), b"replaced");
                    }
                    *conn_guard = Some((conn.clone(), now_secs()));
                    return Ok(conn);
                }
                Err(e) => {
                    warn!(
                        target = %self.target_node_id,
                        attempt = attempt,
                        error = %e,
                        "P2P connection failed"
                    );
                    last_error = Some(e);
                }
            }
        }

        Err(last_error.unwrap_or_else(|| anyhow::anyhow!("Failed to connect after retries")))
    }

    /// Evict the cached connection so the next `get_connection()` creates a fresh one.
    ///
    /// Call this when a stream-level operation (open_bi, write, read) fails,
    /// indicating the underlying QUIC connection may be dead even though
    /// `close_reason()` hasn't propagated yet.
    ///
    /// The old connection is explicitly closed so Iroh releases its path IDs
    /// immediately. Without this, stale connections hold path slots in Iroh's
    /// remote_map until idle timeout, causing `MaxPathIdReached` when new
    /// connections are created to the same peer.
    pub async fn invalidate_connection(&self) {
        let mut conn_guard = self.connection.write().await;
        if let Some((conn, _)) = conn_guard.take() {
            conn.close(0u32.into(), b"stale");
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_pos_challenge_serialization() {
        let challenge = MinerControlMessage::PosChallenge {
            shard_hash: "abc123".to_string(),
            chunk_indices: vec![0, 5, 10, 15],
            nonce: [42u8; 32],
            expected_root: [1, 2, 3, 4, 5, 6, 7, 8],
            expires_at: 1234567890,
        };
        let bytes = serde_json::to_vec(&challenge).unwrap();
        let decoded: MinerControlMessage = serde_json::from_slice(&bytes).unwrap();
        match decoded {
            MinerControlMessage::PosChallenge {
                shard_hash,
                chunk_indices,
                ..
            } => {
                assert_eq!(shard_hash, "abc123");
                assert_eq!(chunk_indices, vec![0, 5, 10, 15]);
            }
            _ => panic!("Wrong variant"),
        }
    }

    #[test]
    fn test_pos_proof_response_serialization() {
        let response = ValidatorControlMessage::PosProofResponse {
            nonce: [42u8; 32],
            proof_bytes: vec![1, 2, 3, 4],
            public_inputs: vec![100, 200, 300],
            proving_time_ms: 500,
        };
        let bytes = serde_json::to_vec(&response).unwrap();
        let decoded: ValidatorControlMessage = serde_json::from_slice(&bytes).unwrap();
        match decoded {
            ValidatorControlMessage::PosProofResponse {
                proving_time_ms, ..
            } => {
                assert_eq!(proving_time_ms, 500);
            }
            _ => panic!("Wrong variant"),
        }
    }

    #[test]
    fn test_gateway_control_message_serialization() {
        // Test GetClusterMap request
        let request = GatewayControlMessage::GetClusterMap;
        let bytes = serde_json::to_vec(&request).unwrap();
        let decoded: GatewayControlMessage = serde_json::from_slice(&bytes).unwrap();
        assert!(matches!(decoded, GatewayControlMessage::GetClusterMap));

        // Test GetManifest request
        let request = GatewayControlMessage::GetManifest {
            file_hash: "abc123def456".to_string(),
        };
        let bytes = serde_json::to_vec(&request).unwrap();
        let decoded: GatewayControlMessage = serde_json::from_slice(&bytes).unwrap();
        match decoded {
            GatewayControlMessage::GetManifest { file_hash } => {
                assert_eq!(file_hash, "abc123def456");
            }
            _ => panic!("Wrong variant"),
        }

        // Test UploadFile request
        let request = GatewayControlMessage::UploadFile {
            filename: "test.txt".to_string(),
            size: 1024,
            data: vec![1, 2, 3, 4],
            content_type: Some("text/plain".to_string()),
        };
        let bytes = serde_json::to_vec(&request).unwrap();
        let decoded: GatewayControlMessage = serde_json::from_slice(&bytes).unwrap();
        match decoded {
            GatewayControlMessage::UploadFile {
                filename,
                size,
                data,
                content_type,
            } => {
                assert_eq!(filename, "test.txt");
                assert_eq!(size, 1024);
                assert_eq!(data, vec![1, 2, 3, 4]);
                assert_eq!(content_type, Some("text/plain".to_string()));
            }
            _ => panic!("Wrong variant"),
        }

        // Test ClusterMapResponse
        let response = GatewayControlMessage::ClusterMapResponse {
            map: Some(ClusterMap::new()),
            error: None,
        };
        let bytes = serde_json::to_vec(&response).unwrap();
        let decoded: GatewayControlMessage = serde_json::from_slice(&bytes).unwrap();
        match decoded {
            GatewayControlMessage::ClusterMapResponse { map, error } => {
                assert!(map.is_some());
                assert!(error.is_none());
            }
            _ => panic!("Wrong variant"),
        }

        // Test ReportBandwidth
        let request = GatewayControlMessage::ReportBandwidth {
            reports: vec![BandwidthReport {
                miner_uid: "42".to_string(),
                bytes: 1024 * 1024,
            }],
        };
        let bytes = serde_json::to_vec(&request).unwrap();
        let decoded: GatewayControlMessage = serde_json::from_slice(&bytes).unwrap();
        match decoded {
            GatewayControlMessage::ReportBandwidth { reports } => {
                assert_eq!(reports.len(), 1);
                assert_eq!(reports[0].miner_uid, "42");
                assert_eq!(reports[0].bytes, 1024 * 1024);
            }
            _ => panic!("Wrong variant"),
        }
    }

    #[test]
    fn test_warden_control_message_serialization() {
        // Test PushShardCommitment
        let request = WardenControlMessage::PushShardCommitment {
            shard_hash: "abc123".to_string(),
            merkle_root: [1, 2, 3, 4, 5, 6, 7, 8],
            chunk_count: 100,
            miner_uid: 42,
            miner_endpoint: "http://127.0.0.1:3001".to_string(),
        };
        let bytes = serde_json::to_vec(&request).unwrap();
        let decoded: WardenControlMessage = serde_json::from_slice(&bytes).unwrap();
        match decoded {
            WardenControlMessage::PushShardCommitment {
                shard_hash,
                merkle_root,
                chunk_count,
                miner_uid,
                ..
            } => {
                assert_eq!(shard_hash, "abc123");
                assert_eq!(merkle_root, [1, 2, 3, 4, 5, 6, 7, 8]);
                assert_eq!(chunk_count, 100);
                assert_eq!(miner_uid, 42);
            }
            _ => panic!("Wrong variant"),
        }

        // Test PushAuditResults
        let request = WardenControlMessage::PushAuditResults {
            batch: WardenAuditBatch {
                reports: vec![WardenAuditReport {
                    audit_id: "audit-1".to_string(),
                    warden_pubkey: "warden-key".to_string(),
                    miner_uid: 42,
                    shard_hash: "shard-hash".to_string(),
                    result: AuditResultType::Passed,
                    timestamp: 1234567890,
                    signature: vec![1, 2, 3, 4],
                    block_number: 0,
                    merkle_proof_sig_hash: vec![],
                    warden_id: String::new(),
                }],
            },
        };
        let bytes = serde_json::to_vec(&request).unwrap();
        let decoded: WardenControlMessage = serde_json::from_slice(&bytes).unwrap();
        match decoded {
            WardenControlMessage::PushAuditResults { batch } => {
                assert_eq!(batch.reports.len(), 1);
                assert_eq!(batch.reports[0].miner_uid, 42);
                assert_eq!(batch.reports[0].result, AuditResultType::Passed);
            }
            _ => panic!("Wrong variant"),
        }

        // Test PushShardCommitmentsBatch
        let request = WardenControlMessage::PushShardCommitmentsBatch {
            commitments: vec![
                WardenShardCommitment {
                    shard_hash: "shard1".to_string(),
                    merkle_root: [1, 2, 3, 4, 5, 6, 7, 8],
                    chunk_count: 100,
                    miner_uid: 42,
                    miner_endpoint: "http://127.0.0.1:3001".to_string(),
                },
                WardenShardCommitment {
                    shard_hash: "shard2".to_string(),
                    merkle_root: [8, 7, 6, 5, 4, 3, 2, 1],
                    chunk_count: 200,
                    miner_uid: 43,
                    miner_endpoint: "http://127.0.0.1:3002".to_string(),
                },
            ],
        };
        let bytes = serde_json::to_vec(&request).unwrap();
        let decoded: WardenControlMessage = serde_json::from_slice(&bytes).unwrap();
        match decoded {
            WardenControlMessage::PushShardCommitmentsBatch { commitments } => {
                assert_eq!(commitments.len(), 2);
                assert_eq!(commitments[0].shard_hash, "shard1");
                assert_eq!(commitments[0].miner_uid, 42);
                assert_eq!(commitments[1].shard_hash, "shard2");
                assert_eq!(commitments[1].chunk_count, 200);
            }
            _ => panic!("Wrong variant"),
        }

        // Test DeleteShardsBatch
        let request = WardenControlMessage::DeleteShardsBatch {
            shard_hashes: vec![
                "hash1".to_string(),
                "hash2".to_string(),
                "hash3".to_string(),
            ],
        };
        let bytes = serde_json::to_vec(&request).unwrap();
        let decoded: WardenControlMessage = serde_json::from_slice(&bytes).unwrap();
        match decoded {
            WardenControlMessage::DeleteShardsBatch { shard_hashes } => {
                assert_eq!(shard_hashes.len(), 3);
                assert_eq!(shard_hashes[0], "hash1");
                assert_eq!(shard_hashes[2], "hash3");
            }
            _ => panic!("Wrong variant"),
        }

        // Test Ack
        let response = WardenControlMessage::Ack {
            success: true,
            message: Some("OK".to_string()),
        };
        let bytes = serde_json::to_vec(&response).unwrap();
        let decoded: WardenControlMessage = serde_json::from_slice(&bytes).unwrap();
        match decoded {
            WardenControlMessage::Ack { success, message } => {
                assert!(success);
                assert_eq!(message, Some("OK".to_string()));
            }
            _ => panic!("Wrong variant"),
        }
    }

    #[test]
    fn test_submitter_control_message_serialization() {
        // Test GetClusterMap request
        let request = SubmitterControlMessage::GetClusterMap;
        let bytes = serde_json::to_vec(&request).unwrap();
        let decoded: SubmitterControlMessage = serde_json::from_slice(&bytes).unwrap();
        assert!(matches!(decoded, SubmitterControlMessage::GetClusterMap));

        // Test GetNetworkStats request
        let request = SubmitterControlMessage::GetNetworkStats;
        let bytes = serde_json::to_vec(&request).unwrap();
        let decoded: SubmitterControlMessage = serde_json::from_slice(&bytes).unwrap();
        assert!(matches!(decoded, SubmitterControlMessage::GetNetworkStats));

        // Test ClusterMapResponse (success)
        let response = SubmitterControlMessage::ClusterMapResponse {
            map: Some(ClusterMap::new()),
            error: None,
        };
        let bytes = serde_json::to_vec(&response).unwrap();
        let decoded: SubmitterControlMessage = serde_json::from_slice(&bytes).unwrap();
        match decoded {
            SubmitterControlMessage::ClusterMapResponse { map, error } => {
                assert!(map.is_some());
                assert_eq!(map.unwrap().epoch, 0);
                assert!(error.is_none());
            }
            _ => panic!("Wrong variant"),
        }

        // Test ClusterMapResponse (error)
        let response = SubmitterControlMessage::ClusterMapResponse {
            map: None,
            error: Some("Test error".to_string()),
        };
        let bytes = serde_json::to_vec(&response).unwrap();
        let decoded: SubmitterControlMessage = serde_json::from_slice(&bytes).unwrap();
        match decoded {
            SubmitterControlMessage::ClusterMapResponse { map, error } => {
                assert!(map.is_none());
                assert_eq!(error, Some("Test error".to_string()));
            }
            _ => panic!("Wrong variant"),
        }

        // Test NetworkStatsResponse
        let mut miner_stats = HashMap::new();
        miner_stats.insert("42".to_string(), [1024u64, 10u64]);
        let mut bandwidth_stats = HashMap::new();
        bandwidth_stats.insert("42".to_string(), 2048u64);

        let response = SubmitterControlMessage::NetworkStatsResponse {
            total_files: 100,
            miner_stats,
            bandwidth_stats,
            is_ready: true,
        };
        let bytes = serde_json::to_vec(&response).unwrap();
        let decoded: SubmitterControlMessage = serde_json::from_slice(&bytes).unwrap();
        match decoded {
            SubmitterControlMessage::NetworkStatsResponse {
                total_files,
                miner_stats,
                bandwidth_stats,
                is_ready,
            } => {
                assert_eq!(total_files, 100);
                assert_eq!(miner_stats.get("42"), Some(&[1024u64, 10u64]));
                assert_eq!(bandwidth_stats.get("42"), Some(&2048u64));
                assert!(is_ready);
            }
            _ => panic!("Wrong variant"),
        }

        // Test SyncEpoch request
        let request = SubmitterControlMessage::SyncEpoch {
            on_chain_epoch: 2090,
        };
        let bytes = serde_json::to_vec(&request).unwrap();
        let decoded: SubmitterControlMessage = serde_json::from_slice(&bytes).unwrap();
        match decoded {
            SubmitterControlMessage::SyncEpoch { on_chain_epoch } => {
                assert_eq!(on_chain_epoch, 2090);
            }
            _ => panic!("Wrong variant"),
        }

        // Test SyncEpochResponse (success)
        let response = SubmitterControlMessage::SyncEpochResponse {
            success: true,
            new_epoch: 2091,
            error: None,
        };
        let bytes = serde_json::to_vec(&response).unwrap();
        let decoded: SubmitterControlMessage = serde_json::from_slice(&bytes).unwrap();
        match decoded {
            SubmitterControlMessage::SyncEpochResponse {
                success,
                new_epoch,
                error,
            } => {
                assert!(success);
                assert_eq!(new_epoch, 2091);
                assert!(error.is_none());
            }
            _ => panic!("Wrong variant"),
        }

        // Test SyncEpochResponse (failure)
        let response = SubmitterControlMessage::SyncEpochResponse {
            success: false,
            new_epoch: 0,
            error: Some("persist failed".to_string()),
        };
        let bytes = serde_json::to_vec(&response).unwrap();
        let decoded: SubmitterControlMessage = serde_json::from_slice(&bytes).unwrap();
        match decoded {
            SubmitterControlMessage::SyncEpochResponse {
                success,
                new_epoch,
                error,
            } => {
                assert!(!success);
                assert_eq!(new_epoch, 0);
                assert_eq!(error, Some("persist failed".to_string()));
            }
            _ => panic!("Wrong variant"),
        }
    }

    #[test]
    fn test_cluster_map_default_has_correct_params() {
        let map = ClusterMap::default();
        assert_eq!(map.pg_count, 16384);
        assert_eq!(map.ec_k, 10);
        assert_eq!(map.ec_m, 20);
        assert_eq!(map.epoch, 0);
        assert!(map.miners.is_empty());
    }

    #[test]
    fn test_ensure_defaults_fixes_zeros() {
        let mut map = ClusterMap {
            epoch: 5,
            miners: vec![],
            pg_count: 0,
            ec_k: 0,
            ec_m: 0,
        };
        map.ensure_defaults();
        assert_eq!(map.pg_count, 16384);
        assert_eq!(map.ec_k, 10);
        assert_eq!(map.ec_m, 20);
        assert_eq!(map.epoch, 5); // epoch should NOT be touched
    }

    #[test]
    fn test_ensure_defaults_preserves_nonzero() {
        let mut map = ClusterMap {
            epoch: 3,
            miners: vec![],
            pg_count: 8192,
            ec_k: 5,
            ec_m: 15,
        };
        map.ensure_defaults();
        assert_eq!(map.pg_count, 8192);
        assert_eq!(map.ec_k, 5);
        assert_eq!(map.ec_m, 15);
    }

    #[test]
    fn test_ensure_defaults_rounds_pg_count_to_power_of_two() {
        let mut map = ClusterMap {
            epoch: 1,
            miners: vec![],
            pg_count: 15000,
            ec_k: 10,
            ec_m: 20,
        };
        map.ensure_defaults();
        assert_eq!(map.pg_count, 16384); // next power of 2 above 15000
    }

    #[test]
    fn test_ensure_defaults_preserves_power_of_two_pg_count() {
        let mut map = ClusterMap {
            epoch: 1,
            miners: vec![],
            pg_count: 4096,
            ec_k: 10,
            ec_m: 20,
        };
        map.ensure_defaults();
        assert_eq!(map.pg_count, 4096);
    }

    #[test]
    fn test_calculate_uptime_score() {
        // New miner (< 60s elapsed) gets perfect score
        assert_eq!(calculate_uptime_score(0, 1000, 1050), 1.0);

        // Zero expected heartbeats returns 1.0
        assert_eq!(calculate_uptime_score(0, 100, 100), 1.0);

        // 100% uptime: 10 heartbeats in 300s (expected 10 at 30s interval)
        assert_eq!(calculate_uptime_score(10, 0, 300), 1.0);

        // 50% uptime: 5 heartbeats in 300s
        assert!((calculate_uptime_score(5, 0, 300) - 0.5).abs() < 0.01);

        // 0 heartbeats, > 60s elapsed
        assert_eq!(calculate_uptime_score(0, 0, 120), 0.0);

        // More heartbeats than expected clamps to 1.0
        assert_eq!(calculate_uptime_score(100, 0, 300), 1.0);
    }

    #[test]
    fn test_alpn_constants() {
        // Verify ALPN constants are valid byte strings
        assert_eq!(VALIDATOR_CONTROL_ALPN, b"hippius/validator-control");
        assert_eq!(GATEWAY_CONTROL_ALPN, b"hippius/gateway-control");
        assert_eq!(WARDEN_CONTROL_ALPN, b"hippius/warden-control");
        assert_eq!(SUBMITTER_CONTROL_ALPN, b"hippius/submitter-control");

        // Verify they are distinct
        assert_ne!(VALIDATOR_CONTROL_ALPN, GATEWAY_CONTROL_ALPN);
        assert_ne!(VALIDATOR_CONTROL_ALPN, WARDEN_CONTROL_ALPN);
        assert_ne!(VALIDATOR_CONTROL_ALPN, SUBMITTER_CONTROL_ALPN);
        assert_ne!(GATEWAY_CONTROL_ALPN, WARDEN_CONTROL_ALPN);
        assert_ne!(GATEWAY_CONTROL_ALPN, SUBMITTER_CONTROL_ALPN);
        assert_ne!(WARDEN_CONTROL_ALPN, SUBMITTER_CONTROL_ALPN);
    }

    #[test]
    fn test_extract_miner_ip_from_direct_addr() {
        let secret = iroh::SecretKey::from_bytes(&[1u8; 32]);
        let public = secret.public();
        let sock = std::net::SocketAddr::new(
            std::net::IpAddr::V4(std::net::Ipv4Addr::new(203, 0, 113, 5)),
            3001,
        );
        let addr = iroh::EndpointAddr::from(public).with_addrs(vec![iroh::TransportAddr::Ip(sock)]);
        let result = extract_miner_ip(Some(&addr), "");
        assert_eq!(result, Some("203.0.113.5".to_string()));
    }

    #[test]
    fn test_extract_miner_ip_skips_loopback_direct_addr() {
        let secret = iroh::SecretKey::from_bytes(&[2u8; 32]);
        let public = secret.public();
        let loopback =
            std::net::SocketAddr::new(std::net::IpAddr::V4(std::net::Ipv4Addr::LOCALHOST), 3001);
        let addr =
            iroh::EndpointAddr::from(public).with_addrs(vec![iroh::TransportAddr::Ip(loopback)]);
        // Loopback direct addr skipped, falls through to http_addr
        let result = extract_miner_ip(Some(&addr), "http://198.51.100.1:3001");
        assert_eq!(result, Some("198.51.100.1".to_string()));
    }

    #[test]
    fn test_extract_miner_ip_from_http_addr() {
        let result = extract_miner_ip(None, "http://203.0.113.5:3001");
        assert_eq!(result, Some("203.0.113.5".to_string()));
    }

    #[test]
    fn test_extract_miner_ip_hostname_returns_none() {
        let result = extract_miner_ip(None, "http://miner.example.com:3001");
        assert_eq!(result, None);
    }

    #[test]
    fn test_extract_miner_ip_empty_returns_none() {
        let result = extract_miner_ip(None, "");
        assert_eq!(result, None);
    }

    #[test]
    fn test_extract_miner_ip_loopback_http_returns_none() {
        let result = extract_miner_ip(None, "http://127.0.0.1:3001");
        assert_eq!(result, None);
    }

    #[test]
    fn test_extract_miner_ip_from_ipv6_http_addr() {
        let result = extract_miner_ip(None, "http://[2001:db8::1]:3001");
        assert_eq!(result, Some("2001:db8::1".to_string()));
    }

    #[test]
    fn test_extract_miner_ip_ipv6_loopback_returns_none() {
        let result = extract_miner_ip(None, "http://[::1]:3001");
        assert_eq!(result, None);
    }

    #[test]
    fn test_extract_miner_ip_from_https_addr() {
        let result = extract_miner_ip(None, "https://203.0.113.5:3001");
        assert_eq!(result, Some("203.0.113.5".to_string()));
    }

    #[test]
    fn test_pg_placement_uids_matches_full_placement() {
        let miners: Vec<MinerNode> = (0..30)
            .map(|i| {
                let sk = iroh::SecretKey::from_bytes(&[i as u8 + 1; 32]);
                MinerNode {
                    uid: i,
                    weight: 100,
                    family_id: format!("family-{}", i % 10),
                    endpoint: iroh::EndpointAddr::from(sk.public()),
                    ip_subnet: String::new(),
                    ip_address: None,
                    http_addr: format!("http://10.0.0.{}:3001", i),
                    public_key: format!("{:064x}", i),
                    total_storage: 1_000_000,
                    available_storage: 500_000,
                    strikes: 0,
                    last_seen: 0,
                    heartbeat_count: 0,
                    registration_time: 0,
                    bandwidth_total: 0,
                    bandwidth_window_start: 0,
                    weight_manual_override: false,
                    reputation: 0.0,
                    consecutive_audit_passes: 0,
                    integrity_fails: 0,
                    version: String::new(),
                    base_weight: 0,
                    warden_challenges_total: 0,
                    warden_challenges_passed: 0,
                    fetch_timeout_count: 0,
                    expected_shards: 0,
                    actual_shards: 0,
                    trust_score: 0.0,
                    earned_capacity_bytes: 0,
                    draining: false,
                    p2p_reliability_score: 1.0,
                }
            })
            .collect();

        let map = ClusterMap {
            miners,
            pg_count: 64,
            ec_k: 10,
            ec_m: 20,
            ..ClusterMap::default()
        };

        for pg_id in 0..64 {
            let full = calculate_pg_placement(pg_id, 30, &map).expect("full");
            let uids = calculate_pg_placement_uids(pg_id, 30, &map).expect("uids");

            let full_uids: Vec<u32> = full.iter().map(|m| m.uid).collect();
            assert_eq!(full_uids, uids, "PG {} mismatch", pg_id);
        }
    }

    #[test]
    fn compute_miner_uid_deterministic() {
        let key = "abc123def456";
        assert_eq!(compute_miner_uid(key), compute_miner_uid(key));
        assert_ne!(compute_miner_uid(key), compute_miner_uid("xyz789"));
        assert!(compute_miner_uid(key) <= 0x7FFF_FFFF);
    }

    #[test]
    fn test_is_advertisable_ip_accepts_private_ranges() {
        use std::net::IpAddr;
        // RFC 1918
        assert!(is_advertisable_ip("10.0.0.1".parse::<IpAddr>().unwrap()));
        assert!(is_advertisable_ip("172.16.5.1".parse::<IpAddr>().unwrap()));
        assert!(is_advertisable_ip("192.168.1.1".parse::<IpAddr>().unwrap()));
        // CGNAT (RFC 6598)
        assert!(is_advertisable_ip("100.64.0.1".parse::<IpAddr>().unwrap()));
        assert!(is_advertisable_ip(
            "100.127.255.254".parse::<IpAddr>().unwrap()
        ));
        // Public
        assert!(is_advertisable_ip("203.0.113.5".parse::<IpAddr>().unwrap()));
        // ULA IPv6
        assert!(is_advertisable_ip("fd00::1".parse::<IpAddr>().unwrap()));
    }

    #[test]
    fn test_is_advertisable_ip_rejects_unusable() {
        use std::net::IpAddr;
        assert!(!is_advertisable_ip("127.0.0.1".parse::<IpAddr>().unwrap()));
        assert!(!is_advertisable_ip("0.0.0.0".parse::<IpAddr>().unwrap()));
        assert!(!is_advertisable_ip(
            "169.254.1.1".parse::<IpAddr>().unwrap()
        ));
        assert!(!is_advertisable_ip(
            "255.255.255.255".parse::<IpAddr>().unwrap()
        ));
        assert!(!is_advertisable_ip("224.0.0.1".parse::<IpAddr>().unwrap()));
        assert!(!is_advertisable_ip("::1".parse::<IpAddr>().unwrap()));
        assert!(!is_advertisable_ip("::".parse::<IpAddr>().unwrap()));
        assert!(!is_advertisable_ip("fe80::1".parse::<IpAddr>().unwrap()));
        assert!(!is_advertisable_ip("ff02::1".parse::<IpAddr>().unwrap()));
        // Reserved/experimental 240.0.0.0/4
        assert!(!is_advertisable_ip("240.0.0.1".parse::<IpAddr>().unwrap()));
    }

    #[test]
    fn test_has_direct_addr_accepts_any_ip() {
        let secret = iroh::SecretKey::from_bytes(&[99u8; 32]);
        let public = secret.public();
        // Private IP should pass (was previously rejected by has_routable_direct_addr)
        let private_sock = std::net::SocketAddr::new(
            std::net::IpAddr::V4(std::net::Ipv4Addr::new(10, 0, 0, 1)),
            3001,
        );
        let addr = iroh::EndpointAddr::from(public)
            .with_addrs(vec![iroh::TransportAddr::Ip(private_sock)]);
        assert!(has_direct_addr(&addr));
    }

    #[test]
    fn test_has_direct_addr_rejects_relay_only() {
        let secret = iroh::SecretKey::from_bytes(&[100u8; 32]);
        let public = secret.public();
        // No direct addrs at all
        let addr = iroh::EndpointAddr::from(public);
        assert!(!has_direct_addr(&addr));
    }

    // ====================================================================
    // Straw2 tests
    // ====================================================================

    fn make_straw2_test_map(num_miners: u32, families: u32) -> ClusterMap {
        let miners: Vec<MinerNode> = (0..num_miners)
            .map(|i| {
                let sk = iroh::SecretKey::from_bytes(&[i as u8 + 1; 32]);
                MinerNode {
                    uid: i,
                    weight: 100,
                    family_id: format!("family-{}", i % families),
                    endpoint: iroh::EndpointAddr::from(sk.public()),
                    ip_subnet: String::new(),
                    ip_address: None,
                    http_addr: format!("http://10.0.0.{}:3001", i),
                    public_key: format!("{:064x}", i),
                    total_storage: 1_000_000,
                    available_storage: 500_000,
                    strikes: 0,
                    last_seen: 0,
                    heartbeat_count: 0,
                    registration_time: 0,
                    bandwidth_total: 0,
                    bandwidth_window_start: 0,
                    weight_manual_override: false,
                    reputation: 0.0,
                    consecutive_audit_passes: 0,
                    integrity_fails: 0,
                    version: String::new(),
                    base_weight: 0,
                    warden_challenges_total: 0,
                    warden_challenges_passed: 0,
                    fetch_timeout_count: 0,
                    expected_shards: 0,
                    actual_shards: 0,
                    trust_score: 0.0,
                    earned_capacity_bytes: 0,
                    draining: false,
                    p2p_reliability_score: 1.0,
                }
            })
            .collect();

        ClusterMap {
            epoch: 1,
            miners,
            pg_count: 64,
            ec_k: 10,
            ec_m: 20,
        }
    }

    #[test]
    fn test_straw2_placement_deterministic() {
        let map = make_straw2_test_map(30, 10);
        let result1 =
            calculate_placement_for_stripe_straw2("abc123", 0, 30, &map).expect("placement");
        let result2 =
            calculate_placement_for_stripe_straw2("abc123", 0, 30, &map).expect("placement");

        let uids1: Vec<u32> = result1.iter().map(|m| m.uid).collect();
        let uids2: Vec<u32> = result2.iter().map(|m| m.uid).collect();
        assert_eq!(uids1, uids2, "straw2 must be deterministic");
    }

    #[test]
    fn test_straw2_selects_correct_count() {
        let map = make_straw2_test_map(50, 15);
        let result =
            calculate_placement_for_stripe_straw2("file_hash", 0, 30, &map).expect("placement");
        assert_eq!(result.len(), 30);
    }

    #[test]
    fn test_straw2_family_diversity() {
        // 30 miners across 30 unique families → each shard should be in a different family
        let map = make_straw2_test_map(30, 30);
        let result =
            calculate_placement_for_stripe_straw2("file_hash", 0, 30, &map).expect("placement");

        let mut families: std::collections::HashSet<&str> = std::collections::HashSet::new();
        for miner in &result {
            families.insert(&miner.family_id);
        }
        assert_eq!(
            families.len(),
            30,
            "each shard should be in a unique family"
        );
    }

    #[test]
    fn test_straw2_no_duplicate_miners() {
        let map = make_straw2_test_map(50, 15);
        let result =
            calculate_placement_for_stripe_straw2("file_hash", 0, 30, &map).expect("placement");

        let mut seen = std::collections::HashSet::new();
        for miner in &result {
            assert!(
                seen.insert(miner.uid),
                "duplicate miner UID {} in placement",
                miner.uid
            );
        }
    }

    #[test]
    fn test_straw2_uid_only_matches_full() {
        let map = make_straw2_test_map(30, 10);

        for pg_id in 0..64 {
            let full = calculate_pg_placement_straw2(pg_id, 30, &map).expect("full");
            let uids = calculate_pg_placement_uids_straw2(pg_id, 30, &map).expect("uids");

            let full_uids: Vec<u32> = full.iter().map(|m| m.uid).collect();
            assert_eq!(full_uids, uids, "PG {} straw2 uid mismatch", pg_id);
        }
    }

    #[test]
    fn test_straw2_pg_stripe_rotation() {
        let map = make_straw2_test_map(30, 10);
        let stripe0 =
            calculate_pg_placement_for_stripe_straw2("hash", 0, 30, &map).expect("stripe 0");
        let stripe1 =
            calculate_pg_placement_for_stripe_straw2("hash", 1, 30, &map).expect("stripe 1");

        // Same miners, different rotation
        let uids0: std::collections::HashSet<u32> = stripe0.iter().map(|m| m.uid).collect();
        let uids1: std::collections::HashSet<u32> = stripe1.iter().map(|m| m.uid).collect();
        assert_eq!(uids0, uids1, "same PG should have same miner set");

        // But order should differ (rotation)
        let ordered0: Vec<u32> = stripe0.iter().map(|m| m.uid).collect();
        let ordered1: Vec<u32> = stripe1.iter().map(|m| m.uid).collect();
        assert_ne!(ordered0, ordered1, "stripe rotation should change order");
    }

    #[test]
    fn test_straw2_minimal_data_movement() {
        // Core straw2 property: removing one miner should only affect
        // placements where that miner was selected.
        let map_full = make_straw2_test_map(40, 15);
        let removed_uid = 5;

        let mut map_minus_one = map_full.clone();
        map_minus_one.miners.retain(|m| m.uid != removed_uid);

        let mut unchanged = 0;
        let mut changed = 0;

        for pg_id in 0..64 {
            let full = calculate_pg_placement_straw2(pg_id, 30, &map_full).expect("full");
            let minus = calculate_pg_placement_straw2(pg_id, 30, &map_minus_one).expect("minus");

            let full_uids: Vec<u32> = full.iter().map(|m| m.uid).collect();
            let minus_uids: Vec<u32> = minus.iter().map(|m| m.uid).collect();

            if full_uids.contains(&removed_uid) {
                changed += 1;
            } else if full_uids == minus_uids {
                unchanged += 1;
            }
        }

        // PGs that didn't include the removed miner should be completely unchanged
        assert!(
            unchanged > 0,
            "some PGs should be unaffected by removing one miner"
        );
        assert!(
            changed > 0,
            "some PGs should be affected (the removed miner was placed there)"
        );
    }

    #[test]
    fn test_straw2_dispatch_via_version_3() {
        let map = make_straw2_test_map(30, 10);
        let direct = calculate_pg_placement_for_stripe_straw2("hash", 0, 30, &map).expect("direct");
        let dispatched = calculate_stripe_placement("hash", 0, 30, &map, 3).expect("dispatched");

        let uids_direct: Vec<u32> = direct.iter().map(|m| m.uid).collect();
        let uids_dispatched: Vec<u32> = dispatched.iter().map(|m| m.uid).collect();
        assert_eq!(uids_direct, uids_dispatched, "v3 dispatch must match");
    }

    #[test]
    fn test_straw2_weight_influence() {
        // Heavily-weighted miner should appear more often across many PGs
        let mut map = make_straw2_test_map(35, 35);
        let heavy_uid = 0;
        map.miners[0].weight = 1000; // 10x other miners

        let mut appearances = 0;
        for pg_id in 0..64 {
            let result = calculate_pg_placement_straw2(pg_id, 30, &map).expect("placement");
            if result.iter().any(|m| m.uid == heavy_uid) {
                appearances += 1;
            }
        }

        // With 30/35 slots and 10x weight, heavy miner should appear very often
        assert!(
            appearances > 50,
            "heavy miner appeared in {}/64 PGs, expected > 50",
            appearances
        );
    }

    /// Regression test for C1: shortfall redistribution.
    /// Cluster with families [1, 1, 3] miners, request 5.
    /// The two single-miner families can only contribute 1 each,
    /// so the 3-miner family must absorb the shortfall.
    /// `calculate_placement_for_stripe` and `placement_uids_for_stripe`
    /// must produce identical UID sets.
    #[test]
    fn test_shortfall_redistribution_matches() {
        // 5 miners across 3 families: A(1), B(1), C(3)
        let family_sizes = [("fam-a", 1), ("fam-b", 1), ("fam-c", 3)];
        let mut uid_counter = 0u32;
        let mut miners = Vec::new();
        for (fam, count) in &family_sizes {
            for _ in 0..*count {
                let sk = iroh::SecretKey::from_bytes(&[uid_counter as u8 + 1; 32]);
                miners.push(MinerNode {
                    uid: uid_counter,
                    weight: 100,
                    family_id: fam.to_string(),
                    endpoint: iroh::EndpointAddr::from(sk.public()),
                    ip_subnet: String::new(),
                    ip_address: None,
                    http_addr: format!("http://10.0.0.{}:3001", uid_counter),
                    public_key: format!("{:064x}", uid_counter),
                    total_storage: 1_000_000,
                    available_storage: 500_000,
                    strikes: 0,
                    last_seen: 0,
                    heartbeat_count: 0,
                    registration_time: 0,
                    bandwidth_total: 0,
                    bandwidth_window_start: 0,
                    weight_manual_override: false,
                    reputation: 0.0,
                    consecutive_audit_passes: 0,
                    integrity_fails: 0,
                    version: String::new(),
                    base_weight: 0,
                    warden_challenges_total: 0,
                    warden_challenges_passed: 0,
                    fetch_timeout_count: 0,
                    expected_shards: 0,
                    actual_shards: 0,
                    trust_score: 0.0,
                    earned_capacity_bytes: 0,
                    draining: false,
                    p2p_reliability_score: 1.0,
                });
                uid_counter += 1;
            }
        }

        let map = ClusterMap {
            miners,
            pg_count: 64,
            ec_k: 10,
            ec_m: 20,
            ..ClusterMap::default()
        };

        let file_hash = "shortfall_test_hash";
        let count = 5;

        // V2 weighted: MinerNode vs UID-only must agree
        let full =
            calculate_placement_for_stripe(file_hash, 0, count, &map).expect("full placement");
        let uids = placement_uids_for_stripe(file_hash, 0, count, &map).expect("uid placement");

        assert_eq!(full.len(), count, "full placement returned wrong count");
        assert_eq!(uids.len(), count, "uid placement returned wrong count");

        let full_uids: Vec<u32> = full.iter().map(|m| m.uid).collect();
        assert_eq!(
            full_uids
                .iter()
                .copied()
                .collect::<std::collections::HashSet<u32>>(),
            uids.iter()
                .copied()
                .collect::<std::collections::HashSet<u32>>(),
            "V2 weighted: MinerNode and UID placements diverge on shortfall"
        );

        // Straw2: MinerNode vs UID-only must agree
        let full_s2 = calculate_placement_for_stripe_straw2(file_hash, 0, count, &map)
            .expect("straw2 full placement");
        let uids_s2 = placement_uids_for_stripe_straw2(file_hash, 0, count, &map)
            .expect("straw2 uid placement");

        assert_eq!(full_s2.len(), count, "straw2 full returned wrong count");
        assert_eq!(uids_s2.len(), count, "straw2 uid returned wrong count");

        let full_s2_uids: Vec<u32> = full_s2.iter().map(|m| m.uid).collect();
        assert_eq!(
            full_s2_uids
                .iter()
                .copied()
                .collect::<std::collections::HashSet<u32>>(),
            uids_s2
                .iter()
                .copied()
                .collect::<std::collections::HashSet<u32>>(),
            "Straw2: MinerNode and UID placements diverge on shortfall"
        );
    }

    // ====================================================================
    // Commitment selection tests
    // ====================================================================

    #[test]
    fn test_commitment_count_zero_shards() {
        assert_eq!(calculate_commitment_count(0), 0);
    }

    #[test]
    fn test_commitment_count_single_shard() {
        assert_eq!(calculate_commitment_count(1), 1);
    }

    #[test]
    fn test_commitment_count_small_file_30_shards() {
        // 30 * 100 / 3840 = 0.78 -> ceil = 1, max(3,1) = 3, min(30,3) = 3
        assert_eq!(calculate_commitment_count(30), 3);
    }

    #[test]
    fn test_commitment_count_32mb_file_120_shards() {
        // 120 * 100 / 3840 = 3.125 -> ceil = 4, max(3,4) = 4, min(120,4) = 4
        assert_eq!(calculate_commitment_count(120), 4);
    }

    #[test]
    fn test_commitment_count_1gb_file_3840_shards() {
        // 3840 * 100 / 3840 = 100, max(3,100) = 100, min(3840,100) = 100
        assert_eq!(calculate_commitment_count(3840), 100);
    }

    #[test]
    fn test_commitment_count_2gb_file_7680_shards() {
        // 7680 * 100 / 3840 = 200, max(3,200) = 200, min(7680,200) = 200
        assert_eq!(calculate_commitment_count(7680), 200);
    }

    #[test]
    fn test_commitment_count_tiny_file_2_shards() {
        // 2 * 100 / 3840 = 0.05 -> ceil = 1, max(3,1) = 3, min(2,3) = 2
        assert_eq!(calculate_commitment_count(2), 2);
    }

    #[test]
    fn test_commitment_selection_seed_deterministic() {
        let s1 = commitment_selection_seed("abc123");
        let s2 = commitment_selection_seed("abc123");
        assert_eq!(s1, s2);
    }

    #[test]
    fn test_commitment_selection_seed_different_files() {
        let s1 = commitment_selection_seed("file_a");
        let s2 = commitment_selection_seed("file_b");
        assert_ne!(s1, s2);
    }

    #[test]
    fn test_select_commitment_indices_deterministic() {
        let i1 = select_commitment_indices("hash123", 3840);
        let i2 = select_commitment_indices("hash123", 3840);
        assert_eq!(i1, i2);
    }

    #[test]
    fn test_select_commitment_indices_correct_count() {
        let indices = select_commitment_indices("hash123", 3840);
        assert_eq!(indices.len(), 100);
    }

    #[test]
    fn test_select_commitment_indices_in_range() {
        let total = 3840;
        let indices = select_commitment_indices("hash_abc", total);
        for &idx in &indices {
            assert!(idx < total, "index {idx} out of range [0, {total})");
        }
    }

    #[test]
    fn test_select_commitment_indices_empty_for_zero() {
        let indices = select_commitment_indices("hash", 0);
        assert!(indices.is_empty());
    }

    #[test]
    fn test_select_commitment_indices_small_file() {
        let indices = select_commitment_indices("small", 30);
        assert_eq!(indices.len(), 3);
        for &idx in &indices {
            assert!(idx < 30);
        }
    }
}

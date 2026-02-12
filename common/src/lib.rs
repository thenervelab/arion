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
//! Arion supports two placement versions (controlled by `FileManifest.placement_version`):
//!
//! - **Version 1 (legacy)**: Per-stripe CRUSH with seed = `hash(file_hash + stripe_index)`
//! - **Version 2 (PG-based)**: File → PG mapping, then CRUSH on PG ID with stripe rotation
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
        Self {
            epoch: 0,
            miners: Vec::new(),
            pg_count: default_pg_count(),
            ec_k: default_ec_k(),
            ec_m: default_ec_m(),
        }
    }

    /// Ensure critical placement parameters are never zero.
    /// Call after deserialization from untrusted sources.
    pub fn ensure_defaults(&mut self) {
        if self.pg_count == 0 {
            self.pg_count = default_pg_count();
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
    /// Shard index within the stripe (0 to k+m-1)
    pub index: usize,
    /// BLAKE3 hash of the shard data (used for content addressing and verification)
    pub blob_hash: String,
    /// Miner UID where shard was originally stored (optional, for debugging/migration)
    #[serde(default)]
    pub miner_uid: Option<u32>,
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
#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct FileManifest {
    /// BLAKE3 hash of the original file (64 hex characters)
    pub file_hash: String,
    /// Placement algorithm version for shard location calculation:
    /// - 1: legacy per-stripe CRUSH (seed = hash(file_hash + stripe_index))
    /// - 2: PG-based placement (file → PG → CRUSH with stripe rotation)
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

/// Configuration for Reed-Solomon erasure coding stripes.
///
/// Files are split into fixed-size stripes, each independently erasure-coded
/// into k data shards + m parity shards. Any k shards can reconstruct the stripe.
///
/// # Default Configuration
///
/// - `size`: 2 MiB per stripe
/// - `k`: 10 data shards
/// - `m`: 20 parity shards
///
/// This provides 66% fault tolerance (can lose 20 of 30 shards and still reconstruct).
#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct StripeConfig {
    /// Stripe size in bytes (default: 2 MiB)
    pub size: u64,
    /// Number of data shards (minimum shards needed for reconstruction)
    pub k: usize,
    /// Number of parity shards (redundancy for fault tolerance)
    pub m: usize,
}

impl Default for StripeConfig {
    fn default() -> Self {
        Self {
            size: 2 * 1024 * 1024,
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
/// Sent over Iroh QUIC connections with bincode serialization.
#[derive(Serialize, Deserialize, Debug, Clone)]
pub enum MinerControlMessage {
    /// Store a shard (push from validator or pull from peer)
    Store {
        /// BLAKE3 hash of the shard data
        hash: String,
        /// For push (validator → miner): Some(blob_data)
        /// For pull (miner → miner): None
        data: Option<Vec<u8>>,
        /// For pull: Some(source_miner_id)
        /// For push: None
        source_miner: Option<String>,
    },
    /// Delete a shard by hash
    Delete {
        /// BLAKE3 hash of the shard to delete
        hash: String,
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
    },
    /// Query files in a Placement Group (Miner → Validator)
    QueryPgFiles {
        /// Placement Group ID to query
        pg_id: u32,
    },
    /// Response containing files in a Placement Group
    PgFilesResponse {
        /// Placement Group ID this response is for
        pg_id: u32,
        /// List of file hashes belonging to this PG
        files: Vec<String>,
    },
    /// Instruct miner to pull a blob from a peer via Iroh P2P
    PullFromPeer {
        /// BLAKE3 hash of the blob to pull
        hash: String,
        /// Peer's EndpointAddr as JSON string
        peer_endpoint: String,
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
    },
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

            selected_miners.extend(miners_from_family);

            if selected_miners.len() >= count {
                break;
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

// ============================================================================
// P2P Protocol Constants (Hybrid Migration)
// ============================================================================

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
/// - DELETE /blobs/{hash} → `DeleteFile`
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
/// PG ID in range [0, pg_count). Returns 0 if pg_count is 0.
pub fn calculate_pg(file_hash: &str, pg_count: u32) -> u32 {
    // Guard against division by zero
    if pg_count == 0 {
        return 0;
    }
    let mut hasher = xxh3::Xxh3::new();
    hasher.write(file_hash.as_bytes());
    // Perform modulo before truncation to preserve full 64-bit entropy
    (hasher.finish() % (pg_count as u64)) as u32
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
    let pg_id = calculate_pg(file_hash, map.pg_count);
    let mut miners = calculate_pg_placement(pg_id, shards_per_stripe, map)?;

    if miners.is_empty() {
        return Err("No miners available for stripe placement".to_string());
    }

    // Rotate miner list by stripe_index for per-stripe spreading
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
/// * `placement_version` - Algorithm version (1=legacy, 2=PG-based)
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
        2 => calculate_pg_placement_for_stripe(file_hash, stripe_index, shards_per_stripe, map),
        _ => calculate_placement_for_stripe(file_hash, stripe_index, shards_per_stripe, map),
    }
}

/// Calculate which Placement Groups a miner is responsible for.
///
/// Used by miners during self-rebalancing to discover their workload.
/// This is an expensive operation (O(pg_count * placement_cost)) - cache results.
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
            calculate_pg_placement(pg_id, shards_per_file, map)
                .map(|miners| miners.iter().any(|m| m.uid == miner_uid))
                .unwrap_or(false)
        })
        .collect()
}

// ============================================================================
// Store Failure Helpers (CRUSH-aware replacement)
// ============================================================================

/// Create a copy of the cluster map with specified miners' weights zeroed out.
///
/// Used before CRUSH placement to exclude soft-banned miners without altering
/// the miner vec indices (critical for deterministic placement).
pub fn cluster_map_with_zeroed_miners(
    map: &ClusterMap,
    zero_uids: &std::collections::HashSet<u32>,
) -> ClusterMap {
    let mut cloned = map.clone();
    for miner in &mut cloned.miners {
        if zero_uids.contains(&miner.uid) {
            miner.weight = 0;
        }
    }
    cloned
}

/// Select a replacement miner for a failed shard distribution.
///
/// Performs weighted random selection from miners not in `excluded_uids` and with `weight > 0`.
/// The seed is non-deterministic (includes current timestamp) because replacement placement
/// doesn't need to be reproducible — the manifest records the actual miner assignment.
///
/// # Returns
/// `None` if all miners are excluded or have zero weight.
pub fn select_replacement_miner(
    map: &ClusterMap,
    excluded_uids: &std::collections::HashSet<u32>,
    file_hash: &str,
    shard_index: usize,
) -> Option<MinerNode> {
    let candidates: Vec<&MinerNode> = map
        .miners
        .iter()
        .filter(|m| m.weight > 0 && !excluded_uids.contains(&m.uid))
        .collect();

    if candidates.is_empty() {
        return None;
    }

    // Non-deterministic seed: file_hash + shard_index + timestamp
    let mut hasher = xxh3::Xxh3::new();
    hasher.write(file_hash.as_bytes());
    hasher.write_usize(shard_index);
    hasher.write_u64(now_secs());
    let seed = hasher.finish();

    // Weighted random selection
    let total_weight: u64 = candidates.iter().map(|m| m.weight as u64).sum();
    if total_weight == 0 {
        return None;
    }
    let target = seed % total_weight;
    let mut cumulative: u64 = 0;
    for candidate in &candidates {
        cumulative += candidate.weight as u64;
        if target < cumulative {
            return Some((*candidate).clone());
        }
    }

    // Fallback (should not happen due to modulo arithmetic)
    Some((*candidates.last().unwrap()).clone())
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
    if let Ok(ip) = host.parse::<std::net::IpAddr>() {
        if !ip.is_loopback() {
            return Some(ip.to_string());
        }
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
/// With 50 shards per miner and max_shards=50,000, supports up to 1000 miners.
/// Lower shard count per miner = more miners supported on the network.
pub const DEFAULT_SHARDS_PER_MINER_PER_EPOCH: usize = 50;

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
pub const P2P_CONNECTION_TTL_SECS: u64 = 60;

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
    send.write_all(data).await?;
    send.flush().await?;
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

/// Default Hippius relay URL - used when IROH_RELAY_URL is not set.
pub const DEFAULT_RELAY_URL: &str = "https://relay.hippius.com";

/// Maximum retries for initial endpoint binding.
pub const ENDPOINT_BIND_MAX_RETRIES: u32 = 3;

/// Initial backoff for endpoint bind retry (milliseconds).
pub const ENDPOINT_BIND_INITIAL_BACKOFF_MS: u64 = 500;

/// Time to wait for relay connection after successful bind (seconds).
pub const RELAY_CONNECTION_WAIT_SECS: u64 = 5;

/// Load relay URL from environment variable or config, falling back to default.
///
/// Priority: config value > IROH_RELAY_URL env var > DEFAULT_RELAY_URL
pub fn get_relay_url(config_url: Option<&str>) -> iroh_base::RelayUrl {
    config_url
        .and_then(|s| s.parse().ok())
        .or_else(|| {
            std::env::var("IROH_RELAY_URL")
                .ok()
                .and_then(|s| s.parse().ok())
        })
        .unwrap_or_else(|| DEFAULT_RELAY_URL.parse().expect("valid default relay URL"))
}

/// Build RelayMode::Custom with the given URL using consistent RelayMap pattern.
///
/// This ensures all components use the same relay configuration pattern.
pub fn build_relay_mode(url: &iroh_base::RelayUrl) -> iroh::endpoint::RelayMode {
    let relay_config = iroh::RelayConfig {
        url: url.clone(),
        quic: None,
    };
    iroh::endpoint::RelayMode::Custom(iroh::RelayMap::from_iter([relay_config]))
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
    /// Connection TTL in seconds
    connection_ttl_secs: u64,
    /// Counter for unhealthy connections detected (for metrics)
    unhealthy_connections: std::sync::Arc<std::sync::atomic::AtomicU64>,
}

impl Clone for P2pConnectionManager {
    fn clone(&self) -> Self {
        Self {
            endpoint: self.endpoint.clone(),
            target_node_id: self.target_node_id.clone(),
            alpn: self.alpn,
            connection: self.connection.clone(),
            connection_ttl_secs: self.connection_ttl_secs,
            unhealthy_connections: self.unhealthy_connections.clone(),
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
            connection_ttl_secs: P2P_CONNECTION_TTL_SECS,
            unhealthy_connections: std::sync::Arc::new(std::sync::atomic::AtomicU64::new(0)),
        }
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
    pub async fn get_connection(&self) -> anyhow::Result<iroh::endpoint::Connection> {
        use std::sync::atomic::Ordering;
        use tracing::{debug, warn};

        let now = now_secs();

        // Check if we have a valid cached connection
        {
            let conn_guard = self.connection.read().await;
            if let Some((conn, last_used)) = conn_guard.as_ref() {
                if now.saturating_sub(*last_used) < self.connection_ttl_secs {
                    // Connection is still valid - verify it's healthy
                    if conn.close_reason().is_none() {
                        debug!(
                            target = %self.target_node_id,
                            conn_id = conn.stable_id(),
                            "Reusing cached P2P connection"
                        );
                        return Ok(conn.clone());
                    }
                    // Connection is unhealthy - track and log
                    self.unhealthy_connections.fetch_add(1, Ordering::Relaxed);
                    warn!(
                        target = %self.target_node_id,
                        conn_id = conn.stable_id(),
                        reason = ?conn.close_reason(),
                        "Cached P2P connection is unhealthy, will reconnect"
                    );
                }
            }
        }

        // Need to create a new connection
        let mut conn_guard = self.connection.write().await;

        // Double-check after acquiring write lock (another task may have connected)
        if let Some((conn, last_used)) = conn_guard.as_ref() {
            if now.saturating_sub(*last_used) < self.connection_ttl_secs
                && conn.close_reason().is_none()
            {
                debug!(
                    target = %self.target_node_id,
                    conn_id = conn.stable_id(),
                    "Reusing cached P2P connection (after lock)"
                );
                return Ok(conn.clone());
            }
        }

        // Create new connection with exponential backoff retries
        let mut last_error = None;
        for attempt in 0..=P2P_MAX_CONNECT_RETRIES {
            if attempt > 0 {
                // Calculate backoff: 100ms, 200ms, 400ms, ... capped at 5s
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

            match tokio::time::timeout(
                std::time::Duration::from_secs(P2P_DEFAULT_TIMEOUT_SECS),
                self.endpoint
                    .connect(self.target_node_id.clone(), self.alpn),
            )
            .await
            {
                Ok(Ok(conn)) => {
                    debug!(
                        target = %self.target_node_id,
                        conn_id = conn.stable_id(),
                        "P2P connection established"
                    );
                    *conn_guard = Some((conn.clone(), now));
                    return Ok(conn);
                }
                Ok(Err(e)) => {
                    warn!(
                        target = %self.target_node_id,
                        attempt = attempt,
                        error = %e,
                        "P2P connection failed"
                    );
                    last_error = Some(anyhow::anyhow!("Failed to connect: {}", e));
                }
                Err(_) => {
                    warn!(
                        target = %self.target_node_id,
                        attempt = attempt,
                        "P2P connection timed out"
                    );
                    last_error = Some(anyhow::anyhow!("Connection timeout"));
                }
            }
        }

        Err(last_error.unwrap_or_else(|| anyhow::anyhow!("Failed to connect after retries")))
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
        };
        let bytes = serde_json::to_vec(&response).unwrap();
        let decoded: SubmitterControlMessage = serde_json::from_slice(&bytes).unwrap();
        match decoded {
            SubmitterControlMessage::NetworkStatsResponse {
                total_files,
                miner_stats,
                bandwidth_stats,
            } => {
                assert_eq!(total_files, 100);
                assert_eq!(miner_stats.get("42"), Some(&[1024u64, 10u64]));
                assert_eq!(bandwidth_stats.get("42"), Some(&2048u64));
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
        assert_eq!(GATEWAY_CONTROL_ALPN, b"hippius/gateway-control");
        assert_eq!(WARDEN_CONTROL_ALPN, b"hippius/warden-control");
        assert_eq!(SUBMITTER_CONTROL_ALPN, b"hippius/submitter-control");

        // Verify they are distinct
        assert_ne!(GATEWAY_CONTROL_ALPN, WARDEN_CONTROL_ALPN);
        assert_ne!(GATEWAY_CONTROL_ALPN, SUBMITTER_CONTROL_ALPN);
        assert_ne!(WARDEN_CONTROL_ALPN, SUBMITTER_CONTROL_ALPN);
    }

    /// Helper: create a MinerNode with a deterministic endpoint from the UID.
    fn test_miner(uid: u32, weight: u32) -> MinerNode {
        let mut seed = [0u8; 32];
        seed[0..4].copy_from_slice(&uid.to_le_bytes());
        let secret_key = iroh::SecretKey::from_bytes(&seed);
        let public_key = secret_key.public();
        let endpoint = iroh::EndpointAddr::from(public_key);
        MinerNode {
            uid,
            endpoint,
            weight,
            ip_subnet: String::new(),
            ip_address: None,
            http_addr: String::new(),
            public_key: String::new(),
            total_storage: 0,
            available_storage: 0,
            family_id: String::new(),
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
        }
    }

    #[test]
    fn test_cluster_map_with_zeroed_miners() {
        let mut map = ClusterMap::new();
        map.miners = vec![test_miner(1, 100), test_miner(2, 200), test_miner(3, 300)];

        let zero_uids: std::collections::HashSet<u32> = [2].into_iter().collect();
        let zeroed = cluster_map_with_zeroed_miners(&map, &zero_uids);

        assert_eq!(zeroed.miners[0].weight, 100, "UID 1 should be unchanged");
        assert_eq!(zeroed.miners[1].weight, 0, "UID 2 should be zeroed");
        assert_eq!(zeroed.miners[2].weight, 300, "UID 3 should be unchanged");
        // Original map should be unmodified
        assert_eq!(map.miners[1].weight, 200);
    }

    #[test]
    fn test_select_replacement_excludes_banned() {
        let mut map = ClusterMap::new();
        map.miners = vec![test_miner(1, 100), test_miner(2, 100), test_miner(3, 100)];

        let excluded: std::collections::HashSet<u32> = [1, 3].into_iter().collect();
        // Run multiple times to cover randomness
        for i in 0..20 {
            let result = select_replacement_miner(&map, &excluded, "filehash", i);
            let replacement = result.expect("Should find miner 2");
            assert_eq!(replacement.uid, 2, "Only non-excluded miner is UID 2");
        }
    }

    #[test]
    fn test_select_replacement_none_when_all_excluded() {
        let mut map = ClusterMap::new();
        map.miners = vec![test_miner(1, 100), test_miner(2, 100)];

        let excluded: std::collections::HashSet<u32> = [1, 2].into_iter().collect();
        let result = select_replacement_miner(&map, &excluded, "filehash", 0);
        assert!(result.is_none(), "No candidates when all excluded");
    }

    #[test]
    fn test_select_replacement_none_when_all_zero_weight() {
        let mut map = ClusterMap::new();
        map.miners = vec![test_miner(1, 0), test_miner(2, 0)];

        let excluded: std::collections::HashSet<u32> = std::collections::HashSet::new();
        let result = select_replacement_miner(&map, &excluded, "filehash", 0);
        assert!(result.is_none(), "No candidates when all have zero weight");
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
}

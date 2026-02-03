//! Application state and type definitions for the validator.
//!
//! This module defines the core state types used throughout the validator:
//!
//! - `AppState`: Central application state shared across HTTP handlers and background tasks
//! - `Blacklist`: Node and family banning for security
//! - `CooldownList`: Temporary rate limiting after failures
//! - `PgRebalanceStatus`: Tracks placement group migration progress
//!
//! # Concurrency Model
//!
//! The validator uses lock-free data structures for high concurrency:
//! - `DashMap` for frequently accessed concurrent state (pg_index, rate_limits, miner_latency)
//! - `QuickCache` for bounded LRU caches (repair_hint_dedupe, manifest_cache)
//! - `RwLock` for cluster_map and connection_pool (allows concurrent reads)
//! - `Mutex` for map_lock and queues (sequential operations)
//!
//! # Lock Ordering
//!
//! When acquiring multiple locks, follow this order to prevent deadlocks:
//! 1. `cluster_map` (RwLock)
//! 2. `map_lock` (Mutex)
//! 3. Other locks as needed

// Some types and methods are reserved for future use
#![allow(dead_code)]
#![allow(clippy::type_complexity)]

use crate::chain_registry;
use crate::constants::CACHE_MAX_ENTRIES;
use crate::families;
use crate::metrics;
use crate::upload_progress::SharedUploadProgressStore;
use common::{ClusterMap, FileSummary, now_secs};
use dashmap::DashMap;
use iroh::Endpoint;
use iroh_docs::api::Doc;
use iroh_docs::engine::Engine;
use quick_cache::sync::Cache as QuickCache;
use serde::{Deserialize, Serialize};
use std::collections::{HashMap, VecDeque};
use std::sync::Arc;
use std::sync::atomic::{AtomicU8, Ordering};
use tokio::sync::{Mutex, RwLock, Semaphore};

// ============================================================================
// Ready State
// ============================================================================

/// Validator startup readiness state.
///
/// The validator goes through these states during startup:
/// 1. `WarmingUp`: P2P is up, but storage is still loading
/// 2. `IndexingInProgress`: Storage loaded, building sync index and PG index
/// 3. `Ready`: Fully operational, can handle all requests
///
/// During WarmingUp and IndexingInProgress, some operations are restricted:
/// - GetClusterMap: Always allowed (in-memory)
/// - GetManifest, Upload, Delete: Blocked until Ready
/// - Ping, Heartbeat: Always allowed for health checks
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
#[repr(u8)]
pub enum ValidatorReadyState {
    /// P2P is up, storage loading
    #[default]
    WarmingUp = 0,
    /// Storage loaded, index building
    IndexingInProgress = 1,
    /// Fully operational
    Ready = 2,
}

impl ValidatorReadyState {
    /// Convert from u8 (for AtomicU8 operations)
    pub fn from_u8(value: u8) -> Self {
        match value {
            0 => ValidatorReadyState::WarmingUp,
            1 => ValidatorReadyState::IndexingInProgress,
            2 => ValidatorReadyState::Ready,
            _ => ValidatorReadyState::WarmingUp,
        }
    }

    /// Check if the validator is ready for full operations
    pub fn is_ready(&self) -> bool {
        *self == ValidatorReadyState::Ready
    }

    /// Check if the validator can serve read-only operations (cluster map, etc.)
    pub fn can_serve_readonly(&self) -> bool {
        // Can serve readonly once storage is at least loaded
        matches!(
            self,
            ValidatorReadyState::IndexingInProgress | ValidatorReadyState::Ready
        )
    }

    /// Human-readable status string
    pub fn status_str(&self) -> &'static str {
        match self {
            ValidatorReadyState::WarmingUp => "warming_up",
            ValidatorReadyState::IndexingInProgress => "indexing",
            ValidatorReadyState::Ready => "ready",
        }
    }
}

// ============================================================================
// Security Types
// ============================================================================

/// Blacklist for permanently banned nodes and families.
///
/// Banned entities are excluded from shard placement and rejected during registration.
/// Used for security enforcement against malicious or unreliable nodes.
#[derive(Serialize, Deserialize, Default, Clone, Debug)]
pub struct Blacklist {
    /// Banned node IDs (P2P public keys)
    pub banned_nodes: Vec<String>,
    /// Banned family IDs (failure domain identifiers)
    pub banned_families: Vec<String>,
}

impl Blacklist {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn is_banned(&self, node_id: &str, family_id: &str) -> bool {
        self.banned_nodes.iter().any(|n| n == node_id)
            || self.banned_families.iter().any(|f| f == family_id)
    }

    #[allow(dead_code)]
    pub fn add_ban(&mut self, node_id: String, family_id: String) {
        if !self.banned_nodes.contains(&node_id) {
            self.banned_nodes.push(node_id);
        }
        if !self.banned_families.contains(&family_id) {
            self.banned_families.push(family_id);
        }
    }
}

/// Temporary cooldown list for rate-limiting nodes after failures.
///
/// Unlike the blacklist, cooldowns expire automatically after a configurable duration.
/// Used for temporary exclusion after transient failures (network issues, timeouts).
#[derive(Serialize, Deserialize, Default, Clone, Debug)]
pub struct CooldownList {
    /// Node ID → expiry timestamp (Unix seconds)
    pub cooldowns: HashMap<String, u64>,
}

impl CooldownList {
    pub fn new() -> Self {
        Self::default()
    }

    #[allow(dead_code)]
    pub fn add_cooldown(&mut self, node_id: String, duration_secs: u64) {
        let expiry = now_secs() + duration_secs;
        self.cooldowns.insert(node_id, expiry);
    }

    #[allow(dead_code)]
    pub fn is_in_cooldown(&self, node_id: &str) -> bool {
        self.cooldowns
            .get(node_id)
            .is_some_and(|expiry| now_secs() < *expiry)
    }

    #[allow(dead_code)]
    pub fn cleanup(&mut self) {
        let now = now_secs();
        self.cooldowns.retain(|_, expiry| *expiry > now);
    }
}

/// Request from gateway to repair a specific file region.
///
/// Gateways send repair hints when they detect missing or corrupted shards
/// during downloads. The validator deduplicates and processes these asynchronously.
#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct RepairHintRequest {
    /// BLAKE3 hash of the file needing repair
    pub file_hash: String,
    /// First stripe index to repair
    pub stripe_idx: u64,
    /// Number of stripes to repair starting at stripe_idx (defaults to small batch)
    pub count: Option<usize>,
    /// Allow full file scan as fallback (validator may ignore unless enabled)
    pub allow_scan: Option<bool>,
}

/// Metadata for paginated PG index stored in iroh-docs.
///
/// Each Placement Group has an index of file hashes, paginated for scalability.
#[derive(Serialize, Deserialize, Clone, Debug, Default)]
pub struct PgIndexMeta {
    /// Highest page number with data (0-indexed)
    pub last_page: u32,
    /// Total file count across all pages
    pub total_files: u64,
}

/// Page size for PG index entries
pub const PG_INDEX_PAGE_SIZE: usize = 1000;

// ============================================================================
// Rebalance Status Tracking
// ============================================================================

/// Status of rebalance for a specific (epoch, pg_id) pair
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PgRebalanceStatus {
    pub epoch: u64,
    pub pg_id: u32,
    pub total_shards: usize,
    pub confirmed_shards: usize,
    pub started_at: u64,
    pub settled_at: Option<u64>, // None = in progress
    /// Number of files expected to be processed for this PG (set when rebalance starts)
    #[serde(default)]
    pub expected_files: usize,
    /// Number of files that have completed processing (incremented per-file)
    #[serde(default)]
    pub processed_files: usize,
}

impl PgRebalanceStatus {
    pub fn is_settled(&self) -> bool {
        self.settled_at.is_some()
    }
}

/// Generate key for PG index metadata
pub fn pg_index_meta_key(pg_id: u32) -> Vec<u8> {
    format!("pg_index:meta:{}", pg_id).into_bytes()
}

/// Generate key for PG index page
pub fn pg_index_page_key(pg_id: u32, page: u32) -> Vec<u8> {
    format!("pg_index:pg:{}:page:{}", pg_id, page).into_bytes()
}

// ============================================================================
// Application State
// ============================================================================

/// Central application state shared across HTTP handlers and background tasks.
///
/// This struct holds all shared mutable state for the validator. It uses a mix of
/// lock-free and locked data structures optimized for the access patterns of each field.
///
/// # Cloning
///
/// AppState is not Clone - it should be wrapped in `Arc<AppState>` and shared.
/// All interior fields use appropriate synchronization primitives.
///
/// # Initialization
///
/// AppState is constructed in `main()` after loading configuration and initializing
/// the Iroh endpoint and iroh-docs engine.
///
/// # Ready State
///
/// The validator uses a `ready_state` field (AtomicU8) to track startup progress.
/// During startup, some operations are restricted until the validator is fully ready.
/// Use `get_ready_state()` and `set_ready_state()` helper methods for type-safe access.
pub struct AppState {
    // ---- Ready state for graceful degradation during startup ----
    /// Startup readiness state (0=WarmingUp, 1=IndexingInProgress, 2=Ready)
    /// Uses AtomicU8 for lock-free reads in hot paths
    pub ready_state: AtomicU8,

    pub doc: Doc,
    pub blobs_store: iroh_blobs::store::fs::FsStore,
    pub author_id: iroh_docs::AuthorId,
    pub endpoint: Endpoint,
    pub _docs_engine: Arc<Engine>,
    pub map_lock: Mutex<()>,
    pub manifest_hashes: Arc<Mutex<Vec<FileSummary>>>,
    /// PG index: pg_id -> list of file hashes (for scalable rebalancing queries)
    /// Uses DashMap for lock-free concurrent access
    pub pg_index: Arc<DashMap<u32, Vec<String>>>,
    /// Rate limiter: public_key -> last_message_timestamp
    /// Uses DashMap for lock-free concurrent access
    pub rate_limits: Arc<DashMap<String, u64>>,
    /// Relay URL for P2P connectivity
    pub relay_url: Option<iroh_base::RelayUrl>,
    /// P2P connection pool: miner_uid -> (Connection, last_used_timestamp)
    /// Uses RwLock for consistency with gateway/miner (allows concurrent reads)
    pub connection_pool: Arc<RwLock<HashMap<u32, (iroh::endpoint::Connection, u64)>>>,
    /// In-memory cluster map for fast access during uploads (avoids iroh-docs read latency)
    pub cluster_map: Arc<RwLock<ClusterMap>>,
    /// Family registry for miner verification
    pub family_registry: Arc<families::FamilyRegistry>,
    /// On-chain registry cache (pallet-arion) for deriving family_id deterministically.
    pub chain_registry: Arc<chain_registry::ChainRegistry>,
    /// Persistent upload progress tracking
    pub upload_progress: SharedUploadProgressStore,
    /// Prometheus Metrics
    pub metrics: metrics::Metrics,
    /// Concurrency Limiter for Processing (RS Encoding)
    pub processing_semaphore: Arc<Semaphore>,
    /// Rebalance coordinator: last epoch we've enqueued PG rebalance work for
    pub rebalance_last_epoch: Arc<Mutex<u64>>,
    /// Queue of PG IDs to process for the current rebalance window
    pub rebalance_queue: Arc<Mutex<VecDeque<u32>>>,

    // ---- Automatic "repair hint" queue (gateway -> validator) ----
    pub repair_hint_enabled: bool,
    pub repair_hint_queue_max: usize,
    pub repair_hint_concurrency: usize,
    pub repair_hint_default_count: usize,
    pub repair_hint_dedupe_ttl_secs: u64,
    /// Dedup cache key: "{file_hash}:{stripe_idx}" -> (last_seen_epoch_secs, allow_scan, count)
    /// Uses bounded QuickCache to prevent unbounded memory growth (max 10,000 entries)
    pub repair_hint_dedupe: Arc<QuickCache<String, (u64, bool, usize)>>,
    /// Queue: (file_hash, start_stripe, count_stripes, allow_scan)
    pub repair_hint_queue: Arc<Mutex<VecDeque<(String, usize, usize, bool)>>>,

    // ---- Backpressure / rebuild tuning (loaded from config/env) ----
    pub rebuild_enabled: bool,
    pub rebuild_tick_secs: u64,
    pub rebuild_files_per_tick: usize,
    pub rebuild_stripes_per_file: usize,
    pub rebuild_concurrency: usize,
    pub miner_out_threshold_secs: u64,

    // ---- Upload redundancy requirements ----
    /// Minimum shards above k that must succeed for upload (0 = accept k minimum)
    pub upload_min_redundancy_buffer: usize,

    // ---- Placement weight update tuning (loaded from config/env) ----
    pub weight_update_enabled: bool,
    pub weight_update_tick_secs: u64,
    pub weight_update_min_change_pct: u32,

    // ---- Cached expensive endpoints (network-stats) ----
    pub network_stats_cache_secs: u64,
    pub network_stats_cache: Arc<RwLock<Option<(u64, bytes::Bytes)>>>,

    // ---- Manifest cache (reduces disk I/O on repeated manifest reads) ----
    /// LRU cache for manifests: file_hash -> (manifest JSON string, cached_at_timestamp)
    /// Tombstones ("DELETED") expire after manifest_cache_tombstone_ttl_secs
    pub manifest_cache: Arc<QuickCache<String, (String, u64)>>,
    /// TTL for "DELETED" tombstones in manifest cache (seconds)
    pub manifest_cache_tombstone_ttl_secs: u64,

    // ---- Miner latency tracking (gateway pattern) ----
    /// EMA-based latency tracking: miner_uid -> avg_latency_ms (for smart routing decisions)
    pub miner_latency: Arc<DashMap<u32, f64>>,

    // ---- Rebalance status tracking (for pure CRUSH-based downloads) ----
    /// Rebalance status tracking: (epoch, pg_id) -> status
    /// DashMap for lock-free concurrent access
    pub rebalance_status: Arc<DashMap<(u64, u32), PgRebalanceStatus>>,

    /// Pending ACKs: (epoch, pg_id, shard_hash) -> miner_uid
    /// Tracks which shards we're waiting for confirmation
    pub rebalance_pending_acks: Arc<DashMap<(u64, u32, String), u32>>,

    // ---- Warden (Proof-of-Storage audit) integration ----
    /// Optional Warden client for pushing shard commitments
    pub warden_client: Option<Arc<crate::warden_client::WardenClient>>,
    /// Audit epoch duration in seconds for shard sampling
    pub audit_epoch_secs: u64,
    /// Number of shards to sample per miner per epoch
    pub shards_per_miner_per_epoch: usize,
    /// Validator node ID for deterministic epoch sampling seed
    pub validator_node_id: String,

    // ---- Reputation system (warden audit results) ----
    /// Reputation processor for handling warden audit results
    pub reputation_processor: Arc<crate::reputation::ReputationProcessor>,

    // ---- Attestation aggregation (epoch bundling) ----
    /// Aggregates warden attestations for merkle tree bundling at epoch boundaries
    pub attestation_aggregator: Arc<crate::attestation_aggregator::AttestationAggregator>,
    /// Gateway URL for uploading attestation bundles to Arion
    pub gateway_url: Option<String>,
    /// Chain-submitter P2P connection manager for sending commitments
    pub submitter_connection_manager: Option<Arc<common::P2pConnectionManager>>,
}

impl AppState {
    /// Create default QuickCache instances for the state
    pub fn new_repair_hint_dedupe() -> Arc<QuickCache<String, (u64, bool, usize)>> {
        Arc::new(QuickCache::new(CACHE_MAX_ENTRIES))
    }

    pub fn new_manifest_cache() -> Arc<QuickCache<String, (String, u64)>> {
        Arc::new(QuickCache::new(CACHE_MAX_ENTRIES))
    }

    /// Get the current ready state (lock-free)
    ///
    /// Uses `Ordering::Acquire` to synchronize with `set_ready_state` which uses `Ordering::Release`.
    /// This ensures that when a thread observes a state transition (e.g., to `Ready`),
    /// it also observes all the data that was written before the transition (indexes, etc.).
    #[inline]
    pub fn get_ready_state(&self) -> ValidatorReadyState {
        ValidatorReadyState::from_u8(self.ready_state.load(Ordering::Acquire))
    }

    /// Set the ready state (lock-free)
    ///
    /// Uses `Ordering::Release` to ensure all prior writes (indexes, caches) are visible
    /// to threads that subsequently observe this state change via `get_ready_state`.
    #[inline]
    pub fn set_ready_state(&self, state: ValidatorReadyState) {
        self.ready_state.store(state as u8, Ordering::Release);
    }

    /// Check if the validator is fully ready for all operations
    #[inline]
    pub fn is_ready(&self) -> bool {
        self.get_ready_state().is_ready()
    }

    /// Check if the validator can serve read-only operations
    #[inline]
    pub fn can_serve_readonly(&self) -> bool {
        self.get_ready_state().can_serve_readonly()
    }
}

// ============================================================================
// Epoch-Based Shard Sampling
// ============================================================================

/// Shard commitment tuple: (shard_hash, merkle_root, chunk_count, miner_uid, miner_endpoint)
pub type ShardCommitment = (String, [u32; 8], u32, u32, iroh::EndpointAddr);

/// Sample shards for warden audit using deterministic epoch-based selection.
///
/// This function takes a list of shard commitments and samples a subset per miner
/// based on the current audit epoch. The sampling is deterministic: given the same
/// epoch, validator node ID, and miner shards, the same subset will always be selected.
///
/// # Arguments
/// * `commitments` - All shard commitments from the upload
/// * `epoch` - Current audit epoch number
/// * `validator_node_id` - Validator's node ID for seed generation
/// * `shards_per_miner` - Maximum shards to sample per miner per epoch
///
/// # Returns
/// A filtered list of commitments with at most `shards_per_miner` shards per miner.
pub fn sample_warden_commitments(
    commitments: &[ShardCommitment],
    epoch: u64,
    validator_node_id: &str,
    shards_per_miner: usize,
) -> Vec<ShardCommitment> {
    use std::collections::HashMap;

    if commitments.is_empty() || shards_per_miner == 0 {
        return Vec::new();
    }

    // Group commitments by miner UID (field index 3)
    let mut by_miner: HashMap<u32, Vec<&ShardCommitment>> = HashMap::new();
    for commitment in commitments {
        let (_shard_hash, _merkle_root, _chunk_count, miner_uid, _endpoint) = commitment;
        by_miner.entry(*miner_uid).or_default().push(commitment);
    }

    // Generate epoch sampling seed
    let base_seed = common::epoch_sampling_seed(epoch, validator_node_id);

    let mut sampled = Vec::new();

    for (miner_uid, miner_shards) in by_miner {
        if miner_shards.len() <= shards_per_miner {
            // If miner has fewer shards than the limit, keep all
            sampled.extend(miner_shards.into_iter().cloned());
        } else {
            // Generate miner-specific seed by combining base seed with miner UID
            // Use BLAKE3 for proper cryptographic mixing (XOR is too weak)
            let mut hasher = blake3::Hasher::new();
            hasher.update(&base_seed);
            hasher.update(&miner_uid.to_le_bytes());
            let miner_seed: [u8; 32] = *hasher.finalize().as_bytes();

            // Sample indices deterministically
            let indices = common::sample_indices(&miner_seed, miner_shards.len(), shards_per_miner);

            // Collect sampled shards
            sampled.extend(indices.into_iter().map(|idx| miner_shards[idx].clone()));
        }
    }

    sampled
}

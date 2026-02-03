//! Application state for the gateway.
//!
//! This module defines `AppState`, the central shared state for all HTTP handlers
//! and background tasks in the gateway.
//!
//! # Concurrency Model
//!
//! The gateway uses lock-free data structures for high throughput:
//! - `DashMap` for bandwidth_stats, miner_latency, miner_blacklist, rebalance_status_cache
//! - `quick_cache::Cache` for blob_cache (bounded LRU with 50k entries)
//! - `RwLock` for connection_pool (allows concurrent reads)
//! - `Mutex` for cluster_map and repair_hint_last_sent (sequential access)
//!
//! # Backpressure
//!
//! - `upload_semaphore`: Limits concurrent uploads (default 500)
//! - `download_global_semaphore`: Limits total FetchBlob tasks system-wide
//! - `download_request_parallelism`: Limits FetchBlob tasks per request

use crate::helpers::RebalanceStatusCache;
use crate::metrics::Metrics;
use common::{ClusterMap, MinerFailureReport};
use dashmap::DashMap;
use iroh::Endpoint;
use iroh_blobs::store::mem::MemStore;
use iroh_docs::api::Doc;
use quick_cache::sync::Cache;
use std::collections::{HashMap, VecDeque};
use std::sync::Arc;
use tokio::sync::Mutex;

/// Shared application state for all HTTP handlers and background tasks.
#[derive(Clone)]
#[allow(dead_code)]
pub struct AppState {
    pub endpoint: Endpoint,
    pub _store: MemStore,
    pub cluster_map: Arc<Mutex<ClusterMap>>,
    /// Recent cluster map history (latest maps first/last depending on insertion).
    /// Used for epoch-fallback reads during rebalancing.
    pub cluster_map_history: Arc<Mutex<Vec<ClusterMap>>>,
    pub bandwidth_stats: Arc<DashMap<String, u64>>,
    /// Tracks average latency per miner (uid -> avg latency in ms) - DashMap for lock-free access
    pub miner_latency: Arc<DashMap<u32, f64>>,
    pub miner_failures: Arc<Mutex<VecDeque<MinerFailureReport>>>,
    pub validator_url: String,
    /// In-memory blob cache (hash -> data) - LRU cache with bounded size
    pub blob_cache: Arc<Cache<String, Arc<Vec<u8>>>>,
    /// Prometheus Metrics
    pub metrics: Metrics,
    /// Concurrency Limiter for Uploads
    pub upload_semaphore: Arc<tokio::sync::Semaphore>,
    /// Global concurrency limiter for shard FetchBlob calls (all requests combined)
    pub download_global_semaphore: Arc<tokio::sync::Semaphore>,
    /// Max concurrent shard fetch tasks per download request
    pub download_request_parallelism: usize,
    /// Max time to wait for a global FetchBlob permit before skipping this candidate.
    /// If 0, wait indefinitely (bounded only by global semaphore capacity).
    pub download_permit_timeout_ms: u64,
    /// Connect timeout for miner-control FetchBlob
    pub fetch_connect_timeout_secs: u64,
    /// Read timeout for miner-control FetchBlob response
    pub fetch_read_timeout_secs: u64,
    /// Automatically send repair hints to validator when a stripe cannot be reconstructed.
    pub auto_repair_hint_enabled: bool,
    /// API key used to authenticate gateway -> validator repair hint calls
    pub validator_gateway_key: Option<String>,
    /// Dedup key -> last_sent_epoch_secs
    pub repair_hint_last_sent: Arc<Mutex<HashMap<String, u64>>>,
    /// Minimum seconds between repeated hints for same (file,stripe)
    pub repair_hint_min_interval_secs: u64,
    /// Default stripe count to request per hint (starting at stripe_idx)
    pub repair_hint_count: usize,
    /// Allow validator scan fallback for stranded legacy files (expensive; off by default)
    pub repair_hint_allow_scan: bool,
    /// Connection pool for P2P connections (miner_uid -> (connection, last_used_timestamp))
    pub connection_pool: Arc<tokio::sync::RwLock<HashMap<u32, (iroh::endpoint::Connection, u64)>>>,
    /// Temporary blacklist for Byzantine miners that served corrupted data.
    /// Key: (miner_uid, blob_hash), Value: blacklist_start_timestamp
    /// Entries expire after MINER_BLACKLIST_DURATION_SECS (5 minutes).
    pub miner_blacklist: Arc<DashMap<(u32, String), u64>>,

    // Optional local replica of validator doc (read-only) for manifest/map reads.
    // When present, gateway can serve reads even if validator HTTP is unavailable (paper-aligned).
    pub doc_replica: Option<Doc>,
    pub doc_replica_blobs: Option<iroh_blobs::store::fs::FsStore>,
    /// Shared HTTP client for connection pooling and reuse
    pub http_client: reqwest::Client,

    /// Cache of rebalance status: (epoch, pg_id) -> (settled, cached_at)
    /// Short TTL (30s) to balance freshness vs validator load
    /// DashMap for lock-free concurrent access
    pub rebalance_status_cache: Arc<RebalanceStatusCache>,

    /// P2P client for validator communication (None if USE_P2P=false or no VALIDATOR_NODE_ID)
    pub validator_p2p_client: Option<crate::validator_p2p::ValidatorP2pClient>,

    /// Whether to use P2P for validator communication
    pub use_p2p: bool,

    /// Whether to fall back to HTTP when P2P fails
    pub http_fallback: bool,
}

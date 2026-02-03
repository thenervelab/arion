//! Configuration constants and types for the gateway.
//!
//! This module defines compile-time constants used throughout the gateway.
//! Many values have corresponding environment variable overrides in `main.rs`.
//!
//! # Constant Categories
//!
//! - **P2P Communication**: FetchBlob size limits, connection pool TTL
//! - **Backpressure**: Queue limits, concurrent upload caps
//! - **Caching**: Blob cache sizing, rebalance status cache TTL
//! - **Latency Tracking**: EMA weights, failure penalties
//! - **Upload Retries**: Retry counts, backoff delays, timeouts
//! - **Security**: Miner blacklist duration for hash failures
//!
//! # Memory Budget
//!
//! Key memory-bound constants:
//! - `BLOB_CACHE_MAX_ENTRIES`: 50k entries × ~200KB = ~10GB max
//! - `MAX_FAILURE_REPORTS`: 10k entries × ~100B = ~1MB
//! - `MAX_REPAIR_HINT_ENTRIES`: 10k entries × ~100B = ~1MB

use common::LATENCY_EMA_ALPHA;
use serde::{Deserialize, Serialize};

// ============================================================================
// Constants
// ============================================================================

/// Maximum response size for FetchBlob (4 MiB)
/// Based on stripe config: default shard ~200KB (2MB stripe / 10 data shards)
/// 4MB provides safety margin for larger stripe configurations
pub const MAX_FETCH_RESPONSE_SIZE: usize = 4 * 1024 * 1024;

/// Connection time-to-live in seconds for P2P connection pool
pub const CONNECTION_TTL_SECS: u64 = 60;

/// Maximum connections before triggering pool cleanup
pub const CONNECTION_POOL_CLEANUP_THRESHOLD: usize = 1000;

/// Maximum failure reports to keep in bounded queue
pub const MAX_FAILURE_REPORTS: usize = 10_000;

/// Maximum repair hint entries before triggering eviction
pub const MAX_REPAIR_HINT_ENTRIES: usize = 10_000;

/// Duration to blacklist a miner for a specific blob after hash verification failure (seconds)
pub const MINER_BLACKLIST_DURATION_SECS: u64 = 300;

/// Maximum entries in miner blacklist to prevent unbounded memory growth.
/// Each entry is (miner_uid: u32, blob_hash: String) -> timestamp, ~100 bytes.
/// 100k entries ≈ 10MB max memory.
pub const MAX_MINER_BLACKLIST_ENTRIES: usize = 100_000;

/// Exponential moving average weight for existing latency (derived from common::LATENCY_EMA_ALPHA)
pub const LATENCY_EMA_OLD_WEIGHT: f64 = 1.0 - LATENCY_EMA_ALPHA;

/// Exponential moving average weight for new latency sample (from common crate)
pub const LATENCY_EMA_NEW_WEIGHT: f64 = LATENCY_EMA_ALPHA;

/// Penalty latency applied when fetch fails (ms)
pub const LATENCY_FAILURE_PENALTY: f64 = 2500.0;

/// Default latency for miners with no history (ms)
pub const LATENCY_DEFAULT: f64 = 5000.0;

/// Decay factor for latency on failure
pub const LATENCY_FAILURE_DECAY: f64 = 0.5;

/// Maximum cluster map history entries for epoch lookback
pub const MAX_CLUSTER_MAP_HISTORY: usize = 10;

/// TTL for rebalance status cache entries (seconds)
/// Short TTL balances freshness vs validator HTTP load
pub const REBALANCE_STATUS_CACHE_TTL_SECS: u64 = 30;

/// Maximum upload retry attempts before giving up
pub const UPLOAD_MAX_RETRIES: u32 = 5;

/// Base delay for upload retry backoff (milliseconds)
pub const UPLOAD_RETRY_BASE_DELAY_MS: u64 = 250;

/// Upload timeout for large files (1 hour)
pub const UPLOAD_TIMEOUT_SECS: u64 = 3600;

/// Maximum entries in blob cache (LRU eviction)
/// Each entry holds shard data (~200KB), so 50k entries ≈ 10GB max memory
pub const BLOB_CACHE_MAX_ENTRIES: usize = 50_000;

/// Maximum concurrent uploads before backpressure
pub const MAX_CONCURRENT_UPLOADS: usize = 500;

/// Request body for repair hint endpoint
#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct RepairHintRequest {
    pub file_hash: String,
    pub stripe_idx: u64,
    pub count: Option<usize>,
    pub allow_scan: Option<bool>,
}

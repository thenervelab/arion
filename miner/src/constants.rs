//! Constants for the miner.
//!
//! This module defines tuning constants for the miner's operation.
//! Many constants have corresponding environment variable overrides
//! in the `TuningConfig` struct.
//!
//! # Categories
//!
//! - **Orphan Management**: Grace periods and limits for orphan shard cleanup
//! - **Epoch Validation**: Bounds for cluster map epoch updates
//! - **Connection Pool**: TTL and sizing for P2P connection reuse
//! - **Caching**: Blob cache sizing for FetchBlob responses
//! - **Timeouts**: Connect and read timeouts for P2P operations
//! - **Backoff**: Exponential backoff parameters for retries
//! - **Buffer Sizes**: Message and response size limits

/// Grace period before deleting orphan shards (1 hour default)
pub const ORPHAN_GRACE_PERIOD_SECS: u64 = 3600;

/// Maximum number of orphan entries to track (prevents unbounded memory growth)
pub const MAX_ORPHAN_ENTRIES: usize = 100_000;

/// Maximum epoch jump to accept (prevents malformed updates)
pub const MAX_EPOCH_JUMP: u64 = 100;

/// Connection pool TTL in seconds.
/// Must match or exceed `max_idle_timeout` in transport config (120s)
/// to avoid evicting connections that QUIC still considers alive.
pub const CONNECTION_TTL_SECS: u64 = 120;

/// Blob cache size (number of entries)
pub const BLOB_CACHE_SIZE: usize = 10_000;

/// Maximum peer cache entries (prevents unbounded memory growth)
/// Based on typical cluster size: 10k miners should be more than enough
pub const MAX_PEER_CACHE_ENTRIES: usize = 10_000;

/// Default timeout constants (fallback if TuningConfig unavailable)
pub const DEFAULT_CONNECT_TIMEOUT_SECS: u64 = 20;
pub const DEFAULT_READ_TIMEOUT_SECS: u64 = 30;

/// Buffer sizes
/// 2MB to accommodate V1 JSON-encoded Store messages with larger shards
pub const MAX_MESSAGE_SIZE: usize = 2 * 1024 * 1024; // 2MB
/// Maximum raw shard data size for V2 binary framing (4 MiB).
/// Separate from MAX_MESSAGE_SIZE (which covers V1 JSON overhead).
/// Matches MAX_FETCH_RESPONSE_SIZE since both bound single-shard payloads.
pub const MAX_V2_DATA_SIZE: u64 = 4 * 1024 * 1024; // 4MB
/// Maximum FetchBlob response size (4 MiB)
/// Based on stripe config: default shard ~200KB (2MB stripe / 10 data shards)
pub const MAX_FETCH_RESPONSE_SIZE: usize = 4 * 1024 * 1024;

/// Maximum files to process per rebalance cycle (prevents memory exhaustion)
/// With ~30 shards/file and ~200KB/shard, 1000 files = ~6GB potential memory
pub const REBALANCE_MAX_FILES_PER_CYCLE: usize = 1000;

/// Maximum concurrent P2P stream handlers to prevent connection flood attacks.
/// This bounds task spawning in handle_miner_control() to prevent OOM.
/// Must exceed store_concurrency (1024) + pull + fetch + pos to avoid
/// Store operations starving FetchBlob and other handler types.
pub const MAX_CONCURRENT_HANDLERS: usize = 2048;

/// Maximum connection pool size (prevents unbounded growth between cleanups)
pub const MAX_CONNECTION_POOL_SIZE: usize = 500;

/// Maximum cluster_map_json size (10MB - prevents malicious large payloads)
/// Note: This is a secondary check. The primary limit is MAX_MESSAGE_SIZE (2MB) which
/// bounds the entire P2P message. This larger limit exists for future-proofing if
/// message structure changes or cluster maps are received via a different path.
pub const MAX_CLUSTER_MAP_JSON_SIZE: usize = 10 * 1024 * 1024;

/// Maximum batch PG response size (20MB - reduced from 50MB)
pub const MAX_BATCH_PG_RESPONSE_SIZE: usize = 20 * 1024 * 1024;

/// Maximum tag map entries (Hash -> Tag) for O(1) delete lookups
pub const MAX_TAG_MAP_ENTRIES: usize = 200_000;

/// PoS commitment cache size (number of entries, ~200KB each ≈ 20MB max)
pub const POS_COMMITMENT_CACHE_SIZE: usize = 100;

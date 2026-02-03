//! Constants for the validator.
//!
//! This module defines tuning constants for the validator's operation.
//! Many constants have corresponding environment variable overrides
//! in the configuration modules.
//!
//! # Categories
//!
//! - **Caching**: LRU cache sizing for manifests and repair hints
//! - **Rate Limiting**: Rate limit windows for miner registration
//! - **P2P**: Connection timeouts, ACK timeouts, retry delays
//! - **Memory Bounds**: Limits for manifest tracking to prevent OOM

/// Maximum entries in LRU caches (manifest cache, repair hint dedupe).
/// Bounds memory usage while providing good hit rates for typical workloads.
pub const CACHE_MAX_ENTRIES: usize = 10_000;

/// Rate limit window for miner registration (seconds between attempts).
pub const REGISTRATION_RATE_LIMIT_SECS: u64 = 10;

/// Maximum FetchBlob response size (4 MiB)
/// Based on stripe config: default shard ~200KB (2MB stripe / 10 data shards)
/// 4MB provides safety margin for larger stripe configurations
pub const MAX_FETCH_RESPONSE_SIZE: usize = 4 * 1024 * 1024;

/// Maximum files to track in manifest_hashes before warning.
/// Each FileSummary is ~100 bytes, so 1M files ≈ 100MB memory.
pub const MANIFEST_HASHES_WARN_THRESHOLD: usize = 500_000;

/// Hard limit for manifest_hashes to prevent unbounded memory growth.
/// Beyond this, new uploads will be rejected until files are deleted.
pub const MANIFEST_HASHES_MAX_ENTRIES: usize = 1_000_000;

/// Connection timeout for P2P miner connections (seconds)
pub const MINER_CONNECT_TIMEOUT_SECS: u64 = 15;

/// ACK timeout when waiting for miner acknowledgement (seconds)
pub const MINER_ACK_TIMEOUT_SECS: u64 = 10;

/// Retry delay between connection attempts (milliseconds)
pub const MINER_RETRY_DELAY_MS: u64 = 500;

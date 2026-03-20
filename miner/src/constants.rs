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
//! - **QUIC Transport**: Transport config for the QUIC endpoint
//! - **Registration & Heartbeat**: Registration retry and heartbeat exchange parameters
//! - **Retry & Backoff**: Jitter and backoff for registration, heartbeat, and failure recovery
//! - **Relay & Monitoring**: Relay health checks and validator address refresh
//! - **Rebalance**: Self-rebalance loop jitter and direct path waits
//! - **P2P Operations**: Timeouts and permits for shard store/pull/fetch
//! - **Rebalance Batch Operations**: Batch PG query and manifest fetch parameters
//! - **Miscellaneous**: Logging, version check, file permissions, connection pool eviction

// ============================================================================
// Epoch Validation
// ============================================================================

/// Maximum epoch jump to accept (prevents malformed updates)
pub const MAX_EPOCH_JUMP: u64 = 100;

// ============================================================================
// Connection Pool
// ============================================================================

/// Connection pool TTL in seconds.
/// Must match or exceed `max_idle_timeout` in transport config (120s)
/// to avoid evicting connections that QUIC still considers alive.
pub const CONNECTION_TTL_SECS: u64 = 120;

/// Maximum connection pool size (prevents unbounded growth between cleanups)
pub const MAX_CONNECTION_POOL_SIZE: usize = 500;

/// Default timeout for pooled connection direct-path wait (seconds)
pub const POOLED_CONN_DEFAULT_TIMEOUT_SECS: u64 = 30;

/// Fraction of pool entries to evict when at capacity (1/N of pool size)
pub const CONNECTION_POOL_EVICTION_FRACTION: usize = 10;

// ============================================================================
// Caching
// ============================================================================

/// Blob cache size (number of entries)
pub const BLOB_CACHE_SIZE: usize = 10_000;

/// Maximum peer cache entries (prevents unbounded memory growth)
/// Based on typical cluster size: 10k miners should be more than enough
pub const MAX_PEER_CACHE_ENTRIES: usize = 10_000;

/// PoS commitment cache size (number of entries, ~200KB each ≈ 20MB max)
pub const POS_COMMITMENT_CACHE_SIZE: usize = 100;

// ============================================================================
// Timeouts
// ============================================================================

/// Default timeout constants (fallback if TuningConfig unavailable)
pub const DEFAULT_CONNECT_TIMEOUT_SECS: u64 = 20;
pub const DEFAULT_READ_TIMEOUT_SECS: u64 = 30;

// ============================================================================
// Buffer Sizes
// ============================================================================

/// Maximum JSON control message size (2 MiB).
/// Intentionally larger than common::P2P_MAX_MESSAGE_SIZE (1 MiB) because
/// miners receive ClusterMapUpdate messages containing full cluster map JSON.
/// Covers non-Store messages (Delete, FetchBlob, ClusterMapUpdate, etc.)
/// and the StoreV2 JSON header within binary framing.
pub const MAX_MESSAGE_SIZE: usize = 2 * 1024 * 1024;
/// Maximum raw shard data size for binary store framing (4 MiB).
/// Separate from MAX_MESSAGE_SIZE (which covers JSON control messages).
/// Matches MAX_FETCH_RESPONSE_SIZE since both bound single-shard payloads.
pub const MAX_V2_DATA_SIZE: u64 = 4 * 1024 * 1024; // 4MB
/// Maximum FetchBlob response size (4 MiB)
/// Based on stripe config: default shard ~800KB (8MB stripe / 10 data shards)
pub const MAX_FETCH_RESPONSE_SIZE: usize = 4 * 1024 * 1024;

/// Maximum cluster_map_json size (10MB - prevents malicious large payloads)
/// Note: This is a secondary check. The primary limit is MAX_MESSAGE_SIZE (2MB) which
/// bounds the entire P2P message. This larger limit exists for future-proofing if
/// message structure changes or cluster maps are received via a different path.
pub const MAX_CLUSTER_MAP_JSON_SIZE: usize = 10 * 1024 * 1024;

/// Maximum batch PG response size (20MB - reduced from 50MB)
pub const MAX_BATCH_PG_RESPONSE_SIZE: usize = 20 * 1024 * 1024;

/// Maximum files to process per rebalance cycle (prevents memory exhaustion)
/// With ~30 shards/file and ~800KB/shard, 1000 files = ~24GB potential memory
pub const REBALANCE_MAX_FILES_PER_CYCLE: usize = 1000;

/// Maximum concurrent P2P stream handlers to prevent connection flood attacks.
/// This bounds task spawning in handle_miner_control() to prevent OOM.
/// Must exceed store_concurrency (1024) + pull + fetch + pos to avoid
/// Store operations starving FetchBlob and other handler types.
pub const MAX_CONCURRENT_HANDLERS: usize = 2048;

// ============================================================================
// QUIC Transport
// ============================================================================

/// IPv6 P2P port (hardcoded, used when IPv6 bind is configured)
pub const IPV6_P2P_PORT: u16 = 11231;

/// QUIC keep-alive interval to maintain relay connections (seconds)
pub const KEEP_ALIVE_INTERVAL_SECS: u64 = 15;

/// Default path keep-alive interval for QUIC NAT traversal (seconds)
pub const DEFAULT_PATH_KEEP_ALIVE_SECS: u64 = 5;

/// Maximum idle timeout before QUIC connection is closed (seconds)
pub const MAX_IDLE_TIMEOUT_SECS: u64 = 120;

/// Maximum concurrent bidirectional QUIC streams per connection.
/// u32 because iroh's VarInt only implements From<u32>.
pub const MAX_CONCURRENT_BIDI_STREAMS: u32 = 16384;

/// Maximum concurrent unidirectional QUIC streams per connection
/// u32 because iroh's VarInt only implements From<u32>.
pub const MAX_CONCURRENT_UNI_STREAMS: u32 = 1024;

/// QUIC send window size (16 MiB per-connection)
pub const SEND_WINDOW_BYTES: u64 = 16 * 1024 * 1024;

/// QUIC per-stream receive window size (2 MiB).
/// u32 because iroh's VarInt only implements From<u32>.
pub const STREAM_RECEIVE_WINDOW_BYTES: u32 = 2 * 1024 * 1024;

/// QUIC aggregate receive window size (64 MiB per-connection).
/// u32 because iroh's VarInt only implements From<u32>.
pub const RECEIVE_WINDOW_BYTES: u32 = 64 * 1024 * 1024;

// ============================================================================
// Registration & Heartbeat
// ============================================================================

/// Sleep between registration retries when validator is warming up (seconds)
pub const REGISTRATION_RETRY_SLEEP_SECS: u64 = 5;

/// Timeout for STUN public IP detection (seconds)
pub const STUN_TIMEOUT_SECS: u64 = 3;

/// Timeout for direct address discovery before registration (seconds)
pub const DIRECT_ADDR_DISCOVERY_TIMEOUT_SECS: u64 = 15;

/// Timeout for the entire heartbeat exchange (open_bi + write + read) (seconds)
pub const HEARTBEAT_EXCHANGE_TIMEOUT_SECS: u64 = 30;

/// Maximum buffer size for heartbeat ACK response (bytes)
/// Increased to accommodate doc_ticket field in heartbeat response.
pub const HEARTBEAT_ACK_BUFFER_SIZE: usize = 4096;

/// Timeout for registration ACK from validator (seconds)
pub const REGISTER_COMPLETION_TIMEOUT_SECS: u64 = 10;

/// Maximum buffer size for registration ACK response (bytes)
pub const REGISTER_ACK_BUFFER_SIZE: usize = 4096;

// ============================================================================
// Retry & Backoff
// ============================================================================

/// Maximum jitter added to registration retry sleep (milliseconds)
pub const MAX_REGISTRATION_RETRY_JITTER_MS: u64 = 2000;

/// Maximum jitter added to post-re-registration heartbeat delay (milliseconds)
pub const MAX_HEARTBEAT_RETRY_JITTER_MS: u64 = 5000;

/// Maximum jitter for re-registration retry after socket refresh failure (milliseconds)
pub const MAX_SOCKET_REFRESH_JITTER_MS: u64 = 10000;

/// Base retry sleep for warming-up validator responses (seconds)
pub const RETRY_BACKOFF_BASE_SECS: u64 = 5;

/// Base backoff for heartbeat failures (seconds)
pub const FAILURE_BACKOFF_BASE_SECS: u64 = 30;

/// Number of consecutive heartbeat failures before triggering automatic re-registration.
/// After a validator restart, miners lose their connection. This triggers re-registration
/// after 3 failures (~30s × 3 = ~90s) instead of waiting indefinitely.
pub const HEARTBEAT_FAILURES_BEFORE_REREGISTRATION: u32 = 3;

/// Maximum consecutive re-registration failures before triggering a clean exit.
/// When iroh's QUIC path to the validator goes stale, re-registration keeps
/// timing out on the same dead path. After this many failures the miner exits
/// cleanly so systemd restarts it with a fresh iroh endpoint.
pub const MAX_REREGISTRATION_FAILURES_BEFORE_EXIT: u32 = 10;

/// Maximum backoff cap for heartbeat failures (seconds)
pub const FAILURE_BACKOFF_MAX_SECS: u64 = 120;

/// Maximum jitter added to heartbeat failure backoff (milliseconds)
pub const FAILURE_BACKOFF_JITTER_MS: u64 = 5000;

/// Maximum jitter for warming-up retry sleep (milliseconds)
pub const ERROR_RETRY_JITTER_MS: u64 = 2000;

/// Delay after re-registration failure before retry (seconds)
pub const RELAY_LOSS_RECOVERY_DELAY_SECS: u64 = 5;

// ============================================================================
// Relay & Monitoring
// ============================================================================

/// Grace period before closing router during shutdown (milliseconds)
pub const SHUTDOWN_GRACE_PERIOD_MS: u64 = 500;

/// Number of consecutive relay-only heartbeat failures before re-registration
#[allow(dead_code)]
pub const RELAY_FAILURES_REREGISTER_THRESHOLD: u32 = 3;

/// Interval (in heartbeat cycles) to refresh validator address from environment
pub const VALIDATOR_ADDR_REFRESH_INTERVAL_CYCLES: u32 = 10;

/// How often to refresh the cached endpoint addr in the heartbeat loop
/// (in heartbeat cycles, ~30s each). After iroh discovers the public IP
/// via QUIC addr discovery, the next refresh will advertise the direct addr.
pub const ENDPOINT_ADDR_REFRESH_INTERVAL_CYCLES: u32 = 3; // ~90s

/// How often to check relay status after detecting loss (seconds).
/// Between checks, the monitor calls endpoint.online() to nudge reconnection.
pub const RELAY_CHECK_INTERVAL_SECS: u64 = 15;

/// Max time without any relay before triggering clean exit (seconds).
/// After this duration of continuous relay loss, the miner exits so systemd
/// can restart it with a fresh iroh endpoint.
pub const RELAY_LOSS_EXIT_TIMEOUT_SECS: u64 = 300;

/// Timeout for each endpoint.online() nudge attempt (seconds).
pub const RELAY_ONLINE_NUDGE_TIMEOUT_SECS: u64 = 10;

// ============================================================================
// Rebalance
// ============================================================================

/// Minimum initial jitter before first self-rebalance (seconds)
pub const MIN_REBALANCE_JITTER_SECS: u64 = 10;

/// Maximum jitter between rebalance ticks to desynchronize miners (seconds)
pub const MAX_REBALANCE_INITIAL_JITTER_SECS: u64 = 30;

/// Direct path wait timeout during heartbeat probe (seconds)
#[allow(dead_code)]
pub const REBALANCE_DIRECT_PATH_WAIT_SECS: u64 = 10;

/// Minimum time since last epoch change before rebalance runs (seconds).
/// Prevents rebalance from acting on a stale or rapidly-changing topology.
pub const REBALANCE_STABLE_WINDOW_SECS: u64 = 300;

/// Timeout for quick connectivity check to a peer before fetching shards (seconds)
pub const REBALANCE_PEER_CONNECT_TIMEOUT_SECS: u64 = 3;

/// Number of concurrent shard fetches during rebalance (adaptive, starts here)
pub const REBALANCE_FETCH_CONCURRENCY: usize = 4;

/// Max concurrent shard fetches (adaptive ceiling)
pub const REBALANCE_FETCH_MAX_CONCURRENCY: usize = 16;

/// Min concurrent shard fetches (adaptive floor)
pub const REBALANCE_FETCH_MIN_CONCURRENCY: usize = 1;

/// Number of consecutive successes before increasing rebalance fetch concurrency
pub const REBALANCE_FETCH_SCALEUP_THRESHOLD: usize = 5;

/// Epoch lookback depth for shard placement during rebalance.
/// Shards placed on this miner under any cluster map within this window
/// are considered expected, preventing premature orphan GC during transitions.
pub const EPOCH_LOOKBACK: u64 = 50;

/// Maximum cluster map history entries retained for epoch lookback.
pub const MAX_CLUSTER_MAP_HISTORY: usize = 10;

// ============================================================================
// P2P Operations
// ============================================================================

/// Data frame read timeout for binary store framing (seconds).
/// Slightly shorter than the validator's write timeout (60s)
/// to ensure the miner times out first, producing a clean error.
pub const DATA_FRAME_READ_TIMEOUT_SECS: u64 = 55;

/// Timeout for acquiring a Store semaphore permit (seconds)
pub const STORE_PERMIT_TIMEOUT_SECS: u64 = 30;

/// Timeout for acquiring a PullFromPeer semaphore permit (seconds)
pub const PULL_PERMIT_TIMEOUT_SECS: u64 = 30;

/// Timeout for downloading a blob from a peer via PullFromPeer (seconds)
pub const PEER_BLOB_DOWNLOAD_TIMEOUT_SECS: u64 = 30;

/// Wait time for direct path to peer before aborting PullFromPeer (milliseconds)
pub const PULL_DIRECT_PATH_WAIT_MS: u64 = 500;

/// Timeout for reading FetchBlob response from peer (seconds)
pub const PEER_DATA_RECEPTION_TIMEOUT_SECS: u64 = 30;

// ============================================================================
// Rebalance Batch Operations
// ============================================================================

/// Timeout for reading batch PG query response from validator (seconds)
pub const BATCH_RESPONSE_TIMEOUT_SECS: u64 = 60;

/// Number of PGs to query per batch chunk
pub const PG_BATCH_CHUNK_SIZE: usize = 50;

/// Maximum total file entries accepted from a batch PG response
pub const MAX_PG_BATCH_FILE_ENTRIES: usize = 100_000;

/// Number of concurrent QUIC streams for manifest fetches during rebalance
pub const CONCURRENT_MANIFEST_FETCH_STREAMS: usize = 16;

/// Maximum consecutive manifest fetch failures before aborting rebalance
pub const MAX_CONSECUTIVE_MANIFEST_FAILURES: u32 = 10;

/// Timeout for opening a bidi stream for manifest fetch (seconds)
pub const MANIFEST_STREAM_OPEN_TIMEOUT_SECS: u64 = 10;

/// Maximum manifest response size (1 MiB)
pub const MANIFEST_RESPONSE_MAX_SIZE: usize = 1024 * 1024;

/// Timeout for reading a manifest response from validator (seconds)
pub const MANIFEST_READ_TIMEOUT_SECS: u64 = 30;

// ============================================================================
// Erasure Reconstruction
// ============================================================================

/// Maximum concurrent erasure reconstruction tasks per miner.
/// Reconstruction is CPU + network intensive (fetches k=10 shards from peers
/// then runs RS decode), so keep this low.
#[allow(dead_code)]
pub const MAX_CONCURRENT_RECONSTRUCTIONS: usize = 2;

/// Timeout for connecting to a peer miner during shard reconstruction (seconds)
#[allow(dead_code)]
pub const RECONSTRUCT_PEER_CONNECT_TIMEOUT_SECS: u64 = 10;

/// Timeout for reading shard data from a peer during reconstruction (seconds)
#[allow(dead_code)]
pub const RECONSTRUCT_PEER_READ_TIMEOUT_SECS: u64 = 30;

// ============================================================================
// Miscellaneous
// ============================================================================

/// Maximum characters to show when truncating strings for log output
pub const LOG_STRING_TRUNCATE_LEN: usize = 120;

/// Timeout for the GitHub version check HTTP request (seconds)
pub const VERSION_CHECK_TIMEOUT_SECS: u64 = 10;

/// Unix file permissions for the keypair file (owner read/write only)
pub const KEYPAIR_FILE_PERMISSIONS: u32 = 0o600;

// ============================================================================
// Gateway Keepalive
// ============================================================================

/// Default interval between gateway keepalive connection attempts (seconds).
/// Override via `MINER_GATEWAY_KEEPALIVE_INTERVAL_SECS`.
pub const DEFAULT_GATEWAY_KEEPALIVE_INTERVAL_SECS: u64 = 60;

/// Default timeout for connecting to a gateway endpoint (seconds).
/// Override via `MINER_GATEWAY_CONNECT_TIMEOUT_SECS`.
pub const DEFAULT_GATEWAY_CONNECT_TIMEOUT_SECS: u64 = 10;

/// Maximum number of gateway endpoints to track (prevents unbounded growth)
pub const MAX_GATEWAY_ENDPOINTS: usize = 100;

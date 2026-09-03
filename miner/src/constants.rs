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

/// Blob cache weight ceiling — bytes. Each cached blob counts its own
/// length toward this ceiling via a custom Weighter (see `state.rs::BlobWeighter`).
///
/// Replaces the previous count-bounded `BLOB_CACHE_SIZE = 10_000` which,
/// at shard sizes up to ~800 KiB, allowed the cache to grow to ~8 GiB
/// in pathological cases and competed with the page cache + chain node
/// for RAM on memory-constrained boxes.
pub const BLOB_CACHE_BYTES: u64 = 4 * 1024 * 1024 * 1024; // 4 GiB

/// Estimated entry count for the cache's internal hash table sizing.
/// Approximately `BLOB_CACHE_BYTES / typical_shard_size`. Doesn't bound
/// the actual entry count — that's enforced by byte weight.
pub const BLOB_CACHE_ESTIMATED_ITEMS: usize = 5_000;

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

/// Maximum concurrent inbound connections accepted by the P2P endpoint.
/// Must stay comfortably above the fleet size: during a fleet-wide
/// rebalance or recovery wave most of the network can legitimately dial
/// one miner at once, and a saturated accept loop drops gateway store
/// pushes (creating permanent manifest gaps) and audit connections
/// (creating undeserved reputation penalties) alike.
pub const INBOUND_CONNECTION_LIMIT: usize = 1024;

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

/// Timeout for opening the QUIC connection to the validator during registration.
///
/// Decoupled from `DEFAULT_CONNECT_TIMEOUT_SECS` (which governs peer-to-peer
/// connects for rebalance/fetch) so the registration path can tolerate
/// validator-side load spikes without forcing peer connects to wait longer
/// than they need to. Observed in production: the validator QUIC accept queue
/// can miss the 20s default during high-load windows, causing the
/// heartbeat re-registration loop to fail repeatedly.
pub const REGISTER_CONNECT_TIMEOUT_SECS: u64 = 60;

/// Maximum buffer size for registration ACK response (bytes)
pub const REGISTER_ACK_BUFFER_SIZE: usize = 4096;

// ============================================================================
// Retry & Backoff
// ============================================================================

/// Maximum jitter added to post-re-registration heartbeat delay (milliseconds)
pub const MAX_HEARTBEAT_RETRY_JITTER_MS: u64 = 5000;

/// Heartbeat period while the validator link is healthy (seconds)
pub const FAILURE_BACKOFF_BASE_SECS: u64 = 30;

/// Decorrelated-jitter backoff for transient validator failures (heartbeat
/// I/O errors, WARMING_UP, RATE_LIMITED, UNKNOWN, re-registration failures):
/// `sleep = random(base, min(cap, prev * 3))`. See `reconnect.rs`.
/// The fleet sees every validator restart at once; the jitter keeps ~300
/// miners from re-registering in lockstep. The cap bounds how long a miner
/// can stay unaware that the validator is back: it must stay well below the
/// validator's startup grace (300s) and miner-offline threshold (600s), or
/// a miner asleep at the cap when the validator recovers is scored stale
/// or offline. 120s is the cap the heartbeat failure path already used.
pub const VALIDATOR_BACKOFF_BASE_SECS: u64 = 5;
pub const VALIDATOR_BACKOFF_CAP_SECS: u64 = 120;

/// Number of consecutive heartbeat failures before triggering automatic re-registration.
/// After a validator restart, miners lose their connection. This triggers re-registration
/// after 3 failures (~30s × 3 = ~90s) instead of waiting indefinitely.
pub const HEARTBEAT_FAILURES_BEFORE_REREGISTRATION: u32 = 3;

/// Consecutive re-registration failures after which the miner escalates its
/// "still disconnected" log line to error level. It keeps retrying with
/// backoff either way: transient validator failures (restart, warm-up, rate
/// limiting, network) never exit the process. This used to be an exit
/// threshold, which turned every validator restart into a fleet-wide miner
/// restart cascade — all miners hit it at the same time.
pub const REREGISTRATION_FAILURES_BEFORE_ESCALATION: u32 = 10;

/// Maximum jitter added to the healthy heartbeat period (milliseconds)
pub const FAILURE_BACKOFF_JITTER_MS: u64 = 5000;

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

/// How often the fetch phase logs a progress line at info. Without it a
/// failing fetch phase is indistinguishable from a hung one: every failure
/// path in `fetch_missing_shards` logs at debug only (observed in production:
/// 85 min of total journal silence mid-pass).
pub const REBALANCE_FETCH_PROGRESS_SECS: u64 = 60;

/// Hard deadline for one shard's entire fetch attempt (peer loop + erasure
/// recovery). `open_bi()`/`write_all()` have no timeout of their own, so a
/// half-dead pooled connection could stall the pass forever; this also caps
/// the legitimate worst case (~30 candidate peers x 33 s reads).
pub const REBALANCE_SHARD_FETCH_DEADLINE_SECS: u64 = 180;

/// Epoch lookback depth for shard placement during rebalance.
/// Shards placed on this miner under any cluster map within this window
/// are considered expected, preventing premature orphan GC during transitions.
pub const EPOCH_LOOKBACK: u64 = 50;

/// Maximum cluster map history entries retained for epoch lookback.
pub const MAX_CLUSTER_MAP_HISTORY: usize = 10;

/// Cap on fetch candidate peers per missing shard. The list merges upload-era,
/// historical-window and current-stripe holders; without a cap one shard could
/// spend the whole fetch-phase budget dialing peers.
pub const REBALANCE_FETCH_MAX_PEERS_PER_SHARD: usize = 40;

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

/// Number of PGs to query per batch chunk. Only the starting point of a
/// cycle: the query loop halves the chunk size automatically when a
/// response overflows the entry cap, so growing per-PG file density
/// degrades gracefully instead of erroring.
pub const PG_BATCH_CHUNK_SIZE: usize = 50;

/// Maximum total file entries accepted from a batch PG response.
///
/// Raised 100k → 400k: this check runs AFTER the response has
/// been fully read (bounded by `MAX_BATCH_PG_RESPONSE_SIZE` = 20 MiB, the
/// real memory guard) and JSON-parsed, so tripping it only discards data we
/// already paid to transfer. 20 MiB of JSON cannot exceed ~290k hash entries,
/// so at 400k this cap can never bind before the byte cap — it survives only
/// as a sanity ceiling.
pub const MAX_PG_BATCH_FILE_ENTRIES: usize = 400_000;

/// Maximum consecutive failed batch PG chunk queries before the cycle's
/// query loop aborts (prevents hammering a broken validator connection
/// with dozens of doomed chunk requests every tick).
pub const MAX_CONSECUTIVE_BATCH_FAILURES: u32 = 5;

/// Maximum validator reconnects per rebalance cycle after a batch PG chunk
/// query fails. Each reconnect is preceded by a backoff (see
/// `BATCH_RECONNECT_BACKOFF_SECS`) and retries the SAME chunk window.
/// Rationale: a loaded validator closes the batch connection ~30-45 s
/// in and answers an *immediate* reconnect with `server busy` (code 1); the
/// old single instant reconnect therefore always failed and roughly half of
/// observed cycles aborted having checked nothing.
pub const MAX_BATCH_RECONNECTS: u32 = 3;

/// Base backoff before a batch-query reconnect; attempt `n` waits `n x base`
/// (20 s, 40 s, 60 s -> at most 120 s per cycle, well under the 300 s tick).
pub const BATCH_RECONNECT_BACKOFF_SECS: u64 = 20;

/// Number of concurrent QUIC streams for manifest fetches during rebalance
// 16 -> 8: with 16 parallel streams one connection stall made
// all in-flight fetches time out together, so the 10-consecutive-failures
// abort tripped on a single wave (observed in production: 10 failures
// within 4 ms). At 8, an abort requires sustained failure across two
// waves, and the load
// on the struggling validator is halved.
pub const CONCURRENT_MANIFEST_FETCH_STREAMS: usize = 8;

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

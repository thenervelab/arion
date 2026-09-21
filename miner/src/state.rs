//! Global state accessors for the miner.
//!
//! This module provides shared state accessed via accessor functions (OnceLock-wrapped).
//!
//! # Global State Design
//!
//! Unlike validator/gateway which pass `Arc<AppState>` everywhere, the miner uses
//! `static OnceLock<T>` globals for state that needs to be accessed from P2P handlers
//! where passing context is impractical.
//!
//! All globals use lazy initialization via `OnceLock::get_or_init()` and thread-safe
//! interior mutability (`DashMap`, `RwLock`).
//!
//! # Concurrency Model
//!
//! - `DashMap` for frequently accessed lookups (peer cache, orphan shards)
//! - `RwLock` for epoch, cluster map, and connection pool (allows concurrent reads)
//! - `quick_cache::Cache` for bounded LRU blob cache (10k entries)

#![allow(clippy::type_complexity)]

use crate::constants::{
    CONNECTION_POOL_EVICTION_FRACTION, CONNECTION_TTL_SECS, MAX_CONNECTION_POOL_SIZE,
};
use anyhow::Result;
use common::now_secs;
use dashmap::DashMap;
use quick_cache::sync::Cache;
use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::Arc;
use std::sync::OnceLock;
use std::sync::atomic::AtomicBool;
use tokio::sync::RwLock;

// ============================================================================
// Global State (using DashMap for lock-free concurrent access)
// ============================================================================

/// Global cache of peer miner addresses for M2M transfers (lock-free).
/// Key: node_id hex string, Value: iroh::EndpointAddr (still used for protocol compat)
static PEER_MINER_CACHE: OnceLock<DashMap<String, iroh::EndpointAddr>> = OnceLock::new();

/// Track current epoch for self-rebalancing detection
static CURRENT_EPOCH: OnceLock<Arc<RwLock<u64>>> = OnceLock::new();

/// Store the current cluster map for CRUSH calculations (needs Arc for cloning)
static CLUSTER_MAP: OnceLock<Arc<RwLock<Option<Arc<common::ClusterMap>>>>> = OnceLock::new();

/// Store the validator's socket address for quinn connections
static VALIDATOR_ADDR: OnceLock<Arc<RwLock<Option<SocketAddr>>>> = OnceLock::new();

/// Store the validator's node ID (hex string) for identity verification
static VALIDATOR_NODE_ID: OnceLock<Arc<RwLock<String>>> = OnceLock::new();

/// Store the blobs directory path for file system access
static BLOBS_DIR: OnceLock<Arc<RwLock<Option<std::path::PathBuf>>>> = OnceLock::new();

/// Connection pool for quinn P2P connections (with TTL)
/// Key: node_id hex string
static CONNECTION_POOL: OnceLock<Arc<RwLock<HashMap<String, (quinn::Connection, u64)>>>> =
    OnceLock::new();

/// Blob cache for FetchBlob responses.
/// Key: iroh_blobs::Hash (32 bytes, Copy — no heap alloc for key)
/// Value: bytes::Bytes (refcounted — clone is just a refcount bump)
///
/// Byte-weighted (see `BlobWeighter`): the cache evicts LRU entries until
/// total byte weight is at or below `BLOB_CACHE_BYTES`. This gives
/// a predictable memory ceiling regardless of variable shard sizes.
#[derive(Clone, Copy, Default)]
pub struct BlobWeighter;

impl quick_cache::Weighter<iroh_blobs::Hash, bytes::Bytes> for BlobWeighter {
    fn weight(&self, _key: &iroh_blobs::Hash, val: &bytes::Bytes) -> u64 {
        // Each entry weighs its own byte length toward the cache ceiling.
        // quick_cache treats 0-weight entries as never evicted, so clamp to >= 1.
        (val.len() as u64).max(1)
    }
}

static BLOB_CACHE: OnceLock<Arc<Cache<iroh_blobs::Hash, bytes::Bytes, BlobWeighter>>> =
    OnceLock::new();

/// Flag to signal that re-registration is needed (set when validator returns UNKNOWN)
static NEEDS_REREGISTRATION: OnceLock<Arc<std::sync::atomic::AtomicBool>> = OnceLock::new();

/// Dynamic warden node IDs for PoS challenge authorization (hex strings)
static WARDEN_NODE_IDS: OnceLock<Arc<RwLock<Vec<String>>>> = OnceLock::new();

/// Node IDs allowed to issue storage-proof challenges on top of the
/// validator and the wardens (hex strings), replaced on every heartbeat
/// reply that carries `storage_proof_requesters`.
static STORAGE_PROOF_REQUESTERS: OnceLock<Arc<RwLock<Vec<String>>>> = OnceLock::new();

/// Whether the validator is currently reachable (set by heartbeat loop, read by rebalance loop)
static VALIDATOR_REACHABLE: OnceLock<AtomicBool> = OnceLock::new();

/// Whether at least one relay server is connected (set by relay health monitor)
static RELAY_CONNECTED: OnceLock<AtomicBool> = OnceLock::new();

/// Miner UID computed once from public key hash (avoids repeated hashing + heap alloc)
static MINER_UID: OnceLock<u32> = OnceLock::new();

/// Cached PG assignments: (epoch, pgs) — recomputed only when epoch changes
static MY_PGS_CACHE: OnceLock<Arc<RwLock<(u64, Vec<u32>)>>> = OnceLock::new();

/// Tracks the last epoch change: (epoch, instant when it changed).
/// Used by rebalance to defer work during topology churn.
static LAST_EPOCH_CHANGE: OnceLock<Arc<RwLock<(u64, tokio::time::Instant)>>> = OnceLock::new();

/// Data directory path for persisting cluster map cache to disk
static DATA_DIR: OnceLock<std::path::PathBuf> = OnceLock::new();

/// PoS commitment cache: avoids rebuilding Poseidon2 Merkle trees on repeated challenges
static POS_COMMITMENT_CACHE: OnceLock<
    Arc<Cache<iroh_blobs::Hash, Arc<pos_circuits::commitment::CommitmentWithTree>>>,
> = OnceLock::new();

/// Recent cluster map history for epoch lookback (newest at back).
/// Prevents premature orphan GC during rebalancing transitions.
static CLUSTER_MAP_HISTORY: OnceLock<
    Arc<RwLock<std::collections::VecDeque<Arc<common::ClusterMap>>>>,
> = OnceLock::new();

/// Whether the miner has already joined the iroh-doc manifest gossip
static DOC_JOINED: OnceLock<AtomicBool> = OnceLock::new();

/// iroh-docs API handle (set once after joining the doc)
static DOC_REPLICA: OnceLock<Arc<RwLock<Option<iroh_docs::api::Doc>>>> = OnceLock::new();

/// iroh-docs blob store for reading doc entry content (set once after joining the doc)
static DOC_REPLICA_BLOBS: OnceLock<Arc<RwLock<Option<iroh_blobs::store::fs::FsStore>>>> =
    OnceLock::new();

/// Known gateway endpoints received from ClusterMapUpdate broadcasts.
/// Key: node_id hex string, Value: GatewayEndpoint (node_id, public_addr, last_seen).
/// Updated on each ClusterMapUpdate; read by the gateway keepalive background task.
static GATEWAY_ENDPOINTS: OnceLock<DashMap<String, common::GatewayEndpoint>> = OnceLock::new();

/// Whether the miner has fully synchronized the historical Hash Chain.
static IS_HISTORICAL_SEEDER: OnceLock<AtomicBool> = OnceLock::new();

/// Per-hash write locks (hex hash -> mutex). Held by Store and
/// PullFromPeer for the whole write, and by the obligation-list purge
/// across its final check and delete, so a write and a purge of the same
/// hash never interleave. Entries are removed when the last holder drops.
static HASH_WRITE_LOCKS: OnceLock<DashMap<String, Arc<tokio::sync::Mutex<()>>>> = OnceLock::new();

pub fn get_peer_cache() -> &'static DashMap<String, iroh::EndpointAddr> {
    PEER_MINER_CACHE.get_or_init(DashMap::new)
}

pub fn get_current_epoch() -> &'static Arc<RwLock<u64>> {
    CURRENT_EPOCH.get_or_init(|| Arc::new(RwLock::new(0)))
}

pub fn get_cluster_map() -> &'static Arc<RwLock<Option<Arc<common::ClusterMap>>>> {
    CLUSTER_MAP.get_or_init(|| Arc::new(RwLock::new(None)))
}

pub fn get_validator_addr() -> &'static Arc<RwLock<Option<SocketAddr>>> {
    VALIDATOR_ADDR.get_or_init(|| Arc::new(RwLock::new(None)))
}

pub fn get_validator_node_id_global() -> &'static Arc<RwLock<String>> {
    VALIDATOR_NODE_ID.get_or_init(|| Arc::new(RwLock::new(String::new())))
}

pub fn get_blobs_dir() -> &'static Arc<RwLock<Option<std::path::PathBuf>>> {
    BLOBS_DIR.get_or_init(|| Arc::new(RwLock::new(None)))
}

pub fn get_connection_pool() -> &'static Arc<RwLock<HashMap<String, (quinn::Connection, u64)>>> {
    CONNECTION_POOL.get_or_init(|| Arc::new(RwLock::new(HashMap::new())))
}

pub fn get_blob_cache() -> &'static Arc<Cache<iroh_blobs::Hash, bytes::Bytes, BlobWeighter>> {
    BLOB_CACHE.get_or_init(|| {
        Arc::new(Cache::with_weighter(
            crate::constants::BLOB_CACHE_ESTIMATED_ITEMS,
            crate::constants::BLOB_CACHE_BYTES,
            BlobWeighter,
        ))
    })
}

pub fn get_needs_reregistration() -> &'static Arc<std::sync::atomic::AtomicBool> {
    NEEDS_REREGISTRATION.get_or_init(|| Arc::new(std::sync::atomic::AtomicBool::new(false)))
}

pub fn get_warden_node_ids() -> &'static Arc<RwLock<Vec<String>>> {
    WARDEN_NODE_IDS.get_or_init(|| Arc::new(RwLock::new(Vec::new())))
}

pub fn get_storage_proof_requesters() -> &'static Arc<RwLock<Vec<String>>> {
    STORAGE_PROOF_REQUESTERS.get_or_init(|| Arc::new(RwLock::new(Vec::new())))
}

pub fn get_validator_reachable() -> &'static AtomicBool {
    VALIDATOR_REACHABLE.get_or_init(|| AtomicBool::new(false))
}

pub fn get_relay_connected() -> &'static AtomicBool {
    RELAY_CONNECTED.get_or_init(|| AtomicBool::new(true))
}

pub fn set_miner_uid(uid: u32) {
    let _ = MINER_UID.set(uid);
}

pub fn get_miner_uid() -> u32 {
    *MINER_UID
        .get()
        .expect("MINER_UID not initialized — call set_miner_uid() during startup")
}

pub fn get_my_pgs_cache() -> &'static Arc<RwLock<(u64, Vec<u32>)>> {
    MY_PGS_CACHE.get_or_init(|| Arc::new(RwLock::new((0, Vec::new()))))
}

pub fn get_last_epoch_change() -> &'static Arc<RwLock<(u64, tokio::time::Instant)>> {
    LAST_EPOCH_CHANGE.get_or_init(|| Arc::new(RwLock::new((0, tokio::time::Instant::now()))))
}

pub fn set_data_dir(path: std::path::PathBuf) {
    let _ = DATA_DIR.set(path);
}

pub fn get_data_dir() -> Option<&'static std::path::PathBuf> {
    DATA_DIR.get()
}

pub fn get_pos_commitment_cache()
-> &'static Arc<Cache<iroh_blobs::Hash, Arc<pos_circuits::commitment::CommitmentWithTree>>> {
    POS_COMMITMENT_CACHE
        .get_or_init(|| Arc::new(Cache::new(crate::constants::POS_COMMITMENT_CACHE_SIZE)))
}

pub fn get_cluster_map_history()
-> &'static Arc<RwLock<std::collections::VecDeque<Arc<common::ClusterMap>>>> {
    CLUSTER_MAP_HISTORY.get_or_init(|| {
        Arc::new(RwLock::new(std::collections::VecDeque::with_capacity(
            crate::constants::MAX_CLUSTER_MAP_HISTORY,
        )))
    })
}

pub fn get_doc_joined() -> &'static AtomicBool {
    DOC_JOINED.get_or_init(|| AtomicBool::new(false))
}

pub fn get_doc_replica() -> &'static Arc<RwLock<Option<iroh_docs::api::Doc>>> {
    DOC_REPLICA.get_or_init(|| Arc::new(RwLock::new(None)))
}

pub fn get_doc_replica_blobs() -> &'static Arc<RwLock<Option<iroh_blobs::store::fs::FsStore>>> {
    DOC_REPLICA_BLOBS.get_or_init(|| Arc::new(RwLock::new(None)))
}

pub fn get_gateway_endpoints() -> &'static DashMap<String, common::GatewayEndpoint> {
    GATEWAY_ENDPOINTS.get_or_init(DashMap::new)
}

pub fn get_is_historical_seeder() -> &'static AtomicBool {
    IS_HISTORICAL_SEEDER.get_or_init(|| AtomicBool::new(false))
}

fn hash_write_locks() -> &'static DashMap<String, Arc<tokio::sync::Mutex<()>>> {
    HASH_WRITE_LOCKS.get_or_init(DashMap::new)
}

fn hash_write_mutex(hash_hex: &str) -> Arc<tokio::sync::Mutex<()>> {
    hash_write_locks()
        .entry(hash_hex.to_string())
        .or_insert_with(|| Arc::new(tokio::sync::Mutex::new(())))
        .clone()
}

/// Exclusive hold on a hash for the duration of a write (or a purge
/// delete). Dropping it releases the hash and frees the map entry when
/// nobody else is waiting on it.
pub struct HashWriteLock {
    hash_hex: String,
    guard: Option<tokio::sync::OwnedMutexGuard<()>>,
}

impl Drop for HashWriteLock {
    fn drop(&mut self) {
        // Release first, then drop the entry only if we were the last
        // holder (the map's own Arc is the single remaining reference).
        self.guard.take();
        hash_write_locks().remove_if(&self.hash_hex, |_, m| Arc::strong_count(m) == 1);
    }
}

/// Wait for and take the write lock of `hash_hex` (writers: Store,
/// PullFromPeer).
pub async fn lock_hash_write(hash_hex: &str) -> HashWriteLock {
    /// A waiter cancelled mid-wait (connection dropped) must not leave a
    /// free entry behind: run the same last-holder cleanup on drop.
    struct WaitCleanup<'a>(&'a str, bool);
    impl Drop for WaitCleanup<'_> {
        fn drop(&mut self) {
            if !self.1 {
                hash_write_locks().remove_if(self.0, |_, m| Arc::strong_count(m) == 1);
            }
        }
    }
    let mutex = hash_write_mutex(hash_hex);
    let mut cleanup = WaitCleanup(hash_hex, false);
    let guard = mutex.lock_owned().await;
    cleanup.1 = true;
    HashWriteLock {
        hash_hex: hash_hex.to_string(),
        guard: Some(guard),
    }
}

/// Take the write lock of `hash_hex` only if nobody holds it (the purge:
/// a busy hash is skipped, never waited for).
pub fn try_lock_hash_write(hash_hex: &str) -> Option<HashWriteLock> {
    let mutex = hash_write_mutex(hash_hex);
    match mutex.try_lock_owned() {
        Ok(guard) => Some(HashWriteLock {
            hash_hex: hash_hex.to_string(),
            guard: Some(guard),
        }),
        Err(_) => None,
    }
}

/// A purge pass is walking the inventory and deleting. The backfill reads
/// this and waits: the two loops touch disjoint blobs (unlisted vs
/// listed) but share the disk, and a purge pass must not race a fill for
/// I/O on a node that is already reclaiming space.
static PURGE_PASS_ACTIVE: std::sync::atomic::AtomicBool = std::sync::atomic::AtomicBool::new(false);

/// Mark a purge pass running for the lifetime of the returned guard.
pub fn mark_purge_pass_active() -> PurgePassGuard {
    PURGE_PASS_ACTIVE.store(true, std::sync::atomic::Ordering::Release);
    PurgePassGuard(())
}

/// Whether a purge pass is running right now. Read by the backfill loop,
/// which is not compiled into the release binary.
#[cfg_attr(not(any(test, feature = "backfill")), allow(dead_code))]
pub fn purge_pass_active() -> bool {
    PURGE_PASS_ACTIVE.load(std::sync::atomic::Ordering::Acquire)
}

/// Clears the purge-pass flag on drop, whichever way the pass ends.
pub struct PurgePassGuard(());

impl Drop for PurgePassGuard {
    fn drop(&mut self) {
        PURGE_PASS_ACTIVE.store(false, std::sync::atomic::Ordering::Release);
    }
}

/// Whether a write for `hash_hex` is currently in progress.
pub fn is_write_inflight(hash_hex: &str) -> bool {
    hash_write_locks()
        .get(hash_hex)
        .is_some_and(|m| m.try_lock().is_err())
}

/// Get a pooled quinn connection or create a new one.
/// Uses read lock for initial check, write lock only when needed.
pub async fn get_pooled_connection(
    endpoint: &quinn::Endpoint,
    peer_node_id: &str,
    peer_addr: SocketAddr,
) -> Result<quinn::Connection> {
    let key = peer_node_id.to_string();
    let now = now_secs();

    // Guard: if clock skew detected (now_secs returns 0), skip pool and create new connection.
    if now == 0 {
        return common::transport::connect(endpoint, peer_addr, peer_node_id).await;
    }

    // Try pool first (read lock - faster for common case)
    {
        let pool = get_connection_pool().read().await;
        if let Some((conn, created)) = pool.get(&key) {
            // Check: timestamp valid, not expired, and connection still open
            if *created <= now
                && now - *created < CONNECTION_TTL_SECS
                && conn.close_reason().is_none()
            {
                return Ok(conn.clone());
            }
        }
    }

    // Create new connection
    let conn = common::transport::connect(endpoint, peer_addr, peer_node_id).await?;

    // Store in pool with double-check to avoid race condition
    {
        let mut pool = get_connection_pool().write().await;

        // Double-check: another task may have inserted while we were connecting
        if let Some((existing_conn, created)) = pool.get(&key)
            && *created <= now
            && now - *created < CONNECTION_TTL_SECS
            && existing_conn.close_reason().is_none()
        {
            // Use existing connection, close the one we just created
            conn.close(0u32.into(), b"stale");
            return Ok(existing_conn.clone());
        }

        // Enforce hard cap on pool size to prevent OOM
        if pool.len() >= MAX_CONNECTION_POOL_SIZE {
            // First pass: cheap threshold-based cleanup (expired + closed).
            let threshold = now.saturating_sub(CONNECTION_TTL_SECS);
            pool.retain(|_, (conn, created)| {
                *created > threshold && *created <= now && conn.close_reason().is_none()
            });
            // If still over capacity after TTL cleanup, fall back to sort-based eviction
            if pool.len() >= MAX_CONNECTION_POOL_SIZE {
                let entries_to_remove = pool.len() / CONNECTION_POOL_EVICTION_FRACTION + 1;
                let mut oldest: Vec<_> = pool.iter().map(|(k, (_, ts))| (k.clone(), *ts)).collect();
                oldest.sort_by_key(|(_, ts)| *ts);
                for (evict_key, _) in oldest.into_iter().take(entries_to_remove) {
                    pool.remove(&evict_key);
                }
            }
        }

        pool.insert(key, (conn.clone(), now));
    }

    Ok(conn)
}

/// Extract a SocketAddr from an iroh::EndpointAddr (first direct IP address).
pub fn socket_addr_from_endpoint(addr: &iroh::EndpointAddr) -> Option<SocketAddr> {
    addr.addrs.iter().find_map(|a| match a {
        iroh::TransportAddr::Ip(sock) => Some(*sock),
        _ => None,
    })
}

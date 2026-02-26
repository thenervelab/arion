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
    BLOB_CACHE_SIZE, CONNECTION_TTL_SECS, MAX_CONNECTION_POOL_SIZE, MAX_TAG_MAP_ENTRIES,
};
use anyhow::Result;
use common::now_secs;
use dashmap::DashMap;
use iroh::endpoint::Endpoint;
use quick_cache::sync::Cache;
use std::collections::HashMap;
use std::sync::Arc;
use std::sync::OnceLock;
use std::sync::atomic::AtomicBool;
use tokio::sync::RwLock;

// ============================================================================
// Global State (using DashMap for lock-free concurrent access)
// ============================================================================

/// Global cache of peer miner addresses for M2M transfers (lock-free)
static PEER_MINER_CACHE: OnceLock<DashMap<String, iroh::EndpointAddr>> = OnceLock::new();

/// Track current epoch for self-rebalancing detection
static CURRENT_EPOCH: OnceLock<Arc<RwLock<u64>>> = OnceLock::new();

/// Store the current cluster map for CRUSH calculations (needs Arc for cloning)
static CLUSTER_MAP: OnceLock<Arc<RwLock<Option<Arc<common::ClusterMap>>>>> = OnceLock::new();

/// Store the validator endpoint address for P2P queries
static VALIDATOR_ENDPOINT: OnceLock<Arc<RwLock<Option<iroh::EndpointAddr>>>> = OnceLock::new();

/// Track orphan shards: blob_hash -> timestamp when first identified as orphan (lock-free)
/// Key is iroh_blobs::Hash (32 bytes, Copy) instead of String to avoid heap allocation.
static ORPHAN_SHARDS: OnceLock<DashMap<iroh_blobs::Hash, u64>> = OnceLock::new();

/// Store the blobs directory path for GC file system access
static BLOBS_DIR: OnceLock<Arc<RwLock<Option<std::path::PathBuf>>>> = OnceLock::new();

/// Connection pool for P2P connections (with TTL)
/// Key: iroh::PublicKey (32 bytes, Copy) — avoids Debug-formatting the entire EndpointAddr
static CONNECTION_POOL: OnceLock<
    Arc<RwLock<HashMap<iroh::PublicKey, (iroh::endpoint::Connection, u64)>>>,
> = OnceLock::new();

/// Blob cache for FetchBlob responses
/// Key: iroh_blobs::Hash (32 bytes, Copy — no heap alloc for key)
/// Value: bytes::Bytes (refcounted — clone is just a refcount bump)
static BLOB_CACHE: OnceLock<Arc<Cache<iroh_blobs::Hash, bytes::Bytes>>> = OnceLock::new();

/// Flag to signal that re-registration is needed (set when validator returns UNKNOWN)
static NEEDS_REREGISTRATION: OnceLock<Arc<std::sync::atomic::AtomicBool>> = OnceLock::new();

/// Dynamic warden node IDs for PoS challenge authorization (auto-distributed by validator)
static WARDEN_NODE_IDS: OnceLock<Arc<RwLock<Vec<iroh::PublicKey>>>> = OnceLock::new();

/// Whether the validator is currently reachable (set by heartbeat loop, read by rebalance loop)
static VALIDATOR_REACHABLE: OnceLock<AtomicBool> = OnceLock::new();

/// Whether at least one relay server is connected (set by relay health monitor)
static RELAY_CONNECTED: OnceLock<AtomicBool> = OnceLock::new();

/// Miner UID computed once from public key hash (avoids repeated hashing + heap alloc)
static MINER_UID: OnceLock<u32> = OnceLock::new();

/// Tag map for O(1) delete: maps blob Hash to its Tag name.
/// Populated on Store/Pull, used by Delete to skip full tag scan.
static TAG_MAP: OnceLock<DashMap<iroh_blobs::Hash, iroh_blobs::api::Tag>> = OnceLock::new();

/// Static discovery provider for seeding peer direct addresses into iroh's
/// address book. Updated on ClusterMapUpdate so peer-to-peer connections
/// (PullFromPeer, FetchBlob) resolve directly without relay discovery.
static STATIC_DISCOVERY: OnceLock<iroh::address_lookup::memory::MemoryLookup> = OnceLock::new();

/// Cached PG assignments: (epoch, pgs) — recomputed only when epoch changes
static MY_PGS_CACHE: OnceLock<Arc<RwLock<(u64, Vec<u32>)>>> = OnceLock::new();

/// PoS commitment cache: avoids rebuilding Poseidon2 Merkle trees on repeated challenges
static POS_COMMITMENT_CACHE: OnceLock<
    Arc<Cache<iroh_blobs::Hash, Arc<pos_circuits::commitment::CommitmentWithTree>>>,
> = OnceLock::new();

pub fn get_peer_cache() -> &'static DashMap<String, iroh::EndpointAddr> {
    PEER_MINER_CACHE.get_or_init(DashMap::new)
}

pub fn get_current_epoch() -> &'static Arc<RwLock<u64>> {
    CURRENT_EPOCH.get_or_init(|| Arc::new(RwLock::new(0)))
}

pub fn get_cluster_map() -> &'static Arc<RwLock<Option<Arc<common::ClusterMap>>>> {
    CLUSTER_MAP.get_or_init(|| Arc::new(RwLock::new(None)))
}

pub fn get_validator_endpoint() -> &'static Arc<RwLock<Option<iroh::EndpointAddr>>> {
    VALIDATOR_ENDPOINT.get_or_init(|| Arc::new(RwLock::new(None)))
}

pub fn get_orphan_shards() -> &'static DashMap<iroh_blobs::Hash, u64> {
    ORPHAN_SHARDS.get_or_init(DashMap::new)
}

pub fn get_blobs_dir() -> &'static Arc<RwLock<Option<std::path::PathBuf>>> {
    BLOBS_DIR.get_or_init(|| Arc::new(RwLock::new(None)))
}

pub fn get_connection_pool()
-> &'static Arc<RwLock<HashMap<iroh::PublicKey, (iroh::endpoint::Connection, u64)>>> {
    CONNECTION_POOL.get_or_init(|| Arc::new(RwLock::new(HashMap::new())))
}

pub fn get_blob_cache() -> &'static Arc<Cache<iroh_blobs::Hash, bytes::Bytes>> {
    BLOB_CACHE.get_or_init(|| Arc::new(Cache::new(BLOB_CACHE_SIZE)))
}

pub fn get_needs_reregistration() -> &'static Arc<std::sync::atomic::AtomicBool> {
    NEEDS_REREGISTRATION.get_or_init(|| Arc::new(std::sync::atomic::AtomicBool::new(false)))
}

pub fn get_warden_node_ids() -> &'static Arc<RwLock<Vec<iroh::PublicKey>>> {
    WARDEN_NODE_IDS.get_or_init(|| Arc::new(RwLock::new(Vec::new())))
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

pub fn get_tag_map() -> &'static DashMap<iroh_blobs::Hash, iroh_blobs::api::Tag> {
    TAG_MAP.get_or_init(DashMap::new)
}

/// Insert a tag mapping, respecting the size limit
pub fn tag_map_insert(hash: iroh_blobs::Hash, tag: iroh_blobs::api::Tag) {
    let map = get_tag_map();
    if map.len() < MAX_TAG_MAP_ENTRIES {
        map.insert(hash, tag);
    }
}

pub fn init_static_discovery(discovery: iroh::address_lookup::memory::MemoryLookup) {
    let _ = STATIC_DISCOVERY.set(discovery);
}

pub fn get_static_discovery() -> Option<&'static iroh::address_lookup::memory::MemoryLookup> {
    STATIC_DISCOVERY.get()
}

pub fn get_my_pgs_cache() -> &'static Arc<RwLock<(u64, Vec<u32>)>> {
    MY_PGS_CACHE.get_or_init(|| Arc::new(RwLock::new((0, Vec::new()))))
}

pub fn get_pos_commitment_cache()
-> &'static Arc<Cache<iroh_blobs::Hash, Arc<pos_circuits::commitment::CommitmentWithTree>>> {
    POS_COMMITMENT_CACHE
        .get_or_init(|| Arc::new(Cache::new(crate::constants::POS_COMMITMENT_CACHE_SIZE)))
}

/// Get a pooled connection or create a new one
/// Uses read lock for initial check, write lock only when needed
pub async fn get_pooled_connection(
    endpoint: &Endpoint,
    peer_addr: &iroh::EndpointAddr,
    alpn: &'static [u8],
) -> Result<iroh::endpoint::Connection> {
    use futures::future::FutureExt;

    // Use node ID as key (32 bytes, Copy — no heap allocation)
    let key = peer_addr.id;
    let now = now_secs();

    // Guard: if clock skew detected (now_secs returns 0), skip pool and create new connection.
    if now == 0 {
        return common::connect_with_direct_path(
            endpoint,
            peer_addr.clone(),
            alpn,
            std::time::Duration::from_secs(crate::constants::DEFAULT_CONNECT_TIMEOUT_SECS),
            std::time::Duration::from_secs(5),
        )
        .await;
    }

    // Try pool first (read lock - faster for common case)
    {
        let pool = get_connection_pool().read().await;
        if let Some((conn, created)) = pool.get(&key) {
            // Check: timestamp valid, not expired, and connection still open
            if *created <= now
                && now - *created < CONNECTION_TTL_SECS
                && conn.closed().now_or_never().is_none()
            {
                return Ok(conn.clone());
            }
        }
    }

    // Create new connection with direct path guarantee.
    let conn = common::connect_with_direct_path(
        endpoint,
        peer_addr.clone(),
        alpn,
        std::time::Duration::from_secs(crate::constants::DEFAULT_CONNECT_TIMEOUT_SECS),
        std::time::Duration::from_secs(5),
    )
    .await?;

    // Store in pool with double-check to avoid race condition
    {
        let mut pool = get_connection_pool().write().await;

        // Double-check: another task may have inserted while we were connecting
        if let Some((existing_conn, created)) = pool.get(&key)
            && *created <= now
            && now - *created < CONNECTION_TTL_SECS
            && existing_conn.closed().now_or_never().is_none()
        {
            // Use existing connection, close the one we just created
            conn.close(0u32.into(), b"stale");
            return Ok(existing_conn.clone());
        }

        // Enforce hard cap on pool size to prevent OOM
        if pool.len() >= MAX_CONNECTION_POOL_SIZE {
            // First pass: cheap threshold-based cleanup (expired + closed).
            // Don't call conn.close() on eviction — it races with
            // concurrent I/O on cloned handles, triggering quinn slab
            // panics. Dropped connections drain via idle timeout.
            let threshold = now.saturating_sub(CONNECTION_TTL_SECS);
            pool.retain(|_, (conn, created)| {
                *created > threshold && *created <= now && conn.closed().now_or_never().is_none()
            });
            // If still over capacity after TTL cleanup, fall back to sort-based eviction
            if pool.len() >= MAX_CONNECTION_POOL_SIZE {
                let entries_to_remove = pool.len() / 10 + 1;
                let mut oldest: Vec<_> = pool.iter().map(|(k, (_, ts))| (*k, *ts)).collect();
                oldest.sort_by_key(|(_, ts)| *ts);
                // Don't call conn.close() — see retain comment above.
                for (evict_key, _) in oldest.into_iter().take(entries_to_remove) {
                    pool.remove(&evict_key);
                }
            }
        }

        pool.insert(key, (conn.clone(), now));
    }

    Ok(conn)
}

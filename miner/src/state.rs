//! Application state and global state accessors for the miner.
//!
//! This module provides two categories of state:
//!
//! 1. **AppState**: Per-request state passed to HTTP handlers (endpoint, blob store)
//! 2. **Global statics**: Shared state accessed via accessor functions (OnceLock-wrapped)
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

// Some accessors are reserved for future use (rebalance, connection pooling)
#![allow(dead_code)]
#![allow(clippy::type_complexity)]

use crate::constants::{BLOB_CACHE_SIZE, CONNECTION_TTL_SECS, MAX_CONNECTION_POOL_SIZE};
use anyhow::Result;
use common::now_secs;
use dashmap::DashMap;
use iroh::endpoint::Endpoint;
use iroh_blobs::store::fs::FsStore;
use quick_cache::sync::Cache;
use std::collections::HashMap;
use std::sync::Arc;
use std::sync::OnceLock;
use tokio::sync::RwLock;

/// Application state for HTTP handlers
#[derive(Clone)]
pub struct AppState {
    pub endpoint: Endpoint,
    pub store: FsStore,
}

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
static ORPHAN_SHARDS: OnceLock<DashMap<String, u64>> = OnceLock::new();

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

pub fn get_orphan_shards() -> &'static DashMap<String, u64> {
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

/// Get a pooled connection or create a new one
/// Uses read lock for initial check, write lock only when needed
pub async fn get_pooled_connection(
    endpoint: &Endpoint,
    peer_addr: &iroh::EndpointAddr,
    alpn: &[u8],
) -> Result<iroh::endpoint::Connection> {
    use futures::future::FutureExt;

    // Use node ID as key (32 bytes, Copy — no heap allocation)
    let key = peer_addr.id;
    let now = now_secs();

    // Guard: if clock skew detected (now_secs returns 0), skip pool and create new connection
    if now == 0 {
        return endpoint
            .connect(peer_addr.clone(), alpn)
            .await
            .map_err(|e| anyhow::anyhow!("Failed to connect to peer: {}", e));
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

    // Create new connection
    let conn = endpoint
        .connect(peer_addr.clone(), alpn)
        .await
        .map_err(|e| anyhow::anyhow!("Failed to connect to peer: {}", e))?;

    // Store in pool with double-check to avoid race condition
    {
        let mut pool = get_connection_pool().write().await;

        // Double-check: another task may have inserted while we were connecting
        if let Some((existing_conn, created)) = pool.get(&key)
            && *created <= now
            && now - *created < CONNECTION_TTL_SECS
            && existing_conn.closed().now_or_never().is_none()
        {
            // Use existing connection, drop the one we just created
            return Ok(existing_conn.clone());
        }

        // Enforce hard cap on pool size to prevent OOM
        // If at capacity, evict ~10% oldest entries to reduce eviction frequency under burst
        if pool.len() >= MAX_CONNECTION_POOL_SIZE {
            let entries_to_remove = pool.len() / 10 + 1; // Remove ~10%
            let mut oldest: Vec<_> = pool.iter().map(|(k, (_, ts))| (*k, *ts)).collect();
            oldest.sort_by_key(|(_, ts)| *ts);
            for (key, _) in oldest.into_iter().take(entries_to_remove) {
                pool.remove(&key);
            }
        }

        pool.insert(key, (conn.clone(), now));

        // Periodic cleanup when pool gets large: remove expired/closed connections.
        // Build removal list inline to minimize time holding the write lock.
        if pool.len() > 100 {
            let stale_keys: Vec<_> = pool
                .iter()
                .filter(|(_, (c, created))| {
                    *created > now
                        || now - *created >= CONNECTION_TTL_SECS * 2
                        || c.closed().now_or_never().is_some()
                })
                .map(|(k, _)| *k)
                .collect();
            for k in stale_keys {
                pool.remove(&k);
            }
        }
    }

    Ok(conn)
}

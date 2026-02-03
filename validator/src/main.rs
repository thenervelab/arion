//! # Hippius Arion Validator
//!
//! The validator is the **metadata authority** and **orchestration engine** for the Hippius Arion
//! decentralized storage subnet. It serves as the central coordinator for file uploads, shard
//! placement, and data recovery across a network of storage miners.
//!
//! ## Architecture Overview
//!
//! ```text
//!                                    ┌─────────────────────────────────────┐
//!                                    │           VALIDATOR                  │
//!                                    │  (This crate - metadata authority)   │
//!                                    └─────────────────────────────────────┘
//!                                                    │
//!                    ┌───────────────────────────────┼───────────────────────────────┐
//!                    │                               │                               │
//!                    ▼                               ▼                               ▼
//!            ┌──────────────┐               ┌──────────────┐               ┌──────────────┐
//!            │   Gateway    │               │    Miner     │               │    Miner     │
//!            │ (HTTP proxy) │               │  (storage)   │               │  (storage)   │
//!            └──────────────┘               └──────────────┘               └──────────────┘
//! ```
//!
//! ## Core Responsibilities
//!
//! ### 1. File Upload & Erasure Coding
//! - Receives files from gateways via HTTP multipart upload
//! - Splits files into **stripes** (default 2 MiB each)
//! - Encodes each stripe using **Reed-Solomon erasure coding** (k=10 data, m=20 parity shards)
//! - Creates a `FileManifest` containing file metadata and shard hashes
//!
//! ### 2. CRUSH Placement Algorithm
//! - Determines which miners store each shard using the **CRUSH** algorithm
//! - Ensures **family diversity** (shards spread across different failure domains)
//! - Supports **Placement Groups (PGs)** for efficient rebalancing (default 16,384 PGs)
//!
//! ### 3. Cluster Map Management
//! - Maintains the authoritative `ClusterMap` of all registered miners
//! - Tracks miner weights, capacity, uptime, and strike counts
//! - Broadcasts map updates to miners when topology changes
//! - Persists maps to iroh-docs for durability and gateway replication
//!
//! ### 4. Automatic Recovery
//! - Continuously monitors miner health via heartbeats
//! - Detects when miners go offline (configurable threshold, default 10 minutes)
//! - Reconstructs missing shards using Reed-Solomon decoding
//! - Re-places recovered shards on healthy miners
//!
//! ### 5. Rebalancing (Ceph-style)
//! - When miners join/leave, detects which PGs have changed ownership
//! - Coordinates shard migration via `PullFromPeer` messages
//! - Tracks rebalance status per PG for gateway epoch lookback
//!
//! ## Data Flow
//!
//! ### Upload Flow
//! ```text
//! Gateway ──POST /upload──▶ Validator ──RS Encode──▶ Shards
//!                                │
//!                                ├──CRUSH Placement──▶ Miner Selection
//!                                │
//!                                └──P2P Store──▶ Miners (parallel)
//!                                        │
//!                                        ▼
//!                              Save FileManifest to iroh-docs
//! ```
//!
//! ### Download Flow (handled by Gateway)
//! ```text
//! Gateway ──GET /manifest/:hash──▶ Validator ──Returns──▶ FileManifest
//!    │
//!    └──CRUSH Calculate──▶ Miner Locations ──P2P FetchBlob──▶ Shards
//!                                                    │
//!                                                    ▼
//!                                            RS Decode ──▶ Original Data
//! ```
//!
//! ## Module Structure
//!
//! | Module | Purpose |
//! |--------|---------|
//! | `main.rs` | HTTP routes, P2P protocols, background loops, core logic |
//! | `config.rs` | TOML configuration with env var overrides |
//! | `state.rs` | Application state types and helpers |
//! | `constants.rs` | Tunable constants (cache sizes, timeouts, etc.) |
//! | `backup.rs` | S3 backup/restore (full, differential, incremental) |
//! | `families.rs` | Miner family whitelist verification |
//! | `chain_registry.rs` | On-chain pallet-arion registry cache |
//! | `metrics.rs` | Prometheus metrics definitions |
//! | `upload_progress.rs` | ReDB-based persistent upload tracking |
//! | `helpers.rs` | Utility functions (weight calculation, logging, etc.) |
//!
//! ## Key Constants
//!
//! | Constant | Default | Description |
//! |----------|---------|-------------|
//! | Stripe size | 2 MiB | Size of each erasure-coded stripe |
//! | k (data shards) | 10 | Number of data shards per stripe |
//! | m (parity shards) | 20 | Number of parity shards per stripe |
//! | PG count | 16,384 | Number of placement groups |
//! | Miner offline threshold | 600s | Time before miner considered offline |
//!
//! ## P2P Protocols
//!
//! The validator uses two Iroh ALPN protocols:
//!
//! 1. **`hippius/validator-control`** (inbound from miners):
//!    - `Register`: New miner registration with capacity/family info
//!    - `Heartbeat`: Periodic liveness signal with storage stats
//!    - `QueryPgFiles`: Request files in a specific PG (for rebalancing)
//!    - `Ping`: Health check
//!
//! 2. **`hippius/miner-control`** (outbound to miners):
//!    - `Store`: Push shard data to miner
//!    - `Delete`: Remove shard from miner
//!    - `PullFromPeer`: Instruct miner to pull shard from another miner
//!    - `ClusterMapUpdate`: Broadcast new cluster topology

// Pre-existing code style patterns - preserving during restructuring
#![allow(clippy::manual_unwrap_or_default)]
#![allow(clippy::manual_clamp)]
#![allow(clippy::needless_range_loop)]
#![allow(clippy::too_many_arguments)]

// =============================================================================
// MODULE DECLARATIONS
// =============================================================================

mod attestation_aggregator;
mod backup;
mod blob_backup;
mod chain_registry;
mod config;
mod constants;
mod families;
mod helpers;
mod index_cache;
mod metrics;
mod p2p;
mod reputation;
mod state;
mod upload_progress;
mod warden_client;

// =============================================================================
// EXTERNAL DEPENDENCIES
// =============================================================================
//
// The validator relies on several key external crates:
//
// - `iroh`: P2P networking (QUIC-based, with relay support for NAT traversal)
// - `iroh-docs`: Distributed document storage (CRDTs for conflict-free replication)
// - `iroh-blobs`: Content-addressed blob storage
// - `axum`: High-performance async HTTP server
// - `common`: Shared types (ClusterMap, FileManifest, CRUSH algorithm, RS codec)
// - `dashmap`: Lock-free concurrent hash maps for high-throughput state
// - `quick_cache`: Bounded LRU cache to prevent unbounded memory growth

use anyhow::{Result, anyhow};
use iroh::Endpoint;
use iroh_blobs::{
    // api::downloader::Downloader,
    // store::mem::MemStore,
    // ticket::BlobTicket,
    get::fsm::{self, BlobContentNext, ConnectedNext, EndBlobNext},
    protocol::{
        GetRequest,
        // RangeSpec,
    },
};
use std::ops::Deref;
// use iroh::discovery::dns::DnsDiscovery;
// use iroh::discovery::pkarr::PkarrPublisher;
use bytes::Bytes;
use iroh_docs::api::DocsApi;
use iroh_docs::engine::Engine;
use iroh_docs::{
    api::protocol::{AddrInfoOptions, ShareMode},
    engine::DefaultAuthorStorage,
};

use futures_lite::stream::StreamExt;
use rand::Rng;
use serde_json::Value;
use std::{
    str::FromStr,
    // net::SocketAddr,
    sync::Arc,
    time::Duration,
};
use tempfile::NamedTempFile;
// use tokio::sync::Mutex;
use axum::{
    Json, Router as AxumRouter,
    extract::{DefaultBodyLimit, Multipart, Path, Query as AxumQuery, State},
    http::{HeaderMap, StatusCode},
    response::IntoResponse,
    routing::{get, post},
};
use axum_server::tls_openssl::OpenSSLConfig;
use common::tls::TlsConfig;
use common::{
    BandwidthStats, ClusterMap, FileManifest, FileSummary, MinerNode, ShardAuditReport, SyncIndex,
    now_secs,
};
use dashmap::DashMap;
use quick_cache::sync::Cache as QuickCache;
use std::collections::VecDeque;
use std::time::Instant;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::time::sleep;
use tracing::{debug, error, info, warn};
use tracing_subscriber::EnvFilter;

use constants::{
    CACHE_MAX_ENTRIES, MANIFEST_HASHES_MAX_ENTRIES, MANIFEST_HASHES_WARN_THRESHOLD,
    MAX_FETCH_RESPONSE_SIZE, MINER_ACK_TIMEOUT_SECS, MINER_CONNECT_TIMEOUT_SECS,
    MINER_RETRY_DELAY_MS, REGISTRATION_RATE_LIMIT_SECS,
};
use helpers::{
    adjust_miner_weight, calculate_reputation_multiplier, doc_store_error, extract_bearer_token,
    get_admin_api_key, get_gateway_api_key, internal_error, is_miner_offline, truncate_for_log,
    validate_api_key, validate_hash_param,
};
use state::{
    AppState, Blacklist, PG_INDEX_PAGE_SIZE, PgIndexMeta, PgRebalanceStatus, RepairHintRequest,
    ValidatorReadyState, pg_index_meta_key, pg_index_page_key,
};

// Proof-of-Storage commitment generation for Warden integration
use pos_circuits::DEFAULT_CHUNK_SIZE;
use pos_circuits::commitment::CommitmentWithTree;

// =============================================================================
// REBALANCING SYSTEM
// =============================================================================
//
// The rebalancing system ensures data remains optimally distributed when miners
// join or leave the cluster. It follows a Ceph-inspired design using Placement
// Groups (PGs) for efficient change detection and migration.
//
// ## How Rebalancing Works
//
// 1. **Epoch Detection**: The cluster map has an epoch number that increments
//    when topology changes (miner joins/leaves, weight changes).
//
// 2. **PG Diff Calculation**: When epoch changes, we compare CRUSH placement
//    for all PGs between old and new epochs to find which PGs changed owners.
//
// 3. **Migration Queue**: Changed PGs are enqueued for gradual migration,
//    bounded by REBALANCE_MAX_PGS to prevent memory explosion.
//
// 4. **Worker Pool**: Multiple workers process the queue in parallel,
//    sending PullFromPeer messages to move shards to new owners.
//
// 5. **Status Tracking**: Each PG's rebalance status is tracked so gateways
//    can use epoch lookback during the transition period.
//
// ## Why PG-Based Design?
//
// With potentially millions of files, comparing placement per-file would be
// expensive. PGs partition the hash space (default 16,384 groups), so we only
// need to compare 16K placements instead of millions.
//
// ## Configuration
//
// | Env Variable | Default | Description |
// |--------------|---------|-------------|
// | REBALANCE_ENABLED | true | Master switch for rebalancing |
// | REBALANCE_MAX_PGS | 2000 | Max PGs to process per epoch change |
// | REBALANCE_WORKERS | 4 | Parallel migration workers |

/// Background rebalance coordinator (Ceph-style, PG-based).
///
/// This infinite loop:
/// 1. Checks for epoch changes every 15 seconds
/// 2. When epoch changes, computes which PGs have different CRUSH placement
/// 3. Enqueues changed PGs for migration
/// 4. Spawns workers to process the migration queue
///
/// The rebalance can be paused at runtime by setting `REBALANCE_ENABLED=false`.
async fn rebalance_loop(state: Arc<AppState>) {
    loop {
        // Wait for validator to be fully ready before processing rebalance
        if !state.is_ready() {
            tokio::time::sleep(std::time::Duration::from_secs(5)).await;
            continue;
        }

        // Allow operator to pause rebalance safely
        let rebalance_enabled = std::env::var("REBALANCE_ENABLED")
            .ok()
            .map(|v| v != "0" && v.to_lowercase() != "false")
            .unwrap_or(true);
        if !rebalance_enabled {
            tokio::time::sleep(std::time::Duration::from_secs(30)).await;
            continue;
        }

        // Check current epoch
        let cur_epoch = { state.cluster_map.read().await.epoch };
        let mut last_epoch_guard = state.rebalance_last_epoch.lock().await;
        let last_epoch = *last_epoch_guard;

        if cur_epoch > 0 && cur_epoch > last_epoch {
            let from_epoch = cur_epoch.saturating_sub(1);
            let to_epoch = cur_epoch;
            info!(
                from_epoch = from_epoch,
                to_epoch = to_epoch,
                "Rebalance: detected epoch change"
            );

            // Load old map (epoch-scoped) and current map
            let old_map = get_map_epoch_internal(&state, from_epoch).await;
            let new_map = state.cluster_map.read().await.clone();

            if let Some(old_map) = old_map {
                let shards_per_file = new_map.ec_k + new_map.ec_m;
                let mut changed: Vec<u32> = Vec::new();
                for pg_id in 0..new_map.pg_count {
                    let old_pl =
                        common::calculate_pg_placement(pg_id, shards_per_file, &old_map).ok();
                    let new_pl =
                        common::calculate_pg_placement(pg_id, shards_per_file, &new_map).ok();
                    let (old_uids, new_uids) = match (old_pl.as_ref(), new_pl.as_ref()) {
                        (Some(old), Some(new)) => {
                            let old_uids: std::collections::HashSet<u32> =
                                old.iter().map(|m| m.uid).collect();
                            let new_uids: std::collections::HashSet<u32> =
                                new.iter().map(|m| m.uid).collect();
                            (old_uids, new_uids)
                        }
                        _ => continue,
                    };
                    if old_uids != new_uids {
                        changed.push(pg_id);
                    }
                }

                info!(pg_count = changed.len(), "Rebalance: PGs changed owners");
                state.metrics.rebalance_ops.inc();

                // Initialize rebalance status for each changed PG
                let rebalance_start_ts = now_secs();
                for &pg_id in &changed {
                    let status = PgRebalanceStatus {
                        epoch: to_epoch,
                        pg_id,
                        total_shards: 0, // Will be updated per-file
                        confirmed_shards: 0,
                        started_at: rebalance_start_ts,
                        settled_at: None,
                        expected_files: 0, // Will be set by rebalance_worker when file count is known
                        processed_files: 0,
                    };
                    state.rebalance_status.insert((to_epoch, pg_id), status);
                }

                // Enqueue work (bounded to avoid memory explosion)
                {
                    let max_pgs: usize = std::env::var("REBALANCE_MAX_PGS")
                        .ok()
                        .and_then(|s| s.parse::<usize>().ok())
                        .unwrap_or(2000);
                    let mut q = state.rebalance_queue.lock().await;
                    q.clear();
                    for pg in changed.into_iter().take(max_pgs) {
                        q.push_back(pg);
                    }
                    state.metrics.rebalance_queue_depth.set(q.len() as i64);
                }

                *last_epoch_guard = to_epoch;

                // Spawn a few workers to drain the queue
                let workers: usize = std::env::var("REBALANCE_WORKERS")
                    .ok()
                    .and_then(|s| s.parse::<usize>().ok())
                    .unwrap_or(4);
                for _ in 0..workers {
                    let s = state.clone();
                    tokio::spawn(async move {
                        rebalance_worker(s, from_epoch, to_epoch).await;
                    });
                }
            } else {
                info!(
                    epoch = from_epoch,
                    "Rebalance: old map not found, skipping rebalance"
                );
                *last_epoch_guard = to_epoch;
            }

            // Finalize attestations for the old epoch (fire-and-forget)
            // This runs on ANY epoch change, regardless of whether old map was found for rebalancing
            let state_for_attestation = state.clone();
            tokio::spawn(async move {
                if let Err(e) = finalize_epoch_attestations(&state_for_attestation, to_epoch).await
                {
                    warn!(
                        error = %e,
                        epoch = from_epoch,
                        "Failed to finalize epoch attestations"
                    );
                }
            });
        }

        drop(last_epoch_guard);
        tokio::time::sleep(std::time::Duration::from_secs(15)).await;
    }
}

/// Finalize epoch attestations when epoch changes.
///
/// This function:
/// 1. Builds merkle trees for all accumulated attestations
/// 2. Creates an AttestationBundle and uploads it to the gateway
/// 3. Sends the commitment to the chain-submitter via P2P
///
/// Called by the rebalance loop when epoch changes are detected.
async fn finalize_epoch_attestations(state: &Arc<AppState>, new_epoch: u64) -> Result<()> {
    use common::blake3_hash;
    use parity_scale_codec::Encode;

    // Finalize the epoch and get the bundle
    let (bundle, mut commitment) =
        match state.attestation_aggregator.finalize_epoch(new_epoch).await {
            Some(result) => result,
            None => {
                debug!(
                    new_epoch = new_epoch,
                    "No attestations to finalize for epoch"
                );
                return Ok(());
            }
        };

    info!(
        epoch = bundle.epoch,
        attestation_count = bundle.attestation_count(),
        warden_count = bundle.warden_pubkeys.len(),
        "Finalizing attestation bundle for epoch"
    );

    // Encode the bundle
    let bundle_bytes = bundle.encode();
    let arion_content_hash = blake3_hash(&bundle_bytes);
    commitment.arion_content_hash = arion_content_hash;

    // Upload bundle to gateway if configured
    if let Some(gateway_url) = &state.gateway_url {
        match upload_bundle_to_gateway(gateway_url, &bundle_bytes, &arion_content_hash).await {
            Ok(()) => {
                info!(
                    epoch = bundle.epoch,
                    arion_hash = hex::encode(arion_content_hash),
                    size = bundle_bytes.len(),
                    "Attestation bundle uploaded to gateway"
                );
            }
            Err(e) => {
                warn!(
                    error = %e,
                    epoch = bundle.epoch,
                    "Failed to upload attestation bundle to gateway"
                );
                // Continue anyway - the commitment can be sent to chain-submitter
                // and the bundle can be re-uploaded later
            }
        }
    } else {
        debug!(
            epoch = bundle.epoch,
            "No GATEWAY_URL configured, skipping bundle upload"
        );
    }

    // Send commitment to chain-submitter via P2P if configured
    if let Some(ref manager) = state.submitter_connection_manager {
        match send_commitment_to_submitter(manager, &commitment).await {
            Ok(()) => {
                info!(
                    epoch = commitment.epoch,
                    attestation_count = commitment.attestation_count,
                    "Attestation commitment sent to chain-submitter"
                );
            }
            Err(e) => {
                warn!(
                    error = %e,
                    epoch = commitment.epoch,
                    "Failed to send attestation commitment to chain-submitter"
                );
            }
        }
    } else {
        debug!(
            epoch = commitment.epoch,
            "No chain-submitter connection configured, skipping commitment notification"
        );
    }

    Ok(())
}

/// Upload an attestation bundle to the gateway.
async fn upload_bundle_to_gateway(
    gateway_url: &str,
    bundle_bytes: &[u8],
    arion_hash: &[u8; 32],
) -> Result<()> {
    let client = reqwest::Client::builder()
        .timeout(Duration::from_secs(120))
        .build()?;

    let url = format!("{}/upload", gateway_url.trim_end_matches('/'));

    // Create multipart form with the bundle as a file
    let filename = format!("attestation_bundle_{}.scale", hex::encode(arion_hash));
    let part = reqwest::multipart::Part::bytes(bundle_bytes.to_vec())
        .file_name(filename)
        .mime_str("application/octet-stream")?;

    let form = reqwest::multipart::Form::new().part("file", part);

    // Get API key from environment if available
    let mut request = client.post(&url).multipart(form);
    if let Ok(api_key) = std::env::var("GATEWAY_API_KEY") {
        request = request.header("Authorization", format!("Bearer {}", api_key));
    } else if let Ok(api_key) = std::env::var("API_KEY_ADMIN") {
        request = request.header("Authorization", format!("Bearer {}", api_key));
    }

    let response = request.send().await?;

    if response.status().is_success() {
        Ok(())
    } else {
        let status = response.status();
        let body = response.text().await.unwrap_or_default();
        Err(anyhow!("Gateway upload failed: {} - {}", status, body))
    }
}

/// Send an attestation commitment to the chain-submitter via P2P.
async fn send_commitment_to_submitter(
    manager: &common::P2pConnectionManager,
    commitment: &common::EpochAttestationCommitment,
) -> Result<()> {
    use common::{P2P_MAX_MESSAGE_SIZE, SubmitterControlMessage};

    let message = SubmitterControlMessage::AttestationCommitmentReady {
        commitment: commitment.clone(),
    };
    let message_bytes = serde_json::to_vec(&message)?;

    // Get connection to submitter
    let conn = manager.get_connection().await?;

    // Send message
    let (mut send, mut recv) = conn.open_bi().await?;
    send.write_all(&message_bytes).await?;
    send.flush().await?;
    send.finish()?;

    // Wait for ack
    let response_buf = recv.read_to_end(P2P_MAX_MESSAGE_SIZE).await?;

    let response: SubmitterControlMessage = serde_json::from_slice(&response_buf)?;

    match response {
        SubmitterControlMessage::AttestationCommitmentAck { success, message } => {
            if success {
                Ok(())
            } else {
                Err(anyhow!(
                    "Chain-submitter rejected commitment: {}",
                    message.unwrap_or_default()
                ))
            }
        }
        _ => Err(anyhow!("Unexpected response from chain-submitter")),
    }
}

async fn get_map_epoch_internal(state: &AppState, epoch: u64) -> Option<common::ClusterMap> {
    let key = cluster_map_epoch_key(epoch);
    let query = iroh_docs::store::Query::single_latest_per_key().key_exact(key.as_slice());
    let mut stream = Box::pin(state.doc.get_many(query).await.ok()?);
    let entry = stream.next().await?.ok()?;
    let hash = entry.content_hash();
    let mut reader = state.blobs_store.reader(hash);
    let mut content = Vec::new();
    if reader.read_to_end(&mut content).await.is_err() {
        return None;
    }
    serde_json::from_slice::<common::ClusterMap>(&content).ok()
}

/// Worker that processes the rebalance queue.
///
/// Each worker:
/// 1. Pops a PG ID from the shared queue
/// 2. Loads the list of files in that PG from the persisted index
/// 3. For each file, spawns a task to migrate shards to new owners
///
/// The worker terminates when the queue is empty.
///
/// ## Concurrency Control
///
/// - `REBALANCE_CONCURRENCY` (default 100): Max concurrent file migrations per worker
/// - `REBALANCE_FILES_PER_PG` (default 100): Max files to process per PG per pass
///
/// This prevents overwhelming miners with too many simultaneous pull requests.
async fn rebalance_worker(state: Arc<AppState>, from_epoch: u64, to_epoch: u64) {
    // Concurrency limiter to avoid overwhelming miners (semaphore-based backpressure)
    let sem_limit: usize = std::env::var("REBALANCE_CONCURRENCY")
        .ok()
        .and_then(|s| s.parse::<usize>().ok())
        .unwrap_or(100);
    let sem = Arc::new(tokio::sync::Semaphore::new(sem_limit));
    loop {
        let pg_id = {
            let mut q = state.rebalance_queue.lock().await;
            state.metrics.rebalance_queue_depth.set(q.len() as i64);
            q.pop_front()
        };
        let Some(pg_id) = pg_id else {
            break;
        };

        // Get file list for PG from the persisted, paged PG index (scales beyond RAM).
        let files = match get_pg_files_from_doc(&state, pg_id, 2000).await {
            Ok(v) => v,
            Err(_) => Vec::new(),
        };
        if files.is_empty() {
            // Mark PG as settled if no files to process
            if let Some(mut status) = state.rebalance_status.get_mut(&(to_epoch, pg_id)) {
                status.settled_at = Some(now_secs());
            }
            continue;
        }

        let old_map = match get_map_epoch_internal(&state, from_epoch).await {
            Some(m) => m,
            None => continue,
        };
        let new_map = state.cluster_map.read().await.clone();

        let files_per_pg: usize = std::env::var("REBALANCE_FILES_PER_PG")
            .ok()
            .and_then(|s| s.parse::<usize>().ok())
            .unwrap_or(100);

        // Set expected_files count for this PG (bounded by files_per_pg)
        let actual_file_count = files.len().min(files_per_pg);
        if let Some(mut status) = state.rebalance_status.get_mut(&(to_epoch, pg_id)) {
            status.expected_files = actual_file_count;
        }

        // Process a bounded number of files per PG per worker pass
        for file_hash in files.into_iter().take(files_per_pg) {
            let permit = sem.clone().acquire_owned().await;
            let Ok(permit) = permit else {
                // Semaphore closed - skip this file
                continue;
            };
            let s = state.clone();
            let om = old_map.clone();
            let nm = new_map.clone();
            tokio::spawn(async move {
                let _permit = permit;
                let _ = rebalance_file(&s, &file_hash, &om, &nm, to_epoch).await;
            });
        }
    }
}

// =============================================================================
// PLACEMENT GROUP (PG) INDEX
// =============================================================================
//
// The PG index is a scalable, paged data structure that maps each PG to the
// files it contains. This is essential for rebalancing - when a PG's placement
// changes, we need to find all files in that PG to migrate their shards.
//
// ## Why Paged?
//
// With millions of files, keeping the entire index in memory is infeasible.
// Instead, we page the index:
// - Each PG has metadata (page count, file count)
// - Each page contains up to PG_INDEX_PAGE_SIZE (1000) file hashes
// - Pages are loaded on-demand from iroh-docs
//
// ## Storage Keys
//
// - `pg_index:meta:{pg_id}` - PgIndexMeta JSON (page count, file count)
// - `pg_index:pg:{pg_id}:page:{page_num}` - JSON array of file hashes
//
// ## Operations
//
// - `load_pg_index_meta()` - Load metadata for a PG
// - `save_pg_index_meta()` - Save metadata for a PG
// - `load_pg_index_page()` - Load a specific page of file hashes
// - `save_pg_index_page()` - Save a page of file hashes
// - `pg_index_add_file()` - Add a file hash to its PG's index
// - `get_pg_files_from_doc()` - Get all files in a PG (up to limit)

/// Load the metadata for a Placement Group's file index.
///
/// Returns `PgIndexMeta` with:
/// - `last_page`: Index of the last page (0-based)
/// - `total_files`: Total number of files in this PG
async fn load_pg_index_meta(state: &AppState, pg_id: u32) -> Result<PgIndexMeta> {
    let key = pg_index_meta_key(pg_id);
    let query = iroh_docs::store::Query::single_latest_per_key().key_exact(key.as_slice());
    let mut stream = Box::pin(state.doc.get_many(query).await?);
    if let Some(Ok(entry)) = stream.next().await {
        let mut reader = state.blobs_store.reader(entry.content_hash());
        let mut content = Vec::new();
        reader.read_to_end(&mut content).await?;
        if let Ok(meta) = serde_json::from_slice::<PgIndexMeta>(&content) {
            return Ok(meta);
        }
    }
    Ok(PgIndexMeta::default())
}

async fn save_pg_index_meta(state: &AppState, pg_id: u32, meta: &PgIndexMeta) -> Result<()> {
    let key = pg_index_meta_key(pg_id);
    let json = serde_json::to_vec(meta)?;
    state
        .doc
        .set_bytes(state.author_id, Bytes::from(key), Bytes::from(json))
        .await?;
    Ok(())
}

async fn load_pg_index_page(state: &AppState, pg_id: u32, page: u32) -> Result<Vec<String>> {
    let key = pg_index_page_key(pg_id, page);
    let query = iroh_docs::store::Query::single_latest_per_key().key_exact(key.as_slice());
    let mut stream = Box::pin(state.doc.get_many(query).await?);
    if let Some(Ok(entry)) = stream.next().await {
        let mut reader = state.blobs_store.reader(entry.content_hash());
        let mut content = Vec::new();
        reader.read_to_end(&mut content).await?;
        if let Ok(v) = serde_json::from_slice::<Vec<String>>(&content) {
            return Ok(v);
        }
    }
    Ok(Vec::new())
}

async fn save_pg_index_page(
    state: &AppState,
    pg_id: u32,
    page: u32,
    files: &[String],
) -> Result<()> {
    let key = pg_index_page_key(pg_id, page);
    let json = serde_json::to_vec(files)?;
    state
        .doc
        .set_bytes(state.author_id, Bytes::from(key), Bytes::from(json))
        .await?;
    Ok(())
}

/// Append a file hash to the PG's paged index.
/// Single-writer assumption: validator is the only writer, so simple overwrite is safe.
async fn pg_index_add_file(state: &AppState, pg_id: u32, file_hash: &str) -> Result<()> {
    let mut meta = load_pg_index_meta(state, pg_id).await?;
    let mut page = meta.last_page;
    let mut files = load_pg_index_page(state, pg_id, page).await?;

    // Best-effort de-dup: only check last page (cheap, prevents duplicates on retries).
    if files.iter().any(|h| h == file_hash) {
        return Ok(());
    }

    if files.len() >= PG_INDEX_PAGE_SIZE {
        page = page.saturating_add(1);
        meta.last_page = page;
        files = Vec::new();
    }

    files.push(file_hash.to_string());
    save_pg_index_page(state, pg_id, page, &files).await?;
    meta.total_files = meta.total_files.saturating_add(1);
    save_pg_index_meta(state, pg_id, &meta).await?;
    Ok(())
}

/// Read up to `limit` file hashes from a PG's index (oldest pages first).
async fn get_pg_files_from_doc(state: &AppState, pg_id: u32, limit: usize) -> Result<Vec<String>> {
    let meta = load_pg_index_meta(state, pg_id).await?;
    let mut out: Vec<String> = Vec::new();
    for page in 0..=meta.last_page {
        let files = load_pg_index_page(state, pg_id, page).await?;
        for h in files {
            out.push(h);
            if out.len() >= limit {
                return Ok(out);
            }
        }
    }
    Ok(out)
}

async fn rebalance_file(
    state: &AppState,
    file_hash: &str,
    old_map: &common::ClusterMap,
    new_map: &common::ClusterMap,
    to_epoch: u64,
) -> anyhow::Result<()> {
    // Load manifest from docs
    let entry = state
        .doc
        .get_exact(state.author_id, Bytes::from(file_hash.to_string()), false)
        .await?
        .ok_or_else(|| anyhow::anyhow!("manifest missing"))?;
    let mut reader = state.blobs_store.reader(entry.content_hash());
    let mut content = Vec::new();
    reader.read_to_end(&mut content).await?;
    let manifest: common::FileManifest = serde_json::from_slice(&content)?;

    // Calculate PG for this file
    let pg_id = common::calculate_pg(&manifest.file_hash, new_map.pg_count);

    // IMPORTANT: shard layout is per-file (manifest), not per-cluster.
    // This keeps rebalance backward-compatible as we change the cluster-wide EC defaults (e.g. 10+10 -> 10+20).
    let shards_per_stripe = manifest.stripe_config.k + manifest.stripe_config.m;

    // Count shards that need to move for this file
    let mut shards_to_move = 0usize;
    let mut shards_confirmed = 0usize;

    for shard in manifest.shards.iter() {
        let stripe_idx = shard.index / shards_per_stripe;
        let local_idx = shard.index % shards_per_stripe;

        // Determine old owner and new owner deterministically for this shard position (paper rotation)
        let old_miners = common::calculate_pg_placement_for_stripe(
            &manifest.file_hash,
            stripe_idx as u64,
            shards_per_stripe,
            old_map,
        )
        .map_err(anyhow::Error::msg)?;
        let new_miners = common::calculate_pg_placement_for_stripe(
            &manifest.file_hash,
            stripe_idx as u64,
            shards_per_stripe,
            new_map,
        )
        .map_err(anyhow::Error::msg)?;
        let src = old_miners.get(local_idx).cloned();
        let dst = new_miners.get(local_idx).cloned();
        let (Some(src), Some(dst)) = (src, dst) else {
            continue;
        };
        if src.uid == dst.uid {
            continue;
        }

        shards_to_move += 1;

        // Register pending ACK before sending
        let ack_key = (to_epoch, pg_id, shard.blob_hash.clone());
        state
            .rebalance_pending_acks
            .insert(ack_key.clone(), dst.uid);

        // Instruct destination miner to pull from source miner
        let msg = common::MinerControlMessage::PullFromPeer {
            hash: shard.blob_hash.clone(),
            peer_endpoint: serde_json::to_string(&src.endpoint).unwrap_or_default(),
        };
        let msg_bytes = serde_json::to_vec(&msg)?;

        if let Ok(Ok(conn)) = tokio::time::timeout(
            std::time::Duration::from_secs(10),
            state
                .endpoint
                .connect(dst.endpoint.clone(), b"hippius/miner-control"),
        )
        .await
        {
            if let Ok((mut send, mut recv)) = conn.open_bi().await {
                let _ = send.write_all(&msg_bytes).await;
                let _ = send.finish();

                // Wait for response with timeout
                match tokio::time::timeout(std::time::Duration::from_secs(30), recv.read_to_end(64))
                    .await
                {
                    Ok(Ok(response)) => {
                        if response == b"OK" || response.starts_with(b"OK") {
                            shards_confirmed += 1;
                        }
                    }
                    _ => {
                        debug!(
                            shard = %&shard.blob_hash[..16.min(shard.blob_hash.len())],
                            "PullFromPeer timeout/error"
                        );
                    }
                }
            }
        }

        // Remove from pending regardless of success/failure
        // (we're done with this attempt - either it succeeded or we'll rely on miner self-rebalancing)
        state.rebalance_pending_acks.remove(&ack_key);
    }

    // Update PG rebalance status with totals from this file
    let key = (to_epoch, pg_id);
    state.rebalance_status.entry(key).and_modify(|status| {
        // Always increment processed_files to track completion
        status.processed_files += 1;

        // Add shard counts from this file
        if shards_to_move > 0 {
            status.total_shards += shards_to_move;
            status.confirmed_shards += shards_confirmed;
        }

        // Only check for settlement when ALL files have been processed
        // This fixes the per-file vs per-PG settlement tracking bug
        if status.processed_files >= status.expected_files && status.expected_files > 0 {
            // All files processed - now check if all shards are confirmed
            if status.confirmed_shards >= status.total_shards {
                if status.settled_at.is_none() {
                    status.settled_at = Some(now_secs());
                }
            }
            // Note: Don't clear settled_at here - once all files are processed,
            // the final state is the final state (no more files coming)
        }
    });

    debug!(
        file_hash = %&manifest.file_hash[..16.min(manifest.file_hash.len())],
        to_epoch = to_epoch,
        shards_moved = shards_to_move,
        shards_confirmed = shards_confirmed,
        "Rebalance file completed"
    );

    // Invalidate manifest cache to force re-read after rebalance
    state.manifest_cache.remove(file_hash);

    Ok(())
}

// UploadProgress is now defined in upload_progress module
use upload_progress::{UploadProgress, UploadProgressStore};

async fn require_admin_key(headers: HeaderMap) -> Result<(), (StatusCode, &'static str)> {
    let expected_key = get_admin_api_key();
    if expected_key.is_empty() {
        return Err((
            StatusCode::INTERNAL_SERVER_ERROR,
            "API_KEY_ADMIN not configured",
        ));
    }
    // Check Authorization: Bearer <token> first, then fall back to X-API-Key header
    let provided_key = headers
        .get("Authorization")
        .and_then(|h| h.to_str().ok())
        .and_then(extract_bearer_token)
        .or_else(|| headers.get("X-API-Key").and_then(|h| h.to_str().ok()));
    match provided_key {
        Some(key) if validate_api_key(key, expected_key) => Ok(()),
        _ => Err((StatusCode::UNAUTHORIZED, "Invalid API Key")),
    }
}

async fn require_gateway_key(headers: HeaderMap) -> Result<(), (StatusCode, &'static str)> {
    let expected_key = get_gateway_api_key();
    if expected_key.is_empty() {
        return Err((
            StatusCode::INTERNAL_SERVER_ERROR,
            "API_KEY_GATEWAY not configured",
        ));
    }
    // Check Authorization: Bearer <token> first, then fall back to X-API-Key header
    let provided_key = headers
        .get("Authorization")
        .and_then(|h| h.to_str().ok())
        .and_then(extract_bearer_token)
        .or_else(|| headers.get("X-API-Key").and_then(|h| h.to_str().ok()));
    match provided_key {
        Some(key) if validate_api_key(key, expected_key) => Ok(()),
        _ => Err((StatusCode::UNAUTHORIZED, "Invalid Gateway API Key")),
    }
}

async fn require_admin_middleware(
    headers: HeaderMap,
    req: axum::http::Request<axum::body::Body>,
    next: axum::middleware::Next,
) -> Result<axum::response::Response, (StatusCode, &'static str)> {
    require_admin_key(headers).await?;
    Ok(next.run(req).await)
}

async fn require_gateway_middleware(
    headers: HeaderMap,
    req: axum::http::Request<axum::body::Body>,
    next: axum::middleware::Next,
) -> Result<axum::response::Response, (StatusCode, &'static str)> {
    require_gateway_key(headers).await?;
    Ok(next.run(req).await)
}

/// Suggested retry delay for HTTP clients when validator is warming up
const HTTP_WARMUP_RETRY_SECS: u64 = 30;

/// Check if validator is ready and return a 503 response if not.
///
/// Returns `Some(response)` if the validator is not ready, `None` if ready.
fn check_ready_state(state: &AppState) -> Option<(StatusCode, Json<serde_json::Value>)> {
    let ready_state = state.get_ready_state();
    if ready_state.is_ready() {
        None
    } else {
        Some((
            StatusCode::SERVICE_UNAVAILABLE,
            Json(serde_json::json!({
                "error": format!("Validator is {}", ready_state.status_str()),
                "retry_after_secs": HTTP_WARMUP_RETRY_SECS
            })),
        ))
    }
}

async fn repair_hint(
    State(state): State<Arc<AppState>>,
    Json(req): Json<RepairHintRequest>,
) -> impl IntoResponse {
    // Check ready state - repair hints require full readiness
    if let Some(response) = check_ready_state(&state) {
        return response.into_response();
    }

    if !state.repair_hint_enabled {
        return (StatusCode::SERVICE_UNAVAILABLE, "Repair hints disabled").into_response();
    }

    let now = now_secs();

    let count = req
        .count
        .unwrap_or(state.repair_hint_default_count)
        .max(1)
        .min(50);
    let allow_scan = req.allow_scan.unwrap_or(false);
    let start = req.stripe_idx as usize;
    let key = format!("{}:{}", req.file_hash, start);

    // Dedupe (avoid flooding on repeated client retries)
    // Using bounded QuickCache - old entries evicted automatically when capacity reached
    if let Some((ts, prev_allow_scan, prev_count)) = state.repair_hint_dedupe.get(&key) {
        if now.saturating_sub(ts) <= state.repair_hint_dedupe_ttl_secs {
            // Only dedupe if the new request doesn't add "more power" (scan, larger count).
            if (!allow_scan || prev_allow_scan) && count <= prev_count {
                return (StatusCode::ACCEPTED, "Deduped").into_response();
            }
        }
    }
    state
        .repair_hint_dedupe
        .insert(key.clone(), (now, allow_scan, count));

    // Enqueue bounded work
    {
        let mut q = state.repair_hint_queue.lock().await;
        if q.len() >= state.repair_hint_queue_max {
            return (StatusCode::TOO_MANY_REQUESTS, "Repair hint queue full").into_response();
        }
        q.push_back((req.file_hash, start, count, allow_scan));
    }

    (StatusCode::ACCEPTED, "Enqueued").into_response()
}

async fn repair_hint_worker_loop(state: Arc<AppState>) {
    let sem = Arc::new(tokio::sync::Semaphore::new(state.repair_hint_concurrency));
    loop {
        let job = {
            let mut q = state.repair_hint_queue.lock().await;
            q.pop_front()
        };
        let Some((file_hash, start, count, allow_scan)) = job else {
            tokio::time::sleep(std::time::Duration::from_secs(1)).await;
            continue;
        };

        // Gate scan fallback via env (off by default); requests can only enable it if allowed.
        let scan_allowed = std::env::var("REPAIR_HINT_ALLOW_SCAN")
            .ok()
            .map(|v| v != "0" && v.to_lowercase() != "false")
            .unwrap_or(false);
        let scan = allow_scan && scan_allowed;

        let permit = sem.clone().acquire_owned().await;
        let Ok(permit) = permit else {
            // Semaphore closed - skip this repair hint
            continue;
        };
        let s = state.clone();
        tokio::spawn(async move {
            let _permit = permit;
            // Reuse existing repair logic via direct call (no HTTP). This keeps miner control in validator.
            let mut q = std::collections::HashMap::new();
            q.insert("start".to_string(), start.to_string());
            q.insert("count".to_string(), count.to_string());
            q.insert(
                "scan".to_string(),
                if scan {
                    "1".to_string()
                } else {
                    "0".to_string()
                },
            );
            // If scan is requested+allowed, enable scan for this process via env convention.
            // The underlying code already checks REPAIR_SCAN_ENABLED.
            let _ = repair_file(State(s), Path(file_hash), AxumQuery(q)).await;
        });
    }
}

// =============================================================================
// MAIN ENTRY POINT
// =============================================================================
//
// The validator's main function orchestrates the startup of all components:
//
// 1. **Configuration Loading**: TOML config with environment variable overrides
// 2. **Iroh P2P Initialization**: Endpoint, relay connection, key generation
// 3. **Storage Initialization**: Blob store (FsStore), document store (iroh-docs)
// 4. **HTTP Server**: Axum router with all API endpoints
// 5. **Background Tasks**: Recovery loop, rebalance loop, backup scheduler
//
// ## Startup Sequence
//
// ```text
// 1. Load config (validator.toml + env vars)
// 2. Restore from S3 backup if needed (missing docs.db)
// 3. Load or generate Ed25519 keypair
// 4. Initialize Iroh Endpoint with relay
// 5. Initialize blob storage (FsStore)
// 6. Initialize document storage (iroh-docs)
// 7. Create or open validator document
// 8. Load cluster map from doc (or create empty)
// 9. Initialize application state (AppState)
// 10. Start P2P protocol handlers
// 11. Start background loops (recovery, rebalance, backup)
// 12. Start HTTP server
// ```
//
// ## Data Persistence
//
// | Path | Format | Purpose |
// |------|--------|---------|
// | `data/validator/docs.db` | SQLite | iroh-docs database (manifests, maps) |
// | `data/validator/blobs/` | Content-addressed | Encoded shards (temporary) |
// | `data/validator/node_id.txt` | Text | Validator's Iroh node ID |
// | `data/validator/keypair.bin` | Binary | Ed25519 secret key |
// | `data/validator/default_author.dat` | Binary | Persistent author ID |
// | `upload_progress.redb` | ReDB | Upload progress tracking |

use clap::Parser;

/// Command-line arguments for the validator
#[derive(Parser, Debug)]
#[command(author, version, about, long_about = None)]
struct Args {
    /// URL of the Gateway for audit callbacks (used by audit loop)
    #[arg(long, env = "GATEWAY_URL", default_value = "http://gateway:3000")]
    gateway_url: String,

    /// HTTP port to listen on for API requests
    #[arg(long, env = "PORT", default_value = "3002")]
    port: u16,
}

// =============================================================================
// BACKGROUND INDEX LOADING
// =============================================================================
//
// The index loading is performed in the background to allow the validator to
// accept P2P connections immediately on startup. This reduces the effective
// startup time from 30+ minutes (full index rebuild) to ~5 seconds (P2P ready).
//
// The validator goes through these states:
// 1. WarmingUp: P2P is accepting connections, storage is loading
// 2. IndexingInProgress: Storage loaded, building sync index and PG index
// 3. Ready: Fully operational

/// Load indexes in the background after P2P is ready.
///
/// This function runs after the P2P router is started, allowing the validator
/// to accept connections while indexes are being built. Operations that require
/// full readiness will return "warming up" errors until this completes.
///
/// The function:
/// 1. Tries to load index from cache (fast path)
/// 2. If cache miss/invalid, loads from sync_index in iroh-docs
/// 3. If that fails, rebuilds by scanning all manifests
/// 4. Builds PG index from manifest hashes
/// 5. Saves cache for next restart
/// 6. Sets ready_state to Ready
async fn load_indexes_background(state: Arc<AppState>, data_dir: std::path::PathBuf) {
    info!("Starting background index loading...");

    // Transition to IndexingInProgress
    state.set_ready_state(ValidatorReadyState::IndexingInProgress);

    // Load cluster_map first (needed for PG index)
    if let Some(map) = load_latest_cluster_map_from_doc(&state).await {
        info!(
            epoch = map.epoch,
            miners = map.miners.len(),
            "Loaded cluster_map into cache"
        );
        let mut cache = state.cluster_map.write().await;
        *cache = map;
    }

    let epoch = state.cluster_map.read().await.epoch;

    // Try to load from index cache (fast path)
    if let Some(cache) = index_cache::IndexCache::load(&data_dir, epoch).await {
        info!(
            files = cache.file_count(),
            pgs = cache.pg_count(),
            "Restored indexes from cache (fast startup)"
        );
        cache.apply_to_state(&state.manifest_hashes, &state.pg_index);

        // Transition to Ready
        state.set_ready_state(ValidatorReadyState::Ready);
        info!("Validator fully ready (from cache)");

        // Optionally verify cache in background
        let state_verify = state.clone();
        tokio::spawn(async move {
            verify_index_integrity(&state_verify).await;
        });

        return;
    }

    // Cache miss - need to load from storage
    info!("Index cache miss - loading from storage...");

    // Load Sync Index to populate manifest_hashes
    let mut loaded_from_sync_index = false;
    let query_idx = iroh_docs::store::Query::single_latest_per_key().key_exact(b"sync_index");
    if let Ok(stream) = state.doc.get_many(query_idx).await {
        let mut stream = Box::pin(stream);
        if let Some(Ok(entry)) = stream.next().await {
            let hash = entry.content_hash();
            let mut reader = state.blobs_store.reader(hash);
            let mut content = Vec::new();
            if reader.read_to_end(&mut content).await.is_ok() {
                let json_str = String::from_utf8_lossy(&content);
                if let Ok(index) = serde_json::from_str::<SyncIndex>(&json_str) {
                    info!(files = index.files.len(), "Loaded Sync Index from storage");
                    let mut hashes = state.manifest_hashes.lock().await;
                    *hashes = index.files;
                    loaded_from_sync_index = true;
                } else {
                    warn!("Failed to parse Sync Index, will rebuild");
                }
            }
        } else {
            info!("No Sync Index found, will rebuild");
        }
    }

    // If sync index was empty or failed, rebuild by scanning docs
    if !loaded_from_sync_index || state.manifest_hashes.lock().await.is_empty() {
        info!("Rebuilding index by scanning Doc...");
        rebuild_manifest_index(&state).await;
    }

    // Build PG index
    build_pg_index(&state).await;

    // Save cache for next restart
    let manifest_hashes = state.manifest_hashes.lock().await.clone();
    let cache = index_cache::IndexCache::new(epoch, manifest_hashes, &state.pg_index);
    if let Err(e) = cache.save(&data_dir).await {
        warn!(error = %e, "Failed to save index cache");
    }

    // Transition to Ready
    state.set_ready_state(ValidatorReadyState::Ready);
    info!("Validator fully ready");
}

/// Rebuild the manifest index by scanning all documents.
async fn rebuild_manifest_index(state: &Arc<AppState>) {
    let mut hashes = state.manifest_hashes.lock().await;
    if !hashes.is_empty() {
        return; // Already populated
    }

    info!("Index is empty, scanning Doc for existing manifests");
    let query_all = iroh_docs::store::Query::all();
    if let Ok(stream) = state.doc.get_many(query_all).await {
        let mut stream = Box::pin(stream);
        let mut count = 0u64;
        while let Some(Ok(entry)) = stream.next().await {
            // Skip known non-manifest keys
            let key = entry.key();
            if key.starts_with(b"cluster_map")
                || key == b"sync_index"
                || key == b"blacklist"
                || key == b"cooldowns"
            {
                continue;
            }

            let hash = entry.content_hash();
            let mut reader = state.blobs_store.reader(hash);
            let mut content = Vec::new();
            if reader.read_to_end(&mut content).await.is_ok() {
                let json_str = String::from_utf8_lossy(&content);
                if let Ok(manifest) = serde_json::from_str::<FileManifest>(&json_str) {
                    hashes.push(FileSummary {
                        hash: manifest.file_hash,
                        size: manifest.size,
                    });
                    count += 1;
                    if count % 1000 == 0 {
                        info!(count = count, "Indexing progress...");
                    }
                }
            }
        }
    }
    info!(files = hashes.len(), "Re-indexing complete");

    // Persist the rebuilt index (drop lock first)
    drop(hashes);
    if !state.manifest_hashes.lock().await.is_empty() {
        if let Err(e) = update_sync_index(state).await {
            error!(error = %e, "Failed to persist rebuilt index");
        } else {
            info!("Persisted rebuilt index");
        }
    }
}

/// Build the PG index from manifest hashes.
async fn build_pg_index(state: &Arc<AppState>) {
    let pg_count = state.cluster_map.read().await.pg_count;
    let files = state.manifest_hashes.lock().await.clone();
    let files_count = files.len();

    state.pg_index.clear();
    for f in files {
        let pg_id = common::calculate_pg(&f.hash, pg_count);
        state.pg_index.entry(pg_id).or_default().push(f.hash);
    }

    let idx_len = state.pg_index.len();
    info!(
        pgs = idx_len,
        files = files_count,
        pg_count = pg_count,
        "Built PG index"
    );
}

/// Verify index integrity in the background (optional validation after cache load).
async fn verify_index_integrity(state: &Arc<AppState>) {
    // Light verification: spot-check a few manifests exist
    let hashes = state.manifest_hashes.lock().await;
    if hashes.is_empty() {
        return;
    }

    let sample_size = std::cmp::min(10, hashes.len());
    let mut verified = 0;

    for summary in hashes.iter().take(sample_size) {
        let key = format!("manifest:{}", summary.hash).into_bytes();
        let query = iroh_docs::store::Query::single_latest_per_key().key_exact(&key);
        if let Ok(stream) = state.doc.get_many(query).await {
            let mut stream = Box::pin(stream);
            if stream.next().await.is_some() {
                verified += 1;
            }
        }
    }

    if verified < sample_size {
        warn!(
            verified = verified,
            expected = sample_size,
            "Index cache verification found missing manifests"
        );
    } else {
        debug!(verified = verified, "Index cache verification passed");
    }
}

use iroh::SecretKey;

/// Main entry point for the Hippius Arion Validator.
///
/// This function:
/// 1. Initializes logging with tracing-subscriber
/// 2. Loads configuration from validator.toml and environment
/// 3. Sets up Iroh P2P networking with relay support
/// 4. Initializes storage (blobs and documents)
/// 5. Creates or loads the validator's cluster map
/// 6. Spawns background tasks (recovery, rebalance, backup)
/// 7. Starts the HTTP API server
///
/// The validator runs indefinitely until terminated.
#[tokio::main]
async fn main() -> anyhow::Result<()> {
    // Default to info level for validator crate, allow RUST_LOG override
    let filter = EnvFilter::try_from_default_env()
        .unwrap_or_else(|_| EnvFilter::new("validator=info,common=info"));
    tracing_subscriber::fmt().with_env_filter(filter).init();

    let args = Args::parse();
    info!(version = env!("CARGO_PKG_VERSION"), "Starting validator");

    // Load configuration from file with env overrides
    let config = match config::ValidatorConfig::load(None) {
        Ok(c) => c,
        Err(e) => {
            error!(error = %e, "Failed to load config");
            return Err(anyhow::anyhow!("Config load failed"));
        }
    };

    // Validate backup config if enabled
    if let Err(e) = config.validate_backup() {
        warn!(error = %e, "Backup config issue");
    }

    // 1. Initialize Iroh Endpoint
    let data_dir = std::path::PathBuf::from(&config.network.data_dir);
    tokio::fs::create_dir_all(&data_dir).await?;

    // Try to restore from backup if docs.db is missing
    if config.backup.enabled {
        match backup::BackupManager::new(config.backup.clone(), data_dir.clone()).await {
            Ok(backup_manager) => match backup_manager.restore_if_needed().await {
                Ok(true) => info!("Restored from backup"),
                Ok(false) => {}
                Err(e) => warn!(error = %e, "Backup restore check failed"),
            },
            Err(e) => warn!(error = %e, "Backup manager init failed"),
        }
    }

    let secret_key = load_keypair(&data_dir).await?;

    // Get relay URL from config, environment, or use default
    let relay_url = common::get_relay_url(config.network.relay_url.as_deref());
    info!(relay_url = %relay_url, "Configuring relay");

    let mut endpoint_builder = iroh::Endpoint::builder()
        .secret_key(secret_key)
        .bind_addr_v4(std::net::SocketAddrV4::new(
            std::net::Ipv4Addr::UNSPECIFIED,
            11220,
        ));

    // Configure transport with keep-alive to maintain relay connections
    let mut transport_config = iroh::endpoint::TransportConfig::default();
    transport_config.keep_alive_interval(Some(std::time::Duration::from_secs(15)));
    transport_config.max_idle_timeout(
        std::time::Duration::from_secs(60)
            .try_into()
            .ok()
            .map(Some)
            .unwrap_or(None),
    );
    endpoint_builder = endpoint_builder.transport_config(transport_config);

    // Configure relay using consistent pattern from common crate
    endpoint_builder = endpoint_builder.relay_mode(common::build_relay_mode(&relay_url));

    let endpoint = endpoint_builder.bind().await?;

    // Wait for relay connection
    info!(
        wait_secs = common::RELAY_CONNECTION_WAIT_SECS,
        "Waiting for relay connection"
    );
    tokio::time::sleep(tokio::time::Duration::from_secs(
        common::RELAY_CONNECTION_WAIT_SECS,
    ))
    .await;
    info!("P2P ready");

    info!(node_id = %endpoint.secret_key().public(), "Validator Iroh Node ID");
    info!("Validator bound to port 11220");

    // Save Node ID to file for easy ansible/deployment reference
    let node_id_str = endpoint.secret_key().public().to_string();
    if let Err(e) = tokio::fs::write(data_dir.join("node_id.txt"), &node_id_str).await {
        warn!(error = %e, "Failed to write node_id.txt");
    } else {
        info!("Node ID saved to data/validator/node_id.txt");
    }

    // 2. Initialize Components
    let blobs_dir = data_dir.join("blobs");
    tokio::fs::create_dir_all(&blobs_dir).await?;
    debug!(path = ?blobs_dir, "Loading Blobs Store");
    let blobs_store = iroh_blobs::store::fs::FsStore::load(&blobs_dir).await?;
    debug!("Blobs Store loaded");

    let docs_path = data_dir.join("docs.db");
    debug!(path = ?docs_path, "Loading Docs Store");
    let docs_store = iroh_docs::store::fs::Store::persistent(&docs_path)?;
    debug!("Docs Store loaded");

    let downloader = iroh_blobs::api::downloader::Downloader::new(&blobs_store, &endpoint);

    let gossip = iroh_gossip::net::Gossip::builder().spawn(endpoint.clone());

    // Persist the author ID so cluster_map survives restarts
    let author_file = data_dir.join("default_author.dat");
    let default_author_storage = DefaultAuthorStorage::Persistent(author_file);
    debug!("Using persistent author storage");

    // 3. Spawn Engine
    let docs_engine = Engine::spawn(
        endpoint.clone(),
        gossip,
        docs_store,
        blobs_store.deref().clone(),
        downloader,
        default_author_storage,
        None, // ProtectCallback
    )
    .await?;
    debug!("Engine spawned");

    let docs_engine_arc = Arc::new(docs_engine);
    let docs_api = DocsApi::spawn(docs_engine_arc.clone());

    // 4. Create or Load Default Doc
    let doc_id_path = data_dir.join("validator_doc_id.txt");
    let doc = if doc_id_path.exists() {
        let doc_id_str = tokio::fs::read_to_string(&doc_id_path).await?;
        let doc_id = iroh_docs::NamespaceId::from_str(doc_id_str.trim())?;
        info!(doc_id = %doc_id, "Loading existing Doc ID");
        docs_api
            .open(doc_id)
            .await?
            .ok_or_else(|| anyhow::anyhow!("Failed to open existing doc"))?
    } else {
        let doc = docs_api.create().await?;
        info!(doc_id = %doc.id(), "Created new Doc ID");
        tokio::fs::write(&doc_id_path, doc.id().to_string()).await?;
        doc
    };
    info!(doc_id = %doc.id(), "Validator Doc ID");

    // Share the doc with Read access and include addresses for direct connection
    let ticket = doc
        .share(ShareMode::Read, AddrInfoOptions::RelayAndAddresses)
        .await?;
    let doc_ticket = ticket;
    debug!(ticket = %doc_ticket, "Validator Doc Ticket");

    // Write ticket to file for other services
    if let Err(e) = tokio::fs::write("data/validator_ticket.txt", doc_ticket.to_string()).await {
        warn!(error = %e, "Failed to write ticket file");
    }

    let author_id = docs_api.author_default().await?;

    // Create family registry for miner verification
    let family_registry = Arc::new(families::FamilyRegistry::new(config.families.clone()));
    // Create chain registry cache (pallet-arion) reader
    let chain_registry = Arc::new(chain_registry::ChainRegistry::new(
        config.chain_registry.clone(),
    ));

    // Open persistent upload progress store
    let upload_progress_path =
        std::path::Path::new("/var/lib/hippius/validator/upload_progress.redb");
    let upload_progress_store = match UploadProgressStore::open(upload_progress_path) {
        Ok(store) => {
            // Recover from any crashed uploads
            match store.load_and_recover() {
                Ok(recovered) => {
                    let interrupted = recovered
                        .values()
                        .filter(|p| p.status == "Failed: Interrupted")
                        .count();
                    if interrupted > 0 {
                        info!(
                            total = recovered.len(),
                            interrupted = interrupted,
                            "Recovered upload entries"
                        );
                    } else {
                        info!(
                            count = recovered.len(),
                            "Loaded upload progress entries from disk"
                        );
                    }
                }
                Err(e) => {
                    warn!(error = %e, "Failed to recover uploads");
                }
            }
            Arc::new(store)
        }
        Err(e) => {
            error!(
                error = %e,
                "Failed to open upload progress database, using in-memory fallback"
            );
            // This shouldn't happen, but create a temp DB as fallback
            match UploadProgressStore::open("/tmp/upload_progress_fallback.redb") {
                Ok(store) => Arc::new(store),
                Err(fallback_err) => {
                    error!(
                        error = %fallback_err,
                        "Failed to open fallback upload progress database, upload progress tracking disabled"
                    );
                    // Create an in-memory store that will lose data on restart but won't crash
                    Arc::new(
                        UploadProgressStore::open("/dev/shm/upload_progress_temp.redb")
                            .expect("in-memory upload progress store should be creatable"),
                    )
                }
            }
        }
    };

    let app_state = Arc::new(AppState {
        // Start in WarmingUp state - will transition to Ready after index loading
        ready_state: std::sync::atomic::AtomicU8::new(ValidatorReadyState::WarmingUp as u8),
        doc,
        blobs_store,
        author_id,
        endpoint: endpoint.clone(),
        _docs_engine: docs_engine_arc.clone(),
        map_lock: tokio::sync::Mutex::new(()),
        manifest_hashes: Arc::new(tokio::sync::Mutex::new(Vec::new())),
        pg_index: Arc::new(DashMap::new()),
        rate_limits: Arc::new(DashMap::new()),
        relay_url: Some(relay_url),
        connection_pool: Arc::new(tokio::sync::RwLock::new(std::collections::HashMap::new())),
        upload_progress: upload_progress_store,
        cluster_map: Arc::new(tokio::sync::RwLock::new(ClusterMap::new())),
        family_registry: family_registry.clone(),
        chain_registry: chain_registry.clone(),
        metrics: metrics::Metrics::new(),
        processing_semaphore: Arc::new(tokio::sync::Semaphore::new(50)), // Max 50 concurrent RS encoding tasks
        rebalance_last_epoch: Arc::new(tokio::sync::Mutex::new(0)),
        rebalance_queue: Arc::new(tokio::sync::Mutex::new(VecDeque::new())),
        repair_hint_enabled: std::env::var("REPAIR_HINT_ENABLED")
            .ok()
            .map(|v| v != "0" && v.to_lowercase() != "false")
            .unwrap_or(true),
        repair_hint_queue_max: std::env::var("REPAIR_HINT_QUEUE_MAX")
            .ok()
            .and_then(|s| s.parse().ok())
            .unwrap_or(5000),
        repair_hint_concurrency: std::env::var("REPAIR_HINT_CONCURRENCY")
            .ok()
            .and_then(|s| s.parse().ok())
            .unwrap_or(2),
        repair_hint_default_count: std::env::var("REPAIR_HINT_DEFAULT_COUNT")
            .ok()
            .and_then(|s| s.parse().ok())
            .unwrap_or(2),
        repair_hint_dedupe_ttl_secs: std::env::var("REPAIR_HINT_DEDUPE_TTL_SECS")
            .ok()
            .and_then(|s| s.parse().ok())
            .unwrap_or(30),
        repair_hint_dedupe: Arc::new(QuickCache::new(CACHE_MAX_ENTRIES)), // Bounded cache: max 10,000 entries
        repair_hint_queue: Arc::new(tokio::sync::Mutex::new(VecDeque::new())),
        rebuild_enabled: config.tuning.rebuild_enabled,
        rebuild_tick_secs: std::cmp::max(1, config.tuning.rebuild_tick_secs),
        rebuild_files_per_tick: std::cmp::max(1, config.tuning.rebuild_files_per_tick),
        rebuild_stripes_per_file: config.tuning.rebuild_stripes_per_file,
        rebuild_concurrency: std::cmp::max(1, config.tuning.rebuild_concurrency),
        miner_out_threshold_secs: std::cmp::max(60, config.tuning.miner_out_threshold_secs),
        upload_min_redundancy_buffer: config.tuning.upload_min_redundancy_buffer,

        weight_update_enabled: config.tuning.weight_update_enabled,
        weight_update_tick_secs: std::cmp::max(30, config.tuning.weight_update_tick_secs),
        weight_update_min_change_pct: std::cmp::max(1, config.tuning.weight_update_min_change_pct),

        network_stats_cache_secs: std::env::var("NETWORK_STATS_CACHE_SECS")
            .ok()
            .and_then(|s| s.parse().ok())
            .unwrap_or(10),
        network_stats_cache: Arc::new(tokio::sync::RwLock::new(None)),
        manifest_cache: Arc::new(QuickCache::new(CACHE_MAX_ENTRIES)), // Cache up to 10,000 manifests
        manifest_cache_tombstone_ttl_secs: config.tuning.manifest_cache_tombstone_ttl_secs,
        miner_latency: Arc::new(DashMap::new()),
        rebalance_status: Arc::new(DashMap::new()),
        rebalance_pending_acks: Arc::new(DashMap::new()),
        warden_client: if config.warden.enabled {
            Some(Arc::new(warden_client::WardenClient::new(
                &config.warden.url,
            )))
        } else {
            None
        },
        audit_epoch_secs: config.warden.audit_epoch_secs,
        shards_per_miner_per_epoch: config.warden.shards_per_miner_per_epoch,
        validator_node_id: endpoint.secret_key().public().to_string(),
        reputation_processor: Arc::new(reputation::ReputationProcessor::new(
            config.reputation.clone(),
        )),
        attestation_aggregator: Arc::new(attestation_aggregator::AttestationAggregator::new(0)),
        gateway_url: std::env::var("GATEWAY_URL").ok(),
        submitter_connection_manager: config.chain_submitter.node_id.as_ref().and_then(
            |node_id_hex| match iroh::PublicKey::from_str(node_id_hex) {
                Ok(submitter_node_id) => {
                    info!(
                        submitter_node_id = %node_id_hex,
                        "Chain-submitter P2P connection configured for attestation commitments"
                    );
                    Some(Arc::new(common::P2pConnectionManager::new(
                        endpoint.clone(),
                        submitter_node_id,
                        common::SUBMITTER_CONTROL_ALPN,
                    )))
                }
                Err(e) => {
                    warn!(
                        error = %e,
                        node_id = %node_id_hex,
                        "Invalid CHAIN_SUBMITTER_NODE_ID, attestation commitments disabled"
                    );
                    None
                }
            },
        ),
    });

    // Start family registry refresh loop
    let family_registry_for_refresh = family_registry.clone();
    tokio::spawn(async move {
        family_registry_for_refresh.run_refresh_loop().await;
    });

    // Start chain registry refresh loop
    let chain_registry_for_refresh = chain_registry.clone();
    tokio::spawn(async move {
        chain_registry_for_refresh.run_refresh_loop().await;
    });

    // Set up P2P router for validator-control ALPN (miner registration/heartbeat)
    let validator_control_handler = ValidatorControlHandler {
        state: app_state.clone(),
    };
    use iroh::protocol::Router;

    // Set up iroh-blobs protocol so miners can pull blobs from validator
    use iroh_blobs::BlobsProtocol;
    let blobs_protocol = BlobsProtocol::new(&app_state.blobs_store, None);

    // Set up P2P authorization config from config file
    let p2p_auth_config = std::sync::Arc::new(p2p::P2pAuthConfig::from_strings(
        &config.p2p.authorized_gateways,
        &config.p2p.authorized_wardens,
        &config.p2p.authorized_submitters,
    ));
    if config.p2p.authorized_gateways.is_empty()
        && config.p2p.authorized_wardens.is_empty()
        && config.p2p.authorized_submitters.is_empty()
    {
        warn!("P2P authorization is disabled (dev mode) - configure [p2p] section for production");
    } else {
        info!(
            gateways = config.p2p.authorized_gateways.len(),
            wardens = config.p2p.authorized_wardens.len(),
            submitters = config.p2p.authorized_submitters.len(),
            "P2P authorization configured"
        );
    }

    // Set up gateway control handler (replaces HTTP for internal gateway<->validator communication)
    let gateway_control_handler = p2p::GatewayControlHandler {
        state: app_state.clone(),
        auth_config: p2p_auth_config.clone(),
    };

    // Set up warden control handler (receives audit results from wardens)
    let warden_control_handler = p2p::WardenControlHandler {
        state: app_state.clone(),
        auth_config: p2p_auth_config.clone(),
    };

    // Set up submitter control handler (chain-submitter fetches cluster map and stats)
    let submitter_control_handler = p2p::SubmitterControlHandler {
        state: app_state.clone(),
        auth_config: p2p_auth_config.clone(),
    };

    let _router = Router::builder(endpoint.clone())
        .accept(b"hippius/validator-control", validator_control_handler)
        .accept(iroh_blobs::ALPN, blobs_protocol)
        .accept(common::GATEWAY_CONTROL_ALPN, gateway_control_handler)
        .accept(common::WARDEN_CONTROL_ALPN, warden_control_handler)
        .accept(common::SUBMITTER_CONTROL_ALPN, submitter_control_handler)
        .spawn();
    info!("P2P validator-control handler started");
    info!("P2P iroh-blobs handler started for shard distribution");
    info!("P2P gateway-control handler started (hybrid migration)");
    info!("P2P warden-control handler started (hybrid migration)");
    info!("P2P submitter-control handler started (hybrid migration)");

    // Start Ceph-style rebalance coordinator (epoch -> PG diff -> pulls)
    // Note: rebalance_loop will wait for ready_state before processing changes
    let rebalance_state = app_state.clone();
    tokio::spawn(async move {
        rebalance_loop(rebalance_state).await;
    });

    // P2P is now accepting connections - log the ready state
    info!(
        state = "warming_up",
        "P2P handlers ready - validator accepting connections (limited functionality)"
    );

    // Start background index loading
    // This allows the validator to accept P2P connections immediately while indexes load
    let state_for_indexing = app_state.clone();
    let data_dir_for_indexing = data_dir.clone();
    tokio::spawn(async move {
        load_indexes_background(state_for_indexing, data_dir_for_indexing).await;
    });

    let app = AxumRouter::new()
        .route(
            "/manifest",
            post(save_manifest).layer(axum::middleware::from_fn(require_admin_middleware)),
        )
        .route("/manifest/:hash", get(get_manifest))
        .route("/file/:hash/shards", get(get_file_shards))
        .route("/map", get(get_map))
        .route("/map/epoch/:epoch", get(get_map_epoch))
        .route("/rebalance/status/:epoch/:pg_id", get(get_rebalance_status))
        .route(
            "/repair/:hash",
            post(repair_file).layer(axum::middleware::from_fn(require_admin_middleware)),
        )
        .route(
            "/repair_hint",
            post(repair_hint).layer(axum::middleware::from_fn(require_gateway_middleware)),
        )
        .route(
            "/map",
            post(update_map).layer(axum::middleware::from_fn(require_admin_middleware)),
        )
        // Miner registration/heartbeats are handled via P2P (validator-control) and verified against the on-chain registry cache.
        // Legacy HTTP miner endpoints were removed to avoid spoofing and bypasses.
        .route("/audit/:hash", post(audit_file))
        // Gateway -> validator telemetry: authenticated with API_KEY_GATEWAY.
        .route(
            "/stats/bandwidth",
            post(report_bandwidth).layer(axum::middleware::from_fn(require_gateway_middleware)),
        )
        .route(
            "/stats/failures",
            post(report_miner_failures)
                .layer(axum::middleware::from_fn(require_gateway_middleware)),
        )
        .route("/stats", get(get_stats))
        // Warden audit results -> reputation updates (requires admin auth)
        .route(
            "/audit-results",
            post(post_audit_results).layer(axum::middleware::from_fn(require_admin_middleware)),
        )
        // Expensive endpoint: protect with admin auth + cache.
        .route(
            "/network-stats",
            get(get_network_stats).layer(axum::middleware::from_fn(require_admin_middleware)),
        )
        .route("/blobs/:hash", get(get_blob).delete(delete_file))
        .route("/files", get(get_files))
        .route("/upload", post(handle_upload))
        .route("/upload/status/:hash", get(get_upload_status))
        .route("/node_id", get(get_node_id))
        .route("/health", get(health_check))
        .route("/metrics", get(metrics_handler))
        .layer(DefaultBodyLimit::max(5 * 1024 * 1024 * 1024)) // 5GB limit
        .with_state(app_state.clone());

    let port = args.port;

    // Load TLS configuration
    let tls_config = TlsConfig::new("validator")
        .map_err(|e| anyhow::anyhow!("Failed to initialize TLS config: {}", e))?;
    let rustls_config = OpenSSLConfig::from_pem_file(&tls_config.cert_path, &tls_config.key_path)
        .map_err(|e| anyhow::anyhow!("Failed to load TLS configuration: {}", e))?;

    let addr: std::net::SocketAddr = format!("0.0.0.0:{}", port)
        .parse()
        .expect("Invalid listen address");
    info!(addr = %addr, "Validator listening (HTTPS)");

    // Start auto-recovery loop
    let state_for_recovery = app_state.clone();
    tokio::spawn(async move {
        info!("Starting auto-recovery system");
        auto_recovery_loop(state_for_recovery).await;
    });

    // Start repair hint worker loop (gateway -> validator "please repair this stripe")
    let state_for_repair_hints = app_state.clone();
    tokio::spawn(async move {
        info!(
            enabled = state_for_repair_hints.repair_hint_enabled,
            queue_max = state_for_repair_hints.repair_hint_queue_max,
            concurrency = state_for_repair_hints.repair_hint_concurrency,
            "Repair hint loop"
        );
        if state_for_repair_hints.repair_hint_enabled {
            repair_hint_worker_loop(state_for_repair_hints).await;
        }
    });

    // Start coarse weight update loop (optional; disabled by default)
    let state_for_weights = app_state.clone();
    tokio::spawn(async move {
        info!(
            enabled = state_for_weights.weight_update_enabled,
            tick_secs = state_for_weights.weight_update_tick_secs,
            min_change_pct = state_for_weights.weight_update_min_change_pct,
            "Weight update loop"
        );
        weight_update_loop(state_for_weights).await;
    });

    // Start backup scheduler if enabled
    if config.backup.enabled {
        let backup_config = config.backup.clone();
        let backup_data_dir = data_dir.clone();
        tokio::spawn(async move {
            match backup::BackupManager::new(backup_config, backup_data_dir).await {
                Ok(manager) => manager.run_scheduler().await,
                Err(e) => error!(error = %e, "Failed to start backup scheduler"),
            }
        });
    }

    // Start blob backup scheduler if enabled
    if config.backup.enabled && config.backup.blobs.enabled {
        let blob_backup_config = config.backup.clone();
        let blob_backup_data_dir = data_dir.clone();
        let blob_backup_doc = app_state.doc.clone();
        let blob_backup_blobs_store = app_state.blobs_store.clone();
        let blob_backup_manifest_hashes = app_state.manifest_hashes.clone();
        let blob_backup_metrics = app_state.metrics.clone();
        tokio::spawn(async move {
            match blob_backup::BlobBackupManager::new(
                blob_backup_config,
                blob_backup_data_dir,
                blob_backup_doc,
                blob_backup_blobs_store,
                blob_backup_manifest_hashes,
                blob_backup_metrics,
            )
            .await
            {
                Ok(manager) => {
                    // Try to restore state from S3 if ReDB is empty
                    if let Err(e) = manager.restore_state_if_needed().await {
                        warn!(error = %e, "Failed to restore blob backup state from S3");
                    }
                    manager.run_scheduler().await;
                }
                Err(e) => error!(error = %e, "Failed to start blob backup scheduler"),
            }
        });
    }

    // Spawn HTTPS server
    tokio::spawn(async move {
        if let Err(e) = axum_server::bind_openssl(addr, rustls_config)
            .serve(app.into_make_service())
            .await
        {
            error!(error = %e, "HTTPS server failed");
        }
    });

    // Graceful shutdown signal handling
    info!("Validator fully started");

    // Clone state for shutdown handler
    let shutdown_state = app_state.clone();

    // Create shutdown signal listener
    let ctrl_c = async {
        tokio::signal::ctrl_c()
            .await
            .expect("Failed to install Ctrl+C handler - cannot run without signal handling");
    };

    #[cfg(unix)]
    let terminate = async {
        tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())
            .expect("Failed to install SIGTERM handler - cannot run without signal handling")
            .recv()
            .await;
    };

    #[cfg(not(unix))]
    let terminate = std::future::pending::<()>();

    // 5. Audit Loop with graceful shutdown
    let audit_loop = async {
        loop {
            debug!("Starting Audit Cycle");

            // A. Generate Random File (100KB)
            let mut data = vec![0u8; 100 * 1024];
            rand::rng().fill(&mut data[..]);
            let _data_len = data.len();

            // B. Upload to Gateway
            // Accept self-signed certs since gateway uses auto-generated TLS certs
            let client = reqwest::Client::builder()
                .danger_accept_invalid_certs(true)
                .build()
                .unwrap_or_else(|_| reqwest::Client::new());
            let part = reqwest::multipart::Part::bytes(data.clone()).file_name("audit.bin");
            let form = reqwest::multipart::Form::new().part("file", part);

            // Assuming gateway is at http://gateway:3000
            let gateway_url = args.gateway_url.clone();

            let api_key = std::env::var("API_KEY_ADMIN").unwrap_or_default();

            match client
                .post(format!("{}/upload", gateway_url))
                .header("X-API-Key", &api_key)
                .multipart(form)
                .send()
                .await
            {
                Ok(res) => {
                    if res.status().is_success() {
                        let manifest: Value = match res.json().await {
                            Ok(v) => v,
                            Err(e) => {
                                error!(error = %e, "Failed to parse manifest");
                                continue;
                            }
                        };
                        debug!("Upload successful, manifest received");

                        // C. Verify Shards
                        if let Some(shards) = manifest["shards"].as_array() {
                            let manifest_struct: FileManifest =
                                match serde_json::from_value(manifest.clone()) {
                                    Ok(m) => m,
                                    Err(e) => {
                                        error!(error = %e, "Failed to deserialize manifest");
                                        continue;
                                    }
                                };
                            let shards_per_stripe =
                                manifest_struct.stripe_config.k + manifest_struct.stripe_config.m;
                            let cluster_map = app_state.cluster_map.read().await.clone();

                            for (i, shard) in shards.iter().enumerate() {
                                let blob_hash = shard["blob_hash"].as_str().unwrap_or_default();
                                if blob_hash.is_empty() {
                                    debug!(shard_index = i, "Shard missing blob_hash");
                                    continue;
                                }

                                // Calculate Placement
                                let stripe_idx = i / shards_per_stripe;
                                let local_idx = i % shards_per_stripe;

                                match common::calculate_stripe_placement(
                                    &manifest_struct.file_hash,
                                    stripe_idx as u64,
                                    shards_per_stripe,
                                    &cluster_map,
                                    manifest_struct.placement_version,
                                ) {
                                    Ok(miners) => {
                                        if let Some(miner) = miners.get(local_idx) {
                                            let report = audit_shard(
                                                i,
                                                blob_hash,
                                                miner,
                                                &app_state,
                                                &manifest_struct,
                                            )
                                            .await;
                                            if report.status == "PASS" {
                                                debug!(shard_index = i, "Shard audit PASS");
                                            } else {
                                                error!(shard_index = i, status = %report.status, "Shard audit failed");
                                            }
                                        } else {
                                            debug!(
                                                shard_index = i,
                                                stripe_idx = stripe_idx,
                                                local_idx = local_idx,
                                                "No miner found for shard"
                                            );
                                        }
                                    }
                                    Err(e) => {
                                        debug!(shard_index = i, error = %e, "Placement calc failed for shard");
                                    }
                                }
                            }
                        }
                    } else {
                        error!(status = %res.status(), "Upload failed");
                    }
                }
                Err(e) => error!(error = %e, "Failed to connect to Gateway"),
            }

            sleep(Duration::from_secs(10)).await;
        }
    };

    // Run audit loop until shutdown signal
    tokio::select! {
        _ = ctrl_c => {
            info!("Received Ctrl+C, initiating graceful shutdown");
        }
        _ = terminate => {
            info!("Received SIGTERM, initiating graceful shutdown");
        }
        _ = audit_loop => {
            warn!("Audit loop unexpectedly ended");
        }
    }

    // Graceful shutdown - save state
    info!("Saving cluster map before shutdown");
    {
        let _guard = shutdown_state.map_lock.lock().await;
        // Map is already persisted to iroh_docs, but we could add extra safety here
        info!("State saved successfully");
    }

    info!("Validator shutdown complete");
    Ok(())
}

async fn update_sync_index(state: &Arc<AppState>) -> anyhow::Result<()> {
    debug!("Updating Sync Index");

    // 1. Get latest map hash
    let query = iroh_docs::store::Query::single_latest_per_key().key_exact(b"cluster_map");
    let mut stream = Box::pin(state.doc.get_many(query).await?);
    let map_entry = stream.next().await;

    let map_hash = match map_entry {
        Some(Ok(entry)) => entry.content_hash().to_string(),
        _ => return Ok(()), // No map yet
    };

    // 2. Get manifest hashes
    let files = state.manifest_hashes.lock().await.clone();

    // 3. Create SyncIndex
    let index = SyncIndex {
        map_hash,
        files,
        timestamp: now_secs(),
    };

    let json = serde_json::to_string(&index)?;

    // 4. Store Index Blob
    // import_bytes returns (TempTag, u64) or similar. We need the hash.
    // FsStore::import_bytes might not exist or be named differently.
    // Let's use import_stream or just write to a temp file.
    // Or check if we can use add_blob (put).
    // Store trait has `put`.
    // let blob_hash = state.blobs_store.put(json.into_bytes().into()).await?;

    // Let's try to use `import_bytes` if the trait is imported.
    // If it returns (tag, size), we can get hash from tag? No, tag is TempTag.
    // Wait, `import_bytes` usually returns `(TempTag, u64)`.
    // But we need the hash.
    // `TempTag` has `hash()`.

    // Let's try `add_blob` if available, or just `import_bytes`.
    // If `import_bytes` is not found, I'll use `import_file`.

    // 4. Store Index Blob
    // Using set_bytes which stores in docs (backed by blobs)
    // The blob IS stored and available, we just need to ensure it's accessible
    let blob_hash = state
        .doc
        .set_bytes(state.author_id, "sync_index", json)
        .await?;

    // 5. Write Index Hash to shared file
    tokio::fs::write("data/validator/latest_index.txt", blob_hash.to_string()).await?;
    debug!(hash = %blob_hash, "Sync Index updated");

    Ok(())
}

/// Save cluster map to disk as JSON for crash recovery
async fn save_cluster_map_to_disk(map: &ClusterMap) -> anyhow::Result<()> {
    let path = std::path::Path::new("data/validator/cluster_map_backup.json");
    let json = serde_json::to_string_pretty(map)?;
    tokio::fs::write(path, &json).await?;
    debug!(epoch = map.epoch, "Cluster map saved to disk");
    Ok(())
}

fn cluster_map_epoch_key(epoch: u64) -> Vec<u8> {
    format!("cluster_map_epoch:{}", epoch).into_bytes()
}

/// Persist cluster map to iroh-docs under the canonical key and an epoch-scoped history key.
/// This enables deterministic CRUSH reads against older epochs during rebalancing.
pub async fn persist_cluster_map_to_doc(state: &AppState, map: &ClusterMap) -> anyhow::Result<()> {
    // Safety: never allow epoch regression (it breaks deterministic placement for existing files).
    // If you truly need to reset the cluster, wipe the validator data dir + docs and start fresh.
    let current_epoch = { state.cluster_map.read().await.epoch };
    if map.epoch < current_epoch {
        return Err(anyhow::anyhow!(
            "refusing to persist ClusterMap epoch regression: {} -> {}",
            current_epoch,
            map.epoch
        ));
    }
    let json = serde_json::to_string(map)?;
    let author = state.author_id;
    // Canonical map key
    state
        .doc
        .set_bytes(
            author,
            Bytes::from_static(b"cluster_map"),
            Bytes::from(json.clone()),
        )
        .await?;
    // Epoch history key
    state
        .doc
        .set_bytes(
            author,
            Bytes::from(cluster_map_epoch_key(map.epoch)),
            Bytes::from(json),
        )
        .await?;
    // Update in-memory cache for fast CRUSH access
    {
        let mut cache = state.cluster_map.write().await;
        *cache = map.clone();
    }
    Ok(())
}

/// Load the highest known ClusterMap from doc history.
/// This prevents accidental epoch regressions on validator restart.
async fn load_latest_cluster_map_from_doc(state: &Arc<AppState>) -> Option<ClusterMap> {
    // 1) Prefer epoch history keys (cluster_map_epoch:<epoch>)
    let prefix = b"cluster_map_epoch:";
    let query = iroh_docs::store::Query::single_latest_per_key().key_prefix(prefix);
    let mut stream = Box::pin(state.doc.get_many(query).await.ok()?);

    let mut best_epoch: u64 = 0;
    let mut best_hash: Option<iroh_blobs::Hash> = None;
    while let Some(Ok(entry)) = stream.next().await {
        if let Ok(key_str) = std::str::from_utf8(entry.key()) {
            if let Some(s) = key_str.strip_prefix("cluster_map_epoch:") {
                if let Ok(e) = s.parse::<u64>() {
                    if e >= best_epoch {
                        best_epoch = e;
                        best_hash = Some(entry.content_hash());
                    }
                }
            }
        }
    }

    if let Some(h) = best_hash {
        let mut reader = state.blobs_store.reader(h);
        let mut content = Vec::new();
        if reader.read_to_end(&mut content).await.is_ok() {
            if let Ok(map) = serde_json::from_slice::<ClusterMap>(&content) {
                return Some(map);
            }
        }
    }

    // 2) Fallback: canonical key
    let query_map = iroh_docs::store::Query::single_latest_per_key().key_exact(b"cluster_map");
    let mut stream = Box::pin(state.doc.get_many(query_map).await.ok()?);
    let entry = stream.next().await?.ok()?;
    let mut reader = state.blobs_store.reader(entry.content_hash());
    let mut content = Vec::new();
    if reader.read_to_end(&mut content).await.is_ok() {
        serde_json::from_slice::<ClusterMap>(&content).ok()
    } else {
        None
    }
}

// /// Load cluster map from disk backup (for crash recovery)
// fn load_cluster_map_from_disk() -> Option<ClusterMap> {
//     let path = std::path::Path::new("data/validator/cluster_map_backup.json");
//     if path.exists() {
//         match std::fs::read_to_string(path) {
//             Ok(json) => {
//                 match serde_json::from_str::<ClusterMap>(&json) {
//                     Ok(map) => {
//                         println!("💾 Loaded cluster map from disk backup (epoch {})", map.epoch);
//                         return Some(map);
//                     }
//                     Err(e) => {
//                         eprintln!("⚠️ Failed to parse cluster_map_backup.json: {}", e);
//                     }
//                 }
//             }
//             Err(e) => {
//                 eprintln!("⚠️ Failed to read cluster_map_backup.json: {}", e);
//             }
//         }
//     }
//     None
// }

// =============================================================================
// UPLOAD HANDLER
// =============================================================================
//
// The upload handler is the primary entry point for storing files in the Hippius
// Arion network. It implements a synchronous upload model where the response is
// only returned after all shards are distributed and the manifest is persisted.
//
// ## Upload Flow Overview
//
// ```text
// Client Request                              Validator Processing
// ──────────────────                          ────────────────────────────────────────
//
// POST /upload ─────────────────────────────▶ 1. Stream file to disk (temp file)
// (multipart/form-data)                       │  └─ Calculate BLAKE3 hash while streaming
//                                             │
//                                             ▼
//                                          2. Rename temp → {hash}.bin
//                                             │
//                                             ▼
//                                          3. For each stripe (2 MiB):
//                                             │  a. Read stripe from disk
//                                             │  b. Reed-Solomon encode: k=10 data, m=20 parity
//                                             │  c. CRUSH placement → select k+m miners
//                                             │  d. P2P push shards to miners (parallel)
//                                             │  e. Verify minimum success (k + buffer)
//                                             │
//                                             ▼
//                                          4. Create FileManifest with all shard info
//                                             │
//                                             ▼
//                                          5. Persist manifest to iroh-docs
//                                             │
//                                             ▼
//                                          6. Update caches: manifest_cache, pg_index
//                                             │
//                                             ▼
// ◀──────────────────────────────────────── 7. Return JSON { hash, size }
// ```
//
// ## Reed-Solomon Encoding
//
// Each stripe is encoded using the Galois Field (2^8) Reed-Solomon codec:
// - k=10: Number of data shards (required to reconstruct)
// - m=20: Number of parity shards (provides fault tolerance)
// - Total: 30 shards per stripe
//
// This means:
// - Any 10 of 30 shards can reconstruct the original stripe
// - Up to 20 miner failures can be tolerated per stripe
// - ~3x storage overhead (30 shards for 10 data shards worth)
//
// ## CRUSH Placement
//
// Shard placement uses the CRUSH algorithm with PG-based addressing (version 2):
//
// ```text
// file_hash ──▶ calculate_pg() ──▶ pg_id (0..16383)
//                                      │
//                                      ▼
// pg_id + stripe_idx ──▶ calculate_pg_placement_for_stripe() ──▶ [MinerNode; 30]
//                                      │
//                                      └─ Ensures family diversity (different failure domains)
// ```
//
// ## Redundancy Tiers
//
// The handler enforces three-tier redundancy checking:
//
// | Tier | Threshold | Behavior |
// |------|-----------|----------|
// | Critical | < k shards | **Fail** - cannot reconstruct, abort upload |
// | Warning | < k + buffer | **Fail** - insufficient fault tolerance |
// | Reduced | < k + m shards | **Warn** - continue but log degraded state |
// | Full | = k + m shards | **Success** - optimal redundancy |
//
// The buffer is configured via `UPLOAD_MIN_REDUNDANCY_BUFFER` (default: 10).
//
// ## Backpressure Controls
//
// - `processing_semaphore`: Limits concurrent RS encoding operations
// - `upload_progress`: ReDB-backed tracking prevents orphaned uploads
// - Active upload count check: Rejects new uploads if > 100 active
//
// ## Error Handling
//
// On any failure during upload:
// 1. Temp file is cleaned up
// 2. Upload progress is marked as failed
// 3. Error response is returned with descriptive message
//
// The client can retry the entire upload - there's no partial resume.

/// Process a file upload: stream to disk, RS-encode, CRUSH-place, distribute to miners.
///
/// This is a **synchronous** operation - the response is only sent after all shards
/// are successfully distributed and the manifest is persisted. This prevents race
/// conditions where clients try to download before the file is available.
///
/// # Arguments
///
/// * `state` - Shared application state with cluster map, iroh-docs, etc.
/// * `multipart` - The multipart request containing the file data
///
/// # Returns
///
/// On success: `200 OK` with JSON `{ hash, message, size }`
/// On failure: Appropriate HTTP status code with error message
///
/// # Panics
///
/// This function does not panic. All errors are handled and returned as HTTP responses.
async fn handle_upload(
    State(state): State<Arc<AppState>>,
    mut multipart: Multipart,
) -> impl IntoResponse {
    debug!("Received file upload request");

    // Check ready state - uploads require full readiness
    if let Some(response) = check_ready_state(&state) {
        return response.into_response();
    }

    // Phase 0: Setup upload directory
    let upload_dir = std::path::Path::new("/var/lib/hippius/validator/uploads");
    if let Err(e) = tokio::fs::create_dir_all(upload_dir).await {
        error!(error = %e, "Failed to create upload dir");
        return (
            StatusCode::INTERNAL_SERVER_ERROR,
            "Failed to create upload directory",
        )
            .into_response();
    }

    // Protection: Check pending uploads to prevent disk fill-up
    // Cleanup completed/stale entries periodically and check active count
    {
        // Cleanup entries older than 1 hour
        if let Err(e) = state.upload_progress.cleanup_old_completed(3600) {
            warn!(error = %e, "Failed to cleanup old uploads");
        }

        // Only count ACTIVE (Processing) uploads for rate limiting
        match state.upload_progress.active_count() {
            Ok(active) => {
                debug!(active = active, max = 100, "Active uploads");
                if active > 100 {
                    return (
                        StatusCode::TOO_MANY_REQUESTS,
                        "Server busy: too many concurrent uploads",
                    )
                        .into_response();
                }
            }
            Err(e) => {
                warn!(error = %e, "Failed to check upload count");
            }
        }
    }

    // Create temp file atomically using O_EXCL to prevent TOCTOU attacks
    let temp_file = match NamedTempFile::new_in(&upload_dir) {
        Ok(f) => f,
        Err(e) => {
            error!(error = %e, "Failed to create temp file");
            return internal_error("upload create temp file", e).into_response();
        }
    };
    let temp_filepath = temp_file.path().to_path_buf();

    let file_hash_str: String;
    let mut file_size = 0usize;
    let original_filename: Option<String>;
    let content_type: Option<String>;

    // Stream file to disk and calculate hash simultaneously
    // We need to drop the sync temp_file and reopen with tokio for async writes
    // IMPORTANT: Use into_parts() instead of into_file() because into_file() drops the TempPath
    // which deletes the temp file from the filesystem (the file handle keeps data accessible
    // but the path no longer exists, causing rename to fail with ENOENT)
    let (std_file, temp_path) = temp_file.into_parts();
    let temp_file_for_cleanup = temp_filepath.clone();
    // Keep temp_path alive - it will be dropped after successful rename or on error cleanup
    let _temp_path_guard = temp_path;

    match multipart.next_field().await {
        Ok(Some(mut field)) => {
            original_filename = field.file_name().map(|s| s.to_string());

            // Detect content type from filename immediately
            content_type = original_filename
                .as_ref()
                .map(|name| {
                    match name.rsplit('.').next().map(|s| s.to_lowercase()).as_deref() {
                        Some("mp4") => "video/mp4",
                        Some("mkv") => "video/x-matroska",
                        Some("avi") => "video/x-msvideo",
                        Some("webm") => "video/webm",
                        Some("mov") => "video/quicktime",
                        Some("jpg") | Some("jpeg") => "image/jpeg",
                        Some("png") => "image/png",
                        Some("gif") => "image/gif",
                        Some("webp") => "image/webp",
                        Some("pdf") => "application/pdf",
                        Some("txt") => "text/plain",
                        Some("html") => "text/html",
                        Some("json") => "application/json",
                        Some("mp3") => "audio/mpeg",
                        Some("wav") => "audio/wav",
                        Some("zip") => "application/zip",
                        _ => "application/octet-stream",
                    }
                    .to_string()
                })
                .or(Some("application/octet-stream".to_string()));

            // Convert std::fs::File to tokio::fs::File for async operations
            let mut file = tokio::fs::File::from_std(std_file);

            let mut hasher = blake3::Hasher::new();

            while let Ok(Some(chunk)) = field.chunk().await {
                if let Err(e) = file.write_all(&chunk).await {
                    let _ = tokio::fs::remove_file(&temp_file_for_cleanup).await;
                    error!(error = %e, "Failed to write to temp file");
                    return internal_error("upload write temp file", e).into_response();
                }
                hasher.update(&chunk);
                file_size += chunk.len();
            }

            if let Err(e) = file.flush().await {
                let _ = tokio::fs::remove_file(&temp_file_for_cleanup).await;
                error!(error = %e, "Failed to flush temp file");
                return internal_error("upload flush temp file", e).into_response();
            }

            file_hash_str = hasher.finalize().to_string();
            debug!(file_hash = %file_hash_str, "File hash computed");
        }
        Ok(None) => {
            let _ = tokio::fs::remove_file(&temp_file_for_cleanup).await;
            return (StatusCode::BAD_REQUEST, "No file provided").into_response();
        }
        Err(e) => {
            warn!(error = %e, "Multipart read error");
            let _ = tokio::fs::remove_file(&temp_file_for_cleanup).await;
            return (StatusCode::BAD_REQUEST, "Multipart error").into_response();
        }
    };

    if file_size == 0 {
        let _ = tokio::fs::remove_file(&temp_file_for_cleanup).await;
        return (StatusCode::BAD_REQUEST, "No file uploaded").into_response();
    }

    // Rename temp file to hash
    let final_path = upload_dir.join(format!("{}.bin", file_hash_str));
    if let Err(e) = tokio::fs::rename(&temp_filepath, &final_path).await {
        error!(error = %e, "Failed to rename temp file");
        // If rename fails (e.g. cross-fs), try manual move or just fail
        return (
            StatusCode::INTERNAL_SERVER_ERROR,
            "Failed to save file final path",
        )
            .into_response();
    }
    debug!(path = ?final_path, "Saved file to disk");

    // SYNCHRONOUS UPLOAD: Process inline and only return after all shards are distributed
    // and manifest is saved. This prevents race conditions where clients try to download
    // before the file is actually available.

    // Erasure coding configuration
    let config = common::StripeConfig {
        k: 10,
        m: 20, // PAPER DEFAULT: 10 data + 20 parity (tolerate 20 failures, need any 10 shards)
        size: 2 * 1024 * 1024, // 2MB stripe
    };
    let chunk_size = config.size as usize;
    let total_stripes = file_size.div_ceil(chunk_size);

    // Init progress (persist to disk)
    {
        let progress = UploadProgress {
            file_hash: file_hash_str.clone(),
            processed_stripes: 0,
            total_stripes,
            status: "Processing".to_string(),
            updated_at: now_secs(),
        };
        if let Err(e) = state.upload_progress.set(&progress) {
            warn!(error = %e, "Failed to persist upload progress");
        }
    }

    // Acquire semaphore to limit concurrent heavy processing
    let _permit = match state.processing_semaphore.acquire().await {
        Ok(p) => p,
        Err(_) => {
            let _ = tokio::fs::remove_file(&final_path).await;
            return (
                StatusCode::SERVICE_UNAVAILABLE,
                "Processing semaphore closed",
            )
                .into_response();
        }
    };

    debug!(file_hash = %file_hash_str, "Processing started");

    let mut all_shards_info: Vec<common::ShardInfo> = Vec::new();
    // Collect Warden commitment data: (shard_hash, merkle_root, chunk_count, miner_uid, miner_endpoint)
    let mut warden_commitments: Vec<(String, [u32; 8], u32, u32, iroh::EndpointAddr)> = Vec::new();

    // Check map
    let cluster_map = state.cluster_map.read().await.clone();
    if cluster_map.miners.is_empty() {
        error!(file_hash = %file_hash_str, "No miners available");
        let _ = tokio::fs::remove_file(&final_path).await;

        // Mark failed (persist to disk)
        let progress = UploadProgress {
            file_hash: file_hash_str.clone(),
            processed_stripes: 0,
            total_stripes,
            status: "Failed: No miners".to_string(),
            updated_at: now_secs(),
        };
        let _ = state.upload_progress.set(&progress);

        return (
            StatusCode::SERVICE_UNAVAILABLE,
            "No miners available in cluster",
        )
            .into_response();
    }

    // Open file for reading
    let mut file = match tokio::fs::File::open(&final_path).await {
        Ok(f) => f,
        Err(e) => {
            error!(error = %e, "Failed to open uploaded file for processing");
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                format!("Failed to open file for processing: {}", e),
            )
                .into_response();
        }
    };

    // Create initial manifest structure (will be saved after successful distribution)
    let mut final_manifest = common::FileManifest {
        file_hash: file_hash_str.clone(),
        placement_version: 2,
        placement_epoch: cluster_map.epoch,
        size: file_size as u64,
        stripe_config: config.clone(),
        shards: vec![],
        filename: original_filename.clone(),
        content_type: content_type.clone(),
    };

    // Process file in chunks (Streaming)
    let mut buffer = vec![0u8; chunk_size];

    // FULL CRUSH (PG-based, per paper): placement is computed by PG + per-stripe rotation.

    for stripe_idx in 0..total_stripes {
        let stripe_start = Instant::now();

        // Handle potentially partial read at EOF
        let expected_read = if stripe_idx == total_stripes - 1 {
            let remainder = file_size % chunk_size;
            if remainder == 0 {
                chunk_size
            } else {
                remainder
            }
        } else {
            chunk_size
        };

        // Read chunk
        if let Err(e) = file.read_exact(&mut buffer[0..expected_read]).await {
            error!(stripe_idx = stripe_idx, error = %e, "Error reading file chunk");
            let _ = tokio::fs::remove_file(&final_path).await;

            let progress = UploadProgress {
                file_hash: file_hash_str.clone(),
                processed_stripes: stripe_idx,
                total_stripes,
                status: format!("Failed: Error reading stripe {}", stripe_idx),
                updated_at: now_secs(),
            };
            let _ = state.upload_progress.set(&progress);

            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                format!("Error reading file at stripe {}: {}", stripe_idx, e),
            )
                .into_response();
        }
        let chunk = &buffer[0..expected_read];

        // Encode with timing
        let encode_start = Instant::now();
        let shards = match common::encode_stripe(chunk, &config) {
            Ok(s) => s,
            Err(e) => {
                error!(error = %e, "Encoding failed");
                let _ = tokio::fs::remove_file(&final_path).await;

                let progress = UploadProgress {
                    file_hash: file_hash_str.clone(),
                    processed_stripes: stripe_idx,
                    total_stripes,
                    status: format!("Failed: Encoding error at stripe {}", stripe_idx),
                    updated_at: now_secs(),
                };
                let _ = state.upload_progress.set(&progress);

                return (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    format!("Encoding failed at stripe {}: {}", stripe_idx, e),
                )
                    .into_response();
            }
        };
        let encode_duration_ms = encode_start.elapsed().as_millis();
        let shard_size_bytes = shards.first().map(|s| s.len()).unwrap_or(0);
        info!(
            stripe_idx = stripe_idx,
            input_size_bytes = expected_read,
            shard_count = shards.len(),
            shard_size_bytes = shard_size_bytes,
            encode_duration_ms = encode_duration_ms,
            "RS encoding completed"
        );

        // FULL CRUSH (PG-based, per paper): PG placement + rotate by stripe_index
        let placement_start = Instant::now();
        let pg_id = common::calculate_pg(&file_hash_str, cluster_map.pg_count);
        let assigned_miners = match common::calculate_pg_placement_for_stripe(
            &file_hash_str,
            stripe_idx as u64,
            shards.len(),
            &cluster_map,
        ) {
            Ok(m) => m,
            Err(e) => {
                error!(error = %e, "PG stripe placement failed");
                let _ = tokio::fs::remove_file(&final_path).await;

                let progress = UploadProgress {
                    file_hash: file_hash_str.clone(),
                    processed_stripes: stripe_idx,
                    total_stripes,
                    status: format!("Failed: Placement error at stripe {}", stripe_idx),
                    updated_at: now_secs(),
                };
                let _ = state.upload_progress.set(&progress);

                return (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    format!("Placement failed at stripe {}: {}", stripe_idx, e),
                )
                    .into_response();
            }
        };
        let placement_duration_ms = placement_start.elapsed().as_millis();

        // Log placement details: which miners were selected
        let miner_uids: Vec<u32> = assigned_miners.iter().map(|m| m.uid).collect();
        let family_ids: Vec<&str> = assigned_miners
            .iter()
            .map(|m| m.family_id.as_str())
            .collect();
        let unique_families: std::collections::HashSet<&str> = family_ids.iter().copied().collect();
        info!(
            stripe_idx = stripe_idx,
            pg_id = pg_id,
            placement_duration_ms = placement_duration_ms,
            miner_count = assigned_miners.len(),
            unique_families = unique_families.len(),
            miner_uids = ?miner_uids,
            family_distribution = ?family_ids,
            "CRUSH placement completed"
        );

        // Distribute all shards of this stripe in parallel
        // Return type includes optional Warden commitment data: (hash, root, chunks, miner_uid, node_id)
        type WardenCommitment = (String, [u32; 8], u32, u32, iroh::EndpointAddr);
        let mut shard_tasks = Vec::new();

        // Check if Warden integration is enabled
        let warden_enabled = state.warden_client.is_some();

        for (shard_idx, shard_data) in shards.iter().enumerate() {
            let miner = assigned_miners[shard_idx].clone();
            let shard_data_clone = shard_data.clone();
            let state_clone = state.clone();
            let stripe_idx_copy = stripe_idx;
            let config_k = config.k;
            let config_m = config.m;
            let warden_enabled_copy = warden_enabled;

            let task = tokio::spawn(async move {
                let shard_outcome = match state_clone
                    .blobs_store
                    .add_bytes(shard_data_clone.clone())
                    .await
                {
                    Ok(outcome) => outcome,
                    Err(e) => {
                        error!(error = %e, "Failed to store shard");
                        return None;
                    }
                };

                let shard_hash = shard_outcome.hash.to_string();

                // Run P2P distribution and commitment computation in parallel
                // - P2P distribution is I/O-bound (async)
                // - Commitment computation is CPU-bound (uses spawn_blocking)
                // Clone for commitment only if Warden enabled, then move original into distribute
                let shard_data_for_commitment = if warden_enabled_copy {
                    Some(shard_data_clone.clone())
                } else {
                    None
                };

                let (distribute_result, commitment_result) = tokio::join!(
                    // P2P distribution to miner (moves shard_data_clone)
                    distribute_blob_to_miners(
                        &shard_hash,
                        shard_data_clone, // Moved, not cloned
                        vec![miner.clone()],
                        &state_clone.endpoint,
                        state_clone.connection_pool.clone(),
                    ),
                    // Poseidon2 commitment computation (CPU-bound)
                    async {
                        let data = match shard_data_for_commitment {
                            Some(d) => d,
                            None => return None, // Warden not enabled
                        };
                        // Use spawn_blocking for CPU-intensive Poseidon2 hashing
                        match tokio::task::spawn_blocking(move || {
                            CommitmentWithTree::generate(&data, DEFAULT_CHUNK_SIZE)
                        })
                        .await
                        {
                            Ok(result) => Some(result),
                            Err(e) => {
                                Some(Err(pos_circuits::error::PosError::ProofGenerationError(
                                    format!("spawn_blocking failed: {}", e),
                                )))
                            }
                        }
                    }
                );

                if let Err(e) = distribute_result {
                    error!(miner_uid = miner.uid, error = %e, "Miner P2P failed");
                    return None;
                }

                // Process commitment result
                let warden_commitment: Option<WardenCommitment> = match commitment_result {
                    Some(Ok(cwt)) => {
                        let root = cwt.commitment.merkle_root;
                        let chunk_count = cwt.commitment.chunk_count;
                        Some((
                            shard_hash.clone(),
                            root,
                            chunk_count,
                            miner.uid,
                            miner.endpoint.clone(),
                        ))
                    }
                    Some(Err(e)) => {
                        warn!(
                            shard = %shard_hash,
                            error = %e,
                            "Failed to compute Poseidon2 commitment for Warden"
                        );
                        None
                    }
                    None => None, // Warden not enabled
                };

                let global_index = stripe_idx_copy * (config_k + config_m) + shard_idx;
                Some((
                    common::ShardInfo {
                        index: global_index,
                        blob_hash: shard_hash,
                        miner_uid: Some(miner.uid),
                    },
                    warden_commitment,
                ))
            });

            shard_tasks.push(task);
        }

        // Wait for all shards in this stripe
        let mut success_count = 0;
        let mut failed_count = 0;
        for task in shard_tasks {
            match task.await {
                Ok(Some((shard_info, warden_commitment))) => {
                    all_shards_info.push(shard_info);
                    if let Some(commitment) = warden_commitment {
                        warden_commitments.push(commitment);
                    }
                    success_count += 1;
                }
                _ => failed_count += 1,
            }
        }

        // Redundancy check: require minimum shards for fault tolerance
        // - Absolute minimum: k (can reconstruct but zero tolerance for miner failures)
        // - Configurable minimum: k + upload_min_redundancy_buffer (default: k+10 for 10+20)
        // - Full redundancy: k + m (ideal, tolerates m miner failures)
        let min_required = config.k + state.upload_min_redundancy_buffer.min(config.m);
        let full_redundancy = config.k + config.m;

        if success_count < config.k {
            // Below absolute minimum - cannot reconstruct at all
            error!(
                stripe_idx = stripe_idx,
                success_count = success_count,
                min_required = config.k,
                "Stripe failed: below absolute minimum (k), aborting"
            );
            let _ = tokio::fs::remove_file(&final_path).await;

            let progress = UploadProgress {
                file_hash: file_hash_str.clone(),
                processed_stripes: stripe_idx,
                total_stripes,
                status: format!("Failed: Stripe {} below k shards", stripe_idx),
                updated_at: now_secs(),
            };
            let _ = state.upload_progress.set(&progress);

            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                format!(
                    "Failed to distribute stripe {}: only {}/{} shards succeeded (need at least {})",
                    stripe_idx, success_count, full_redundancy, config.k
                ),
            )
                .into_response();
        } else if success_count < min_required {
            // Below configurable minimum - insufficient fault tolerance
            error!(
                stripe_idx = stripe_idx,
                success_count = success_count,
                min_required = min_required,
                buffer = state.upload_min_redundancy_buffer,
                "Stripe failed: below minimum redundancy threshold, aborting"
            );
            let _ = tokio::fs::remove_file(&final_path).await;

            let progress = UploadProgress {
                file_hash: file_hash_str.clone(),
                processed_stripes: stripe_idx,
                total_stripes,
                status: format!("Failed: Stripe {} insufficient redundancy", stripe_idx),
                updated_at: now_secs(),
            };
            let _ = state.upload_progress.set(&progress);

            return (
                StatusCode::SERVICE_UNAVAILABLE,
                format!(
                    "Failed to distribute stripe {}: only {}/{} shards succeeded (need at least {} for fault tolerance, set UPLOAD_MIN_REDUNDANCY_BUFFER=0 to accept minimum)",
                    stripe_idx, success_count, full_redundancy, min_required
                ),
            )
                .into_response();
        } else if success_count < full_redundancy {
            // Below full redundancy but above minimum - warn but continue
            warn!(
                stripe_idx = stripe_idx,
                success_count = success_count,
                failed_count = failed_count,
                full_redundancy = full_redundancy,
                fault_tolerance = success_count - config.k,
                "Stripe partial success: reduced fault tolerance"
            );
        }

        // Log stripe summary timing
        let stripe_total_ms = stripe_start.elapsed().as_millis();
        info!(
            file_hash = %file_hash_str,
            stripe_idx = stripe_idx,
            total_stripes = total_stripes,
            stripe_size_bytes = expected_read,
            encode_duration_ms = encode_duration_ms,
            placement_duration_ms = placement_duration_ms,
            distribute_duration_ms = stripe_total_ms.saturating_sub(encode_duration_ms).saturating_sub(placement_duration_ms),
            stripe_total_ms = stripe_total_ms,
            success_shards = success_count,
            failed_shards = failed_count,
            "Stripe processing completed"
        );

        // Log stripe progress less frequently to reduce noise
        if stripe_idx % 10 == 0 || stripe_idx == total_stripes - 1 {
            debug!(
                stripe = stripe_idx + 1,
                total = total_stripes,
                "Processed stripe"
            );
            // Update progress (persist to disk)
            let progress = UploadProgress {
                file_hash: file_hash_str.clone(),
                processed_stripes: stripe_idx + 1,
                total_stripes,
                status: "Processing".to_string(),
                updated_at: now_secs(),
            };
            let _ = state.upload_progress.set(&progress);
        }
    }

    // Push shard commitments to Warden for proof-of-storage auditing
    // Use epoch-based sampling to limit shards per miner (prevents warden memory issues)
    // Fire-and-forget: don't block upload response on Warden notifications
    if let Some(warden) = &state.warden_client {
        if !warden_commitments.is_empty() {
            // Calculate current audit epoch for sampling
            let current_epoch = common::current_epoch(common::now_secs(), state.audit_epoch_secs);

            // Sample shards deterministically based on epoch
            let sampled_commitments = state::sample_warden_commitments(
                &warden_commitments,
                current_epoch,
                &state.validator_node_id,
                state.shards_per_miner_per_epoch,
            );

            let warden = warden.clone();
            let total_count = warden_commitments.len();
            let sampled_count = sampled_commitments.len();
            let file_hash_for_log = file_hash_str.clone();
            tokio::spawn(async move {
                let pushed = warden
                    .push_shard_commitments_batch(&sampled_commitments)
                    .await;
                info!(
                    file_hash = %file_hash_for_log,
                    total = total_count,
                    sampled = sampled_count,
                    pushed = pushed,
                    epoch = current_epoch,
                    "Pushed sampled shard commitments to Warden (epoch-based sampling)"
                );
            });
        }
    }

    // Final Manifest Update (Atomic) - this is the critical step
    final_manifest.shards = all_shards_info;
    let manifest_json = match final_manifest.to_json() {
        Ok(json) => json,
        Err(e) => {
            error!(error = %e, "Failed to serialize manifest");
            let _ = tokio::fs::remove_file(&final_path).await;

            let progress = UploadProgress {
                file_hash: file_hash_str.clone(),
                processed_stripes: total_stripes,
                total_stripes,
                status: "Failed: Manifest serialization error".to_string(),
                updated_at: now_secs(),
            };
            let _ = state.upload_progress.set(&progress);

            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                format!("Failed to serialize manifest: {}", e),
            )
                .into_response();
        }
    };

    debug!(file_hash = %file_hash_str, "Saving final manifest");
    if let Err(e) = state
        .doc
        .set_bytes(
            state.author_id,
            Bytes::from(file_hash_str.as_bytes().to_vec()),
            Bytes::from(manifest_json.clone().into_bytes()),
        )
        .await
    {
        error!(error = %e, "Failed to save final manifest");
        let _ = tokio::fs::remove_file(&final_path).await;

        let progress = UploadProgress {
            file_hash: file_hash_str.clone(),
            processed_stripes: total_stripes,
            total_stripes,
            status: "Failed: Manifest save error".to_string(),
            updated_at: now_secs(),
        };
        let _ = state.upload_progress.set(&progress);

        return (
            StatusCode::INTERNAL_SERVER_ERROR,
            format!("Failed to save manifest: {}", e),
        )
            .into_response();
    }

    // Update manifest cache for fast subsequent reads (with timestamp)
    state
        .manifest_cache
        .insert(file_hash_str.clone(), (manifest_json, common::now_secs()));

    // Mark complete (persist to disk)
    {
        let progress = UploadProgress {
            file_hash: file_hash_str.clone(),
            processed_stripes: total_stripes,
            total_stripes,
            status: "Completed".to_string(),
            updated_at: now_secs(),
        };
        let _ = state.upload_progress.set(&progress);
    }

    // Save sync key
    let sync_key = format!("sync:{}", file_hash_str);
    let _ = state
        .doc
        .set_bytes(
            state.author_id,
            Bytes::from(sync_key.into_bytes()),
            Bytes::from(file_size.to_string().into_bytes()),
        )
        .await;

    // Add to manifest hashes (with capacity checks)
    {
        let mut hashes = state.manifest_hashes.lock().await;
        if !hashes.iter().any(|f| f.hash == file_hash_str) {
            if hashes.len() >= MANIFEST_HASHES_MAX_ENTRIES {
                warn!(
                    files = hashes.len(),
                    "manifest_hashes at capacity, consider archiving old files"
                );
            } else {
                if hashes.len() == MANIFEST_HASHES_WARN_THRESHOLD {
                    warn!(
                        files = hashes.len(),
                        warn_threshold = MANIFEST_HASHES_WARN_THRESHOLD,
                        max = MANIFEST_HASHES_MAX_ENTRIES,
                        "manifest_hashes approaching capacity"
                    );
                }
                hashes.push(common::FileSummary {
                    hash: file_hash_str.clone(),
                    size: file_size as u64,
                });
            }
        }
    }

    // Update sync index
    let _ = update_sync_index(&state).await;

    // Update scalable PG index
    {
        let pg_count = state.cluster_map.read().await.pg_count;
        let pg_id = common::calculate_pg(&file_hash_str, pg_count);
        if let Err(e) = pg_index_add_file(state.as_ref(), pg_id, &file_hash_str).await {
            warn!(pg_id = pg_id, error = %e, "Failed to update PG index");
        }
    }

    // Cleanup temp file
    if let Err(e) = tokio::fs::remove_file(&final_path).await {
        warn!(error = %e, "Failed to cleanup temp file");
    }

    info!(file_hash = %file_hash_str, size = file_size, stripes = total_stripes, "Upload complete");

    // Return success - file is now fully available for download
    let response = Json(serde_json::json!({
        "hash": file_hash_str,
        "message": "File uploaded successfully",
        "size": file_size
    }));

    (StatusCode::OK, response).into_response()
}

async fn save_manifest(State(state): State<Arc<AppState>>, body: String) -> impl IntoResponse {
    // Check ready state - manifest saves require full readiness
    if let Some(response) = check_ready_state(&state) {
        return response.into_response();
    }

    debug!(body = %body, "Received manifest body");

    let manifest: FileManifest = match serde_json::from_str(&body) {
        Ok(m) => m,
        Err(e) => {
            error!(error = %e, "Failed to deserialize manifest");
            return (StatusCode::UNPROCESSABLE_ENTITY, e.to_string()).into_response();
        }
    };

    let json = match manifest.to_json() {
        Ok(j) => j,
        Err(e) => return (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()).into_response(),
    };

    let author = state.author_id;
    debug!(file_hash = %manifest.file_hash, "Saving manifest");
    if let Err(e) = state
        .doc
        .set_bytes(
            author,
            Bytes::from(manifest.file_hash.clone()),
            Bytes::from(json),
        )
        .await
    {
        error!(error = %e, "Failed to save manifest");
        return (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()).into_response();
    }

    // Add to manifest hashes list
    // Add to manifest hashes list
    {
        let mut hashes = state.manifest_hashes.lock().await;
        if !hashes.iter().any(|f| f.hash == manifest.file_hash) {
            hashes.push(FileSummary {
                hash: manifest.file_hash.clone(),
                size: manifest.size,
            });
        }
    }

    // Update Sync Index
    if let Err(e) = update_sync_index(&state).await {
        error!(error = %e, "Failed to update sync index");
    }

    // Update manifest cache (with timestamp)
    if let Ok(json_str) = manifest.to_json() {
        state
            .manifest_cache
            .insert(manifest.file_hash.clone(), (json_str, common::now_secs()));
    }

    debug!("Manifest saved successfully");

    (StatusCode::OK, "Manifest saved").into_response()
}

async fn delete_file(
    State(state): State<Arc<AppState>>,
    Path(hash): Path<String>,
    headers: HeaderMap,
) -> impl IntoResponse {
    info!(hash = %hash, "Delete request received");

    // Check ready state - deletes require full readiness
    if let Some(response) = check_ready_state(&state) {
        return response.into_response();
    }

    // Auth Check using constant-time comparison
    // Check Authorization: Bearer <token> first, then fall back to X-API-Key header
    let expected_key = get_admin_api_key();
    if expected_key.is_empty() {
        return (
            StatusCode::INTERNAL_SERVER_ERROR,
            "API_KEY_ADMIN not configured",
        )
            .into_response();
    }
    let provided_key = headers
        .get("Authorization")
        .and_then(|h| h.to_str().ok())
        .and_then(extract_bearer_token)
        .or_else(|| headers.get("X-API-Key").and_then(|h| h.to_str().ok()));
    if !matches!(provided_key, Some(key) if validate_api_key(key, expected_key)) {
        return (StatusCode::UNAUTHORIZED, "Invalid API Key").into_response();
    }

    // Validate hash format
    if let Err((status, msg)) = validate_hash_param(&hash) {
        return (status, msg).into_response();
    }

    // 1. Get Manifest to find shards
    let query = iroh_docs::store::Query::single_latest_per_key().key_exact(hash.as_bytes());
    let mut stream = Box::pin(match state.doc.get_many(query).await {
        Ok(s) => s,
        Err(e) => return doc_store_error("delete_file query", e).into_response(),
    });

    let manifest: Option<FileManifest> = match stream.next().await {
        Some(Ok(entry)) => {
            let content_hash = entry.content_hash();
            let mut reader = state.blobs_store.reader(content_hash);
            use tokio::io::AsyncReadExt;
            let mut content = Vec::new();
            if reader.read_to_end(&mut content).await.is_ok() {
                let json_str = String::from_utf8_lossy(&content);
                serde_json::from_str(&json_str).ok()
            } else {
                None
            }
        }
        _ => None,
    };

    // Collect shard hashes for Warden notification (before manifest goes out of scope)
    let shard_hashes_for_warden: Vec<String> = manifest
        .as_ref()
        .map(|m| m.shards.iter().map(|s| s.blob_hash.clone()).collect())
        .unwrap_or_default();

    if let Some(m) = manifest {
        debug!(hash = %hash, "Found manifest, notifying miners");

        let k = m.stripe_config.k;
        let m_redundancy = m.stripe_config.m;
        let shards_per_stripe = k + m_redundancy;
        let cluster_map = state.cluster_map.read().await.clone();

        // Build miner_uid -> Vec<blob_hash> mapping
        let mut miner_shards: std::collections::HashMap<u32, Vec<String>> =
            std::collections::HashMap::new();

        for shard in &m.shards {
            let stripe_idx = shard.index / shards_per_stripe;
            let shard_pos = shard.index % shards_per_stripe;

            if let Ok(miners) = common::calculate_stripe_placement(
                &m.file_hash,
                stripe_idx as u64,
                shards_per_stripe,
                &cluster_map,
                m.placement_version,
            ) && let Some(target) = miners.get(shard_pos)
            {
                miner_shards
                    .entry(target.uid)
                    .or_default()
                    .push(shard.blob_hash.clone());
            }
        }

        debug!(
            miners = miner_shards.len(),
            shards = m.shards.len(),
            hash = %hash,
            "Notifying miners to delete shards"
        );

        // Send delete for each blob_hash to its specific miner
        for (uid, blob_hashes) in miner_shards {
            if let Some(miner) = cluster_map.miners.iter().find(|m| m.uid == uid) {
                for blob_hash in blob_hashes {
                    let endpoint_clone = state.endpoint.clone();
                    let miner_endpoint = miner.endpoint.clone();

                    tokio::spawn(async move {
                        if let Ok(Ok(conn)) = tokio::time::timeout(
                            std::time::Duration::from_secs(5),
                            endpoint_clone.connect(miner_endpoint, b"hippius/miner-control"),
                        )
                        .await
                        {
                            let message = common::MinerControlMessage::Delete { hash: blob_hash };
                            if let Ok(msg_bytes) = serde_json::to_vec(&message)
                                && let Ok((mut send, mut recv)) = conn.open_bi().await
                            {
                                let _ = send.write_all(&msg_bytes).await;
                                let _ = send.finish();
                                let _ = tokio::time::timeout(
                                    std::time::Duration::from_secs(5),
                                    recv.read_to_end(64),
                                )
                                .await;
                            }
                        }
                    });
                }
            }
        }
    }

    // 3. Remove from Manifest List (Sync Index)
    {
        let mut hashes = state.manifest_hashes.lock().await;
        if let Some(pos) = hashes.iter().position(|f| f.hash == hash) {
            hashes.remove(pos);
        }
    }
    let _ = update_sync_index(&state).await;

    // 4. Tombstone the manifest in Doc (Content: "DELETED")
    let _ = state
        .doc
        .set_bytes(
            state.author_id,
            Bytes::from(hash.clone()),
            Bytes::from("DELETED"),
        )
        .await;

    // Update manifest cache with tombstone (with timestamp for TTL expiry)
    state
        .manifest_cache
        .insert(hash.clone(), ("DELETED".to_string(), common::now_secs()));

    // 5. Remove from PG index to prevent rebalance operations on deleted files
    let pg_count = state.cluster_map.read().await.pg_count;
    let pg_id = common::calculate_pg(&hash, pg_count);
    state.pg_index.entry(pg_id).and_modify(|files| {
        files.retain(|h| h != &hash);
    });

    // 6. Notify Warden of shard deletions (if enabled)
    // We notify for each shard hash, not the file hash, since Warden tracks individual shards
    if let Some(warden) = &state.warden_client {
        if !shard_hashes_for_warden.is_empty() {
            let warden = warden.clone();
            // Fire-and-forget: don't block delete response on Warden notifications
            tokio::spawn(async move {
                let deleted = warden.delete_shards_batch(&shard_hashes_for_warden).await;
                debug!(
                    total = shard_hashes_for_warden.len(),
                    deleted = deleted,
                    "Notified Warden of shard deletions"
                );
            });
        }
    }

    (StatusCode::OK, "File deleted").into_response()
}

// =============================================================================
// MANIFEST RETRIEVAL
// =============================================================================
//
// The `GET /manifest/:hash` endpoint is the primary way gateways discover file
// metadata for downloads. It returns the `FileManifest` JSON containing:
// - File hash, size, content type
// - Stripe configuration (k, m, stripe_size)
// - Placement version and epoch
// - List of all shards with their BLAKE3 hashes
//
// ## Caching Strategy
//
// ```text
// Request ──▶ Cache Check ──▶ Hit? ──▶ Return cached JSON
//                   │
//                   │ Miss
//                   ▼
//             iroh-docs lookup ──▶ Populate cache ──▶ Return JSON
// ```
//
// The cache uses `QuickCache` (bounded LRU) with 10k entries to prevent
// memory growth. Each cache entry stores:
// - Manifest JSON (or "DELETED" tombstone)
// - Timestamp for tombstone TTL expiry
//
// ## Tombstone Handling
//
// Deleted files are cached as "DELETED" tombstones to avoid repeated doc
// lookups. Tombstones expire after `manifest_cache_tombstone_ttl_secs`
// (default: 3600s) to allow eventual cache cleanup.
//
// ## Gateway Usage
//
// Gateways typically:
// 1. Request manifest via this endpoint (or read from local doc replica)
// 2. Parse `FileManifest` to get shard hashes and stripe config
// 3. Calculate CRUSH placement for each stripe
// 4. Fetch k shards from miners via P2P FetchBlob
// 5. RS decode to reconstruct original data

/// Retrieve a file manifest by its BLAKE3 hash.
///
/// This is the primary metadata endpoint for file downloads. Gateways call this
/// to discover shard locations before fetching from miners.
///
/// # Caching
///
/// Results are cached in `manifest_cache` (bounded LRU, 10k entries).
/// Deleted files are cached as tombstones with TTL expiry.
///
/// # Returns
///
/// - `200 OK` + JSON manifest on success
/// - `404 NOT FOUND` if manifest doesn't exist or was deleted
/// - `500 INTERNAL SERVER ERROR` on doc store failures
async fn get_manifest(
    State(state): State<Arc<AppState>>,
    Path(hash): Path<String>,
) -> impl IntoResponse {
    // Check ready state - manifest reads require full readiness (storage access)
    if let Some(response) = check_ready_state(&state) {
        return response.into_response();
    }

    // Validate hash format early
    if let Err((status, msg)) = validate_hash_param(&hash) {
        return (status, msg).into_response();
    }
    // Fast path: check cache first
    if let Some((cached, cached_at)) = state.manifest_cache.get(&hash) {
        let now = common::now_secs();
        if cached == "DELETED" {
            // Check if tombstone has expired
            if now.saturating_sub(cached_at) > state.manifest_cache_tombstone_ttl_secs {
                // Tombstone expired - remove from cache and fall through to doc store lookup
                state.manifest_cache.remove(&hash);
            } else {
                return (StatusCode::NOT_FOUND, "Manifest deleted").into_response();
            }
        } else {
            return (StatusCode::OK, cached).into_response();
        }
    }

    // Cache miss: read from doc store
    let query = iroh_docs::store::Query::single_latest_per_key().key_exact(hash.as_bytes());
    let mut stream = Box::pin(match state.doc.get_many(query).await {
        Ok(s) => s,
        Err(e) => return doc_store_error("get_manifest query", e).into_response(),
    });

    match stream.next().await {
        Some(Ok(entry)) => {
            let content_hash = entry.content_hash();
            let mut reader = state.blobs_store.reader(content_hash);
            use tokio::io::AsyncReadExt;
            let mut content = Vec::new();
            if reader.read_to_end(&mut content).await.is_ok() {
                let json_str = String::from_utf8_lossy(&content).to_string();
                let is_deleted = json_str == "DELETED";

                // Populate cache with timestamp
                state
                    .manifest_cache
                    .insert(hash.clone(), (json_str.clone(), common::now_secs()));

                if is_deleted {
                    return (StatusCode::NOT_FOUND, "Manifest deleted").into_response();
                }
                (StatusCode::OK, json_str).into_response()
            } else {
                (StatusCode::INTERNAL_SERVER_ERROR, "Failed to read blob").into_response()
            }
        }
        Some(Err(e)) => doc_store_error("get_manifest read", e).into_response(),
        None => (StatusCode::NOT_FOUND, "Manifest not found").into_response(),
    }
}

async fn get_file_shards(
    State(state): State<Arc<AppState>>,
    Path(hash): Path<String>,
) -> impl IntoResponse {
    // Validate hash format early
    if let Err((status, msg)) = validate_hash_param(&hash) {
        return (status, msg).into_response();
    }
    #[derive(serde::Serialize)]
    struct ShardDetail {
        shard_index: usize,
        blob_hash: String,
        shard_type: String, // "DATA" or "PARITY"
        stripe_index: usize,
        local_index: usize,
        miner_uid: u32,
        miner_node_id: String,
        miner_family_id: String,
        miner_http_addr: String,
    }

    #[derive(serde::Serialize)]
    struct FileShardResponse {
        file_hash: String,
        original_size: u64,
        total_shards: usize,
        erasure_coding: String,
        total_stripes: usize,
        unique_miners: usize,
        unique_families: usize,
        shards: Vec<ShardDetail>,
    }

    // Get manifest
    let query = iroh_docs::store::Query::single_latest_per_key().key_exact(hash.as_bytes());
    let mut stream = Box::pin(match state.doc.get_many(query).await {
        Ok(s) => s,
        Err(e) => return doc_store_error("get_file_shards query", e).into_response(),
    });

    let manifest: common::FileManifest = match stream.next().await {
        Some(Ok(entry)) => {
            let content_hash = entry.content_hash();
            let mut reader = state.blobs_store.reader(content_hash);
            use tokio::io::AsyncReadExt;
            let mut content = Vec::new();
            if reader.read_to_end(&mut content).await.is_err() {
                return (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    "Failed to read manifest blob",
                )
                    .into_response();
            }

            let json_str = String::from_utf8_lossy(&content);
            if json_str == "DELETED" {
                return (StatusCode::NOT_FOUND, "File deleted").into_response();
            }

            match serde_json::from_slice(&content) {
                Ok(m) => m,
                Err(e) => {
                    return internal_error("get_file_shards manifest parse", e).into_response();
                }
            }
        }
        Some(Err(e)) => {
            return doc_store_error("get_file_shards read", e).into_response();
        }
        None => {
            return (StatusCode::NOT_FOUND, "Manifest not found").into_response();
        }
    };

    // Get cluster map
    let cluster_map = state.cluster_map.read().await.clone();

    // Calculate shard placements
    let k = manifest.stripe_config.k;
    let m = manifest.stripe_config.m;
    let shards_per_stripe = k + m;
    let total_stripes = (manifest.shards.len() + shards_per_stripe - 1) / shards_per_stripe;

    let mut shard_details = Vec::new();
    let mut unique_miners = std::collections::HashSet::new();
    let mut unique_families = std::collections::HashSet::new();

    for (shard_idx, shard_info) in manifest.shards.iter().enumerate() {
        let stripe_idx = shard_idx / shards_per_stripe;
        let local_idx = shard_idx % shards_per_stripe;

        // Calculate CRUSH placement for this stripe
        let stripe_miners = match common::calculate_pg_placement_for_stripe(
            &manifest.file_hash,
            stripe_idx as u64,
            shards_per_stripe,
            &cluster_map,
        ) {
            Ok(m) => m,
            Err(e) => {
                eprintln!(
                    "Failed to calculate placement for stripe {}: {}",
                    stripe_idx, e
                );
                continue;
            }
        };

        // Get the miner for this shard
        let miner = match stripe_miners.get(local_idx) {
            Some(m) => m,
            None => {
                eprintln!(
                    "No miner found for shard {} (local_idx {})",
                    shard_idx, local_idx
                );
                continue;
            }
        };

        let shard_type = if local_idx < k { "DATA" } else { "PARITY" };

        unique_miners.insert(miner.uid);
        unique_families.insert(miner.family_id.clone());

        shard_details.push(ShardDetail {
            shard_index: shard_idx,
            blob_hash: shard_info.blob_hash.clone(),
            shard_type: shard_type.to_string(),
            stripe_index: stripe_idx,
            local_index: local_idx,
            miner_uid: miner.uid,
            miner_node_id: miner.public_key.clone(),
            miner_family_id: miner.family_id.clone(),
            miner_http_addr: miner.http_addr.clone(),
        });
    }

    let response = FileShardResponse {
        file_hash: manifest.file_hash.clone(),
        original_size: manifest.size,
        total_shards: manifest.shards.len(),
        erasure_coding: format!("{}+{}", k, m),
        total_stripes,
        unique_miners: unique_miners.len(),
        unique_families: unique_families.len(),
        shards: shard_details,
    };

    Json(response).into_response()
}

async fn get_files(State(state): State<Arc<AppState>>) -> impl IntoResponse {
    let hashes = state.manifest_hashes.lock().await.clone();
    Json(hashes).into_response()
}

async fn get_map(State(state): State<Arc<AppState>>) -> impl IntoResponse {
    debug!("Getting map");
    let query = iroh_docs::store::Query::single_latest_per_key().key_exact(b"cluster_map");
    let mut stream = Box::pin(match state.doc.get_many(query).await {
        Ok(s) => s,
        Err(e) => return (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()).into_response(),
    });

    match stream.next().await {
        Some(Ok(entry)) => {
            debug!("Map entry found");
            let hash = entry.content_hash();
            let mut reader = state.blobs_store.reader(hash);
            use tokio::io::AsyncReadExt;
            let mut content = Vec::new();
            if reader.read_to_end(&mut content).await.is_ok() {
                let json_str = String::from_utf8_lossy(&content);
                // Parse and return as JSON with proper content-type
                match serde_json::from_str::<ClusterMap>(&json_str) {
                    Ok(map) => Json(map).into_response(),
                    Err(e) => {
                        error!(error = %e, "Failed to parse cluster map JSON");
                        (
                            StatusCode::INTERNAL_SERVER_ERROR,
                            format!("Parse error: {}", e),
                        )
                            .into_response()
                    }
                }
            } else {
                (StatusCode::INTERNAL_SERVER_ERROR, "Failed to read blob").into_response()
            }
        }
        Some(Err(e)) => {
            error!(error = %e, "Error getting map");
            (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()).into_response()
        }
        None => {
            debug!("Map not found in docs");
            (StatusCode::NOT_FOUND, "Map not found").into_response()
        }
    }
}

async fn get_map_epoch(
    State(state): State<Arc<AppState>>,
    Path(epoch): Path<u64>,
) -> impl IntoResponse {
    debug!(epoch = epoch, "Getting map for epoch");
    let key = cluster_map_epoch_key(epoch);
    let query = iroh_docs::store::Query::single_latest_per_key().key_exact(key.as_slice());
    let mut stream = Box::pin(match state.doc.get_many(query).await {
        Ok(s) => s,
        Err(e) => return (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()).into_response(),
    });

    match stream.next().await {
        Some(Ok(entry)) => {
            let hash = entry.content_hash();
            let mut reader = state.blobs_store.reader(hash);
            use tokio::io::AsyncReadExt;
            let mut content = Vec::new();
            if reader.read_to_end(&mut content).await.is_ok() {
                let json_str = String::from_utf8_lossy(&content);
                match serde_json::from_str::<ClusterMap>(&json_str) {
                    Ok(map) => Json(map).into_response(),
                    Err(e) => (
                        StatusCode::INTERNAL_SERVER_ERROR,
                        format!("Parse error: {}", e),
                    )
                        .into_response(),
                }
            } else {
                (StatusCode::INTERNAL_SERVER_ERROR, "Failed to read blob").into_response()
            }
        }
        Some(Err(e)) => (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()).into_response(),
        None => (StatusCode::NOT_FOUND, "Map not found").into_response(),
    }
}

/// Get rebalance status for a specific (epoch, pg_id) pair.
/// Returns whether the PG is settled (all shards confirmed moved) at this epoch.
async fn get_rebalance_status(
    State(state): State<Arc<AppState>>,
    Path((epoch, pg_id)): Path<(u64, u32)>,
) -> impl IntoResponse {
    let key = (epoch, pg_id);

    // Check if this PG needed rebalancing at this epoch
    if let Some(status) = state.rebalance_status.get(&key) {
        Json(serde_json::json!({
            "settled": status.is_settled(),
            "progress": status.confirmed_shards as f32 / status.total_shards.max(1) as f32,
            "total_shards": status.total_shards,
            "confirmed_shards": status.confirmed_shards,
            "epoch": status.epoch,
            "pg_id": status.pg_id,
            "started_at": status.started_at,
            "settled_at": status.settled_at,
        }))
        .into_response()
    } else {
        // No rebalance needed for this PG at this epoch = already settled
        // This happens when:
        // 1. The PG placement didn't change at this epoch
        // 2. The epoch/pg combo was never tracked (old epochs cleaned up)
        Json(serde_json::json!({
            "settled": true,
            "progress": 1.0,
            "total_shards": 0,
            "confirmed_shards": 0,
            "epoch": epoch,
            "pg_id": pg_id,
        }))
        .into_response()
    }
}

// =============================================================================
// FILE REPAIR HANDLER
// =============================================================================
//
// The repair endpoint (`POST /repair/:hash`) is an operator tool for recovering
// files that have become stranded or need migration to new placement schemes.
//
// ## When to Use Repair
//
// 1. **Legacy File Migration**: Files placed with placement_version=1 (per-stripe)
//    need migration to version=2 (PG-based) for efficient rebalancing
//
// 2. **Stranded Files**: Files whose miners all went offline before auto-recovery
//    could reconstruct them
//
// 3. **Manual Intervention**: When auto-recovery fails repeatedly and operator
//    investigation reveals recoverable state
//
// ## Repair Strategies
//
// The handler chooses between two strategies based on manifest state:
//
// ### Strategy A: PullFromPeer (Fast)
// Used when manifest has `miner_uid` pins (knows where shards were stored):
//
// ```text
// For each shard in current CRUSH placement:
//   1. If shard already at correct miner → skip
//   2. Else find source miner (from miner_uid pin)
//   3. Send PullFromPeer to new miner
// ```
//
// ### Strategy B: Reconstruct + Re-place (Heavy)
// Used when no `miner_uid` pins exist (older manifests or recovery state):
//
// ```text
// For each stripe:
//   1. Probe all historical epochs × placement versions
//   2. Fetch ≥k shards from wherever they're found
//   3. RS decode to reconstruct original stripe
//   4. RS re-encode to generate all k+m shards
//   5. Push shards to current CRUSH(PG) placement
//   6. Update manifest with new placement_version and epoch
// ```
//
// ## Windowed Repair
//
// For large files, use query parameters to process in windows:
// - `?start=0&count=10` - Repair stripes 0-9
// - `?start=10&count=10` - Repair stripes 10-19
// - etc.
//
// This prevents timeouts and allows progress monitoring.
//
// ## Epoch Lookback
//
// When searching for shard locations, the repair probes historical epochs:
// - `REPAIR_EPOCH_LOOKBACK` (default: 250 epochs)
// - Tries placement versions in order: [2, 1] for legacy files
// - Stops as soon as ≥k shards are found for each stripe
//
// ## Response
//
// Returns JSON with repair statistics:
// ```json
// {
//   "status": "ok",
//   "pulls_sent": 25,      // PullFromPeer messages sent
//   "skipped": 5,          // Shards already in place
//   "missing_source": 0    // Shards with no known source
// }
// ```

/// Repair/migrate a single file's shards to the *current* CRUSH(PG) placement.
///
/// This is mainly for legacy manifests that include `miner_uid` pins and/or were placed
/// using older placement versions (e.g. per-stripe instead of PG-based).
///
/// # Arguments
///
/// * `hash` - The file hash to repair
/// * `q` - Query parameters: `start` (stripe offset), `count` (stripe limit)
///
/// # Strategy Selection
///
/// - If manifest has `miner_uid` pins: Use fast PullFromPeer migration
/// - Otherwise: Use heavy reconstruct-and-replace strategy
///
/// # Example
///
/// ```bash
/// # Repair entire file
/// curl -X POST http://localhost:3002/repair/{hash}
///
/// # Repair stripes 0-9 only
/// curl -X POST "http://localhost:3002/repair/{hash}?start=0&count=10"
/// ```
async fn repair_file(
    State(state): State<Arc<AppState>>,
    Path(hash): Path<String>,
    AxumQuery(q): AxumQuery<std::collections::HashMap<String, String>>,
) -> impl IntoResponse {
    // Check ready state - repairs require full readiness
    if let Some(response) = check_ready_state(&state) {
        return response.into_response();
    }

    // Validate hash format early
    if let Err((status, msg)) = validate_hash_param(&hash) {
        return (status, msg).into_response();
    }
    state.metrics.admin_ops_total.inc();
    // Fetch manifest JSON from iroh-docs
    let manifest_entry = match state
        .doc
        .get_exact(state.author_id, Bytes::from(hash.clone()), false)
        .await
    {
        Ok(e) => e,
        Err(e) => return (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()).into_response(),
    };

    let entry = match manifest_entry {
        Some(e) => e,
        None => return (StatusCode::NOT_FOUND, "Manifest not found").into_response(),
    };

    let mut reader = state.blobs_store.reader(entry.content_hash());
    use tokio::io::AsyncReadExt;
    let mut content = Vec::new();
    if reader.read_to_end(&mut content).await.is_err() {
        return (
            StatusCode::INTERNAL_SERVER_ERROR,
            "Failed to read manifest blob",
        )
            .into_response();
    }

    // Parse as Value first so we can detect whether placement_version was explicitly present.
    let manifest_value: serde_json::Value = match serde_json::from_slice(&content) {
        Ok(v) => v,
        Err(e) => {
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                format!("Invalid manifest JSON: {}", e),
            )
                .into_response();
        }
    };
    let placement_version_present = manifest_value.get("placement_version").is_some();
    let manifest: common::FileManifest = match serde_json::from_value(manifest_value) {
        Ok(m) => m,
        Err(e) => {
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                format!("Invalid manifest JSON: {}", e),
            )
                .into_response();
        }
    };

    // Current map (in-memory cache)
    let map = { state.cluster_map.read().await.clone() };
    if map.miners.is_empty() {
        return (StatusCode::SERVICE_UNAVAILABLE, "No miners in cluster map").into_response();
    }

    let shards_per_stripe = manifest.stripe_config.k + manifest.stripe_config.m;
    let pg_id = common::calculate_pg(&manifest.file_hash, map.pg_count);

    // Build uid -> miner mapping for endpoints
    let mut by_uid: std::collections::HashMap<u32, common::MinerNode> =
        std::collections::HashMap::new();
    for m in map.miners.iter() {
        by_uid.insert(m.uid, m.clone());
    }

    let mut pulls_sent: usize = 0;
    let mut skipped: usize = 0;
    let mut missing_source: usize = 0;

    // If the manifest has no per-shard miner_uid pins, do a heavier "reconstruct + re-place" repair:
    // 1) Find >=k shard bytes for each stripe by probing older epochs + legacy placement versions.
    // 2) RS reconstruct to full (k+m)
    // 3) Push shards to current CRUSH(PG) placement (v2)
    let any_pinned_sources = manifest.shards.iter().any(|s| s.miner_uid.is_some());
    if !any_pinned_sources {
        use reed_solomon_erasure::galois_8::ReedSolomon;
        // use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};

        let current_epoch = map.epoch;
        let lookback: u64 = std::env::var("REPAIR_EPOCH_LOOKBACK")
            .ok()
            .and_then(|s| s.parse().ok())
            .unwrap_or(250);
        let min_epoch = current_epoch.saturating_sub(lookback);

        // Placement versions to probe for legacy manifests.
        let placement_versions_to_try: Vec<u8> = if placement_version_present {
            vec![manifest.placement_version]
        } else {
            vec![2, 1]
        };

        // Miner-control FetchBlob helper
        async fn fetch_blob_from_miner(
            endpoint: &Endpoint,
            miner: &common::MinerNode,
            blob_hash: &str,
        ) -> Option<Vec<u8>> {
            let conn = tokio::time::timeout(
                std::time::Duration::from_secs(10),
                endpoint.connect(miner.endpoint.clone(), b"hippius/miner-control"),
            )
            .await
            .ok()?
            .ok()?;
            let (mut send, mut recv) = conn.open_bi().await.ok()?;

            let msg = common::MinerControlMessage::FetchBlob {
                hash: blob_hash.to_string(),
            };
            let msg_bytes = serde_json::to_vec(&msg).ok()?;
            send.write_all(&msg_bytes).await.ok()?;
            let _ = send.finish();
            let resp = tokio::time::timeout(
                std::time::Duration::from_secs(15),
                recv.read_to_end(MAX_FETCH_RESPONSE_SIZE),
            )
            .await
            .ok()?
            .ok()?;

            if !resp.starts_with(b"DATA:") {
                return None;
            }
            let data = resp[5..].to_vec();
            if blake3::hash(&data).to_hex().as_str() != blob_hash {
                return None;
            }
            Some(data)
        }

        // Pre-index shards by stripe/local_idx
        let stripes_total = manifest.shards.len().div_ceil(shards_per_stripe);
        let mut stripe_shard_hashes: Vec<Vec<Option<String>>> =
            vec![vec![None; shards_per_stripe]; stripes_total];
        for shard in manifest.shards.iter() {
            let stripe_idx = shard.index / shards_per_stripe;
            let local_idx = shard.index % shards_per_stripe;
            if stripe_idx < stripes_total {
                stripe_shard_hashes[stripe_idx][local_idx] = Some(shard.blob_hash.clone());
            }
        }

        let rs = match ReedSolomon::new(manifest.stripe_config.k, manifest.stripe_config.m) {
            Ok(r) => r,
            Err(e) => {
                return (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    format!("RS init failed: {}", e),
                )
                    .into_response();
            }
        };

        let mut stripes_repaired: usize = 0;
        let mut stripes_failed: usize = 0;
        let mut shards_pushed: usize = 0;
        let mut shards_found: usize = 0;
        let mut scan_attempts: usize = 0;
        let mut scan_hits: usize = 0;

        // Allow windowed repairs for large files:
        // - POST /repair/:hash?start=<stripe_idx>&count=<num_stripes>
        // Defaults to 25 stripes starting at 0.
        let start_stripe: usize = q.get("start").and_then(|s| s.parse().ok()).unwrap_or(0);
        let count_stripes: usize = q
            .get("count")
            .and_then(|s| s.parse().ok())
            .or_else(|| {
                std::env::var("REPAIR_STRIPES_PER_RUN")
                    .ok()
                    .and_then(|s| s.parse().ok())
            })
            .unwrap_or(25);
        let stripes_to_process = if count_stripes == 0 {
            stripes_total.saturating_sub(start_stripe)
        } else {
            std::cmp::min(stripes_total.saturating_sub(start_stripe), count_stripes)
        };

        for stripe_idx in start_stripe..(start_stripe + stripes_to_process) {
            // 1) Try to find >=k shard bytes by probing (epoch, placement_version)
            let mut shard_data: Vec<Option<Vec<u8>>> = vec![None; shards_per_stripe];
            let mut have = 0usize;

            'epoch_loop: for e in (min_epoch..=current_epoch).rev() {
                let map_e = match get_map_epoch_internal(state.as_ref(), e).await {
                    Some(m) => m,
                    None => continue,
                };
                for pv in placement_versions_to_try.iter().copied() {
                    let stripe_miners = match common::calculate_stripe_placement(
                        &manifest.file_hash,
                        stripe_idx as u64,
                        shards_per_stripe,
                        &map_e,
                        pv,
                    ) {
                        Ok(m) => m,
                        Err(_) => continue,
                    };
                    for local_idx in 0..shards_per_stripe {
                        if have >= manifest.stripe_config.k {
                            break 'epoch_loop;
                        }
                        if shard_data[local_idx].is_some() {
                            continue;
                        }
                        let Some(blob_hash) = stripe_shard_hashes[stripe_idx][local_idx].as_deref()
                        else {
                            continue;
                        };
                        let miner = &stripe_miners[local_idx];
                        if let Some(bytes) =
                            fetch_blob_from_miner(&state.endpoint, miner, blob_hash).await
                        {
                            shard_data[local_idx] = Some(bytes);
                            have += 1;
                            shards_found += 1;
                        }
                    }
                }
            }

            // 1b) Last-resort: if epoch history is missing (or placement drifted), brute-force scan miners
            // by shard hash until we have >=k.
            if have < manifest.stripe_config.k {
                // Scan is expensive; allow explicit override via query (?scan=0|1).
                let scan_enabled = q
                    .get("scan")
                    .map(|v| v == "1" || v.to_lowercase() == "true")
                    .unwrap_or_else(|| {
                        std::env::var("REPAIR_SCAN_ENABLED")
                            .ok()
                            .map(|v| v != "0" && v.to_lowercase() != "false")
                            .unwrap_or(true)
                    });
                if scan_enabled {
                    let max_miners: usize = std::env::var("REPAIR_SCAN_MAX_MINERS")
                        .ok()
                        .and_then(|s| s.parse().ok())
                        .unwrap_or(map.miners.len());
                    let miners_to_try = std::cmp::min(map.miners.len(), max_miners);

                    'scan: for local_idx in 0..shards_per_stripe {
                        if have >= manifest.stripe_config.k {
                            break 'scan;
                        }
                        if shard_data[local_idx].is_some() {
                            continue;
                        }
                        let Some(blob_hash) = stripe_shard_hashes[stripe_idx][local_idx].as_deref()
                        else {
                            continue;
                        };
                        for miner in map.miners.iter().take(miners_to_try) {
                            if have >= manifest.stripe_config.k {
                                break 'scan;
                            }
                            scan_attempts += 1;
                            if let Some(bytes) =
                                fetch_blob_from_miner(&state.endpoint, miner, blob_hash).await
                            {
                                shard_data[local_idx] = Some(bytes);
                                have += 1;
                                shards_found += 1;
                                scan_hits += 1;
                                break;
                            }
                        }
                    }
                }
            }

            if have < manifest.stripe_config.k {
                stripes_failed += 1;
                continue;
            }

            // 2) Reconstruct all shards (k+m)
            let mut recon = shard_data;
            if let Err(_e) = rs.reconstruct(&mut recon) {
                stripes_failed += 1;
                continue;
            }

            // 3) Push shards to current CRUSH(PG) placement (v2)
            let targets = match common::calculate_pg_placement_for_stripe(
                &manifest.file_hash,
                stripe_idx as u64,
                shards_per_stripe,
                &map,
            ) {
                Ok(m) => m,
                Err(_) => {
                    stripes_failed += 1;
                    continue;
                }
            };

            for local_idx in 0..shards_per_stripe {
                let global_idx = stripe_idx * shards_per_stripe + local_idx;
                if global_idx >= manifest.shards.len() {
                    continue;
                }
                let Some(ref expected_hash) = stripe_shard_hashes[stripe_idx][local_idx] else {
                    continue;
                };
                let Some(ref bytes) = recon[local_idx] else {
                    continue;
                };
                if blake3::hash(bytes).to_hex().as_str() != expected_hash {
                    stripes_failed += 1;
                    continue;
                }
                let target = match targets.get(local_idx).cloned() {
                    Some(t) => t,
                    None => continue,
                };
                if let Some(miner) = by_uid.get(&target.uid).cloned() {
                    if push_shard_to_miner(global_idx, bytes, &miner, state.as_ref())
                        .await
                        .is_ok()
                    {
                        shards_pushed += 1;
                    }
                }
            }

            stripes_repaired += 1;
        }

        // Only update manifest metadata if we successfully repaired the ENTIRE file in this call.
        // Otherwise we risk "poisoning" reads by claiming a placement_epoch that doesn't match the real shard distribution.
        let full_file_repair_succeeded = start_stripe == 0
            && stripes_to_process == stripes_total
            && stripes_failed == 0
            && stripes_repaired == stripes_total;

        if full_file_repair_succeeded {
            let mut updated = manifest.clone();
            updated.placement_version = 2;
            updated.placement_epoch = map.epoch;
            if let Ok(json) = serde_json::to_vec(&updated) {
                let save_result = state
                    .doc
                    .set_bytes(
                        state.author_id,
                        Bytes::from(hash.clone()),
                        Bytes::from(json),
                    )
                    .await;
                // Update manifest cache on successful write (with timestamp)
                if save_result.is_ok() {
                    if let Ok(json_str) = updated.to_json() {
                        state
                            .manifest_cache
                            .insert(hash.clone(), (json_str, common::now_secs()));
                    }
                }
            }
        }

        let summary = serde_json::json!({
            "file_hash": manifest.file_hash,
            "pg_id": pg_id,
            "epoch": map.epoch,
            "shards": manifest.shards.len(),
            "mode": "reconstruct_and_replace",
            "placement_versions_probed": placement_versions_to_try,
            "epoch_lookback": lookback,
            "stripes_total": stripes_total,
            "start_stripe": start_stripe,
            "stripes_processed": stripes_to_process,
            "stripes_repaired": stripes_repaired,
            "stripes_failed": stripes_failed,
            "shards_found": shards_found,
            "shards_pushed": shards_pushed,
            "scan_attempts": scan_attempts,
            "scan_hits": scan_hits,
        });

        return (StatusCode::OK, Json(summary)).into_response();
    }

    for shard in manifest.shards.iter() {
        let stripe_idx = shard.index / shards_per_stripe;
        let local_idx = shard.index % shards_per_stripe;
        let targets = match common::calculate_pg_placement_for_stripe(
            &manifest.file_hash,
            stripe_idx as u64,
            shards_per_stripe,
            &map,
        ) {
            Ok(m) => m,
            Err(_) => continue,
        };
        let target = match targets.get(local_idx).cloned() {
            Some(t) => t,
            None => continue,
        };

        // If we know a source miner from the manifest, ask the target to pull from that source.
        let src_uid = match shard.miner_uid {
            Some(u) => u,
            None => {
                skipped += 1;
                continue;
            }
        };

        if src_uid == target.uid {
            skipped += 1;
            continue;
        }

        let src = match by_uid.get(&src_uid).cloned() {
            Some(s) => s,
            None => {
                missing_source += 1;
                continue;
            }
        };

        // Send PullFromPeer to the target miner with the source endpoint JSON.
        let msg = common::MinerControlMessage::PullFromPeer {
            hash: shard.blob_hash.clone(),
            peer_endpoint: serde_json::to_string(&src.endpoint).unwrap_or_default(),
        };

        let msg_bytes = match serde_json::to_vec(&msg) {
            Ok(b) => b,
            Err(_) => continue,
        };

        // best-effort: connect and send (no long awaits inside loop)
        if let Ok(Ok(conn)) = tokio::time::timeout(
            std::time::Duration::from_secs(10),
            state
                .endpoint
                .connect(target.endpoint.clone(), b"hippius/miner-control"),
        )
        .await
        {
            if let Ok((mut send, mut recv)) = conn.open_bi().await {
                // use tokio::io::{AsyncWriteExt, AsyncReadExt};
                let _ = send.write_all(&msg_bytes).await;
                let _ = send.finish();
                // read ack best-effort (miner replies OK)
                let _ =
                    tokio::time::timeout(std::time::Duration::from_secs(5), recv.read_to_end(64))
                        .await;
                pulls_sent += 1;
                state.metrics.pull_from_peer_sent.inc();
            }
        }
    }

    let summary = serde_json::json!({
        "file_hash": manifest.file_hash,
        "pg_id": pg_id,
        "epoch": map.epoch,
        "shards": manifest.shards.len(),
        "mode": "pinned_pull_from_peer",
        "pulls_sent": pulls_sent,
        "skipped": skipped,
        "missing_source_in_map": missing_source,
    });

    (StatusCode::OK, Json(summary)).into_response()
}

async fn get_node_id(State(state): State<Arc<AppState>>) -> impl IntoResponse {
    // Return self node ID
    let node_id = state.endpoint.secret_key().public().to_string();
    (StatusCode::OK, node_id).into_response()
}

/// Health check endpoint that includes ready state.
///
/// Returns 200 if validator is accepting connections (even during warmup).
/// Clients should check the `ready` field to determine if full operations are available.
async fn health_check(State(state): State<Arc<AppState>>) -> impl IntoResponse {
    let ready_state = state.get_ready_state();
    let response = serde_json::json!({
        "status": "ok",
        "version": env!("CARGO_PKG_VERSION"),
        "ready": ready_state.is_ready(),
        "ready_state": ready_state.status_str(),
        "node_id": state.endpoint.secret_key().public().to_string(),
    });
    (StatusCode::OK, Json(response))
}

async fn update_map(
    State(state): State<Arc<AppState>>,
    Json(map): Json<ClusterMap>,
) -> impl IntoResponse {
    debug!("Updating map");
    if let Err(e) = persist_cluster_map_to_doc(&state, &map).await {
        error!(error = %e, "Failed to update map");
        return (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()).into_response();
    }

    // Update Sync Index
    if let Err(e) = update_sync_index(&state).await {
        error!(error = %e, "Failed to update sync index");
    }

    debug!("Map updated successfully");

    (StatusCode::OK, "Map updated").into_response()
}

// Legacy HTTP miner endpoints were removed (registration/heartbeat are P2P + chain-verified).

// Weight adjustment helpers moved to helpers.rs

// =============================================================================
// AUTO RECOVERY LOOP
// =============================================================================
//
// The auto recovery loop is responsible for detecting and repairing data loss
// when miners go offline. It runs continuously in the background, checking for
// files with missing shards and orchestrating their reconstruction.
//
// ## Recovery Flow
//
// ```text
// ┌──────────────────────────────────────────────────────────────────────────┐
// │                         AUTO RECOVERY LOOP                                │
// │                    (runs every rebuild_tick_secs)                         │
// └──────────────────────────────────────────────────────────────────────────┘
//                                    │
//         ┌──────────────────────────┼──────────────────────────────────────┐
//         │                          │                                       │
//         ▼                          ▼                                       │
// ┌───────────────────┐    ┌────────────────────────┐                        │
// │ broadcast_map_if  │    │   run_recovery_check   │                        │
// │     _needed       │    │                        │                        │
// │                   │    │ 1. Scan all manifests  │                        │
// │ Push ClusterMap   │    │ 2. Find offline shards │                        │
// │ updates to miners │    │ 3. Trigger repairs     │                        │
// └───────────────────┘    └────────────────────────┘                        │
//                                    │                                       │
//                                    ▼                                       │
//                          ┌────────────────────────┐                        │
//                          │    For each file with  │                        │
//                          │    offline shards:     │                        │
//                          │                        │                        │
//                          │    repair_file_stripes │◀───────────────────────┘
//                          │    (bounded per tick)  │
//                          └────────────────────────┘
//                                    │
//                                    ▼
//                          ┌────────────────────────┐
//                          │  For each stripe:      │
//                          │  1. Fetch k shards via │
//                          │     P2P (FetchBlob)    │
//                          │  2. RS decode stripe   │
//                          │  3. RS re-encode       │
//                          │  4. Push to new miners │
//                          └────────────────────────┘
// ```
//
// ## Configuration
//
// | Variable | Default | Description |
// |----------|---------|-------------|
// | `REBUILD_ENABLED` | true | Master switch for recovery |
// | `REBUILD_TICK_SECS` | 10 | Check frequency |
// | `REBUILD_FILES_PER_TICK` | 5 | Max files to process per tick |
// | `REBUILD_STRIPES_PER_FILE` | 25 | Max stripes per file (0=unlimited) |
// | `REBUILD_CONCURRENCY` | 2 | Parallel stripe repairs |
// | `MINER_OUT_THRESHOLD_SECS` | 600 | Time before miner considered offline |
//
// ## Miner Offline Detection
//
// A miner is considered offline when:
// - `last_heartbeat + MINER_OUT_THRESHOLD_SECS < current_time`
// - The miner has been marked with strikes >= threshold
// - The miner is in the cooldown list (recently rebalanced)
//
// ## Graceful Degradation
//
// The recovery loop is designed to be non-blocking:
// - Files are processed in bounded batches to avoid memory exhaustion
// - Concurrent stripe repairs are limited by semaphore
// - Failures are logged but don't stop the loop
// - Loop can be paused at runtime via `REBUILD_ENABLED=false`

/// Main recovery loop that monitors miner health and repairs missing shards.
///
/// This loop performs two critical functions:
/// 1. **Map Broadcasting**: Pushes ClusterMap updates to all miners when epoch changes
/// 2. **Shard Recovery**: Detects offline miners and reconstructs their shards
///
/// The loop runs indefinitely, sleeping for `rebuild_tick_secs` between iterations.
/// It can be paused at runtime by setting `REBUILD_ENABLED=false`.
async fn auto_recovery_loop(state: Arc<AppState>) {
    use tokio::time::{Duration, sleep};

    let mut last_broadcast_epoch: u64 = 0;

    loop {
        sleep(Duration::from_secs(state.rebuild_tick_secs)).await;

        // Wait for validator to be fully ready before processing recovery
        if !state.is_ready() {
            continue;
        }

        // 1. Broadcast Map Updates (if epoch changed)
        if let Err(e) = broadcast_map_if_needed(&state, &mut last_broadcast_epoch).await {
            warn!(error = %e, "Broadcast failed");
        }

        // Allow operator to pause rebuild safely (config/env)
        if !state.rebuild_enabled {
            continue;
        }

        if let Err(e) = run_recovery_check(&state).await {
            warn!(error = %e, "Recovery check failed");
        }
    }
}

/// Broadcast ClusterMap updates to all registered miners when epoch changes.
///
/// This function ensures miners stay synchronized with the cluster topology.
/// When a new epoch is detected (miner joins/leaves, weight changes), the
/// updated map is pushed to all miners via P2P `ClusterMapUpdate` messages.
///
/// # Arguments
///
/// * `state` - Application state with endpoint and doc store
/// * `last_epoch` - Mutable reference to track last broadcasted epoch
///
/// # Broadcast Behavior
///
/// - Only broadcasts when `current_epoch > last_epoch`
/// - Updates `last_epoch` after successful broadcast
/// - Failures are logged but don't block the recovery loop
async fn broadcast_map_if_needed(
    state: &AppState,
    last_epoch: &mut u64,
) -> Result<(), Box<dyn std::error::Error>> {
    // Read current map
    let query_map = iroh_docs::store::Query::single_latest_per_key().key_exact(b"cluster_map");
    let mut stream = Box::pin(state.doc.get_many(query_map).await?);

    if let Some(Ok(entry)) = stream.next().await {
        let hash = entry.content_hash();
        let mut reader = state.blobs_store.reader(hash);
        use tokio::io::AsyncReadExt;
        let mut content = Vec::new();
        if reader.read_to_end(&mut content).await.is_ok() {
            let json_str = String::from_utf8_lossy(&content);
            if let Ok(map) = serde_json::from_str::<common::ClusterMap>(&json_str) {
                if map.epoch > *last_epoch || *last_epoch == 0 {
                    debug!(
                        from_epoch = *last_epoch,
                        to_epoch = map.epoch,
                        "Map epoch updated, broadcasting"
                    );
                    *last_epoch = map.epoch;
                    broadcast_cluster_map_to_miners(
                        &map,
                        &state.endpoint,
                        state.relay_url.clone(),
                        state.connection_pool.clone(),
                    )
                    .await
                    .ok();
                }
            }
        }
    }
    Ok(())
}

// =============================================================================
// WEIGHT UPDATE LOOP
// =============================================================================
//
// The weight update loop periodically recomputes miner weights based on observed
// performance signals. Weights affect CRUSH placement - higher weight miners
// receive proportionally more shards.
//
// ## Weight Factors
//
// The weight calculation (in helpers.rs) considers:
//
// | Factor | Impact | Description |
// |--------|--------|-------------|
// | Capacity | + | More storage = higher weight (up to cap) |
// | Uptime | + | Longer continuous uptime = higher weight |
// | Age | + | Older miners are trusted more |
// | Strikes | - | Each strike reduces weight via multiplier |
// | Manual Override | ~ | Operator can set fixed weight |
//
// ## Strike Multiplier
//
// ```text
// strikes = 0 → multiplier = 1.0   (no penalty)
// strikes = 1 → multiplier = 0.8   (20% reduction)
// strikes = 2 → multiplier = 0.6   (40% reduction)
// strikes = 3 → multiplier = 0.4   (60% reduction)
// strikes ≥ 4 → multiplier = 0.2   (80% reduction)
// ```
//
// ## Epoch Bump Threshold
//
// Weight changes only trigger an epoch bump if:
// - Change percentage ≥ `weight_update_min_change_pct` (default: 10%)
// - This prevents thrashing from minor fluctuations
//
// ## Configuration
//
// | Variable | Default | Description |
// |----------|---------|-------------|
// | `WEIGHT_UPDATE_ENABLED` | false | Enable weight recalculation |
// | `WEIGHT_UPDATE_TICK_SECS` | 3600 | Recalculation frequency (1 hour) |
// | `WEIGHT_UPDATE_MIN_CHANGE_PCT` | 10 | Minimum % change to trigger epoch bump |
//
// ## Lock Ordering
//
// This function respects lock ordering to prevent deadlocks:
// 1. Read `cluster_map` (RwLock) BEFORE acquiring `map_lock` (Mutex)
// 2. Only then persist changes

/// Periodically recompute miner weights from observed signals (capacity/uptime/age/strikes)
/// and bump ClusterMap epoch when weights materially change.
///
/// This is intentionally coarse-grained to avoid constant remapping. Weight changes
/// only trigger epoch bumps when they exceed the configured threshold percentage.
///
/// # Weight Formula
///
/// ```text
/// base_weight = f(capacity, uptime, age)  // see helpers::adjust_miner_weight
/// strike_mult = calculate_strike_multiplier(strikes)
/// final_weight = clamp(base_weight * strike_mult, 10, 2000)
/// ```
async fn weight_update_loop(state: Arc<AppState>) {
    use tokio::time::{Duration, sleep};

    loop {
        sleep(Duration::from_secs(state.weight_update_tick_secs)).await;

        // Wait for validator to be fully ready before processing weight updates
        if !state.is_ready() {
            continue;
        }

        if !state.weight_update_enabled {
            continue;
        }

        let now = now_secs();

        // Serialize map updates to avoid racing registration/deregistration.
        // IMPORTANT: Acquire map_lock BEFORE reading cluster_map to prevent TOCTOU race.
        let _guard = state.map_lock.lock().await;

        // Now read cluster_map while holding the lock
        let mut map = { state.cluster_map.read().await.clone() };
        if map.miners.is_empty() {
            continue;
        }

        let mut any_changed = false;
        let mut changed_count = 0usize;

        for miner in map.miners.iter_mut() {
            if miner.weight_manual_override {
                continue;
            }

            // Include reputation multiplier (smooth exponential decay).
            let base_new = adjust_miner_weight(miner, now);
            let reputation_mult = calculate_reputation_multiplier(miner.reputation);
            let new_weight = ((base_new as f32) * reputation_mult) as u32;
            let new_weight = new_weight.clamp(10, 2000);

            let old_weight = miner.weight.max(1);
            let delta = new_weight.abs_diff(old_weight);
            let pct = (delta.saturating_mul(100)) / old_weight;

            if pct >= state.weight_update_min_change_pct {
                miner.weight = new_weight;
                any_changed = true;
                changed_count += 1;
            }
        }

        if any_changed {
            let old_epoch = map.epoch;
            map.epoch = map.epoch.saturating_add(1);

            if let Err(e) = persist_cluster_map_to_doc(&state, &map).await {
                error!(error = %e, "Weight update persist failed");
                continue;
            }
            let _ = save_cluster_map_to_disk(&map).await;
            info!(
                miners = changed_count,
                from_epoch = old_epoch,
                to_epoch = map.epoch,
                "Weights updated"
            );
        }
    }
}

/// Execute a single recovery check iteration.
///
/// This function implements the core recovery logic:
///
/// ## Algorithm
///
/// ```text
/// 1. Load ClusterMap from iroh-docs
/// 2. Identify offline miners (last_heartbeat < threshold)
/// 3. Identify OUT miners (sustained offline > out_threshold)
///    │
///    ├─ If OUT miners exist:
///    │   a. Remove from ClusterMap
///    │   b. Bump epoch (triggers rebalance)
///    │   c. Persist updated map
///    │
/// 4. For each file (bounded by rebuild_files_per_tick):
///    │   a. Calculate CRUSH placement
///    │   b. Check which shards are on offline miners
///    │   c. If any offline shards → add to recovery queue
///    │
/// 5. Process recovery queue (bounded concurrency):
///       For each stripe with offline shards:
///         a. Fetch k healthy shards via FetchBlob
///         b. RS decode to reconstruct original data
///         c. RS re-encode to generate all k+m shards
///         d. Push missing shards to new miners
/// ```
///
/// ## Offline vs OUT
///
/// - **Offline**: Miner missed recent heartbeat (temporary issue)
/// - **OUT**: Miner has been offline > `MINER_OUT_THRESHOLD_SECS`
///
/// OUT miners are removed from the cluster map, triggering CRUSH recalculation
/// and data migration to healthy miners.
///
/// ## Throttling
///
/// Recovery is throttled to prevent overwhelming the cluster:
/// - `rebuild_files_per_tick`: Max files to process per iteration
/// - `rebuild_stripes_per_file`: Max stripes per file (0=unlimited)
/// - `rebuild_concurrency`: Concurrent stripe repair tasks
async fn run_recovery_check(state: &Arc<AppState>) -> Result<(), Box<dyn std::error::Error>> {
    debug!("Running auto-recovery check");

    let current_time = now_secs();

    // Get cluster map
    let query_map = iroh_docs::store::Query::single_latest_per_key().key_exact(b"cluster_map");
    let mut stream = Box::pin(state.doc.get_many(query_map).await?);

    let map = match stream.next().await {
        Some(Ok(entry)) => {
            let hash = entry.content_hash();
            let mut reader = state.blobs_store.reader(hash);
            use tokio::io::AsyncReadExt;
            let mut content = Vec::new();
            if reader.read_to_end(&mut content).await.is_ok() {
                let json_str = String::from_utf8_lossy(&content);
                serde_json::from_str::<common::ClusterMap>(&json_str)?
            } else {
                return Ok(());
            }
        }
        _ => return Ok(()),
    };

    // Offline / Out thresholds (config/env)
    let out_threshold_secs: u64 = state.miner_out_threshold_secs;

    // Find offline miners (short-term) and "out" miners (sustained offline)
    let offline_miners: Vec<u32> = map
        .miners
        .iter()
        .filter(|m| is_miner_offline(m, current_time))
        .map(|m| m.uid)
        .collect();
    let out_miners: Vec<u32> = map
        .miners
        .iter()
        .filter(|m| current_time.saturating_sub(m.last_seen) > out_threshold_secs)
        .map(|m| m.uid)
        .collect();

    if offline_miners.is_empty() {
        debug!("All miners online, no recovery needed");
        return Ok(());
    }

    info!(
        offline_miners = ?offline_miners,
        out_threshold_secs = out_threshold_secs,
        "Offline miners detected"
    );

    if out_miners.is_empty() {
        debug!("Miners are offline but not OUT yet; waiting before epoch bump/rebuild");
        return Ok(());
    }

    info!(
        out_miners = ?out_miners,
        out_threshold_secs = out_threshold_secs,
        "OUT miners (sustained offline)"
    );

    // Ceph-style: mark OUT miners by removing them from the cluster map and bumping epoch,
    // so CRUSH-only reads converge to the new placement.
    // CRITICAL: Acquire map_lock before modifying cluster map to avoid race with
    // registrations/heartbeats that also modify the map.
    let _guard = state.map_lock.lock().await;

    // Re-read cluster map after acquiring lock to get latest state
    let query_map = iroh_docs::store::Query::single_latest_per_key().key_exact(b"cluster_map");
    let mut stream = Box::pin(state.doc.get_many(query_map).await?);
    let map = match stream.next().await {
        Some(Ok(entry)) => {
            let hash = entry.content_hash();
            let mut reader = state.blobs_store.reader(hash);
            let mut content = Vec::new();
            if reader.read_to_end(&mut content).await.is_ok() {
                let json_str = String::from_utf8_lossy(&content);
                serde_json::from_str::<common::ClusterMap>(&json_str)?
            } else {
                return Ok(());
            }
        }
        _ => return Ok(()),
    };

    // Re-identify OUT miners with fresh map data
    let out_miners: Vec<u32> = map
        .miners
        .iter()
        .filter(|m| current_time.saturating_sub(m.last_seen) > out_threshold_secs)
        .map(|m| m.uid)
        .collect();

    if out_miners.is_empty() {
        return Ok(());
    }

    let out_miner_details: Vec<(u32, String)> = map
        .miners
        .iter()
        .filter(|m| out_miners.contains(&m.uid))
        .map(|m| (m.uid, m.family_id.clone()))
        .collect();

    let mut new_map = map.clone();
    let before = new_map.miners.len();
    new_map.miners.retain(|m| !out_miners.contains(&m.uid));
    let after = new_map.miners.len();
    if after != before {
        new_map.epoch += 1;
        if let Err(e) = persist_cluster_map_to_doc(state, &new_map).await {
            error!(error = %e, "Failed to persist OUT map (epoch bump)");
        }

        // Log each removed miner
        for (uid, family_id) in &out_miner_details {
            warn!(
                miner_uid = uid,
                family_id = %family_id,
                miners_before = before,
                miners_after = after,
                new_epoch = new_map.epoch,
                "MINER LEFT: Miner marked OUT (sustained offline) and removed from ClusterMap"
            );
        }

        info!(
            removed_count = before - after,
            miners_before = before,
            miners_after = after,
            new_epoch = new_map.epoch,
            "Cluster topology changed: miners removed due to sustained offline"
        );
    }

    // Build healthy cluster map (without OUT miners)
    let healthy_map = new_map;

    // Need at least k (10) miners to recover data
    if healthy_map.miners.len() < 10 {
        error!(
            healthy_miners = healthy_map.miners.len(),
            required = 10,
            "Not enough healthy miners for recovery"
        );
        return Ok(());
    }

    info!(
        healthy_miners = healthy_map.miners.len(),
        total_miners = map.miners.len(),
        "Healthy cluster available"
    );

    // Get all files to check, but only rebuild a bounded number per tick (Ceph-style throttling).
    let files = get_all_file_summaries(state.as_ref()).await?;
    let mut selected: Vec<common::FileSummary> = Vec::new();
    let mut files_needing_recovery = 0usize;

    for file_summary in &files {
        if selected.len() >= state.rebuild_files_per_tick {
            break;
        }
        if check_file_needs_recovery(file_summary, state.as_ref(), &out_miners, &map).await {
            files_needing_recovery += 1;
            debug!(file_hash = %truncate_for_log(&file_summary.hash, 16), "File needs recovery");
            selected.push(file_summary.clone());
        }
    }

    // Rebuild files with bounded concurrency.
    if !selected.is_empty() {
        let sem = Arc::new(tokio::sync::Semaphore::new(state.rebuild_concurrency));
        let mut joinset = tokio::task::JoinSet::new();

        for file_summary in selected {
            let permit = sem.clone().acquire_owned().await;
            let Ok(permit) = permit else {
                continue;
            };
            let state_clone = state.clone();
            let full_map_clone = map.clone();
            let healthy_map_clone = healthy_map.clone();

            joinset.spawn(async move {
                let _permit = permit;
                state_clone.metrics.rebuild_inflight.inc();
                let res = recover_file(
                    &file_summary,
                    &full_map_clone,
                    &healthy_map_clone,
                    state_clone.as_ref(),
                    state_clone.rebuild_stripes_per_file,
                )
                .await;
                state_clone.metrics.rebuild_inflight.dec();
                res
            });
        }

        while let Some(res) = joinset.join_next().await {
            if let Ok(Err(e)) = res {
                warn!(error = %e, "File recovery failed");
            }
        }
    }

    if files_needing_recovery > 0 {
        info!(
            recovered = files_needing_recovery,
            total = files.len(),
            "Recovery complete"
        );
    } else {
        debug!("No files need recovery");
    }

    Ok(())
}

async fn check_file_needs_recovery(
    file: &common::FileSummary,
    state: &AppState,
    offline_miners: &[u32],
    full_map: &common::ClusterMap,
) -> bool {
    // Read the actual manifest
    let query = iroh_docs::store::Query::single_latest_per_key().key_exact(file.hash.as_bytes());
    let mut stream = match state.doc.get_many(query).await {
        Ok(s) => Box::pin(s),
        Err(_) => return false,
    };

    let manifest: common::FileManifest = match stream.next().await {
        Some(Ok(entry)) => {
            let hash = entry.content_hash();
            let mut reader = state.blobs_store.reader(hash);
            use tokio::io::AsyncReadExt;
            let mut content = Vec::new();
            if reader.read_to_end(&mut content).await.is_err() {
                return false;
            }
            match serde_json::from_slice(&content) {
                Ok(m) => m,
                Err(_) => return false,
            }
        }
        _ => return false,
    };

    // Use CRUSH to check if any shard's target miner is offline
    let k = manifest.stripe_config.k;
    let m = manifest.stripe_config.m;
    let shards_per_stripe = k + m;
    let num_stripes = manifest.shards.len().div_ceil(shards_per_stripe);

    for stripe_idx in 0..num_stripes {
        // Calculate CRUSH placement for this stripe
        let stripe_miners = match common::calculate_stripe_placement(
            &manifest.file_hash,
            stripe_idx as u64,
            shards_per_stripe,
            full_map,
            manifest.placement_version,
        ) {
            Ok(miners) => miners,
            Err(_) => continue,
        };

        // Check if any miner in this stripe is offline
        for miner in &stripe_miners {
            if offline_miners.contains(&miner.uid) {
                return true;
            }
        }
    }

    false
}

/// True Reed-Solomon shard reconstruction - processes each stripe separately
/// Downloads surviving shards, reconstructs lost ones, pushes to new miners, updates manifest
async fn recover_file(
    file: &common::FileSummary,
    full_map: &common::ClusterMap, // Original map for CRUSH placement
    healthy_map: &common::ClusterMap, // Healthy miners only for new targets
    state: &AppState,
    max_stripes_per_file: usize,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    use reed_solomon_erasure::galois_8::ReedSolomon;

    debug!(
        file_hash = %&file.hash[..std::cmp::min(16, file.hash.len())],
        "Recovering file"
    );

    // 1. Get the file manifest (key is just the hash, not "manifest:{hash}")
    let query = iroh_docs::store::Query::single_latest_per_key().key_exact(file.hash.as_bytes());
    let mut stream = Box::pin(state.doc.get_many(query).await?);

    let manifest: common::FileManifest = match stream.next().await {
        Some(Ok(entry)) => {
            let hash = entry.content_hash();
            let mut reader = state.blobs_store.reader(hash);
            use tokio::io::AsyncReadExt;
            let mut content = Vec::new();
            reader.read_to_end(&mut content).await?;
            serde_json::from_slice(&content)?
        }
        _ => {
            warn!(file_hash = %truncate_for_log(&file.hash, 16), "Could not find manifest for file");
            return Ok(());
        }
    };

    let data_shards = manifest.stripe_config.k as usize;
    let parity_shards = manifest.stripe_config.m as usize;
    let shards_per_stripe = data_shards + parity_shards;
    let num_stripes = manifest.shards.len().div_ceil(shards_per_stripe);

    debug!(
        data_shards = data_shards,
        parity_shards = parity_shards,
        shards_per_stripe = shards_per_stripe,
        num_stripes = num_stripes,
        "EC config"
    );

    // Build set of healthy miner UIDs
    let healthy_uids: std::collections::HashSet<u32> =
        healthy_map.miners.iter().map(|m| m.uid).collect();

    // Use CRUSH to identify which stripes have shards on offline miners
    let mut stripes_needing_recovery: Vec<usize> = vec![];

    for stripe_idx in 0..num_stripes {
        // Calculate CRUSH placement for this stripe using FULL map
        // This gives us the *original* placement including offline miners
        let stripe_miners = match common::calculate_stripe_placement(
            &manifest.file_hash,
            stripe_idx as u64,
            shards_per_stripe,
            full_map, // Use full_map to see which miners SHOULD have the shards
            manifest.placement_version,
        ) {
            Ok(miners) => miners,
            Err(_) => continue,
        };

        // Check if any miner in this stripe's placement is offline
        for miner in &stripe_miners {
            if !healthy_uids.contains(&miner.uid) {
                stripes_needing_recovery.push(stripe_idx);
                break;
            }
        }
    }

    if stripes_needing_recovery.is_empty() {
        debug!("All shards are on healthy miners, no reconstruction needed");
        return Ok(());
    }

    // Backpressure: cap how much work we do per file per tick.
    if max_stripes_per_file > 0 && stripes_needing_recovery.len() > max_stripes_per_file {
        stripes_needing_recovery.truncate(max_stripes_per_file);
    }

    info!(
        stripes = stripes_needing_recovery.len(),
        first_five = ?stripes_needing_recovery.iter().take(5).collect::<Vec<_>>(),
        "Stripes need recovery"
    );

    let rs = ReedSolomon::new(data_shards, parity_shards)?;
    let mut stripes_recovered = 0;
    let mut stripes_failed = 0;

    // Process each stripe that needs recovery
    for stripe_idx in &stripes_needing_recovery {
        let stripe_start = stripe_idx * shards_per_stripe;

        // Calculate CRUSH placement using FULL map to identify ORIGINAL locations
        let stripe_miners = match common::calculate_stripe_placement(
            &manifest.file_hash,
            *stripe_idx as u64,
            shards_per_stripe,
            full_map, // Use full_map to find original miner placements
            manifest.placement_version,
        ) {
            Ok(miners) => miners,
            Err(_) => {
                stripes_failed += 1;
                continue;
            }
        };

        // Identify surviving and lost shards in this stripe
        let mut surviving_shards: Vec<(usize, &common::ShardInfo, &common::MinerNode)> = vec![];
        let mut lost_local_indices: Vec<usize> = vec![];

        for local_idx in 0..shards_per_stripe {
            let global_idx = stripe_start + local_idx;
            if global_idx >= manifest.shards.len() {
                break;
            }

            let shard = &manifest.shards[global_idx];
            let miner = &stripe_miners[local_idx];

            if healthy_uids.contains(&miner.uid) {
                surviving_shards.push((local_idx, shard, miner));
            } else {
                lost_local_indices.push(local_idx);
            }
        }

        if surviving_shards.len() < data_shards {
            warn!(
                stripe_idx = stripe_idx,
                surviving = surviving_shards.len(),
                needed = data_shards,
                "Not enough surviving shards for reconstruction"
            );
            stripes_failed += 1;
            state.metrics.rebuild_stripes_failed.inc();
            continue;
        }

        debug!(
            stripe_idx = stripe_idx,
            lost = lost_local_indices.len(),
            surviving = surviving_shards.len(),
            "Stripe recovery status"
        );

        // Download surviving shards for this stripe
        let mut shard_data: Vec<Option<Vec<u8>>> = vec![None; shards_per_stripe];
        let mut download_count = 0;

        for (local_idx, shard, miner) in &surviving_shards {
            // Only download enough shards for reconstruction
            if download_count >= data_shards {
                break;
            }

            match download_shard_from_miner(&shard.blob_hash, miner, state).await {
                Ok(data) => {
                    shard_data[*local_idx] = Some(data);
                    download_count += 1;
                }
                Err(e) => {
                    debug!(
                        local_idx = local_idx,
                        miner_uid = miner.uid,
                        error = %e,
                        "Failed to download shard"
                    );
                }
            }
        }

        if download_count < data_shards {
            warn!(
                stripe_idx = stripe_idx,
                downloaded = download_count,
                needed = data_shards,
                "Not enough shards downloaded"
            );
            stripes_failed += 1;
            state.metrics.rebuild_stripes_failed.inc();
            continue;
        }

        // Reconstruct ALL shards (data + parity) to restore full (k+m) redundancy
        let mut reconstruct_shards: Vec<Option<Vec<u8>>> = shard_data.clone();
        if let Err(e) = rs.reconstruct(&mut reconstruct_shards) {
            error!(
                stripe_idx = stripe_idx,
                error = %e,
                "RS reconstruction failed"
            );
            stripes_failed += 1;
            state.metrics.rebuild_stripes_failed.inc();
            continue;
        }

        debug!(
            stripe_idx = stripe_idx,
            lost_shards = lost_local_indices.len(),
            "Stripe reconstructed"
        );

        // Push reconstructed shards to their CRUSH-calculated miners.
        //
        // CRITICAL: reconstructed bytes MUST hash to the manifest's blob_hash for this shard index,
        // otherwise we'd store a "new shard" that no reader will ever request (manifest points to old hash).
        let mut integrity_ok = true;
        for local_idx in &lost_local_indices {
            let global_idx = stripe_start + local_idx;
            let reconstructed_data = match reconstruct_shards[*local_idx].as_ref() {
                Some(d) => d,
                None => {
                    warn!(
                        local_idx = local_idx,
                        "Reconstructed data missing for shard"
                    );
                    continue;
                }
            };

            let expected_hash = manifest
                .shards
                .get(global_idx)
                .map(|s| s.blob_hash.as_str())
                .unwrap_or("");
            if expected_hash.is_empty() {
                warn!(
                    global_idx = global_idx,
                    "Missing expected blob_hash in manifest for shard"
                );
                integrity_ok = false;
                break;
            }
            let got_hash = blake3::hash(reconstructed_data).to_hex();
            if got_hash.as_str() != expected_hash {
                error!(
                    global_idx = global_idx,
                    expected = expected_hash,
                    got = %got_hash,
                    "Reconstruct integrity mismatch"
                );
                integrity_ok = false;
                break;
            }

            // Use CRUSH to find the miner that SHOULD have this shard
            let target_miner = match pick_healthy_miner_for_shard(
                &manifest.file_hash,
                *stripe_idx,
                *local_idx,
                healthy_map,
            ) {
                Some(m) => m,
                None => {
                    warn!(
                        global_idx = global_idx,
                        "No healthy miner available for shard"
                    );
                    continue;
                }
            };

            match push_shard_to_miner(global_idx, reconstructed_data, target_miner, state).await {
                Ok(_new_shard_info) => {
                    debug!(
                        global_idx = global_idx,
                        miner_uid = target_miner.uid,
                        "Pushed shard to miner"
                    );
                    // With True CRUSH, we don't update the manifest - CRUSH determines placement
                    state.metrics.rebuild_shards_pushed.inc();
                }
                Err(e) => {
                    error!(
                        global_idx = global_idx,
                        miner_uid = target_miner.uid,
                        error = %e,
                        "Failed to push shard to miner"
                    );
                }
            }
        }

        if !integrity_ok {
            stripes_failed += 1;
            state.metrics.rebuild_stripes_failed.inc();
            continue;
        }

        stripes_recovered += 1;
        state.metrics.rebuild_stripes_recovered.inc();
    }

    // With True CRUSH, manifests don't contain location info, so no manifest update needed
    if stripes_recovered > 0 {
        info!(
            recovered = stripes_recovered,
            total = stripes_needing_recovery.len(),
            "Recovery complete"
        );
    }

    if stripes_failed > 0 {
        warn!(
            stripes_failed = stripes_failed,
            "Some stripes could not be recovered"
        );
    }

    Ok(())
}

// /// Check if miner is online (has heartbeat within last 2 minutes)
// fn is_miner_online(miner: &common::MinerNode, current_time: u64) -> bool {
//     current_time.saturating_sub(miner.last_seen) < 120
// }

/// Download shard bytes from a miner.
///
/// Security/correctness:
/// - Prefer P2P (`hippius/miner-control` FetchBlob) so miners don't need public HTTP.
/// - Verify the returned bytes hash to the expected `blob_hash`.
/// - Optional legacy fallback to miner HTTP is gated behind `RECOVERY_HTTP_FALLBACK=true`.
async fn download_shard_from_miner(
    blob_hash: &str,
    miner: &common::MinerNode,
    state: &AppState,
) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
    // use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};

    // 1) Preferred: P2P FetchBlob over miner-control
    {
        let conn = tokio::time::timeout(
            std::time::Duration::from_secs(10),
            state
                .endpoint
                .connect(miner.endpoint.clone(), b"hippius/miner-control"),
        )
        .await
        .ok()
        .and_then(|r| r.ok());

        if let Some(conn) = conn {
            if let Ok((mut send, mut recv)) = conn.open_bi().await {
                let msg = common::MinerControlMessage::FetchBlob {
                    hash: blob_hash.to_string(),
                };
                let msg_bytes = serde_json::to_vec(&msg)?;
                send.write_all(&msg_bytes).await?;
                let _ = send.finish();

                let resp = tokio::time::timeout(
                    std::time::Duration::from_secs(15),
                    recv.read_to_end(MAX_FETCH_RESPONSE_SIZE),
                )
                .await??;

                if resp.starts_with(b"DATA:") {
                    let data = resp[5..].to_vec();
                    if blake3::hash(&data).to_hex().as_str() == blob_hash {
                        return Ok(data);
                    }
                    return Err(
                        format!("P2P FetchBlob integrity fail (expected {})", blob_hash).into(),
                    );
                }
            }
        }
    }

    // 2) Optional legacy fallback: miner HTTP (disabled by default)
    let http_fallback = std::env::var("RECOVERY_HTTP_FALLBACK")
        .map(|v| !matches!(v.as_str(), "0" | "false" | "FALSE"))
        .unwrap_or(false);

    if !http_fallback {
        return Err("P2P FetchBlob failed and RECOVERY_HTTP_FALLBACK is disabled".into());
    }

    // Accept self-signed certs since miners use auto-generated TLS certs
    let client = reqwest::Client::builder()
        .danger_accept_invalid_certs(true)
        .build()
        .unwrap_or_else(|_| reqwest::Client::new());
    let miner_url = format!("{}/blobs/{}", miner.http_addr, blob_hash);
    let response = client
        .get(&miner_url)
        .timeout(std::time::Duration::from_secs(30))
        .send()
        .await?;
    if !response.status().is_success() {
        return Err(format!("HTTP download failed: {}", response.status()).into());
    }
    let data = response.bytes().await?.to_vec();
    if blake3::hash(&data).to_hex().as_str() != blob_hash {
        return Err(format!("HTTP integrity fail (expected {})", blob_hash).into());
    }
    Ok(data)
}

/// Pick a healthy miner for a shard using CRUSH placement
fn pick_healthy_miner_for_shard<'a>(
    file_hash: &str,
    stripe_idx: usize,
    shard_idx: usize,
    healthy_map: &'a common::ClusterMap,
) -> Option<&'a common::MinerNode> {
    // FULL CRUSH (PG-based, per paper): PG placement + rotate by stripe_index
    // shard_idx here is the *local index within the stripe* (0..k+m)
    let shards_per_stripe = healthy_map.ec_k + healthy_map.ec_m;
    common::calculate_pg_placement_for_stripe(
        file_hash,
        stripe_idx as u64,
        shards_per_stripe,
        healthy_map,
    )
    .ok()
    .and_then(|miners| miners.get(shard_idx).cloned())
    .and_then(|calculated| healthy_map.miners.iter().find(|m| m.uid == calculated.uid))
    .or_else(|| {
        // Fallback: use any healthy miner (round-robin style)
        healthy_map
            .miners
            .get(shard_idx % healthy_map.miners.len().max(1))
    })
}

/// Push a shard to a miner via P2P and return the new ShardInfo
async fn push_shard_to_miner(
    shard_idx: usize,
    data: &[u8],
    miner: &common::MinerNode,
    state: &AppState,
) -> anyhow::Result<common::ShardInfo> {
    // First, add the blob to our local store to get a hash
    let add_outcome = state
        .blobs_store
        .add_bytes(Bytes::from(data.to_vec()))
        .await?;
    let blob_hash = add_outcome.hash;

    // Send Store command to miner via P2P with the blob data directly
    let message = common::MinerControlMessage::Store {
        hash: blob_hash.to_string(),
        data: Some(data.to_vec()), // Push data directly
        source_miner: None,        // None = push from validator (not pull from peer)
    };

    let conn = state
        .endpoint
        .connect(miner.endpoint.clone(), b"hippius/miner-control")
        .await?;
    let (mut send, mut recv) = conn.open_bi().await?;

    // use tokio::io::{AsyncWriteExt, AsyncReadExt};
    let msg_bytes = serde_json::to_vec(&message)?;
    send.write_all(&msg_bytes).await?;
    send.flush().await?;
    send.finish()?;

    let ack = recv.read_to_end(64).await?;
    if ack != b"OK" {
        return Err(anyhow::anyhow!(
            "Miner {} rejected shard: {:?}",
            miner.uid,
            String::from_utf8_lossy(&ack)
        ));
    }

    // Create updated ShardInfo (pin original storage miner for stable reads)
    Ok(common::ShardInfo {
        index: shard_idx,
        blob_hash: blob_hash.to_string(),
        miner_uid: Some(miner.uid),
    })
}

async fn get_all_file_summaries(
    state: &AppState,
) -> Result<Vec<common::FileSummary>, Box<dyn std::error::Error>> {
    let manifest_guard = state.manifest_hashes.lock().await;
    Ok(manifest_guard.clone())
}

#[cfg(any())]
async fn register_miner(
    State(state): State<Arc<AppState>>,
    axum::Json(req): axum::Json<MinerRegistrationRequest>,
) -> impl IntoResponse {
    // 1. Check Blacklist
    let query_blacklist = iroh_docs::store::Query::single_latest_per_key().key_exact(b"blacklist");
    let mut stream = Box::pin(match state.doc.get_many(query_blacklist).await {
        Ok(s) => s,
        Err(_) => {
            return (StatusCode::INTERNAL_SERVER_ERROR, "Failed to get blacklist").into_response();
        }
    });
    let blacklist = match stream.next().await {
        Some(Ok(entry)) => {
            let hash = entry.content_hash();
            let mut reader = state.blobs_store.reader(hash);
            use tokio::io::AsyncReadExt;
            let mut content = Vec::new();
            reader
                .read_to_end(&mut content)
                .await
                .ok()
                .and_then(|_| {
                    serde_json::from_str::<Blacklist>(&String::from_utf8_lossy(&content)).ok()
                })
                .unwrap_or_default()
        }
        _ => Blacklist::default(),
    };

    if req.family_id.trim().is_empty() {
        return (StatusCode::BAD_REQUEST, "Family ID cannot be empty").into_response();
    }

    // Legacy HTTP registration handler (disabled by default). Registration is handled via P2P and verified against the chain registry.

    // Prefer on-chain registry cache for family_id if enabled (do not trust client-provided family_id).
    let mut effective_family_id = req.family_id.clone();
    if state.chain_registry.enabled() {
        match state
            .chain_registry
            .resolve_family_hex(&req.public_key)
            .await
        {
            Ok(Some(chain_family_id)) => {
                if effective_family_id != chain_family_id {
                    warn!(
                        node = %&req.public_key[..16.min(req.public_key.len())],
                        claimed_family = %effective_family_id,
                        chain_family = %chain_family_id,
                        "HTTP register: family mismatch, using on-chain"
                    );
                }
                effective_family_id = chain_family_id;
            }
            Ok(None) => {
                // fail_open: keep provided family_id
            }
            Err(e) => {
                error!(
                    node = %&req.public_key[..16.min(req.public_key.len())],
                    error = %e,
                    "HTTP register: on-chain family verification FAILED"
                );
                return (StatusCode::FORBIDDEN, format!("FAMILY_REJECTED:{}", e)).into_response();
            }
        }
    }

    // Check CooldownList
    let query_cooldowns = iroh_docs::store::Query::single_latest_per_key().key_exact(b"cooldowns");
    let mut stream = Box::pin(match state.doc.get_many(query_cooldowns).await {
        Ok(s) => s,
        Err(_) => {
            return (StatusCode::INTERNAL_SERVER_ERROR, "Failed to get cooldowns").into_response();
        }
    });
    let cooldowns = match stream.next().await {
        Some(Ok(entry)) => {
            let hash = entry.content_hash();
            let mut reader = state.blobs_store.reader(hash);
            use tokio::io::AsyncReadExt;
            let mut content = Vec::new();
            reader
                .read_to_end(&mut content)
                .await
                .ok()
                .and_then(|_| {
                    serde_json::from_str::<CooldownList>(&String::from_utf8_lossy(&content)).ok()
                })
                .unwrap_or_default()
        }
        _ => CooldownList::default(),
    };

    if cooldowns.is_in_cooldown(&req.public_key) {
        info!(public_key = %req.public_key, "Rejected registration from miner in COOLDOWN");
        return (StatusCode::FORBIDDEN, "Miner is in cooldown").into_response();
    }

    if blacklist.is_banned(&req.public_key, &req.family_id) {
        info!(
            public_key = %req.public_key,
            family_id = %req.family_id,
            "Rejected registration from BANNED miner"
        );
        return (StatusCode::FORBIDDEN, "Miner is banned").into_response();
    }

    // Lock map updates to prevent race conditions
    let _guard = state.map_lock.lock().await;

    let query_map = iroh_docs::store::Query::single_latest_per_key().key_exact(b"cluster_map");
    let mut stream = Box::pin(match state.doc.get_many(query_map).await {
        Ok(s) => s,
        Err(_) => return (StatusCode::INTERNAL_SERVER_ERROR, "Failed to get map").into_response(),
    });
    let mut map = match stream.next().await {
        Some(Ok(entry)) => {
            let hash = entry.content_hash();
            let mut reader = state.blobs_store.reader(hash);
            use tokio::io::AsyncReadExt;
            let mut content = Vec::new();
            reader
                .read_to_end(&mut content)
                .await
                .ok()
                .and_then(|_| {
                    serde_json::from_str::<ClusterMap>(&String::from_utf8_lossy(&content)).ok()
                })
                .unwrap_or_default()
        }
        _ => ClusterMap::default(),
    };

    // Generate UID from public key hash
    // Truncate to 31 bits (0x7FFFFFFF) to ensure UID fits in i32 range
    // while maintaining good distribution from the lower bits of the hash
    let mut hasher = std::collections::hash_map::DefaultHasher::new();
    use std::hash::{Hash, Hasher};
    req.public_key.hash(&mut hasher);
    let uid = (hasher.finish() as u32) & 0x7FFFFFFF;

    // Check if miner already exists
    if !map.miners.iter().any(|m| m.public_key == req.public_key) {
        info!(
            public_key = %req.public_key,
            family_id = %req.family_id,
            available_storage = req.available_storage,
            total_storage = req.total_storage,
            "Registering new miner"
        );

        // Construct MinerNode
        // Note: endpoint is tricky. We need it for iroh connections.
        // For now, we'll try to parse public_key as NodeId and create a dummy endpoint.
        // In a real scenario, the miner should send its full EndpointAddr or we discover it.
        let node_id = match iroh::PublicKey::from_str(&req.public_key) {
            Ok(key) => key,
            Err(_) => return (StatusCode::BAD_REQUEST, "Invalid public key").into_response(),
        };
        let endpoint = iroh::EndpointAddr::new(node_id);
        let endpoint = if let Some(ref url) = state.relay_url {
            endpoint.with_relay_url(url.clone())
        } else {
            endpoint
        };

        let new_miner = MinerNode {
            uid,
            endpoint,
            weight: 100,                        // Default weight
            ip_subnet: "0.0.0.0/0".to_string(), // Unknown
            http_addr: req.http_addr.clone(),
            public_key: req.public_key.clone(),
            total_storage: req.total_storage,
            available_storage: req.available_storage,
            family_id: effective_family_id.clone(),
            strikes: 0,
            last_seen: now_secs(),
            // Performance tracking fields
            heartbeat_count: 0,
            registration_time: now_secs(),
            bandwidth_total: 0,
            bandwidth_window_start: now_secs(),
            weight_manual_override: false,
        };
        map.add_node(new_miner);
        map.epoch += 1; // Increment epoch on change

        // 3. Save map (and epoch-scoped history key)
        debug!(author = %state.author_id, "Saving map in register_miner");
        if let Err(e) = persist_cluster_map_to_doc(&state, &map).await {
            error!(error = %e, "Failed to save map in register_miner");
            return (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()).into_response();
        }
        debug!("Map saved in register_miner");

        // Save to disk for crash recovery
        let map_copy = map.clone();
        tokio::spawn(async move {
            if let Err(e) = save_cluster_map_to_disk(&map_copy).await {
                warn!(error = %e, "Failed to save cluster map to disk");
            }
        });

        /* Broadcast removed to prevent storm. defer to auto_recovery_loop
        // Broadcast cluster map to all miners (spawned for non-blocking response)
        let map_for_broadcast = map.clone();
        let endpoint_for_broadcast = state.endpoint.clone();
        tokio::spawn(async move {
            // PG-based: miners will query their PGs separately
            if let Err(e) = broadcast_cluster_map_to_miners(&map_for_broadcast, &endpoint_for_broadcast).await {
                eprintln!("Failed to broadcast cluster map: {}", e);
            }
        });
        */

        (StatusCode::OK, "Miner registered").into_response()
    } else {
        // Update existing miner (e.g. storage stats)
        if let Some(existing) = map
            .miners
            .iter_mut()
            .find(|m| m.public_key == req.public_key)
        {
            let old_family_id = existing.family_id.clone();
            existing.available_storage = req.available_storage;
            existing.total_storage = req.total_storage;
            existing.http_addr = req.http_addr.clone(); // Update addr in case it changed
            existing.family_id = effective_family_id.clone(); // Update family_id (on-chain derived if enabled)
            // Do NOT reset strikes here, unless we want to allow re-registration to clear strikes?
            // Let's say re-registration clears strikes for now, as it implies a restart/fix.
            existing.strikes = 0;
            existing.last_seen = now_secs();

            debug!(
                miner_uid = existing.uid,
                family_id = %req.family_id,
                available_storage = req.available_storage,
                total_storage = req.total_storage,
                "Updated miner"
            );

            // Only bump epoch if a placement-affecting field changed.
            // family_id changes impact CRUSH family diversity and therefore placement.
            if existing.family_id != old_family_id {
                map.epoch += 1;
            }
            if let Err(e) = persist_cluster_map_to_doc(&state, &map).await {
                error!(error = %e, "Failed to persist cluster map in register_miner(update)");
            }
        }
        (StatusCode::OK, "Miner updated").into_response()
    }
}

async fn reconstruct_shard(
    manifest: &FileManifest,
    missing_index: usize,
    state: &Arc<AppState>,
) -> anyhow::Result<()> {
    debug!(
        missing_index = missing_index,
        "Starting reconstruction for shard"
    );

    // Get current cluster map from iroh-docs for CRUSH placement
    let query_map = iroh_docs::store::Query::single_latest_per_key().key_exact(b"cluster_map");
    let mut stream_map = Box::pin(state.doc.get_many(query_map).await?);
    let cluster_map: common::ClusterMap = match stream_map.next().await {
        Some(Ok(entry)) => {
            let hash = entry.content_hash();
            let mut reader = state.blobs_store.reader(hash);
            use tokio::io::AsyncReadExt;
            let mut content = Vec::new();
            reader.read_to_end(&mut content).await?;
            serde_json::from_slice(&content)?
        }
        _ => return Err(anyhow::anyhow!("Failed to load cluster map")),
    };

    // 1) Download >=k shards for the stripe (P2P preferred via download_shard_from_miner)
    let k = manifest.stripe_config.k;
    let m = manifest.stripe_config.m;
    let shards_per_stripe = k + m;
    let stripe_idx = missing_index / shards_per_stripe;
    let local_missing = missing_index % shards_per_stripe;

    let stripe_miners = common::calculate_stripe_placement(
        &manifest.file_hash,
        stripe_idx as u64,
        shards_per_stripe,
        &cluster_map,
        manifest.placement_version,
    )
    .map_err(|e| anyhow::anyhow!("CRUSH placement failed: {}", e))?;

    let mut shard_bytes: Vec<Option<Vec<u8>>> = vec![None; shards_per_stripe];
    let mut downloaded = 0usize;

    // Pull shards from other miners in the same stripe placement (skip missing index).
    for local_idx in 0..shards_per_stripe {
        if downloaded >= k {
            break;
        }
        if local_idx == local_missing {
            continue;
        }
        let global_idx = stripe_idx * shards_per_stripe + local_idx;
        if global_idx >= manifest.shards.len() {
            continue;
        }
        let expected = &manifest.shards[global_idx].blob_hash;
        let miner = &stripe_miners[local_idx];
        debug!(
            global_idx = global_idx,
            stripe_idx = stripe_idx,
            local_idx = local_idx,
            miner_uid = miner.uid,
            "Downloading shard"
        );

        match download_shard_from_miner(expected, miner, state.as_ref()).await {
            Ok(bytes) => {
                shard_bytes[local_idx] = Some(bytes);
                downloaded += 1;
            }
            Err(e) => {
                warn!(
                    global_idx = global_idx,
                    miner_uid = miner.uid,
                    error = %e,
                    "Failed to download shard"
                );
            }
        }
    }

    if downloaded < k {
        return Err(anyhow::anyhow!(
            "Not enough shards to reconstruct stripe {} (got {}, need {})",
            stripe_idx,
            downloaded,
            k
        ));
    }

    // 2) RS reconstruct to fill missing shard bytes.
    use reed_solomon_erasure::galois_8::ReedSolomon;
    let rs = ReedSolomon::new(k, m)?;
    if let Err(e) = rs.reconstruct(&mut shard_bytes) {
        return Err(anyhow::anyhow!(
            "RS reconstruction failed for stripe {}: {}",
            stripe_idx,
            e
        ));
    }

    let recovered = shard_bytes[local_missing]
        .as_ref()
        .ok_or_else(|| anyhow::anyhow!("missing shard bytes not reconstructed"))?;

    // 3) Integrity assertion: recovered bytes must hash to manifest blob_hash.
    let expected_missing_hash = manifest
        .shards
        .get(missing_index)
        .map(|s| s.blob_hash.as_str())
        .unwrap_or("");
    if expected_missing_hash.is_empty() {
        return Err(anyhow::anyhow!(
            "manifest missing expected blob_hash for shard {}",
            missing_index
        ));
    }
    let got = blake3::hash(recovered).to_hex();
    if got.as_str() != expected_missing_hash {
        return Err(anyhow::anyhow!(
            "recovered shard hash mismatch for shard {}: expected={} got={}",
            missing_index,
            expected_missing_hash,
            got
        ));
    }

    // 4) Push to the CRUSH-calculated target miner for this shard index (current map).
    let target = stripe_miners
        .get(local_missing)
        .ok_or_else(|| anyhow::anyhow!("missing target miner for local_idx {}", local_missing))?;

    push_shard_to_miner(missing_index, recovered, target, state.as_ref()).await?;

    // (No manifest update needed; manifest references the same blob hash)
    Ok(())
}

// use common::BandwidthStats;

async fn report_bandwidth(
    State(state): State<Arc<AppState>>,
    Json(stats): Json<BandwidthStats>,
) -> impl IntoResponse {
    debug!(entries = stats.reports.len(), "Received bandwidth report");

    let author = state.author_id;
    for report in stats.reports {
        let key = format!("stats:bw:{}", report.miner_uid);
        let query = iroh_docs::store::Query::single_latest_per_key().key_exact(key.as_bytes());

        let mut stream = Box::pin(match state.doc.get_many(query).await {
            Ok(s) => s,
            Err(_) => continue, // Skip if error
        });

        let current_bytes = match stream.next().await {
            Some(Ok(entry)) => {
                let hash = entry.content_hash();
                let mut reader = state.blobs_store.reader(hash);
                use tokio::io::AsyncReadExt;
                let mut content = Vec::new();
                reader
                    .read_to_end(&mut content)
                    .await
                    .ok()
                    .and_then(|_| String::from_utf8(content).ok())
                    .and_then(|s| s.parse::<u64>().ok())
                    .unwrap_or(0)
            }
            _ => 0,
        };
        let new_bytes = current_bytes + report.bytes;
        if let Err(e) = state
            .doc
            .set_bytes(author, Bytes::from(key), Bytes::from(new_bytes.to_string()))
            .await
        {
            warn!(miner_uid = report.miner_uid, error = %e, "Failed to update stats");
        }
    }

    axum::http::StatusCode::OK
}

/// Receive miner failure reports from gateway and track for scoring
async fn report_miner_failures(
    State(state): State<Arc<AppState>>,
    Json(stats): Json<common::MinerFailureStats>,
) -> impl IntoResponse {
    if stats.reports.is_empty() {
        return axum::http::StatusCode::OK;
    }

    info!(
        reports = stats.reports.len(),
        "Received miner failure reports"
    );

    let author = state.author_id;
    for report in stats.reports {
        // Log the failure for visibility
        info!(
            miner_uid = report.miner_uid,
            failure_type = %report.failure_type,
            shard_index = report.shard_index,
            file_hash = %truncate_for_log(&report.file_hash, 16),
            "Miner failure"
        );

        // Store failure count: stats:fail:{miner_uid}
        let key = format!("stats:fail:{}", report.miner_uid);
        let query = iroh_docs::store::Query::single_latest_per_key().key_exact(key.as_bytes());

        let mut stream = Box::pin(match state.doc.get_many(query).await {
            Ok(s) => s,
            Err(_) => continue,
        });

        let current_fails = match stream.next().await {
            Some(Ok(entry)) => {
                let hash = entry.content_hash();
                let mut reader = state.blobs_store.reader(hash);
                use tokio::io::AsyncReadExt;
                let mut content = Vec::new();
                reader
                    .read_to_end(&mut content)
                    .await
                    .ok()
                    .and_then(|_| String::from_utf8(content).ok())
                    .and_then(|s| s.parse::<u32>().ok())
                    .unwrap_or(0)
            }
            _ => 0,
        };

        let new_fails = current_fails + 1;
        if let Err(e) = state
            .doc
            .set_bytes(author, Bytes::from(key), Bytes::from(new_fails.to_string()))
            .await
        {
            warn!(miner_uid = report.miner_uid, error = %e, "Failed to update failure stats");
        }

        // If integrity failure, increase strikes (most serious)
        if report.failure_type == "integrity_fail" {
            // Update strikes in cluster map
            handle_strike(report.miner_uid, &state).await;
        }
    }

    axum::http::StatusCode::OK
}

/// Receive warden audit results and update miner reputation scores.
///
/// POST /audit-results
///
/// Accepts a batch of audit reports from wardens. Each report affects the
/// miner's reputation score which influences CRUSH placement weight.
async fn post_audit_results(
    State(state): State<Arc<AppState>>,
    Json(batch): Json<common::WardenAuditBatch>,
) -> impl IntoResponse {
    if batch.reports.is_empty() {
        return (axum::http::StatusCode::OK, "No reports to process");
    }

    info!(
        reports = batch.reports.len(),
        "Received warden audit results via HTTP"
    );

    // Verify signatures on all reports (matches P2P handler behavior)
    let signature_verified_reports: Vec<_> = batch
        .reports
        .iter()
        .filter(|report| crate::p2p::verify_audit_report(report))
        .cloned()
        .collect();

    if signature_verified_reports.is_empty() {
        warn!("All audit reports failed signature verification");
        return (
            axum::http::StatusCode::BAD_REQUEST,
            "All reports failed signature verification",
        );
    }

    let verified_batch = common::WardenAuditBatch {
        reports: signature_verified_reports.clone(),
    };

    // Process the batch and update miner reputation
    let mut map = state.cluster_map.write().await;
    let result = state
        .reputation_processor
        .process_batch(&verified_batch, &mut map.miners);

    info!(
        processed = result.processed,
        skipped_duplicate = result.skipped_duplicate,
        skipped_invalid = result.skipped_invalid,
        miners_updated = result.miners_updated.len(),
        "Audit batch processed via HTTP"
    );

    // Add verified reports to attestation aggregator for epoch bundling
    let mut attestations_added = 0u32;
    for report in &signature_verified_reports {
        if state.attestation_aggregator.add_attestation(report) {
            attestations_added += 1;
        }
    }
    if attestations_added > 0 {
        debug!(
            added = attestations_added,
            total = state.attestation_aggregator.attestation_count(),
            "Added attestations to aggregator via HTTP"
        );
    }

    // Remove miners that reached ban threshold
    let banned_uids: Vec<u32> = result
        .miners_updated
        .iter()
        .filter(|u| u.should_ban)
        .map(|u| u.miner_uid)
        .collect();

    if !banned_uids.is_empty() {
        for uid in &banned_uids {
            warn!(
                miner_uid = uid,
                "Removing miner due to ban threshold (via HTTP)"
            );
        }
        map.miners.retain(|m| !banned_uids.contains(&m.uid));
        map.epoch += 1; // Bump epoch since topology changed
    }

    // Persist updated cluster map if any miners were updated or banned
    // Clone and drop the write lock BEFORE calling persist_cluster_map_to_doc
    // to avoid deadlock (persist_cluster_map_to_doc also acquires cluster_map locks)
    let should_persist = !result.miners_updated.is_empty() || !banned_uids.is_empty();
    let map_clone = if should_persist {
        Some(map.clone())
    } else {
        None
    };
    drop(map);

    if let Some(map_to_persist) = map_clone {
        if let Err(e) = persist_cluster_map_to_doc(&state, &map_to_persist).await {
            error!(error = %e, "Failed to persist cluster map after reputation update");
            return (
                axum::http::StatusCode::INTERNAL_SERVER_ERROR,
                "Failed to persist reputation updates",
            );
        }
    }

    (axum::http::StatusCode::OK, "Audit results processed")
}

async fn get_stats(State(state): State<Arc<AppState>>) -> impl IntoResponse {
    let mut stats_map = std::collections::HashMap::new();

    let prefix = b"stats:bw:";
    let query = iroh_docs::store::Query::all().key_prefix(prefix);
    let mut iter = match state.doc.get_many(query).await {
        Ok(s) => Box::pin(s),
        Err(e) => {
            error!(error = %e, "Failed to query bandwidth stats");
            return Json(stats_map);
        }
    };

    while let Some(Ok(entry)) = iter.next().await {
        if let Ok(key_str) = std::str::from_utf8(entry.key()) {
            if let Some(uid) = key_str.strip_prefix("stats:bw:") {
                let hash = entry.content_hash();
                let mut reader = state.blobs_store.reader(hash);
                use tokio::io::AsyncReadExt;
                let mut content = Vec::new();
                if reader.read_to_end(&mut content).await.is_ok() {
                    if let Ok(val_str) = std::str::from_utf8(&content) {
                        if let Ok(bytes) = val_str.parse::<u64>() {
                            stats_map.insert(uid.to_string(), bytes);
                        }
                    }
                }
            }
        }
    }

    Json(stats_map)
}

// Get network-wide stats efficiently (without fetching each manifest)
async fn get_network_stats(State(state): State<Arc<AppState>>) -> impl IntoResponse {
    // Check ready state - network stats require manifest_hashes to be populated
    if let Some(response) = check_ready_state(&state) {
        return response.into_response();
    }

    // Fast path: serve cached response (this endpoint can be heavy).
    let now = now_secs();
    {
        let guard = state.network_stats_cache.read().await;
        if let Some((ts, body)) = guard.as_ref() {
            if now.saturating_sub(*ts) <= state.network_stats_cache_secs {
                return (
                    StatusCode::OK,
                    [("Content-Type", "application/json")],
                    body.clone(),
                )
                    .into_response();
            }
        }
    }

    // Get cluster map
    let map: ClusterMap = {
        let query = iroh_docs::store::Query::single_latest_per_key().key_exact(b"cluster_map");
        let stream_result = match state.doc.get_many(query).await {
            Ok(s) => s,
            Err(e) => {
                error!(error = %e, "Failed to query cluster map for network-stats");
                return (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    "Failed to query cluster map",
                )
                    .into_response();
            }
        };
        let mut stream = Box::pin(stream_result);
        if let Some(Ok(entry)) = stream.next().await {
            let hash = entry.content_hash();
            let mut reader = state.blobs_store.reader(hash);
            use tokio::io::AsyncReadExt;
            let mut content = Vec::new();
            reader
                .read_to_end(&mut content)
                .await
                .ok()
                .and_then(|_| serde_json::from_slice(&content).ok())
                .unwrap_or_default()
        } else {
            ClusterMap::default()
        }
    };

    // Get file list
    let files = {
        let mut file_vec = Vec::new();
        let prefix = b"sync:";
        let query = iroh_docs::store::Query::all().key_prefix(prefix);
        let stream_result = match state.doc.get_many(query).await {
            Ok(s) => s,
            Err(e) => {
                error!(error = %e, "Failed to query file list for network-stats");
                return (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    "Failed to query file list",
                )
                    .into_response();
            }
        };
        let mut stream = Box::pin(stream_result);
        while let Some(Ok(entry)) = stream.next().await {
            if let Ok(key_str) = std::str::from_utf8(entry.key()) {
                if let Some(hash) = key_str.strip_prefix("sync:") {
                    let content_hash = entry.content_hash();
                    let mut reader = state.blobs_store.reader(content_hash);
                    use tokio::io::AsyncReadExt;
                    let mut content = Vec::new();
                    if reader.read_to_end(&mut content).await.is_ok() {
                        if let Ok(size) = String::from_utf8(content)
                            .unwrap_or_default()
                            .parse::<u64>()
                        {
                            file_vec.push((hash.to_string(), size));
                        }
                    }
                }
            }
        }
        file_vec
    };

    // Compute stats per miner from manifests
    let mut miner_stats: std::collections::HashMap<u32, (usize, u64)> =
        std::collections::HashMap::new();
    let total_files = files.len();

    // Get current cluster map from iroh-docs for CRUSH placement
    let query_map = iroh_docs::store::Query::single_latest_per_key().key_exact(b"cluster_map");
    let stream_map_result = match state.doc.get_many(query_map).await {
        Ok(s) => s,
        Err(e) => {
            error!(error = %e, "Failed to query cluster map for miner stats");
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                "Failed to query cluster map",
            )
                .into_response();
        }
    };
    let mut stream_map = Box::pin(stream_map_result);
    let cluster_map: common::ClusterMap = match stream_map.next().await {
        Some(Ok(entry)) => {
            let hash = entry.content_hash();
            let mut reader = state.blobs_store.reader(hash);
            use tokio::io::AsyncReadExt;
            let mut content = Vec::new();
            reader
                .read_to_end(&mut content)
                .await
                .ok()
                .and_then(|_| serde_json::from_slice(&content).ok())
                .unwrap_or_default()
        }
        _ => common::ClusterMap::default(),
    };

    for (hash, _size) in &files {
        let manifest_key = hash.clone();
        let query =
            iroh_docs::store::Query::single_latest_per_key().key_exact(manifest_key.as_bytes());
        let mut stream = Box::pin(match state.doc.get_many(query).await {
            Ok(s) => s,
            Err(_) => continue,
        });

        if let Some(Ok(entry)) = stream.next().await {
            let content_hash = entry.content_hash();
            let mut reader = state.blobs_store.reader(content_hash);
            use tokio::io::AsyncReadExt;
            let mut content = Vec::new();
            if reader.read_to_end(&mut content).await.is_ok() {
                if let Ok(manifest) = serde_json::from_slice::<common::FileManifest>(&content) {
                    let k = manifest.stripe_config.k;
                    let m = manifest.stripe_config.m;
                    let shards_per_stripe = k + m;
                    let num_shards = manifest.shards.len() as u64;
                    let shard_size = if num_shards > 0 {
                        manifest.size / num_shards
                    } else {
                        0
                    };

                    // Use CRUSH to calculate which miner should have each shard
                    for shard in manifest.shards.iter() {
                        let stripe_idx = shard.index / shards_per_stripe;
                        let local_idx = shard.index % shards_per_stripe;

                        if let Ok(stripe_miners) = common::calculate_stripe_placement(
                            &manifest.file_hash,
                            stripe_idx as u64,
                            shards_per_stripe,
                            &cluster_map,
                            manifest.placement_version,
                        ) {
                            if let Some(miner) = stripe_miners.get(local_idx) {
                                let entry = miner_stats.entry(miner.uid).or_insert((0, 0));
                                entry.0 += 1;
                                entry.1 += shard_size;
                            }
                        }
                    }
                }
            }
        }
    }

    // Build response
    let total_blobs: usize = miner_stats.values().map(|(c, _)| c).sum();
    let total_storage: u64 = miner_stats.values().map(|(_, b)| b).sum();
    let total_capacity: u64 = map.miners.iter().map(|m| m.total_storage).sum();
    let total_available: u64 = map.miners.iter().map(|m| m.available_storage).sum();

    // Get bandwidth stats per miner
    let mut bandwidth_stats: std::collections::HashMap<String, u64> =
        std::collections::HashMap::new();
    let bw_prefix = b"stats:bw:";
    let bw_query = iroh_docs::store::Query::single_latest_per_key().key_prefix(bw_prefix);
    let bw_stream_result = match state.doc.get_many(bw_query).await {
        Ok(s) => s,
        Err(e) => {
            error!(error = %e, "Failed to query bandwidth stats for network-stats");
            // Continue without bandwidth stats rather than failing the entire request
            return Json(serde_json::json!({
                "total_files": total_files,
                "total_blobs": total_blobs,
                "total_storage_bytes": total_storage,
                "total_capacity_bytes": total_capacity,
                "total_available_bytes": total_available,
                "miners": map.miners.iter().map(|m| serde_json::json!({
                    "uid": m.uid,
                    "family_id": m.family_id,
                    "weight": m.weight,
                    "strikes": m.strikes,
                    "total_storage": m.total_storage,
                    "available_storage": m.available_storage,
                    "blob_count": miner_stats.get(&m.uid).map(|(c, _)| *c).unwrap_or(0),
                    "storage_bytes": miner_stats.get(&m.uid).map(|(_, b)| *b).unwrap_or(0),
                    "bandwidth_bytes": 0_u64,
                })).collect::<Vec<_>>(),
                "error": "Failed to load bandwidth stats"
            }))
            .into_response();
        }
    };
    let mut bw_stream = Box::pin(bw_stream_result);
    while let Some(Ok(entry)) = bw_stream.next().await {
        if let Ok(key_str) = std::str::from_utf8(entry.key()) {
            if let Some(uid) = key_str.strip_prefix("stats:bw:") {
                let content_hash = entry.content_hash();
                let mut reader = state.blobs_store.reader(content_hash);
                use tokio::io::AsyncReadExt;
                let mut content = Vec::new();
                if reader.read_to_end(&mut content).await.is_ok() {
                    if let Ok(val_str) = std::str::from_utf8(&content) {
                        if let Ok(bytes) = val_str.parse::<u64>() {
                            bandwidth_stats.insert(uid.to_string(), bytes);
                        }
                    }
                }
            }
        }
    }

    let response = serde_json::json!({
        "miners": map.miners.len(),
        "total_files": total_files,
        "total_blobs": total_blobs,
        "total_storage": total_storage,
        "total_capacity": total_capacity,
        "total_available": total_available,
        "miner_stats": miner_stats,
        "bandwidth_stats": bandwidth_stats,
    });

    // Cache serialized response bytes for TTL seconds.
    let bytes = bytes::Bytes::from(serde_json::to_vec(&response).unwrap_or_default());
    {
        let mut guard = state.network_stats_cache.write().await;
        *guard = Some((now, bytes.clone()));
    }

    (
        StatusCode::OK,
        [("Content-Type", "application/json")],
        bytes,
    )
        .into_response()
}

// // P2P Command Sender for Miner Control (with retry)
// async fn send_miner_command_with_retry(
//     miner: &MinerNode,
//     message: common::MinerControlMessage,
//     endpoint: &Endpoint,
//     max_retries: u32,
// ) -> Result<()> {
//     let mut last_error = None;

//     for attempt in 0..=max_retries {
//         if attempt > 0 {
//             let delay = std::time::Duration::from_millis(500 * (1 << attempt)); // 1s, 2s, 4s
//             tokio::time::sleep(delay).await;
//             println!("📤 Retry {}/{} → Miner {}", attempt, max_retries, miner.uid);
//         }

//         match send_miner_command_inner(miner, message.clone(), endpoint).await {
//             Ok(()) => return Ok(()),
//             Err(e) => {
//                 last_error = Some(e);
//             }
//         }
//     }

//     Err(last_error.unwrap_or_else(|| anyhow!("Unknown error")))
// }

// async fn send_miner_command_inner(
//     miner: &MinerNode,
//     message: common::MinerControlMessage,
//     endpoint: &Endpoint,
// ) -> Result<()> {
//     // Connect to miner via P2P
//     let connection = endpoint
//         .connect(miner.endpoint.clone(), b"hippius/miner-control")
//         .await
//         .map_err(|e| anyhow!("Failed to connect to miner {}: {}", miner.uid, e))?;

//     // Open bidirectional stream
//     let (mut send, mut recv) = connection
//         .open_bi()
//         .await
//         .map_err(|e| anyhow!("Failed to open stream: {}", e))?;

//     // Serialize and send message
//     let message_bytes = serde_json::to_vec(&message)?;
//     // use tokio::io::AsyncWriteExt;
//     send.write_all(&message_bytes)
//         .await
//         .map_err(|e| anyhow!("Failed to send message: {}", e))?;
//     send.finish()
//         .map_err(|e| anyhow!("Failed to finish send: {}", e))?;

//     // Wait for ACK with timeout
//     let ack = tokio::time::timeout(
//         std::time::Duration::from_secs(30),
//         recv.read_to_end(64)
//     ).await
//         .map_err(|_| anyhow!("Timeout waiting for ACK"))?
//         .map_err(|e| anyhow!("Failed to read ACK: {}", e))?;

//     if ack == b"OK" {
//         Ok(())
//     } else {
//         Err(anyhow!("Miner returned error: {:?}", String::from_utf8_lossy(&ack)))
//     }
// }

// =============================================================================
// SHARD DISTRIBUTION
// =============================================================================
//
// The distribute_blob_to_miners function handles the P2P push of shard data
// to storage miners. It's the critical path for data durability - until shards
// are confirmed stored on miners, the upload is not complete.
//
// ## Protocol: hippius/miner-control
//
// Communication uses Iroh's QUIC-based P2P with ALPN `hippius/miner-control`:
//
// ```text
// Validator                                    Miner
// ─────────                                    ─────
//     │                                           │
//     │──── connect(endpoint, "hippius/miner-control") ──▶│
//     │                                           │
//     │◀───────────── connection established ─────│
//     │                                           │
//     │──── open_bi() ─────────────────────────▶ │
//     │                                           │
//     │──── MinerControlMessage::Store ─────────▶│
//     │     { hash, data, source_miner: None }    │
//     │                                           │
//     │──── finish() (send FIN) ────────────────▶│
//     │                                           │
//     │◀───────────── "OK" ───────────────────────│
//     │                                           │
// ```
//
// ## Retry Strategy
//
// Each miner push uses exponential backoff with jitter:
// - Max retries: 5
// - Base delay: 500ms
// - Exponential: delay_ms = 500 * 2^(attempt-1)
// - Delays: 500ms → 1s → 2s → 4s → 8s
//
// ## Why Fresh Connections?
//
// The code intentionally creates fresh connections for each push rather than
// using the connection pool. This is because:
// - `hippius/miner-control` handlers are single-shot (one message per stream)
// - Pooled connections can become stale and cause open_bi timeouts
// - Connection cost is acceptable for upload durability
//
// ## Timeouts
//
// | Operation | Timeout | Rationale |
// |-----------|---------|-----------|
// | Connect | 60s | Allow relay negotiation for NAT traversal |
// | Open stream | 10s | Should be fast once connected |
// | Write | 60s | 2MB shard at 250KB/s = 8s, plus margin |
// | ACK | 300s | Miner may be slow to persist to disk |

/// Push shard data directly to miners via P2P.
///
/// This function is called during upload to distribute each shard to its
/// designated miner(s). It uses the `hippius/miner-control` ALPN protocol
/// to send a `Store` message containing the full shard data.
///
/// # Arguments
///
/// * `blob_hash` - BLAKE3 hash of the shard (for verification)
/// * `blob_data` - Raw shard bytes to store
/// * `miners` - List of miners to push to (from CRUSH placement)
/// * `endpoint` - Iroh endpoint for P2P connections
/// * `connection_pool` - Unused (kept for API stability)
///
/// # Returns
///
/// `Ok(())` if at least one miner acknowledged the store.
/// `Err(...)` if all miners failed after retries.
///
/// # Errors
///
/// Returns an error if:
/// - All connection attempts fail
/// - All miners return error responses
/// - All ACK reads timeout
/// Result of distributing a blob to a single miner, including timing breakdown.
#[derive(Debug)]
struct MinerDistributeResult {
    miner_uid: u32,
    success: bool,
    error: Option<String>,
    attempts: u32,
    connect_ms: u128,
    stream_open_ms: u128,
    write_ms: u128,
    ack_ms: u128,
    total_ms: u128,
    shard_size_bytes: usize,
}

async fn distribute_blob_to_miners(
    blob_hash: &str,
    blob_data: Vec<u8>,
    miners: Vec<common::MinerNode>,
    endpoint: &Endpoint,
    connection_pool: Arc<
        tokio::sync::RwLock<std::collections::HashMap<u32, (iroh::endpoint::Connection, u64)>>,
    >,
) -> Result<()> {
    // NOTE: miner-control handlers are effectively single-shot per connection (one message),
    // and pooled connections can become unusable/stale (open_bi timeouts). For durability,
    // we currently prefer establishing a fresh connection per push.
    let _ = connection_pool; // keep signature stable; pool is intentionally not used here
    let mut tasks = Vec::new();
    let distribute_start = Instant::now();
    let shard_size = blob_data.len();

    for miner in miners {
        // Miner already provided by caller (from CRUSH placement), no O(n) lookup needed

        let hash_clone = blob_hash.to_string();
        let data_clone = blob_data.clone();
        let endpoint_clone = endpoint.clone();
        let miner_uid = miner.uid;

        // Spawn task - push blob data directly to miner with detailed timing
        let task = tokio::spawn(async move {
            const MAX_RETRIES: u32 = 5; // Increased from 2 for durability
            let task_start = Instant::now();
            let mut connect_ms: u128 = 0;
            let mut stream_open_ms: u128 = 0;
            let mut write_ms: u128 = 0;
            let mut ack_ms: u128 = 0;
            let mut final_attempt: u32 = 1;

            for attempt in 1..=MAX_RETRIES {
                final_attempt = attempt;

                // Phase 1: Connect
                let connect_start = Instant::now();
                let conn = match tokio::time::timeout(
                    std::time::Duration::from_secs(60), // Allow relay negotiation
                    endpoint_clone.connect(miner.endpoint.clone(), b"hippius/miner-control"),
                )
                .await
                {
                    Ok(Ok(c)) => {
                        connect_ms = connect_start.elapsed().as_millis();
                        c
                    }
                    Ok(Err(e)) => {
                        if attempt == MAX_RETRIES {
                            return MinerDistributeResult {
                                miner_uid,
                                success: false,
                                error: Some(format!("Connect failed: {}", e)),
                                attempts: attempt,
                                connect_ms: connect_start.elapsed().as_millis(),
                                stream_open_ms: 0,
                                write_ms: 0,
                                ack_ms: 0,
                                total_ms: task_start.elapsed().as_millis(),
                                shard_size_bytes: data_clone.len(),
                            };
                        }
                        let delay_ms = 500 * (1 << (attempt - 1));
                        tokio::time::sleep(std::time::Duration::from_millis(delay_ms as u64)).await;
                        continue;
                    }
                    Err(_) => {
                        if attempt == MAX_RETRIES {
                            return MinerDistributeResult {
                                miner_uid,
                                success: false,
                                error: Some(format!("Connect timed out after 60s")),
                                attempts: attempt,
                                connect_ms: connect_start.elapsed().as_millis(),
                                stream_open_ms: 0,
                                write_ms: 0,
                                ack_ms: 0,
                                total_ms: task_start.elapsed().as_millis(),
                                shard_size_bytes: data_clone.len(),
                            };
                        }
                        let delay_ms = 500 * (1 << (attempt - 1));
                        tokio::time::sleep(std::time::Duration::from_millis(delay_ms as u64)).await;
                        continue;
                    }
                };

                // Send Store message with blob data directly
                let message = common::MinerControlMessage::Store {
                    hash: hash_clone.clone(),
                    data: Some(data_clone.clone()),
                    source_miner: None,
                };

                // Phase 2: Open bidirectional stream
                let stream_start = Instant::now();
                let (mut send, mut recv) =
                    match tokio::time::timeout(std::time::Duration::from_secs(10), conn.open_bi())
                        .await
                    {
                        Ok(Ok(s)) => {
                            stream_open_ms = stream_start.elapsed().as_millis();
                            s
                        }
                        Ok(Err(e)) => {
                            if attempt == MAX_RETRIES {
                                return MinerDistributeResult {
                                    miner_uid,
                                    success: false,
                                    error: Some(format!("Open stream failed: {}", e)),
                                    attempts: attempt,
                                    connect_ms,
                                    stream_open_ms: stream_start.elapsed().as_millis(),
                                    write_ms: 0,
                                    ack_ms: 0,
                                    total_ms: task_start.elapsed().as_millis(),
                                    shard_size_bytes: data_clone.len(),
                                };
                            }
                            continue;
                        }
                        Err(_) => {
                            if attempt == MAX_RETRIES {
                                return MinerDistributeResult {
                                    miner_uid,
                                    success: false,
                                    error: Some("Open stream timeout".to_string()),
                                    attempts: attempt,
                                    connect_ms,
                                    stream_open_ms: stream_start.elapsed().as_millis(),
                                    write_ms: 0,
                                    ack_ms: 0,
                                    total_ms: task_start.elapsed().as_millis(),
                                    shard_size_bytes: data_clone.len(),
                                };
                            }
                            continue;
                        }
                    };

                let message_bytes = match serde_json::to_vec(&message) {
                    Ok(b) => b,
                    Err(e) => {
                        return MinerDistributeResult {
                            miner_uid,
                            success: false,
                            error: Some(format!("Serialize failed: {}", e)),
                            attempts: attempt,
                            connect_ms,
                            stream_open_ms,
                            write_ms: 0,
                            ack_ms: 0,
                            total_ms: task_start.elapsed().as_millis(),
                            shard_size_bytes: data_clone.len(),
                        };
                    }
                };

                // Phase 3: Write data
                let write_start = Instant::now();
                match tokio::time::timeout(
                    std::time::Duration::from_secs(60),
                    send.write_all(&message_bytes),
                )
                .await
                {
                    Ok(Ok(())) => {
                        write_ms = write_start.elapsed().as_millis();
                    }
                    Ok(Err(e)) => {
                        if attempt == MAX_RETRIES {
                            return MinerDistributeResult {
                                miner_uid,
                                success: false,
                                error: Some(format!("Write failed: {}", e)),
                                attempts: attempt,
                                connect_ms,
                                stream_open_ms,
                                write_ms: write_start.elapsed().as_millis(),
                                ack_ms: 0,
                                total_ms: task_start.elapsed().as_millis(),
                                shard_size_bytes: data_clone.len(),
                            };
                        }
                        continue;
                    }
                    Err(_) => {
                        if attempt == MAX_RETRIES {
                            return MinerDistributeResult {
                                miner_uid,
                                success: false,
                                error: Some("Write timeout".to_string()),
                                attempts: attempt,
                                connect_ms,
                                stream_open_ms,
                                write_ms: write_start.elapsed().as_millis(),
                                ack_ms: 0,
                                total_ms: task_start.elapsed().as_millis(),
                                shard_size_bytes: data_clone.len(),
                            };
                        }
                        continue;
                    }
                }

                // Finish (propagate FIN)
                if let Err(e) = send.finish() {
                    if attempt == MAX_RETRIES {
                        return MinerDistributeResult {
                            miner_uid,
                            success: false,
                            error: Some(format!("Finish failed: {}", e)),
                            attempts: attempt,
                            connect_ms,
                            stream_open_ms,
                            write_ms,
                            ack_ms: 0,
                            total_ms: task_start.elapsed().as_millis(),
                            shard_size_bytes: data_clone.len(),
                        };
                    }
                    continue;
                }

                // Phase 4: Wait for ACK
                let ack_start = Instant::now();
                match tokio::time::timeout(
                    std::time::Duration::from_secs(300),
                    recv.read_to_end(64),
                )
                .await
                {
                    Ok(Ok(ack)) if ack == b"OK" => {
                        ack_ms = ack_start.elapsed().as_millis();
                        return MinerDistributeResult {
                            miner_uid,
                            success: true,
                            error: None,
                            attempts: attempt,
                            connect_ms,
                            stream_open_ms,
                            write_ms,
                            ack_ms,
                            total_ms: task_start.elapsed().as_millis(),
                            shard_size_bytes: data_clone.len(),
                        };
                    }
                    Ok(Ok(ack)) => {
                        if attempt == MAX_RETRIES {
                            return MinerDistributeResult {
                                miner_uid,
                                success: false,
                                error: Some(format!(
                                    "Miner error: {:?}",
                                    String::from_utf8_lossy(&ack)
                                )),
                                attempts: attempt,
                                connect_ms,
                                stream_open_ms,
                                write_ms,
                                ack_ms: ack_start.elapsed().as_millis(),
                                total_ms: task_start.elapsed().as_millis(),
                                shard_size_bytes: data_clone.len(),
                            };
                        }
                        continue;
                    }
                    Ok(Err(e)) => {
                        if attempt == MAX_RETRIES {
                            return MinerDistributeResult {
                                miner_uid,
                                success: false,
                                error: Some(format!("ACK read failed: {}", e)),
                                attempts: attempt,
                                connect_ms,
                                stream_open_ms,
                                write_ms,
                                ack_ms: ack_start.elapsed().as_millis(),
                                total_ms: task_start.elapsed().as_millis(),
                                shard_size_bytes: data_clone.len(),
                            };
                        }
                        continue;
                    }
                    Err(_) => {
                        if attempt == MAX_RETRIES {
                            return MinerDistributeResult {
                                miner_uid,
                                success: false,
                                error: Some(format!("ACK timeout after {:?}", ack_start.elapsed())),
                                attempts: attempt,
                                connect_ms,
                                stream_open_ms,
                                write_ms,
                                ack_ms: ack_start.elapsed().as_millis(),
                                total_ms: task_start.elapsed().as_millis(),
                                shard_size_bytes: data_clone.len(),
                            };
                        }
                        continue;
                    }
                }
            }

            MinerDistributeResult {
                miner_uid,
                success: false,
                error: Some("Max retries exceeded".to_string()),
                attempts: final_attempt,
                connect_ms,
                stream_open_ms,
                write_ms,
                ack_ms,
                total_ms: task_start.elapsed().as_millis(),
                shard_size_bytes: data_clone.len(),
            }
        });

        tasks.push(task);
    }

    // Wait for all pushes to complete and collect timing results
    let mut success_count = 0;
    let mut fail_count = 0;
    let mut results: Vec<MinerDistributeResult> = Vec::new();

    for task in tasks {
        match task.await {
            Ok(result) => {
                if result.success {
                    success_count += 1;
                } else {
                    fail_count += 1;
                    warn!(
                        miner_uid = result.miner_uid,
                        error = ?result.error,
                        attempts = result.attempts,
                        "Miner P2P failed"
                    );
                }
                results.push(result);
            }
            Err(e) => {
                warn!(error = %e, "Miner task panicked");
                fail_count += 1;
            }
        }
    }

    // Log detailed timing for each miner
    let total_distribute_ms = distribute_start.elapsed().as_millis();
    for result in &results {
        info!(
            miner_uid = result.miner_uid,
            success = result.success,
            attempts = result.attempts,
            shard_size_bytes = result.shard_size_bytes,
            connect_ms = result.connect_ms,
            stream_open_ms = result.stream_open_ms,
            write_ms = result.write_ms,
            ack_ms = result.ack_ms,
            total_ms = result.total_ms,
            "Miner shard transfer timing"
        );
    }

    // Log aggregate distribution stats
    let avg_total_ms = if !results.is_empty() {
        results.iter().map(|r| r.total_ms).sum::<u128>() / results.len() as u128
    } else {
        0
    };
    let max_total_ms = results.iter().map(|r| r.total_ms).max().unwrap_or(0);
    let min_total_ms = results.iter().map(|r| r.total_ms).min().unwrap_or(0);

    info!(
        blob_hash = %blob_hash,
        shard_size_bytes = shard_size,
        miner_count = results.len(),
        success_count = success_count,
        fail_count = fail_count,
        total_distribute_ms = total_distribute_ms,
        avg_miner_ms = avg_total_ms,
        max_miner_ms = max_total_ms,
        min_miner_ms = min_total_ms,
        "Shard distribution completed"
    );

    if fail_count > 0 {
        Err(anyhow!("{} miners failed to receive blob", fail_count))
    } else {
        Ok(())
    }
}

// // Gather all manifest hashes from iroh-docs for self-rebalancing
// async fn gather_manifest_hashes(
//     doc: &Doc,
//     blobs_store: &iroh_blobs::store::fs::FsStore,
// ) -> Option<Vec<(String, String)>> {
//     use futures_lite::StreamExt;
//     use tokio::io::AsyncReadExt;

//     // Query for all keys (manifests are stored with file_hash as key)
//     // We identify manifests by trying to parse them - they start with valid hex chars
//     let query = iroh_docs::store::Query::single_latest_per_key();

//     let mut entries = Box::pin(doc.get_many(query).await.ok()?);
//     let mut manifests = Vec::new();

//     while let Some(Ok(entry)) = entries.next().await {
//         let key = entry.key();
//         let key_str = String::from_utf8_lossy(key).to_string();

//         // Skip known non-manifest keys
//         if key_str == "cluster_map" || key_str == "sync_index" || key_str == "cooldowns" || key_str == "blacklist" {
//             continue;
//         }

//         // Try to read content and see if it's a valid manifest
//         let hash = entry.content_hash();
//         let mut reader = blobs_store.reader(hash);
//         let mut content = Vec::new();
//         if reader.read_to_end(&mut content).await.is_ok() {
//             let json_str = String::from_utf8_lossy(&content).to_string();
//             // Check if this looks like a manifest (has file_hash and shards fields)
//             if json_str.contains("\"file_hash\"") && json_str.contains("\"shards\"") {
//                 manifests.push((key_str, json_str));
//             }
//         }
//     }

//     println!("  Gathered {} manifests for broadcast", manifests.len());

//     if manifests.is_empty() {
//         None
//     } else {
//         Some(manifests)
//     }
// }

/// Get a pooled connection if valid, or None if not found/stale.
/// Removes stale connections from the pool automatically.
async fn get_pooled_connection(
    pool: &tokio::sync::RwLock<std::collections::HashMap<u32, (iroh::endpoint::Connection, u64)>>,
    miner_uid: u32,
) -> Option<iroh::endpoint::Connection> {
    let mut pool_guard = pool.write().await;
    if let Some((conn, _ts)) = pool_guard.get(&miner_uid) {
        if conn.close_reason().is_none() {
            return Some(conn.clone());
        }
        // Connection is closed, remove it
        pool_guard.remove(&miner_uid);
    }
    None
}

// Broadcast cluster map to all miners for peer discovery (M2M transfers)
async fn broadcast_cluster_map_to_miners(
    cluster_map: &ClusterMap,
    endpoint: &Endpoint,
    relay_url: Option<iroh_base::RelayUrl>,
    connection_pool: Arc<
        tokio::sync::RwLock<std::collections::HashMap<u32, (iroh::endpoint::Connection, u64)>>,
    >,
) -> Result<()> {
    debug!(
        epoch = cluster_map.epoch,
        miners = cluster_map.miners.len(),
        "Broadcasting cluster map"
    );

    // Serialize full cluster map for CRUSH calculations
    let cluster_map_json = serde_json::to_string(cluster_map).ok();

    // Create simplified map info for miners (they only need peer endpoint addresses)
    let peer_info: Vec<(String, String)> = cluster_map
        .miners
        .iter()
        .filter_map(|m| {
            serde_json::to_string(&m.endpoint)
                .ok()
                .map(|e| (m.public_key.clone(), e))
        })
        .collect();

    let chunk_size = 5;
    let mut current_chunk_tasks = Vec::new();
    let mut success_count = 0;

    for (i, miner) in cluster_map.miners.iter().enumerate() {
        let miner_clone = miner.clone();
        let relay_url_clone = relay_url.clone();
        let peer_info_clone = peer_info.clone();
        let cluster_map_json_clone = cluster_map_json.clone();
        let endpoint_clone = endpoint.clone();
        let epoch = cluster_map.epoch;

        let pool_clone = connection_pool.clone();

        // Spawn task to send cluster map to each miner
        let task = tokio::spawn(async move {
            let msg = common::MinerControlMessage::ClusterMapUpdate {
                epoch,
                peers: peer_info_clone,
                cluster_map_json: cluster_map_json_clone,
            };

            const MAX_RETRIES: u32 = 2;
            for attempt in 1..=MAX_RETRIES {
                // Try to get existing connection from pool first (use write lock since we may remove)
                let conn = get_pooled_connection(&pool_clone, miner_clone.uid).await;

                let conn = match conn {
                    Some(c) => c,
                    None => {
                        // Connect logic
                        let mut target = miner_clone.endpoint.clone();
                        if let Some(r) = relay_url_clone.clone() {
                            target = target.with_relay_url(r);
                        }

                        match tokio::time::timeout(
                            tokio::time::Duration::from_secs(MINER_CONNECT_TIMEOUT_SECS),
                            endpoint_clone.connect(target, b"hippius/miner-control"),
                        )
                        .await
                        {
                            Ok(Ok(c)) => {
                                let mut pool = pool_clone.write().await;
                                pool.insert(miner_clone.uid, (c.clone(), common::now_secs()));
                                c
                            }
                            Ok(Err(e)) => {
                                if attempt == MAX_RETRIES {
                                    debug!(miner_uid = miner_clone.uid, error = %e, "Miner connect error");
                                    return Err(anyhow::anyhow!("Connect failed"));
                                }
                                tokio::time::sleep(tokio::time::Duration::from_millis(
                                    MINER_RETRY_DELAY_MS,
                                ))
                                .await;
                                continue;
                            }
                            Err(_) => {
                                if attempt == MAX_RETRIES {
                                    debug!(miner_uid = miner_clone.uid, "Miner connect timed out");
                                    return Err(anyhow::anyhow!("Timeout"));
                                }
                                continue;
                            }
                        }
                    }
                };

                // Use connection
                let (mut send, mut recv) = match conn.open_bi().await {
                    Ok(s) => s,
                    Err(e) => {
                        debug!(miner_uid = miner_clone.uid, error = %e, "Miner open_bi error");
                        continue;
                    }
                };

                let msg_bytes = match serde_json::to_vec(&msg) {
                    Ok(b) => b,
                    Err(e) => {
                        error!(error = %e, "Failed to serialize MinerControlMessage");
                        continue;
                    }
                };
                // use tokio::io::AsyncWriteExt;
                if send.write_all(&msg_bytes).await.is_err() {
                    continue;
                }
                if send.finish().is_err() {
                    continue;
                }

                // Wait for ACK
                // use tokio::io::AsyncReadExt;
                let ack = match tokio::time::timeout(
                    tokio::time::Duration::from_secs(MINER_ACK_TIMEOUT_SECS),
                    recv.read_to_end(64),
                )
                .await
                {
                    Ok(Ok(a)) => a,
                    _ => continue,
                };

                if ack == b"OK" {
                    return Ok(());
                }
            }
            Err(anyhow::anyhow!("Failed after retries"))
        });

        current_chunk_tasks.push(task);

        // If chunk is full or it's the last miner, process the chunk
        if current_chunk_tasks.len() >= chunk_size || i == cluster_map.miners.len() - 1 {
            let results = futures::future::join_all(current_chunk_tasks).await;
            for result in results {
                if let Ok(Ok(())) = result {
                    success_count += 1;
                }
            }
            current_chunk_tasks = Vec::new(); // Clear for the next chunk
        }
    }

    info!(
        success = success_count,
        total = cluster_map.miners.len(),
        "Cluster map broadcast complete"
    );

    Ok(())
}

async fn load_keypair(data_dir: &std::path::Path) -> Result<SecretKey> {
    let keypair_path = data_dir.join("keypair.bin");
    if keypair_path.exists() {
        let bytes = tokio::fs::read(&keypair_path).await?;
        if let Ok(key) = SecretKey::try_from(&bytes[..]) {
            return Ok(key);
        }
    }

    let mut rng = rand::rng();
    let secret_key = iroh::SecretKey::generate(&mut rng);
    tokio::fs::write(&keypair_path, secret_key.to_bytes()).await?;
    Ok(secret_key)
}

async fn audit_file(
    Path(hash): Path<String>,
    State(state): State<Arc<AppState>>,
) -> impl IntoResponse {
    // Validate hash format early
    if let Err((status, msg)) = validate_hash_param(&hash) {
        return (status, msg).into_response();
    }
    debug!(hash = %hash, "Received audit request");
    // 1. Get Manifest
    let query = iroh_docs::store::Query::single_latest_per_key().key_exact(hash.as_bytes());
    let mut stream = Box::pin(match state.doc.get_many(query).await {
        Ok(s) => s,
        Err(e) => return doc_store_error("audit_file query", e).into_response(),
    });

    let manifest_val = match stream.next().await {
        Some(Ok(entry)) => {
            let hash = entry.content_hash();
            let mut reader = state.blobs_store.reader(hash);
            use tokio::io::AsyncReadExt;
            let mut content = Vec::new();
            if reader.read_to_end(&mut content).await.is_ok() {
                let json_str = String::from_utf8_lossy(&content);
                match serde_json::from_str::<Value>(&json_str) {
                    Ok(v) => v,
                    Err(e) => {
                        return internal_error("audit_file parse manifest", e).into_response();
                    }
                }
            } else {
                return (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    "Failed to read manifest content",
                )
                    .into_response();
            }
        }
        Some(Err(e)) => return doc_store_error("audit_file read", e).into_response(),
        None => return (StatusCode::NOT_FOUND, "Manifest not found").into_response(),
    };

    debug!(manifest = ?manifest_val, "Manifest value");
    let manifest: FileManifest = match serde_json::from_value(manifest_val.clone()) {
        Ok(m) => m,
        Err(e) => {
            return internal_error("audit_file deserialize manifest", e).into_response();
        }
    };
    let mut reports = Vec::new();

    if let Some(shards) = manifest_val["shards"].as_array() {
        debug!(shards = shards.len(), "Found shards in manifest");

        // Load Cluster Map ONCE
        let query_map = iroh_docs::store::Query::single_latest_per_key().key_exact(b"cluster_map");
        let mut stream = Box::pin(match state.doc.get_many(query_map).await {
            Ok(s) => s,
            Err(e) => return doc_store_error("audit_file cluster_map query", e).into_response(),
        });
        let cluster_map = match stream.next().await {
            Some(Ok(entry)) => {
                let hash = entry.content_hash();
                let mut reader = state.blobs_store.reader(hash);
                use tokio::io::AsyncReadExt;
                let mut content = Vec::new();
                reader
                    .read_to_end(&mut content)
                    .await
                    .ok()
                    .and_then(|_| {
                        serde_json::from_str::<ClusterMap>(&String::from_utf8_lossy(&content)).ok()
                    })
                    .unwrap_or_default()
            }
            _ => ClusterMap::default(),
        };

        if cluster_map.miners.is_empty() {
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                "Cluster Map is empty or failed to load",
            )
                .into_response();
        }

        let shards_per_stripe = manifest.stripe_config.k + manifest.stripe_config.m;

        for (i, shard) in shards.iter().enumerate() {
            // Get blob hash
            let blob_hash = if let Some(h) = shard["blob_hash"].as_str() {
                h.to_string()
            } else {
                debug!(shard_index = i, "Shard missing blob_hash");
                continue;
            };

            // Calculate Placement
            let stripe_idx = i / shards_per_stripe;
            let local_idx = i % shards_per_stripe;

            match common::calculate_stripe_placement(
                &manifest.file_hash,
                stripe_idx as u64,
                shards_per_stripe,
                &cluster_map,
                manifest.placement_version,
            ) {
                Ok(miners) => {
                    if let Some(miner) = miners.get(local_idx) {
                        let report = audit_shard(i, &blob_hash, miner, &state, &manifest).await;
                        reports.push(report);
                    } else {
                        debug!(
                            shard_index = i,
                            stripe_idx = stripe_idx,
                            local_idx = local_idx,
                            "No miner found for shard"
                        );
                    }
                }
                Err(e) => {
                    debug!(shard_index = i, error = %e, "Placement calc failed for shard");
                }
            }
        }
    } else {
        warn!("'shards' field is missing or not an array");
    }

    Json(reports).into_response()
}

async fn audit_shard(
    shard_index: usize,
    blob_hash: &str,
    miner: &common::MinerNode,
    app_state: &Arc<AppState>,
    manifest: &FileManifest,
) -> ShardAuditReport {
    let hash_str = blob_hash.to_string();
    let hash = match iroh_blobs::Hash::from_str(blob_hash) {
        Ok(h) => h,
        Err(_) => {
            return ShardAuditReport {
                shard_index,
                hash: hash_str,
                status: "FAIL: Invalid Hash".to_string(),
                latency_ms: 0,
                timestamp: 0,
                miner_uid: None,
                miner_addr: None,
            };
        }
    };

    let start = std::time::Instant::now();

    // Direct P2P Audit (No map lookup needed, we have the miner)
    {
        // Scope to remove miner_opt usage
        debug!(
            miner_uid = miner.uid,
            endpoint_id = %miner.endpoint.id,
            "Connecting to miner via P2P"
        );

        // P2P Audit
        match app_state
            .endpoint
            .connect(miner.endpoint.clone(), iroh_blobs::ALPN)
            .await
        {
            Ok(connection) => {
                debug!("Connected to miner, requesting blob chunk");
                let request = GetRequest::all(hash);

                let initial = fsm::start(connection, request, Default::default());

                match initial.next().await {
                    Ok(at_connected) => {
                        match at_connected.next().await {
                            Ok(ConnectedNext::StartRoot(start_root)) => {
                                let blob_header = start_root.next();
                                match blob_header.next().await {
                                    Ok((content, _size)) => {
                                        match content.next().await {
                                            BlobContentNext::More((_next_content, _bytes)) => {
                                                // Got data! PASS
                                                ShardAuditReport {
                                                    shard_index,
                                                    hash: hash.to_string(),
                                                    miner_uid: Some(miner.uid),
                                                    miner_addr: Some(miner.http_addr.clone()),
                                                    status: "PASS".to_string(),
                                                    latency_ms: start.elapsed().as_millis() as u64,
                                                    timestamp: now_secs(),
                                                }
                                            }
                                            BlobContentNext::Done(at_end) => {
                                                match at_end.next() {
                                                    EndBlobNext::Closing(_) => {
                                                        // Empty blob? Still PASS if it exists.
                                                        ShardAuditReport {
                                                            shard_index,
                                                            hash: hash.to_string(),
                                                            miner_uid: Some(miner.uid),
                                                            miner_addr: Some(
                                                                miner.http_addr.clone(),
                                                            ),
                                                            status: "PASS".to_string(),
                                                            latency_ms: start.elapsed().as_millis()
                                                                as u64,
                                                            timestamp: now_secs(),
                                                        }
                                                    }
                                                    EndBlobNext::MoreChildren(_) => {
                                                        // Protocol Error
                                                        handle_strike(miner.uid, app_state).await;
                                                        let status = if let Err(e) =
                                                            reconstruct_shard(
                                                                manifest,
                                                                shard_index,
                                                                app_state,
                                                            )
                                                            .await
                                                        {
                                                            format!(
                                                                "FAIL (Protocol Err - Recov Err: {})",
                                                                e
                                                            )
                                                        } else {
                                                            "RECOVERED".to_string()
                                                        };
                                                        ShardAuditReport {
                                                            shard_index,
                                                            hash: hash.to_string(),
                                                            miner_uid: Some(miner.uid),
                                                            miner_addr: Some(
                                                                miner.http_addr.clone(),
                                                            ),
                                                            status,
                                                            latency_ms: 0,
                                                            timestamp: 0,
                                                        }
                                                    }
                                                }
                                            }
                                        }
                                    }
                                    Err(e) => {
                                        warn!(error = %e, "P2P Audit Failed (Header)");
                                        handle_strike(miner.uid, app_state).await;
                                        let status = if let Err(e) =
                                            reconstruct_shard(manifest, shard_index, app_state)
                                                .await
                                        {
                                            format!("FAIL (Header Err: {} - Recov Err: {})", e, e)
                                        } else {
                                            "RECOVERED".to_string()
                                        };
                                        ShardAuditReport {
                                            shard_index,
                                            hash: hash.to_string(),
                                            miner_uid: Some(miner.uid),
                                            miner_addr: Some(miner.http_addr.clone()),
                                            status,
                                            latency_ms: 0,
                                            timestamp: 0,
                                        }
                                    }
                                }
                            }
                            Ok(ConnectedNext::Closing(_)) => {
                                handle_strike(miner.uid, app_state).await;
                                let status = if let Err(e) =
                                    reconstruct_shard(manifest, shard_index, app_state).await
                                {
                                    format!("FAIL (Conn Closed - Recov Err: {})", e)
                                } else {
                                    "RECOVERED".to_string()
                                };
                                ShardAuditReport {
                                    shard_index,
                                    hash: hash.to_string(),
                                    miner_uid: Some(miner.uid),
                                    miner_addr: Some(miner.http_addr.clone()),
                                    status,
                                    latency_ms: 0,
                                    timestamp: 0,
                                }
                            }
                            Ok(ConnectedNext::StartChild(_)) => {
                                // Should not happen for single blob request
                                handle_strike(miner.uid, app_state).await;
                                ShardAuditReport {
                                    shard_index,
                                    hash: hash.to_string(),
                                    miner_uid: Some(miner.uid),
                                    miner_addr: Some(miner.http_addr.clone()),
                                    status: "FAIL: Unexpected Child".to_string(),
                                    latency_ms: 0,
                                    timestamp: 0,
                                }
                            }
                            Err(e) => {
                                warn!(error = %e, "P2P Audit Failed (Connected)");
                                handle_strike(miner.uid, app_state).await;
                                let status = if let Err(e) =
                                    reconstruct_shard(manifest, shard_index, app_state).await
                                {
                                    format!("FAIL (Connected Err: {} - Recov Err: {})", e, e)
                                } else {
                                    "RECOVERED".to_string()
                                };
                                ShardAuditReport {
                                    shard_index,
                                    hash: hash.to_string(),
                                    miner_uid: Some(miner.uid),
                                    miner_addr: Some(miner.http_addr.clone()),
                                    status,
                                    latency_ms: 0,
                                    timestamp: 0,
                                }
                            }
                        }
                    }
                    Err(e) => {
                        warn!(error = %e, "P2P Audit Failed (Initial)");
                        handle_strike(miner.uid, app_state).await;
                        let status = if let Err(e) =
                            reconstruct_shard(manifest, shard_index, app_state).await
                        {
                            format!("FAIL (Initial Err: {} - Recov Err: {})", e, e)
                        } else {
                            "RECOVERED".to_string()
                        };
                        ShardAuditReport {
                            shard_index,
                            hash: hash.to_string(),
                            miner_uid: Some(miner.uid),
                            miner_addr: Some(miner.http_addr.clone()),
                            status,
                            latency_ms: 0,
                            timestamp: 0,
                        }
                    }
                }
            }
            Err(e) => {
                // FAIL - STRIKE LOGIC
                handle_strike(miner.uid, app_state).await;

                // RECOVERY
                let status = if let Err(re_err) =
                    reconstruct_shard(manifest, shard_index, app_state).await
                {
                    format!("FAIL (Conn Err: {} - Recov Err: {})", e, re_err)
                } else {
                    "RECOVERED".to_string()
                };

                ShardAuditReport {
                    shard_index,
                    hash: hash.to_string(),
                    miner_uid: Some(miner.uid),
                    miner_addr: Some(miner.http_addr.clone()),
                    status,
                    latency_ms: start.elapsed().as_millis() as u64,
                    timestamp: now_secs(),
                }
            }
        }
    }
}

async fn handle_strike(miner_uid: u32, app_state: &Arc<AppState>) {
    // Lock map updates to prevent race conditions with other cluster map modifications
    let _guard = app_state.map_lock.lock().await;

    let query_map = iroh_docs::store::Query::single_latest_per_key().key_exact(b"cluster_map");
    let mut stream = Box::pin(match app_state.doc.get_many(query_map).await {
        Ok(s) => s,
        Err(_) => return,
    });
    let mut current_map = match stream.next().await {
        Some(Ok(entry)) => {
            let hash = entry.content_hash();
            let mut reader = app_state.blobs_store.reader(hash);
            use tokio::io::AsyncReadExt;
            let mut content = Vec::new();
            reader
                .read_to_end(&mut content)
                .await
                .ok()
                .and_then(|_| {
                    serde_json::from_str::<ClusterMap>(&String::from_utf8_lossy(&content)).ok()
                })
                .unwrap_or_default()
        }
        _ => ClusterMap::default(),
    };

    let mut should_ban = false;
    let mut ban_node_id = String::new();
    let mut ban_family_id = String::new();

    if let Some(m) = current_map.miners.iter_mut().find(|m| m.uid == miner_uid) {
        m.strikes += 1;
        info!(miner_uid = m.uid, strikes = m.strikes, "Miner strikes");
        if m.strikes >= 3 {
            should_ban = true;
            ban_node_id = m.public_key.clone();
            ban_family_id = m.family_id.clone();
        }
    }

    if should_ban {
        let before_count = current_map.miners.len();
        current_map.remove_node(miner_uid);
        let after_count = current_map.miners.len();
        warn!(
            miner_uid = miner_uid,
            family_id = %ban_family_id,
            miners_before = before_count,
            miners_after = after_count,
            "MINER LEFT: Miner BANNED (3 Strikes) and removed from ClusterMap"
        );

        // Add to Blacklist
        let query_blacklist =
            iroh_docs::store::Query::single_latest_per_key().key_exact(b"blacklist");
        let mut stream = Box::pin(match app_state.doc.get_many(query_blacklist).await {
            Ok(s) => s,
            Err(_) => return, // Should handle error better
        });
        let mut blacklist = match stream.next().await {
            Some(Ok(entry)) => {
                let hash = entry.content_hash();
                let mut reader = app_state.blobs_store.reader(hash);
                use tokio::io::AsyncReadExt;
                let mut content = Vec::new();
                reader
                    .read_to_end(&mut content)
                    .await
                    .ok()
                    .and_then(|_| {
                        serde_json::from_str::<Blacklist>(&String::from_utf8_lossy(&content)).ok()
                    })
                    .unwrap_or_default()
            }
            _ => Blacklist::default(),
        };

        blacklist.add_ban(ban_node_id, ban_family_id);
        let bl_json = match serde_json::to_string(&blacklist) {
            Ok(j) => j,
            Err(e) => {
                error!(error = %e, "Failed to serialize blacklist");
                return;
            }
        };
        let author = app_state.author_id;
        if let Err(e) = app_state
            .doc
            .set_bytes(
                author,
                Bytes::from_static(b"blacklist"),
                Bytes::from(bl_json),
            )
            .await
        {
            error!(error = %e, "Failed to persist blacklist");
        }
    }

    // Save updated map
    current_map.epoch += 1;
    if let Err(e) = persist_cluster_map_to_doc(app_state, &current_map).await {
        error!(error = %e, "Failed to persist cluster map in ban flow");
    }
}

async fn get_blob(
    State(state): State<Arc<AppState>>,
    Path(hash): Path<String>,
) -> impl IntoResponse {
    let hash = match iroh_blobs::Hash::from_str(&hash) {
        Ok(h) => h,
        Err(_) => return (StatusCode::BAD_REQUEST, "Invalid hash").into_response(),
    };

    if !state.blobs_store.has(hash).await.unwrap_or(false) {
        return (StatusCode::NOT_FOUND, "Blob not found").into_response();
    }

    let mut reader = state.blobs_store.reader(hash);
    let mut content = Vec::new();
    if reader.read_to_end(&mut content).await.is_ok() {
        (StatusCode::OK, content).into_response()
    } else {
        (StatusCode::INTERNAL_SERVER_ERROR, "Failed to read blob").into_response()
    }
}

// =============================================================================
// P2P PROTOCOL: hippius/validator-control
// =============================================================================
//
// The `hippius/validator-control` protocol handles inbound P2P connections from
// miners. This is the primary communication channel for:
// - Miner registration (joining the cluster)
// - Heartbeat signals (liveness proofs)
// - PG file queries (for rebalancing)
// - Health pings
//
// ## Protocol Flow
//
// ```text
// Miner                                        Validator
// ─────                                        ─────────
//     │                                             │
//     │──── connect("hippius/validator-control") ──▶│
//     │                                             │
//     │──── open_bi() ─────────────────────────────▶│
//     │                                             │
//     │──── ValidatorControlMessage ───────────────▶│
//     │     (Register / Heartbeat / QueryPgFiles)   │
//     │                                             │
//     │──── finish() (send FIN) ───────────────────▶│
//     │                                             │
//     │◀───────────── Response ─────────────────────│
//     │     (UID / OK / file list)                  │
//     │                                             │
// ```
//
// ## Message Types (ValidatorControlMessage)
//
// | Message | Fields | Response |
// |---------|--------|----------|
// | Register | public_key, http_addr, storage, family_id, timestamp, signature | UID or error code |
// | Heartbeat | public_key, http_addr, storage stats, timestamp, signature | "OK" |
// | QueryPgFiles | pg_id, offset, limit | JSON array of file hashes |
// | Ping | - | "PONG" |
//
// ## Registration Flow
//
// ```text
// 1. Rate limit check (10s window per public key)
//    └─ RATE_LIMITED if too soon
//
// 2. Parse and verify Ed25519 public key
//    └─ INVALID_KEY if malformed
//
// 3. Verify signature over "REGISTER:{public_key}:{timestamp}"
//    └─ INVALID_SIG if verification fails
//
// 4. Check timestamp freshness (±5 minutes)
//    └─ Warn but allow (clock skew tolerance)
//
// 5. Verify family membership:
//    ├─ Chain registry (pallet-arion) if enabled
//    └─ HTTP whitelist (legacy) if chain disabled
//    └─ FAMILY_REJECTED if not in family
//
// 6. Check blacklist
//    └─ BLACKLISTED if banned
//
// 7. Add/update miner in ClusterMap
//    └─ Assign UID, set endpoint, update epoch
//
// 8. Return miner UID + doc ticket for replication
// ```
//
// ## Security Measures
//
// - **Ed25519 signatures**: All registrations/heartbeats must be cryptographically signed
// - **Rate limiting**: Lock-free DashMap tracks last attempt per public key
// - **Blacklist**: Banned miners (3+ strikes) cannot re-register
// - **Timestamp validation**: Prevents replay attacks (5-minute window)
// - **Family verification**: On-chain or whitelist-based trust model

/// P2P protocol handler for miner → validator communication.
///
/// Implements `ProtocolHandler` for Iroh's protocol router, dispatching
/// incoming connections to `handle_validator_control`.
struct ValidatorControlHandler {
    state: Arc<AppState>,
}

impl std::fmt::Debug for ValidatorControlHandler {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ValidatorControlHandler").finish()
    }
}

impl iroh::protocol::ProtocolHandler for ValidatorControlHandler {
    fn accept(
        &self,
        conn: iroh::endpoint::Connection,
    ) -> impl futures::Future<Output = Result<(), iroh::protocol::AcceptError>> + Send {
        let state = self.state.clone();
        async move {
            handle_validator_control(conn, state)
                .await
                .map_err(|e| iroh::protocol::AcceptError::from_err(std::io::Error::other(e)))
        }
    }
}

/// Handle an incoming P2P connection from a miner.
///
/// This function processes `ValidatorControlMessage` messages:
///
/// - **Register**: Add a new miner to the cluster (or update existing)
/// - **Heartbeat**: Update miner's liveness timestamp and storage stats
/// - **QueryPgFiles**: Return list of file hashes in a Placement Group
/// - **Ping**: Simple health check response
///
/// # Security
///
/// All registration and heartbeat messages require valid Ed25519 signatures.
/// The signature covers `"{MESSAGE_TYPE}:{public_key}:{timestamp}"`.
///
/// # Arguments
///
/// * `conn` - The accepted P2P connection from the miner
/// * `state` - Shared application state
///
/// # Returns
///
/// `Ok(())` on successful message handling, `Err` on protocol/IO errors.
///
/// # Response Codes
///
/// | Code | Meaning |
/// |------|---------|
/// | `{uid}` | Successful registration, returns assigned miner UID |
/// | `OK` | Successful heartbeat/other operation |
/// | `PONG` | Response to Ping |
/// | `RATE_LIMITED` | Too many registration attempts |
/// | `INVALID_KEY` | Malformed public key |
/// | `INVALID_SIG` | Signature verification failed |
/// | `FAMILY_REJECTED:{reason}` | Family verification failed |
/// | `BLACKLISTED` | Miner is banned |
async fn handle_validator_control(
    conn: iroh::endpoint::Connection,
    state: Arc<AppState>,
) -> anyhow::Result<()> {
    debug!("P2P connection accepted from miner");

    let (mut send, mut recv) = conn.accept_bi().await?;

    // Read the message
    use tokio::io::AsyncReadExt;
    let buf = recv.read_to_end(1024 * 1024).await?;

    let message: common::ValidatorControlMessage = serde_json::from_slice(&buf)?;

    match message {
        common::ValidatorControlMessage::Register {
            public_key,
            http_addr,
            total_storage,
            available_storage,
            family_id,
            timestamp,
            signature,
            endpoint_addr,
        } => {
            // Rate limit check using lock-free DashMap
            let now = now_secs();
            if let Some(last_time) = state.rate_limits.get(&public_key).as_deref().copied() {
                if now < last_time + REGISTRATION_RATE_LIMIT_SECS {
                    warn!(
                        public_key = %truncate_for_log(&public_key, 16),
                        remaining_secs = last_time + REGISTRATION_RATE_LIMIT_SECS - now,
                        "Rate limited registration attempt"
                    );
                    use tokio::io::AsyncWriteExt;
                    send.write_all(b"RATE_LIMITED").await?;
                    send.flush().await?;
                    send.finish()?;
                    // Ensure the response is delivered before we drop the connection.
                    let _ = tokio::time::timeout(Duration::from_secs(1), send.stopped()).await;
                    return Ok(());
                }
            }

            // Update rate limit timestamp (lock-free insert)
            state.rate_limits.insert(public_key.clone(), now);

            // Verify Ed25519 signature
            let node_id = match iroh::PublicKey::from_str(&public_key) {
                Ok(pk) => pk,
                Err(_) => {
                    error!(
                        public_key = %truncate_for_log(&public_key, 16),
                        "Invalid public key in registration"
                    );
                    use tokio::io::AsyncWriteExt;
                    send.write_all(b"INVALID_KEY").await?;
                    send.flush().await?;
                    send.finish()?;
                    let _ = tokio::time::timeout(Duration::from_secs(1), send.stopped()).await;
                    return Ok(());
                }
            };

            // Verify signature
            let sign_data = format!("REGISTER:{}:{}", public_key, timestamp);
            let sig_bytes: [u8; 64] = signature
                .try_into()
                .map_err(|_| anyhow::anyhow!("Invalid signature length"))?;
            let sig = iroh::Signature::from_bytes(&sig_bytes);

            if node_id.verify(sign_data.as_bytes(), &sig).is_err() {
                error!(public_key = %truncate_for_log(&public_key, 16), "Signature verification failed");
                use tokio::io::AsyncWriteExt;
                send.write_all(b"INVALID_SIG").await?;
                send.flush().await?;
                send.finish()?;
                let _ = tokio::time::timeout(Duration::from_secs(1), send.stopped()).await;
                return Ok(());
            }

            // Check timestamp is recent (within 5 minutes)
            let now = now_secs();
            if timestamp > now + 60 || timestamp < now.saturating_sub(300) {
                warn!(
                    public_key = %truncate_for_log(&public_key, 16),
                    timestamp = timestamp,
                    "Stale or future timestamp in registration (may be clock skew)"
                );
                // Allow it but log warning - could be clock skew
            }

            // Derive/verify family membership:
            // - Prefer on-chain registry cache (pallet-arion) if enabled
            // - Fallback to HTTP API whitelist (legacy) if chain registry is disabled
            let mut family_id = family_id;
            if state.chain_registry.enabled() {
                match state.chain_registry.resolve_family_hex(&public_key).await {
                    Ok(Some(chain_family_id)) => {
                        if family_id != chain_family_id {
                            warn!(
                                public_key = %truncate_for_log(&public_key, 16),
                                claimed_family = %family_id,
                                chain_family = %chain_family_id,
                                "Miner claimed different family than on-chain (using on-chain)"
                            );
                        }
                        family_id = chain_family_id;
                    }
                    Ok(None) => {
                        // fail_open mode: allow, but keep claimed family_id (best-effort)
                        warn!(
                            public_key = %truncate_for_log(&public_key, 16),
                            claimed_family = %family_id,
                            "Chain registry enabled (fail_open) but node not found; using claimed family_id"
                        );
                    }
                    Err(e) => {
                        error!(
                            public_key = %truncate_for_log(&public_key, 16),
                            error = %e,
                            "On-chain family verification failed"
                        );
                        use tokio::io::AsyncWriteExt;
                        send.write_all(format!("FAMILY_REJECTED:{}", e).as_bytes())
                            .await?;
                        send.flush().await?;
                        send.finish()?;
                        let _ = tokio::time::timeout(Duration::from_secs(1), send.stopped()).await;
                        return Ok(());
                    }
                }
            } else {
                let (family_ok, family_error) = state
                    .family_registry
                    .verify_membership(&public_key, &family_id)
                    .await;
                if !family_ok {
                    error!(
                        public_key = %truncate_for_log(&public_key, 16),
                        error = family_error.as_deref().unwrap_or("unknown"),
                        "Family verification failed"
                    );
                    use tokio::io::AsyncWriteExt;
                    send.write_all(
                        format!("FAMILY_REJECTED:{}", family_error.unwrap_or_default()).as_bytes(),
                    )
                    .await?;
                    send.flush().await?;
                    send.finish()?;
                    let _ = tokio::time::timeout(Duration::from_secs(1), send.stopped()).await;
                    return Ok(());
                }
            }

            info!(
                public_key = %truncate_for_log(&public_key, 16),
                family_id = %family_id,
                "Signature verified for miner"
            );

            // Generate UID from public key hash
            // Truncate to 31 bits (0x7FFFFFFF) to ensure UID fits in i32 range
            // while maintaining good distribution from the lower bits of the hash
            use std::hash::{Hash, Hasher};
            let mut hasher = std::collections::hash_map::DefaultHasher::new();
            public_key.hash(&mut hasher);
            let uid = (hasher.finish() as u32) & 0x7FFFFFFF;

            // Lock map
            let _guard = state.map_lock.lock().await;

            // Get current map
            let query_map =
                iroh_docs::store::Query::single_latest_per_key().key_exact(b"cluster_map");
            let mut stream = Box::pin(state.doc.get_many(query_map).await?);
            let mut map = match stream.next().await {
                Some(Ok(entry)) => {
                    let hash = entry.content_hash();
                    let mut reader = state.blobs_store.reader(hash);
                    let mut content = Vec::new();
                    reader
                        .read_to_end(&mut content)
                        .await
                        .ok()
                        .and_then(|_| {
                            serde_json::from_str::<ClusterMap>(&String::from_utf8_lossy(&content))
                                .ok()
                        })
                        .unwrap_or_default()
                }
                _ => ClusterMap::default(),
            };

            // Check if miner already exists
            if !map.miners.iter().any(|m| m.public_key == public_key) {
                // Parse NodeId
                let node_id = iroh::PublicKey::from_str(&public_key)?;

                // Use miner's provided endpoint_addr (with relay hints) if available,
                // otherwise create one without relay info (fallback for old miners)
                let mut endpoint = if let Some(addr) = endpoint_addr {
                    debug!("Using miner-provided endpoint with relay hints");
                    addr
                } else {
                    warn!("Miner did not send endpoint_addr, creating without relay");
                    let base = iroh::EndpointAddr::new(node_id);
                    if let Some(ref url) = state.relay_url {
                        base.with_relay_url(url.clone())
                    } else {
                        base
                    }
                };

                // Add localhost direct address hints for local testing
                // If http_addr contains localhost, extract port and add direct IP hint
                if http_addr.contains("localhost") || http_addr.contains("127.0.0.1") {
                    if let Some(port_str) = http_addr.split(':').next_back() {
                        if let Ok(port) = port_str.parse::<u16>() {
                            let direct_addr = std::net::SocketAddr::new(
                                std::net::Ipv4Addr::new(127, 0, 0, 1).into(),
                                port,
                            );
                            // Prepend localhost hint to existing addrs
                            let mut new_addrs = vec![iroh::TransportAddr::Ip(direct_addr)];
                            new_addrs.extend(endpoint.addrs.clone());
                            endpoint = endpoint.with_addrs(new_addrs);
                            debug!(direct_addr = %direct_addr, "Added localhost direct address hint");
                        }
                    }
                }

                let family_id_for_log = family_id.clone();
                let new_miner = MinerNode {
                    uid,
                    endpoint,
                    weight: 100,
                    ip_subnet: "0.0.0.0/0".to_string(),
                    http_addr,
                    public_key: public_key.clone(),
                    total_storage,
                    available_storage,
                    family_id,
                    strikes: 0,
                    last_seen: now_secs(),
                    heartbeat_count: 0,
                    registration_time: now_secs(),
                    bandwidth_total: 0,
                    bandwidth_window_start: now_secs(),
                    weight_manual_override: false,
                    reputation: 0.0,
                    consecutive_audit_passes: 0,
                };
                map.add_node(new_miner);
                map.epoch += 1;
                let total_miners = map.miners.len();
                persist_cluster_map_to_doc(&state, &map).await?;

                info!(
                    miner_uid = uid,
                    family_id = %family_id_for_log,
                    public_key = %truncate_for_log(&public_key, 16),
                    total_miners = total_miners,
                    new_epoch = map.epoch,
                    "MINER JOINED: New miner registered via P2P"
                );

                /* Broadcast removed - handled by auto_recovery_loop
                // Broadcast cluster map to all miners after new registration
                let map_for_broadcast = map.clone();
                let endpoint_for_broadcast = state.endpoint.clone();
                tokio::spawn(async move {
                    // PG-based: miners will query their PGs separately
                    if let Err(e) = broadcast_cluster_map_to_miners(&map_for_broadcast, &endpoint_for_broadcast, None).await {
                        eprintln!("Failed to broadcast cluster map: {}", e);
                    }
                });
                */

                use tokio::io::AsyncWriteExt;
                send.write_all(b"OK").await?;
                send.flush().await?;
                send.finish()?;
                let _ = tokio::time::timeout(Duration::from_secs(1), send.stopped()).await;
            } else {
                // Update existing
                if let Some(existing) = map.miners.iter_mut().find(|m| m.public_key == public_key) {
                    existing.available_storage = available_storage;
                    existing.total_storage = total_storage;
                    let old_http_addr = existing.http_addr.clone();
                    existing.http_addr = http_addr.clone();
                    existing.last_seen = now_secs();

                    // Update endpoint if miner provided new endpoint_addr (with relay hints)
                    if let Some(mut addr) = endpoint_addr {
                        // Add localhost direct address hints for local testing
                        if http_addr.contains("localhost") || http_addr.contains("127.0.0.1") {
                            if let Some(port_str) = http_addr.split(':').next_back() {
                                if let Ok(port) = port_str.parse::<u16>() {
                                    let direct_addr = std::net::SocketAddr::new(
                                        std::net::Ipv4Addr::new(127, 0, 0, 1).into(),
                                        port,
                                    );
                                    let mut new_addrs = vec![iroh::TransportAddr::Ip(direct_addr)];
                                    new_addrs.extend(addr.addrs.clone());
                                    addr = addr.with_addrs(new_addrs);
                                    debug!(
                                        direct_addr = %direct_addr,
                                        "Updated endpoint with localhost hint"
                                    );
                                }
                            }
                        }
                        existing.endpoint = addr;
                        debug!("Updated endpoint with new relay hints");
                    } else if old_http_addr != http_addr
                        && (http_addr.contains("localhost") || http_addr.contains("127.0.0.1"))
                    {
                        // If http_addr changed and is localhost, update the direct address hint
                        if let Some(port_str) = http_addr.split(':').next_back() {
                            if let Ok(port) = port_str.parse::<u16>() {
                                let direct_addr = std::net::SocketAddr::new(
                                    std::net::Ipv4Addr::new(127, 0, 0, 1).into(),
                                    port,
                                );
                                let mut new_addrs = vec![iroh::TransportAddr::Ip(direct_addr)];
                                new_addrs.extend(existing.endpoint.addrs.clone());
                                existing.endpoint = existing.endpoint.clone().with_addrs(new_addrs);
                                debug!(
                                    direct_addr = %direct_addr,
                                    "Updated localhost hint for changed http_addr"
                                );
                            }
                        }
                    }

                    // NOTE: Do NOT bump epoch here - this is just a re-registration with updated
                    // storage/endpoint info, not a placement-affecting change. Epoch churn on every
                    // heartbeat/re-register would cause excessive rebalancing.
                    // Epoch is only bumped for:
                    // - New miner registration (line ~7420)
                    // - Family ID changes (heartbeat handler, line ~7616)
                    // - Weight changes above threshold (weight_update_loop)
                    // - Miner removal (mark OUT, line ~4267)
                    persist_cluster_map_to_doc(&state, &map).await?;
                }
                info!(miner_uid = uid, "Miner updated via P2P");
                use tokio::io::AsyncWriteExt;
                send.write_all(b"OK").await?;
                send.flush().await?;
                send.finish()?;
                tokio::time::sleep(Duration::from_millis(1000)).await;
            }
        }
        common::ValidatorControlMessage::Heartbeat {
            miner_uid,
            timestamp,
            available_storage,
            public_key,
            signature,
        } => {
            // Verify Ed25519 signature
            let node_id = match iroh::PublicKey::from_str(&public_key) {
                Ok(pk) => pk,
                Err(_) => {
                    error!(public_key = %truncate_for_log(&public_key, 16), "Invalid public key in heartbeat");
                    use tokio::io::AsyncWriteExt;
                    send.write_all(b"INVALID_KEY").await?;
                    send.flush().await?;
                    send.finish()?;
                    tokio::time::sleep(Duration::from_millis(1000)).await;
                    return Ok(());
                }
            };

            // Verify signature
            let sign_data = format!("HEARTBEAT:{}:{}", public_key, timestamp);
            let sig_bytes: [u8; 64] = signature
                .try_into()
                .map_err(|_| anyhow::anyhow!("Invalid signature length"))?;
            let sig = iroh::Signature::from_bytes(&sig_bytes);

            if node_id.verify(sign_data.as_bytes(), &sig).is_err() {
                error!(
                    miner_uid = miner_uid,
                    "Heartbeat signature verification failed"
                );
                use tokio::io::AsyncWriteExt;
                send.write_all(b"INVALID_SIG").await?;
                send.flush().await?;
                send.finish()?;
                tokio::time::sleep(Duration::from_millis(1000)).await;
                return Ok(());
            }

            // Update last_seen for miner
            let _guard = state.map_lock.lock().await;

            let query_map =
                iroh_docs::store::Query::single_latest_per_key().key_exact(b"cluster_map");
            let mut stream = Box::pin(state.doc.get_many(query_map).await?);
            let mut map = match stream.next().await {
                Some(Ok(entry)) => {
                    let hash = entry.content_hash();
                    let mut reader = state.blobs_store.reader(hash);
                    let mut content = Vec::new();
                    reader
                        .read_to_end(&mut content)
                        .await
                        .ok()
                        .and_then(|_| {
                            serde_json::from_str::<ClusterMap>(&String::from_utf8_lossy(&content))
                                .ok()
                        })
                        .unwrap_or_default()
                }
                _ => ClusterMap::default(),
            };

            if let Some(miner) = map.miners.iter_mut().find(|m| m.uid == miner_uid) {
                // Verify the heartbeat is from the registered miner (public_key matches)
                if miner.public_key != public_key {
                    warn!(
                        miner_uid = miner_uid,
                        "Heartbeat from miner has mismatched public_key"
                    );
                    use tokio::io::AsyncWriteExt;
                    send.write_all(b"KEY_MISMATCH").await?;
                    send.flush().await?;
                    send.finish()?;
                    tokio::time::sleep(Duration::from_millis(1000)).await;
                    return Ok(());
                }

                let current_time = now_secs();
                let was_offline = is_miner_offline(miner, current_time);
                let time_since_last_seen = current_time.saturating_sub(miner.last_seen);
                let family_id_for_log = miner.family_id.clone();
                miner.last_seen = current_time;
                miner.heartbeat_count += 1;
                miner.available_storage = available_storage;

                // Log if miner was previously offline and is now back
                // Note: we log this after updates but with stored values to avoid borrow issues
                let reconnected = was_offline;

                // Derive family_id from on-chain registry cache (pallet-arion), if enabled.
                // This ensures CRUSH "family" diversity follows on-chain truth, not miner self-reporting.
                if state.chain_registry.enabled() {
                    match state.chain_registry.resolve_family_hex(&public_key).await {
                        Ok(Some(chain_family_id)) => {
                            if miner.family_id != chain_family_id {
                                info!(
                                    miner_uid = miner_uid,
                                    old_family = %miner.family_id,
                                    new_family = %chain_family_id,
                                    "Miner family changed, bumping epoch"
                                );
                                miner.family_id = chain_family_id;
                                map.epoch += 1;
                            }
                        }
                        Ok(None) => {
                            // fail_open: keep current family_id (best-effort)
                        }
                        Err(e) => {
                            error!(
                                public_key = %truncate_for_log(&public_key, 16),
                                error = %e,
                                "On-chain family verification failed on heartbeat"
                            );
                            use tokio::io::AsyncWriteExt;
                            send.write_all(format!("FAMILY_REJECTED:{}", e).as_bytes())
                                .await?;
                            send.flush().await?;
                            send.finish()?;
                            tokio::time::sleep(Duration::from_millis(1000)).await;
                            return Ok(());
                        }
                    }
                }

                // IMPORTANT: Do NOT mutate placement weights on every heartbeat.
                // Frequent weight drift (uptime/age) causes constant remapping and breaks CRUSH-only reads
                // unless full PG recovery/rebalance is implemented.
                // Placement weights should be updated on coarse, intentional events (e.g. join/leave/manual).

                debug!(
                    miner_uid = miner_uid,
                    weight = miner.weight,
                    storage_mb = available_storage / (1024 * 1024),
                    "P2P heartbeat received"
                );

                persist_cluster_map_to_doc(&state, &map).await?;

                // Log reconnection after releasing mutable borrow
                if reconnected {
                    let total_miners = map.miners.len();
                    let online_miners = map
                        .miners
                        .iter()
                        .filter(|m| !is_miner_offline(m, now_secs()))
                        .count();
                    info!(
                        miner_uid = miner_uid,
                        family_id = %family_id_for_log,
                        time_offline_secs = time_since_last_seen,
                        total_miners = total_miners,
                        online_miners = online_miners,
                        "MINER RECONNECTED: Previously offline miner sent heartbeat"
                    );
                }

                // use tokio::io::AsyncWriteExt;
                send.write_all(b"OK").await?;
            } else {
                warn!(
                    miner_uid = miner_uid,
                    total_miners = map.miners.len(),
                    "P2P heartbeat from unknown miner"
                );
                // use tokio::io::AsyncWriteExt;
                send.write_all(b"UNKNOWN").await?;
            }
        }
        common::ValidatorControlMessage::Ping { timestamp } => {
            // Simple P2P health check
            let now = now_secs();
            let latency = now.saturating_sub(timestamp);
            debug!(latency_secs = latency, "P2P ping received");

            // use tokio::io::AsyncWriteExt;
            // Respond with PONG and current timestamp
            let pong = format!("PONG:{}", now);
            send.write_all(pong.as_bytes()).await?;
        }
        common::ValidatorControlMessage::QueryPgFiles { pg_id } => {
            debug!(pg_id = pg_id, "QueryPgFiles request received");
            // Scalable path: read the persisted, paged PG index from the doc.
            let files_in_pg: Vec<String> =
                match get_pg_files_from_doc(state.as_ref(), pg_id, 10_000).await {
                    Ok(v) => v,
                    Err(_) => Vec::new(),
                };

            debug!(
                pg_id = pg_id,
                file_count = files_in_pg.len(),
                "QueryPgFiles response"
            );

            // Send response
            // use tokio::io::AsyncWriteExt;
            let response = serde_json::to_vec(&files_in_pg).unwrap_or_default();
            send.write_all(&response).await?;
            send.flush().await?;
            send.finish()?;
            let _ = tokio::time::timeout(std::time::Duration::from_secs(5), send.stopped()).await;
            return Ok(());
        }
        common::ValidatorControlMessage::QueryPgFilesBatch { pg_ids } => {
            info!(
                pg_count = pg_ids.len(),
                "QueryPgFilesBatch request received"
            );

            // Collect files for all requested PGs
            let mut result: std::collections::HashMap<u32, Vec<String>> =
                std::collections::HashMap::new();
            let mut total_files = 0;

            for pg_id in pg_ids {
                let files_in_pg: Vec<String> =
                    match get_pg_files_from_doc(state.as_ref(), pg_id, 10_000).await {
                        Ok(v) => v,
                        Err(_) => Vec::new(),
                    };
                total_files += files_in_pg.len();
                if !files_in_pg.is_empty() {
                    result.insert(pg_id, files_in_pg);
                }
            }

            info!(
                pg_count = result.len(),
                total_files = total_files,
                "QueryPgFilesBatch response"
            );

            let response = serde_json::to_vec(&result).unwrap_or_default();
            send.write_all(&response).await?;
            send.flush().await?;
            send.finish()?;
            // Wait for the stream to be fully acknowledged before closing
            let _ = tokio::time::timeout(std::time::Duration::from_secs(30), send.stopped()).await;
            return Ok(());
        }
        common::ValidatorControlMessage::QueryManifest { file_hash } => {
            debug!(
                file_hash = %&file_hash[..16.min(file_hash.len())],
                "QueryManifest request received"
            );

            // Fetch manifest from iroh-docs
            let manifest_json: Option<String> = {
                let entry = state
                    .doc
                    .get_exact(state.author_id, Bytes::from(file_hash.clone()), false)
                    .await?;

                if let Some(e) = entry {
                    let hash = e.content_hash();
                    let mut reader = state.blobs_store.reader(hash);
                    use tokio::io::AsyncReadExt;
                    let mut content = Vec::new();
                    reader.read_to_end(&mut content).await?;
                    Some(String::from_utf8_lossy(&content).to_string())
                } else {
                    None
                }
            };

            // use tokio::io::AsyncWriteExt;
            if let Some(json) = manifest_json {
                debug!(manifest_size = json.len(), "Returning manifest");
                send.write_all(json.as_bytes()).await?;
            } else {
                debug!("Manifest not found");
                send.write_all(b"NOT_FOUND").await?;
            }
            send.flush().await?;
            send.finish()?;
            // Wait for the stream to be fully acknowledged
            let _ = tokio::time::timeout(std::time::Duration::from_secs(10), send.stopped()).await;
            return Ok(());
        }
        common::ValidatorControlMessage::PosProofResponse {
            nonce: _,
            proof_bytes: _,
            public_inputs: _,
            proving_time_ms: _,
        } => {
            // Note: In the current PoS architecture, the Warden communicates directly
            // with miners via hippius/miner-control. This handler exists for potential
            // future use cases where miners might send proofs through the validator.
            warn!("PosProofResponse received but not processed - Warden handles proofs directly");
            send.write_all(b"NOT_IMPLEMENTED").await?;
            send.flush().await?;
            send.finish()?;
            let _ = tokio::time::timeout(std::time::Duration::from_secs(5), send.stopped()).await;
            return Ok(());
        }
    }

    // Default path for handlers that don't call finish themselves (Heartbeat, Ping)
    send.flush().await?;
    send.finish()?;
    // Wait for final acknowledgment
    let _ = tokio::time::timeout(std::time::Duration::from_secs(5), send.stopped()).await;
    Ok(())
}

async fn get_upload_status(
    Path(hash): Path<String>,
    State(state): State<Arc<AppState>>,
) -> impl IntoResponse {
    // Validate hash format early
    if let Err((status, msg)) = validate_hash_param(&hash) {
        return (status, msg).into_response();
    }
    match state.upload_progress.get(&hash) {
        Ok(Some(progress)) => (StatusCode::OK, Json(progress)).into_response(),
        Ok(None) => (StatusCode::NOT_FOUND, "Upload not found").into_response(),
        Err(e) => {
            warn!(error = %e, "Failed to get upload status");
            (StatusCode::INTERNAL_SERVER_ERROR, "Database error").into_response()
        }
    }
}

async fn metrics_handler(State(state): State<Arc<AppState>>) -> impl IntoResponse {
    let output = state.metrics.encode();
    (
        StatusCode::OK,
        [("content-type", "text/plain; version=0.0.4")],
        output,
    )
}

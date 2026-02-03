//! Prometheus metrics for the validator.
//!
//! This module defines all metrics exported at the `/metrics` endpoint.
//!
//! # Metric Categories
//!
//! - **Miner Stats**: Miner counts (online/offline), storage capacity/usage
//! - **Operations**: Recovery attempts, rebalance triggers, rebuild progress
//! - **System**: Active file count, total stored data
//! - **Blob Backup**: Incremental blob backup to S3
//!
//! # Usage
//!
//! Metrics are updated throughout the validator codebase:
//! - `miner_count`: Updated when miners register/heartbeat/go offline
//! - `recovery_ops`: Incremented after each recovery attempt (success/fail)
//! - `rebuild_*`: Updated by the automatic rebuild agent
//! - `blob_backup_*`: Updated by the blob backup scheduler
//!
//! # Scraping
//!
//! Configure Prometheus to scrape `http://validator:3002/metrics` at your desired interval.

use prometheus_client::encoding::text::encode;
use prometheus_client::metrics::counter::Counter;
use prometheus_client::metrics::family::Family;
use prometheus_client::metrics::gauge::Gauge;
use prometheus_client::metrics::histogram::{Histogram, exponential_buckets};
use prometheus_client::registry::Registry;
use std::sync::atomic::AtomicU64;
use std::sync::{Arc, Mutex};
use tracing::error;

/// Prometheus metrics collection for the validator.
///
/// All metrics are registered with the Prometheus registry on construction
/// and can be scraped via the `/metrics` HTTP endpoint.
#[derive(Clone)]
#[allow(dead_code)]
pub struct Metrics {
    pub registry: Arc<Mutex<Registry>>,

    // Miner Stats
    pub miner_count: Family<[(String, String); 1], Gauge>, // Label: status (online/offline)
    pub total_storage: Gauge<f64, AtomicU64>,
    pub used_storage: Gauge<f64, AtomicU64>,
    pub bandwidth_total: Counter,

    // Operations
    pub recovery_ops: Family<[(String, String); 1], Counter>, // Label: result (success/fail)
    pub rebalance_ops: Counter,
    pub rebalance_queue_depth: Gauge,
    pub pull_from_peer_sent: Counter,
    pub rebuild_stripes_recovered: Counter,
    pub rebuild_stripes_failed: Counter,
    pub rebuild_shards_pushed: Counter,
    pub rebuild_inflight: Gauge,
    pub admin_ops_total: Counter,

    // System
    pub file_count: Gauge,
    pub total_stored_data: Gauge<f64, AtomicU64>, // Actual file size sum

    // P2P Protocols
    /// P2P requests received by protocol and message type
    pub p2p_requests_total: Family<[(String, String); 2], Counter>,
    /// P2P request errors by protocol
    pub p2p_request_errors_total: Family<[(String, String); 1], Counter>,
    /// Active P2P connections per protocol
    pub p2p_connections_active: Family<[(String, String); 1], Gauge>,

    // Blob Backup
    /// Total blobs backed up to S3
    pub blob_backup_blobs_total: Counter,
    /// Total bytes backed up to S3
    pub blob_backup_bytes_total: Counter,
    /// Blob backup errors
    pub blob_backup_errors_total: Counter,
    /// Unix timestamp of last successful sync
    pub blob_backup_last_sync_timestamp: Gauge,
    /// Blobs pending backup in current sync
    pub blob_backup_pending_blobs: Gauge,
    /// Sync cycle duration in seconds
    pub blob_backup_sync_duration_seconds: Histogram,
}

impl Metrics {
    pub fn new() -> Self {
        let mut registry = Registry::default();

        let miner_count = Family::<[(String, String); 1], Gauge>::default();
        registry.register(
            "miner_count",
            "Number of miners connected",
            miner_count.clone(),
        );

        let total_storage = Gauge::default();
        registry.register(
            "cluster_storage_capacity_bytes",
            "Total storage capacity across all miners",
            total_storage.clone(),
        );

        let used_storage = Gauge::default();
        registry.register(
            "cluster_storage_used_bytes",
            "Total storage used across all miners",
            used_storage.clone(),
        );

        let bandwidth_total = Counter::default();
        registry.register(
            "total_bandwidth_bytes",
            "Total bandwidth served by cluster",
            bandwidth_total.clone(),
        );

        let recovery_ops = Family::<[(String, String); 1], Counter>::default();
        registry.register(
            "recovery_operations_total",
            "Number of file recovery attempts",
            recovery_ops.clone(),
        );

        let rebalance_ops = Counter::default();
        registry.register(
            "rebalance_operations_total",
            "Number of automatic rebalance triggers",
            rebalance_ops.clone(),
        );

        let rebalance_queue_depth = Gauge::default();
        registry.register(
            "rebalance_queue_depth",
            "Number of PGs queued for rebalance",
            rebalance_queue_depth.clone(),
        );

        let pull_from_peer_sent = Counter::default();
        registry.register(
            "pull_from_peer_sent_total",
            "Number of PullFromPeer commands sent by validator",
            pull_from_peer_sent.clone(),
        );

        let rebuild_stripes_recovered = Counter::default();
        registry.register(
            "rebuild_stripes_recovered_total",
            "Number of stripes successfully rebuilt (k+m restored)",
            rebuild_stripes_recovered.clone(),
        );

        let rebuild_stripes_failed = Counter::default();
        registry.register(
            "rebuild_stripes_failed_total",
            "Number of stripes that failed rebuild",
            rebuild_stripes_failed.clone(),
        );

        let rebuild_shards_pushed = Counter::default();
        registry.register(
            "rebuild_shards_pushed_total",
            "Number of reconstructed shards pushed during rebuild",
            rebuild_shards_pushed.clone(),
        );

        let rebuild_inflight = Gauge::default();
        registry.register(
            "rebuild_inflight",
            "Number of file rebuild tasks currently in progress",
            rebuild_inflight.clone(),
        );

        let admin_ops_total = Counter::default();
        registry.register(
            "admin_ops_total",
            "Number of authenticated admin operations executed",
            admin_ops_total.clone(),
        );

        let file_count = Gauge::default();
        registry.register(
            "active_files_count",
            "Number of active files tracked by validator",
            file_count.clone(),
        );

        let total_stored_data = Gauge::default();
        registry.register(
            "active_data_stored_bytes",
            "Total size of active files (replicated)",
            total_stored_data.clone(),
        );

        // P2P metrics
        let p2p_requests_total = Family::<[(String, String); 2], Counter>::default();
        registry.register(
            "p2p_requests_total",
            "Total P2P requests received by protocol and message type",
            p2p_requests_total.clone(),
        );

        let p2p_request_errors_total = Family::<[(String, String); 1], Counter>::default();
        registry.register(
            "p2p_request_errors_total",
            "Total P2P request errors by protocol",
            p2p_request_errors_total.clone(),
        );

        let p2p_connections_active = Family::<[(String, String); 1], Gauge>::default();
        registry.register(
            "p2p_connections_active",
            "Active P2P connections per protocol",
            p2p_connections_active.clone(),
        );

        // Blob Backup metrics
        let blob_backup_blobs_total = Counter::default();
        registry.register(
            "blob_backup_blobs_total",
            "Total blobs backed up to S3",
            blob_backup_blobs_total.clone(),
        );

        let blob_backup_bytes_total = Counter::default();
        registry.register(
            "blob_backup_bytes_total",
            "Total bytes backed up to S3",
            blob_backup_bytes_total.clone(),
        );

        let blob_backup_errors_total = Counter::default();
        registry.register(
            "blob_backup_errors_total",
            "Total blob backup errors",
            blob_backup_errors_total.clone(),
        );

        let blob_backup_last_sync_timestamp = Gauge::default();
        registry.register(
            "blob_backup_last_sync_timestamp",
            "Unix timestamp of last successful blob backup sync",
            blob_backup_last_sync_timestamp.clone(),
        );

        let blob_backup_pending_blobs = Gauge::default();
        registry.register(
            "blob_backup_pending_blobs",
            "Number of blobs pending backup in current sync cycle",
            blob_backup_pending_blobs.clone(),
        );

        // Histogram with buckets: 1, 2, 4, 8, 16, 32, 64, 128, 256, 512 seconds
        let blob_backup_sync_duration_seconds = Histogram::new(exponential_buckets(1.0, 2.0, 10));
        registry.register(
            "blob_backup_sync_duration_seconds",
            "Duration of blob backup sync cycles in seconds",
            blob_backup_sync_duration_seconds.clone(),
        );

        Self {
            registry: Arc::new(Mutex::new(registry)),
            miner_count,
            total_storage,
            used_storage,
            bandwidth_total,
            recovery_ops,
            rebalance_ops,
            rebalance_queue_depth,
            pull_from_peer_sent,
            rebuild_stripes_recovered,
            rebuild_stripes_failed,
            rebuild_shards_pushed,
            rebuild_inflight,
            admin_ops_total,
            file_count,
            total_stored_data,
            p2p_requests_total,
            p2p_request_errors_total,
            p2p_connections_active,
            blob_backup_blobs_total,
            blob_backup_bytes_total,
            blob_backup_errors_total,
            blob_backup_last_sync_timestamp,
            blob_backup_pending_blobs,
            blob_backup_sync_duration_seconds,
        }
    }

    pub fn encode(&self) -> String {
        let mut buffer = String::new();
        let registry = match self.registry.lock() {
            Ok(r) => r,
            Err(e) => {
                error!(error = %e, "Failed to acquire metrics registry lock");
                return buffer;
            }
        };
        if let Err(e) = encode(&mut buffer, &registry) {
            error!(error = %e, "Failed to encode metrics");
            return String::new();
        }
        buffer
    }
}

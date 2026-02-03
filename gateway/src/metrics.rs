//! Prometheus metrics for the gateway.
//!
//! This module defines all metrics exported at the `/metrics` endpoint.
//!
//! # Metric Categories
//!
//! - **HTTP**: Request counts by method/status, request duration histograms
//! - **Transfer**: Upload/download byte counters, active upload/download gauges
//! - **Scalability**: Cache hits/misses, connection pool size
//!
//! # Key Metrics
//!
//! | Metric | Type | Description |
//! |--------|------|-------------|
//! | `gateway_http_requests_total` | Counter | Total requests by method/status |
//! | `gateway_request_duration_seconds` | Histogram | Request latency distribution |
//! | `gateway_cache_hits_total` | Counter | Blob cache hits |
//! | `gateway_cache_misses_total` | Counter | Blob cache misses |
//! | `gateway_connection_pool_size` | Gauge | Current P2P connection pool size |
//! | `gateway_active_downloads` | Gauge | In-flight download requests |
//!
//! # Scraping
//!
//! Configure Prometheus to scrape `http://gateway:3000/metrics` at your desired interval.

use parking_lot::RwLock;
use prometheus_client::encoding::text::encode;
use prometheus_client::metrics::counter::Counter;
use prometheus_client::metrics::family::Family;
use prometheus_client::metrics::gauge::Gauge;
use prometheus_client::metrics::histogram::{Histogram, exponential_buckets};
use prometheus_client::registry::Registry;
use std::sync::Arc;

/// Prometheus metrics collection for the gateway.
///
/// All metrics are registered with the Prometheus registry on construction
/// and can be scraped via the `/metrics` HTTP endpoint.
///
/// Uses `parking_lot::RwLock` for the registry to allow non-blocking
/// concurrent reads during metric encoding.
#[derive(Clone)]
#[allow(dead_code)]
pub struct Metrics {
    pub registry: Arc<RwLock<Registry>>,
    pub http_requests: Family<[(String, String); 2], Counter>, // method, status
    pub http_duration: Family<[(String, String); 1], Histogram>, // method
    pub upload_bytes: Counter,
    pub download_bytes: Counter,
    pub active_uploads: Gauge,
    // Scalability metrics
    pub cache_hits: Counter,
    pub cache_misses: Counter,
    pub connection_pool_size: Gauge,
    pub active_downloads: Gauge,
}

impl Metrics {
    pub fn new() -> Self {
        let mut registry = Registry::default();

        let http_requests = Family::<[(String, String); 2], Counter>::default();
        registry.register(
            "gateway_http_requests_total",
            "Total HTTP requests handled",
            http_requests.clone(),
        );

        let http_duration =
            Family::<[(String, String); 1], Histogram>::new_with_constructor(|| {
                Histogram::new(exponential_buckets(0.1, 2.0, 10))
            });
        registry.register(
            "gateway_request_duration_seconds",
            "HTTP request duration",
            http_duration.clone(),
        );

        let upload_bytes = Counter::default();
        registry.register(
            "gateway_upload_bytes_total",
            "Total bytes uploaded",
            upload_bytes.clone(),
        );

        let download_bytes = Counter::default();
        registry.register(
            "gateway_download_bytes_total",
            "Total bytes downloaded",
            download_bytes.clone(),
        );

        let active_uploads = Gauge::default();
        registry.register(
            "gateway_active_uploads",
            "Number of currently active uploads",
            active_uploads.clone(),
        );

        let cache_hits = Counter::default();
        registry.register(
            "gateway_cache_hits_total",
            "Total blob cache hits",
            cache_hits.clone(),
        );

        let cache_misses = Counter::default();
        registry.register(
            "gateway_cache_misses_total",
            "Total blob cache misses",
            cache_misses.clone(),
        );

        let connection_pool_size = Gauge::default();
        registry.register(
            "gateway_connection_pool_size",
            "Current size of the P2P connection pool",
            connection_pool_size.clone(),
        );

        let active_downloads = Gauge::default();
        registry.register(
            "gateway_active_downloads",
            "Number of currently active downloads",
            active_downloads.clone(),
        );

        Self {
            registry: Arc::new(RwLock::new(registry)),
            http_requests,
            http_duration,
            upload_bytes,
            download_bytes,
            active_uploads,
            cache_hits,
            cache_misses,
            connection_pool_size,
            active_downloads,
        }
    }

    pub fn encode(&self) -> String {
        let mut buffer = String::new();
        // Use read lock - multiple readers allowed, non-blocking with parking_lot
        let registry = self.registry.read();
        // Handle encoding errors gracefully instead of panicking
        if let Err(e) = encode(&mut buffer, &registry) {
            tracing::error!(error = %e, "Failed to encode Prometheus metrics");
            return format!("# Error encoding metrics: {}", e);
        }
        buffer
    }
}

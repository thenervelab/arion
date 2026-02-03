//! Utility functions for the gateway.
//!
//! This module provides shared helper functions used across gateway handlers.
//!
//! # Categories
//!
//! - **HTTP Parsing**: Range header parsing, content type detection
//! - **Connection Pool**: P2P connection reuse with TTL and health checks
//! - **Key Management**: Keypair loading and generation
//! - **Rebalance**: PG settlement status checking with caching
//!
//! # Connection Pool Design
//!
//! The gateway maintains a pool of P2P connections to miners:
//! - Connections are keyed by `miner_uid`
//! - TTL is 60 seconds (from `CONNECTION_TTL_SECS`)
//! - Health checks use `conn.closed().now_or_never()` to detect stale connections
//! - Double-check locking prevents race conditions during connection creation
//!
//! # Rebalance Status Caching
//!
//! The `is_pg_settled()` function caches validator queries to reduce HTTP load:
//! - Cache TTL is 30 seconds
//! - Returns `true` on error (safe fallback to current epoch CRUSH)

use crate::config::{
    CONNECTION_POOL_CLEANUP_THRESHOLD, CONNECTION_TTL_SECS, REBALANCE_STATUS_CACHE_TTL_SECS,
};
use anyhow::Result;
use axum::http::{HeaderMap, StatusCode};
use common::now_secs;
use dashmap::DashMap;
use futures::FutureExt;
use iroh::SecretKey;
use std::collections::HashMap;
use std::sync::Arc;
use std::time::Duration;
use tracing::{debug, error};

/// Parsed HTTP Range header result
pub struct ByteRange {
    pub start: u64,
    pub end: u64,
    pub is_range_request: bool,
}

/// Parse HTTP Range header into start/end byte positions
///
/// Supports RFC 7233 range formats:
/// - `bytes=0-499`: First 500 bytes
/// - `bytes=500-`: From byte 500 to end
/// - `bytes=-500`: Last 500 bytes (suffix range)
///
/// Note: Multi-range requests (e.g., `bytes=0-100,200-300`) are not supported
/// and will be treated as invalid, returning the full file.
pub fn parse_range_header(headers: &HeaderMap, file_size: u64) -> ByteRange {
    // Handle zero-size files
    if file_size == 0 {
        return ByteRange {
            start: 0,
            end: 0,
            is_range_request: false,
        };
    }

    let max_end = file_size - 1;

    let (start, end, is_range_request) = headers
        .get("range")
        .and_then(|h| h.to_str().ok())
        .and_then(|s| s.strip_prefix("bytes="))
        .and_then(|range_val| {
            // Multi-range not supported - reject if contains comma
            if range_val.contains(',') {
                return None;
            }

            let parts: Vec<&str> = range_val.split('-').collect();
            if parts.len() != 2 {
                return None;
            }

            // Handle suffix range: bytes=-N (last N bytes)
            if parts[0].is_empty() {
                // Suffix range: bytes=-500 means last 500 bytes
                let suffix_len: u64 = parts[1].parse().ok()?;
                if suffix_len == 0 {
                    return None;
                }
                let start = file_size.saturating_sub(suffix_len);
                return Some((start, max_end, true));
            }

            // Normal range: bytes=start-end or bytes=start-
            let start: u64 = parts[0].parse().ok()?;
            let end = if parts[1].is_empty() {
                max_end
            } else {
                parts[1].parse().ok()?
            };
            Some((start, end, true))
        })
        .unwrap_or((0, max_end, false));

    // Clamp start and end to valid range
    ByteRange {
        start: start.min(max_end),
        end: end.min(max_end),
        is_range_request,
    }
}

/// Detect content type from filename extension
pub fn detect_content_type(filename: Option<&str>) -> String {
    const MIME_TYPES: &[(&str, &str)] = &[
        ("mp4", "video/mp4"),
        ("mkv", "video/x-matroska"),
        ("webm", "video/webm"),
        ("jpg", "image/jpeg"),
        ("jpeg", "image/jpeg"),
        ("png", "image/png"),
        ("gif", "image/gif"),
        ("pdf", "application/pdf"),
        ("html", "text/html"),
        ("htm", "text/html"),
        ("css", "text/css"),
        ("js", "application/javascript"),
        ("json", "application/json"),
        ("xml", "application/xml"),
        ("txt", "text/plain"),
        ("zip", "application/zip"),
        ("tar", "application/x-tar"),
        ("gz", "application/gzip"),
    ];

    filename
        .and_then(|name| name.rsplit('.').next())
        .and_then(|ext| {
            let ext_lower = ext.to_lowercase();
            MIME_TYPES
                .iter()
                .find(|(e, _)| *e == ext_lower)
                .map(|(_, mime)| *mime)
        })
        .unwrap_or("application/octet-stream")
        .to_string()
}

/// Sanitize a filename for use in Content-Disposition header.
///
/// Removes or replaces characters that could cause header injection or parsing issues:
/// - Quotes, backslashes, control characters, newlines
/// - Non-ASCII characters replaced with underscore
/// - Limits length to prevent header overflow
pub fn sanitize_filename(filename: &str) -> String {
    const MAX_FILENAME_LEN: usize = 255;

    let sanitized: String = filename
        .chars()
        .filter_map(|c| {
            match c {
                // Allow alphanumeric, dots, hyphens, underscores, spaces
                'a'..='z' | 'A'..='Z' | '0'..='9' | '.' | '-' | '_' | ' ' => Some(c),
                // Replace problematic characters with underscore
                '"' | '\\' | '/' | ':' | '*' | '?' | '<' | '>' | '|' => Some('_'),
                // Remove control characters and newlines
                c if c.is_control() => None,
                // Replace non-ASCII with underscore
                c if !c.is_ascii() => Some('_'),
                _ => Some('_'),
            }
        })
        .collect();

    // Truncate if too long
    if sanitized.len() > MAX_FILENAME_LEN {
        sanitized[..MAX_FILENAME_LEN].to_string()
    } else if sanitized.is_empty() {
        "download".to_string()
    } else {
        sanitized
    }
}

/// Create an internal server error response while logging the detailed error.
///
/// Returns a generic message to the client to prevent information leakage,
/// while logging the full error details for debugging.
pub fn internal_error(context: &str, error: impl std::fmt::Display) -> (StatusCode, String) {
    error!(context = context, error = %error, "Internal error");
    (
        StatusCode::INTERNAL_SERVER_ERROR,
        "An internal error occurred. Please try again later.".to_string(),
    )
}

/// Create a bad gateway error response while logging the detailed error.
///
/// Used when upstream services (validator, miners) fail.
pub fn bad_gateway_error(context: &str, error: impl std::fmt::Display) -> (StatusCode, String) {
    error!(context = context, error = %error, "Upstream service error");
    (
        StatusCode::BAD_GATEWAY,
        "Failed to communicate with upstream service.".to_string(),
    )
}

/// Get a pooled P2P connection or create a new one
/// Returns None if connection cannot be established
pub async fn get_pooled_connection(
    pool: &tokio::sync::RwLock<HashMap<u32, (iroh::endpoint::Connection, u64)>>,
    miner_uid: u32,
    endpoint: &iroh::Endpoint,
    addr: &iroh::EndpointAddr,
    connect_timeout: std::time::Duration,
) -> Option<iroh::endpoint::Connection> {
    // Single timestamp for the entire function to avoid race conditions
    let now = now_secs();

    // Guard: if clock skew detected (now_secs returns 0), skip pool and create fresh connection
    if now == 0 {
        let conn = match tokio::time::timeout(
            connect_timeout,
            endpoint.connect(addr.clone(), b"hippius/miner-control"),
        )
        .await
        {
            Ok(Ok(c)) => c,
            _ => return None,
        };
        return Some(conn);
    }

    // Try pool first (read lock)
    {
        let pool_read = pool.read().await;
        if let Some((conn, ts)) = pool_read.get(&miner_uid) {
            // Guard: if stored timestamp is in the future (clock skew), treat as expired
            if *ts <= now
                && now - ts < CONNECTION_TTL_SECS
                && conn.closed().now_or_never().is_none()
            {
                return Some(conn.clone());
            }
        }
    }

    // Create new connection
    let conn = match tokio::time::timeout(
        connect_timeout,
        endpoint.connect(addr.clone(), b"hippius/miner-control"),
    )
    .await
    {
        Ok(Ok(c)) => c,
        _ => return None,
    };

    // Store in pool (write lock) with double-check to avoid race condition
    {
        let mut pool_write = pool.write().await;

        // Double-check: another task may have inserted a connection while we were connecting
        if let Some((existing_conn, ts)) = pool_write.get(&miner_uid) {
            // Guard: if stored timestamp is in the future (clock skew), treat as expired
            if *ts <= now
                && now - ts < CONNECTION_TTL_SECS
                && existing_conn.closed().now_or_never().is_none()
            {
                // Use the existing connection, drop the one we just created
                return Some(existing_conn.clone());
            }
        }

        pool_write.insert(miner_uid, (conn.clone(), now));

        // Periodic cleanup: remove stale connections when pool gets large
        if pool_write.len() > CONNECTION_POOL_CLEANUP_THRESHOLD {
            // Guard: use saturating_sub to avoid underflow if ts > now (clock skew)
            pool_write.retain(|_, (_, ts)| {
                *ts <= now && now.saturating_sub(*ts) < CONNECTION_TTL_SECS * 2
            });
        }
    }

    Some(conn)
}

/// Load or generate P2P keypair
pub async fn load_keypair(data_dir: &std::path::Path) -> Result<SecretKey> {
    let keypair_path = data_dir.join("keypair.bin");
    if keypair_path.exists() {
        let bytes = tokio::fs::read(&keypair_path).await?;
        if let Ok(key) = SecretKey::try_from(&bytes[..]) {
            debug!("Loaded existing keypair from {:?}", keypair_path);
            return Ok(key);
        }
    }

    let key = SecretKey::generate(&mut rand::rng());
    tokio::fs::write(&keypair_path, key.to_bytes()).await?;
    debug!("Generated new keypair at {:?}", keypair_path);
    Ok(key)
}

/// Type alias for rebalance status cache: (epoch, pg_id) -> (settled, cached_at)
pub type RebalanceStatusCache = DashMap<(u64, u32), (bool, u64)>;

/// Check if a PG is settled (all rebalance shards confirmed) at a given epoch.
/// Uses cache with short TTL to reduce validator HTTP load.
/// Returns true if settled (safe to use current epoch CRUSH), false if still rebalancing.
pub async fn is_pg_settled(
    validator_url: &str,
    http_client: &reqwest::Client,
    cache: &Arc<RebalanceStatusCache>,
    epoch: u64,
    pg_id: u32,
) -> bool {
    let key = (epoch, pg_id);
    let now = now_secs();

    // Guard: if clock skew detected, skip cache and assume settled
    if now == 0 {
        return true;
    }

    // Check cache first (lock-free DashMap access)
    if let Some(entry) = cache.get(&key) {
        let (settled, cached_at) = *entry;
        // Check TTL validity (guard against clock skew: cached_at should be <= now)
        if cached_at <= now && now.saturating_sub(cached_at) < REBALANCE_STATUS_CACHE_TTL_SECS {
            return settled;
        }
    }

    // Query validator for rebalance status
    let url = format!(
        "{}/rebalance/status/{}/{}",
        validator_url.trim_end_matches('/'),
        epoch,
        pg_id
    );
    match http_client
        .get(&url)
        .timeout(Duration::from_secs(5))
        .send()
        .await
    {
        Ok(res) if res.status().is_success() => {
            if let Ok(json) = res.json::<serde_json::Value>().await {
                let settled = json
                    .get("settled")
                    .and_then(|v| v.as_bool())
                    .unwrap_or(true);
                // Update cache
                cache.insert(key, (settled, now));
                return settled;
            }
        }
        _ => {
            // On error, assume settled (fall through to CRUSH)
            // This is safe: worst case we try current epoch placement which may fail,
            // then fall back to epoch lookback
            debug!(
                epoch = epoch,
                pg_id = pg_id,
                "Rebalance status query failed, assuming settled"
            );
        }
    }

    // Default: assume settled on error
    true
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_headers(range: &str) -> HeaderMap {
        let mut headers = HeaderMap::new();
        headers.insert("range", range.parse().unwrap());
        headers
    }

    #[test]
    fn test_parse_range_header_no_range() {
        let headers = HeaderMap::new();
        let result = parse_range_header(&headers, 1000);
        assert_eq!(result.start, 0);
        assert_eq!(result.end, 999);
        assert!(!result.is_range_request);
    }

    #[test]
    fn test_parse_range_header_normal_range() {
        let headers = make_headers("bytes=0-499");
        let result = parse_range_header(&headers, 1000);
        assert_eq!(result.start, 0);
        assert_eq!(result.end, 499);
        assert!(result.is_range_request);
    }

    #[test]
    fn test_parse_range_header_open_end() {
        let headers = make_headers("bytes=500-");
        let result = parse_range_header(&headers, 1000);
        assert_eq!(result.start, 500);
        assert_eq!(result.end, 999);
        assert!(result.is_range_request);
    }

    #[test]
    fn test_parse_range_header_suffix_range() {
        // bytes=-500 means "last 500 bytes"
        let headers = make_headers("bytes=-500");
        let result = parse_range_header(&headers, 1000);
        assert_eq!(result.start, 500);
        assert_eq!(result.end, 999);
        assert!(result.is_range_request);
    }

    #[test]
    fn test_parse_range_header_suffix_larger_than_file() {
        // bytes=-2000 on a 1000 byte file should return entire file
        let headers = make_headers("bytes=-2000");
        let result = parse_range_header(&headers, 1000);
        assert_eq!(result.start, 0);
        assert_eq!(result.end, 999);
        assert!(result.is_range_request);
    }

    #[test]
    fn test_parse_range_header_clamp_to_file_size() {
        // Range beyond file size should be clamped
        let headers = make_headers("bytes=0-5000");
        let result = parse_range_header(&headers, 1000);
        assert_eq!(result.start, 0);
        assert_eq!(result.end, 999);
        assert!(result.is_range_request);
    }

    #[test]
    fn test_parse_range_header_multi_range_rejected() {
        // Multi-range requests not supported - falls back to full file
        let headers = make_headers("bytes=0-100,200-300");
        let result = parse_range_header(&headers, 1000);
        assert_eq!(result.start, 0);
        assert_eq!(result.end, 999);
        assert!(!result.is_range_request);
    }

    #[test]
    fn test_parse_range_header_zero_size_file() {
        let headers = make_headers("bytes=0-100");
        let result = parse_range_header(&headers, 0);
        assert_eq!(result.start, 0);
        assert_eq!(result.end, 0);
        assert!(!result.is_range_request);
    }

    #[test]
    fn test_parse_range_header_invalid_format() {
        // Invalid range formats should fall back to full file
        let headers = make_headers("bytes=abc-def");
        let result = parse_range_header(&headers, 1000);
        assert_eq!(result.start, 0);
        assert_eq!(result.end, 999);
        assert!(!result.is_range_request);
    }

    #[test]
    fn test_detect_content_type() {
        assert_eq!(detect_content_type(Some("video.mp4")), "video/mp4");
        assert_eq!(detect_content_type(Some("image.PNG")), "image/png");
        assert_eq!(detect_content_type(Some("doc.pdf")), "application/pdf");
        assert_eq!(
            detect_content_type(Some("unknown.xyz")),
            "application/octet-stream"
        );
        assert_eq!(detect_content_type(None), "application/octet-stream");
    }

    #[test]
    fn test_sanitize_filename_normal() {
        assert_eq!(sanitize_filename("document.pdf"), "document.pdf");
        assert_eq!(sanitize_filename("my file.txt"), "my file.txt");
        assert_eq!(sanitize_filename("test-file_v2.zip"), "test-file_v2.zip");
    }

    #[test]
    fn test_sanitize_filename_removes_dangerous_chars() {
        // Quotes and backslashes should be replaced
        assert_eq!(sanitize_filename("file\"name.txt"), "file_name.txt");
        assert_eq!(sanitize_filename("file\\name.txt"), "file_name.txt");
        // Path separators should be replaced
        assert_eq!(sanitize_filename("path/to/file.txt"), "path_to_file.txt");
    }

    #[test]
    fn test_sanitize_filename_removes_control_chars() {
        assert_eq!(sanitize_filename("file\nname.txt"), "filename.txt");
        assert_eq!(sanitize_filename("file\rname.txt"), "filename.txt");
        assert_eq!(sanitize_filename("file\0name.txt"), "filename.txt");
    }

    #[test]
    fn test_sanitize_filename_empty() {
        assert_eq!(sanitize_filename(""), "download");
    }

    #[test]
    fn test_sanitize_filename_truncates_long_names() {
        let long_name = "a".repeat(300);
        let result = sanitize_filename(&long_name);
        assert_eq!(result.len(), 255);
    }

    #[test]
    fn test_sanitize_filename_non_ascii() {
        // Non-ASCII characters should be replaced with underscore
        // Note: Each Unicode character becomes one underscore (not per-byte)
        assert_eq!(sanitize_filename("文件.txt"), "__.txt");
        assert_eq!(sanitize_filename("café.pdf"), "caf_.pdf");
    }
}

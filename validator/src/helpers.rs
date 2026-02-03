//! Helper functions for the validator.
//!
//! This module provides utility functions used across the validator codebase.
//!
//! # Categories
//!
//! - **Task Management**: Panic-catching task spawning for resilient background tasks
//! - **Latency Tracking**: EMA-based latency updates for miner routing decisions
//! - **String Utilities**: Safe truncation for logging
//! - **Weight Calculation**: Dynamic miner weight computation for CRUSH placement
//! - **Health Checks**: Miner online/offline status detection
//! - **Security**: API key validation with caching and constant-time comparison
//!
//! # Weight Calculation Model
//!
//! Miner weights are dynamically calculated based on:
//! - **Capacity**: Total storage in GB (10-1000 weight points)
//! - **Uptime**: Heartbeat reliability (0.5x - 1.5x multiplier)
//! - **Free Space**: Available capacity incentive (0.5x - 1.2x multiplier)
//! - **Age**: Sybil resistance ramp-up (0.5x - 1.0x over 24 hours)

use axum::http::StatusCode;
use common::LATENCY_EMA_ALPHA;
use common::middleware::constant_time_eq;
use dashmap::DashMap;
use std::sync::OnceLock;
use tracing::{error, warn};

// ============================================================================
// Weight Calculation Constants
// ============================================================================

/// Expected heartbeat interval in seconds.
const HEARTBEAT_INTERVAL_SECS: u64 = 30;

/// Duration without heartbeat before miner is considered offline.
const MINER_OFFLINE_THRESHOLD_SECS: u64 = 120;

/// Seconds in a day - used for sybil resistance age ramp.
const SECS_PER_DAY: f32 = 86400.0;

/// Minimum age multiplier for new miners (sybil resistance).
const MIN_AGE_MULTIPLIER: f32 = 0.5;

/// Minimum CRUSH weight for any miner.
const MIN_MINER_WEIGHT: u32 = 10;

/// Maximum CRUSH weight for any miner.
const MAX_MINER_WEIGHT: u32 = 2000;

/// Decay rate for reputation -> weight multiplier conversion.
/// Chosen so that reputation=3.0 (ban threshold) maps to ~0.1 multiplier.
const REPUTATION_DECAY_RATE: f32 = 0.767;

/// Minimum reputation multiplier (floor for banned miners).
const MIN_REPUTATION_MULTIPLIER: f32 = 0.1;

/// Maximum reputation multiplier (perfect reputation).
const MAX_REPUTATION_MULTIPLIER: f32 = 1.0;

/// Spawns a task with panic catching to prevent silent task deaths.
/// Logs the panic message if the task panics.
///
/// Note: Infrastructure for future use - not yet wired into background tasks.
#[allow(dead_code)]
pub fn spawn_with_panic_log<F>(name: &'static str, future: F) -> tokio::task::JoinHandle<()>
where
    F: std::future::Future<Output = ()> + Send + 'static,
{
    tokio::spawn(async move {
        if let Err(e) = tokio::task::spawn(future).await {
            if e.is_panic() {
                error!(task = %name, error = ?e, "Task panicked");
            } else {
                error!(task = %name, "Task was cancelled");
            }
        }
    })
}

/// Updates miner latency using exponential moving average (EMA).
/// Uses common::LATENCY_EMA_ALPHA (0.2) for consistent smoothing across components.
///
/// Note: Infrastructure for smart routing - not yet wired into miner selection.
#[allow(dead_code)]
pub fn update_miner_latency(miner_latency: &DashMap<u32, f64>, miner_uid: u32, latency_ms: f64) {
    miner_latency
        .entry(miner_uid)
        .and_modify(|ema| *ema = LATENCY_EMA_ALPHA * latency_ms + (1.0 - LATENCY_EMA_ALPHA) * *ema)
        .or_insert(latency_ms);
}

/// Safely truncate a string for logging (handles non-ASCII gracefully).
/// Returns at most `max_chars` characters from the start of the string.
pub fn truncate_for_log(s: &str, max_chars: usize) -> &str {
    match s.char_indices().nth(max_chars) {
        Some((idx, _)) => &s[..idx],
        None => s,
    }
}

// ============================================================================
// Weight Calculation Helpers
// ============================================================================

/// Calculate uptime multiplier based on uptime score
pub fn calculate_uptime_multiplier(uptime_score: f32) -> f32 {
    if uptime_score >= 0.95 {
        1.5
    } else if uptime_score >= 0.80 {
        1.2
    } else if uptime_score >= 0.50 {
        1.0
    } else {
        0.5
    }
}

/// Calculate strike multiplier based on number of strikes (legacy discrete version)
pub fn calculate_strike_multiplier(strikes: u8) -> f32 {
    match strikes {
        0 => 1.0,
        1 => 0.8,
        2 => 0.5,
        _ => 0.1,
    }
}

/// Calculate reputation multiplier using smooth exponential decay.
///
/// Uses formula: e^(-REPUTATION_DECAY_RATE * reputation), clamped to [0.1, 1.0]
///
/// | Reputation | Multiplier | Scenario |
/// |------------|------------|----------|
/// | 0.0 | 1.00 | Perfect |
/// | 0.3 | 0.79 | 1 timeout |
/// | 1.0 | 0.46 | 1 failed audit |
/// | 2.0 | 0.22 | 2 failed audits |
/// | 3.0 | 0.10 | Ban threshold |
pub fn calculate_reputation_multiplier(reputation: f32) -> f32 {
    (-REPUTATION_DECAY_RATE * reputation)
        .exp()
        .clamp(MIN_REPUTATION_MULTIPLIER, MAX_REPUTATION_MULTIPLIER)
}

/// Calculate uptime score based on heartbeat count and time since registration
pub fn calculate_uptime_score(
    heartbeat_count: u32,
    registration_time: u64,
    current_time: u64,
) -> f32 {
    let elapsed = current_time.saturating_sub(registration_time);
    let expected_heartbeats = elapsed / HEARTBEAT_INTERVAL_SECS;

    // New miners or very short elapsed time get benefit of doubt
    let is_newly_registered = elapsed < 60;
    let insufficient_data = expected_heartbeats == 0;
    if is_newly_registered || insufficient_data {
        return 1.0;
    }

    (heartbeat_count as f32 / expected_heartbeats as f32).clamp(0.0, 1.0)
}

/// Adjust miner weight based on capacity, uptime, and age
pub fn adjust_miner_weight(miner: &mut common::MinerNode, current_time: u64) -> u32 {
    // DYNAMIC WEIGHTING ENABLED (Cabal Resistance)
    // Weight = Capacity * Reputation
    // Reputation = Age Factor * Uptime Factor

    // Base weight = Total Storage in GB * 10. (e.g. 40GB -> 400).
    // Min 10, Max 1000.
    let size_gb = miner.total_storage / (1024 * 1024 * 1024);
    let base_weight = (size_gb as f32 * 10.0).clamp(10.0, 1000.0);

    // Apply manual override if set
    if miner.weight_manual_override {
        return miner.weight;
    }

    // 1. Uptime Factor (Reliability)
    // Target: 95% uptime.
    let uptime_score =
        calculate_uptime_score(miner.heartbeat_count, miner.registration_time, current_time);
    let uptime_multiplier = calculate_uptime_multiplier(uptime_score);

    // 2. Capacity Factor (Incentivize free space)
    let capacity_multiplier =
        calculate_capacity_multiplier(miner.available_storage, miner.total_storage);

    // 3. Age Factor (Sybil Resistance)
    // New miners start at MIN_AGE_MULTIPLIER, ramp up to 1.0x over 24 hours
    let secs_since_registration = current_time.saturating_sub(miner.registration_time);
    let sybil_resistance_multiplier = (MIN_AGE_MULTIPLIER
        + (MIN_AGE_MULTIPLIER * (secs_since_registration as f32 / SECS_PER_DAY)))
        .min(1.0);

    // Calculate final weight
    let final_weight =
        (base_weight * uptime_multiplier * capacity_multiplier * sybil_resistance_multiplier)
            as u32;

    // Clamp to ensure non-zero and reasonable max
    final_weight.clamp(MIN_MINER_WEIGHT, MAX_MINER_WEIGHT)
}

/// Capacity multiplier: favor miners with more free space
pub fn calculate_capacity_multiplier(available: u64, total: u64) -> f32 {
    if total == 0 {
        return 1.0;
    }
    let usage_ratio = 1.0 - (available as f64 / total as f64);

    match usage_ratio {
        r if r < 0.50 => 1.2, // <50% full → bonus
        r if r < 0.75 => 1.0, // 50-75% → normal
        r if r < 0.90 => 0.8, // 75-90% → slight penalty
        _ => 0.5,             // >90% → strong penalty
    }
}

/// Check if miner is considered offline based on last_seen timestamp
pub fn is_miner_offline(miner: &common::MinerNode, current_time: u64) -> bool {
    current_time.saturating_sub(miner.last_seen) > MINER_OFFLINE_THRESHOLD_SECS
}

// ============================================================================
// Security Helpers
// ============================================================================

/// Cached admin API key read once at startup.
static ADMIN_KEY_CACHE: OnceLock<String> = OnceLock::new();

/// Cached gateway API key read once at startup.
static GATEWAY_KEY_CACHE: OnceLock<String> = OnceLock::new();

/// Get the admin API key, reading from environment once and caching.
///
/// Returns an empty string if `API_KEY_ADMIN` is not set (caller should check).
pub fn get_admin_api_key() -> &'static str {
    ADMIN_KEY_CACHE.get_or_init(|| {
        std::env::var("API_KEY_ADMIN").unwrap_or_else(|_| {
            warn!("API_KEY_ADMIN not set - admin endpoints will be inaccessible");
            String::new()
        })
    })
}

/// Get the gateway API key, reading from environment once and caching.
///
/// Returns an empty string if `API_KEY_GATEWAY` is not set (caller should check).
pub fn get_gateway_api_key() -> &'static str {
    GATEWAY_KEY_CACHE.get_or_init(|| {
        std::env::var("API_KEY_GATEWAY").unwrap_or_else(|_| {
            warn!("API_KEY_GATEWAY not set - gateway endpoints will be inaccessible");
            String::new()
        })
    })
}

/// Validate an API key using constant-time comparison.
///
/// Returns `true` if the provided key matches the expected key.
/// Uses constant-time comparison to prevent timing side-channel attacks.
///
/// # Arguments
/// * `provided` - The API key provided in the request
/// * `expected` - The expected API key from the cached environment
pub fn validate_api_key(provided: &str, expected: &str) -> bool {
    if expected.is_empty() {
        return false;
    }
    constant_time_eq(provided, expected)
}

/// Extract Bearer token from Authorization header value.
///
/// Returns the token if the header is in the format "Bearer <token>",
/// otherwise returns None.
pub fn extract_bearer_token(auth_header: &str) -> Option<&str> {
    auth_header.strip_prefix("Bearer ").map(|s| s.trim())
}

/// Validate a file hash and return an error response if invalid.
///
/// Returns `Ok(())` if the hash is valid (64 hex characters),
/// or `Err((StatusCode::BAD_REQUEST, &str))` if invalid.
///
/// # Usage
/// ```ignore
/// validate_hash_param(&hash)?;
/// // hash is valid, continue processing
/// ```
pub fn validate_hash_param(hash: &str) -> Result<(), (StatusCode, &'static str)> {
    if common::is_valid_file_hash(hash) {
        Ok(())
    } else {
        Err((StatusCode::BAD_REQUEST, "Invalid file hash format"))
    }
}

// ============================================================================
// Error Response Helpers
// ============================================================================

/// Returns a generic internal server error response, logging the actual error details.
///
/// This prevents leaking internal implementation details to clients while
/// ensuring errors are properly logged for debugging.
///
/// # Arguments
/// * `context` - A short description of what operation failed (logged)
/// * `error` - The actual error to log
pub fn internal_error(context: &str, error: impl std::fmt::Display) -> (StatusCode, &'static str) {
    error!(context = context, error = %error, "Internal error");
    (
        StatusCode::INTERNAL_SERVER_ERROR,
        "An internal error occurred. Please try again later.",
    )
}

/// Returns a generic internal server error response for database/doc store operations.
///
/// # Arguments
/// * `context` - A short description of what operation failed (logged)
/// * `error` - The actual error to log
pub fn doc_store_error(context: &str, error: impl std::fmt::Display) -> (StatusCode, &'static str) {
    error!(context = context, error = %error, "Document store error");
    (
        StatusCode::INTERNAL_SERVER_ERROR,
        "Failed to access document store.",
    )
}

/// Returns a generic unprocessable entity error response, logging the actual error details.
///
/// # Arguments
/// * `context` - A short description of what validation failed (logged)
/// * `error` - The actual error to log
pub fn validation_error(
    context: &str,
    error: impl std::fmt::Display,
) -> (StatusCode, &'static str) {
    warn!(context = context, error = %error, "Validation error");
    (StatusCode::UNPROCESSABLE_ENTITY, "Invalid request data.")
}

#[cfg(test)]
mod security_tests {
    use super::*;

    #[test]
    fn test_extract_bearer_token() {
        assert_eq!(extract_bearer_token("Bearer my-token"), Some("my-token"));
        assert_eq!(extract_bearer_token("Bearer   spaced  "), Some("spaced"));
        assert_eq!(extract_bearer_token("bearer token"), None);
        assert_eq!(extract_bearer_token("Basic abc123"), None);
        assert_eq!(extract_bearer_token(""), None);
    }

    #[test]
    fn test_validate_api_key() {
        assert!(validate_api_key("secret123", "secret123"));
        assert!(!validate_api_key("secret123", "secret124"));
        assert!(!validate_api_key("secret123", ""));
        assert!(!validate_api_key("", "secret123"));
    }
}

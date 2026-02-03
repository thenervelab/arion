//! HTTP middleware for Hippius Arion services.
//!
//! Provides X-API-Key authentication following the hccs pattern.

use axum::{
    extract::Request,
    http::{HeaderMap, StatusCode},
    middleware::Next,
    response::Response,
};
use std::sync::OnceLock;
use subtle::ConstantTimeEq;
use tracing::warn;

/// Header name for API key authentication.
pub const API_KEY_HEADER: &str = "X-API-Key";

/// Default test API key (used when ARION_API_KEY not set).
/// Logs a warning when used - DO NOT USE IN PRODUCTION.
const DEFAULT_TEST_KEY: &str = "Hippius-Arion-Dev-01";

/// Cached API key read once at startup to avoid log spam on every request.
static API_KEY_CACHE: OnceLock<String> = OnceLock::new();

/// Get the expected API key, reading from environment once and caching.
///
/// This function is public so other components (like gateway) can reuse the
/// cached API key instead of re-reading the environment variable on each request.
pub fn get_expected_api_key() -> &'static str {
    API_KEY_CACHE.get_or_init(|| {
        std::env::var("ARION_API_KEY").unwrap_or_else(|_| {
            warn!("ARION_API_KEY not set, using default test key - DO NOT USE IN PRODUCTION");
            DEFAULT_TEST_KEY.to_string()
        })
    })
}

/// Constant-time string comparison to prevent timing side-channel attacks.
///
/// Returns `true` if the strings are equal, `false` otherwise.
/// The comparison time is constant regardless of where strings differ.
///
/// # Security
/// - Length comparison is not constant-time (length may leak)
/// - Content comparison is constant-time (prevents character-by-character timing attacks)
#[inline]
pub fn constant_time_eq(a: &str, b: &str) -> bool {
    let a_bytes = a.as_bytes();
    let b_bytes = b.as_bytes();
    a_bytes.len() == b_bytes.len() && bool::from(a_bytes.ct_eq(b_bytes))
}

/// Middleware to validate API key from request headers.
///
/// Reads the expected key from `ARION_API_KEY` environment variable.
/// Falls back to a test key with warning if not set.
///
/// # Returns
/// - `Ok(Response)` if API key is valid
/// - `Err(StatusCode::UNAUTHORIZED)` if key is missing or invalid
///
/// # Example
/// ```ignore
/// use axum::{Router, middleware};
/// use common::middleware::validate_api_key;
///
/// let protected = Router::new()
///     .route("/upload", post(handle_upload))
///     .layer(middleware::from_fn(validate_api_key));
/// ```
pub async fn validate_api_key(
    headers: HeaderMap,
    request: Request,
    next: Next,
) -> Result<Response, StatusCode> {
    let expected_key = get_expected_api_key();

    let provided_key = headers.get(API_KEY_HEADER).and_then(|v| v.to_str().ok());

    match provided_key {
        Some(key) if constant_time_eq(key, expected_key) => Ok(next.run(request).await),
        Some(_) => {
            warn!("Invalid API key provided");
            Err(StatusCode::UNAUTHORIZED)
        }
        None => {
            warn!("No API key provided in {} header", API_KEY_HEADER);
            Err(StatusCode::UNAUTHORIZED)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_api_key_header_name() {
        assert_eq!(API_KEY_HEADER, "X-API-Key");
    }

    #[test]
    fn test_default_key_exists() {
        assert!(!DEFAULT_TEST_KEY.is_empty());
    }

    #[test]
    fn test_constant_time_eq_equal() {
        assert!(constant_time_eq("secret_key_123", "secret_key_123"));
    }

    #[test]
    fn test_constant_time_eq_not_equal() {
        assert!(!constant_time_eq("secret_key_123", "secret_key_124"));
    }

    #[test]
    fn test_constant_time_eq_different_lengths() {
        assert!(!constant_time_eq("short", "longer_string"));
    }

    #[test]
    fn test_constant_time_eq_empty() {
        assert!(constant_time_eq("", ""));
        assert!(!constant_time_eq("", "non_empty"));
    }
}

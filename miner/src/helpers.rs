//! Helper functions for the miner.
//!
//! This module provides utility functions used across the miner codebase.
//!
//! # Functions
//!
//! - `truncate_for_log()`: Safe string truncation for logging (handles UTF-8)
//! - `load_keypair()`: Load or generate Ed25519 keypair for miner identity
//!
//! # Key Management
//!
//! The miner's identity is an Ed25519 keypair stored at `<data_dir>/keypair.bin`.
//! - On first run, a new keypair is generated
//! - On subsequent runs, the existing keypair is loaded
//! - Corrupted or invalid keypairs cause a startup error (delete to regenerate)

use anyhow::Result;
use iroh::SecretKey;
use tracing::{debug, warn};

/// Returns true if the connection has a direct IP path (not relay-only).
///
/// In iroh 0.96+, `remote_info().addrs()` only reflects the address book
/// (discovery), not live paths discovered via NAT traversal. Use
/// `Connection::paths()` to inspect actual live paths on a connection.
pub fn has_direct_ip_path(conn: &iroh::endpoint::Connection) -> bool {
    use iroh::Watcher as _;
    conn.paths().get().iter().any(|p| p.is_ip())
}

/// Safely truncate a string for logging (handles non-ASCII gracefully)
pub fn truncate_for_log(s: &str, max_chars: usize) -> &str {
    match s.char_indices().nth(max_chars) {
        Some((idx, _)) => &s[..idx],
        None => s,
    }
}

/// Load or generate keypair from disk
pub async fn load_keypair(data_dir: &std::path::Path) -> Result<SecretKey> {
    let keypair_path = data_dir.join("keypair.bin");

    if keypair_path.exists() {
        let bytes = tokio::fs::read(&keypair_path).await?;
        anyhow::ensure!(
            bytes.len() == 32,
            "Corrupted keypair file at {}: expected 32 bytes, got {}. Delete the file to regenerate.",
            keypair_path.display(),
            bytes.len()
        );
        let key = SecretKey::try_from(&bytes[..]).map_err(|_| {
            anyhow::anyhow!(
                "Invalid keypair file at {}. Delete the file to regenerate.",
                keypair_path.display()
            )
        })?;
        debug!(path = %keypair_path.display(), "Loaded existing keypair");
        return Ok(key);
    }

    let key = SecretKey::generate(&mut rand::rng());
    tokio::fs::write(&keypair_path, key.to_bytes()).await?;

    // Set restrictive permissions (0600) to prevent other users from reading the keypair
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let perms = std::fs::Permissions::from_mode(0o600);
        if let Err(e) = std::fs::set_permissions(&keypair_path, perms) {
            warn!(path = %keypair_path.display(), error = %e, "Failed to set keypair file permissions");
        }
    }

    debug!(path = %keypair_path.display(), "Generated new keypair");
    Ok(key)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn truncate_within_limit() {
        assert_eq!(truncate_for_log("hello", 10), "hello");
    }

    #[test]
    fn truncate_exact_limit() {
        assert_eq!(truncate_for_log("hello", 5), "hello");
    }

    #[test]
    fn truncate_over_limit() {
        assert_eq!(truncate_for_log("hello world", 5), "hello");
    }

    #[test]
    fn truncate_empty() {
        assert_eq!(truncate_for_log("", 5), "");
    }

    #[test]
    fn truncate_zero_limit() {
        assert_eq!(truncate_for_log("hello", 0), "");
    }

    #[test]
    fn truncate_multibyte_chars() {
        // Each emoji is 4 bytes but 1 char — must not split mid-codepoint
        let emoji = "😀😁😂";
        assert_eq!(truncate_for_log(emoji, 2), "😀😁");
    }

    #[test]
    fn truncate_mixed_ascii_multibyte() {
        let mixed = "ab😀cd";
        assert_eq!(truncate_for_log(mixed, 3), "ab😀");
    }

    #[tokio::test]
    async fn load_keypair_generates_and_reloads() {
        let dir = tempfile::tempdir().unwrap();
        let key1 = load_keypair(dir.path()).await.unwrap();
        let key2 = load_keypair(dir.path()).await.unwrap();
        assert_eq!(key1.public(), key2.public());
    }

    #[tokio::test]
    async fn load_keypair_rejects_corrupted() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("keypair.bin");
        std::fs::write(&path, b"too_short").unwrap();
        assert!(load_keypair(dir.path()).await.is_err());
    }
}

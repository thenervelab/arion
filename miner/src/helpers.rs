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

use crate::constants::KEYPAIR_FILE_PERMISSIONS;
use anyhow::Result;
use ed25519_dalek::SigningKey;
use tracing::{debug, warn};

/// Safely truncate a string for logging (handles non-ASCII gracefully)
pub fn truncate_for_log(s: &str, max_chars: usize) -> &str {
    match s.char_indices().nth(max_chars) {
        Some((idx, _)) => &s[..idx],
        None => s,
    }
}

/// Load or generate keypair from disk
pub async fn load_keypair(data_dir: &std::path::Path) -> Result<SigningKey> {
    let keypair_path = data_dir.join("keypair.bin");

    if keypair_path.exists() {
        let bytes = tokio::fs::read(&keypair_path).await?;
        anyhow::ensure!(
            bytes.len() == 32,
            "Corrupted keypair file at {}: expected 32 bytes, got {}. Delete the file to regenerate.",
            keypair_path.display(),
            bytes.len()
        );
        let key_bytes: [u8; 32] = bytes[..].try_into().map_err(|_| {
            anyhow::anyhow!(
                "Invalid keypair file at {}. Delete the file to regenerate.",
                keypair_path.display()
            )
        })?;
        let key = SigningKey::from_bytes(&key_bytes);
        debug!(path = %keypair_path.display(), "Loaded existing keypair");
        return Ok(key);
    }

    let mut rng_bytes = [0u8; 32];
    rand::Fill::fill(&mut rng_bytes, &mut rand::rng());
    let key = SigningKey::from_bytes(&rng_bytes);
    tokio::fs::write(&keypair_path, key.to_bytes()).await?;

    // Set restrictive permissions (0600) to prevent other users from reading the keypair
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let perms = std::fs::Permissions::from_mode(KEYPAIR_FILE_PERMISSIONS);
        if let Err(e) = std::fs::set_permissions(&keypair_path, perms) {
            warn!(path = %keypair_path.display(), error = %e, "Failed to set keypair file permissions");
        }
    }

    debug!(path = %keypair_path.display(), "Generated new keypair");
    Ok(key)
}

/// Verify an Ed25519 signature from a node identified by hex node ID.
///
/// Returns `true` if the signature is valid, `false` otherwise.
pub fn verify_signature(node_id_hex: &str, message: &[u8], signature: &[u8; 64]) -> bool {
    let Ok(key_bytes) = hex::decode(node_id_hex) else {
        return false;
    };
    let Ok(key_array): Result<[u8; 32], _> = key_bytes.try_into() else {
        return false;
    };
    let Ok(verifying_key) = ed25519_dalek::VerifyingKey::from_bytes(&key_array) else {
        return false;
    };
    let sig = ed25519_dalek::Signature::from_bytes(signature);
    use ed25519_dalek::Verifier;
    verifying_key.verify(message, &sig).is_ok()
}

/// Run blocking work (a filesystem call, a SQLite query, a lookup that
/// faults mmap pages in, a CPU-bound decode) from async code without
/// stalling the runtime.
///
/// On a multi-thread runtime the worker hands its core (and the IO, timer
/// and signal drivers it may be driving) to another thread for the
/// duration (`tokio::task::block_in_place`), so a slow disk never freezes
/// heartbeats, timers or signal delivery. Elsewhere (a current-thread
/// runtime, as in `#[tokio::test]`, a blocking-pool thread or no runtime)
/// `f` runs inline, which is what the caller did before.
///
/// Unlike `spawn_blocking`, borrowed data may be used and the call cannot
/// outlive its caller: dropping the calling future cannot leave the work
/// running detached, which matters at shutdown.
pub fn blocking<R>(f: impl FnOnce() -> R) -> R {
    match tokio::runtime::Handle::try_current() {
        Ok(handle) if handle.runtime_flavor() == tokio::runtime::RuntimeFlavor::MultiThread => {
            tokio::task::block_in_place(f)
        }
        _ => f(),
    }
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

    #[test]
    fn blocking_runs_inline_without_a_runtime() {
        assert_eq!(blocking(|| 7), 7);
    }

    #[tokio::test]
    async fn blocking_runs_inline_on_a_current_thread_runtime() {
        let local = String::from("borrowed");
        assert_eq!(blocking(|| local.len()), 8);
    }

    /// With every worker inside `blocking`, timers still fire: the cores
    /// were handed off instead of being held by the blocked calls.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn blocking_keeps_timers_running_on_a_multi_thread_runtime() {
        let (tx, rx) = std::sync::mpsc::channel::<()>();
        let rx = std::sync::Arc::new(std::sync::Mutex::new(rx));
        let mut blocked = Vec::new();
        for _ in 0..2 {
            let rx = std::sync::Arc::clone(&rx);
            blocked.push(tokio::spawn(async move {
                blocking(|| {
                    let _ = rx
                        .lock()
                        .unwrap()
                        .recv_timeout(std::time::Duration::from_secs(10));
                })
            }));
        }
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;
        let started = std::time::Instant::now();
        tokio::time::sleep(std::time::Duration::from_millis(20)).await;
        let elapsed = started.elapsed();
        drop(tx);
        for task in blocked {
            task.await.unwrap();
        }
        assert!(
            elapsed < std::time::Duration::from_secs(5),
            "a timer must fire while workers block, took {elapsed:?}"
        );
    }

    #[tokio::test]
    async fn load_keypair_generates_and_reloads() {
        let dir = tempfile::tempdir().unwrap();
        let key1 = load_keypair(dir.path()).await.unwrap();
        let key2 = load_keypair(dir.path()).await.unwrap();
        assert_eq!(
            key1.verifying_key().as_bytes(),
            key2.verifying_key().as_bytes()
        );
    }

    #[tokio::test]
    async fn load_keypair_rejects_corrupted() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("keypair.bin");
        std::fs::write(&path, b"too_short").unwrap();
        assert!(load_keypair(dir.path()).await.is_err());
    }

    #[test]
    fn verify_signature_roundtrip() {
        use ed25519_dalek::Signer;
        let key = SigningKey::from_bytes(&[42u8; 32]);
        let node_id = common::transport::node_id_from_public_key(&key.verifying_key());
        let message = b"test message";
        let sig = key.sign(message);
        assert!(verify_signature(&node_id, message, &sig.to_bytes()));
    }
}

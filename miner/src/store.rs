//! Storage backend abstraction for the miner's shard store.
//!
//! Every consumer (P2P handlers, rebalance, inventory reconcile, background
//! maintenance) goes through [`BlobStore`] instead of a concrete store type.
//! [`FlatBlobStore`](crate::flat_store::FlatBlobStore) is the first
//! implementation (sharded flat files, one file per blob); the trait exists
//! so an alternative backend with a different on-disk representation can be
//! selected without touching any call site.
//!
//! Contract expected by consumers:
//! - `store` is atomic: a blob is either fully present or absent, never
//!   partially readable (crash-safe on the write path).
//! - `delete` is two-phase: the blob stops being listed/served/counted but
//!   remains restorable via `restore` until `purge_trashed`.
//! - `list_hashes`/`has` reflect live blobs only, never trashed ones —
//!   the inventory reported to the validator is derived from this view.
//! - Byte counters (`used_bytes`/`trash_bytes`) are advisory (quota
//!   reporting), maintained incrementally and corrected by
//!   `recompute_usage`.

use std::time::Duration;

use bytes::Bytes;

/// Backend-agnostic interface to the miner's blob store.
#[async_trait::async_trait]
pub trait BlobStore: Send + Sync + std::fmt::Debug {
    /// Store blob data atomically under its hex hash.
    async fn store(&self, hash_hex: &str, data: &[u8]) -> std::io::Result<()>;

    /// Read a live blob's data.
    async fn read(&self, hash_hex: &str) -> std::io::Result<Bytes>;

    /// Whether a live blob exists.
    fn has(&self, hash_hex: &str) -> bool;

    /// Two-phase delete: move the blob to the trash (quota freed, blob no
    /// longer listed or served) while staying restorable.
    async fn delete(&self, hash_hex: &str) -> std::io::Result<()>;

    /// Permanently delete a live blob, bypassing the trash.
    async fn remove(&self, hash_hex: &str) -> std::io::Result<()>;

    /// Bring a trashed blob back into the live store. Returns `false` if it
    /// was not in the trash.
    async fn restore(&self, hash_hex: &str) -> std::io::Result<bool>;

    /// Permanently remove one blob from the trash. No-op if absent.
    async fn purge_trashed(&self, hash_hex: &str) -> std::io::Result<()>;

    /// All live blob hashes.
    fn list_hashes(&self) -> Vec<String>;

    /// All trashed blob hashes.
    fn list_trashed_hashes(&self) -> Vec<String>;

    /// Whether a blob is currently in the trash.
    fn has_trashed(&self, hash_hex: &str) -> bool;

    /// Total size of live blobs in bytes (advisory counter).
    fn used_bytes(&self) -> u64;

    /// Total size of trashed blobs in bytes (advisory counter).
    fn trash_bytes(&self) -> u64;

    /// Walk the backing storage and correct the usage counters. Expensive
    /// and blocking — call from `spawn_blocking`, off the startup path.
    fn recompute_usage(&self);

    /// Remove stale write artifacts left behind by crashes. Returns the
    /// number of artifacts removed.
    fn cleanup_stale_tmp(&self) -> usize;

    /// Migrate entries from a legacy on-disk layout, throttled and
    /// resumable. Returns the number of entries moved; backends without a
    /// legacy layout return 0.
    async fn migrate_legacy_layout(&self, batch: usize, pause: Duration) -> u64;
}

/// Shared handles are stores too: lets call sites hold `Arc<dyn BlobStore>`
/// and pass it wherever a `BlobStore` is expected, without re-borrowing.
#[async_trait::async_trait]
impl<T: BlobStore + ?Sized> BlobStore for std::sync::Arc<T> {
    async fn store(&self, hash_hex: &str, data: &[u8]) -> std::io::Result<()> {
        (**self).store(hash_hex, data).await
    }
    async fn read(&self, hash_hex: &str) -> std::io::Result<Bytes> {
        (**self).read(hash_hex).await
    }
    fn has(&self, hash_hex: &str) -> bool {
        (**self).has(hash_hex)
    }
    async fn delete(&self, hash_hex: &str) -> std::io::Result<()> {
        (**self).delete(hash_hex).await
    }
    async fn remove(&self, hash_hex: &str) -> std::io::Result<()> {
        (**self).remove(hash_hex).await
    }
    async fn restore(&self, hash_hex: &str) -> std::io::Result<bool> {
        (**self).restore(hash_hex).await
    }
    async fn purge_trashed(&self, hash_hex: &str) -> std::io::Result<()> {
        (**self).purge_trashed(hash_hex).await
    }
    fn list_hashes(&self) -> Vec<String> {
        (**self).list_hashes()
    }
    fn list_trashed_hashes(&self) -> Vec<String> {
        (**self).list_trashed_hashes()
    }
    fn has_trashed(&self, hash_hex: &str) -> bool {
        (**self).has_trashed(hash_hex)
    }
    fn used_bytes(&self) -> u64 {
        (**self).used_bytes()
    }
    fn trash_bytes(&self) -> u64 {
        (**self).trash_bytes()
    }
    fn recompute_usage(&self) {
        (**self).recompute_usage()
    }
    fn cleanup_stale_tmp(&self) -> usize {
        (**self).cleanup_stale_tmp()
    }
    async fn migrate_legacy_layout(&self, batch: usize, pause: Duration) -> u64 {
        (**self).migrate_legacy_layout(batch, pause).await
    }
}

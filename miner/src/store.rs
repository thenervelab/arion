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
/// Snapshot of a backend's in-flight write budget against one payload,
/// taken before the payload is read off the wire (see
/// [`BlobStore::inflight_headroom`]).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct InflightHeadroom {
    /// Bytes the writer queue can still admit right now.
    pub available: u64,
    /// The whole budget.
    pub budget: u64,
    /// What admitting this payload would cost (payload + fixed overhead,
    /// capped at the budget like the backend does).
    pub cost: u64,
}

impl InflightHeadroom {
    /// Whether `store()` would be admitted without waiting.
    pub fn admits(&self) -> bool {
        self.cost <= self.available
    }

    /// The delay to advertise when it does not: 500 ms with an almost
    /// empty queue, 5000 ms with a full one, linear in between
    /// (`common::store_reply::RETRY_AFTER_MS_{MIN,MAX}`).
    pub fn retry_after_ms(&self) -> u32 {
        use common::store_reply::{RETRY_AFTER_MS_MAX, RETRY_AFTER_MS_MIN};
        if self.budget == 0 {
            return RETRY_AFTER_MS_MAX;
        }
        let fill = 1.0 - (self.available.min(self.budget) as f64 / self.budget as f64);
        let span = (RETRY_AFTER_MS_MAX - RETRY_AFTER_MS_MIN) as f64;
        (RETRY_AFTER_MS_MIN as f64 + fill * span)
            .round()
            .clamp(RETRY_AFTER_MS_MIN as f64, RETRY_AFTER_MS_MAX as f64) as u32
    }
}

#[async_trait::async_trait]
pub trait BlobStore: Send + Sync + std::fmt::Debug {
    /// Store blob data atomically under its hex hash.
    async fn store(&self, hash_hex: &str, data: &[u8]) -> std::io::Result<()>;

    /// Headroom of the in-flight write budget for a payload of
    /// `payload_len` bytes, `None` for a backend whose `store()` never
    /// waits for admission (the flat store). A snapshot, not a
    /// reservation: `store()` still takes the permits itself. The Store
    /// handler consults it before reading the payload so an exhausted
    /// budget answers a structured Busy instead of buffering bytes it
    /// cannot admit.
    fn inflight_headroom(&self, payload_len: u64) -> Option<InflightHeadroom> {
        let _ = payload_len;
        None
    }

    /// Read a live blob's data.
    async fn read(&self, hash_hex: &str) -> std::io::Result<Bytes>;

    /// Read a live blob's data only if it is at most `max_len` bytes long.
    ///
    /// A longer blob fails with [`std::io::ErrorKind::FileTooLarge`] before
    /// its content is buffered: the backend checks the stored length first
    /// and never allocates or reads past `max_len` (plus one byte to detect
    /// a blob growing under the read). Consumers that know the expected
    /// length (the storage-proof path) use this instead of `read` so an
    /// oversized or corrupted entry cannot allocate beyond their bound.
    async fn read_at_most(&self, hash_hex: &str, max_len: u64) -> std::io::Result<Bytes>;

    /// Whether a live blob exists.
    fn has(&self, hash_hex: &str) -> bool;

    /// Stored length of a live blob in bytes, `None` if absent. Cheap
    /// (index or one `stat`), never reads the payload.
    fn blob_len(&self, hash_hex: &str) -> Option<u64>;

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
    fn inflight_headroom(&self, payload_len: u64) -> Option<InflightHeadroom> {
        (**self).inflight_headroom(payload_len)
    }
    async fn read(&self, hash_hex: &str) -> std::io::Result<Bytes> {
        (**self).read(hash_hex).await
    }
    async fn read_at_most(&self, hash_hex: &str, max_len: u64) -> std::io::Result<Bytes> {
        (**self).read_at_most(hash_hex, max_len).await
    }
    fn has(&self, hash_hex: &str) -> bool {
        (**self).has(hash_hex)
    }
    fn blob_len(&self, hash_hex: &str) -> Option<u64> {
        (**self).blob_len(hash_hex)
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

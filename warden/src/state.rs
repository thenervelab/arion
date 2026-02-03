//! Persistent state for tracking shards (sled) and in-memory pending challenges.

use common::WardenAuditReport;
use dashmap::DashMap;
use parking_lot::RwLock;
use serde::{Deserialize, Serialize};
use std::path::Path;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Instant;
use tracing::{debug, info, warn};

/// Persistent shard info stored in sled (bincode serialized).
#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct PersistentShardInfo {
    pub shard_hash: String,
    pub merkle_root: [u32; 8],
    pub chunk_count: u32,
    pub miner_uid: u32,
    /// Miner's EndpointAddr serialized as JSON (iroh::EndpointAddr doesn't implement Serialize)
    pub miner_endpoint_json: Option<String>,
    /// Unix timestamp of last audit (replaces Instant which cannot be serialized)
    pub last_audited_secs: Option<u64>,
}

/// Runtime shard info (includes non-serializable fields).
#[derive(Clone, Debug)]
pub struct ShardInfo {
    pub shard_hash: String,
    pub merkle_root: [u32; 8],
    pub chunk_count: u32,
    pub miner_uid: u32,
    pub miner_endpoint: Option<iroh::EndpointAddr>,
    pub last_audited: Option<Instant>,
}

impl ShardInfo {
    /// Convert to persistent format for sled storage.
    fn to_persistent(&self) -> PersistentShardInfo {
        PersistentShardInfo {
            shard_hash: self.shard_hash.clone(),
            merkle_root: self.merkle_root,
            chunk_count: self.chunk_count,
            miner_uid: self.miner_uid,
            miner_endpoint_json: self
                .miner_endpoint
                .as_ref()
                .and_then(|ep| serde_json::to_string(ep).ok()),
            // Preserve the original audit time by calculating elapsed since then
            last_audited_secs: self.last_audited.map(|instant| {
                let elapsed = instant.elapsed().as_secs();
                common::now_secs().saturating_sub(elapsed)
            }),
        }
    }

    /// Convert from persistent format (reconstructs approximate Instant).
    fn from_persistent(p: PersistentShardInfo) -> Self {
        Self {
            shard_hash: p.shard_hash,
            merkle_root: p.merkle_root,
            chunk_count: p.chunk_count,
            miner_uid: p.miner_uid,
            miner_endpoint: p
                .miner_endpoint_json
                .and_then(|json| serde_json::from_str(&json).ok()),
            // Reconstruct approximate Instant based on how long ago the audit was
            last_audited: p.last_audited_secs.and_then(|ts| {
                let age_secs = common::now_secs().saturating_sub(ts);
                Instant::now().checked_sub(std::time::Duration::from_secs(age_secs))
            }),
        }
    }
}

/// A pending challenge awaiting response.
///
/// Fields marked as scaffolding are used by `process_proof_response` and
/// `create_timeout_attestation` when P2P is implemented.
#[derive(Clone, Debug)]
pub struct PendingChallenge {
    /// The challenge nonce (correlation ID)
    pub nonce: [u8; 32],
    /// Shard hash being challenged
    #[allow(dead_code)] // Used by process_proof_response (P2P scaffolding)
    pub shard_hash: String,
    /// Chunk indices in the challenge
    #[allow(dead_code)] // Used by process_proof_response (P2P scaffolding)
    pub chunk_indices: Vec<u32>,
    /// Expected Merkle root
    #[allow(dead_code)] // Used by process_proof_response (P2P scaffolding)
    pub expected_root: [u32; 8],
    /// Miner UID being challenged
    #[allow(dead_code)] // Used by process_proof_response (P2P scaffolding)
    pub miner_uid: u32,
    /// When the challenge was sent
    #[allow(dead_code)] // Used for latency metrics (P2P scaffolding)
    pub sent_at: Instant,
    /// When the challenge expires
    pub expires_at: u64,
}

/// Persistent attestation for retry queue (serializable).
#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct RetryableAttestation {
    /// The audit report to retry
    pub report: WardenAuditReport,
    /// Number of retry attempts so far
    pub retry_count: u32,
    /// Timestamp when first queued
    pub queued_at: u64,
    /// Timestamp of last retry attempt
    pub last_retry_at: u64,
}

/// Maximum number of retry attempts before dropping attestation
pub const MAX_RETRY_ATTEMPTS: u32 = 10;

/// Minimum seconds between retry attempts (exponential backoff base)
pub const RETRY_BACKOFF_BASE_SECS: u64 = 30;

/// Maximum backoff time in seconds
pub const RETRY_BACKOFF_MAX_SECS: u64 = 3600; // 1 hour

/// Sled tree names
const SHARDS_TREE: &str = "shards";
const META_TREE: &str = "meta";
const RETRY_QUEUE_TREE: &str = "retry_queue";
const CURSOR_KEY: &[u8] = b"audit_cursor";
const EPOCH_KEY: &[u8] = b"current_epoch";

/// Global Warden state with sled persistence for shards.
pub struct WardenState {
    /// Sled database handle
    db: sled::Db,
    /// Tree for shard storage
    shards_tree: sled::Tree,
    /// Tree for metadata (cursor, etc.)
    meta_tree: sled::Tree,
    /// Tree for retry queue (failed attestations)
    retry_queue_tree: sled::Tree,

    /// Pending challenges: nonce (hex) -> PendingChallenge (in-memory, transient)
    pub pending: DashMap<String, PendingChallenge>,

    /// Round-robin cursor for fair audit selection (persisted in sled)
    audit_cursor: AtomicU64,

    /// Current audit epoch (for epoch-based shard sampling)
    current_epoch: AtomicU64,

    /// Cached list of shard hashes for round-robin (rebuilt on startup)
    shard_list: RwLock<Vec<String>>,

    /// Maximum number of shards to track
    max_shards: usize,

    /// Maximum number of pending challenges
    max_pending_challenges: usize,

    /// Maximum number of attestations in retry queue
    max_retry_queue_size: usize,
}

impl WardenState {
    /// Open sled database and initialize state.
    pub fn open(
        db_path: &Path,
        max_shards: usize,
        max_pending_challenges: usize,
    ) -> anyhow::Result<Self> {
        Self::open_with_retry_queue(db_path, max_shards, max_pending_challenges, 10_000)
    }

    /// Open sled database and initialize state with custom retry queue size.
    pub fn open_with_retry_queue(
        db_path: &Path,
        max_shards: usize,
        max_pending_challenges: usize,
        max_retry_queue_size: usize,
    ) -> anyhow::Result<Self> {
        // Ensure parent directory exists
        if let Some(parent) = db_path.parent() {
            std::fs::create_dir_all(parent)?;
        }

        let db = sled::open(db_path)?;
        let shards_tree = db.open_tree(SHARDS_TREE)?;
        let meta_tree = db.open_tree(META_TREE)?;
        let retry_queue_tree = db.open_tree(RETRY_QUEUE_TREE)?;

        // Load persisted cursor or start at 0
        let cursor = meta_tree
            .get(CURSOR_KEY)?
            .and_then(|v| bincode::deserialize::<u64>(&v).ok())
            .unwrap_or(0);

        // Load persisted epoch or start at 0
        let epoch = meta_tree
            .get(EPOCH_KEY)?
            .and_then(|v| bincode::deserialize::<u64>(&v).ok())
            .unwrap_or(0);

        Ok(Self {
            db,
            shards_tree,
            meta_tree,
            retry_queue_tree,
            pending: DashMap::new(),
            audit_cursor: AtomicU64::new(cursor),
            current_epoch: AtomicU64::new(epoch),
            shard_list: RwLock::new(Vec::new()),
            max_shards,
            max_pending_challenges,
            max_retry_queue_size,
        })
    }

    /// Load shards from disk and rebuild in-memory cache.
    /// Returns the number of shards loaded.
    pub fn load_and_recover(&self) -> anyhow::Result<usize> {
        let mut shard_list = self.shard_list.write();
        shard_list.clear();

        let mut count = 0;
        let mut corrupted = 0;

        for result in self.shards_tree.iter() {
            match result {
                Ok((key, value)) => {
                    match bincode::deserialize::<PersistentShardInfo>(&value) {
                        Ok(info) => {
                            shard_list.push(info.shard_hash.clone());
                            count += 1;
                        }
                        Err(e) => {
                            // Log and skip corrupted entries
                            let key_str = String::from_utf8_lossy(&key);
                            warn!(key = %key_str, error = %e, "Skipping corrupted shard entry");
                            corrupted += 1;
                        }
                    }
                }
                Err(e) => {
                    warn!(error = %e, "Error reading shard from database");
                    corrupted += 1;
                }
            }
        }

        if corrupted > 0 {
            warn!(corrupted, "Some shard entries were corrupted and skipped");
        }

        let retry_queue_size = self.retry_queue_tree.len();

        info!(
            shards_loaded = count,
            cursor = self.audit_cursor.load(Ordering::Relaxed),
            epoch = self.current_epoch.load(Ordering::Relaxed),
            retry_queue_size,
            "Warden state recovered from disk"
        );
        Ok(count)
    }

    /// Serialize and store a shard in the database.
    fn serialize_and_store(&self, hash: &str, info: &ShardInfo) -> bool {
        let persistent = info.to_persistent();
        let bytes = match bincode::serialize(&persistent) {
            Ok(b) => b,
            Err(e) => {
                warn!(error = %e, shard_hash = %hash, "Failed to serialize shard");
                return false;
            }
        };
        if let Err(e) = self.shards_tree.insert(hash.as_bytes(), bytes) {
            warn!(error = %e, shard_hash = %hash, "Failed to store shard in database");
            return false;
        }
        true
    }

    /// Add or update a shard.
    ///
    /// Returns false if at capacity (for new shards only, updates always succeed).
    pub fn upsert_shard(&self, info: ShardInfo) -> bool {
        let hash = info.shard_hash.clone();
        let is_update = self
            .shards_tree
            .contains_key(hash.as_bytes())
            .unwrap_or(false);

        // Updates always allowed
        if is_update {
            return self.serialize_and_store(&hash, &info);
        }

        // New shards: check capacity first
        if self.shards_tree.len() >= self.max_shards {
            warn!(
                capacity = self.max_shards,
                shard_hash = %hash,
                "Shard capacity reached, rejecting new shard"
            );
            return false;
        }

        // Insert new shard
        if self.serialize_and_store(&hash, &info) {
            self.shard_list.write().push(hash);
            true
        } else {
            false
        }
    }

    /// Remove a shard.
    pub fn remove_shard(&self, shard_hash: &str) {
        if let Err(e) = self.shards_tree.remove(shard_hash.as_bytes()) {
            warn!(error = %e, shard_hash = %shard_hash, "Failed to remove shard from database");
        }
        self.shard_list.write().retain(|h| h != shard_hash);
    }

    /// Get a shard by hash.
    pub fn get_shard(&self, shard_hash: &str) -> Option<ShardInfo> {
        self.shards_tree
            .get(shard_hash.as_bytes())
            .ok()
            .flatten()
            .and_then(|v| bincode::deserialize::<PersistentShardInfo>(&v).ok())
            .map(ShardInfo::from_persistent)
    }

    /// Get the next N shards for auditing (round-robin with cursor).
    ///
    /// Returns at most `count` shards, or fewer if there are less shards available.
    /// Will not return duplicates even if count > shard_count.
    pub fn select_shards_for_audit(&self, count: usize) -> Vec<ShardInfo> {
        let list = self.shard_list.read();
        if list.is_empty() {
            return Vec::new();
        }

        // Limit iterations to avoid duplicates when count > list.len()
        let actual_count = count.min(list.len());
        let cursor = self
            .audit_cursor
            .fetch_add(actual_count as u64, Ordering::Relaxed);

        // Persist cursor periodically (every 100 increments to reduce disk I/O)
        if cursor % 100 == 0 {
            self.save_cursor(cursor + actual_count as u64);
        }

        let mut result = Vec::with_capacity(actual_count);

        for i in 0..actual_count {
            let idx = ((cursor as usize) + i) % list.len();
            if let Some(info) = self.get_shard(&list[idx]) {
                result.push(info);
            }
        }

        result
    }

    /// Persist the audit cursor to sled.
    fn save_cursor(&self, cursor: u64) {
        let bytes = match bincode::serialize(&cursor) {
            Ok(b) => b,
            Err(e) => {
                warn!(error = %e, "Failed to serialize audit cursor");
                return;
            }
        };
        if let Err(e) = self.meta_tree.insert(CURSOR_KEY, bytes) {
            warn!(error = %e, "Failed to persist audit cursor");
        }
    }

    /// Record a pending challenge.
    ///
    /// Returns false if at capacity.
    pub fn add_pending(&self, challenge: PendingChallenge) -> bool {
        if self.pending.len() >= self.max_pending_challenges {
            warn!(
                capacity = self.max_pending_challenges,
                "Pending challenge capacity reached, skipping"
            );
            return false;
        }
        let key = hex::encode(challenge.nonce);
        self.pending.insert(key, challenge);
        true
    }

    /// Remove and return a pending challenge by nonce.
    #[allow(dead_code)] // Scaffolding for P2P integration
    pub fn take_pending(&self, nonce: &[u8; 32]) -> Option<PendingChallenge> {
        let key = hex::encode(nonce);
        self.pending.remove(&key).map(|(_, v)| v)
    }

    /// Get count of tracked shards.
    pub fn shard_count(&self) -> usize {
        self.shards_tree.len()
    }

    /// Get count of pending challenges.
    pub fn pending_count(&self) -> usize {
        self.pending.len()
    }

    /// Clean up expired pending challenges.
    pub fn cleanup_expired(&self, now_secs: u64) {
        self.pending.retain(|_, c| c.expires_at > now_secs);
    }

    // ==================== Retry Queue Methods ====================

    /// Queue a failed attestation for retry.
    ///
    /// Returns false if at capacity or attestation has exceeded max retries.
    pub fn queue_for_retry(&self, report: WardenAuditReport) -> bool {
        self.queue_for_retry_with_count(report, 0)
    }

    /// Queue a failed attestation for retry with specified retry count.
    fn queue_for_retry_with_count(&self, report: WardenAuditReport, retry_count: u32) -> bool {
        if retry_count >= MAX_RETRY_ATTEMPTS {
            warn!(
                audit_id = %report.audit_id,
                miner_uid = report.miner_uid,
                retry_count,
                "Attestation exceeded max retries, dropping"
            );
            return false;
        }

        if self.retry_queue_tree.len() >= self.max_retry_queue_size {
            warn!(
                capacity = self.max_retry_queue_size,
                "Retry queue at capacity, dropping attestation"
            );
            return false;
        }

        let now = common::now_secs();
        let entry = RetryableAttestation {
            report: report.clone(),
            retry_count,
            queued_at: now,
            last_retry_at: now,
        };

        let key = format!("{}:{}", report.audit_id, report.miner_uid);
        let bytes = match bincode::serialize(&entry) {
            Ok(b) => b,
            Err(e) => {
                warn!(error = %e, "Failed to serialize retry attestation");
                return false;
            }
        };

        if let Err(e) = self.retry_queue_tree.insert(key.as_bytes(), bytes) {
            warn!(error = %e, "Failed to queue attestation for retry");
            return false;
        }

        debug!(
            audit_id = %report.audit_id,
            miner_uid = report.miner_uid,
            retry_count,
            "Attestation queued for retry"
        );
        true
    }

    /// Get attestations ready for retry (respecting backoff).
    ///
    /// Returns up to `limit` attestations that are ready to be retried based on
    /// exponential backoff timing.
    pub fn get_retry_ready(&self, limit: usize) -> Vec<(String, RetryableAttestation)> {
        let now = common::now_secs();
        let mut ready = Vec::new();

        for result in self.retry_queue_tree.iter() {
            if ready.len() >= limit {
                break;
            }

            match result {
                Ok((key, value)) => {
                    match bincode::deserialize::<RetryableAttestation>(&value) {
                        Ok(entry) => {
                            // Calculate backoff: base * 2^retry_count, capped at max
                            let backoff = RETRY_BACKOFF_BASE_SECS
                                .saturating_mul(1u64 << entry.retry_count.min(10))
                                .min(RETRY_BACKOFF_MAX_SECS);
                            let next_retry_at = entry.last_retry_at.saturating_add(backoff);

                            if now >= next_retry_at {
                                let key_str = String::from_utf8_lossy(&key).to_string();
                                ready.push((key_str, entry));
                            }
                        }
                        Err(e) => {
                            // Remove corrupted entry
                            let key_str = String::from_utf8_lossy(&key);
                            warn!(key = %key_str, error = %e, "Removing corrupted retry entry");
                            let _ = self.retry_queue_tree.remove(&key);
                        }
                    }
                }
                Err(e) => {
                    warn!(error = %e, "Error reading retry queue");
                }
            }
        }

        ready
    }

    /// Mark an attestation as successfully sent (remove from retry queue).
    pub fn remove_from_retry_queue(&self, key: &str) {
        if let Err(e) = self.retry_queue_tree.remove(key.as_bytes()) {
            warn!(error = %e, key = %key, "Failed to remove from retry queue");
        }
    }

    /// Update retry count after a failed retry attempt.
    pub fn mark_retry_failed(&self, key: &str, entry: &RetryableAttestation) {
        let updated = RetryableAttestation {
            report: entry.report.clone(),
            retry_count: entry.retry_count + 1,
            queued_at: entry.queued_at,
            last_retry_at: common::now_secs(),
        };

        if updated.retry_count >= MAX_RETRY_ATTEMPTS {
            warn!(
                audit_id = %entry.report.audit_id,
                miner_uid = entry.report.miner_uid,
                "Attestation exceeded max retries, removing from queue"
            );
            self.remove_from_retry_queue(key);
            return;
        }

        let bytes = match bincode::serialize(&updated) {
            Ok(b) => b,
            Err(e) => {
                warn!(error = %e, "Failed to serialize updated retry entry");
                return;
            }
        };

        if let Err(e) = self.retry_queue_tree.insert(key.as_bytes(), bytes) {
            warn!(error = %e, "Failed to update retry entry");
        }
    }

    /// Get the current size of the retry queue.
    pub fn retry_queue_size(&self) -> usize {
        self.retry_queue_tree.len()
    }

    // ==================== Epoch Management Methods ====================

    /// Get the current audit epoch.
    pub fn get_epoch(&self) -> u64 {
        self.current_epoch.load(Ordering::SeqCst)
    }

    /// Set the current audit epoch and persist to disk.
    pub fn set_epoch(&self, epoch: u64) {
        self.current_epoch.store(epoch, Ordering::SeqCst);
        self.save_epoch(epoch);
    }

    /// Persist the current epoch to sled.
    fn save_epoch(&self, epoch: u64) {
        let bytes = match bincode::serialize(&epoch) {
            Ok(b) => b,
            Err(e) => {
                warn!(error = %e, "Failed to serialize current epoch");
                return;
            }
        };
        if let Err(e) = self.meta_tree.insert(EPOCH_KEY, bytes) {
            warn!(error = %e, "Failed to persist current epoch");
        }
    }

    /// Clear all shards from the database and in-memory cache.
    ///
    /// Called at epoch boundaries when the validator samples new shards.
    /// Returns the number of shards that were cleared.
    pub fn clear_all_shards(&self) -> usize {
        // Acquire write lock on shard_list FIRST to block concurrent upserts
        // This prevents race condition where upsert adds to tree between clear operations
        let mut shard_list = self.shard_list.write();

        let count = self.shards_tree.len();

        // Clear sled tree (now safe because we hold the lock)
        if let Err(e) = self.shards_tree.clear() {
            warn!(error = %e, "Failed to clear shards tree");
        }

        // Clear in-memory cache
        shard_list.clear();

        // Reset cursor to 0 for new epoch
        self.audit_cursor.store(0, Ordering::Relaxed);
        self.save_cursor(0);

        // Clear any pending challenges (they're now stale)
        let pending_cleared = self.pending.len();
        self.pending.clear();

        info!(
            shards_cleared = count,
            pending_cleared, "Cleared all shards for new epoch"
        );

        count
    }

    /// Flush all pending writes to disk.
    pub fn flush(&self) -> anyhow::Result<()> {
        // Save the current cursor
        let cursor = self.audit_cursor.load(Ordering::Relaxed);
        self.save_cursor(cursor);

        // Save the current epoch
        let epoch = self.current_epoch.load(Ordering::SeqCst);
        self.save_epoch(epoch);

        // Flush sled
        self.db.flush()?;
        Ok(())
    }
}

impl Drop for WardenState {
    fn drop(&mut self) {
        // Best-effort flush on drop
        let _ = self.flush();
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    /// Default maximum shards for tests
    const DEFAULT_MAX_SHARDS: usize = 100_000;

    /// Default maximum pending challenges for tests
    const DEFAULT_MAX_PENDING_CHALLENGES: usize = 10_000;

    fn make_shard(hash: &str, miner_uid: u32) -> ShardInfo {
        ShardInfo {
            shard_hash: hash.to_string(),
            merkle_root: [0; 8],
            chunk_count: 100,
            miner_uid,
            miner_endpoint: None,
            last_audited: None,
        }
    }

    fn create_test_state() -> (WardenState, tempfile::TempDir) {
        let dir = tempdir().unwrap();
        let db_path = dir.path().join("test.db");
        let state = WardenState::open(&db_path, DEFAULT_MAX_SHARDS, DEFAULT_MAX_PENDING_CHALLENGES)
            .unwrap();
        state.load_and_recover().unwrap();
        (state, dir)
    }

    #[test]
    fn test_upsert_and_remove_shard() {
        let (state, _dir) = create_test_state();

        state.upsert_shard(make_shard("shard1", 1));
        assert_eq!(state.shard_count(), 1);

        state.upsert_shard(make_shard("shard2", 2));
        assert_eq!(state.shard_count(), 2);

        // Update existing
        state.upsert_shard(make_shard("shard1", 3));
        assert_eq!(state.shard_count(), 2);

        state.remove_shard("shard1");
        assert_eq!(state.shard_count(), 1);
    }

    #[test]
    fn test_select_shards_round_robin() {
        let (state, _dir) = create_test_state();

        for i in 0..5 {
            state.upsert_shard(make_shard(&format!("shard{}", i), i as u32));
        }

        // First selection starts at 0
        let batch1 = state.select_shards_for_audit(3);
        assert_eq!(batch1.len(), 3);

        // Second selection continues from 3
        let batch2 = state.select_shards_for_audit(3);
        assert_eq!(batch2.len(), 3);

        // Cursor wraps around
        let batch3 = state.select_shards_for_audit(3);
        assert_eq!(batch3.len(), 3);
    }

    #[test]
    fn test_pending_challenges() {
        let (state, _dir) = create_test_state();

        let nonce = [42u8; 32];
        let challenge = PendingChallenge {
            nonce,
            shard_hash: "test".to_string(),
            chunk_indices: vec![0, 1, 2],
            expected_root: [0; 8],
            miner_uid: 1,
            sent_at: Instant::now(),
            expires_at: u64::MAX,
        };

        state.add_pending(challenge);
        assert_eq!(state.pending_count(), 1);

        let taken = state.take_pending(&nonce);
        assert!(taken.is_some());
        assert_eq!(state.pending_count(), 0);

        // Taking again returns None
        assert!(state.take_pending(&nonce).is_none());
    }

    #[test]
    fn test_cleanup_expired() {
        let (state, _dir) = create_test_state();

        // Add expired challenge
        state.add_pending(PendingChallenge {
            nonce: [1u8; 32],
            shard_hash: "expired".to_string(),
            chunk_indices: vec![],
            expected_root: [0; 8],
            miner_uid: 1,
            sent_at: Instant::now(),
            expires_at: 100, // Expired
        });

        // Add valid challenge
        state.add_pending(PendingChallenge {
            nonce: [2u8; 32],
            shard_hash: "valid".to_string(),
            chunk_indices: vec![],
            expected_root: [0; 8],
            miner_uid: 2,
            sent_at: Instant::now(),
            expires_at: u64::MAX,
        });

        assert_eq!(state.pending_count(), 2);
        state.cleanup_expired(1000);
        assert_eq!(state.pending_count(), 1);
    }

    #[test]
    fn test_shard_capacity_limit() {
        let dir = tempdir().unwrap();
        let db_path = dir.path().join("test.db");
        let state = WardenState::open(&db_path, 3, 100).unwrap();
        state.load_and_recover().unwrap();

        assert!(state.upsert_shard(make_shard("shard1", 1)));
        assert!(state.upsert_shard(make_shard("shard2", 2)));
        assert!(state.upsert_shard(make_shard("shard3", 3)));
        assert_eq!(state.shard_count(), 3);

        // At capacity - new shard should be rejected
        assert!(!state.upsert_shard(make_shard("shard4", 4)));
        assert_eq!(state.shard_count(), 3);

        // Updates to existing shards should still work
        assert!(state.upsert_shard(make_shard("shard1", 99)));
        assert_eq!(state.shard_count(), 3);
    }

    #[test]
    fn test_pending_capacity_limit() {
        let (_state, _dir) = create_test_state();

        // Override capacity for test
        let dir = tempdir().unwrap();
        let db_path = dir.path().join("test.db");
        let state = WardenState::open(&db_path, 100, 2).unwrap();

        let c1 = PendingChallenge {
            nonce: [1u8; 32],
            shard_hash: "s1".to_string(),
            chunk_indices: vec![],
            expected_root: [0; 8],
            miner_uid: 1,
            sent_at: Instant::now(),
            expires_at: u64::MAX,
        };
        let c2 = PendingChallenge {
            nonce: [2u8; 32],
            shard_hash: "s2".to_string(),
            chunk_indices: vec![],
            expected_root: [0; 8],
            miner_uid: 2,
            sent_at: Instant::now(),
            expires_at: u64::MAX,
        };
        let c3 = PendingChallenge {
            nonce: [3u8; 32],
            shard_hash: "s3".to_string(),
            chunk_indices: vec![],
            expected_root: [0; 8],
            miner_uid: 3,
            sent_at: Instant::now(),
            expires_at: u64::MAX,
        };

        assert!(state.add_pending(c1));
        assert!(state.add_pending(c2));
        assert_eq!(state.pending_count(), 2);

        // At capacity - should be rejected
        assert!(!state.add_pending(c3));
        assert_eq!(state.pending_count(), 2);
    }

    #[test]
    fn test_persistence_across_restarts() {
        let dir = tempdir().unwrap();
        let db_path = dir.path().join("test.db");

        // First session: add shards
        {
            let state =
                WardenState::open(&db_path, DEFAULT_MAX_SHARDS, DEFAULT_MAX_PENDING_CHALLENGES)
                    .unwrap();
            state.load_and_recover().unwrap();

            state.upsert_shard(make_shard("persistent1", 1));
            state.upsert_shard(make_shard("persistent2", 2));
            assert_eq!(state.shard_count(), 2);

            // Advance cursor
            state.select_shards_for_audit(1);
            state.flush().unwrap();
        }

        // Second session: verify shards persist
        {
            let state =
                WardenState::open(&db_path, DEFAULT_MAX_SHARDS, DEFAULT_MAX_PENDING_CHALLENGES)
                    .unwrap();
            let loaded = state.load_and_recover().unwrap();

            assert_eq!(loaded, 2);
            assert_eq!(state.shard_count(), 2);

            // Verify cursor was persisted (should be >= 1 from previous session)
            let cursor = state.audit_cursor.load(Ordering::Relaxed);
            assert!(cursor >= 1, "Cursor should have been persisted");

            // Verify we can still access shards
            let shard = state.get_shard("persistent1");
            assert!(shard.is_some());
            assert_eq!(shard.unwrap().miner_uid, 1);
        }
    }

    #[test]
    fn test_cursor_persistence() {
        let dir = tempdir().unwrap();
        let db_path = dir.path().join("test.db");

        // First session: advance cursor significantly
        {
            let state =
                WardenState::open(&db_path, DEFAULT_MAX_SHARDS, DEFAULT_MAX_PENDING_CHALLENGES)
                    .unwrap();
            state.load_and_recover().unwrap();

            for i in 0..5 {
                state.upsert_shard(make_shard(&format!("shard{}", i), i as u32));
            }

            // Advance cursor past 100 to trigger persistence
            for _ in 0..50 {
                state.select_shards_for_audit(3);
            }

            state.flush().unwrap();
        }

        // Second session: verify cursor persisted
        {
            let state =
                WardenState::open(&db_path, DEFAULT_MAX_SHARDS, DEFAULT_MAX_PENDING_CHALLENGES)
                    .unwrap();
            state.load_and_recover().unwrap();

            let cursor = state.audit_cursor.load(Ordering::Relaxed);
            // Should be at least 150 (50 iterations * 3 shards each)
            assert!(
                cursor >= 150,
                "Cursor should be at least 150, got {}",
                cursor
            );
        }
    }

    fn make_test_report(audit_id: &str, miner_uid: u32) -> WardenAuditReport {
        WardenAuditReport {
            audit_id: audit_id.to_string(),
            warden_pubkey: hex::encode([1u8; 32]),
            miner_uid,
            shard_hash: "test_shard".to_string(),
            result: common::AuditResultType::Passed,
            timestamp: common::now_secs(),
            signature: vec![0u8; 64],
            block_number: 100,
            merkle_proof_sig_hash: vec![],
            warden_id: "test_warden".to_string(),
        }
    }

    #[test]
    fn test_retry_queue_basic() {
        let (state, _dir) = create_test_state();

        let report = make_test_report("audit1", 1);
        assert!(state.queue_for_retry(report.clone()));
        assert_eq!(state.retry_queue_size(), 1);

        // Queue another
        let report2 = make_test_report("audit2", 2);
        assert!(state.queue_for_retry(report2));
        assert_eq!(state.retry_queue_size(), 2);

        // Remove first
        state.remove_from_retry_queue("audit1:1");
        assert_eq!(state.retry_queue_size(), 1);
    }

    #[test]
    fn test_retry_queue_backoff() {
        let dir = tempdir().unwrap();
        let db_path = dir.path().join("test.db");
        let state = WardenState::open_with_retry_queue(&db_path, 100, 100, 100).unwrap();

        let report = make_test_report("audit_backoff", 1);
        assert!(state.queue_for_retry(report));

        // Should be ready immediately (backoff is 30s for retry_count=0)
        // But since we just queued it, last_retry_at is now, so not ready yet
        let ready = state.get_retry_ready(10);
        assert!(ready.is_empty(), "Should not be ready immediately");

        // Simulate time passing by directly modifying the entry
        // For testing, we'll just verify the logic works
    }

    #[test]
    fn test_retry_queue_max_retries() {
        let (state, _dir) = create_test_state();

        // Create two reports with different keys
        let report1 = make_test_report("audit_other", 99);
        let report2 = make_test_report("audit_max", 1);

        assert!(state.queue_for_retry(report1.clone()));
        assert_eq!(state.retry_queue_size(), 1);

        // Manually create an entry at max retries - 1 with different key
        let key = "audit_max:1";
        let entry = super::RetryableAttestation {
            report: report2.clone(),
            retry_count: super::MAX_RETRY_ATTEMPTS - 1,
            queued_at: common::now_secs(),
            last_retry_at: 0, // Old timestamp so it's ready
        };

        // Serialize and insert directly
        let bytes = bincode::serialize(&entry).unwrap();
        state
            .retry_queue_tree
            .insert(key.as_bytes(), bytes)
            .unwrap();

        // Should be in queue
        assert_eq!(state.retry_queue_size(), 2); // Both entries

        // Mark as failed - should remove since at max retries
        state.mark_retry_failed(key, &entry);
        assert_eq!(state.retry_queue_size(), 1); // Only the other one remains
    }

    #[test]
    fn test_retry_queue_capacity() {
        let dir = tempdir().unwrap();
        let db_path = dir.path().join("test.db");
        let state = WardenState::open_with_retry_queue(&db_path, 100, 100, 2).unwrap();

        let report1 = make_test_report("audit1", 1);
        let report2 = make_test_report("audit2", 2);
        let report3 = make_test_report("audit3", 3);

        assert!(state.queue_for_retry(report1));
        assert!(state.queue_for_retry(report2));
        assert_eq!(state.retry_queue_size(), 2);

        // At capacity - should reject
        assert!(!state.queue_for_retry(report3));
        assert_eq!(state.retry_queue_size(), 2);
    }

    #[test]
    fn test_retry_queue_persistence() {
        let dir = tempdir().unwrap();
        let db_path = dir.path().join("test.db");

        // First session: queue some attestations
        {
            let state = WardenState::open_with_retry_queue(&db_path, 100, 100, 100).unwrap();
            state.load_and_recover().unwrap();

            let report = make_test_report("persist_audit", 42);
            assert!(state.queue_for_retry(report));
            assert_eq!(state.retry_queue_size(), 1);

            state.flush().unwrap();
        }

        // Second session: verify persistence
        {
            let state = WardenState::open_with_retry_queue(&db_path, 100, 100, 100).unwrap();
            let loaded = state.load_and_recover().unwrap();

            // Retry queue should still have the entry
            assert_eq!(state.retry_queue_size(), 1);

            // Can get the entry (set last_retry_at to 0 to make it ready)
            // For this test, just verify it exists
        }
    }
}

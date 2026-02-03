//! Attestation aggregator for collecting and bundling warden audit results.
//!
//! This module accumulates warden attestations over the course of an epoch,
//! then builds a merkle tree bundle when the epoch changes.
//!
//! # Flow
//!
//! 1. Warden sends audit results via P2P (`hippius/warden-control`)
//! 2. Validator processes reputation updates and calls `add_attestation()`
//! 3. On epoch change, `finalize_epoch()` is called to:
//!    - Build BLAKE3 merkle tree of all attestations
//!    - Build BLAKE3 merkle tree of unique warden pubkeys
//!    - Create the `AttestationBundle`
//!    - Return the bundle for upload to Arion
//!
//! # Deduplication
//!
//! Attestations are deduplicated by `audit_id` to prevent the same audit
//! from being included multiple times (e.g., if warden retries).

use common::{
    AttestationBundle, AttestationLeaf, AttestationWithProof, EpochAttestationCommitment,
    WardenAuditReport, build_merkle_tree,
};
use dashmap::{DashMap, DashSet};
use std::sync::atomic::{AtomicU64, Ordering};
use tracing::{debug, info, warn};

/// Default maximum attestations per epoch to prevent unbounded memory growth
const DEFAULT_MAX_ATTESTATIONS_PER_EPOCH: usize = 100_000;

/// Aggregates attestations for bundling at epoch boundaries.
pub struct AttestationAggregator {
    /// Current epoch being accumulated
    current_epoch: AtomicU64,
    /// Attestations for current epoch: audit_id -> AttestationLeaf
    current_attestations: DashMap<String, AttestationLeaf>,
    /// Unique warden pubkeys seen in current epoch (lock-free)
    warden_pubkeys: DashSet<[u8; 32]>,
    /// Maximum attestations to accumulate per epoch
    max_attestations_per_epoch: usize,
    /// Counter for attestations added
    attestations_added: AtomicU64,
    /// Counter for attestations skipped (duplicate)
    attestations_skipped: AtomicU64,
}

impl AttestationAggregator {
    /// Create a new aggregator starting at the given epoch.
    pub fn new(initial_epoch: u64) -> Self {
        Self::with_max_attestations(initial_epoch, DEFAULT_MAX_ATTESTATIONS_PER_EPOCH)
    }

    /// Create a new aggregator with a custom max attestations limit.
    pub fn with_max_attestations(initial_epoch: u64, max_attestations: usize) -> Self {
        Self {
            current_epoch: AtomicU64::new(initial_epoch),
            current_attestations: DashMap::new(),
            warden_pubkeys: DashSet::new(),
            max_attestations_per_epoch: max_attestations,
            attestations_added: AtomicU64::new(0),
            attestations_skipped: AtomicU64::new(0),
        }
    }

    /// Get the current epoch being accumulated
    pub fn current_epoch(&self) -> u64 {
        self.current_epoch.load(Ordering::SeqCst)
    }

    /// Get the count of attestations in the current epoch
    pub fn attestation_count(&self) -> usize {
        self.current_attestations.len()
    }

    /// Get the total attestations added counter (for metrics)
    pub fn total_added(&self) -> u64 {
        self.attestations_added.load(Ordering::Relaxed)
    }

    /// Get the total attestations skipped counter (for metrics)
    pub fn total_skipped(&self) -> u64 {
        self.attestations_skipped.load(Ordering::Relaxed)
    }

    /// Add an attestation from a warden audit report.
    ///
    /// Returns true if the attestation was added, false if it was a duplicate
    /// or the limit was reached.
    pub fn add_attestation(&self, report: &WardenAuditReport) -> bool {
        // Check if we've hit the limit
        if self.current_attestations.len() >= self.max_attestations_per_epoch {
            debug!(
                audit_id = %report.audit_id,
                "Attestation rejected: epoch limit reached"
            );
            return false;
        }

        // Check for duplicate
        if self.current_attestations.contains_key(&report.audit_id) {
            debug!(
                audit_id = %report.audit_id,
                "Attestation skipped: duplicate"
            );
            self.attestations_skipped.fetch_add(1, Ordering::Relaxed);
            return false;
        }

        // Convert to AttestationLeaf
        let leaf = match Self::convert_report_to_leaf(report) {
            Some(leaf) => leaf,
            None => {
                warn!(
                    audit_id = %report.audit_id,
                    "Failed to convert audit report to attestation leaf"
                );
                return false;
            }
        };

        // Store the attestation
        self.current_attestations
            .insert(report.audit_id.clone(), leaf.clone());
        self.attestations_added.fetch_add(1, Ordering::Relaxed);

        // Track the warden pubkey (lock-free insert via DashSet)
        self.warden_pubkeys.insert(leaf.warden_pubkey);

        debug!(
            audit_id = %report.audit_id,
            miner_uid = report.miner_uid,
            count = self.current_attestations.len(),
            "Attestation added to aggregator"
        );

        true
    }

    /// Finalize the current epoch and build the attestation bundle.
    ///
    /// This should be called when the cluster map epoch changes.
    /// Returns `None` if there are no attestations for the epoch.
    ///
    /// After calling this, the aggregator is reset for the new epoch.
    pub async fn finalize_epoch(
        &self,
        new_epoch: u64,
    ) -> Option<(AttestationBundle, EpochAttestationCommitment)> {
        let old_epoch = self.current_epoch.swap(new_epoch, Ordering::SeqCst);

        // Check if epoch actually changed
        if new_epoch == old_epoch {
            return None;
        }

        // Check if there are any attestations
        if self.current_attestations.is_empty() {
            info!(
                old_epoch = old_epoch,
                new_epoch = new_epoch,
                "No attestations for epoch, skipping bundle"
            );
            // Reset state for new epoch
            self.warden_pubkeys.clear();
            return None;
        }

        info!(
            old_epoch = old_epoch,
            new_epoch = new_epoch,
            attestation_count = self.current_attestations.len(),
            "Finalizing epoch attestations"
        );

        // Drain all attestations
        let attestations: Vec<(String, AttestationLeaf)> = self
            .current_attestations
            .iter()
            .map(|entry| (entry.key().clone(), entry.value().clone()))
            .collect();

        self.current_attestations.clear();

        // Get unique warden pubkeys (lock-free via DashSet)
        let warden_pubkeys: Vec<[u8; 32]> = self.warden_pubkeys.iter().map(|r| *r).collect();
        self.warden_pubkeys.clear();

        // Sort attestations by audit_id for deterministic ordering
        let mut attestation_leaves: Vec<AttestationLeaf> =
            attestations.into_iter().map(|(_, leaf)| leaf).collect();
        // Sort by a deterministic key (shard_hash + timestamp)
        attestation_leaves
            .sort_by(|a, b| (&a.shard_hash, a.timestamp).cmp(&(&b.shard_hash, b.timestamp)));

        // Build merkle tree for attestations
        let (attestation_root, attestation_proofs) = build_merkle_tree(&attestation_leaves);

        // Build merkle tree for warden pubkeys
        let mut sorted_pubkeys = warden_pubkeys;
        sorted_pubkeys.sort();
        let (warden_root, warden_proofs) = if sorted_pubkeys.is_empty() {
            ([0u8; 32], Vec::new())
        } else {
            build_merkle_tree(&sorted_pubkeys)
        };

        // Combine attestations with their proofs
        let attestations_with_proofs: Vec<AttestationWithProof> = attestation_leaves
            .into_iter()
            .zip(attestation_proofs.into_iter())
            .map(|(attestation, proof)| AttestationWithProof { attestation, proof })
            .collect();

        // Build the bundle
        let bundle = AttestationBundle {
            version: AttestationBundle::CURRENT_VERSION,
            epoch: old_epoch,
            attestation_merkle_root: attestation_root,
            warden_pubkey_merkle_root: warden_root,
            attestations: attestations_with_proofs,
            warden_pubkeys: sorted_pubkeys.clone(),
            warden_pubkey_proofs: warden_proofs,
        };

        // Create commitment (arion_content_hash will be filled in after upload)
        let commitment = EpochAttestationCommitment {
            epoch: old_epoch,
            arion_content_hash: [0u8; 32], // Placeholder - filled after upload
            attestation_merkle_root: attestation_root,
            warden_pubkey_merkle_root: warden_root,
            attestation_count: bundle.attestation_count() as u32,
        };

        info!(
            epoch = old_epoch,
            attestation_count = bundle.attestation_count(),
            warden_count = bundle.warden_pubkeys.len(),
            "Built attestation bundle"
        );

        Some((bundle, commitment))
    }

    /// Convert a WardenAuditReport to an AttestationLeaf.
    fn convert_report_to_leaf(report: &WardenAuditReport) -> Option<AttestationLeaf> {
        let warden_pubkey = Self::parse_warden_pubkey(&report.warden_pubkey)?;
        let signature: [u8; 64] = report.signature.clone().try_into().ok()?;

        // Parse challenge_seed from audit_id (hex-encoded)
        let challenge_seed: [u8; 32] = hex::decode(&report.audit_id)
            .ok()
            .and_then(|bytes| bytes.try_into().ok())?;

        Some(AttestationLeaf {
            audit_id: report.audit_id.clone(),
            shard_hash: report.shard_hash.clone(),
            miner_uid: report.miner_uid,
            result: report.result.into(),
            challenge_seed,
            block_number: report.block_number,
            timestamp: report.timestamp,
            merkle_proof_sig_hash: report.merkle_proof_sig_hash.clone(),
            warden_id: report.warden_id.as_bytes().to_vec(),
            warden_pubkey,
            signature,
        })
    }

    /// Parse warden public key from Iroh format or hex string.
    fn parse_warden_pubkey(pubkey_str: &str) -> Option<[u8; 32]> {
        // Try Iroh PublicKey format first
        if let Ok(pk) = pubkey_str.parse::<iroh::PublicKey>() {
            return Some(*pk.as_bytes());
        }

        // Fall back to hex decode
        let trimmed = pubkey_str.trim_start_matches("0x");
        let bytes = hex::decode(trimmed).ok()?;
        bytes.try_into().ok()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use common::AuditResultType;

    fn make_test_report(audit_id: &str, miner_uid: u32) -> WardenAuditReport {
        // audit_id must be a valid 32-byte hex string (challenge_seed)
        // Use the audit_id string to generate a deterministic 32-byte value
        let mut challenge_seed = [0u8; 32];
        let audit_bytes = audit_id.as_bytes();
        for (i, &b) in audit_bytes.iter().enumerate() {
            challenge_seed[i % 32] ^= b;
        }
        let audit_id_hex = hex::encode(challenge_seed);

        WardenAuditReport {
            audit_id: audit_id_hex,
            warden_pubkey: "0".repeat(64), // Dummy hex pubkey
            miner_uid,
            shard_hash: "abc123".to_string(),
            result: AuditResultType::Passed,
            timestamp: 1700000000,
            signature: vec![0u8; 64],
            block_number: 0,
            merkle_proof_sig_hash: vec![],
            warden_id: String::new(),
        }
    }

    #[tokio::test]
    async fn test_add_attestation() {
        let aggregator = AttestationAggregator::new(1);

        let report = make_test_report("audit-1", 42);
        assert!(aggregator.add_attestation(&report));
        assert_eq!(aggregator.attestation_count(), 1);

        // Duplicate should be rejected
        assert!(!aggregator.add_attestation(&report));
        assert_eq!(aggregator.attestation_count(), 1);
    }

    #[tokio::test]
    async fn test_finalize_epoch_empty() {
        let aggregator = AttestationAggregator::new(1);

        // Finalize with no attestations
        let result = aggregator.finalize_epoch(2).await;
        assert!(result.is_none());
        assert_eq!(aggregator.current_epoch(), 2);
    }

    #[tokio::test]
    async fn test_finalize_epoch_with_attestations() {
        let aggregator = AttestationAggregator::new(1);

        // Add some attestations
        aggregator.add_attestation(&make_test_report("audit-1", 1));
        aggregator.add_attestation(&make_test_report("audit-2", 2));
        aggregator.add_attestation(&make_test_report("audit-3", 3));

        // Finalize
        let result = aggregator.finalize_epoch(2).await;
        assert!(result.is_some());

        let (bundle, commitment) = result.unwrap();
        assert_eq!(bundle.epoch, 1);
        assert_eq!(bundle.attestation_count(), 3);
        assert_eq!(commitment.epoch, 1);
        assert_eq!(commitment.attestation_count, 3);

        // Aggregator should be reset
        assert_eq!(aggregator.attestation_count(), 0);
        assert_eq!(aggregator.current_epoch(), 2);
    }

    #[tokio::test]
    async fn test_max_attestations_limit() {
        let aggregator = AttestationAggregator::with_max_attestations(1, 2);

        assert!(aggregator.add_attestation(&make_test_report("audit-1", 1)));
        assert!(aggregator.add_attestation(&make_test_report("audit-2", 2)));

        // Third should be rejected due to limit
        assert!(!aggregator.add_attestation(&make_test_report("audit-3", 3)));
        assert_eq!(aggregator.attestation_count(), 2);
    }

    #[tokio::test]
    async fn test_same_epoch_finalize() {
        let aggregator = AttestationAggregator::new(1);
        aggregator.add_attestation(&make_test_report("audit-1", 1));

        // Finalizing with same epoch should return None
        let result = aggregator.finalize_epoch(1).await;
        assert!(result.is_none());

        // Attestations should still be there
        assert_eq!(aggregator.attestation_count(), 1);
    }
}

//! Reputation processor for warden audit integration.
//!
//! Processes audit results from wardens and updates miner reputation scores.

use common::{AuditResultType, MinerNode, WardenAuditBatch, WardenAuditReport};
use quick_cache::sync::Cache;
use tracing::{debug, info, warn};

use crate::config::ReputationConfig;

/// Processes warden audit reports and updates miner reputation.
pub struct ReputationProcessor {
    config: ReputationConfig,
    /// Deduplication cache: audit_id -> timestamp
    processed: Cache<String, u64>,
}

/// Result of processing a single audit report.
#[derive(Debug)]
pub struct AuditProcessResult {
    pub miner_uid: u32,
    pub reputation_delta: f32,
    pub new_reputation: f32,
    pub should_ban: bool,
}

/// Result of processing a batch of audit reports.
#[derive(Debug, Default)]
pub struct BatchResult {
    pub processed: usize,
    pub skipped_duplicate: usize,
    pub skipped_invalid: usize,
    pub miners_updated: Vec<AuditProcessResult>,
}

impl ReputationProcessor {
    /// Create a new reputation processor with the given config.
    pub fn new(config: ReputationConfig) -> Self {
        Self {
            config,
            processed: Cache::new(10_000), // Track last 10k audit IDs
        }
    }

    /// Check if a warden is allowed to submit reports.
    pub fn is_warden_allowed(&self, warden_pubkey: &str) -> bool {
        // Empty list = allow all wardens (skip signature check)
        if self.config.allowed_wardens.is_empty() {
            return true;
        }
        self.config
            .allowed_wardens
            .iter()
            .any(|w| w == warden_pubkey)
    }

    /// Process a batch of audit reports, updating miner reputation.
    ///
    /// Returns results for each processed report and counts of skipped reports.
    pub fn process_batch(&self, batch: &WardenAuditBatch, miners: &mut [MinerNode]) -> BatchResult {
        let mut result = BatchResult::default();

        for report in &batch.reports {
            // Check warden authorization
            if !self.is_warden_allowed(&report.warden_pubkey) {
                warn!(
                    warden = %report.warden_pubkey,
                    audit_id = %report.audit_id,
                    "Rejected audit from unauthorized warden"
                );
                result.skipped_invalid += 1;
                continue;
            }

            // Deduplication check
            if self.processed.get(&report.audit_id).is_some() {
                debug!(audit_id = %report.audit_id, "Skipping duplicate audit");
                result.skipped_duplicate += 1;
                continue;
            }

            // Find the miner
            let miner = match miners.iter_mut().find(|m| m.uid == report.miner_uid) {
                Some(m) => m,
                None => {
                    warn!(
                        miner_uid = report.miner_uid,
                        audit_id = %report.audit_id,
                        "Miner not found for audit report"
                    );
                    result.skipped_invalid += 1;
                    continue;
                }
            };

            // Apply the audit result
            let old_reputation = miner.reputation;
            let should_ban = self.apply_audit(report, miner);

            let audit_result = AuditProcessResult {
                miner_uid: report.miner_uid,
                reputation_delta: miner.reputation - old_reputation,
                new_reputation: miner.reputation,
                should_ban,
            };

            info!(
                miner_uid = report.miner_uid,
                result = ?report.result,
                old_reputation = old_reputation,
                new_reputation = miner.reputation,
                should_ban = should_ban,
                "Processed audit report"
            );

            // Mark as processed
            self.processed
                .insert(report.audit_id.clone(), report.timestamp);
            result.miners_updated.push(audit_result);
            result.processed += 1;
        }

        result
    }

    /// Apply a single audit result to a miner's reputation.
    ///
    /// Returns true if the miner should be banned (reputation >= ban_threshold).
    fn apply_audit(&self, report: &WardenAuditReport, miner: &mut MinerNode) -> bool {
        match report.result {
            AuditResultType::Passed => {
                miner.consecutive_audit_passes += 1;
                let recovery_threshold_met =
                    miner.consecutive_audit_passes >= self.config.min_passes_for_recovery;
                if recovery_threshold_met {
                    miner.reputation = (miner.reputation - self.config.recovery_rate).max(0.0);
                }
            }
            AuditResultType::Failed | AuditResultType::InvalidProof | AuditResultType::Timeout => {
                let penalty = match report.result {
                    AuditResultType::Failed => self.config.strike_weight_failed,
                    AuditResultType::InvalidProof => self.config.strike_weight_invalid_proof,
                    AuditResultType::Timeout => self.config.strike_weight_timeout,
                    AuditResultType::Passed => unreachable!(),
                };
                miner.reputation += penalty;
                miner.consecutive_audit_passes = 0;
            }
        }

        // Sync strikes from reputation (backward compatibility)
        miner.strikes = miner.reputation.floor() as u8;

        // Check ban threshold
        miner.reputation >= self.config.ban_threshold
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::str::FromStr;

    fn test_config() -> ReputationConfig {
        ReputationConfig {
            allowed_wardens: vec![],
            strike_weight_failed: 1.0,
            strike_weight_invalid_proof: 1.0,
            strike_weight_timeout: 0.3,
            recovery_rate: 0.05,
            min_passes_for_recovery: 10,
            ban_threshold: 3.0,
        }
    }

    fn test_miner(uid: u32) -> MinerNode {
        // Use a valid hex-encoded public key for tests
        let test_pubkey = "0000000000000000000000000000000000000000000000000000000000000000";
        let node_id = iroh::PublicKey::from_str(test_pubkey).unwrap();
        MinerNode {
            uid,
            endpoint: iroh::EndpointAddr::new(node_id),
            weight: 100,
            ip_subnet: "0.0.0.0/0".to_string(),
            http_addr: "http://localhost:3001".to_string(),
            public_key: "test".to_string(),
            total_storage: 1_000_000,
            available_storage: 500_000,
            family_id: "test".to_string(),
            strikes: 0,
            last_seen: 0,
            heartbeat_count: 0,
            registration_time: 0,
            bandwidth_total: 0,
            bandwidth_window_start: 0,
            weight_manual_override: false,
            reputation: 0.0,
            consecutive_audit_passes: 0,
        }
    }

    fn test_report(miner_uid: u32, result: AuditResultType) -> WardenAuditReport {
        WardenAuditReport {
            audit_id: format!("audit-{}-{:?}", miner_uid, result),
            warden_pubkey: "warden1".to_string(),
            miner_uid,
            shard_hash: "shard123".to_string(),
            result,
            timestamp: 1000,
            signature: vec![],
            block_number: 0,
            merkle_proof_sig_hash: vec![],
            warden_id: String::new(),
        }
    }

    #[test]
    fn test_failed_audit_increases_reputation() {
        let processor = ReputationProcessor::new(test_config());
        let mut miners = vec![test_miner(1)];

        let batch = WardenAuditBatch {
            reports: vec![test_report(1, AuditResultType::Failed)],
        };

        let result = processor.process_batch(&batch, &mut miners);

        assert_eq!(result.processed, 1);
        assert_eq!(miners[0].reputation, 1.0);
        assert_eq!(miners[0].strikes, 1);
        assert_eq!(miners[0].consecutive_audit_passes, 0);
    }

    #[test]
    fn test_timeout_increases_reputation_fractionally() {
        let processor = ReputationProcessor::new(test_config());
        let mut miners = vec![test_miner(1)];

        let batch = WardenAuditBatch {
            reports: vec![test_report(1, AuditResultType::Timeout)],
        };

        let result = processor.process_batch(&batch, &mut miners);

        assert_eq!(result.processed, 1);
        assert!((miners[0].reputation - 0.3).abs() < 0.001);
        assert_eq!(miners[0].strikes, 0); // floor(0.3) = 0
    }

    #[test]
    fn test_passed_audit_increments_passes() {
        let processor = ReputationProcessor::new(test_config());
        let mut miners = vec![test_miner(1)];
        miners[0].reputation = 1.0; // Start with some reputation

        let batch = WardenAuditBatch {
            reports: vec![test_report(1, AuditResultType::Passed)],
        };

        let result = processor.process_batch(&batch, &mut miners);

        assert_eq!(result.processed, 1);
        assert_eq!(miners[0].consecutive_audit_passes, 1);
        assert_eq!(miners[0].reputation, 1.0); // No recovery yet (need 10 passes)
    }

    #[test]
    fn test_recovery_after_min_passes() {
        let processor = ReputationProcessor::new(test_config());
        let mut miners = vec![test_miner(1)];
        miners[0].reputation = 1.0;
        miners[0].consecutive_audit_passes = 9; // One more pass triggers recovery

        let batch = WardenAuditBatch {
            reports: vec![test_report(1, AuditResultType::Passed)],
        };

        let result = processor.process_batch(&batch, &mut miners);

        assert_eq!(result.processed, 1);
        assert_eq!(miners[0].consecutive_audit_passes, 10);
        assert!((miners[0].reputation - 0.95).abs() < 0.001); // 1.0 - 0.05 = 0.95
    }

    #[test]
    fn test_ban_threshold() {
        let processor = ReputationProcessor::new(test_config());
        let mut miners = vec![test_miner(1)];
        miners[0].reputation = 2.5;

        let batch = WardenAuditBatch {
            reports: vec![test_report(1, AuditResultType::Failed)],
        };

        let result = processor.process_batch(&batch, &mut miners);

        assert_eq!(result.processed, 1);
        assert!(result.miners_updated[0].should_ban);
        assert_eq!(miners[0].reputation, 3.5);
    }

    #[test]
    fn test_deduplication() {
        let processor = ReputationProcessor::new(test_config());
        let mut miners = vec![test_miner(1)];

        let report = test_report(1, AuditResultType::Failed);
        let batch = WardenAuditBatch {
            reports: vec![report.clone(), report],
        };

        let result = processor.process_batch(&batch, &mut miners);

        assert_eq!(result.processed, 1);
        assert_eq!(result.skipped_duplicate, 1);
        assert_eq!(miners[0].reputation, 1.0); // Only applied once
    }
}

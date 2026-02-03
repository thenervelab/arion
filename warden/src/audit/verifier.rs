//! Proof verification using pos-circuits.
//!
//! This module is scaffolding for P2P proof-of-storage verification.
//! Currently tested but not wired up to the P2P layer.

use pos_circuits::{Challenge as PosChallenge, Commitment, Proof, verify_proof as pos_verify};
use tracing::{debug, warn};

/// Default chunk size in bytes for proof verification.
#[allow(dead_code)]
const DEFAULT_CHUNK_SIZE: usize = 1024;

/// Result of verifying a proof.
#[allow(dead_code)] // Scaffolding for P2P integration
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum VerifyResult {
    /// Proof is valid
    Passed,
    /// Proof failed verification
    Failed,
    /// Proof data was malformed
    InvalidProof,
}

/// Verify a proof-of-storage response.
///
/// # Arguments
/// * `proof_bytes` - Serialized proof from miner
/// * `merkle_root` - Expected Merkle root from commitment
/// * `chunk_indices` - The challenged chunk indices
/// * `chunk_count` - Total chunks in the shard
/// * `shard_hash` - The shard being verified
/// * `expires_at` - Challenge expiry timestamp
///
/// # Returns
/// `VerifyResult` indicating pass/fail/invalid
#[allow(dead_code)] // Scaffolding for P2P integration
pub fn verify_pos_proof(
    proof_bytes: &[u8],
    merkle_root: [u32; 8],
    chunk_indices: &[u32],
    chunk_count: u32,
    shard_hash: &str,
    expires_at: u64,
) -> VerifyResult {
    // Deserialize the proof
    let proof = match Proof::from_bytes(proof_bytes) {
        Ok(p) => p,
        Err(e) => {
            warn!(error = %e, "Failed to deserialize proof");
            return VerifyResult::InvalidProof;
        }
    };

    // Build the commitment for verification
    let tree_depth = if chunk_count > 0 {
        (chunk_count as f64).log2().ceil() as usize
    } else {
        0
    };
    let commitment = Commitment {
        merkle_root,
        chunk_count,
        chunk_size: DEFAULT_CHUNK_SIZE,
        data_size: (chunk_count as usize) * DEFAULT_CHUNK_SIZE,
        shard_hash: shard_hash.to_string(),
        tree_depth,
    };

    // Build the challenge for verification
    let challenge = PosChallenge::new(shard_hash, chunk_indices.to_vec(), merkle_root, expires_at);

    // Verify the proof
    match pos_verify(&proof, &commitment, Some(&challenge)) {
        Ok(true) => {
            debug!("Proof verification passed");
            VerifyResult::Passed
        }
        Ok(false) => {
            debug!("Proof verification failed");
            VerifyResult::Failed
        }
        Err(e) => {
            warn!(error = %e, "Proof verification error");
            VerifyResult::InvalidProof
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use pos_circuits::commitment::CommitmentWithTree;
    use pos_circuits::prover::generate_proof;

    #[test]
    fn test_verify_valid_proof() {
        // Generate test data
        let data = vec![0xABu8; 4096]; // 4 chunks of 1024 bytes
        let commitment = CommitmentWithTree::generate(&data, 1024).unwrap();

        // Create challenge
        let chunk_indices = vec![0, 2];
        let challenge = PosChallenge::new(
            &commitment.commitment.shard_hash,
            chunk_indices.clone(),
            commitment.commitment.merkle_root,
            u64::MAX,
        );

        // Generate proof
        let proof = generate_proof(&data, &commitment, &challenge).unwrap();
        let proof_bytes = proof.to_bytes().unwrap();

        // Verify
        let result = verify_pos_proof(
            &proof_bytes,
            commitment.commitment.merkle_root,
            &chunk_indices,
            commitment.commitment.chunk_count,
            &commitment.commitment.shard_hash,
            u64::MAX,
        );

        assert_eq!(result, VerifyResult::Passed);
    }

    #[test]
    fn test_verify_invalid_proof_bytes() {
        let result = verify_pos_proof(
            &[1, 2, 3, 4], // Invalid proof bytes
            [0; 8],
            &[0],
            100,
            "test_shard",
            u64::MAX,
        );

        assert_eq!(result, VerifyResult::InvalidProof);
    }

    #[test]
    fn test_verify_wrong_root() {
        // Generate test data
        let data = vec![0xABu8; 4096];
        let commitment = CommitmentWithTree::generate(&data, 1024).unwrap();

        // Create challenge
        let chunk_indices = vec![0, 2];
        let challenge = PosChallenge::new(
            &commitment.commitment.shard_hash,
            chunk_indices.clone(),
            commitment.commitment.merkle_root,
            u64::MAX,
        );

        // Generate proof
        let proof = generate_proof(&data, &commitment, &challenge).unwrap();
        let proof_bytes = proof.to_bytes().unwrap();

        // Verify with WRONG root
        let result = verify_pos_proof(
            &proof_bytes,
            [1, 2, 3, 4, 5, 6, 7, 8], // Wrong root
            &chunk_indices,
            commitment.commitment.chunk_count,
            &commitment.commitment.shard_hash,
            u64::MAX,
        );

        assert_eq!(result, VerifyResult::Failed);
    }
}

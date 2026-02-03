//! Proof verification for proof-of-storage using Plonky3.
//!
//! This module provides verification functionality for Wardens and any
//! party that wants to verify a miner's proof-of-storage.
//!
//! Note: This implementation uses native Merkle proof verification.
//! A full STARK-based ZK implementation would use the Plonky3 uni-stark
//! verifier with the AIR defined in circuit.rs.

use crate::commitment::Commitment;
use crate::prover::deserialize_proof_data;
use crate::types::{Challenge, Proof};
use crate::{PosError, Result};

/// Get current Unix timestamp in seconds.
fn current_timestamp() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

/// Verify a proof-of-storage proof.
///
/// This verifies that:
/// 1. The proof data is valid
/// 2. All Merkle proofs verify against the commitment root
/// 3. The public inputs match the expected values
///
/// # Arguments
/// * `proof` - The proof to verify
/// * `commitment` - The commitment being verified against
/// * `challenge` - The original challenge (optional, for freshness check)
///
/// # Returns
/// `Ok(true)` if the proof is valid, `Ok(false)` if invalid, or an error
pub fn verify_proof(
    proof: &Proof,
    commitment: &Commitment,
    challenge: Option<&Challenge>,
) -> Result<bool> {
    let roots_match = proof.public_inputs.merkle_root == commitment.merkle_root;
    if !roots_match {
        return Ok(false);
    }

    if let Some(ch) = challenge {
        let indices_match = proof.public_inputs.chunk_indices == ch.chunk_indices;
        if !indices_match {
            return Ok(false);
        }

        let now = current_timestamp();
        if ch.expires_at < now {
            return Err(PosError::ChallengeExpired {
                expires_at: ch.expires_at,
                current: now,
            });
        }
    }

    let all_indices_valid = proof
        .public_inputs
        .chunk_indices
        .iter()
        .all(|&idx| idx < commitment.chunk_count);
    if !all_indices_valid {
        return Ok(false);
    }

    let proof_data = deserialize_proof_data(&proof.proof_bytes)
        .map_err(|e| PosError::InvalidProofFormat(format!("Failed to deserialize: {}", e)))?;

    let proof_root_matches = proof_data.merkle_root == commitment.merkle_root;
    let merkle_proofs_valid = proof_data.verify_native();
    let chunk_hashes_match = proof_data.chunk_hashes == proof.public_inputs.chunk_hashes;

    Ok(proof_root_matches && merkle_proofs_valid && chunk_hashes_match)
}

/// A verifier instance for verifying multiple proofs.
pub struct Verifier {
    // Reserved for future STARK configuration caching
}

impl Verifier {
    /// Create a new verifier instance.
    pub fn new() -> Self {
        Self {}
    }

    /// Verify a proof.
    pub fn verify(
        &mut self,
        proof: &Proof,
        commitment: &Commitment,
        challenge: Option<&Challenge>,
    ) -> Result<bool> {
        verify_proof(proof, commitment, challenge)
    }
}

impl Default for Verifier {
    fn default() -> Self {
        Self::new()
    }
}

/// Batch verification result.
#[derive(Debug)]
pub struct BatchVerifyResult {
    /// Number of proofs that passed verification
    pub passed: usize,
    /// Number of proofs that failed verification
    pub failed: usize,
    /// Indices of failed proofs
    pub failed_indices: Vec<usize>,
}

/// Verify multiple proofs in a batch.
pub fn batch_verify(
    verifier: &mut Verifier,
    proofs: &[(&Proof, &Commitment, Option<&Challenge>)],
) -> BatchVerifyResult {
    let mut passed = 0;
    let mut failed = 0;
    let mut failed_indices = Vec::new();

    for (i, (proof, commitment, challenge)) in proofs.iter().enumerate() {
        match verifier.verify(proof, commitment, *challenge) {
            Ok(true) => passed += 1,
            Ok(false) | Err(_) => {
                failed += 1;
                failed_indices.push(i);
            }
        }
    }

    BatchVerifyResult {
        passed,
        failed,
        failed_indices,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::commitment::CommitmentWithTree;
    use crate::prover::generate_proof;
    use crate::types::Challenge;

    fn create_valid_proof() -> (Proof, Commitment, CommitmentWithTree, Challenge) {
        let data = vec![0xABu8; 4096]; // 4 chunks
        let commitment = CommitmentWithTree::generate(&data, 1024).unwrap();

        let challenge = Challenge::new(
            &commitment.commitment.shard_hash,
            vec![0, 2],
            commitment.commitment.merkle_root,
            u64::MAX, // Never expires for tests
        );

        let proof = generate_proof(&data, &commitment, &challenge).unwrap();

        (proof, commitment.commitment.clone(), commitment, challenge)
    }

    #[test]
    fn test_verify_valid_proof() {
        let (proof, commitment, _, challenge) = create_valid_proof();

        let valid = verify_proof(&proof, &commitment, Some(&challenge)).unwrap();
        assert!(valid);
    }

    #[test]
    fn test_verify_without_challenge() {
        let (proof, commitment, _, _) = create_valid_proof();

        // Should still verify without challenge (no freshness check)
        let valid = verify_proof(&proof, &commitment, None).unwrap();
        assert!(valid);
    }

    #[test]
    fn test_verify_wrong_root() {
        let (proof, mut commitment, _, challenge) = create_valid_proof();

        // Tamper with the commitment root
        commitment.merkle_root = [1, 2, 3, 4, 5, 6, 7, 8];

        let valid = verify_proof(&proof, &commitment, Some(&challenge)).unwrap();
        assert!(!valid);
    }

    #[test]
    fn test_verify_wrong_indices() {
        let (proof, commitment, _, mut challenge) = create_valid_proof();

        // Change the challenge indices
        challenge.chunk_indices = vec![1, 3];

        let valid = verify_proof(&proof, &commitment, Some(&challenge)).unwrap();
        assert!(!valid);
    }

    #[test]
    fn test_verifier_struct() {
        let (proof, commitment, _, challenge) = create_valid_proof();

        let mut verifier = Verifier::new();

        let valid = verifier
            .verify(&proof, &commitment, Some(&challenge))
            .unwrap();
        assert!(valid);
    }

    #[test]
    fn test_batch_verify() {
        let (proof1, commitment1, _, challenge1) = create_valid_proof();
        let (proof2, commitment2, _, challenge2) = create_valid_proof();

        let mut verifier = Verifier::new();

        let proofs = vec![
            (&proof1, &commitment1, Some(&challenge1)),
            (&proof2, &commitment2, Some(&challenge2)),
        ];

        let result = batch_verify(&mut verifier, &proofs);

        assert_eq!(result.passed, 2);
        assert_eq!(result.failed, 0);
        assert!(result.failed_indices.is_empty());
    }

    #[test]
    fn test_batch_verify_with_invalid() {
        let (proof1, commitment1, _, challenge1) = create_valid_proof();
        let (proof2, mut commitment2, _, challenge2) = create_valid_proof();

        // Tamper with second commitment
        commitment2.merkle_root = [9, 9, 9, 9, 9, 9, 9, 9];

        let mut verifier = Verifier::new();

        let proofs = vec![
            (&proof1, &commitment1, Some(&challenge1)),
            (&proof2, &commitment2, Some(&challenge2)),
        ];

        let result = batch_verify(&mut verifier, &proofs);

        assert_eq!(result.passed, 1);
        assert_eq!(result.failed, 1);
        assert_eq!(result.failed_indices, vec![1]);
    }
}

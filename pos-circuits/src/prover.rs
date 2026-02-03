//! Proof generation for proof-of-storage using Plonky3.
//!
//! This module provides the prover functionality that miners use to
//! generate proofs demonstrating possession of challenged chunks.
//!
//! Note: This implementation uses native Merkle proof verification with
//! cryptographic commitments. A full STARK-based ZK implementation would
//! require integrating the Plonky3 uni-stark prover with the AIR defined
//! in circuit.rs.

use std::time::Instant;

use crate::circuit::PosProofData;
use crate::commitment::CommitmentWithTree;
use crate::config::DIGEST_ELEMS;
use crate::types::{Challenge, Proof, PublicInputs};
use crate::{PosError, Result};

/// Generate a proof-of-storage proof for a challenge.
///
/// This is the main entry point for miners to generate proofs.
/// Given the shard data and a challenge, it:
/// 1. Extracts the challenged chunks
/// 2. Computes their hashes and Merkle proofs
/// 3. Verifies the proofs are valid
/// 4. Returns the proof data
///
/// # Arguments
/// * `_shard_data` - The complete shard data (unused, for API compatibility)
/// * `commitment` - The commitment with Merkle tree (from `CommitmentWithTree::generate`)
/// * `challenge` - The challenge specifying which chunks to prove
///
/// # Returns
/// A `Proof` that can be verified by any party with the commitment
pub fn generate_proof(
    _shard_data: &[u8],
    commitment: &CommitmentWithTree,
    challenge: &Challenge,
) -> Result<Proof> {
    let start = Instant::now();

    // Validate challenge
    challenge.validate(commitment.commitment.chunk_count)?;

    // Verify the challenge is for this shard
    if challenge.shard_hash != commitment.commitment.shard_hash {
        return Err(PosError::MerkleRootMismatch {
            expected: challenge.expected_root,
            actual: commitment.commitment.merkle_root,
        });
    }

    // Verify the expected root matches
    if challenge.expected_root != commitment.commitment.merkle_root {
        return Err(PosError::MerkleRootMismatch {
            expected: challenge.expected_root,
            actual: commitment.commitment.merkle_root,
        });
    }

    // Generate proof data
    let proof_data = PosProofData::from_commitment(commitment, &challenge.chunk_indices)?;

    // Verify proofs are valid (sanity check)
    if !proof_data.verify_native() {
        return Err(PosError::ProofGenerationError(
            "Internal error: Merkle proofs failed verification".to_string(),
        ));
    }

    // Serialize proof data
    // In a full STARK implementation, this would be the STARK proof bytes
    let proof_bytes = serialize_proof_data(&proof_data)?;

    let elapsed = start.elapsed();

    Ok(Proof {
        proof_bytes,
        public_inputs: PublicInputs {
            merkle_root: commitment.commitment.merkle_root,
            chunk_indices: challenge.chunk_indices.clone(),
            chunk_hashes: proof_data.chunk_hashes,
        },
        num_challenges: challenge.chunk_indices.len(),
        proving_time_ms: elapsed.as_millis() as u64,
    })
}

/// Serialize proof data to bytes.
fn serialize_proof_data(proof_data: &PosProofData) -> Result<Vec<u8>> {
    let mut bytes = Vec::new();

    write_hash(&mut bytes, &proof_data.merkle_root);
    write_u32(&mut bytes, proof_data.tree_depth as u32);
    write_u32(&mut bytes, proof_data.chunk_hashes.len() as u32);

    for (hash, proof) in proof_data
        .chunk_hashes
        .iter()
        .zip(proof_data.merkle_proofs.iter())
    {
        write_u32(&mut bytes, proof.leaf_index);
        write_hash(&mut bytes, hash);
        write_u32(&mut bytes, proof.siblings.len() as u32);
        for sibling in &proof.siblings {
            write_hash(&mut bytes, sibling);
        }
    }

    Ok(bytes)
}

fn write_u32(bytes: &mut Vec<u8>, value: u32) {
    bytes.extend_from_slice(&value.to_le_bytes());
}

fn write_hash(bytes: &mut Vec<u8>, hash: &[u32; DIGEST_ELEMS]) {
    for &elem in hash {
        bytes.extend_from_slice(&elem.to_le_bytes());
    }
}

/// Deserialize proof data from bytes.
pub fn deserialize_proof_data(bytes: &[u8]) -> Result<PosProofData> {
    use crate::types::MerkleProof;

    let mut reader = ByteReader::new(bytes);

    let merkle_root = reader.read_hash();
    let tree_depth = reader.read_u32() as usize;
    let num_proofs = reader.read_u32() as usize;

    let mut chunk_hashes = Vec::with_capacity(num_proofs);
    let mut merkle_proofs = Vec::with_capacity(num_proofs);
    let mut chunk_indices = Vec::with_capacity(num_proofs);

    for _ in 0..num_proofs {
        let leaf_index = reader.read_u32();
        chunk_indices.push(leaf_index);
        chunk_hashes.push(reader.read_hash());

        let num_siblings = reader.read_u32() as usize;
        let siblings: Vec<_> = (0..num_siblings).map(|_| reader.read_hash()).collect();

        merkle_proofs.push(MerkleProof {
            leaf_index,
            siblings,
        });
    }

    Ok(PosProofData {
        chunk_hashes,
        merkle_proofs,
        merkle_root,
        tree_depth,
        chunk_indices,
    })
}

struct ByteReader<'a> {
    bytes: &'a [u8],
    offset: usize,
}

impl<'a> ByteReader<'a> {
    fn new(bytes: &'a [u8]) -> Self {
        Self { bytes, offset: 0 }
    }

    fn read_u32(&mut self) -> u32 {
        let value =
            u32::from_le_bytes(self.bytes[self.offset..self.offset + 4].try_into().unwrap());
        self.offset += 4;
        value
    }

    fn read_hash(&mut self) -> [u32; DIGEST_ELEMS] {
        let mut hash = [0u32; DIGEST_ELEMS];
        for elem in &mut hash {
            *elem = self.read_u32();
        }
        hash
    }
}

/// A prover instance for generating multiple proofs.
pub struct Prover {
    // Reserved for future STARK configuration caching
}

impl Prover {
    /// Create a new prover instance.
    pub fn new() -> Self {
        Self {}
    }

    /// Generate a proof.
    pub fn prove(
        &mut self,
        shard_data: &[u8],
        commitment: &CommitmentWithTree,
        challenge: &Challenge,
    ) -> Result<Proof> {
        generate_proof(shard_data, commitment, challenge)
    }
}

impl Default for Prover {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::commitment::CommitmentWithTree;
    use crate::types::Challenge;

    fn create_test_data() -> (Vec<u8>, CommitmentWithTree) {
        let data = vec![0xABu8; 4096]; // 4 chunks
        let commitment = CommitmentWithTree::generate(&data, 1024).unwrap();
        (data, commitment)
    }

    #[test]
    fn test_generate_proof() {
        let (data, commitment) = create_test_data();

        let challenge = Challenge::new(
            &commitment.commitment.shard_hash,
            vec![0, 2],
            commitment.commitment.merkle_root,
            u64::MAX,
        );

        let proof = generate_proof(&data, &commitment, &challenge).unwrap();

        assert_eq!(proof.num_challenges, 2);
        assert_eq!(proof.public_inputs.chunk_indices, vec![0, 2]);
        assert!(!proof.proof_bytes.is_empty());
    }

    #[test]
    fn test_generate_proof_invalid_index() {
        let (data, commitment) = create_test_data();

        let challenge = Challenge::new(
            &commitment.commitment.shard_hash,
            vec![0, 100], // 100 is out of bounds
            commitment.commitment.merkle_root,
            u64::MAX,
        );

        assert!(generate_proof(&data, &commitment, &challenge).is_err());
    }

    #[test]
    fn test_proof_serialization_roundtrip() {
        let (data, commitment) = create_test_data();

        let challenge = Challenge::new(
            &commitment.commitment.shard_hash,
            vec![0, 1, 2, 3],
            commitment.commitment.merkle_root,
            u64::MAX,
        );

        let proof = generate_proof(&data, &commitment, &challenge).unwrap();

        // Deserialize
        let recovered = deserialize_proof_data(&proof.proof_bytes).unwrap();

        assert_eq!(recovered.merkle_root, commitment.commitment.merkle_root);
        assert_eq!(recovered.chunk_indices, vec![0, 1, 2, 3]);
        assert!(recovered.verify_native());
    }

    #[test]
    fn test_prover_struct() {
        let (data, commitment) = create_test_data();

        let mut prover = Prover::new();

        let challenge = Challenge::new(
            &commitment.commitment.shard_hash,
            vec![1, 3],
            commitment.commitment.merkle_root,
            u64::MAX,
        );

        let proof = prover.prove(&data, &commitment, &challenge).unwrap();
        assert_eq!(proof.num_challenges, 2);
    }
}

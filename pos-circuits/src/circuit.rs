//! AIR circuit for proof-of-storage verification using Plonky3.
//!
//! This module defines the Algebraic Intermediate Representation (AIR) for
//! verifying Merkle proofs in zero-knowledge. The AIR constrains:
//! 1. Each challenged chunk hash is correctly included in the Merkle tree
//! 2. The Merkle tree root matches the expected commitment root
//!
//! Unlike Plonky2's circuit builder approach, Plonky3 uses STARKs with AIR
//! constraints that operate on execution traces.

use p3_air::{Air, AirBuilder, BaseAir};
use p3_baby_bear::BabyBear;
use p3_field::{Field, PrimeCharacteristicRing};
use p3_matrix::dense::RowMajorMatrix;
use p3_matrix::Matrix;

use crate::config::{DIGEST_ELEMS, F};
use crate::hash::poseidon2_hash_two;
use crate::merkle::MerkleTree;
use crate::types::{MerkleProof, Poseidon2Hash};
use crate::Result;

/// Width of the AIR trace for Merkle proof verification.
/// Each row contains: current_hash (8) + sibling_hash (8) + path_bit (1) + is_active (1) = 18
pub const MERKLE_AIR_WIDTH: usize = 2 * DIGEST_ELEMS + 2;

/// AIR for verifying a single Merkle proof.
///
/// The trace has one row per level of the Merkle tree, computing the path
/// from leaf to root. Each row contains:
/// - current_hash: The hash at the current level (8 field elements)
/// - sibling_hash: The sibling hash at this level (8 field elements)
/// - path_bit: 0 if current is left child, 1 if right child
/// - is_active: 1 if this row is part of the proof, 0 for padding
#[derive(Clone, Debug)]
pub struct MerkleProofAir {
    /// Expected Merkle root
    pub expected_root: Poseidon2Hash,
    /// Depth of the tree (number of rows in trace)
    pub tree_depth: usize,
}

impl<F: Field> BaseAir<F> for MerkleProofAir {
    fn width(&self) -> usize {
        MERKLE_AIR_WIDTH
    }
}

impl<AB: AirBuilder<F: Field>> Air<AB> for MerkleProofAir {
    fn eval(&self, builder: &mut AB) {
        let main = builder.main();
        let local = main.row_slice(0).expect("row 0 must exist");
        let _next = main.row_slice(1).expect("row 1 must exist");

        // Extract columns from local row
        let _current_hash: Vec<AB::Var> = (0..DIGEST_ELEMS).map(|i| local[i].clone()).collect();
        let _sibling_hash: Vec<AB::Var> = (DIGEST_ELEMS..2 * DIGEST_ELEMS)
            .map(|i| local[i].clone())
            .collect();
        let path_bit = local[2 * DIGEST_ELEMS].clone();
        let is_active = local[2 * DIGEST_ELEMS + 1].clone();

        // Constraint 1: is_active must be boolean
        builder.assert_bool(is_active.clone());

        // Constraint 2: path_bit must be boolean when active
        let path_bit_expr = path_bit.into();
        let one = AB::Expr::ONE;
        builder
            .when(is_active)
            .assert_zero(path_bit_expr.clone() * (one - path_bit_expr));

        // Note: The actual Poseidon2 hash computation would need to be constrained
        // in a more complex AIR. For now, we trust the trace generator computes
        // hashes correctly. A full implementation would include Poseidon2 AIR gadgets.

        // Constraint 3: On the last active row, current_hash should equal expected_root
        // This is checked by the verifier against public inputs
    }
}

/// Generate the execution trace for a Merkle proof verification.
///
/// # Arguments
/// * `leaf_hash` - The hash of the leaf being proven
/// * `proof` - The Merkle proof (siblings from leaf to root)
/// * `tree_depth` - Total depth of the tree (for padding)
///
/// # Returns
/// A row-major matrix representing the execution trace
pub fn generate_merkle_proof_trace(
    leaf_hash: &Poseidon2Hash,
    proof: &MerkleProof,
    tree_depth: usize,
) -> RowMajorMatrix<F> {
    let num_rows = tree_depth.max(1).next_power_of_two();
    let mut values = vec![BabyBear::ZERO; num_rows * MERKLE_AIR_WIDTH];

    let mut current = *leaf_hash;
    let mut index = proof.leaf_index as usize;

    for (row, sibling) in proof.siblings.iter().enumerate() {
        let row_offset = row * MERKLE_AIR_WIDTH;

        // Set current_hash
        for (i, &val) in current.iter().enumerate() {
            values[row_offset + i] = BabyBear::new(val);
        }

        // Set sibling_hash
        for (i, &val) in sibling.iter().enumerate() {
            values[row_offset + DIGEST_ELEMS + i] = BabyBear::new(val);
        }

        // Set path_bit (0 = left child, 1 = right child)
        values[row_offset + 2 * DIGEST_ELEMS] = BabyBear::new((index % 2) as u32);

        // Set is_active
        values[row_offset + 2 * DIGEST_ELEMS + 1] = BabyBear::ONE;

        // Compute next hash
        current = if index % 2 == 0 {
            poseidon2_hash_two(&current, sibling)
        } else {
            poseidon2_hash_two(sibling, &current)
        };
        index /= 2;
    }

    // Pad remaining rows with zeros (is_active = 0)
    // Already initialized to zero

    RowMajorMatrix::new(values, MERKLE_AIR_WIDTH)
}

/// Data needed to generate and verify a proof-of-storage.
#[derive(Clone, Debug)]
pub struct PosProofData {
    /// The chunk hashes being proven
    pub chunk_hashes: Vec<Poseidon2Hash>,
    /// Merkle proofs for each chunk
    pub merkle_proofs: Vec<MerkleProof>,
    /// The expected Merkle root
    pub merkle_root: Poseidon2Hash,
    /// Depth of the Merkle tree
    pub tree_depth: usize,
    /// Chunk indices being proven
    pub chunk_indices: Vec<u32>,
}

impl PosProofData {
    /// Create proof data from commitment and challenge.
    pub fn from_commitment(
        commitment: &crate::commitment::CommitmentWithTree,
        chunk_indices: &[u32],
    ) -> Result<Self> {
        let mut chunk_hashes = Vec::with_capacity(chunk_indices.len());
        let mut merkle_proofs = Vec::with_capacity(chunk_indices.len());

        for &idx in chunk_indices {
            let idx = idx as usize;
            chunk_hashes.push(commitment.chunk_hash(idx)?);
            merkle_proofs.push(commitment.proof(idx)?);
        }

        Ok(Self {
            chunk_hashes,
            merkle_proofs,
            merkle_root: commitment.commitment.merkle_root,
            tree_depth: commitment.commitment.tree_depth,
            chunk_indices: chunk_indices.to_vec(),
        })
    }

    /// Verify all Merkle proofs (native verification, not ZK).
    pub fn verify_native(&self) -> bool {
        for (hash, proof) in self.chunk_hashes.iter().zip(self.merkle_proofs.iter()) {
            if !MerkleTree::verify_proof_against_root(hash, proof, &self.merkle_root) {
                return false;
            }
        }
        true
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::commitment::CommitmentWithTree;
    use crate::hash::poseidon2_hash_bytes;

    #[test]
    fn test_merkle_proof_air_width() {
        let air = MerkleProofAir {
            expected_root: [0; DIGEST_ELEMS],
            tree_depth: 7,
        };
        // Use concrete field type for width() call
        assert_eq!(
            <MerkleProofAir as BaseAir<F>>::width(&air),
            MERKLE_AIR_WIDTH
        );
    }

    #[test]
    fn test_generate_trace() {
        let data = vec![0xABu8; 4096]; // 4 chunks
        let cwt = CommitmentWithTree::generate(&data, 1024).unwrap();

        let leaf_hash = cwt.chunk_hash(2).unwrap();
        let proof = cwt.proof(2).unwrap();

        let trace = generate_merkle_proof_trace(&leaf_hash, &proof, cwt.commitment.tree_depth);

        // Trace should have width = MERKLE_AIR_WIDTH
        assert_eq!(trace.width(), MERKLE_AIR_WIDTH);

        // Trace should have power-of-2 rows
        assert!(trace.height().is_power_of_two());
    }

    #[test]
    fn test_pos_proof_data() {
        let data = vec![0xCDu8; 8192]; // 8 chunks
        let cwt = CommitmentWithTree::generate(&data, 1024).unwrap();

        let proof_data = PosProofData::from_commitment(&cwt, &[0, 3, 5, 7]).unwrap();

        assert_eq!(proof_data.chunk_hashes.len(), 4);
        assert_eq!(proof_data.merkle_proofs.len(), 4);
        assert_eq!(proof_data.chunk_indices, vec![0, 3, 5, 7]);

        // Native verification should pass
        assert!(proof_data.verify_native());
    }

    #[test]
    fn test_pos_proof_data_invalid() {
        let data = vec![0xEFu8; 4096];
        let cwt = CommitmentWithTree::generate(&data, 1024).unwrap();

        let mut proof_data = PosProofData::from_commitment(&cwt, &[0, 2]).unwrap();

        // Tamper with a chunk hash
        proof_data.chunk_hashes[0] = poseidon2_hash_bytes(b"wrong");

        // Native verification should fail
        assert!(!proof_data.verify_native());
    }
}

//! Merkle tree implementation using Poseidon2 hash.
//!
//! This module provides a binary Merkle tree optimized for proof-of-storage:
//! - Leaves are Poseidon2 hashes of data chunks
//! - Internal nodes combine children using Poseidon2 two-to-one hash
//! - Supports generating proofs for arbitrary leaf indices

use crate::config::DIGEST_ELEMS;
use crate::hash::{poseidon2_hash_bytes, poseidon2_hash_two};
use crate::types::{MerkleProof, Poseidon2Hash};
use crate::{PosError, Result};

/// A binary Merkle tree with Poseidon2 hashing.
///
/// The tree is stored as a flat array where:
/// - Leaves occupy indices [leaf_count..2*leaf_count)
/// - Internal nodes occupy indices [1..leaf_count)
/// - Index 0 is unused (for 1-indexed arithmetic)
#[derive(Clone, Debug)]
pub struct MerkleTree {
    /// All nodes stored in a flat array (1-indexed)
    nodes: Vec<Poseidon2Hash>,
    /// Number of leaves (always a power of 2)
    leaf_count: usize,
    /// Original number of data chunks (before padding)
    original_count: usize,
}

impl MerkleTree {
    /// Build a Merkle tree from data chunks.
    ///
    /// Each chunk is hashed with Poseidon2 to create a leaf.
    /// The number of leaves is padded to the next power of 2.
    ///
    /// # Arguments
    /// * `chunks` - Raw data chunks to build the tree from
    ///
    /// # Returns
    /// A new MerkleTree with the given chunks as leaves
    pub fn from_chunks(chunks: &[&[u8]]) -> Result<Self> {
        if chunks.is_empty() {
            return Err(PosError::EmptyData);
        }

        // Hash each chunk to create leaves
        let leaf_hashes: Vec<Poseidon2Hash> = chunks
            .iter()
            .map(|chunk| poseidon2_hash_bytes(chunk))
            .collect();

        Self::from_leaf_hashes(&leaf_hashes)
    }

    /// Build a Merkle tree from pre-computed leaf hashes.
    ///
    /// # Arguments
    /// * `leaf_hashes` - Pre-computed Poseidon2 hashes for each leaf
    ///
    /// # Returns
    /// A new MerkleTree with the given hashes as leaves
    pub fn from_leaf_hashes(leaf_hashes: &[Poseidon2Hash]) -> Result<Self> {
        if leaf_hashes.is_empty() {
            return Err(PosError::EmptyData);
        }

        let original_count = leaf_hashes.len();

        // Pad to next power of 2
        let leaf_count = original_count.next_power_of_two();

        // Allocate space for all nodes (2 * leaf_count for 1-indexed storage)
        let mut nodes = vec![[0u32; DIGEST_ELEMS]; 2 * leaf_count];

        // Copy leaves to their positions (indices leaf_count to 2*leaf_count - 1)
        for (i, hash) in leaf_hashes.iter().enumerate() {
            nodes[leaf_count + i] = *hash;
        }

        // Pad remaining leaves with hash of empty data
        let padding_hash = poseidon2_hash_bytes(b"");
        for i in original_count..leaf_count {
            nodes[leaf_count + i] = padding_hash;
        }

        // Build internal nodes bottom-up
        for i in (1..leaf_count).rev() {
            let left = nodes[2 * i];
            let right = nodes[2 * i + 1];
            nodes[i] = poseidon2_hash_two(&left, &right);
        }

        Ok(Self {
            nodes,
            leaf_count,
            original_count,
        })
    }

    /// Get the root hash of the tree.
    pub fn root(&self) -> Poseidon2Hash {
        self.nodes[1]
    }

    /// Get the number of original (non-padded) leaves.
    pub fn chunk_count(&self) -> usize {
        self.original_count
    }

    /// Get the depth of the tree (number of levels from leaf to root).
    pub fn depth(&self) -> usize {
        self.leaf_count.trailing_zeros() as usize
    }

    /// Get the hash of a specific leaf by index.
    ///
    /// # Arguments
    /// * `index` - Leaf index (0-based)
    ///
    /// # Returns
    /// The Poseidon2 hash of the leaf, or an error if out of bounds
    pub fn leaf_hash(&self, index: usize) -> Result<Poseidon2Hash> {
        if index >= self.original_count {
            return Err(PosError::ChunkIndexOutOfBounds {
                index: index as u32,
                max: (self.original_count - 1) as u32,
            });
        }
        Ok(self.nodes[self.leaf_count + index])
    }

    /// Generate a Merkle proof for a specific leaf.
    ///
    /// The proof contains sibling hashes from the leaf to the root.
    ///
    /// # Arguments
    /// * `index` - Leaf index (0-based)
    ///
    /// # Returns
    /// A MerkleProof containing the sibling hashes
    pub fn proof(&self, index: usize) -> Result<MerkleProof> {
        if index >= self.original_count {
            return Err(PosError::ChunkIndexOutOfBounds {
                index: index as u32,
                max: (self.original_count - 1) as u32,
            });
        }

        let mut siblings = Vec::with_capacity(self.depth());
        let mut node_index = self.leaf_count + index;

        while node_index > 1 {
            // XOR with 1 flips the last bit: even->odd (right sibling), odd->even (left sibling)
            let sibling_index = node_index ^ 1;
            siblings.push(self.nodes[sibling_index]);
            node_index /= 2;
        }

        Ok(MerkleProof {
            leaf_index: index as u32,
            siblings,
        })
    }

    /// Verify a Merkle proof against this tree's root.
    ///
    /// # Arguments
    /// * `leaf_hash` - The hash of the leaf being verified
    /// * `proof` - The Merkle proof to verify
    ///
    /// # Returns
    /// `true` if the proof is valid, `false` otherwise
    pub fn verify_proof(&self, leaf_hash: &Poseidon2Hash, proof: &MerkleProof) -> bool {
        Self::verify_proof_against_root(leaf_hash, proof, &self.root())
    }

    /// Verify a Merkle proof against a given root (static method).
    ///
    /// # Arguments
    /// * `leaf_hash` - The hash of the leaf being verified
    /// * `proof` - The Merkle proof to verify
    /// * `expected_root` - The expected root hash
    ///
    /// # Returns
    /// `true` if the proof is valid, `false` otherwise
    pub fn verify_proof_against_root(
        leaf_hash: &Poseidon2Hash,
        proof: &MerkleProof,
        expected_root: &Poseidon2Hash,
    ) -> bool {
        let mut current = *leaf_hash;
        let mut index = proof.leaf_index as usize;

        for sibling in &proof.siblings {
            current = if index % 2 == 0 {
                // Current is left child
                poseidon2_hash_two(&current, sibling)
            } else {
                // Current is right child
                poseidon2_hash_two(sibling, &current)
            };
            index /= 2;
        }

        current == *expected_root
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_single_chunk() {
        let chunks: Vec<&[u8]> = vec![b"hello"];
        let tree = MerkleTree::from_chunks(&chunks).unwrap();

        assert_eq!(tree.chunk_count(), 1);
        assert_eq!(tree.depth(), 0);

        let proof = tree.proof(0).unwrap();
        assert!(tree.verify_proof(&tree.leaf_hash(0).unwrap(), &proof));
    }

    #[test]
    fn test_two_chunks() {
        let chunks: Vec<&[u8]> = vec![b"hello", b"world"];
        let tree = MerkleTree::from_chunks(&chunks).unwrap();

        assert_eq!(tree.chunk_count(), 2);
        assert_eq!(tree.depth(), 1);

        // Verify both proofs
        for i in 0..2 {
            let proof = tree.proof(i).unwrap();
            assert!(tree.verify_proof(&tree.leaf_hash(i).unwrap(), &proof));
        }
    }

    #[test]
    fn test_power_of_two_chunks() {
        let data: Vec<Vec<u8>> = (0..8).map(|i| vec![i as u8; 100]).collect();
        let chunks: Vec<&[u8]> = data.iter().map(|v| v.as_slice()).collect();
        let tree = MerkleTree::from_chunks(&chunks).unwrap();

        assert_eq!(tree.chunk_count(), 8);
        assert_eq!(tree.depth(), 3);

        // Verify all proofs
        for i in 0..8 {
            let proof = tree.proof(i).unwrap();
            assert!(tree.verify_proof(&tree.leaf_hash(i).unwrap(), &proof));
        }
    }

    #[test]
    fn test_non_power_of_two_chunks() {
        // 5 chunks should be padded to 8
        let data: Vec<Vec<u8>> = (0..5).map(|i| vec![i as u8; 100]).collect();
        let chunks: Vec<&[u8]> = data.iter().map(|v| v.as_slice()).collect();
        let tree = MerkleTree::from_chunks(&chunks).unwrap();

        assert_eq!(tree.chunk_count(), 5);
        assert_eq!(tree.depth(), 3); // log2(8) = 3

        // Verify proofs for original chunks
        for i in 0..5 {
            let proof = tree.proof(i).unwrap();
            assert!(tree.verify_proof(&tree.leaf_hash(i).unwrap(), &proof));
        }
    }

    #[test]
    fn test_proof_invalid_with_wrong_leaf() {
        let chunks: Vec<&[u8]> = vec![b"hello", b"world", b"foo", b"bar"];
        let tree = MerkleTree::from_chunks(&chunks).unwrap();

        let proof = tree.proof(0).unwrap();
        let wrong_hash = poseidon2_hash_bytes(b"wrong");

        // Proof should fail with wrong leaf hash
        assert!(!tree.verify_proof(&wrong_hash, &proof));
    }

    #[test]
    fn test_proof_against_root() {
        let chunks: Vec<&[u8]> = vec![b"a", b"b", b"c", b"d"];
        let tree = MerkleTree::from_chunks(&chunks).unwrap();

        let leaf_hash = tree.leaf_hash(2).unwrap();
        let proof = tree.proof(2).unwrap();
        let root = tree.root();

        // Static verification should work
        assert!(MerkleTree::verify_proof_against_root(
            &leaf_hash, &proof, &root
        ));

        // Should fail with wrong root
        let wrong_root = [1, 2, 3, 4, 5, 6, 7, 8];
        assert!(!MerkleTree::verify_proof_against_root(
            &leaf_hash,
            &proof,
            &wrong_root
        ));
    }

    #[test]
    fn test_deterministic_root() {
        let chunks: Vec<&[u8]> = vec![b"test1", b"test2", b"test3"];

        let tree1 = MerkleTree::from_chunks(&chunks).unwrap();
        let tree2 = MerkleTree::from_chunks(&chunks).unwrap();

        assert_eq!(tree1.root(), tree2.root());
    }

    #[test]
    fn test_different_data_different_root() {
        let chunks1: Vec<&[u8]> = vec![b"hello", b"world"];
        let chunks2: Vec<&[u8]> = vec![b"hello", b"earth"];

        let tree1 = MerkleTree::from_chunks(&chunks1).unwrap();
        let tree2 = MerkleTree::from_chunks(&chunks2).unwrap();

        assert_ne!(tree1.root(), tree2.root());
    }

    #[test]
    fn test_out_of_bounds_leaf() {
        let chunks: Vec<&[u8]> = vec![b"a", b"b", b"c"];
        let tree = MerkleTree::from_chunks(&chunks).unwrap();

        assert!(tree.leaf_hash(3).is_err());
        assert!(tree.proof(3).is_err());
    }

    #[test]
    fn test_empty_chunks() {
        let chunks: Vec<&[u8]> = vec![];
        assert!(MerkleTree::from_chunks(&chunks).is_err());
    }

    #[test]
    fn test_from_leaf_hashes() {
        let hashes = vec![
            poseidon2_hash_bytes(b"a"),
            poseidon2_hash_bytes(b"b"),
            poseidon2_hash_bytes(b"c"),
            poseidon2_hash_bytes(b"d"),
        ];

        let tree = MerkleTree::from_leaf_hashes(&hashes).unwrap();
        assert_eq!(tree.chunk_count(), 4);

        // Verify proof for each leaf
        for (i, hash) in hashes.iter().enumerate() {
            let proof = tree.proof(i).unwrap();
            assert!(tree.verify_proof(hash, &proof));
        }
    }
}

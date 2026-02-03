//! BLAKE3-based Merkle tree implementation for attestation proofs.
//!
//! This module provides functions to build merkle trees from SCALE-encoded data
//! and generate/verify inclusion proofs.
//!
//! # Design
//!
//! - Uses BLAKE3 for hashing (fast, cryptographically secure)
//! - Leaves are SCALE-encoded before hashing
//! - Domain-separated hashing: leaf hash = BLAKE3(0x00 || SCALE(leaf))
//! - Internal node hash = BLAKE3(0x01 || left || right)
//! - Handles non-power-of-two leaves by duplicating the last leaf
//!
//! # Example
//!
//! ```rust,ignore
//! use common::merkle::{build_merkle_tree, verify_merkle_proof};
//! use parity_scale_codec::Encode;
//!
//! let leaves = vec![1u32, 2u32, 3u32, 4u32];
//! let (root, proofs) = build_merkle_tree(&leaves);
//!
//! // Verify each leaf
//! for (i, leaf) in leaves.iter().enumerate() {
//!     assert!(verify_merkle_proof(leaf, &proofs[i], &root));
//! }
//! ```

use crate::attestation_bundle::MerkleProof;
use parity_scale_codec::Encode;

/// Domain separator for leaf hashes (prevents second-preimage attacks)
const LEAF_DOMAIN: u8 = 0x00;

/// Domain separator for internal node hashes
const NODE_DOMAIN: u8 = 0x01;

/// Hash a leaf node: BLAKE3(0x00 || SCALE(leaf))
fn hash_leaf<T: Encode>(leaf: &T) -> [u8; 32] {
    let encoded = leaf.encode();
    let mut hasher = blake3::Hasher::new();
    hasher.update(&[LEAF_DOMAIN]);
    hasher.update(&encoded);
    *hasher.finalize().as_bytes()
}

/// Hash an internal node: BLAKE3(0x01 || left || right)
fn hash_node(left: &[u8; 32], right: &[u8; 32]) -> [u8; 32] {
    let mut hasher = blake3::Hasher::new();
    hasher.update(&[NODE_DOMAIN]);
    hasher.update(left);
    hasher.update(right);
    *hasher.finalize().as_bytes()
}

/// Build a BLAKE3 merkle tree from SCALE-encoded leaves.
///
/// Returns the merkle root and a proof for each leaf.
///
/// # Arguments
/// * `leaves` - Items to include in the tree (will be SCALE-encoded)
///
/// # Returns
/// * `root` - The 32-byte merkle root
/// * `proofs` - Vec of MerkleProof, one per leaf
///
/// # Panics
/// Panics if leaves is empty.
pub fn build_merkle_tree<T: Encode>(leaves: &[T]) -> ([u8; 32], Vec<MerkleProof>) {
    if leaves.is_empty() {
        // Return zero root and empty proofs for empty input
        return ([0u8; 32], Vec::new());
    }

    // Special case: single leaf
    if leaves.len() == 1 {
        let root = hash_leaf(&leaves[0]);
        return (root, vec![MerkleProof::empty(0)]);
    }

    // Hash all leaves
    let mut leaf_hashes: Vec<[u8; 32]> = leaves.iter().map(|l| hash_leaf(l)).collect();
    let original_leaf_count = leaf_hashes.len();

    // Pad to power of 2 by duplicating last leaf
    let tree_size = leaf_hashes.len().next_power_of_two();
    while leaf_hashes.len() < tree_size {
        leaf_hashes.push(*leaf_hashes.last().unwrap());
    }

    // Build tree bottom-up, tracking paths for proofs
    // Tree layout: [leaves..., level1..., level2..., root]
    // We'll build levels separately to track sibling positions
    let mut levels: Vec<Vec<[u8; 32]>> = vec![leaf_hashes.clone()];

    let mut current_level = leaf_hashes;
    while current_level.len() > 1 {
        let mut next_level = Vec::with_capacity(current_level.len() / 2);
        for chunk in current_level.chunks(2) {
            let left = &chunk[0];
            let right = if chunk.len() > 1 { &chunk[1] } else { left };
            next_level.push(hash_node(left, right));
        }
        levels.push(next_level.clone());
        current_level = next_level;
    }

    let root = levels.last().unwrap()[0];

    // Generate proofs for each original leaf
    let mut proofs = Vec::with_capacity(original_leaf_count);
    for i in 0..original_leaf_count {
        let mut siblings = Vec::new();
        let mut directions = Vec::new();
        let mut idx = i;

        for level in levels.iter().take(levels.len() - 1) {
            // Sibling index
            let sibling_idx = if idx % 2 == 0 { idx + 1 } else { idx - 1 };

            // Get sibling hash (handle edge case where sibling might be out of bounds)
            if sibling_idx < level.len() {
                siblings.push(level[sibling_idx]);
            } else {
                siblings.push(level[idx]); // Self as sibling (should not happen with proper padding)
            }

            // Direction: true if sibling is on the right (idx is even)
            directions.push(idx % 2 == 0);

            // Move to parent index
            idx /= 2;
        }

        proofs.push(MerkleProof {
            leaf_index: i as u32,
            siblings,
            directions,
        });
    }

    (root, proofs)
}

/// Verify a merkle proof against a root.
///
/// # Arguments
/// * `leaf` - The leaf data (will be SCALE-encoded)
/// * `proof` - The merkle proof to verify
/// * `root` - The expected merkle root
///
/// # Returns
/// `true` if the proof is valid, `false` otherwise.
pub fn verify_merkle_proof<T: Encode>(leaf: &T, proof: &MerkleProof, root: &[u8; 32]) -> bool {
    // Empty proof is valid only for single-leaf trees
    if proof.siblings.is_empty() && proof.directions.is_empty() {
        let leaf_hash = hash_leaf(leaf);
        return leaf_hash == *root;
    }

    // Mismatched lengths
    if proof.siblings.len() != proof.directions.len() {
        return false;
    }

    let mut current_hash = hash_leaf(leaf);

    for (sibling, &is_right) in proof.siblings.iter().zip(proof.directions.iter()) {
        current_hash = if is_right {
            // Sibling is on the right
            hash_node(&current_hash, sibling)
        } else {
            // Sibling is on the left
            hash_node(sibling, &current_hash)
        };
    }

    current_hash == *root
}

/// Compute the BLAKE3 hash of raw bytes.
///
/// Used for computing arion_content_hash of the SCALE-encoded bundle.
pub fn blake3_hash(data: &[u8]) -> [u8; 32] {
    *blake3::hash(data).as_bytes()
}

#[cfg(test)]
mod tests {
    use super::*;
    use parity_scale_codec::Decode;

    #[test]
    fn test_single_leaf() {
        let leaves = vec![42u32];
        let (root, proofs) = build_merkle_tree(&leaves);

        assert_eq!(proofs.len(), 1);
        assert!(proofs[0].siblings.is_empty());
        assert!(verify_merkle_proof(&42u32, &proofs[0], &root));
        assert!(!verify_merkle_proof(&43u32, &proofs[0], &root));
    }

    #[test]
    fn test_two_leaves() {
        let leaves = vec![1u32, 2u32];
        let (root, proofs) = build_merkle_tree(&leaves);

        assert_eq!(proofs.len(), 2);
        assert!(verify_merkle_proof(&1u32, &proofs[0], &root));
        assert!(verify_merkle_proof(&2u32, &proofs[1], &root));

        // Wrong leaf should fail
        assert!(!verify_merkle_proof(&3u32, &proofs[0], &root));
        assert!(!verify_merkle_proof(&1u32, &proofs[1], &root));
    }

    #[test]
    fn test_four_leaves() {
        let leaves = vec![1u32, 2u32, 3u32, 4u32];
        let (root, proofs) = build_merkle_tree(&leaves);

        assert_eq!(proofs.len(), 4);
        for (i, leaf) in leaves.iter().enumerate() {
            assert!(
                verify_merkle_proof(leaf, &proofs[i], &root),
                "Proof {} failed",
                i
            );
        }

        // Verify each proof has correct depth (log2(4) = 2)
        for proof in &proofs {
            assert_eq!(proof.siblings.len(), 2);
        }
    }

    #[test]
    fn test_five_leaves() {
        // Non-power-of-two: should be padded to 8
        let leaves = vec![1u32, 2u32, 3u32, 4u32, 5u32];
        let (root, proofs) = build_merkle_tree(&leaves);

        assert_eq!(proofs.len(), 5);
        for (i, leaf) in leaves.iter().enumerate() {
            assert!(
                verify_merkle_proof(leaf, &proofs[i], &root),
                "Proof {} failed",
                i
            );
        }

        // Verify each proof has correct depth (log2(8) = 3)
        for proof in &proofs {
            assert_eq!(proof.siblings.len(), 3);
        }
    }

    #[test]
    fn test_empty_leaves() {
        let leaves: Vec<u32> = vec![];
        let (root, proofs) = build_merkle_tree(&leaves);

        assert_eq!(root, [0u8; 32]);
        assert!(proofs.is_empty());
    }

    #[test]
    fn test_deterministic() {
        let leaves = vec![1u32, 2u32, 3u32];

        let (root1, _) = build_merkle_tree(&leaves);
        let (root2, _) = build_merkle_tree(&leaves);

        assert_eq!(root1, root2);
    }

    #[test]
    fn test_different_types() {
        // Works with any Encode type
        let string_leaves = vec!["hello".to_string(), "world".to_string()];
        let (root, proofs) = build_merkle_tree(&string_leaves);

        assert!(verify_merkle_proof(&"hello".to_string(), &proofs[0], &root));
        assert!(verify_merkle_proof(&"world".to_string(), &proofs[1], &root));
    }

    #[test]
    fn test_blake3_hash() {
        let data = b"hello world";
        let hash = blake3_hash(data);

        // Verify it's deterministic
        assert_eq!(hash, blake3_hash(data));

        // Different data should give different hash
        assert_ne!(hash, blake3_hash(b"hello world!"));
    }

    #[test]
    fn test_proof_serialization() {
        let leaves = vec![1u32, 2u32, 3u32, 4u32];
        let (root, proofs) = build_merkle_tree(&leaves);

        // Encode and decode proof
        let encoded = proofs[0].encode();
        let decoded = MerkleProof::decode(&mut &encoded[..]).unwrap();

        // Verify decoded proof still works
        assert!(verify_merkle_proof(&1u32, &decoded, &root));
    }

    #[test]
    fn test_wrong_proof() {
        let leaves = vec![1u32, 2u32, 3u32, 4u32];
        let (root, proofs) = build_merkle_tree(&leaves);

        // Try to use proof[0] for leaf[1] - should fail
        assert!(!verify_merkle_proof(&2u32, &proofs[0], &root));

        // Try to use proof[1] for leaf[0] - should fail
        assert!(!verify_merkle_proof(&1u32, &proofs[1], &root));
    }

    #[test]
    fn test_tampered_proof() {
        let leaves = vec![1u32, 2u32, 3u32, 4u32];
        let (root, proofs) = build_merkle_tree(&leaves);

        // Tamper with a sibling hash
        let mut tampered = proofs[0].clone();
        if !tampered.siblings.is_empty() {
            tampered.siblings[0][0] ^= 0xFF;
        }

        assert!(!verify_merkle_proof(&1u32, &tampered, &root));
    }

    #[test]
    fn test_wrong_root() {
        let leaves = vec![1u32, 2u32, 3u32, 4u32];
        let (_, proofs) = build_merkle_tree(&leaves);

        let wrong_root = [0xFFu8; 32];
        assert!(!verify_merkle_proof(&1u32, &proofs[0], &wrong_root));
    }
}

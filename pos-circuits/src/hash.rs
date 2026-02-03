//! Poseidon2 hash functions for proof-of-storage.
//!
//! This module provides native (non-circuit) Poseidon2 hashing for:
//! - Arbitrary byte arrays (chunks)
//! - Pairs of hashes (for Merkle tree construction)

use p3_baby_bear::{default_babybear_poseidon2_16, BabyBear};
use p3_field::{PrimeCharacteristicRing, PrimeField32};
use p3_symmetric::Permutation;

use crate::config::{DIGEST_ELEMS, POSEIDON2_WIDTH};
use crate::types::Poseidon2Hash;

/// Hash arbitrary bytes using Poseidon2.
///
/// The bytes are packed into BabyBear field elements (3 bytes per element
/// to stay within the 31-bit field modulus), then hashed using Poseidon2.
///
/// # Arguments
/// * `data` - The bytes to hash
///
/// # Returns
/// A DIGEST_ELEMS-element array representing the Poseidon2 hash output
pub fn poseidon2_hash_bytes(data: &[u8]) -> Poseidon2Hash {
    let perm = default_babybear_poseidon2_16();
    let field_elements = pack_bytes_to_field_elements(data);

    let mut state = [BabyBear::ZERO; POSEIDON2_WIDTH];
    let rate = POSEIDON2_WIDTH - DIGEST_ELEMS;

    // Absorb: add field elements to state and permute
    for chunk in field_elements.chunks(rate) {
        for (i, &elem) in chunk.iter().enumerate() {
            state[i] += elem;
        }
        perm.permute_mut(&mut state);
    }

    extract_digest(&state)
}

/// Extract DIGEST_ELEMS elements from state as canonical u32 values.
fn extract_digest(state: &[BabyBear; POSEIDON2_WIDTH]) -> Poseidon2Hash {
    let mut result = [0u32; DIGEST_ELEMS];
    for (i, elem) in state[..DIGEST_ELEMS].iter().enumerate() {
        result[i] = elem.as_canonical_u32();
    }
    result
}

/// Hash two Poseidon2 hashes together (for Merkle tree nodes).
///
/// # Arguments
/// * `left` - Left child hash
/// * `right` - Right child hash
///
/// # Returns
/// The parent hash
pub fn poseidon2_hash_two(left: &Poseidon2Hash, right: &Poseidon2Hash) -> Poseidon2Hash {
    let perm = default_babybear_poseidon2_16();
    let mut state = [BabyBear::ZERO; POSEIDON2_WIDTH];

    // Load left and right hashes into state
    for (i, &val) in left.iter().enumerate() {
        state[i] = BabyBear::new(val);
    }
    for (i, &val) in right.iter().enumerate() {
        state[DIGEST_ELEMS + i] = BabyBear::new(val);
    }

    perm.permute_mut(&mut state);
    extract_digest(&state)
}

/// Pack bytes into BabyBear field elements.
///
/// Uses 3 bytes per field element to stay safely within the 31-bit modulus.
fn pack_bytes_to_field_elements(data: &[u8]) -> Vec<BabyBear> {
    const BYTES_PER_ELEMENT: usize = 3; // 24 bits < 31 bits

    let mut elements = Vec::with_capacity(data.len().div_ceil(BYTES_PER_ELEMENT) + 1);

    for chunk in data.chunks(BYTES_PER_ELEMENT) {
        let mut value: u32 = 0;
        for (i, &byte) in chunk.iter().enumerate() {
            value |= (byte as u32) << (i * 8);
        }
        elements.push(BabyBear::new(value));
    }

    // Add length as final element for domain separation
    elements.push(BabyBear::new(data.len() as u32));

    elements
}

/// Convert a Poseidon2Hash to bytes (for storage/transmission).
pub fn hash_to_bytes(hash: &Poseidon2Hash) -> [u8; DIGEST_ELEMS * 4] {
    let mut result = [0u8; DIGEST_ELEMS * 4];
    for (i, &element) in hash.iter().enumerate() {
        result[i * 4..(i + 1) * 4].copy_from_slice(&element.to_le_bytes());
    }
    result
}

/// Convert bytes back to a Poseidon2Hash.
pub fn bytes_to_hash(bytes: &[u8]) -> Poseidon2Hash {
    assert!(bytes.len() >= DIGEST_ELEMS * 4);
    let mut result = [0u32; DIGEST_ELEMS];
    for (i, chunk) in bytes.chunks(4).take(DIGEST_ELEMS).enumerate() {
        result[i] = u32::from_le_bytes(chunk.try_into().unwrap());
    }
    result
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_hash_bytes_deterministic() {
        let data = b"Hello, World!";
        let hash1 = poseidon2_hash_bytes(data);
        let hash2 = poseidon2_hash_bytes(data);
        assert_eq!(hash1, hash2);
    }

    #[test]
    fn test_hash_bytes_different_inputs() {
        let hash1 = poseidon2_hash_bytes(b"Hello");
        let hash2 = poseidon2_hash_bytes(b"World");
        assert_ne!(hash1, hash2);
    }

    #[test]
    fn test_hash_two_deterministic() {
        let left = poseidon2_hash_bytes(b"left");
        let right = poseidon2_hash_bytes(b"right");

        let combined1 = poseidon2_hash_two(&left, &right);
        let combined2 = poseidon2_hash_two(&left, &right);
        assert_eq!(combined1, combined2);
    }

    #[test]
    fn test_hash_two_order_matters() {
        let left = poseidon2_hash_bytes(b"left");
        let right = poseidon2_hash_bytes(b"right");

        let lr = poseidon2_hash_two(&left, &right);
        let rl = poseidon2_hash_two(&right, &left);
        assert_ne!(lr, rl);
    }

    #[test]
    fn test_hash_bytes_roundtrip() {
        let original = poseidon2_hash_bytes(b"test data");
        let bytes = hash_to_bytes(&original);
        let recovered = bytes_to_hash(&bytes);
        assert_eq!(original, recovered);
    }

    #[test]
    fn test_empty_data() {
        let hash = poseidon2_hash_bytes(b"");
        // Should produce a valid hash even for empty input
        assert_ne!(hash, [0; DIGEST_ELEMS]);
    }

    #[test]
    fn test_large_data() {
        // Test with 1KB of data
        let data = vec![0xABu8; 1024];
        let hash = poseidon2_hash_bytes(&data);
        assert_ne!(hash, [0; DIGEST_ELEMS]);
    }
}

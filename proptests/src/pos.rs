//! Property-based tests for Proof-of-Storage challenge generation.
//!
//! Tests the following invariants:
//! - POS-1: Challenge nonce is deterministic
//! - POS-2: Challenge nonce changes with any input change
//!
//! Note: POS-3 through POS-7 require integration testing with pos-circuits
//! and are deferred to integration tests.

#![allow(unused_imports)]
use crate::strategies::*;
use proptest::prelude::*;
use warden::audit::challenger::{generate_challenge_indices, generate_nonce};

proptest! {
    #![proptest_config(ProptestConfig::with_cases(256))]

    /// POS-1: Nonce generation is deterministic.
    /// Same inputs must always produce the same nonce.
    #[test]
    fn prop_nonce_is_deterministic(
        shard_hash in "[a-f0-9]{64}",
        block_hash in prop::array::uniform32(any::<u8>()),
        warden_id in prop::array::uniform32(any::<u8>()),
    ) {
        let nonce1 = generate_nonce(&shard_hash, &block_hash, &warden_id);
        let nonce2 = generate_nonce(&shard_hash, &block_hash, &warden_id);

        prop_assert_eq!(
            nonce1,
            nonce2,
            "Nonce must be deterministic"
        );
    }

    /// POS-2a: Nonce changes when shard_hash changes.
    #[test]
    fn prop_nonce_changes_with_shard_hash(
        shard_hash1 in "[a-f0-9]{64}",
        shard_hash2 in "[a-f0-9]{64}",
        block_hash in prop::array::uniform32(any::<u8>()),
        warden_id in prop::array::uniform32(any::<u8>()),
    ) {
        prop_assume!(shard_hash1 != shard_hash2);

        let nonce1 = generate_nonce(&shard_hash1, &block_hash, &warden_id);
        let nonce2 = generate_nonce(&shard_hash2, &block_hash, &warden_id);

        prop_assert_ne!(
            nonce1,
            nonce2,
            "Different shard hashes must produce different nonces"
        );
    }

    /// POS-2b: Nonce changes when block_hash changes.
    #[test]
    fn prop_nonce_changes_with_block_hash(
        shard_hash in "[a-f0-9]{64}",
        block_hash1 in prop::array::uniform32(any::<u8>()),
        block_hash2 in prop::array::uniform32(any::<u8>()),
        warden_id in prop::array::uniform32(any::<u8>()),
    ) {
        prop_assume!(block_hash1 != block_hash2);

        let nonce1 = generate_nonce(&shard_hash, &block_hash1, &warden_id);
        let nonce2 = generate_nonce(&shard_hash, &block_hash2, &warden_id);

        prop_assert_ne!(
            nonce1,
            nonce2,
            "Different block hashes must produce different nonces"
        );
    }

    /// POS-2c: Nonce changes when warden_id changes.
    #[test]
    fn prop_nonce_changes_with_warden_id(
        shard_hash in "[a-f0-9]{64}",
        block_hash in prop::array::uniform32(any::<u8>()),
        warden_id1 in prop::array::uniform32(any::<u8>()),
        warden_id2 in prop::array::uniform32(any::<u8>()),
    ) {
        prop_assume!(warden_id1 != warden_id2);

        let nonce1 = generate_nonce(&shard_hash, &block_hash, &warden_id1);
        let nonce2 = generate_nonce(&shard_hash, &block_hash, &warden_id2);

        prop_assert_ne!(
            nonce1,
            nonce2,
            "Different warden IDs must produce different nonces"
        );
    }

    /// Challenge indices are deterministic given same nonce.
    #[test]
    fn prop_challenge_indices_deterministic(
        nonce in prop::array::uniform32(any::<u8>()),
        chunk_count in 1u32..1000,
        num_challenges in 1usize..20,
    ) {
        let indices1 = generate_challenge_indices(&nonce, chunk_count, num_challenges);
        let indices2 = generate_challenge_indices(&nonce, chunk_count, num_challenges);

        prop_assert_eq!(
            indices1,
            indices2,
            "Challenge indices must be deterministic"
        );
    }

    /// Challenge indices are always unique within a single challenge.
    #[test]
    fn prop_challenge_indices_unique(
        nonce in prop::array::uniform32(any::<u8>()),
        chunk_count in 1u32..1000,
        num_challenges in 1usize..20,
    ) {
        let indices = generate_challenge_indices(&nonce, chunk_count, num_challenges);

        let unique: std::collections::HashSet<_> = indices.iter().collect();
        prop_assert_eq!(
            unique.len(),
            indices.len(),
            "All challenge indices must be unique"
        );
    }

    /// Challenge indices are always sorted.
    #[test]
    fn prop_challenge_indices_sorted(
        nonce in prop::array::uniform32(any::<u8>()),
        chunk_count in 1u32..1000,
        num_challenges in 1usize..20,
    ) {
        let indices = generate_challenge_indices(&nonce, chunk_count, num_challenges);

        for window in indices.windows(2) {
            prop_assert!(
                window[0] <= window[1],
                "Challenge indices must be sorted: {} > {}",
                window[0],
                window[1]
            );
        }
    }

    /// Challenge indices are always within valid range [0, chunk_count).
    #[test]
    fn prop_challenge_indices_in_range(
        nonce in prop::array::uniform32(any::<u8>()),
        chunk_count in 1u32..1000,
        num_challenges in 1usize..20,
    ) {
        let indices = generate_challenge_indices(&nonce, chunk_count, num_challenges);

        for &idx in &indices {
            prop_assert!(
                idx < chunk_count,
                "Index {} must be less than chunk_count {}",
                idx,
                chunk_count
            );
        }
    }

    /// When num_challenges > chunk_count, indices are capped at chunk_count.
    #[test]
    fn prop_challenge_indices_capped_by_chunk_count(
        nonce in prop::array::uniform32(any::<u8>()),
        chunk_count in 1u32..100,
    ) {
        // Request more challenges than chunks available
        let num_challenges = chunk_count as usize + 10;
        let indices = generate_challenge_indices(&nonce, chunk_count, num_challenges);

        prop_assert!(
            indices.len() <= chunk_count as usize,
            "Indices count {} should not exceed chunk_count {}",
            indices.len(),
            chunk_count
        );
    }

    /// Different nonces produce different challenge indices (with high probability).
    ///
    /// With large chunk_count and multiple challenges, the probability of collision
    /// is negligible. We use thresholds that make collision probability < 1e-10.
    #[test]
    fn prop_different_nonces_different_indices(
        nonce1 in prop::array::uniform32(any::<u8>()),
        nonce2 in prop::array::uniform32(any::<u8>()),
        // Use larger chunk_count to make collisions extremely unlikely
        // With 10000 chunks and 4 challenges: C(10000,4) ≈ 4.1e14 possible outcomes
        chunk_count in 1000u32..10000,
        num_challenges in 4usize..8,
    ) {
        prop_assume!(nonce1 != nonce2);

        let indices1 = generate_challenge_indices(&nonce1, chunk_count, num_challenges);
        let indices2 = generate_challenge_indices(&nonce2, chunk_count, num_challenges);

        // With these parameters, collision probability is negligible
        prop_assert_ne!(
            indices1,
            indices2,
            "Different nonces should produce different indices (chunk_count={}, num_challenges={})",
            chunk_count,
            num_challenges
        );
    }
}

/// Test empty input handling.
#[test]
fn test_empty_inputs() {
    let nonce = [0u8; 32];

    // Zero chunk count should return empty
    let indices = generate_challenge_indices(&nonce, 0, 4);
    assert!(indices.is_empty(), "Zero chunk_count should return empty");

    // Zero num_challenges should return empty
    let indices = generate_challenge_indices(&nonce, 100, 0);
    assert!(
        indices.is_empty(),
        "Zero num_challenges should return empty"
    );
}

/// Test nonce has full 256-bit entropy.
#[test]
fn test_nonce_entropy() {
    use std::collections::HashSet;

    let mut nonces = HashSet::new();
    let block_hash = [1u8; 32];
    let warden_id = [2u8; 32];

    // Generate 1000 nonces from different shard hashes
    for i in 0..1000 {
        let shard_hash = format!("{:064x}", i);
        let nonce = generate_nonce(&shard_hash, &block_hash, &warden_id);
        nonces.insert(nonce);
    }

    // All nonces should be unique (collision extremely unlikely with 256-bit output)
    assert_eq!(nonces.len(), 1000, "All 1000 nonces should be unique");
}

/// Test nonce is 32 bytes.
#[test]
fn test_nonce_size() {
    let shard_hash = "0".repeat(64);
    let block_hash = [0u8; 32];
    let warden_id = [0u8; 32];

    let nonce = generate_nonce(&shard_hash, &block_hash, &warden_id);
    assert_eq!(nonce.len(), 32, "Nonce must be 32 bytes (256 bits)");
}

/// Test challenge indices distribution is uniform.
#[test]
fn test_challenge_indices_uniform_distribution() {
    let chunk_count = 100u32;
    let num_challenges = 4;
    let iterations = 10000;

    let mut index_counts = vec![0u32; chunk_count as usize];

    for i in 0..iterations {
        // Use different nonces
        let mut nonce = [0u8; 32];
        nonce[0..8].copy_from_slice(&(i as u64).to_le_bytes());

        let indices = generate_challenge_indices(&nonce, chunk_count, num_challenges);
        for idx in indices {
            index_counts[idx as usize] += 1;
        }
    }

    // Each index should appear roughly the same number of times
    // Expected: iterations * num_challenges / chunk_count = 10000 * 4 / 100 = 400
    let expected = (iterations * num_challenges as u32) as f64 / chunk_count as f64;

    let min_count = *index_counts.iter().min().unwrap() as f64;
    let max_count = *index_counts.iter().max().unwrap() as f64;

    // Allow 40% deviation
    assert!(
        min_count >= expected * 0.6,
        "Minimum count {} is too low (expected ~{})",
        min_count,
        expected
    );
    assert!(
        max_count <= expected * 1.4,
        "Maximum count {} is too high (expected ~{})",
        max_count,
        expected
    );
}

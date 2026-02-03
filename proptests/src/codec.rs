//! Property-based tests for Reed-Solomon erasure coding.
//!
//! Tests the following invariants:
//! - RS-1: Encode produces exactly k+m shards
//! - RS-2: All shards have the same size
//! - RS-3: Reconstruction with any k shards succeeds
//! - RS-4: Reconstruction fails with k-1 shards
//! - RS-5: Round-trip integrity: decode(encode(data)) == data
//! - RS-6: Shard size = ceil(data_len / k)

#![allow(unused_imports)]
use crate::strategies::*;
use common::{StripeConfig, decode_stripe, encode_stripe};
use proptest::prelude::*;
use std::collections::HashSet;

proptest! {
    #![proptest_config(ProptestConfig::with_cases(256))]

    /// RS-1: encode_stripe produces exactly k+m shards.
    #[test]
    fn prop_encode_produces_correct_shard_count(
        data in prop::collection::vec(any::<u8>(), 1..100_000),
        k in 2usize..20,
        m in 1usize..20,
    ) {
        prop_assume!(k + m <= 256); // GF(2^8) limit

        let config = StripeConfig {
            k,
            m,
            size: data.len() as u64 + 1, // Ensure data fits in stripe
        };

        let shards = encode_stripe(&data, &config)
            .expect("encoding should succeed");

        prop_assert_eq!(
            shards.len(),
            k + m,
            "Encode must produce exactly k+m={} shards, got {}",
            k + m,
            shards.len()
        );
    }

    /// RS-2: All shards have the same size.
    #[test]
    fn prop_all_shards_same_size(
        data in prop::collection::vec(any::<u8>(), 1..100_000),
        k in 2usize..20,
        m in 1usize..20,
    ) {
        prop_assume!(k + m <= 256);

        let config = StripeConfig {
            k,
            m,
            size: data.len() as u64 + 1,
        };

        let shards = encode_stripe(&data, &config)
            .expect("encoding should succeed");

        let first_size = shards[0].len();
        for (idx, shard) in shards.iter().enumerate() {
            prop_assert_eq!(
                shard.len(),
                first_size,
                "Shard {} has size {} but expected {} (same as shard 0)",
                idx,
                shard.len(),
                first_size
            );
        }
    }

    /// RS-3: Reconstruction succeeds with any k shards (out of k+m).
    #[test]
    fn prop_reconstruct_with_any_k_shards(
        data in prop::collection::vec(any::<u8>(), 1..50_000),
        missing_indices in prop::collection::hash_set(0usize..30, 0..20),
    ) {
        let config = StripeConfig::default(); // k=10, m=20
        let shards = encode_stripe(&data, &config)
            .expect("encoding should succeed");

        prop_assert_eq!(shards.len(), 30, "Must have k+m=30 shards");

        // Create decode input with Some/None based on missing indices
        let mut decode_input: Vec<Option<Vec<u8>>> = shards
            .into_iter()
            .map(Some)
            .collect();

        for idx in &missing_indices {
            if *idx < decode_input.len() {
                decode_input[*idx] = None;
            }
        }

        let available_count = 30 - missing_indices.iter().filter(|&&i| i < 30).count();

        if available_count >= config.k {
            // Should successfully reconstruct
            let reconstructed = decode_stripe(&mut decode_input, &config, data.len())
                .expect("reconstruction should succeed with k+ shards");

            prop_assert_eq!(
                reconstructed,
                data,
                "Reconstructed data must match original"
            );
        } else {
            // Should fail with insufficient shards
            let result = decode_stripe(&mut decode_input, &config, data.len());
            prop_assert!(
                result.is_err(),
                "Reconstruction should fail with fewer than k shards (available: {})",
                available_count
            );
        }
    }

    /// RS-4: Reconstruction fails with exactly k-1 shards.
    #[test]
    fn prop_reconstruct_fails_with_k_minus_one_shards(
        data in prop::collection::vec(any::<u8>(), 1..50_000),
        keep_indices in prop::collection::hash_set(0usize..30, 9..10), // Keep exactly 9
    ) {
        let config = StripeConfig::default(); // k=10, m=20

        // Only run if we have exactly k-1 shards
        prop_assume!(keep_indices.len() == config.k - 1);

        let shards = encode_stripe(&data, &config)
            .expect("encoding should succeed");

        // Create decode input keeping only k-1 shards
        let mut decode_input: Vec<Option<Vec<u8>>> = vec![None; 30];
        for idx in &keep_indices {
            if *idx < shards.len() {
                decode_input[*idx] = Some(shards[*idx].clone());
            }
        }

        let result = decode_stripe(&mut decode_input, &config, data.len());

        prop_assert!(
            result.is_err(),
            "Reconstruction should fail with k-1={} shards",
            config.k - 1
        );
    }

    /// RS-5: Round-trip integrity - decode(encode(data)) == data.
    #[test]
    fn prop_round_trip_integrity(
        data in prop::collection::vec(any::<u8>(), 1..100_000),
    ) {
        let config = StripeConfig::default(); // k=10, m=20

        let shards = encode_stripe(&data, &config)
            .expect("encoding should succeed");

        // Decode with all shards available
        let mut decode_input: Vec<Option<Vec<u8>>> = shards
            .into_iter()
            .map(Some)
            .collect();

        let reconstructed = decode_stripe(&mut decode_input, &config, data.len())
            .expect("decoding should succeed");

        prop_assert_eq!(
            reconstructed,
            data,
            "Round-trip must preserve data integrity"
        );
    }

    /// RS-5 (extended): Round-trip with various k/m configurations.
    #[test]
    fn prop_round_trip_various_configs(
        data in prop::collection::vec(any::<u8>(), 1..50_000),
        k in 2usize..15,
        m in 1usize..15,
    ) {
        prop_assume!(k + m <= 256);

        let config = StripeConfig {
            k,
            m,
            size: data.len() as u64 + 1,
        };

        let shards = encode_stripe(&data, &config)
            .expect("encoding should succeed");

        let mut decode_input: Vec<Option<Vec<u8>>> = shards
            .into_iter()
            .map(Some)
            .collect();

        let reconstructed = decode_stripe(&mut decode_input, &config, data.len())
            .expect("decoding should succeed");

        prop_assert_eq!(
            reconstructed,
            data,
            "Round-trip must preserve data with k={}, m={}",
            k,
            m
        );
    }

    /// RS-6: Shard size equals ceil(data_len / k).
    #[test]
    fn prop_shard_size_calculation(
        data_len in 1usize..1_000_000,
        k in 2usize..50,
    ) {
        prop_assume!(k <= 255); // GF(2^8) limit for k

        let config = StripeConfig {
            k,
            m: 1, // Minimum parity
            size: data_len as u64 + 1,
        };

        let data = vec![0u8; data_len];
        let shards = encode_stripe(&data, &config)
            .expect("encoding should succeed");

        let expected_shard_size = data_len.div_ceil(k);

        for (idx, shard) in shards.iter().enumerate() {
            prop_assert_eq!(
                shard.len(),
                expected_shard_size,
                "Shard {} has size {} but expected ceil({}/{})={}",
                idx,
                shard.len(),
                data_len,
                k,
                expected_shard_size
            );
        }
    }

    /// Test that reconstruction produces identical shard hashes.
    /// (REC-3 from recovery invariants, but tested at codec level)
    #[test]
    fn prop_reconstructed_shard_hash_matches_original(
        data in prop::collection::vec(any::<u8>(), 1..50_000),
        missing_idx in 0usize..30,
    ) {
        let config = StripeConfig::default(); // k=10, m=20

        let shards = encode_stripe(&data, &config)
            .expect("encoding should succeed");

        // Record original hashes
        let original_hashes: Vec<_> = shards.iter()
            .map(|s| blake3::hash(s))
            .collect();

        // Remove one shard
        let mut decode_input: Vec<Option<Vec<u8>>> = shards
            .into_iter()
            .map(Some)
            .collect();
        decode_input[missing_idx] = None;

        // Reconstruct (this modifies decode_input in place, filling in missing shards)
        let _ = decode_stripe(&mut decode_input, &config, data.len())
            .expect("reconstruction should succeed");

        // Verify reconstructed shard hash matches original
        let reconstructed = decode_input[missing_idx]
            .as_ref()
            .expect("shard should be reconstructed");
        let reconstructed_hash = blake3::hash(reconstructed);

        prop_assert_eq!(
            reconstructed_hash,
            original_hashes[missing_idx],
            "Reconstructed shard {} hash must match original",
            missing_idx
        );
    }
}

/// Test empty data handling (edge case).
#[test]
fn test_empty_data_fails() {
    let config = StripeConfig::default();
    let result = encode_stripe(&[], &config);
    assert!(result.is_err(), "Empty data should fail to encode");
}

/// Test data exactly at stripe boundary.
#[test]
fn test_data_at_stripe_boundary() {
    let config = StripeConfig {
        k: 10,
        m: 20,
        size: 1000,
    };

    // Data exactly at stripe size
    let data = vec![0xABu8; 1000];
    let shards = encode_stripe(&data, &config).expect("encoding should succeed");

    assert_eq!(shards.len(), 30);

    // Each shard should be 100 bytes (1000 / 10)
    for shard in &shards {
        assert_eq!(shard.len(), 100);
    }

    // Round-trip test
    let mut decode_input: Vec<Option<Vec<u8>>> = shards.into_iter().map(Some).collect();
    let reconstructed =
        decode_stripe(&mut decode_input, &config, data.len()).expect("decoding should succeed");
    assert_eq!(reconstructed, data);
}

/// Test minimum viable configuration (k=1, m=1).
#[test]
fn test_minimum_config() {
    let config = StripeConfig {
        k: 1,
        m: 1,
        size: 100,
    };

    let data = vec![0x42u8; 50];
    let shards = encode_stripe(&data, &config).expect("encoding should succeed");

    assert_eq!(shards.len(), 2, "k+m = 1+1 = 2 shards");
    assert_eq!(shards[0].len(), 50, "Shard size = data_len / k = 50");

    // Can reconstruct with just the data shard
    let mut decode_input = vec![Some(shards[0].clone()), None];
    let reconstructed =
        decode_stripe(&mut decode_input, &config, data.len()).expect("decoding should succeed");
    assert_eq!(reconstructed, data);

    // Can also reconstruct with just the parity shard
    let mut decode_input = vec![None, Some(shards[1].clone())];
    // Note: With k=1, the parity shard IS the data (XOR of one element is itself)
    // This should still work
    let result = decode_stripe(&mut decode_input, &config, data.len());
    // k=1 means we need at least 1 shard, so this should succeed
    assert!(result.is_ok());
}

/// Test reconstruction with exactly k shards (minimum required).
#[test]
fn test_reconstruct_with_exactly_k_shards() {
    let config = StripeConfig::default(); // k=10, m=20
    let data = vec![0xFFu8; 10_000];

    let shards = encode_stripe(&data, &config).expect("encoding should succeed");

    // Keep only the first k=10 shards (all data shards)
    let mut decode_input: Vec<Option<Vec<u8>>> = shards
        .into_iter()
        .enumerate()
        .map(|(i, s)| if i < 10 { Some(s) } else { None })
        .collect();

    let reconstructed = decode_stripe(&mut decode_input, &config, data.len())
        .expect("should reconstruct with exactly k shards");

    assert_eq!(reconstructed, data);
}

/// Test reconstruction with k shards from parity only.
#[test]
fn test_reconstruct_from_parity_shards() {
    let config = StripeConfig::default(); // k=10, m=20
    let data = vec![0xAAu8; 10_000];

    let shards = encode_stripe(&data, &config).expect("encoding should succeed");

    // Keep only shards 10-19 (first 10 parity shards, skipping all data shards)
    let mut decode_input: Vec<Option<Vec<u8>>> = shards
        .into_iter()
        .enumerate()
        .map(|(i, s)| if i >= 10 && i < 20 { Some(s) } else { None })
        .collect();

    let reconstructed = decode_stripe(&mut decode_input, &config, data.len())
        .expect("should reconstruct from parity shards alone");

    assert_eq!(reconstructed, data);
}

/// Test that shards contain deterministic content.
#[test]
fn test_encode_is_deterministic() {
    let config = StripeConfig::default();
    let data = vec![0x42u8; 5000];

    let shards1 = encode_stripe(&data, &config).expect("first encode");
    let shards2 = encode_stripe(&data, &config).expect("second encode");

    assert_eq!(shards1, shards2, "Encoding must be deterministic");
}

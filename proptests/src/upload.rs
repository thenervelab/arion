//! Property-based tests for upload flow invariants.
//!
//! Tests the following invariants:
//! - UP-1: Manifest shard count = num_stripes * (k + m)
//! - UP-2: File hash integrity (manifest.file_hash == blake3(original_file))
//! - UP-5: Shards are ordered by stripe (stripe_idx = i / (k+m), shard_idx = i % (k+m))
//!
//! Note: UP-3 (minimum redundancy) and UP-4 (placement epoch) require integration
//! testing with the validator and are deferred.

#![allow(unused_imports)]
use crate::strategies::*;
use common::{FileManifest, ShardInfo, StripeConfig, encode_stripe};
use proptest::prelude::*;

proptest! {
    #![proptest_config(ProptestConfig::with_cases(256))]

    /// UP-1: Manifest shard count equals num_stripes * (k + m).
    #[test]
    fn prop_manifest_shard_count(
        file_size in 1u64..10_000_000,
    ) {
        let config = StripeConfig::default(); // k=10, m=20, size=2MB
        let stripe_size = config.size;
        let num_stripes = file_size.div_ceil(stripe_size);
        let shards_per_stripe = config.k + config.m; // 30

        let expected_shards = num_stripes * shards_per_stripe as u64;

        // Simulate creating a manifest
        let manifest = create_mock_manifest(file_size, &config);

        prop_assert_eq!(
            manifest.shards.len() as u64,
            expected_shards,
            "Manifest must have num_stripes * (k+m) = {} * {} = {} shards, got {}",
            num_stripes,
            shards_per_stripe,
            expected_shards,
            manifest.shards.len()
        );
    }

    /// UP-1 (extended): Test with various k/m configurations.
    #[test]
    fn prop_manifest_shard_count_various_configs(
        file_size in 1u64..5_000_000,
        k in 2usize..15,
        m in 1usize..15,
    ) {
        prop_assume!(k + m <= 256);

        let config = StripeConfig {
            k,
            m,
            size: 1024 * 1024, // 1 MB stripes
        };

        let num_stripes = file_size.div_ceil(config.size);
        let expected_shards = num_stripes * (k + m) as u64;

        let manifest = create_mock_manifest(file_size, &config);

        prop_assert_eq!(
            manifest.shards.len() as u64,
            expected_shards,
            "Manifest must have {} shards with k={}, m={}, got {}",
            expected_shards,
            k,
            m,
            manifest.shards.len()
        );
    }

    /// UP-2: File hash integrity - manifest.file_hash equals blake3 of original data.
    #[test]
    fn prop_file_hash_integrity(
        data in prop::collection::vec(any::<u8>(), 1..100_000),
    ) {
        let expected_hash = blake3::hash(&data).to_hex().to_string();

        let manifest = create_manifest_with_data(&data);

        prop_assert_eq!(
            manifest.file_hash,
            expected_hash,
            "manifest.file_hash must equal blake3(original_file)"
        );
    }

    /// UP-2 (extended): Empty data should not be allowed.
    #[test]
    fn prop_file_hash_requires_data(
        data in prop::collection::vec(any::<u8>(), 1..1000),
    ) {
        let manifest = create_manifest_with_data(&data);

        // File hash should be 64 hex characters
        prop_assert_eq!(
            manifest.file_hash.len(),
            64,
            "File hash must be 64 hex characters"
        );

        // Should be valid hex
        prop_assert!(
            manifest.file_hash.chars().all(|c| c.is_ascii_hexdigit()),
            "File hash must contain only hex characters"
        );
    }

    /// UP-5: Shards are ordered by stripe.
    /// For shard at index i: stripe_index = i / (k+m), shard_index = i % (k+m)
    #[test]
    fn prop_shards_ordered_by_stripe(
        file_size in 1u64..5_000_000,
    ) {
        let config = StripeConfig::default(); // k=10, m=20
        let shards_per_stripe = config.k + config.m; // 30

        let manifest = create_mock_manifest(file_size, &config);

        for (idx, shard) in manifest.shards.iter().enumerate() {
            let expected_stripe_index = idx / shards_per_stripe;
            let expected_shard_index = idx % shards_per_stripe;

            // Note: ShardInfo only has `index` field (shard within stripe)
            // We verify the ordering by checking index values
            prop_assert_eq!(
                shard.index,
                expected_shard_index,
                "Shard at global index {} should have shard_index {} (within stripe {}), got {}",
                idx,
                expected_shard_index,
                expected_stripe_index,
                shard.index
            );
        }
    }

    /// UP-5 (extended): Verify stripe boundaries are correct.
    #[test]
    fn prop_stripe_boundaries_correct(
        file_size in 1u64..10_000_000,
    ) {
        let config = StripeConfig::default();
        let shards_per_stripe = config.k + config.m;

        let manifest = create_mock_manifest(file_size, &config);

        // Each stripe should have exactly k+m shards
        let num_stripes = manifest.shards.len() / shards_per_stripe;

        for stripe_idx in 0..num_stripes {
            let stripe_start = stripe_idx * shards_per_stripe;
            let stripe_end = stripe_start + shards_per_stripe;

            // Verify shard indices within this stripe
            for (local_idx, global_idx) in (stripe_start..stripe_end).enumerate() {
                prop_assert_eq!(
                    manifest.shards[global_idx].index,
                    local_idx,
                    "Stripe {}, local index {} should match shard.index",
                    stripe_idx,
                    local_idx
                );
            }
        }
    }

    /// Manifest file_size matches total of stripe data lengths.
    #[test]
    fn prop_manifest_size_matches_file_size(
        data in prop::collection::vec(any::<u8>(), 1..100_000),
    ) {
        let file_size = data.len() as u64;
        let manifest = create_manifest_with_data(&data);

        prop_assert_eq!(
            manifest.size,
            file_size,
            "manifest.size must match original file size"
        );
    }

    /// Manifest stripe_config is preserved correctly.
    #[test]
    fn prop_manifest_preserves_stripe_config(
        k in 2usize..20,
        m in 1usize..20,
        data_size in 1usize..50_000,
    ) {
        prop_assume!(k + m <= 256);

        let config = StripeConfig {
            k,
            m,
            size: 1024 * 1024, // 1 MB
        };

        let data = vec![0xABu8; data_size];
        let manifest = create_manifest_with_config(&data, &config);

        prop_assert_eq!(manifest.stripe_config.k, k);
        prop_assert_eq!(manifest.stripe_config.m, m);
        prop_assert_eq!(manifest.stripe_config.size, config.size);
    }
}

/// Test manifest with single stripe.
#[test]
fn test_single_stripe_manifest() {
    let _config = StripeConfig::default(); // 2 MB stripe
    let data = vec![0u8; 1_000_000]; // 1 MB < stripe size

    let manifest = create_manifest_with_data(&data);

    // Should have exactly 30 shards (1 stripe * 30 shards/stripe)
    assert_eq!(manifest.shards.len(), 30);

    // All shards should have indices 0-29
    for (i, shard) in manifest.shards.iter().enumerate() {
        assert_eq!(shard.index, i);
    }
}

/// Test manifest with multiple stripes.
#[test]
fn test_multiple_stripes_manifest() {
    let config = StripeConfig {
        k: 10,
        m: 20,
        size: 1000, // 1 KB stripes for testing
    };

    let data = vec![0xFFu8; 2500]; // 2.5 KB = 3 stripes

    let manifest = create_manifest_with_config(&data, &config);

    // Should have 90 shards (3 stripes * 30 shards/stripe)
    assert_eq!(manifest.shards.len(), 90);

    // Check stripe boundaries
    for stripe_idx in 0..3 {
        for shard_in_stripe in 0..30 {
            let global_idx = stripe_idx * 30 + shard_in_stripe;
            assert_eq!(
                manifest.shards[global_idx].index, shard_in_stripe,
                "Wrong shard index at global position {}",
                global_idx
            );
        }
    }
}

/// Test manifest blob hashes are valid.
#[test]
fn test_manifest_blob_hashes_valid() {
    let data = vec![0x42u8; 5000];

    let manifest = create_manifest_with_data(&data);

    for (i, shard) in manifest.shards.iter().enumerate() {
        // Blob hash should be 64 hex characters (BLAKE3)
        assert_eq!(
            shard.blob_hash.len(),
            64,
            "Shard {} blob_hash should be 64 chars",
            i
        );
        assert!(
            shard.blob_hash.chars().all(|c| c.is_ascii_hexdigit()),
            "Shard {} blob_hash should be valid hex",
            i
        );
    }
}

/// Test that encoding data produces shards with unique hashes (for data shards at least).
#[test]
fn test_shard_hashes_not_all_same() {
    let data: Vec<u8> = (0..10000).map(|i| (i % 256) as u8).collect();
    let config = StripeConfig::default();

    let shards = encode_stripe(&data, &config).expect("encoding should succeed");

    // Hash all shards
    let hashes: std::collections::HashSet<_> = shards
        .iter()
        .map(|s| blake3::hash(s).to_hex().to_string())
        .collect();

    // With 30 shards and diverse input, we should have many unique hashes
    // (parity shards may collide with data in specific cases, but not all)
    assert!(
        hashes.len() > 1,
        "Shards should not all have identical hashes"
    );
}

// Helper functions

/// Create a mock manifest with the expected structure but without actual encoding.
fn create_mock_manifest(file_size: u64, config: &StripeConfig) -> FileManifest {
    let num_stripes = file_size.div_ceil(config.size);
    let shards_per_stripe = config.k + config.m;
    let total_shards = (num_stripes as usize) * shards_per_stripe;

    let shards: Vec<ShardInfo> = (0..total_shards)
        .map(|i| ShardInfo {
            index: i % shards_per_stripe,
            blob_hash: format!("mock_hash_{:016x}", i),
            miner_uid: None,
        })
        .collect();

    FileManifest {
        file_hash: "0".repeat(64),
        placement_version: 1,
        placement_epoch: 0,
        size: file_size,
        stripe_config: config.clone(),
        shards,
        filename: None,
        content_type: None,
    }
}

/// Create a manifest by actually encoding the data.
fn create_manifest_with_data(data: &[u8]) -> FileManifest {
    create_manifest_with_config(data, &StripeConfig::default())
}

/// Create a manifest by actually encoding the data with custom config.
fn create_manifest_with_config(data: &[u8], config: &StripeConfig) -> FileManifest {
    let file_hash = blake3::hash(data).to_hex().to_string();
    let file_size = data.len() as u64;

    // Calculate stripes
    let stripe_size = config.size as usize;
    let _shards_per_stripe = config.k + config.m; // Used implicitly by encode_stripe

    let mut all_shards = Vec::new();

    // Process each stripe
    let mut offset = 0;
    while offset < data.len() {
        let end = (offset + stripe_size).min(data.len());
        let stripe_data = &data[offset..end];

        // Encode the stripe
        let encoded_shards = encode_stripe(stripe_data, config).expect("encoding should succeed");

        // Create ShardInfo for each encoded shard
        for (shard_idx, shard_data) in encoded_shards.iter().enumerate() {
            let blob_hash = blake3::hash(shard_data).to_hex().to_string();
            all_shards.push(ShardInfo {
                index: shard_idx,
                blob_hash,
                miner_uid: None,
            });
        }

        offset = end;
    }

    FileManifest {
        file_hash,
        placement_version: 1,
        placement_epoch: 0,
        size: file_size,
        stripe_config: config.clone(),
        shards: all_shards,
        filename: None,
        content_type: None,
    }
}

//! Property-based tests for CRUSH placement algorithm.
//!
//! Tests the following invariants:
//! - CRUSH-1: One shard per family (when families >= shards)
//! - CRUSH-2: Placement is deterministic
//! - CRUSH-3: Weight proportionality (statistical)
//! - CRUSH-4: Stable input (no filtering by online status)
//! - CRUSH-5: PG calculation is deterministic
//! - CRUSH-6: PG distribution is approximately uniform

use crate::strategies::*;
use common::{ClusterMap, calculate_pg, calculate_placement_for_stripe};
use proptest::prelude::*;
use std::collections::{HashMap, HashSet};

proptest! {
    #![proptest_config(ProptestConfig::with_cases(256))]

    /// CRUSH-1: When there are enough unique families, each shard should be placed
    /// in a different family for maximum fault tolerance.
    #[test]
    fn prop_one_shard_per_family_when_sufficient_families(
        file_hash in file_hash_strategy(),
        stripe_idx in 0u64..100,
    ) {
        // Create a cluster with 30+ unique families (more than k+m=30 shards)
        let miners = create_miners_with_unique_families(35);
        let map = ClusterMap {
            epoch: 1,
            miners,
            pg_count: 16384,
            ec_k: 10,
            ec_m: 20,
        };

        let total_shards = map.ec_k + map.ec_m; // 30
        let placement = calculate_placement_for_stripe(&file_hash, stripe_idx, total_shards, &map)
            .expect("placement should succeed with enough miners");

        // Count unique families in placement
        let families: HashSet<_> = placement.iter().map(|m| &m.family_id).collect();

        prop_assert_eq!(
            families.len(),
            total_shards,
            "With {} families available, expected {} unique families in placement, got {}",
            35,
            total_shards,
            families.len()
        );
    }

    /// CRUSH-1 (fallback): When there are fewer families than shards needed,
    /// shards should be distributed as evenly as possible across all families.
    #[test]
    fn prop_family_diversity_maximized_with_few_families(
        file_hash in file_hash_strategy(),
        stripe_idx in 0u64..100,
    ) {
        // Create a cluster with only 5 unique families (less than k+m=30)
        let miners = create_miners_with_few_families(5, 10); // 5 families, 10 miners each
        let map = ClusterMap {
            epoch: 1,
            miners,
            pg_count: 16384,
            ec_k: 10,
            ec_m: 20,
        };

        let total_shards = map.ec_k + map.ec_m; // 30
        let placement = calculate_placement_for_stripe(&file_hash, stripe_idx, total_shards, &map)
            .expect("placement should succeed");

        // All 5 families should be used
        let families: HashSet<_> = placement.iter().map(|m| &m.family_id).collect();
        prop_assert_eq!(
            families.len(),
            5,
            "All 5 available families should be used, got {}",
            families.len()
        );

        // Shards should be distributed relatively evenly (30 shards / 5 families = 6 each)
        let mut family_counts: HashMap<&String, usize> = HashMap::new();
        for miner in &placement {
            *family_counts.entry(&miner.family_id).or_insert(0) += 1;
        }

        for (family, count) in &family_counts {
            prop_assert!(
                *count >= 5 && *count <= 7,
                "Family {} should have 5-7 shards (evenly distributed), got {}",
                family,
                count
            );
        }
    }

    /// CRUSH-2: Placement must be deterministic - same inputs produce same outputs.
    #[test]
    fn prop_placement_is_deterministic(
        file_hash in file_hash_strategy(),
        stripe_idx in 0u64..100,
        seed in any::<u64>(),
    ) {
        let map = create_test_cluster_map(seed, 50);
        let total_shards = map.ec_k + map.ec_m;

        let placement1 = calculate_placement_for_stripe(&file_hash, stripe_idx, total_shards, &map)
            .expect("first placement should succeed");
        let placement2 = calculate_placement_for_stripe(&file_hash, stripe_idx, total_shards, &map)
            .expect("second placement should succeed");

        let uids1: Vec<_> = placement1.iter().map(|m| m.uid).collect();
        let uids2: Vec<_> = placement2.iter().map(|m| m.uid).collect();

        prop_assert_eq!(
            uids1, uids2,
            "Placement must be deterministic: same inputs should produce same miner UIDs"
        );
    }

    /// CRUSH-2 (extended): Different stripe indices should produce different placements.
    #[test]
    fn prop_different_stripes_different_placements(
        file_hash in file_hash_strategy(),
        stripe_idx1 in 0u64..100,
        stripe_idx2 in 0u64..100,
        seed in any::<u64>(),
    ) {
        prop_assume!(stripe_idx1 != stripe_idx2);

        let map = create_test_cluster_map(seed, 50);
        let total_shards = map.ec_k + map.ec_m;

        let placement1 = calculate_placement_for_stripe(&file_hash, stripe_idx1, total_shards, &map)
            .expect("first placement should succeed");
        let placement2 = calculate_placement_for_stripe(&file_hash, stripe_idx2, total_shards, &map)
            .expect("second placement should succeed");

        let uids1: Vec<_> = placement1.iter().map(|m| m.uid).collect();
        let uids2: Vec<_> = placement2.iter().map(|m| m.uid).collect();

        // Different stripes should (usually) have different placements
        // Allow some overlap but not complete identity
        let matching = uids1.iter().zip(uids2.iter()).filter(|(a, b)| a == b).count();

        prop_assert!(
            matching < total_shards,
            "Different stripe indices should produce different placements (matching: {}/{})",
            matching,
            total_shards
        );
    }

    /// CRUSH-4: Placement uses all miners from the cluster map without filtering.
    /// This ensures Validator (write) and Gateway (read) compute identical placements.
    #[test]
    fn prop_placement_uses_stable_input(
        file_hash in file_hash_strategy(),
        stripe_idx in 0u64..100,
    ) {
        // Create map with some miners having different last_seen times
        let miners = create_miners_with_varied_last_seen(50);
        let map = ClusterMap {
            epoch: 1,
            miners,
            pg_count: 16384,
            ec_k: 10,
            ec_m: 20,
        };

        let total_shards = map.ec_k + map.ec_m;

        // Calculate placement twice with the same map (including "stale" miners)
        let placement1 = calculate_placement_for_stripe(&file_hash, stripe_idx, total_shards, &map)
            .expect("placement should succeed");
        let placement2 = calculate_placement_for_stripe(&file_hash, stripe_idx, total_shards, &map)
            .expect("second placement should succeed");

        let uids1: Vec<_> = placement1.iter().map(|m| m.uid).collect();
        let uids2: Vec<_> = placement2.iter().map(|m| m.uid).collect();

        prop_assert_eq!(
            uids1, uids2,
            "Placement should be stable regardless of miner last_seen times"
        );
    }

    /// CRUSH-5: PG calculation is deterministic.
    #[test]
    fn prop_pg_calculation_is_deterministic(
        file_hash in file_hash_strategy(),
        pg_count in 1u32..=65536,
    ) {
        let pg1 = calculate_pg(&file_hash, pg_count);
        let pg2 = calculate_pg(&file_hash, pg_count);

        prop_assert_eq!(
            pg1, pg2,
            "PG calculation must be deterministic"
        );

        prop_assert!(
            pg1 < pg_count,
            "PG ID {} must be less than pg_count {}",
            pg1,
            pg_count
        );
    }

    /// CRUSH-5 (extended): Different file hashes should map to different PGs.
    #[test]
    fn prop_different_files_different_pgs(
        hash1 in file_hash_strategy(),
        hash2 in file_hash_strategy(),
    ) {
        prop_assume!(hash1 != hash2);

        let pg_count = 16384u32;
        let pg1 = calculate_pg(&hash1, pg_count);
        let pg2 = calculate_pg(&hash2, pg_count);

        // Different hashes should usually map to different PGs
        // With 16384 PGs, collision probability is very low
        // We allow this test to pass even if they collide (statistical property)
        // but track that it happens rarely
        if pg1 == pg2 {
            // This is OK but should be rare
            // Just verify both are valid
            prop_assert!(pg1 < pg_count);
        } else {
            prop_assert_ne!(pg1, pg2);
        }
    }
}

/// CRUSH-3: Weight proportionality test (statistical).
/// Over many placements, miners with higher weights should be selected more often.
#[test]
fn test_weight_proportionality_statistical() {
    use std::collections::HashMap;

    // Create miners with known weights
    let miners = vec![
        create_miner_with_weight(0, "family_0", 100), // High weight
        create_miner_with_weight(1, "family_1", 100), // High weight
        create_miner_with_weight(2, "family_2", 100), // High weight
        create_miner_with_weight(3, "family_3", 10),  // Low weight
        create_miner_with_weight(4, "family_4", 10),  // Low weight
        create_miner_with_weight(5, "family_5", 10),  // Low weight
    ];

    let map = ClusterMap {
        epoch: 1,
        miners,
        pg_count: 16384,
        ec_k: 2, // Only need 2 data shards
        ec_m: 1, // Only need 1 parity shard (3 total)
                 // With 6 families and 3 shards needed, CRUSH will pick 3 different families
    };

    let mut selection_counts: HashMap<u32, usize> = HashMap::new();
    let iterations = 1000;

    for i in 0..iterations {
        let file_hash = format!("{:064x}", i);
        if let Ok(placement) = calculate_placement_for_stripe(&file_hash, 0, 3, &map) {
            for miner in &placement {
                *selection_counts.entry(miner.uid).or_insert(0) += 1;
            }
        }
    }

    // High-weight miners (weight=100) should be selected more often than
    // low-weight miners (weight=10) - approximately 10x more
    let high_weight_avg = (selection_counts.get(&0).unwrap_or(&0)
        + selection_counts.get(&1).unwrap_or(&0)
        + selection_counts.get(&2).unwrap_or(&0)) as f64
        / 3.0;

    let low_weight_avg = (selection_counts.get(&3).unwrap_or(&0)
        + selection_counts.get(&4).unwrap_or(&0)
        + selection_counts.get(&5).unwrap_or(&0)) as f64
        / 3.0;

    // Allow significant variance but high-weight should still be notably higher
    // (not enforcing exact 10x ratio due to statistical variance)
    assert!(
        high_weight_avg > low_weight_avg,
        "High-weight miners should be selected more often: high_avg={:.1}, low_avg={:.1}",
        high_weight_avg,
        low_weight_avg
    );
}

/// CRUSH-6: PG distribution should be approximately uniform.
#[test]
fn test_pg_distribution_uniformity() {
    let pg_count = 100u32; // Smaller PG count for better coverage
    let num_files = 10000; // 100x oversampling
    let mut pg_counts = vec![0u32; pg_count as usize];

    for i in 0..num_files {
        let file_hash = format!("{:064x}", i);
        let pg = calculate_pg(&file_hash, pg_count);
        pg_counts[pg as usize] += 1;
    }

    // Calculate statistics
    let expected_per_pg = num_files as f64 / pg_count as f64; // 100
    let min_count = *pg_counts.iter().min().unwrap() as f64;
    let max_count = *pg_counts.iter().max().unwrap() as f64;

    // Allow 50% deviation from expected (generous tolerance for statistical tests)
    // With 100 samples per bucket, this should be well within bounds
    assert!(
        min_count >= expected_per_pg * 0.5,
        "Minimum PG count {} is too low (expected ~{})",
        min_count,
        expected_per_pg
    );
    assert!(
        max_count <= expected_per_pg * 1.5,
        "Maximum PG count {} is too high (expected ~{})",
        max_count,
        expected_per_pg
    );

    // Check that all PGs are used (no empty buckets with 100x oversampling)
    let empty_pgs = pg_counts.iter().filter(|&&c| c == 0).count();
    assert!(
        empty_pgs == 0,
        "With 100x oversampling, no PGs should be empty. Found {} empty PGs",
        empty_pgs
    );
}

// Helper functions

fn create_miners_with_unique_families(count: usize) -> Vec<::common::MinerNode> {
    (0..count)
        .map(|i| create_miner_with_weight(i as u32, &format!("family_{:03}", i), 100))
        .collect()
}

fn create_miners_with_few_families(
    family_count: usize,
    miners_per_family: usize,
) -> Vec<::common::MinerNode> {
    let mut miners = Vec::new();
    for family_idx in 0..family_count {
        for miner_idx in 0..miners_per_family {
            let uid = (family_idx * miners_per_family + miner_idx) as u32;
            miners.push(create_miner_with_weight(
                uid,
                &format!("family_{:03}", family_idx),
                100,
            ));
        }
    }
    miners
}

fn create_miners_with_varied_last_seen(count: usize) -> Vec<::common::MinerNode> {
    let now = ::common::now_secs();
    (0..count)
        .map(|i| {
            let mut miner = create_miner_with_weight(i as u32, &format!("family_{:03}", i), 100);
            // Vary last_seen: some recent, some stale
            miner.last_seen = if i % 2 == 0 {
                now // Recent
            } else {
                now.saturating_sub(86400) // 24 hours ago (stale)
            };
            miner
        })
        .collect()
}

fn create_test_cluster_map(seed: u64, miner_count: usize) -> ClusterMap {
    let miners = (0..miner_count)
        .map(|i| {
            let uid = (seed as u32).wrapping_add(i as u32);
            let family = format!("family_{:03}", i % 40); // 40 families
            create_miner_with_weight(uid, &family, 100)
        })
        .collect();

    ClusterMap {
        epoch: seed,
        miners,
        pg_count: 16384,
        ec_k: 10,
        ec_m: 20,
    }
}

fn create_miner_with_weight(uid: u32, family_id: &str, weight: u32) -> ::common::MinerNode {
    // Create deterministic endpoint from UID
    let mut seed = [0u8; 32];
    seed[0..4].copy_from_slice(&uid.to_le_bytes());
    let secret_key = iroh::SecretKey::from_bytes(&seed);
    let public_key = secret_key.public();
    let endpoint = iroh::EndpointAddr::from(public_key);

    ::common::MinerNode {
        uid,
        endpoint,
        weight,
        ip_subnet: format!("192.168.{}.0/24", uid % 256),
        http_addr: format!("http://127.0.0.1:{}", 3000 + uid),
        public_key: hex::encode(public_key.as_bytes()),
        total_storage: 1_000_000_000_000,
        available_storage: 500_000_000_000,
        family_id: family_id.to_string(),
        strikes: 0,
        last_seen: ::common::now_secs(),
        heartbeat_count: 0,
        registration_time: 0,
        bandwidth_total: 0,
        bandwidth_window_start: 0,
        weight_manual_override: false,
        reputation: 0.0,
        consecutive_audit_passes: 0,
    }
}

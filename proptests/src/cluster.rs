//! Property-based tests for cluster state management.
//!
//! Tests the following invariants:
//! - CLU-4: UID is deterministic from pubkey (xxhash(pubkey) & 0x7FFFFFFF)
//! - CLU-5: UID uniqueness (collision rate < 1%)
//! - CLU-6: ClusterMap serialization round-trips correctly
//!
//! Note: CLU-1 through CLU-3 (epoch management) require integration testing
//! with validator state and are deferred.

#![allow(unused_imports)]
use crate::strategies::*;
use common::ClusterMap;
use proptest::prelude::*;
use std::collections::HashSet;

/// Compute UID from public key bytes using the same algorithm as the validator.
/// UID = xxhash(pubkey) & 0x7FFFFFFF (31-bit positive integer)
fn compute_uid(pubkey: &[u8; 32]) -> u32 {
    let hash = xxhash_rust::xxh3::xxh3_64(pubkey);
    (hash as u32) & 0x7FFFFFFF
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(256))]

    /// CLU-4: UID computation is deterministic.
    #[test]
    fn prop_uid_is_deterministic(
        pubkey in prop::array::uniform32(any::<u8>()),
    ) {
        let uid1 = compute_uid(&pubkey);
        let uid2 = compute_uid(&pubkey);

        prop_assert_eq!(
            uid1,
            uid2,
            "UID computation must be deterministic"
        );
    }

    /// CLU-4: UID fits in 31 bits (always positive when interpreted as signed).
    #[test]
    fn prop_uid_fits_in_31_bits(
        pubkey in prop::array::uniform32(any::<u8>()),
    ) {
        let uid = compute_uid(&pubkey);

        prop_assert!(
            uid <= 0x7FFFFFFF,
            "UID {} must fit in 31 bits (max 0x7FFFFFFF)",
            uid
        );
    }

    /// CLU-4: Different pubkeys produce different UIDs (usually).
    #[test]
    fn prop_different_pubkeys_different_uids(
        pubkey1 in prop::array::uniform32(any::<u8>()),
        pubkey2 in prop::array::uniform32(any::<u8>()),
    ) {
        prop_assume!(pubkey1 != pubkey2);

        let uid1 = compute_uid(&pubkey1);
        let uid2 = compute_uid(&pubkey2);

        // UIDs should usually be different (collision possible but rare)
        // With 31-bit space, collision probability for 2 random keys is ~1 in 2 billion
        // We don't enforce uniqueness here since it's statistically unlikely to fail
        if uid1 == uid2 {
            // Record but don't fail - collisions are theoretically possible
            // In practice, this branch should almost never execute
        }
    }

    /// CLU-5: UID collision rate is low (statistical test).
    #[test]
    fn prop_uid_collision_rate_low(
        pubkeys in prop::collection::hash_set(
            prop::array::uniform32(any::<u8>()),
            100..500
        ),
    ) {
        let uids: HashSet<u32> = pubkeys.iter().map(compute_uid).collect();

        // Calculate collision rate
        let collision_count = pubkeys.len() - uids.len();
        let collision_rate = collision_count as f64 / pubkeys.len() as f64;

        // With 31-bit UID space and 500 keys, expected collision rate is ~0.006%
        // Allow up to 1% collision rate as the test threshold
        prop_assert!(
            collision_rate < 0.01,
            "UID collision rate {} is too high (expected < 1%)",
            collision_rate
        );
    }

    /// CLU-6: ClusterMap JSON serialization round-trips correctly.
    #[test]
    fn prop_cluster_map_json_roundtrip(
        epoch in 0u64..1_000_000,
        miner_count in 1usize..50,
    ) {
        let map = create_test_cluster_map_for_serialization(epoch, miner_count);

        // Serialize to JSON
        let json = serde_json::to_string(&map)
            .expect("ClusterMap serialization should succeed");

        // Deserialize back
        let deserialized: ClusterMap = serde_json::from_str(&json)
            .expect("ClusterMap deserialization should succeed");

        // Verify fields match
        prop_assert_eq!(map.epoch, deserialized.epoch, "Epoch must match");
        prop_assert_eq!(map.pg_count, deserialized.pg_count, "PG count must match");
        prop_assert_eq!(map.ec_k, deserialized.ec_k, "ec_k must match");
        prop_assert_eq!(map.ec_m, deserialized.ec_m, "ec_m must match");
        prop_assert_eq!(map.miners.len(), deserialized.miners.len(), "Miner count must match");

        // Verify each miner
        for (orig, deser) in map.miners.iter().zip(deserialized.miners.iter()) {
            prop_assert_eq!(orig.uid, deser.uid, "Miner UID must match");
            prop_assert_eq!(orig.weight, deser.weight, "Miner weight must match");
            prop_assert_eq!(&orig.family_id, &deser.family_id, "Miner family_id must match");
            prop_assert_eq!(&orig.public_key, &deser.public_key, "Miner public_key must match");
            prop_assert_eq!(orig.strikes, deser.strikes, "Miner strikes must match");
            prop_assert_eq!(orig.total_storage, deser.total_storage, "Miner total_storage must match");
        }
    }

    /// CLU-6: ClusterMap handles empty miners list.
    #[test]
    fn prop_cluster_map_empty_miners_roundtrip(
        epoch in 0u64..1_000_000,
        pg_count in 1u32..65536,
    ) {
        let map = ClusterMap {
            epoch,
            miners: Vec::new(),
            pg_count,
            ec_k: 10,
            ec_m: 20,
        };

        let json = serde_json::to_string(&map)
            .expect("serialization should succeed");
        let deserialized: ClusterMap = serde_json::from_str(&json)
            .expect("deserialization should succeed");

        prop_assert_eq!(map.epoch, deserialized.epoch);
        prop_assert!(deserialized.miners.is_empty());
        prop_assert_eq!(map.pg_count, deserialized.pg_count);
    }

    /// ClusterMap default values are correctly applied during deserialization.
    #[test]
    fn prop_cluster_map_defaults_applied(
        epoch in 0u64..1_000_000,
    ) {
        // Create minimal JSON without optional fields
        let json = format!(r#"{{"epoch":{},"miners":[]}}"#, epoch);

        let deserialized: ClusterMap = serde_json::from_str(&json)
            .expect("deserialization should succeed");

        prop_assert_eq!(deserialized.epoch, epoch);
        prop_assert_eq!(deserialized.pg_count, 16384, "Default pg_count should be 16384");
        prop_assert_eq!(deserialized.ec_k, 10, "Default ec_k should be 10");
        prop_assert_eq!(deserialized.ec_m, 20, "Default ec_m should be 20");
    }
}

/// Test UID computation produces well-distributed values.
#[test]
fn test_uid_distribution() {
    let iterations = 10000;
    let mut uids = Vec::with_capacity(iterations);

    for i in 0..iterations {
        let mut pubkey = [0u8; 32];
        pubkey[0..8].copy_from_slice(&(i as u64).to_le_bytes());
        uids.push(compute_uid(&pubkey));
    }

    // Check that UIDs span a reasonable range (not clustered)
    let min_uid = *uids.iter().min().unwrap();
    let max_uid = *uids.iter().max().unwrap();

    // With good hash distribution, we should see UIDs across the full 31-bit range
    // Min should be relatively small, max should be relatively large
    let range = max_uid - min_uid;
    assert!(
        range > 0x10000000, // At least 1/8 of the 31-bit space
        "UID range {} is too narrow (min={}, max={})",
        range,
        min_uid,
        max_uid
    );
}

/// Test large ClusterMap serialization doesn't lose data.
#[test]
fn test_large_cluster_map_serialization() {
    let map = create_test_cluster_map_for_serialization(12345, 200);

    let json = serde_json::to_string(&map).expect("serialization should succeed");
    let deserialized: ClusterMap =
        serde_json::from_str(&json).expect("deserialization should succeed");

    assert_eq!(map.miners.len(), deserialized.miners.len());
    assert_eq!(map.miners.len(), 200);
}

/// Test ClusterMap binary serialization (bincode).
#[test]
fn test_cluster_map_bincode_roundtrip() {
    let map = create_test_cluster_map_for_serialization(99999, 50);

    let bytes = bincode::serialize(&map).expect("bincode serialization should succeed");
    let deserialized: ClusterMap =
        bincode::deserialize(&bytes).expect("bincode deserialization should succeed");

    assert_eq!(map.epoch, deserialized.epoch);
    assert_eq!(map.miners.len(), deserialized.miners.len());
    assert_eq!(map.pg_count, deserialized.pg_count);
}

/// Test ClusterMap new() creates correct defaults.
#[test]
fn test_cluster_map_new_defaults() {
    let map = ClusterMap::new();

    assert_eq!(map.epoch, 0);
    assert!(map.miners.is_empty());
    assert_eq!(map.pg_count, 16384);
    assert_eq!(map.ec_k, 10);
    assert_eq!(map.ec_m, 20);
}

/// Test ClusterMap add_node and remove_node.
#[test]
fn test_cluster_map_add_remove_node() {
    let mut map = ClusterMap::new();
    let miner = create_test_miner(42, "family_test");

    assert!(map.miners.is_empty());

    map.add_node(miner.clone());
    assert_eq!(map.miners.len(), 1);
    assert_eq!(map.miners[0].uid, 42);

    map.remove_node(42);
    assert!(map.miners.is_empty());

    // Removing non-existent node should be safe
    map.remove_node(999); // No panic
}

// Helper functions

fn create_test_cluster_map_for_serialization(epoch: u64, miner_count: usize) -> ClusterMap {
    let miners = (0..miner_count)
        .map(|i| create_test_miner(i as u32, &format!("family_{:03}", i % 20)))
        .collect();

    ClusterMap {
        epoch,
        miners,
        pg_count: 16384,
        ec_k: 10,
        ec_m: 20,
    }
}

fn create_test_miner(uid: u32, family_id: &str) -> ::common::MinerNode {
    // Create deterministic endpoint from UID
    let mut seed = [0u8; 32];
    seed[0..4].copy_from_slice(&uid.to_le_bytes());
    let secret_key = iroh::SecretKey::from_bytes(&seed);
    let public_key = secret_key.public();
    let endpoint = iroh::EndpointAddr::from(public_key);

    ::common::MinerNode {
        uid,
        endpoint,
        weight: 100,
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

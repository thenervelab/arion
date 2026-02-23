//! Shared proptest strategies for property-based testing.
//!
//! This module provides reusable strategies for generating:
//! - MinerNode instances with valid endpoints
//! - ClusterMap configurations
//! - StripeConfig parameters
//! - File hashes and data
//! - Attestation structures

use common::{ClusterMap, MinerNode, StripeConfig};
use proptest::prelude::*;
use std::collections::HashSet;

/// Generate a valid 64-character hex file hash.
pub fn file_hash_strategy() -> impl Strategy<Value = String> {
    "[a-f0-9]{64}"
}

/// Generate random file data within a size range.
pub fn file_data_strategy(min_size: usize, max_size: usize) -> impl Strategy<Value = Vec<u8>> {
    prop::collection::vec(any::<u8>(), min_size..=max_size)
}

/// Generate a valid family ID (e.g., "dc_01", "rack_02").
pub fn family_id_strategy() -> impl Strategy<Value = String> {
    prop_oneof![
        "[a-z]{2}_[0-9]{2}",
        "datacenter_[0-9]{1,2}",
        "rack_[a-z][0-9]",
    ]
}

/// Generate a valid CRUSH weight (1-2000).
pub fn weight_strategy() -> impl Strategy<Value = u32> {
    1u32..=2000
}

/// Generate a valid MinerNode for testing.
///
/// Note: The endpoint field requires a valid iroh::EndpointAddr which needs
/// a valid Ed25519 public key. We create a deterministic key from the UID.
pub fn miner_node_strategy() -> impl Strategy<Value = MinerNode> {
    (
        0u32..100_000,        // uid
        weight_strategy(),    // weight
        family_id_strategy(), // family_id
        0u8..10,              // strikes
        0u64..1_000_000_000,  // last_seen offset from now
    )
        .prop_map(|(uid, weight, family_id, strikes, last_seen_offset)| {
            // Create a deterministic secret key from UID for reproducibility
            let mut seed = [0u8; 32];
            seed[0..4].copy_from_slice(&uid.to_le_bytes());
            seed[4..8].copy_from_slice(&weight.to_le_bytes());
            let secret_key = iroh::SecretKey::from_bytes(&seed);
            let public_key = secret_key.public();
            let endpoint = iroh::EndpointAddr::from(public_key);

            MinerNode {
                uid,
                endpoint,
                weight,
                ip_subnet: format!("192.168.{}.0/24", uid % 256),
                ip_address: None,
                http_addr: format!("http://127.0.0.1:{}", 3000 + uid),
                public_key: hex::encode(public_key.as_bytes()),
                total_storage: 1_000_000_000_000,   // 1 TB
                available_storage: 500_000_000_000, // 500 GB
                family_id,
                strikes,
                last_seen: common::now_secs().saturating_sub(last_seen_offset),
                heartbeat_count: 0,
                registration_time: 0,
                bandwidth_total: 0,
                bandwidth_window_start: 0,
                weight_manual_override: false,
                reputation: 0.0,
                consecutive_audit_passes: 0,
                integrity_fails: 0,
                version: String::new(),
            }
        })
}

/// Generate miners with guaranteed unique UIDs.
pub fn miners_with_unique_uids(count: usize) -> impl Strategy<Value = Vec<MinerNode>> {
    prop::collection::vec(miner_node_strategy(), count..=count * 2).prop_filter_map(
        "need unique UIDs",
        move |miners| {
            let mut seen_uids = HashSet::new();
            let unique: Vec<_> = miners
                .into_iter()
                .filter(|m| seen_uids.insert(m.uid))
                .take(count)
                .collect();

            if unique.len() == count {
                Some(unique)
            } else {
                None
            }
        },
    )
}

/// Generate miners with guaranteed unique families (one miner per family).
///
/// This is useful for testing CRUSH family diversity.
pub fn miners_with_unique_families(count: usize) -> impl Strategy<Value = Vec<MinerNode>> {
    let family_names: Vec<String> = (0..count).map(|i| format!("family_{:03}", i)).collect();

    prop::collection::vec((0u32..100_000, weight_strategy(), 0u8..10), count..=count).prop_map(
        move |params| {
            params
                .into_iter()
                .enumerate()
                .map(|(i, (uid_base, weight, strikes))| {
                    let uid = uid_base + i as u32 * 1000; // Ensure unique UIDs

                    // Create deterministic endpoint
                    let mut seed = [0u8; 32];
                    seed[0..4].copy_from_slice(&uid.to_le_bytes());
                    let secret_key = iroh::SecretKey::from_bytes(&seed);
                    let public_key = secret_key.public();
                    let endpoint = iroh::EndpointAddr::from(public_key);

                    MinerNode {
                        uid,
                        endpoint,
                        weight,
                        ip_subnet: format!("192.168.{}.0/24", uid % 256),
                        ip_address: None,
                        http_addr: format!("http://127.0.0.1:{}", 3000 + uid),
                        public_key: hex::encode(public_key.as_bytes()),
                        total_storage: 1_000_000_000_000,
                        available_storage: 500_000_000_000,
                        family_id: family_names[i].clone(),
                        strikes,
                        last_seen: common::now_secs(),
                        heartbeat_count: 0,
                        registration_time: 0,
                        bandwidth_total: 0,
                        bandwidth_window_start: 0,
                        weight_manual_override: false,
                        reputation: 0.0,
                        consecutive_audit_passes: 0,
                        integrity_fails: 0,
                        version: String::new(),
                    }
                })
                .collect()
        },
    )
}

/// Generate a ClusterMap with the specified number of miners.
pub fn cluster_map_strategy(
    miner_count: impl Into<prop::sample::SizeRange>,
) -> impl Strategy<Value = ClusterMap> {
    let range = miner_count.into();
    (
        1u64..1_000_000,                                     // epoch
        prop::collection::vec(miner_node_strategy(), range), // miners
    )
        .prop_map(|(epoch, miners)| {
            // Ensure unique UIDs by deduplicating
            let mut seen = HashSet::new();
            let unique_miners: Vec<_> = miners.into_iter().filter(|m| seen.insert(m.uid)).collect();

            ClusterMap {
                epoch,
                miners: unique_miners,
                pg_count: 16384,
                ec_k: 10,
                ec_m: 20,
            }
        })
}

/// Generate a ClusterMap with miners that have unique families.
pub fn cluster_map_with_unique_families(family_count: usize) -> impl Strategy<Value = ClusterMap> {
    (1u64..1_000_000, miners_with_unique_families(family_count)).prop_map(|(epoch, miners)| {
        ClusterMap {
            epoch,
            miners,
            pg_count: 16384,
            ec_k: 10,
            ec_m: 20,
        }
    })
}

/// Generate a valid StripeConfig.
///
/// Constraints:
/// - k >= 1 (at least one data shard)
/// - m >= 1 (at least one parity shard)
/// - k + m <= 256 (GF(2^8) Reed-Solomon limit)
pub fn stripe_config_strategy() -> impl Strategy<Value = StripeConfig> {
    (2usize..50, 1usize..50).prop_filter_map("k+m must be <= 256", |(k, m)| {
        if k + m <= 256 {
            Some(StripeConfig {
                k,
                m,
                size: 2 * 1024 * 1024, // 2 MiB default
            })
        } else {
            None
        }
    })
}

/// Generate the default StripeConfig (k=10, m=20, 2 MiB).
pub fn default_stripe_config() -> StripeConfig {
    StripeConfig::default()
}

/// Generate an Ed25519 signing key seed (32 bytes).
pub fn signing_key_seed_strategy() -> impl Strategy<Value = [u8; 32]> {
    prop::array::uniform32(any::<u8>())
}

/// Generate a 32-byte nonce/hash.
pub fn bytes32_strategy() -> impl Strategy<Value = [u8; 32]> {
    prop::array::uniform32(any::<u8>())
}

/// Generate a u32 array of length 8 (for Merkle roots).
pub fn merkle_root_strategy() -> impl Strategy<Value = [u32; 8]> {
    prop::array::uniform8(any::<u32>())
}

/// Generate a Unix timestamp within a reasonable range.
pub fn timestamp_strategy() -> impl Strategy<Value = u64> {
    // Range: 2020-01-01 to 2030-01-01 (approximately)
    1577836800u64..1893456000u64
}

/// Generate a recent timestamp (within 5 minutes of now).
pub fn recent_timestamp_strategy() -> impl Strategy<Value = u64> {
    let now = common::now_secs();
    (now.saturating_sub(300))..=(now + 300)
}

/// Generate a stale timestamp (more than 5 minutes old).
pub fn stale_timestamp_strategy() -> impl Strategy<Value = u64> {
    let now = common::now_secs();
    0u64..now.saturating_sub(301)
}

#[cfg(test)]
mod tests {
    use super::*;
    use proptest::strategy::ValueTree;
    use proptest::test_runner::TestRunner;

    #[test]
    fn test_miner_node_strategy_produces_valid_miners() {
        let mut runner = TestRunner::default();
        for _ in 0..10 {
            let miner = miner_node_strategy()
                .new_tree(&mut runner)
                .unwrap()
                .current();
            assert!(miner.weight >= 1);
            assert!(miner.weight <= 2000);
            assert!(!miner.family_id.is_empty());
            assert!(!miner.public_key.is_empty());
        }
    }

    #[test]
    fn test_cluster_map_strategy_produces_valid_maps() {
        let mut runner = TestRunner::default();
        for _ in 0..10 {
            let map = cluster_map_strategy(10..50)
                .new_tree(&mut runner)
                .unwrap()
                .current();
            assert!(map.epoch >= 1);
            assert!(!map.miners.is_empty());
            assert_eq!(map.pg_count, 16384);
            assert_eq!(map.ec_k, 10);
            assert_eq!(map.ec_m, 20);
        }
    }

    #[test]
    fn test_miners_with_unique_families_are_unique() {
        let mut runner = TestRunner::default();
        let miners = miners_with_unique_families(30)
            .new_tree(&mut runner)
            .unwrap()
            .current();

        let families: HashSet<_> = miners.iter().map(|m| &m.family_id).collect();
        assert_eq!(families.len(), 30, "All families should be unique");
    }
}

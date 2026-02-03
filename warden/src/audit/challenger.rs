//! Challenge generation using deterministic seeding.
//!
//! Challenges are generated using a deterministic seed derived from:
//! - Shard hash (what we're auditing)
//! - Block hash (recent finalized block for freshness)
//! - Warden ID (prevent cross-warden replay)

use rand::rngs::StdRng;
use rand::{Rng, SeedableRng};

/// Generate a challenge nonce from seed components.
pub fn generate_nonce(shard_hash: &str, block_hash: &[u8; 32], warden_id: &[u8; 32]) -> [u8; 32] {
    let mut hasher = blake3::Hasher::new();
    hasher.update(shard_hash.as_bytes());
    hasher.update(block_hash);
    hasher.update(warden_id);
    hasher.update(b"nonce");
    *hasher.finalize().as_bytes()
}

/// Generate random chunk indices for a challenge.
///
/// Uses deterministic PRNG seeded from the nonce to ensure reproducibility.
pub fn generate_challenge_indices(
    nonce: &[u8; 32],
    chunk_count: u32,
    num_challenges: usize,
) -> Vec<u32> {
    if chunk_count == 0 || num_challenges == 0 {
        return Vec::new();
    }

    let mut rng = StdRng::from_seed(*nonce);
    let mut indices = Vec::with_capacity(num_challenges);
    let mut seen = std::collections::HashSet::new();

    // Generate unique indices
    while indices.len() < num_challenges && indices.len() < chunk_count as usize {
        let idx = rng.random_range(0..chunk_count);
        if seen.insert(idx) {
            indices.push(idx);
        }
    }

    // Sort for deterministic ordering
    indices.sort();
    indices
}

/// Generate a complete challenge.
pub fn generate_challenge(
    shard_hash: &str,
    merkle_root: [u32; 8],
    chunk_count: u32,
    num_challenges: usize,
    block_hash: &[u8; 32],
    warden_id: &[u8; 32],
    expires_at: u64,
) -> common::MinerControlMessage {
    let nonce = generate_nonce(shard_hash, block_hash, warden_id);
    let chunk_indices = generate_challenge_indices(&nonce, chunk_count, num_challenges);

    common::MinerControlMessage::PosChallenge {
        shard_hash: shard_hash.to_string(),
        chunk_indices,
        nonce,
        expected_root: merkle_root,
        expires_at,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_generate_nonce_deterministic() {
        let shard = "test_shard";
        let block = [1u8; 32];
        let warden = [2u8; 32];

        let n1 = generate_nonce(shard, &block, &warden);
        let n2 = generate_nonce(shard, &block, &warden);
        assert_eq!(n1, n2);
    }

    #[test]
    fn test_generate_nonce_different_inputs() {
        let block = [1u8; 32];
        let warden = [2u8; 32];

        let n1 = generate_nonce("shard1", &block, &warden);
        let n2 = generate_nonce("shard2", &block, &warden);
        assert_ne!(n1, n2);
    }

    #[test]
    fn test_generate_challenge_indices() {
        let nonce = [42u8; 32];
        let indices = generate_challenge_indices(&nonce, 100, 4);

        assert_eq!(indices.len(), 4);
        // All indices should be unique
        let unique: std::collections::HashSet<_> = indices.iter().collect();
        assert_eq!(unique.len(), 4);
        // All indices should be < chunk_count
        assert!(indices.iter().all(|&i| i < 100));
        // Should be sorted
        assert!(indices.windows(2).all(|w| w[0] <= w[1]));
    }

    #[test]
    fn test_generate_challenge_indices_small_chunk_count() {
        let nonce = [42u8; 32];
        // Only 3 chunks but requesting 4 challenges
        let indices = generate_challenge_indices(&nonce, 3, 4);
        assert_eq!(indices.len(), 3); // Can only get 3 unique indices
    }

    #[test]
    fn test_generate_challenge_indices_deterministic() {
        let nonce = [99u8; 32];
        let i1 = generate_challenge_indices(&nonce, 100, 4);
        let i2 = generate_challenge_indices(&nonce, 100, 4);
        assert_eq!(i1, i2);
    }

    #[test]
    fn test_generate_challenge() {
        let block = [1u8; 32];
        let warden = [2u8; 32];
        let root = [3, 4, 5, 6, 7, 8, 9, 10];

        let msg = generate_challenge("shard123", root, 100, 4, &block, &warden, 1234567890);

        match msg {
            common::MinerControlMessage::PosChallenge {
                shard_hash,
                chunk_indices,
                expires_at,
                expected_root,
                ..
            } => {
                assert_eq!(shard_hash, "shard123");
                assert_eq!(chunk_indices.len(), 4);
                assert_eq!(expires_at, 1234567890);
                assert_eq!(expected_root, root);
            }
            _ => panic!("Wrong message type"),
        }
    }
}

//! Commitment generation for proof-of-storage.
//!
//! A commitment represents a miner's cryptographic promise to store specific data.
//! It contains the Merkle root of all chunk hashes, allowing efficient verification
//! of any subset of chunks.

use serde::{Deserialize, Serialize};

use crate::hash::poseidon2_hash_bytes;
use crate::merkle::MerkleTree;
use crate::types::Poseidon2Hash;
use crate::{PosError, Result, DEFAULT_CHUNK_SIZE};

/// A storage commitment for a shard.
///
/// Contains all information needed to verify chunk possession proofs.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Commitment {
    /// Merkle root of all chunk hashes
    pub merkle_root: Poseidon2Hash,

    /// Total number of chunks in the shard
    pub chunk_count: u32,

    /// Size of each chunk in bytes
    pub chunk_size: usize,

    /// Total size of the original data in bytes
    pub data_size: usize,

    /// BLAKE3 hash of the original shard (for identification)
    pub shard_hash: String,

    /// Depth of the Merkle tree
    pub tree_depth: usize,
}

impl Commitment {
    /// Get the Merkle root.
    pub fn root(&self) -> &Poseidon2Hash {
        &self.merkle_root
    }

    /// Check if a chunk index is valid for this commitment.
    pub fn is_valid_chunk_index(&self, index: u32) -> bool {
        index < self.chunk_count
    }
}

/// Validate commitment inputs.
fn validate_commitment_inputs(data: &[u8], chunk_size: usize) -> Result<()> {
    if data.is_empty() {
        return Err(PosError::EmptyData);
    }
    if chunk_size == 0 {
        return Err(PosError::InvalidChunkSize(
            "Chunk size must be greater than 0".to_string(),
        ));
    }
    Ok(())
}

/// Compute BLAKE3 shard hash as hex string.
fn compute_shard_hash(data: &[u8]) -> String {
    blake3::hash(data).to_hex().to_string()
}

/// Generate a commitment for shard data.
///
/// This function:
/// 1. Splits the data into fixed-size chunks
/// 2. Computes the Poseidon2 hash of each chunk
/// 3. Builds a Merkle tree from the chunk hashes
/// 4. Returns the commitment containing the Merkle root
///
/// # Arguments
/// * `data` - The shard data to commit to
/// * `chunk_size` - Size of each chunk in bytes (default: 1024)
///
/// # Returns
/// A `Commitment` that can be used for proof generation and verification
///
/// # Example
/// ```ignore
/// use pos_circuits::generate_commitment;
///
/// let shard_data = vec![0u8; 68 * 1024]; // 68 KB shard
/// let commitment = generate_commitment(&shard_data, 1024)?;
/// println!("Merkle root: {:?}", commitment.merkle_root);
/// println!("Chunk count: {}", commitment.chunk_count);
/// ```
pub fn generate_commitment(data: &[u8], chunk_size: usize) -> Result<Commitment> {
    validate_commitment_inputs(data, chunk_size)?;

    let chunks: Vec<&[u8]> = data.chunks(chunk_size).collect();
    let tree = MerkleTree::from_chunks(&chunks)?;

    Ok(Commitment {
        merkle_root: tree.root(),
        chunk_count: chunks.len() as u32,
        chunk_size,
        data_size: data.len(),
        shard_hash: compute_shard_hash(data),
        tree_depth: tree.depth(),
    })
}

/// Generate a commitment with the default chunk size.
///
/// Uses `DEFAULT_CHUNK_SIZE` (1024 bytes) for chunk splitting.
pub fn generate_commitment_default(data: &[u8]) -> Result<Commitment> {
    generate_commitment(data, DEFAULT_CHUNK_SIZE)
}

/// Commitment data paired with the full Merkle tree.
///
/// This is used by miners who need to generate proofs, as they need
/// access to the full tree structure to create Merkle proofs.
#[derive(Clone, Debug)]
pub struct CommitmentWithTree {
    /// The commitment (public data)
    pub commitment: Commitment,

    /// The full Merkle tree (private, held by miner)
    pub tree: MerkleTree,

    /// The original chunk hashes
    pub chunk_hashes: Vec<Poseidon2Hash>,
}

impl CommitmentWithTree {
    /// Generate a commitment with the full Merkle tree.
    ///
    /// This is what miners should use when they need to generate proofs later.
    pub fn generate(data: &[u8], chunk_size: usize) -> Result<Self> {
        validate_commitment_inputs(data, chunk_size)?;

        let chunk_hashes: Vec<Poseidon2Hash> =
            data.chunks(chunk_size).map(poseidon2_hash_bytes).collect();

        let tree = MerkleTree::from_leaf_hashes(&chunk_hashes)?;

        let commitment = Commitment {
            merkle_root: tree.root(),
            chunk_count: chunk_hashes.len() as u32,
            chunk_size,
            data_size: data.len(),
            shard_hash: compute_shard_hash(data),
            tree_depth: tree.depth(),
        };

        Ok(Self {
            commitment,
            tree,
            chunk_hashes,
        })
    }

    /// Get a Merkle proof for a specific chunk index.
    pub fn proof(&self, chunk_index: usize) -> Result<crate::types::MerkleProof> {
        self.tree.proof(chunk_index)
    }

    /// Get the hash of a specific chunk.
    pub fn chunk_hash(&self, chunk_index: usize) -> Result<Poseidon2Hash> {
        if chunk_index >= self.chunk_hashes.len() {
            return Err(PosError::ChunkIndexOutOfBounds {
                index: chunk_index as u32,
                max: (self.chunk_hashes.len() - 1) as u32,
            });
        }
        Ok(self.chunk_hashes[chunk_index])
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_generate_commitment() {
        let data = vec![0xABu8; 4096]; // 4 KB of data
        let commitment = generate_commitment(&data, 1024).unwrap();

        assert_eq!(commitment.chunk_count, 4);
        assert_eq!(commitment.chunk_size, 1024);
        assert_eq!(commitment.data_size, 4096);
        assert_eq!(commitment.tree_depth, 2); // 4 leaves = depth 2
    }

    #[test]
    fn test_generate_commitment_non_divisible() {
        // Data size not divisible by chunk size
        let data = vec![0xCDu8; 3500]; // 3500 bytes
        let commitment = generate_commitment(&data, 1024).unwrap();

        // ceil(3500 / 1024) = 4 chunks
        assert_eq!(commitment.chunk_count, 4);
        assert_eq!(commitment.data_size, 3500);
    }

    #[test]
    fn test_generate_commitment_deterministic() {
        let data = vec![0x12u8; 2048];

        let c1 = generate_commitment(&data, 1024).unwrap();
        let c2 = generate_commitment(&data, 1024).unwrap();

        assert_eq!(c1.merkle_root, c2.merkle_root);
        assert_eq!(c1.shard_hash, c2.shard_hash);
    }

    #[test]
    fn test_generate_commitment_different_data() {
        let data1 = vec![0x00u8; 2048];
        let data2 = vec![0xFFu8; 2048];

        let c1 = generate_commitment(&data1, 1024).unwrap();
        let c2 = generate_commitment(&data2, 1024).unwrap();

        assert_ne!(c1.merkle_root, c2.merkle_root);
        assert_ne!(c1.shard_hash, c2.shard_hash);
    }

    #[test]
    fn test_empty_data() {
        let data: Vec<u8> = vec![];
        assert!(generate_commitment(&data, 1024).is_err());
    }

    #[test]
    fn test_zero_chunk_size() {
        let data = vec![0u8; 100];
        assert!(generate_commitment(&data, 0).is_err());
    }

    #[test]
    fn test_default_chunk_size() {
        let data = vec![0u8; 4096];
        let commitment = generate_commitment_default(&data).unwrap();
        assert_eq!(commitment.chunk_size, DEFAULT_CHUNK_SIZE);
    }

    #[test]
    fn test_commitment_with_tree() {
        let data = vec![0xABu8; 4096];
        let cwt = CommitmentWithTree::generate(&data, 1024).unwrap();

        // Commitment should match direct generation
        let direct = generate_commitment(&data, 1024).unwrap();
        assert_eq!(cwt.commitment.merkle_root, direct.merkle_root);

        // Should be able to get proofs
        let proof = cwt.proof(0).unwrap();
        let hash = cwt.chunk_hash(0).unwrap();

        // Proof should verify
        assert!(cwt.tree.verify_proof(&hash, &proof));
    }

    #[test]
    fn test_commitment_with_tree_all_chunks() {
        let data = vec![0x55u8; 8192]; // 8 chunks
        let cwt = CommitmentWithTree::generate(&data, 1024).unwrap();

        for i in 0..8 {
            let proof = cwt.proof(i).unwrap();
            let hash = cwt.chunk_hash(i).unwrap();
            assert!(cwt.tree.verify_proof(&hash, &proof));
        }
    }

    #[test]
    fn test_is_valid_chunk_index() {
        let data = vec![0u8; 4096];
        let commitment = generate_commitment(&data, 1024).unwrap();

        assert!(commitment.is_valid_chunk_index(0));
        assert!(commitment.is_valid_chunk_index(3));
        assert!(!commitment.is_valid_chunk_index(4));
        assert!(!commitment.is_valid_chunk_index(100));
    }

    #[test]
    fn test_large_shard() {
        // Test with ~68KB shard (typical size)
        let data = vec![0xAAu8; 68 * 1024];
        let commitment = generate_commitment(&data, 1024).unwrap();

        assert_eq!(commitment.chunk_count, 68);
        assert_eq!(commitment.tree_depth, 7); // ceil(log2(68)) padded to 128 = 7
    }
}

//! Plonky3-based Proof-of-Storage circuits for Hippius Arion.
//!
//! This crate provides zero-knowledge proof-of-storage functionality using Plonky3.
//! It allows miners to prove they possess specific data chunks without revealing
//! the actual data.
//!
//! # Architecture
//!
//! ```text
//! STORE PHASE:
//!   Shard Data → Split into Chunks → Poseidon2 Hash Each → Build Merkle Tree → Commitment
//!
//! PROVE PHASE:
//!   Challenge(indices) → Extract Chunks → Generate ZK Proof → Verify
//! ```
//!
//! # Example
//!
//! ```ignore
//! use pos_circuits::{Commitment, Challenge, generate_commitment, generate_proof, verify_proof};
//!
//! // Store phase: compute commitment
//! let shard_data = vec![0u8; 68 * 1024]; // ~68KB shard
//! let commitment = generate_commitment(&shard_data, 1024)?;
//!
//! // Challenge phase: warden sends challenge
//! let challenge = Challenge::new(&commitment, vec![3, 17, 42, 61]);
//!
//! // Prove phase: miner generates proof
//! let proof = generate_proof(&shard_data, &commitment, &challenge)?;
//!
//! // Verify phase: warden verifies proof
//! let valid = verify_proof(&proof, &commitment, &challenge)?;
//! assert!(valid);
//! ```

pub mod circuit;
pub mod commitment;
pub mod error;
pub mod hash;
pub mod merkle;
pub mod prover;
pub mod types;
pub mod verifier;

// Re-export main types and functions
pub use commitment::{generate_commitment, Commitment};
pub use error::{PosError, Result};
pub use hash::poseidon2_hash_bytes;
pub use merkle::MerkleTree;
pub use prover::generate_proof;
pub use types::{Challenge, Proof, PublicInputs};
pub use verifier::verify_proof;

/// Default chunk size in bytes (1 KB)
pub const DEFAULT_CHUNK_SIZE: usize = 1024;

/// Default number of challenges per audit
pub const DEFAULT_NUM_CHALLENGES: usize = 4;

/// Plonky3 configuration type aliases
pub mod config {
    use p3_baby_bear::BabyBear;
    use p3_field::extension::BinomialExtensionField;

    /// Base field type (BabyBear: 2^31 - 2^27 + 1)
    pub type F = BabyBear;

    /// Extension field for FRI (degree 4 extension)
    pub type EF = BinomialExtensionField<F, 4>;

    /// Number of elements in a Poseidon2 hash digest
    pub const DIGEST_ELEMS: usize = 8;

    /// Poseidon2 permutation width
    pub const POSEIDON2_WIDTH: usize = 16;
}

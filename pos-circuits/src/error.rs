//! Error types for the pos-circuits crate.

use thiserror::Error;

use crate::config::DIGEST_ELEMS;

/// Result type alias using PosError
pub type Result<T> = std::result::Result<T, PosError>;

/// Errors that can occur in proof-of-storage operations
#[derive(Error, Debug)]
pub enum PosError {
    /// Invalid chunk size (must be > 0 and divide evenly)
    #[error("Invalid chunk size: {0}")]
    InvalidChunkSize(String),

    /// Invalid chunk index in challenge
    #[error("Chunk index {index} out of bounds (max: {max})")]
    ChunkIndexOutOfBounds { index: u32, max: u32 },

    /// Data size mismatch
    #[error("Data size mismatch: expected {expected}, got {actual}")]
    DataSizeMismatch { expected: usize, actual: usize },

    /// Merkle tree construction error
    #[error("Merkle tree error: {0}")]
    MerkleTreeError(String),

    /// Proof generation failed
    #[error("Proof generation failed: {0}")]
    ProofGenerationError(String),

    /// Proof verification failed
    #[error("Proof verification failed: {0}")]
    ProofVerificationError(String),

    /// Serialization error
    #[error("Serialization error: {0}")]
    SerializationError(String),

    /// Invalid proof format
    #[error("Invalid proof format: {0}")]
    InvalidProofFormat(String),

    /// Challenge expired
    #[error("Challenge expired at {expires_at}, current time is {current}")]
    ChallengeExpired { expires_at: u64, current: u64 },

    /// Merkle root mismatch
    #[error("Merkle root mismatch: expected {expected:?}, got {actual:?}")]
    MerkleRootMismatch {
        expected: [u32; DIGEST_ELEMS],
        actual: [u32; DIGEST_ELEMS],
    },

    /// Empty data
    #[error("Cannot process empty data")]
    EmptyData,

    /// Circuit building error
    #[error("Circuit building error: {0}")]
    CircuitBuildError(String),
}

impl From<anyhow::Error> for PosError {
    fn from(err: anyhow::Error) -> Self {
        PosError::ProofGenerationError(err.to_string())
    }
}

impl From<wincode::Error> for PosError {
    fn from(err: wincode::Error) -> Self {
        PosError::SerializationError(err.to_string())
    }
}

impl From<wincode::WriteError> for PosError {
    fn from(err: wincode::WriteError) -> Self {
        PosError::SerializationError(format!("write error: {}", err))
    }
}

impl From<wincode::ReadError> for PosError {
    fn from(err: wincode::ReadError) -> Self {
        PosError::SerializationError(format!("read error: {}", err))
    }
}

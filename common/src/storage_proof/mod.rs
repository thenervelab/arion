//! Storage chunk proof protocol v1 (`docs/storage-proof-protocol.md`).
//!
//! Shared by the miner (prover path) and the warden (verifier path):
//! - [`geometry`]: the single authoritative shard derivation (§1),
//! - [`wire`]: canonical message encodings, error codes and verdicts (§1, §2, §4),
//! - [`sig`]: the strict Ed25519 profile common to all messages (§1),
//! - [`prover`]: outboard construction, validating slice encoder, response
//!   framing and challenge admission (§1, §2, §3).
//!
//! The verifier state machine lives in the warden crate. Transport, budgets
//! and priority (§5) are not implemented; activation stays blocked until the
//! transport profile is qualified.

pub mod geometry;
pub mod prover;
pub mod sig;
pub mod wire;

pub use geometry::{
    CHALLENGE_CHUNK_COUNT, CHUNK_SIZE, GeometryError, MAX_CHUNK_COUNT, MAX_PROOF_DEPTH,
    MAX_SHARD_LENGTH, ShardGeometry, derive_shard_geometry, derive_shard_geometry_for_manifest,
    expected_proof_length, proof_depth,
};
pub use wire::{ErrorCode, Verdict};

//! Property-based tests for Hippius Arion.
//!
//! This crate contains proptest-based property tests for verifying
//! invariants across the Arion storage subnet components.
//!
//! ## Running Tests
//!
//! ```bash
//! # Run all property tests
//! cargo test -p proptests
//!
//! # Run with more test cases (slower but more thorough)
//! PROPTEST_CASES=10000 cargo test -p proptests
//!
//! # Run specific test module
//! cargo test -p proptests crush
//!
//! # Run single test
//! cargo test -p proptests prop_placement_is_deterministic
//! ```
//!
//! ## Test Categories
//!
//! - **CRUSH tests**: Placement algorithm correctness (determinism, family diversity)
//! - **Codec tests**: Reed-Solomon encoding/decoding (round-trip, reconstruction)
//! - **Attestation tests**: Ed25519 signing (determinism, verification, tampering)
//! - **PoS tests**: Proof-of-storage challenge generation (nonce determinism)
//! - **Cluster tests**: Cluster state management (UID computation, serialization)
//! - **Upload tests**: File manifest structure (shard count, ordering)
//! - **Registration tests**: Miner registration signatures (verification, freshness)

// Re-export common for use in test modules
pub use common;

/// Shared test strategies and helpers.
pub mod strategies;

// Test modules
#[cfg(test)]
mod attestation;
#[cfg(test)]
mod cluster;
#[cfg(test)]
mod codec;
#[cfg(test)]
mod crush;
#[cfg(test)]
mod pos;
#[cfg(test)]
mod registration;
#[cfg(test)]
mod upload;

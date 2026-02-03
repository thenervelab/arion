//! Warden library - exports public types for testing and external use.
//!
//! The Warden is a proof-of-storage audit service that challenges miners
//! to prove they still store the data they claim to store.
//!
//! This library exports only the standalone modules that can be used
//! without the full application context:
//! - `attestation`: Audit result signing and verification
//! - `audit::challenger`: Challenge generation (nonce, indices)
//! - `audit::verifier`: Proof verification

pub mod attestation;

/// Audit submodule - only exports standalone components.
pub mod audit {
    pub mod challenger;
    pub mod verifier;
    // Note: scheduler requires full application context (config, state, p2p, submitter)
    // and is not exported through the library interface
}

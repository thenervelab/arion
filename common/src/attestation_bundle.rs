//! Attestation bundle types for verifiable proof of warden attestations.
//!
//! This module provides types for aggregating warden audit attestations into
//! merkle tree bundles that can be verified off-chain. The bundle is uploaded
//! to Arion storage, and a compact commitment is submitted on-chain.
//!
//! # Architecture
//!
//! ```text
//! Warden Audits ──▶ Validator Aggregator ──▶ AttestationBundle (SCALE)
//!                                                  │
//!                                     Upload to Arion Gateway
//!                                                  │
//!                                                  ▼
//!                                         arion_content_hash
//!                                                  │
//!                           EpochAttestationCommitment ──▶ On-chain
//! ```
//!
//! # Verification Flow
//!
//! 1. Query chain: `EpochAttestationCommitments[epoch]`
//! 2. Download bundle from Arion: `GET /download/{arion_content_hash}`
//! 3. Verify `BLAKE3(bundle_bytes) == arion_content_hash`
//! 4. Recompute attestation merkle root, compare
//! 5. Recompute warden pubkey merkle root, compare
//! 6. For each attestation: verify Ed25519 signature, verify merkle proof

use parity_scale_codec::{Decode, Encode};
use scale_info::TypeInfo;
use serde::{Deserialize, Serialize};
use serde_big_array::BigArray;

// ============================================================================
// Audit Result Type
// ============================================================================

/// Result of a warden proof-of-storage audit.
///
/// Matches the off-chain `AuditResultType` from warden audits.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Encode, Decode, TypeInfo, Serialize, Deserialize)]
#[repr(u8)]
pub enum AttestationAuditResult {
    /// Proof verified successfully
    Passed = 0,
    /// Proof verification failed
    Failed = 1,
    /// No response within deadline
    Timeout = 2,
    /// Malformed proof data
    InvalidProof = 3,
}

impl AttestationAuditResult {
    /// Convert to u8 for on-chain encoding
    pub fn as_u8(self) -> u8 {
        self as u8
    }

    /// Try to convert from u8
    pub fn from_u8(v: u8) -> Option<Self> {
        match v {
            0 => Some(Self::Passed),
            1 => Some(Self::Failed),
            2 => Some(Self::Timeout),
            3 => Some(Self::InvalidProof),
            _ => None,
        }
    }
}

impl From<crate::AuditResultType> for AttestationAuditResult {
    fn from(r: crate::AuditResultType) -> Self {
        match r {
            crate::AuditResultType::Passed => Self::Passed,
            crate::AuditResultType::Failed => Self::Failed,
            crate::AuditResultType::Timeout => Self::Timeout,
            crate::AuditResultType::InvalidProof => Self::InvalidProof,
        }
    }
}

// ============================================================================
// Attestation Leaf
// ============================================================================

/// Domain separator for attestation signing (must match pallet and warden)
const ATTESTATION_DOMAIN_SEPARATOR: &[u8] = b"ARION_ATTESTATION_V1";

/// A single attestation (leaf node content) in the merkle tree.
///
/// Contains all data needed to verify the warden's audit result.
#[derive(Clone, Debug, PartialEq, Eq, Encode, Decode, TypeInfo, Serialize, Deserialize)]
pub struct AttestationLeaf {
    /// Unique audit identifier (for signature verification)
    pub audit_id: String,
    /// BLAKE3 hash of the shard that was audited (hex string)
    pub shard_hash: String,
    /// UID of the miner that was audited
    pub miner_uid: u32,
    /// Audit result
    pub result: AttestationAuditResult,
    /// Random seed used for the challenge
    pub challenge_seed: [u8; 32],
    /// Block number when the audit was performed
    pub block_number: u64,
    /// Unix timestamp of the audit
    pub timestamp: u64,
    /// BLAKE3 hash of the proof (if received), used for on-chain verification.
    /// Empty Vec for timeout/invalid cases.
    pub merkle_proof_sig_hash: Vec<u8>,
    /// Hex-encoded warden Ed25519 public key (used in signing)
    pub warden_id: Vec<u8>,
    /// Warden's Ed25519 public key (32 bytes)
    pub warden_pubkey: [u8; 32],
    /// Ed25519 signature over the attestation data (64 bytes)
    #[serde(with = "BigArray")]
    pub signature: [u8; 64],
}

impl AttestationLeaf {
    /// Generate canonical bytes for signature verification using SCALE encoding.
    ///
    /// This format must match the warden's `to_signing_bytes()` and pallet's
    /// `verify_attestation_sig()` implementations exactly.
    ///
    /// Format: SCALE encode (domain_sep, shard_hash, miner_uid, result,
    ///         challenge_seed, block_number, timestamp, merkle_proof_sig_hash, warden_id)
    pub fn to_signing_bytes(&self) -> Vec<u8> {
        (
            ATTESTATION_DOMAIN_SEPARATOR,
            self.shard_hash.as_bytes(),
            self.miner_uid,
            self.result.as_u8(),
            self.challenge_seed,
            self.block_number,
            self.timestamp,
            &self.merkle_proof_sig_hash,
            &self.warden_id,
        )
            .encode()
    }

    /// Create the message that was signed by the warden (legacy format).
    ///
    /// Format: `"{audit_id}:{miner_uid}:{shard_hash}:{result:?}:{timestamp}"`
    /// where result is the Debug representation (e.g., "Passed", "Failed", etc.)
    #[deprecated(note = "Use to_signing_bytes() for SCALE encoding")]
    pub fn sign_message(&self) -> String {
        format!(
            "{}:{}:{}:{:?}:{}",
            self.audit_id, self.miner_uid, self.shard_hash, self.result, self.timestamp
        )
    }

    /// Verify the Ed25519 signature using SCALE-encoded signing bytes.
    ///
    /// Returns true if the signature is valid, false otherwise.
    #[cfg(feature = "verify")]
    pub fn verify_signature(&self) -> bool {
        use ed25519_dalek::{Signature, Verifier, VerifyingKey};

        let Ok(pubkey) = VerifyingKey::from_bytes(&self.warden_pubkey) else {
            return false;
        };

        let signature = Signature::from_bytes(&self.signature);

        let message = self.to_signing_bytes();
        pubkey.verify(&message, &signature).is_ok()
    }
}

// ============================================================================
// Merkle Proof
// ============================================================================

/// Merkle proof for a single leaf in the tree.
///
/// Contains the sibling hashes and direction flags needed to
/// reconstruct the path from leaf to root.
#[derive(Clone, Debug, PartialEq, Eq, Encode, Decode, TypeInfo, Serialize, Deserialize)]
pub struct MerkleProof {
    /// Zero-based index of the leaf in the tree
    pub leaf_index: u32,
    /// Sibling hashes along the path from leaf to root
    pub siblings: Vec<[u8; 32]>,
    /// Direction flags: true = sibling is on the right
    pub directions: Vec<bool>,
}

impl MerkleProof {
    /// Create an empty proof (for single-leaf trees)
    pub fn empty(leaf_index: u32) -> Self {
        Self {
            leaf_index,
            siblings: Vec::new(),
            directions: Vec::new(),
        }
    }
}

// ============================================================================
// Attestation With Proof
// ============================================================================

/// Attestation with its precomputed merkle proof.
///
/// This allows verifying a single attestation against the merkle root
/// without needing to download/process all attestations.
#[derive(Clone, Debug, PartialEq, Eq, Encode, Decode, TypeInfo, Serialize, Deserialize)]
pub struct AttestationWithProof {
    /// The attestation data
    pub attestation: AttestationLeaf,
    /// Merkle proof for this attestation
    pub proof: MerkleProof,
}

// ============================================================================
// Attestation Bundle
// ============================================================================

/// Complete attestation bundle stored in Arion (SCALE encoded).
///
/// Contains all attestations for an epoch along with merkle proofs
/// for efficient individual verification.
#[derive(Clone, Debug, PartialEq, Eq, Encode, Decode, TypeInfo, Serialize, Deserialize)]
pub struct AttestationBundle {
    /// Bundle format version (for future compatibility)
    pub version: u8,
    /// Epoch this bundle covers
    pub epoch: u64,
    /// Merkle root of all attestation leaves
    pub attestation_merkle_root: [u8; 32],
    /// Merkle root of unique warden public keys
    pub warden_pubkey_merkle_root: [u8; 32],
    /// All attestations with their merkle proofs
    pub attestations: Vec<AttestationWithProof>,
    /// Unique warden public keys (for merkle tree)
    pub warden_pubkeys: Vec<[u8; 32]>,
    /// Merkle proofs for warden public keys
    pub warden_pubkey_proofs: Vec<MerkleProof>,
}

impl AttestationBundle {
    /// Current bundle format version
    pub const CURRENT_VERSION: u8 = 1;

    /// Create a new empty bundle for an epoch
    pub fn new(epoch: u64) -> Self {
        Self {
            version: Self::CURRENT_VERSION,
            epoch,
            attestation_merkle_root: [0u8; 32],
            warden_pubkey_merkle_root: [0u8; 32],
            attestations: Vec::new(),
            warden_pubkeys: Vec::new(),
            warden_pubkey_proofs: Vec::new(),
        }
    }

    /// Get the number of attestations in this bundle
    pub fn attestation_count(&self) -> usize {
        self.attestations.len()
    }

    /// Check if the bundle is empty
    pub fn is_empty(&self) -> bool {
        self.attestations.is_empty()
    }
}

// ============================================================================
// Epoch Attestation Commitment
// ============================================================================

/// Compact commitment for on-chain storage (~136 bytes).
///
/// This is what gets submitted to the blockchain. The full bundle
/// is stored in Arion and can be retrieved using the arion_content_hash.
#[derive(Clone, Debug, PartialEq, Eq, Encode, Decode, TypeInfo, Serialize, Deserialize)]
pub struct EpochAttestationCommitment {
    /// Epoch this commitment covers
    pub epoch: u64,
    /// BLAKE3 hash of the SCALE-encoded AttestationBundle
    /// Used to retrieve the full bundle from Arion: GET /download/{arion_content_hash}
    pub arion_content_hash: [u8; 32],
    /// Merkle root of all attestation leaves
    pub attestation_merkle_root: [u8; 32],
    /// Merkle root of unique warden public keys
    pub warden_pubkey_merkle_root: [u8; 32],
    /// Number of attestations in the bundle
    pub attestation_count: u32,
}

impl EpochAttestationCommitment {
    /// Create a commitment from a bundle and its Arion content hash
    pub fn from_bundle(bundle: &AttestationBundle, arion_content_hash: [u8; 32]) -> Self {
        Self {
            epoch: bundle.epoch,
            arion_content_hash,
            attestation_merkle_root: bundle.attestation_merkle_root,
            warden_pubkey_merkle_root: bundle.warden_pubkey_merkle_root,
            attestation_count: bundle.attestation_count() as u32,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_audit_result_encoding() {
        assert_eq!(AttestationAuditResult::Passed.as_u8(), 0);
        assert_eq!(AttestationAuditResult::Failed.as_u8(), 1);
        assert_eq!(AttestationAuditResult::Timeout.as_u8(), 2);
        assert_eq!(AttestationAuditResult::InvalidProof.as_u8(), 3);

        assert_eq!(
            AttestationAuditResult::from_u8(0),
            Some(AttestationAuditResult::Passed)
        );
        assert_eq!(
            AttestationAuditResult::from_u8(1),
            Some(AttestationAuditResult::Failed)
        );
        assert_eq!(
            AttestationAuditResult::from_u8(2),
            Some(AttestationAuditResult::Timeout)
        );
        assert_eq!(
            AttestationAuditResult::from_u8(3),
            Some(AttestationAuditResult::InvalidProof)
        );
        assert_eq!(AttestationAuditResult::from_u8(4), None);
    }

    #[test]
    fn test_attestation_leaf_scale_roundtrip() {
        let leaf = AttestationLeaf {
            audit_id: "test-audit-123".to_string(),
            shard_hash: "abc123def456".to_string(),
            miner_uid: 42,
            result: AttestationAuditResult::Passed,
            challenge_seed: [1u8; 32],
            block_number: 12345,
            timestamp: 1700000000,
            merkle_proof_sig_hash: vec![3u8; 32],
            warden_id: b"test-warden-id".to_vec(),
            warden_pubkey: [4u8; 32],
            signature: [5u8; 64],
        };

        let encoded = leaf.encode();
        let decoded = AttestationLeaf::decode(&mut &encoded[..]).unwrap();
        assert_eq!(leaf, decoded);
    }

    #[test]
    fn test_attestation_leaf_to_signing_bytes() {
        let leaf = AttestationLeaf {
            audit_id: "test-audit-123".to_string(),
            shard_hash: "abc123def456".to_string(),
            miner_uid: 42,
            result: AttestationAuditResult::Passed,
            challenge_seed: [1u8; 32],
            block_number: 12345,
            timestamp: 1700000000,
            merkle_proof_sig_hash: vec![3u8; 32],
            warden_id: b"test-warden-id".to_vec(),
            warden_pubkey: [4u8; 32],
            signature: [5u8; 64],
        };

        let bytes1 = leaf.to_signing_bytes();
        let bytes2 = leaf.to_signing_bytes();
        assert_eq!(bytes1, bytes2, "to_signing_bytes must be deterministic");
        assert!(!bytes1.is_empty());
    }

    #[test]
    fn test_merkle_proof_scale_roundtrip() {
        let proof = MerkleProof {
            leaf_index: 5,
            siblings: vec![[1u8; 32], [2u8; 32], [3u8; 32]],
            directions: vec![true, false, true],
        };

        let encoded = proof.encode();
        let decoded = MerkleProof::decode(&mut &encoded[..]).unwrap();
        assert_eq!(proof, decoded);
    }

    #[test]
    fn test_attestation_bundle_scale_roundtrip() {
        let bundle = AttestationBundle {
            version: 1,
            epoch: 42,
            attestation_merkle_root: [1u8; 32],
            warden_pubkey_merkle_root: [2u8; 32],
            attestations: vec![AttestationWithProof {
                attestation: AttestationLeaf {
                    audit_id: "test-audit-1".to_string(),
                    shard_hash: "test".to_string(),
                    miner_uid: 1,
                    result: AttestationAuditResult::Passed,
                    challenge_seed: [0u8; 32],
                    block_number: 100,
                    timestamp: 1000,
                    merkle_proof_sig_hash: vec![],
                    warden_id: vec![],
                    warden_pubkey: [0u8; 32],
                    signature: [0u8; 64],
                },
                proof: MerkleProof::empty(0),
            }],
            warden_pubkeys: vec![[0u8; 32]],
            warden_pubkey_proofs: vec![MerkleProof::empty(0)],
        };

        let encoded = bundle.encode();
        let decoded = AttestationBundle::decode(&mut &encoded[..]).unwrap();
        assert_eq!(bundle, decoded);
    }

    #[test]
    fn test_commitment_from_bundle() {
        let bundle = AttestationBundle {
            version: 1,
            epoch: 42,
            attestation_merkle_root: [1u8; 32],
            warden_pubkey_merkle_root: [2u8; 32],
            attestations: vec![],
            warden_pubkeys: vec![],
            warden_pubkey_proofs: vec![],
        };

        let arion_hash = [3u8; 32];
        let commitment = EpochAttestationCommitment::from_bundle(&bundle, arion_hash);

        assert_eq!(commitment.epoch, 42);
        assert_eq!(commitment.arion_content_hash, arion_hash);
        assert_eq!(
            commitment.attestation_merkle_root,
            bundle.attestation_merkle_root
        );
        assert_eq!(
            commitment.warden_pubkey_merkle_root,
            bundle.warden_pubkey_merkle_root
        );
        assert_eq!(commitment.attestation_count, 0);
    }
}

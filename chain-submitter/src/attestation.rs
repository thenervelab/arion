//! Attestation types for warden proof-of-storage verification.
//!
//! These types must match the warden's attestation format exactly for JSON deserialization.
//! The warden signs attestations after verifying proof-of-storage challenges from miners.

use ed25519_dalek::{Signature, VerifyingKey};
use parity_scale_codec::Encode;
use serde::{Deserialize, Serialize};

/// Result of a proof-of-storage audit performed by the warden.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Encode)]
pub enum AuditResult {
    /// Miner provided valid proof for the challenged data
    Passed,
    /// Miner provided incorrect proof
    Failed,
    /// Miner did not respond within timeout
    Timeout,
    /// Miner's proof was malformed or cryptographically invalid
    InvalidProof,
}

impl AuditResult {
    /// Convert to u8 for SCALE encoding in signatures.
    ///
    /// These values must match the pallet's `AuditResult` enum encoding.
    pub fn as_u8(&self) -> u8 {
        match self {
            AuditResult::Passed => 0,
            AuditResult::Failed => 1,
            AuditResult::Timeout => 2,
            AuditResult::InvalidProof => 3,
        }
    }

    /// Get the variant name for subxt dynamic encoding.
    ///
    /// This must match the exact variant names in the pallet's `AuditResult` enum.
    pub fn variant_name(&self) -> &'static str {
        match self {
            AuditResult::Passed => "Passed",
            AuditResult::Failed => "Failed",
            AuditResult::Timeout => "Timeout",
            AuditResult::InvalidProof => "InvalidProof",
        }
    }
}

/// Domain separator for attestation signing (must match pallet and warden)
const ATTESTATION_DOMAIN_SEPARATOR: &[u8] = b"ARION_ATTESTATION_V1";

/// Unsigned attestation containing audit details.
///
/// This is the payload that gets signed by the warden's Ed25519 key.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Attestation {
    /// BLAKE3 hash of the shard that was audited (hex string)
    pub shard_hash: String,
    /// UID of the miner being audited
    pub miner_uid: u32,
    /// Result of the audit
    pub result: AuditResult,
    /// Random seed used to generate the challenge
    pub challenge_seed: [u8; 32],
    /// Block number when challenge was issued
    pub block_number: u64,
    /// Unix timestamp when challenge was issued
    pub timestamp: u64,
    /// BLAKE3 hash of the proof (if received), used for on-chain verification
    /// This is empty Vec if no proof was received (timeout/invalid)
    pub merkle_proof_sig_hash: Vec<u8>,
    /// Hex-encoded warden Ed25519 public key
    pub warden_id: String,
}

impl Attestation {
    /// Generate canonical bytes for signature verification using SCALE encoding.
    ///
    /// This must match the warden's `to_signing_bytes()` and pallet's
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
            self.warden_id.as_bytes(),
        )
            .encode()
    }
}

/// Attestation signed by a warden's Ed25519 key.
///
/// The signature proves the warden verified the proof-of-storage challenge
/// and recorded the result in the attestation.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SignedAttestation {
    /// The attestation payload
    pub attestation: Attestation,
    /// Warden's Ed25519 public key (32 bytes)
    pub warden_pubkey: Vec<u8>,
    /// Ed25519 signature over `attestation.to_signing_bytes()` (64 bytes)
    pub signature: Vec<u8>,
}

impl SignedAttestation {
    /// Verify the Ed25519 signature.
    ///
    /// Returns true if:
    /// - warden_pubkey is exactly 32 bytes and a valid Ed25519 public key
    /// - signature is exactly 64 bytes
    /// - signature verifies against attestation.to_signing_bytes()
    pub fn verify(&self) -> bool {
        let pubkey_bytes: [u8; 32] = match self.warden_pubkey.as_slice().try_into() {
            Ok(b) => b,
            Err(_) => return false,
        };
        let Ok(pubkey) = VerifyingKey::from_bytes(&pubkey_bytes) else {
            return false;
        };

        let sig_bytes: [u8; 64] = match self.signature.as_slice().try_into() {
            Ok(b) => b,
            Err(_) => return false,
        };
        let signature = Signature::from_bytes(&sig_bytes);

        pubkey
            .verify_strict(&self.attestation.to_signing_bytes(), &signature)
            .is_ok()
    }

    /// Generate a unique key for deduplication.
    ///
    /// Format: `{shard_hash}:{miner_uid}:{challenge_seed_hex}`
    ///
    /// This ensures the same challenge (same shard + same miner + same nonce) is only
    /// processed once, preventing replay attacks.
    pub fn dedup_key(&self) -> String {
        format!(
            "{}:{}:{}",
            self.attestation.shard_hash,
            self.attestation.miner_uid,
            hex::encode(self.attestation.challenge_seed)
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::SigningKey;

    fn test_warden_id(signing_key: &SigningKey) -> String {
        hex::encode(signing_key.verifying_key().to_bytes())
    }

    fn create_test_attestation() -> Attestation {
        let signing_key = SigningKey::from_bytes(&[42u8; 32]);
        Attestation {
            shard_hash: "abc123def456".to_string(),
            miner_uid: 42,
            result: AuditResult::Passed,
            challenge_seed: [1u8; 32],
            block_number: 12345,
            timestamp: 1700000000,
            merkle_proof_sig_hash: vec![3u8; 32],
            warden_id: test_warden_id(&signing_key),
        }
    }

    fn sign_attestation(attestation: &Attestation, signing_key: &SigningKey) -> SignedAttestation {
        use ed25519_dalek::Signer;
        let message = attestation.to_signing_bytes();
        let signature = signing_key.sign(&message);
        SignedAttestation {
            attestation: attestation.clone(),
            warden_pubkey: signing_key.verifying_key().as_bytes().to_vec(),
            signature: signature.to_bytes().to_vec(),
        }
    }

    #[test]
    fn test_audit_result_as_u8() {
        assert_eq!(AuditResult::Passed.as_u8(), 0);
        assert_eq!(AuditResult::Failed.as_u8(), 1);
        assert_eq!(AuditResult::Timeout.as_u8(), 2);
        assert_eq!(AuditResult::InvalidProof.as_u8(), 3);
    }

    #[test]
    fn test_to_signing_bytes_determinism() {
        let attestation = create_test_attestation();
        let bytes1 = attestation.to_signing_bytes();
        let bytes2 = attestation.to_signing_bytes();
        assert_eq!(bytes1, bytes2, "to_signing_bytes must be deterministic");
    }

    #[test]
    fn test_to_signing_bytes_with_empty_proof_hash() {
        let mut attestation = create_test_attestation();
        attestation.merkle_proof_sig_hash = vec![];
        let bytes = attestation.to_signing_bytes();

        // Should still produce valid bytes (empty vec is SCALE encoded)
        assert!(!bytes.is_empty());
    }

    #[test]
    fn test_to_signing_bytes_with_proof_hash() {
        let attestation = create_test_attestation();
        let bytes = attestation.to_signing_bytes();

        // Should produce valid SCALE-encoded bytes
        assert!(!bytes.is_empty());
        // Verify determinism
        assert_eq!(bytes, attestation.to_signing_bytes());
    }

    #[test]
    fn test_signature_verification_valid() {
        let signing_key = SigningKey::from_bytes(&[42u8; 32]);
        let attestation = create_test_attestation();
        let signed = sign_attestation(&attestation, &signing_key);

        assert!(signed.verify(), "Valid signature should verify");
    }

    #[test]
    fn test_signature_verification_invalid_signature() {
        let signing_key = SigningKey::from_bytes(&[42u8; 32]);
        let attestation = create_test_attestation();
        let mut signed = sign_attestation(&attestation, &signing_key);

        // Tamper with signature
        signed.signature[0] ^= 0xFF;

        assert!(!signed.verify(), "Tampered signature should not verify");
    }

    #[test]
    fn test_signature_verification_invalid_pubkey() {
        let signing_key = SigningKey::from_bytes(&[42u8; 32]);
        let attestation = create_test_attestation();
        let mut signed = sign_attestation(&attestation, &signing_key);

        // Use wrong pubkey
        signed.warden_pubkey = vec![99u8; 32];

        assert!(!signed.verify(), "Wrong pubkey should not verify");
    }

    #[test]
    fn test_signature_verification_tampered_attestation() {
        let signing_key = SigningKey::from_bytes(&[42u8; 32]);
        let attestation = create_test_attestation();
        let mut signed = sign_attestation(&attestation, &signing_key);

        // Tamper with attestation data
        signed.attestation.miner_uid = 9999;

        assert!(!signed.verify(), "Tampered attestation should not verify");
    }

    #[test]
    fn test_signature_verification_wrong_length_pubkey() {
        let signing_key = SigningKey::from_bytes(&[42u8; 32]);
        let attestation = create_test_attestation();
        let mut signed = sign_attestation(&attestation, &signing_key);

        // Wrong length pubkey
        signed.warden_pubkey = vec![0u8; 31];

        assert!(!signed.verify(), "Wrong length pubkey should not verify");
    }

    #[test]
    fn test_signature_verification_wrong_length_signature() {
        let signing_key = SigningKey::from_bytes(&[42u8; 32]);
        let attestation = create_test_attestation();
        let mut signed = sign_attestation(&attestation, &signing_key);

        // Wrong length signature
        signed.signature = vec![0u8; 63];

        assert!(!signed.verify(), "Wrong length signature should not verify");
    }

    #[test]
    fn test_dedup_key_uniqueness() {
        let mut attestation1 = create_test_attestation();
        let mut attestation2 = create_test_attestation();

        attestation1.challenge_seed = [1u8; 32];
        attestation2.challenge_seed = [2u8; 32];

        let signed1 = SignedAttestation {
            attestation: attestation1,
            warden_pubkey: vec![0u8; 32],
            signature: vec![0u8; 64],
        };
        let signed2 = SignedAttestation {
            attestation: attestation2,
            warden_pubkey: vec![0u8; 32],
            signature: vec![0u8; 64],
        };

        assert_ne!(
            signed1.dedup_key(),
            signed2.dedup_key(),
            "Different nonces should produce different dedup keys"
        );
    }

    #[test]
    fn test_dedup_key_same_challenge() {
        let attestation = create_test_attestation();
        let signed1 = SignedAttestation {
            attestation: attestation.clone(),
            warden_pubkey: vec![0u8; 32],
            signature: vec![0u8; 64],
        };
        let signed2 = SignedAttestation {
            attestation,
            warden_pubkey: vec![99u8; 32], // Different warden
            signature: vec![99u8; 64],
        };

        assert_eq!(
            signed1.dedup_key(),
            signed2.dedup_key(),
            "Same challenge should produce same dedup key regardless of signer"
        );
    }

    #[test]
    fn test_json_round_trip() {
        let signing_key = SigningKey::from_bytes(&[42u8; 32]);
        let attestation = create_test_attestation();
        let signed = sign_attestation(&attestation, &signing_key);

        let json = serde_json::to_string(&signed).expect("serialize");
        let deserialized: SignedAttestation = serde_json::from_str(&json).expect("deserialize");

        assert!(
            deserialized.verify(),
            "Round-tripped attestation should verify"
        );
        assert_eq!(deserialized.dedup_key(), signed.dedup_key());
    }
}

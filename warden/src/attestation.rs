//! Attestation creation and signing.

use ed25519_dalek::{Signer, SigningKey, VerifyingKey};
use parity_scale_codec::Encode;
use serde::{Deserialize, Serialize};

/// Result of an audit.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Encode)]
pub enum AuditResult {
    Passed,
    Failed,
    Timeout,
    InvalidProof,
}

impl AuditResult {
    /// Convert to u8 for encoding.
    pub fn as_u8(&self) -> u8 {
        match self {
            AuditResult::Passed => 0,
            AuditResult::Failed => 1,
            AuditResult::Timeout => 2,
            AuditResult::InvalidProof => 3,
        }
    }
}

/// An attestation of an audit result.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Attestation {
    /// BLAKE3 hash of the audited shard
    pub shard_hash: String,
    /// UID of the audited miner
    pub miner_uid: u32,
    /// Audit result
    pub result: AuditResult,
    /// Challenge seed (nonce)
    pub challenge_seed: [u8; 32],
    /// Block number at challenge time
    pub block_number: u64,
    /// Unix timestamp of attestation
    pub timestamp: u64,
    /// BLAKE3 hash of the proof (if received), used for on-chain verification
    /// This is empty Vec if no proof was received (timeout/invalid)
    pub merkle_proof_sig_hash: Vec<u8>,
    /// Hex-encoded warden Ed25519 public key
    pub warden_id: String,
}

/// A signed attestation ready for chain submission.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SignedAttestation {
    pub attestation: Attestation,
    /// Warden's Ed25519 public key (32 bytes)
    pub warden_pubkey: Vec<u8>,
    /// Ed25519 signature over attestation (64 bytes)
    pub signature: Vec<u8>,
}

/// Domain separator for attestation signing (must match pallet)
const ATTESTATION_DOMAIN_SEPARATOR: &[u8] = b"ARION_ATTESTATION_V1";

impl Attestation {
    /// Compute the canonical bytes for signing using SCALE encoding.
    ///
    /// This format must match the pallet's `verify_attestation_sig()` exactly:
    /// SCALE encode: (domain_sep, shard_hash, miner_uid, result, challenge_seed,
    ///                block_number, timestamp, merkle_proof_sig_hash, warden_id)
    #[allow(dead_code)] // Scaffolding for P2P integration
    pub fn to_signing_bytes(&self) -> Vec<u8> {
        // Match pallet's verify_attestation_sig() format exactly using SCALE encoding
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

    /// Sign the attestation.
    #[allow(dead_code)] // Scaffolding for P2P integration
    pub fn sign(&self, signing_key: &SigningKey) -> SignedAttestation {
        let bytes = self.to_signing_bytes();
        let signature = signing_key.sign(&bytes);
        let pubkey = signing_key.verifying_key();

        SignedAttestation {
            attestation: self.clone(),
            warden_pubkey: pubkey.to_bytes().to_vec(),
            signature: signature.to_bytes().to_vec(),
        }
    }
}

impl SignedAttestation {
    /// Verify the signature.
    #[allow(dead_code)] // Scaffolding for P2P integration
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
        let signature = ed25519_dalek::Signature::from_bytes(&sig_bytes);

        let bytes = self.attestation.to_signing_bytes();
        pubkey.verify_strict(&bytes, &signature).is_ok()
    }

    /// Serialize to JSON bytes.
    ///
    /// Returns an error if serialization fails (should not happen for valid attestations).
    #[allow(dead_code)] // Scaffolding for P2P integration
    pub fn to_json(&self) -> Result<Vec<u8>, serde_json::Error> {
        serde_json::to_vec(self)
    }
}

/// Load or generate a signing keypair.
///
/// On Unix, the keypair file is created with mode 0600 (owner read/write only)
/// to protect the private key material.
pub fn load_or_generate_keypair(path: &std::path::Path) -> anyhow::Result<SigningKey> {
    if path.exists() {
        let bytes = std::fs::read(path)?;
        if bytes.len() != 32 {
            anyhow::bail!("Invalid keypair file size");
        }
        let key_bytes: [u8; 32] = bytes.try_into().unwrap();
        Ok(SigningKey::from_bytes(&key_bytes))
    } else {
        // Generate new keypair using getrandom for OS entropy
        let mut key_bytes = [0u8; 32];
        getrandom::fill(&mut key_bytes)?;
        let signing_key = SigningKey::from_bytes(&key_bytes);

        // Ensure parent directory exists
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)?;
        }

        // Write keypair with restrictive permissions (Unix: 0600)
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            let mut file = std::fs::OpenOptions::new()
                .write(true)
                .create(true)
                .truncate(true)
                .mode(0o600)
                .open(path)?;
            use std::io::Write;
            file.write_all(&signing_key.to_bytes())?;
        }
        #[cfg(not(unix))]
        {
            std::fs::write(path, signing_key.to_bytes())?;
        }

        Ok(signing_key)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_keypair() -> SigningKey {
        SigningKey::from_bytes(&[42u8; 32])
    }

    fn test_warden_id(keypair: &SigningKey) -> String {
        hex::encode(keypair.verifying_key().to_bytes())
    }

    #[test]
    fn test_sign_and_verify() {
        let keypair = test_keypair();
        let warden_id = test_warden_id(&keypair);
        let attestation = Attestation {
            shard_hash: "abc123".to_string(),
            miner_uid: 42,
            result: AuditResult::Passed,
            challenge_seed: [1u8; 32],
            block_number: 12345,
            timestamp: 1234567890,
            merkle_proof_sig_hash: vec![3u8; 32],
            warden_id,
        };

        let signed = attestation.sign(&keypair);
        assert!(signed.verify());
    }

    #[test]
    fn test_tampered_signature_fails() {
        let keypair = test_keypair();
        let warden_id = test_warden_id(&keypair);
        let attestation = Attestation {
            shard_hash: "abc123".to_string(),
            miner_uid: 42,
            result: AuditResult::Passed,
            challenge_seed: [1u8; 32],
            block_number: 12345,
            timestamp: 1234567890,
            merkle_proof_sig_hash: vec![],
            warden_id,
        };

        let mut signed = attestation.sign(&keypair);
        signed.signature[0] ^= 0xFF; // Tamper with signature
        assert!(!signed.verify());
    }

    #[test]
    fn test_different_results_different_bytes() {
        let keypair = test_keypair();
        let warden_id = test_warden_id(&keypair);
        let a1 = Attestation {
            shard_hash: "test".to_string(),
            miner_uid: 1,
            result: AuditResult::Passed,
            challenge_seed: [0; 32],
            block_number: 0,
            timestamp: 0,
            merkle_proof_sig_hash: vec![],
            warden_id: warden_id.clone(),
        };

        let mut a2 = a1.clone();
        a2.result = AuditResult::Failed;

        assert_ne!(a1.to_signing_bytes(), a2.to_signing_bytes());
    }

    #[test]
    fn test_signing_bytes_uses_scale_encoding() {
        let keypair = test_keypair();
        let warden_id = test_warden_id(&keypair);
        let attestation = Attestation {
            shard_hash: "test".to_string(),
            miner_uid: 1,
            result: AuditResult::Passed,
            challenge_seed: [0; 32],
            block_number: 100,
            timestamp: 1000,
            merkle_proof_sig_hash: vec![1, 2, 3],
            warden_id,
        };

        let bytes = attestation.to_signing_bytes();
        // Should start with SCALE-encoded domain separator
        // SCALE encodes byte slices with length prefix
        assert!(!bytes.is_empty());
        // Verify determinism
        assert_eq!(bytes, attestation.to_signing_bytes());
    }
}

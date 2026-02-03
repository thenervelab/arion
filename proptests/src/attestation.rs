//! Property-based tests for attestation signing.
//!
//! Tests the following invariants:
//! - ATT-1: Signature is deterministic
//! - ATT-2: Valid signature verifies
//! - ATT-3: Tampered attestation/signature fails verification
//! - ATT-4: Different results produce different signatures
//! - ATT-5: to_signing_bytes() is deterministic (canonical)

#![allow(unused_imports)]
use crate::strategies::*;
use ed25519_dalek::SigningKey;
use proptest::prelude::*;
use warden::attestation::{Attestation, AuditResult, SignedAttestation};

/// Generate a valid AuditResult.
fn audit_result_strategy() -> impl Strategy<Value = AuditResult> {
    prop_oneof![
        Just(AuditResult::Passed),
        Just(AuditResult::Failed),
        Just(AuditResult::Timeout),
        Just(AuditResult::InvalidProof),
    ]
}

/// Generate a valid Attestation.
fn attestation_strategy() -> impl Strategy<Value = Attestation> {
    (
        "[a-f0-9]{64}",                            // shard_hash
        0u32..1_000_000,                           // miner_uid
        audit_result_strategy(),                   // result
        prop::array::uniform32(any::<u8>()),       // challenge_seed
        0u64..10_000_000,                          // block_number
        1577836800u64..1893456000u64,              // timestamp (2020-2030)
        prop::collection::vec(any::<u8>(), 0..33), // merkle_proof_sig_hash
        "[a-f0-9]{64}",                            // warden_id
    )
        .prop_map(
            |(
                shard_hash,
                miner_uid,
                result,
                challenge_seed,
                block_number,
                timestamp,
                merkle_proof_sig_hash,
                warden_id,
            )| {
                Attestation {
                    shard_hash,
                    miner_uid,
                    result,
                    challenge_seed,
                    block_number,
                    timestamp,
                    merkle_proof_sig_hash,
                    warden_id,
                }
            },
        )
}

/// Create a deterministic signing key from a seed.
fn create_signing_key(seed: &[u8; 32]) -> SigningKey {
    SigningKey::from_bytes(seed)
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(256))]

    /// ATT-1: Signature is deterministic - same attestation + key produces same signature.
    #[test]
    fn prop_signature_is_deterministic(
        attestation in attestation_strategy(),
        key_seed in prop::array::uniform32(any::<u8>()),
    ) {
        let key = create_signing_key(&key_seed);

        let signed1 = attestation.sign(&key);
        let signed2 = attestation.sign(&key);

        prop_assert_eq!(
            signed1.signature,
            signed2.signature,
            "Signature must be deterministic"
        );
        prop_assert_eq!(
            signed1.warden_pubkey,
            signed2.warden_pubkey,
            "Public key must be consistent"
        );
    }

    /// ATT-2: Valid signature verifies correctly.
    #[test]
    fn prop_valid_signature_verifies(
        attestation in attestation_strategy(),
        key_seed in prop::array::uniform32(any::<u8>()),
    ) {
        let key = create_signing_key(&key_seed);
        let signed = attestation.sign(&key);

        prop_assert!(
            signed.verify(),
            "Valid signature must verify"
        );
    }

    /// ATT-3a: Tampered signature fails verification.
    #[test]
    fn prop_tampered_signature_fails(
        attestation in attestation_strategy(),
        key_seed in prop::array::uniform32(any::<u8>()),
        tamper_byte in 0usize..64,
        tamper_bit in 0u8..8,
    ) {
        let key = create_signing_key(&key_seed);
        let mut signed = attestation.sign(&key);

        // Verify it's valid before tampering
        prop_assert!(signed.verify(), "Should be valid before tampering");

        // Tamper with one bit in the signature
        signed.signature[tamper_byte] ^= 1 << tamper_bit;

        prop_assert!(
            !signed.verify(),
            "Tampered signature must not verify"
        );
    }

    /// ATT-3b: Tampered attestation data fails verification.
    #[test]
    fn prop_tampered_attestation_fails(
        attestation in attestation_strategy(),
        key_seed in prop::array::uniform32(any::<u8>()),
    ) {
        let key = create_signing_key(&key_seed);
        let mut signed = attestation.sign(&key);

        // Modify the attestation after signing
        signed.attestation.miner_uid = signed.attestation.miner_uid.wrapping_add(1);

        prop_assert!(
            !signed.verify(),
            "Modified attestation must not verify"
        );
    }

    /// ATT-3c: Tampered shard_hash fails verification.
    #[test]
    fn prop_tampered_shard_hash_fails(
        attestation in attestation_strategy(),
        key_seed in prop::array::uniform32(any::<u8>()),
    ) {
        let key = create_signing_key(&key_seed);
        let mut signed = attestation.sign(&key);

        // Modify the shard_hash
        signed.attestation.shard_hash = format!("{}x", &signed.attestation.shard_hash[..63]);

        prop_assert!(
            !signed.verify(),
            "Modified shard_hash must not verify"
        );
    }

    /// ATT-3d: Tampered timestamp fails verification.
    #[test]
    fn prop_tampered_timestamp_fails(
        attestation in attestation_strategy(),
        key_seed in prop::array::uniform32(any::<u8>()),
    ) {
        let key = create_signing_key(&key_seed);
        let mut signed = attestation.sign(&key);

        // Modify the timestamp
        signed.attestation.timestamp = signed.attestation.timestamp.wrapping_add(1);

        prop_assert!(
            !signed.verify(),
            "Modified timestamp must not verify"
        );
    }

    /// ATT-4: Different audit results produce different signatures.
    #[test]
    fn prop_different_results_different_signatures(
        base_attestation in attestation_strategy(),
        key_seed in prop::array::uniform32(any::<u8>()),
    ) {
        let key = create_signing_key(&key_seed);

        // Create attestations with different results
        let mut att_passed = base_attestation.clone();
        att_passed.result = AuditResult::Passed;

        let mut att_failed = base_attestation.clone();
        att_failed.result = AuditResult::Failed;

        let signed_passed = att_passed.sign(&key);
        let signed_failed = att_failed.sign(&key);

        prop_assert_ne!(
            signed_passed.signature,
            signed_failed.signature,
            "Different results must produce different signatures"
        );
    }

    /// ATT-5: to_signing_bytes() is deterministic (canonical serialization).
    #[test]
    fn prop_signing_bytes_deterministic(
        attestation in attestation_strategy(),
    ) {
        let bytes1 = attestation.to_signing_bytes();
        let bytes2 = attestation.to_signing_bytes();

        prop_assert_eq!(
            bytes1,
            bytes2,
            "to_signing_bytes() must be deterministic"
        );
    }

    /// ATT-5 (extended): Different attestations produce different signing bytes.
    #[test]
    fn prop_different_attestations_different_bytes(
        att1 in attestation_strategy(),
        att2 in attestation_strategy(),
    ) {
        // Skip if attestations happen to be identical
        if att1.shard_hash != att2.shard_hash
            || att1.miner_uid != att2.miner_uid
            || att1.timestamp != att2.timestamp
        {
            let bytes1 = att1.to_signing_bytes();
            let bytes2 = att2.to_signing_bytes();

            prop_assert_ne!(
                bytes1,
                bytes2,
                "Different attestations should produce different signing bytes"
            );
        }
    }

    /// Test that wrong public key fails verification.
    #[test]
    fn prop_wrong_pubkey_fails_verification(
        attestation in attestation_strategy(),
        key_seed1 in prop::array::uniform32(any::<u8>()),
        key_seed2 in prop::array::uniform32(any::<u8>()),
    ) {
        prop_assume!(key_seed1 != key_seed2);

        let key1 = create_signing_key(&key_seed1);
        let key2 = create_signing_key(&key_seed2);

        let mut signed = attestation.sign(&key1);

        // Replace pubkey with different key's pubkey
        signed.warden_pubkey = key2.verifying_key().to_bytes().to_vec();

        prop_assert!(
            !signed.verify(),
            "Signature with wrong public key must not verify"
        );
    }
}

/// Test all AuditResult variants produce unique signing bytes.
#[test]
fn test_all_audit_results_unique_bytes() {
    let warden_id = hex::encode([42u8; 32]);
    let base = Attestation {
        shard_hash: "0".repeat(64),
        miner_uid: 1,
        result: AuditResult::Passed,
        challenge_seed: [0; 32],
        block_number: 100,
        timestamp: 1600000000,
        merkle_proof_sig_hash: vec![],
        warden_id: warden_id.clone(),
    };

    let results = [
        AuditResult::Passed,
        AuditResult::Failed,
        AuditResult::Timeout,
        AuditResult::InvalidProof,
    ];

    let mut bytes_set = std::collections::HashSet::new();
    for result in results {
        let mut att = base.clone();
        att.result = result;
        let bytes = att.to_signing_bytes();
        assert!(
            bytes_set.insert(bytes),
            "Each AuditResult must produce unique signing bytes"
        );
    }
}

/// Test merkle_proof_sig_hash empty vs populated produces different bytes.
#[test]
fn test_proof_hash_affects_signing_bytes() {
    let warden_id = hex::encode([42u8; 32]);
    let att1 = Attestation {
        shard_hash: "0".repeat(64),
        miner_uid: 1,
        result: AuditResult::Passed,
        challenge_seed: [0; 32],
        block_number: 100,
        timestamp: 1600000000,
        merkle_proof_sig_hash: vec![],
        warden_id: warden_id.clone(),
    };

    let mut att2 = att1.clone();
    att2.merkle_proof_sig_hash = vec![1; 32];

    let bytes1 = att1.to_signing_bytes();
    let bytes2 = att2.to_signing_bytes();

    assert_ne!(
        bytes1, bytes2,
        "merkle_proof_sig_hash must affect signing bytes"
    );
}

/// Test signature length is always 64 bytes.
#[test]
fn test_signature_length() {
    let key = create_signing_key(&[42; 32]);
    let warden_id = hex::encode(key.verifying_key().to_bytes());
    let attestation = Attestation {
        shard_hash: "a".repeat(64),
        miner_uid: 1,
        result: AuditResult::Passed,
        challenge_seed: [0; 32],
        block_number: 100,
        timestamp: 1600000000,
        merkle_proof_sig_hash: vec![],
        warden_id,
    };

    let signed = attestation.sign(&key);
    assert_eq!(
        signed.signature.len(),
        64,
        "Ed25519 signature must be 64 bytes"
    );
    assert_eq!(
        signed.warden_pubkey.len(),
        32,
        "Ed25519 pubkey must be 32 bytes"
    );
}

/// Test JSON serialization round-trip.
#[test]
fn test_signed_attestation_json_roundtrip() {
    let key = create_signing_key(&[99; 32]);
    let warden_id = hex::encode(key.verifying_key().to_bytes());
    let attestation = Attestation {
        shard_hash: "b".repeat(64),
        miner_uid: 42,
        result: AuditResult::Failed,
        challenge_seed: [1; 32],
        block_number: 12345,
        timestamp: 1700000000,
        merkle_proof_sig_hash: vec![3; 32],
        warden_id,
    };

    let signed = attestation.sign(&key);
    let json = signed.to_json().expect("JSON serialization should succeed");
    let deserialized: SignedAttestation =
        serde_json::from_slice(&json).expect("JSON deserialization should succeed");

    assert_eq!(signed.signature, deserialized.signature);
    assert_eq!(signed.warden_pubkey, deserialized.warden_pubkey);
    assert_eq!(
        signed.attestation.shard_hash,
        deserialized.attestation.shard_hash
    );
    assert!(
        deserialized.verify(),
        "Deserialized attestation should verify"
    );
}

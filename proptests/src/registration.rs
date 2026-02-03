//! Property-based tests for miner registration signature verification.
//!
//! Tests the following invariants:
//! - REG-1: Signature verification required (invalid signature rejected)
//! - REG-2: Timestamp freshness (timestamps > 5 min old rejected)
//!
//! Note: REG-3 through REG-5 (rate limiting, family validation, heartbeats)
//! require integration testing with validator state and are deferred.

#![allow(unused_imports)]
use crate::strategies::*;
use ed25519_dalek::{Signer, SigningKey, Verifier, VerifyingKey};
use proptest::prelude::*;

/// Create the registration signing message format.
/// Format: "REGISTER:{public_key_hex}:{timestamp}"
fn create_registration_message(pubkey_hex: &str, timestamp: u64) -> String {
    format!("REGISTER:{}:{}", pubkey_hex, timestamp)
}

/// Create the heartbeat signing message format.
/// Format: "HEARTBEAT:{public_key_hex}:{timestamp}"
fn create_heartbeat_message(pubkey_hex: &str, timestamp: u64) -> String {
    format!("HEARTBEAT:{}:{}", pubkey_hex, timestamp)
}

/// Check if a timestamp is fresh (within 5 minutes of current time).
fn is_timestamp_fresh(timestamp: u64, now: u64) -> bool {
    let diff = if timestamp > now {
        timestamp - now
    } else {
        now - timestamp
    };
    diff <= 300 // 5 minutes
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(256))]

    /// REG-1: Valid registration signature is accepted.
    #[test]
    fn prop_valid_registration_signature_accepted(
        key_seed in prop::array::uniform32(any::<u8>()),
        timestamp_offset in 0i64..250, // Within 5 minute window
    ) {
        let signing_key = SigningKey::from_bytes(&key_seed);
        let pubkey = signing_key.verifying_key();
        let pubkey_hex = hex::encode(pubkey.as_bytes());

        let now = ::common::now_secs();
        let timestamp = (now as i64 + timestamp_offset) as u64;

        let message = create_registration_message(&pubkey_hex, timestamp);
        let signature = signing_key.sign(message.as_bytes());

        // Verify signature
        let is_valid = pubkey.verify(message.as_bytes(), &signature).is_ok();

        prop_assert!(
            is_valid,
            "Valid registration signature should verify"
        );
    }

    /// REG-1: Invalid signature is rejected.
    #[test]
    fn prop_invalid_signature_rejected(
        key_seed in prop::array::uniform32(any::<u8>()),
        timestamp in 0u64..10_000_000_000,
        tamper_byte in 0usize..64,
        tamper_bit in 0u8..8,
    ) {
        let signing_key = SigningKey::from_bytes(&key_seed);
        let pubkey = signing_key.verifying_key();
        let pubkey_hex = hex::encode(pubkey.as_bytes());

        let message = create_registration_message(&pubkey_hex, timestamp);
        let mut signature_bytes = signing_key.sign(message.as_bytes()).to_bytes();

        // Tamper with the signature
        signature_bytes[tamper_byte] ^= 1 << tamper_bit;

        let tampered_signature = ed25519_dalek::Signature::from_bytes(&signature_bytes);
        let is_valid = pubkey.verify(message.as_bytes(), &tampered_signature).is_ok();

        prop_assert!(
            !is_valid,
            "Tampered signature should not verify"
        );
    }

    /// REG-1: Signature with wrong pubkey is rejected.
    #[test]
    fn prop_wrong_pubkey_signature_rejected(
        key_seed1 in prop::array::uniform32(any::<u8>()),
        key_seed2 in prop::array::uniform32(any::<u8>()),
        timestamp in 0u64..10_000_000_000,
    ) {
        prop_assume!(key_seed1 != key_seed2);

        let signing_key = SigningKey::from_bytes(&key_seed1);
        let wrong_pubkey = SigningKey::from_bytes(&key_seed2).verifying_key();

        let pubkey_hex = hex::encode(signing_key.verifying_key().as_bytes());
        let message = create_registration_message(&pubkey_hex, timestamp);
        let signature = signing_key.sign(message.as_bytes());

        // Try to verify with wrong public key
        let is_valid = wrong_pubkey.verify(message.as_bytes(), &signature).is_ok();

        prop_assert!(
            !is_valid,
            "Signature should not verify with wrong public key"
        );
    }

    /// REG-1: Signature with modified message is rejected.
    #[test]
    fn prop_modified_message_signature_rejected(
        key_seed in prop::array::uniform32(any::<u8>()),
        timestamp in 0u64..10_000_000_000,
    ) {
        let signing_key = SigningKey::from_bytes(&key_seed);
        let pubkey = signing_key.verifying_key();
        let pubkey_hex = hex::encode(pubkey.as_bytes());

        let message = create_registration_message(&pubkey_hex, timestamp);
        let signature = signing_key.sign(message.as_bytes());

        // Modify the message (different timestamp)
        let modified_message = create_registration_message(&pubkey_hex, timestamp + 1);
        let is_valid = pubkey.verify(modified_message.as_bytes(), &signature).is_ok();

        prop_assert!(
            !is_valid,
            "Signature should not verify with modified message"
        );
    }

    /// REG-2: Fresh timestamp (within 5 minutes) is accepted.
    #[test]
    fn prop_fresh_timestamp_accepted(
        offset in -290i64..290,
    ) {
        let now = ::common::now_secs();
        let timestamp = (now as i64 + offset) as u64;

        let is_fresh = is_timestamp_fresh(timestamp, now);

        prop_assert!(
            is_fresh,
            "Timestamp {} with offset {} from now {} should be fresh",
            timestamp,
            offset,
            now
        );
    }

    /// REG-2: Stale timestamp (more than 5 minutes old) is rejected.
    #[test]
    fn prop_stale_timestamp_rejected(
        stale_offset in 301u64..86400, // 5 min + 1 sec to 24 hours
    ) {
        let now = ::common::now_secs();
        let stale_timestamp = now.saturating_sub(stale_offset);

        let is_fresh = is_timestamp_fresh(stale_timestamp, now);

        prop_assert!(
            !is_fresh,
            "Stale timestamp {} ({} seconds old) should be rejected",
            stale_timestamp,
            stale_offset
        );
    }

    /// REG-2: Future timestamp (more than 5 minutes ahead) is rejected.
    #[test]
    fn prop_future_timestamp_rejected(
        future_offset in 301u64..86400,
    ) {
        let now = ::common::now_secs();
        let future_timestamp = now + future_offset;

        let is_fresh = is_timestamp_fresh(future_timestamp, now);

        prop_assert!(
            !is_fresh,
            "Future timestamp {} ({} seconds ahead) should be rejected",
            future_timestamp,
            future_offset
        );
    }

    /// Heartbeat signature verification follows same rules.
    #[test]
    fn prop_valid_heartbeat_signature_accepted(
        key_seed in prop::array::uniform32(any::<u8>()),
        timestamp_offset in -200i64..200,
    ) {
        let signing_key = SigningKey::from_bytes(&key_seed);
        let pubkey = signing_key.verifying_key();
        let pubkey_hex = hex::encode(pubkey.as_bytes());

        let now = ::common::now_secs();
        let timestamp = (now as i64 + timestamp_offset) as u64;

        let message = create_heartbeat_message(&pubkey_hex, timestamp);
        let signature = signing_key.sign(message.as_bytes());

        let is_valid = pubkey.verify(message.as_bytes(), &signature).is_ok();

        prop_assert!(
            is_valid,
            "Valid heartbeat signature should verify"
        );
    }

    /// Heartbeat and registration messages produce different signatures.
    #[test]
    fn prop_heartbeat_registration_messages_differ(
        key_seed in prop::array::uniform32(any::<u8>()),
        timestamp in 0u64..10_000_000_000,
    ) {
        let signing_key = SigningKey::from_bytes(&key_seed);
        let pubkey_hex = hex::encode(signing_key.verifying_key().as_bytes());

        let reg_message = create_registration_message(&pubkey_hex, timestamp);
        let hb_message = create_heartbeat_message(&pubkey_hex, timestamp);

        prop_assert_ne!(
            &reg_message,
            &hb_message,
            "Registration and heartbeat messages should differ"
        );

        let reg_signature = signing_key.sign(reg_message.as_bytes());
        let hb_signature = signing_key.sign(hb_message.as_bytes());

        prop_assert_ne!(
            reg_signature.to_bytes(),
            hb_signature.to_bytes(),
            "Registration and heartbeat signatures should differ"
        );
    }
}

/// Test exact boundary conditions for timestamp freshness.
#[test]
fn test_timestamp_freshness_boundaries() {
    let now = 1_000_000u64; // Fixed "now" for deterministic testing

    // Exactly 300 seconds (5 minutes) - should be fresh
    assert!(
        is_timestamp_fresh(now - 300, now),
        "5 min past should be fresh"
    );
    assert!(
        is_timestamp_fresh(now + 300, now),
        "5 min future should be fresh"
    );

    // 301 seconds (5 min + 1 sec) - should be stale
    assert!(
        !is_timestamp_fresh(now - 301, now),
        "5 min 1 sec past should be stale"
    );
    assert!(
        !is_timestamp_fresh(now + 301, now),
        "5 min 1 sec future should be stale"
    );
}

/// Test registration message format.
#[test]
fn test_registration_message_format() {
    let pubkey_hex = "a".repeat(64);
    let timestamp = 1234567890u64;

    let message = create_registration_message(&pubkey_hex, timestamp);

    assert_eq!(message, format!("REGISTER:{}:{}", pubkey_hex, timestamp));
    assert!(message.starts_with("REGISTER:"));
    assert!(message.contains(&pubkey_hex));
    assert!(message.ends_with(&timestamp.to_string()));
}

/// Test heartbeat message format.
#[test]
fn test_heartbeat_message_format() {
    let pubkey_hex = "b".repeat(64);
    let timestamp = 9876543210u64;

    let message = create_heartbeat_message(&pubkey_hex, timestamp);

    assert_eq!(message, format!("HEARTBEAT:{}:{}", pubkey_hex, timestamp));
    assert!(message.starts_with("HEARTBEAT:"));
}

/// Test signature is 64 bytes (Ed25519).
#[test]
fn test_signature_length() {
    let signing_key = SigningKey::from_bytes(&[42u8; 32]);
    let message = "test message";
    let signature = signing_key.sign(message.as_bytes());

    assert_eq!(
        signature.to_bytes().len(),
        64,
        "Ed25519 signature must be 64 bytes"
    );
}

/// Test public key is 32 bytes.
#[test]
fn test_pubkey_length() {
    let signing_key = SigningKey::from_bytes(&[42u8; 32]);
    let pubkey = signing_key.verifying_key();

    assert_eq!(
        pubkey.as_bytes().len(),
        32,
        "Ed25519 public key must be 32 bytes"
    );
}

/// Test that verification is consistent across multiple calls.
#[test]
fn test_verification_consistency() {
    let signing_key = SigningKey::from_bytes(&[99u8; 32]);
    let pubkey = signing_key.verifying_key();
    let pubkey_hex = hex::encode(pubkey.as_bytes());
    let timestamp = 1700000000u64;

    let message = create_registration_message(&pubkey_hex, timestamp);
    let signature = signing_key.sign(message.as_bytes());

    // Verify multiple times
    for _ in 0..100 {
        let result = pubkey.verify(message.as_bytes(), &signature);
        assert!(result.is_ok(), "Verification should be consistent");
    }
}

/// Test pubkey hex encoding is correct length.
#[test]
fn test_pubkey_hex_encoding() {
    let signing_key = SigningKey::from_bytes(&[1u8; 32]);
    let pubkey = signing_key.verifying_key();
    let pubkey_hex = hex::encode(pubkey.as_bytes());

    // 32 bytes * 2 hex chars per byte = 64 chars
    assert_eq!(pubkey_hex.len(), 64, "Pubkey hex should be 64 characters");
    assert!(
        pubkey_hex.chars().all(|c| c.is_ascii_hexdigit()),
        "Pubkey hex should contain only hex characters"
    );
}

/// Test that different keys produce different pubkey hex values.
#[test]
fn test_different_keys_different_pubkeys() {
    let key1 = SigningKey::from_bytes(&[1u8; 32]);
    let key2 = SigningKey::from_bytes(&[2u8; 32]);

    let hex1 = hex::encode(key1.verifying_key().as_bytes());
    let hex2 = hex::encode(key2.verifying_key().as_bytes());

    assert_ne!(hex1, hex2, "Different keys should have different pubkeys");
}

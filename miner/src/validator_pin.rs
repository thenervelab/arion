//! Pin of the validator's identity on the control connections the miner
//! opens to it (registration, heartbeat).
//!
//! `common::transport::connect_with_alpn` accepts any self-signed Ed25519
//! certificate: its `expected_node_id` argument is not enforced by the TLS
//! verifier. The heartbeat reply provisions the storage-proof requester
//! set and the warden ids the miner will then honour, so a connection
//! whose far end is not the configured validator must never be spoken
//! on. This module is that check: the peer's node id (its certificate's
//! Ed25519 public key, `common::transport::remote_node_id`) is compared to
//! the configured `VALIDATOR_NODE_ID` right after the handshake and before
//! the first byte is written; on a mismatch the connection is closed,
//! counted and refused, and the caller's previous state (requester set,
//! warden ids, epoch) is left as it was.

use std::sync::atomic::{AtomicU64, Ordering};

/// Connections refused because the far end was not the configured
/// validator. Rendered as `miner_validator_identity_mismatch_total`.
pub static VALIDATOR_IDENTITY_MISMATCHES: AtomicU64 = AtomicU64::new(0);

/// Why a control connection was refused.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IdentityMismatch {
    /// The configured validator node id.
    pub expected: String,
    /// The node id the peer's certificate carried, `None` when it carried
    /// no usable Ed25519 certificate at all.
    pub got: Option<String>,
}

impl std::fmt::Display for IdentityMismatch {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match &self.got {
            Some(got) => write!(
                f,
                "validator identity mismatch: expected {}, peer presented {got}",
                self.expected
            ),
            None => write!(
                f,
                "validator identity mismatch: expected {}, peer presented no Ed25519 certificate",
                self.expected
            ),
        }
    }
}

impl std::error::Error for IdentityMismatch {}

/// Pure comparison: the identity the peer presented against the one
/// configured. Case-insensitive on the hex, whitespace-trimmed on the
/// configured side (it comes from the environment).
pub fn identity_matches(presented: Option<&str>, expected: &str) -> bool {
    let expected = expected.trim();
    !expected.is_empty()
        && presented
            .is_some_and(|got| got.len() == expected.len() && got.eq_ignore_ascii_case(expected))
}

/// Check `conn` against `expected`. On a mismatch the connection is closed
/// with an application code and the counter is bumped; the error names
/// both identities. On a match the connection is handed back untouched.
pub fn pin(conn: quinn::Connection, expected: &str) -> Result<quinn::Connection, IdentityMismatch> {
    let got = common::transport::remote_node_id(&conn);
    if identity_matches(got.as_deref(), expected) {
        return Ok(conn);
    }
    VALIDATOR_IDENTITY_MISMATCHES.fetch_add(1, Ordering::Relaxed);
    conn.close(1u32.into(), b"validator identity mismatch");
    Err(IdentityMismatch {
        expected: expected.trim().to_string(),
        got,
    })
}

/// Prometheus text for the counter.
pub fn render_prometheus() -> String {
    format!(
        "# TYPE miner_validator_identity_mismatch_total counter\n\
         miner_validator_identity_mismatch_total {}\n",
        VALIDATOR_IDENTITY_MISMATCHES.load(Ordering::Relaxed)
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use common::transport::{connect_with_alpn, create_endpoint, node_id_from_public_key};
    use ed25519_dalek::SigningKey;

    #[test]
    fn identity_comparison_is_exact_up_to_hex_case() {
        assert!(identity_matches(Some("ab12"), "ab12"));
        assert!(identity_matches(Some("AB12"), " ab12 "));
        assert!(!identity_matches(Some("ab13"), "ab12"));
        assert!(!identity_matches(Some("ab1"), "ab12"));
        assert!(!identity_matches(None, "ab12"));
        assert!(
            !identity_matches(Some(""), ""),
            "an empty pin matches nothing"
        );
        assert!(!identity_matches(Some("ab12"), ""));
    }

    /// Two endpoints in-process. The client connects with the WRONG
    /// expected node id and the QUIC handshake still succeeds: that is
    /// the transport gap. The pin is what refuses it, closes the
    /// connection and counts it; the right id passes.
    #[tokio::test]
    async fn wrong_validator_identity_is_refused_after_a_successful_handshake() {
        let server_key = SigningKey::from_bytes(&[31u8; 32]);
        let client_key = SigningKey::from_bytes(&[32u8; 32]);
        let impostor_key = SigningKey::from_bytes(&[33u8; 32]);
        let server_id = node_id_from_public_key(&server_key.verifying_key());
        let impostor_id = node_id_from_public_key(&impostor_key.verifying_key());

        let server = create_endpoint("127.0.0.1:0".parse().unwrap(), &server_key, None)
            .await
            .unwrap();
        let addr = server.local_addr().unwrap();
        let client = create_endpoint("127.0.0.1:0".parse().unwrap(), &client_key, None)
            .await
            .unwrap();
        let accept = tokio::spawn(async move {
            let mut kept = Vec::new();
            for _ in 0..2 {
                let incoming = server.accept().await.unwrap();
                kept.push(incoming.await.unwrap());
            }
            kept
        });

        let before = VALIDATOR_IDENTITY_MISMATCHES.load(Ordering::Relaxed);

        // Expecting the impostor's id, reaching the real server: the
        // transport hands back a live connection anyway.
        let conn = connect_with_alpn(
            &client,
            addr,
            &impostor_id,
            &client_key,
            &[common::VALIDATOR_CONTROL_ALPN],
        )
        .await
        .expect("the transport does not pin: handshake succeeds");
        assert!(conn.close_reason().is_none());
        let err = pin(conn.clone(), &impostor_id).expect_err("pin must refuse");
        assert_eq!(err.expected, impostor_id);
        assert_eq!(err.got.as_deref(), Some(server_id.as_str()));
        assert!(err.to_string().contains("validator identity mismatch"));
        assert!(
            conn.close_reason().is_some(),
            "the refused connection is closed before any byte is written"
        );
        assert_eq!(
            VALIDATOR_IDENTITY_MISMATCHES.load(Ordering::Relaxed),
            before + 1
        );

        // The configured validator id passes and the connection is usable.
        let conn = connect_with_alpn(
            &client,
            addr,
            &server_id,
            &client_key,
            &[common::VALIDATOR_CONTROL_ALPN],
        )
        .await
        .unwrap();
        let conn = pin(conn, &server_id.to_ascii_uppercase()).expect("right id passes");
        assert!(conn.close_reason().is_none());
        assert_eq!(
            VALIDATOR_IDENTITY_MISMATCHES.load(Ordering::Relaxed),
            before + 1
        );
        assert!(render_prometheus().contains("miner_validator_identity_mismatch_total"));

        let _kept = accept.await.unwrap();
        client.close(0u32.into(), b"done");
    }
}

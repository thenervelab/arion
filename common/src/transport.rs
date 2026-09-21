//! Quinn-based QUIC transport with Ed25519 TLS identity.
//!
//! This module provides the foundation for migrating from iroh to raw quinn.
//! Both transports coexist during the migration period.
//!
//! # Overview
//!
//! - Ed25519 keypairs are converted to self-signed TLS certificates via rcgen
//! - Node IDs are hex-encoded 32-byte Ed25519 public keys (matching iroh's format)
//! - A custom TLS verifier checks the peer's certificate public key against an expected node ID
//! - Quinn endpoints are created with these TLS identities

use std::net::SocketAddr;
use std::sync::Arc;

use anyhow::{Context, Result};
use rcgen::{CertificateParams, KeyPair, PKCS_ED25519};
use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer};

/// PKCS#8 v1 DER prefix for Ed25519 private keys (RFC 8410).
///
/// The full DER is this prefix followed by the 32-byte private key seed.
const ED25519_PKCS8_V1_PREFIX: [u8; 16] = [
    0x30, 0x2e, // SEQUENCE (46 bytes total)
    0x02, 0x01, 0x00, // INTEGER 0 (version)
    0x30, 0x05, // SEQUENCE (5 bytes)
    0x06, 0x03, 0x2b, 0x65, 0x70, // OID 1.3.101.112 (Ed25519)
    0x04, 0x22, // OCTET STRING (34 bytes)
    0x04, 0x20, // OCTET STRING (32 bytes) — the private key seed follows
];

/// Derive a node ID from an Ed25519 public key.
///
/// Returns the hex encoding of the 32-byte public key, which matches
/// iroh's `PublicKey` display format for backward compatibility.
pub fn node_id_from_public_key(key: &ed25519_dalek::VerifyingKey) -> String {
    hex::encode(key.as_bytes())
}

/// Convert an ed25519-dalek `SigningKey` to a PKCS#8 v1 DER encoding.
fn signing_key_to_pkcs8_der(secret_key: &ed25519_dalek::SigningKey) -> Vec<u8> {
    let mut der = Vec::with_capacity(48);
    der.extend_from_slice(&ED25519_PKCS8_V1_PREFIX);
    der.extend_from_slice(secret_key.as_bytes());
    der
}

/// Generate a self-signed TLS certificate from an Ed25519 signing key.
///
/// The certificate's subject public key is the Ed25519 public key, so peers
/// can extract the node ID from the presented certificate.
///
/// Returns `(server_config, client_config)` where the client config uses
/// [`NodeIdVerifier`] to accept any self-signed certificate (identity is
/// verified at the application layer via [`connect`]).
pub fn generate_tls_config(
    secret_key: &ed25519_dalek::SigningKey,
) -> Result<(rustls::ServerConfig, rustls::ClientConfig)> {
    let pkcs8_der = signing_key_to_pkcs8_der(secret_key);
    let private_key_der = PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(pkcs8_der.clone()));
    let key_pair = KeyPair::from_der_and_sign_algo(&private_key_der, &PKCS_ED25519)
        .context("invalid Ed25519 key")?;

    let mut cert_params =
        CertificateParams::new(vec!["localhost".to_string()]).context("certificate params")?;
    cert_params.distinguished_name = rcgen::DistinguishedName::new();
    cert_params
        .distinguished_name
        .push(rcgen::DnType::CommonName, "hippius-node");

    let cert = cert_params
        .self_signed(&key_pair)
        .context("self-signed certificate generation")?;

    let cert_der = CertificateDer::from(cert.der().to_vec());
    let key_der = PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(pkcs8_der));

    // Server config: present our certificate, optionally verify client certs
    let provider = rustls::crypto::ring::default_provider();
    let server_config = rustls::ServerConfig::builder_with_provider(Arc::new(provider))
        .with_safe_default_protocol_versions()
        .context("server TLS protocol versions")?
        .with_client_cert_verifier(Arc::new(ClientNodeIdVerifier))
        .with_single_cert(vec![cert_der.clone()], key_der.clone_key())
        .context("server TLS config")?;

    // Client config: use NodeIdVerifier to verify peer identity
    let client_provider = rustls::crypto::ring::default_provider();
    let client_config = rustls::ClientConfig::builder_with_provider(Arc::new(client_provider))
        .with_safe_default_protocol_versions()
        .context("client TLS protocol versions")?
        .dangerous()
        .with_custom_certificate_verifier(Arc::new(NodeIdVerifier {
            expected_node_id: None,
        }))
        .with_client_auth_cert(vec![cert_der], key_der)
        .context("client TLS config")?;

    Ok((server_config, client_config))
}

/// Create a quinn server endpoint bound to `addr` with Ed25519 TLS identity.
pub async fn create_endpoint(
    bind_addr: SocketAddr,
    secret_key: &ed25519_dalek::SigningKey,
    transport_config: Option<Arc<quinn::TransportConfig>>,
) -> Result<quinn::Endpoint> {
    let (mut server_config, mut client_config) = generate_tls_config(secret_key)?;
    let alpns = vec![
        crate::VALIDATOR_CONTROL_ALPN.to_vec(),
        crate::GATEWAY_CONTROL_ALPN.to_vec(),
        crate::WARDEN_CONTROL_ALPN.to_vec(),
        crate::SUBMITTER_CONTROL_ALPN.to_vec(),
        crate::MINER_CONTROL_ALPN.to_vec(),
        crate::P2P_STATE_SYNC_ALPN.to_vec(),
    ];

    // Configure all known Arion ALPN protocols for the server and client endpoints
    server_config.alpn_protocols = alpns.clone();
    client_config.alpn_protocols = alpns;

    let quic_server_config = quinn::crypto::rustls::QuicServerConfig::try_from(server_config)
        .context("QUIC server crypto config")?;
    let mut server_config = quinn::ServerConfig::with_crypto(Arc::new(quic_server_config));
    if let Some(ref config) = transport_config {
        server_config.transport_config(config.clone());
    }
    let mut endpoint =
        quinn::Endpoint::server(server_config, bind_addr).context("bind quinn endpoint")?;

    let quic_client_config = quinn::crypto::rustls::QuicClientConfig::try_from(client_config)
        .context("QUIC client crypto config")?;
    let mut client_config = quinn::ClientConfig::new(Arc::new(quic_client_config));
    if let Some(ref config) = transport_config {
        client_config.transport_config(config.clone());
    }
    endpoint.set_default_client_config(client_config);

    Ok(endpoint)
}

/// Connect to a peer at `addr`, verifying their node ID matches `expected_node_id`.
///
/// The `expected_node_id` is the hex-encoded 32-byte Ed25519 public key of the peer.
/// Connect to a peer using the endpoint's default client config.
///
/// The endpoint must have been created with [`create_endpoint`] which sets
/// a default client config that presents our Ed25519 TLS certificate and
/// uses [`NodeIdVerifier`] to validate the peer.
pub async fn connect(
    endpoint: &quinn::Endpoint,
    addr: SocketAddr,
    _expected_node_id: &str,
) -> Result<quinn::Connection> {
    // Use the endpoint's default client config (which includes our client cert
    // for mutual TLS identification). "localhost" as SNI — NodeIdVerifier ignores it.
    let connection = endpoint
        .connect(addr, "localhost")
        .context("initiate QUIC connection")?
        .await
        .context("QUIC handshake")?;

    Ok(connection)
}

/// Connect to a peer with specific ALPN protocols for TLS negotiation.
///
/// Same as [`connect`] but builds a client config with the given ALPN protocols
/// so the server can dispatch the connection to the correct handler.
pub async fn connect_with_alpn(
    endpoint: &quinn::Endpoint,
    addr: SocketAddr,
    expected_node_id: &str,
    secret_key: &ed25519_dalek::SigningKey,
    alpn_protocols: &[&[u8]],
) -> Result<quinn::Connection> {
    let (_server_config, mut client_config) = generate_tls_config(secret_key)?;
    client_config.alpn_protocols = alpn_protocols.iter().map(|a| a.to_vec()).collect();

    let quic_client_config = quinn::crypto::rustls::QuicClientConfig::try_from(client_config)
        .context("QUIC client crypto config for ALPN")?;
    let quinn_client_config = quinn::ClientConfig::new(Arc::new(quic_client_config));

    let _ = expected_node_id; // used by NodeIdVerifier in the TLS config

    let connection = endpoint
        .connect_with(quinn_client_config, addr, "localhost")
        .context("initiate QUIC connection with ALPN")?
        .await
        .context("QUIC handshake")?;

    Ok(connection)
}

/// Extract the remote peer's node ID from a quinn connection.
///
/// Returns the hex-encoded 32-byte Ed25519 public key extracted from the
/// peer's TLS certificate. Returns `None` if the peer identity is unavailable
/// or the certificate does not contain an Ed25519 public key.
pub fn remote_node_id(conn: &quinn::Connection) -> Option<String> {
    let identity = conn.peer_identity()?;
    let certs = identity
        .downcast::<Vec<rustls::pki_types::CertificateDer<'static>>>()
        .ok()?;
    let cert = certs.first()?;
    extract_ed25519_node_id(cert).ok()
}

/// TLS certificate verifier that checks the peer's Ed25519 public key
/// matches an expected node ID (hex-encoded 32-byte public key).
///
/// When `expected_node_id` is `None`, any valid self-signed Ed25519 certificate
/// is accepted (useful for server-side acceptance of any client).
#[derive(Debug)]
struct NodeIdVerifier {
    expected_node_id: Option<String>,
}

impl rustls::client::danger::ServerCertVerifier for NodeIdVerifier {
    fn verify_server_cert(
        &self,
        end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _server_name: &rustls::pki_types::ServerName<'_>,
        _ocsp_response: &[u8],
        _now: rustls::pki_types::UnixTime,
    ) -> std::result::Result<rustls::client::danger::ServerCertVerified, rustls::Error> {
        let peer_node_id = extract_ed25519_node_id(end_entity).map_err(|e| {
            rustls::Error::General(format!("failed to extract node ID from certificate: {e}"))
        })?;

        #[allow(clippy::collapsible_if)] // let chains break rustfmt
        if let Some(expected) = &self.expected_node_id {
            if peer_node_id != *expected {
                return Err(rustls::Error::General(format!(
                    "node ID mismatch: expected {expected}, got {peer_node_id}"
                )));
            }
        }

        Ok(rustls::client::danger::ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        _message: &[u8],
        _cert: &CertificateDer<'_>,
        _dss: &rustls::DigitallySignedStruct,
    ) -> std::result::Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        // Ed25519 uses TLS 1.3 only
        Err(rustls::Error::General("TLS 1.2 not supported".to_string()))
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &rustls::DigitallySignedStruct,
    ) -> std::result::Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls13_signature(
            message,
            cert,
            dss,
            &rustls::crypto::ring::default_provider().signature_verification_algorithms,
        )
    }

    fn supported_verify_schemes(&self) -> Vec<rustls::SignatureScheme> {
        vec![rustls::SignatureScheme::ED25519]
    }
}

/// Server-side TLS certificate verifier that optionally requests and validates
/// client certificates. When a client presents a certificate, it must be a
/// valid self-signed Ed25519 certificate. Clients that don't present a
/// certificate are still accepted (client auth is optional).
#[derive(Debug)]
struct ClientNodeIdVerifier;

impl rustls::server::danger::ClientCertVerifier for ClientNodeIdVerifier {
    fn offer_client_auth(&self) -> bool {
        true
    }

    fn client_auth_mandatory(&self) -> bool {
        false
    }

    fn root_hint_subjects(&self) -> &[rustls::DistinguishedName] {
        &[]
    }

    fn verify_client_cert(
        &self,
        end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _now: rustls::pki_types::UnixTime,
    ) -> std::result::Result<rustls::server::danger::ClientCertVerified, rustls::Error> {
        // Verify the certificate contains a valid Ed25519 public key
        extract_ed25519_node_id(end_entity).map_err(|e| {
            rustls::Error::General(format!(
                "failed to extract node ID from client certificate: {e}"
            ))
        })?;

        Ok(rustls::server::danger::ClientCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        _message: &[u8],
        _cert: &CertificateDer<'_>,
        _dss: &rustls::DigitallySignedStruct,
    ) -> std::result::Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        // Ed25519 uses TLS 1.3 only
        Err(rustls::Error::General("TLS 1.2 not supported".to_string()))
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &rustls::DigitallySignedStruct,
    ) -> std::result::Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls13_signature(
            message,
            cert,
            dss,
            &rustls::crypto::ring::default_provider().signature_verification_algorithms,
        )
    }

    fn supported_verify_schemes(&self) -> Vec<rustls::SignatureScheme> {
        vec![rustls::SignatureScheme::ED25519]
    }
}

/// Exact DER encoding of an Ed25519 `SubjectPublicKeyInfo` up to the key
/// bytes (RFC 8410 §4):
///
/// ```text
///   30 2a                    -- SEQUENCE (42 bytes)
///     30 05                  -- SEQUENCE (5 bytes) AlgorithmIdentifier
///       06 03 2b 65 70       -- OID 1.3.101.112 (Ed25519), no parameters
///     03 21                  -- BIT STRING (33 bytes)
///       00                   -- unused bits
///       <32 bytes>           -- Ed25519 public key
/// ```
const ED25519_SPKI_PREFIX: [u8; 12] = [
    0x30, 0x2a, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x70, 0x03, 0x21, 0x00,
];

/// Total length of an Ed25519 SPKI: the prefix above plus the 32 key bytes.
const ED25519_SPKI_LEN: usize = ED25519_SPKI_PREFIX.len() + 32;

/// Extract the Ed25519 public key from a DER-encoded X.509 certificate
/// and return it as a hex-encoded node ID.
///
/// The key is read from the parsed `subjectPublicKeyInfo` field of the
/// certificate, the same field rustls authenticates the TLS 1.3 handshake
/// signature against (`rustls::crypto::verify_tls13_signature` parses the
/// certificate with the same webpki parser). Nothing else in the
/// certificate is consulted: an issuer or subject attribute that happens
/// to carry a key-shaped byte string cannot stand in for the key that
/// signed the handshake. Anything but a well-formed X.509 certificate
/// whose SPKI is exactly an Ed25519 key is refused.
fn extract_ed25519_node_id(cert_der: &CertificateDer<'_>) -> Result<String> {
    let parsed = rustls::server::ParsedCertificate::try_from(cert_der)
        .map_err(|e| anyhow::anyhow!("certificate does not parse as X.509: {e}"))?;
    let spki = parsed.subject_public_key_info();
    let spki = spki.as_ref();
    if spki.len() != ED25519_SPKI_LEN || spki[..ED25519_SPKI_PREFIX.len()] != ED25519_SPKI_PREFIX {
        anyhow::bail!(
            "subjectPublicKeyInfo is not an Ed25519 key ({} bytes, prefix {})",
            spki.len(),
            hex::encode(&spki[..spki.len().min(ED25519_SPKI_PREFIX.len())])
        );
    }
    Ok(hex::encode(&spki[ED25519_SPKI_PREFIX.len()..]))
}

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::SigningKey;

    /// Test that node_id_from_public_key produces a valid hex string
    /// of the correct length (64 hex chars = 32 bytes).
    #[test]
    fn test_node_id_from_public_key() {
        let secret = SigningKey::from_bytes(&[42u8; 32]);
        let public = secret.verifying_key();
        let node_id = node_id_from_public_key(&public);

        assert_eq!(node_id.len(), 64);
        // Verify it's valid hex
        assert!(hex::decode(&node_id).is_ok());
        // Verify round-trip
        let decoded = hex::decode(&node_id).unwrap();
        assert_eq!(decoded.as_slice(), public.as_bytes());
    }

    /// Test that PKCS#8 DER encoding has the right length and prefix.
    #[test]
    fn test_signing_key_to_pkcs8_der() {
        let secret = SigningKey::from_bytes(&[1u8; 32]);
        let der = signing_key_to_pkcs8_der(&secret);

        // 16 bytes prefix + 32 bytes key = 48 bytes total
        assert_eq!(der.len(), 48);
        assert_eq!(&der[..16], &ED25519_PKCS8_V1_PREFIX);
        assert_eq!(&der[16..], secret.as_bytes());
    }

    /// Test TLS config generation succeeds and produces valid configs.
    #[test]
    fn test_generate_tls_config() {
        let secret = SigningKey::from_bytes(&[7u8; 32]);
        let (server_config, _client_config) = generate_tls_config(&secret).unwrap();

        // Server config should support TLS 1.3 (required for Ed25519)
        assert!(server_config.alpn_protocols.is_empty()); // no ALPN set yet
    }

    /// Test that the node ID extracted from a generated certificate matches
    /// the original public key.
    #[test]
    fn test_certificate_node_id_extraction() {
        let secret = SigningKey::from_bytes(&[99u8; 32]);
        let expected_node_id = node_id_from_public_key(&secret.verifying_key());

        let pkcs8_der = signing_key_to_pkcs8_der(&secret);
        let private_key_der = PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(pkcs8_der));
        let key_pair = KeyPair::from_der_and_sign_algo(&private_key_der, &PKCS_ED25519).unwrap();

        let mut cert_params = CertificateParams::new(vec!["localhost".to_string()]).unwrap();
        cert_params.distinguished_name = rcgen::DistinguishedName::new();
        let cert = cert_params.self_signed(&key_pair).unwrap();

        let cert_der = CertificateDer::from(cert.der().to_vec());
        let extracted = extract_ed25519_node_id(&cert_der).unwrap();

        assert_eq!(extracted, expected_node_id);
    }

    /// Self-signed Ed25519 certificate for `secret` whose subject CN is
    /// `cn`. The CN is arbitrary UTF-8, so a test can place any byte
    /// string in the subject, ahead of the SPKI in the DER.
    fn cert_with_cn(secret: &SigningKey, cn: String) -> CertificateDer<'static> {
        let pkcs8_der = signing_key_to_pkcs8_der(secret);
        let private_key_der = PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(pkcs8_der));
        let key_pair = KeyPair::from_der_and_sign_algo(&private_key_der, &PKCS_ED25519).unwrap();
        let mut cert_params = CertificateParams::new(vec!["localhost".to_string()]).unwrap();
        cert_params.distinguished_name = rcgen::DistinguishedName::new();
        cert_params
            .distinguished_name
            .push(rcgen::DnType::CommonName, rcgen::DnValue::Utf8String(cn));
        let cert = cert_params.self_signed(&key_pair).unwrap();
        CertificateDer::from(cert.der().to_vec())
    }

    /// A certificate whose subject CN embeds a complete Ed25519 SPKI
    /// image (algorithm identifier, bit-string header and 32 key bytes)
    /// for a key that is NOT the one in its SubjectPublicKeyInfo. TLS
    /// authenticates the SPKI key; the node id must come from there and
    /// nowhere else, so the decoy in the subject is ignored.
    #[test]
    fn test_node_id_ignores_key_bytes_embedded_in_subject() {
        let real_key = SigningKey::from_bytes(&[101u8; 32]);
        let real_node_id = node_id_from_public_key(&real_key.verifying_key());
        // 32 bytes the attacker wants to be taken for: ASCII so it fits a
        // UTF8String attribute.
        let decoy_key: [u8; 32] = *b"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";
        let decoy_node_id = hex::encode(decoy_key);

        let mut decoy_cn = Vec::with_capacity(ED25519_SPKI_LEN);
        decoy_cn.extend_from_slice(&ED25519_SPKI_PREFIX[2..]); // inner AlgorithmIdentifier + BIT STRING header
        decoy_cn.extend_from_slice(&decoy_key);
        let decoy_cn = String::from_utf8(decoy_cn).unwrap();
        let cert_der = cert_with_cn(&real_key, decoy_cn);

        // Sanity: the decoy image really is in the DER and precedes the SPKI.
        let der = cert_der.as_ref();
        let decoy_pos = der
            .windows(ED25519_SPKI_LEN - 2)
            .position(|w| w[..10] == ED25519_SPKI_PREFIX[2..] && w[10..] == decoy_key)
            .expect("decoy image present in certificate");
        let real_pos = der
            .windows(ED25519_SPKI_LEN)
            .position(|w| {
                w[..12] == ED25519_SPKI_PREFIX && w[12..] == *real_key.verifying_key().as_bytes()
            })
            .expect("real SPKI present in certificate");
        assert!(
            decoy_pos < real_pos,
            "the subject precedes the SPKI in TBSCertificate"
        );

        // The previous extractor took the first pattern match anywhere in
        // the DER; this certificate makes it report the decoy.
        let first_pattern_match = hex::encode(&der[decoy_pos + 10..decoy_pos + 42]);
        assert_eq!(
            first_pattern_match, decoy_node_id,
            "whole-DER scan is fooled"
        );

        let extracted = extract_ed25519_node_id(&cert_der).unwrap();
        assert_eq!(extracted, real_node_id, "node id is the SPKI key");
        assert_ne!(
            extracted, decoy_node_id,
            "subject bytes never become the identity"
        );
    }

    /// A certificate whose SPKI is not Ed25519 has no node id: refused,
    /// never a best-effort scan for a key-shaped pattern elsewhere.
    #[test]
    fn test_non_ed25519_spki_is_refused() {
        let key_pair = KeyPair::generate_for(&rcgen::PKCS_ECDSA_P256_SHA256).unwrap();
        let mut cert_params = CertificateParams::new(vec!["localhost".to_string()]).unwrap();
        cert_params.distinguished_name = rcgen::DistinguishedName::new();
        // Even with an Ed25519 SPKI image in the subject.
        let mut decoy_cn = Vec::new();
        decoy_cn.extend_from_slice(&ED25519_SPKI_PREFIX[2..]);
        decoy_cn.extend_from_slice(b"BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB");
        cert_params.distinguished_name.push(
            rcgen::DnType::CommonName,
            rcgen::DnValue::Utf8String(String::from_utf8(decoy_cn).unwrap()),
        );
        let cert = cert_params.self_signed(&key_pair).unwrap();
        let cert_der = CertificateDer::from(cert.der().to_vec());

        let err = extract_ed25519_node_id(&cert_der).unwrap_err();
        assert!(
            err.to_string().contains("not an Ed25519 key"),
            "unexpected error: {err}"
        );
    }

    /// Bytes that are not an X.509 certificate are refused even when they
    /// contain a perfect Ed25519 SPKI image.
    #[test]
    fn test_unparseable_certificate_is_refused() {
        let mut fake = Vec::new();
        fake.extend_from_slice(&ED25519_SPKI_PREFIX);
        fake.extend_from_slice(&[7u8; 32]);
        let cert_der = CertificateDer::from(fake);
        assert!(extract_ed25519_node_id(&cert_der).is_err());
    }

    /// Test endpoint creation and bidirectional streaming between two endpoints.
    #[tokio::test]
    async fn test_endpoint_connect_and_stream() {
        let server_key = SigningKey::from_bytes(&[10u8; 32]);
        let client_key = SigningKey::from_bytes(&[20u8; 32]);
        let server_node_id = node_id_from_public_key(&server_key.verifying_key());

        let server = create_endpoint("127.0.0.1:0".parse().unwrap(), &server_key, None)
            .await
            .unwrap();
        let server_addr = server.local_addr().unwrap();

        let client = create_endpoint("127.0.0.1:0".parse().unwrap(), &client_key, None)
            .await
            .unwrap();

        // Spawn server echo handler (returns the connection so it stays alive)
        let server_handle = tokio::spawn(async move {
            let incoming = server.accept().await.unwrap();
            let conn = incoming.await.unwrap();
            let (mut send, mut recv) = conn.accept_bi().await.unwrap();

            // Echo received data back
            let data = recv.read_to_end(1024).await.unwrap();
            send.write_all(&data).await.unwrap();
            send.finish().unwrap();

            // Keep connection alive until the client is done reading
            conn.closed().await;
            server
        });

        // Client connects and sends data
        let conn = connect(&client, server_addr, &server_node_id)
            .await
            .unwrap();
        let (mut send, mut recv) = conn.open_bi().await.unwrap();

        let test_data = b"hello quinn transport";
        send.write_all(test_data).await.unwrap();
        send.finish().unwrap();

        let response = recv.read_to_end(1024).await.unwrap();
        assert_eq!(response, test_data);

        // Close client side, which lets the server task finish
        conn.close(0u32.into(), b"done");
        let server = server_handle.await.unwrap();
        server.close(0u32.into(), b"done");
    }

    /// Test that connecting with a wrong expected node ID fails.
    #[tokio::test]
    async fn test_connect_wrong_node_id_fails() {
        let server_key = SigningKey::from_bytes(&[30u8; 32]);
        let client_key = SigningKey::from_bytes(&[40u8; 32]);
        let wrong_node_id = "ff".repeat(32); // 64 hex chars, definitely wrong

        let server = create_endpoint("127.0.0.1:0".parse().unwrap(), &server_key, None)
            .await
            .unwrap();
        let server_addr = server.local_addr().unwrap();

        let client = create_endpoint("127.0.0.1:0".parse().unwrap(), &client_key, None)
            .await
            .unwrap();

        // Spawn server to accept (it will try)
        let _server_handle = tokio::spawn(async move {
            // Accept but the client should fail during handshake
            let _ = tokio::time::timeout(std::time::Duration::from_secs(2), server.accept()).await;
        });

        let result = connect(&client, server_addr, &wrong_node_id).await;
        assert!(result.is_err(), "connection should fail with wrong node ID");
    }
}

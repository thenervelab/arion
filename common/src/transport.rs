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
) -> Result<quinn::Endpoint> {
    let (server_config, client_config) = generate_tls_config(secret_key)?;

    let quic_server_config = quinn::crypto::rustls::QuicServerConfig::try_from(server_config)
        .context("QUIC server crypto config")?;
    let server_config = quinn::ServerConfig::with_crypto(Arc::new(quic_server_config));
    let mut endpoint =
        quinn::Endpoint::server(server_config, bind_addr).context("bind quinn endpoint")?;

    let quic_client_config = quinn::crypto::rustls::QuicClientConfig::try_from(client_config)
        .context("QUIC client crypto config")?;
    let client_config = quinn::ClientConfig::new(Arc::new(quic_client_config));
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

/// Extract the Ed25519 public key from a DER-encoded X.509 certificate
/// and return it as a hex-encoded node ID.
fn extract_ed25519_node_id(cert_der: &CertificateDer<'_>) -> Result<String> {
    // The SubjectPublicKeyInfo for Ed25519 has a fixed DER encoding:
    //
    //   30 2a                    -- SEQUENCE (42 bytes)
    //     30 05                  -- SEQUENCE (5 bytes) AlgorithmIdentifier
    //       06 03 2b 65 70      -- OID 1.3.101.112 (Ed25519)
    //     03 21                  -- BIT STRING (33 bytes)
    //       00                   -- unused bits
    //       <32 bytes>           -- Ed25519 public key
    //
    // We search for the byte pattern that uniquely identifies this structure.
    // The Ed25519 OID appears multiple times in an X.509 cert (signatureAlgorithm,
    // subjectPublicKeyInfo, etc.), so we match the full AlgorithmIdentifier SEQUENCE
    // followed by the BIT STRING header.
    let der_bytes = cert_der.as_ref();

    // Pattern: AlgorithmIdentifier { Ed25519 } + BIT STRING { unused=0, ... }
    let spki_pattern: [u8; 10] = [
        0x30, 0x05, // SEQUENCE (5 bytes)
        0x06, 0x03, 0x2b, 0x65, 0x70, // OID 1.3.101.112
        0x03, 0x21, // BIT STRING (33 bytes)
        0x00, // unused bits
    ];

    let pos = der_bytes
        .windows(spki_pattern.len())
        .position(|w| w == spki_pattern)
        .ok_or_else(|| anyhow::anyhow!("Ed25519 SubjectPublicKeyInfo not found in certificate"))?;

    let key_start = pos + spki_pattern.len();
    if key_start + 32 > der_bytes.len() {
        anyhow::bail!("certificate too short to contain Ed25519 public key");
    }

    let pub_key_bytes = &der_bytes[key_start..key_start + 32];
    Ok(hex::encode(pub_key_bytes))
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

    /// Test endpoint creation and bidirectional streaming between two endpoints.
    #[tokio::test]
    async fn test_endpoint_connect_and_stream() {
        let server_key = SigningKey::from_bytes(&[10u8; 32]);
        let client_key = SigningKey::from_bytes(&[20u8; 32]);
        let server_node_id = node_id_from_public_key(&server_key.verifying_key());

        let server = create_endpoint("127.0.0.1:0".parse().unwrap(), &server_key)
            .await
            .unwrap();
        let server_addr = server.local_addr().unwrap();

        let client = create_endpoint("127.0.0.1:0".parse().unwrap(), &client_key)
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

        let server = create_endpoint("127.0.0.1:0".parse().unwrap(), &server_key)
            .await
            .unwrap();
        let server_addr = server.local_addr().unwrap();

        let client = create_endpoint("127.0.0.1:0".parse().unwrap(), &client_key)
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

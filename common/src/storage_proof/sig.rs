//! Strict Ed25519 profile shared by the three protocol messages (spec §1).
//!
//! Pure Ed25519 (RFC 8032, SHA-512, no prehash, no context). Beyond the
//! library's `verify_strict`, the profile explicitly requires:
//! - `S < L` (canonical scalar),
//! - `A` and `R` decompress and recompress to the exact received bytes,
//! - `A` and `R` are non-identity points of the prime-order subgroup,
//! - the cofactorless equation `[S]B = R + [h]A`.
//!
//! No ZIP-215 acceptance, no batch verification, no downgrade.
//!
//! Verification hashes `R || A || domain || message` as a stream: the
//! message is read where it lives and never copied next to the domain, so
//! a verifier holding a bounded response buffer does not double it (spec
//! §3, at most 8936 response bytes stored).

use curve25519_dalek::edwards::{CompressedEdwardsY, EdwardsPoint};
use curve25519_dalek::scalar::Scalar;
use curve25519_dalek::traits::IsIdentity;
use ed25519_dalek::{Signer, SigningKey};
use sha2::{Digest, Sha512};

/// Ed25519 raw public key.
pub type PublicKey = [u8; 32];
/// Ed25519 signature `R[32] || S[32]`.
pub type SignatureBytes = [u8; 64];

/// Why a signature was refused under the strict profile.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SignatureError {
    /// `S >= L`.
    NonCanonicalScalar,
    /// Public key does not decompress or is not canonically encoded.
    NonCanonicalPublicKey,
    /// `R` does not decompress or is not canonically encoded.
    NonCanonicalR,
    /// Public key is the identity or has a torsion component.
    WeakPublicKey,
    /// `R` is the identity or has a torsion component.
    WeakR,
    /// The verification equation does not hold.
    Invalid,
}

impl std::fmt::Display for SignatureError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            Self::NonCanonicalScalar => "signature scalar is not canonical",
            Self::NonCanonicalPublicKey => "public key is not a canonical point",
            Self::NonCanonicalR => "signature R is not a canonical point",
            Self::WeakPublicKey => "public key is identity or has torsion",
            Self::WeakR => "signature R is identity or has torsion",
            Self::Invalid => "signature equation does not hold",
        })
    }
}

impl std::error::Error for SignatureError {}

/// Decompress a point and require canonical encoding, prime-order subgroup
/// membership and non-identity.
fn strict_point(
    bytes: &[u8; 32],
    non_canonical: SignatureError,
    weak: SignatureError,
) -> Result<EdwardsPoint, SignatureError> {
    let compressed = CompressedEdwardsY(*bytes);
    let point = compressed.decompress().ok_or(non_canonical)?;
    if point.compress().as_bytes() != bytes {
        return Err(non_canonical);
    }
    if point.is_identity() || !point.is_torsion_free() {
        return Err(weak);
    }
    Ok(point)
}

/// Verify `signature` over `domain || message` under `public_key` with the
/// strict profile. Allocation-free: `message` is hashed in place.
pub fn verify_strict(
    public_key: &PublicKey,
    domain: &[u8],
    message: &[u8],
    signature: &SignatureBytes,
) -> Result<(), SignatureError> {
    let mut s_bytes = [0u8; 32];
    s_bytes.copy_from_slice(&signature[32..]);
    let s = Option::<Scalar>::from(Scalar::from_canonical_bytes(s_bytes))
        .ok_or(SignatureError::NonCanonicalScalar)?;
    let a = strict_point(
        public_key,
        SignatureError::NonCanonicalPublicKey,
        SignatureError::WeakPublicKey,
    )?;
    let mut r_bytes = [0u8; 32];
    r_bytes.copy_from_slice(&signature[..32]);
    let r = strict_point(
        &r_bytes,
        SignatureError::NonCanonicalR,
        SignatureError::WeakR,
    )?;

    // h = SHA512(R || A || domain || message) mod L (RFC 8032 §5.1.7, the
    // signed message being `domain || message`), fed part by part.
    let mut hasher = Sha512::new();
    hasher.update(r_bytes);
    hasher.update(public_key);
    hasher.update(domain);
    hasher.update(message);
    let h = Scalar::from_bytes_mod_order_wide(&hasher.finalize().into());
    // Cofactorless equation [S]B = R + [h]A, checked as [S]B - [h]A == R on
    // the decompressed points: both are canonical, torsion-free and
    // non-identity from `strict_point`, so point equality is equality of
    // the received encoding.
    let expected_r = EdwardsPoint::vartime_double_scalar_mul_basepoint(&h, &-a, &s);
    if expected_r == r {
        Ok(())
    } else {
        Err(SignatureError::Invalid)
    }
}

/// Sign `domain || message` with pure Ed25519 (unchecked emission).
pub fn sign(key: &SigningKey, domain: &[u8], message: &[u8]) -> SignatureBytes {
    let mut signed = Vec::with_capacity(domain.len() + message.len());
    signed.extend_from_slice(domain);
    signed.extend_from_slice(message);
    key.sign(&signed).to_bytes()
}

/// Sign and refuse to emit a signature the strict profile would reject
/// (identity or non-canonical `R`, weak key). Deterministic Ed25519 makes
/// such a failure permanent for this key and message.
pub fn sign_strict(
    key: &SigningKey,
    domain: &[u8],
    message: &[u8],
) -> Result<SignatureBytes, SignatureError> {
    let signature = sign(key, domain, message);
    verify_strict(&key.verifying_key().to_bytes(), domain, message, &signature)?;
    Ok(signature)
}

#[cfg(test)]
mod tests {
    use super::*;
    use curve25519_dalek::constants::ED25519_BASEPOINT_POINT;
    use curve25519_dalek::traits::Identity;

    const DOMAIN: &[u8] = b"ARION_TEST_DOMAIN";

    fn key(seed: u8) -> SigningKey {
        SigningKey::from_bytes(&[seed; 32])
    }

    // Order of the prime-order subgroup, little-endian.
    const L: [u8; 32] = [
        0xed, 0xd3, 0xf5, 0x5c, 0x1a, 0x63, 0x12, 0x58, 0xd6, 0x9c, 0xf7, 0xa2, 0xde, 0xf9, 0xde,
        0x14, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x10,
    ];

    #[test]
    fn valid_signature_is_accepted() {
        let k = key(7);
        let sig = sign(&k, DOMAIN, b"hello");
        assert_eq!(sign_strict(&k, DOMAIN, b"hello"), Ok(sig));
        assert_eq!(
            verify_strict(&k.verifying_key().to_bytes(), DOMAIN, b"hello", &sig),
            Ok(())
        );
        assert_eq!(
            verify_strict(&k.verifying_key().to_bytes(), b"other", b"hello", &sig),
            Err(SignatureError::Invalid)
        );
        assert_eq!(
            verify_strict(&k.verifying_key().to_bytes(), DOMAIN, b"hellO", &sig),
            Err(SignatureError::Invalid)
        );
    }

    #[test]
    fn agrees_with_library_verification() {
        use ed25519_dalek::{Signature, Verifier};
        // Same equation as `ed25519_dalek::VerifyingKey::verify_strict` over
        // the concatenation, without materialising it: accept and reject the
        // same inputs.
        for seed in 1u8..=8 {
            let k = key(seed);
            let vk = k.verifying_key();
            let msg: Vec<u8> = (0..(seed as usize * 700))
                .map(|i| (i * 31 + 7) as u8)
                .collect();
            let sig = sign(&k, DOMAIN, &msg);
            let joined: Vec<u8> = [DOMAIN, &msg].concat();
            assert!(
                vk.verify_strict(&joined, &Signature::from_bytes(&sig))
                    .is_ok()
            );
            assert!(vk.verify(&joined, &Signature::from_bytes(&sig)).is_ok());
            assert_eq!(verify_strict(&vk.to_bytes(), DOMAIN, &msg, &sig), Ok(()));
            let mut bad = sig;
            bad[40] ^= 0x80;
            assert!(
                vk.verify_strict(&joined, &Signature::from_bytes(&bad))
                    .is_err()
            );
            assert_eq!(
                verify_strict(&vk.to_bytes(), DOMAIN, &msg, &bad),
                Err(SignatureError::Invalid)
            );
            // Moving one byte across the domain/message boundary changes
            // the parts but not the concatenation: still accepted.
            let (d2, m2) = (&joined[..DOMAIN.len() - 1], &joined[DOMAIN.len() - 1..]);
            assert_eq!(verify_strict(&vk.to_bytes(), d2, m2, &sig), Ok(()));
        }
    }

    #[test]
    fn rfc8032_test_vector_1_is_accepted() {
        // RFC 8032 §7.1 TEST 1: empty message.
        let secret =
            hex::decode("9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60")
                .unwrap();
        let public =
            hex::decode("d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a")
                .unwrap();
        let expected = hex::decode(
            "e5564300c360ac729086e2cc806e828a84877f1eb8e5d974d873e065224901555fb8821590a33bacc61e39701cf9b46bd25bf5f0595bbe24655141438e7a100b",
        )
        .unwrap();
        let sk = SigningKey::from_bytes(&secret.try_into().unwrap());
        let sig = sign(&sk, b"", b"");
        assert_eq!(sig.to_vec(), expected);
        let pk: [u8; 32] = public.try_into().unwrap();
        assert_eq!(verify_strict(&pk, b"", b"", &sig), Ok(()));
    }

    #[test]
    fn non_canonical_scalar_is_rejected() {
        let k = key(1);
        let mut sig = sign(&k, DOMAIN, b"m");
        // S + L is a non-canonical encoding of the same scalar mod L.
        let mut s = [0u8; 32];
        s.copy_from_slice(&sig[32..]);
        let mut carry = 0u16;
        for i in 0..32 {
            let v = u16::from(s[i]) + u16::from(L[i]) + carry;
            s[i] = v as u8;
            carry = v >> 8;
        }
        sig[32..].copy_from_slice(&s);
        assert_eq!(
            verify_strict(&k.verifying_key().to_bytes(), DOMAIN, b"m", &sig),
            Err(SignatureError::NonCanonicalScalar)
        );
    }

    #[test]
    fn non_canonical_public_key_and_r_are_rejected() {
        let k = key(2);
        let sig = sign(&k, DOMAIN, b"m");
        // y = 2^255 - 19 + 1 with sign bit: non-canonical encoding of y = 1,
        // which is the identity point. Decompresses, recompresses differently.
        let mut nc = [0xffu8; 32];
        nc[0] = 0xee;
        nc[31] = 0x7f;
        assert_eq!(
            verify_strict(&nc, DOMAIN, b"m", &sig),
            Err(SignatureError::NonCanonicalPublicKey)
        );
        let mut bad = sig;
        bad[..32].copy_from_slice(&nc);
        assert_eq!(
            verify_strict(&k.verifying_key().to_bytes(), DOMAIN, b"m", &bad),
            Err(SignatureError::NonCanonicalR)
        );
        // A y coordinate with no point on the curve does not decompress.
        let mut off = [0u8; 32];
        off[0] = 2;
        assert_eq!(
            verify_strict(&off, DOMAIN, b"m", &sig),
            Err(SignatureError::NonCanonicalPublicKey)
        );
    }

    #[test]
    fn small_order_and_identity_points_are_rejected() {
        let k = key(3);
        let sig = sign(&k, DOMAIN, b"m");
        let identity = EdwardsPoint::identity().compress().to_bytes();
        assert_eq!(
            verify_strict(&identity, DOMAIN, b"m", &sig),
            Err(SignatureError::WeakPublicKey)
        );
        // Order-8 point (canonical encoding).
        let small = curve25519_dalek::constants::EIGHT_TORSION[1]
            .compress()
            .to_bytes();
        assert_eq!(
            verify_strict(&small, DOMAIN, b"m", &sig),
            Err(SignatureError::WeakPublicKey)
        );
        let mut bad = sig;
        bad[..32].copy_from_slice(&identity);
        assert_eq!(
            verify_strict(&k.verifying_key().to_bytes(), DOMAIN, b"m", &bad),
            Err(SignatureError::WeakR)
        );
        bad[..32].copy_from_slice(&small);
        assert_eq!(
            verify_strict(&k.verifying_key().to_bytes(), DOMAIN, b"m", &bad),
            Err(SignatureError::WeakR)
        );
    }

    #[test]
    fn mixed_order_points_are_rejected() {
        let k = key(4);
        let sig = sign(&k, DOMAIN, b"m");
        // A + T where T is a torsion point: not in the prime-order subgroup.
        let a = k.verifying_key().to_edwards();
        let mixed = (a + curve25519_dalek::constants::EIGHT_TORSION[1]).compress();
        assert_eq!(
            verify_strict(mixed.as_bytes(), DOMAIN, b"m", &sig),
            Err(SignatureError::WeakPublicKey)
        );
        let r_mixed =
            (ED25519_BASEPOINT_POINT + curve25519_dalek::constants::EIGHT_TORSION[2]).compress();
        let mut bad = sig;
        bad[..32].copy_from_slice(r_mixed.as_bytes());
        assert_eq!(
            verify_strict(&k.verifying_key().to_bytes(), DOMAIN, b"m", &bad),
            Err(SignatureError::WeakR)
        );
    }

    #[test]
    fn altered_signature_bytes_are_rejected() {
        let k = key(5);
        let pk = k.verifying_key().to_bytes();
        let sig = sign(&k, DOMAIN, b"m");
        for i in [0usize, 31, 32, 63] {
            let mut bad = sig;
            bad[i] ^= 0x01;
            assert_ne!(verify_strict(&pk, DOMAIN, b"m", &bad), Ok(()), "byte {i}");
        }
    }
}

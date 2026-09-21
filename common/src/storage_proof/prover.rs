//! Miner-side path of the protocol (spec §1, §2): outboard construction from
//! the authoritative projection, validating slice encoder, response framing
//! and challenge admission.
//!
//! Transport integration (spec §5) is not wired here; see the warden TODO.

use std::io::Cursor;

use bao_tree::io::outboard::PostOrderMemOutboard;
use bao_tree::io::sync::encode_ranges_validated;
use bao_tree::{BlockSize, ChunkNum, ChunkRanges};
use ed25519_dalek::SigningKey;

use super::geometry::{CHALLENGE_CHUNK_COUNT, ShardGeometry, derive_shard_geometry};
use super::sig::{self, PublicKey};
use super::wire::{
    self, CHALLENGE_BODY_LEN, CHALLENGE_FRAMED_LEN, CHALLENGE_SIGNED_LEN, CHALLENGE_WINDOW_MS,
    Challenge, DOMAIN_CHALLENGE, DOMAIN_RESPONSE, RecordHeader, ResponseHeader, STATUS_BUSY,
    STATUS_PROOF, WireError, expected_records, proof_framed_len,
};

/// Failure while building an outboard or a proof.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ProverError {
    /// Source length differs from the derived `shard_length`.
    SourceLengthMismatch { expected: u64, actual: u64 },
    /// Computed BLAKE3 root differs from the authoritative digest.
    RootMismatch,
    /// The challenge's `shard_length` differs from the common derivation.
    GeometryMismatch,
    /// The challenge indices are not valid for the derived geometry.
    InvalidIndices,
    /// The validating encoder refused the source data or outboard.
    Encode(String),
    /// The local signing key produced a signature outside the strict profile.
    Signature,
}

impl std::fmt::Display for ProverError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::SourceLengthMismatch { expected, actual } => {
                write!(f, "source length {actual} differs from derived {expected}")
            }
            Self::RootMismatch => f.write_str("computed root differs from authoritative digest"),
            Self::GeometryMismatch => f.write_str("challenge shard_length differs from derivation"),
            Self::InvalidIndices => f.write_str("challenge indices invalid for geometry"),
            Self::Encode(e) => write!(f, "validating encoder failed: {e}"),
            Self::Signature => f.write_str("signature outside the strict profile"),
        }
    }
}

impl std::error::Error for ProverError {}

/// Reconstructible Bao outboard of one shard, bound to its authoritative root.
///
/// It is an index, never an authority for the digest: construction fails
/// unless the root computed from the stored bytes equals `expected_root`.
#[derive(Debug, Clone)]
pub struct ShardOutboard {
    geometry: ShardGeometry,
    outboard: PostOrderMemOutboard,
}

impl ShardOutboard {
    /// Build the outboard for `data` under `geometry`, requiring the exact
    /// derived length and the authoritative root.
    pub fn build(
        data: &[u8],
        geometry: &ShardGeometry,
        expected_root: &[u8; 32],
    ) -> Result<Self, ProverError> {
        if data.len() as u64 != geometry.shard_length {
            return Err(ProverError::SourceLengthMismatch {
                expected: geometry.shard_length,
                actual: data.len() as u64,
            });
        }
        let outboard = PostOrderMemOutboard::create(data, BlockSize::ZERO);
        if outboard.root.as_bytes() != expected_root {
            return Err(ProverError::RootMismatch);
        }
        debug_assert_eq!(outboard.tree, geometry.bao_tree());
        Ok(Self {
            geometry: *geometry,
            outboard,
        })
    }

    pub fn geometry(&self) -> &ShardGeometry {
        &self.geometry
    }

    pub fn root(&self) -> [u8; 32] {
        *self.outboard.root.as_bytes()
    }

    /// Encode the independent slice for chunk range `[index, index + 1)`
    /// with the validating encoder: parent pairs root-to-leaf, then the
    /// chunk bytes. `data` must be the exact stored bytes of the shard.
    pub fn encode_chunk_slice(&self, data: &[u8], index: u32) -> Result<Vec<u8>, ProverError> {
        if data.len() as u64 != self.geometry.shard_length {
            return Err(ProverError::SourceLengthMismatch {
                expected: self.geometry.shard_length,
                actual: data.len() as u64,
            });
        }
        if u64::from(index) >= self.geometry.chunk_count {
            return Err(ProverError::InvalidIndices);
        }
        let ranges = ChunkRanges::from(ChunkNum(u64::from(index))..ChunkNum(u64::from(index) + 1));
        let mut out = Vec::new();
        encode_ranges_validated(data, &self.outboard, &ranges, &mut out)
            .map_err(|e| ProverError::Encode(format!("{e:?}")))?;
        Ok(out)
    }
}

/// Build the framed PROOF response for an admitted challenge.
///
/// The miner recomputes the geometry with the common derivation and refuses
/// a challenge whose `shard_length` differs; it never takes it as an order.
pub fn build_proof_response(
    challenge: &Challenge,
    miner_key: &SigningKey,
    data: &[u8],
    outboard: &ShardOutboard,
) -> Result<Vec<u8>, ProverError> {
    let geometry = derive_shard_geometry(
        challenge.file_size,
        challenge.stripe_size,
        challenge.k,
        challenge.m,
        challenge.shard_index,
    )
    .map_err(|_| ProverError::GeometryMismatch)?;
    if geometry.shard_length != challenge.shard_length || geometry != *outboard.geometry() {
        return Err(ProverError::GeometryMismatch);
    }
    // A stale outboard bound to another digest is "not ready", never a
    // proof under the wrong root.
    if outboard.root() != challenge.blob_hash {
        return Err(ProverError::RootMismatch);
    }
    if !Challenge::indices_valid(&challenge.indices, geometry.chunk_count) {
        return Err(ProverError::InvalidIndices);
    }
    let mut slices = Vec::with_capacity(CHALLENGE_CHUNK_COUNT);
    for &index in &challenge.indices {
        slices.push(outboard.encode_chunk_slice(data, index)?);
    }
    let header = ResponseHeader {
        count: wire::COUNT,
        status: STATUS_PROOF,
        challenge_id: challenge.challenge_id,
        miner_id: challenge.miner_id,
        incarnation: challenge.incarnation,
        blob_hash: challenge.blob_hash,
        shard_length: challenge.shard_length,
    };
    assemble_response(&header, &challenge.indices, &slices, &geometry, miner_key)
}

/// Assemble and sign a PROOF body from explicit slices. Exposed so fixtures
/// can build adversarial frames with a valid signature; production code uses
/// [`build_proof_response`].
pub fn assemble_response(
    header: &ResponseHeader,
    indices: &[u32; CHALLENGE_CHUNK_COUNT],
    slices: &[Vec<u8>],
    geometry: &ShardGeometry,
    miner_key: &SigningKey,
) -> Result<Vec<u8>, ProverError> {
    let mut body = Vec::new();
    body.extend_from_slice(&header.encode());
    for (i, slice) in slices.iter().enumerate() {
        let index = indices[i];
        let chunk_length = geometry.chunk_length(u64::from(index)).unwrap_or(0);
        body.extend_from_slice(
            &RecordHeader {
                index,
                chunk_length: chunk_length as u16,
                proof_length: slice.len() as u16,
            }
            .encode(),
        );
        body.extend_from_slice(slice);
    }
    sign_response_body(body, miner_key)
}

/// Append the miner signature over `R_unsigned` and frame the body.
pub fn sign_response_body(
    mut unsigned: Vec<u8>,
    miner_key: &SigningKey,
) -> Result<Vec<u8>, ProverError> {
    let signature = sig::sign_strict(miner_key, DOMAIN_RESPONSE, &unsigned)
        .map_err(|_| ProverError::Signature)?;
    unsigned.extend_from_slice(&signature);
    Ok(wire::frame(&unsigned))
}

/// Build the framed BUSY response (exactly 200 bytes).
pub fn build_busy_response(
    challenge: &Challenge,
    miner_key: &SigningKey,
) -> Result<Vec<u8>, ProverError> {
    let header = ResponseHeader {
        count: 0,
        status: STATUS_BUSY,
        challenge_id: challenge.challenge_id,
        miner_id: challenge.miner_id,
        incarnation: challenge.incarnation,
        blob_hash: challenge.blob_hash,
        shard_length: challenge.shard_length,
    };
    sign_response_body(header.encode().to_vec(), miner_key)
}

/// Why the miner refused a challenge (spec §3, "Admission du challenge").
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ChallengeRejection {
    /// Frame or body size, or non-canonical constant bytes.
    Malformed,
    /// Recomputed identifier differs from the announced one.
    IdMismatch,
    /// Issuer key not in the provisioned authorization list.
    UnauthorizedIssuer,
    /// Verifier signature invalid under the strict profile.
    InvalidSignature,
    /// Authenticated challenge with an all-zero verifier session or
    /// incarnation: the lifecycle contract of spec §1 requires non-zero
    /// values, whatever the local incarnation is.
    InvalidContext,
    /// Challenge addressed to another miner or incarnation.
    WrongRecipient,
    /// Derivation fails or differs from the announced `shard_length`.
    GeometryMismatch,
    /// Indices not strictly increasing or out of bounds.
    InvalidIndices,
    /// `expires_at_ms` or `max_response_bytes` differ from the computed values.
    InvalidBounds,
    /// The authenticated TLS peer is not the challenge issuer.
    PeerMismatch,
}

/// Outcome of a successful admission.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AdmittedChallenge {
    pub challenge: Challenge,
    /// The miner's clock says the window is over: answer BUSY if the budget
    /// allows those 200 bytes, otherwise close. Never a fault.
    pub expired_locally: bool,
}

/// Miner-side admission of a framed challenge (spec §3, "Admission du
/// challenge"). `authorized_verifiers` is the provisioned list of issuer
/// keys; an empty list admits nothing. `peer_id` is the authenticated TLS
/// identity of the client that opened the flow. `now_ms` is the miner's
/// civil clock, used only to decide BUSY-versus-work, never to judge delay.
pub fn admit_challenge(
    framed: &[u8],
    authorized_verifiers: &[PublicKey],
    peer_id: &PublicKey,
    my_id: &PublicKey,
    my_incarnation: &[u8; 16],
    now_ms: u64,
) -> Result<AdmittedChallenge, ChallengeRejection> {
    if framed.len() != CHALLENGE_FRAMED_LEN {
        return Err(ChallengeRejection::Malformed);
    }
    let declared = u32::from_le_bytes(framed[..4].try_into().expect("prefix"));
    if declared as usize != CHALLENGE_BODY_LEN {
        return Err(ChallengeRejection::Malformed);
    }
    let body: &[u8; CHALLENGE_BODY_LEN] = framed[4..].try_into().expect("body length checked");
    let challenge =
        Challenge::decode_body(body).map_err(|_: WireError| ChallengeRejection::Malformed)?;
    if Challenge::compute_id(body) != challenge.challenge_id {
        return Err(ChallengeRejection::IdMismatch);
    }
    if !authorized_verifiers.contains(&challenge.verifier_id) {
        return Err(ChallengeRejection::UnauthorizedIssuer);
    }
    if *peer_id != challenge.verifier_id {
        return Err(ChallengeRejection::PeerMismatch);
    }
    sig::verify_strict(
        &challenge.verifier_id,
        DOMAIN_CHALLENGE,
        &body[..CHALLENGE_SIGNED_LEN],
        &challenge.verifier_signature,
    )
    .map_err(|_| ChallengeRejection::InvalidSignature)?;
    // Semantic controls below run only on an authenticated challenge.
    if challenge.verifier_session == [0u8; 16] || challenge.incarnation == [0u8; 16] {
        return Err(ChallengeRejection::InvalidContext);
    }
    if challenge.miner_id != *my_id || challenge.incarnation != *my_incarnation {
        return Err(ChallengeRejection::WrongRecipient);
    }
    let geometry = derive_shard_geometry(
        challenge.file_size,
        challenge.stripe_size,
        challenge.k,
        challenge.m,
        challenge.shard_index,
    )
    .map_err(|_| ChallengeRejection::GeometryMismatch)?;
    if geometry.shard_length != challenge.shard_length || !geometry.eligible_for_challenge() {
        return Err(ChallengeRejection::GeometryMismatch);
    }
    if !Challenge::indices_valid(&challenge.indices, geometry.chunk_count) {
        return Err(ChallengeRejection::InvalidIndices);
    }
    let records = expected_records(&geometry, &challenge.indices)
        .ok_or(ChallengeRejection::InvalidIndices)?;
    let expected_expiry = challenge
        .issued_at_ms
        .checked_add(CHALLENGE_WINDOW_MS)
        .ok_or(ChallengeRejection::InvalidBounds)?;
    if challenge.expires_at_ms != expected_expiry
        || challenge.max_response_bytes as usize != proof_framed_len(&records)
    {
        return Err(ChallengeRejection::InvalidBounds);
    }
    let expired_locally = now_ms >= challenge.expires_at_ms;
    Ok(AdmittedChallenge {
        challenge,
        expired_locally,
    })
}

/// Parse a framed response produced by this module (fixture helper): returns
/// `(body, records region)` without any verification.
pub fn split_frame(framed: &[u8]) -> Option<&[u8]> {
    let declared = u32::from_le_bytes(framed.get(..4)?.try_into().ok()?) as usize;
    let body = framed.get(4..)?;
    (body.len() == declared).then_some(body)
}

/// Whether a status byte denotes BUSY.
pub fn is_busy(status: u8) -> bool {
    status == STATUS_BUSY
}

/// Decode a single slice with the reference decoder, for fixture sanity
/// checks. Returns the chunk bytes on success.
pub fn decode_slice_for_test(
    root: &[u8; 32],
    geometry: &ShardGeometry,
    index: u32,
    slice: &[u8],
) -> Result<Vec<u8>, String> {
    use bao_tree::io::BaoContentItem;
    use bao_tree::io::sync::DecodeResponseIter;
    let ranges = ChunkRanges::from(ChunkNum(u64::from(index))..ChunkNum(u64::from(index) + 1));
    let iter = DecodeResponseIter::new(
        blake3::Hash::from_bytes(*root),
        geometry.bao_tree(),
        Cursor::new(slice),
        &ranges,
    );
    let mut out = Vec::new();
    for item in iter {
        if let BaoContentItem::Leaf(leaf) = item.map_err(|e| format!("{e:?}"))? {
            out.extend_from_slice(&leaf.data);
        }
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::StripeConfig;
    use crate::encode_stripe;
    use crate::storage_proof::geometry::expected_proof_length;

    fn stripe_shards(file_size: u64, stripe_size: u64, stripe_index: u64) -> (Vec<Vec<u8>>, u64) {
        let config = StripeConfig {
            size: stripe_size,
            k: 10,
            m: 20,
        };
        let file: Vec<u8> = (0..file_size as u32)
            .map(|i| (i.wrapping_mul(31) % 251) as u8)
            .collect();
        let start = (stripe_index * stripe_size) as usize;
        let len = crate::calculate_stripe_data_len(file_size, stripe_index, stripe_size);
        let shards = encode_stripe(&file[start..start + len], &config).unwrap();
        (shards, len as u64)
    }

    #[test]
    fn outboard_root_equals_blake3_of_stored_bytes_including_padding() {
        let (shards, _) = stripe_shards(71681, 40960, 1);
        for global in [30u64, 39, 59] {
            let g = derive_shard_geometry(71681, 40960, 10, 20, global).unwrap();
            let shard = &shards[g.shard_in_stripe as usize];
            assert_eq!(shard.len() as u64, 3073);
            let root = *blake3::hash(shard).as_bytes();
            let ob = ShardOutboard::build(shard, &g, &root).unwrap();
            assert_eq!(ob.root(), root);
            for index in 0..4u32 {
                let slice = ob.encode_chunk_slice(shard, index).unwrap();
                assert_eq!(
                    slice.len() as u64,
                    expected_proof_length(&g, index.into()).unwrap()
                );
                let chunk = decode_slice_for_test(&root, &g, index, &slice).unwrap();
                let start = index as usize * 1024;
                assert_eq!(chunk, &shard[start..(start + 1024).min(shard.len())]);
            }
            let slice = ob.encode_chunk_slice(shard, 3).unwrap();
            assert_eq!(slice.len(), 129);
        }
    }

    #[test]
    fn outboard_refuses_wrong_length_or_root() {
        let (shards, _) = stripe_shards(71681, 40960, 1);
        let g = derive_shard_geometry(71681, 40960, 10, 20, 39).unwrap();
        let shard = &shards[9];
        let root = *blake3::hash(shard).as_bytes();
        // Truncating the nine padding zeros is a source length rejection.
        assert_eq!(
            ShardOutboard::build(&shard[..3064], &g, &root).err(),
            Some(ProverError::SourceLengthMismatch {
                expected: 3073,
                actual: 3064
            })
        );
        // Rounding the last chunk to 1024 is also a source length rejection.
        let mut padded = shard.clone();
        padded.resize(4096, 0);
        assert!(matches!(
            ShardOutboard::build(&padded, &g, &root),
            Err(ProverError::SourceLengthMismatch { .. })
        ));
        let mut corrupted = shard.clone();
        corrupted[3070] ^= 0x5a;
        assert_eq!(
            ShardOutboard::build(&corrupted, &g, &root).err(),
            Some(ProverError::RootMismatch)
        );
        // A valid outboard refuses to encode from corrupted bytes.
        let ob = ShardOutboard::build(shard, &g, &root).unwrap();
        assert!(matches!(
            ob.encode_chunk_slice(&corrupted, 2),
            Err(ProverError::Encode(_))
        ));
        assert!(ob.encode_chunk_slice(&corrupted, 0).is_ok());
        assert_eq!(
            ob.encode_chunk_slice(shard, 4),
            Err(ProverError::InvalidIndices)
        );
    }

    #[test]
    fn slice_lengths_match_proof_depth_for_irregular_trees() {
        // Non-power-of-two chunk counts exercise the split rule of §2.
        for chunks in [1u64, 2, 3, 5, 6, 7, 9, 12, 257, 300] {
            let shard_length = chunks * 1024 - 7;
            let data: Vec<u8> = (0..shard_length).map(|i| (i % 241) as u8).collect();
            let g = derive_shard_geometry(shard_length, shard_length, 1, 1, 0).unwrap();
            assert_eq!(g.chunk_count, chunks);
            let root = *blake3::hash(&data).as_bytes();
            let ob = ShardOutboard::build(&data, &g, &root).unwrap();
            for index in 0..chunks as u32 {
                let slice = ob.encode_chunk_slice(&data, index).unwrap();
                assert_eq!(
                    slice.len() as u64,
                    expected_proof_length(&g, index.into()).unwrap(),
                    "chunks {chunks} index {index}"
                );
                let chunk = decode_slice_for_test(&root, &g, index, &slice).unwrap();
                let start = index as usize * 1024;
                assert_eq!(chunk, &data[start..(start + 1024).min(data.len())]);
            }
        }
    }

    /// A canonical, correctly identified and signed challenge frame for
    /// admission tests: only `session` and `incarnation` vary.
    fn signed_challenge_frame(
        verifier_key: &SigningKey,
        miner_id: &PublicKey,
        session: [u8; 16],
        incarnation: [u8; 16],
    ) -> Vec<u8> {
        let geometry = derive_shard_geometry(4096, 4096, 1, 1, 0).unwrap();
        let indices = [0u32, 1, 2, 3];
        let records = expected_records(&geometry, &indices).unwrap();
        let mut challenge = Challenge {
            challenge_id: [0; 32],
            verifier_id: verifier_key.verifying_key().to_bytes(),
            verifier_session: session,
            miner_id: *miner_id,
            incarnation,
            manifest_id: [5; 32],
            shard_index: 0,
            blob_hash: [6; 32],
            file_size: 4096,
            stripe_size: 4096,
            k: 1,
            m: 1,
            shard_length: geometry.shard_length,
            indices,
            nonce: [7; 32],
            issued_at_ms: 1_000,
            expires_at_ms: 1_000 + CHALLENGE_WINDOW_MS,
            max_response_bytes: proof_framed_len(&records) as u32,
            verifier_signature: [0; 64],
        };
        challenge.challenge_id = Challenge::compute_id(&challenge.encode_body());
        let body = challenge.encode_body();
        challenge.verifier_signature = sig::sign_strict(
            verifier_key,
            DOMAIN_CHALLENGE,
            &body[..CHALLENGE_SIGNED_LEN],
        )
        .unwrap();
        wire::frame(&challenge.encode_body())
    }

    #[test]
    fn admission_rejects_zero_session_and_zero_incarnation_after_signature() {
        let verifier_key = SigningKey::from_bytes(&[0x11; 32]);
        let verifier_id = verifier_key.verifying_key().to_bytes();
        let miner_id = SigningKey::from_bytes(&[0x22; 32])
            .verifying_key()
            .to_bytes();
        let session = [0x33; 16];
        let incarnation = [0xA5; 16];
        let admit = |frame: &[u8], my_incarnation: &[u8; 16]| {
            admit_challenge(
                frame,
                &[verifier_id],
                &verifier_id,
                &miner_id,
                my_incarnation,
                1_010,
            )
            .map(|a| a.expired_locally)
        };
        // Control: the vector builder produces admissible challenges.
        let valid = signed_challenge_frame(&verifier_key, &miner_id, session, incarnation);
        assert_eq!(admit(&valid, &incarnation), Ok(false));
        // Zero session, correctly identified and re-signed: rejected on the
        // semantic control, not on the signature.
        let zero_session = signed_challenge_frame(&verifier_key, &miner_id, [0; 16], incarnation);
        assert_eq!(
            admit(&zero_session, &incarnation),
            Err(ChallengeRejection::InvalidContext)
        );
        // Zero incarnation: rejected whether the local incarnation differs
        // or is the same invalid value.
        let zero_incarnation = signed_challenge_frame(&verifier_key, &miner_id, session, [0; 16]);
        assert_eq!(
            admit(&zero_incarnation, &incarnation),
            Err(ChallengeRejection::InvalidContext)
        );
        assert_eq!(
            admit(&zero_incarnation, &[0; 16]),
            Err(ChallengeRejection::InvalidContext)
        );
        // Without re-signing, the same mutation never reaches that control.
        let mut unsigned_mutation = valid.clone();
        unsigned_mutation[4 + 76..4 + 92].fill(0);
        let mut body: [u8; CHALLENGE_BODY_LEN] = unsigned_mutation[4..].try_into().unwrap();
        let id = Challenge::compute_id(&body);
        body[12..44].copy_from_slice(&id);
        assert_eq!(
            admit(&wire::frame(&body), &incarnation),
            Err(ChallengeRejection::InvalidSignature)
        );
    }

    #[test]
    fn busy_response_is_exactly_200_bytes() {
        let key = SigningKey::from_bytes(&[9; 32]);
        let challenge = Challenge {
            challenge_id: [1; 32],
            verifier_id: [2; 32],
            verifier_session: [3; 16],
            miner_id: key.verifying_key().to_bytes(),
            incarnation: [4; 16],
            manifest_id: [5; 32],
            shard_index: 0,
            blob_hash: [6; 32],
            file_size: 4096,
            stripe_size: 4096,
            k: 1,
            m: 1,
            shard_length: 4096,
            indices: [0, 1, 2, 3],
            nonce: [7; 32],
            issued_at_ms: 0,
            expires_at_ms: 5000,
            max_response_bytes: 0,
            verifier_signature: [0; 64],
        };
        let busy = build_busy_response(&challenge, &key).unwrap();
        assert_eq!(busy.len(), wire::BUSY_FRAMED_LEN);
        let body = split_frame(&busy).unwrap();
        let header = ResponseHeader::decode(body).unwrap();
        assert_eq!(header.status, STATUS_BUSY);
        assert_eq!(header.count, 0);
        assert!(is_busy(header.status));
    }
}

//! Canonical binary encoding of the three protocol messages (spec §1, §2, §4).
//!
//! Every message is framed as `body_length:u32 LE || body`. All integers are
//! unsigned little-endian of fixed width. There are no optional fields.

use super::geometry::{
    CHALLENGE_CHUNK_COUNT, CHUNK_SIZE, MAX_PROOF_DEPTH, ShardGeometry, expected_proof_length,
};
use super::sig::{PublicKey, SignatureBytes};

/// ASCII magic and version shared by all messages.
pub const MAGIC_VERSION: [u8; 8] = *b"ARBAO001";
/// Only chunk grouping admitted in v1.
pub const GROUPING_LOG: u8 = 0;
/// Fixed challenge cardinality in v1.
pub const COUNT: u8 = CHALLENGE_CHUNK_COUNT as u8;

pub const MESSAGE_TYPE_CHALLENGE: u8 = 1;
pub const MESSAGE_TYPE_RESPONSE: u8 = 2;
pub const MESSAGE_TYPE_OBSERVATION: u8 = 3;

pub const STATUS_PROOF: u8 = 0;
pub const STATUS_BUSY: u8 = 1;

pub const DOMAIN_CHALLENGE_ID: &[u8] = b"ARION_BAO_CHALLENGE_ID_V1";
pub const DOMAIN_CHALLENGE: &[u8] = b"ARION_BAO_CHALLENGE_V1";
pub const DOMAIN_RESPONSE: &[u8] = b"ARION_BAO_RESPONSE_V1";
pub const DOMAIN_OBSERVATION: &[u8] = b"ARION_BAO_OBSERVATION_V1";
pub const DOMAIN_TRANSCRIPT: &[u8] = b"ARION_BAO_TRANSCRIPT_V1";

/// Length of the framing prefix.
pub const FRAME_PREFIX_LEN: usize = 4;
/// Challenge body length.
pub const CHALLENGE_BODY_LEN: usize = 372;
/// Challenge framed length.
pub const CHALLENGE_FRAMED_LEN: usize = CHALLENGE_BODY_LEN + FRAME_PREFIX_LEN;
/// Offset of the challenge signature; the id and signature cover `[0..308)`.
pub const CHALLENGE_SIGNED_LEN: usize = 308;
/// Fixed response header length (before records).
pub const RESPONSE_HEADER_LEN: usize = 132;
/// Length of a record header (`index:u32 || chunk_length:u16 || proof_length:u16`).
pub const RECORD_HEADER_LEN: usize = 8;
/// Ed25519 signature length.
pub const SIGNATURE_LEN: usize = 64;
/// BUSY body length (header + signature).
///
/// The negative frame is the only answer a miner gives to a valid
/// challenge it cannot serve (shard absent, digest mismatch, no permit,
/// rate limited, expired by its own clock). Fixed layout, 200 bytes:
///
/// ```text
/// off  len  field
///   0    4  frame prefix: body length, u32 LE = 196
///   4    8  MAGIC_VERSION "ARBAO001"
///  12    1  message type = MESSAGE_TYPE_RESPONSE
///  13    1  grouping log = GROUPING_LOG
///  14    1  record count = 0
///  15    1  status = STATUS_BUSY (1)
///  16   32  challenge_id
///  48   32  miner_id
///  80   16  incarnation
///  96   32  blob_hash
/// 128    8  shard_length, u64 LE
/// 136   64  Ed25519 signature over bytes 4..136 (DOMAIN_RESPONSE)
/// ```
///
/// The verifier reads it as `Busy` (22) → `MissingCoverage`, evidence
/// `(frame complete, signature valid)`; no negative frame is ever a fault.
pub const BUSY_BODY_LEN: usize = RESPONSE_HEADER_LEN + SIGNATURE_LEN;
/// BUSY framed length.
pub const BUSY_FRAMED_LEN: usize = BUSY_BODY_LEN + FRAME_PREFIX_LEN;
/// Largest PROOF body length in v1 (`d <= 18`, full chunks).
pub const MAX_PROOF_BODY_LEN: usize = RESPONSE_HEADER_LEN
    + CHALLENGE_CHUNK_COUNT
        * (RECORD_HEADER_LEN + CHUNK_SIZE as usize + 64 * MAX_PROOF_DEPTH as usize)
    + SIGNATURE_LEN;
/// Largest PROOF framed length in v1.
pub const MAX_PROOF_FRAMED_LEN: usize = MAX_PROOF_BODY_LEN + FRAME_PREFIX_LEN;
/// Observation body length (signature included).
pub const OBSERVATION_BODY_LEN: usize = 368;
/// Observation framed length.
pub const OBSERVATION_FRAMED_LEN: usize = OBSERVATION_BODY_LEN + FRAME_PREFIX_LEN;
/// Challenge window in milliseconds.
pub const CHALLENGE_WINDOW_MS: u64 = 5000;
/// Retention of terminal identifiers and evidence freshness bound.
pub const EVIDENCE_TTL_MS: u64 = 3_600_000;

const _: () = assert!(MAX_PROOF_BODY_LEN == 8932);
const _: () = assert!(MAX_PROOF_FRAMED_LEN == 8936);
const _: () = assert!(BUSY_BODY_LEN == 196);

/// Whether a would-be frame prefix is the start of a control-plane text
/// reply instead: four printable ASCII bytes (`ERROR: ...`, `RATE_LIMITED`,
/// `WARMING_UP`, `NOT_FOUND`). The miner's control protocol answers in
/// text on every stream it refuses before reading the message (handler
/// pool exhausted), a storage-proof flow included; read as a little-endian
/// length such a prefix is at least `0x2020_2020` (538 MiB), above every
/// response bound, so the two encodings never overlap and a verifier can
/// name the case (`UnsupportedEncoding`, the peer answered in another
/// protocol) instead of `ResponseTooLarge`. Both verdicts are missing
/// coverage with no frame and no signature.
pub fn prefix_is_text(prefix: &[u8]) -> bool {
    prefix.len() == FRAME_PREFIX_LEN && prefix.iter().all(|b| (0x20..=0x7E).contains(b))
}

const _: () = assert!(0x2020_2020usize > MAX_PROOF_BODY_LEN);

/// Stable `u16` error codes of the ordered controls (spec §3).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(u16)]
pub enum ErrorCode {
    Ok = 0,
    MetadataUnavailable = 1,
    InvalidGeometry = 2,
    IneligibleChallenge = 3,
    UnauthorizedContext = 4,
    LocalDeferred = 5,
    ResponseTooLarge = 10,
    TruncatedResponse = 11,
    UnsupportedEncoding = 12,
    UnknownChallenge = 13,
    ReplayedChallenge = 14,
    ExpiredChallenge = 15,
    WrongMiner = 16,
    WrongIncarnation = 17,
    ContextRevoked = 18,
    InvalidSignature = 19,
    RootMismatch = 20,
    ShardLengthMismatch = 21,
    Busy = 22,
    CardinalityMismatch = 23,
    IndicesMismatch = 24,
    ChunkLengthMismatch = 25,
    ProofLengthMismatch = 26,
    InvalidBaoProof = 27,
    TrailingData = 28,
    IncompleteCoverage = 29,
    FrameLengthMismatch = 30,
}

impl ErrorCode {
    pub fn as_u16(self) -> u16 {
        self as u16
    }

    pub fn from_u16(value: u16) -> Option<Self> {
        use ErrorCode::*;
        Some(match value {
            0 => Ok,
            1 => MetadataUnavailable,
            2 => InvalidGeometry,
            3 => IneligibleChallenge,
            4 => UnauthorizedContext,
            5 => LocalDeferred,
            10 => ResponseTooLarge,
            11 => TruncatedResponse,
            12 => UnsupportedEncoding,
            13 => UnknownChallenge,
            14 => ReplayedChallenge,
            15 => ExpiredChallenge,
            16 => WrongMiner,
            17 => WrongIncarnation,
            18 => ContextRevoked,
            19 => InvalidSignature,
            20 => RootMismatch,
            21 => ShardLengthMismatch,
            22 => Busy,
            23 => CardinalityMismatch,
            24 => IndicesMismatch,
            25 => ChunkLengthMismatch,
            26 => ProofLengthMismatch,
            27 => InvalidBaoProof,
            28 => TrailingData,
            29 => IncompleteCoverage,
            30 => FrameLengthMismatch,
            _ => return None,
        })
    }

    /// Verdict of the normative matrix (spec §4). `None` for diagnostics
    /// that never produce an observation (13, 14) and for admission codes.
    pub fn verdict(self) -> Option<Verdict> {
        use ErrorCode::*;
        Some(match self {
            Ok => Verdict::SampledBytesVerified,
            RootMismatch | ShardLengthMismatch | CardinalityMismatch | IndicesMismatch
            | ChunkLengthMismatch | ProofLengthMismatch | InvalidBaoProof | IncompleteCoverage => {
                Verdict::InvalidResponse
            }
            ResponseTooLarge | TruncatedResponse | UnsupportedEncoding | ExpiredChallenge
            | WrongMiner | WrongIncarnation | ContextRevoked | InvalidSignature | Busy
            | TrailingData | FrameLengthMismatch | LocalDeferred => Verdict::MissingCoverage,
            UnknownChallenge | ReplayedChallenge | MetadataUnavailable | InvalidGeometry
            | IneligibleChallenge | UnauthorizedContext => return None,
        })
    }
}

/// Observation verdict (spec §4).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum Verdict {
    SampledBytesVerified = 0,
    InvalidResponse = 1,
    MissingCoverage = 2,
}

impl Verdict {
    pub fn from_u8(value: u8) -> Option<Self> {
        match value {
            0 => Some(Self::SampledBytesVerified),
            1 => Some(Self::InvalidResponse),
            2 => Some(Self::MissingCoverage),
            _ => None,
        }
    }
}

/// `evidence_flags` bit 0: complete framed response received.
pub const EVIDENCE_FRAME_COMPLETE: u16 = 0b01;
/// `evidence_flags` bit 1: miner signature verified.
pub const EVIDENCE_SIGNATURE_VALID: u16 = 0b10;

/// Expected `(F, S)` evidence pair for a terminal code (spec §4 matrix).
/// `None` means "as completed": any pair with `S <= F`.
pub fn expected_evidence(code: ErrorCode) -> Option<(bool, bool)> {
    use ErrorCode::*;
    match code {
        Ok | Busy | RootMismatch | ShardLengthMismatch | CardinalityMismatch | IndicesMismatch
        | ChunkLengthMismatch | ProofLengthMismatch | InvalidBaoProof | IncompleteCoverage => {
            Some((true, true))
        }
        ResponseTooLarge | TruncatedResponse | UnsupportedEncoding | WrongMiner
        | WrongIncarnation | FrameLengthMismatch | TrailingData => Some((false, false)),
        InvalidSignature => Some((true, false)),
        ExpiredChallenge | ContextRevoked | LocalDeferred => None,
        MetadataUnavailable | InvalidGeometry | IneligibleChallenge | UnauthorizedContext
        | UnknownChallenge | ReplayedChallenge => Some((false, false)),
    }
}

/// Decoding failure of a message body.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WireError {
    /// Body length differs from the fixed length of this message.
    Length,
    /// Magic, message type, grouping, reserved or status byte unsupported.
    Encoding,
    /// Observation fields contradict the normative verdict/evidence matrix.
    Matrix,
}

/// Decode a 64-character ASCII hex digest (mixed case) into 32 bytes.
pub fn decode_hash_hex(text: &str) -> Option<[u8; 32]> {
    if text.len() != 64 || !text.bytes().all(|b| b.is_ascii_hexdigit()) {
        return None;
    }
    let mut out = [0u8; 32];
    hex::decode_to_slice(text, &mut out).ok()?;
    Some(out)
}

/// Canonical lowercase textual export of a digest.
pub fn encode_hash_hex(hash: &[u8; 32]) -> String {
    hex::encode(hash)
}

// ---------------------------------------------------------------------------
// Little helpers for fixed-offset reads
// ---------------------------------------------------------------------------

fn read_u16(body: &[u8], at: usize) -> u16 {
    u16::from_le_bytes([body[at], body[at + 1]])
}

fn read_u32(body: &[u8], at: usize) -> u32 {
    u32::from_le_bytes(body[at..at + 4].try_into().expect("4 bytes"))
}

fn read_u64(body: &[u8], at: usize) -> u64 {
    u64::from_le_bytes(body[at..at + 8].try_into().expect("8 bytes"))
}

fn read_array<const N: usize>(body: &[u8], at: usize) -> [u8; N] {
    body[at..at + N].try_into().expect("fixed array")
}

/// Frame a body: `LE_u32(len) || body`.
pub fn frame(body: &[u8]) -> Vec<u8> {
    let len = u32::try_from(body.len()).expect("body fits u32");
    let mut out = Vec::with_capacity(FRAME_PREFIX_LEN + body.len());
    out.extend_from_slice(&len.to_le_bytes());
    out.extend_from_slice(body);
    out
}

// ---------------------------------------------------------------------------
// Challenge
// ---------------------------------------------------------------------------

/// Decoded challenge body (spec §1).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Challenge {
    pub challenge_id: [u8; 32],
    pub verifier_id: PublicKey,
    pub verifier_session: [u8; 16],
    pub miner_id: PublicKey,
    pub incarnation: [u8; 16],
    pub manifest_id: [u8; 32],
    pub shard_index: u64,
    pub blob_hash: [u8; 32],
    pub file_size: u64,
    pub stripe_size: u64,
    pub k: u16,
    pub m: u16,
    pub shard_length: u64,
    pub indices: [u32; CHALLENGE_CHUNK_COUNT],
    pub nonce: [u8; 32],
    pub issued_at_ms: u64,
    pub expires_at_ms: u64,
    pub max_response_bytes: u32,
    pub verifier_signature: SignatureBytes,
}

impl Challenge {
    /// Serialize the body prefix `[0..308)`, without id/signature validity
    /// assumptions: the caller fills `challenge_id` and `verifier_signature`.
    pub fn encode_body(&self) -> [u8; CHALLENGE_BODY_LEN] {
        let mut c = [0u8; CHALLENGE_BODY_LEN];
        c[0..8].copy_from_slice(&MAGIC_VERSION);
        c[8] = MESSAGE_TYPE_CHALLENGE;
        c[9] = GROUPING_LOG;
        c[10] = COUNT;
        c[11] = 0;
        c[12..44].copy_from_slice(&self.challenge_id);
        c[44..76].copy_from_slice(&self.verifier_id);
        c[76..92].copy_from_slice(&self.verifier_session);
        c[92..124].copy_from_slice(&self.miner_id);
        c[124..140].copy_from_slice(&self.incarnation);
        c[140..172].copy_from_slice(&self.manifest_id);
        c[172..180].copy_from_slice(&self.shard_index.to_le_bytes());
        c[180..212].copy_from_slice(&self.blob_hash);
        c[212..220].copy_from_slice(&self.file_size.to_le_bytes());
        c[220..228].copy_from_slice(&self.stripe_size.to_le_bytes());
        c[228..230].copy_from_slice(&self.k.to_le_bytes());
        c[230..232].copy_from_slice(&self.m.to_le_bytes());
        c[232..240].copy_from_slice(&self.shard_length.to_le_bytes());
        for (i, index) in self.indices.iter().enumerate() {
            c[240 + 4 * i..244 + 4 * i].copy_from_slice(&index.to_le_bytes());
        }
        c[256..288].copy_from_slice(&self.nonce);
        c[288..296].copy_from_slice(&self.issued_at_ms.to_le_bytes());
        c[296..304].copy_from_slice(&self.expires_at_ms.to_le_bytes());
        c[304..308].copy_from_slice(&self.max_response_bytes.to_le_bytes());
        c[308..372].copy_from_slice(&self.verifier_signature);
        c
    }

    /// `BLAKE3(domain || C[0..12] || C[44..308])` over an encoded body.
    pub fn compute_id(body: &[u8; CHALLENGE_BODY_LEN]) -> [u8; 32] {
        let mut hasher = blake3::Hasher::new();
        hasher.update(DOMAIN_CHALLENGE_ID);
        hasher.update(&body[0..12]);
        hasher.update(&body[44..CHALLENGE_SIGNED_LEN]);
        *hasher.finalize().as_bytes()
    }

    /// Parse a body of exactly 372 bytes; checks only fixed size and the
    /// canonical constant bytes. Id, signature and semantics are checked by
    /// the caller.
    pub fn decode_body(body: &[u8]) -> Result<Self, WireError> {
        if body.len() != CHALLENGE_BODY_LEN {
            return Err(WireError::Length);
        }
        if body[0..8] != MAGIC_VERSION
            || body[8] != MESSAGE_TYPE_CHALLENGE
            || body[9] != GROUPING_LOG
            || body[10] != COUNT
            || body[11] != 0
        {
            return Err(WireError::Encoding);
        }
        let mut indices = [0u32; CHALLENGE_CHUNK_COUNT];
        for (i, slot) in indices.iter_mut().enumerate() {
            *slot = read_u32(body, 240 + 4 * i);
        }
        Ok(Self {
            challenge_id: read_array(body, 12),
            verifier_id: read_array(body, 44),
            verifier_session: read_array(body, 76),
            miner_id: read_array(body, 92),
            incarnation: read_array(body, 124),
            manifest_id: read_array(body, 140),
            shard_index: read_u64(body, 172),
            blob_hash: read_array(body, 180),
            file_size: read_u64(body, 212),
            stripe_size: read_u64(body, 220),
            k: read_u16(body, 228),
            m: read_u16(body, 230),
            shard_length: read_u64(body, 232),
            indices,
            nonce: read_array(body, 256),
            issued_at_ms: read_u64(body, 288),
            expires_at_ms: read_u64(body, 296),
            max_response_bytes: read_u32(body, 304),
            verifier_signature: read_array(body, 308),
        })
    }

    /// Whether the indices are strictly increasing and all below `chunk_count`.
    pub fn indices_valid(indices: &[u32; CHALLENGE_CHUNK_COUNT], chunk_count: u64) -> bool {
        indices.windows(2).all(|w| w[0] < w[1])
            && indices.iter().all(|&i| u64::from(i) < chunk_count)
    }
}

// ---------------------------------------------------------------------------
// Response
// ---------------------------------------------------------------------------

/// Fixed 132-byte response header (spec §2).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ResponseHeader {
    pub count: u8,
    pub status: u8,
    pub challenge_id: [u8; 32],
    pub miner_id: PublicKey,
    pub incarnation: [u8; 16],
    pub blob_hash: [u8; 32],
    pub shard_length: u64,
}

impl ResponseHeader {
    pub fn encode(&self) -> [u8; RESPONSE_HEADER_LEN] {
        let mut h = [0u8; RESPONSE_HEADER_LEN];
        h[0..8].copy_from_slice(&MAGIC_VERSION);
        h[8] = MESSAGE_TYPE_RESPONSE;
        h[9] = GROUPING_LOG;
        h[10] = self.count;
        h[11] = self.status;
        h[12..44].copy_from_slice(&self.challenge_id);
        h[44..76].copy_from_slice(&self.miner_id);
        h[76..92].copy_from_slice(&self.incarnation);
        h[92..124].copy_from_slice(&self.blob_hash);
        h[124..132].copy_from_slice(&self.shard_length.to_le_bytes());
        h
    }

    /// Parse the first 132 bytes. Rejects unknown version, type, grouping
    /// or status (V3). `count` is returned as-is for V13/V14.
    pub fn decode(header: &[u8]) -> Result<Self, WireError> {
        if header.len() < RESPONSE_HEADER_LEN {
            return Err(WireError::Length);
        }
        if header[0..8] != MAGIC_VERSION
            || header[8] != MESSAGE_TYPE_RESPONSE
            || header[9] != GROUPING_LOG
            || (header[11] != STATUS_PROOF && header[11] != STATUS_BUSY)
        {
            return Err(WireError::Encoding);
        }
        Ok(Self {
            count: header[10],
            status: header[11],
            challenge_id: read_array(header, 12),
            miner_id: read_array(header, 44),
            incarnation: read_array(header, 76),
            blob_hash: read_array(header, 92),
            shard_length: read_u64(header, 124),
        })
    }
}

/// One record header as declared on the wire.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RecordHeader {
    pub index: u32,
    pub chunk_length: u16,
    pub proof_length: u16,
}

impl RecordHeader {
    pub fn encode(&self) -> [u8; RECORD_HEADER_LEN] {
        let mut r = [0u8; RECORD_HEADER_LEN];
        r[0..4].copy_from_slice(&self.index.to_le_bytes());
        r[4..6].copy_from_slice(&self.chunk_length.to_le_bytes());
        r[6..8].copy_from_slice(&self.proof_length.to_le_bytes());
        r
    }

    pub fn decode(bytes: &[u8]) -> Self {
        Self {
            index: read_u32(bytes, 0),
            chunk_length: read_u16(bytes, 4),
            proof_length: read_u16(bytes, 6),
        }
    }
}

/// Expected record layout for a challenge: exact lengths determined by the
/// geometry, never by the miner.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ExpectedRecord {
    pub index: u32,
    pub chunk_length: u64,
    pub proof_length: u64,
    /// Offset of the record header inside the response body.
    pub offset: usize,
}

/// Compute the four expected records and the exact PROOF framed size for
/// `indices` under `geometry`. `None` when an index is out of bounds.
pub fn expected_records(
    geometry: &ShardGeometry,
    indices: &[u32; CHALLENGE_CHUNK_COUNT],
) -> Option<[ExpectedRecord; CHALLENGE_CHUNK_COUNT]> {
    let mut records = [ExpectedRecord {
        index: 0,
        chunk_length: 0,
        proof_length: 0,
        offset: 0,
    }; CHALLENGE_CHUNK_COUNT];
    let mut offset = RESPONSE_HEADER_LEN;
    for (slot, &index) in records.iter_mut().zip(indices.iter()) {
        let chunk_length = geometry.chunk_length(u64::from(index))?;
        let proof_length = expected_proof_length(geometry, u64::from(index))?;
        *slot = ExpectedRecord {
            index,
            chunk_length,
            proof_length,
            offset,
        };
        offset += RECORD_HEADER_LEN + proof_length as usize;
    }
    Some(records)
}

/// Exact PROOF body length for the given expected records.
pub fn proof_body_len(records: &[ExpectedRecord; CHALLENGE_CHUNK_COUNT]) -> usize {
    RESPONSE_HEADER_LEN
        + records
            .iter()
            .map(|r| RECORD_HEADER_LEN + r.proof_length as usize)
            .sum::<usize>()
        + SIGNATURE_LEN
}

/// Exact PROOF framed length: the `max_response_bytes` of the challenge.
pub fn proof_framed_len(records: &[ExpectedRecord; CHALLENGE_CHUNK_COUNT]) -> usize {
    proof_body_len(records) + FRAME_PREFIX_LEN
}

// ---------------------------------------------------------------------------
// Observation
// ---------------------------------------------------------------------------

/// Dated observation body (spec §4), 368 bytes with signature.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Observation {
    pub verdict: Verdict,
    pub challenge_id: [u8; 32],
    pub verifier_id: PublicKey,
    pub verifier_session: [u8; 16],
    pub miner_id: PublicKey,
    pub incarnation: [u8; 16],
    pub manifest_id: [u8; 32],
    pub shard_index: u64,
    pub blob_hash: [u8; 32],
    pub shard_length: u64,
    pub indices: [u32; CHALLENGE_CHUNK_COUNT],
    pub issued_at_ms: u64,
    pub received_at_ms: u64,
    pub completed_at_ms: u64,
    pub latency_us: u64,
    pub error_code: ErrorCode,
    pub evidence_flags: u16,
    pub transcript_hash: [u8; 32],
    pub observer_signature: SignatureBytes,
}

impl Observation {
    /// Offset of the signature inside the body.
    pub const SIGNATURE_OFFSET: usize = OBSERVATION_BODY_LEN - SIGNATURE_LEN;

    pub fn encode_body(&self) -> [u8; OBSERVATION_BODY_LEN] {
        let mut o = [0u8; OBSERVATION_BODY_LEN];
        o[0..8].copy_from_slice(&MAGIC_VERSION);
        o[8] = MESSAGE_TYPE_OBSERVATION;
        o[9] = GROUPING_LOG;
        o[10] = COUNT;
        o[11] = self.verdict as u8;
        o[12..44].copy_from_slice(&self.challenge_id);
        o[44..76].copy_from_slice(&self.verifier_id);
        o[76..92].copy_from_slice(&self.verifier_session);
        o[92..124].copy_from_slice(&self.miner_id);
        o[124..140].copy_from_slice(&self.incarnation);
        o[140..172].copy_from_slice(&self.manifest_id);
        o[172..180].copy_from_slice(&self.shard_index.to_le_bytes());
        o[180..212].copy_from_slice(&self.blob_hash);
        o[212..220].copy_from_slice(&self.shard_length.to_le_bytes());
        for (i, index) in self.indices.iter().enumerate() {
            o[220 + 4 * i..224 + 4 * i].copy_from_slice(&index.to_le_bytes());
        }
        o[236..244].copy_from_slice(&self.issued_at_ms.to_le_bytes());
        o[244..252].copy_from_slice(&self.received_at_ms.to_le_bytes());
        o[252..260].copy_from_slice(&self.completed_at_ms.to_le_bytes());
        o[260..268].copy_from_slice(&self.latency_us.to_le_bytes());
        o[268..270].copy_from_slice(&self.error_code.as_u16().to_le_bytes());
        o[270..272].copy_from_slice(&self.evidence_flags.to_le_bytes());
        o[272..304].copy_from_slice(&self.transcript_hash);
        o[304..368].copy_from_slice(&self.observer_signature);
        o
    }

    pub fn decode_body(body: &[u8]) -> Result<Self, WireError> {
        if body.len() != OBSERVATION_BODY_LEN {
            return Err(WireError::Length);
        }
        if body[0..8] != MAGIC_VERSION
            || body[8] != MESSAGE_TYPE_OBSERVATION
            || body[9] != GROUPING_LOG
            || body[10] != COUNT
        {
            return Err(WireError::Encoding);
        }
        let verdict = Verdict::from_u8(body[11]).ok_or(WireError::Encoding)?;
        let error_code = ErrorCode::from_u16(read_u16(body, 268)).ok_or(WireError::Encoding)?;
        let mut indices = [0u32; CHALLENGE_CHUNK_COUNT];
        for (i, slot) in indices.iter_mut().enumerate() {
            *slot = read_u32(body, 220 + 4 * i);
        }
        Ok(Self {
            verdict,
            challenge_id: read_array(body, 12),
            verifier_id: read_array(body, 44),
            verifier_session: read_array(body, 76),
            miner_id: read_array(body, 92),
            incarnation: read_array(body, 124),
            manifest_id: read_array(body, 140),
            shard_index: read_u64(body, 172),
            blob_hash: read_array(body, 180),
            shard_length: read_u64(body, 212),
            indices,
            issued_at_ms: read_u64(body, 236),
            received_at_ms: read_u64(body, 244),
            completed_at_ms: read_u64(body, 252),
            latency_us: read_u64(body, 260),
            error_code,
            evidence_flags: read_u16(body, 270),
            transcript_hash: read_array(body, 272),
            observer_signature: read_array(body, 304),
        })
    }
}

impl Observation {
    /// Check the normative verdict, evidence flags, sentinels and transcript
    /// rules of spec §4. Signature and encoding are checked separately.
    pub fn validate_matrix(&self) -> Result<(), WireError> {
        let verdict = self.error_code.verdict().ok_or(WireError::Matrix)?;
        if verdict != self.verdict {
            return Err(WireError::Matrix);
        }
        if self.evidence_flags & !(EVIDENCE_FRAME_COMPLETE | EVIDENCE_SIGNATURE_VALID) != 0 {
            return Err(WireError::Matrix);
        }
        let f = self.evidence_flags & EVIDENCE_FRAME_COMPLETE != 0;
        let s = self.evidence_flags & EVIDENCE_SIGNATURE_VALID != 0;
        if s && !f {
            return Err(WireError::Matrix);
        }
        if let Some(expected) = expected_evidence(self.error_code)
            && expected != (f, s)
        {
            return Err(WireError::Matrix);
        }
        // F=1: real reception anchors; the transcript digest is whatever the
        // formula produced (recomputed by full reverification). F=0: the
        // sentinels and a zero transcript are mandatory.
        let zero_transcript = self.transcript_hash == [0u8; 32];
        let no_reception = self.received_at_ms == u64::MAX && self.latency_us == u64::MAX;
        if f {
            if self.received_at_ms == u64::MAX || self.latency_us == u64::MAX {
                return Err(WireError::Matrix);
            }
        } else if !zero_transcript || !no_reception {
            return Err(WireError::Matrix);
        }
        if self.completed_at_ms == u64::MAX {
            return Err(WireError::Matrix);
        }
        Ok(())
    }
}

/// `BLAKE3(domain || LE_u32(len(CW)) || CW || LE_u32(len(RW)) || RW)` over
/// the exact framed challenge and response.
pub fn transcript_hash(challenge_frame: &[u8], response_frame: &[u8]) -> [u8; 32] {
    let mut hasher = blake3::Hasher::new();
    hasher.update(DOMAIN_TRANSCRIPT);
    hasher.update(&(challenge_frame.len() as u32).to_le_bytes());
    hasher.update(challenge_frame);
    hasher.update(&(response_frame.len() as u32).to_le_bytes());
    hasher.update(response_frame);
    *hasher.finalize().as_bytes()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::storage_proof::geometry::derive_shard_geometry;

    #[test]
    fn text_prefix_is_never_a_valid_length() {
        for text in [
            &b"ERROR: RATE_LIMITED"[..],
            b"RATE_LIMITED",
            b"WARMING_UP",
            b"NOT_FOUND",
        ] {
            let prefix = &text[..FRAME_PREFIX_LEN];
            assert!(prefix_is_text(prefix), "{}", String::from_utf8_lossy(text));
            let declared = u32::from_le_bytes(prefix.try_into().unwrap()) as usize;
            assert!(declared > MAX_PROOF_BODY_LEN);
        }
        assert!(!prefix_is_text(&(BUSY_BODY_LEN as u32).to_le_bytes()));
        assert!(!prefix_is_text(&(MAX_PROOF_BODY_LEN as u32).to_le_bytes()));
        assert!(!prefix_is_text(b"ERR"));
        assert!(!prefix_is_text(b"ERROR"));
    }

    #[test]
    fn spec_sizes_hold() {
        let g = derive_shard_geometry(262_144, 262_144, 1, 1, 0).unwrap();
        let records = expected_records(&g, &[0, 1, 2, 3]).unwrap();
        assert_eq!(proof_body_len(&records), 6372);
        assert_eq!(proof_framed_len(&records), 6376);
        assert_eq!(CHALLENGE_FRAMED_LEN + proof_framed_len(&records), 6752);
        let g = derive_shard_geometry(268_435_456, 268_435_456, 1, 1, 0).unwrap();
        let records = expected_records(&g, &[0, 1, 2, 3]).unwrap();
        assert_eq!(proof_body_len(&records), MAX_PROOF_BODY_LEN);
        assert_eq!(BUSY_FRAMED_LEN, 200);
        assert_eq!(OBSERVATION_FRAMED_LEN, 372);
        assert_eq!(CHALLENGE_FRAMED_LEN, 376);
    }

    #[test]
    fn expected_records_for_last_partial_chunk() {
        let g = derive_shard_geometry(71681, 40960, 10, 20, 39).unwrap();
        let records = expected_records(&g, &[0, 1, 2, 3]).unwrap();
        assert_eq!(records[3].chunk_length, 1);
        assert_eq!(records[3].proof_length, 129);
        assert_eq!(records[0].offset, 132);
        assert_eq!(records[1].offset, 132 + 8 + 1152);
        assert_eq!(proof_body_len(&records), 132 + 3 * 1160 + 137 + 64);
        assert!(expected_records(&g, &[0, 1, 2, 4]).is_none());
    }

    #[test]
    fn challenge_round_trips_and_id_is_stable() {
        let c = Challenge {
            challenge_id: [0; 32],
            verifier_id: [1; 32],
            verifier_session: [2; 16],
            miner_id: [3; 32],
            incarnation: [4; 16],
            manifest_id: [5; 32],
            shard_index: 39,
            blob_hash: [6; 32],
            file_size: 71681,
            stripe_size: 40960,
            k: 10,
            m: 20,
            shard_length: 3073,
            indices: [0, 1, 2, 3],
            nonce: [7; 32],
            issued_at_ms: 1_000,
            expires_at_ms: 6_000,
            max_response_bytes: 3817,
            verifier_signature: [8; 64],
        };
        let body = c.encode_body();
        let id = Challenge::compute_id(&body);
        let mut with_id = c.clone();
        with_id.challenge_id = id;
        let body = with_id.encode_body();
        assert_eq!(Challenge::compute_id(&body), id);
        assert_eq!(Challenge::decode_body(&body).unwrap(), with_id);
        // The id does not cover the id field itself nor the signature.
        let mut altered = body;
        altered[308] ^= 1;
        assert_eq!(Challenge::compute_id(&altered), id);
        altered[256] ^= 1;
        assert_ne!(Challenge::compute_id(&altered), id);
        assert_eq!(Challenge::decode_body(&body[..371]), Err(WireError::Length));
        let mut bad = body;
        bad[9] = 4;
        assert_eq!(Challenge::decode_body(&bad), Err(WireError::Encoding));
    }

    #[test]
    fn hash_hex_is_strict() {
        let h = [0xabu8; 32];
        let text = encode_hash_hex(&h);
        assert_eq!(text.len(), 64);
        assert_eq!(decode_hash_hex(&text), Some(h));
        assert_eq!(decode_hash_hex(&text.to_uppercase()), Some(h));
        assert_eq!(decode_hash_hex(&format!("0x{text}")), None);
        assert_eq!(decode_hash_hex(&text[..63]), None);
        assert_eq!(decode_hash_hex(&format!(" {}", &text[..63])), None);
        assert_eq!(decode_hash_hex(&format!("{}g", &text[..63])), None);
    }

    #[test]
    fn observation_round_trips() {
        let o = Observation {
            verdict: Verdict::InvalidResponse,
            challenge_id: [1; 32],
            verifier_id: [2; 32],
            verifier_session: [3; 16],
            miner_id: [4; 32],
            incarnation: [5; 16],
            manifest_id: [6; 32],
            shard_index: 9,
            blob_hash: [7; 32],
            shard_length: 4096,
            indices: [0, 1, 2, 3],
            issued_at_ms: 10,
            received_at_ms: 20,
            completed_at_ms: 30,
            latency_us: 10_000,
            error_code: ErrorCode::InvalidBaoProof,
            evidence_flags: 3,
            transcript_hash: [8; 32],
            observer_signature: [9; 64],
        };
        let body = o.encode_body();
        assert_eq!(Observation::decode_body(&body).unwrap(), o);
        assert_eq!(frame(&body).len(), OBSERVATION_FRAMED_LEN);
    }

    #[test]
    fn observation_matrix_validation() {
        let mut o = Observation {
            verdict: Verdict::SampledBytesVerified,
            challenge_id: [1; 32],
            verifier_id: [2; 32],
            verifier_session: [3; 16],
            miner_id: [4; 32],
            incarnation: [5; 16],
            manifest_id: [6; 32],
            shard_index: 9,
            blob_hash: [7; 32],
            shard_length: 4096,
            indices: [0, 1, 2, 3],
            issued_at_ms: 10,
            received_at_ms: 20,
            completed_at_ms: 30,
            latency_us: 10_000,
            error_code: ErrorCode::Ok,
            evidence_flags: 3,
            transcript_hash: [8; 32],
            observer_signature: [9; 64],
        };
        assert_eq!(o.validate_matrix(), Ok(()));
        o.verdict = Verdict::MissingCoverage;
        assert_eq!(o.validate_matrix(), Err(WireError::Matrix));
        o.verdict = Verdict::SampledBytesVerified;
        o.evidence_flags = 0xffff;
        assert_eq!(o.validate_matrix(), Err(WireError::Matrix));
        o.evidence_flags = 2;
        assert_eq!(o.validate_matrix(), Err(WireError::Matrix));
        o.evidence_flags = 1;
        assert_eq!(o.validate_matrix(), Err(WireError::Matrix));
        o.evidence_flags = 3;
        o.received_at_ms = u64::MAX;
        assert_eq!(o.validate_matrix(), Err(WireError::Matrix));
        o.received_at_ms = 20;
        o.completed_at_ms = u64::MAX;
        assert_eq!(o.validate_matrix(), Err(WireError::Matrix));
        o.completed_at_ms = 30;
        // No-reception codes require the sentinels and a zero transcript.
        o.error_code = ErrorCode::TruncatedResponse;
        o.verdict = Verdict::MissingCoverage;
        o.evidence_flags = 0;
        assert_eq!(o.validate_matrix(), Err(WireError::Matrix));
        o.received_at_ms = u64::MAX;
        o.latency_us = u64::MAX;
        o.transcript_hash = [0; 32];
        assert_eq!(o.validate_matrix(), Ok(()));
        // Diagnostics never appear in an observation.
        o.error_code = ErrorCode::UnknownChallenge;
        assert_eq!(o.validate_matrix(), Err(WireError::Matrix));
        // Expiry accepts any completed pair with S <= F.
        o.error_code = ErrorCode::ExpiredChallenge;
        assert_eq!(o.validate_matrix(), Ok(()));
        o.evidence_flags = 3;
        o.received_at_ms = 20;
        o.latency_us = 5;
        o.transcript_hash = [8; 32];
        assert_eq!(o.validate_matrix(), Ok(()));
    }

    #[test]
    fn verdict_matrix() {
        use ErrorCode::*;
        assert_eq!(Ok.verdict(), Some(Verdict::SampledBytesVerified));
        for c in [
            ResponseTooLarge,
            TruncatedResponse,
            UnsupportedEncoding,
            WrongMiner,
            WrongIncarnation,
            FrameLengthMismatch,
            InvalidSignature,
            ExpiredChallenge,
            ContextRevoked,
            Busy,
            TrailingData,
            LocalDeferred,
        ] {
            assert_eq!(c.verdict(), Some(Verdict::MissingCoverage), "{c:?}");
        }
        for c in [
            RootMismatch,
            ShardLengthMismatch,
            CardinalityMismatch,
            IndicesMismatch,
            ChunkLengthMismatch,
            ProofLengthMismatch,
            InvalidBaoProof,
            IncompleteCoverage,
        ] {
            assert_eq!(c.verdict(), Some(Verdict::InvalidResponse), "{c:?}");
        }
        assert_eq!(UnknownChallenge.verdict(), None);
        assert_eq!(ReplayedChallenge.verdict(), None);
        for v in 0..=30u16 {
            if let Some(code) = ErrorCode::from_u16(v) {
                assert_eq!(code.as_u16(), v);
            }
        }
    }
}

//! Compact binary encoding of [`FileManifest`] (format v1).
//!
//! Goal: a 30-shard manifest in ≈ 1.1 KiB, below the Postgres TOAST
//! threshold (~2 KiB), so the row stays in the heap. Everything variable is
//! LEB128 (unsigned varint); hashes are raw 32 bytes instead of 64 hex
//! characters; no field names.
//!
//! # Layout (all integers little-endian-free: varints or single bytes)
//!
//! | offset | size | field |
//! |---|---|---|
//! | 0 | 4 | magic `ARMF` (`0x41 0x52 0x4D 0x46`) |
//! | 4 | 1 | format version = `1` |
//! | 5 | 1 | flags: bit0 filename present, bit1 content_type present, bit2 holders present; other bits must be 0 |
//! | 6 | 32 | `file_hash` (raw BLAKE3, decoded from the 64-hex string) |
//! | 38 | 1 | `placement_version` |
//! | 39 | var | `placement_epoch` (u64 varint) |
//! | | var | `size` (u64 varint) |
//! | | var | `stripe_config.size` (u64 varint) |
//! | | var | `stripe_config.k` (varint) |
//! | | var | `stripe_config.m` (varint) |
//! | | var + n | if bit0: filename length (varint, ≤ [`MAX_FILENAME_LEN`]) + UTF-8 bytes |
//! | | var + n | if bit1: content_type length (varint, ≤ [`MAX_CONTENT_TYPE_LEN`]) + UTF-8 bytes |
//! | | var | shard count |
//! | | per shard | `index` (varint) · `blob_hash` raw 32 bytes · if bit2: `holder_uid` (u32 varint, `u32::MAX` = unknown; 0 is a real UID) |
//!
//! No trailing bytes are allowed. Hex strings must be lowercase 64-char so
//! that `decode(encode(m)) == m` exactly (hex round-trips lowercase).
//! Size bound for a 30-shard manifest: [`MAX_ENCODED_LEN_30_SHARDS_WITH_HOLDERS`].

use crate::{FileManifest, ShardInfo, StripeConfig};

/// Leading 4 bytes of every binary manifest.
pub const MAGIC: [u8; 4] = *b"ARMF";
/// Current format version, byte 4.
pub const VERSION: u8 = 1;

const FLAG_FILENAME: u8 = 1 << 0;
const FLAG_CONTENT_TYPE: u8 = 1 << 1;
const FLAG_HOLDERS: u8 = 1 << 2;
const KNOWN_FLAGS: u8 = FLAG_FILENAME | FLAG_CONTENT_TYPE | FLAG_HOLDERS;

/// Format bound on `filename`, in UTF-8 bytes (`NAME_MAX` on every Linux
/// filesystem). The encoder REFUSES longer names (the write falls back to
/// legacy JSON, nothing is truncated); the decoder rejects them as corrupt.
pub const MAX_FILENAME_LEN: usize = 255;
/// Format bound on `content_type`, in UTF-8 bytes. RFC 6838 allows 127 per
/// type/subtype token; real media types are under 100 bytes.
pub const MAX_CONTENT_TYPE_LEN: usize = 128;
/// Sanity bound so a corrupt shard count cannot make the decoder allocate
/// blindly.
const MAX_SHARDS: u64 = 1 << 20;

/// Size of the largest 30-shard manifest with holders this format can
/// produce when every varint is at its widest and both strings at their
/// cap, shard indices 0..29:
///
/// ```text
/// 39                    magic 4 + version 1 + flags 1 + file_hash 32 + placement_version 1
/// + 5 × 10              placement_epoch, size, stripe_size, k, m as u64::MAX varints
/// + 2 + 255             filename (length varint + bytes)
/// + 2 + 128             content_type
/// + 1                   shard count
/// + 30 × (1 + 32 + 5)   index < 128, raw blob hash, holder uid u32::MAX
/// = 1617
/// ```
///
/// A row this size stays in the Postgres heap (TOAST threshold 2032 bytes
/// per tuple; the other `manifests` columns are ~150 bytes). The
/// representative fixture is 1153 bytes; see `thirty_shards_fit_in_line`.
/// Indices are not bounded by the format (a partial manifest can carry any
/// index): each index byte beyond the first adds 30 bytes to this figure.
pub const MAX_ENCODED_LEN_30_SHARDS_WITH_HOLDERS: usize = 1_617;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Error {
    /// Encoder: a hash field is not a lowercase 64-character hex string.
    NonCanonicalHash { field: &'static str, value: String },
    /// Encoder: `shard_holders` is neither empty nor `shards.len()` long.
    HolderCountMismatch { shards: usize, holders: usize },
    /// Encoder: a string longer than the format allows.
    StringTooLong { field: &'static str, len: usize },
    /// Decoder: magic bytes absent.
    BadMagic,
    /// Decoder: version byte not understood.
    UnsupportedVersion(u8),
    /// Decoder: reserved flag bits set.
    UnknownFlags(u8),
    /// Decoder: ran out of bytes.
    Truncated,
    /// Decoder: varint longer than 10 bytes / overflow.
    BadVarint,
    /// Decoder: length field over the sanity bound.
    LengthOutOfRange { field: &'static str, len: u64 },
    /// Decoder: string bytes are not UTF-8.
    InvalidUtf8(&'static str),
    /// Decoder: bytes remain after the last shard.
    TrailingBytes(usize),
    /// Decoder: a varint does not fit the target integer type.
    IntegerOverflow(&'static str),
}

impl std::fmt::Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Error::NonCanonicalHash { field, value } => {
                write!(f, "{field} is not lowercase 64-hex: {value:?}")
            }
            Error::HolderCountMismatch { shards, holders } => {
                write!(f, "shard_holders has {holders} entries for {shards} shards")
            }
            Error::StringTooLong { field, len } => write!(f, "{field} too long: {len} bytes"),
            Error::BadMagic => write!(f, "missing ARMF magic"),
            Error::UnsupportedVersion(v) => write!(f, "unsupported format version {v}"),
            Error::UnknownFlags(b) => write!(f, "unknown flag bits {b:#04x}"),
            Error::Truncated => write!(f, "truncated payload"),
            Error::BadVarint => write!(f, "malformed varint"),
            Error::LengthOutOfRange { field, len } => {
                write!(f, "{field} length {len} out of range")
            }
            Error::InvalidUtf8(field) => write!(f, "{field} is not utf-8"),
            Error::TrailingBytes(n) => write!(f, "{n} trailing bytes"),
            Error::IntegerOverflow(field) => write!(f, "{field} does not fit its type"),
        }
    }
}

impl std::error::Error for Error {}

// ---------------------------------------------------------------------------
// Encoder
// ---------------------------------------------------------------------------

fn put_varint(out: &mut Vec<u8>, mut v: u64) {
    loop {
        let byte = (v & 0x7f) as u8;
        v >>= 7;
        if v == 0 {
            out.push(byte);
            return;
        }
        out.push(byte | 0x80);
    }
}

fn canonical_hash(field: &'static str, value: &str) -> Result<[u8; 32], Error> {
    let err = || Error::NonCanonicalHash {
        field,
        value: value.to_string(),
    };
    if value.len() != 64 {
        return Err(err());
    }
    let raw = hex::decode(value).map_err(|_| err())?;
    // hex::encode is lowercase; anything else would not round-trip.
    if hex::encode(&raw) != value {
        return Err(err());
    }
    let mut out = [0u8; 32];
    out.copy_from_slice(&raw);
    Ok(out)
}

fn string_cap(field: &'static str) -> usize {
    match field {
        "filename" => MAX_FILENAME_LEN,
        "content_type" => MAX_CONTENT_TYPE_LEN,
        _ => unreachable!("unknown string field {field}"),
    }
}

fn put_string(out: &mut Vec<u8>, field: &'static str, s: &str) -> Result<(), Error> {
    if s.len() > string_cap(field) {
        return Err(Error::StringTooLong {
            field,
            len: s.len(),
        });
    }
    put_varint(out, s.len() as u64);
    out.extend_from_slice(s.as_bytes());
    Ok(())
}

/// Encode a manifest in binary v1. Deterministic: same input, same bytes.
pub fn encode(m: &FileManifest) -> Result<Vec<u8>, Error> {
    let file_hash = canonical_hash("file_hash", &m.file_hash)?;
    let with_holders = !m.shard_holders.is_empty();
    if with_holders && m.shard_holders.len() != m.shards.len() {
        return Err(Error::HolderCountMismatch {
            shards: m.shards.len(),
            holders: m.shard_holders.len(),
        });
    }
    if m.shards.len() as u64 > MAX_SHARDS {
        return Err(Error::LengthOutOfRange {
            field: "shards",
            len: m.shards.len() as u64,
        });
    }

    let mut flags = 0u8;
    if m.filename.is_some() {
        flags |= FLAG_FILENAME;
    }
    if m.content_type.is_some() {
        flags |= FLAG_CONTENT_TYPE;
    }
    if with_holders {
        flags |= FLAG_HOLDERS;
    }

    let mut out = Vec::with_capacity(64 + m.shards.len() * 36);
    out.extend_from_slice(&MAGIC);
    out.push(VERSION);
    out.push(flags);
    out.extend_from_slice(&file_hash);
    out.push(m.placement_version);
    put_varint(&mut out, m.placement_epoch);
    put_varint(&mut out, m.size);
    put_varint(&mut out, m.stripe_config.size);
    put_varint(&mut out, m.stripe_config.k as u64);
    put_varint(&mut out, m.stripe_config.m as u64);
    if let Some(name) = &m.filename {
        put_string(&mut out, "filename", name)?;
    }
    if let Some(ct) = &m.content_type {
        put_string(&mut out, "content_type", ct)?;
    }
    put_varint(&mut out, m.shards.len() as u64);
    for (i, shard) in m.shards.iter().enumerate() {
        put_varint(&mut out, shard.index as u64);
        out.extend_from_slice(&canonical_hash("blob_hash", &shard.blob_hash)?);
        if with_holders {
            put_varint(&mut out, u64::from(m.shard_holders[i]));
        }
    }
    Ok(out)
}

// ---------------------------------------------------------------------------
// Decoder
// ---------------------------------------------------------------------------

struct Reader<'a> {
    buf: &'a [u8],
    pos: usize,
}

impl<'a> Reader<'a> {
    fn take(&mut self, n: usize) -> Result<&'a [u8], Error> {
        let end = self.pos.checked_add(n).ok_or(Error::Truncated)?;
        if end > self.buf.len() {
            return Err(Error::Truncated);
        }
        let s = &self.buf[self.pos..end];
        self.pos = end;
        Ok(s)
    }

    fn u8(&mut self) -> Result<u8, Error> {
        Ok(self.take(1)?[0])
    }

    fn varint(&mut self) -> Result<u64, Error> {
        let mut result = 0u64;
        for i in 0..10 {
            let b = self.u8()?;
            let payload = u64::from(b & 0x7f);
            if i == 9 && payload > 1 {
                return Err(Error::BadVarint);
            }
            result |= payload << (7 * i);
            if b & 0x80 == 0 {
                return Ok(result);
            }
        }
        Err(Error::BadVarint)
    }

    fn hash_hex(&mut self) -> Result<String, Error> {
        Ok(hex::encode(self.take(32)?))
    }

    fn string(&mut self, field: &'static str) -> Result<String, Error> {
        let len = self.varint()?;
        if len > string_cap(field) as u64 {
            return Err(Error::LengthOutOfRange { field, len });
        }
        let bytes = self.take(len as usize)?;
        String::from_utf8(bytes.to_vec()).map_err(|_| Error::InvalidUtf8(field))
    }

    fn remaining(&self) -> usize {
        self.buf.len() - self.pos
    }
}

fn to_usize(field: &'static str, v: u64) -> Result<usize, Error> {
    usize::try_from(v).map_err(|_| Error::IntegerOverflow(field))
}

/// Decode a binary v1 manifest. Rejects anything that is not exactly one
/// well-formed payload (bad magic, unknown version or flags, truncation,
/// trailing bytes).
pub fn decode(bytes: &[u8]) -> Result<FileManifest, Error> {
    let mut r = Reader { buf: bytes, pos: 0 };
    if r.take(4)? != MAGIC {
        return Err(Error::BadMagic);
    }
    let version = r.u8()?;
    if version != VERSION {
        return Err(Error::UnsupportedVersion(version));
    }
    let flags = r.u8()?;
    if flags & !KNOWN_FLAGS != 0 {
        return Err(Error::UnknownFlags(flags));
    }
    let file_hash = r.hash_hex()?;
    let placement_version = r.u8()?;
    let placement_epoch = r.varint()?;
    let size = r.varint()?;
    let stripe_size = r.varint()?;
    let k = to_usize("stripe_config.k", r.varint()?)?;
    let m = to_usize("stripe_config.m", r.varint()?)?;
    let filename = if flags & FLAG_FILENAME != 0 {
        Some(r.string("filename")?)
    } else {
        None
    };
    let content_type = if flags & FLAG_CONTENT_TYPE != 0 {
        Some(r.string("content_type")?)
    } else {
        None
    };
    let count = r.varint()?;
    if count > MAX_SHARDS {
        return Err(Error::LengthOutOfRange {
            field: "shards",
            len: count,
        });
    }
    let count = count as usize;
    let with_holders = flags & FLAG_HOLDERS != 0;
    let mut shards = Vec::with_capacity(count);
    let mut shard_holders = Vec::with_capacity(if with_holders { count } else { 0 });
    for _ in 0..count {
        let index = to_usize("shard.index", r.varint()?)?;
        let blob_hash = r.hash_hex()?;
        shards.push(ShardInfo { index, blob_hash });
        if with_holders {
            let uid = r.varint()?;
            shard_holders
                .push(u32::try_from(uid).map_err(|_| Error::IntegerOverflow("holder_uid"))?);
        }
    }
    if r.remaining() != 0 {
        return Err(Error::TrailingBytes(r.remaining()));
    }
    Ok(FileManifest {
        file_hash,
        placement_version,
        placement_epoch,
        size,
        stripe_config: StripeConfig {
            size: stripe_size,
            k,
            m,
        },
        shards,
        filename,
        content_type,
        shard_holders,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use proptest::prelude::*;

    fn hex32(seed: u8) -> String {
        format!("{seed:02x}").repeat(32)
    }

    pub(super) fn thirty_shard_manifest(with_holders: bool) -> FileManifest {
        FileManifest {
            file_hash: hex32(0xab),
            placement_version: 3,
            placement_epoch: 54_126,
            size: 6 * 1024 * 1024 + 12_345,
            stripe_config: StripeConfig {
                size: 8 * 1024 * 1024,
                k: 10,
                m: 20,
            },
            shards: (0..30)
                .map(|i| ShardInfo {
                    index: i,
                    blob_hash: hex32(i as u8 + 1),
                })
                .collect(),
            filename: Some("quarterly-report-2026-Q3-final-v2.pdf".into()),
            content_type: Some("application/pdf".into()),
            shard_holders: if with_holders {
                (0..30).map(|i| 100 + i as u32 * 7).collect()
            } else {
                Vec::new()
            },
        }
    }

    fn assert_same(a: &FileManifest, b: &FileManifest) {
        assert_eq!(a.file_hash, b.file_hash);
        assert_eq!(a.placement_version, b.placement_version);
        assert_eq!(a.placement_epoch, b.placement_epoch);
        assert_eq!(a.size, b.size);
        assert_eq!(a.stripe_config.size, b.stripe_config.size);
        assert_eq!(a.stripe_config.k, b.stripe_config.k);
        assert_eq!(a.stripe_config.m, b.stripe_config.m);
        assert_eq!(a.shards.len(), b.shards.len());
        for (x, y) in a.shards.iter().zip(&b.shards) {
            assert_eq!(x.index, y.index);
            assert_eq!(x.blob_hash, y.blob_hash);
        }
        assert_eq!(a.filename, b.filename);
        assert_eq!(a.content_type, b.content_type);
        assert_eq!(a.shard_holders, b.shard_holders);
    }

    #[test]
    fn header_layout_is_pinned() {
        let m = thirty_shard_manifest(true);
        let b = encode(&m).unwrap();
        assert_eq!(&b[0..4], b"ARMF");
        assert_eq!(b[4], 1, "version");
        assert_eq!(b[5], FLAG_FILENAME | FLAG_CONTENT_TYPE | FLAG_HOLDERS);
        assert_eq!(hex::encode(&b[6..38]), m.file_hash);
        assert_eq!(b[38], 3, "placement_version");
        // 54126 = 0xD36E -> LEB128: 0xEE 0xA6 0x03
        assert_eq!(&b[39..42], &[0xEE, 0xA6, 0x03]);
    }

    #[test]
    fn thirty_shards_fit_in_line() {
        let with = encode(&thirty_shard_manifest(true)).unwrap();
        let without = encode(&thirty_shard_manifest(false)).unwrap();
        assert!(
            with.len() <= 1_300,
            "30-shard manifest with holders is {} bytes",
            with.len()
        );
        assert!(without.len() <= 1_300, "{} bytes", without.len());
        // The legacy encoding of the same manifest is what we are replacing.
        let json = thirty_shard_manifest(false).to_json().unwrap();
        assert!(
            json.len() > 2_032,
            "legacy is {} bytes (toasted)",
            json.len()
        );
    }

    /// The largest 30-shard manifest the encoder accepts: every varint at
    /// its widest, both strings at their cap, holders present.
    fn worst_case_thirty_shards() -> FileManifest {
        FileManifest {
            file_hash: hex32(0xff),
            placement_version: u8::MAX,
            placement_epoch: u64::MAX,
            size: u64::MAX,
            stripe_config: StripeConfig {
                size: u64::MAX,
                k: usize::MAX,
                m: usize::MAX,
            },
            shards: (0..30)
                .map(|i| ShardInfo {
                    index: i,
                    blob_hash: hex32(0xff),
                })
                .collect(),
            filename: Some("f".repeat(MAX_FILENAME_LEN)),
            content_type: Some("c".repeat(MAX_CONTENT_TYPE_LEN)),
            shard_holders: vec![u32::MAX; 30],
        }
    }

    #[test]
    fn thirty_shard_format_bound_is_exact() {
        let bytes = encode(&worst_case_thirty_shards()).unwrap();
        // The arithmetic in the constant's doc, term by term.
        let expected = 39
            + 5 * 10
            + (2 + MAX_FILENAME_LEN)
            + (2 + MAX_CONTENT_TYPE_LEN)
            + 1
            + 30 * (1 + 32 + 5);
        assert_eq!(expected, MAX_ENCODED_LEN_30_SHARDS_WITH_HOLDERS);
        assert_eq!(bytes.len(), MAX_ENCODED_LEN_30_SHARDS_WITH_HOLDERS);
        // And it round-trips: the widest values are representable.
        let d = decode(&bytes).unwrap();
        assert_same(&worst_case_thirty_shards(), &d);
        // Every other 30-shard manifest with indices 0..29 is no larger.
        assert!(
            encode(&thirty_shard_manifest(true)).unwrap().len()
                <= MAX_ENCODED_LEN_30_SHARDS_WITH_HOLDERS
        );
    }

    #[test]
    fn strings_over_the_cap_are_refused_not_truncated() {
        let mut m = thirty_shard_manifest(false);
        m.filename = Some("x".repeat(MAX_FILENAME_LEN + 1));
        assert_eq!(
            encode(&m).unwrap_err(),
            Error::StringTooLong {
                field: "filename",
                len: MAX_FILENAME_LEN + 1
            }
        );
        let mut m = thirty_shard_manifest(false);
        m.content_type = Some("y".repeat(MAX_CONTENT_TYPE_LEN + 1));
        assert_eq!(
            encode(&m).unwrap_err(),
            Error::StringTooLong {
                field: "content_type",
                len: MAX_CONTENT_TYPE_LEN + 1
            }
        );
        // Multi-byte UTF-8 counts in bytes, not chars: 128 × 'é' = 256 bytes.
        let mut m = thirty_shard_manifest(false);
        m.filename = Some("é".repeat(128));
        assert!(matches!(
            encode(&m),
            Err(Error::StringTooLong {
                field: "filename",
                ..
            })
        ));
        // Exactly at the cap encodes and round-trips unchanged.
        let mut m = thirty_shard_manifest(false);
        m.filename = Some("x".repeat(MAX_FILENAME_LEN));
        m.content_type = Some("y".repeat(MAX_CONTENT_TYPE_LEN));
        let d = decode(&encode(&m).unwrap()).unwrap();
        assert_same(&m, &d);
    }

    #[test]
    fn decoder_rejects_string_lengths_over_the_cap() {
        // Hand-build a payload whose filename length varint says 256.
        let mut v = Vec::new();
        v.extend_from_slice(&MAGIC);
        v.push(VERSION);
        v.push(FLAG_FILENAME);
        v.extend_from_slice(&[0u8; 32]);
        v.push(3);
        for _ in 0..5 {
            put_varint(&mut v, 1);
        }
        put_varint(&mut v, (MAX_FILENAME_LEN + 1) as u64);
        v.extend(std::iter::repeat_n(b'x', MAX_FILENAME_LEN + 1));
        put_varint(&mut v, 0);
        assert_eq!(
            decode(&v).unwrap_err(),
            Error::LengthOutOfRange {
                field: "filename",
                len: (MAX_FILENAME_LEN + 1) as u64
            }
        );
    }

    #[test]
    fn round_trip_fixed_cases() {
        for m in [
            thirty_shard_manifest(true),
            thirty_shard_manifest(false),
            FileManifest {
                shards: Vec::new(),
                filename: None,
                content_type: None,
                shard_holders: Vec::new(),
                ..thirty_shard_manifest(false)
            },
        ] {
            let b = encode(&m).unwrap();
            let d = decode(&b).unwrap();
            assert_same(&m, &d);
            assert_eq!(encode(&d).unwrap(), b, "deterministic");
        }
    }

    #[test]
    fn encoder_refuses_non_canonical_hashes_and_bad_holder_counts() {
        let mut m = thirty_shard_manifest(false);
        m.file_hash = "ABCD".repeat(16);
        assert!(matches!(
            encode(&m),
            Err(Error::NonCanonicalHash {
                field: "file_hash",
                ..
            })
        ));
        let mut m = thirty_shard_manifest(false);
        m.shards[3].blob_hash = "shard3".into();
        assert!(matches!(
            encode(&m),
            Err(Error::NonCanonicalHash {
                field: "blob_hash",
                ..
            })
        ));
        let mut m = thirty_shard_manifest(false);
        m.shard_holders = vec![1, 2];
        assert_eq!(
            encode(&m).unwrap_err(),
            Error::HolderCountMismatch {
                shards: 30,
                holders: 2
            }
        );
    }

    #[test]
    fn decoder_rejects_malformed_payloads() {
        let good = encode(&thirty_shard_manifest(true)).unwrap();
        assert_eq!(decode(b"{\"x\":1}").unwrap_err(), Error::BadMagic);
        assert_eq!(decode(b"ARM").unwrap_err(), Error::Truncated);
        let mut v = good.clone();
        v[4] = 2;
        assert_eq!(decode(&v).unwrap_err(), Error::UnsupportedVersion(2));
        let mut v = good.clone();
        v[5] |= 0x80;
        assert_eq!(decode(&v).unwrap_err(), Error::UnknownFlags(v[5]));
        for cut in [5usize, 37, 40, 60, good.len() - 1] {
            assert_eq!(
                decode(&good[..cut]).unwrap_err(),
                Error::Truncated,
                "cut at {cut}"
            );
        }
        let mut v = good.clone();
        v.push(0);
        assert_eq!(decode(&v).unwrap_err(), Error::TrailingBytes(1));
        // 11-byte continuation run is not a varint
        let mut v = good[..39].to_vec();
        v.extend_from_slice(&[0xff; 11]);
        assert_eq!(decode(&v).unwrap_err(), Error::BadVarint);
    }

    fn arb_hex32() -> impl Strategy<Value = String> {
        proptest::array::uniform32(any::<u8>()).prop_map(hex::encode)
    }

    fn arb_manifest() -> impl Strategy<Value = FileManifest> {
        (
            arb_hex32(),
            any::<u8>(),
            any::<u64>(),
            any::<u64>(),
            (any::<u64>(), 0usize..=255, 0usize..=255),
            proptest::collection::vec((any::<u32>(), arb_hex32()), 0..=40),
            // ≤ 60 chars × 4 bytes stays under MAX_FILENAME_LEN.
            proptest::option::of(".{0,60}"),
            proptest::option::of("[a-z/+.-]{0,40}"),
            any::<bool>(),
        )
            .prop_map(
                |(
                    file_hash,
                    placement_version,
                    placement_epoch,
                    size,
                    (ssize, k, m),
                    shard_seed,
                    filename,
                    content_type,
                    with_holders,
                )| {
                    // Indices are arbitrary and may have gaps or be out of
                    // order: the format stores them explicitly.
                    let shards: Vec<ShardInfo> = shard_seed
                        .iter()
                        .map(|(idx, h)| ShardInfo {
                            index: *idx as usize,
                            blob_hash: h.clone(),
                        })
                        .collect();
                    let shard_holders = if with_holders {
                        shards
                            .iter()
                            .enumerate()
                            .map(|(i, _)| (i as u32).wrapping_mul(2_654_435_761))
                            .collect()
                    } else {
                        Vec::new()
                    };
                    FileManifest {
                        file_hash,
                        placement_version,
                        placement_epoch,
                        size,
                        stripe_config: StripeConfig { size: ssize, k, m },
                        shards,
                        filename,
                        content_type,
                        shard_holders,
                    }
                },
            )
    }

    proptest! {
        #![proptest_config(ProptestConfig::with_cases(512))]

        #[test]
        fn round_trip_random_manifests(m in arb_manifest()) {
            let b = encode(&m).unwrap();
            let d = decode(&b).unwrap();
            assert_same(&m, &d);
            prop_assert_eq!(encode(&d).unwrap(), b);
            // The legacy encoding of the decoded value equals that of the
            // input: the binary form loses nothing the JSON form carries.
            prop_assert_eq!(d.to_json().unwrap(), m.to_json().unwrap());
        }

        #[test]
        fn random_bytes_never_panic(bytes in proptest::collection::vec(any::<u8>(), 0..300)) {
            let _ = decode(&bytes);
            let mut with_magic = MAGIC.to_vec();
            with_magic.push(VERSION);
            with_magic.extend_from_slice(&bytes);
            let _ = decode(&with_magic);
        }

        #[test]
        fn varint_round_trip(v in any::<u64>()) {
            let mut out = Vec::new();
            put_varint(&mut out, v);
            let mut r = Reader { buf: &out, pos: 0 };
            prop_assert_eq!(r.varint().unwrap(), v);
            prop_assert_eq!(r.remaining(), 0);
        }
    }
}

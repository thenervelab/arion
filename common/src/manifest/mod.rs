//! Stored-manifest encodings and the dual-read entry point.
//!
//! Two encodings of [`FileManifest`] exist on disk:
//!
//! * **legacy** — the `serde_json` text produced by [`FileManifest::to_json`]
//!   (2–3 KiB for a 30-shard file, always TOASTed in Postgres);
//! * **binary v1** — the compact layout in [`binary`] (≈ 1.1 KiB for 30
//!   shards, stays in-line).
//!
//! Every reader goes through [`decode_any`], which sniffs the leading bytes:
//! the 4-byte magic selects the binary decoder, anything else is handed to the
//! legacy JSON decoder unchanged. Rows written before this module existed
//! therefore decode exactly as before.

pub mod binary;

use crate::FileManifest;
use std::borrow::Cow;

/// Why stored manifest bytes could not be turned into a [`FileManifest`].
#[derive(Debug)]
pub enum DecodeError {
    /// The bytes are the `"DELETED"` tombstone marker, not a manifest.
    Tombstone,
    /// Binary magic matched but the payload is malformed.
    Binary(binary::Error),
    /// No magic: legacy JSON decoding failed.
    Json(serde_json::Error),
}

impl std::fmt::Display for DecodeError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            DecodeError::Tombstone => write!(f, "manifest bytes are a tombstone"),
            DecodeError::Binary(e) => write!(f, "binary manifest: {e}"),
            DecodeError::Json(e) => write!(f, "legacy json manifest: {e}"),
        }
    }
}

impl std::error::Error for DecodeError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            DecodeError::Tombstone => None,
            DecodeError::Binary(e) => Some(e),
            DecodeError::Json(e) => Some(e),
        }
    }
}

/// Which encoding a stored payload uses, decided from its leading bytes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Encoding {
    Binary,
    Legacy,
}

/// Sniff the encoding of stored manifest bytes. Cheap: compares 4 bytes.
pub fn sniff(bytes: &[u8]) -> Encoding {
    if bytes.starts_with(&binary::MAGIC) {
        Encoding::Binary
    } else {
        Encoding::Legacy
    }
}

/// Decode stored manifest bytes whatever their encoding.
///
/// Binary payloads (magic `ARMF`) go to [`binary::decode`]; everything else
/// is the legacy JSON path, byte-for-byte the same call as before this
/// module existed (`serde_json::from_slice::<FileManifest>`). The
/// `"DELETED"` tombstone marker is reported as [`DecodeError::Tombstone`]
/// instead of a JSON syntax error so callers can tell the two apart.
pub fn decode_any(bytes: &[u8]) -> Result<FileManifest, DecodeError> {
    match sniff(bytes) {
        Encoding::Binary => binary::decode(bytes).map_err(DecodeError::Binary),
        Encoding::Legacy => {
            if bytes == crate::MANIFEST_TOMBSTONE.as_bytes() {
                return Err(DecodeError::Tombstone);
            }
            serde_json::from_slice::<FileManifest>(bytes).map_err(DecodeError::Json)
        }
    }
}

/// Convenience for callers holding text (the in-memory manifest cache).
pub fn decode_any_str(text: &str) -> Result<FileManifest, DecodeError> {
    decode_any(text.as_bytes())
}

/// Return the legacy JSON encoding of stored manifest bytes.
///
/// Legacy bytes are returned as-is (no copy, no re-serialisation: the
/// bytes a client sees are the bytes stored). A binary payload is decoded
/// and re-serialised with [`FileManifest::to_json`]. Used at the transport
/// boundaries that ship the stored payload verbatim to peers that only
/// speak JSON (HTTP `GET /manifest/:hash`, P2P `QueryManifest`).
pub fn to_json_bytes(bytes: &[u8]) -> Result<Cow<'_, [u8]>, DecodeError> {
    match sniff(bytes) {
        Encoding::Legacy => Ok(Cow::Borrowed(bytes)),
        Encoding::Binary => {
            let manifest = binary::decode(bytes).map_err(DecodeError::Binary)?;
            let json = manifest.to_json().map_err(DecodeError::Json)?;
            Ok(Cow::Owned(json.into_bytes()))
        }
    }
}

/// Environment variable that selects the encoding of NEW manifest writes.
/// `1` / `true` (case-insensitive) = binary v1; anything else, or unset, =
/// legacy JSON. Read once per process (see [`binary_write_enabled`]).
pub const BINARY_WRITE_ENV: &str = "ARION_MANIFEST_BINARY_WRITE";

/// Which encoding new writes use. Off unless the flag is set: every reader
/// already accepts both, so flipping it is a write-side decision only.
pub fn binary_write_enabled() -> bool {
    static FLAG: std::sync::OnceLock<bool> = std::sync::OnceLock::new();
    *FLAG.get_or_init(|| {
        std::env::var(BINARY_WRITE_ENV)
            .map(|v| {
                let v = v.trim();
                v == "1" || v.eq_ignore_ascii_case("true")
            })
            .unwrap_or(false)
    })
}

/// Bytes to store for `manifest`: binary v1 when `binary` is set, else the
/// legacy JSON. A manifest the binary encoder refuses (a non-canonical hash,
/// a holder vector of the wrong length) is stored as legacy JSON rather than
/// failing the write, and the fallback is logged once per call.
pub fn encode_for_store(
    manifest: &FileManifest,
    binary: bool,
) -> Result<Vec<u8>, serde_json::Error> {
    if binary {
        match binary::encode(manifest) {
            Ok(bytes) => return Ok(bytes),
            Err(e) => tracing::warn!(
                file_hash = %manifest.file_hash,
                error = %e,
                "binary manifest encoding refused; storing legacy JSON"
            ),
        }
    }
    manifest.to_json().map(String::into_bytes)
}

/// Bytes to store when the caller already holds `json = manifest.to_json()`
/// (the merge path needs the JSON anyway, for caches and mirrors). With
/// `binary` off the JSON bytes are BORROWED: no second serialisation, no
/// allocation, the stored bytes are the very buffer the caller holds. With
/// `binary` on, binary v1; when the encoder refuses (non-canonical hash,
/// holder vector of the wrong length) the same borrowed JSON, logged.
pub fn encode_for_store_with_json<'a>(
    manifest: &FileManifest,
    json: &'a str,
    binary: bool,
) -> Cow<'a, [u8]> {
    if binary {
        match binary::encode(manifest) {
            Ok(bytes) => return Cow::Owned(bytes),
            Err(e) => tracing::warn!(
                file_hash = %manifest.file_hash,
                error = %e,
                "binary manifest encoding refused; storing legacy JSON"
            ),
        }
    }
    Cow::Borrowed(json.as_bytes())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{ShardInfo, StripeConfig};

    #[test]
    fn encode_for_store_selects_encoding_and_falls_back_on_refusal() {
        let m = sample();
        let legacy = encode_for_store(&m, false).unwrap();
        assert_eq!(sniff(&legacy), Encoding::Legacy);
        assert_eq!(legacy, m.to_json().unwrap().into_bytes());
        let bin = encode_for_store(&m, true).unwrap();
        assert_eq!(sniff(&bin), Encoding::Binary);
        assert!(
            bin.len() < legacy.len() / 2,
            "{} vs {}",
            bin.len(),
            legacy.len()
        );
        assert_eq!(
            decode_any(&bin).unwrap().to_json().unwrap(),
            m.to_json().unwrap()
        );
        assert_eq!(
            decode_any(&legacy).unwrap().to_json().unwrap(),
            m.to_json().unwrap()
        );
        // A non-canonical hash cannot be encoded in binary: the write still
        // happens, as legacy JSON.
        let mut odd = m.clone();
        odd.shards[0].blob_hash = "not-a-hash".into();
        let stored = encode_for_store(&odd, true).unwrap();
        assert_eq!(sniff(&stored), Encoding::Legacy);
        assert_eq!(
            decode_any(&stored).unwrap().to_json().unwrap(),
            odd.to_json().unwrap()
        );
    }

    #[test]
    fn encode_for_store_with_json_borrows_the_json_when_binary_is_off() {
        let m = sample();
        let json = m.to_json().unwrap();
        // Flag off: the stored bytes ARE the caller's JSON buffer. Pointer
        // identity proves there was no second serialisation and no copy.
        let off = encode_for_store_with_json(&m, &json, false);
        assert!(matches!(off, Cow::Borrowed(_)));
        assert!(std::ptr::eq(off.as_ptr(), json.as_ptr()));
        assert_eq!(off.len(), json.len());
        assert_eq!(&*off, encode_for_store(&m, false).unwrap().as_slice());

        // Flag on: binary bytes, owned.
        let on = encode_for_store_with_json(&m, &json, true);
        assert!(matches!(on, Cow::Owned(_)));
        assert_eq!(sniff(&on), Encoding::Binary);
        assert_eq!(&*on, encode_for_store(&m, true).unwrap().as_slice());

        // Flag on but refused: back to the borrowed JSON, still no copy.
        let mut odd = m.clone();
        odd.shards[0].blob_hash = "not-a-hash".into();
        let odd_json = odd.to_json().unwrap();
        let refused = encode_for_store_with_json(&odd, &odd_json, true);
        assert!(matches!(refused, Cow::Borrowed(_)));
        assert!(std::ptr::eq(refused.as_ptr(), odd_json.as_ptr()));
    }

    fn sample() -> FileManifest {
        FileManifest {
            file_hash: "ab".repeat(32),
            placement_version: 3,
            placement_epoch: 54126,
            size: 1_048_576,
            stripe_config: StripeConfig {
                size: 8 * 1024 * 1024,
                k: 10,
                m: 20,
            },
            shards: (0..30)
                .map(|i| ShardInfo {
                    index: i,
                    blob_hash: format!("{:02x}", i).repeat(32),
                })
                .collect(),
            filename: Some("file.bin".into()),
            content_type: Some("application/octet-stream".into()),
            shard_holders: Vec::new(),
        }
    }

    #[test]
    fn legacy_json_decodes_unchanged() {
        let m = sample();
        let json = m.to_json().unwrap();
        let d = decode_any(json.as_bytes()).unwrap();
        assert_eq!(d.to_json().unwrap(), json);
        assert!(
            d.shard_holders.is_empty(),
            "legacy decode fills unknown holders"
        );
        assert_eq!(sniff(json.as_bytes()), Encoding::Legacy);
    }

    #[test]
    fn binary_decodes_through_decode_any() {
        let m = sample();
        let bytes = binary::encode(&m).unwrap();
        assert_eq!(sniff(&bytes), Encoding::Binary);
        let d = decode_any(&bytes).unwrap();
        assert_eq!(d.to_json().unwrap(), m.to_json().unwrap());
    }

    #[test]
    fn tombstone_is_reported_as_such() {
        match decode_any(crate::MANIFEST_TOMBSTONE.as_bytes()) {
            Err(DecodeError::Tombstone) => {}
            other => panic!("expected Tombstone, got {other:?}"),
        }
    }

    #[test]
    fn garbage_is_a_json_error_not_a_panic() {
        assert!(matches!(
            decode_any(b"\x00\x01ARION-v2\xff\xfe not json"),
            Err(DecodeError::Json(_))
        ));
        assert!(matches!(decode_any(b""), Err(DecodeError::Json(_))));
    }

    #[test]
    fn to_json_bytes_is_identity_on_legacy_and_canonical_on_binary() {
        let m = sample();
        let json = m.to_json().unwrap();
        let out = to_json_bytes(json.as_bytes()).unwrap();
        assert!(matches!(out, Cow::Borrowed(_)));
        assert_eq!(&*out, json.as_bytes());

        let bin = binary::encode(&m).unwrap();
        let out = to_json_bytes(&bin).unwrap();
        assert_eq!(&*out, json.as_bytes());
    }

    #[test]
    fn legacy_json_omits_empty_holders_and_accepts_present_ones() {
        let mut m = sample();
        let json = m.to_json().unwrap();
        assert!(!json.contains("shard_holders"));
        m.shard_holders = vec![7; 30];
        let json = m.to_json().unwrap();
        assert!(json.contains("\"shard_holders\""));
        let d = decode_any(json.as_bytes()).unwrap();
        assert_eq!(d.shard_holders, vec![7; 30]);
    }
}

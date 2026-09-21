//! Wire format of the per-PG obligation lists (`APGL` version 3).
//!
//! The list writer (`pg-lists`) and the miner reader share this codec so
//! the two can never drift on a byte offset. A list is one 32-byte header
//! followed by `count` 40-byte records, one record per **shard** of every
//! file placed in the PG, each naming the miner that holds it. Neither
//! version 1 (one record per blob hash, `shard_length` as u64) nor
//! version 2 (per shard, holder recomputed by the reader) was ever
//! published; version 3 replaces both and a reader refuses any other
//! version.
//!
//! ## Header (32 bytes)
//!
//! | offset | size | field |
//! |-------:|-----:|-------|
//! |  0 | 4 | magic `APGL` |
//! |  4 | 1 | version = 3 |
//! |  5 | 3 | reserved, zero |
//! |  8 | 4 | `pg_id` u32 LE |
//! | 12 | 8 | `generation` u64 LE |
//! | 20 | 4 | `count` u32 LE (records) |
//! | 24 | 1 | `ec_k` |
//! | 25 | 1 | `ec_m` |
//! | 26 | 2 | reserved, zero |
//! | 28 | 4 | `flags` u32 LE, must be zero |
//!
//! ## Record (40 bytes)
//!
//! | offset | size | field |
//! |-------:|-----:|-------|
//! |  0 | 32 | `blob_hash` (blake3 of the shard) |
//! | 32 |  4 | `shard_length` u32 LE |
//! | 36 |  4 | `holder_uid` u32 LE (the miner the write path placed this shard on) |
//!
//! `shard_length` fits a u32: a shard is at most one stripe (8 MiB by
//! default, bounded by the gateway's request body limit) divided by `k`.
//!
//! ## Holder
//!
//! The **writer** resolves the holder of every shard with the write
//! path's own function, [`crate::calculate_stripe_placement`] on the
//! draining-filtered map, and stores its UID. The reader computes
//! nothing: a miner keeps the records whose `holder_uid` is its own UID
//! and treats any other blob as not its obligation, even when the blob is
//! listed for a PG it owns (the shard sits on another holder of the same
//! PG). Version 2 had the reader recompute the holder from the PG
//! placement; the writer and the reader fed different maps (filtered vs
//! raw) to the same formula and attributed shards to the wrong miner.
//! Carrying the UID removes that class of bug: there is one placement
//! computation and it is the writer's.
//!
//! ## Order
//!
//! Records are sorted by `(blob_hash, holder_uid)`, strictly ascending
//! (no exact duplicate). The same blob hash may appear more than once
//! (identical shard content in several files or stripes: zero-filled
//! shards, repeated data; or one blob placed on several holders) but
//! always with the same `shard_length`; a conflicting length is a
//! malformed list.
//!
//! ## Tombstones (`APGD`)
//!
//! Next to `pg/<N>.list` a generation publishes `pg/<N>.deleted`: the
//! blob hashes of every shard of every manifest of the PG deleted since
//! the previous generation's scan started. Same 32-byte header with
//! magic [`TOMBSTONE_MAGIC`] instead of [`MAGIC`] (so a reader can never
//! take one file for the other), then `count` records of 32 bytes each,
//! the bare blob hash, strictly ascending. A hash that also appears in
//! the `.list` of the same generation is never written to the `.deleted`
//! (the list wins: the blob is still obliged through another file).

use std::cmp::Ordering;

use anyhow::{Context, Result, bail, ensure};

/// Magic at the start of every list file.
pub const MAGIC: &[u8; 4] = b"APGL";
/// Magic at the start of every tombstone (`.deleted`) file.
pub const TOMBSTONE_MAGIC: &[u8; 4] = b"APGD";
/// The only list format version this codec reads or writes.
pub const VERSION: u8 = 3;
/// Fixed header length in bytes.
pub const HEADER_LEN: usize = 32;
/// Length of one record in bytes.
pub const RECORD_LEN: usize = 40;
/// Length of one tombstone record (a bare blob hash) in bytes.
pub const TOMBSTONE_RECORD_LEN: usize = 32;

/// Decoded list header.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Header {
    pub pg_id: u32,
    pub generation: u64,
    pub count: u32,
    pub ec_k: u8,
    pub ec_m: u8,
    pub flags: u32,
}

impl Header {
    /// Encode, refusing invalid EC parameters and non-zero flags.
    pub fn encode(&self) -> Result<[u8; HEADER_LEN]> {
        self.encode_with_magic(MAGIC)
    }

    /// Encode as a tombstone (`.deleted`) header: [`TOMBSTONE_MAGIC`],
    /// otherwise identical to [`Header::encode`].
    pub fn encode_tombstone(&self) -> Result<[u8; HEADER_LEN]> {
        self.encode_with_magic(TOMBSTONE_MAGIC)
    }

    fn encode_with_magic(&self, magic: &[u8; 4]) -> Result<[u8; HEADER_LEN]> {
        validate_ec(self.ec_k, self.ec_m)?;
        ensure!(self.flags == 0, "unknown list flags {:#x}", self.flags);
        let mut bytes = [0u8; HEADER_LEN];
        bytes[..4].copy_from_slice(magic);
        bytes[4] = VERSION;
        bytes[8..12].copy_from_slice(&self.pg_id.to_le_bytes());
        bytes[12..20].copy_from_slice(&self.generation.to_le_bytes());
        bytes[20..24].copy_from_slice(&self.count.to_le_bytes());
        bytes[24] = self.ec_k;
        bytes[25] = self.ec_m;
        bytes[28..32].copy_from_slice(&self.flags.to_le_bytes());
        Ok(bytes)
    }

    /// Decode the header at the start of `bytes` (longer input is fine).
    /// Fails closed on any version other than [`VERSION`], on a bad
    /// magic, non-zero reserved bytes, non-zero flags or invalid EC.
    pub fn decode(bytes: &[u8]) -> Result<Self> {
        Self::decode_with_magic(bytes, MAGIC, "list")
    }

    /// Decode a tombstone (`.deleted`) header. A `.list` header is
    /// refused here exactly as a `.deleted` header is refused by
    /// [`Header::decode`].
    pub fn decode_tombstone(bytes: &[u8]) -> Result<Self> {
        Self::decode_with_magic(bytes, TOMBSTONE_MAGIC, "tombstone")
    }

    fn decode_with_magic(bytes: &[u8], magic: &[u8; 4], what: &str) -> Result<Self> {
        ensure!(
            bytes.len() >= HEADER_LEN,
            "{what} too short for header: {} bytes",
            bytes.len()
        );
        ensure!(&bytes[..4] == magic, "bad {what} magic {:?}", &bytes[..4]);
        let version = bytes[4];
        ensure!(
            version == VERSION,
            "unsupported list version {version} (this reader understands version {VERSION} only)"
        );
        ensure!(
            bytes[5..8] == [0; 3] && bytes[26..28] == [0; 2],
            "nonzero reserved header bytes"
        );
        let header = Self {
            pg_id: u32::from_le_bytes(bytes[8..12].try_into().unwrap()),
            generation: u64::from_le_bytes(bytes[12..20].try_into().unwrap()),
            count: u32::from_le_bytes(bytes[20..24].try_into().unwrap()),
            ec_k: bytes[24],
            ec_m: bytes[25],
            flags: u32::from_le_bytes(bytes[28..32].try_into().unwrap()),
        };
        // Re-encoding applies the EC and flags rules.
        header.encode()?;
        Ok(header)
    }

    /// Shards per stripe, `ec_k + ec_m`.
    pub fn shards_per_stripe(&self) -> usize {
        usize::from(self.ec_k) + usize::from(self.ec_m)
    }

    /// Exact byte length of a list with this header.
    pub fn list_len(&self) -> Result<usize> {
        usize::try_from(self.count)?
            .checked_mul(RECORD_LEN)
            .and_then(|n| n.checked_add(HEADER_LEN))
            .context("list length overflow")
    }

    /// Exact byte length of a tombstone file with this header.
    pub fn tombstone_len(&self) -> Result<usize> {
        usize::try_from(self.count)?
            .checked_mul(TOMBSTONE_RECORD_LEN)
            .and_then(|n| n.checked_add(HEADER_LEN))
            .context("tombstone length overflow")
    }
}

/// One shard obligation: this blob, of this length, is held by this miner.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct Record {
    pub blob_hash: [u8; 32],
    pub shard_length: u32,
    /// UID of the miner the write path placed the shard on.
    pub holder_uid: u32,
}

impl Record {
    pub fn encode(&self) -> [u8; RECORD_LEN] {
        let mut bytes = [0u8; RECORD_LEN];
        bytes[..32].copy_from_slice(&self.blob_hash);
        bytes[32..36].copy_from_slice(&self.shard_length.to_le_bytes());
        bytes[36..40].copy_from_slice(&self.holder_uid.to_le_bytes());
        bytes
    }

    /// Decode exactly one record.
    pub fn decode(bytes: &[u8]) -> Result<Self> {
        ensure!(
            bytes.len() == RECORD_LEN,
            "record must be exactly {RECORD_LEN} bytes, got {}",
            bytes.len()
        );
        Ok(Self {
            blob_hash: bytes[..32].try_into().unwrap(),
            shard_length: u32::from_le_bytes(bytes[32..36].try_into().unwrap()),
            holder_uid: u32::from_le_bytes(bytes[36..40].try_into().unwrap()),
        })
    }

    /// Sort key: hash first, then holder.
    pub fn key(&self) -> ([u8; 32], u32) {
        (self.blob_hash, self.holder_uid)
    }

    /// Order used by the list files.
    pub fn cmp_key(&self, other: &Self) -> Ordering {
        self.key().cmp(&other.key())
    }

    /// Whether this record is `miner_uid`'s obligation. This is the
    /// reader's entire holder filter.
    pub fn is_held_by(&self, miner_uid: u32) -> bool {
        self.holder_uid == miner_uid
    }
}

/// Placement versions whose holder is derived from a PG placement
/// (2 = PG + weighted, 3 = PG + straw2). The writer only lists files
/// with one of these versions.
pub fn is_pg_placement_version(version: u8) -> bool {
    matches!(version, 2 | 3)
}

fn validate_ec(k: u8, m: u8) -> Result<()> {
    ensure!(
        k > 0 && m > 0 && u16::from(k) + u16::from(m) <= 256,
        "invalid EC parameters {k}+{m}"
    );
    Ok(())
}

/// Sort `records` into list order, drop exact duplicates, refuse two
/// lengths for one blob hash.
pub fn normalize_records(records: &mut Vec<Record>) -> Result<()> {
    records.sort_unstable_by(Record::cmp_key);
    records.dedup();
    validate_record_order(records)
}

/// Strictly ascending by [`Record::key`], one length per blob hash.
pub fn validate_record_order(records: &[Record]) -> Result<()> {
    for (i, pair) in records.windows(2).enumerate() {
        ensure!(
            pair[0].cmp_key(&pair[1]) == Ordering::Less,
            "records not strictly sorted at record {}",
            i + 1
        );
        ensure!(
            pair[0].blob_hash != pair[1].blob_hash || pair[0].shard_length == pair[1].shard_length,
            "conflicting lengths for one blob hash at record {}",
            i + 1
        );
    }
    Ok(())
}

/// Encode a complete list. `header.count` must equal `records.len()`;
/// the records must already be in list order (see [`normalize_records`]).
pub fn encode_list(header: &Header, records: &[Record]) -> Result<Vec<u8>> {
    let head = header.encode()?;
    ensure!(
        usize::try_from(header.count)? == records.len(),
        "header count {} but {} records",
        header.count,
        records.len()
    );
    validate_record_order(records)?;
    let mut out = Vec::with_capacity(header.list_len()?);
    out.extend_from_slice(&head);
    for record in records {
        out.extend_from_slice(&record.encode());
    }
    Ok(out)
}

/// Decode and validate a whole list, handing every record in file order
/// to `visit`. Checks the header, the exact body length for `count`, the
/// strict order and the one-length-per-hash rule. Streams: nothing but
/// the header is kept.
pub fn visit_list(bytes: &[u8], visit: &mut dyn FnMut(&Record)) -> Result<Header> {
    let header = Header::decode(bytes)?;
    let expected = header.list_len()?;
    ensure!(
        bytes.len() == expected,
        "list declares {} records ({expected} bytes) but is {} bytes",
        header.count,
        bytes.len()
    );
    let mut previous: Option<Record> = None;
    let (records, _) = bytes[HEADER_LEN..].as_chunks::<RECORD_LEN>();
    for (i, chunk) in records.iter().enumerate() {
        let record = Record::decode(chunk)?;
        if let Some(prev) = previous {
            if prev.cmp_key(&record) != Ordering::Less {
                bail!("records not strictly sorted at record {i}");
            }
            if prev.blob_hash == record.blob_hash && prev.shard_length != record.shard_length {
                bail!("conflicting lengths for one blob hash at record {i}");
            }
        }
        previous = Some(record);
        visit(&record);
    }
    Ok(header)
}

/// [`visit_list`] collecting the records.
pub fn decode_list(bytes: &[u8]) -> Result<(Header, Vec<Record>)> {
    let mut records = Vec::new();
    let header = Header::decode(bytes)?;
    records.reserve_exact(usize::try_from(header.count)?.min(bytes.len() / RECORD_LEN));
    let header = visit_list(bytes, &mut |r| records.push(*r))?;
    Ok((header, records))
}

// ============================================================================
// Tombstones
// ============================================================================

/// Sort `hashes` into tombstone order and drop duplicates.
pub fn normalize_hashes(hashes: &mut Vec<[u8; 32]>) {
    hashes.sort_unstable();
    hashes.dedup();
}

/// Strictly ascending, no duplicate.
pub fn validate_hash_order(hashes: &[[u8; 32]]) -> Result<()> {
    for (i, pair) in hashes.windows(2).enumerate() {
        ensure!(
            pair[0] < pair[1],
            "tombstones not strictly sorted at record {}",
            i + 1
        );
    }
    Ok(())
}

/// Encode a complete tombstone file. `header.count` must equal
/// `hashes.len()`; the hashes must already be in order (see
/// [`normalize_hashes`]).
pub fn encode_tombstones(header: &Header, hashes: &[[u8; 32]]) -> Result<Vec<u8>> {
    let head = header.encode_tombstone()?;
    ensure!(
        usize::try_from(header.count)? == hashes.len(),
        "header count {} but {} tombstones",
        header.count,
        hashes.len()
    );
    validate_hash_order(hashes)?;
    let mut out = Vec::with_capacity(header.tombstone_len()?);
    out.extend_from_slice(&head);
    for hash in hashes {
        out.extend_from_slice(hash);
    }
    Ok(out)
}

/// Decode and validate a whole tombstone file, handing every hash in
/// file order to `visit`. Checks the tombstone header (a `.list` is
/// refused), the exact body length for `count` and the strict order.
pub fn visit_tombstones(bytes: &[u8], visit: &mut dyn FnMut(&[u8; 32])) -> Result<Header> {
    let header = Header::decode_tombstone(bytes)?;
    let expected = header.tombstone_len()?;
    ensure!(
        bytes.len() == expected,
        "tombstone file declares {} records ({expected} bytes) but is {} bytes",
        header.count,
        bytes.len()
    );
    let mut previous: Option<[u8; 32]> = None;
    let (hashes, _) = bytes[HEADER_LEN..].as_chunks::<TOMBSTONE_RECORD_LEN>();
    for (i, chunk) in hashes.iter().enumerate() {
        let hash: [u8; 32] = *chunk;
        if previous.is_some_and(|prev| prev >= hash) {
            bail!("tombstones not strictly sorted at record {i}");
        }
        previous = Some(hash);
        visit(&hash);
    }
    Ok(header)
}

/// [`visit_tombstones`] collecting the hashes.
pub fn decode_tombstones(bytes: &[u8]) -> Result<(Header, Vec<[u8; 32]>)> {
    let mut hashes = Vec::new();
    let header = Header::decode_tombstone(bytes)?;
    hashes.reserve_exact(usize::try_from(header.count)?.min(bytes.len() / TOMBSTONE_RECORD_LEN));
    let header = visit_tombstones(bytes, &mut |h| hashes.push(*h))?;
    Ok((header, hashes))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn header(count: u32) -> Header {
        Header {
            pg_id: 0x1234_5678,
            generation: 0x0102_0304_0506_0708,
            count,
            ec_k: 10,
            ec_m: 20,
            flags: 0,
        }
    }

    fn record(byte: u8, holder_uid: u32) -> Record {
        Record {
            blob_hash: [byte; 32],
            shard_length: 0x000A_0B0C,
            holder_uid,
        }
    }

    #[test]
    fn header_exact_offsets_and_roundtrip() {
        let h = header(0x1122_3344);
        let expected = [
            b'A', b'P', b'G', b'L', 3, 0, 0, 0, 0x78, 0x56, 0x34, 0x12, 8, 7, 6, 5, 4, 3, 2, 1,
            0x44, 0x33, 0x22, 0x11, 10, 20, 0, 0, 0, 0, 0, 0,
        ];
        assert_eq!(h.encode().unwrap(), expected);
        assert_eq!(Header::decode(&expected).unwrap(), h);
        assert_eq!(h.shards_per_stripe(), 30);
    }

    #[test]
    fn record_exact_offsets_and_roundtrip() {
        let r = Record {
            blob_hash: [0xab; 32],
            shard_length: 0x0102_0304,
            holder_uid: 0x0DB3_2E15,
        };
        let bytes = r.encode();
        assert_eq!(&bytes[..32], &[0xab; 32]);
        assert_eq!(&bytes[32..36], &[4, 3, 2, 1], "shard_length u32 LE");
        assert_eq!(
            &bytes[36..40],
            &[0x15, 0x2e, 0xb3, 0x0d],
            "holder_uid u32 LE"
        );
        assert_eq!(Record::decode(&bytes).unwrap(), r);
        assert_eq!(bytes.len(), RECORD_LEN);
        assert!(r.is_held_by(0x0DB3_2E15));
        assert!(!r.is_held_by(0x0DB3_2E16));
        assert!(Record::decode(&bytes[..39]).is_err());
    }

    #[test]
    fn header_fails_closed_on_version_reserved_flags_and_ec() {
        let valid = header(0).encode().unwrap();
        for old in [1u8, 2] {
            let mut v = valid;
            v[4] = old;
            let err = Header::decode(&v).unwrap_err().to_string();
            assert!(
                err.contains(&format!("unsupported list version {old}")),
                "{err}"
            );
        }
        let mut v4 = valid;
        v4[4] = 4;
        assert!(Header::decode(&v4).is_err());
        for offset in [0, 1, 2, 3, 5, 6, 7, 26, 27, 28, 29, 30, 31] {
            let mut bad = valid;
            bad[offset] ^= 1;
            assert!(Header::decode(&bad).is_err(), "offset {offset}");
        }
        let mut zero_k = valid;
        zero_k[24] = 0;
        assert!(Header::decode(&zero_k).is_err());
        let mut too_wide = valid;
        too_wide[24] = 200;
        too_wide[25] = 100;
        assert!(Header::decode(&too_wide).is_err());
        assert!(Header::decode(&valid[..31]).is_err());
    }

    #[test]
    fn list_roundtrip_keeps_order_and_duplicated_hashes() {
        // The same blob hash on two holders is two records.
        let mut records = vec![
            record(2, 5),
            record(1, 300),
            record(1, 29),
            record(1, 29), // exact duplicate, dropped
        ];
        normalize_records(&mut records).unwrap();
        assert_eq!(records, vec![record(1, 29), record(1, 300), record(2, 5)]);
        let bytes = encode_list(&header(3), &records).unwrap();
        assert_eq!(bytes.len(), HEADER_LEN + 3 * RECORD_LEN);
        let (h, decoded) = decode_list(&bytes).unwrap();
        assert_eq!(h, header(3));
        assert_eq!(decoded, records);
    }

    #[test]
    fn list_rejects_unsorted_conflicting_and_truncated() {
        let sorted = vec![record(1, 0), record(2, 0)];
        let bytes = encode_list(&header(2), &sorted).unwrap();

        let mut swapped = bytes.clone();
        let (a, b) = swapped[HEADER_LEN..].split_at_mut(RECORD_LEN);
        a.swap_with_slice(b);
        assert!(
            decode_list(&swapped)
                .unwrap_err()
                .to_string()
                .contains("not strictly sorted")
        );

        let mut conflict = vec![record(1, 0), record(1, 1)];
        conflict[1].shard_length += 1;
        let err = encode_list(&header(2), &conflict).unwrap_err().to_string();
        assert!(err.contains("conflicting lengths"), "{err}");
        let mut raw = header(2).encode().unwrap().to_vec();
        for r in &conflict {
            raw.extend_from_slice(&r.encode());
        }
        assert!(decode_list(&raw).is_err());

        assert!(decode_list(&bytes[..bytes.len() - 1]).is_err());
        let mut trailing = bytes.clone();
        trailing.push(0);
        assert!(decode_list(&trailing).is_err());

        // Same hash, same length, two holders: legitimate (one blob placed
        // on two miners) and ordered by holder.
        let two_holders = vec![record(1, 7), record(1, 9)];
        let bytes = encode_list(&header(2), &two_holders).unwrap();
        assert_eq!(decode_list(&bytes).unwrap().1, two_holders);
    }

    /// The reader's whole filter is `holder_uid == my uid`. Nothing is
    /// recomputed, so a map the reader sees differently from the writer
    /// cannot change who a record belongs to.
    #[test]
    fn holder_filter_is_the_record_uid_and_nothing_else() {
        let me = 229_834_997;
        let mut records = vec![record(1, me), record(2, 1), record(3, me), record(1, 42)];
        normalize_records(&mut records).unwrap();
        let mine: Vec<_> = records.iter().filter(|r| r.is_held_by(me)).collect();
        assert_eq!(mine, vec![&record(1, me), &record(3, me)]);
        let bytes = encode_list(&header(4), &records).unwrap();
        let mut seen = 0;
        visit_list(&bytes, &mut |r| {
            if r.is_held_by(me) {
                seen += 1;
            }
        })
        .unwrap();
        assert_eq!(seen, 2);
    }

    #[test]
    fn tombstone_header_differs_from_list_header_only_by_magic() {
        let h = header(2);
        let list = h.encode().unwrap();
        let tomb = h.encode_tombstone().unwrap();
        assert_eq!(&tomb[..4], b"APGD");
        assert_eq!(&list[4..], &tomb[4..]);
        assert_eq!(Header::decode_tombstone(&tomb).unwrap(), h);
        // Neither decoder accepts the other's file.
        let err = Header::decode(&tomb).unwrap_err().to_string();
        assert!(err.contains("bad list magic"), "{err}");
        let err = Header::decode_tombstone(&list).unwrap_err().to_string();
        assert!(err.contains("bad tombstone magic"), "{err}");
        assert_eq!(h.tombstone_len().unwrap(), HEADER_LEN + 2 * 32);
    }

    #[test]
    fn tombstones_roundtrip_sorted_deduped_and_fail_closed() {
        let mut hashes = vec![[3u8; 32], [1u8; 32], [2u8; 32], [1u8; 32]];
        normalize_hashes(&mut hashes);
        assert_eq!(hashes, vec![[1u8; 32], [2u8; 32], [3u8; 32]]);
        let bytes = encode_tombstones(&header(3), &hashes).unwrap();
        assert_eq!(bytes.len(), HEADER_LEN + 3 * TOMBSTONE_RECORD_LEN);
        let (h, decoded) = decode_tombstones(&bytes).unwrap();
        assert_eq!(h, header(3));
        assert_eq!(decoded, hashes);

        // Count mismatch and unsorted input are refused at encode time.
        assert!(encode_tombstones(&header(2), &hashes).is_err());
        assert!(encode_tombstones(&header(2), &[[2u8; 32], [1u8; 32]]).is_err());
        assert!(encode_tombstones(&header(2), &[[1u8; 32], [1u8; 32]]).is_err());

        // Truncated, trailing, swapped bodies are refused at decode time.
        assert!(decode_tombstones(&bytes[..bytes.len() - 1]).is_err());
        let mut trailing = bytes.clone();
        trailing.push(0);
        assert!(decode_tombstones(&trailing).is_err());
        let mut swapped = bytes.clone();
        let (a, b) = swapped[HEADER_LEN..HEADER_LEN + 64].split_at_mut(32);
        a.swap_with_slice(b);
        assert!(
            decode_tombstones(&swapped)
                .unwrap_err()
                .to_string()
                .contains("not strictly sorted")
        );

        // A `.list` body handed to the tombstone decoder (and the
        // reverse) is refused by the magic before any record is read.
        let list = encode_list(&header(1), &[record(1, 0)]).unwrap();
        assert!(decode_tombstones(&list).is_err());
        assert!(decode_list(&bytes).is_err());

        // Empty tombstone file: header only.
        let empty = encode_tombstones(&header(0), &[]).unwrap();
        assert_eq!(empty.len(), HEADER_LEN);
        assert_eq!(decode_tombstones(&empty).unwrap().1, Vec::<[u8; 32]>::new());
    }
}

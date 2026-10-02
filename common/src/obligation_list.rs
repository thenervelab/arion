//! Wire format of the per-PG obligation lists (`APGL` version 4).
//!
//! The list writer (`pg-lists`) and the miner reader share this codec so
//! the two can never drift on a byte offset. A list is one 32-byte header
//! followed by `count` 40-byte records, one record per **shard** of every
//! file placed in the PG, each naming the miner that holds it. Neither
//! version 1 (one record per blob hash, `shard_length` as u64) nor
//! version 2 (per shard, holder recomputed by the reader) was ever
//! published. Version 3 had the same bytes as version 4 but named each
//! shard's holder on the generation's current map; version 4 names it on
//! the map of the file's placement epoch and comes with the holder index
//! (below). The version is bumped so that a reader that predates the
//! holder index (it reads version 3 only) refuses every list, tombstone
//! and delta section of such a generation outright, instead of loading
//! it without the index and purging the placement-epoch holders' copies
//! of PGs it does not own; and so that this reader never enforces a
//! version 3 generation. A reader refuses any version but [`VERSION`].
//!
//! ## Header (32 bytes)
//!
//! | offset | size | field |
//! |-------:|-----:|-------|
//! |  0 | 4 | magic `APGL` |
//! |  4 | 1 | version = 4 |
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
//! path's own function, [`crate::calculate_stripe_placement`] (through
//! [`pg_holder_uids`] and [`shard_holder`]), on the draining-filtered map
//! **of the file's `placement_epoch`**, and stores its UID. That is the
//! map the gateway reads the file through (`stripe_download_candidates`
//! on the placement-epoch map, primaries first): until the validator
//! copies a shard to its current-map holder and moves the manifest's
//! `placement_epoch` forward, the only copy the read path looks for first
//! is on the placement-epoch holder, so that miner is the one obliged to
//! keep it. Only the map of exactly that epoch is used (the validator's
//! Postgres row, else the signed map it serves for that epoch); a file
//! whose epoch has no exact map is not listed and counts as a placement
//! skip that blocks publication, never placed on another epoch's map
//! (which may place differently). Holding
//! the current-map holder to the same shard is NOT listed: that miner
//! keeps a copy it already has through the reader's moved class (the
//! record names another holder of a PG it protects), and listing it would
//! make every miner's backfill pull every not-yet-rebalanced shard.
//!
//! The reader computes nothing: a miner keeps the records whose
//! `holder_uid` is its own UID and treats any other blob as not its
//! obligation, even when the blob is listed for a PG it owns (the shard
//! sits on another holder of the same PG). Version 2 had the reader
//! recompute the holder from the PG placement; the writer and the reader
//! fed different maps (filtered vs raw) to the same formula and
//! attributed shards to the wrong miner. Carrying the UID removes that
//! class of bug: there is one placement computation and it is the
//! writer's.
//!
//! Because the holder follows the placement epoch, a miner is named in
//! the lists of PGs it no longer owns under the current map. A reader
//! derives the PGs it must load from its current ownership AND from the
//! generation's holder index (below); a generation without a holder index
//! was written by a writer that placed on the current map only and must
//! never drive a deletion.
//!
//! ## Holder index (`APGH`)
//!
//! A base generation over the **whole partition** (every PG of
//! `pg_count`; a generation over a subset declares none, and a reader
//! trusts none there) publishes, for every UID named by at least one
//! record, `holders/<uid 10 digits>.pgs` ([`holder_index_path`]): the
//! ascending PG ids whose list names that UID. The base manifest declares
//! each object (`holders`, sha256 and size). Same 32-byte header shape:
//!
//! | offset | size | field |
//! |-------:|-----:|-------|
//! |  0 | 4 | magic `APGH` |
//! |  4 | 1 | version = 1 |
//! |  5 | 3 | reserved, zero |
//! |  8 | 4 | `uid` u32 LE |
//! | 12 | 8 | `generation` u64 LE |
//! | 20 | 4 | `count` u32 LE (PG ids) |
//! | 24 | 4 | `pg_count` u32 LE |
//! | 28 | 4 | reserved, zero |
//!
//! then `count` u32 LE PG ids, strictly ascending, each below `pg_count`.
//! A UID with no object holds no record of the generation's base.
//!
//! Every delta publishes its own index the same way, under its directory
//! (`delta/<generation>/<seq>/holders/<uid>.pgs`, headers naming the base
//! generation), declared in the delta manifest's `holders`: the PGs in
//! which that delta adds records naming each uid.
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
//!
//! ## Delta bundles (delta manifest `format` 2)
//!
//! A delta publishes the additions of the PGs that gained records as
//! [`delta_bundle_count`] range bundles, `bundle/<b:03>.added` with
//! `b = pg / DELTA_BUNDLE_PGS`, instead of one small object per PG: a
//! reader protecting thousands of PGs issues at most one GET per bundle
//! per delta. A bundle is the concatenation, ascending by PG, of the same
//! per-PG `APGL` bodies a stand-alone list would carry; the delta
//! manifest declares every section ([`DeltaBundle`], [`DeltaSection`]) and
//! [`check_delta_bundles`] is the shape both sides enforce.

use std::{cmp::Ordering, collections::BTreeMap};

use anyhow::{Context, Result, bail, ensure};
use serde::{Deserialize, Serialize};

/// Magic at the start of every list file.
pub const MAGIC: &[u8; 4] = b"APGL";
/// Magic at the start of every tombstone (`.deleted`) file.
pub const TOMBSTONE_MAGIC: &[u8; 4] = b"APGD";
/// The only list format version this codec reads or writes (see the
/// module docs for why version 3 is refused).
pub const VERSION: u8 = 4;
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

/// Uids of the PG placement of `file_hash` under `placement_version` on
/// `map`, unrotated (stripe 0 of any file of the PG): the write path's
/// own [`crate::calculate_stripe_placement`]. `map` is the map of the
/// file's `placement_epoch`; pass it filtered for placement
/// ([`crate::filter_map_for_placement`]), as the gateway does before it
/// places or reads (an unfiltered map is filtered by the callee, at the
/// cost of a clone per call). The holder of global shard `i` is
/// [`shard_holder`]`(&uids, i, shards_per_stripe)`.
pub fn pg_holder_uids(
    file_hash: &str,
    shards_per_stripe: usize,
    map: &crate::ClusterMap,
    placement_version: u8,
) -> std::result::Result<Vec<u32>, String> {
    let placed =
        crate::calculate_stripe_placement(file_hash, 0, shards_per_stripe, map, placement_version)?;
    if placed.len() != shards_per_stripe {
        return Err(format!(
            "{} holders for {shards_per_stripe} shards",
            placed.len()
        ));
    }
    Ok(placed.into_iter().map(|node| node.uid).collect())
}

/// The placement version a gateway reads stripe 0 of `file_hash`
/// through, on `map` (the map of the file's `placement_epoch`): the first
/// version of [`crate::get_placement_probing_sequence`]`(tagged)` whose
/// placement succeeds on the map filtered for placement, which is what the
/// gateway's download loop does (`stripe_download_candidates` per version;
/// a failed placement moves on to the next version). `Err` carries every
/// version's error: the gateway then computes no candidate at all, fetches
/// nothing (its retry on the current map runs only after a placement on the
/// placement-epoch map succeeded) and the download fails at stripe 0.
pub fn gateway_read_version(
    file_hash: &str,
    shards_per_stripe: usize,
    map: &crate::ClusterMap,
    tagged: u8,
) -> std::result::Result<u8, String> {
    let filtered;
    let map = if map.miners.iter().any(|m| m.draining || m.placement_hold) {
        filtered = crate::filter_map_for_placement(map);
        &filtered
    } else {
        map
    };
    let mut errors = Vec::new();
    for version in crate::get_placement_probing_sequence(tagged) {
        match crate::calculate_stripe_placement(file_hash, 0, shards_per_stripe, map, version) {
            Ok(_) => return Ok(version),
            Err(error) => errors.push(format!("v{version}: {error}")),
        }
    }
    Err(errors.join("; "))
}

/// Holder of global shard `shard_index` (`stripe * (k + m) + position`)
/// given the unrotated PG placement `uids` ([`pg_holder_uids`]): the same
/// per-stripe rotation the write path applies
/// ([`crate::expected_uid_index_for_shard`]). `uids` must not be empty.
pub fn shard_holder(uids: &[u32], shard_index: usize, shards_per_stripe: usize) -> u32 {
    uids[crate::expected_uid_index_for_shard(shard_index, shards_per_stripe, uids.len())]
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

// ============================================================================
// Holder index
// ============================================================================

/// Magic at the start of every holder index (`holders/<uid>.pgs`).
pub const HOLDER_INDEX_MAGIC: &[u8; 4] = b"APGH";
/// The only holder index version this codec reads or writes.
pub const HOLDER_INDEX_VERSION: u8 = 1;
/// Length of one holder index record (a PG id) in bytes.
pub const HOLDER_INDEX_RECORD_LEN: usize = 4;

/// Path of `uid`'s holder index relative to the generation directory.
pub fn holder_index_path(uid: u32) -> String {
    format!("holders/{uid:010}.pgs")
}

/// The UID a canonical holder index path names, `None` for any other
/// string (non-canonical padding included).
pub fn holder_index_uid(path: &str) -> Option<u32> {
    let digits = path.strip_prefix("holders/")?.strip_suffix(".pgs")?;
    if digits.len() != 10 || !digits.bytes().all(|b| b.is_ascii_digit()) {
        return None;
    }
    let uid = digits.parse::<u32>().ok()?;
    (holder_index_path(uid) == path).then_some(uid)
}

/// Decoded holder index header.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct HolderIndexHeader {
    pub uid: u32,
    pub generation: u64,
    pub count: u32,
    pub pg_count: u32,
}

impl HolderIndexHeader {
    /// Exact byte length of an index with this header.
    pub fn index_len(&self) -> Result<usize> {
        usize::try_from(self.count)?
            .checked_mul(HOLDER_INDEX_RECORD_LEN)
            .and_then(|n| n.checked_add(HEADER_LEN))
            .context("holder index length overflow")
    }
}

/// Whether an object of `size` bytes has holder index framing (a header
/// and a whole number of PG ids).
pub fn holder_index_framing_ok(size: u64) -> bool {
    let header = HEADER_LEN as u64;
    let record = HOLDER_INDEX_RECORD_LEN as u64;
    size >= header
        && (size - header).is_multiple_of(record)
        && (size - header) / record <= u64::from(u32::MAX)
}

fn validate_holder_pgs(pgs: &[u32], pg_count: u32) -> Result<()> {
    for (i, pg) in pgs.iter().enumerate() {
        ensure!(
            *pg < pg_count,
            "holder index PG {pg} outside pg_count {pg_count}"
        );
        ensure!(
            i == 0 || pgs[i - 1] < *pg,
            "holder index PGs not strictly ascending at record {i}"
        );
    }
    Ok(())
}

/// Encode `uid`'s holder index. `pgs` must be strictly ascending and each
/// below `pg_count`.
pub fn encode_holder_index(
    uid: u32,
    generation: u64,
    pg_count: u32,
    pgs: &[u32],
) -> Result<Vec<u8>> {
    ensure!(pg_count > 0, "holder index needs a positive pg_count");
    validate_holder_pgs(pgs, pg_count)?;
    let count = u32::try_from(pgs.len()).context("holder index count overflow")?;
    let header = HolderIndexHeader {
        uid,
        generation,
        count,
        pg_count,
    };
    let mut out = Vec::with_capacity(header.index_len()?);
    out.extend_from_slice(HOLDER_INDEX_MAGIC);
    out.push(HOLDER_INDEX_VERSION);
    out.extend_from_slice(&[0; 3]);
    out.extend_from_slice(&uid.to_le_bytes());
    out.extend_from_slice(&generation.to_le_bytes());
    out.extend_from_slice(&count.to_le_bytes());
    out.extend_from_slice(&pg_count.to_le_bytes());
    out.extend_from_slice(&[0; 4]);
    for pg in pgs {
        out.extend_from_slice(&pg.to_le_bytes());
    }
    Ok(out)
}

/// Decode and validate a whole holder index: magic, version, reserved
/// bytes, exact length for `count`, strictly ascending PG ids below
/// `pg_count`. The caller checks `uid`, `generation` and `pg_count`
/// against what it asked for.
pub fn decode_holder_index(bytes: &[u8]) -> Result<(HolderIndexHeader, Vec<u32>)> {
    ensure!(
        bytes.len() >= HEADER_LEN,
        "holder index too short for header: {} bytes",
        bytes.len()
    );
    ensure!(
        &bytes[..4] == HOLDER_INDEX_MAGIC,
        "bad holder index magic {:?}",
        &bytes[..4]
    );
    ensure!(
        bytes[4] == HOLDER_INDEX_VERSION,
        "unsupported holder index version {} (this reader understands version {HOLDER_INDEX_VERSION} only)",
        bytes[4]
    );
    ensure!(
        bytes[5..8] == [0; 3] && bytes[28..32] == [0; 4],
        "nonzero reserved holder index bytes"
    );
    let header = HolderIndexHeader {
        uid: u32::from_le_bytes(bytes[8..12].try_into().unwrap()),
        generation: u64::from_le_bytes(bytes[12..20].try_into().unwrap()),
        count: u32::from_le_bytes(bytes[20..24].try_into().unwrap()),
        pg_count: u32::from_le_bytes(bytes[24..28].try_into().unwrap()),
    };
    ensure!(header.pg_count > 0, "holder index declares pg_count 0");
    let expected = header.index_len()?;
    ensure!(
        bytes.len() == expected,
        "holder index declares {} PGs ({expected} bytes) but is {} bytes",
        header.count,
        bytes.len()
    );
    let (records, _) = bytes[HEADER_LEN..].as_chunks::<HOLDER_INDEX_RECORD_LEN>();
    let pgs: Vec<u32> = records.iter().map(|r| u32::from_le_bytes(*r)).collect();
    validate_holder_pgs(&pgs, header.pg_count)?;
    Ok((header, pgs))
}

/// Collects, while the lists of a base are written, which PGs name each
/// holder, then encodes one [`holder_index_path`] object per holder.
/// PGs are noted in ascending order (the order every finalization walks
/// them).
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct HolderIndexBuilder {
    by_uid: BTreeMap<u32, Vec<u32>>,
}

impl HolderIndexBuilder {
    /// Note that `pg`'s list names `uid`. Idempotent for the PG being
    /// walked; a PG below one already noted for `uid` is refused.
    pub fn note(&mut self, pg: u32, uid: u32) -> Result<()> {
        let pgs = self.by_uid.entry(uid).or_default();
        match pgs.last() {
            Some(last) if *last == pg => Ok(()),
            Some(last) if *last > pg => {
                bail!("holder index: PG {pg} noted after PG {last} for uid {uid}")
            }
            _ => {
                pgs.push(pg);
                Ok(())
            }
        }
    }

    /// [`Self::note`] every holder of `records`, the records of `pg`'s list.
    pub fn add_pg(&mut self, pg: u32, records: &[Record]) -> Result<()> {
        for record in records {
            self.note(pg, record.holder_uid)?;
        }
        Ok(())
    }

    /// The PGs noted for `uid`, ascending (empty when none).
    pub fn pgs_of(&self, uid: u32) -> &[u32] {
        self.by_uid.get(&uid).map_or(&[], Vec::as_slice)
    }

    /// `(path, bytes)` of every holder's index, ascending by UID.
    pub fn encode(&self, generation: u64, pg_count: u32) -> Result<Vec<(String, Vec<u8>)>> {
        self.by_uid
            .iter()
            .map(|(uid, pgs)| {
                Ok((
                    holder_index_path(*uid),
                    encode_holder_index(*uid, generation, pg_count, pgs)?,
                ))
            })
            .collect()
    }
}

// ============================================================================
// Delta bundles
// ============================================================================

/// Delta manifest format this writer produces and this reader accepts.
/// Format 2 packs the per-PG additions into range bundles
/// ([`DeltaBundle`]); format 1 (one `pg/<N>.added` object per PG, an
/// `objects` map, no `format` key) is no longer written or read.
pub const DELTA_FORMAT: u64 = 2;

/// Width of one delta bundle in PGs: bundle `b` holds the additions of
/// PGs `b * DELTA_BUNDLE_PGS ..= (b + 1) * DELTA_BUNDLE_PGS - 1`
/// (64 bundles for 16384 PGs).
pub const DELTA_BUNDLE_PGS: u32 = 256;

/// Upper bound a reader accepts on one published body (a base list or a
/// delta bundle), whatever the manifest declares. A writer refuses to
/// produce a delta bundle above it.
pub const MAX_OBJECT_BYTES: u64 = 256 << 20;

/// The bundle a PG's additions go to.
pub fn delta_bundle_of(pg: u32) -> u32 {
    pg / DELTA_BUNDLE_PGS
}

/// How many bundles `pg_count` PGs span: `ceil(pg_count / DELTA_BUNDLE_PGS)`.
pub fn delta_bundle_count(pg_count: u32) -> u32 {
    pg_count.div_ceil(DELTA_BUNDLE_PGS)
}

/// Path of bundle `index` relative to the delta's directory
/// (`bundle/<index 3 digits>.added`).
pub fn delta_bundle_path(index: u32) -> String {
    format!("bundle/{index:03}.added")
}

/// One PG's additions inside a bundle: `size` bytes at `offset`, an
/// `APGL` body exactly as a stand-alone list (same header, codec and
/// order), digested by `sha256`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DeltaSection {
    pub pg: u32,
    pub offset: u64,
    pub size: u64,
    pub sha256: String,
}

/// One delta bundle as the delta manifest declares it: the digest and
/// size of the whole object and its sections, ascending by PG,
/// contiguous from offset 0, covering exactly `size` bytes.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DeltaBundle {
    pub sha256: String,
    pub size: u64,
    pub pgs: Vec<DeltaSection>,
}

fn is_lower_sha256_hex(text: &str) -> bool {
    text.len() == 64 && text.bytes().all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f'))
}

/// Shape of a delta manifest's `bundles`, checked by the writer before
/// signing and by the reader before any fetch. `pgs` are the PGs the
/// delta covers (ascending), `pg_count` the map's PG count.
///
/// Every key is the canonical path of a bundle in range; every digest is
/// lowercase hex; a bundle is non-empty and at most [`MAX_OBJECT_BYTES`];
/// its sections are strictly ascending by PG, each PG in the bundle's
/// range and covered, each section a non-empty `APGL` framing (a header
/// plus at least one record), contiguous from offset 0 and summing to the
/// bundle size.
pub fn check_delta_bundles(
    bundles: &BTreeMap<String, DeltaBundle>,
    pgs: &[u32],
    pg_count: u32,
) -> Result<()> {
    let count = delta_bundle_count(pg_count);
    for (path, bundle) in bundles {
        let index = path
            .strip_prefix("bundle/")
            .and_then(|rest| rest.strip_suffix(".added"))
            .filter(|digits| digits.len() == 3 && digits.bytes().all(|b| b.is_ascii_digit()))
            .and_then(|digits| digits.parse::<u32>().ok())
            .filter(|index| *path == delta_bundle_path(*index))
            .with_context(|| format!("noncanonical delta bundle path {path:?}"))?;
        ensure!(
            index < count,
            "delta bundle {path} is out of range for {pg_count} PGs ({count} bundles)"
        );
        ensure!(
            is_lower_sha256_hex(&bundle.sha256),
            "delta bundle {path}: digest must be canonical lowercase hex"
        );
        ensure!(
            bundle.size > 0 && bundle.size <= MAX_OBJECT_BYTES,
            "delta bundle {path}: size {} outside 1..={MAX_OBJECT_BYTES}",
            bundle.size
        );
        ensure!(
            !bundle.pgs.is_empty(),
            "delta bundle {path} declares no section (an empty bundle must be omitted)"
        );
        let mut next_offset = 0u64;
        let mut previous: Option<u32> = None;
        for section in &bundle.pgs {
            let pg = section.pg;
            ensure!(
                previous.is_none_or(|p| p < pg),
                "delta bundle {path}: sections must be strictly ascending by PG (pg {pg})"
            );
            previous = Some(pg);
            ensure!(
                delta_bundle_of(pg) == index,
                "delta bundle {path}: pg {pg} belongs to bundle {}",
                delta_bundle_of(pg)
            );
            ensure!(
                pgs.binary_search(&pg).is_ok(),
                "delta bundle {path}: pg {pg} is outside the delta's coverage"
            );
            ensure!(
                section.offset == next_offset,
                "delta bundle {path}: section of pg {pg} starts at {} instead of {next_offset} (sections must be contiguous)",
                section.offset
            );
            let body = section.size.checked_sub(HEADER_LEN as u64);
            ensure!(
                body.is_some_and(|b| b > 0
                    && b.is_multiple_of(RECORD_LEN as u64)
                    && b / RECORD_LEN as u64 <= u64::from(u32::MAX)),
                "delta bundle {path}: section of pg {pg} size {} is not a non-empty APGL framing",
                section.size
            );
            ensure!(
                is_lower_sha256_hex(&section.sha256),
                "delta bundle {path}: section of pg {pg} digest must be canonical lowercase hex"
            );
            next_offset = next_offset
                .checked_add(section.size)
                .context("delta bundle section offsets overflow")?;
        }
        ensure!(
            next_offset == bundle.size,
            "delta bundle {path}: sections cover {next_offset} bytes, the bundle is {}",
            bundle.size
        );
    }
    Ok(())
}

/// Path, relative to a delta's directory, of the blob hashes of the files
/// the delta's window withholds from the lists (excluded or unplaceable:
/// live, with no resolvable holder). The base carries its own in the live
/// filter; a delta carries those that appeared after the base cut here.
pub const DELTA_WITHHELD_PATH: &str = "withheld.hashes";

/// A delta manifest's `withheld` entry: the object at
/// [`DELTA_WITHHELD_PATH`], `count` raw 32-byte blob hashes strictly
/// ascending (no header, no duplicate), digested by `sha256`. Declared only
/// when the window withheld at least one file.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DeltaWithheld {
    pub path: String,
    pub sha256: String,
    pub size: u64,
    pub count: u64,
}

/// Shape of a delta manifest's `withheld` entry, checked by the writer
/// before signing and by the reader before the fetch: canonical path,
/// lowercase digest, `count >= 1`, `size = 32 * count`, at most
/// [`MAX_OBJECT_BYTES`].
pub fn check_delta_withheld(entry: &DeltaWithheld) -> Result<()> {
    ensure!(
        entry.path == DELTA_WITHHELD_PATH,
        "delta withheld hashes at {:?}, not {DELTA_WITHHELD_PATH:?}",
        entry.path
    );
    ensure!(
        is_lower_sha256_hex(&entry.sha256),
        "delta withheld hashes: digest must be canonical lowercase hex"
    );
    ensure!(
        entry.count >= 1 && entry.count.checked_mul(32) == Some(entry.size),
        "delta withheld hashes: {} bytes for {} hashes (an empty set is omitted)",
        entry.size,
        entry.count
    );
    ensure!(
        entry.size <= MAX_OBJECT_BYTES,
        "delta withheld hashes: {} bytes, above the {MAX_OBJECT_BYTES} byte limit",
        entry.size
    );
    Ok(())
}

/// Encode sorted, unique blob hashes as a [`DELTA_WITHHELD_PATH`] body.
pub fn encode_withheld_hashes(hashes: &[[u8; 32]]) -> Result<Vec<u8>> {
    ensure!(
        hashes.windows(2).all(|pair| pair[0] < pair[1]),
        "withheld hashes must be strictly ascending"
    );
    Ok(hashes.concat())
}

/// Check a [`DELTA_WITHHELD_PATH`] body (whole 32-byte hashes, strictly
/// ascending) and iterate its hashes.
pub fn decode_withheld_hashes(bytes: &[u8]) -> Result<impl Iterator<Item = &[u8; 32]>> {
    ensure!(
        !bytes.is_empty() && bytes.len().is_multiple_of(32),
        "withheld hashes body of {} bytes is not a non-empty run of 32-byte hashes",
        bytes.len()
    );
    let hashes = || bytes.as_chunks::<32>().0.iter();
    ensure!(
        hashes().zip(hashes().skip(1)).all(|(a, b)| a < b),
        "withheld hashes are not strictly ascending"
    );
    Ok(hashes())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn delta_withheld_shape_and_body() {
        let hashes = [[1u8; 32], [2u8; 32], [9u8; 32]];
        let body = encode_withheld_hashes(&hashes).unwrap();
        assert_eq!(body.len(), 96);
        let decoded: Vec<[u8; 32]> = decode_withheld_hashes(&body).unwrap().copied().collect();
        assert_eq!(decoded, hashes);
        assert!(encode_withheld_hashes(&[[2u8; 32], [1u8; 32]]).is_err());
        assert!(encode_withheld_hashes(&[[2u8; 32], [2u8; 32]]).is_err());
        let mut unsorted = body.clone();
        unsorted[..32].copy_from_slice(&[9u8; 32]);
        assert!(decode_withheld_hashes(&unsorted).is_err());
        assert!(decode_withheld_hashes(&body[..95]).is_err());
        assert!(decode_withheld_hashes(&[]).is_err());

        let entry = DeltaWithheld {
            path: DELTA_WITHHELD_PATH.into(),
            sha256: "ab".repeat(32),
            size: 96,
            count: 3,
        };
        check_delta_withheld(&entry).unwrap();
        for bad in [
            DeltaWithheld {
                path: "withheld.raw".into(),
                ..entry.clone()
            },
            DeltaWithheld {
                sha256: "AB".repeat(32),
                ..entry.clone()
            },
            DeltaWithheld {
                size: 95,
                ..entry.clone()
            },
            DeltaWithheld {
                size: 0,
                count: 0,
                ..entry.clone()
            },
        ] {
            assert!(check_delta_withheld(&bad).is_err(), "{bad:?}");
        }
    }

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
            b'A', b'P', b'G', b'L', 4, 0, 0, 0, 0x78, 0x56, 0x34, 0x12, 8, 7, 6, 5, 4, 3, 2, 1,
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
        assert_eq!(valid[4], 4, "version 4 is written");
        // Version 3 (holders on the current map, no holder index) is
        // refused like every other version.
        for old in [1u8, 2, 3, 5] {
            let mut v = valid;
            v[4] = old;
            let err = Header::decode(&v).unwrap_err().to_string();
            assert!(
                err.contains(&format!("unsupported list version {old}")),
                "{err}"
            );
            assert!(
                Header::decode_tombstone(&{
                    let mut t = header(0).encode_tombstone().unwrap();
                    t[4] = old;
                    t
                })
                .is_err()
            );
        }
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
    fn holder_index_exact_offsets_roundtrip_and_path() {
        let bytes = encode_holder_index(0x0102_0304, 9, 16_384, &[0, 7, 16_383]).unwrap();
        assert_eq!(bytes.len(), HEADER_LEN + 3 * HOLDER_INDEX_RECORD_LEN);
        assert_eq!(&bytes[..4], b"APGH");
        assert_eq!(bytes[4], 1);
        assert_eq!(&bytes[8..12], &0x0102_0304u32.to_le_bytes());
        assert_eq!(&bytes[12..20], &9u64.to_le_bytes());
        assert_eq!(&bytes[20..24], &3u32.to_le_bytes());
        assert_eq!(&bytes[24..28], &16_384u32.to_le_bytes());
        assert_eq!(&bytes[32..36], &0u32.to_le_bytes());
        assert_eq!(&bytes[40..44], &16_383u32.to_le_bytes());
        let (header, pgs) = decode_holder_index(&bytes).unwrap();
        assert_eq!(
            header,
            HolderIndexHeader {
                uid: 0x0102_0304,
                generation: 9,
                count: 3,
                pg_count: 16_384
            }
        );
        assert_eq!(pgs, vec![0, 7, 16_383]);
        assert!(holder_index_framing_ok(bytes.len() as u64));
        assert!(!holder_index_framing_ok(bytes.len() as u64 - 1));
        assert!(!holder_index_framing_ok(31));

        assert_eq!(holder_index_path(42), "holders/0000000042.pgs");
        assert_eq!(holder_index_uid("holders/0000000042.pgs"), Some(42));
        assert_eq!(holder_index_uid("holders/42.pgs"), None);
        assert_eq!(holder_index_uid("holders/000000004a.pgs"), None);
        assert_eq!(holder_index_uid("pg/00042.list"), None);
        assert_eq!(
            holder_index_uid(&holder_index_path(u32::MAX)),
            Some(u32::MAX)
        );
    }

    #[test]
    fn holder_index_fails_closed() {
        assert!(encode_holder_index(1, 1, 16, &[3, 3]).is_err(), "duplicate");
        assert!(encode_holder_index(1, 1, 16, &[4, 3]).is_err(), "unsorted");
        assert!(encode_holder_index(1, 1, 16, &[16]).is_err(), "range");
        assert!(encode_holder_index(1, 1, 0, &[]).is_err(), "pg_count 0");
        let good = encode_holder_index(1, 1, 16, &[1, 2]).unwrap();
        let mut bad = good.clone();
        bad[0] = b'X';
        assert!(decode_holder_index(&bad).is_err(), "magic");
        let mut bad = good.clone();
        bad[4] = 2;
        assert!(decode_holder_index(&bad).is_err(), "version");
        let mut bad = good.clone();
        bad[29] = 1;
        assert!(decode_holder_index(&bad).is_err(), "reserved");
        assert!(
            decode_holder_index(&good[..good.len() - 1]).is_err(),
            "short"
        );
        let mut bad = good.clone();
        bad.extend_from_slice(&3u32.to_le_bytes());
        assert!(decode_holder_index(&bad).is_err(), "trailing");
        let mut bad = good.clone();
        bad[32..36].copy_from_slice(&2u32.to_le_bytes());
        assert!(decode_holder_index(&bad).is_err(), "not ascending");
        // A list is never taken for a holder index.
        let list = encode_list(&header(0), &[]).unwrap();
        assert!(decode_holder_index(&list).is_err());
    }

    #[test]
    fn holder_index_builder_collects_pgs_per_uid_in_order() {
        let mut builder = HolderIndexBuilder::default();
        builder
            .add_pg(3, &[record(1, 7), record(2, 9), record(3, 7)])
            .unwrap();
        builder.add_pg(5, &[record(1, 9)]).unwrap();
        builder.note(5, 9).unwrap();
        assert_eq!(builder.pgs_of(7), &[3]);
        assert_eq!(builder.pgs_of(9), &[3, 5]);
        assert!(builder.pgs_of(8).is_empty());
        assert!(builder.note(4, 9).is_err(), "PG below the last noted");
        let objects = builder.encode(2, 16).unwrap();
        assert_eq!(
            objects.iter().map(|(p, _)| p.as_str()).collect::<Vec<_>>(),
            vec!["holders/0000000007.pgs", "holders/0000000009.pgs"]
        );
        let (header, pgs) = decode_holder_index(&objects[1].1).unwrap();
        assert_eq!((header.uid, header.generation, header.pg_count), (9, 2, 16));
        assert_eq!(pgs, vec![3, 5]);
    }

    #[test]
    fn shard_holder_rotates_by_stripe() {
        let uids: Vec<u32> = (100..130).collect();
        // Stripe 0: position i on uids[i].
        assert_eq!(shard_holder(&uids, 0, 30), 100);
        assert_eq!(shard_holder(&uids, 29, 30), 129);
        // Stripe 1 is rotated left by one: position 0 on uids[1].
        assert_eq!(shard_holder(&uids, 30, 30), 101);
        assert_eq!(shard_holder(&uids, 59, 30), 100);
    }
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

    fn section(pg: u32, offset: u64, records: u64) -> DeltaSection {
        DeltaSection {
            pg,
            offset,
            size: HEADER_LEN as u64 + records * RECORD_LEN as u64,
            sha256: "ab".repeat(32),
        }
    }

    fn bundle(sections: Vec<DeltaSection>) -> DeltaBundle {
        DeltaBundle {
            sha256: "cd".repeat(32),
            size: sections.iter().map(|s| s.size).sum(),
            pgs: sections,
        }
    }

    #[test]
    fn delta_bundle_index_count_and_path() {
        assert_eq!(DELTA_BUNDLE_PGS, 256);
        assert_eq!(
            (
                delta_bundle_of(0),
                delta_bundle_of(255),
                delta_bundle_of(256)
            ),
            (0, 0, 1)
        );
        assert_eq!(delta_bundle_of(16383), 63);
        assert_eq!(delta_bundle_count(16384), 64);
        assert_eq!(delta_bundle_count(16385), 65);
        assert_eq!(delta_bundle_count(1), 1);
        assert_eq!(delta_bundle_path(0), "bundle/000.added");
        assert_eq!(delta_bundle_path(63), "bundle/063.added");
    }

    #[test]
    fn delta_bundles_shape_is_checked() {
        let pgs = [0, 3, 255, 256, 300];
        let good = BTreeMap::from([
            (
                delta_bundle_path(0),
                bundle(vec![
                    section(0, 0, 1),
                    section(3, 72, 2),
                    section(255, 184, 1),
                ]),
            ),
            (delta_bundle_path(1), bundle(vec![section(256, 0, 3)])),
        ]);
        check_delta_bundles(&good, &pgs, 16384).unwrap();
        check_delta_bundles(&BTreeMap::new(), &pgs, 16384).unwrap();

        type Mutation = Box<dyn Fn(&mut BTreeMap<String, DeltaBundle>)>;
        let b0 = || delta_bundle_path(0);
        let cases: Vec<(&str, Mutation)> = vec![
            (
                "noncanonical path",
                Box::new(|m| {
                    let b = m.remove(&delta_bundle_path(1)).unwrap();
                    m.insert("bundle/1.added".into(), b);
                }),
            ),
            (
                "out of range",
                Box::new(|m| {
                    let b = m.remove(&delta_bundle_path(1)).unwrap();
                    m.insert(delta_bundle_path(64), b);
                }),
            ),
            (
                "overlap",
                Box::new(move |m| m.get_mut(&b0()).unwrap().pgs[1].offset = 40),
            ),
            (
                "gap",
                Box::new(move |m| {
                    let b = m.get_mut(&b0()).unwrap();
                    b.pgs[2].offset += 40;
                    b.size += 40;
                }),
            ),
            (
                "unsorted",
                Box::new(move |m| m.get_mut(&b0()).unwrap().pgs.swap(0, 1)),
            ),
            (
                "duplicate pg",
                Box::new(move |m| m.get_mut(&b0()).unwrap().pgs[1].pg = 0),
            ),
            (
                "pg of another bundle",
                Box::new(|m| {
                    m.get_mut(&delta_bundle_path(1)).unwrap().pgs[0].pg = 255;
                }),
            ),
            (
                "uncovered pg",
                Box::new(move |m| m.get_mut(&b0()).unwrap().pgs[1].pg = 4),
            ),
            (
                "size mismatch",
                Box::new(move |m| m.get_mut(&b0()).unwrap().size += 40),
            ),
            (
                "empty section",
                Box::new(|m| {
                    let b = m.get_mut(&delta_bundle_path(1)).unwrap();
                    b.pgs[0].size = HEADER_LEN as u64;
                    b.size = HEADER_LEN as u64;
                }),
            ),
            (
                "bad framing",
                Box::new(|m| {
                    let b = m.get_mut(&delta_bundle_path(1)).unwrap();
                    b.pgs[0].size += 1;
                    b.size += 1;
                }),
            ),
            (
                "uppercase digest",
                Box::new(move |m| {
                    m.get_mut(&b0()).unwrap().pgs[0].sha256 = "AB".repeat(32);
                }),
            ),
            (
                "bundle digest",
                Box::new(move |m| m.get_mut(&b0()).unwrap().sha256 = "x".into()),
            ),
            (
                "no section",
                Box::new(|m| {
                    let b = m.get_mut(&delta_bundle_path(1)).unwrap();
                    b.pgs.clear();
                    b.size = 0;
                }),
            ),
            (
                "oversize",
                Box::new(|m| {
                    let b = m.get_mut(&delta_bundle_path(1)).unwrap();
                    let records = (MAX_OBJECT_BYTES - HEADER_LEN as u64) / RECORD_LEN as u64 + 1;
                    b.pgs[0].size = HEADER_LEN as u64 + records * RECORD_LEN as u64;
                    b.size = b.pgs[0].size;
                }),
            ),
        ];
        for (name, mutate) in cases {
            let mut bad = good.clone();
            mutate(&mut bad);
            assert!(
                check_delta_bundles(&bad, &pgs, 16384).is_err(),
                "{name} accepted"
            );
        }
        // A bundle index valid for 16384 PGs is out of range for 300.
        let mut small = good.clone();
        small.remove(&delta_bundle_path(1));
        check_delta_bundles(&small, &[0, 3, 255], 256).unwrap();
        assert!(check_delta_bundles(&good, &pgs, 256).is_err());
    }
}

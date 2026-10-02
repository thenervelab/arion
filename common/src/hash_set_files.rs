//! Per-holder key sets (`APGS`) and the global live filter (`APGF`) of an
//! obligation-list base generation.
//!
//! A purge reader only asks three membership questions of a generation:
//! is this hash listed under me, is it listed under anyone, is it
//! tombstoned. Answering the first two from the per-PG lists forces every
//! reader named in every PG to download every list and rebuild the same
//! filters. The writer (`pg-lists`) therefore publishes, next to the
//! lists, the answer itself:
//!
//! - `holders/<uid:010>/<part:03>.hashes`: the sorted, deduplicated set of
//!   the 64-bit keys ([`blob_key`]) of every record naming `uid` as its
//!   holder, split in parts of at most [`HOLDER_SET_PART_MAX_KEYS`] keys
//!   by key range;
//! - `live/<shard:03>.bloom`: a Bloom filter over every listed hash, one
//!   filter per first hash byte ([`live_filter_shard`]), 256 in all.
//!
//! Both are declared (path, sha256, size) in the signed base manifest. The
//! writer and the reader share this codec, so the Bloom positions and the
//! key derivation can never drift.
//!
//! ## Holder set part (`APGS` v1)
//!
//! | offset | size | field |
//! |-------:|-----:|-------|
//! |  0 | 4 | magic `APGS` |
//! |  4 | 1 | version = 1 |
//! |  5 | 3 | reserved, zero |
//! |  8 | 4 | `uid` u32 LE |
//! | 12 | 4 | `part` u32 LE |
//! | 16 | 8 | `generation` u64 LE |
//! | 24 | 8 | `count` u64 LE (keys, at least one) |
//! | 32 | 8 | `key_lo` u64 LE (first key) |
//! | 40 | 8 | `key_hi` u64 LE (last key) |
//!
//! then `count` u64 LE keys, strictly ascending. Parts of one uid cover
//! disjoint ascending key ranges; a uid with no record has no part (the
//! manifest declares it with an empty list, which is not the same as an
//! absent uid). The key is the first 8 bytes of the blake3 digest: two
//! distinct hashes sharing a key make a reader keep a blob it could have
//! deleted (probability 2^-64 per pair), never the reverse.
//!
//! ## Live filter shard (`APGF` v1)
//!
//! | offset | size | field |
//! |-------:|-----:|-------|
//! |  0 | 4 | magic `APGF` |
//! |  4 | 1 | version = 1 |
//! |  5 | 3 | reserved, zero |
//! |  8 | 4 | `shard` u32 LE (< 256) |
//! | 12 | 4 | `probes` u32 LE (1..=16) |
//! | 16 | 8 | `generation` u64 LE |
//! | 24 | 8 | `bit_count` u64 LE |
//! | 32 | 8 | `inserted` u64 LE |
//! | 40 | 8 | `fp_ppm` u64 LE (target false-positive rate, parts per million) |
//!
//! then `ceil(bit_count / 64)` u64 LE words; bit `p` is bit `p % 64` of
//! word `p / 64`. Positions ([`bloom_positions`]) use bytes 8..24 of the
//! hash, independent of the shard byte and of the holder-set key: double
//! hashing `h1 + i * h2 mod bit_count`, `h1` = u64 LE of bytes 8..16,
//! `h2` = u64 LE of bytes 16..24 with the low bit set. A false positive
//! means "listed somewhere": the reader keeps the blob.

use anyhow::{Context, Result, bail, ensure};

/// Magic of a holder set part.
pub const HOLDER_SET_MAGIC: &[u8; 4] = b"APGS";
/// The only holder set version this codec reads or writes.
pub const HOLDER_SET_VERSION: u8 = 1;
/// Header length of a holder set part.
pub const HOLDER_SET_HEADER_LEN: usize = 48;
/// Most keys in one part: 16 Mi keys, 128 MiB of body.
pub const HOLDER_SET_PART_MAX_KEYS: usize = 16 << 20;

/// Magic of a live filter shard.
pub const LIVE_FILTER_MAGIC: &[u8; 4] = b"APGF";
/// The only live filter version this codec reads or writes.
pub const LIVE_FILTER_VERSION: u8 = 1;
/// Header length of a live filter shard.
pub const LIVE_FILTER_HEADER_LEN: usize = 48;
/// Number of live filter shards (one per first hash byte).
pub const LIVE_FILTER_SHARDS: u32 = 256;
/// Smallest shard ever written (8 KiB).
pub const MIN_LIVE_FILTER_BITS: u64 = 1 << 16;
/// Default target false-positive rate of the live filter (5 %).
pub const DEFAULT_LIVE_FILTER_FP_PPM: u64 = 50_000;

/// The 64-bit key of a blob hash in a holder set.
pub fn blob_key(hash: &[u8; 32]) -> u64 {
    u64::from_le_bytes(hash[0..8].try_into().expect("8 bytes"))
}

/// Directory of `uid`'s holder set parts, relative to the generation.
pub fn holder_set_dir(uid: u32) -> String {
    format!("holders/{uid:010}")
}

/// Path of part `part` of `uid`'s holder set, relative to the generation.
pub fn holder_set_path(uid: u32, part: u32) -> String {
    format!("holders/{uid:010}/{part:03}.hashes")
}

/// Path of live filter shard `shard`, relative to the generation.
pub fn live_filter_path(shard: u32) -> String {
    format!("live/{shard:03}.bloom")
}

/// The live filter shard a hash belongs to.
pub fn live_filter_shard(hash: &[u8; 32]) -> u32 {
    u32::from(hash[0])
}

fn read_u32(bytes: &[u8], at: usize) -> u32 {
    u32::from_le_bytes(bytes[at..at + 4].try_into().expect("4 bytes"))
}

fn read_u64(bytes: &[u8], at: usize) -> u64 {
    u64::from_le_bytes(bytes[at..at + 8].try_into().expect("8 bytes"))
}

fn check_prefix(bytes: &[u8], magic: &[u8; 4], version: u8, what: &str) -> Result<()> {
    ensure!(
        bytes.len() >= 48,
        "{what}: {} bytes, shorter than its header",
        bytes.len()
    );
    ensure!(&bytes[0..4] == magic, "{what}: bad magic");
    ensure!(
        bytes[4] == version,
        "{what}: unsupported version {}",
        bytes[4]
    );
    ensure!(bytes[5..8] == [0, 0, 0], "{what}: reserved bytes not zero");
    Ok(())
}

// ============================================================================
// Holder sets
// ============================================================================

/// Decoded header of a holder set part.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct HolderSetHeader {
    pub uid: u32,
    pub part: u32,
    pub generation: u64,
    pub count: u64,
    pub key_lo: u64,
    pub key_hi: u64,
}

impl HolderSetHeader {
    /// Header of a part holding `keys` (non-empty, strictly ascending).
    pub fn for_keys(uid: u32, part: u32, generation: u64, keys: &[u64]) -> Result<Self> {
        let (Some(&key_lo), Some(&key_hi)) = (keys.first(), keys.last()) else {
            bail!("holder set part {part} of uid {uid} is empty");
        };
        ensure!(
            keys.windows(2).all(|w| w[0] < w[1]),
            "holder set part {part} of uid {uid} is not strictly ascending"
        );
        Ok(Self {
            uid,
            part,
            generation,
            count: keys.len() as u64,
            key_lo,
            key_hi,
        })
    }

    pub fn encode(&self) -> [u8; HOLDER_SET_HEADER_LEN] {
        let mut out = [0u8; HOLDER_SET_HEADER_LEN];
        out[0..4].copy_from_slice(HOLDER_SET_MAGIC);
        out[4] = HOLDER_SET_VERSION;
        out[8..12].copy_from_slice(&self.uid.to_le_bytes());
        out[12..16].copy_from_slice(&self.part.to_le_bytes());
        out[16..24].copy_from_slice(&self.generation.to_le_bytes());
        out[24..32].copy_from_slice(&self.count.to_le_bytes());
        out[32..40].copy_from_slice(&self.key_lo.to_le_bytes());
        out[40..48].copy_from_slice(&self.key_hi.to_le_bytes());
        out
    }

    /// Parse the header only (magic, version, reserved bytes).
    pub fn decode(bytes: &[u8]) -> Result<Self> {
        check_prefix(bytes, HOLDER_SET_MAGIC, HOLDER_SET_VERSION, "holder set")?;
        Ok(Self {
            uid: read_u32(bytes, 8),
            part: read_u32(bytes, 12),
            generation: read_u64(bytes, 16),
            count: read_u64(bytes, 24),
            key_lo: read_u64(bytes, 32),
            key_hi: read_u64(bytes, 40),
        })
    }

    /// Exact byte length of a part with this header.
    pub fn object_len(&self) -> Result<u64> {
        self.count
            .checked_mul(8)
            .and_then(|n| n.checked_add(HOLDER_SET_HEADER_LEN as u64))
            .context("holder set length overflow")
    }
}

/// Encode one part in memory (header then keys).
pub fn encode_holder_set_part(
    uid: u32,
    part: u32,
    generation: u64,
    keys: &[u64],
) -> Result<Vec<u8>> {
    let header = HolderSetHeader::for_keys(uid, part, generation, keys)?;
    let mut out = Vec::with_capacity(usize::try_from(header.object_len()?)?);
    out.extend_from_slice(&header.encode());
    for key in keys {
        out.extend_from_slice(&key.to_le_bytes());
    }
    Ok(out)
}

/// Split a sorted key set into parts of at most `max_keys` keys, in key
/// order. An empty set has no part.
pub fn split_holder_set(keys: &[u64], max_keys: usize) -> impl Iterator<Item = &[u64]> {
    keys.chunks(max_keys.max(1))
}

/// A validated holder set part over borrowed bytes (a mmap in the reader).
#[derive(Debug, Clone, Copy)]
pub struct HolderSetView<'a> {
    header: HolderSetHeader,
    keys: &'a [u8],
}

impl<'a> HolderSetView<'a> {
    /// Check the framing and the strict order of every key. The order is
    /// what makes the binary search of [`Self::contains`] exact.
    pub fn parse(bytes: &'a [u8]) -> Result<Self> {
        let header = HolderSetHeader::decode(bytes)?;
        ensure!(
            header.object_len()? == bytes.len() as u64,
            "holder set part {} of uid {}: {} bytes, header says {} keys",
            header.part,
            header.uid,
            bytes.len(),
            header.count
        );
        ensure!(
            header.count > 0,
            "holder set part {} of uid {} is empty",
            header.part,
            header.uid
        );
        let keys = &bytes[HOLDER_SET_HEADER_LEN..];
        let view = Self { header, keys };
        let mut previous: Option<u64> = None;
        for key in view.iter() {
            if let Some(prev) = previous {
                ensure!(
                    prev < key,
                    "holder set part {} of uid {} is not strictly ascending",
                    header.part,
                    header.uid
                );
            }
            previous = Some(key);
        }
        ensure!(
            view.key(0) == header.key_lo && previous == Some(header.key_hi),
            "holder set part {} of uid {}: key range does not match its header",
            header.part,
            header.uid
        );
        Ok(view)
    }

    pub fn header(&self) -> &HolderSetHeader {
        &self.header
    }

    pub fn len(&self) -> usize {
        self.keys.len() / 8
    }

    pub fn is_empty(&self) -> bool {
        self.keys.is_empty()
    }

    fn key(&self, index: usize) -> u64 {
        read_u64(self.keys, index * 8)
    }

    pub fn iter(&self) -> impl Iterator<Item = u64> + 'a {
        let (keys, _) = self.keys.as_chunks::<8>();
        keys.iter().map(|key| u64::from_le_bytes(*key))
    }

    /// Whether `key` is in this part (binary search).
    pub fn contains(&self, key: u64) -> bool {
        if key < self.header.key_lo || key > self.header.key_hi {
            return false;
        }
        let (mut lo, mut hi) = (0usize, self.len());
        while lo < hi {
            let mid = lo + (hi - lo) / 2;
            match self.key(mid).cmp(&key) {
                std::cmp::Ordering::Equal => return true,
                std::cmp::Ordering::Less => lo = mid + 1,
                std::cmp::Ordering::Greater => hi = mid,
            }
        }
        false
    }
}

// ============================================================================
// Live filter
// ============================================================================

/// Target false-positive rate of a `fp_ppm` value, clamped to a sane range.
pub fn fp_rate(fp_ppm: u64) -> f64 {
    (fp_ppm as f64 / 1e6).clamp(1e-6, 0.5)
}

/// `(bit_count, probes)` of a Bloom filter for `expected_items` at
/// `fp_ppm`: `bits = ceil(-n ln p / ln2²)` (at least
/// [`MIN_LIVE_FILTER_BITS`]), `probes = round(bits / n * ln2)` in 1..=16.
pub fn bloom_dimensions(expected_items: u64, fp_ppm: u64) -> (u64, u32) {
    let n = expected_items.max(1) as f64;
    let p = fp_rate(fp_ppm);
    let ln2 = std::f64::consts::LN_2;
    let bit_count = ((-n * p.ln()) / (ln2 * ln2))
        .ceil()
        .max(MIN_LIVE_FILTER_BITS as f64) as u64;
    let probes = ((bit_count as f64 / n) * ln2).round().clamp(1.0, 16.0) as u32;
    (bit_count, probes)
}

/// Bytes of the bit array of a `bit_count`-bit filter.
pub fn bloom_bytes(bit_count: u64) -> u64 {
    bit_count.div_ceil(64) * 8
}

/// Bit positions of `hash` in a `bit_count`-bit filter with `probes` probes.
pub fn bloom_positions(hash: &[u8; 32], bit_count: u64, probes: u32) -> impl Iterator<Item = u64> {
    let h1 = read_u64(hash, 8);
    let h2 = read_u64(hash, 16) | 1;
    (0..u64::from(probes)).map(move |i| h1.wrapping_add(i.wrapping_mul(h2)) % bit_count)
}

/// Decoded header of a live filter shard.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct LiveFilterHeader {
    pub shard: u32,
    pub probes: u32,
    pub generation: u64,
    pub bit_count: u64,
    pub inserted: u64,
    pub fp_ppm: u64,
}

impl LiveFilterHeader {
    pub fn encode(&self) -> [u8; LIVE_FILTER_HEADER_LEN] {
        let mut out = [0u8; LIVE_FILTER_HEADER_LEN];
        out[0..4].copy_from_slice(LIVE_FILTER_MAGIC);
        out[4] = LIVE_FILTER_VERSION;
        out[8..12].copy_from_slice(&self.shard.to_le_bytes());
        out[12..16].copy_from_slice(&self.probes.to_le_bytes());
        out[16..24].copy_from_slice(&self.generation.to_le_bytes());
        out[24..32].copy_from_slice(&self.bit_count.to_le_bytes());
        out[32..40].copy_from_slice(&self.inserted.to_le_bytes());
        out[40..48].copy_from_slice(&self.fp_ppm.to_le_bytes());
        out
    }

    /// Parse and range-check the header.
    pub fn decode(bytes: &[u8]) -> Result<Self> {
        check_prefix(bytes, LIVE_FILTER_MAGIC, LIVE_FILTER_VERSION, "live filter")?;
        let header = Self {
            shard: read_u32(bytes, 8),
            probes: read_u32(bytes, 12),
            generation: read_u64(bytes, 16),
            bit_count: read_u64(bytes, 24),
            inserted: read_u64(bytes, 32),
            fp_ppm: read_u64(bytes, 40),
        };
        ensure!(
            header.shard < LIVE_FILTER_SHARDS,
            "live filter: shard {} out of range",
            header.shard
        );
        ensure!(
            (1..=16).contains(&header.probes),
            "live filter: {} probes",
            header.probes
        );
        ensure!(header.bit_count > 0, "live filter: zero bits");
        Ok(header)
    }

    /// Exact byte length of a shard with this header.
    pub fn object_len(&self) -> u64 {
        LIVE_FILTER_HEADER_LEN as u64 + bloom_bytes(self.bit_count)
    }
}

/// One live filter shard being built.
#[derive(Debug, Clone)]
pub struct LiveFilterBuilder {
    header: LiveFilterHeader,
    bits: Vec<u8>,
}

impl LiveFilterBuilder {
    /// A shard sized for `expected_items` hashes at `fp_ppm`.
    pub fn new(shard: u32, generation: u64, expected_items: u64, fp_ppm: u64) -> Result<Self> {
        ensure!(
            shard < LIVE_FILTER_SHARDS,
            "live filter: shard {shard} out of range"
        );
        let (bit_count, probes) = bloom_dimensions(expected_items, fp_ppm);
        let bytes = usize::try_from(bloom_bytes(bit_count))?;
        Ok(Self {
            header: LiveFilterHeader {
                shard,
                probes,
                generation,
                bit_count,
                inserted: 0,
                fp_ppm,
            },
            bits: vec![0u8; bytes],
        })
    }

    pub fn header(&self) -> &LiveFilterHeader {
        &self.header
    }

    /// Insert a hash; it must belong to this shard.
    pub fn insert(&mut self, hash: &[u8; 32]) -> Result<()> {
        ensure!(
            live_filter_shard(hash) == self.header.shard,
            "hash of shard {} inserted into live filter shard {}",
            live_filter_shard(hash),
            self.header.shard
        );
        for pos in bloom_positions(hash, self.header.bit_count, self.header.probes) {
            self.bits[(pos >> 3) as usize] |= 1u8 << (pos & 7);
        }
        self.header.inserted += 1;
        Ok(())
    }

    /// Header then bit array (the bytes of the published object).
    pub fn encode(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(LIVE_FILTER_HEADER_LEN + self.bits.len());
        out.extend_from_slice(&self.header.encode());
        out.extend_from_slice(&self.bits);
        out
    }

    pub fn memory_bytes(&self) -> u64 {
        self.bits.len() as u64
    }
}

/// A validated live filter shard over borrowed bytes (a mmap in the reader).
#[derive(Debug, Clone, Copy)]
pub struct LiveFilterView<'a> {
    header: LiveFilterHeader,
    bits: &'a [u8],
}

impl<'a> LiveFilterView<'a> {
    pub fn parse(bytes: &'a [u8]) -> Result<Self> {
        let header = LiveFilterHeader::decode(bytes)?;
        ensure!(
            header.object_len() == bytes.len() as u64,
            "live filter shard {}: {} bytes, header says {} bits",
            header.shard,
            bytes.len(),
            header.bit_count
        );
        Ok(Self {
            header,
            bits: &bytes[LIVE_FILTER_HEADER_LEN..],
        })
    }

    pub fn header(&self) -> &LiveFilterHeader {
        &self.header
    }

    /// `false`: the hash is listed nowhere in the generation. `true`:
    /// probably listed (keep). A hash of another shard is never in it.
    pub fn contains(&self, hash: &[u8; 32]) -> bool {
        if live_filter_shard(hash) != self.header.shard {
            return false;
        }
        bloom_positions(hash, self.header.bit_count, self.header.probes)
            .all(|pos| self.bits[(pos >> 3) as usize] & (1u8 << (pos & 7)) != 0)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn hash(i: u64, salt: u8) -> [u8; 32] {
        *blake3::hash(&[&i.to_le_bytes()[..], &[salt]].concat()).as_bytes()
    }

    #[test]
    fn holder_set_round_trip() {
        let mut keys: Vec<u64> = (0..1000).map(|i| blob_key(&hash(i, 0))).collect();
        keys.sort_unstable();
        keys.dedup();
        let bytes = encode_holder_set_part(7, 2, 11, &keys).unwrap();
        let view = HolderSetView::parse(&bytes).unwrap();
        assert_eq!(
            *view.header(),
            HolderSetHeader {
                uid: 7,
                part: 2,
                generation: 11,
                count: keys.len() as u64,
                key_lo: keys[0],
                key_hi: *keys.last().unwrap(),
            }
        );
        assert_eq!(view.iter().collect::<Vec<_>>(), keys);
        for key in &keys {
            assert!(view.contains(*key));
        }
        for i in 1000..2000 {
            let key = blob_key(&hash(i, 0));
            assert_eq!(view.contains(key), keys.binary_search(&key).is_ok());
        }
    }

    #[test]
    fn holder_set_rejects_bad_framing() {
        let bytes = encode_holder_set_part(1, 0, 3, &[1, 5, 9]).unwrap();
        assert!(HolderSetView::parse(&bytes[..bytes.len() - 1]).is_err());
        let mut bad = bytes.clone();
        bad[0] = b'X';
        assert!(HolderSetView::parse(&bad).is_err());
        let mut bad = bytes.clone();
        bad[4] = 2;
        assert!(HolderSetView::parse(&bad).is_err());
        let mut bad = bytes.clone();
        bad[48..56].copy_from_slice(&6u64.to_le_bytes());
        assert!(HolderSetView::parse(&bad).is_err(), "order and key_lo");
        let mut bad = bytes.clone();
        bad[40..48].copy_from_slice(&10u64.to_le_bytes());
        assert!(HolderSetView::parse(&bad).is_err(), "key_hi");
        assert!(encode_holder_set_part(1, 0, 3, &[]).is_err());
        assert!(encode_holder_set_part(1, 0, 3, &[2, 2]).is_err());
        assert!(encode_holder_set_part(1, 0, 3, &[3, 2]).is_err());
    }

    #[test]
    fn holder_set_split_at_bounds() {
        let keys: Vec<u64> = (0..10u64).map(|k| k * 3).collect();
        let parts: Vec<&[u64]> = split_holder_set(&keys, 4).collect();
        assert_eq!(parts.len(), 3);
        assert_eq!(parts[0], &[0, 3, 6, 9]);
        assert_eq!(parts[1], &[12, 15, 18, 21]);
        assert_eq!(parts[2], &[24, 27]);
        assert_eq!(split_holder_set(&keys[..8], 4).count(), 2, "exact multiple");
        assert_eq!(split_holder_set(&keys[..4], 4).count(), 1);
        assert_eq!(split_holder_set(&[], 4).count(), 0);
        for (i, part) in split_holder_set(&keys, 4).enumerate() {
            let bytes = encode_holder_set_part(9, i as u32, 1, part).unwrap();
            let view = HolderSetView::parse(&bytes).unwrap();
            assert_eq!(view.header().key_lo, part[0]);
            assert_eq!(view.header().key_hi, *part.last().unwrap());
        }
        assert_eq!(HOLDER_SET_PART_MAX_KEYS as u64 * 8 + 48, (128 << 20) + 48);
        assert_eq!(holder_set_path(42, 3), "holders/0000000042/003.hashes");
        assert_eq!(live_filter_path(7), "live/007.bloom");
    }

    #[test]
    fn live_filter_round_trip_and_no_false_negative() {
        const N: u64 = 1_000_000;
        let per_shard = N.div_ceil(u64::from(LIVE_FILTER_SHARDS)) + 1024;
        let mut builders: Vec<LiveFilterBuilder> = (0..LIVE_FILTER_SHARDS)
            .map(|s| LiveFilterBuilder::new(s, 5, per_shard, DEFAULT_LIVE_FILTER_FP_PPM).unwrap())
            .collect();
        for i in 0..N {
            let h = hash(i, 1);
            builders[live_filter_shard(&h) as usize].insert(&h).unwrap();
        }
        let encoded: Vec<Vec<u8>> = builders.iter().map(LiveFilterBuilder::encode).collect();
        let views: Vec<LiveFilterView<'_>> = encoded
            .iter()
            .map(|b| LiveFilterView::parse(b).unwrap())
            .collect();
        for (s, view) in views.iter().enumerate() {
            assert_eq!(view.header().shard, s as u32);
            assert_eq!(view.header().generation, 5);
            assert_eq!(*view.header(), *builders[s].header());
        }
        let inserted: u64 = views.iter().map(|v| v.header().inserted).sum();
        assert_eq!(inserted, N);
        for i in 0..N {
            let h = hash(i, 1);
            assert!(
                views[live_filter_shard(&h) as usize].contains(&h),
                "false negative"
            );
        }
        let trials = 200_000u64;
        let hits = (0..trials)
            .filter(|i| {
                let h = hash(*i, 2);
                views[live_filter_shard(&h) as usize].contains(&h)
            })
            .count() as f64;
        let measured = hits / trials as f64;
        assert!(
            measured <= 1.5 * fp_rate(DEFAULT_LIVE_FILTER_FP_PPM),
            "fp {measured}"
        );
        let other = views[0];
        let foreign = (0..)
            .map(|i| hash(i, 3))
            .find(|h| live_filter_shard(h) == 1)
            .unwrap();
        assert!(
            !other.contains(&foreign),
            "a hash of another shard is never in it"
        );
    }

    #[test]
    fn live_filter_positions_match_between_writer_and_reader() {
        let h = (0..)
            .map(|i| hash(i, 4))
            .find(|h| live_filter_shard(h) == 3)
            .unwrap();
        let mut builder = LiveFilterBuilder::new(3, 1, 10, 10_000).unwrap();
        builder.insert(&h).unwrap();
        let bytes = builder.encode();
        let header = LiveFilterHeader::decode(&bytes).unwrap();
        let mut set = 0;
        for pos in bloom_positions(&h, header.bit_count, header.probes) {
            let word = read_u64(&bytes[LIVE_FILTER_HEADER_LEN..], (pos / 64) as usize * 8);
            assert_ne!(word & (1u64 << (pos % 64)), 0, "bit {pos} set as word bit");
            set += 1;
        }
        assert_eq!(set, header.probes);
        let ones: u32 = bytes[LIVE_FILTER_HEADER_LEN..]
            .iter()
            .map(|b| b.count_ones())
            .sum();
        assert!(ones <= header.probes);
        assert!(LiveFilterView::parse(&bytes).unwrap().contains(&h));
    }

    #[test]
    fn live_filter_rejects_bad_framing() {
        let bytes = LiveFilterBuilder::new(9, 1, 100, 50_000).unwrap().encode();
        assert!(LiveFilterView::parse(&bytes[..bytes.len() - 8]).is_err());
        let mut bad = bytes.clone();
        bad[8..12].copy_from_slice(&256u32.to_le_bytes());
        assert!(LiveFilterView::parse(&bad).is_err());
        let mut bad = bytes.clone();
        bad[12..16].copy_from_slice(&0u32.to_le_bytes());
        assert!(LiveFilterView::parse(&bad).is_err());
        let mut bad = bytes.clone();
        bad[5] = 1;
        assert!(LiveFilterView::parse(&bad).is_err());
        let wrong = (0..)
            .map(|i| hash(i, 5))
            .find(|h| live_filter_shard(h) != 9)
            .unwrap();
        let mut builder = LiveFilterBuilder::new(9, 1, 100, 50_000).unwrap();
        assert!(builder.insert(&wrong).is_err());
    }

    #[test]
    fn bloom_dimensions_follow_the_formula() {
        let (bits, probes) = bloom_dimensions(1_000_000, 50_000);
        assert_eq!(bits, 6_235_225);
        assert_eq!(probes, 4);
        let (bits, _) = bloom_dimensions(1, 50_000);
        assert_eq!(bits, MIN_LIVE_FILTER_BITS);
    }
}

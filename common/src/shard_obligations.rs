//! Per-shard obligation projection of a file manifest.
//!
//! An obligation list record (`obligation_list::Record`) is
//! `(blob_hash, shard_length, holder_uid)`. The first two are pure
//! functions of the manifest; the holder depends on the cluster map and is
//! computed when a list is exported. This module projects a manifest into
//! the map-independent part: one row per shard the manifest carries, keyed
//! by the global shard index, plus the PG the file belongs to. The
//! validator writes these rows into the `shard_obligations` table in the
//! same transaction as the manifest; the list exporter reads them back
//! instead of decoding every manifest payload.
//!
//! Eligibility is the exporter's: a manifest that would not be listed
//! (legacy placement, malformed geometry, non-canonical hash) yields an
//! [`ObligationSkip`] and no rows, so the table and the lists agree on
//! which files exist.

use std::fmt;

use crate::obligation_list::is_pg_placement_version;
use crate::storage_proof::derive_shard_geometry_for_manifest;
use crate::{FileManifest, calculate_pg};

/// One shard the manifest carries.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ObligationRow {
    /// Global shard index, `stripe_idx * (k + m) + shard_idx`
    /// (`ShardInfo::index`).
    pub shard_index: u32,
    /// BLAKE3 of the shard bytes.
    pub blob_hash: [u8; 32],
    /// Byte length of the shard on disk (storage-proof geometry, padded
    /// last stripe included), as the list record carries it.
    pub shard_length: u32,
}

/// The rows of one manifest and what identifies the file.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ObligationProjection {
    /// BLAKE3 of the file (the manifest's `file_hash`, decoded).
    pub file_hash: [u8; 32],
    /// `calculate_pg(file_hash, pg_count)`.
    pub pg_id: u32,
    pub placement_version: u8,
    /// The file's erasure parameters: `shard_index` decomposes into
    /// `(stripe, position)` by `k + m`, and an export lists only the files
    /// whose parameters equal the generation's.
    pub ec_k: u8,
    pub ec_m: u8,
    /// In ascending shard index order, no duplicates.
    pub rows: Vec<ObligationRow>,
    /// Shard indices below `stripes * (k + m)` the manifest does not carry.
    /// A live manifest may legitimately miss some (the gateway acknowledges
    /// once every stripe holds at least `k`); they are counted, never
    /// fabricated.
    pub missing: u64,
}

/// Why a manifest has no obligation rows. The variants mirror the
/// exporter's skip classes so operators see the same counters.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ObligationSkip {
    /// `placement_version` is not PG-based (legacy 1): the file has no PG
    /// and no list.
    LegacyPlacement(u8),
    /// Erasure parameters outside the list codec's header (`k`, `m` must
    /// fit one byte each, `k + m` must not exceed 255, both non-zero).
    ErasureOutOfRange {
        k: usize,
        m: usize,
    },
    ZeroStripeSize,
    /// `file_hash` is not 64 lowercase hex characters. Placement hashes the
    /// text, so a differently-cased hash would be a different file.
    NonCanonicalFileHash,
    /// The size implies at least one shard and the manifest carries none.
    NoShard,
    /// More shards than `stripes * (k + m)`.
    TooManyShards {
        present: usize,
        expected: u64,
    },
    ShardIndexOutOfRange {
        index: u64,
        count: u64,
    },
    DuplicateShardIndex(u64),
    /// A shard's `blob_hash` is not 64 hex characters.
    InvalidShardHash(u64),
    /// The same blob hash appears with two lengths (the list codec refuses
    /// such a list, `normalize_records`).
    ConflictingShardLength(u64),
    /// The storage-proof geometry refused the index.
    Geometry {
        index: u64,
        reason: String,
    },
    ShardCountOverflow,
    PgCalculation(String),
}

impl fmt::Display for ObligationSkip {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::LegacyPlacement(v) => write!(f, "placement_version {v} is not PG-based"),
            Self::ErasureOutOfRange { k, m } => {
                write!(f, "erasure parameters {k}+{m} outside the list header")
            }
            Self::ZeroStripeSize => write!(f, "zero stripe size"),
            Self::NonCanonicalFileHash => write!(f, "file hash is not canonical lowercase hex"),
            Self::NoShard => write!(f, "manifest carries no shard"),
            Self::TooManyShards { present, expected } => {
                write!(f, "{present} shards but the size implies {expected}")
            }
            Self::ShardIndexOutOfRange { index, count } => {
                write!(f, "shard index {index} out of range (count {count})")
            }
            Self::DuplicateShardIndex(i) => write!(f, "duplicate shard index {i}"),
            Self::InvalidShardHash(i) => write!(f, "shard {i}: blob hash is not hex"),
            Self::ConflictingShardLength(i) => {
                write!(f, "shard {i}: blob hash already listed with another length")
            }
            Self::Geometry { index, reason } => write!(f, "shard {index}: geometry: {reason}"),
            Self::ShardCountOverflow => write!(f, "shard count overflow"),
            Self::PgCalculation(e) => write!(f, "pg calculation: {e}"),
        }
    }
}

impl std::error::Error for ObligationSkip {}

/// Label for metrics and logs, one per variant.
impl ObligationSkip {
    pub fn label(&self) -> &'static str {
        match self {
            Self::LegacyPlacement(_) => "legacy_placement",
            Self::ErasureOutOfRange { .. } => "erasure_out_of_range",
            Self::ZeroStripeSize => "zero_stripe_size",
            Self::NonCanonicalFileHash => "non_canonical_file_hash",
            Self::NoShard => "no_shard",
            Self::TooManyShards { .. } => "too_many_shards",
            Self::ShardIndexOutOfRange { .. } => "shard_index_out_of_range",
            Self::DuplicateShardIndex(_) => "duplicate_shard_index",
            Self::InvalidShardHash(_) => "invalid_shard_hash",
            Self::ConflictingShardLength(_) => "conflicting_shard_length",
            Self::Geometry { .. } => "geometry",
            Self::ShardCountOverflow => "shard_count_overflow",
            Self::PgCalculation(_) => "pg_calculation",
        }
    }
}

/// The file hash must be canonical lowercase: placement hashes the text.
fn decode_file_hash(text: &str) -> Option<[u8; 32]> {
    if !text
        .bytes()
        .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
    {
        return None;
    }
    decode_blob_hash(text)
}

/// A shard hash is bytes: any case is accepted, as the exporter does.
fn decode_blob_hash(text: &str) -> Option<[u8; 32]> {
    if text.len() != 64 {
        return None;
    }
    let mut out = [0u8; 32];
    hex::decode_to_slice(text, &mut out).ok()?;
    Some(out)
}

/// Project `manifest` into its obligation rows.
///
/// Same eligibility and the same per-shard derivation as the list
/// exporter (`pg-lists` `manifest_records`), minus the holder: shards are
/// taken in ascending global index, every index must be unique and below
/// the count the size implies, the shard length comes from the
/// storage-proof geometry. One deliberate difference: the exporter also
/// requires the manifest's erasure parameters to equal the generation's
/// (and the map's); that is a property of one export, not of the file,
/// so the table keeps every valid geometry and the exporter filters on
/// `placement_version`/EC when it reads the rows.
pub fn project_obligations(
    manifest: &FileManifest,
    pg_count: u32,
) -> Result<ObligationProjection, ObligationSkip> {
    if !is_pg_placement_version(manifest.placement_version) {
        return Err(ObligationSkip::LegacyPlacement(manifest.placement_version));
    }
    let config = &manifest.stripe_config;
    let (k, m) = (config.k, config.m);
    // The list header's own rule (`obligation_list::validate_ec`).
    if k == 0 || m == 0 || k > 255 || m > 255 || k + m > 256 {
        return Err(ObligationSkip::ErasureOutOfRange { k, m });
    }
    if config.size == 0 {
        return Err(ObligationSkip::ZeroStripeSize);
    }
    let file_hash =
        decode_file_hash(&manifest.file_hash).ok_or(ObligationSkip::NonCanonicalFileHash)?;
    let pg_id =
        calculate_pg(&manifest.file_hash, pg_count).map_err(ObligationSkip::PgCalculation)?;
    let shards_per_stripe = (k + m) as u64;
    let count = manifest
        .size
        .div_ceil(config.size)
        .checked_mul(shards_per_stripe)
        .ok_or(ObligationSkip::ShardCountOverflow)?;
    if count > 0 && manifest.shards.is_empty() {
        return Err(ObligationSkip::NoShard);
    }
    if manifest.shards.len() as u64 > count {
        return Err(ObligationSkip::TooManyShards {
            present: manifest.shards.len(),
            expected: count,
        });
    }
    let mut shards: Vec<_> = manifest.shards.iter().collect();
    shards.sort_unstable_by_key(|shard| shard.index);
    let mut rows = Vec::with_capacity(shards.len());
    let mut missing = 0u64;
    let mut expected = 0u64;
    // One length per blob hash within the file, as the list codec requires
    // of a list (`normalize_records`).
    let mut lengths: std::collections::HashMap<[u8; 32], u32> = std::collections::HashMap::new();
    for shard in shards {
        let index = shard.index as u64;
        if index >= count {
            return Err(ObligationSkip::ShardIndexOutOfRange { index, count });
        }
        if index < expected {
            return Err(ObligationSkip::DuplicateShardIndex(index));
        }
        missing += index - expected;
        expected = index + 1;
        let blob_hash =
            decode_blob_hash(&shard.blob_hash).ok_or(ObligationSkip::InvalidShardHash(index))?;
        let geometry = derive_shard_geometry_for_manifest(manifest.size, config, shard.index)
            .map_err(|e| ObligationSkip::Geometry {
                index,
                reason: e.to_string(),
            })?;
        let shard_length =
            u32::try_from(geometry.shard_length).map_err(|_| ObligationSkip::Geometry {
                index,
                reason: "shard length exceeds the record width".to_string(),
            })?;
        if *lengths.entry(blob_hash).or_insert(shard_length) != shard_length {
            return Err(ObligationSkip::ConflictingShardLength(index));
        }
        rows.push(ObligationRow {
            shard_index: u32::try_from(index)
                .map_err(|_| ObligationSkip::ShardIndexOutOfRange { index, count })?,
            blob_hash,
            shard_length,
        });
    }
    missing += count - expected;
    Ok(ObligationProjection {
        file_hash,
        pg_id,
        placement_version: manifest.placement_version,
        ec_k: k as u8,
        ec_m: m as u8,
        rows,
        missing,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{ShardInfo, StripeConfig};

    const PG_COUNT: u32 = 16_384;

    fn hex64(seed: u8) -> String {
        hex::encode([seed; 32])
    }

    fn manifest(size: u64, indices: &[usize]) -> FileManifest {
        FileManifest {
            file_hash: hex64(0xab),
            placement_version: 2,
            placement_epoch: 7,
            size,
            stripe_config: StripeConfig {
                size: 1024,
                k: 2,
                m: 1,
            },
            shards: indices
                .iter()
                .map(|&i| ShardInfo {
                    index: i,
                    blob_hash: hex64(i as u8),
                })
                .collect(),
            filename: None,
            content_type: None,
            shard_holders: vec![],
        }
    }

    #[test]
    fn complete_manifest_projects_every_shard_in_index_order() {
        // 2 stripes of 3 shards, given out of order.
        let m = manifest(2000, &[5, 0, 3, 1, 4, 2]);
        let p = project_obligations(&m, PG_COUNT).unwrap();
        assert_eq!(p.pg_id, calculate_pg(&m.file_hash, PG_COUNT).unwrap());
        assert_eq!(p.placement_version, 2);
        assert_eq!(p.missing, 0);
        let idx: Vec<u32> = p.rows.iter().map(|r| r.shard_index).collect();
        assert_eq!(idx, vec![0, 1, 2, 3, 4, 5]);
        assert_eq!(p.rows[4].blob_hash, [4u8; 32]);
        assert_eq!(p.file_hash, [0xab; 32]);
        // k = 2, stripe 1024 → 512 bytes per shard of the full stripe 0;
        // stripe 1 carries the remaining 976 bytes, so its shards are
        // shorter. The length is per stripe, never per shard position.
        let full = p.rows[0].shard_length;
        let last = p.rows[3].shard_length;
        assert!(full > 0);
        assert!(p.rows[..3].iter().all(|r| r.shard_length == full));
        assert!(p.rows[3..].iter().all(|r| r.shard_length == last));
        assert!(last > 0 && last <= full);
    }

    #[test]
    fn partial_manifest_counts_missing_indices() {
        let m = manifest(2000, &[0, 1, 3, 5]);
        let p = project_obligations(&m, PG_COUNT).unwrap();
        assert_eq!(p.rows.len(), 4);
        assert_eq!(p.missing, 2);
    }

    #[test]
    fn legacy_placement_is_a_skip() {
        let mut m = manifest(2000, &[0, 1, 2, 3, 4, 5]);
        m.placement_version = 1;
        assert_eq!(
            project_obligations(&m, PG_COUNT).unwrap_err(),
            ObligationSkip::LegacyPlacement(1)
        );
    }

    #[test]
    fn malformed_manifests_are_skips_not_rows() {
        let m = manifest(2000, &[0, 1, 2, 3, 4, 6]);
        assert!(matches!(
            project_obligations(&m, PG_COUNT).unwrap_err(),
            ObligationSkip::ShardIndexOutOfRange { index: 6, count: 6 }
        ));
        let m = manifest(2000, &[0, 1, 1, 3, 4, 5]);
        assert_eq!(
            project_obligations(&m, PG_COUNT).unwrap_err(),
            ObligationSkip::DuplicateShardIndex(1)
        );
        let m = manifest(2000, &[0, 1, 2, 3, 4, 5, 6]);
        assert!(matches!(
            project_obligations(&m, PG_COUNT).unwrap_err(),
            ObligationSkip::TooManyShards { .. }
        ));
        let mut m = manifest(2000, &[0, 1, 2]);
        m.file_hash = m.file_hash.to_uppercase();
        assert_eq!(
            project_obligations(&m, PG_COUNT).unwrap_err(),
            ObligationSkip::NonCanonicalFileHash
        );
        let mut m = manifest(2000, &[0, 1, 2]);
        m.shards[1].blob_hash = "nothex".to_string();
        assert_eq!(
            project_obligations(&m, PG_COUNT).unwrap_err(),
            ObligationSkip::InvalidShardHash(1)
        );
        let m = manifest(2000, &[]);
        assert_eq!(
            project_obligations(&m, PG_COUNT).unwrap_err(),
            ObligationSkip::NoShard
        );
    }

    #[test]
    fn shard_hashes_accept_any_case_but_the_file_hash_must_be_canonical() {
        let mut m = manifest(2000, &[0, 1, 2, 3, 4, 5]);
        m.shards[2].blob_hash = m.shards[2].blob_hash.to_uppercase();
        let p = project_obligations(&m, PG_COUNT).unwrap();
        assert_eq!(p.rows[2].blob_hash, [2u8; 32]);
    }

    #[test]
    fn one_blob_hash_with_two_lengths_is_a_skip() {
        // Shard 3 (first of the shorter last stripe) reuses shard 0's hash.
        let mut m = manifest(2000, &[0, 1, 2, 3, 4, 5]);
        m.shards[3].blob_hash = m.shards[0].blob_hash.clone();
        assert_eq!(
            project_obligations(&m, PG_COUNT).unwrap_err(),
            ObligationSkip::ConflictingShardLength(3)
        );
        // The same hash at the same length (two stripes of equal length)
        // is fine: 2048 bytes = two full stripes.
        let mut m = manifest(2048, &[0, 1, 2, 3, 4, 5]);
        m.shards[3].blob_hash = m.shards[0].blob_hash.clone();
        assert_eq!(project_obligations(&m, PG_COUNT).unwrap().rows.len(), 6);
    }

    #[test]
    fn empty_file_has_no_rows_and_is_not_a_skip() {
        let m = manifest(0, &[]);
        let p = project_obligations(&m, PG_COUNT).unwrap();
        assert!(p.rows.is_empty());
        assert_eq!(p.missing, 0);
    }
}

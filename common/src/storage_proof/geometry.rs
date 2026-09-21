//! Authoritative shard geometry for the storage-proof protocol (spec §1).
//!
//! `derive_shard_geometry` is the single pure derivation shared by the miner
//! (outboard construction, challenge admission) and the verifier (challenge
//! emission, response controls). It reads no clock, file, network or
//! database, and never saturates: every arithmetic failure is an error.

use bao_tree::{BaoTree, BlockSize};

use crate::StripeConfig;

/// Bao chunk size in bytes (grouping log 0).
pub const CHUNK_SIZE: u64 = 1024;
/// Largest shard length admitted by protocol v1 (256 MiB).
pub const MAX_SHARD_LENGTH: u64 = 268_435_456;
/// Largest chunk count that follows from [`MAX_SHARD_LENGTH`].
pub const MAX_CHUNK_COUNT: u64 = 262_144;
/// Largest single-chunk proof depth that follows from [`MAX_CHUNK_COUNT`].
pub const MAX_PROOF_DEPTH: u64 = 18;
/// Largest number of shards in one stripe (`k + m`).
pub const MAX_SHARDS_PER_STRIPE: u64 = 256;
/// Number of distinct chunks challenged per shard in v1.
pub const CHALLENGE_CHUNK_COUNT: usize = 4;

/// Result of the common derivation, all fields in `u64`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ShardGeometry {
    /// Stripe holding this shard (`shard_index / (k + m)`).
    pub stripe_index: u64,
    /// Position of the shard inside its stripe (`shard_index % (k + m)`).
    pub shard_in_stripe: u64,
    /// Number of source bytes fed to `encode_stripe` for this stripe.
    pub stripe_data_len: u64,
    /// Stored length of every shard of the stripe, RS padding included.
    pub shard_length: u64,
    /// Number of Bao chunks of 1024 bytes covering `shard_length`.
    pub chunk_count: u64,
    /// Length of the last chunk, in `1..=1024`.
    pub last_chunk_length: u64,
}

impl ShardGeometry {
    /// The Bao geometry prescribed by spec §1: chunk grouping zero.
    pub fn bao_tree(&self) -> BaoTree {
        BaoTree::new(self.shard_length, BlockSize::ZERO)
    }

    /// Length in bytes of chunk `index`, or `None` when out of bounds.
    pub fn chunk_length(&self, index: u64) -> Option<u64> {
        if index >= self.chunk_count {
            return None;
        }
        Some((self.shard_length - index * CHUNK_SIZE).min(CHUNK_SIZE))
    }

    /// Whether the shard is eligible for a four-chunk challenge.
    pub fn eligible_for_challenge(&self) -> bool {
        self.chunk_count >= CHALLENGE_CHUNK_COUNT as u64
    }
}

/// Derivation failure, in spec order of control.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum GeometryError {
    /// Zero sizes or counts, `k + m > 256`, or a manifest value that does
    /// not fit its wire type.
    InvalidParameters,
    /// `stripe_index * stripe_size` overflowed `u64`.
    ArithmeticOverflow,
    /// The stripe starts at or after the end of the file.
    StripeOutOfBounds,
    /// The shard length is outside `1..=256 MiB`.
    ShardLengthOutOfBounds,
}

impl std::fmt::Display for GeometryError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let text = match self {
            Self::InvalidParameters => "invalid geometry parameters",
            Self::ArithmeticOverflow => "geometry arithmetic overflow",
            Self::StripeOutOfBounds => "stripe beyond end of file",
            Self::ShardLengthOutOfBounds => "shard length outside 1..=256 MiB",
        };
        f.write_str(text)
    }
}

impl std::error::Error for GeometryError {}

/// Derive the authoritative geometry of shard `shard_index` (spec §1).
///
/// This reproduces `calculate_shard_size` after input validation, without its
/// zero sentinel or saturating conversions. All arithmetic is checked `u64`.
pub fn derive_shard_geometry(
    file_size: u64,
    stripe_size: u64,
    k: u16,
    m: u16,
    shard_index: u64,
) -> Result<ShardGeometry, GeometryError> {
    if file_size == 0 || stripe_size == 0 || k == 0 || m == 0 {
        return Err(GeometryError::InvalidParameters);
    }
    let w = u64::from(k) + u64::from(m);
    if w > MAX_SHARDS_PER_STRIPE {
        return Err(GeometryError::InvalidParameters);
    }
    let stripe_index = shard_index / w;
    let shard_in_stripe = shard_index % w;
    let stripe_start = stripe_index
        .checked_mul(stripe_size)
        .ok_or(GeometryError::ArithmeticOverflow)?;
    if stripe_start >= file_size {
        return Err(GeometryError::StripeOutOfBounds);
    }
    let stripe_data_len = stripe_size.min(file_size - stripe_start);
    let k = u64::from(k);
    let shard_length = stripe_data_len / k + u64::from(!stripe_data_len.is_multiple_of(k));
    if !(1..=MAX_SHARD_LENGTH).contains(&shard_length) {
        return Err(GeometryError::ShardLengthOutOfBounds);
    }
    let chunk_count =
        shard_length / CHUNK_SIZE + u64::from(!shard_length.is_multiple_of(CHUNK_SIZE));
    let last_chunk_length = shard_length - (chunk_count - 1) * CHUNK_SIZE;
    Ok(ShardGeometry {
        stripe_index,
        shard_in_stripe,
        stripe_data_len,
        shard_length,
        chunk_count,
        last_chunk_length,
    })
}

/// Convert a manifest's stripe configuration and global shard index to the
/// normative `(u64, u64, u16, u16, u64)` inputs, then derive.
///
/// Values that do not fit their wire type are `InvalidParameters`, never
/// truncated. Callers validate that the index exists in the manifest before
/// converting it.
pub fn derive_shard_geometry_for_manifest(
    file_size: u64,
    stripe_config: &StripeConfig,
    shard_index: usize,
) -> Result<ShardGeometry, GeometryError> {
    let k = u16::try_from(stripe_config.k).map_err(|_| GeometryError::InvalidParameters)?;
    let m = u16::try_from(stripe_config.m).map_err(|_| GeometryError::InvalidParameters)?;
    let shard_index = u64::try_from(shard_index).map_err(|_| GeometryError::InvalidParameters)?;
    derive_shard_geometry(file_size, stripe_config.size, k, m, shard_index)
}

/// Depth of the single-chunk Bao path for chunk `index` in a tree of
/// `chunk_count` leaves (spec §2), computed without reading any proof.
///
/// Zero for one leaf; otherwise split at the largest power of two strictly
/// below the leaf count, descend into the side holding `index`, add one.
pub fn proof_depth(index: u64, chunk_count: u64) -> Option<u64> {
    if chunk_count == 0 || index >= chunk_count {
        return None;
    }
    let mut depth = 0;
    let mut index = index;
    let mut leaves = chunk_count;
    while leaves > 1 {
        let left = largest_power_of_two_below(leaves);
        if index < left {
            leaves = left;
        } else {
            index -= left;
            leaves -= left;
        }
        depth += 1;
    }
    Some(depth)
}

fn largest_power_of_two_below(n: u64) -> u64 {
    debug_assert!(n > 1);
    1u64 << (63 - (n - 1).leading_zeros())
}

/// Exact byte length of the proof slice for chunk `index`:
/// `chunk_length + 64 * depth`.
pub fn expected_proof_length(geometry: &ShardGeometry, index: u64) -> Option<u64> {
    let chunk_length = geometry.chunk_length(index)?;
    let depth = proof_depth(index, geometry.chunk_count)?;
    Some(chunk_length + 64 * depth)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{calculate_shard_size, calculate_stripe_data_len, encode_stripe};

    fn geom(file_size: u64, stripe_size: u64, index: u64) -> Result<ShardGeometry, GeometryError> {
        derive_shard_geometry(file_size, stripe_size, 10, 20, index)
    }

    #[test]
    fn normative_vectors_from_spec_section_8() {
        for index in [0, 9, 29] {
            let g = geom(40960, 40960, index).unwrap();
            assert_eq!(g.stripe_index, 0);
            assert_eq!(g.shard_in_stripe, index);
            assert_eq!(g.stripe_data_len, 40960);
            assert_eq!(g.shard_length, 4096);
            assert_eq!(g.chunk_count, 4);
            assert_eq!(g.last_chunk_length, 1024);
        }
        for index in [30, 39, 59] {
            let g = geom(71681, 40960, index).unwrap();
            assert_eq!(g.stripe_index, 1);
            assert_eq!(g.shard_in_stripe, index - 30);
            assert_eq!(g.stripe_data_len, 30721);
            assert_eq!(g.shard_length, 3073);
            assert_eq!(g.chunk_count, 4);
            assert_eq!(g.last_chunk_length, 1);
        }
        let g = geom(81920, 40960, 59).unwrap();
        assert_eq!(
            (g.stripe_data_len, g.shard_length, g.chunk_count),
            (40960, 4096, 4)
        );
        assert_eq!(g.last_chunk_length, 1024);
        assert_eq!(
            geom(81920, 40960, 60),
            Err(GeometryError::StripeOutOfBounds)
        );
    }

    #[test]
    fn invalid_parameters_are_rejected_before_any_arithmetic() {
        assert_eq!(
            derive_shard_geometry(0, 4096, 10, 20, 0),
            Err(GeometryError::InvalidParameters)
        );
        assert_eq!(
            derive_shard_geometry(4096, 0, 10, 20, 0),
            Err(GeometryError::InvalidParameters)
        );
        assert_eq!(
            derive_shard_geometry(4096, 4096, 0, 20, 0),
            Err(GeometryError::InvalidParameters)
        );
        assert_eq!(
            derive_shard_geometry(4096, 4096, 10, 0, 0),
            Err(GeometryError::InvalidParameters)
        );
        assert_eq!(
            derive_shard_geometry(4096, 4096, 200, 57, 0),
            Err(GeometryError::InvalidParameters)
        );
        assert!(derive_shard_geometry(4096, 4096, 200, 56, 0).is_ok());
        assert_eq!(
            derive_shard_geometry(4096, 4096, u16::MAX, u16::MAX, 0),
            Err(GeometryError::InvalidParameters)
        );
    }

    #[test]
    fn overflow_is_an_error_not_a_saturation() {
        assert_eq!(
            derive_shard_geometry(u64::MAX, u64::MAX / 2, 1, 1, 6),
            Err(GeometryError::ArithmeticOverflow)
        );
        assert_eq!(
            derive_shard_geometry(u64::MAX, u64::MAX, 1, 1, 4),
            Err(GeometryError::ArithmeticOverflow)
        );
        // stripe_index 1 does not overflow; it is simply beyond the file.
        assert_eq!(
            derive_shard_geometry(u64::MAX, u64::MAX, 1, 1, 2),
            Err(GeometryError::StripeOutOfBounds)
        );
    }

    #[test]
    fn stripe_out_of_bounds_precedes_length_bounds() {
        assert_eq!(
            derive_shard_geometry(100, 100, 1, 1, 2),
            Err(GeometryError::StripeOutOfBounds)
        );
        assert_eq!(
            derive_shard_geometry(u64::MAX, u64::MAX, 1, 1, 0),
            Err(GeometryError::ShardLengthOutOfBounds)
        );
        assert_eq!(
            derive_shard_geometry(MAX_SHARD_LENGTH + 1, MAX_SHARD_LENGTH + 1, 1, 1, 0),
            Err(GeometryError::ShardLengthOutOfBounds)
        );
        assert_eq!(
            derive_shard_geometry(MAX_SHARD_LENGTH, MAX_SHARD_LENGTH, 1, 1, 0)
                .unwrap()
                .shard_length,
            MAX_SHARD_LENGTH
        );
    }

    #[test]
    fn shard_length_edge_vectors() {
        // (shard_length, chunk_count, last_chunk_length, eligible)
        let cases: [(u64, u64, u64, bool); 10] = [
            (1, 1, 1, false),
            (1023, 1, 1023, false),
            (1024, 1, 1024, false),
            (1025, 2, 1, false),
            (3072, 3, 1024, false),
            (3073, 4, 1, true),
            (262_143, 256, 1023, true),
            (262_144, 256, 1024, true),
            (262_145, 257, 1, true),
            (268_435_456, 262_144, 1024, true),
        ];
        for (length, chunks, last, eligible) in cases {
            let g = derive_shard_geometry(length, length, 1, 1, 0).unwrap();
            assert_eq!(g.shard_length, length, "length {length}");
            assert_eq!(g.chunk_count, chunks, "length {length}");
            assert_eq!(g.last_chunk_length, last, "length {length}");
            assert_eq!(g.eligible_for_challenge(), eligible, "length {length}");
            assert_eq!(g.bao_tree().chunks().0, chunks, "bao chunks {length}");
            assert_eq!(g.bao_tree().size(), length);
        }
    }

    #[test]
    fn proof_depth_follows_bao_split_rule() {
        assert_eq!(proof_depth(0, 1), Some(0));
        assert_eq!(proof_depth(0, 2), Some(1));
        assert_eq!(proof_depth(1, 2), Some(1));
        assert_eq!(proof_depth(0, 3), Some(2));
        assert_eq!(proof_depth(2, 3), Some(1));
        for i in 0..4 {
            assert_eq!(proof_depth(i, 4), Some(2));
        }
        assert_eq!(proof_depth(4, 5), Some(1));
        assert_eq!(proof_depth(3, 5), Some(3));
        for i in 0..256 {
            assert_eq!(proof_depth(i, 256), Some(8));
        }
        assert_eq!(proof_depth(256, 257), Some(1));
        assert_eq!(proof_depth(0, 257), Some(9));
        assert_eq!(proof_depth(0, MAX_CHUNK_COUNT), Some(MAX_PROOF_DEPTH));
        assert_eq!(proof_depth(MAX_CHUNK_COUNT - 1, MAX_CHUNK_COUNT), Some(18));
        assert_eq!(proof_depth(4, 4), None);
        assert_eq!(proof_depth(0, 0), None);
    }

    #[test]
    fn expected_proof_lengths_match_spec_examples() {
        let g = derive_shard_geometry(262_144, 262_144, 1, 1, 0).unwrap();
        assert_eq!(expected_proof_length(&g, 0), Some(1536));
        assert_eq!(expected_proof_length(&g, 255), Some(1536));
        let g = geom(71681, 40960, 39).unwrap();
        assert_eq!(expected_proof_length(&g, 0), Some(1152));
        assert_eq!(expected_proof_length(&g, 3), Some(129));
        assert_eq!(expected_proof_length(&g, 4), None);
        let g = derive_shard_geometry(MAX_SHARD_LENGTH, MAX_SHARD_LENGTH, 1, 1, 0).unwrap();
        assert_eq!(expected_proof_length(&g, 0), Some(2176));
    }

    #[test]
    fn agrees_with_legacy_helpers_and_real_encoding() {
        let config = StripeConfig {
            size: 40960,
            k: 10,
            m: 20,
        };
        let file: Vec<u8> = (0..71681u32).map(|i| (i % 253) as u8).collect();
        for index in 0..60usize {
            let g = derive_shard_geometry_for_manifest(file.len() as u64, &config, index).unwrap();
            let legacy_len =
                calculate_stripe_data_len(file.len() as u64, g.stripe_index, config.size);
            assert_eq!(legacy_len as u64, g.stripe_data_len);
            assert_eq!(
                calculate_shard_size(file.len() as u64, g.stripe_index, config.size, config.k),
                g.shard_length
            );
            // Upload path: each encode call receives exactly stripe_data_len bytes.
            let start = (g.stripe_index * config.size) as usize;
            let stripe = &file[start..start + legacy_len];
            assert_eq!(stripe.len() as u64, g.stripe_data_len);
            let shards = encode_stripe(stripe, &config).unwrap();
            assert_eq!(shards.len(), 30);
            for shard in &shards {
                assert_eq!(shard.len() as u64, g.shard_length);
            }
            if g.stripe_index == 1 {
                assert_eq!(g.shard_length, 3073);
                let last_data = &shards[9];
                assert_eq!(&last_data[3064..], &[0u8; 9]);
                assert_eq!(&last_data[..3064], &stripe[9 * 3073..]);
            }
        }
        assert_eq!(
            derive_shard_geometry_for_manifest(file.len() as u64, &config, 60),
            Err(GeometryError::StripeOutOfBounds)
        );
    }

    #[test]
    fn manifest_conversions_never_truncate() {
        let config = StripeConfig {
            size: 4096,
            k: 70_000,
            m: 1,
        };
        assert_eq!(
            derive_shard_geometry_for_manifest(4096, &config, 0),
            Err(GeometryError::InvalidParameters)
        );
        let config = StripeConfig {
            size: 4096,
            k: 1,
            m: 65_536,
        };
        assert_eq!(
            derive_shard_geometry_for_manifest(4096, &config, 0),
            Err(GeometryError::InvalidParameters)
        );
    }
}

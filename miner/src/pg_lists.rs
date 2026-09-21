//! Reader for the published per-PG obligation lists.
//!
//! The validator publishes, on a public HTTP bucket, the flat list of
//! blob hashes each placement group is obliged to hold. This module
//! fetches and verifies those lists and folds the union of the lists of
//! the PGs this miner owns into a compact membership filter that the purge
//! loop consults (see [`crate::purge`]).
//!
//! ## Layout (frozen, `PG_LISTS_BASE_URL` relative)
//!
//! - `current.json` -> [`CurrentPointer`]: `{"generation": u64}` plus,
//!   by writer version, `delta_seq` (v1) or `base_cut`, `manifest_sha`
//!   and `deltas` (v2). A v2 `manifest_sha` must match the base
//!   manifest's bytes or the manifest is refused; a v2 chain is adopted
//!   when the base declares none (`Manifest::adopt_pointer_chain`), each
//!   link verified against its signed delta manifest.
//! - `gen/<generation>/manifest.json` -> [`Manifest`], Ed25519-signed by
//!   the validator key (`signature` = hex over the canonical JSON of the
//!   manifest without the `signature` field: keys sorted, no whitespace).
//! - `gen/<generation>/pg/<pg_id 5 digits>.list` -> binary `APGL`
//!   version 3, one 40-byte record per **shard** of every file in the PG
//!   (`common::obligation_list`; see [`decode_list`]).
//!
//! ## Deltas (differential lists, same generation)
//!
//! A base generation is a multi-day scan; blobs uploaded after its cut
//! are unlisted until the next one. A delta-capable writer stamps the
//! base with `base_cut` (seconds or RFC 3339: the instant its scan
//! stopped seeing new manifests) and appends, every window, a signed
//! delta that lists what was added since:
//!
//! - `delta/<generation>/<seq>/manifest.json` -> [`DeltaManifest`],
//!   signed like the base; `seq` = 1, 2, ... with no gap; the windows
//!   `[since, until]` tile from `base_cut` ([`check_delta_chain`]).
//! - `delta/<generation>/<seq>/pg/<pg_id 5 digits>.added` -> `APGL` v3,
//!   same header as the base list (pg_id, generation, ec): the records
//!   added to that PG in the window. A PG in the delta's `pgs` with no
//!   `.added` gained nothing. There is no delta `.deleted`: a deletion
//!   waits for the next base.
//! - The base manifest's `deltas: [`[`DeltaRef`]`]` names each delta
//!   (seq, window, sha256 and size of its manifest); the base is
//!   re-signed each time the chain grows. A reader that predates deltas
//!   rejects a base WITH `deltas` (`deny_unknown_fields`); one on this
//!   code accepts `deltas: []` and `base_cut` and applies the chain.
//!
//! The enforced view is the base plus every delta in order: a delta's
//! records are obligations like the base's (a filter hit is a keep), a
//! tombstone the delta re-lists is withdrawn, and the age bound
//! ([`LoadedGeneration::snapshot_secs`]) moves to the last `until`. The
//! chain is verified link by link with the key that verified the base
//! ([`Manifest::verified_by`]); the first link that fails to chain,
//! fetch, verify or apply (or that did not scan an owned PG) sets
//! [`LoadedGeneration::chain_broken_at`]: the load succeeds with what
//! came before, coverage is incomplete
//! ([`LoadedGeneration::coverage_complete`]), the purge waits and the
//! reader retries at the next poll. A loaded generation grows in place
//! with [`LoadedGeneration::extend`] (only the new `.added` bodies are
//! fetched); a writer that rewrites an applied link or a base list is
//! refused the same way.
//!
//! ## Trust
//!
//! - An unsigned or wrongly signed manifest is rejected; the caller keeps
//!   the previous generation.
//! - Every list is checked against the manifest's sha256 before decoding,
//!   then its header must name the expected pg_id/generation and the
//!   manifest's erasure-coding parameters (any list version other than 3
//!   is refused), and its records must be sorted.
//!
//! ## Holder filter
//!
//! A PG list names every shard of every file in the PG, and each record
//! carries the uid of the miner the write path placed that shard on
//! (`holder_uid`, resolved by the writer with the write path's own
//! placement function on the write path's own map). This reader does not
//! compute placement at all: a record is this miner's iff
//! `record.holder_uid == my uid` ([`common::obligation_list::Record::is_held_by`]).
//! A blob listed for an owned PG but placed on another holder of that PG is
//! NOT this miner's obligation (purgeable, not backfilled). Version 2 had
//! the reader recompute the holder from `(stripe_idx, shard_idx,
//! placement_version)` and the current map; reader and writer used the
//! same formula on different inputs (raw vs draining-filtered map) and
//! attributed shards to the wrong miner. There is no "unresolved" state
//! any more: every record names a holder.
//!
//! ## Membership filter
//!
//! This miner's records are folded into [`HashFilter`], a plain Bloom
//! filter sized for a 1% false-positive rate (~9.6 bits per hash, 7
//! probes). A full-size miner owns ~1600 PGs of ~180k records; one
//! thirtieth of those (k+m = 30) are its own: ~9.6M hashes ≈ 11.5 MB
//! (the union of whole lists, 288M hashes, would have cost ~345 MB). A
//! false positive answers "mine" and therefore means KEEP — the filter
//! can only make the purge miss a blob, never delete one it should keep.
//! The probe positions come straight from the blob hash (already a
//! uniform blake3 digest), so no hashing is done on insert or lookup.

use std::collections::{BTreeMap, BTreeSet};
use std::path::PathBuf;

use anyhow::{Context, Result, bail};
use bytes::Bytes;
use serde::Deserialize;
use sha2::{Digest, Sha256};
use tracing::{debug, info, warn};

pub use common::obligation_list::{
    HEADER_LEN as LIST_HEADER_LEN, Header as ListHeader, MAGIC as LIST_MAGIC,
    RECORD_LEN as LIST_RECORD_LEN, Record, TOMBSTONE_MAGIC, TOMBSTONE_RECORD_LEN,
    VERSION as LIST_VERSION,
};
/// Tombstone bodies share the list header layout (magic aside).
pub const TOMBSTONE_HEADER_LEN: usize = LIST_HEADER_LEN;

/// Upper bound on a `current.json` / `manifest.json` body.
const MAX_JSON_BYTES: u64 = 64 << 20;
/// Upper bound on a single list body, whatever the manifest claims
/// (256 MiB = 6.7M records; a PG holds ~180k).
pub const MAX_LIST_BYTES: u64 = 256 << 20;

// ============================================================================
// Manifest
// ============================================================================

/// Digest and size of one published object, as declared by the manifest.
#[derive(Debug, Clone, Deserialize, PartialEq, Eq)]
pub struct ObjectEntry {
    pub sha256: String,
    pub size: u64,
}

/// `gen/<generation>/manifest.json`, after signature verification.
#[derive(Debug, Clone, Deserialize)]
pub struct Manifest {
    pub generation: u64,
    /// Finalization time of the generation (publication).
    #[serde(default)]
    pub created_at: serde_json::Value,
    /// Start of the scan that produced the lists, when the writer
    /// publishes it: nothing committed after this instant is guaranteed
    /// to be listed, so it is the bound of the age rule. Absent on older
    /// generations, which fall back to `created_at`.
    #[serde(default)]
    pub scan_started_at: serde_json::Value,
    pub pg_count: u32,
    pub ec_k: u8,
    pub ec_m: u8,
    /// PGs whose list is part of this generation (may be a subset).
    pub pgs: Vec<u32>,
    /// `"pg/00042.list" -> {sha256, size}`.
    pub objects: BTreeMap<String, ObjectEntry>,
    /// Instant (seconds or RFC 3339) every manifest committed before is
    /// in the base lists; the first delta's window starts here. Absent on
    /// generations without deltas.
    #[serde(default)]
    pub base_cut: serde_json::Value,
    /// Differential lists appended since the base was published, in
    /// `seq` order (1, 2, ...), each a signed delta manifest at
    /// `delta/<generation>/<seq>/manifest.json`. The enforced view is the
    /// base plus every delta; the chain's shape is checked by
    /// [`check_delta_chain`] at fetch, each link is fetched and verified
    /// when applied ([`load_generation`], [`LoadedGeneration::extend`]).
    /// Empty on today's writer.
    #[serde(default)]
    pub deltas: Vec<DeltaRef>,
    #[serde(default)]
    pub signature: Option<String>,
    /// Hex node id of the key that verified this manifest's signature
    /// (set by [`parse_verified_manifest`], never parsed). Every delta of
    /// the chain must be signed by the same key.
    #[serde(skip)]
    pub verified_by: String,
}

/// One link of the base manifest's `deltas` chain: where the signed delta
/// manifest is and what window it covers.
#[derive(Debug, Clone, Deserialize, PartialEq, Eq)]
pub struct DeltaRef {
    pub seq: u64,
    /// Window start (seconds or RFC 3339): `base_cut` for `seq` 1, the
    /// previous delta's `until` after (the windows tile).
    #[serde(default)]
    pub since: serde_json::Value,
    /// Window end: every manifest committed before it is in the base or
    /// in a delta up to this one.
    #[serde(default)]
    pub until: serde_json::Value,
    /// sha256 (hex) of `delta/<generation>/<seq>/manifest.json`.
    pub sha256: String,
    /// Its size; `0` = not declared (a link adopted from a v2 pointer,
    /// which digests the delta manifest but does not size it): the fetch
    /// is then capped at the JSON bound and only the digest is checked.
    #[serde(default)]
    pub size: u64,
}

/// `delta/<generation>/<seq>/manifest.json`, after verification: the
/// records added to the PGs' lists between `since` and `until`. Same
/// signing rule as the base manifest.
#[derive(Debug, Clone, Deserialize)]
pub struct DeltaManifest {
    pub generation: u64,
    pub seq: u64,
    #[serde(default)]
    pub since: serde_json::Value,
    #[serde(default)]
    pub until: serde_json::Value,
    #[serde(default)]
    pub created_at: serde_json::Value,
    pub pg_count: u32,
    pub ec_k: u8,
    pub ec_m: u8,
    /// PGs the delta scan covered. A covered PG with no `.added` object
    /// gained nothing in the window; an owned PG absent from here breaks
    /// the chain (the reader cannot tell "nothing new" from "not
    /// scanned").
    pub pgs: Vec<u32>,
    /// `"pg/00042.added" -> {sha256, size}` (`APGL` v3 bodies, same
    /// header as the base list: pg_id, generation, ec).
    pub objects: BTreeMap<String, ObjectEntry>,
    #[serde(default)]
    pub signature: Option<String>,
    /// sha256 of the fetched body (what the base manifest's ref names).
    #[serde(skip)]
    pub body_sha256: [u8; 32],
}

impl DeltaManifest {
    /// Relative path of a PG's additions inside the delta.
    pub fn added_path(pg_id: u32) -> String {
        format!("pg/{pg_id:05}.added")
    }

    /// Declared digest/size of a PG's additions, if any in this delta.
    pub fn added_for_pg(&self, pg_id: u32) -> Option<&ObjectEntry> {
        self.objects.get(&Self::added_path(pg_id))
    }

    /// Bucket path of the delta's directory (`delta/<gen>/<seq>`).
    pub fn dir_path(generation: u64, seq: u64) -> String {
        format!("delta/{generation}/{seq}")
    }

    /// Bucket path of the delta's manifest.
    pub fn manifest_path(generation: u64, seq: u64) -> String {
        format!("{}/manifest.json", Self::dir_path(generation, seq))
    }

    /// Bucket path of a PG's additions in this delta.
    pub fn added_object_path(&self, pg_id: u32) -> String {
        format!(
            "{}/{}",
            Self::dir_path(self.generation, self.seq),
            Self::added_path(pg_id)
        )
    }

    /// Window end as Unix seconds.
    pub fn until_secs(&self) -> Option<u64> {
        secs_of(&self.until)
    }

    /// Owned PGs this delta did not scan.
    pub fn uncovered_pgs(&self, wanted: &[u32]) -> Vec<u32> {
        let covered: BTreeSet<u32> = self.pgs.iter().copied().collect();
        wanted
            .iter()
            .copied()
            .filter(|pg| !covered.contains(pg))
            .collect()
    }
}

impl Manifest {
    /// Instant every manifest committed before is in the base lists.
    pub fn base_cut_secs(&self) -> Option<u64> {
        secs_of(&self.base_cut)
    }

    /// Highest delta `seq` the chain declares (0 without deltas).
    pub fn declared_delta_seq(&self) -> u64 {
        self.deltas.last().map_or(0, |d| d.seq)
    }

    /// Take the delta chain from a v2 `current.json` when this base
    /// declares none of its own (v2 bases are write-once: `base_cut` and
    /// the chain live in the pointer). Each pointer link `(seq, cut,
    /// manifest_sha)` becomes a [`DeltaRef`] whose window runs from the
    /// previous link's `cut` (the pointer's `base_cut` for the first) to
    /// its own, with no declared size. Nothing is trusted from the
    /// pointer: every delta manifest is fetched, digest-checked, signature
    /// verified with the key that verified this base, and its own signed
    /// `since`/`until` must equal the window the pointer implies
    /// ([`parse_verified_delta_manifest`]). A base that declares a chain
    /// (v1 writer) keeps it; a pointer without `base_cut` cannot anchor a
    /// chain and is ignored. Returns whether a chain was adopted.
    pub fn adopt_pointer_chain(&mut self, pointer: &CurrentPointer) -> bool {
        if !self.deltas.is_empty() || pointer.deltas.is_empty() {
            return false;
        }
        let Some(base_cut) = pointer.base_cut else {
            return false;
        };
        if self.base_cut_secs().is_none() {
            self.base_cut = serde_json::Value::from(base_cut);
        }
        let mut since = base_cut;
        self.deltas = pointer
            .deltas
            .iter()
            .map(|d| {
                let link = DeltaRef {
                    seq: d.seq,
                    since: serde_json::Value::from(since),
                    until: serde_json::Value::from(d.cut),
                    sha256: d.manifest_sha.clone(),
                    size: 0,
                };
                since = d.cut;
                link
            })
            .collect();
        true
    }

    /// Relative path of a PG's list inside the generation.
    pub fn list_path(pg_id: u32) -> String {
        format!("pg/{pg_id:05}.list")
    }

    /// Declared digest/size of a PG's list, if the generation covers it.
    pub fn object_for_pg(&self, pg_id: u32) -> Option<&ObjectEntry> {
        self.objects.get(&Self::list_path(pg_id))
    }

    /// Relative path of a PG's tombstones (`APGD`) inside the generation.
    pub fn tombstone_path(pg_id: u32) -> String {
        format!("pg/{pg_id:05}.deleted")
    }

    /// Declared digest/size of a PG's tombstones. `None` on a generation
    /// written before tombstones existed: the PG's blobs then have no
    /// tombstone class and stay under the orphan gates.
    pub fn tombstone_for_pg(&self, pg_id: u32) -> Option<&ObjectEntry> {
        self.objects.get(&Self::tombstone_path(pg_id))
    }

    /// Finalization time of the generation as Unix seconds. Accepts a
    /// number (seconds) or an RFC 3339 string; `None` when absent or
    /// malformed.
    pub fn created_at_secs(&self) -> Option<u64> {
        secs_of(&self.created_at)
    }

    /// The instant after which a committed manifest may be missing from
    /// the lists: `scan_started_at` when the writer published it,
    /// `created_at` otherwise. A present but unparseable `scan_started_at`
    /// is an error (fail closed), never a fallback to the later stamp.
    pub fn snapshot_secs(&self) -> Result<u64> {
        if !self.scan_started_at.is_null() {
            return secs_of(&self.scan_started_at)
                .ok_or_else(|| anyhow::anyhow!("manifest scan_started_at is unparseable"));
        }
        self.created_at_secs()
            .ok_or_else(|| anyhow::anyhow!("manifest created_at is missing or unparseable"))
    }

    /// PGs among `wanted` that this generation does not list.
    pub fn missing_pgs(&self, wanted: &[u32]) -> Vec<u32> {
        let covered: BTreeSet<u32> = self.pgs.iter().copied().collect();
        wanted
            .iter()
            .copied()
            .filter(|pg| !covered.contains(pg) || self.object_for_pg(*pg).is_none())
            .collect()
    }
}

/// A manifest time stamp as Unix seconds: a number (seconds) or an RFC
/// 3339 string; `None` when absent or malformed.
fn secs_of(value: &serde_json::Value) -> Option<u64> {
    match value {
        serde_json::Value::Number(n) => n
            .as_u64()
            .or_else(|| n.as_f64().filter(|f| *f >= 0.0).map(|f| f as u64)),
        serde_json::Value::String(s) => chrono::DateTime::parse_from_rfc3339(s)
            .ok()
            .and_then(|t| u64::try_from(t.timestamp()).ok()),
        _ => None,
    }
}

/// The bytes the validator signs: the manifest object without its
/// `signature` member, serialized with sorted keys and no whitespace.
pub fn canonical_manifest_bytes(value: &serde_json::Value) -> Result<Vec<u8>> {
    let serde_json::Value::Object(map) = value else {
        bail!("manifest is not a JSON object");
    };
    let mut unsigned = map.clone();
    unsigned.remove("signature");
    // serde_json's default `Map` is a BTreeMap: keys come out sorted.
    Ok(serde_json::to_vec(&serde_json::Value::Object(unsigned))?)
}

/// Parse a manifest and verify its Ed25519 signature against the
/// validator's public key (hex node id, as used for PosChallenge/Store
/// authorization). Rejects a missing, malformed or invalid signature.
pub fn parse_verified_manifest(bytes: &[u8], validator_node_id_hex: &str) -> Result<Manifest> {
    let value = verify_signed_json(bytes, validator_node_id_hex)?;
    let mut manifest: Manifest =
        serde_json::from_value(value).context("manifest has an unexpected shape")?;
    if manifest.ec_k == 0 || manifest.ec_m == 0 {
        bail!(
            "manifest declares ec_k={} ec_m={}",
            manifest.ec_k,
            manifest.ec_m
        );
    }
    manifest.verified_by = validator_node_id_hex.to_string();
    Ok(manifest)
}

/// Parse a signed JSON object (base or delta manifest) and verify its
/// Ed25519 signature against the validator key. Rejects a missing,
/// malformed or invalid signature.
fn verify_signed_json(bytes: &[u8], validator_node_id_hex: &str) -> Result<serde_json::Value> {
    let value: serde_json::Value =
        serde_json::from_slice(bytes).context("manifest is not valid JSON")?;
    let signature_hex = value
        .get("signature")
        .and_then(|s| s.as_str())
        .ok_or_else(|| anyhow::anyhow!("manifest is unsigned"))?;
    let signature = hex::decode(signature_hex).context("manifest signature is not hex")?;
    let signature: [u8; 64] = signature
        .try_into()
        .map_err(|_| anyhow::anyhow!("manifest signature is not 64 bytes"))?;
    let message = canonical_manifest_bytes(&value)?;
    if !crate::helpers::verify_signature(validator_node_id_hex, &message, &signature) {
        bail!("manifest signature does not verify against the validator key");
    }
    Ok(value)
}

/// Parse a delta manifest body, verify its signature and check it is the
/// delta `base` names at `link`: same generation, `seq`, window and
/// erasure parameters, body digest and size as declared.
pub fn parse_verified_delta_manifest(
    bytes: &[u8],
    base: &Manifest,
    link: &DeltaRef,
    validator_node_id_hex: &str,
) -> Result<DeltaManifest> {
    if link.size != 0 && bytes.len() as u64 != link.size {
        bail!(
            "delta manifest is {} bytes, base manifest declares {}",
            bytes.len(),
            link.size
        );
    }
    let body_sha256: [u8; 32] = Sha256::digest(bytes).into();
    if !hex::encode(body_sha256).eq_ignore_ascii_case(&link.sha256) {
        bail!("delta manifest sha256 does not match the base manifest's ref");
    }
    let value = verify_signed_json(bytes, validator_node_id_hex)?;
    let mut delta: DeltaManifest =
        serde_json::from_value(value).context("delta manifest has an unexpected shape")?;
    delta.body_sha256 = body_sha256;
    if delta.generation != base.generation || delta.seq != link.seq {
        bail!(
            "delta manifest declares generation {} seq {}, expected {} / {}",
            delta.generation,
            delta.seq,
            base.generation,
            link.seq
        );
    }
    if delta.ec_k != base.ec_k || delta.ec_m != base.ec_m || delta.pg_count != base.pg_count {
        bail!(
            "delta manifest declares ec {}+{} pg_count {}, base has {}+{} / {}",
            delta.ec_k,
            delta.ec_m,
            delta.pg_count,
            base.ec_k,
            base.ec_m,
            base.pg_count
        );
    }
    if secs_of(&delta.since) != secs_of(&link.since)
        || secs_of(&delta.until) != secs_of(&link.until)
    {
        bail!("delta manifest window disagrees with the base manifest's ref");
    }
    Ok(delta)
}

/// Check that `base.deltas` is a chain: `seq` 1, 2, ... without gaps, the
/// first window starting at `base_cut`, each next one at the previous
/// `until`, no window ending before it starts. Returns the first `seq`
/// that breaks it, with the reason.
pub fn check_delta_chain(base: &Manifest) -> Result<(), (u64, anyhow::Error)> {
    let mut expected_since = None;
    for (i, link) in base.deltas.iter().enumerate() {
        let expected_seq = i as u64 + 1;
        if link.seq != expected_seq {
            return Err((
                link.seq.max(expected_seq),
                anyhow::anyhow!(
                    "delta chain gap: position {i} carries seq {}, expected {expected_seq}",
                    link.seq
                ),
            ));
        }
        let since = expected_since.or_else(|| base.base_cut_secs());
        let Some(since) = since else {
            return Err((
                link.seq,
                anyhow::anyhow!("base manifest carries deltas but no usable base_cut"),
            ));
        };
        match (secs_of(&link.since), secs_of(&link.until)) {
            (Some(s), Some(u)) if s == since && u >= s => expected_since = Some(u),
            (Some(s), Some(u)) => {
                return Err((
                    link.seq,
                    anyhow::anyhow!(
                        "delta {} window [{s}, {u}) does not tile from {since}",
                        link.seq
                    ),
                ));
            }
            _ => {
                return Err((
                    link.seq,
                    anyhow::anyhow!("delta {} has an unparseable window", link.seq),
                ));
            }
        }
    }
    Ok(())
}

/// One link of a v2 pointer's delta chain: the delta's `seq`, the end of
/// its window (`cut`, Unix seconds) and the sha256 (hex) of its manifest.
#[derive(Debug, Clone, Deserialize, PartialEq, Eq)]
pub struct CurrentDelta {
    pub seq: u64,
    #[serde(default)]
    pub cut: u64,
    #[serde(default)]
    pub manifest_sha: String,
}

/// `current.json`, in any shape a writer has published:
///
/// - v0 `{"generation":G}`;
/// - v1 `{"generation":G,"delta_seq":N}`: `N` is the highest delta `seq`
///   appended to the generation, a change-detection hint;
/// - v2 `{"generation":G,"base_cut":S,"manifest_sha":"<hex>",
///   "deltas":[{"seq","cut","manifest_sha"},...]}`: the base manifest is
///   write-once and the pointer digests its exact bytes.
///
/// Unknown fields are tolerated (a newer writer may add some). The
/// pointer is never an authority for what to enforce: the signed base
/// manifest is. Two things are taken from it: [`Self::delta_hint`], which
/// decides whether a loaded generation needs its manifest re-fetched, and
/// [`Self::manifest_sha`], which when present must match the bytes of
/// `gen/<G>/manifest.json` before they are even parsed
/// ([`fetch_manifest_expecting`]): a pointer and a manifest that disagree
/// are a bucket mid-publication or a tampered object, and the reader keeps
/// what it had. A v2 `deltas` chain is adopted when the signed base
/// declares none of its own ([`Manifest::adopt_pointer_chain`]); every
/// link is still verified against its signed delta manifest.
#[derive(Debug, Clone, Deserialize, PartialEq, Eq, Default)]
pub struct CurrentPointer {
    pub generation: u64,
    /// v1 hint; absent on v0 and v2 writers (= 0).
    #[serde(default)]
    pub delta_seq: u64,
    /// v2: instant every manifest committed before is in the base lists.
    #[serde(default)]
    pub base_cut: Option<u64>,
    /// v2: sha256 (hex) of the exact bytes of `gen/<generation>/manifest.json`.
    #[serde(default)]
    pub manifest_sha: Option<String>,
    /// v2: deltas appended to the generation, in `seq` order.
    #[serde(default)]
    pub deltas: Vec<CurrentDelta>,
}

impl CurrentPointer {
    /// Highest delta `seq` the pointer says exists for its generation, in
    /// any shape (0 when it says nothing).
    pub fn delta_hint(&self) -> u64 {
        self.deltas
            .iter()
            .map(|d| d.seq)
            .max()
            .unwrap_or(0)
            .max(self.delta_seq)
    }

    /// The manifest digest a v2 pointer carries, if any.
    pub fn manifest_sha(&self) -> Option<&str> {
        self.manifest_sha.as_deref()
    }
}

/// `current.json` -> the generation it points at.
pub fn parse_current(bytes: &[u8]) -> Result<u64> {
    parse_current_pointer(bytes).map(|c| c.generation)
}

/// `current.json` -> generation and delta hint. A pointer carrying a
/// `manifest_sha` that is not a 64-digit hex string is refused: it could
/// never match any manifest, so trusting it would mean ignoring the check.
pub fn parse_current_pointer(bytes: &[u8]) -> Result<CurrentPointer> {
    let pointer: CurrentPointer =
        serde_json::from_slice(bytes).context("current.json is invalid")?;
    if let Some(sha) = pointer.manifest_sha.as_deref()
        && !is_sha256_hex(sha)
    {
        bail!("current.json manifest_sha is not a sha256 hex digest: {sha:?}");
    }
    Ok(pointer)
}

fn is_sha256_hex(s: &str) -> bool {
    s.len() == 64 && s.bytes().all(|b| b.is_ascii_hexdigit())
}

// ============================================================================
// List decoding
// ============================================================================

/// What a list must match before its records are trusted.
#[derive(Debug, Clone, Copy)]
pub struct ListExpectation<'a> {
    pub pg_id: u32,
    pub generation: u64,
    pub ec_k: u8,
    pub ec_m: u8,
    /// Hex sha256 declared by the manifest.
    pub sha256_hex: &'a str,
}

/// Parse the 32-byte header only (no record validation). Fails closed on
/// any list version other than [`LIST_VERSION`].
pub fn decode_header(bytes: &[u8]) -> Result<ListHeader> {
    ListHeader::decode(bytes)
}

/// Verify a list body against its manifest entry and expected identity,
/// then hand every record (in file order) to `visit`.
///
/// Checks, in order: sha256 against the manifest, magic/version, pg_id,
/// generation, erasure parameters, then the shared codec's rules (exact
/// body length for `count` records, strictly ascending `(blob_hash,
/// holder_uid)` keys, one length per blob hash). Returns the header.
pub fn decode_list(
    bytes: &[u8],
    expect: ListExpectation<'_>,
    visit: &mut dyn FnMut(&Record),
) -> Result<ListHeader> {
    let digest = hex::encode(Sha256::digest(bytes));
    if !digest.eq_ignore_ascii_case(expect.sha256_hex) {
        bail!(
            "sha256 mismatch for pg {}: manifest {} body {}",
            expect.pg_id,
            expect.sha256_hex,
            digest
        );
    }
    let header = decode_header(bytes)?;
    if header.pg_id != expect.pg_id {
        bail!(
            "list names pg {} but was fetched as pg {}",
            header.pg_id,
            expect.pg_id
        );
    }
    if header.generation != expect.generation {
        bail!(
            "list for pg {} names generation {} but manifest is generation {}",
            expect.pg_id,
            header.generation,
            expect.generation
        );
    }
    if header.ec_k != expect.ec_k || header.ec_m != expect.ec_m {
        bail!(
            "list for pg {} has ec {}+{} but manifest says {}+{}",
            expect.pg_id,
            header.ec_k,
            header.ec_m,
            expect.ec_k,
            expect.ec_m
        );
    }
    common::obligation_list::visit_list(bytes, visit)
        .with_context(|| format!("list for pg {}", expect.pg_id))
}

/// Verify a tombstone body (`pg/<N>.deleted`) against its manifest entry
/// and expected identity, then return its hashes (strictly sorted,
/// unique, checked by the shared codec).
pub fn decode_tombstones(bytes: &[u8], expect: ListExpectation<'_>) -> Result<Vec<[u8; 32]>> {
    let digest = hex::encode(Sha256::digest(bytes));
    if !digest.eq_ignore_ascii_case(expect.sha256_hex) {
        bail!(
            "sha256 mismatch for tombstones of pg {}: manifest {} body {}",
            expect.pg_id,
            expect.sha256_hex,
            digest
        );
    }
    let (header, hashes) = common::obligation_list::decode_tombstones(bytes)
        .with_context(|| format!("tombstones of pg {}", expect.pg_id))?;
    if header.pg_id != expect.pg_id
        || header.generation != expect.generation
        || header.ec_k != expect.ec_k
        || header.ec_m != expect.ec_m
    {
        bail!(
            "tombstones of pg {} name pg {} generation {} ec {}+{} but manifest says generation {} ec {}+{}",
            expect.pg_id,
            header.pg_id,
            header.generation,
            header.ec_k,
            header.ec_m,
            expect.generation,
            expect.ec_k,
            expect.ec_m
        );
    }
    Ok(hashes)
}

/// Upper bound on the tombstone hashes a load keeps in memory (32 bytes
/// each): 8 M hashes, 256 MiB. Above it the load keeps no tombstones at
/// all (never a subset) and says so: the tombstone class is an
/// acceleration, the orphan gates still reclaim the same blobs later.
pub const MAX_TOMBSTONE_HASHES: usize = 8 << 20;

/// Records a list of `size` bytes holds (header excluded).
pub fn records_in_list(size: u64) -> u64 {
    size.saturating_sub(LIST_HEADER_LEN as u64) / LIST_RECORD_LEN as u64
}

/// Upper bound on this miner's records in a list of `size` bytes when it
/// holds `my_positions` of the PG's `shards_per_stripe` placement
/// positions (one in production: the write path places each shard of a
/// stripe on a distinct miner, so a miner appears once per stripe): one
/// record per stripe per position. Used to size the filter before any
/// list is downloaded. The list itself is the truth (each record names
/// its holder); this is only the capacity estimate.
pub fn expected_my_records(size: u64, shards_per_stripe: usize, my_positions: usize) -> u64 {
    let n = shards_per_stripe.max(1) as u64;
    (records_in_list(size) * (my_positions as u64).min(n)).div_ceil(n)
}

// ============================================================================
// Membership filter
// ============================================================================

/// Bloom filter over 32-byte blob hashes. See the module docs for sizing
/// and the false-positive contract (FP = keep, never purge).
#[derive(Debug)]
pub struct HashFilter {
    bits: Vec<u64>,
    bit_count: u64,
    probes: u32,
    inserted: u64,
    /// Generation whose lists were folded in (`None` until tagged). A
    /// purge pass enforcing generation `g` refuses a filter whose tag is
    /// not `g`: the bits must come from the lists being enforced.
    generation: Option<u64>,
}

/// Smallest filter ever allocated: 8 KiB. The capacity estimate is one
/// record per stripe per owned PG; for a handful of PGs that estimate is
/// tens of hashes, and a writer that names this miner on several
/// positions of a stripe would saturate it in one list. 8 KiB absorbs
/// thousands of extra hashes and costs nothing on a full-size node.
pub const MIN_FILTER_BITS: u64 = 1 << 16;

impl HashFilter {
    /// `(bits, probes)` for `expected_items` at `fp_rate` (clamped).
    fn dimensions(expected_items: u64, fp_rate: f64) -> (u64, u32) {
        let n = expected_items.max(1) as f64;
        let p = fp_rate.clamp(1e-6, 0.5);
        let ln2 = std::f64::consts::LN_2;
        let bit_count = ((-n * p.ln()) / (ln2 * ln2))
            .ceil()
            .max(MIN_FILTER_BITS as f64) as u64;
        let probes = ((bit_count as f64 / n) * ln2).round().clamp(1.0, 16.0) as u32;
        (bit_count, probes)
    }

    /// Bytes `new(expected_items, fp_rate)` would allocate.
    pub fn bytes_for(expected_items: u64, fp_rate: f64) -> u64 {
        Self::dimensions(expected_items, fp_rate).0.div_ceil(64) * 8
    }

    /// Size for `expected_items` at `fp_rate` (clamped to a sane range).
    pub fn new(expected_items: u64, fp_rate: f64) -> Self {
        let (bit_count, probes) = Self::dimensions(expected_items, fp_rate);
        let words = bit_count.div_ceil(64) as usize;
        Self {
            bits: vec![0u64; words],
            bit_count,
            probes,
            inserted: 0,
            generation: None,
        }
    }

    /// Tag the filter with the generation its bits are built from.
    pub fn for_generation(mut self, generation: u64) -> Self {
        self.generation = Some(generation);
        self
    }

    /// Generation this filter was built from, if tagged.
    pub fn generation(&self) -> Option<u64> {
        self.generation
    }

    /// Anonymous memory held by the bit array.
    pub fn memory_bytes(&self) -> u64 {
        (self.bits.len() * 8) as u64
    }

    pub fn probes(&self) -> u32 {
        self.probes
    }

    pub fn inserted(&self) -> u64 {
        self.inserted
    }

    /// Bit positions for a hash: double hashing over two 64-bit slices of
    /// the (uniform) digest.
    fn positions(&self, hash: &[u8; 32]) -> impl Iterator<Item = u64> + '_ {
        let h1 = u64::from_le_bytes(hash[0..8].try_into().unwrap());
        let h2 = u64::from_le_bytes(hash[8..16].try_into().unwrap()) | 1;
        let bit_count = self.bit_count;
        (0..self.probes as u64).map(move |i| h1.wrapping_add(i.wrapping_mul(h2)) % bit_count)
    }

    pub fn insert(&mut self, hash: &[u8; 32]) {
        let positions: Vec<u64> = self.positions(hash).collect();
        for pos in positions {
            self.bits[(pos / 64) as usize] |= 1u64 << (pos % 64);
        }
        self.inserted += 1;
    }

    /// `false` means definitely not in any inserted list; `true` means
    /// probably in one (and must be treated as "keep").
    pub fn contains(&self, hash: &[u8; 32]) -> bool {
        self.positions(hash)
            .all(|pos| self.bits[(pos / 64) as usize] & (1u64 << (pos % 64)) != 0)
    }
}

// ============================================================================
// Sources
// ============================================================================

/// Where generation objects come from. Production is HTTP; tests read a
/// directory laid out exactly like the bucket.
#[async_trait::async_trait]
pub trait ListSource: Send + Sync {
    /// Fetch `rel_path` (e.g. `current.json`, `gen/7/pg/00042.list`),
    /// refusing bodies longer than `max_len`.
    async fn fetch(&self, rel_path: &str, max_len: u64) -> Result<Bytes>;
}

/// Public HTTP bucket rooted at `base_url`.
pub struct HttpListSource {
    client: reqwest::Client,
    base_url: String,
}

impl HttpListSource {
    pub fn new(base_url: &str) -> Result<Self> {
        let client = reqwest::Client::builder()
            .connect_timeout(std::time::Duration::from_secs(20))
            .timeout(std::time::Duration::from_secs(300))
            .build()
            .context("pg-lists HTTP client")?;
        Ok(Self {
            client,
            base_url: base_url.trim_end_matches('/').to_string(),
        })
    }
}

#[async_trait::async_trait]
impl ListSource for HttpListSource {
    async fn fetch(&self, rel_path: &str, max_len: u64) -> Result<Bytes> {
        let url = format!("{}/{}", self.base_url, rel_path);
        let response = self
            .client
            .get(&url)
            .send()
            .await
            .with_context(|| format!("GET {url}"))?;
        let status = response.status();
        if !status.is_success() {
            bail!("GET {url}: HTTP {status}");
        }
        if let Some(len) = response.content_length()
            && len > max_len
        {
            bail!("GET {url}: body {len} bytes exceeds limit {max_len}");
        }
        // Stream so an unbounded body (no Content-Length) cannot exhaust RAM.
        use futures::StreamExt;
        let mut body =
            Vec::with_capacity(response.content_length().unwrap_or(0).min(max_len) as usize);
        let mut stream = response.bytes_stream();
        while let Some(chunk) = stream.next().await {
            let chunk = chunk.with_context(|| format!("GET {url}: body read"))?;
            if body.len() as u64 + chunk.len() as u64 > max_len {
                bail!("GET {url}: body exceeds limit {max_len}");
            }
            body.extend_from_slice(&chunk);
        }
        Ok(Bytes::from(body))
    }
}

/// Directory mirror of the bucket (fixtures).
pub struct DirListSource {
    root: PathBuf,
}

impl DirListSource {
    pub fn new(root: impl Into<PathBuf>) -> Self {
        Self { root: root.into() }
    }
}

#[async_trait::async_trait]
impl ListSource for DirListSource {
    async fn fetch(&self, rel_path: &str, max_len: u64) -> Result<Bytes> {
        let path = self.root.join(rel_path);
        let len = tokio::fs::metadata(&path)
            .await
            .with_context(|| format!("stat {}", path.display()))?
            .len();
        if len > max_len {
            bail!("{}: {len} bytes exceeds limit {max_len}", path.display());
        }
        let data = tokio::fs::read(&path)
            .await
            .with_context(|| format!("read {}", path.display()))?;
        if data.len() as u64 > max_len {
            bail!(
                "{}: {} bytes exceeds limit {max_len}",
                path.display(),
                data.len()
            );
        }
        Ok(Bytes::from(data))
    }
}

// ============================================================================
// Generation loading
// ============================================================================

/// This miner's verified obligations for one generation: the records of
/// the owned PGs' lists whose holder is this miner.
#[derive(Debug)]
pub struct LoadedGeneration {
    pub generation: u64,
    /// Finalization time (Unix seconds): how old the publication is.
    pub created_at_secs: u64,
    /// Snapshot bound (Unix seconds, `Manifest::snapshot_secs`): a blob
    /// stored after it may be missing from these lists whatever its age,
    /// so the age rule measures from the earlier of now and this.
    pub snapshot_secs: u64,
    pub ec_k: u8,
    pub ec_m: u8,
    /// PGs the load was asked for (this miner's ownership at load time).
    pub owned_pgs: Vec<u32>,
    /// Owned PGs the manifest does not cover. Non-empty = coverage
    /// incomplete = the purge must not run.
    pub missing_pgs: Vec<u32>,
    /// Owned PGs whose list was fetched, verified and folded in.
    pub listed_pgs: usize,
    /// Records in the fetched lists, all holders.
    pub total_records: u64,
    /// Records folded into the filter: those whose `holder_uid` is this
    /// miner.
    pub total_hashes: u64,
    /// Sum of `shard_length` over this miner's records.
    pub total_shard_bytes: u64,
    /// Bloom filter over this miner's records, tagged with the generation
    /// it was built from (`HashFilter::generation`); a pass refuses a
    /// filter whose tag is not `generation`.
    pub filter: HashFilter,
    /// Bloom filter over the OTHER holders' records of the owned lists
    /// (every record `is_held_by(my_uid)` rejected), backing the moved
    /// class: a blob on this miner whose hash is in here is a live shard
    /// another miner of one of this miner's PGs is obliged to hold. A
    /// false positive is a keep. `None` only when the caller asked for no
    /// others filter (`others_filter_max_bytes == 0`); a filter over the
    /// cap refuses the whole load ([`OthersFilterOverCap`]).
    pub others: Option<HashFilter>,
    /// Records folded into `others` (0 when not built).
    pub total_other_hashes: u64,
    /// Bytes the others filter needs, as sized from the manifest (0 when
    /// not wanted).
    pub others_filter_bytes_needed: u64,
    /// [`lists_digest`] of the manifest and owned set this was loaded
    /// from: two loads with the same digest folded byte-identical lists.
    pub lists_digest: [u8; 32],
    /// Blob hashes of every shard of every manifest of an owned PG that
    /// the writer saw deleted inside its tombstone window: sorted, unique,
    /// exact (no false positive: a hit is a deletion without the age
    /// gate). Empty when the generation predates tombstones, when a PG's
    /// tombstones failed to load, or when they exceed
    /// [`MAX_TOMBSTONE_HASHES`]; `tombstone_pgs` tells which.
    pub tombstones: Vec<[u8; 32]>,
    /// Owned PGs whose tombstones were fetched, verified and kept. Less
    /// than `listed_pgs` means some PGs are enforced without tombstones.
    pub tombstone_pgs: usize,
    /// Tombstone hashes the load removed from `tombstones` because a
    /// record of an enforced list names them — this miner's or another
    /// holder's, in any owned PG. Exact (one binary search per record
    /// while the lists stream, no filter involved): a blob any live
    /// manifest references is never tombstoned on this side either,
    /// whatever the writer emitted.
    pub tombstones_retained_live_ref: u64,
    /// Highest delta `seq` folded in (0 = base only).
    pub delta_seq: u64,
    /// `(seq, body sha256 of the delta manifest)` of every delta folded
    /// in, in order: [`LoadedGeneration::extend`] refuses a base manifest
    /// whose chain disagrees with it (a rewritten history is never
    /// silently re-enforced).
    pub applied_deltas: Vec<(u64, [u8; 32])>,
    /// First delta `seq` the last load or extension could not apply
    /// (fetch, verification, chain or coverage failure). `Some` = coverage
    /// incomplete: the base and the deltas before it stay folded in, the
    /// purge waits, the next poll retries from `delta_seq + 1`.
    pub chain_broken_at: Option<u64>,
    /// Records in the applied deltas, all holders.
    pub delta_records: u64,
    /// Delta records folded into the filter (this miner's).
    pub delta_hashes: u64,
    /// [`lists_digest_through`] of the base alone: what `extend` compares
    /// a re-fetched manifest against before trusting its new deltas.
    base_digest: [u8; 32],
}

impl LoadedGeneration {
    /// Whether the writer saw `hash`'s file deleted in this generation's
    /// window (exact membership). A hash the lists still oblige wins over
    /// its tombstone; the caller checks `may_be_obliged` first.
    pub fn is_tombstoned(&self, hash: &[u8; 32]) -> bool {
        self.tombstones.binary_search(hash).is_ok()
    }

    /// Every owned PG listed by the base and every declared delta applied.
    pub fn coverage_complete(&self) -> bool {
        self.missing_pgs.is_empty() && self.chain_broken_at.is_none()
    }

    /// Fold the deltas of a re-fetched `manifest` (same generation) that
    /// this load has not applied yet, without downloading the base again.
    ///
    /// Refuses, by marking the chain broken (coverage incomplete, nothing
    /// re-folded), a manifest whose base lists or already-applied deltas
    /// differ from what was loaded: a writer may only append. A delta that
    /// does not scan every listed owned PG, or whose `.added` fails to
    /// fetch or verify, breaks the chain at its seq; what it folded before
    /// failing only adds bits to the filters (a keep), never removes.
    /// Returns the number of deltas applied.
    pub async fn extend(
        &mut self,
        source: &dyn ListSource,
        manifest: &Manifest,
        my_uid: u32,
        concurrency: usize,
    ) -> Result<usize> {
        if manifest.generation != self.generation {
            bail!(
                "extend: manifest is generation {}, loaded {}",
                manifest.generation,
                self.generation
            );
        }
        if lists_digest_through(manifest, &self.owned_pgs, 0) != self.base_digest {
            warn!(
                generation = self.generation,
                "pg-lists: base lists changed under a loaded generation: chain refused, coverage incomplete until a new generation"
            );
            self.chain_broken_at = Some(self.delta_seq.max(1));
            return Ok(0);
        }
        Ok(apply_deltas(self, source, manifest, my_uid, concurrency).await)
    }

    /// Whether this load already holds exactly the lists `manifest`
    /// declares for `owned_pgs` (same generation, same PGs, same sha256
    /// per list): a caller may reuse it instead of downloading again.
    pub fn covers(&self, manifest: &Manifest, owned_pgs: &[u32]) -> bool {
        self.lists_digest == lists_digest(manifest, owned_pgs)
    }

    /// Whether `hash` may be one of this miner's obligations (a shard
    /// placed on this miner in an owned PG).
    pub fn may_be_obliged(&self, hash: &[u8; 32]) -> bool {
        self.filter.contains(hash)
    }

    /// Whether `hash` may be a live shard another holder of an owned PG
    /// is obliged to hold (the moved class). `false` whenever the others
    /// filter was not built: the caller then has no moved class.
    pub fn may_be_held_by_other(&self, hash: &[u8; 32]) -> bool {
        self.others.as_ref().is_some_and(|f| f.contains(hash))
    }

    /// Whether the moved class can be enforced on this load.
    pub fn has_others_filter(&self) -> bool {
        self.others.is_some()
    }

    /// The filter's bits come from this generation's lists. `load_generation`
    /// always builds it that way; a pass checks it anyway before trusting
    /// a filter miss, since a miss is a deletion.
    pub fn filter_matches_generation(&self) -> bool {
        self.filter.generation() == Some(self.generation)
    }
}

/// Identity of "the lists of `owned_pgs` in `manifest`": blake3 over the
/// generation, then each owned PG in ascending order with the declared
/// sha256 of its list (all zeros when the manifest does not cover it).
/// Equal digests mean the same verified bytes would be downloaded.
pub fn lists_digest(manifest: &Manifest, owned_pgs: &[u32]) -> [u8; 32] {
    lists_digest_through(manifest, owned_pgs, manifest.declared_delta_seq())
}

/// [`lists_digest`] restricted to the deltas up to `delta_seq` (the
/// identity of a load that applied that many). Deltas are folded in
/// after the base entries as `(seq, sha256 of the delta manifest)`; a
/// generation without deltas keeps the pre-delta digest.
pub fn lists_digest_through(manifest: &Manifest, owned_pgs: &[u32], delta_seq: u64) -> [u8; 32] {
    let mut pgs: Vec<u32> = owned_pgs.to_vec();
    pgs.sort_unstable();
    pgs.dedup();
    let mut hasher = blake3::Hasher::new();
    hasher.update(&manifest.generation.to_le_bytes());
    for pg in pgs {
        hasher.update(&pg.to_le_bytes());
        let mut sha = [0u8; 32];
        if let Some(obj) = manifest.object_for_pg(pg) {
            // A malformed hex digest is a verification failure later; here
            // it only has to be a stable identity.
            let _ = hex::decode_to_slice(&obj.sha256, &mut sha);
        }
        hasher.update(&sha);
        // Tombstones are part of the identity too: a generation that
        // gains or changes a `.deleted` is a different set of bytes. A
        // generation without any keeps the pre-tombstone digest.
        if let Some(obj) = manifest.tombstone_for_pg(pg) {
            let mut sha = [0u8; 32];
            let _ = hex::decode_to_slice(&obj.sha256, &mut sha);
            hasher.update(b"deleted");
            hasher.update(&sha);
        }
    }
    for link in manifest.deltas.iter().filter(|d| d.seq <= delta_seq) {
        let mut sha = [0u8; 32];
        let _ = hex::decode_to_slice(&link.sha256, &mut sha);
        hasher.update(b"delta");
        hasher.update(&link.seq.to_le_bytes());
        hasher.update(&sha);
    }
    *hasher.finalize().as_bytes()
}

/// Fetch `current.json` and return the generation it points at.
pub async fn fetch_current_generation(source: &dyn ListSource) -> Result<u64> {
    fetch_current(source).await.map(|c| c.generation)
}

/// Fetch `current.json`.
pub async fn fetch_current(source: &dyn ListSource) -> Result<CurrentPointer> {
    let bytes = source.fetch("current.json", MAX_JSON_BYTES).await?;
    parse_current_pointer(&bytes)
}

/// Fetch and verify the manifest `pointer` names: the base manifest's
/// bytes must match the pointer's `manifest_sha` when it carries one
/// ([`fetch_manifest_expecting`]), and a v2 pointer's delta chain is
/// adopted when the base declares none ([`Manifest::adopt_pointer_chain`]).
/// This is what every consumer of `current.json` should call.
pub async fn fetch_manifest_at(
    source: &dyn ListSource,
    pointer: &CurrentPointer,
    validator_node_id_hex: &str,
) -> Result<Manifest> {
    let mut manifest = fetch_manifest_expecting(
        source,
        pointer.generation,
        validator_node_id_hex,
        pointer.manifest_sha(),
    )
    .await?;
    if manifest.adopt_pointer_chain(pointer) {
        debug!(
            generation = manifest.generation,
            links = manifest.deltas.len(),
            "pg-lists: delta chain taken from current.json (v2 pointer)"
        );
        if let Err((seq, e)) = check_delta_chain(&manifest) {
            warn!(
                generation = manifest.generation,
                seq,
                declared = manifest.deltas.len(),
                error = %format!("{e:#}"),
                "pg-lists: delta chain in current.json malformed: deltas from this seq on will not be applied"
            );
        }
    }
    Ok(manifest)
}

/// Fetch and verify the manifest of `generation`. Its `deltas` chain is
/// only checked for shape here ([`check_delta_chain`]; a malformed chain
/// is logged, the manifest is still returned): the delta manifests
/// themselves are fetched and verified one at a time when applied.
pub async fn fetch_manifest(
    source: &dyn ListSource,
    generation: u64,
    validator_node_id_hex: &str,
) -> Result<Manifest> {
    fetch_manifest_expecting(source, generation, validator_node_id_hex, None).await
}

/// [`fetch_manifest`], additionally refusing a body whose sha256 is not
/// `expected_sha256_hex` when the caller has one (a v2 `current.json`
/// digests the base manifest it points at). Checked on the exact bytes
/// before any parsing or signature verification.
pub async fn fetch_manifest_expecting(
    source: &dyn ListSource,
    generation: u64,
    validator_node_id_hex: &str,
    expected_sha256_hex: Option<&str>,
) -> Result<Manifest> {
    let bytes = source
        .fetch(&format!("gen/{generation}/manifest.json"), MAX_JSON_BYTES)
        .await?;
    if let Some(expected) = expected_sha256_hex {
        let digest = hex::encode(Sha256::digest(&bytes));
        if !digest.eq_ignore_ascii_case(expected) {
            bail!(
                "manifest at gen/{generation} has sha256 {digest}, current.json declares {expected}"
            );
        }
    }
    let manifest = parse_verified_manifest(&bytes, validator_node_id_hex)?;
    if manifest.generation != generation {
        bail!(
            "manifest at gen/{generation} declares generation {}",
            manifest.generation
        );
    }
    if let Err((seq, e)) = check_delta_chain(&manifest) {
        warn!(
            generation,
            seq,
            declared = manifest.deltas.len(),
            error = %format!("{e:#}"),
            "pg-lists: delta chain malformed: deltas from this seq on will not be applied"
        );
    }
    Ok(manifest)
}

/// Fetch and verify the delta manifest `link` of `base` names.
/// Fetch and verify the delta manifest `link` of `base` names, with the
/// key that verified `base` (`base.verified_by`; a hand-built base with
/// no verifier refuses every delta).
pub async fn fetch_delta_manifest(
    source: &dyn ListSource,
    base: &Manifest,
    link: &DeltaRef,
) -> Result<DeltaManifest> {
    if base.verified_by.is_empty() {
        bail!("base manifest was not verified: refusing its deltas");
    }
    let path = DeltaManifest::manifest_path(base.generation, link.seq);
    let cap = if link.size == 0 {
        MAX_JSON_BYTES
    } else {
        link.size.min(MAX_JSON_BYTES)
    };
    let bytes = source
        .fetch(&path, cap)
        .await
        .with_context(|| path.clone())?;
    parse_verified_delta_manifest(&bytes, base, link, &base.verified_by).with_context(|| path)
}

/// Load this miner's records of `owned_pgs` from `generation` into a
/// fresh filter.
///
/// Every owned PG the manifest covers must fetch and verify, otherwise the
/// load fails (a partial filter would purge the blobs of the failed PG).
/// PGs the manifest does not cover are reported in `missing_pgs` and do
/// not fail the load: the caller sees coverage incomplete and purges
/// nothing, but can still report it. A record is this miner's iff its
/// `holder_uid` is `my_uid`; nothing is computed from a map here.
///
/// `others_filter_max_bytes` caps the second filter, over the records
/// that are NOT this miner's (the moved class): `0` builds none (the
/// caller switched the class off); a filter that would exceed the cap
/// REFUSES the generation (`Err` downcasting to [`OthersFilterOverCap`],
/// before any list is downloaded) — the moved class is never silently
/// dropped from a generation the purge then enforces. Sized like the
/// main filter, from the manifest, before any download; k+m-1 records
/// per stripe are other holders', so it is (k+m-1)x the main filter at
/// the same `fp_rate`.
///
/// After the base, every delta the manifest chains is fetched, verified
/// with the key that verified the base and folded in, in seq order
/// ([`LoadedGeneration::extend`] does the same for deltas appended
/// later). A delta that fails leaves `chain_broken_at` set: the load
/// succeeds, coverage is incomplete.
#[allow(clippy::too_many_arguments)]
/// A generation refused at load because its others filter (the moved
/// class) would exceed `PURGE_OTHERS_FILTER_MAX_BYTES`. Raised before any
/// list is downloaded; the caller keeps its previous generation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OthersFilterOverCap {
    pub generation: u64,
    pub expected_others: u64,
    pub needed_bytes: u64,
    pub cap_bytes: u64,
}

impl std::fmt::Display for OthersFilterOverCap {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "others filter for {} other-holder records of generation {} needs {} bytes, above the {} byte cap (PURGE_OTHERS_FILTER_MAX_BYTES): generation refused",
            self.expected_others, self.generation, self.needed_bytes, self.cap_bytes
        )
    }
}

impl std::error::Error for OthersFilterOverCap {}

pub async fn load_generation(
    source: &dyn ListSource,
    manifest: &Manifest,
    owned_pgs: &[u32],
    my_uid: u32,
    fp_rate: f64,
    concurrency: usize,
    max_filter_bytes: u64,
    others_filter_max_bytes: u64,
) -> Result<LoadedGeneration> {
    let created_at_secs = manifest
        .created_at_secs()
        .ok_or_else(|| anyhow::anyhow!("manifest created_at is missing or unparseable"))?;
    let snapshot_secs = manifest.snapshot_secs()?;
    let missing_pgs = manifest.missing_pgs(owned_pgs);
    let listed: Vec<(u32, ObjectEntry)> = owned_pgs
        .iter()
        .filter(|pg| !missing_pgs.contains(pg))
        .map(|pg| (*pg, manifest.object_for_pg(*pg).cloned().unwrap()))
        .collect();
    if let Some((pg, obj)) = listed.iter().find(|(_, obj)| obj.size > MAX_LIST_BYTES) {
        bail!(
            "list of pg {pg} declares {} bytes, above the {MAX_LIST_BYTES} byte limit",
            obj.size
        );
    }
    let shards_per_stripe = usize::from(manifest.ec_k) + usize::from(manifest.ec_m);

    // Records are 40 bytes behind a 32-byte header and one per stripe is
    // this miner's (the write path places each shard of a stripe on a
    // distinct miner): the manifest sizes give the filter's capacity
    // before a single list is downloaded.
    let expected_hashes: u64 = listed
        .iter()
        .map(|(_, obj)| expected_my_records(obj.size, shards_per_stripe, 1))
        .sum();
    let filter_bytes = HashFilter::bytes_for(expected_hashes, fp_rate);
    if filter_bytes > max_filter_bytes {
        bail!(
            "filter for {expected_hashes} hashes needs {filter_bytes} bytes, above the {max_filter_bytes} byte cap"
        );
    }
    let mut filter = HashFilter::new(expected_hashes, fp_rate).for_generation(manifest.generation);

    // The others filter holds everything the main one rejects: all the
    // records minus this miner's.
    let expected_records: u64 = listed
        .iter()
        .map(|(_, obj)| records_in_list(obj.size))
        .sum();
    let expected_others = expected_records.saturating_sub(expected_hashes);
    let others_filter_bytes_needed = if others_filter_max_bytes == 0 {
        0
    } else {
        HashFilter::bytes_for(expected_others, fp_rate)
    };
    if others_filter_bytes_needed > others_filter_max_bytes {
        // Without the others filter a blob another holder is obliged to
        // keep would fall under the orphan gates: the generation is
        // refused rather than enforced with the class silently off.
        let refusal = OthersFilterOverCap {
            generation: manifest.generation,
            expected_others,
            needed_bytes: others_filter_bytes_needed,
            cap_bytes: others_filter_max_bytes,
        };
        warn!(
            generation = refusal.generation,
            expected_others = refusal.expected_others,
            needed_bytes = refusal.needed_bytes,
            cap_bytes = refusal.cap_bytes,
            "pg-lists: others filter exceeds PURGE_OTHERS_FILTER_MAX_BYTES: generation refused, nothing loaded"
        );
        return Err(refusal.into());
    }
    let mut others = if others_filter_max_bytes == 0 {
        None
    } else {
        Some(HashFilter::new(expected_others, fp_rate).for_generation(manifest.generation))
    };
    info!(
        generation = manifest.generation,
        owned_pgs = owned_pgs.len(),
        listed_pgs = listed.len(),
        missing_pgs = missing_pgs.len(),
        expected_hashes,
        filter_bytes = filter.memory_bytes(),
        probes = filter.probes(),
        expected_others,
        others_filter_bytes = others.as_ref().map_or(0, HashFilter::memory_bytes),
        "pg-lists: loading generation"
    );

    let generation = manifest.generation;
    let (ec_k, ec_m) = (manifest.ec_k, manifest.ec_m);

    // Tombstones first: the lists are streamed once and never kept, so
    // the only exact way to know which tombstoned hash a live record
    // still names is to mark the tombstone set while the records go by.
    let (mut tombstones, tombstone_pgs) = load_tombstones(
        source,
        manifest,
        owned_pgs
            .iter()
            .filter(|pg| !missing_pgs.contains(pg))
            .copied(),
        concurrency,
    )
    .await;
    let jobs: Vec<ListJob> = listed
        .into_iter()
        .map(|(pg_id, obj)| ListJob {
            pg_id,
            path: format!("gen/{generation}/{}", Manifest::list_path(pg_id)),
            obj,
        })
        .collect();
    let folded = fold_lists(
        source,
        jobs,
        ListIdentity {
            generation,
            ec_k,
            ec_m,
        },
        my_uid,
        concurrency,
        &mut filter,
        &mut others,
        &mut tombstones,
        "list",
    )
    .await?;
    let FoldStats {
        lists: listed_pgs,
        records: total_records,
        mine: total_hashes,
        others: total_other_hashes,
        shard_bytes: total_shard_bytes,
        tombstones_retained: tombstones_retained_live_ref,
    } = folded;

    if !missing_pgs.is_empty() {
        warn!(
            generation,
            missing = missing_pgs.len(),
            owned = owned_pgs.len(),
            "pg-lists: generation does not cover every owned PG"
        );
    }
    if total_hashes > expected_hashes {
        // More records kept than one per stripe (a writer that placed
        // this miner at several positions of a stripe): the
        // false-positive rate is above the target, which only makes the
        // purge keep more.
        warn!(
            generation,
            expected_hashes,
            total_hashes,
            "pg-lists: filter holds more hashes than it was sized for"
        );
    }
    let base_digest = lists_digest_through(manifest, owned_pgs, 0);
    let mut loaded = LoadedGeneration {
        generation,
        created_at_secs,
        snapshot_secs,
        ec_k,
        ec_m,
        owned_pgs: owned_pgs.to_vec(),
        missing_pgs,
        listed_pgs,
        total_records,
        total_hashes,
        total_shard_bytes,
        filter,
        others,
        total_other_hashes,
        others_filter_bytes_needed,
        lists_digest: base_digest,
        tombstones,
        tombstone_pgs,
        tombstones_retained_live_ref,
        delta_seq: 0,
        applied_deltas: Vec::new(),
        chain_broken_at: None,
        delta_records: 0,
        delta_hashes: 0,
        base_digest,
    };
    apply_deltas(&mut loaded, source, manifest, my_uid, concurrency).await;
    Ok(loaded)
}

/// Fold into `loaded` every delta `manifest` chains beyond
/// `loaded.delta_seq`, in order: check the link against what was already
/// applied, fetch and verify its delta manifest, fold its additions, drop
/// it (one delta manifest in memory at a time). Stops at the first link
/// that fails to chain, fetch, verify or apply and records its seq in
/// `chain_broken_at` (`None` when the whole chain is folded). Returns how
/// many deltas were applied.
async fn apply_deltas(
    loaded: &mut LoadedGeneration,
    source: &dyn ListSource,
    manifest: &Manifest,
    my_uid: u32,
    concurrency: usize,
) -> usize {
    let mut applied = 0usize;
    let mut broken: Option<(u64, anyhow::Error)> = None;
    // Links that fail the shape check are never applied, whatever comes
    // before them in the array.
    let shape_ok_upto = match check_delta_chain(manifest) {
        Ok(()) => manifest.deltas.len(),
        Err((seq, e)) => {
            broken = Some((seq, e));
            manifest
                .deltas
                .iter()
                .position(|d| d.seq >= seq)
                .unwrap_or(manifest.deltas.len())
        }
    };
    for link in &manifest.deltas[..shape_ok_upto] {
        if link.seq <= loaded.delta_seq {
            // Already folded in: the body must be the one that was.
            let same = loaded.applied_deltas.iter().any(|(seq, sha)| {
                *seq == link.seq && hex::encode(sha).eq_ignore_ascii_case(&link.sha256)
            });
            if !same {
                broken = Some((
                    link.seq,
                    anyhow::anyhow!(
                        "delta {} was applied with another body: the writer rewrote the chain",
                        link.seq
                    ),
                ));
                break;
            }
            continue;
        }
        if link.seq != loaded.delta_seq + 1 {
            broken = Some((
                link.seq,
                anyhow::anyhow!(
                    "delta {} follows applied seq {}",
                    link.seq,
                    loaded.delta_seq
                ),
            ));
            break;
        }
        let outcome = async {
            let delta = fetch_delta_manifest(source, manifest, link).await?;
            let stats = apply_delta(loaded, source, &delta, my_uid, concurrency).await?;
            Ok::<_, anyhow::Error>((delta.body_sha256, delta.until_secs(), stats))
        }
        .await;
        match outcome {
            Ok((body_sha256, until, stats)) => {
                loaded.delta_seq = link.seq;
                loaded.applied_deltas.push((link.seq, body_sha256));
                loaded.delta_records += stats.records;
                loaded.delta_hashes += stats.mine;
                loaded.total_records += stats.records;
                loaded.total_hashes += stats.mine;
                loaded.total_other_hashes += stats.others;
                loaded.total_shard_bytes =
                    loaded.total_shard_bytes.saturating_add(stats.shard_bytes);
                loaded.tombstones_retained_live_ref += stats.tombstones_retained;
                if let Some(until) = until {
                    loaded.snapshot_secs = loaded.snapshot_secs.max(until);
                }
                loaded.lists_digest =
                    lists_digest_through(manifest, &loaded.owned_pgs, loaded.delta_seq);
                applied += 1;
                info!(
                    generation = loaded.generation,
                    seq = link.seq,
                    lists = stats.lists,
                    records = stats.records,
                    mine = stats.mine,
                    tombstones_withdrawn = stats.tombstones_retained,
                    snapshot_secs = loaded.snapshot_secs,
                    "pg-lists: delta applied"
                );
            }
            Err(e) => {
                broken = Some((link.seq, e));
                break;
            }
        }
    }
    if broken.is_none() && loaded.delta_seq > manifest.declared_delta_seq() {
        broken = Some((
            manifest.declared_delta_seq() + 1,
            anyhow::anyhow!(
                "delta {} was applied but the chain now stops at {}",
                loaded.delta_seq,
                manifest.declared_delta_seq()
            ),
        ));
    }
    if let Some((seq, e)) = &broken {
        warn!(
            generation = loaded.generation,
            seq,
            applied_through = loaded.delta_seq,
            declared = manifest.declared_delta_seq(),
            error = %format!("{e:#}"),
            "pg-lists: delta chain broken: coverage incomplete until it resolves"
        );
    }
    loaded.chain_broken_at = broken.map(|(seq, _)| seq);
    applied
}

/// Fold one delta's `.added` bodies for the listed owned PGs into the
/// filters, withdrawing the tombstones its records name. A listed owned
/// PG the delta did not scan is an error (its additions are unknown).
async fn apply_delta(
    loaded: &mut LoadedGeneration,
    source: &dyn ListSource,
    delta: &DeltaManifest,
    my_uid: u32,
    concurrency: usize,
) -> Result<FoldStats> {
    let enforced: Vec<u32> = loaded
        .owned_pgs
        .iter()
        .copied()
        .filter(|pg| !loaded.missing_pgs.contains(pg))
        .collect();
    let uncovered = delta.uncovered_pgs(&enforced);
    if !uncovered.is_empty() {
        bail!(
            "delta {} did not scan {} of the {} enforced PGs (first: {})",
            delta.seq,
            uncovered.len(),
            enforced.len(),
            uncovered[0]
        );
    }
    let jobs: Vec<ListJob> = enforced
        .iter()
        .filter_map(|pg| {
            delta.added_for_pg(*pg).map(|obj| ListJob {
                pg_id: *pg,
                path: delta.added_object_path(*pg),
                obj: obj.clone(),
            })
        })
        .collect();
    if let Some(job) = jobs.iter().find(|j| j.obj.size > MAX_LIST_BYTES) {
        bail!(
            "additions of pg {} declare {} bytes, above the {MAX_LIST_BYTES} byte limit",
            job.pg_id,
            job.obj.size
        );
    }
    fold_lists(
        source,
        jobs,
        ListIdentity {
            generation: loaded.generation,
            ec_k: loaded.ec_k,
            ec_m: loaded.ec_m,
        },
        my_uid,
        concurrency,
        &mut loaded.filter,
        &mut loaded.others,
        &mut loaded.tombstones,
        "additions",
    )
    .await
}

/// One `APGL` body to fold: its PG, bucket path and manifest entry.
struct ListJob {
    pg_id: u32,
    path: String,
    obj: ObjectEntry,
}

/// What every folded body's header must name.
#[derive(Clone, Copy)]
struct ListIdentity {
    generation: u64,
    ec_k: u8,
    ec_m: u8,
}

/// Counts of one [`fold_lists`] call.
#[derive(Debug, Default)]
struct FoldStats {
    lists: usize,
    records: u64,
    mine: u64,
    others: u64,
    shard_bytes: u64,
    /// Tombstones withdrawn because a folded record named them.
    tombstones_retained: u64,
}

/// Fetch, verify and fold `jobs` (base lists or delta additions): this
/// miner's records into `filter`, the other holders' into `others` when
/// built, and every record's hash withdraws its tombstone (a live
/// reference in any enforced list wins). Any body failing to fetch or
/// verify fails the fold: a partial view of a PG would purge its blobs.
#[allow(clippy::too_many_arguments)]
async fn fold_lists(
    source: &dyn ListSource,
    jobs: Vec<ListJob>,
    identity: ListIdentity,
    my_uid: u32,
    concurrency: usize,
    filter: &mut HashFilter,
    others: &mut Option<HashFilter>,
    tombstones: &mut Vec<[u8; 32]>,
    what: &'static str,
) -> Result<FoldStats> {
    use futures::StreamExt;
    let mut tombstone_named = vec![false; tombstones.len()];
    let mut fetches = futures::stream::iter(jobs.into_iter().map(|job| async move {
        let bytes = source
            .fetch(&job.path, job.obj.size.min(MAX_LIST_BYTES))
            .await;
        (job, bytes)
    }))
    .buffer_unordered(concurrency.max(1));

    let mut stats = FoldStats::default();
    while let Some((job, bytes)) = fetches.next().await {
        let pg_id = job.pg_id;
        let bytes = bytes.with_context(|| format!("fetch {what} of pg {pg_id} ({})", job.path))?;
        if bytes.len() as u64 != job.obj.size {
            bail!(
                "{what} of pg {pg_id}: manifest size {} but body is {} bytes",
                job.obj.size,
                bytes.len()
            );
        }
        let expect = ListExpectation {
            pg_id,
            generation: identity.generation,
            ec_k: identity.ec_k,
            ec_m: identity.ec_m,
            sha256_hex: &job.obj.sha256,
        };
        let (mut pg_records, mut pg_mine, mut pg_others) = (0u64, 0u64, 0u64);
        let header = decode_list(&bytes, expect, &mut |record| {
            pg_records += 1;
            // Every record, whoever holds it: a live reference in any
            // owned PG withdraws the tombstone.
            if let Ok(i) = tombstones.binary_search(&record.blob_hash) {
                tombstone_named[i] = true;
            }
            if record.is_held_by(my_uid) {
                filter.insert(&record.blob_hash);
                pg_mine += 1;
                stats.shard_bytes = stats
                    .shard_bytes
                    .saturating_add(u64::from(record.shard_length));
            } else if let Some(others) = others.as_mut() {
                others.insert(&record.blob_hash);
                pg_others += 1;
            }
        })?;
        debug!(
            pg_id,
            count = header.count,
            mine = pg_mine,
            "pg-lists: {what} verified"
        );
        stats.records += pg_records;
        stats.mine += pg_mine;
        stats.others += pg_others;
        stats.lists += 1;
    }

    stats.tombstones_retained = tombstone_named.iter().filter(|named| **named).count() as u64;
    if stats.tombstones_retained > 0 {
        let mut i = 0usize;
        tombstones.retain(|_| {
            let keep = !tombstone_named[i];
            i += 1;
            keep
        });
        warn!(
            generation = identity.generation,
            retained = stats.tombstones_retained,
            kept = tombstones.len(),
            "pg-lists: tombstones named by a live record of an enforced {what}: withdrawn (the writer's list and tombstone disagree; the list wins)"
        );
    }
    Ok(stats)
}

/// Fetch and verify the tombstones of `pgs`, merged into one sorted,
/// unique set. Unlike the lists, a failure here never fails the load: a
/// missing tombstone is a blob kept under the orphan gates, the safe
/// direction. All-or-nothing though — one PG's failure drops every
/// tombstone of the load, so the class is never enforced on a partial
/// view of what the writer saw deleted, and the caller can tell from
/// `tombstone_pgs == 0` versus `listed_pgs`.
async fn load_tombstones(
    source: &dyn ListSource,
    manifest: &Manifest,
    pgs: impl Iterator<Item = u32>,
    concurrency: usize,
) -> (Vec<[u8; 32]>, usize) {
    let generation = manifest.generation;
    let wanted: Vec<(u32, ObjectEntry)> = pgs
        .filter_map(|pg| manifest.tombstone_for_pg(pg).cloned().map(|obj| (pg, obj)))
        .collect();
    if wanted.is_empty() {
        debug!(generation, "pg-lists: generation carries no tombstones");
        return (Vec::new(), 0);
    }
    let declared: u64 = wanted
        .iter()
        .map(|(_, obj)| obj.size.saturating_sub(TOMBSTONE_HEADER_LEN as u64) / 32)
        .sum();
    if declared > MAX_TOMBSTONE_HASHES as u64
        || wanted.iter().any(|(_, obj)| obj.size > MAX_LIST_BYTES)
    {
        warn!(
            generation,
            declared,
            cap = MAX_TOMBSTONE_HASHES,
            "pg-lists: tombstones exceed the in-memory cap: none kept, blobs stay under the orphan gates"
        );
        return (Vec::new(), 0);
    }
    use futures::StreamExt;
    let (ec_k, ec_m) = (manifest.ec_k, manifest.ec_m);
    let mut fetches = futures::stream::iter(wanted.into_iter().map(|(pg_id, obj)| async move {
        let path = format!("gen/{generation}/{}", Manifest::tombstone_path(pg_id));
        let bytes = source.fetch(&path, obj.size).await;
        (pg_id, obj, bytes)
    }))
    .buffer_unordered(concurrency.max(1));
    let mut hashes: Vec<[u8; 32]> = Vec::with_capacity(declared as usize);
    let mut pgs_done = 0usize;
    while let Some((pg_id, obj, bytes)) = fetches.next().await {
        let decoded = bytes
            .with_context(|| format!("fetch tombstones of pg {pg_id}"))
            .and_then(|bytes| {
                if bytes.len() as u64 != obj.size {
                    bail!(
                        "tombstones of pg {pg_id}: manifest size {} but body is {} bytes",
                        obj.size,
                        bytes.len()
                    );
                }
                decode_tombstones(
                    &bytes,
                    ListExpectation {
                        pg_id,
                        generation,
                        ec_k,
                        ec_m,
                        sha256_hex: &obj.sha256,
                    },
                )
            });
        match decoded {
            Ok(pg_hashes) => {
                debug!(
                    pg_id,
                    count = pg_hashes.len(),
                    "pg-lists: tombstones verified"
                );
                hashes.extend(pg_hashes);
                pgs_done += 1;
            }
            Err(e) => {
                warn!(
                    generation,
                    pg_id,
                    error = %e,
                    "pg-lists: tombstones failed to load: none kept for this generation, blobs stay under the orphan gates"
                );
                return (Vec::new(), 0);
            }
        }
    }
    // Per PG the codec guarantees order; across PGs the same shard bytes
    // can belong to two deleted files.
    hashes.sort_unstable();
    hashes.dedup();
    (hashes, pgs_done)
}

/// Builders that write a bucket layout to a directory, shared by the
/// reader tests here and the purge-loop tests in the binary (which
/// cannot see a `cfg(test)` item of the library). Not part of the API.
#[doc(hidden)]
pub mod test_fixtures {

    use super::*;
    use ed25519_dalek::{Signer, SigningKey};
    use std::path::Path;

    pub struct Fixture {
        pub key: SigningKey,
    }

    impl Fixture {
        pub fn validator_hex(&self) -> String {
            hex::encode(self.key.verifying_key().to_bytes())
        }
    }

    /// `created_at` written by `write_generation` (2026-09-11T00:00:00Z).
    pub const CREATED_AT: &str = "2026-09-11T00:00:00Z";
    pub const CREATED_AT_SECS: u64 = 1_789_084_800;

    pub fn deterministic_key(seed: u8) -> SigningKey {
        SigningKey::from_bytes(&[seed; 32])
    }

    /// Hash `i` of pg `pg`: deterministic, distinct across (pg, i).
    pub fn hash_for(pg: u32, i: u32) -> [u8; 32] {
        *blake3::hash(format!("pg{pg}-blob{i}").as_bytes()).as_bytes()
    }

    /// Shards per stripe of every fixture list (10 + 20).
    pub const SHARDS_PER_STRIPE: usize = 30;

    /// Miner uid the fixtures' records name as holder: every record of
    /// `record_for` is this miner's, which reproduces the "whole list is
    /// obliged" semantics the purge and backfill scenarios are built on.
    pub const MY_UID: u32 = 7_001;

    /// A uid no fixture record names: `load_generation` for it keeps
    /// nothing.
    pub const OTHER_UID: u32 = 7_002;

    /// Encode a list with the shared codec after normalising the records
    /// (sorted, deduplicated).
    pub fn encode_list(
        pg_id: u32,
        generation: u64,
        ec_k: u8,
        ec_m: u8,
        records: &[Record],
    ) -> Vec<u8> {
        let mut records = records.to_vec();
        common::obligation_list::normalize_records(&mut records).unwrap();
        let header = ListHeader {
            pg_id,
            generation,
            count: records.len() as u32,
            ec_k,
            ec_m,
            flags: 0,
        };
        common::obligation_list::encode_list(&header, &records).unwrap()
    }

    /// Encode without normalising or validating: the raw bytes a hostile
    /// or buggy writer could publish.
    pub fn encode_list_raw(header: &ListHeader, records: &[Record]) -> Vec<u8> {
        let mut out = header.encode().unwrap().to_vec();
        for r in records {
            out.extend_from_slice(&r.encode());
        }
        out
    }

    /// Record `i` of pg `pg`: hash `hash_for(pg, i)`, length `100 + i`,
    /// held by `MY_UID`.
    pub fn record_for(pg: u32, i: u32) -> Record {
        record_held_by(pg, i, MY_UID)
    }

    /// Record `i` of pg `pg` held by `holder_uid`.
    pub fn record_held_by(pg: u32, i: u32, holder_uid: u32) -> Record {
        Record {
            blob_hash: hash_for(pg, i),
            shard_length: 100 + i,
            holder_uid,
        }
    }

    pub fn sorted_records(pg: u32, count: u32) -> Vec<Record> {
        let mut records: Vec<Record> = (0..count).map(|i| record_for(pg, i)).collect();
        records.sort_unstable_by(Record::cmp_key);
        records
    }

    pub fn sign_manifest(key: &SigningKey, unsigned: &serde_json::Value) -> serde_json::Value {
        let message = canonical_manifest_bytes(unsigned).unwrap();
        let signature = key.sign(&message);
        let mut signed = unsigned.clone();
        signed["signature"] = serde_json::Value::String(hex::encode(signature.to_bytes()));
        signed
    }

    /// Manifest time stamps of a fixture generation.
    #[derive(Debug, Clone)]
    pub struct Stamps {
        pub created_at: serde_json::Value,
        /// Written only when `Some` (older writers do not publish it).
        pub scan_started_at: Option<serde_json::Value>,
    }

    impl Default for Stamps {
        fn default() -> Self {
            Self {
                created_at: serde_json::json!(CREATED_AT),
                scan_started_at: None,
            }
        }
    }

    /// Write a complete generation covering `pgs` with `per_pg` hashes
    /// each, pointed at by `current.json`, stamped `CREATED_AT` and
    /// without `scan_started_at`.
    pub fn write_generation(
        root: &Path,
        key: &SigningKey,
        generation: u64,
        pgs: &[u32],
        per_pg: u32,
    ) -> Fixture {
        write_generation_stamped(root, key, generation, pgs, per_pg, &Stamps::default())
    }

    /// [`write_generation`] with explicit manifest time stamps.
    pub fn write_generation_stamped(
        root: &Path,
        key: &SigningKey,
        generation: u64,
        pgs: &[u32],
        per_pg: u32,
        stamps: &Stamps,
    ) -> Fixture {
        write_generation_with(root, key, generation, pgs, stamps, &|pg| {
            sorted_records(pg, per_pg)
        })
    }

    /// [`write_generation_stamped`] with the records of each PG supplied
    /// by `records` (normalised by the codec on encode). No tombstones:
    /// the layout a pre-tombstone writer publishes.
    pub fn write_generation_with(
        root: &Path,
        key: &SigningKey,
        generation: u64,
        pgs: &[u32],
        stamps: &Stamps,
        records: &dyn Fn(u32) -> Vec<Record>,
    ) -> Fixture {
        write_generation_with_tombstones(root, key, generation, pgs, stamps, records, None)
    }

    /// Encode a PG's tombstones with the shared codec (sorted, deduped).
    pub fn encode_tombstones(
        pg_id: u32,
        generation: u64,
        ec_k: u8,
        ec_m: u8,
        hashes: &[[u8; 32]],
    ) -> Vec<u8> {
        let mut hashes = hashes.to_vec();
        common::obligation_list::normalize_hashes(&mut hashes);
        let header = ListHeader {
            pg_id,
            generation,
            count: hashes.len() as u32,
            ec_k,
            ec_m,
            flags: 0,
        };
        common::obligation_list::encode_tombstones(&header, &hashes).unwrap()
    }

    /// [`write_generation_with`] plus, when `tombstones` is `Some`, one
    /// `pg/<N>.deleted` per PG holding the hashes it returns (possibly
    /// none): the layout a tombstone-aware writer publishes.
    pub fn write_generation_with_tombstones(
        root: &Path,
        key: &SigningKey,
        generation: u64,
        pgs: &[u32],
        stamps: &Stamps,
        records: &dyn Fn(u32) -> Vec<Record>,
        tombstones: Option<&dyn Fn(u32) -> Vec<[u8; 32]>>,
    ) -> Fixture {
        let gen_dir = root.join(format!("gen/{generation}"));
        std::fs::create_dir_all(gen_dir.join("pg")).unwrap();
        let mut objects = serde_json::Map::new();
        for &pg in pgs {
            let body = encode_list(pg, generation, 10, 20, &records(pg));
            std::fs::write(gen_dir.join(Manifest::list_path(pg)), &body).unwrap();
            objects.insert(
                Manifest::list_path(pg),
                serde_json::json!({
                    "sha256": hex::encode(Sha256::digest(&body)),
                    "size": body.len(),
                }),
            );
            if let Some(tombstones) = tombstones {
                let body = encode_tombstones(pg, generation, 10, 20, &tombstones(pg));
                std::fs::write(gen_dir.join(Manifest::tombstone_path(pg)), &body).unwrap();
                objects.insert(
                    Manifest::tombstone_path(pg),
                    serde_json::json!({
                        "sha256": hex::encode(Sha256::digest(&body)),
                        "size": body.len(),
                    }),
                );
            }
        }
        let mut unsigned = serde_json::json!({
            "generation": generation,
            "created_at": stamps.created_at,
            "pg_count": 16384,
            "ec_k": 10,
            "ec_m": 20,
            "pgs": pgs,
            "objects": objects,
        });
        if let Some(scan_started_at) = &stamps.scan_started_at {
            unsigned["scan_started_at"] = scan_started_at.clone();
        }
        let signed = sign_manifest(key, &unsigned);
        std::fs::write(
            gen_dir.join("manifest.json"),
            serde_json::to_vec_pretty(&signed).unwrap(),
        )
        .unwrap();
        std::fs::write(
            root.join("current.json"),
            serde_json::json!({ "generation": generation }).to_string(),
        )
        .unwrap();
        Fixture { key: key.clone() }
    }

    /// Read back the signed base manifest of `generation` as a JSON value.
    fn read_base_manifest(root: &Path, generation: u64) -> serde_json::Value {
        let bytes = std::fs::read(root.join(format!("gen/{generation}/manifest.json"))).unwrap();
        serde_json::from_slice(&bytes).unwrap()
    }

    /// Re-sign and rewrite the base manifest of `generation` after
    /// `edit` mutated its unsigned fields.
    pub fn rewrite_base_manifest(
        root: &Path,
        key: &SigningKey,
        generation: u64,
        edit: &dyn Fn(&mut serde_json::Value),
    ) {
        let mut value = read_base_manifest(root, generation);
        value.as_object_mut().unwrap().remove("signature");
        edit(&mut value);
        let signed = sign_manifest(key, &value);
        std::fs::write(
            root.join(format!("gen/{generation}/manifest.json")),
            serde_json::to_vec_pretty(&signed).unwrap(),
        )
        .unwrap();
    }

    /// Set `base_cut` on an existing base manifest (a delta-capable
    /// writer stamps it at publication) and re-sign.
    pub fn set_base_cut(root: &Path, key: &SigningKey, generation: u64, base_cut_secs: u64) {
        rewrite_base_manifest(root, key, generation, &|v| {
            v["base_cut"] = serde_json::json!(base_cut_secs);
        });
    }

    /// Append delta `seq` (`[since, until]`) to `generation`: writes
    /// `delta/<gen>/<seq>/pg/<N>.added` for every PG `added` returns
    /// records for (a PG with no records is covered but gets no object),
    /// the signed delta manifest, appends the ref to the base manifest's
    /// `deltas` (re-signed) and bumps `current.json`'s `delta_seq`.
    /// Returns the delta manifest's body sha256.
    #[allow(clippy::too_many_arguments)]
    pub fn append_delta(
        root: &Path,
        key: &SigningKey,
        generation: u64,
        seq: u64,
        since: u64,
        until: u64,
        pgs: &[u32],
        added: &dyn Fn(u32) -> Vec<Record>,
    ) -> [u8; 32] {
        let (sha, size) = write_delta(root, key, generation, seq, since, until, pgs, added);
        rewrite_base_manifest(root, key, generation, &|v| {
            let deltas = v
                .as_object_mut()
                .unwrap()
                .entry("deltas")
                .or_insert_with(|| serde_json::json!([]));
            deltas.as_array_mut().unwrap().push(serde_json::json!({
                "seq": seq,
                "since": since,
                "until": until,
                "sha256": hex::encode(sha),
                "size": size,
            }));
        });
        std::fs::write(
            root.join("current.json"),
            serde_json::json!({ "generation": generation, "delta_seq": seq }).to_string(),
        )
        .unwrap();
        sha
    }

    /// Write the signed delta `seq` of `generation` only (its manifest and
    /// `.added` bodies), touching neither the base manifest nor
    /// `current.json`: the v2 layout, where the base is write-once and the
    /// chain lives in the pointer. Returns the delta manifest's sha256 and
    /// size.
    #[allow(clippy::too_many_arguments)]
    pub fn write_delta(
        root: &Path,
        key: &SigningKey,
        generation: u64,
        seq: u64,
        since: u64,
        until: u64,
        pgs: &[u32],
        added: &dyn Fn(u32) -> Vec<Record>,
    ) -> ([u8; 32], usize) {
        let dir = root.join(DeltaManifest::dir_path(generation, seq));
        std::fs::create_dir_all(dir.join("pg")).unwrap();
        let mut objects = serde_json::Map::new();
        for &pg in pgs {
            let records = added(pg);
            if records.is_empty() {
                continue;
            }
            let body = encode_list(pg, generation, 10, 20, &records);
            std::fs::write(dir.join(DeltaManifest::added_path(pg)), &body).unwrap();
            objects.insert(
                DeltaManifest::added_path(pg),
                serde_json::json!({
                    "sha256": hex::encode(Sha256::digest(&body)),
                    "size": body.len(),
                }),
            );
        }
        let unsigned = serde_json::json!({
            "generation": generation,
            "seq": seq,
            "since": since,
            "until": until,
            "created_at": until,
            "pg_count": 16384,
            "ec_k": 10,
            "ec_m": 20,
            "pgs": pgs,
            "objects": objects,
        });
        let signed = serde_json::to_vec_pretty(&sign_manifest(key, &unsigned)).unwrap();
        std::fs::write(dir.join("manifest.json"), &signed).unwrap();
        let sha: [u8; 32] = Sha256::digest(&signed).into();
        (sha, signed.len())
    }

    /// Write a v2 `current.json` for `generation`: the digest of its
    /// (write-once) base manifest as published, `base_cut` and a chain of
    /// `(seq, cut, delta manifest sha256)` links.
    pub fn write_current_v2(
        root: &Path,
        generation: u64,
        base_cut: u64,
        deltas: &[(u64, u64, [u8; 32])],
    ) {
        let manifest_sha = hex::encode(Sha256::digest(
            std::fs::read(root.join(format!("gen/{generation}/manifest.json"))).unwrap(),
        ));
        let deltas: Vec<serde_json::Value> = deltas
            .iter()
            .map(|(seq, cut, sha)| {
                serde_json::json!({ "seq": seq, "cut": cut, "manifest_sha": hex::encode(sha) })
            })
            .collect();
        std::fs::write(
            root.join("current.json"),
            serde_json::json!({
                "generation": generation,
                "base_cut": base_cut,
                "manifest_sha": manifest_sha,
                "deltas": deltas,
            })
            .to_string(),
        )
        .unwrap();
    }
}

#[cfg(test)]
mod tests {
    use super::test_fixtures::*;
    use super::*;

    fn sample_list(pg: u32) -> (Vec<u8>, String) {
        let body = encode_list(pg, 7, 10, 20, &sorted_records(pg, 50));
        let digest = hex::encode(Sha256::digest(&body));
        (body, digest)
    }

    fn expect<'a>(pg: u32, digest: &'a str) -> ListExpectation<'a> {
        ListExpectation {
            pg_id: pg,
            generation: 7,
            ec_k: 10,
            ec_m: 20,
            sha256_hex: digest,
        }
    }

    fn raw_header(pg: u32, count: u32) -> ListHeader {
        ListHeader {
            pg_id: pg,
            generation: 7,
            count,
            ec_k: 10,
            ec_m: 20,
            flags: 0,
        }
    }

    /// The holder filter is the record's `holder_uid` and nothing else: no
    /// map, no placement version, no stripe arithmetic. Records naming
    /// another miner are not this miner's whatever PG they sit in.
    #[test]
    fn holder_filter_is_the_record_uid() {
        let mine = record_held_by(42, 0, MY_UID);
        let other = record_held_by(42, 1, OTHER_UID);
        assert!(mine.is_held_by(MY_UID));
        assert!(!mine.is_held_by(OTHER_UID));
        assert!(other.is_held_by(OTHER_UID));
        assert!(!other.is_held_by(MY_UID));
        // The same hash listed for two holders (two files sharing a
        // blob, placed on two miners) is two records; each names its own.
        let mut twin = other;
        twin.blob_hash = mine.blob_hash;
        assert!(twin.is_held_by(OTHER_UID) && !twin.is_held_by(MY_UID));
        assert_eq!(twin.key(), (mine.blob_hash, OTHER_UID));
    }

    /// End to end: a generation whose records name thirty distinct
    /// holders, one per position of each stripe, keeps one record in
    /// thirty for a miner and counts the others as not mine; a miner
    /// named by every record keeps them all; a miner named by none keeps
    /// nothing.
    #[tokio::test]
    async fn load_generation_folds_only_my_records() {
        let dir = tempfile::tempdir().unwrap();
        let key = deterministic_key(1);
        // Record i of the PG: shard i % 30 of stripe i / 30, held by
        // `500 + (i % 30 + i / 30) % 30` (the write path's rotation).
        let holder_of = |i: u32| 500 + (i % 30 + i / 30) % 30;
        let fx = write_generation_with(dir.path(), &key, 7, &[10], &Stamps::default(), &|pg| {
            (0..300)
                .map(|i| record_held_by(pg, i, holder_of(i)))
                .collect()
        });
        let source = DirListSource::new(dir.path());
        let manifest = fetch_manifest(&source, 7, &fx.validator_hex())
            .await
            .unwrap();
        let loaded = load_generation(&source, &manifest, &[10], 500, 0.01, 1, 1 << 30, 0)
            .await
            .unwrap();
        assert_eq!(loaded.total_records, 300);
        assert_eq!(loaded.total_hashes, 10, "one per stripe of 30");
        assert!(loaded.filter_matches_generation());
        let mine: Vec<u32> = (0..300).filter(|i| holder_of(*i) == 500).collect();
        assert_eq!(mine.len(), 10);
        assert!(
            mine.iter()
                .all(|i| loaded.may_be_obliged(&hash_for(10, *i)))
        );
        assert_eq!(
            loaded.total_shard_bytes,
            mine.iter().map(|i| 100 + u64::from(*i)).sum::<u64>()
        );
        let others = (0..300)
            .filter(|i| !mine.contains(i))
            .filter(|i| loaded.may_be_obliged(&hash_for(10, *i)))
            .count();
        assert!(others < 30, "{others} false positives on 290");

        // A miner none of the records name keeps nothing.
        let none = load_generation(&source, &manifest, &[10], 499, 0.01, 1, 1 << 30, 0)
            .await
            .unwrap();
        assert_eq!(none.total_hashes, 0);
        assert_eq!(none.total_shard_bytes, 0);
        assert!((0..300).all(|i| !none.may_be_obliged(&hash_for(10, i))));

        // The default fixture names MY_UID on every record: all its own.
        let dir = tempfile::tempdir().unwrap();
        let fx = write_generation(dir.path(), &key, 7, &[10], 300);
        let source = DirListSource::new(dir.path());
        let manifest = fetch_manifest(&source, 7, &fx.validator_hex())
            .await
            .unwrap();
        let all = load_generation(&source, &manifest, &[10], MY_UID, 0.01, 1, 1 << 30, 0)
            .await
            .unwrap();
        assert_eq!(all.total_hashes, 300);
        assert!(
            all.total_hashes > 10,
            "more than one per stripe: logged, kept"
        );
    }

    /// A base without deltas loads exactly as before: seq 0, nothing
    /// applied, chain whole, coverage complete, `current.json` without
    /// `delta_seq` parses as 0.
    #[tokio::test]
    async fn base_without_deltas_loads_unchanged() {
        let dir = tempfile::tempdir().unwrap();
        let key = deterministic_key(1);
        let fx = write_generation(dir.path(), &key, 7, &[10, 11], 50);
        let source = DirListSource::new(dir.path());
        let pointer = fetch_current(&source).await.unwrap();
        assert_eq!((pointer.generation, pointer.delta_seq), (7, 0));
        let manifest = fetch_manifest(&source, 7, &fx.validator_hex())
            .await
            .unwrap();
        assert!(manifest.deltas.is_empty());
        assert_eq!(manifest.declared_delta_seq(), 0);
        assert!(check_delta_chain(&manifest).is_ok());
        let loaded = load_generation(&source, &manifest, &[10, 11], MY_UID, 0.01, 2, 1 << 30, 0)
            .await
            .unwrap();
        assert_eq!(loaded.delta_seq, 0);
        assert!(loaded.applied_deltas.is_empty());
        assert_eq!(loaded.chain_broken_at, None);
        assert_eq!(loaded.delta_records, 0);
        assert!(loaded.coverage_complete());
        assert_eq!(loaded.total_hashes, 100);
        assert_eq!(loaded.snapshot_secs, CREATED_AT_SECS);
    }

    /// Three deltas tiling from `base_cut` are applied in seq order: their
    /// records become obligations (a filter hit is a keep), the
    /// tombstones they withdraw are dropped, `snapshot_secs` moves to the
    /// last `until`, the digest changes with each seq, and an already
    /// loaded generation folds only the deltas appended since
    /// (`extend`) without re-downloading the base.
    #[tokio::test]
    async fn deltas_apply_in_order_and_extend_a_loaded_generation() {
        let dir = tempfile::tempdir().unwrap();
        let key = deterministic_key(1);
        let cut = CREATED_AT_SECS - 300;
        let fx = write_generation_with_tombstones(
            dir.path(),
            &key,
            7,
            &[10, 11],
            &Stamps::default(),
            &|pg| sorted_records(pg, 50),
            Some(&|pg| vec![hash_for(pg, 900)]),
        );
        set_base_cut(dir.path(), &key, 7, cut);
        let source = DirListSource::new(dir.path());
        let hex = fx.validator_hex();

        // Two deltas published before this reader first loads.
        append_delta(dir.path(), &key, 7, 1, cut, cut + 3600, &[10, 11], &|pg| {
            (100..110).map(|i| record_for(pg, i)).collect()
        });
        // Delta 2 re-lists a tombstoned hash of PG 10: the tombstone is
        // withdrawn. PG 11 is covered with nothing added.
        append_delta(
            dir.path(),
            &key,
            7,
            2,
            cut + 3600,
            cut + 7200,
            &[10, 11],
            &|pg| {
                if pg == 10 {
                    vec![record_for(pg, 900)]
                } else {
                    Vec::new()
                }
            },
        );
        let manifest = fetch_manifest(&source, 7, &hex).await.unwrap();
        assert_eq!(manifest.declared_delta_seq(), 2);
        assert_eq!(manifest.base_cut_secs(), Some(cut));
        let mut loaded =
            load_generation(&source, &manifest, &[10, 11], MY_UID, 0.01, 2, 1 << 30, 0)
                .await
                .unwrap();
        assert_eq!(loaded.delta_seq, 2);
        assert_eq!(loaded.chain_broken_at, None);
        assert!(loaded.coverage_complete());
        assert_eq!(loaded.applied_deltas.len(), 2);
        assert_eq!(loaded.delta_records, 21);
        assert_eq!(loaded.delta_hashes, 21);
        assert_eq!(loaded.total_hashes, 121);
        assert!((100..110).all(|i| loaded.may_be_obliged(&hash_for(10, i))));
        assert!((100..110).all(|i| loaded.may_be_obliged(&hash_for(11, i))));
        assert!(loaded.may_be_obliged(&hash_for(10, 900)));
        assert!(!loaded.is_tombstoned(&hash_for(10, 900)), "withdrawn");
        assert!(loaded.is_tombstoned(&hash_for(11, 900)), "still deleted");
        assert_eq!(loaded.snapshot_secs, cut + 7200);
        let digest_2 = loaded.lists_digest;
        assert_ne!(digest_2, lists_digest_through(&manifest, &[10, 11], 0));
        assert_eq!(digest_2, lists_digest_through(&manifest, &[10, 11], 2));

        // Nothing new: extend is a no-op.
        let same = fetch_manifest(&source, 7, &hex).await.unwrap();
        assert_eq!(loaded.extend(&source, &same, MY_UID, 2).await.unwrap(), 0);
        assert_eq!(loaded.delta_seq, 2);

        // A third delta lands: current.json hints, the base chain grew,
        // extend folds only seq 3.
        append_delta(
            dir.path(),
            &key,
            7,
            3,
            cut + 7200,
            cut + 9000,
            &[10, 11],
            &|pg| vec![record_for(pg, 200)],
        );
        let pointer = fetch_current(&source).await.unwrap();
        assert_eq!(pointer.delta_seq, 3);
        let grown = fetch_manifest(&source, 7, &hex).await.unwrap();
        assert_eq!(loaded.extend(&source, &grown, MY_UID, 2).await.unwrap(), 1);
        assert_eq!(loaded.delta_seq, 3);
        assert_eq!(loaded.applied_deltas.len(), 3);
        assert_eq!(loaded.delta_records, 23);
        assert!(loaded.may_be_obliged(&hash_for(11, 200)));
        assert_eq!(loaded.snapshot_secs, cut + 9000);
        assert_ne!(loaded.lists_digest, digest_2);
        assert!(loaded.coverage_complete());

        // A fresh load of the same bucket lands on the same state.
        let fresh = load_generation(&source, &grown, &[10, 11], MY_UID, 0.01, 2, 1 << 30, 0)
            .await
            .unwrap();
        assert_eq!(fresh.delta_seq, 3);
        assert_eq!(fresh.applied_deltas, loaded.applied_deltas);
        assert_eq!(fresh.lists_digest, loaded.lists_digest);
    }

    /// A chain with a gap (seq 1 then 3), a window that does not tile, a
    /// delta that skipped an owned PG, a delta signed by another key, or
    /// a base that lost its `base_cut` all leave the load usable but
    /// coverage incomplete at the offending seq: what came before is
    /// enforced, nothing after it is, and the purge gate stays closed
    /// until the writer resolves it.
    #[tokio::test]
    async fn broken_delta_chain_is_coverage_incomplete_not_a_refusal() {
        let key = deterministic_key(1);
        let cut = CREATED_AT_SECS - 300;
        let setup = |dir: &std::path::Path| -> Fixture {
            let fx = write_generation(dir, &key, 7, &[10, 11], 50);
            set_base_cut(dir, &key, 7, cut);
            append_delta(dir, &key, 7, 1, cut, cut + 3600, &[10, 11], &|pg| {
                vec![record_for(pg, 100)]
            });
            fx
        };

        // Gap: seq 3 declared after seq 1.
        let dir = tempfile::tempdir().unwrap();
        let fx = setup(dir.path());
        let source = DirListSource::new(dir.path());
        append_delta(
            dir.path(),
            &key,
            7,
            3,
            cut + 3600,
            cut + 7200,
            &[10, 11],
            &|pg| vec![record_for(pg, 300)],
        );
        let manifest = fetch_manifest(&source, 7, &fx.validator_hex())
            .await
            .unwrap();
        assert_eq!(check_delta_chain(&manifest).unwrap_err().0, 3);
        let loaded = load_generation(&source, &manifest, &[10, 11], MY_UID, 0.01, 2, 1 << 30, 0)
            .await
            .unwrap();
        assert_eq!(loaded.delta_seq, 1);
        assert_eq!(loaded.chain_broken_at, Some(3));
        assert!(!loaded.coverage_complete());
        assert!(loaded.missing_pgs.is_empty(), "the base covers every PG");
        assert!(loaded.may_be_obliged(&hash_for(10, 100)), "seq 1 enforced");
        assert!(
            !loaded.may_be_obliged(&hash_for(10, 300)),
            "seq 3 not applied"
        );
        assert_eq!(loaded.snapshot_secs, cut + 3600);

        // Window that does not tile: seq 2 starts after seq 1 ended.
        let dir = tempfile::tempdir().unwrap();
        let fx = setup(dir.path());
        let source = DirListSource::new(dir.path());
        append_delta(
            dir.path(),
            &key,
            7,
            2,
            cut + 4000,
            cut + 7200,
            &[10, 11],
            &|pg| vec![record_for(pg, 300)],
        );
        let manifest = fetch_manifest(&source, 7, &fx.validator_hex())
            .await
            .unwrap();
        let loaded = load_generation(&source, &manifest, &[10, 11], MY_UID, 0.01, 2, 1 << 30, 0)
            .await
            .unwrap();
        assert_eq!((loaded.delta_seq, loaded.chain_broken_at), (1, Some(2)));

        // Delta 2 scanned PG 10 only: PG 11 is owned, the chain breaks
        // at 2 even though the manifest fetched and verified.
        let dir = tempfile::tempdir().unwrap();
        let fx = setup(dir.path());
        let source = DirListSource::new(dir.path());
        append_delta(
            dir.path(),
            &key,
            7,
            2,
            cut + 3600,
            cut + 7200,
            &[10],
            &|pg| vec![record_for(pg, 300)],
        );
        let manifest = fetch_manifest(&source, 7, &fx.validator_hex())
            .await
            .unwrap();
        assert!(check_delta_chain(&manifest).is_ok(), "shape is fine");
        let loaded = load_generation(&source, &manifest, &[10, 11], MY_UID, 0.01, 2, 1 << 30, 0)
            .await
            .unwrap();
        assert_eq!((loaded.delta_seq, loaded.chain_broken_at), (1, Some(2)));
        assert!(
            !loaded.may_be_obliged(&hash_for(10, 300)),
            "no partial apply"
        );
        // A reader owning PG 10 alone is whole.
        let only_10 = load_generation(&source, &manifest, &[10], MY_UID, 0.01, 2, 1 << 30, 0)
            .await
            .unwrap();
        assert_eq!((only_10.delta_seq, only_10.chain_broken_at), (2, None));
        assert!(only_10.may_be_obliged(&hash_for(10, 300)));

        // Delta 2 signed by another key: verified against the base's key.
        let dir = tempfile::tempdir().unwrap();
        let fx = setup(dir.path());
        let source = DirListSource::new(dir.path());
        let sha = append_delta(
            dir.path(),
            &deterministic_key(2),
            7,
            2,
            cut + 3600,
            cut + 7200,
            &[10, 11],
            &|pg| vec![record_for(pg, 300)],
        );
        // append_delta re-signed the base with key 2 too: restore the
        // real writer's signature over the grown chain.
        rewrite_base_manifest(dir.path(), &key, 7, &|_| {});
        let manifest = fetch_manifest(&source, 7, &fx.validator_hex())
            .await
            .unwrap();
        assert_eq!(manifest.deltas[1].sha256, hex::encode(sha));
        let loaded = load_generation(&source, &manifest, &[10, 11], MY_UID, 0.01, 2, 1 << 30, 0)
            .await
            .unwrap();
        assert_eq!((loaded.delta_seq, loaded.chain_broken_at), (1, Some(2)));

        // No base_cut on a base that declares deltas: seq 1 cannot anchor.
        let dir = tempfile::tempdir().unwrap();
        let fx = write_generation(dir.path(), &key, 7, &[10, 11], 50);
        let source = DirListSource::new(dir.path());
        append_delta(dir.path(), &key, 7, 1, cut, cut + 3600, &[10, 11], &|pg| {
            vec![record_for(pg, 100)]
        });
        let manifest = fetch_manifest(&source, 7, &fx.validator_hex())
            .await
            .unwrap();
        assert_eq!(check_delta_chain(&manifest).unwrap_err().0, 1);
        let loaded = load_generation(&source, &manifest, &[10, 11], MY_UID, 0.01, 2, 1 << 30, 0)
            .await
            .unwrap();
        assert_eq!((loaded.delta_seq, loaded.chain_broken_at), (0, Some(1)));
        assert!(!loaded.coverage_complete());
        assert!(!loaded.may_be_obliged(&hash_for(10, 100)));
    }

    /// A writer that rewrites history is refused by `extend`: an applied
    /// delta whose ref changed, a chain shorter than what was applied, or
    /// base lists whose digests moved all mark the chain broken and fold
    /// nothing; the already enforced view stays.
    #[tokio::test]
    async fn extend_refuses_a_rewritten_chain() {
        let key = deterministic_key(1);
        let cut = CREATED_AT_SECS - 300;
        let dir = tempfile::tempdir().unwrap();
        let fx = write_generation(dir.path(), &key, 7, &[10, 11], 50);
        set_base_cut(dir.path(), &key, 7, cut);
        append_delta(dir.path(), &key, 7, 1, cut, cut + 3600, &[10, 11], &|pg| {
            vec![record_for(pg, 100)]
        });
        let source = DirListSource::new(dir.path());
        let manifest = fetch_manifest(&source, 7, &fx.validator_hex())
            .await
            .unwrap();
        let mut loaded =
            load_generation(&source, &manifest, &[10, 11], MY_UID, 0.01, 2, 1 << 30, 0)
                .await
                .unwrap();
        assert_eq!((loaded.delta_seq, loaded.chain_broken_at), (1, None));

        // Seq 1 replaced by another body.
        rewrite_base_manifest(dir.path(), &key, 7, &|v| {
            v["deltas"][0]["sha256"] = serde_json::json!(hex::encode([0xAA; 32]));
        });
        let rewritten = fetch_manifest(&source, 7, &fx.validator_hex())
            .await
            .unwrap();
        assert_eq!(
            loaded.extend(&source, &rewritten, MY_UID, 2).await.unwrap(),
            0
        );
        assert_eq!((loaded.delta_seq, loaded.chain_broken_at), (1, Some(1)));
        assert!(!loaded.coverage_complete());
        assert!(loaded.may_be_obliged(&hash_for(10, 100)), "view kept");

        // Chain truncated below what was applied.
        rewrite_base_manifest(dir.path(), &key, 7, &|v| {
            v["deltas"] = serde_json::json!([]);
        });
        let truncated = fetch_manifest(&source, 7, &fx.validator_hex())
            .await
            .unwrap();
        loaded.chain_broken_at = None;
        assert_eq!(
            loaded.extend(&source, &truncated, MY_UID, 2).await.unwrap(),
            0
        );
        assert_eq!(
            loaded.chain_broken_at,
            Some(1),
            "first seq no longer declared"
        );

        // Base list of an owned PG rewritten.
        rewrite_base_manifest(dir.path(), &key, 7, &|v| {
            v["objects"][Manifest::list_path(10)]["sha256"] =
                serde_json::json!(hex::encode([0xBB; 32]));
        });
        let relisted = fetch_manifest(&source, 7, &fx.validator_hex())
            .await
            .unwrap();
        loaded.chain_broken_at = None;
        assert_eq!(
            loaded.extend(&source, &relisted, MY_UID, 2).await.unwrap(),
            0
        );
        assert!(loaded.chain_broken_at.is_some());

        // Another generation is not an extension at all.
        let mut other = relisted.clone();
        other.generation = 8;
        assert!(loaded.extend(&source, &other, MY_UID, 2).await.is_err());
    }

    /// The others filter is the complement of the main one over the same
    /// lists: on the thirty-holder fixture it holds the 290 records that
    /// are not this miner's and answers "moved" for each of them; the
    /// miner's own 10 hashes are not folded in (a hit there is only a
    /// false positive). Sized from the manifest at (k+m-1)/(k+m) of the
    /// records; a cap it does not fit under leaves it unbuilt without
    /// failing the load; cap 0 means "not wanted".
    #[tokio::test]
    async fn others_filter_holds_the_other_holders_records() {
        let dir = tempfile::tempdir().unwrap();
        let key = deterministic_key(1);
        let holder_of = |i: u32| 500 + (i % 30 + i / 30) % 30;
        let fx = write_generation_with(dir.path(), &key, 7, &[10], &Stamps::default(), &|pg| {
            (0..300)
                .map(|i| record_held_by(pg, i, holder_of(i)))
                .collect()
        });
        let source = DirListSource::new(dir.path());
        let manifest = fetch_manifest(&source, 7, &fx.validator_hex())
            .await
            .unwrap();
        let loaded = load_generation(&source, &manifest, &[10], 500, 0.01, 1, 1 << 30, 1 << 30)
            .await
            .unwrap();
        assert!(loaded.has_others_filter());
        assert_eq!(loaded.total_hashes, 10);
        assert_eq!(loaded.total_other_hashes, 290);
        assert_eq!(loaded.total_records, 300);
        let others = loaded.others.as_ref().unwrap();
        assert_eq!(others.generation(), Some(7));
        assert_eq!(others.inserted(), 290);
        for i in 0..300 {
            let h = hash_for(10, i);
            if holder_of(i) == 500 {
                assert!(loaded.may_be_obliged(&h));
            } else {
                assert!(
                    loaded.may_be_held_by_other(&h),
                    "record {i} is another holder's"
                );
            }
        }
        // Sizing: the manifest predicts 300 records, 10 mine, 290 others;
        // `bytes_for` floors at MIN_FILTER_BITS so both are 8 KiB here.
        assert_eq!(
            loaded.others_filter_bytes_needed,
            HashFilter::bytes_for(290, 0.01)
        );
        assert_eq!(others.memory_bytes(), loaded.others_filter_bytes_needed);

        // Over the cap: the generation is refused with a typed error
        // that reports the need, before any list is read.
        let err = load_generation(&source, &manifest, &[10], 500, 0.01, 1, 1 << 30, 1)
            .await
            .expect_err("over the cap refuses the generation");
        let refusal = err
            .downcast_ref::<OthersFilterOverCap>()
            .expect("typed refusal");
        assert_eq!(
            *refusal,
            OthersFilterOverCap {
                generation: 7,
                expected_others: 290,
                needed_bytes: HashFilter::bytes_for(290, 0.01),
                cap_bytes: 1,
            }
        );
        assert!(refusal.to_string().contains("generation refused"));

        // Not wanted at all: no filter, no refusal.
        let none = load_generation(&source, &manifest, &[10], 500, 0.01, 1, 1 << 30, 0)
            .await
            .unwrap();
        assert!(!none.has_others_filter());
        assert_eq!(none.others_filter_bytes_needed, 0);
        assert_eq!(none.total_other_hashes, 0);
    }

    #[test]
    fn list_header_decodes_every_field() {
        let (body, _) = sample_list(42);
        let header = decode_header(&body).unwrap();
        assert_eq!(
            header,
            ListHeader {
                pg_id: 42,
                generation: 7,
                count: 50,
                ec_k: 10,
                ec_m: 20,
                flags: 0,
            }
        );
    }

    #[test]
    fn list_decodes_sorted_records_in_order() {
        let (body, digest) = sample_list(42);
        let mut seen = Vec::new();
        let header = decode_list(&body, expect(42, &digest), &mut |r| seen.push(*r)).unwrap();
        assert_eq!(header.count, 50);
        assert_eq!(seen, sorted_records(42, 50));
    }

    #[test]
    fn list_rejects_unsorted_records() {
        let mut records = sorted_records(42, 50);
        records.swap(3, 4);
        let body = encode_list_raw(&raw_header(42, 50), &records);
        let digest = hex::encode(Sha256::digest(&body));
        let err = decode_list(&body, expect(42, &digest), &mut |_| {}).unwrap_err();
        assert!(
            format!("{err:#}").contains("not strictly sorted"),
            "{err:#}"
        );
    }

    #[test]
    fn list_rejects_duplicate_records() {
        let mut records = sorted_records(42, 50);
        records[5] = records[4];
        let body = encode_list_raw(&raw_header(42, 50), &records);
        let digest = hex::encode(Sha256::digest(&body));
        assert!(decode_list(&body, expect(42, &digest), &mut |_| {}).is_err());
    }

    #[test]
    fn list_rejects_sha256_mismatch() {
        let (body, _) = sample_list(42);
        let wrong = hex::encode([0u8; 32]);
        let err = decode_list(&body, expect(42, &wrong), &mut |_| {}).unwrap_err();
        assert!(err.to_string().contains("sha256 mismatch"), "{err}");
    }

    #[test]
    fn list_rejects_pg_id_mismatch() {
        let (body, digest) = sample_list(42);
        let err = decode_list(&body, expect(43, &digest), &mut |_| {}).unwrap_err();
        assert!(err.to_string().contains("names pg 42"), "{err}");
    }

    #[test]
    fn list_rejects_generation_mismatch() {
        let (body, digest) = sample_list(42);
        let mut e = expect(42, &digest);
        e.generation = 8;
        let err = decode_list(&body, e, &mut |_| {}).unwrap_err();
        assert!(err.to_string().contains("generation"), "{err}");
    }

    #[test]
    fn list_rejects_ec_mismatch_bad_magic_version_and_truncation() {
        let (body, digest) = sample_list(42);
        let mut e = expect(42, &digest);
        e.ec_m = 21;
        assert!(decode_list(&body, e, &mut |_| {}).is_err());

        let mut bad_magic = body.clone();
        bad_magic[0] = b'X';
        let d = hex::encode(Sha256::digest(&bad_magic));
        assert!(decode_list(&bad_magic, expect(42, &d), &mut |_| {}).is_err());

        // Legacy version 1 (one record per file) is refused, not misread.
        let mut bad_version = body.clone();
        bad_version[4] = 1;
        let d = hex::encode(Sha256::digest(&bad_version));
        let err = decode_list(&bad_version, expect(42, &d), &mut |_| {}).unwrap_err();
        assert!(
            format!("{err:#}").contains("unsupported list version 1"),
            "{err:#}"
        );

        let truncated = &body[..body.len() - 1];
        let d = hex::encode(Sha256::digest(truncated));
        let err = decode_list(truncated, expect(42, &d), &mut |_| {}).unwrap_err();
        assert!(
            format!("{err:#}").contains("declares 50 records"),
            "{err:#}"
        );
    }

    #[test]
    fn manifest_signature_verified_and_rejected() {
        let dir = tempfile::tempdir().unwrap();
        let key = deterministic_key(1);
        let fx = write_generation(dir.path(), &key, 7, &[1, 2, 3], 5);
        let bytes = std::fs::read(dir.path().join("gen/7/manifest.json")).unwrap();

        let manifest = parse_verified_manifest(&bytes, &fx.validator_hex()).unwrap();
        assert_eq!(manifest.generation, 7);
        assert_eq!(manifest.pgs, vec![1, 2, 3]);
        assert_eq!(manifest.objects.len(), 3);
        assert_eq!(manifest.missing_pgs(&[2, 9]), vec![9]);

        // Wrong key.
        let other = hex::encode(deterministic_key(2).verifying_key().to_bytes());
        assert!(parse_verified_manifest(&bytes, &other).is_err());

        // Tampered content under a valid signature.
        let mut value: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
        value["pgs"] = serde_json::json!([1, 2, 3, 4]);
        let tampered = serde_json::to_vec(&value).unwrap();
        assert!(parse_verified_manifest(&tampered, &fx.validator_hex()).is_err());

        // Unsigned.
        value.as_object_mut().unwrap().remove("signature");
        let unsigned = serde_json::to_vec(&value).unwrap();
        let err = parse_verified_manifest(&unsigned, &fx.validator_hex()).unwrap_err();
        assert!(err.to_string().contains("unsigned"), "{err}");

        // Signature hex of the wrong length.
        value["signature"] = serde_json::Value::String("abcd".into());
        assert!(
            parse_verified_manifest(&serde_json::to_vec(&value).unwrap(), &fx.validator_hex())
                .is_err()
        );
    }

    #[test]
    fn manifest_signature_survives_reformatting() {
        // Whitespace and key order of the transported JSON must not matter.
        let dir = tempfile::tempdir().unwrap();
        let key = deterministic_key(1);
        let fx = write_generation(dir.path(), &key, 7, &[1], 5);
        let value: serde_json::Value =
            serde_json::from_slice(&std::fs::read(dir.path().join("gen/7/manifest.json")).unwrap())
                .unwrap();
        let compact = serde_json::to_vec(&value).unwrap();
        assert!(parse_verified_manifest(&compact, &fx.validator_hex()).is_ok());
    }

    #[test]
    fn current_json_parses() {
        assert_eq!(parse_current(br#"{"generation": 12}"#).unwrap(), 12);
        assert!(parse_current(br#"{"gen": 12}"#).is_err());
    }

    /// Every pointer shape a writer has published parses; the delta hint
    /// comes from whichever field carries it; a v2 digest must look like
    /// one; fields this reader does not know are ignored.
    #[test]
    fn current_json_accepts_v0_v1_and_v2_shapes() {
        let v0 = parse_current_pointer(br#"{"generation": 12}"#).unwrap();
        assert_eq!(
            (v0.generation, v0.delta_hint(), v0.manifest_sha()),
            (12, 0, None)
        );

        let v1 = parse_current_pointer(br#"{"generation": 12, "delta_seq": 3}"#).unwrap();
        assert_eq!(
            (v1.generation, v1.delta_hint(), v1.manifest_sha()),
            (12, 3, None)
        );

        let sha = "ab".repeat(32);
        let v2 = parse_current_pointer(
            format!(
                r#"{{"generation":12,"base_cut":1700000000,"manifest_sha":"{sha}","deltas":[{{"seq":1,"cut":1700000300,"manifest_sha":"{sha}"}},{{"seq":2,"cut":1700000600,"manifest_sha":"{sha}"}}]}}"#
            )
            .as_bytes(),
        )
        .unwrap();
        assert_eq!(v2.generation, 12);
        assert_eq!(v2.base_cut, Some(1_700_000_000));
        assert_eq!(v2.manifest_sha(), Some(sha.as_str()));
        assert_eq!(v2.delta_hint(), 2);
        assert_eq!(v2.deltas.len(), 2);
        assert_eq!(v2.deltas[1].cut, 1_700_000_600);

        // A v2 pointer without deltas yet (fresh base).
        let fresh = parse_current_pointer(
            format!(r#"{{"generation":13,"base_cut":1,"manifest_sha":"{sha}"}}"#).as_bytes(),
        )
        .unwrap();
        assert_eq!((fresh.generation, fresh.delta_hint()), (13, 0));

        // Unknown fields from a newer writer are tolerated.
        let newer =
            parse_current_pointer(br#"{"generation": 14, "schema": 3, "note": "x"}"#).unwrap();
        assert_eq!(newer.generation, 14);

        // A digest that could never match a manifest is refused up front.
        for bad in [
            "",
            "abc",
            "zz".repeat(32).as_str(),
            "ab".repeat(31).as_str(),
        ] {
            let body = format!(r#"{{"generation":12,"manifest_sha":"{bad}"}}"#);
            assert!(
                parse_current_pointer(body.as_bytes()).is_err(),
                "manifest_sha {bad:?} must be refused"
            );
        }
        // Case of the hex digits does not matter.
        let upper = parse_current_pointer(
            format!(
                r#"{{"generation":12,"manifest_sha":"{}"}}"#,
                "AB".repeat(32)
            )
            .as_bytes(),
        )
        .unwrap();
        assert_eq!(upper.manifest_sha(), Some("AB".repeat(32).as_str()));
    }

    /// v2 layout: the base manifest is write-once (no `base_cut`, no
    /// `deltas`), the pointer digests it and carries the chain. The
    /// reader adopts the chain, applies both deltas (each verified against
    /// its own signed manifest), extends when the pointer grows, and
    /// breaks the chain at a link whose digest names no valid delta.
    #[tokio::test]
    async fn v2_pointer_chain_is_adopted_and_applied() {
        let dir = tempfile::tempdir().unwrap();
        let key = deterministic_key(1);
        let cut = CREATED_AT_SECS - 300;
        let fx = write_generation(dir.path(), &key, 7, &[10, 11], 50);
        let source = DirListSource::new(dir.path());
        let hex = fx.validator_hex();
        let base_bytes = std::fs::read(dir.path().join("gen/7/manifest.json")).unwrap();

        let (sha1, _) = write_delta(dir.path(), &key, 7, 1, cut, cut + 3600, &[10, 11], &|pg| {
            (100..110).map(|i| record_for(pg, i)).collect()
        });
        let (sha2, _) = write_delta(
            dir.path(),
            &key,
            7,
            2,
            cut + 3600,
            cut + 7200,
            &[10, 11],
            &|pg| vec![record_for(pg, 200)],
        );
        write_current_v2(
            dir.path(),
            7,
            cut,
            &[(1, cut + 3600, sha1), (2, cut + 7200, sha2)],
        );
        // The base was not touched.
        assert_eq!(
            std::fs::read(dir.path().join("gen/7/manifest.json")).unwrap(),
            base_bytes
        );

        let pointer = fetch_current(&source).await.unwrap();
        assert_eq!((pointer.generation, pointer.delta_hint()), (7, 2));
        // Without the pointer the base declares no chain at all.
        let bare = fetch_manifest(&source, 7, &hex).await.unwrap();
        assert!(bare.deltas.is_empty());
        assert_eq!(bare.base_cut_secs(), None);

        let manifest = fetch_manifest_at(&source, &pointer, &hex).await.unwrap();
        assert_eq!(manifest.declared_delta_seq(), 2);
        assert_eq!(manifest.base_cut_secs(), Some(cut));
        assert_eq!(
            manifest.deltas[0].size, 0,
            "size not declared by the pointer"
        );
        assert_eq!(secs_of(&manifest.deltas[1].since), Some(cut + 3600));
        assert!(check_delta_chain(&manifest).is_ok());

        let mut loaded =
            load_generation(&source, &manifest, &[10, 11], MY_UID, 0.01, 2, 1 << 30, 0)
                .await
                .unwrap();
        assert_eq!((loaded.delta_seq, loaded.chain_broken_at), (2, None));
        assert!(loaded.coverage_complete());
        assert!((100..110).all(|i| loaded.may_be_obliged(&hash_for(10, i))));
        assert!(loaded.may_be_obliged(&hash_for(11, 200)));
        assert_eq!(loaded.snapshot_secs, cut + 7200);

        // The chain grows in the pointer only: extend folds seq 3.
        let (sha3, _) = write_delta(
            dir.path(),
            &key,
            7,
            3,
            cut + 7200,
            cut + 10_800,
            &[10, 11],
            &|pg| vec![record_for(pg, 300)],
        );
        write_current_v2(
            dir.path(),
            7,
            cut,
            &[
                (1, cut + 3600, sha1),
                (2, cut + 7200, sha2),
                (3, cut + 10_800, sha3),
            ],
        );
        let pointer = fetch_current(&source).await.unwrap();
        assert_eq!(pointer.delta_hint(), 3);
        let grown = fetch_manifest_at(&source, &pointer, &hex).await.unwrap();
        assert_eq!(loaded.extend(&source, &grown, MY_UID, 2).await.unwrap(), 1);
        assert_eq!((loaded.delta_seq, loaded.chain_broken_at), (3, None));
        assert!(loaded.may_be_obliged(&hash_for(10, 300)));

        // A link whose digest matches no delta on the bucket, or whose
        // window disagrees with the signed delta, breaks the chain there:
        // seq 1..3 stay enforced, coverage is incomplete.
        write_current_v2(
            dir.path(),
            7,
            cut,
            &[
                (1, cut + 3600, sha1),
                (2, cut + 7200, sha2),
                (3, cut + 10_800, sha3),
                (4, cut + 14_400, [0xEF; 32]),
            ],
        );
        let pointer = fetch_current(&source).await.unwrap();
        let bad = fetch_manifest_at(&source, &pointer, &hex).await.unwrap();
        assert_eq!(loaded.extend(&source, &bad, MY_UID, 2).await.unwrap(), 0);
        assert_eq!((loaded.delta_seq, loaded.chain_broken_at), (3, Some(4)));
        assert!(!loaded.coverage_complete());
        assert!(loaded.may_be_obliged(&hash_for(10, 300)));

        // A pointer whose cut does not match the delta's signed window is
        // refused too (fresh load, seq 1 mis-stamped).
        write_current_v2(dir.path(), 7, cut, &[(1, cut + 3601, sha1)]);
        let pointer = fetch_current(&source).await.unwrap();
        let skewed = fetch_manifest_at(&source, &pointer, &hex).await.unwrap();
        let fresh = load_generation(&source, &skewed, &[10, 11], MY_UID, 0.01, 2, 1 << 30, 0)
            .await
            .unwrap();
        assert_eq!((fresh.delta_seq, fresh.chain_broken_at), (0, Some(1)));

        // A v1 base that declares its own chain keeps it whatever the
        // pointer says.
        let mut v1 = fetch_manifest(&source, 7, &hex).await.unwrap();
        v1.deltas.push(DeltaRef {
            seq: 1,
            since: serde_json::Value::from(cut),
            until: serde_json::Value::from(cut + 3600),
            sha256: hex::encode(sha1),
            size: 0,
        });
        assert!(!v1.adopt_pointer_chain(&pointer));
        assert_eq!(v1.deltas.len(), 1);
        // No base_cut in the pointer: nothing to anchor, nothing adopted.
        let mut bare = fetch_manifest(&source, 7, &hex).await.unwrap();
        let unanchored = CurrentPointer {
            generation: 7,
            deltas: pointer.deltas.clone(),
            ..CurrentPointer::default()
        };
        assert!(!bare.adopt_pointer_chain(&unanchored));
        assert!(bare.deltas.is_empty());
    }

    /// The v2 pointer digests the exact bytes of the base manifest: the
    /// matching digest loads, any other refuses the manifest before its
    /// signature is even checked, and no digest keeps the old behaviour.
    #[tokio::test]
    async fn fetch_manifest_expecting_checks_the_pointer_digest() {
        use test_fixtures::{deterministic_key, write_generation};
        let dir = tempfile::tempdir().unwrap();
        let key = deterministic_key(1);
        let fx = write_generation(dir.path(), &key, 7, &[1], 5);
        let source = DirListSource::new(dir.path());
        let bytes = std::fs::read(dir.path().join("gen/7/manifest.json")).unwrap();
        let sha = hex::encode(Sha256::digest(&bytes));

        let ok = fetch_manifest_expecting(&source, 7, &fx.validator_hex(), Some(&sha))
            .await
            .unwrap();
        assert_eq!(ok.generation, 7);
        let upper = fetch_manifest_expecting(
            &source,
            7,
            &fx.validator_hex(),
            Some(&sha.to_ascii_uppercase()),
        )
        .await
        .unwrap();
        assert_eq!(upper.generation, 7);
        assert!(
            fetch_manifest_expecting(&source, 7, &fx.validator_hex(), None)
                .await
                .is_ok()
        );

        let other = "cd".repeat(32);
        let err = fetch_manifest_expecting(&source, 7, &fx.validator_hex(), Some(&other))
            .await
            .unwrap_err();
        let msg = format!("{err:#}");
        assert!(msg.contains("current.json declares"), "{msg}");
        assert!(msg.contains(&sha), "{msg}");
    }

    #[test]
    fn filter_has_no_false_negatives_and_bounded_false_positives() {
        let mut filter = HashFilter::new(100_000, 0.01);
        let inserted: Vec<[u8; 32]> = (0..100_000u32).map(|i| hash_for(1, i)).collect();
        for h in &inserted {
            filter.insert(h);
        }
        assert!(inserted.iter().all(|h| filter.contains(h)));
        let false_positives = (0..100_000u32)
            .map(|i| hash_for(2, i))
            .filter(|h| filter.contains(h))
            .count();
        // 1% target; allow 2x slack for the deterministic sample.
        assert!(
            false_positives < 2_000,
            "false positives: {false_positives}"
        );
        assert_eq!(filter.inserted(), 100_000);
    }

    #[test]
    fn filter_sizing_matches_documented_cost() {
        // ~9.6 bits per hash at 1%, 7 probes. A full-size miner's own
        // records: 1600 PGs × 180k records / 30 holders = 9.6M ≈ 11.5 MB.
        // Sizing is checked without allocating (the test must not cost
        // hundreds of MB); `new` and `bytes_for` share `dimensions`.
        let mb = HashFilter::bytes_for(9_600_000, 0.01) / (1024 * 1024);
        assert!((10..=12).contains(&mb), "{mb} MB");
        assert_eq!(HashFilter::dimensions(9_600_000, 0.01).1, 7);
        // The whole lists (every holder) would have cost ~345 MB.
        let mb = HashFilter::bytes_for(288_000_000, 0.01) / (1024 * 1024);
        assert!((325..=350).contains(&mb), "{mb} MB");
        // The manifest sizes give the per-holder bound before any fetch.
        let list_bytes = (LIST_HEADER_LEN + 180_000 * LIST_RECORD_LEN) as u64;
        assert_eq!(records_in_list(list_bytes), 180_000);
        assert_eq!(expected_my_records(list_bytes, 30, 1), 6_000);
        assert_eq!(expected_my_records(list_bytes, 30, 30), 180_000);
        assert_eq!(expected_my_records(list_bytes, 30, 31), 180_000);
        assert_eq!(expected_my_records(LIST_HEADER_LEN as u64, 30, 1), 0);
        // Degenerate input never allocates less than the floor.
        assert_eq!(HashFilter::new(0, 0.01).memory_bytes(), MIN_FILTER_BITS / 8);
        assert_eq!(HashFilter::bytes_for(0, 0.01), MIN_FILTER_BITS / 8);
    }

    #[tokio::test]
    async fn load_generation_from_fixture_dir() {
        let dir = tempfile::tempdir().unwrap();
        let key = deterministic_key(1);
        let fx = write_generation(dir.path(), &key, 7, &[10, 11, 12], 100);
        let source = DirListSource::new(dir.path());

        assert_eq!(fetch_current_generation(&source).await.unwrap(), 7);
        let manifest = fetch_manifest(&source, 7, &fx.validator_hex())
            .await
            .unwrap();

        // Full coverage.
        let loaded = load_generation(&source, &manifest, &[10, 12], MY_UID, 0.01, 2, 1 << 30, 0)
            .await
            .unwrap();
        assert!(loaded.coverage_complete());
        assert_eq!(loaded.listed_pgs, 2);
        assert_eq!(loaded.total_hashes, 200);
        assert!(loaded.may_be_obliged(&hash_for(10, 3)));
        assert!(loaded.may_be_obliged(&hash_for(12, 99)));
        // Unlisted PG's hashes are (almost surely) absent from the filter.
        let hits = (0..100)
            .filter(|i| loaded.may_be_obliged(&hash_for(11, *i)))
            .count();
        assert!(hits < 10, "{hits}");

        // Partial coverage: PG 99 is not in the generation.
        let partial = load_generation(&source, &manifest, &[10, 99], MY_UID, 0.01, 2, 1 << 30, 0)
            .await
            .unwrap();
        assert!(!partial.coverage_complete());
        assert_eq!(partial.missing_pgs, vec![99]);
        assert_eq!(partial.listed_pgs, 1);
    }

    #[test]
    fn manifest_created_at_accepts_rfc3339_and_seconds() {
        let mut m: Manifest = serde_json::from_value(serde_json::json!({
            "generation": 1, "created_at": CREATED_AT, "pg_count": 16384,
            "ec_k": 10, "ec_m": 20, "pgs": [], "objects": {}
        }))
        .unwrap();
        assert_eq!(m.created_at_secs(), Some(CREATED_AT_SECS));
        m.created_at = serde_json::json!(1_700_000_000u64);
        assert_eq!(m.created_at_secs(), Some(1_700_000_000));
        m.created_at = serde_json::json!("yesterday");
        assert_eq!(m.created_at_secs(), None);
        m.created_at = serde_json::Value::Null;
        assert_eq!(m.created_at_secs(), None);
    }

    /// The age bound is `scan_started_at` when published, `created_at`
    /// otherwise; a present but unparseable `scan_started_at` fails
    /// closed instead of falling back to the later stamp.
    #[test]
    fn manifest_snapshot_prefers_scan_started_at() {
        let mut m: Manifest = serde_json::from_value(serde_json::json!({
            "generation": 1, "created_at": CREATED_AT, "pg_count": 16384,
            "ec_k": 10, "ec_m": 20, "pgs": [], "objects": {}
        }))
        .unwrap();
        assert!(m.scan_started_at.is_null(), "absent on older writers");
        assert_eq!(m.snapshot_secs().unwrap(), CREATED_AT_SECS);
        m.scan_started_at = serde_json::json!(CREATED_AT_SECS - 4 * 86_400);
        assert_eq!(m.snapshot_secs().unwrap(), CREATED_AT_SECS - 4 * 86_400);
        m.scan_started_at = serde_json::json!("2026-09-07T00:00:00Z");
        assert_eq!(m.snapshot_secs().unwrap(), CREATED_AT_SECS - 4 * 86_400);
        m.scan_started_at = serde_json::json!("last tuesday");
        assert!(m.snapshot_secs().is_err(), "unparseable: fail closed");
        m.scan_started_at = serde_json::Value::Null;
        m.created_at = serde_json::Value::Null;
        assert!(m.snapshot_secs().is_err());
    }

    /// A signed manifest carrying `scan_started_at` verifies (the field is
    /// part of the canonical bytes) and the loaded generation exposes
    /// both stamps.
    #[tokio::test]
    async fn loaded_generation_carries_scan_start_and_creation() {
        let dir = tempfile::tempdir().unwrap();
        let key = deterministic_key(1);
        let stamps = Stamps {
            created_at: serde_json::json!(CREATED_AT),
            scan_started_at: Some(serde_json::json!(CREATED_AT_SECS - 3 * 86_400)),
        };
        let fx = write_generation_stamped(dir.path(), &key, 7, &[10], 5, &stamps);
        let source = DirListSource::new(dir.path());
        let manifest = fetch_manifest(&source, 7, &fx.validator_hex())
            .await
            .unwrap();
        let loaded = load_generation(&source, &manifest, &[10], MY_UID, 0.01, 1, 1 << 30, 0)
            .await
            .unwrap();
        assert_eq!(loaded.created_at_secs, CREATED_AT_SECS);
        assert_eq!(loaded.snapshot_secs, CREATED_AT_SECS - 3 * 86_400);
        // Without the field the bound is the creation time.
        let fx = write_generation(dir.path(), &key, 8, &[10], 5);
        let manifest = fetch_manifest(&source, 8, &fx.validator_hex())
            .await
            .unwrap();
        let loaded = load_generation(&source, &manifest, &[10], MY_UID, 0.01, 1, 1 << 30, 0)
            .await
            .unwrap();
        assert_eq!(loaded.snapshot_secs, CREATED_AT_SECS);
    }

    #[tokio::test]
    async fn load_generation_enforces_memory_caps() {
        let dir = tempfile::tempdir().unwrap();
        let key = deterministic_key(1);
        let fx = write_generation(dir.path(), &key, 7, &[10, 11], 1000);
        let source = DirListSource::new(dir.path());
        let manifest = fetch_manifest(&source, 7, &fx.validator_hex())
            .await
            .unwrap();
        // 2000 records, 67 expected mine, floored at MIN_FILTER_BITS (8 KiB):
        // a 1 KiB cap refuses before any fetch.
        let err = load_generation(&source, &manifest, &[10, 11], MY_UID, 0.01, 2, 1024, 0)
            .await
            .unwrap_err();
        assert!(err.to_string().contains("byte cap"), "{err}");
        assert!(
            load_generation(&source, &manifest, &[10, 11], MY_UID, 0.01, 2, 1 << 20, 0)
                .await
                .is_ok()
        );
        // A manifest entry above MAX_LIST_BYTES is refused up front.
        let mut oversized = manifest.clone();
        oversized
            .objects
            .get_mut(&Manifest::list_path(10))
            .unwrap()
            .size = MAX_LIST_BYTES + 1;
        let err = load_generation(&source, &oversized, &[10], MY_UID, 0.01, 1, 1 << 30, 0)
            .await
            .unwrap_err();
        assert!(err.to_string().contains("byte limit"), "{err}");
        // A generation without a usable created_at is refused.
        let mut undated = manifest.clone();
        undated.created_at = serde_json::Value::Null;
        assert!(
            load_generation(&source, &undated, &[10], MY_UID, 0.01, 1, 1 << 30, 0)
                .await
                .is_err()
        );
    }

    #[tokio::test]
    async fn dir_source_refuses_oversized_file_before_reading() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join("big.bin"), vec![0u8; 4096]).unwrap();
        let source = DirListSource::new(dir.path());
        assert!(source.fetch("big.bin", 4095).await.is_err());
        assert_eq!(source.fetch("big.bin", 4096).await.unwrap().len(), 4096);
    }

    #[tokio::test]
    async fn load_generation_fails_on_corrupted_list() {
        let dir = tempfile::tempdir().unwrap();
        let key = deterministic_key(1);
        let fx = write_generation(dir.path(), &key, 7, &[10, 11], 20);
        // Flip a byte inside the list of PG 11: sha256 must fail the load.
        let path = dir.path().join("gen/7/pg/00011.list");
        let mut body = std::fs::read(&path).unwrap();
        body[LIST_HEADER_LEN + 5] ^= 0xff;
        std::fs::write(&path, &body).unwrap();

        let source = DirListSource::new(dir.path());
        let manifest = fetch_manifest(&source, 7, &fx.validator_hex())
            .await
            .unwrap();
        let err = load_generation(&source, &manifest, &[10, 11], MY_UID, 0.01, 1, 1 << 30, 0)
            .await
            .unwrap_err();
        assert!(format!("{err:#}").contains("sha256 mismatch"), "{err:#}");
    }

    /// Content addressing: a deleted file of one PG shares shard hashes
    /// with a live file of another PG (the PG is a function of the file
    /// hash). Its tombstone must not reach the pass while ANY record of an
    /// enforced list — this miner's or another holder's — names the hash,
    /// with or without the others filter. Once the other file is deleted
    /// too (next generation, its record gone) the hash is tombstoned.
    #[tokio::test]
    async fn tombstone_withdrawn_while_a_live_record_of_any_owned_pg_names_it() {
        let key = deterministic_key(1);
        let held_by_other = hash_for(10, 200);
        let held_by_me = hash_for(10, 201);
        let unreferenced = hash_for(10, 202);
        let pg11_with_refs = || {
            let mut records = sorted_records(11, 5);
            records.push(Record {
                blob_hash: held_by_other,
                shard_length: 300,
                holder_uid: OTHER_UID,
            });
            records.push(Record {
                blob_hash: held_by_me,
                shard_length: 301,
                holder_uid: MY_UID,
            });
            records.sort_unstable_by(Record::cmp_key);
            records
        };
        let tombstones_of_pg10 = |pg: u32| match pg {
            10 => vec![held_by_other, held_by_me, unreferenced],
            _ => vec![],
        };

        // Generation 7: file A (PG 10) deleted, file B (PG 11) live.
        let dir = tempfile::tempdir().unwrap();
        let fx = write_generation_with_tombstones(
            dir.path(),
            &key,
            7,
            &[10, 11],
            &Stamps::default(),
            &|pg| {
                if pg == 11 {
                    pg11_with_refs()
                } else {
                    sorted_records(pg, 5)
                }
            },
            Some(&tombstones_of_pg10),
        );
        let source = DirListSource::new(dir.path());
        let manifest = fetch_manifest(&source, 7, &fx.validator_hex())
            .await
            .unwrap();
        for others_cap in [1u64 << 28, 0] {
            let loaded = load_generation(
                &source,
                &manifest,
                &[10, 11],
                MY_UID,
                0.01,
                2,
                1 << 30,
                others_cap,
            )
            .await
            .unwrap();
            assert_eq!(loaded.tombstone_pgs, 2);
            assert_eq!(
                loaded.tombstones_retained_live_ref, 2,
                "others_cap={others_cap}"
            );
            assert_eq!(loaded.tombstones, vec![unreferenced]);
            assert!(
                !loaded.is_tombstoned(&held_by_other),
                "another holder's record"
            );
            assert!(!loaded.is_tombstoned(&held_by_me), "my own record");
            assert!(loaded.is_tombstoned(&unreferenced));
            // The live record is still enforced as a list entry.
            assert!(loaded.may_be_obliged(&held_by_me));
            if others_cap > 0 {
                assert!(loaded.may_be_held_by_other(&held_by_other));
            }
        }

        // A record of a PG this miner does NOT own does not withdraw the
        // tombstone: that PG's lists are not enforced here.
        let loaded = load_generation(&source, &manifest, &[10], MY_UID, 0.01, 2, 1 << 30, 0)
            .await
            .unwrap();
        assert_eq!(loaded.tombstones_retained_live_ref, 0);
        assert_eq!(loaded.tombstones.len(), 3);

        // Generation 8: file B deleted too, its records gone from PG 11.
        let dir = tempfile::tempdir().unwrap();
        let fx = write_generation_with_tombstones(
            dir.path(),
            &key,
            8,
            &[10, 11],
            &Stamps::default(),
            &|pg| sorted_records(pg, 5),
            Some(&|pg| match pg {
                10 => vec![held_by_other, held_by_me, unreferenced],
                11 => vec![held_by_other, held_by_me],
                _ => vec![],
            }),
        );
        let source = DirListSource::new(dir.path());
        let manifest = fetch_manifest(&source, 8, &fx.validator_hex())
            .await
            .unwrap();
        let loaded = load_generation(&source, &manifest, &[10, 11], MY_UID, 0.01, 2, 1 << 30, 0)
            .await
            .unwrap();
        assert_eq!(loaded.tombstones_retained_live_ref, 0);
        assert_eq!(loaded.tombstones.len(), 3);
        assert!(loaded.is_tombstoned(&held_by_other));
        assert!(loaded.is_tombstoned(&held_by_me));
    }

    /// Tombstones of the owned PGs are fetched, verified and merged into
    /// one exact sorted set; a generation without any keeps none; the
    /// same hash tombstoned in two PGs is one.
    #[tokio::test]
    async fn load_generation_merges_tombstones_of_owned_pgs() {
        let dir = tempfile::tempdir().unwrap();
        let key = deterministic_key(1);
        let shared = hash_for(99, 0);
        let fx = write_generation_with_tombstones(
            dir.path(),
            &key,
            7,
            &[10, 11, 12],
            &Stamps::default(),
            &|pg| sorted_records(pg, 5),
            Some(&|pg| match pg {
                10 => vec![hash_for(10, 100), shared, hash_for(10, 101)],
                11 => vec![shared],
                _ => vec![],
            }),
        );
        let source = DirListSource::new(dir.path());
        let manifest = fetch_manifest(&source, 7, &fx.validator_hex())
            .await
            .unwrap();
        assert_eq!(manifest.objects.len(), 6);
        assert_eq!(manifest.missing_pgs(&[10, 11, 12]), Vec::<u32>::new());
        let loaded = load_generation(&source, &manifest, &[10, 11], MY_UID, 0.01, 2, 1 << 30, 0)
            .await
            .unwrap();
        assert_eq!(loaded.listed_pgs, 2);
        assert_eq!(loaded.tombstone_pgs, 2);
        assert_eq!(loaded.tombstones.len(), 3, "shared hash deduplicated");
        assert!(loaded.tombstones.windows(2).all(|w| w[0] < w[1]));
        assert!(loaded.is_tombstoned(&shared));
        assert!(loaded.is_tombstoned(&hash_for(10, 100)));
        assert!(
            !loaded.is_tombstoned(&hash_for(10, 0)),
            "listed, not tombstoned"
        );
        assert!(!loaded.is_tombstoned(&hash_for(12, 5)), "PG 12 not owned");

        // Pre-tombstone generation: nothing, and the pass falls back to gates.
        let dir = tempfile::tempdir().unwrap();
        let fx = write_generation(dir.path(), &key, 8, &[10, 11], 5);
        let source = DirListSource::new(dir.path());
        let manifest = fetch_manifest(&source, 8, &fx.validator_hex())
            .await
            .unwrap();
        let loaded = load_generation(&source, &manifest, &[10, 11], MY_UID, 0.01, 2, 1 << 30, 0)
            .await
            .unwrap();
        assert_eq!((loaded.tombstone_pgs, loaded.tombstones.len()), (0, 0));
    }

    /// One corrupted `.deleted` drops every tombstone of the load (never
    /// a partial view) without failing the lists; the digest identity
    /// changes with the tombstones so a rewritten `.deleted` reloads.
    #[tokio::test]
    async fn corrupted_tombstones_drop_the_class_but_keep_the_lists() {
        let dir = tempfile::tempdir().unwrap();
        let key = deterministic_key(1);
        let fx = write_generation_with_tombstones(
            dir.path(),
            &key,
            7,
            &[10, 11],
            &Stamps::default(),
            &|pg| sorted_records(pg, 5),
            Some(&|pg| vec![hash_for(pg, 100)]),
        );
        let source = DirListSource::new(dir.path());
        let manifest = fetch_manifest(&source, 7, &fx.validator_hex())
            .await
            .unwrap();
        let intact = load_generation(&source, &manifest, &[10, 11], MY_UID, 0.01, 2, 1 << 30, 0)
            .await
            .unwrap();
        assert_eq!(intact.tombstones.len(), 2);

        let path = dir.path().join("gen/7/pg/00011.deleted");
        let mut body = std::fs::read(&path).unwrap();
        body[TOMBSTONE_HEADER_LEN + 3] ^= 0xff;
        std::fs::write(&path, &body).unwrap();
        let loaded = load_generation(&source, &manifest, &[10, 11], MY_UID, 0.01, 2, 1 << 30, 0)
            .await
            .unwrap();
        assert_eq!(loaded.listed_pgs, 2);
        assert_eq!(loaded.total_hashes, 10);
        assert_eq!((loaded.tombstone_pgs, loaded.tombstones.len()), (0, 0));
        assert!(
            !loaded.is_tombstoned(&hash_for(10, 100)),
            "PG 10 was fine but the class is all-or-nothing"
        );

        // Digest: with vs without tombstone objects differ; a changed
        // tombstone digest differs.
        let mut stripped = manifest.clone();
        stripped.objects.retain(|k, _| k.ends_with(".list"));
        assert_ne!(
            lists_digest(&manifest, &[10, 11]),
            lists_digest(&stripped, &[10, 11])
        );
        let mut changed = manifest.clone();
        changed.objects.get_mut("pg/00010.deleted").unwrap().sha256 = "00".repeat(32);
        assert_ne!(
            lists_digest(&manifest, &[10, 11]),
            lists_digest(&changed, &[10, 11])
        );
    }

    #[test]
    fn tombstone_body_rejects_wrong_identity_and_apgl_bytes() {
        let hashes = [hash_for(1, 1), hash_for(1, 2)];
        let body = encode_tombstones(3, 7, 10, 20, &hashes);
        let digest = hex::encode(Sha256::digest(&body));
        let ok = decode_tombstones(&body, expect(3, &digest)).unwrap();
        assert_eq!(ok.len(), 2);
        assert!(decode_tombstones(&body, expect(4, &digest)).is_err(), "pg");
        let mut other_gen = expect(3, &digest);
        other_gen.generation = 8;
        assert!(decode_tombstones(&body, other_gen).is_err(), "generation");
        let mut other_ec = expect(3, &digest);
        other_ec.ec_m = 21;
        assert!(decode_tombstones(&body, other_ec).is_err(), "ec");
        assert!(
            decode_tombstones(&body, expect(3, &"00".repeat(32))).is_err(),
            "sha"
        );
        // A list body under a tombstone entry: magic mismatch.
        let (list, list_digest) = sample_list(3);
        let err = decode_tombstones(&list, expect(3, &list_digest)).unwrap_err();
        assert!(format!("{err:#}").contains("magic"), "{err:#}");
    }

    /// The digest identifies "these lists for these PGs": stable across
    /// PG order and duplicates, different for another generation, another
    /// owned set, or a list whose declared sha256 changed; a load `covers`
    /// exactly the manifest and owned set it was made from.
    #[tokio::test]
    async fn lists_digest_identifies_the_owned_lists() {
        let dir = tempfile::tempdir().unwrap();
        let key = deterministic_key(1);
        let fx = write_generation(dir.path(), &key, 7, &[10, 11, 12], 5);
        let source = DirListSource::new(dir.path());
        let manifest = fetch_manifest(&source, 7, &fx.validator_hex())
            .await
            .unwrap();
        let d = lists_digest(&manifest, &[10, 11]);
        assert_eq!(d, lists_digest(&manifest, &[11, 10, 10]), "order, dups");
        assert_ne!(d, lists_digest(&manifest, &[10, 11, 12]), "owned set");
        assert_ne!(d, lists_digest(&manifest, &[10, 11, 99]), "uncovered PG");
        let mut other_gen = manifest.clone();
        other_gen.generation = 8;
        assert_ne!(d, lists_digest(&other_gen, &[10, 11]), "generation");
        let mut other_list = manifest.clone();
        other_list
            .objects
            .get_mut(&Manifest::list_path(11))
            .unwrap()
            .sha256 = hex::encode([7u8; 32]);
        assert_ne!(d, lists_digest(&other_list, &[10, 11]), "list content");

        let loaded = load_generation(&source, &manifest, &[10, 11], MY_UID, 0.01, 1, 1 << 30, 0)
            .await
            .unwrap();
        assert_eq!(loaded.lists_digest, d);
        assert!(loaded.covers(&manifest, &[11, 10]));
        assert!(!loaded.covers(&manifest, &[10, 11, 12]));
        assert!(!loaded.covers(&other_list, &[10, 11]));
    }

    #[tokio::test]
    async fn fetch_manifest_rejects_generation_mismatch_and_wrong_key() {
        let dir = tempfile::tempdir().unwrap();
        let key = deterministic_key(1);
        let fx = write_generation(dir.path(), &key, 7, &[1], 3);
        // Place generation 7's manifest under gen/8.
        std::fs::create_dir_all(dir.path().join("gen/8")).unwrap();
        std::fs::copy(
            dir.path().join("gen/7/manifest.json"),
            dir.path().join("gen/8/manifest.json"),
        )
        .unwrap();
        let source = DirListSource::new(dir.path());
        assert!(
            fetch_manifest(&source, 8, &fx.validator_hex())
                .await
                .is_err()
        );
        let other = hex::encode(deterministic_key(9).verifying_key().to_bytes());
        assert!(fetch_manifest(&source, 7, &other).await.is_err());
    }
}

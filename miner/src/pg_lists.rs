//! Reader for the published per-PG obligation lists.
//!
//! The validator publishes, on a public HTTP bucket, the flat list of
//! blob hashes each placement group is obliged to hold. This module
//! fetches and verifies what this miner needs of them: its holder set and
//! the live filter of the generation ([`crate::pg_sets`]), the holder
//! index, the tombstones of the PGs it protects and the delta chain; the
//! purge loop consults the result (see [`crate::purge`]).
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
//!   version 4, one 40-byte record per **shard** of every file in the PG
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
//! - `delta/<generation>/<seq>/bundle/<b 3 digits>.added` -> range
//!   bundle `b = pg_id / DELTA_BUNDLE_PGS` (256 PGs, 64 bundles for 16384
//!   PGs): the concatenation, ascending by PG, of one `APGL` v4 body per
//!   PG of the range that gained records, each with the same header as
//!   the base list (pg_id, generation, ec). The delta manifest (`format`
//!   2) declares every bundle's sha256 and size and every section's PG,
//!   offset, size and sha256. A PG in the delta's `pgs` with no section
//!   gained nothing. A reader fetches only the bundles holding an
//!   enforced PG with additions (one GET per bundle, not per PG) and folds
//!   only the enforced sections. There is no delta `.deleted`: a deletion
//!   waits for the next base.
//! - Format 1 (one `pg/<N>.added` object per PG, an `objects` map) is not
//!   read: a delta manifest without `format` 2 breaks the chain, and a
//!   reader that predates format 2 fails on the missing `objects` map the
//!   same way (chain broken, coverage incomplete, no purge).
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
//! with [`LoadedGeneration::extend`] (only the new deltas' bundles are
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
//! carries the uid of the miner holding that shard for the read path
//! (`holder_uid`, resolved by the writer with the write path's own
//! placement function on the map of the file's `placement_epoch`: the
//! map the gateway reads the file through). This reader does not
//! compute placement at all: a record is this miner's iff
//! `record.holder_uid == my uid` ([`common::obligation_list::Record::is_held_by`]).
//!
//! ## Holder index: PGs this miner holds without owning them
//!
//! Because holders follow the placement epoch, this miner is named in the
//! lists of PGs it no longer owns under the current map (a shard placed on
//! it at an older epoch, not yet moved by the validator). Its current
//! ownership alone would never load those lists, and their blobs would
//! look like orphans. A base generation therefore publishes, per holder,
//! `gen/<g>/holders/<uid 10 digits>.pgs` (declared in the manifest's
//! `holders`, sha256 and size; codec in `common::obligation_list`): the
//! PGs whose list names that uid. [`load_generation`] fetches this
//! miner's index and loads the union of the asked PGs and the indexed
//! ones ([`LoadedGeneration::held_pgs`]); the purge requires both to be
//! covered. A manifest without `holders` was written by a writer that
//! placed holders on the current map only: it loads (the backfill may
//! read it) but it never opens the purge gate ([`LoadedGeneration::held_pgs`]
//! is `None`). Each delta declares its own holder index (`holders`, the
//! PGs in which it adds records naming each uid, objects under the delta's
//! directory): before folding a delta the reader loads the indexed PGs it
//! does not hold yet ([`LoadedGeneration::add_pgs`]) and adds them to
//! `held_pgs`; a delta without one, chained on a base with one, breaks the
//! chain (coverage incomplete).
//! A blob listed for an owned PG but placed on another holder of that PG is
//! NOT this miner's obligation (purgeable, not backfilled). Version 2 had
//! the reader recompute the holder from `(stripe_idx, shard_idx,
//! placement_version)` and the current map; reader and writer used the
//! same formula on different inputs (raw vs draining-filtered map) and
//! attributed shards to the wrong miner. There is no "unresolved" state
//! any more: every record names a holder.
//!
//! ## Membership: holder sets and the live filter
//!
//! A base over the whole partition declares, next to `holders`, per uid
//! the sorted 64-bit keys (`blob_hash[0..8]`) of every record naming it
//! (`holder_sets`, `APGS` parts) and a 256-shard Bloom filter over the
//! hash of every record of every list plus the shards of the files the
//! base withholds from the lists (`live_filter`, `APGF` shards). The miner
//! fetches only its own parts and the 256 shards, verifies them against
//! the signed manifest, caches them under `<data_dir>/pg-lists-cache/`
//! and maps them ([`crate::pg_sets::GenerationSets`]); no per-PG base list
//! is downloaded. "Mine" is a key hit in the holder set or a key of a
//! delta record naming this miner; "someone's" (the moved class) is a live
//! filter hit or a key of a delta record naming another holder in an
//! enforced PG. Both are "may" answers (64-bit prefix, Bloom false
//! positive): a hit means KEEP, so neither can make the purge delete a
//! blob it should keep. A base without the sets loads (the backfill and
//! the census may read it) but never covers anything: it never drives a
//! deletion.

use std::collections::{BTreeMap, BTreeSet};
use std::path::{Path, PathBuf};
use std::sync::Arc;

use anyhow::{Context, Result, anyhow, bail, ensure};
use bytes::Bytes;
use serde::Deserialize;
use sha2::{Digest, Sha256};
use tracing::{debug, info, warn};

pub use crate::pg_sets::{GenerationSets, HolderSetEntry, LiveFilterEntry};
use common::hash_set_files::blob_key;
pub use common::obligation_list::{
    DELTA_BUNDLE_PGS, DELTA_FORMAT, DeltaBundle, DeltaSection, HEADER_LEN as LIST_HEADER_LEN,
    Header as ListHeader, MAGIC as LIST_MAGIC, RECORD_LEN as LIST_RECORD_LEN, Record,
    TOMBSTONE_MAGIC, TOMBSTONE_RECORD_LEN, VERSION as LIST_VERSION,
};
/// Tombstone bodies share the list header layout (magic aside).
pub const TOMBSTONE_HEADER_LEN: usize = LIST_HEADER_LEN;

/// Upper bound on a `current.json` / `manifest.json` body.
const MAX_JSON_BYTES: u64 = 64 << 20;
/// Upper bound on a single list body or delta bundle, whatever the
/// manifest claims (256 MiB = 6.7M records; a PG holds ~180k). The writer
/// refuses to produce a delta bundle above it.
pub const MAX_LIST_BYTES: u64 = common::obligation_list::MAX_OBJECT_BYTES;

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
    /// Holder index: `"holders/<uid 10 digits>.pgs" -> {sha256, size}`,
    /// one object per uid a record of the base names, listing the PGs
    /// whose list names it. `None` on a generation written before holders
    /// followed the placement epoch: never enforced (see the module docs).
    #[serde(default)]
    pub holders: Option<BTreeMap<String, ObjectEntry>>,
    /// Holder sets: per uid, the parts of the sorted keys of every record
    /// naming it (`holders/<uid 10 digits>/<part 3 digits>.hashes`). Present
    /// with `live_filter` on a base over the whole partition that carries
    /// `holders`; `None` otherwise (such a base is never enforced).
    #[serde(default)]
    pub holder_sets: Option<BTreeMap<u32, Vec<HolderSetEntry>>>,
    /// Live filter: 256 Bloom shards over every listed hash and every
    /// withheld one (`live/<shard 3 digits>.bloom`).
    #[serde(default)]
    pub live_filter: Option<LiveFilterEntry>,
    #[serde(default)]
    pub signature: Option<String>,
    /// Hex node id of the key that verified this manifest's signature
    /// (set by [`parse_verified_manifest`], never parsed). Every delta of
    /// the chain must be signed by the same key.
    #[serde(skip)]
    pub verified_by: String,
    /// `base_cut` as the signed manifest declared it (set by
    /// [`parse_verified_manifest`], before any chain is adopted from an
    /// unsigned `current.json`): the only base cut the freshness of a
    /// view may be measured from.
    #[serde(skip)]
    pub signed_base_cut: Option<u64>,
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
/// signing rule as the base manifest. Parsed strictly (unknown keys
/// refused) and its bundle layout checked ([`Self::check_layout`]) before
/// any bundle is fetched.
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
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
    /// PGs the delta scan covered. A covered PG with no section gained
    /// nothing in the window; an owned PG absent from here breaks the
    /// chain (the reader cannot tell "nothing new" from "not scanned").
    pub pgs: Vec<u32>,
    /// Layout version; only [`DELTA_FORMAT`] (2) is read.
    pub format: u64,
    /// `"bundle/000.added" -> {sha256, size, pgs: [{pg, offset, size,
    /// sha256}]}`: each section an `APGL` v4 body with the same header as
    /// the base list (pg_id, generation, ec).
    pub bundles: BTreeMap<String, DeltaBundle>,
    /// This delta's holder index (`"holders/<uid>.pgs" -> {sha256, size}`,
    /// relative to the delta's directory): per uid, the PGs in which the
    /// delta adds records naming it. Required on a delta chained on a base
    /// that declares a holder index (see [`apply_deltas`]).
    #[serde(default)]
    pub holders: Option<BTreeMap<String, ObjectEntry>>,
    /// List format version of the chain; must be
    /// [`common::obligation_list::VERSION`]. A delta without it predates
    /// version 4 and is refused (chain broken).
    #[serde(default)]
    pub list_version: Option<u8>,
    /// Shard blob hashes of the covered files the window withheld from the
    /// lists (`withheld.hashes` in the delta's directory; declared only
    /// when there is at least one): what the base's live filter carries
    /// for the base. Folded as live under another holder in every PG and
    /// withdrawn from the tombstones ([`apply_delta`]).
    #[serde(default)]
    pub withheld: Option<common::obligation_list::DeltaWithheld>,
    #[serde(default)]
    pub signature: Option<String>,
    /// sha256 of the fetched body (what the base manifest's ref names).
    #[serde(skip)]
    pub body_sha256: [u8; 32],
}

impl DeltaManifest {
    /// Relative path of bundle `index` inside the delta.
    pub fn bundle_path(index: u32) -> String {
        common::obligation_list::delta_bundle_path(index)
    }

    /// Refuse any layout but [`DELTA_FORMAT`] and any bundle declaration
    /// that is not canonical: paths in range, sections strictly ascending,
    /// each PG in its bundle's range and covered, contiguous from offset 0
    /// and covering exactly the bundle, every size framed and bounded by
    /// [`MAX_LIST_BYTES`] ([`common::obligation_list::check_delta_bundles`]).
    pub fn check_layout(&self) -> Result<()> {
        if self.list_version != Some(common::obligation_list::VERSION) {
            bail!(
                "delta manifest list_version {:?} is not {} (a chain written before holders followed the placement epoch)",
                self.list_version,
                common::obligation_list::VERSION
            );
        }
        if self.format != DELTA_FORMAT {
            bail!(
                "delta manifest format {} is not supported (this reader reads format {DELTA_FORMAT})",
                self.format
            );
        }
        if !self.pgs.windows(2).all(|pair| pair[0] < pair[1]) {
            bail!("delta manifest pgs are not strictly ascending");
        }
        if let Some(withheld) = &self.withheld {
            common::obligation_list::check_delta_withheld(withheld)
                .context("delta manifest withheld hashes")?;
        }
        common::obligation_list::check_delta_bundles(&self.bundles, &self.pgs, self.pg_count)
            .context("delta manifest bundle layout")
    }

    /// The bundles to fetch for `wanted` PGs: each bundle holding at least
    /// one section of a wanted PG, with only those sections. A bundle is
    /// fetched once however many wanted PGs it carries.
    fn fetch_jobs(&self, wanted: &BTreeSet<u32>) -> Vec<FetchJob> {
        let dir = Self::dir_path(self.generation, self.seq);
        self.bundles
            .iter()
            .filter_map(|(relative, bundle)| {
                let sections: Vec<ListJob> = bundle
                    .pgs
                    .iter()
                    .filter(|section| wanted.contains(&section.pg))
                    .map(|section| ListJob {
                        pg_id: section.pg,
                        offset: section.offset,
                        size: section.size,
                        sha256: section.sha256.clone(),
                    })
                    .collect();
                (!sections.is_empty()).then(|| FetchJob {
                    path: format!("{dir}/{relative}"),
                    size: bundle.size,
                    sha256: Some(bundle.sha256.clone()),
                    sections,
                })
            })
            .collect()
    }

    /// Bucket path of the delta's directory (`delta/<gen>/<seq>`).
    pub fn dir_path(generation: u64, seq: u64) -> String {
        format!("delta/{generation}/{seq}")
    }

    /// Bucket path of the delta's manifest.
    pub fn manifest_path(generation: u64, seq: u64) -> String {
        format!("{}/manifest.json", Self::dir_path(generation, seq))
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
    manifest.signed_base_cut = manifest.base_cut_secs();
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
    delta.check_layout()?;
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

/// Attempts per object before a transient failure is surfaced: a single
/// truncated or reset transfer must not fail a whole generation load of
/// thousands of lists.
const FETCH_ATTEMPTS: u32 = 4;

/// Why one HTTP attempt failed: transient failures are retried, the rest
/// are final.
#[derive(Debug)]
enum FetchFailure {
    Transient(anyhow::Error),
    Final(anyhow::Error),
}

/// Run `attempt` up to `attempts` times, sleeping `backoff(n)` between
/// tries, retrying only transient failures.
async fn with_retries<F, Fut, B>(attempts: u32, backoff: B, mut attempt: F) -> Result<Bytes>
where
    F: FnMut() -> Fut,
    Fut: std::future::Future<Output = std::result::Result<Bytes, FetchFailure>>,
    B: Fn(u32) -> std::time::Duration,
{
    let mut last = None;
    for n in 0..attempts.max(1) {
        if n > 0 {
            tokio::time::sleep(backoff(n)).await;
        }
        match attempt().await {
            Ok(body) => return Ok(body),
            Err(FetchFailure::Final(e)) => return Err(e),
            Err(FetchFailure::Transient(e)) => last = Some(e),
        }
    }
    Err(last.unwrap_or_else(|| anyhow!("fetch: no attempt made")))
}

/// Fetch an object whose size the signed manifest declares, re-fetching
/// when the body does not have that size: a transfer ended early without a
/// transport error or a `Content-Length` header is still a truncated
/// object. The source's own retries cover transport failures; the size
/// and digest checks of the callers stay the final word.
pub async fn fetch_sized(source: &dyn ListSource, rel_path: &str, expected: u64) -> Result<Bytes> {
    let mut last_len = 0usize;
    for n in 0..FETCH_ATTEMPTS {
        if n > 0 {
            tokio::time::sleep(std::time::Duration::from_secs(1u64 << (n - 1).min(4))).await;
        }
        let bytes = source.fetch(rel_path, expected).await?;
        if bytes.len() as u64 == expected {
            return Ok(bytes);
        }
        last_len = bytes.len();
    }
    bail!(
        "{rel_path}: manifest size {expected} but body is {last_len} bytes after {FETCH_ATTEMPTS} attempts"
    )
}

impl HttpListSource {
    async fn fetch_once(
        &self,
        url: &str,
        max_len: u64,
    ) -> std::result::Result<Bytes, FetchFailure> {
        let response = self
            .client
            .get(url)
            .send()
            .await
            .with_context(|| format!("GET {url}"))
            .map_err(FetchFailure::Transient)?;
        let status = response.status();
        if !status.is_success() {
            let e = anyhow!("GET {url}: HTTP {status}");
            return Err(if status.is_server_error() || status.as_u16() == 429 {
                FetchFailure::Transient(e)
            } else {
                FetchFailure::Final(e)
            });
        }
        let declared = response.content_length();
        if let Some(len) = declared
            && len > max_len
        {
            return Err(FetchFailure::Final(anyhow!(
                "GET {url}: body {len} bytes exceeds limit {max_len}"
            )));
        }
        // Stream so an unbounded body (no Content-Length) cannot exhaust RAM.
        use futures::StreamExt;
        let mut body = Vec::with_capacity(declared.unwrap_or(0).min(max_len) as usize);
        let mut stream = response.bytes_stream();
        while let Some(chunk) = stream.next().await {
            let chunk = chunk
                .with_context(|| format!("GET {url}: body read"))
                .map_err(FetchFailure::Transient)?;
            if body.len() as u64 + chunk.len() as u64 > max_len {
                return Err(FetchFailure::Final(anyhow!(
                    "GET {url}: body exceeds limit {max_len}"
                )));
            }
            body.extend_from_slice(&chunk);
        }
        // A transfer cut short without a transport error is still a
        // truncated body: never hand it to the caller as the object.
        if let Some(len) = declared
            && body.len() as u64 != len
        {
            return Err(FetchFailure::Transient(anyhow!(
                "GET {url}: truncated body, {} of {len} bytes",
                body.len()
            )));
        }
        Ok(Bytes::from(body))
    }
}

#[async_trait::async_trait]
impl ListSource for HttpListSource {
    async fn fetch(&self, rel_path: &str, max_len: u64) -> Result<Bytes> {
        let url = format!("{}/{}", self.base_url, rel_path);
        with_retries(
            FETCH_ATTEMPTS,
            |n| std::time::Duration::from_secs(1u64 << (n - 1).min(4)),
            || self.fetch_once(&url, max_len),
        )
        .await
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
#[derive(Debug, Clone)]
pub struct LoadedGeneration {
    pub generation: u64,
    /// Finalization time (Unix seconds): how old the publication is.
    pub created_at_secs: u64,
    /// Snapshot bound (Unix seconds, `Manifest::snapshot_secs`): a blob
    /// stored after it may be missing from these lists whatever its age,
    /// so the age rule measures from the earlier of now and this.
    pub snapshot_secs: u64,
    /// Newest signed cut folded into this view (Unix seconds): the `until`
    /// of the last applied delta (from its verified delta manifest), else
    /// the base manifest's own signed `base_cut`, else its snapshot bound.
    /// Never taken from `current.json`. How far it lags now is how stale
    /// the view is (the purge refuses a view older than
    /// `PURGE_VIEW_MAX_LAG_SECS`).
    pub view_cut_secs: u64,
    pub ec_k: u8,
    pub ec_m: u8,
    /// PGs loaded: those the load was asked for (this miner's ownership
    /// at load time) plus [`Self::held_pgs`].
    pub owned_pgs: Vec<u32>,
    /// PGs whose base list names this miner as a holder, from the
    /// generation's holder index (sorted). `None` when the manifest
    /// declares no holder index: such a generation never decides a
    /// deletion. Every PG here is in `owned_pgs`.
    pub held_pgs: Option<Vec<u32>>,
    /// Owned PGs the manifest does not cover. Non-empty = coverage
    /// incomplete = the purge must not run.
    pub missing_pgs: Vec<u32>,
    /// Owned PGs the manifest covers (their tombstones and delta sections
    /// are part of the view).
    pub listed_pgs: usize,
    /// This miner's holder set and the live filter of the generation,
    /// mapped from the local cache. `None` when the base declares none (or
    /// declares them over a subset of the partition, or without this
    /// miner's uid): such a load never
    /// covers anything and every hash reads as "may be obliged".
    pub sets: Option<Arc<GenerationSets>>,
    /// Keys (`blob_key`) of the delta records naming this miner in the
    /// enforced PGs: sorted, unique.
    pub delta_mine: Vec<u64>,
    /// Keys of the delta records naming another holder in the enforced
    /// PGs (the moved class for what the base's live filter predates):
    /// sorted, unique.
    pub delta_others: Vec<u64>,
    /// Keys in this miner's holder set plus the delta records naming it.
    pub total_hashes: u64,
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
    /// Highest delta `seq` ever announced for this generation (by a
    /// verified base manifest's chain or by `current.json`). Monotonic
    /// within a generation: a later manifest or pointer declaring fewer
    /// deltas is a stale or replayed publication and never makes the view
    /// whole again; while `delta_seq` is below it the chain stays broken.
    pub announced_delta_seq: u64,
    /// Records in the applied deltas, all holders.
    pub delta_records: u64,
    /// Delta records folded into the filter (this miner's).
    pub delta_hashes: u64,
    /// [`lists_digest_through`] of the base alone: what `extend` compares
    /// a re-fetched manifest against before trusting its new deltas.
    base_digest: [u8; 32],
}

impl LoadedGeneration {
    /// The PGs a deletion decided on this load requires covered:
    /// `protected` (this miner's ownership window) plus the PGs the holder
    /// index names it in. Sorted, unique.
    pub fn required_pgs(&self, protected: &[u32]) -> Vec<u32> {
        let mut required: Vec<u32> = protected
            .iter()
            .chain(self.held_pgs.iter().flatten())
            .copied()
            .collect();
        required.sort_unstable();
        required.dedup();
        required
    }

    /// Whether the writer saw `hash`'s file deleted in this generation's
    /// window (exact membership). A hash the lists still oblige wins over
    /// its tombstone; the caller checks `may_be_obliged` first.
    pub fn is_tombstoned(&self, hash: &[u8; 32]) -> bool {
        self.tombstones.binary_search(hash).is_ok()
    }

    /// Record that deltas up to `seq` are announced for this generation
    /// (a pointer or manifest said so). Raises the monotonic
    /// [`Self::announced_delta_seq`] and, while fewer are folded, marks
    /// the chain broken (coverage incomplete). Returns whether the view
    /// is behind what was announced.
    pub fn note_announced(&mut self, seq: u64) -> bool {
        self.announced_delta_seq = self.announced_delta_seq.max(seq);
        let behind = self.delta_seq < self.announced_delta_seq;
        if behind && self.chain_broken_at.is_none() {
            self.chain_broken_at = Some(self.delta_seq + 1);
        }
        behind
    }

    /// Every owned PG listed by the base, the holder set and live filter
    /// mapped, and every declared delta applied.
    pub fn coverage_complete(&self) -> bool {
        self.sets.is_some() && self.missing_pgs.is_empty() && self.chain_broken_at.is_none()
    }

    /// Fold the deltas of a re-fetched `manifest` (same generation) that
    /// this load has not applied yet, without downloading the base again.
    ///
    /// Refuses, by marking the chain broken (coverage incomplete, nothing
    /// re-folded), a manifest whose base lists, holder sets, live filter or
    /// already-applied deltas differ from what was loaded: a writer may only
    /// append. A delta that does not scan every listed owned PG, or whose
    /// bundle or section fails to fetch or verify, breaks the chain at its
    /// seq; what it folded before failing only adds keys (a keep), never
    /// removes.
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

    /// Add to this load the PGs of `pgs` it does not hold yet, for the
    /// same generation: no base list is fetched (the holder set and the
    /// live filter already cover every PG of the partition), only each new
    /// PG's section in every delta already applied is folded; a PG the
    /// manifest does not cover joins `missing_pgs` (coverage incomplete).
    /// Used when the purge's protected set grows under a loaded generation
    /// (a PG gained) and when a delta's holder index names a PG not loaded.
    ///
    /// Refused (`Err`) when `manifest` is another generation, when its
    /// declaration of what was loaded differs, when an applied delta is no
    /// longer chained or changed, when an applied delta did not scan one of
    /// the new PGs, or when a body fails to fetch or verify. What a refused
    /// call folded before failing only adds keys (a keep, never a delete),
    /// and the new PGs are NOT recorded in `owned_pgs`: a protected set
    /// that includes them stays uncovered and the caller retries.
    /// Tombstones of the new PGs are not loaded (their unlisted blobs stay
    /// under the orphan age clause); tombstones the replayed sections name
    /// are withdrawn as at load. Returns the number of PGs added.
    pub async fn add_pgs(
        &mut self,
        source: &dyn ListSource,
        manifest: &Manifest,
        pgs: &[u32],
        my_uid: u32,
        concurrency: usize,
    ) -> Result<usize> {
        if manifest.generation != self.generation {
            bail!(
                "add_pgs: manifest is generation {}, loaded {}",
                manifest.generation,
                self.generation
            );
        }
        if lists_digest_through(manifest, &self.owned_pgs, 0) != self.base_digest {
            bail!(
                "add_pgs: base lists of generation {} changed under the loaded view",
                self.generation
            );
        }
        let held: BTreeSet<u32> = self.owned_pgs.iter().copied().collect();
        let new: Vec<u32> = pgs
            .iter()
            .copied()
            .filter(|pg| !held.contains(pg))
            .collect::<BTreeSet<u32>>()
            .into_iter()
            .collect();
        if new.is_empty() {
            return Ok(0);
        }
        let missing_new = manifest.missing_pgs(&new);
        let listed_new: Vec<u32> = new
            .iter()
            .copied()
            .filter(|pg| !missing_new.contains(pg))
            .collect();
        let generation = self.generation;
        let identity = ListIdentity {
            generation,
            ec_k: self.ec_k,
            ec_m: self.ec_m,
        };
        let mut added = FoldStats::default();
        for (seq, applied_sha) in self.applied_deltas.clone() {
            let Some(link) = manifest.deltas.iter().find(|d| d.seq == seq) else {
                bail!("add_pgs: applied delta {seq} is no longer chained");
            };
            if !hex::encode(applied_sha).eq_ignore_ascii_case(&link.sha256) {
                bail!("add_pgs: delta {seq} was applied with another body");
            }
            let delta = fetch_delta_manifest(source, manifest, link).await?;
            if delta.body_sha256 != applied_sha {
                bail!("add_pgs: delta {seq} manifest body changed");
            }
            let uncovered = delta.uncovered_pgs(&listed_new);
            if let Some(first) = uncovered.first() {
                bail!(
                    "add_pgs: delta {seq} did not scan {} of the {} added PGs (first: {first})",
                    uncovered.len(),
                    listed_new.len()
                );
            }
            let jobs = delta.fetch_jobs(&listed_new.iter().copied().collect());
            let stats = fold_lists(
                source,
                jobs,
                identity,
                my_uid,
                concurrency,
                &mut self.delta_mine,
                &mut self.delta_others,
                &mut self.tombstones,
                "additions",
            )
            .await?;
            added.records += stats.records;
            added.mine += stats.mine;
            added.others += stats.others;
            added.tombstones_retained += stats.tombstones_retained;
        }
        self.owned_pgs.extend(new.iter().copied());
        self.owned_pgs.sort_unstable();
        self.owned_pgs.dedup();
        self.missing_pgs.extend(missing_new.iter().copied());
        self.missing_pgs.sort_unstable();
        self.missing_pgs.dedup();
        self.listed_pgs += listed_new.len();
        self.total_hashes += added.mine;
        self.tombstones_retained_live_ref += added.tombstones_retained;
        self.delta_records += added.records;
        self.delta_hashes += added.mine;
        self.base_digest = lists_digest_through(manifest, &self.owned_pgs, 0);
        self.lists_digest = lists_digest_through(manifest, &self.owned_pgs, self.delta_seq);
        info!(
            generation,
            added_pgs = new.len(),
            listed = listed_new.len(),
            missing = missing_new.len(),
            deltas_replayed = self.applied_deltas.len(),
            records = added.records,
            mine = added.mine,
            owned_pgs = self.owned_pgs.len(),
            "pg-lists: PGs added to the loaded generation"
        );
        Ok(new.len())
    }

    /// Whether this load already holds exactly the lists `manifest`
    /// declares for `owned_pgs` (same generation, same PGs, same sha256
    /// per list): a caller may reuse it instead of downloading again.
    pub fn covers(&self, manifest: &Manifest, owned_pgs: &[u32]) -> bool {
        self.lists_digest == lists_digest(manifest, owned_pgs)
    }

    /// Whether `hash` may be one of this miner's obligations: its key is in
    /// this miner's holder set (any PG of the generation) or in a delta
    /// record naming it. Always `true` when the base declares no sets:
    /// nothing is known, so everything is kept.
    pub fn may_be_obliged(&self, hash: &[u8; 32]) -> bool {
        let Some(sets) = &self.sets else {
            return true;
        };
        sets.holds(hash) || self.delta_mine.binary_search(&blob_key(hash)).is_ok()
    }

    /// Whether `hash` may be a live shard some holder is obliged to keep
    /// (the moved class): a live filter hit (listed anywhere in the base
    /// or withheld by it), or the key of a delta record naming another
    /// holder in an enforced PG.
    pub fn may_be_held_by_other(&self, hash: &[u8; 32]) -> bool {
        self.sets.as_ref().is_some_and(|sets| sets.is_live(hash))
            || self.delta_others.binary_search(&blob_key(hash)).is_ok()
    }

    /// The mapped sets belong to this generation. `load_generation` always
    /// maps them that way; a pass checks it anyway before trusting a miss,
    /// since a miss is a deletion. `true` without sets (such a load never
    /// covers anything).
    pub fn filter_matches_generation(&self) -> bool {
        self.sets
            .as_ref()
            .is_none_or(|sets| sets.generation() == self.generation)
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
    // The holder sets and the live filter are part of the identity: a base
    // re-signed with other sets is other bytes. A base without keeps the
    // pre-sets digest.
    if let (Some(sets), Some(live)) = (&manifest.holder_sets, &manifest.live_filter) {
        hasher.update(b"holder_sets");
        for (uid, parts) in sets {
            hasher.update(&uid.to_le_bytes());
            hasher.update(&(parts.len() as u64).to_le_bytes());
            for part in parts {
                let mut sha = [0u8; 32];
                let _ = hex::decode_to_slice(&part.sha256, &mut sha);
                hasher.update(&sha);
            }
        }
        hasher.update(b"live_filter");
        hasher.update(&live.bit_count.to_le_bytes());
        hasher.update(&live.probes.to_le_bytes());
        for (path, shard) in &live.shards {
            let mut sha = [0u8; 32];
            let _ = hex::decode_to_slice(&shard.sha256, &mut sha);
            hasher.update(path.as_bytes());
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

/// The PGs whose base list names `uid`, from `manifest`'s holder index:
/// `Ok(None)` when the manifest declares no index (a writer that placed
/// holders on the current map only), `Ok(Some(empty))` when it declares
/// one without an object for `uid` (no record names it). The object is
/// checked against its declared size and sha256, then decoded: its header
/// must name `uid`, the manifest's generation and PG count. Any failure is
/// an error (a partial answer would hide PGs this miner holds).
pub async fn fetch_holder_pgs(
    source: &dyn ListSource,
    manifest: &Manifest,
    uid: u32,
) -> Result<Option<Vec<u32>>> {
    // An index over a subset of the partition cannot say "no other PG
    // names you": not trusted (the writer declares none for a subset).
    if !covers_partition(&manifest.pgs, manifest.pg_count) {
        return Ok(None);
    }
    fetch_indexed_pgs(
        source,
        manifest.holders.as_ref(),
        &format!("gen/{}", manifest.generation),
        manifest.generation,
        manifest.pg_count,
        uid,
    )
    .await
}

/// [`fetch_holder_pgs`] for a delta's own index (objects under the
/// delta's directory, headers naming the base generation).
pub async fn fetch_delta_holder_pgs(
    source: &dyn ListSource,
    delta: &DeltaManifest,
    uid: u32,
) -> Result<Option<Vec<u32>>> {
    if !covers_partition(&delta.pgs, delta.pg_count) {
        return Ok(None);
    }
    fetch_indexed_pgs(
        source,
        delta.holders.as_ref(),
        &DeltaManifest::dir_path(delta.generation, delta.seq),
        delta.generation,
        delta.pg_count,
        uid,
    )
    .await
}

/// `manifest`'s `pgs` are every PG of its partition (a holder index or a
/// holder set over a subset is never trusted).
pub fn covers_partition_of(manifest: &Manifest) -> bool {
    covers_partition(&manifest.pgs, manifest.pg_count)
}

/// `pgs` (sorted, unique) is every PG of a `pg_count` partition.
fn covers_partition(pgs: &[u32], pg_count: u32) -> bool {
    usize::try_from(pg_count).is_ok_and(|n| pgs.len() == n)
        && pgs.iter().enumerate().all(|(i, pg)| *pg as usize == i)
}

async fn fetch_indexed_pgs(
    source: &dyn ListSource,
    index: Option<&BTreeMap<String, ObjectEntry>>,
    dir: &str,
    generation: u64,
    pg_count: u32,
    uid: u32,
) -> Result<Option<Vec<u32>>> {
    let Some(index) = index else {
        return Ok(None);
    };
    let relative = common::obligation_list::holder_index_path(uid);
    let Some(entry) = index.get(&relative) else {
        return Ok(Some(Vec::new()));
    };
    if !common::obligation_list::holder_index_framing_ok(entry.size) {
        bail!("holder index {relative} declares {} bytes", entry.size);
    }
    if entry.size > MAX_LIST_BYTES {
        bail!(
            "holder index {relative} declares {} bytes, above the {MAX_LIST_BYTES} byte limit",
            entry.size
        );
    }
    let path = format!("{dir}/{relative}");
    let bytes = fetch_sized(source, &path, entry.size).await?;
    let digest = hex::encode(Sha256::digest(&bytes));
    if !digest.eq_ignore_ascii_case(&entry.sha256) {
        bail!(
            "holder index {path}: sha256 {digest} but the manifest declares {}",
            entry.sha256
        );
    }
    let (header, pgs) = common::obligation_list::decode_holder_index(&bytes)
        .with_context(|| format!("holder index {relative}"))?;
    if header.uid != uid || header.generation != generation || header.pg_count != pg_count {
        bail!(
            "holder index {path} names uid {} generation {} pg_count {} (expected {uid}, {generation}, {pg_count})",
            header.uid,
            header.generation,
            header.pg_count,
        );
    }
    Ok(Some(pgs))
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

/// Load this miner's view of `generation` for `owned_pgs`.
///
/// The PGs of the holder index join `owned_pgs`; PGs the manifest does not
/// cover are reported in `missing_pgs` and do not fail the load (the
/// caller sees coverage incomplete and purges nothing). The holder set of
/// `my_uid` and the live filter are fetched or reused from `cache_root`,
/// verified and mapped ([`GenerationSets::load`]); any failure there fails
/// the load (a partial set would purge what the missing part lists). No
/// per-PG base list is downloaded. The tombstones of the listed PGs are
/// loaded, minus those the live filter names (a live reference wins).
///
/// After the base, every delta the manifest chains is fetched, verified
/// with the key that verified the base and folded in, in seq order
/// ([`LoadedGeneration::extend`] does the same for deltas appended
/// later). A delta that fails leaves `chain_broken_at` set: the load
/// succeeds, coverage is incomplete.
pub async fn load_generation(
    source: &dyn ListSource,
    manifest: &Manifest,
    owned_pgs: &[u32],
    my_uid: u32,
    concurrency: usize,
    cache_root: &Path,
) -> Result<LoadedGeneration> {
    let created_at_secs = manifest
        .created_at_secs()
        .ok_or_else(|| anyhow::anyhow!("manifest created_at is missing or unparseable"))?;
    let snapshot_secs = manifest.snapshot_secs()?;
    // The PGs this miner holds records of without owning them (placed on
    // it at an older epoch) are loaded with the asked ones.
    let held_pgs = fetch_holder_pgs(source, manifest, my_uid)
        .await
        .context("holder index")?;
    if held_pgs.is_none() {
        warn!(
            generation = manifest.generation,
            "pg-lists: generation declares no holder index (holders placed on the current map only): loaded, never enforced"
        );
    }
    let mut wanted: Vec<u32> = owned_pgs
        .iter()
        .chain(held_pgs.iter().flatten())
        .copied()
        .collect();
    wanted.sort_unstable();
    wanted.dedup();
    let owned_pgs: &[u32] = &wanted;
    let missing_pgs = manifest.missing_pgs(owned_pgs);
    let listed: Vec<u32> = owned_pgs
        .iter()
        .copied()
        .filter(|pg| !missing_pgs.contains(pg))
        .collect();
    let generation = manifest.generation;
    let (ec_k, ec_m) = (manifest.ec_k, manifest.ec_m);

    let sets = GenerationSets::load(source, manifest, my_uid, cache_root, concurrency)
        .await
        .context("holder set and live filter")?
        .map(Arc::new);
    if sets.is_none() {
        warn!(
            generation,
            "pg-lists: generation declares no holder sets or live filter: loaded, never enforced"
        );
    }
    let (mut tombstones, tombstone_pgs) =
        load_tombstones(source, manifest, listed.iter().copied(), concurrency).await;
    let mut tombstones_retained_live_ref = 0u64;
    if let Some(sets) = &sets {
        // A hash any list of the generation names (or the base withholds)
        // is live: its tombstone is withdrawn. Filter-based: a false
        // positive only sends a tombstoned blob back to the age clause.
        let before = tombstones.len();
        tombstones.retain(|hash| !sets.is_live(hash));
        tombstones_retained_live_ref = (before - tombstones.len()) as u64;
        if tombstones_retained_live_ref > 0 {
            warn!(
                generation,
                retained = tombstones_retained_live_ref,
                kept = tombstones.len(),
                "pg-lists: tombstones named by the live filter: withdrawn (a live reference wins)"
            );
        }
    }
    if !missing_pgs.is_empty() {
        warn!(
            generation,
            missing = missing_pgs.len(),
            owned = owned_pgs.len(),
            "pg-lists: generation does not cover every owned PG"
        );
    }
    let total_hashes = sets.as_ref().map_or(0, |sets| sets.keys);
    info!(
        generation,
        owned_pgs = owned_pgs.len(),
        held_pgs = held_pgs.as_ref().map_or(0, Vec::len),
        listed_pgs = listed.len(),
        missing_pgs = missing_pgs.len(),
        set_keys = total_hashes,
        mapped_bytes = sets.as_ref().map_or(0, |sets| sets.mapped_bytes()),
        tombstones = tombstones.len(),
        "pg-lists: generation loaded"
    );
    let base_digest = lists_digest_through(manifest, owned_pgs, 0);
    let mut loaded = LoadedGeneration {
        generation,
        created_at_secs,
        snapshot_secs,
        view_cut_secs: manifest.signed_base_cut.unwrap_or(snapshot_secs),
        ec_k,
        ec_m,
        owned_pgs: owned_pgs.to_vec(),
        held_pgs,
        missing_pgs,
        listed_pgs: listed.len(),
        sets,
        delta_mine: Vec::new(),
        delta_others: Vec::new(),
        total_hashes,
        lists_digest: base_digest,
        tombstones,
        tombstone_pgs,
        tombstones_retained_live_ref,
        delta_seq: 0,
        applied_deltas: Vec::new(),
        chain_broken_at: None,
        announced_delta_seq: 0,
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
    loaded.announced_delta_seq = loaded
        .announced_delta_seq
        .max(manifest.declared_delta_seq());
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
            load_delta_holder_pgs(loaded, source, manifest, &delta, my_uid, concurrency).await?;
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
                loaded.total_hashes += stats.mine;
                loaded.tombstones_retained_live_ref += stats.tombstones_retained;
                if let Some(until) = until {
                    loaded.snapshot_secs = loaded.snapshot_secs.max(until);
                }
                // The view is as fresh as the last signed delta folded in,
                // and no fresher: never the max with an earlier stamp
                // (a base snapshot can be later than an old delta's end).
                // A delta without a readable end leaves the view stale.
                loaded.view_cut_secs = until.unwrap_or(0);
                loaded.lists_digest =
                    lists_digest_through(manifest, &loaded.owned_pgs, loaded.delta_seq);
                applied += 1;
                info!(
                    generation = loaded.generation,
                    seq = link.seq,
                    lists = stats.lists,
                    records = stats.records,
                    mine = stats.mine,
                    withheld = stats.withheld,
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
    if broken.is_none() && loaded.delta_seq < loaded.announced_delta_seq {
        broken = Some((
            loaded.delta_seq + 1,
            anyhow::anyhow!(
                "deltas up to {} were announced for this generation, only {} folded (stale or replayed manifest)",
                loaded.announced_delta_seq,
                loaded.delta_seq
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

/// Before a delta is folded: the PGs in which it adds records naming this
/// miner (its holder index) join `held_pgs`, and those not loaded yet are
/// added to the load ([`LoadedGeneration::add_pgs`]: their sections of the
/// deltas already applied), so the delta's records of those PGs are folded
/// too. A base without a holder index is never enforced and needs none; a
/// delta without one on a base with one is refused (the chain breaks).
async fn load_delta_holder_pgs(
    loaded: &mut LoadedGeneration,
    source: &dyn ListSource,
    manifest: &Manifest,
    delta: &DeltaManifest,
    my_uid: u32,
    concurrency: usize,
) -> Result<()> {
    if loaded.held_pgs.is_none() {
        return Ok(());
    }
    let Some(indexed) = fetch_delta_holder_pgs(source, delta, my_uid)
        .await
        .with_context(|| format!("holder index of delta {}", delta.seq))?
    else {
        bail!(
            "delta {} declares no holder index while its base does",
            delta.seq
        );
    };
    let unloaded: Vec<u32> = indexed
        .iter()
        .copied()
        .filter(|pg| loaded.owned_pgs.binary_search(pg).is_err())
        .collect();
    if !unloaded.is_empty() {
        let added = loaded
            .add_pgs(source, manifest, &unloaded, my_uid, concurrency)
            .await
            .with_context(|| format!("PGs of the holder index of delta {}", delta.seq))?;
        info!(
            generation = loaded.generation,
            seq = delta.seq,
            added,
            "pg-lists: PGs named by a delta's holder index added to the load"
        );
    }
    let held = loaded.held_pgs.get_or_insert_with(Vec::new);
    held.extend(indexed);
    held.sort_unstable();
    held.dedup();
    Ok(())
}

/// Fold one delta's sections for the listed owned PGs into the delta keys,
/// withdrawing the tombstones its records name: only the bundles holding
/// an enforced PG with additions are fetched, each once, and only the
/// enforced sections are folded. A listed owned PG the delta did not scan
/// is an error (its additions are unknown).
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
    let jobs = delta.fetch_jobs(&enforced.iter().copied().collect());
    let mut stats = fold_lists(
        source,
        jobs,
        ListIdentity {
            generation: loaded.generation,
            ec_k: loaded.ec_k,
            ec_m: loaded.ec_m,
        },
        my_uid,
        concurrency,
        &mut loaded.delta_mine,
        &mut loaded.delta_others,
        &mut loaded.tombstones,
        "additions",
    )
    .await?;
    if let Some(entry) = &delta.withheld {
        let (hashes, withdrawn) = fold_delta_withheld(loaded, source, delta, entry).await?;
        stats.withheld += hashes;
        stats.tombstones_retained += withdrawn;
    }
    Ok(stats)
}

/// Fold a delta's withheld shard hashes into `delta_others` (all PGs: a
/// withheld file is excluded or unplaceable, its shards may sit anywhere
/// and stay live for the file's other readers) and withdraw them from the
/// tombstones (identical shard bytes shared with a deleted file). Returns
/// the hashes folded and the tombstones withdrawn. The object is checked
/// whole (size, sha256, strict order) before any key is trusted; a failure
/// breaks the chain (the purge waits), and an early exit only ever added
/// keys (a keep).
async fn fold_delta_withheld(
    loaded: &mut LoadedGeneration,
    source: &dyn ListSource,
    delta: &DeltaManifest,
    entry: &common::obligation_list::DeltaWithheld,
) -> Result<(u64, u64)> {
    common::obligation_list::check_delta_withheld(entry)?;
    let path = format!(
        "{}/{}",
        DeltaManifest::dir_path(delta.generation, delta.seq),
        entry.path
    );
    let bytes = fetch_sized(source, &path, entry.size).await?;
    // Digest, decode, sort of the whole object: off the runtime workers.
    let (hashes, withdrawn) = crate::helpers::blocking(|| -> Result<(Vec<[u8; 32]>, u64)> {
        let digest = hex::encode(Sha256::digest(&bytes));
        ensure!(
            digest == entry.sha256,
            "{path}: sha256 {digest} is not the declared {}",
            entry.sha256
        );
        let hashes: Vec<[u8; 32]> = common::obligation_list::decode_withheld_hashes(&bytes)
            .with_context(|| path.clone())?
            .copied()
            .collect();
        ensure!(
            hashes.len() as u64 == entry.count,
            "{path}: {} hashes, the manifest declares {}",
            hashes.len(),
            entry.count
        );
        loaded.delta_others.extend(hashes.iter().map(blob_key));
        loaded.delta_others.sort_unstable();
        loaded.delta_others.dedup();
        let before = loaded.tombstones.len();
        loaded
            .tombstones
            .retain(|hash| hashes.binary_search(hash).is_err());
        let withdrawn = (before - loaded.tombstones.len()) as u64;
        Ok((hashes, withdrawn))
    })?;
    info!(
        generation = delta.generation,
        seq = delta.seq,
        withheld = hashes.len(),
        tombstones_withdrawn = withdrawn,
        "pg-lists: delta withheld hashes folded as live"
    );
    Ok((hashes.len() as u64, withdrawn))
}

/// One `APGL` body to fold: its PG and where it sits in the fetched
/// object (the whole object for a base list, a section of a delta
/// bundle), with the digest the signed manifest declares for it.
struct ListJob {
    pg_id: u32,
    offset: u64,
    size: u64,
    sha256: String,
}

/// One object to fetch and the bodies to fold out of it.
struct FetchJob {
    /// Bucket path.
    path: String,
    /// Declared size of the whole object.
    size: u64,
    /// Declared digest of the whole object, checked before any section;
    /// `None` when the single section is the whole object and carries the
    /// same digest.
    sha256: Option<String>,
    sections: Vec<ListJob>,
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
    /// Bodies folded: base lists, or delta sections.
    lists: usize,
    records: u64,
    mine: u64,
    others: u64,
    /// Withheld shard hashes of a delta folded as live (no record).
    withheld: u64,
    /// Tombstones withdrawn because a folded record or a withheld hash
    /// named them.
    tombstones_retained: u64,
}

/// Fetch, verify and fold `jobs` (delta bundles): the key of each of this
/// miner's records into `mine`, of the other holders' into `others` (both
/// sorted and unique on return, success or not: a partial fold only adds
/// keys, a keep), and every record's hash withdraws its tombstone (a live
/// reference in any enforced list wins). A bundle is checked whole (size,
/// digest) before its sections are sliced, each section checked against
/// its own digest and identity before its records are trusted. Any body
/// failing to fetch or verify fails the fold: a partial view of a PG would
/// purge its blobs.
#[allow(clippy::too_many_arguments)]
async fn fold_lists(
    source: &dyn ListSource,
    jobs: Vec<FetchJob>,
    identity: ListIdentity,
    my_uid: u32,
    concurrency: usize,
    mine: &mut Vec<u64>,
    others: &mut Vec<u64>,
    tombstones: &mut Vec<[u8; 32]>,
    what: &'static str,
) -> Result<FoldStats> {
    let folded = fold_lists_into(
        source,
        jobs,
        identity,
        my_uid,
        concurrency,
        mine,
        others,
        tombstones,
        what,
    )
    .await;
    // The lookups binary-search these: sorted whatever the outcome.
    crate::helpers::blocking(|| {
        for keys in [mine, others] {
            keys.sort_unstable();
            keys.dedup();
        }
    });
    folded
}

#[allow(clippy::too_many_arguments)]
async fn fold_lists_into(
    source: &dyn ListSource,
    jobs: Vec<FetchJob>,
    identity: ListIdentity,
    my_uid: u32,
    concurrency: usize,
    mine: &mut Vec<u64>,
    others: &mut Vec<u64>,
    tombstones: &mut Vec<[u8; 32]>,
    what: &'static str,
) -> Result<FoldStats> {
    use futures::StreamExt;
    let mut tombstone_named = vec![false; tombstones.len()];
    let mut fetches = futures::stream::iter(jobs.into_iter().map(|job| async move {
        let bytes = if job.size > MAX_LIST_BYTES {
            Err(anyhow!(
                "{}: declared {} bytes, above the {MAX_LIST_BYTES} byte limit",
                job.path,
                job.size
            ))
        } else {
            fetch_sized(source, &job.path, job.size).await
        };
        (job, bytes)
    }))
    .buffer_unordered(concurrency.max(1));

    let mut stats = FoldStats::default();
    while let Some((job, bytes)) = fetches.next().await {
        let path = &job.path;
        let first_pg = job.sections.first().map_or(0, |section| section.pg_id);
        let bytes = bytes.with_context(|| format!("fetch {what} of pg {first_pg} ({path})"))?;
        // Digest and decode of a bundle of up to 256 MiB: CPU and memory
        // bound, off the runtime workers.
        crate::helpers::blocking(|| -> Result<()> {
            if bytes.len() as u64 != job.size {
                bail!(
                    "{what} {path}: manifest size {} but body is {} bytes",
                    job.size,
                    bytes.len()
                );
            }
            if let Some(expected) = &job.sha256 {
                let digest = hex::encode(Sha256::digest(&bytes));
                if !digest.eq_ignore_ascii_case(expected) {
                    bail!("{what} {path}: sha256 mismatch: manifest {expected} body {digest}");
                }
            }
            for section in &job.sections {
                let pg_id = section.pg_id;
                let range = usize::try_from(section.offset)
                    .ok()
                    .zip(usize::try_from(section.size).ok())
                    .and_then(|(start, len)| Some(start..start.checked_add(len)?))
                    .filter(|range| range.end <= bytes.len())
                    .with_context(|| {
                        format!("{what} {path}: section of pg {pg_id} out of bounds")
                    })?;
                let body = &bytes[range];
                let expect = ListExpectation {
                    pg_id,
                    generation: identity.generation,
                    ec_k: identity.ec_k,
                    ec_m: identity.ec_m,
                    sha256_hex: &section.sha256,
                };
                let (mut pg_records, mut pg_mine, mut pg_others) = (0u64, 0u64, 0u64);
                let header = decode_list(body, expect, &mut |record| {
                    pg_records += 1;
                    // Every record, whoever holds it: a live reference in any
                    // owned PG withdraws the tombstone.
                    if let Ok(i) = tombstones.binary_search(&record.blob_hash) {
                        tombstone_named[i] = true;
                    }
                    if record.is_held_by(my_uid) {
                        mine.push(blob_key(&record.blob_hash));
                        pg_mine += 1;
                    } else {
                        others.push(blob_key(&record.blob_hash));
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
            Ok(())
        })?;
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
    let mut empty_pgs = 0usize;
    // A header-only body names no hash: the signed size alone says so, and
    // skipping its GET keeps a load of a large holder (every PG listed)
    // from paying one round trip per PG for nothing.
    let wanted: Vec<(u32, ObjectEntry)> = pgs
        .filter_map(|pg| manifest.tombstone_for_pg(pg).cloned().map(|obj| (pg, obj)))
        .filter(|(_, obj)| {
            let empty = obj.size == TOMBSTONE_HEADER_LEN as u64;
            empty_pgs += usize::from(empty);
            !empty
        })
        .collect();
    if wanted.is_empty() {
        debug!(generation, "pg-lists: generation carries no tombstones");
        return (Vec::new(), empty_pgs);
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
        let bytes = fetch_sized(source, &path, obj.size).await;
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
                crate::helpers::blocking(|| {
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
                })
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
    crate::helpers::blocking(|| {
        hashes.sort_unstable();
        hashes.dedup();
    });
    (hashes, pgs_done + empty_pgs)
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
        sorted_records_held_by(pg, count, MY_UID)
    }

    /// [`sorted_records`] with every record held by `holder_uid`.
    pub fn sorted_records_held_by(pg: u32, count: u32, holder_uid: u32) -> Vec<Record> {
        let mut records: Vec<Record> = (0..count)
            .map(|i| record_held_by(pg, i, holder_uid))
            .collect();
        records.sort_unstable_by(Record::cmp_key);
        records
    }

    /// [`write_generation`] where only the lists of `mine` name `MY_UID`
    /// (the other PGs' records are held by `OTHER_UID`): the holder index
    /// then names `MY_UID` in `mine` alone.
    pub fn write_generation_held(
        root: &Path,
        key: &SigningKey,
        generation: u64,
        pgs: &[u32],
        per_pg: u32,
        mine: &[u32],
    ) -> Fixture {
        write_generation_with(root, key, generation, pgs, &Stamps::default(), &|pg| {
            let holder = if mine.contains(&pg) {
                MY_UID
            } else {
                OTHER_UID
            };
            sorted_records_held_by(pg, per_pg, holder)
        })
    }

    pub fn sign_manifest(key: &SigningKey, unsigned: &serde_json::Value) -> serde_json::Value {
        let message = canonical_manifest_bytes(unsigned).unwrap();
        let signature = key.sign(&message);
        let mut signed = unsigned.clone();
        signed["signature"] = serde_json::Value::String(hex::encode(signature.to_bytes()));
        signed
    }

    /// Manifest time stamps of a fixture generation, and whether it
    /// carries a holder index.
    #[derive(Debug, Clone)]
    pub struct Stamps {
        pub created_at: serde_json::Value,
        /// Written only when `Some` (older writers do not publish it).
        pub scan_started_at: Option<serde_json::Value>,
        /// Publish `holders` and the per-uid index objects (what every
        /// generation of today's writer carries). `false` reproduces a
        /// generation written before holders followed the placement epoch.
        /// With it, the generation also carries holder sets and the live
        /// filter (the writer publishes them over a full partition only).
        pub holder_index: bool,
        /// Keys per holder set part (the writer's cap by default).
        pub part_max_keys: usize,
        /// Shard hashes the base withholds from the lists (excluded,
        /// unplaceable files): inserted into the live filter only.
        pub withheld: Vec<[u8; 32]>,
    }

    /// Stamps of a generation without a holder index: for the reader
    /// tests of other mechanics (digests, tombstones, deltas) that load a
    /// subset of the PGs whose lists name the fixture miner. With an index
    /// the load would rightly pull those PGs in too.
    pub fn unindexed() -> Stamps {
        Stamps {
            holder_index: false,
            ..Stamps::default()
        }
    }

    impl Default for Stamps {
        fn default() -> Self {
            Self {
                created_at: serde_json::json!(CREATED_AT),
                scan_started_at: None,
                holder_index: true,
                part_max_keys: common::hash_set_files::HOLDER_SET_PART_MAX_KEYS,
                withheld: Vec::new(),
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
        // A holder index is only trusted over a whole partition: an
        // indexed fixture is a partition of `0..=max(pgs)` whose other PGs
        // hold no record (a small `pg_count`); an unindexed one keeps the
        // production PG count and lists `pgs` alone.
        let given: std::collections::BTreeSet<u32> = pgs.iter().copied().collect();
        let (pgs, pg_count): (Vec<u32>, u32) = if stamps.holder_index {
            let count = pgs.iter().max().map_or(1, |max| max + 1);
            ((0..count).collect(), count)
        } else {
            (pgs.to_vec(), 16384)
        };
        let pgs = pgs.as_slice();
        let records = |pg: u32| {
            if given.contains(&pg) {
                records(pg)
            } else {
                Vec::new()
            }
        };
        let mut ascending = pgs.to_vec();
        ascending.sort_unstable();
        let mut builder = common::obligation_list::HolderIndexBuilder::default();
        let mut keys_by_uid: std::collections::BTreeMap<u32, Vec<u64>> =
            [(MY_UID, Vec::new()), (OTHER_UID, Vec::new())].into();
        let mut listed: Vec<[u8; 32]> = Vec::new();
        for &pg in &ascending {
            let pg_records = records(pg);
            builder.add_pg(pg, &pg_records).unwrap();
            for r in &pg_records {
                keys_by_uid
                    .entry(r.holder_uid)
                    .or_default()
                    .push(common::hash_set_files::blob_key(&r.blob_hash));
                listed.push(r.blob_hash);
            }
        }
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
                let hashes = if given.contains(&pg) {
                    tombstones(pg)
                } else {
                    Vec::new()
                };
                let body = encode_tombstones(pg, generation, 10, 20, &hashes);
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
            "pg_count": pg_count,
            "ec_k": 10,
            "ec_m": 20,
            "pgs": pgs,
            "objects": objects,
        });
        if let Some(scan_started_at) = &stamps.scan_started_at {
            unsigned["scan_started_at"] = scan_started_at.clone();
        }
        if stamps.holder_index {
            std::fs::create_dir_all(gen_dir.join("holders")).unwrap();
            let mut holders = serde_json::Map::new();
            for (path, body) in builder.encode(generation, pg_count).unwrap() {
                std::fs::write(gen_dir.join(&path), &body).unwrap();
                holders.insert(
                    path,
                    serde_json::json!({
                        "sha256": hex::encode(Sha256::digest(&body)),
                        "size": body.len(),
                    }),
                );
            }
            unsigned["holders"] = serde_json::Value::Object(holders);
            write_sets(
                &gen_dir,
                &mut unsigned,
                generation,
                keys_by_uid,
                listed.iter().chain(&stamps.withheld),
                stamps,
            );
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

    /// Write the holder sets of every uid in `keys_by_uid` and the 256 live
    /// filter shards over `live`, and declare both in `unsigned`.
    fn write_sets<'a>(
        gen_dir: &Path,
        unsigned: &mut serde_json::Value,
        generation: u64,
        keys_by_uid: std::collections::BTreeMap<u32, Vec<u64>>,
        live: impl Iterator<Item = &'a [u8; 32]>,
        stamps: &Stamps,
    ) {
        use common::hash_set_files::{
            LIVE_FILTER_SHARDS, LiveFilterBuilder, encode_holder_set_part, holder_set_path,
            live_filter_path, live_filter_shard, split_holder_set,
        };
        let mut holder_sets = serde_json::Map::new();
        for (uid, mut keys) in keys_by_uid {
            keys.sort_unstable();
            keys.dedup();
            let mut parts = Vec::new();
            for (part, chunk) in split_holder_set(&keys, stamps.part_max_keys).enumerate() {
                let part = part as u32;
                let body = encode_holder_set_part(uid, part, generation, chunk).unwrap();
                let path = holder_set_path(uid, part);
                let local = gen_dir.join(&path);
                std::fs::create_dir_all(local.parent().unwrap()).unwrap();
                std::fs::write(&local, &body).unwrap();
                parts.push(serde_json::json!({
                    "path": path,
                    "sha256": hex::encode(Sha256::digest(&body)),
                    "size": body.len(),
                    "count": chunk.len(),
                    "key_lo": chunk[0],
                    "key_hi": chunk[chunk.len() - 1],
                }));
            }
            holder_sets.insert(uid.to_string(), serde_json::Value::Array(parts));
        }
        let live: Vec<[u8; 32]> = live.copied().collect();
        let expected = live.len() as u64 / u64::from(LIVE_FILTER_SHARDS) + 1024;
        let mut builders: Vec<LiveFilterBuilder> = (0..LIVE_FILTER_SHARDS)
            .map(|shard| LiveFilterBuilder::new(shard, generation, expected, 50_000).unwrap())
            .collect();
        for hash in &live {
            builders[live_filter_shard(hash) as usize]
                .insert(hash)
                .unwrap();
        }
        std::fs::create_dir_all(gen_dir.join("live")).unwrap();
        let mut shards = serde_json::Map::new();
        for (shard, builder) in builders.iter().enumerate() {
            let body = builder.encode();
            let path = live_filter_path(shard as u32);
            std::fs::write(gen_dir.join(&path), &body).unwrap();
            shards.insert(
                path,
                serde_json::json!({
                    "sha256": hex::encode(Sha256::digest(&body)),
                    "size": body.len(),
                }),
            );
        }
        let header = builders[0].header();
        unsigned["holder_sets"] = serde_json::Value::Object(holder_sets);
        unsigned["live_filter"] = serde_json::json!({
            "fp_ppm": header.fp_ppm,
            "probes": header.probes,
            "bit_count": header.bit_count,
            "withheld_hashes": stamps.withheld.len(),
            "shards": shards,
        });
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
    /// `delta/<gen>/<seq>/bundle/<b>.added` range bundles holding a
    /// section for every PG `added` returns records for (a PG with no
    /// records is covered but gets no section),
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
        chain_delta(root, key, generation, seq, since, until, sha, size);
        sha
    }

    /// Append the ref of an already written delta manifest (`sha`, `size`)
    /// to the base manifest's `deltas` (re-signed) and bump
    /// `current.json`'s `delta_seq`.
    #[allow(clippy::too_many_arguments)]
    pub fn chain_delta(
        root: &Path,
        key: &SigningKey,
        generation: u64,
        seq: u64,
        since: u64,
        until: u64,
        sha: [u8; 32],
        size: usize,
    ) {
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
    }

    /// Write the signed delta `seq` of `generation` only (its manifest and
    /// bundles, format 2), touching neither the base manifest nor
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
        let unsigned = write_delta_bundles(root, generation, seq, since, until, pgs, added);
        write_signed_delta(root, key, generation, seq, &unsigned)
    }

    /// Write the bundles of delta `seq` of `generation` (format 2: one
    /// section per PG `added` returns records for, grouped by
    /// `pg / DELTA_BUNDLE_PGS`) and return its unsigned manifest, for a
    /// test to alter before [`write_signed_delta`].
    pub fn write_delta_bundles(
        root: &Path,
        generation: u64,
        seq: u64,
        since: u64,
        until: u64,
        pgs: &[u32],
        added: &dyn Fn(u32) -> Vec<Record>,
    ) -> serde_json::Value {
        let dir = root.join(DeltaManifest::dir_path(generation, seq));
        std::fs::create_dir_all(dir.join("bundle")).unwrap();
        // The writer's deltas cover their base's PGs, with its PG count: an
        // indexed base is a whole partition, and so is its delta (records
        // still come from `added` for `pgs` only).
        // Without a base on disk (a layout test): the production PG count.
        let base_path = root.join(format!("gen/{generation}/manifest.json"));
        let base = base_path
            .exists()
            .then(|| read_base_manifest(root, generation));
        let pg_count = base
            .as_ref()
            .map_or(16384, |b| b["pg_count"].as_u64().unwrap() as u32);
        let covered: Vec<u32> = if base.as_ref().is_some_and(|b| b.get("holders").is_some()) {
            (0..pg_count).collect()
        } else {
            pgs.to_vec()
        };
        let mut sorted = pgs.to_vec();
        sorted.sort_unstable();
        let mut by_bundle: BTreeMap<u32, Vec<(u32, Vec<u8>)>> = BTreeMap::new();
        let mut index = common::obligation_list::HolderIndexBuilder::default();
        for pg in sorted {
            let records = added(pg);
            if records.is_empty() {
                continue;
            }
            index.add_pg(pg, &records).unwrap();
            by_bundle
                .entry(pg / DELTA_BUNDLE_PGS)
                .or_default()
                .push((pg, encode_list(pg, generation, 10, 20, &records)));
        }
        let mut bundles = serde_json::Map::new();
        for (index, sections) in by_bundle {
            let mut bundle = Vec::new();
            let mut declared = Vec::new();
            for (pg, body) in sections {
                declared.push(serde_json::json!({
                    "pg": pg,
                    "offset": bundle.len(),
                    "size": body.len(),
                    "sha256": hex::encode(Sha256::digest(&body)),
                }));
                bundle.extend_from_slice(&body);
            }
            let relative = DeltaManifest::bundle_path(index);
            std::fs::write(dir.join(&relative), &bundle).unwrap();
            bundles.insert(
                relative,
                serde_json::json!({
                    "sha256": hex::encode(Sha256::digest(&bundle)),
                    "size": bundle.len(),
                    "pgs": declared,
                }),
            );
        }
        // The delta's own holder index, as today's writer publishes it.
        std::fs::create_dir_all(dir.join("holders")).unwrap();
        let mut holders = serde_json::Map::new();
        for (path, body) in index.encode(generation, pg_count).unwrap() {
            std::fs::write(dir.join(&path), &body).unwrap();
            holders.insert(
                path,
                serde_json::json!({
                    "sha256": hex::encode(Sha256::digest(&body)),
                    "size": body.len(),
                }),
            );
        }
        serde_json::json!({
            "generation": generation,
            "seq": seq,
            "since": since,
            "until": until,
            "created_at": until,
            "pg_count": pg_count,
            "ec_k": 10,
            "ec_m": 20,
            "pgs": covered,
            "format": DELTA_FORMAT,
            "list_version": common::obligation_list::VERSION,
            "bundles": bundles,
            "holders": holders,
        })
    }

    /// Sign `unsigned` as delta `seq` of `generation` and write it; no
    /// shape check, so a test can publish a malformed layout. Returns the
    /// manifest's sha256 and size.
    pub fn write_signed_delta(
        root: &Path,
        key: &SigningKey,
        generation: u64,
        seq: u64,
        unsigned: &serde_json::Value,
    ) -> ([u8; 32], usize) {
        let dir = root.join(DeltaManifest::dir_path(generation, seq));
        std::fs::create_dir_all(&dir).unwrap();
        let signed = serde_json::to_vec_pretty(&sign_manifest(key, unsigned)).unwrap();
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

    /// A fresh holder set cache for one load. The directory goes with the
    /// guard (at the end of the calling statement); the mappings made from
    /// it stay valid.
    fn cache_dir() -> tempfile::TempDir {
        tempfile::tempdir().unwrap()
    }

    /// `hash` is named by a folded delta record of this miner. The delta
    /// tests run on set-less generations, where `may_be_obliged` answers
    /// `true` for everything.
    fn in_delta_mine(loaded: &LoadedGeneration, hash: &[u8; 32]) -> bool {
        loaded.delta_mine.binary_search(&blob_key(hash)).is_ok()
    }

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
    /// A shard placed at an older epoch on miner A, whose current map
    /// moved the PG to miner B. The list names A (the placement-epoch
    /// holder: the gateway reads from it). A no longer owns the PG, yet the
    /// holder index makes its load include that PG and the blob is its
    /// obligation; B owns the PG now, loads its list, and does NOT count
    /// the blob as its own (it is listed for another holder: moved class).
    #[tokio::test]
    async fn holder_index_loads_the_pgs_a_miner_holds_without_owning_them() {
        const A: u32 = MY_UID;
        const B: u32 = OTHER_UID;
        let dir = tempfile::tempdir().unwrap();
        let key = deterministic_key(1);
        let placed_on_a = hash_for(11, 3);
        let fx = write_generation_with(dir.path(), &key, 7, &[10, 11], &Stamps::default(), &|pg| {
            // PG 10: A's own. PG 11: owned by B now; one shard still
            // placed on A at its placement epoch, the rest on B.
            (0..5)
                .map(|i| {
                    let holder = if pg == 10 || hash_for(pg, i) == placed_on_a {
                        A
                    } else {
                        B
                    };
                    record_held_by(pg, i, holder)
                })
                .collect()
        });
        let source = DirListSource::new(dir.path());
        let manifest = fetch_manifest(&source, 7, &fx.validator_hex())
            .await
            .unwrap();
        assert_eq!(
            fetch_holder_pgs(&source, &manifest, A).await.unwrap(),
            Some(vec![10, 11])
        );
        assert_eq!(
            fetch_holder_pgs(&source, &manifest, B).await.unwrap(),
            Some(vec![11])
        );
        assert_eq!(
            fetch_holder_pgs(&source, &manifest, 9_999).await.unwrap(),
            Some(vec![]),
            "a uid no record names has no object: no PG"
        );

        // A owns only PG 10 under the current map.
        let a = load_generation(&source, &manifest, &[10], A, 1, cache_dir().path())
            .await
            .unwrap();
        assert_eq!(a.held_pgs, Some(vec![10, 11]));
        assert_eq!(a.owned_pgs, vec![10, 11], "PG 11 loaded for the index");
        assert_eq!(a.required_pgs(&[10]), vec![10, 11]);
        assert!(a.missing_pgs.is_empty());
        assert!(a.may_be_obliged(&placed_on_a), "A keeps the shard it holds");

        // B owns PG 11: the shard is listed there for A, not for B.
        let b = load_generation(&source, &manifest, &[11], B, 1, cache_dir().path())
            .await
            .unwrap();
        assert_eq!(b.held_pgs, Some(vec![11]));
        assert_eq!(b.owned_pgs, vec![11]);
        assert!(
            (0..5)
                .map(|i| hash_for(11, i))
                .filter(|h| *h != placed_on_a)
                .all(|h| b.may_be_obliged(&h))
        );
        assert!(b.may_be_held_by_other(&placed_on_a), "moved class for B");
        assert_eq!(b.total_hashes, 4, "B's own records only");
    }

    /// A delta adds a record naming this miner in a PG its base index did
    /// not name (a file written after the base cut, placed on it): the
    /// delta's own holder index makes the load add that PG before folding
    /// the delta, and the PG joins `held_pgs`. A delta without an index on
    /// a base with one breaks the chain instead of being folded blind.
    #[tokio::test]
    async fn delta_holder_index_adds_the_pgs_it_names() {
        let key = deterministic_key(1);
        let cut = CREATED_AT_SECS - 300;
        let new_shard = record_held_by(11, 77, MY_UID);
        let setup = |dir: &std::path::Path| {
            let fx = write_generation_held(dir, &key, 7, &[10, 11], 5, &[10]);
            set_base_cut(dir, &key, 7, cut);
            fx
        };

        let dir = tempfile::tempdir().unwrap();
        let fx = setup(dir.path());
        append_delta(dir.path(), &key, 7, 1, cut, cut + 3600, &[10, 11], &|pg| {
            if pg == 11 { vec![new_shard] } else { vec![] }
        });
        let source = DirListSource::new(dir.path());
        let manifest = fetch_manifest(&source, 7, &fx.validator_hex())
            .await
            .unwrap();
        let loaded = load_generation(&source, &manifest, &[10], MY_UID, 2, cache_dir().path())
            .await
            .unwrap();
        assert_eq!(loaded.chain_broken_at, None);
        assert_eq!(loaded.delta_seq, 1);
        assert_eq!(loaded.owned_pgs, vec![10, 11]);
        assert_eq!(loaded.held_pgs, Some(vec![10, 11]));
        assert!(loaded.may_be_obliged(&new_shard.blob_hash));
        assert!(
            loaded.may_be_held_by_other(&hash_for(11, 0)),
            "PG 11's base list folded too (others' records)"
        );

        // The same delta without its holder index.
        let dir = tempfile::tempdir().unwrap();
        let fx = setup(dir.path());
        let mut unsigned =
            write_delta_bundles(dir.path(), 7, 1, cut, cut + 3600, &[10, 11], &|pg| {
                if pg == 11 { vec![new_shard] } else { vec![] }
            });
        unsigned.as_object_mut().unwrap().remove("holders");
        let (sha, size) = write_signed_delta(dir.path(), &key, 7, 1, &unsigned);
        chain_delta(dir.path(), &key, 7, 1, cut, cut + 3600, sha, size);
        let source = DirListSource::new(dir.path());
        let manifest = fetch_manifest(&source, 7, &fx.validator_hex())
            .await
            .unwrap();
        let loaded = load_generation(&source, &manifest, &[10], MY_UID, 2, cache_dir().path())
            .await
            .unwrap();
        assert_eq!(loaded.chain_broken_at, Some(1));
        assert_eq!(loaded.delta_seq, 0);
        assert_eq!(loaded.owned_pgs, vec![10]);
    }

    /// A delta's withheld shard hashes are folded as live under another
    /// holder whatever their PG (none of them is in an owned PG here) and
    /// withdraw the base tombstones they name; a withheld object that does
    /// not match its declaration breaks the chain at that seq.
    #[tokio::test]
    async fn delta_withheld_hashes_fold_globally_and_withdraw_tombstones() {
        let key = deterministic_key(1);
        let cut = CREATED_AT_SECS - 300;
        let shared = hash_for(99, 1);
        let unreferenced = hash_for(99, 2);
        let far = hash_for(4_000, 3);
        let setup = |dir: &std::path::Path| {
            let fx = write_generation_with_tombstones(
                dir,
                &key,
                7,
                &[10, 11],
                &Stamps::default(),
                &|pg| sorted_records(pg, 5),
                Some(&|pg| match pg {
                    10 => {
                        let mut t = vec![shared, unreferenced];
                        t.sort_unstable();
                        t
                    }
                    _ => vec![],
                }),
            );
            set_base_cut(dir, &key, 7, cut);
            fx
        };
        let mut withheld = [shared, far];
        withheld.sort_unstable();
        let body: Vec<u8> = withheld.concat();
        let publish = |dir: &std::path::Path, body: &[u8], declared_sha: String| {
            let mut unsigned =
                write_delta_bundles(dir, 7, 1, cut, cut + 3600, &[10, 11], &|_| vec![]);
            std::fs::write(dir.join("delta/7/1/withheld.hashes"), body).unwrap();
            unsigned["withheld"] = serde_json::json!({
                "path": "withheld.hashes",
                "sha256": declared_sha,
                "size": 64,
                "count": 2,
            });
            let (sha, size) = write_signed_delta(dir, &key, 7, 1, &unsigned);
            chain_delta(dir, &key, 7, 1, cut, cut + 3600, sha, size);
        };

        let dir = tempfile::tempdir().unwrap();
        let fx = setup(dir.path());
        let source = DirListSource::new(dir.path());
        let manifest = fetch_manifest(&source, 7, &fx.validator_hex())
            .await
            .unwrap();
        let before = load_generation(&source, &manifest, &[10], MY_UID, 2, cache_dir().path())
            .await
            .unwrap();
        assert!(before.is_tombstoned(&shared));
        assert!(!before.may_be_held_by_other(&far));

        publish(dir.path(), &body, hex::encode(Sha256::digest(&body)));
        let manifest = fetch_manifest(&source, 7, &fx.validator_hex())
            .await
            .unwrap();
        let loaded = load_generation(&source, &manifest, &[10], MY_UID, 2, cache_dir().path())
            .await
            .unwrap();
        assert_eq!(loaded.chain_broken_at, None);
        assert_eq!(loaded.delta_seq, 1);
        assert!(
            loaded.may_be_held_by_other(&far),
            "a withheld hash of a PG this miner does not own is live"
        );
        assert!(loaded.may_be_held_by_other(&shared));
        assert!(!loaded.is_tombstoned(&shared), "its tombstone is withdrawn");
        assert!(loaded.is_tombstoned(&unreferenced));
        assert_eq!(loaded.tombstones, vec![unreferenced]);
        assert!(
            loaded.delta_others.windows(2).all(|w| w[0] < w[1]),
            "delta_others stays sorted and unique"
        );

        // The same delta whose object does not match its signed digest.
        let dir = tempfile::tempdir().unwrap();
        let fx = setup(dir.path());
        let mut tampered = body.clone();
        tampered[63] ^= 1;
        publish(dir.path(), &tampered, hex::encode(Sha256::digest(&body)));
        let source = DirListSource::new(dir.path());
        let manifest = fetch_manifest(&source, 7, &fx.validator_hex())
            .await
            .unwrap();
        let broken = load_generation(&source, &manifest, &[10], MY_UID, 2, cache_dir().path())
            .await
            .unwrap();
        assert_eq!(broken.chain_broken_at, Some(1));
        assert_eq!(broken.delta_seq, 0);
        assert!(!broken.coverage_complete());
    }

    /// A holder index is trusted only over the whole partition: a manifest
    /// that covers a subset of the PGs (a `--pg-ids` / `--miner-uids` run)
    /// cannot say "no other PG names you", so even if it declares an index
    /// the load has no `held_pgs` and never opens the purge gate.
    #[tokio::test]
    async fn a_holder_index_over_a_partial_generation_is_not_trusted() {
        let dir = tempfile::tempdir().unwrap();
        let key = deterministic_key(1);
        let fx = write_generation(dir.path(), &key, 7, &[1, 2, 3], 5);
        let source = DirListSource::new(dir.path());
        let full = fetch_manifest(&source, 7, &fx.validator_hex())
            .await
            .unwrap();
        assert_eq!(full.pgs, vec![0, 1, 2, 3]);
        assert_eq!(
            fetch_holder_pgs(&source, &full, MY_UID).await.unwrap(),
            Some(vec![1, 2, 3])
        );
        // The same generation restricted to PGs 1..=3 (PG 0 dropped).
        rewrite_base_manifest(dir.path(), &key, 7, &|v| {
            v["pgs"] = serde_json::json!([1, 2, 3]);
            v["objects"]
                .as_object_mut()
                .unwrap()
                .remove(&Manifest::list_path(0));
        });
        let partial = fetch_manifest(&source, 7, &fx.validator_hex())
            .await
            .unwrap();
        assert!(partial.holders.is_some(), "an index is still declared");
        assert_eq!(
            fetch_holder_pgs(&source, &partial, MY_UID).await.unwrap(),
            None
        );
        let loaded = load_generation(&source, &partial, &[1], MY_UID, 1, cache_dir().path())
            .await
            .unwrap();
        assert_eq!(loaded.held_pgs, None, "never enforced");
    }

    /// A delta manifest must carry `list_version` 4: one without it (or
    /// with another value) was written for a version 3 chain and breaks
    /// the chain instead of being folded.
    #[tokio::test]
    async fn delta_without_list_version_4_breaks_the_chain() {
        let key = deterministic_key(1);
        let cut = CREATED_AT_SECS - 300;
        for edit in [
            Box::new(|v: &mut serde_json::Value| {
                v.as_object_mut().unwrap().remove("list_version");
            }) as Box<dyn Fn(&mut serde_json::Value)>,
            Box::new(|v: &mut serde_json::Value| v["list_version"] = serde_json::json!(3)),
        ] {
            let dir = tempfile::tempdir().unwrap();
            let fx = write_generation(dir.path(), &key, 7, &[10], 5);
            set_base_cut(dir.path(), &key, 7, cut);
            let mut unsigned =
                write_delta_bundles(dir.path(), 7, 1, cut, cut + 3600, &[10], &|pg| {
                    vec![record_for(pg, 100)]
                });
            edit(&mut unsigned);
            let (sha, size) = write_signed_delta(dir.path(), &key, 7, 1, &unsigned);
            chain_delta(dir.path(), &key, 7, 1, cut, cut + 3600, sha, size);
            let source = DirListSource::new(dir.path());
            let manifest = fetch_manifest(&source, 7, &fx.validator_hex())
                .await
                .unwrap();
            let loaded = load_generation(&source, &manifest, &[10], MY_UID, 1, cache_dir().path())
                .await
                .unwrap();
            assert_eq!(loaded.chain_broken_at, Some(1));
            assert!(!loaded.may_be_obliged(&hash_for(10, 100)));
        }
    }

    /// A generation without a holder index (holders placed on the current
    /// map only) loads, with `held_pgs` unset: never an index silently
    /// read as empty.
    #[tokio::test]
    async fn generation_without_holder_index_has_no_held_pgs() {
        let dir = tempfile::tempdir().unwrap();
        let key = deterministic_key(1);
        let fx = write_generation_stamped(dir.path(), &key, 7, &[10, 11], 5, &unindexed());
        let source = DirListSource::new(dir.path());
        let manifest = fetch_manifest(&source, 7, &fx.validator_hex())
            .await
            .unwrap();
        assert!(manifest.holders.is_none());
        assert_eq!(
            fetch_holder_pgs(&source, &manifest, MY_UID).await.unwrap(),
            None
        );
        let loaded = load_generation(&source, &manifest, &[10], MY_UID, 1, cache_dir().path())
            .await
            .unwrap();
        assert_eq!(loaded.held_pgs, None);
        assert_eq!(loaded.owned_pgs, vec![10]);
    }

    /// The index object is checked against the manifest (size, sha256)
    /// and its header against the request (uid, generation, pg_count): a
    /// failure fails the load, never a partial answer.
    #[tokio::test]
    async fn holder_index_is_verified_before_use() {
        let key = deterministic_key(1);
        // Tampered bytes (digest mismatch).
        let dir = tempfile::tempdir().unwrap();
        let fx = write_generation(dir.path(), &key, 7, &[10, 11], 5);
        let path = dir.path().join("gen/7/holders/0000007001.pgs");
        let mut bytes = std::fs::read(&path).unwrap();
        let last = bytes.len() - 1;
        bytes[last] ^= 1;
        std::fs::write(&path, &bytes).unwrap();
        let source = DirListSource::new(dir.path());
        let manifest = fetch_manifest(&source, 7, &fx.validator_hex())
            .await
            .unwrap();
        let error = fetch_holder_pgs(&source, &manifest, MY_UID)
            .await
            .unwrap_err();
        assert!(format!("{error:#}").contains("sha256"), "{error:#}");
        assert!(
            load_generation(&source, &manifest, &[10], MY_UID, 1, cache_dir().path())
                .await
                .is_err()
        );

        // An index whose header names another uid, declared under this
        // uid's path with a matching digest.
        let dir = tempfile::tempdir().unwrap();
        let fx = write_generation(dir.path(), &key, 7, &[10, 11], 5);
        let foreign =
            common::obligation_list::encode_holder_index(OTHER_UID, 7, 16384, &[10]).unwrap();
        std::fs::write(dir.path().join("gen/7/holders/0000007001.pgs"), &foreign).unwrap();
        rewrite_base_manifest(dir.path(), &key, 7, &|v| {
            v["holders"]["holders/0000007001.pgs"] = serde_json::json!({
                "sha256": hex::encode(Sha256::digest(&foreign)),
                "size": foreign.len(),
            });
        });
        let source = DirListSource::new(dir.path());
        let manifest = fetch_manifest(&source, 7, &fx.validator_hex())
            .await
            .unwrap();
        let error = fetch_holder_pgs(&source, &manifest, MY_UID)
            .await
            .unwrap_err();
        assert!(format!("{error:#}").contains("names uid"), "{error:#}");
    }

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
        let loaded = load_generation(&source, &manifest, &[10], 500, 1, cache_dir().path())
            .await
            .unwrap();
        assert_eq!(loaded.total_hashes, 10, "one per stripe of 30");
        assert!(loaded.filter_matches_generation());
        let mine: Vec<u32> = (0..300).filter(|i| holder_of(*i) == 500).collect();
        assert_eq!(mine.len(), 10);
        assert!(
            mine.iter()
                .all(|i| loaded.may_be_obliged(&hash_for(10, *i)))
        );
        let others = (0..300)
            .filter(|i| !mine.contains(i))
            .filter(|i| loaded.may_be_obliged(&hash_for(10, *i)))
            .count();
        assert_eq!(others, 0, "the holder set is exact on 64-bit keys");

        // A uid declared with no parts (the fixture declares MY_UID, which
        // no record names here) has an empty set: it keeps nothing.
        let none = load_generation(&source, &manifest, &[10], MY_UID, 1, cache_dir().path())
            .await
            .unwrap();
        assert_eq!(none.total_hashes, 0);
        assert!(none.sets.is_some(), "a uid declared `[]` has an empty set");
        assert!(none.coverage_complete());
        assert!((0..300).all(|i| !none.may_be_obliged(&hash_for(10, i))));

        // A uid the holder sets do not declare at all is not covered: no
        // sets, coverage incomplete, every hash may be an obligation.
        let undeclared = load_generation(&source, &manifest, &[10], 499, 1, cache_dir().path())
            .await
            .unwrap();
        assert!(
            undeclared.sets.is_none(),
            "an undeclared uid is not covered"
        );
        assert!(!undeclared.coverage_complete());
        assert!((0..300).all(|i| undeclared.may_be_obliged(&hash_for(10, i))));
        assert!(undeclared.may_be_obliged(&hash_for(99, 0)));

        // The default fixture names MY_UID on every record: all its own.
        let dir = tempfile::tempdir().unwrap();
        let fx = write_generation(dir.path(), &key, 7, &[10], 300);
        let source = DirListSource::new(dir.path());
        let manifest = fetch_manifest(&source, 7, &fx.validator_hex())
            .await
            .unwrap();
        let all = load_generation(&source, &manifest, &[10], MY_UID, 1, cache_dir().path())
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
        let loaded = load_generation(&source, &manifest, &[10, 11], MY_UID, 2, cache_dir().path())
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
            load_generation(&source, &manifest, &[10, 11], MY_UID, 2, cache_dir().path())
                .await
                .unwrap();
        assert_eq!(loaded.delta_seq, 2);
        assert_eq!(loaded.chain_broken_at, None);
        assert!(loaded.coverage_complete());
        assert_eq!(loaded.applied_deltas.len(), 2);
        assert_eq!(loaded.delta_records, 21);
        assert_eq!(loaded.delta_hashes, 21);
        assert_eq!(loaded.total_hashes, 121);
        assert!((100..110).all(|i| in_delta_mine(&loaded, &hash_for(10, i))));
        assert!((100..110).all(|i| in_delta_mine(&loaded, &hash_for(11, i))));
        assert!(in_delta_mine(&loaded, &hash_for(10, 900)));
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
        assert!(in_delta_mine(&loaded, &hash_for(11, 200)));
        assert_eq!(loaded.snapshot_secs, cut + 9000);
        assert_ne!(loaded.lists_digest, digest_2);
        assert!(loaded.coverage_complete());

        // A fresh load of the same bucket lands on the same state.
        let fresh = load_generation(&source, &grown, &[10, 11], MY_UID, 2, cache_dir().path())
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
            let fx = write_generation_stamped(dir, &key, 7, &[10, 11], 50, &unindexed());
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
        let loaded = load_generation(&source, &manifest, &[10, 11], MY_UID, 2, cache_dir().path())
            .await
            .unwrap();
        assert_eq!(loaded.delta_seq, 1);
        assert_eq!(loaded.chain_broken_at, Some(3));
        assert!(!loaded.coverage_complete());
        assert!(loaded.missing_pgs.is_empty(), "the base covers every PG");
        assert!(in_delta_mine(&loaded, &hash_for(10, 100)), "seq 1 folded");
        assert!(
            !in_delta_mine(&loaded, &hash_for(10, 300)),
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
        let loaded = load_generation(&source, &manifest, &[10, 11], MY_UID, 2, cache_dir().path())
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
        let loaded = load_generation(&source, &manifest, &[10, 11], MY_UID, 2, cache_dir().path())
            .await
            .unwrap();
        assert_eq!((loaded.delta_seq, loaded.chain_broken_at), (1, Some(2)));
        assert!(
            !in_delta_mine(&loaded, &hash_for(10, 300)),
            "no partial apply"
        );
        // A reader owning PG 10 alone is whole.
        let only_10 = load_generation(&source, &manifest, &[10], MY_UID, 2, cache_dir().path())
            .await
            .unwrap();
        assert_eq!((only_10.delta_seq, only_10.chain_broken_at), (2, None));
        assert!(in_delta_mine(&only_10, &hash_for(10, 300)));

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
        let loaded = load_generation(&source, &manifest, &[10, 11], MY_UID, 2, cache_dir().path())
            .await
            .unwrap();
        assert_eq!((loaded.delta_seq, loaded.chain_broken_at), (1, Some(2)));

        // No base_cut on a base that declares deltas: seq 1 cannot anchor.
        let dir = tempfile::tempdir().unwrap();
        let fx = write_generation_stamped(dir.path(), &key, 7, &[10, 11], 50, &unindexed());
        let source = DirListSource::new(dir.path());
        append_delta(dir.path(), &key, 7, 1, cut, cut + 3600, &[10, 11], &|pg| {
            vec![record_for(pg, 100)]
        });
        let manifest = fetch_manifest(&source, 7, &fx.validator_hex())
            .await
            .unwrap();
        assert_eq!(check_delta_chain(&manifest).unwrap_err().0, 1);
        let loaded = load_generation(&source, &manifest, &[10, 11], MY_UID, 2, cache_dir().path())
            .await
            .unwrap();
        assert_eq!((loaded.delta_seq, loaded.chain_broken_at), (0, Some(1)));
        assert!(!loaded.coverage_complete());
        assert!(!in_delta_mine(&loaded, &hash_for(10, 100)));
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
            load_generation(&source, &manifest, &[10, 11], MY_UID, 2, cache_dir().path())
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
        assert!(in_delta_mine(&loaded, &hash_for(10, 100)), "view kept");

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

    /// The live filter holds every record of every list: on the
    /// thirty-holder fixture the 290 records that are not this miner's
    /// answer "moved", and so do the shard hashes the base withholds from
    /// the lists (excluded, unplaceable files) although no holder set
    /// names them.
    #[tokio::test]
    async fn live_filter_holds_other_holders_and_withheld_hashes() {
        let dir = tempfile::tempdir().unwrap();
        let key = deterministic_key(1);
        let holder_of = |i: u32| 500 + (i % 30 + i / 30) % 30;
        let withheld: Vec<[u8; 32]> = (0..40).map(|i| hash_for(900, i)).collect();
        let stamps = Stamps {
            withheld: withheld.clone(),
            ..Stamps::default()
        };
        let fx = write_generation_with(dir.path(), &key, 7, &[10], &stamps, &|pg| {
            (0..300)
                .map(|i| record_held_by(pg, i, holder_of(i)))
                .collect()
        });
        let source = DirListSource::new(dir.path());
        let manifest = fetch_manifest(&source, 7, &fx.validator_hex())
            .await
            .unwrap();
        let loaded = load_generation(&source, &manifest, &[10], 500, 1, cache_dir().path())
            .await
            .unwrap();
        let sets = loaded.sets.as_ref().expect("sets loaded");
        assert_eq!((sets.generation(), sets.keys), (7, 10));
        assert_eq!(sets.withheld_hashes, 40);
        assert_eq!(loaded.total_hashes, 10);
        for i in 0..300 {
            let h = hash_for(10, i);
            assert!(loaded.may_be_held_by_other(&h), "record {i} is listed");
            assert_eq!(loaded.may_be_obliged(&h), holder_of(i) == 500, "{i}");
        }
        for h in &withheld {
            assert!(loaded.may_be_held_by_other(h), "withheld hash is live");
            assert!(!loaded.may_be_obliged(h), "withheld hash is in no set");
        }
        let strays = (0..10_000)
            .filter(|i| loaded.may_be_held_by_other(&hash_for(901, *i)))
            .count();
        assert!(strays < 1_000, "{strays} live filter hits on 10 000 strays");
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
        let fx = write_generation_stamped(dir.path(), &key, 7, &[1, 2, 3], 5, &unindexed());
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
            load_generation(&source, &manifest, &[10, 11], MY_UID, 2, cache_dir().path())
                .await
                .unwrap();
        assert_eq!((loaded.delta_seq, loaded.chain_broken_at), (2, None));
        assert!(loaded.coverage_complete());
        assert!((100..110).all(|i| in_delta_mine(&loaded, &hash_for(10, i))));
        assert!(in_delta_mine(&loaded, &hash_for(11, 200)));
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
        assert!(in_delta_mine(&loaded, &hash_for(10, 300)));

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
        assert!(in_delta_mine(&loaded, &hash_for(10, 300)));

        // A pointer whose cut does not match the delta's signed window is
        // refused too (fresh load, seq 1 mis-stamped).
        write_current_v2(dir.path(), 7, cut, &[(1, cut + 3601, sha1)]);
        let pointer = fetch_current(&source).await.unwrap();
        let skewed = fetch_manifest_at(&source, &pointer, &hex).await.unwrap();
        let fresh = load_generation(&source, &skewed, &[10, 11], MY_UID, 2, cache_dir().path())
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

    #[tokio::test]
    async fn load_generation_from_fixture_dir() {
        let dir = tempfile::tempdir().unwrap();
        let key = deterministic_key(1);
        let fx = write_generation_held(dir.path(), &key, 7, &[10, 11, 12], 100, &[10, 12]);
        let source = DirListSource::new(dir.path());

        assert_eq!(fetch_current_generation(&source).await.unwrap(), 7);
        let manifest = fetch_manifest(&source, 7, &fx.validator_hex())
            .await
            .unwrap();

        // Full coverage.
        let loaded = load_generation(&source, &manifest, &[10, 12], MY_UID, 2, cache_dir().path())
            .await
            .unwrap();
        assert!(loaded.coverage_complete());
        assert_eq!(loaded.listed_pgs, 2);
        assert_eq!(loaded.total_hashes, 200);
        assert!(loaded.may_be_obliged(&hash_for(10, 3)));
        assert!(loaded.may_be_obliged(&hash_for(12, 99)));
        // Another holder's PG: absent from this miner's (exact) set, all
        // present in the live filter.
        assert!((0..100).all(|i| !loaded.may_be_obliged(&hash_for(11, i))));
        assert!((0..100).all(|i| loaded.may_be_held_by_other(&hash_for(11, i))));

        // Partial coverage: PG 99 is not in the generation.
        let partial = load_generation(&source, &manifest, &[10, 99], MY_UID, 2, cache_dir().path())
            .await
            .unwrap();
        assert!(!partial.coverage_complete());
        assert_eq!(partial.missing_pgs, vec![99]);
        assert_eq!(
            partial.listed_pgs, 2,
            "PG 12 joins through the holder index"
        );
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
            ..Stamps::default()
        };
        let fx = write_generation_stamped(dir.path(), &key, 7, &[10], 5, &stamps);
        let source = DirListSource::new(dir.path());
        let manifest = fetch_manifest(&source, 7, &fx.validator_hex())
            .await
            .unwrap();
        let loaded = load_generation(&source, &manifest, &[10], MY_UID, 1, cache_dir().path())
            .await
            .unwrap();
        assert_eq!(loaded.created_at_secs, CREATED_AT_SECS);
        assert_eq!(loaded.snapshot_secs, CREATED_AT_SECS - 3 * 86_400);
        // Without the field the bound is the creation time.
        let fx = write_generation(dir.path(), &key, 8, &[10], 5);
        let manifest = fetch_manifest(&source, 8, &fx.validator_hex())
            .await
            .unwrap();
        let loaded = load_generation(&source, &manifest, &[10], MY_UID, 1, cache_dir().path())
            .await
            .unwrap();
        assert_eq!(loaded.snapshot_secs, CREATED_AT_SECS);
    }

    /// Every declaration the load trusts is checked before any fetch: a
    /// malformed holder set part or live filter declaration fails the load
    /// (a partial set would purge what the missing part lists), and so
    /// does a generation without a usable `created_at`.
    #[tokio::test]
    async fn load_generation_refuses_malformed_set_declarations() {
        let dir = tempfile::tempdir().unwrap();
        let key = deterministic_key(1);
        let fx = write_generation(dir.path(), &key, 7, &[10, 11], 20);
        let source = DirListSource::new(dir.path());
        let manifest = fetch_manifest(&source, 7, &fx.validator_hex())
            .await
            .unwrap();
        let src = &source;
        let load = |m: Manifest| async move {
            let cache = cache_dir();
            load_generation(src, &m, &[10, 11], MY_UID, 2, cache.path())
                .await
                .map(|_| ())
                .map_err(|e| format!("{e:#}"))
        };
        assert!(load(manifest.clone()).await.is_ok());

        let mut m = manifest.clone();
        m.holder_sets.as_mut().unwrap().get_mut(&MY_UID).unwrap()[0].path =
            common::hash_set_files::holder_set_path(MY_UID, 1);
        assert!(load(m).await.unwrap_err().contains("declared at"));

        let mut m = manifest.clone();
        m.holder_sets.as_mut().unwrap().get_mut(&MY_UID).unwrap()[0].size += 8;
        assert!(load(m).await.unwrap_err().contains("bytes for"));

        let mut m = manifest.clone();
        m.holder_sets.as_mut().unwrap().get_mut(&MY_UID).unwrap()[0].count = 0;
        assert!(load(m).await.unwrap_err().contains("declares 0 keys"));

        let mut m = manifest.clone();
        m.live_filter.as_mut().unwrap().shards.pop_last();
        assert!(load(m).await.unwrap_err().contains("255 shards"));

        let mut m = manifest.clone();
        m.live_filter.as_mut().unwrap().bit_count = MAX_LIST_BYTES * 8;
        assert!(load(m).await.unwrap_err().contains("byte limit"));

        let mut m = manifest.clone();
        m.live_filter = None;
        assert!(load(m).await.unwrap_err().contains("without live_filter"));

        // A header that disagrees with its (signed) declaration: the part
        // is verified by sha256, so only a declaration edit can produce
        // it; the load refuses it all the same.
        let mut m = manifest.clone();
        m.holder_sets.as_mut().unwrap().get_mut(&MY_UID).unwrap()[0].key_hi += 1;
        assert!(load(m).await.unwrap_err().contains("header names uid"));

        let mut undated = manifest.clone();
        undated.created_at = serde_json::Value::Null;
        assert!(load(undated).await.is_err());
    }

    #[tokio::test]
    async fn dir_source_refuses_oversized_file_before_reading() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join("big.bin"), vec![0u8; 4096]).unwrap();
        let source = DirListSource::new(dir.path());
        assert!(source.fetch("big.bin", 4095).await.is_err());
        assert_eq!(source.fetch("big.bin", 4096).await.unwrap().len(), 4096);
    }

    /// A generation with a holder index but without holder sets (a writer
    /// that predates them) loads, is never enforced (coverage incomplete),
    /// and answers "may be obliged" for every hash: no pass can run on it.
    #[tokio::test]
    async fn generation_without_sets_loads_but_never_covers() {
        let dir = tempfile::tempdir().unwrap();
        let key = deterministic_key(1);
        let fx = write_generation(dir.path(), &key, 7, &[10, 11], 20);
        let source = DirListSource::new(dir.path());
        let mut manifest = fetch_manifest(&source, 7, &fx.validator_hex())
            .await
            .unwrap();
        manifest.holder_sets = None;
        manifest.live_filter = None;
        let loaded = load_generation(&source, &manifest, &[10, 11], MY_UID, 2, cache_dir().path())
            .await
            .unwrap();
        assert!(loaded.sets.is_none());
        assert!(loaded.held_pgs.is_some(), "the holder index is loaded");
        assert!(loaded.missing_pgs.is_empty());
        assert!(!loaded.coverage_complete());
        let stray = hash_for(900, 1);
        assert!(loaded.may_be_obliged(&stray), "a miss would delete");
        assert!(!loaded.may_be_held_by_other(&stray));
    }

    /// A holder set part or live filter shard that fails its sha256, or
    /// is missing from the bucket, fails the load: nothing is mapped.
    #[tokio::test]
    async fn load_generation_fails_on_a_corrupted_or_missing_set_object() {
        let key = deterministic_key(1);
        let part = common::hash_set_files::holder_set_path(MY_UID, 0);
        let shard = common::hash_set_files::live_filter_path(17);
        for (object, damage) in [(&part, true), (&part, false), (&shard, true)] {
            let dir = tempfile::tempdir().unwrap();
            let fx = write_generation(dir.path(), &key, 7, &[10, 11], 20);
            let path = dir.path().join("gen/7").join(object);
            if damage {
                let mut body = std::fs::read(&path).unwrap();
                let last = body.len() - 1;
                body[last] ^= 0xff;
                std::fs::write(&path, &body).unwrap();
            } else {
                std::fs::remove_file(&path).unwrap();
            }
            let source = DirListSource::new(dir.path());
            let manifest = fetch_manifest(&source, 7, &fx.validator_hex())
                .await
                .unwrap();
            let err = load_generation(&source, &manifest, &[10, 11], MY_UID, 1, cache_dir().path())
                .await
                .unwrap_err();
            let msg = format!("{err:#}");
            if damage {
                assert!(msg.contains("sha256"), "{object}: {msg}");
            }
        }
    }

    /// The cache: a second load of the same generation makes no GET for
    /// the holder set or the live filter; a cached file altered on disk is
    /// fetched again; loading another generation prunes the first one's
    /// directory.
    #[tokio::test]
    async fn holder_sets_are_reused_from_the_cache_and_refetched_when_altered() {
        let dir = tempfile::tempdir().unwrap();
        let key = deterministic_key(1);
        let fx = write_generation(dir.path(), &key, 7, &[10, 11], 20);
        let cache = cache_dir();
        async fn load(source: &CountingSource, validator: &str, root: &Path) -> LoadedGeneration {
            let manifest = fetch_manifest(source, 7, validator).await.unwrap();
            load_generation(source, &manifest, &[10, 11], MY_UID, 4, root)
                .await
                .unwrap()
        }
        let validator = fx.validator_hex();
        let load = |source| load(source, &validator, cache.path());
        // The holder index (`holders/<uid>.pgs`) is fetched on every load;
        // the set parts live one level below it.
        let parts_prefix = format!("gen/7/holders/{MY_UID:010}/");
        let first = CountingSource::new(dir.path());
        let loaded = load(&first).await;
        let sets = loaded.sets.as_ref().unwrap();
        assert_eq!(sets.fetched_objects, 257, "one part and 256 shards");
        assert_eq!(sets.reused_objects, 0);
        assert_eq!(first.fetched_under("gen/7/live/").len(), 256);
        assert_eq!(first.fetched_under(&parts_prefix).len(), 1);

        let second = CountingSource::new(dir.path());
        let again = load(&second).await;
        let sets = again.sets.as_ref().unwrap();
        assert_eq!((sets.fetched_objects, sets.reused_objects), (0, 257));
        assert!(second.fetched_under("gen/7/live/").is_empty());
        assert!(second.fetched_under(&parts_prefix).is_empty());
        assert!((0..20).all(|i| again.may_be_obliged(&hash_for(10, i))));

        // Alter the cached part (a new inode: the mappings above stay
        // valid): it is fetched again, the shards are still reused.
        let cached = cache
            .path()
            .join("gen-7")
            .join(common::hash_set_files::holder_set_path(MY_UID, 0));
        let mut body = std::fs::read(&cached).unwrap();
        body[common::hash_set_files::HOLDER_SET_HEADER_LEN] ^= 1;
        std::fs::remove_file(&cached).unwrap();
        std::fs::write(&cached, &body).unwrap();
        let third = CountingSource::new(dir.path());
        let repaired = load(&third).await;
        let sets = repaired.sets.as_ref().unwrap();
        assert_eq!((sets.fetched_objects, sets.reused_objects), (1, 256));
        assert_eq!(third.fetched_under(&parts_prefix).len(), 1);
        assert!((0..20).all(|i| repaired.may_be_obliged(&hash_for(11, i))));

        // Generation 8 prunes the cache of generation 7.
        write_generation(dir.path(), &key, 8, &[10, 11], 20);
        let source = DirListSource::new(dir.path());
        let manifest = fetch_manifest(&source, 8, &fx.validator_hex())
            .await
            .unwrap();
        load_generation(&source, &manifest, &[10, 11], MY_UID, 4, cache.path())
            .await
            .unwrap();
        assert!(cache.path().join("gen-8").is_dir());
        assert!(!cache.path().join("gen-7").exists());
    }

    /// A holder set split over several parts: every key of every part is
    /// found, a key between two parts' ranges is not.
    #[tokio::test]
    async fn multi_part_holder_set_finds_every_key() {
        let dir = tempfile::tempdir().unwrap();
        let key = deterministic_key(1);
        let stamps = Stamps {
            part_max_keys: 7,
            ..Stamps::default()
        };
        let fx = write_generation_stamped(dir.path(), &key, 7, &[10, 11, 12], 10, &stamps);
        let source = DirListSource::new(dir.path());
        let manifest = fetch_manifest(&source, 7, &fx.validator_hex())
            .await
            .unwrap();
        let parts = &manifest.holder_sets.as_ref().unwrap()[&MY_UID];
        assert_eq!(parts.len(), 5, "30 keys by 7");
        let loaded = load_generation(
            &source,
            &manifest,
            &[10, 11, 12],
            MY_UID,
            2,
            cache_dir().path(),
        )
        .await
        .unwrap();
        assert_eq!(loaded.sets.as_ref().unwrap().keys, 30);
        for pg in [10, 11, 12] {
            assert!((0..10).all(|i| loaded.may_be_obliged(&hash_for(pg, i))));
        }
        let strays = (0..1000)
            .filter(|i| loaded.may_be_obliged(&hash_for(13, *i)))
            .count();
        assert_eq!(strays, 0);
    }

    /// Content addressing: a deleted file of one PG shares shard hashes
    /// with a live file of another PG (the PG is a function of the file
    /// hash). Its tombstone must not reach the pass while ANY record of
    /// the generation — this miner's or another holder's, in any PG —
    /// names the hash: the live filter spans the whole partition. Once
    /// the other file is deleted too (next generation, its record gone)
    /// the hash is tombstoned.
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
        let loaded = load_generation(&source, &manifest, &[10, 11], MY_UID, 2, cache_dir().path())
            .await
            .unwrap();
        assert_eq!(loaded.tombstone_pgs, 2);
        assert_eq!(loaded.tombstones_retained_live_ref, 2);
        assert_eq!(loaded.tombstones, vec![unreferenced]);
        assert!(
            !loaded.is_tombstoned(&held_by_other),
            "another holder's record"
        );
        assert!(!loaded.is_tombstoned(&held_by_me), "my own record");
        assert!(loaded.is_tombstoned(&unreferenced));
        // The live record is still enforced as a set entry.
        assert!(loaded.may_be_obliged(&held_by_me));
        assert!(!loaded.may_be_obliged(&held_by_other));
        assert!(loaded.may_be_held_by_other(&held_by_other));

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
        let loaded = load_generation(&source, &manifest, &[10, 11], MY_UID, 2, cache_dir().path())
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
            &unindexed(),
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
        let loaded = load_generation(&source, &manifest, &[10, 11], MY_UID, 2, cache_dir().path())
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
        let fx = write_generation_stamped(dir.path(), &key, 8, &[10, 11], 5, &unindexed());
        let source = DirListSource::new(dir.path());
        let manifest = fetch_manifest(&source, 8, &fx.validator_hex())
            .await
            .unwrap();
        let loaded = load_generation(&source, &manifest, &[10, 11], MY_UID, 2, cache_dir().path())
            .await
            .unwrap();
        assert_eq!((loaded.tombstone_pgs, loaded.tombstones.len()), (0, 0));
    }

    /// A header-only `.deleted` names no hash: it is counted without a
    /// GET, so its body may even be absent from the bucket.
    #[tokio::test]
    async fn header_only_tombstones_are_not_fetched() {
        let dir = tempfile::tempdir().unwrap();
        let key = deterministic_key(1);
        let fx = write_generation_with_tombstones(
            dir.path(),
            &key,
            7,
            &[10, 11],
            &Stamps::default(),
            &|pg| sorted_records(pg, 5),
            Some(&|pg| {
                if pg == 10 {
                    Vec::new()
                } else {
                    vec![hash_for(pg, 100)]
                }
            }),
        );
        let source = DirListSource::new(dir.path());
        let manifest = fetch_manifest(&source, 7, &fx.validator_hex())
            .await
            .unwrap();
        assert_eq!(
            manifest.objects["pg/00010.deleted"].size,
            TOMBSTONE_HEADER_LEN as u64
        );
        std::fs::remove_file(dir.path().join("gen/7/pg/00010.deleted")).unwrap();
        let loaded = load_generation(&source, &manifest, &[10, 11], MY_UID, 2, cache_dir().path())
            .await
            .unwrap();
        assert_eq!((loaded.tombstone_pgs, loaded.tombstones.len()), (2, 1));
        assert!(loaded.is_tombstoned(&hash_for(11, 100)));
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
        let intact = load_generation(&source, &manifest, &[10, 11], MY_UID, 2, cache_dir().path())
            .await
            .unwrap();
        assert_eq!(intact.tombstones.len(), 2);

        let path = dir.path().join("gen/7/pg/00011.deleted");
        let mut body = std::fs::read(&path).unwrap();
        body[TOMBSTONE_HEADER_LEN + 3] ^= 0xff;
        std::fs::write(&path, &body).unwrap();
        let loaded = load_generation(&source, &manifest, &[10, 11], MY_UID, 2, cache_dir().path())
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
        let fx = write_generation_stamped(dir.path(), &key, 7, &[10, 11, 12], 5, &unindexed());
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

        let loaded = load_generation(&source, &manifest, &[10, 11], MY_UID, 1, cache_dir().path())
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

    #[tokio::test]
    async fn transient_fetch_failures_are_retried_and_final_ones_are_not() {
        use std::sync::atomic::{AtomicU32, Ordering};
        let calls = AtomicU32::new(0);
        let body = with_retries(
            4,
            |_| std::time::Duration::ZERO,
            || {
                let n = calls.fetch_add(1, Ordering::SeqCst);
                async move {
                    if n < 2 {
                        Err(FetchFailure::Transient(anyhow!("truncated body")))
                    } else {
                        Ok(Bytes::from_static(b"list"))
                    }
                }
            },
        )
        .await
        .expect("third attempt succeeds");
        assert_eq!(&body[..], b"list");
        assert_eq!(calls.load(Ordering::SeqCst), 3);

        let calls = AtomicU32::new(0);
        let err = with_retries(
            4,
            |_| std::time::Duration::ZERO,
            || {
                calls.fetch_add(1, Ordering::SeqCst);
                async { Err::<Bytes, _>(FetchFailure::Final(anyhow!("HTTP 404"))) }
            },
        )
        .await
        .expect_err("a final failure is not retried");
        assert!(err.to_string().contains("404"));
        assert_eq!(calls.load(Ordering::SeqCst), 1);

        let calls = AtomicU32::new(0);
        with_retries(
            4,
            |_| std::time::Duration::ZERO,
            || {
                calls.fetch_add(1, Ordering::SeqCst);
                async { Err::<Bytes, _>(FetchFailure::Transient(anyhow!("reset"))) }
            },
        )
        .await
        .expect_err("transient failures give up after the attempt budget");
        assert_eq!(calls.load(Ordering::SeqCst), 4);
    }

    #[tokio::test(start_paused = true)]
    async fn fetch_sized_refetches_a_short_body() {
        use std::sync::atomic::{AtomicU32, Ordering};
        struct Flaky(AtomicU32);
        #[async_trait::async_trait]
        impl ListSource for Flaky {
            async fn fetch(&self, _rel_path: &str, _max_len: u64) -> Result<Bytes> {
                // First answer is cut short without any error, as a transfer
                // ended early with no Content-Length.
                Ok(if self.0.fetch_add(1, Ordering::SeqCst) == 0 {
                    Bytes::from_static(b"li")
                } else {
                    Bytes::from_static(b"list")
                })
            }
        }
        let flaky = Flaky(AtomicU32::new(0));
        assert_eq!(
            &fetch_sized(&flaky, "gen/1/pg/00001.list", 4).await.unwrap()[..],
            b"list"
        );
        assert_eq!(flaky.0.load(Ordering::SeqCst), 2);
        let always_short = Flaky(AtomicU32::new(0));
        let err = fetch_sized(&always_short, "x", 9)
            .await
            .expect_err("never the declared size");
        assert!(err.to_string().contains("manifest size 9"));
    }

    // ------------------------------------------------------------------
    // Delta bundles (format 2)
    // ------------------------------------------------------------------

    /// A [`DirListSource`] that records every path it serves.
    struct CountingSource {
        inner: DirListSource,
        fetched: std::sync::Mutex<Vec<String>>,
    }

    impl CountingSource {
        fn new(root: &std::path::Path) -> Self {
            Self {
                inner: DirListSource::new(root),
                fetched: std::sync::Mutex::new(Vec::new()),
            }
        }

        fn fetched_under(&self, prefix: &str) -> Vec<String> {
            self.fetched
                .lock()
                .unwrap()
                .iter()
                .filter(|path| path.starts_with(prefix))
                .cloned()
                .collect()
        }
    }

    #[async_trait::async_trait]
    impl ListSource for CountingSource {
        async fn fetch(&self, rel_path: &str, max_len: u64) -> Result<Bytes> {
            self.fetched.lock().unwrap().push(rel_path.to_string());
            self.inner.fetch(rel_path, max_len).await
        }
    }

    /// Base PGs 10, 11, 12 (bundle 000) and 300 (bundle 001); the reader
    /// owns 10 and 11. Delta 1 adds 10 records to each of the four.
    fn bundled_setup(dir: &std::path::Path) -> (Fixture, ed25519_dalek::SigningKey, u64) {
        let key = deterministic_key(1);
        let cut = CREATED_AT_SECS - 300;
        let fx = write_generation_stamped(dir, &key, 7, &[10, 11, 12, 300], 5, &unindexed());
        set_base_cut(dir, &key, 7, cut);
        (fx, key, cut)
    }

    fn ten_added(pg: u32) -> Vec<Record> {
        (100..110).map(|i| record_for(pg, i)).collect()
    }

    /// One GET for bundle 000 however many owned PGs it carries, none for
    /// bundle 001 (no owned PG in it), and only the owned sections are
    /// folded: PG 12's section sits in the fetched bundle but is skipped.
    #[tokio::test]
    async fn delta_bundle_is_fetched_once_and_only_enforced_sections_fold() {
        let dir = tempfile::tempdir().unwrap();
        let (fx, key, cut) = bundled_setup(dir.path());
        append_delta(
            dir.path(),
            &key,
            7,
            1,
            cut,
            cut + 3600,
            &[10, 11, 12, 300],
            &ten_added,
        );
        let source = CountingSource::new(dir.path());
        let manifest = fetch_manifest(&source, 7, &fx.validator_hex())
            .await
            .unwrap();
        let loaded = load_generation(&source, &manifest, &[10, 11], MY_UID, 4, cache_dir().path())
            .await
            .unwrap();
        assert_eq!((loaded.delta_seq, loaded.chain_broken_at), (1, None));
        assert!(loaded.missing_pgs.is_empty());
        assert!(!loaded.coverage_complete(), "set-less: never enforced");
        assert_eq!(
            source.fetched_under("delta/7/1/bundle/"),
            vec!["delta/7/1/bundle/000.added".to_string()]
        );
        assert_eq!(loaded.delta_records, 20, "sections of PGs 10 and 11 only");
        assert!((100..110).all(|i| in_delta_mine(&loaded, &hash_for(10, i))));
        assert!((100..110).all(|i| in_delta_mine(&loaded, &hash_for(11, i))));
        let foreign = (100..110)
            .filter(|i| in_delta_mine(&loaded, &hash_for(12, *i)))
            .count();
        assert_eq!(foreign, 0, "PG 12 not folded");

        // Gaining PG 300 fetches bundle 001 for it, once, and folds 10 more.
        let mut loaded = loaded;
        let manifest = fetch_manifest(&source, 7, &fx.validator_hex())
            .await
            .unwrap();
        source.fetched.lock().unwrap().clear();
        assert_eq!(
            loaded
                .add_pgs(&source, &manifest, &[10, 11, 300], MY_UID, 4)
                .await
                .unwrap(),
            1
        );
        assert_eq!(
            source.fetched_under("delta/7/1/bundle/"),
            vec!["delta/7/1/bundle/001.added".to_string()]
        );
        assert_eq!(loaded.delta_records, 30);
        assert!((100..110).all(|i| in_delta_mine(&loaded, &hash_for(300, i))));

        // A reader owning only PG 12 fetches the same bundle for it.
        source.fetched.lock().unwrap().clear();
        let only_12 = load_generation(&source, &manifest, &[12], MY_UID, 4, cache_dir().path())
            .await
            .unwrap();
        assert_eq!(only_12.delta_records, 10);
        assert_eq!(
            source.fetched_under("delta/7/1/bundle/"),
            vec!["delta/7/1/bundle/000.added".to_string()]
        );
    }

    /// Chain delta 1 built from `unsigned` (already altered by the test)
    /// and load PGs 10, 11: the result and the bundles fetched.
    async fn load_with_delta(
        dir: &std::path::Path,
        fx: &Fixture,
        key: &ed25519_dalek::SigningKey,
        cut: u64,
        unsigned: &serde_json::Value,
    ) -> (LoadedGeneration, Vec<String>, String) {
        let (sha, size) = write_signed_delta(dir, key, 7, 1, unsigned);
        chain_delta(dir, key, 7, 1, cut, cut + 3600, sha, size);
        let source = CountingSource::new(dir);
        let manifest = fetch_manifest(&source, 7, &fx.validator_hex())
            .await
            .unwrap();
        let loaded = load_generation(&source, &manifest, &[10, 11], MY_UID, 4, cache_dir().path())
            .await
            .unwrap();
        let fetched = source.fetched_under("delta/7/1/bundle/");
        let parse_error = match fetch_delta_manifest(&source, &manifest, &manifest.deltas[0]).await
        {
            Ok(_) => String::new(),
            Err(error) => format!("{error:#}"),
        };
        (loaded, fetched, parse_error)
    }

    /// A malformed or unsupported delta manifest is refused at parse,
    /// before any bundle is fetched: the chain breaks at that seq and the
    /// base alone stays enforced (coverage incomplete, no purge).
    #[tokio::test]
    async fn delta_manifest_layout_is_verified_before_any_fetch() {
        type Alter = Box<dyn Fn(&mut serde_json::Value)>;
        let b0 = "bundle/000.added";
        let cases: Vec<(&str, &str, Alter)> = vec![
            (
                "format 1",
                "format 1 is not supported",
                Box::new(|v| v["format"] = serde_json::json!(1)),
            ),
            (
                "format 3",
                "format 3 is not supported",
                Box::new(|v| v["format"] = serde_json::json!(3)),
            ),
            (
                "format missing",
                "missing field `format`",
                Box::new(|v| {
                    v.as_object_mut().unwrap().remove("format");
                }),
            ),
            (
                "format 1 objects map",
                "unknown field `objects`",
                Box::new(|v| {
                    let object = v.as_object_mut().unwrap();
                    object.remove("format");
                    object.remove("bundles");
                    object.insert("objects".into(), serde_json::json!({}));
                }),
            ),
            (
                "unknown key",
                "unknown field `objects`",
                Box::new(|v| v["objects"] = serde_json::json!({})),
            ),
            (
                "overlapping sections",
                "sections must be contiguous",
                Box::new(move |v| v["bundles"][b0]["pgs"][1]["offset"] = serde_json::json!(40)),
            ),
            (
                "unsorted sections",
                "strictly ascending by PG",
                Box::new(move |v| {
                    v["bundles"][b0]["pgs"][0]["pg"] = serde_json::json!(11);
                    v["bundles"][b0]["pgs"][1]["pg"] = serde_json::json!(10);
                }),
            ),
            (
                "section outside the bundle's range",
                "belongs to bundle 0",
                Box::new(move |v| {
                    let bundle = v["bundles"][b0].take();
                    v["bundles"]["bundle/002.added"] = bundle;
                    v["bundles"].as_object_mut().unwrap().remove(b0);
                }),
            ),
            (
                "bundle past the PG count",
                "out of range for 16384 PGs",
                Box::new(|v| {
                    let bundle = v["bundles"]["bundle/001.added"].take();
                    v["bundles"]["bundle/064.added"] = bundle;
                    v["bundles"]
                        .as_object_mut()
                        .unwrap()
                        .remove("bundle/001.added");
                }),
            ),
            (
                "section of an uncovered PG",
                "outside the delta's coverage",
                Box::new(|v| v["pgs"] = serde_json::json!([10, 11, 300])),
            ),
            (
                "sections short of the bundle",
                "sections cover",
                Box::new(move |v| {
                    let size = v["bundles"][b0]["size"].as_u64().unwrap();
                    v["bundles"][b0]["size"] = serde_json::json!(size + 40);
                }),
            ),
            (
                "bundle above the body limit",
                "outside 1..=",
                Box::new(|v| {
                    v["bundles"]["bundle/001.added"]["size"] =
                        serde_json::json!(MAX_LIST_BYTES + 1);
                }),
            ),
        ];
        for (what, expected, alter) in cases {
            let dir = tempfile::tempdir().unwrap();
            let (fx, key, cut) = bundled_setup(dir.path());
            let mut unsigned = write_delta_bundles(
                dir.path(),
                7,
                1,
                cut,
                cut + 3600,
                &[10, 11, 12, 300],
                &ten_added,
            );
            alter(&mut unsigned);
            let (loaded, fetched, error) =
                load_with_delta(dir.path(), &fx, &key, cut, &unsigned).await;
            assert!(error.contains(expected), "{what}: {error}");
            assert_eq!(
                (loaded.delta_seq, loaded.chain_broken_at),
                (0, Some(1)),
                "{what}"
            );
            assert!(!loaded.coverage_complete(), "{what}");
            assert!(fetched.is_empty(), "{what}: fetched {fetched:?}");
            assert_eq!(loaded.delta_records, 0, "{what}");
        }
    }

    /// A section whose bytes do not match its declared digest (the bundle
    /// digest matching the bytes), or a bundle whose bytes do not match
    /// its own digest, fails the whole delta: no section of it is folded.
    #[tokio::test]
    async fn tampered_bundle_or_section_fails_the_whole_delta() {
        // Section digest wrong, bundle digest right.
        let dir = tempfile::tempdir().unwrap();
        let (fx, key, cut) = bundled_setup(dir.path());
        let mut unsigned = write_delta_bundles(
            dir.path(),
            7,
            1,
            cut,
            cut + 3600,
            &[10, 11, 12, 300],
            &ten_added,
        );
        unsigned["bundles"]["bundle/000.added"]["pgs"][1]["sha256"] =
            serde_json::json!("00".repeat(32));
        let (loaded, fetched, error) = load_with_delta(dir.path(), &fx, &key, cut, &unsigned).await;
        assert!(error.is_empty(), "the layout itself is valid: {error}");
        assert_eq!((loaded.delta_seq, loaded.chain_broken_at), (0, Some(1)));
        assert_eq!(fetched.len(), 1, "fetched, then refused");
        assert_eq!(loaded.delta_records, 0);

        // Bundle bytes altered after publication: its digest fails first.
        let dir = tempfile::tempdir().unwrap();
        let (fx, key, cut) = bundled_setup(dir.path());
        let unsigned = write_delta_bundles(
            dir.path(),
            7,
            1,
            cut,
            cut + 3600,
            &[10, 11, 12, 300],
            &ten_added,
        );
        let path = dir.path().join("delta/7/1/bundle/000.added");
        let mut bytes = std::fs::read(&path).unwrap();
        let last = bytes.len() - 1;
        bytes[last] ^= 1;
        std::fs::write(&path, &bytes).unwrap();
        let (loaded, _, _) = load_with_delta(dir.path(), &fx, &key, cut, &unsigned).await;
        assert_eq!((loaded.delta_seq, loaded.chain_broken_at), (0, Some(1)));
        assert_eq!(loaded.delta_records, 0);
    }

    /// A reader built before format 2 parses the delta manifest with a
    /// required `objects` map: a format-2 manifest has none, the parse
    /// fails, and that reader breaks the chain (fail closed, no purge)
    /// instead of reading a delta as empty.
    #[test]
    fn pre_bundle_reader_fails_closed_on_a_format_2_manifest() {
        #[derive(Deserialize)]
        #[allow(dead_code)]
        struct PreBundleDeltaManifest {
            generation: u64,
            seq: u64,
            #[serde(default)]
            since: serde_json::Value,
            #[serde(default)]
            until: serde_json::Value,
            #[serde(default)]
            created_at: serde_json::Value,
            pg_count: u32,
            ec_k: u8,
            ec_m: u8,
            pgs: Vec<u32>,
            objects: BTreeMap<String, ObjectEntry>,
            #[serde(default)]
            signature: Option<String>,
        }
        let dir = tempfile::tempdir().unwrap();
        let unsigned = write_delta_bundles(dir.path(), 7, 1, 1, 3601, &[10, 11, 300], &ten_added);
        let signed = sign_manifest(&deterministic_key(1), &unsigned);
        let error = serde_json::from_value::<PreBundleDeltaManifest>(signed.clone())
            .err()
            .expect("a pre-bundle reader must refuse a format-2 manifest");
        assert!(
            error.to_string().contains("missing field `objects`"),
            "{error}"
        );
        // This reader accepts it.
        let parsed: DeltaManifest = serde_json::from_value(signed).unwrap();
        parsed.check_layout().unwrap();
        assert_eq!(parsed.format, DELTA_FORMAT);
        assert_eq!(parsed.bundles.len(), 2);
    }
}

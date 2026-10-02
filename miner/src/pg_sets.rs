//! Holder sets and live filter of a base generation, cached on disk and
//! memory-mapped.
//!
//! A base generation over the whole partition declares, next to its
//! per-PG lists (codec `common::hash_set_files`, layout in
//! `pg-lists/README.md`):
//!
//! - `holder_sets`: per uid, the sorted 64-bit keys (`blob_hash[0..8]`, LE)
//!   of every record naming it in any list, in parts
//!   `gen/<g>/holders/<uid 10 digits>/<part 3 digits>.hashes` (`APGS`);
//! - `live_filter`: a Bloom filter over the hash of every record of every
//!   list plus the shards the base withholds from the lists (excluded,
//!   unplaceable files), in 256 shards `gen/<g>/live/<shard 3 digits>.bloom`
//!   (`APGF`, shard = `blob_hash[0]`).
//!
//! [`GenerationSets::load`] fetches only this miner's parts and the 256
//! shards, checks each against the signed manifest (size, sha256, header),
//! stores it under `<cache_root>/gen-<g>/` (the same relative path as in
//! the bucket) and maps it read-only. A restart reuses a cached object
//! whose size and sha256 still match the manifest, without a GET; a cached
//! object that does not is fetched again. [`GenerationSets::verify`]
//! re-hashes every mapping against the signed digests (the purge runs it
//! before each pass: a cache file damaged after the load drops the
//! coverage until a reload refetches it). Once a generation has loaded,
//! the cache directories of every other generation are removed (a mapping
//! still open on them stays valid until dropped).
//!
//! Lookups: [`GenerationSets::holds`] (key in this miner's set: binary
//! search in the part whose range holds the key) and
//! [`GenerationSets::is_live`] (live filter probe). A 64-bit key match and
//! a Bloom hit are both "may": the purge treats them as a keep.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};

use anyhow::{Context, Result, bail, ensure};
use common::hash_set_files::{
    HOLDER_SET_HEADER_LEN, HOLDER_SET_PART_MAX_KEYS, HolderSetView, LIVE_FILTER_HEADER_LEN,
    LIVE_FILTER_SHARDS, LiveFilterView, blob_key, bloom_bytes, bloom_positions, holder_set_path,
    live_filter_path, live_filter_shard,
};
use serde::Deserialize;
use sha2::{Digest, Sha256};
use tracing::{debug, info, warn};

use crate::pg_lists::{ListSource, MAX_LIST_BYTES, Manifest, ObjectEntry, fetch_sized};

/// One part of a uid's holder set, as the manifest declares it.
#[derive(Debug, Clone, Deserialize, PartialEq, Eq)]
pub struct HolderSetEntry {
    /// Relative to the generation (`holders/<uid>/<part>.hashes`).
    pub path: String,
    pub sha256: String,
    pub size: u64,
    pub count: u64,
    pub key_lo: u64,
    pub key_hi: u64,
}

/// The live filter as the manifest declares it.
#[derive(Debug, Clone, Deserialize, PartialEq, Eq)]
pub struct LiveFilterEntry {
    /// Target false-positive rate, parts per million.
    pub fp_ppm: u64,
    pub probes: u32,
    /// Bits of every shard.
    pub bit_count: u64,
    /// Shard hashes of withheld files (excluded, unplaceable) inserted.
    #[serde(default)]
    pub withheld_hashes: u64,
    /// `"live/000.bloom" -> {sha256, size}`, all 256 shards.
    pub shards: BTreeMap<String, ObjectEntry>,
}

/// Directory name of a generation's cache under the cache root.
fn gen_dir_name(generation: u64) -> String {
    format!("gen-{generation}")
}

/// One mapped part of this miner's holder set.
#[derive(Debug)]
struct MappedPart {
    key_lo: u64,
    key_hi: u64,
    count: usize,
    map: memmap2::Mmap,
    /// Path relative to the generation and signed sha256.
    relative: String,
    sha256: [u8; 32],
}

impl MappedPart {
    fn key(&self, index: usize) -> u64 {
        let at = HOLDER_SET_HEADER_LEN + index * 8;
        u64::from_le_bytes(self.map[at..at + 8].try_into().expect("8 bytes"))
    }

    fn contains(&self, key: u64) -> bool {
        let (mut lo, mut hi) = (0usize, self.count);
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

/// This miner's holder set and the live filter of one generation, mapped
/// from the local cache.
#[derive(Debug)]
pub struct GenerationSets {
    generation: u64,
    parts: Vec<MappedPart>,
    /// Index = shard.
    shards: Vec<memmap2::Mmap>,
    /// Index = shard: path relative to the generation and signed sha256.
    shard_digests: Vec<(String, [u8; 32])>,
    bit_count: u64,
    probes: u32,
    /// Keys in this miner's set.
    pub keys: u64,
    /// Bytes of the 256 live filter shards.
    pub live_bytes: u64,
    /// Withheld shard hashes the live filter declares.
    pub withheld_hashes: u64,
    /// Objects fetched from the bucket by this load, and their bytes.
    pub fetched_objects: usize,
    pub fetched_bytes: u64,
    /// Objects reused from the local cache without a GET.
    pub reused_objects: usize,
}

impl GenerationSets {
    /// Generation the sets belong to.
    pub fn generation(&self) -> u64 {
        self.generation
    }

    /// Whether `hash`'s key is in this miner's holder set (a 64-bit prefix
    /// match: "may hold", a keep).
    pub fn holds(&self, hash: &[u8; 32]) -> bool {
        let key = blob_key(hash);
        let i = self.parts.partition_point(|part| part.key_hi < key);
        self.parts
            .get(i)
            .is_some_and(|part| part.key_lo <= key && part.contains(key))
    }

    /// Whether `hash` may be listed anywhere in the generation or withheld
    /// by it (`false` = listed nowhere).
    pub fn is_live(&self, hash: &[u8; 32]) -> bool {
        let bits = &self.shards[live_filter_shard(hash) as usize][LIVE_FILTER_HEADER_LEN..];
        bloom_positions(hash, self.bit_count, self.probes)
            .all(|pos| bits[(pos >> 3) as usize] & (1u8 << (pos & 7)) != 0)
    }

    /// Re-hash every mapped part and shard against the sha256 the signed
    /// manifest declared for it. A mapping reflects its file: a cache file
    /// modified or truncated after the load reads differently (or faults)
    /// from then on, and this is how the purge notices before a pass.
    /// CPU and I/O bound (the mapped bytes are read once): run it off the
    /// async runtime.
    pub fn verify(&self) -> Result<()> {
        let parts = self
            .parts
            .iter()
            .map(|part| (&part.map, part.relative.as_str(), &part.sha256));
        let shards = self
            .shards
            .iter()
            .zip(&self.shard_digests)
            .map(|(map, (relative, sha256))| (map, relative.as_str(), sha256));
        for (map, relative, expected) in parts.chain(shards) {
            let digest: [u8; 32] = Sha256::digest(&map[..]).into();
            ensure!(
                digest == *expected,
                "generation {}: mapped {relative} no longer matches its signed sha256 (cache file modified after the load)",
                self.generation
            );
        }
        Ok(())
    }

    /// Mapped bytes (this miner's parts plus the live filter).
    pub fn mapped_bytes(&self) -> u64 {
        self.live_bytes + self.parts.iter().map(|p| p.map.len() as u64).sum::<u64>()
    }

    /// Fetch (or reuse from `cache_root`), verify and map `uid`'s holder
    /// set parts and the live filter shards `manifest` declares.
    /// `Ok(None)` when the manifest declares no sets, or declares them
    /// over a subset of the partition (never trusted, like the holder
    /// index). Any declaration, fetch or verification failure is an error:
    /// a partial set would purge what the missing part lists.
    ///
    /// A uid declared with no parts (`"7": []`) has an empty set. A uid
    /// the manifest does not declare at all is not covered (`Ok(None)`,
    /// logged): the writer declares every uid of its map, so an absent uid
    /// means the sets were built without this miner's uid (for instance a
    /// map newer than the generation), never that it holds nothing.
    pub async fn load(
        source: &dyn ListSource,
        manifest: &Manifest,
        uid: u32,
        cache_root: &Path,
        concurrency: usize,
    ) -> Result<Option<Self>> {
        let (holder_sets, live) = match (&manifest.holder_sets, &manifest.live_filter) {
            (None, None) => return Ok(None),
            (Some(sets), Some(live)) => (sets, live),
            _ => bail!("manifest declares holder_sets without live_filter or the reverse"),
        };
        if manifest.holders.is_none() || !crate::pg_lists::covers_partition_of(manifest) {
            warn!(
                generation = manifest.generation,
                "pg-lists: holder sets declared on a generation without a holder index over the whole partition: ignored"
            );
            return Ok(None);
        }
        let Some(parts) = holder_sets.get(&uid) else {
            warn!(
                generation = manifest.generation,
                uid,
                declared_uids = holder_sets.len(),
                "pg-lists: the holder sets do not declare this miner's uid: not covered"
            );
            return Ok(None);
        };
        let parts: &[HolderSetEntry] = parts.as_slice();
        check_parts(parts, uid)?;
        check_live_filter(live)?;

        let generation = manifest.generation;
        let dir = cache_root.join(gen_dir_name(generation));
        tokio::fs::create_dir_all(&dir)
            .await
            .with_context(|| format!("create {}", dir.display()))?;
        let mut sets = Self {
            generation,
            parts: Vec::with_capacity(parts.len()),
            shards: Vec::with_capacity(LIVE_FILTER_SHARDS as usize),
            shard_digests: Vec::with_capacity(LIVE_FILTER_SHARDS as usize),
            bit_count: live.bit_count,
            probes: live.probes,
            keys: 0,
            live_bytes: 0,
            withheld_hashes: live.withheld_hashes,
            fetched_objects: 0,
            fetched_bytes: 0,
            reused_objects: 0,
        };

        for (index, entry) in parts.iter().enumerate() {
            let object = Declared {
                relative: entry.path.clone(),
                sha256: entry.sha256.clone(),
                size: entry.size,
            };
            let sha256 = object.digest()?;
            let (map, fetched) = obtain(source, generation, &dir, &object).await?;
            sets.count_object(fetched, entry.size);
            // The parse checks the order of every key (up to 128 MiB of
            // mapped pages read from disk): off the runtime workers.
            let (header, count) = crate::helpers::blocking(|| {
                HolderSetView::parse(&map).map(|view| (*view.header(), view.len()))
            })
            .with_context(|| format!("holder set {}", entry.path))?;
            ensure!(
                header.uid == uid
                    && header.part as usize == index
                    && header.generation == generation
                    && header.count == entry.count
                    && header.key_lo == entry.key_lo
                    && header.key_hi == entry.key_hi,
                "holder set {}: header names uid {} part {} generation {} count {} keys {}..={}, the manifest declares uid {uid} part {index} generation {generation} count {} keys {}..={}",
                entry.path,
                header.uid,
                header.part,
                header.generation,
                header.count,
                header.key_lo,
                header.key_hi,
                entry.count,
                entry.key_lo,
                entry.key_hi
            );
            sets.keys += entry.count;
            sets.parts.push(MappedPart {
                key_lo: entry.key_lo,
                key_hi: entry.key_hi,
                count,
                map,
                relative: object.relative,
                sha256,
            });
        }

        use futures::StreamExt;
        let dir_ref = &dir;
        let mut fetches = futures::stream::iter((0..LIVE_FILTER_SHARDS).map(|shard| {
            let path = live_filter_path(shard);
            let entry = live.shards[&path].clone();
            async move {
                let object = Declared {
                    relative: path,
                    sha256: entry.sha256,
                    size: entry.size,
                };
                let outcome = obtain(source, generation, dir_ref, &object).await;
                (shard, object, outcome)
            }
        }))
        .buffer_unordered(concurrency.max(1));
        let mut shards: Vec<Option<(memmap2::Mmap, String, [u8; 32])>> =
            (0..LIVE_FILTER_SHARDS).map(|_| None).collect();
        while let Some((shard, object, outcome)) = fetches.next().await {
            let (map, fetched) = outcome?;
            sets.count_object(fetched, object.size);
            let view = LiveFilterView::parse(&map)
                .with_context(|| format!("live filter {}", object.relative))?;
            let header = view.header();
            ensure!(
                header.shard == shard
                    && header.generation == generation
                    && header.bit_count == live.bit_count
                    && header.probes == live.probes
                    && header.fp_ppm == live.fp_ppm,
                "live filter {}: header names shard {} generation {} bits {} probes {} fp_ppm {}, the manifest declares shard {shard} generation {generation} bits {} probes {} fp_ppm {}",
                object.relative,
                header.shard,
                header.generation,
                header.bit_count,
                header.probes,
                header.fp_ppm,
                live.bit_count,
                live.probes,
                live.fp_ppm
            );
            sets.live_bytes += map.len() as u64;
            let sha256 = object.digest()?;
            shards[shard as usize] = Some((map, object.relative, sha256));
        }
        drop(fetches);
        for mapped in shards {
            let (map, relative, sha256) = mapped.expect("every shard mapped");
            sets.shards.push(map);
            sets.shard_digests.push((relative, sha256));
        }

        prune_other_generations(cache_root, generation).await;
        info!(
            generation,
            parts = sets.parts.len(),
            keys = sets.keys,
            live_bytes = sets.live_bytes,
            withheld_hashes = sets.withheld_hashes,
            fetched_objects = sets.fetched_objects,
            fetched_bytes = sets.fetched_bytes,
            reused_objects = sets.reused_objects,
            cache = %dir.display(),
            "pg-lists: holder set and live filter mapped"
        );
        Ok(Some(sets))
    }

    fn count_object(&mut self, fetched: bool, size: u64) {
        if fetched {
            self.fetched_objects += 1;
            self.fetched_bytes += size;
        } else {
            self.reused_objects += 1;
        }
    }
}

/// `uid`'s parts must be numbered from 0 at their canonical paths, framed
/// (`size = 48 + 8 * count`, `count` in 1..=16 Mi) and in ascending,
/// disjoint key ranges.
fn check_parts(parts: &[HolderSetEntry], uid: u32) -> Result<()> {
    let mut previous_hi: Option<u64> = None;
    for (index, entry) in parts.iter().enumerate() {
        let part = u32::try_from(index).context("holder set part index")?;
        ensure!(
            entry.path == holder_set_path(uid, part),
            "holder set part {index} of uid {uid} declared at {}",
            entry.path
        );
        ensure!(
            (1..=HOLDER_SET_PART_MAX_KEYS as u64).contains(&entry.count),
            "holder set {} declares {} keys",
            entry.path,
            entry.count
        );
        ensure!(
            entry.size == HOLDER_SET_HEADER_LEN as u64 + 8 * entry.count,
            "holder set {} declares {} bytes for {} keys",
            entry.path,
            entry.size,
            entry.count
        );
        ensure!(
            entry.key_lo <= entry.key_hi && previous_hi.is_none_or(|hi| hi < entry.key_lo),
            "holder set {} key range {}..={} is not ascending and disjoint",
            entry.path,
            entry.key_lo,
            entry.key_hi
        );
        previous_hi = Some(entry.key_hi);
    }
    Ok(())
}

/// Exactly the 256 canonical shards, each framed for `bit_count`, bounded
/// by [`MAX_LIST_BYTES`], `probes` in 1..=16.
fn check_live_filter(live: &LiveFilterEntry) -> Result<()> {
    ensure!(
        (1..=16).contains(&live.probes),
        "live filter declares {} probes",
        live.probes
    );
    ensure!(live.bit_count > 0, "live filter declares zero bits");
    let size = LIVE_FILTER_HEADER_LEN as u64 + bloom_bytes(live.bit_count);
    ensure!(
        size <= MAX_LIST_BYTES,
        "live filter shards of {size} bytes exceed the {MAX_LIST_BYTES} byte limit"
    );
    ensure!(
        live.shards.len() == LIVE_FILTER_SHARDS as usize,
        "live filter declares {} shards, not {LIVE_FILTER_SHARDS}",
        live.shards.len()
    );
    for shard in 0..LIVE_FILTER_SHARDS {
        let path = live_filter_path(shard);
        let Some(entry) = live.shards.get(&path) else {
            bail!("live filter does not declare {path}");
        };
        ensure!(
            entry.size == size,
            "live filter {path} declares {} bytes, {size} expected for {} bits",
            entry.size,
            live.bit_count
        );
    }
    Ok(())
}

/// An object to obtain: its path relative to the generation, digest and
/// size from the signed manifest.
struct Declared {
    relative: String,
    sha256: String,
    size: u64,
}

impl Declared {
    /// The declared sha256, decoded.
    fn digest(&self) -> Result<[u8; 32]> {
        let mut expected = [0u8; 32];
        hex::decode_to_slice(&self.sha256, &mut expected)
            .with_context(|| format!("{}: declared sha256 is not hex", self.relative))?;
        Ok(expected)
    }
}

/// The mapped object, from the cache when it holds the declared bytes,
/// else fetched, verified and written to the cache first. The flag is
/// `true` when a GET was made.
async fn obtain(
    source: &dyn ListSource,
    generation: u64,
    dir: &Path,
    object: &Declared,
) -> Result<(memmap2::Mmap, bool)> {
    let expected = object.digest()?;
    let local = dir.join(&object.relative);
    let size = object.size;
    let cached = {
        let local = local.clone();
        tokio::task::spawn_blocking(move || map_if_valid(&local, size, &expected))
            .await
            .context("cache check task")??
    };
    if let Some(map) = cached {
        debug!(path = %local.display(), "pg-lists: cached object reused");
        return Ok((map, false));
    }
    let remote = format!("gen/{generation}/{}", object.relative);
    let bytes = fetch_sized(source, &remote, size).await?;
    let map = tokio::task::spawn_blocking(move || write_and_map(&local, &bytes, &expected))
        .await
        .context("cache write task")?
        .with_context(|| remote.clone())?;
    Ok((map, true))
}

/// Map `path` read-only if it exists with `size` bytes and `expected`
/// sha256; a stale or damaged copy is removed (`Ok(None)`).
fn map_if_valid(path: &Path, size: u64, expected: &[u8; 32]) -> Result<Option<memmap2::Mmap>> {
    let file = match std::fs::File::open(path) {
        Ok(file) => file,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(e) => return Err(e).with_context(|| format!("open {}", path.display())),
    };
    let len = file
        .metadata()
        .with_context(|| format!("stat {}", path.display()))?
        .len();
    if len == size {
        // SAFETY: the cache directory belongs to this process; its files
        // are written once through a rename and never modified in place.
        let map = unsafe { memmap2::Mmap::map(&file) }
            .with_context(|| format!("mmap {}", path.display()))?;
        let digest: [u8; 32] = Sha256::digest(&map[..]).into();
        if digest == *expected {
            return Ok(Some(map));
        }
    }
    warn!(
        path = %path.display(),
        len,
        size,
        "pg-lists: cached object does not match the manifest: fetching it again"
    );
    std::fs::remove_file(path).with_context(|| format!("remove {}", path.display()))?;
    Ok(None)
}

/// Unique suffix of temporary cache files.
static TMP_COUNTER: AtomicU64 = AtomicU64::new(0);

/// Verify `bytes` against `expected`, write them to `path` through a
/// temporary file and a rename, and map the result read-only.
fn write_and_map(path: &Path, bytes: &[u8], expected: &[u8; 32]) -> Result<memmap2::Mmap> {
    let digest: [u8; 32] = Sha256::digest(bytes).into();
    if digest != *expected {
        bail!(
            "sha256 {} but the manifest declares {}",
            hex::encode(digest),
            hex::encode(expected)
        );
    }
    let parent = path.parent().context("cache path has no parent")?;
    std::fs::create_dir_all(parent).with_context(|| format!("create {}", parent.display()))?;
    let tmp: PathBuf = parent.join(format!(
        ".{}.tmp-{}-{}",
        path.file_name()
            .map(|n| n.to_string_lossy().into_owned())
            .unwrap_or_default(),
        std::process::id(),
        TMP_COUNTER.fetch_add(1, Ordering::Relaxed)
    ));
    let written = (|| -> Result<()> {
        use std::io::Write;
        let mut file = std::fs::File::create(&tmp)?;
        file.write_all(bytes)?;
        file.sync_all()?;
        std::fs::rename(&tmp, path)?;
        Ok(())
    })();
    if let Err(e) = written {
        let _ = std::fs::remove_file(&tmp);
        return Err(e).with_context(|| format!("write {}", path.display()));
    }
    let file = std::fs::File::open(path).with_context(|| format!("open {}", path.display()))?;
    // SAFETY: as in `map_if_valid`.
    let map =
        unsafe { memmap2::Mmap::map(&file) }.with_context(|| format!("mmap {}", path.display()))?;
    ensure!(
        map.len() == bytes.len(),
        "{}: {} bytes mapped, {} written",
        path.display(),
        map.len(),
        bytes.len()
    );
    Ok(map)
}

/// Remove the cache directories of every generation but `keep`. Failures
/// are logged: a leftover directory only costs disk.
async fn prune_other_generations(cache_root: &Path, keep: u64) {
    let keep_name = gen_dir_name(keep);
    let mut entries = match tokio::fs::read_dir(cache_root).await {
        Ok(entries) => entries,
        Err(e) => {
            warn!(root = %cache_root.display(), error = %e, "pg-lists: cache root unreadable, old generations not pruned");
            return;
        }
    };
    loop {
        let entry = match entries.next_entry().await {
            Ok(Some(entry)) => entry,
            Ok(None) => break,
            Err(e) => {
                warn!(root = %cache_root.display(), error = %e, "pg-lists: cache root listing failed");
                break;
            }
        };
        let name = entry.file_name().to_string_lossy().into_owned();
        if name == keep_name || !name.starts_with("gen-") {
            continue;
        }
        match tokio::fs::remove_dir_all(entry.path()).await {
            Ok(()) => {
                info!(dir = %entry.path().display(), "pg-lists: cache of an older generation removed")
            }
            Err(e) => {
                warn!(dir = %entry.path().display(), error = %e, "pg-lists: cache of an older generation not removed")
            }
        }
    }
}

//! Obligation-list backfill loop: fetch listed blobs this miner lacks.
//!
//! Mirror of `pg_purge`. Every `BACKFILL_PASS_INTERVAL_SECS` a pass walks
//! the owned PGs of the current signed generation from the persisted
//! cursor and collects the listed blobs this miner holds whose hash is
//! absent from the SQLite inventory (the filesystem is never scanned).
//! Up to `BACKFILL_DISCOVERY_CONCURRENCY` lists are fetched, verified,
//! decoded and looked up at once (one batched lookup per list on a
//! read-only inventory connection, in the blocking pool), but their
//! results are consumed in PG order, so the cursor semantics are those of
//! a sequential walk. Candidates are fetched while discovery goes on: each
//! is first looked up in the set-aside local flat roots
//! (`BACKFILL_LOCAL_SOURCE_DIRS`, direct path probes, own concurrency),
//! then, if unresolved, fetched from up to `BACKFILL_PEERS_PER_BLOB` peers
//! placed on the same PG; either way blake3 and the listed length are
//! verified and the blob is stored under the per-hash write lock. A pass
//! collects at most `BACKFILL_MAX_PENDING` candidates. The cursor advances
//! past every fully scanned PG so the next pass resumes there; a PG cut by
//! the cap is rescanned (its fetched blobs are then in the inventory and
//! no longer candidates). A move of the epoch stops the discovery (the
//! owned set is stale) but the candidates already collected are fetched.
//!
//! Interaction with the purge: none on data (the purge only deletes
//! unlisted blobs, the backfill only stores listed ones, both from the
//! same generation), but the backfill waits while a purge pass runs and
//! while the blob volume has less than `BACKFILL_MIN_FREE_BYTES` free.

use std::sync::Arc;
use std::sync::atomic::Ordering;
use std::time::Duration;

use anyhow::{Context, Result};
use tracing::{debug, error, info, warn};

use miner::backfill::{
    BackfillConfig, BackfillMetrics, Candidate, Cursor, FetchError, LocalCopy, LocalLookup,
    LocalSources, PauseReason, Peer, RemoveOutcome, SourceMode, holders_for_pg, peers_for_uids,
    verify_payload,
};
use miner::pg_lists::{self, ListExpectation, ListSource, MAX_LIST_BYTES, Manifest};
use miner::purge::{PurgeConfig, RateLimiter, generation_is_fresh};
use miner::store::BlobStore;

use crate::inventory;
use crate::state;

/// Process-wide counters of the backfill loop.
pub fn metrics() -> &'static BackfillMetrics {
    static METRICS: std::sync::OnceLock<BackfillMetrics> = std::sync::OnceLock::new();
    METRICS.get_or_init(BackfillMetrics::default)
}

/// What a pass needs from the host process. The live implementation
/// reads the globals and dials peers; tests substitute in-memory
/// inventory, fixed holders and a scripted fetch.
#[async_trait::async_trait]
pub trait PassEnv: Send + Sync {
    /// Which of `hashes` the inventory holds as live (not trashed)
    /// shards, in order. Blocking: discovery calls it from the blocking
    /// pool, several lists at once.
    fn live_among(&self, hashes: &[[u8; 32]]) -> Result<Vec<bool>>;
    /// Peers to try for a blob of `pg_id`, at most `max`, best first: the
    /// holders `listed` for the same blob by the list, then the miners
    /// placed on the PG by the current map.
    async fn holders(&self, pg_id: u32, listed: &[u32], max: usize) -> Vec<Peer>;
    /// This miner's uid: the listed records whose `holder_uid` is this
    /// are its own.
    fn my_uid(&self) -> u32;
    /// One FetchBlob round trip; the bytes are blake3-verified already.
    async fn fetch(&self, peer: &Peer, hash_hex: &str) -> Result<Vec<u8>, FetchError>;
    /// Exclusive on the hash while the blob lands (writers: Store,
    /// PullFromPeer, backfill; the purge skips a locked hash).
    async fn lock_write(&self, hash_hex: &str) -> state::HashWriteLock;
    /// The blob is in the store: record its inventory row. An error means
    /// the row may be missing (a moved local source is then kept).
    fn record_stored(&self, hash_hex: &str) -> Result<()>;
    /// Free bytes on the blob volume.
    fn free_bytes(&self) -> u64;
    /// A purge pass is deleting right now.
    fn purge_active(&self) -> bool;
    /// Current cluster-map epoch; a change mid-discovery stops the
    /// discovery (the candidates collected are still fetched).
    async fn current_epoch(&self) -> u64;
}

/// The real miner: SQLite inventory, cluster map, peer cache, QUIC.
pub struct LiveEnv {
    pub endpoint: quinn::Endpoint,
    pub blobs_dir: std::path::PathBuf,
}

#[async_trait::async_trait]
impl PassEnv for LiveEnv {
    fn live_among(&self, hashes: &[[u8; 32]]) -> Result<Vec<bool>> {
        inventory::live_among(hashes)
    }
    async fn holders(&self, pg_id: u32, listed: &[u32], max: usize) -> Vec<Peer> {
        let Some(map) = state::get_cluster_map().read().await.clone() else {
            return Vec::new();
        };
        let me = state::get_miner_uid();
        let cache = state::get_peer_cache();
        let listed = listed.to_vec();
        tokio::task::spawn_blocking(move || {
            let known = |node_id: &str| {
                cache
                    .get(node_id)
                    .and_then(|addr| state::socket_addr_from_endpoint(&addr))
            };
            let mut peers = peers_for_uids(&map, &listed, me, known);
            for peer in holders_for_pg(&map, pg_id, me, known, max) {
                if !peers.iter().any(|p| p.uid == peer.uid) {
                    peers.push(peer);
                }
            }
            peers.truncate(max);
            peers
        })
        .await
        .unwrap_or_default()
    }
    fn my_uid(&self) -> u32 {
        state::get_miner_uid()
    }
    async fn fetch(&self, peer: &Peer, hash_hex: &str) -> Result<Vec<u8>, FetchError> {
        crate::p2p::fetch_blob_from_peer(&self.endpoint, &peer.node_id, peer.addr, hash_hex).await
    }
    async fn lock_write(&self, hash_hex: &str) -> state::HashWriteLock {
        state::lock_hash_write(hash_hex).await
    }
    fn record_stored(&self, hash_hex: &str) -> Result<()> {
        inventory::insert_shard(hash_hex)
    }
    fn free_bytes(&self) -> u64 {
        crate::helpers::blocking(|| fs2::available_space(&self.blobs_dir)).unwrap_or(0)
    }
    fn purge_active(&self) -> bool {
        state::purge_pass_active()
    }
    async fn current_epoch(&self) -> u64 {
        *state::get_current_epoch().read().await
    }
}

/// Outcome of one pass.
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct PassSummary {
    /// Owned PGs whose list was scanned to the end.
    pub scanned_pgs: u64,
    /// Owned PGs the generation does not cover (skipped, cursor advances).
    pub uncovered_pgs: u64,
    /// Lists that failed to fetch or verify (skipped this pass).
    pub list_errors: u64,
    /// Records of the lists consumed by the walk (complete or cut).
    pub records: u64,
    /// Listed records whose holder is another miner of the PG: not this
    /// miner's obligation, never fetched.
    pub other_holder: u64,
    pub candidates: u64,
    /// Wall time of the discovery (the fetch overlaps it).
    pub discovery_ms: u64,
    pub fetched: u64,
    pub fetched_bytes: u64,
    pub no_peer: u64,
    pub bad_peer: u64,
    pub already_present: u64,
    pub store_errors: u64,
    /// Local source lookups: verified copy found, no copy, bad copy only.
    pub local_hit: u64,
    pub local_miss: u64,
    pub local_bad: u64,
    /// Bytes stored from a local source.
    pub local_bytes: u64,
    /// `BACKFILL_LOCAL_SOURCE_DELETE`: source files unlinked after the
    /// blob was confirmed in the live store; source files kept because
    /// the confirmation or the unlink failed.
    pub local_deleted: u64,
    pub local_delete_errors: u64,
    /// The scan stopped at `BACKFILL_MAX_PENDING` before the last PG.
    pub truncated: bool,
    /// The walk reached the last owned PG: the next pass starts over.
    pub walk_complete: bool,
    /// The epoch moved while scanning: the discovery stopped there (the
    /// owned set is stale), the candidates collected were still fetched.
    pub epoch_changed: bool,
    /// Where the next pass resumes.
    pub next_cursor: Cursor,
}

impl PassSummary {
    /// Discovery rate: (PGs/s, records/s) over `discovery_ms`.
    pub fn discovery_rates(&self) -> (f64, f64) {
        let secs = (self.discovery_ms.max(1) as f64) / 1000.0;
        (
            (self.scanned_pgs + self.uncovered_pgs) as f64 / secs,
            self.records as f64 / secs,
        )
    }

    fn add(&mut self, o: &FetchOutcome) {
        self.fetched += o.fetched;
        self.fetched_bytes += o.fetched_bytes;
        self.no_peer += o.no_peer;
        self.bad_peer += o.bad_peer;
        self.already_present += o.already_present;
        self.store_errors += o.store_errors;
        self.local_hit += o.local_hit;
        self.local_miss += o.local_miss;
        self.local_bad += o.local_bad;
        self.local_bytes += o.local_bytes;
        self.local_deleted += o.local_deleted;
        self.local_delete_errors += o.local_delete_errors;
    }
}

/// One pass: discovery from `cursor` over `owned` (sorted), with the
/// fetch (local sources first, then peers) of every candidate starting as
/// soon as discovery emits it. `epoch_at_start` is the epoch the owned set
/// was computed on.
#[allow(clippy::too_many_arguments)]
pub async fn run_pass(
    store: Arc<dyn BlobStore>,
    env: Arc<dyn PassEnv>,
    local: Arc<LocalSources>,
    source: &dyn ListSource,
    manifest: &Manifest,
    owned: &[u32],
    cursor: Cursor,
    cfg: &BackfillConfig,
    epoch_at_start: u64,
    metrics: &'static BackfillMetrics,
) -> PassSummary {
    let mut summary = PassSummary::default();
    let generation = manifest.generation;
    let start = cursor.start_index(generation, owned);
    metrics.pending.store(0, Ordering::Relaxed);

    // Discovery feeds the fetch stages through an unbounded channel: a
    // pass never emits more than `max_pending` candidates, the bound the
    // former collect-then-fetch Vec had.
    let (tx, rx) = tokio::sync::mpsc::unbounded_channel();
    let discovery = discover(
        source,
        manifest,
        owned,
        start,
        &env,
        cfg,
        epoch_at_start,
        metrics,
        tx,
        &mut summary,
    );
    let fetch = fetch_stages(&store, &env, &local, rx, cfg, metrics);
    let (idx, fetched) = tokio::join!(discovery, fetch);

    summary.add(&fetched);
    summary.walk_complete = !summary.epoch_changed && idx >= owned.len();
    summary.next_cursor = Cursor::at(generation, owned, idx, summary.walk_complete);
    metrics.pending.store(0, Ordering::Relaxed);
    summary
}

/// Phase 1: walk `owned[start..]`, at most `discovery_concurrency` lists
/// in flight, consuming their results strictly in PG order; send every
/// candidate to `sink` as soon as its PG is consumed. Returns the index of
/// the first PG not fully scanned (the cursor). A PG counts as scanned
/// only once all its candidates are sent; one cut by the cap is not.
/// `sink` is dropped on return, which ends the fetch stages once drained.
#[allow(clippy::too_many_arguments)]
async fn discover(
    source: &dyn ListSource,
    manifest: &Manifest,
    owned: &[u32],
    start: usize,
    env: &Arc<dyn PassEnv>,
    cfg: &BackfillConfig,
    epoch_at_start: u64,
    metrics: &'static BackfillMetrics,
    sink: tokio::sync::mpsc::UnboundedSender<Candidate>,
    summary: &mut PassSummary,
) -> usize {
    use futures::StreamExt;

    let generation = manifest.generation;
    let my_uid = env.my_uid();
    let started = tokio::time::Instant::now();
    // `buffered` keeps up to N scans running and yields them in input
    // order. Dropping the stream (cap, epoch move) drops the scans still
    // in flight (a list body already in the blocking pool finishes there
    // and is discarded: nothing of it was sent).
    let mut scans = futures::stream::iter(owned.get(start..).unwrap_or_default().iter().copied())
        .map(|pg_id| scan_pg(source, manifest, pg_id, env, my_uid))
        .buffered(cfg.discovery_concurrency.max(1));
    let mut idx = start;
    let mut emitted = 0usize;
    while idx < owned.len() && emitted < cfg.max_pending {
        if env.current_epoch().await != epoch_at_start {
            // The owned set is stale: stop walking it. What was collected
            // stays a candidate: each is a blob a signed list names THIS
            // miner as the holder of, so storing it is safe whatever the
            // epoch (the purge keeps listed blobs; ownership only decides
            // which lists are walked). The cursor stays on the first PG
            // not consumed, even if later lists were already scanned.
            summary.epoch_changed = true;
            break;
        }
        let Some((pg_id, job)) = scans.next().await else {
            break;
        };
        debug_assert_eq!(pg_id, owned[idx], "results are consumed in PG order");
        match job {
            PgJob::Uncovered => {
                summary.uncovered_pgs += 1;
                idx += 1;
            }
            PgJob::Scanned(Ok(scan)) => {
                summary.records += scan.records;
                summary.other_holder += scan.other_holder;
                metrics
                    .discovery_records
                    .fetch_add(scan.records, Ordering::Relaxed);
                let room = cfg.max_pending - emitted;
                let cut = scan.missing.len() > room;
                let take = scan.missing.len().min(room);
                debug!(
                    pg_id,
                    listed = scan.records,
                    other_holder = scan.other_holder,
                    missing = scan.missing.len(),
                    truncated = cut,
                    "backfill: list scanned"
                );
                for candidate in scan.missing.into_iter().take(take) {
                    metrics.pending.fetch_add(1, Ordering::Relaxed);
                    // The receiver lives until this sender is dropped.
                    let _ = sink.send(candidate);
                }
                emitted += take;
                metrics.candidates.fetch_add(take as u64, Ordering::Relaxed);
                if cut {
                    // Rescanned next pass: what this pass fetches is then
                    // in the inventory, the remainder becomes the new
                    // candidates.
                    summary.truncated = true;
                    break;
                }
                summary.scanned_pgs += 1;
                metrics.discovery_pgs.fetch_add(1, Ordering::Relaxed);
                idx += 1;
            }
            PgJob::Scanned(Err(e)) => {
                warn!(pg_id, generation, error = %format!("{e:#}"), "backfill: list skipped");
                summary.list_errors += 1;
                metrics.list_errors.fetch_add(1, Ordering::Relaxed);
                idx += 1;
            }
        }
        let consumed = idx - start;
        if consumed > 0 && consumed.is_multiple_of(DISCOVERY_PROGRESS_EVERY) {
            summary.discovery_ms = started.elapsed().as_millis() as u64;
            let (pgs_per_sec, records_per_sec) = summary.discovery_rates();
            info!(
                generation,
                consumed,
                remaining = owned.len() - idx,
                records = summary.records,
                candidates = emitted,
                pgs_per_sec = format!("{pgs_per_sec:.2}"),
                records_per_sec = format!("{records_per_sec:.0}"),
                "backfill: discovery progress"
            );
        }
    }
    summary.candidates = emitted as u64;
    summary.discovery_ms = started.elapsed().as_millis() as u64;
    let (pgs_per_sec, records_per_sec) = summary.discovery_rates();
    info!(
        generation,
        epoch_at_start,
        epoch_changed = summary.epoch_changed,
        truncated = summary.truncated,
        scanned_pgs = summary.scanned_pgs,
        uncovered_pgs = summary.uncovered_pgs,
        list_errors = summary.list_errors,
        records = summary.records,
        candidates = summary.candidates,
        discovery_ms = summary.discovery_ms,
        pgs_per_sec = format!("{pgs_per_sec:.2}"),
        records_per_sec = format!("{records_per_sec:.0}"),
        next_pg = owned.get(idx).copied(),
        "backfill: discovery finished"
    );
    idx
}

/// PGs consumed between two discovery progress lines.
const DISCOVERY_PROGRESS_EVERY: usize = 256;

/// One PG of the walk, scanned ahead of its turn.
enum PgJob {
    /// The generation does not list this PG.
    Uncovered,
    Scanned(Result<PgScan>),
}

/// What one list contributes.
#[derive(Debug, Default)]
struct PgScan {
    /// Records in the list.
    records: u64,
    /// Records naming another holder.
    other_holder: u64,
    /// This miner's blobs absent from the inventory, in list order.
    missing: Vec<Candidate>,
}

async fn scan_pg(
    source: &dyn ListSource,
    manifest: &Manifest,
    pg_id: u32,
    env: &Arc<dyn PassEnv>,
    my_uid: u32,
) -> (u32, PgJob) {
    let job = match manifest.object_for_pg(pg_id) {
        None => PgJob::Uncovered,
        Some(obj) => PgJob::Scanned(scan_pg_list(source, manifest, pg_id, obj, env, my_uid).await),
    };
    (pg_id, job)
}

/// Fetch one PG list, then, in the blocking pool, verify and decode it
/// and look this miner's blobs up in the inventory (one batch).
async fn scan_pg_list(
    source: &dyn ListSource,
    manifest: &Manifest,
    pg_id: u32,
    obj: &pg_lists::ObjectEntry,
    env: &Arc<dyn PassEnv>,
    my_uid: u32,
) -> Result<PgScan> {
    if obj.size > MAX_LIST_BYTES {
        anyhow::bail!(
            "list declares {} bytes, above the {MAX_LIST_BYTES} byte limit",
            obj.size
        );
    }
    let path = format!("gen/{}/{}", manifest.generation, Manifest::list_path(pg_id));
    let bytes = pg_lists::fetch_sized(source, &path, obj.size).await?;
    if bytes.len() as u64 != obj.size {
        anyhow::bail!(
            "manifest size {} but body is {} bytes",
            obj.size,
            bytes.len()
        );
    }
    let (generation, ec_k, ec_m) = (manifest.generation, manifest.ec_k, manifest.ec_m);
    let sha256 = obj.sha256.clone();
    let env = Arc::clone(env);
    tokio::task::spawn_blocking(move || {
        let expect = ListExpectation {
            pg_id,
            generation,
            ec_k,
            ec_m,
            sha256_hex: &sha256,
        };
        let own = collect_own(&bytes, expect, my_uid)?;
        missing_from_inventory(own, env.as_ref())
    })
    .await
    .context("list scan task")?
}

/// This miner's blobs of one list, before the inventory lookup.
struct OwnBlobs {
    records: u64,
    other_holder: u64,
    /// Blobs whose holders include this miner, with the other listed
    /// holders, in list (hash) order.
    own: Vec<Candidate>,
}

/// Verify and decode one list (`decode_list`: digest, header, order) and
/// keep the blobs whose holders include `my_uid`. Records are sorted by
/// (blob hash, holder): the holders of one blob are consecutive, so a
/// blob is decided once all its holders are seen. A record of another
/// holder costs a hash compare and a push into a reused buffer; only this
/// miner's blobs allocate.
fn collect_own(bytes: &[u8], expect: ListExpectation<'_>, my_uid: u32) -> Result<OwnBlobs> {
    let mut groups = OwnCollector::new(expect.pg_id, my_uid);
    let header = pg_lists::decode_list(bytes, expect, &mut |record| groups.push(record))?;
    groups.close();
    Ok(OwnBlobs {
        records: u64::from(header.count),
        other_holder: groups.other_holder,
        own: groups.own,
    })
}

/// Keep the `own` blobs the inventory does not hold live.
fn missing_from_inventory(own: OwnBlobs, env: &dyn PassEnv) -> Result<PgScan> {
    let hashes: Vec<[u8; 32]> = own.own.iter().map(|c| c.hash).collect();
    // A failed inventory read leaves the PG's candidates unknown: the PG
    // is skipped (list error), nothing of it is a candidate.
    let live = env.live_among(&hashes).context("inventory lookup")?;
    anyhow::ensure!(
        live.len() == hashes.len(),
        "inventory lookup answered {} of {} hashes",
        live.len(),
        hashes.len()
    );
    Ok(PgScan {
        records: own.records,
        other_holder: own.other_holder,
        missing: own
            .own
            .into_iter()
            .zip(live)
            .filter_map(|(c, live)| (!live).then_some(c))
            .collect(),
    })
}

/// Groups consecutive records by blob hash (see [`collect_own`]).
struct OwnCollector {
    pg_id: u32,
    my_uid: u32,
    /// The open group: hash and listed length; its holders so far are in
    /// `holders`.
    open: Option<([u8; 32], u32)>,
    holders: Vec<u32>,
    other_holder: u64,
    own: Vec<Candidate>,
}

impl OwnCollector {
    fn new(pg_id: u32, my_uid: u32) -> Self {
        Self {
            pg_id,
            my_uid,
            open: None,
            holders: Vec::with_capacity(32),
            other_holder: 0,
            own: Vec::new(),
        }
    }

    fn push(&mut self, record: &pg_lists::Record) {
        match self.open {
            Some((hash, _)) if hash == record.blob_hash => {}
            _ => {
                self.close();
                self.open = Some((record.blob_hash, record.shard_length));
            }
        }
        self.holders.push(record.holder_uid);
    }

    /// Decide the open group: a blob whose holders include this miner is
    /// kept, with the other listed holders as its first sources.
    fn close(&mut self) {
        let Some((hash, shard_length)) = self.open.take() else {
            return;
        };
        let me = self.my_uid;
        let others = self.holders.iter().filter(|uid| **uid != me).count();
        self.other_holder += others as u64;
        if others < self.holders.len() {
            self.own.push(Candidate {
                pg_id: self.pg_id,
                hash,
                shard_length: u64::from(shard_length),
                listed_holders: self.holders.iter().copied().filter(|u| *u != me).collect(),
            });
        }
        self.holders.clear();
    }
}

/// Phases 2a/2b, fed by discovery: local sources (if any), then peers.
/// Returns the fetch counters.
async fn fetch_stages(
    store: &Arc<dyn BlobStore>,
    env: &Arc<dyn PassEnv>,
    local: &Arc<LocalSources>,
    candidates: tokio::sync::mpsc::UnboundedReceiver<Candidate>,
    cfg: &BackfillConfig,
    metrics: &'static BackfillMetrics,
) -> FetchOutcome {
    if local.is_empty() {
        return peer_stage(store, env, candidates, cfg, metrics).await;
    }
    let (to_peers, for_peers) = tokio::sync::mpsc::unbounded_channel();
    let (mut total, peers) = tokio::join!(
        local_stage(store, env, local, candidates, to_peers, cfg, metrics),
        peer_stage(store, env, for_peers, cfg, metrics),
    );
    total.add(&peers);
    total
}

/// Phase 2b: fetch from peers, at most `max_concurrent` in flight, paced
/// by the byte budget (charged with the listed length) and paused while a
/// purge pass runs or free space is below the floor.
async fn peer_stage(
    store: &Arc<dyn BlobStore>,
    env: &Arc<dyn PassEnv>,
    mut candidates: tokio::sync::mpsc::UnboundedReceiver<Candidate>,
    cfg: &BackfillConfig,
    metrics: &'static BackfillMetrics,
) -> FetchOutcome {
    // Only the byte budget bounds the backfill; the operation bucket is
    // left effectively unbounded.
    const UNBOUNDED_OPS_PER_SEC: u64 = 1 << 40;
    let mut total = FetchOutcome::default();
    let limiter = Arc::new(tokio::sync::Mutex::new(RateLimiter::new(
        UNBOUNDED_OPS_PER_SEC,
        cfg.max_bytes_per_sec,
    )));
    let sem = Arc::new(tokio::sync::Semaphore::new(cfg.max_concurrent));
    let mut tasks = tokio::task::JoinSet::new();
    let mut dispatched = 0u64;
    loop {
        // Resolve finished fetches while waiting for the next candidate,
        // so `pending` and the counters do not wait for it.
        let candidate = tokio::select! {
            biased;
            Some(joined) = tasks.join_next(), if !tasks.is_empty() => {
                fold_outcome(&mut total, joined, metrics);
                continue;
            }
            next = candidates.recv() => match next {
                Some(candidate) => candidate,
                None => break,
            },
        };
        wait_while_paused(env.as_ref(), cfg, metrics).await;
        limiter.lock().await.acquire(candidate.shard_length).await;
        let permit = Arc::clone(&sem)
            .acquire_owned()
            .await
            .expect("semaphore open");
        let (store, env) = (Arc::clone(store), Arc::clone(env));
        let peers_per_blob = cfg.peers_per_blob;
        tasks.spawn(async move {
            let outcome = fetch_one(
                store.as_ref(),
                env.as_ref(),
                &candidate,
                peers_per_blob,
                metrics,
            )
            .await;
            drop(permit);
            outcome
        });
        while let Some(joined) = tasks.try_join_next() {
            fold_outcome(&mut total, joined, metrics);
        }
        dispatched += 1;
        if dispatched.is_multiple_of(1_000) {
            info!(
                dispatched,
                fetched = total.fetched,
                no_peer = total.no_peer,
                "backfill: progress"
            );
        }
    }
    while let Some(joined) = tasks.join_next().await {
        fold_outcome(&mut total, joined, metrics);
    }
    total
}

/// Phase 2a: look every candidate up in the local sources, at most
/// `local_concurrency` in flight; store the verified copies. Disk-bound:
/// not charged to the network byte budget. The candidates left for the
/// peers (no local copy, or only bad ones) go to `to_peers`, in
/// completion order.
#[allow(clippy::too_many_arguments)]
async fn local_stage(
    store: &Arc<dyn BlobStore>,
    env: &Arc<dyn PassEnv>,
    local: &Arc<LocalSources>,
    mut candidates: tokio::sync::mpsc::UnboundedReceiver<Candidate>,
    to_peers: tokio::sync::mpsc::UnboundedSender<Candidate>,
    cfg: &BackfillConfig,
    metrics: &'static BackfillMetrics,
) -> FetchOutcome {
    let mut total = FetchOutcome::default();
    let sem = Arc::new(tokio::sync::Semaphore::new(cfg.local_concurrency));
    let mut tasks = tokio::task::JoinSet::new();
    let mut dispatched = 0u64;
    loop {
        // Forward unresolved lookups to the peers while waiting for the
        // next candidate: a miss must not wait for discovery to emit
        // another one.
        let candidate = tokio::select! {
            biased;
            Some(joined) = tasks.join_next(), if !tasks.is_empty() => {
                fold_local(&mut total, joined, &to_peers, metrics);
                continue;
            }
            next = candidates.recv() => match next {
                Some(candidate) => candidate,
                None => break,
            },
        };
        wait_while_paused(env.as_ref(), cfg, metrics).await;
        let permit = Arc::clone(&sem)
            .acquire_owned()
            .await
            .expect("semaphore open");
        let (store, env, local) = (Arc::clone(store), Arc::clone(env), Arc::clone(local));
        tasks.spawn(async move {
            let outcome = local_one(store.as_ref(), env.as_ref(), &local, candidate, metrics).await;
            drop(permit);
            outcome
        });
        while let Some(joined) = tasks.try_join_next() {
            fold_local(&mut total, joined, &to_peers, metrics);
        }
        dispatched += 1;
        if dispatched.is_multiple_of(10_000) {
            info!(
                dispatched,
                local_hit = total.local_hit,
                local_miss = total.local_miss,
                local_bad = total.local_bad,
                "backfill: local progress"
            );
        }
    }
    while let Some(joined) = tasks.join_next().await {
        fold_local(&mut total, joined, &to_peers, metrics);
    }
    total
}

/// A local lookup's outcome, and the candidate when the peers must be
/// tried.
struct LocalOutcome {
    outcome: FetchOutcome,
    unresolved: Option<Candidate>,
}

fn fold_local(
    total: &mut FetchOutcome,
    joined: Result<LocalOutcome, tokio::task::JoinError>,
    to_peers: &tokio::sync::mpsc::UnboundedSender<Candidate>,
    metrics: &BackfillMetrics,
) {
    match joined {
        Ok(LocalOutcome {
            outcome,
            unresolved: Some(candidate),
        }) => {
            // Still pending: the peer stage resolves it (its receiver
            // outlives this sender).
            total.add(&outcome);
            let _ = to_peers.send(candidate);
        }
        Ok(LocalOutcome {
            outcome,
            unresolved: None,
        }) => fold_outcome(total, Ok(outcome), metrics),
        Err(e) => fold_outcome(total, Err(e), metrics),
    }
}

/// One candidate against the local sources.
async fn local_one(
    store: &dyn BlobStore,
    env: &dyn PassEnv,
    local: &LocalSources,
    candidate: Candidate,
    metrics: &BackfillMetrics,
) -> LocalOutcome {
    let mut out = FetchOutcome::default();
    match local.lookup(&candidate.hash, candidate.shard_length).await {
        LocalLookup::Hit { data, copy } => {
            out.local_hit += 1;
            metrics.local_hit.fetch_add(1, Ordering::Relaxed);
            let source = local.is_removable(&copy).then_some(MoveSource {
                local,
                copy: &copy,
                hash: &candidate.hash,
                shard_length: candidate.shard_length,
            });
            let hash_hex = candidate.hash_hex();
            if store_verified(store, env, &hash_hex, &data, source, metrics, &mut out).await {
                out.local_bytes += data.len() as u64;
                metrics
                    .local_bytes
                    .fetch_add(data.len() as u64, Ordering::Relaxed);
            }
            LocalOutcome {
                outcome: out,
                unresolved: None,
            }
        }
        LocalLookup::Miss => {
            out.local_miss += 1;
            metrics.local_miss.fetch_add(1, Ordering::Relaxed);
            LocalOutcome {
                outcome: out,
                unresolved: Some(candidate),
            }
        }
        LocalLookup::Bad(reason) => {
            debug!(hash = %candidate.hash_hex(), reason = %reason, "backfill: local copy rejected");
            out.local_bad += 1;
            metrics.local_bad.fetch_add(1, Ordering::Relaxed);
            LocalOutcome {
                outcome: out,
                unresolved: Some(candidate),
            }
        }
    }
}

impl FetchOutcome {
    fn add(&mut self, o: &FetchOutcome) {
        self.fetched += o.fetched;
        self.fetched_bytes += o.fetched_bytes;
        self.no_peer += o.no_peer;
        self.bad_peer += o.bad_peer;
        self.already_present += o.already_present;
        self.store_errors += o.store_errors;
        self.local_hit += o.local_hit;
        self.local_miss += o.local_miss;
        self.local_bad += o.local_bad;
        self.local_bytes += o.local_bytes;
        self.local_deleted += o.local_deleted;
        self.local_delete_errors += o.local_delete_errors;
    }
}

/// A candidate is resolved: count it and release its `pending` slot.
fn fold_outcome(
    total: &mut FetchOutcome,
    joined: Result<FetchOutcome, tokio::task::JoinError>,
    metrics: &BackfillMetrics,
) {
    metrics.pending.fetch_sub(1, Ordering::Relaxed);
    match joined {
        Ok(o) => total.add(&o),
        Err(e) => {
            error!(error = %e, "backfill: fetch task panicked");
            total.store_errors += 1;
            metrics.store_errors.fetch_add(1, Ordering::Relaxed);
        }
    }
}

/// Block while a pause condition holds, re-checking every
/// `pause_poll_secs`; gauges reflect the reason.
async fn wait_while_paused(env: &dyn PassEnv, cfg: &BackfillConfig, metrics: &BackfillMetrics) {
    let mut logged: Option<PauseReason> = None;
    loop {
        let reason = if env.purge_active() {
            Some(PauseReason::PurgeRunning)
        } else if env.free_bytes() < cfg.min_free_bytes {
            Some(PauseReason::LowFreeSpace)
        } else {
            None
        };
        metrics.set_paused(
            PauseReason::PurgeRunning,
            reason == Some(PauseReason::PurgeRunning),
        );
        metrics.set_paused(
            PauseReason::LowFreeSpace,
            reason == Some(PauseReason::LowFreeSpace),
        );
        let Some(reason) = reason else {
            if let Some(r) = logged {
                info!(reason = r.label(), "backfill: resumed");
            }
            return;
        };
        if logged != Some(reason) {
            info!(
                reason = reason.label(),
                free_bytes = env.free_bytes(),
                min_free_bytes = cfg.min_free_bytes,
                "backfill: paused"
            );
            logged = Some(reason);
        }
        tokio::time::sleep(Duration::from_secs(cfg.pause_poll_secs)).await;
    }
}

#[derive(Debug, Default)]
struct FetchOutcome {
    fetched: u64,
    fetched_bytes: u64,
    no_peer: u64,
    bad_peer: u64,
    already_present: u64,
    store_errors: u64,
    local_hit: u64,
    local_miss: u64,
    local_bad: u64,
    local_bytes: u64,
    local_deleted: u64,
    local_delete_errors: u64,
}

/// Try the holders of the candidate's PG in order until one payload
/// verifies, then store it under the write lock unless it landed
/// meanwhile.
async fn fetch_one(
    store: &dyn BlobStore,
    env: &dyn PassEnv,
    candidate: &Candidate,
    peers_per_blob: usize,
    metrics: &BackfillMetrics,
) -> FetchOutcome {
    let mut out = FetchOutcome::default();
    let hash_hex = candidate.hash_hex();
    let peers = env
        .holders(candidate.pg_id, &candidate.listed_holders, peers_per_blob)
        .await;
    if peers.is_empty() {
        debug!(hash = %hash_hex, pg_id = candidate.pg_id, "backfill: no eligible peer");
        out.no_peer += 1;
        metrics.no_peer.fetch_add(1, Ordering::Relaxed);
        return out;
    }
    let mut data = None;
    for peer in &peers {
        let result = env.fetch(peer, &hash_hex).await.and_then(|bytes| {
            verify_payload(&bytes, &candidate.hash, candidate.shard_length).map(|()| bytes)
        });
        match result {
            Ok(bytes) => {
                data = Some(bytes);
                break;
            }
            Err(e) => {
                debug!(
                    hash = %hash_hex,
                    peer_uid = peer.uid,
                    reason = e.reason(),
                    error = %e,
                    "backfill: peer did not yield the blob"
                );
                out.bad_peer += 1;
                metrics.record_bad_peer(&e);
            }
        }
    }
    let Some(data) = data else {
        out.no_peer += 1;
        metrics.no_peer.fetch_add(1, Ordering::Relaxed);
        return out;
    };

    if store_verified(store, env, &hash_hex, &data, None, metrics, &mut out).await {
        out.fetched += 1;
        out.fetched_bytes += data.len() as u64;
        metrics.fetched.fetch_add(1, Ordering::Relaxed);
        metrics
            .fetched_bytes
            .fetch_add(data.len() as u64, Ordering::Relaxed);
    }
    out
}

/// A local hit whose source file is unlinked once the blob is confirmed in
/// the live store (`BACKFILL_LOCAL_SOURCE_DELETE`).
struct MoveSource<'a> {
    local: &'a LocalSources,
    copy: &'a LocalCopy,
    hash: &'a [u8; 32],
    shard_length: u64,
}

/// Store a verified payload under the per-hash write lock, unless it
/// landed meanwhile (`already_present`), then record its inventory row.
/// Both sources (local and peer) go through here. `true` when this call
/// stored it; `already_present` / `store_errors` are counted here.
///
/// With `source` (a local hit in move mode), still under the same lock:
/// once the store returned success (durable on such a store) and the
/// inventory row was written, or the live store already held the blob
/// with a live inventory row, the live copy is read back and verified,
/// and only then is the source file unlinked. A store error, an inventory
/// error or missing row, or a failed read-back keeps the source.
async fn store_verified(
    store: &dyn BlobStore,
    env: &dyn PassEnv,
    hash_hex: &str,
    data: &[u8],
    source: Option<MoveSource<'_>>,
    metrics: &BackfillMetrics,
    out: &mut FetchOutcome,
) -> bool {
    let _lock = env.lock_write(hash_hex).await;
    let (stored, settled) = if store.has(hash_hex) {
        out.already_present += 1;
        metrics.already_present.fetch_add(1, Ordering::Relaxed);
        // Another writer landed it; a move also needs its live inventory
        // row (a Store or PullFromPeer writes one). Only asked in move
        // mode: one SQLite point query, off the runtime workers.
        let settled = match &source {
            None => Ok(()),
            Some(src) => match crate::helpers::blocking(|| env.live_among(&[*src.hash])) {
                Ok(live) if live.first() == Some(&true) => Ok(()),
                Ok(_) => Err("held by the live store without a live inventory row".to_string()),
                Err(e) => Err(format!("inventory lookup failed: {e:#}")),
            },
        };
        (false, settled)
    } else {
        match store.store(hash_hex, data).await {
            Ok(()) => match env.record_stored(hash_hex) {
                Ok(()) => (true, Ok(())),
                Err(e) => {
                    warn!(hash = %hash_hex, error = %format!("{e:#}"), "backfill: inventory insert failed");
                    (true, Err("inventory row not written".to_string()))
                }
            },
            Err(e) => {
                warn!(hash = %hash_hex, error = %e, "backfill: store failed");
                out.store_errors += 1;
                metrics.store_errors.fetch_add(1, Ordering::Relaxed);
                return false;
            }
        }
    };
    if let Some(source) = source {
        match settled {
            Ok(()) => move_source(store, hash_hex, &source, metrics, out).await,
            Err(reason) => {
                warn!(hash = %hash_hex, path = %source.copy.path.display(), reason = %reason, "backfill: local source kept");
                out.local_delete_errors += 1;
                metrics.local_delete_errors.fetch_add(1, Ordering::Relaxed);
            }
        }
    }
    stored
}

/// Unlink a local source file whose blob the live store holds: only on a
/// durable store, and only once the live copy reads back and verifies
/// (blake3 and listed length). Called under the per-hash write lock, so
/// no Delete, purge or other writer of the hash interleaves between the
/// read-back and the unlink. Any doubt keeps the source and counts
/// `local_delete_errors`; nothing here fails the pass.
async fn move_source(
    store: &dyn BlobStore,
    hash_hex: &str,
    source: &MoveSource<'_>,
    metrics: &BackfillMetrics,
    out: &mut FetchOutcome,
) {
    let kept = |out: &mut FetchOutcome, reason: String| {
        warn!(hash = %hash_hex, path = %source.copy.path.display(), reason = %reason, "backfill: local source kept");
        out.local_delete_errors += 1;
        metrics.local_delete_errors.fetch_add(1, Ordering::Relaxed);
    };
    if !store.store_is_durable() {
        kept(
            out,
            "the live store does not sync before acknowledging a write".to_string(),
        );
        return;
    }
    // The packed store's read is a synchronous `pread` inside its future:
    // run it on the blocking side, not on a runtime worker.
    let read_back = crate::helpers::blocking(|| {
        futures::executor::block_on(store.read_at_most(hash_hex, source.shard_length))
    });
    let confirmed = match read_back {
        Ok(bytes) => verify_payload(&bytes, source.hash, source.shard_length)
            .map_err(|e| format!("live copy does not verify: {e}")),
        Err(e) => Err(format!("live copy unreadable: {e}")),
    };
    if let Err(reason) = confirmed {
        kept(out, reason);
        return;
    }
    match source.local.remove_copy(source.hash, source.copy).await {
        RemoveOutcome::Removed => {
            debug!(hash = %hash_hex, path = %source.copy.path.display(), "backfill: local source removed");
            out.local_deleted += 1;
            metrics.local_deleted.fetch_add(1, Ordering::Relaxed);
        }
        RemoveOutcome::Gone => {
            debug!(hash = %hash_hex, path = %source.copy.path.display(), "backfill: local source already gone");
        }
        RemoveOutcome::Failed(reason) => kept(out, reason),
    }
}

// ============================================================================
// Loop
// ============================================================================

/// Background task. Returns immediately when the backfill is disabled or
/// the purge has no bucket URL (the two share `PG_LISTS_BASE_URL`).
pub async fn run_loop(
    store: Arc<dyn BlobStore>,
    validator_node_id: String,
    purge_cfg: PurgeConfig,
    cfg: BackfillConfig,
    endpoint: quinn::Endpoint,
    blobs_dir: std::path::PathBuf,
) {
    if !cfg.enabled {
        info!("backfill: disabled (BACKFILL_ENABLED=false)");
        return;
    }
    let Some(base_url) = purge_cfg.base_url.clone() else {
        error!(
            "backfill: BACKFILL_ENABLED=true but PG_LISTS_BASE_URL is unset, backfill stays off"
        );
        return;
    };
    let source = match crate::pg_purge::build_source(&base_url) {
        Ok(s) => s,
        Err(e) => {
            error!(error = %e, "backfill: cannot build HTTP source, backfill stays off");
            return;
        }
    };
    let Some(data_dir) = state::get_data_dir().cloned() else {
        error!("backfill: data dir unknown, backfill stays off");
        return;
    };
    info!(
        base_url = %base_url,
        max_pending = cfg.max_pending,
        max_bytes_per_sec = cfg.max_bytes_per_sec,
        max_concurrent = cfg.max_concurrent,
        pass_interval_secs = cfg.pass_interval_secs,
        min_free_bytes = cfg.min_free_bytes,
        peers_per_blob = cfg.peers_per_blob,
        local_source_dirs = ?cfg.local_source_dirs,
        local_source_delete = cfg.local_source_delete,
        local_concurrency = cfg.local_concurrency,
        discovery_concurrency = cfg.discovery_concurrency,
        "backfill: enabled"
    );

    let metrics = metrics();
    let mode = source_mode(&cfg, store.as_ref(), &blobs_dir);
    let local = {
        let dirs = cfg.local_source_dirs.clone();
        let mode = mode.clone();
        Arc::new(crate::helpers::blocking(move || {
            LocalSources::open(&dirs, &mode)
        }))
    };
    if !cfg.local_source_dirs.is_empty() {
        info!(
            usable = local.len(),
            configured = cfg.local_source_dirs.len(),
            removable = local.removable_roots(),
            mode = ?mode,
            "backfill: local sources opened"
        );
    }
    let env: Arc<dyn PassEnv> = Arc::new(LiveEnv {
        endpoint,
        blobs_dir,
    });
    let mut cursor = Cursor::load_from(&data_dir);
    if cursor != Cursor::default() {
        info!(
            generation = cursor.generation,
            next_pg = cursor.next_pg,
            "backfill: cursor restored"
        );
    }
    let mut manifest: Option<Manifest> = None;
    // PGs the current generation's holder index names this miner in,
    // fetched once per generation.
    let mut held: Option<(u64, Vec<u32>)> = None;
    let mut last_poll_at: Option<tokio::time::Instant> = None;
    let mut last_pass_at: Option<tokio::time::Instant> = None;
    let mut last_logged_wait: Option<&'static str> = None;
    // Generation the empty-ownership refusal was last logged for.
    let mut last_logged_empty: Option<u64> = None;

    loop {
        tokio::time::sleep(Duration::from_secs(purge_cfg.poll_secs.min(60))).await;

        let Some(crate::pg_purge::Ownership {
            epoch,
            pgs: owned,
            weight,
            ..
        }) = crate::pg_purge::owned_pgs().await
        else {
            debug!("backfill: no cluster map yet");
            continue;
        };
        let poll_due = last_poll_at.is_none_or(|t| t.elapsed().as_secs() >= purge_cfg.poll_secs);
        if manifest.is_none() || poll_due {
            refresh_manifest(source.as_ref(), &validator_node_id, &mut manifest).await;
            last_poll_at = Some(tokio::time::Instant::now());
        }
        let Some(current) = manifest.as_ref() else {
            continue;
        };
        metrics
            .generation
            .store(current.generation, Ordering::Relaxed);

        let now = common::now_secs();
        let fresh = current
            .created_at_secs()
            .is_some_and(|c| generation_is_fresh(c, now, purge_cfg.generation_max_age_secs));
        let wait = if !fresh {
            Some("generation is stale")
        } else if !inventory::is_ready() {
            Some("inventory not reconciled yet")
        } else if inventory::had_write_failure() {
            Some("an inventory write failed since startup")
        } else {
            None
        };
        if let Some(reason) = wait {
            if last_logged_wait != Some(reason) {
                warn!(
                    generation = current.generation,
                    "backfill: waiting: {reason}"
                );
                last_logged_wait = Some(reason);
            }
            continue;
        }
        last_logged_wait = None;
        if last_pass_at.is_some_and(|t| t.elapsed().as_secs() < cfg.pass_interval_secs) {
            continue;
        }
        // The walk covers the PGs owned now and those whose list names this
        // miner as a holder (placed on it at an older epoch). A failed index
        // fetch only narrows the walk to the owned PGs this pass.
        if held.as_ref().is_none_or(|(g, _)| *g != current.generation) {
            match pg_lists::fetch_holder_pgs(source.as_ref(), current, env.my_uid()).await {
                Ok(pgs) => held = Some((current.generation, pgs.unwrap_or_default())),
                Err(e) => warn!(
                    generation = current.generation,
                    error = %format!("{e:#}"),
                    "backfill: holder index unavailable, walking the owned PGs only"
                ),
            }
        }
        let mut owned = owned;
        if let Some((_, pgs)) = held.as_ref().filter(|(g, _)| *g == current.generation) {
            owned.extend(pgs.iter().copied());
            owned.sort_unstable();
            owned.dedup();
        }
        if owned.is_empty() {
            // A miner that owns no PG (weight 0) and that no list names as
            // a holder has nothing to fetch.
            metrics
                .refused_empty_ownership
                .fetch_add(1, Ordering::Relaxed);
            if last_logged_empty != Some(current.generation) {
                warn!(
                    epoch,
                    weight = ?weight,
                    generation = current.generation,
                    "backfill: this miner owns no PG under the current map (weight 0?) and no list names it as a holder, nothing to fetch"
                );
                last_logged_empty = Some(current.generation);
            }
            continue;
        }
        last_logged_empty = None;

        info!(
            generation = current.generation,
            epoch,
            owned_pgs = owned.len(),
            start_index = cursor.start_index(current.generation, &owned),
            "backfill: pass starting"
        );
        let started = tokio::time::Instant::now();
        let summary = run_pass(
            Arc::clone(&store),
            Arc::clone(&env),
            Arc::clone(&local),
            source.as_ref(),
            current,
            &owned,
            cursor,
            &cfg,
            epoch,
            metrics,
        )
        .await;
        cursor = summary.next_cursor;
        if let Err(e) = cursor.persist_to(&data_dir) {
            warn!(error = %e, "backfill: cursor not persisted");
        }
        metrics.passes.fetch_add(1, Ordering::Relaxed);
        if !summary.epoch_changed {
            // A discovery stopped by an epoch move resumes at the next
            // tick on the new owned set, not after a full interval.
            last_pass_at = Some(tokio::time::Instant::now());
        }
        let (pgs_per_sec, records_per_sec) = summary.discovery_rates();
        info!(
            generation = current.generation,
            elapsed_secs = started.elapsed().as_secs(),
            epoch_changed = summary.epoch_changed,
            scanned_pgs = summary.scanned_pgs,
            uncovered_pgs = summary.uncovered_pgs,
            list_errors = summary.list_errors,
            records = summary.records,
            other_holder = summary.other_holder,
            candidates = summary.candidates,
            discovery_ms = summary.discovery_ms,
            pgs_per_sec = format!("{pgs_per_sec:.2}"),
            records_per_sec = format!("{records_per_sec:.0}"),
            fetched = summary.fetched,
            fetched_bytes = summary.fetched_bytes,
            no_peer = summary.no_peer,
            bad_peer = summary.bad_peer,
            local_hit = summary.local_hit,
            local_miss = summary.local_miss,
            local_bad = summary.local_bad,
            local_bytes = summary.local_bytes,
            local_deleted = summary.local_deleted,
            local_delete_errors = summary.local_delete_errors,
            already_present = summary.already_present,
            store_errors = summary.store_errors,
            truncated = summary.truncated,
            walk_complete = summary.walk_complete,
            next_pg = cursor.next_pg,
            "backfill: pass finished"
        );
    }
}

/// Copy or move for the local sources: move only when
/// `BACKFILL_LOCAL_SOURCE_DELETE` is set AND the live store's `store` is
/// durable (synced before it returns); otherwise a source file could be
/// unlinked while its only other copy is still in the page cache.
fn source_mode(
    cfg: &BackfillConfig,
    store: &dyn BlobStore,
    blobs_dir: &std::path::Path,
) -> SourceMode {
    if !cfg.local_source_delete {
        return SourceMode::ReadOnly;
    }
    if !store.store_is_durable() {
        warn!(
            "backfill: BACKFILL_LOCAL_SOURCE_DELETE=true ignored: the live store does not sync a write before acknowledging it (flat backend), the local sources are only copied"
        );
        return SourceMode::ReadOnly;
    }
    SourceMode::Move {
        live_root: blobs_dir.to_path_buf(),
    }
}

/// Load the manifest `current.json` points at, keeping the previous one
/// on any failure. Unlike the purge, an older pointer is not refused
/// here: fetching blobs listed by an older generation is harmless, and
/// the purge's watermark already guards the deletion side.
async fn refresh_manifest(
    source: &dyn ListSource,
    validator_node_id: &str,
    current: &mut Option<Manifest>,
) {
    let pointer = match pg_lists::fetch_current(source).await {
        Ok(p) => p,
        Err(e) => {
            warn!(error = %format!("{e:#}"), "backfill: current.json unavailable");
            return;
        }
    };
    let latest = pointer.generation;
    if current.as_ref().is_some_and(|m| m.generation == latest) {
        return;
    }
    match pg_lists::fetch_manifest_at(source, &pointer, validator_node_id).await {
        Ok(m) => {
            info!(
                generation = m.generation,
                listed_pgs = m.pgs.len(),
                "backfill: manifest loaded"
            );
            *current = Some(m);
        }
        Err(e) => {
            warn!(generation = latest, error = %format!("{e:#}"), "backfill: manifest rejected");
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use miner::flat_store::FlatBlobStore;
    use miner::pg_lists::Record;
    use miner::pg_lists::test_fixtures::{
        CREATED_AT, MY_UID, deterministic_key, encode_list, sign_manifest,
    };
    use miner::pg_lists::{DirListSource, fetch_manifest};
    use sha2::{Digest, Sha256};
    use std::collections::{HashMap, HashSet};
    use std::sync::Mutex;
    use std::sync::atomic::{AtomicBool, AtomicU64};

    const GENERATION: u64 = 9;

    /// A listed blob: the payload the honest peer serves, hashed for
    /// real so the hash check can pass.
    fn blob(pg: u32, i: u32) -> (Vec<u8>, [u8; 32]) {
        let data = format!("pg{pg}-blob{i}-")
            .repeat(i as usize + 1)
            .into_bytes();
        let hash = *blake3::hash(&data).as_bytes();
        (data, hash)
    }

    /// Record `i` of pg `pg`: the true length of the blob (the shared
    /// fixture uses synthetic lengths), held by `holder_uid`.
    fn record_held_by(pg: u32, i: u32, holder_uid: u32) -> Record {
        let (data, hash) = blob(pg, i);
        Record {
            blob_hash: hash,
            shard_length: data.len() as u32,
            holder_uid,
        }
    }

    /// Record `i` of pg `pg`, held by this miner (`MY_UID`).
    fn record(pg: u32, i: u32) -> Record {
        record_held_by(pg, i, MY_UID)
    }

    /// Write a generation whose PG lists declare the true length of
    /// each blob, the holder of record `i` of pg `pg` given by
    /// `holder_of(pg, i)` (`rig` names this miner on every record).
    fn write_generation_held(
        root: &std::path::Path,
        pgs: &[(u32, u32)],
        holder_of: &dyn Fn(u32, u32) -> u32,
    ) -> String {
        write_generation_records(root, pgs, &|pg, count| {
            (0..count)
                .map(|i| record_held_by(pg, i, holder_of(pg, i)))
                .collect()
        })
    }

    /// The generation of `pgs` (`(pg, count)`) whose list of each PG holds
    /// `records_of(pg, count)`.
    fn write_generation_records(
        root: &std::path::Path,
        pgs: &[(u32, u32)],
        records_of: &dyn Fn(u32, u32) -> Vec<Record>,
    ) -> String {
        let key = deterministic_key(3);
        let gen_dir = root.join(format!("gen/{GENERATION}"));
        std::fs::create_dir_all(gen_dir.join("pg")).unwrap();
        let mut objects = serde_json::Map::new();
        for &(pg, count) in pgs {
            let records = records_of(pg, count);
            let body = encode_list(pg, GENERATION, 10, 20, &records);
            std::fs::write(gen_dir.join(Manifest::list_path(pg)), &body).unwrap();
            objects.insert(
                Manifest::list_path(pg),
                serde_json::json!({
                    "sha256": hex::encode(Sha256::digest(&body)),
                    "size": body.len(),
                }),
            );
        }
        let unsigned = serde_json::json!({
            "generation": GENERATION,
            "created_at": CREATED_AT,
            "pg_count": 16384,
            "ec_k": 10,
            "ec_m": 20,
            "pgs": pgs.iter().map(|(pg, _)| *pg).collect::<Vec<_>>(),
            "objects": objects,
        });
        let signed = sign_manifest(&key, &unsigned);
        std::fs::write(
            gen_dir.join("manifest.json"),
            serde_json::to_vec_pretty(&signed).unwrap(),
        )
        .unwrap();
        std::fs::write(
            root.join("current.json"),
            serde_json::json!({ "generation": GENERATION }).to_string(),
        )
        .unwrap();
        hex::encode(key.verifying_key().to_bytes())
    }

    fn peer(uid: u32) -> Peer {
        Peer {
            uid,
            node_id: format!("peer-{uid}"),
            addr: format!("10.0.0.{uid}:4001").parse().unwrap(),
        }
    }

    /// What a scripted peer returns for any hash.
    #[derive(Clone)]
    enum Serve {
        /// The true payload of the requested hash.
        Honest,
        /// A blake3-correct payload with a byte appended: impossible for
        /// a real blob, but the closest stand-in for "hash ok, length
        /// wrong" is the honest bytes truncated — so serve those and let
        /// the hash check fail first; the length case is exercised with
        /// a list that lies instead (see `list_length_disagreement`).
        Garbage,
        NotFound,
        Unreachable,
    }

    struct FakeEnv {
        live: Mutex<HashSet<String>>,
        holders: Vec<Peer>,
        serve: HashMap<u32, Serve>,
        /// Payloads by hex hash, for `Serve::Honest`.
        payloads: HashMap<String, Vec<u8>>,
        fetches: Mutex<Vec<(u32, String)>>,
        free_bytes: AtomicU64,
        purge_active: AtomicBool,
        epoch: AtomicU64,
        /// Epoch bump fired on the first `current_epoch` call after the
        /// first PG (tests the abort path).
        bump_epoch_after_calls: Mutex<Option<u32>>,
        /// This miner's uid (default `MY_UID`, the holder of every
        /// record of `write_generation`).
        my_uid: u32,
        /// Batched inventory lookups served.
        lookup_calls: AtomicU64,
        /// A lookup batch holding this hash fails.
        fail_lookup_of: Mutex<Option<[u8; 32]>>,
        /// `record_stored` fails (inventory insert error).
        fail_record: AtomicBool,
    }

    impl FakeEnv {
        fn new(holders: Vec<Peer>, serve: HashMap<u32, Serve>, pgs: &[(u32, u32)]) -> Self {
            let mut payloads = HashMap::new();
            for &(pg, count) in pgs {
                for i in 0..count {
                    let (data, hash) = blob(pg, i);
                    payloads.insert(hex::encode(hash), data);
                }
            }
            Self {
                live: Mutex::new(HashSet::new()),
                holders,
                serve,
                payloads,
                fetches: Mutex::new(Vec::new()),
                free_bytes: AtomicU64::new(u64::MAX),
                purge_active: AtomicBool::new(false),
                epoch: AtomicU64::new(5),
                bump_epoch_after_calls: Mutex::new(None),
                my_uid: MY_UID,
                lookup_calls: AtomicU64::new(0),
                fail_lookup_of: Mutex::new(None),
                fail_record: AtomicBool::new(false),
            }
        }
    }

    #[async_trait::async_trait]
    impl PassEnv for FakeEnv {
        fn live_among(&self, hashes: &[[u8; 32]]) -> Result<Vec<bool>> {
            self.lookup_calls.fetch_add(1, Ordering::Relaxed);
            let live = self.live.lock().unwrap();
            if let Some(bad) = *self.fail_lookup_of.lock().unwrap() {
                anyhow::ensure!(!hashes.contains(&bad), "injected inventory error");
            }
            Ok(hashes
                .iter()
                .map(|h| live.contains(&hex::encode(h)))
                .collect())
        }
        async fn holders(&self, _pg_id: u32, listed: &[u32], max: usize) -> Vec<Peer> {
            let mut peers: Vec<Peer> = listed.iter().map(|uid| peer(*uid)).collect();
            for p in &self.holders {
                if !peers.iter().any(|q| q.uid == p.uid) {
                    peers.push(p.clone());
                }
            }
            peers.truncate(max);
            peers
        }
        fn my_uid(&self) -> u32 {
            self.my_uid
        }
        async fn fetch(&self, peer: &Peer, hash_hex: &str) -> Result<Vec<u8>, FetchError> {
            self.fetches
                .lock()
                .unwrap()
                .push((peer.uid, hash_hex.to_string()));
            match self
                .serve
                .get(&peer.uid)
                .cloned()
                .unwrap_or(Serve::NotFound)
            {
                Serve::Honest => Ok(self.payloads[hash_hex].clone()),
                Serve::Garbage => Ok(b"definitely not the blob".to_vec()),
                Serve::NotFound => Err(FetchError::NotFound),
                Serve::Unreachable => Err(FetchError::Unreachable("refused".into())),
            }
        }
        async fn lock_write(&self, hash_hex: &str) -> state::HashWriteLock {
            state::lock_hash_write(hash_hex).await
        }
        fn record_stored(&self, hash_hex: &str) -> Result<()> {
            anyhow::ensure!(
                !self.fail_record.load(Ordering::Relaxed),
                "injected inventory insert failure"
            );
            self.live.lock().unwrap().insert(hash_hex.to_string());
            Ok(())
        }
        fn free_bytes(&self) -> u64 {
            self.free_bytes.load(Ordering::Relaxed)
        }
        fn purge_active(&self) -> bool {
            self.purge_active.load(Ordering::Relaxed)
        }
        async fn current_epoch(&self) -> u64 {
            let mut pending = self.bump_epoch_after_calls.lock().unwrap();
            if let Some(n) = pending.as_mut() {
                if *n == 0 {
                    self.epoch.fetch_add(1, Ordering::Relaxed);
                    *pending = None;
                } else {
                    *n -= 1;
                }
            }
            self.epoch.load(Ordering::Relaxed)
        }
    }

    fn fast_cfg() -> BackfillConfig {
        BackfillConfig {
            enabled: true,
            max_pending: 100_000,
            max_bytes_per_sec: 1 << 30,
            max_concurrent: 4,
            pass_interval_secs: 0,
            min_free_bytes: 0,
            peers_per_blob: 3,
            pause_poll_secs: 1,
            local_source_dirs: Vec::new(),
            local_source_delete: false,
            local_concurrency: 4,
            discovery_concurrency: 4,
        }
    }

    struct Rig {
        _bucket: tempfile::TempDir,
        _store_dir: tempfile::TempDir,
        source: DirListSource,
        manifest: Manifest,
        store: Arc<FlatBlobStore>,
        /// Per-test counters: the process-wide ones are shared by the
        /// tests running in parallel.
        metrics: &'static BackfillMetrics,
    }

    fn fresh_metrics() -> &'static BackfillMetrics {
        Box::leak(Box::default())
    }

    async fn rig(pgs: &[(u32, u32)]) -> Rig {
        rig_held(pgs, &|_, _| MY_UID).await
    }

    async fn rig_held(pgs: &[(u32, u32)], holder_of: &dyn Fn(u32, u32) -> u32) -> Rig {
        let bucket = tempfile::tempdir().unwrap();
        let validator_hex = write_generation_held(bucket.path(), pgs, holder_of);
        let source = DirListSource::new(bucket.path());
        let manifest = fetch_manifest(&source, GENERATION, &validator_hex)
            .await
            .unwrap();
        let store_dir = tempfile::tempdir().unwrap();
        let store = Arc::new(FlatBlobStore::new(store_dir.path()).unwrap());
        Rig {
            _bucket: bucket,
            _store_dir: store_dir,
            source,
            manifest,
            store,
            metrics: fresh_metrics(),
        }
    }

    async fn run(
        rig: &Rig,
        env: &Arc<FakeEnv>,
        owned: &[u32],
        cursor: Cursor,
        cfg: &BackfillConfig,
    ) -> PassSummary {
        run_with_local(rig, env, owned, cursor, cfg, LocalSources::default()).await
    }

    async fn run_with_local(
        rig: &Rig,
        env: &Arc<FakeEnv>,
        owned: &[u32],
        cursor: Cursor,
        cfg: &BackfillConfig,
        local: LocalSources,
    ) -> PassSummary {
        run_full(rig, env, &rig.source, owned, cursor, cfg, local).await
    }

    async fn run_on(
        rig: &Rig,
        env: &Arc<FakeEnv>,
        source: &dyn ListSource,
        owned: &[u32],
        cursor: Cursor,
        cfg: &BackfillConfig,
    ) -> PassSummary {
        run_full(
            rig,
            env,
            source,
            owned,
            cursor,
            cfg,
            LocalSources::default(),
        )
        .await
    }

    async fn run_full(
        rig: &Rig,
        env: &Arc<FakeEnv>,
        source: &dyn ListSource,
        owned: &[u32],
        cursor: Cursor,
        cfg: &BackfillConfig,
        local: LocalSources,
    ) -> PassSummary {
        let env_dyn: Arc<dyn PassEnv> = Arc::clone(env) as Arc<dyn PassEnv>;
        run_pass(
            rig.store.clone() as Arc<dyn BlobStore>,
            env_dyn,
            Arc::new(local),
            source,
            &rig.manifest,
            owned,
            cursor,
            cfg,
            5,
            rig.metrics,
        )
        .await
    }

    /// Only the records naming THIS miner as holder are candidates: with
    /// 60 records over two stripes and thirty distinct holders rotating
    /// per stripe, exactly two are its own (one per stripe) and the 58
    /// others are never fetched nor dialled.
    #[tokio::test]
    async fn discovery_fetches_only_this_holders_records() {
        let pgs = [(1u32, 60u32)];
        // Record i: shard i % 30 of stripe i / 30, held by position
        // (shard + stripe) % 30 of a placement of uids MY_UID..MY_UID+30.
        let rig = rig_held(&pgs, &|_, i| MY_UID + (i % 30 + i / 30) % 30).await;
        let mut env = FakeEnv::new(vec![peer(11)], HashMap::from([(11, Serve::Honest)]), &pgs);
        // Position 4: shard 4 of stripe 0, shard 3 of stripe 1.
        env.my_uid = MY_UID + 4;
        let env = Arc::new(env);
        let s = run(&rig, &env, &[1], Cursor::default(), &fast_cfg()).await;
        assert_eq!(s.candidates, 2, "one shard per stripe is mine");
        assert_eq!(s.fetched, 2);
        assert_eq!(s.other_holder, 58);
        assert!(s.walk_complete);
        for i in [4u32, 33] {
            let (data, hash) = blob(1, i);
            assert_eq!(rig.store.read(&hex::encode(hash)).await.unwrap(), data);
        }
        assert_eq!(
            env.fetches.lock().unwrap().len(),
            2,
            "no other record dialled"
        );

        // A miner no record names fetches nothing from the same list.
        let mut env = FakeEnv::new(vec![peer(11)], HashMap::from([(11, Serve::Honest)]), &pgs);
        env.my_uid = MY_UID + 30;
        let env = Arc::new(env);
        let s = run(&rig, &env, &[1], Cursor::default(), &fast_cfg()).await;
        assert_eq!(s.candidates, 0);
        assert_eq!(s.other_holder, 60);
        assert!(env.fetches.lock().unwrap().is_empty());
    }

    /// Listed-and-absent blobs are the candidates; listed-and-held are
    /// not; the cap stops the collection and the cursor stays on the cut
    /// PG; the next pass resumes there and completes the walk.
    #[tokio::test]
    async fn discovery_skips_held_blobs_and_bounds_pending() {
        let pgs = [(1u32, 3u32), (2, 2), (3, 1)];
        let rig = rig(&pgs).await;
        let env = Arc::new(FakeEnv::new(
            vec![peer(11)],
            HashMap::from([(11, Serve::Honest)]),
            &pgs,
        ));
        // Two blobs of pg 1 are already held.
        for i in 0..2 {
            let (data, hash) = blob(1, i);
            rig.store.store(&hex::encode(hash), &data).await.unwrap();
            env.record_stored(&hex::encode(hash)).unwrap();
        }
        let owned = [1u32, 2, 3, 4];
        let mut cfg = fast_cfg();
        cfg.max_pending = 2;

        let first = run(&rig, &env, &owned, Cursor::default(), &cfg).await;
        assert_eq!(first.candidates, 2, "1 missing in pg 1 + first of pg 2");
        assert_eq!(first.fetched, 2);
        assert!(first.truncated);
        assert!(!first.walk_complete);
        assert_eq!(first.scanned_pgs, 1, "pg 1 complete, pg 2 cut");
        assert_eq!(
            first.next_cursor,
            Cursor {
                generation: GENERATION,
                next_pg: 2
            },
            "resume at pg 2, which is rescanned"
        );

        let second = run(&rig, &env, &owned, first.next_cursor, &cfg).await;
        assert_eq!(
            second.candidates, 2,
            "remaining blob of pg 2 + the one of pg 3"
        );
        assert_eq!(second.fetched, 2);
        assert!(!second.truncated, "pg 3 was scanned to its end");
        assert!(!second.walk_complete, "the cap was reached before pg 4");
        assert_eq!(second.next_cursor.next_pg, 4);

        let third = run(&rig, &env, &owned, second.next_cursor, &cfg).await;
        assert_eq!(third.candidates, 0);
        assert_eq!(third.uncovered_pgs, 1, "pg 4 is owned but not listed");
        assert!(third.walk_complete);
        assert_eq!(third.next_cursor.next_pg, 0);

        // Every listed blob is now in the store with the exact payload.
        for &(pg, count) in &pgs {
            for i in 0..count {
                let (data, hash) = blob(pg, i);
                assert_eq!(rig.store.read(&hex::encode(hash)).await.unwrap(), data);
            }
        }
        let again = run(&rig, &env, &owned, third.next_cursor, &cfg).await;
        assert_eq!(again.candidates, 0, "nothing left to fetch");
        assert!(again.walk_complete);
    }

    /// A peer serving wrong bytes or nothing is counted and the next
    /// holder is tried; the payload that verifies is the one stored.
    #[tokio::test]
    async fn bad_peers_are_skipped_until_one_verifies() {
        let pgs = [(7u32, 2u32)];
        let rig = rig(&pgs).await;
        let env = Arc::new(FakeEnv::new(
            vec![peer(1), peer(2), peer(3), peer(4)],
            HashMap::from([
                (1, Serve::Unreachable),
                (2, Serve::Garbage),
                (3, Serve::Honest),
                (4, Serve::Honest),
            ]),
            &pgs,
        ));
        let s = run(&rig, &env, &[7], Cursor::default(), &fast_cfg()).await;
        assert_eq!(s.candidates, 2);
        assert_eq!(s.fetched, 2);
        assert_eq!(s.bad_peer, 4, "unreachable + garbage, per blob");
        assert_eq!(s.no_peer, 0);
        assert_eq!(rig.metrics.bad_peer_total(), 4);
        assert_eq!(rig.metrics.bad_peer_unreachable.load(Ordering::Relaxed), 2);
        assert_eq!(
            rig.metrics.bad_peer_hash_mismatch.load(Ordering::Relaxed),
            2
        );
        assert_eq!(rig.metrics.fetched.load(Ordering::Relaxed), 2);
        assert!(
            env.fetches.lock().unwrap().iter().all(|(uid, _)| *uid != 4),
            "the fourth holder is beyond peers_per_blob=3"
        );
        for i in 0..2 {
            let (data, hash) = blob(7, i);
            assert_eq!(rig.store.read(&hex::encode(hash)).await.unwrap(), data);
        }
    }

    /// The same blob is listed for this miner and for another holder
    /// (identical shard bytes in two files): that holder is tried first,
    /// before the PG's current placement.
    #[tokio::test]
    async fn listed_other_holder_is_the_first_source() {
        let pgs = [(9u32, 2u32)];
        let bucket = tempfile::tempdir().unwrap();
        let validator_hex = write_generation_records(bucket.path(), &pgs, &|pg, count| {
            let mut records: Vec<Record> = (0..count).map(|i| record(pg, i)).collect();
            records.push(record_held_by(pg, 0, 42));
            records
        });
        let source = DirListSource::new(bucket.path());
        let manifest = fetch_manifest(&source, GENERATION, &validator_hex)
            .await
            .unwrap();
        let store_dir = tempfile::tempdir().unwrap();
        let store = Arc::new(FlatBlobStore::new(store_dir.path()).unwrap());
        let rig = Rig {
            _bucket: bucket,
            _store_dir: store_dir,
            source,
            manifest,
            store,
            metrics: fresh_metrics(),
        };
        let env = Arc::new(FakeEnv::new(
            vec![peer(1), peer(2), peer(3)],
            HashMap::from([(42, Serve::Honest), (1, Serve::Honest)]),
            &pgs,
        ));
        let s = run(&rig, &env, &[9], Cursor::default(), &fast_cfg()).await;
        assert_eq!((s.candidates, s.fetched, s.bad_peer), (2, 2, 0), "{s:?}");
        assert_eq!(s.other_holder, 1, "the other holder's record");
        let (_, shared) = blob(9, 0);
        let (_, alone) = blob(9, 1);
        let fetches = env.fetches.lock().unwrap().clone();
        assert!(
            fetches.contains(&(42, hex::encode(shared))),
            "the listed holder served the shared blob: {fetches:?}"
        );
        assert!(
            fetches.contains(&(1, hex::encode(alone))),
            "the placement's first peer served the other: {fetches:?}"
        );
        assert!(!fetches.contains(&(1, hex::encode(shared))), "{fetches:?}");
    }

    /// No holder yields the blob: counted as no_peer, nothing stored,
    /// and the blob stays a candidate for the next pass.
    #[tokio::test]
    async fn no_verifying_peer_stores_nothing() {
        let pgs = [(8u32, 1u32)];
        let rig = rig(&pgs).await;
        let env = Arc::new(FakeEnv::new(
            vec![peer(1), peer(2)],
            HashMap::from([(1, Serve::Garbage), (2, Serve::NotFound)]),
            &pgs,
        ));
        let s = run(&rig, &env, &[8], Cursor::default(), &fast_cfg()).await;
        assert_eq!(s.candidates, 1);
        assert_eq!(s.fetched, 0);
        assert_eq!(s.no_peer, 1);
        assert_eq!(s.bad_peer, 2);
        let (_, hash) = blob(8, 0);
        assert!(!rig.store.has(&hex::encode(hash)));

        let empty = Arc::new(FakeEnv::new(vec![], HashMap::new(), &pgs));
        let s = run(&rig, &empty, &[8], Cursor::default(), &fast_cfg()).await;
        assert_eq!(s.no_peer, 1, "no eligible holder at all");
        assert_eq!(s.fetched, 0);
    }

    /// A list whose declared length disagrees with the real blob: the
    /// hash verifies, the length does not, nothing is stored.
    #[tokio::test]
    async fn list_length_disagreement_rejects_the_payload() {
        let bucket = tempfile::tempdir().unwrap();
        let key = deterministic_key(4);
        let (_, hash) = blob(5, 0);
        let gen_dir = bucket.path().join(format!("gen/{GENERATION}"));
        std::fs::create_dir_all(gen_dir.join("pg")).unwrap();
        let mut lying = record(5, 0);
        lying.shard_length += 1;
        let body = encode_list(5, GENERATION, 10, 20, &[lying]);
        std::fs::write(gen_dir.join(Manifest::list_path(5)), &body).unwrap();
        let unsigned = serde_json::json!({
            "generation": GENERATION, "created_at": CREATED_AT, "pg_count": 16384,
            "ec_k": 10, "ec_m": 20, "pgs": [5],
            "objects": { Manifest::list_path(5): {
                "sha256": hex::encode(Sha256::digest(&body)), "size": body.len() } },
        });
        std::fs::write(
            gen_dir.join("manifest.json"),
            serde_json::to_vec(&sign_manifest(&key, &unsigned)).unwrap(),
        )
        .unwrap();
        let source = DirListSource::new(bucket.path());
        let manifest = fetch_manifest(
            &source,
            GENERATION,
            &hex::encode(key.verifying_key().to_bytes()),
        )
        .await
        .unwrap();
        let store_dir = tempfile::tempdir().unwrap();
        let store = Arc::new(FlatBlobStore::new(store_dir.path()).unwrap());
        let env = Arc::new(FakeEnv::new(
            vec![peer(1)],
            HashMap::from([(1, Serve::Honest)]),
            &[(5, 1)],
        ));
        let metrics = fresh_metrics();
        let s = run_pass(
            store.clone() as Arc<dyn BlobStore>,
            Arc::clone(&env) as Arc<dyn PassEnv>,
            Arc::new(LocalSources::default()),
            &source,
            &manifest,
            &[5],
            Cursor::default(),
            &fast_cfg(),
            5,
            metrics,
        )
        .await;
        assert_eq!(s.fetched, 0);
        assert_eq!(s.no_peer, 1);
        assert_eq!(s.bad_peer, 1);
        assert_eq!(metrics.bad_peer_length_mismatch.load(Ordering::Relaxed), 1);
        assert!(!store.has(&hex::encode(hash)));
    }

    /// A blob that lands through another writer between discovery and
    /// the store is left alone (counted, not overwritten).
    #[tokio::test]
    async fn blob_stored_meanwhile_is_not_rewritten() {
        let pgs = [(6u32, 1u32)];
        let rig = rig(&pgs).await;
        let env = Arc::new(FakeEnv::new(
            vec![peer(1)],
            HashMap::from([(1, Serve::Honest)]),
            &pgs,
        ));
        // Present in the store but not (yet) in the inventory: the
        // inventory row is what discovery reads, so it is a candidate.
        let (data, hash) = blob(6, 0);
        rig.store.store(&hex::encode(hash), &data).await.unwrap();
        let s = run(&rig, &env, &[6], Cursor::default(), &fast_cfg()).await;
        assert_eq!(s.candidates, 1);
        assert_eq!(s.already_present, 1);
        assert_eq!(s.fetched, 0);
    }

    /// The pass waits while a purge pass runs or free space is below the
    /// floor, and resumes when the condition clears.
    #[tokio::test]
    async fn pauses_for_purge_and_low_free_space() {
        let pgs = [(9u32, 1u32)];
        let rig = rig(&pgs).await;
        let env = Arc::new(FakeEnv::new(
            vec![peer(1)],
            HashMap::from([(1, Serve::Honest)]),
            &pgs,
        ));
        env.purge_active.store(true, Ordering::Relaxed);
        let mut cfg = fast_cfg();
        cfg.min_free_bytes = 1_000;
        env.free_bytes.store(10, Ordering::Relaxed);

        let metrics = rig.metrics;
        let env2 = Arc::clone(&env);
        let pass = tokio::spawn(async move {
            let rig = rig;
            let s = run(&rig, &env2, &[9], Cursor::default(), &cfg).await;
            (s, rig)
        });
        tokio::time::sleep(Duration::from_millis(300)).await;
        assert_eq!(metrics.paused_purge_running.load(Ordering::Relaxed), 1);
        assert!(
            env.fetches.lock().unwrap().is_empty(),
            "nothing fetched while paused"
        );

        env.purge_active.store(false, Ordering::Relaxed);
        tokio::time::sleep(Duration::from_millis(1_300)).await;
        assert_eq!(metrics.paused_purge_running.load(Ordering::Relaxed), 0);
        assert_eq!(metrics.paused_low_free_space.load(Ordering::Relaxed), 1);
        assert!(env.fetches.lock().unwrap().is_empty());

        env.free_bytes.store(u64::MAX, Ordering::Relaxed);
        let (s, _rig) = tokio::time::timeout(Duration::from_secs(10), pass)
            .await
            .expect("pass resumes once the floor is cleared")
            .unwrap();
        assert_eq!(s.fetched, 1);
        assert_eq!(metrics.paused_low_free_space.load(Ordering::Relaxed), 0);
    }

    /// The epoch moving during discovery stops the walk there, but the
    /// candidates already collected are fetched; the cursor stays on the
    /// first PG not scanned, so nothing is skipped.
    #[tokio::test]
    async fn epoch_change_keeps_the_candidates_collected() {
        let pgs = [(1u32, 2u32), (2, 1), (3, 1)];
        let rig = rig(&pgs).await;
        let env = Arc::new(FakeEnv::new(
            vec![peer(1)],
            HashMap::from([(1, Serve::Honest)]),
            &pgs,
        ));
        // First check passes (pg 1), second check (before pg 2) bumps.
        *env.bump_epoch_after_calls.lock().unwrap() = Some(1);
        let s = run(&rig, &env, &[1, 2, 3], Cursor::default(), &fast_cfg()).await;
        assert!(s.epoch_changed);
        assert_eq!(s.scanned_pgs, 1);
        assert_eq!(s.candidates, 2, "pg 1's two blobs were collected");
        assert_eq!(s.fetched, 2, "and fetched despite the epoch move");
        for i in 0..2 {
            let (data, hash) = blob(1, i);
            assert_eq!(rig.store.read(&hex::encode(hash)).await.unwrap(), data);
        }
        assert_eq!(s.next_cursor.next_pg, 2, "resume at pg 2");
        assert!(!s.walk_complete);
        assert_eq!(rig.metrics.pending.load(Ordering::Relaxed), 0);

        // The next pass (computed on the new epoch, which `run` passes as
        // `epoch_at_start` = 5) resumes at pg 2 and finishes the walk.
        env.epoch.store(5, Ordering::Relaxed);
        let s2 = run(&rig, &env, &[1, 2, 3], s.next_cursor, &fast_cfg()).await;
        assert!(!s2.epoch_changed);
        assert_eq!((s2.candidates, s2.fetched), (2, 2));
        assert!(s2.walk_complete);
    }

    /// A set-aside flat root with the listed blobs at either layout: each
    /// candidate is read from it (no peer dialled) unless absent or bad,
    /// in which case the peers are tried; counters tell which.
    #[tokio::test]
    async fn local_source_is_preferred_and_peers_take_the_rest() {
        let pgs = [(4u32, 5u32)];
        let rig = rig(&pgs).await;
        let env = Arc::new(FakeEnv::new(
            vec![peer(1)],
            HashMap::from([(1, Serve::Honest)]),
            &pgs,
        ));
        let aside = tempfile::tempdir().unwrap();
        let hex_of = |i: u32| hex::encode(blob(4, i).1);
        // 0: sharded layout, 1: legacy root layout, 2: absent,
        // 3: wrong bytes under its name, 4: listed length exceeded.
        let sharded = |h: &str| aside.path().join(&h[0..2]).join(&h[2..4]);
        std::fs::create_dir_all(sharded(&hex_of(0))).unwrap();
        std::fs::write(
            sharded(&hex_of(0)).join(format!("{}.bin", hex_of(0))),
            blob(4, 0).0,
        )
        .unwrap();
        std::fs::write(
            aside.path().join(format!("{}.bin", hex_of(1))),
            blob(4, 1).0,
        )
        .unwrap();
        std::fs::write(aside.path().join(format!("{}.bin", hex_of(3))), b"bit rot").unwrap();
        let mut longer = blob(4, 4).0;
        longer.push(0);
        std::fs::write(aside.path().join(format!("{}.bin", hex_of(4))), longer).unwrap();
        let local = LocalSources::open(&[aside.path().to_path_buf()], &SourceMode::ReadOnly);
        assert_eq!(local.len(), 1);

        let s = run_with_local(&rig, &env, &[4], Cursor::default(), &fast_cfg(), local).await;
        assert_eq!(s.candidates, 5);
        assert_eq!((s.local_hit, s.local_miss, s.local_bad), (2, 1, 2), "{s:?}");
        assert_eq!(
            s.fetched, 3,
            "the miss and the two bad copies came from the peer"
        );
        assert_eq!(
            s.local_bytes,
            (blob(4, 0).0.len() + blob(4, 1).0.len()) as u64
        );
        assert_eq!(rig.metrics.local_hit.load(Ordering::Relaxed), 2);
        assert_eq!(rig.metrics.pending.load(Ordering::Relaxed), 0);
        let dialled: HashSet<String> = env
            .fetches
            .lock()
            .unwrap()
            .iter()
            .map(|(_, h)| h.clone())
            .collect();
        assert_eq!(
            dialled,
            HashSet::from([hex_of(2), hex_of(3), hex_of(4)]),
            "local hits never reach the network"
        );
        for i in 0..5 {
            let (data, hash) = blob(4, i);
            assert_eq!(rig.store.read(&hex::encode(hash)).await.unwrap(), data);
            assert!(
                env.live.lock().unwrap().contains(&hex::encode(hash)),
                "inventory row"
            );
        }
        assert!(
            !aside.path().join("trash").exists() && !aside.path().join(".tmp").exists(),
            "the set-aside root is read-only"
        );
    }

    fn pg_of_path(rel_path: &str) -> Option<u32> {
        rel_path
            .rsplit('/')
            .next()?
            .strip_suffix(".list")?
            .parse()
            .ok()
    }

    /// A bucket mirror that delays each PG list by `delay_ms(pg)` and
    /// counts the list fetches in flight.
    struct SlowSource {
        inner: DirListSource,
        delay_ms: fn(u32) -> u64,
        in_flight: AtomicU64,
        max_in_flight: AtomicU64,
    }

    impl SlowSource {
        fn new(root: &std::path::Path, delay_ms: fn(u32) -> u64) -> Self {
            Self {
                inner: DirListSource::new(root),
                delay_ms,
                in_flight: AtomicU64::new(0),
                max_in_flight: AtomicU64::new(0),
            }
        }
    }

    #[async_trait::async_trait]
    impl ListSource for SlowSource {
        async fn fetch(&self, rel_path: &str, max_len: u64) -> Result<bytes::Bytes> {
            let Some(pg) = pg_of_path(rel_path) else {
                return self.inner.fetch(rel_path, max_len).await;
            };
            let now = self.in_flight.fetch_add(1, Ordering::SeqCst) + 1;
            self.max_in_flight.fetch_max(now, Ordering::SeqCst);
            tokio::time::sleep(Duration::from_millis((self.delay_ms)(pg))).await;
            let out = self.inner.fetch(rel_path, max_len).await;
            self.in_flight.fetch_sub(1, Ordering::SeqCst);
            out
        }
    }

    /// Several lists in flight, later PGs answering first, a pending cap
    /// cutting PGs and uncovered PGs on the way: every pass ends exactly
    /// as the sequential walk's (candidates, fetched, scanned, uncovered,
    /// truncated, cursor), down to the end of the walk.
    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn concurrent_discovery_keeps_the_sequential_cursor() {
        // PG 5 and 13 are owned but not listed.
        let pgs: Vec<(u32, u32)> = (1..=12)
            .filter(|pg| *pg != 5)
            .map(|pg| (pg, 1 + pg % 3))
            .collect();
        let owned: Vec<u32> = (1..=13).collect();
        let mut runs = Vec::new();
        for concurrency in [1usize, 8] {
            let rig = rig(&pgs).await;
            let env = Arc::new(FakeEnv::new(
                vec![peer(11)],
                HashMap::from([(11, Serve::Honest)]),
                &pgs,
            ));
            let source = SlowSource::new(rig._bucket.path(), |pg| u64::from(20 - pg.min(20)) * 3);
            let mut cfg = fast_cfg();
            cfg.max_pending = 4;
            cfg.discovery_concurrency = concurrency;
            let mut cursor = Cursor::default();
            let mut passes = Vec::new();
            loop {
                let s = run_on(&rig, &env, &source, &owned, cursor, &cfg).await;
                assert_eq!(s.list_errors, 0);
                assert_eq!(rig.metrics.pending.load(Ordering::Relaxed), 0);
                passes.push((
                    s.candidates,
                    s.fetched,
                    s.scanned_pgs,
                    s.uncovered_pgs,
                    s.truncated,
                    s.walk_complete,
                    s.next_cursor,
                ));
                cursor = s.next_cursor;
                if s.walk_complete {
                    break;
                }
                assert!(passes.len() < 50, "the walk ends");
            }
            for &(pg, count) in &pgs {
                for i in 0..count {
                    let (data, hash) = blob(pg, i);
                    assert_eq!(rig.store.read(&hex::encode(hash)).await.unwrap(), data);
                }
            }
            let again = run_on(&rig, &env, &source, &owned, cursor, &cfg).await;
            assert_eq!((again.candidates, again.walk_complete), (0, true));
            runs.push((passes, source.max_in_flight.load(Ordering::SeqCst)));
        }
        assert_eq!(runs[0].0, runs[1].0, "same passes whatever the concurrency");
        assert!(runs[0].0.len() > 3, "the cap cut the walk: {:?}", runs[0].0);
        assert_eq!(runs[0].1, 1, "one list at a time");
        assert!(runs[1].1 > 1, "several lists in flight");
    }

    /// An epoch move while later lists are already scanned: the walk
    /// stops at the first PG not consumed, the candidates consumed are
    /// fetched, nothing of the PGs scanned ahead is.
    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn epoch_move_with_lists_scanned_ahead_keeps_the_cursor() {
        let pgs: Vec<(u32, u32)> = (1..=8).map(|pg| (pg, 2)).collect();
        let owned: Vec<u32> = (1..=8).collect();
        let rig = rig(&pgs).await;
        let env = Arc::new(FakeEnv::new(
            vec![peer(1)],
            HashMap::from([(1, Serve::Honest)]),
            &pgs,
        ));
        // Checks before pg 1 and pg 2 pass, the one before pg 3 bumps.
        *env.bump_epoch_after_calls.lock().unwrap() = Some(2);
        let source = SlowSource::new(rig._bucket.path(), |pg| if pg <= 2 { 100 } else { 0 });
        let mut cfg = fast_cfg();
        cfg.discovery_concurrency = 8;
        let s = run_on(&rig, &env, &source, &owned, Cursor::default(), &cfg).await;
        assert!(s.epoch_changed);
        assert_eq!((s.scanned_pgs, s.candidates, s.fetched), (2, 4, 4), "{s:?}");
        assert_eq!(s.next_cursor.next_pg, 3);
        assert!(!s.walk_complete);
        assert!(source.max_in_flight.load(Ordering::SeqCst) > 2);
        for pg in 3..=8 {
            for i in 0..2 {
                assert!(!rig.store.has(&hex::encode(blob(pg, i).1)), "pg {pg}");
            }
        }
    }

    /// A bucket mirror whose list of `gate_pg` is only served once the
    /// blob `wait_for` is in the inventory: a pass that fetched only after
    /// discovery would time out on it.
    struct GatedSource {
        inner: DirListSource,
        env: Arc<FakeEnv>,
        gate_pg: u32,
        wait_for: String,
    }

    #[async_trait::async_trait]
    impl ListSource for GatedSource {
        async fn fetch(&self, rel_path: &str, max_len: u64) -> Result<bytes::Bytes> {
            if pg_of_path(rel_path) == Some(self.gate_pg) {
                let deadline = tokio::time::Instant::now() + Duration::from_secs(5);
                while !self.env.live.lock().unwrap().contains(&self.wait_for) {
                    anyhow::ensure!(
                        tokio::time::Instant::now() < deadline,
                        "gate: {} never stored",
                        self.wait_for
                    );
                    tokio::time::sleep(Duration::from_millis(10)).await;
                }
            }
            self.inner.fetch(rel_path, max_len).await
        }
    }

    /// The candidates of a consumed PG are fetched while discovery goes
    /// on (pipeline), for the peer path and through the local stage.
    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn fetch_starts_while_discovery_continues() {
        let pgs = [(1u32, 1u32), (2, 1)];
        for with_local in [false, true] {
            let rig = rig(&pgs).await;
            let env = Arc::new(FakeEnv::new(
                vec![peer(1)],
                HashMap::from([(1, Serve::Honest)]),
                &pgs,
            ));
            let source = GatedSource {
                inner: DirListSource::new(rig._bucket.path()),
                env: Arc::clone(&env),
                gate_pg: 2,
                wait_for: hex::encode(blob(1, 0).1),
            };
            let mut cfg = fast_cfg();
            cfg.discovery_concurrency = 1;
            let aside = tempfile::tempdir().unwrap();
            let local = if with_local {
                // Present nowhere locally: the miss goes on to the peers.
                LocalSources::open(&[aside.path().to_path_buf()], &SourceMode::ReadOnly)
            } else {
                LocalSources::default()
            };
            let s = run_full(&rig, &env, &source, &[1, 2], Cursor::default(), &cfg, local).await;
            assert_eq!(
                s.list_errors, 0,
                "pg 1 was stored before pg 2's list: {s:?}"
            );
            assert_eq!((s.candidates, s.fetched), (2, 2));
            assert_eq!(s.local_miss, if with_local { 2 } else { 0 });
            assert!(s.walk_complete);
        }
    }

    /// A failed inventory lookup skips that PG only (a list error, none of
    /// its blobs a candidate); one batched lookup per list.
    #[tokio::test]
    async fn inventory_error_skips_only_its_pg() {
        let pgs = [(1u32, 2u32), (2, 2), (3, 2)];
        let rig = rig(&pgs).await;
        let env = Arc::new(FakeEnv::new(
            vec![peer(1)],
            HashMap::from([(1, Serve::Honest)]),
            &pgs,
        ));
        *env.fail_lookup_of.lock().unwrap() = Some(blob(2, 0).1);
        let s = run(&rig, &env, &[1, 2, 3], Cursor::default(), &fast_cfg()).await;
        assert_eq!((s.list_errors, s.scanned_pgs), (1, 2));
        assert_eq!((s.candidates, s.fetched), (4, 4));
        assert!(s.walk_complete);
        assert_eq!(env.lookup_calls.load(Ordering::Relaxed), 3, "one per list");
        for i in 0..2 {
            assert!(!rig.store.has(&hex::encode(blob(2, i).1)));
        }
    }

    // ------------------------------------------------------------------
    // Micro-benchmark
    // ------------------------------------------------------------------

    /// The live miner's discovery against a real SQLite inventory file:
    /// read-only connections of `crate::inventory`, optional simulated
    /// per-lookup latency (a cold disk), fetches recorded and refused.
    struct BenchEnv {
        path: std::path::PathBuf,
        readers: Mutex<Vec<rusqlite::Connection>>,
        latency: Duration,
        fetched: Mutex<Vec<String>>,
    }

    #[async_trait::async_trait]
    impl PassEnv for BenchEnv {
        fn live_among(&self, hashes: &[[u8; 32]]) -> Result<Vec<bool>> {
            let popped = self.readers.lock().unwrap().pop();
            let conn = match popped {
                Some(c) => c,
                None => crate::inventory::open_reader(&self.path)?,
            };
            if !self.latency.is_zero() {
                std::thread::sleep(self.latency * hashes.len() as u32);
            }
            let out = crate::inventory::live_among_on(&conn, hashes);
            self.readers.lock().unwrap().push(conn);
            out
        }
        async fn holders(&self, _pg_id: u32, _listed: &[u32], _max: usize) -> Vec<Peer> {
            vec![peer(1)]
        }
        fn my_uid(&self) -> u32 {
            MY_UID
        }
        async fn fetch(&self, _peer: &Peer, hash_hex: &str) -> Result<Vec<u8>, FetchError> {
            self.fetched.lock().unwrap().push(hash_hex.to_string());
            Err(FetchError::NotFound)
        }
        async fn lock_write(&self, hash_hex: &str) -> state::HashWriteLock {
            state::lock_hash_write(hash_hex).await
        }
        fn record_stored(&self, _hash_hex: &str) -> Result<()> {
            Ok(())
        }
        fn free_bytes(&self) -> u64 {
            u64::MAX
        }
        fn purge_active(&self) -> bool {
            false
        }
        async fn current_epoch(&self) -> u64 {
            5
        }
    }

    fn bench_hash(pg: u32, i: u32) -> [u8; 32] {
        let mut seed = [0u8; 8];
        seed[..4].copy_from_slice(&pg.to_le_bytes());
        seed[4..].copy_from_slice(&i.to_le_bytes());
        *blake3::hash(&seed).as_bytes()
    }

    /// The former discovery, kept here as the benchmark baseline: one
    /// list at a time decoded on the async worker, a holders `Vec` per
    /// blob, one inventory point query per own blob through the shared
    /// connection lock (`inventory::with_db`: `block_in_place`, mutex,
    /// prepared statement).
    async fn legacy_discovery(
        source: &dyn ListSource,
        manifest: &Manifest,
        owned: &[u32],
        conn: &Mutex<rusqlite::Connection>,
        latency: Duration,
    ) -> (u64, Vec<String>) {
        fn decide(
            conn: &Mutex<rusqlite::Connection>,
            latency: Duration,
            hash: [u8; 32],
            holders: Vec<u32>,
            missing: &mut Vec<String>,
        ) {
            if !holders.contains(&MY_UID) {
                return;
            }
            let hex = hex::encode(hash);
            let live = crate::helpers::blocking(|| {
                let c = conn.lock().unwrap();
                if !latency.is_zero() {
                    std::thread::sleep(latency);
                }
                let mut stmt = c
                    .prepare_cached(
                        "SELECT stored_at FROM shards WHERE hash = ?1 AND trashed_at IS NULL",
                    )
                    .unwrap();
                let mut rows = stmt.query(rusqlite::params![hex]).unwrap();
                rows.next().unwrap().is_some()
            });
            if !live {
                missing.push(hex);
            }
        }
        let mut records = 0u64;
        let mut missing = Vec::new();
        for &pg_id in owned {
            let obj = manifest.object_for_pg(pg_id).unwrap();
            let path = format!("gen/{}/{}", manifest.generation, Manifest::list_path(pg_id));
            let bytes = pg_lists::fetch_sized(source, &path, obj.size)
                .await
                .unwrap();
            let expect = ListExpectation {
                pg_id,
                generation: manifest.generation,
                ec_k: manifest.ec_k,
                ec_m: manifest.ec_m,
                sha256_hex: &obj.sha256,
            };
            let mut group: Option<([u8; 32], Vec<u32>)> = None;
            let header =
                pg_lists::decode_list(&bytes, expect, &mut |record| match group.as_mut() {
                    Some((h, holders)) if *h == record.blob_hash => holders.push(record.holder_uid),
                    _ => {
                        if let Some((h, holders)) =
                            group.replace((record.blob_hash, vec![record.holder_uid]))
                        {
                            decide(conn, latency, h, holders, &mut missing);
                        }
                    }
                })
                .unwrap();
            if let Some((h, holders)) = group.take() {
                decide(conn, latency, h, holders, &mut missing);
            }
            records += u64::from(header.count);
        }
        (records, missing)
    }

    /// Discovery throughput, former path vs this one, on lists of 250 000
    /// records (2 % this miner's, half of those in an inventory of 1 M
    /// other rows), with and without a simulated per-lookup disk latency.
    /// Run: `cargo test -p miner --release -- --ignored --nocapture
    /// discovery_benchmark`.
    #[tokio::test(flavor = "multi_thread", worker_threads = 8)]
    #[ignore = "micro-benchmark, run on demand"]
    async fn discovery_benchmark() {
        const PGS: u32 = 8;
        const RECORDS: u32 = 250_000;
        const OWN_EVERY: u32 = 50;
        const FILLER_ROWS: u32 = 1_000_000;
        let pgs: Vec<(u32, u32)> = (1..=PGS).map(|pg| (pg, RECORDS)).collect();
        let owned: Vec<u32> = (1..=PGS).collect();
        let bucket = tempfile::tempdir().unwrap();
        let validator_hex = write_generation_records(bucket.path(), &pgs, &|pg, count| {
            (0..count)
                .map(|i| Record {
                    blob_hash: bench_hash(pg, i),
                    shard_length: 1000,
                    holder_uid: if i % OWN_EVERY == 0 {
                        MY_UID
                    } else {
                        10_000 + i % 29
                    },
                })
                .collect()
        });
        let source = DirListSource::new(bucket.path());
        let manifest = fetch_manifest(&source, GENERATION, &validator_hex)
            .await
            .unwrap();

        // Inventory: the miner's schema, filler rows, half of the own
        // blobs live.
        let db_dir = tempfile::tempdir().unwrap();
        let db_path = db_dir.path().join("inventory.db");
        let writer = rusqlite::Connection::open(&db_path).unwrap();
        writer
            .execute_batch(
                "PRAGMA journal_mode=WAL; PRAGMA synchronous=NORMAL;
                 CREATE TABLE shards (hash TEXT PRIMARY KEY, stored_at INTEGER NOT NULL,
                   trashed_at INTEGER);
                 CREATE INDEX idx_stored_at ON shards(stored_at);
                 CREATE INDEX idx_trashed_at ON shards(trashed_at) WHERE trashed_at IS NOT NULL;",
            )
            .unwrap();
        {
            let tx = writer.unchecked_transaction().unwrap();
            let mut ins = tx
                .prepare("INSERT INTO shards (hash, stored_at) VALUES (?1, 1)")
                .unwrap();
            for i in 0..FILLER_ROWS {
                ins.execute([hex::encode(blake3::hash(&i.to_be_bytes()).as_bytes())])
                    .unwrap();
            }
            for pg in 1..=PGS {
                for i in (0..RECORDS).step_by((OWN_EVERY * 2) as usize) {
                    ins.execute([hex::encode(bench_hash(pg, i))]).unwrap();
                }
            }
            drop(ins);
            tx.commit().unwrap();
        }
        let shared = Mutex::new(writer);
        let mut expected: Vec<String> = (1..=PGS)
            .flat_map(|pg| {
                (OWN_EVERY..RECORDS)
                    .step_by((OWN_EVERY * 2) as usize)
                    .map(move |i| hex::encode(bench_hash(pg, i)))
            })
            .collect();
        expected.sort_unstable();
        let total_records = u64::from(PGS * RECORDS);

        let mut lines = Vec::new();
        for latency_us in [0u64, 200] {
            let latency = Duration::from_micros(latency_us);
            let t = std::time::Instant::now();
            let (records, mut legacy) =
                legacy_discovery(&source, &manifest, &owned, &shared, latency).await;
            let legacy_secs = t.elapsed().as_secs_f64();
            assert_eq!(records, total_records);
            legacy.sort_unstable();
            assert_eq!(legacy, expected, "baseline finds the absent own blobs");
            lines.push(format!(
                "latency {latency_us:>3} us | former   : {legacy_secs:7.3} s, {:>10.0} records/s, {:6.2} PGs/s",
                records as f64 / legacy_secs,
                f64::from(PGS) / legacy_secs
            ));
            for concurrency in [1usize, 8] {
                let env = Arc::new(BenchEnv {
                    path: db_path.clone(),
                    readers: Mutex::new(Vec::new()),
                    latency,
                    fetched: Mutex::new(Vec::new()),
                });
                let store_dir = tempfile::tempdir().unwrap();
                let store = Arc::new(FlatBlobStore::new(store_dir.path()).unwrap());
                let mut cfg = fast_cfg();
                cfg.max_pending = 1_000_000;
                cfg.max_concurrent = 64;
                cfg.peers_per_blob = 1;
                cfg.discovery_concurrency = concurrency;
                let s = run_pass(
                    store as Arc<dyn BlobStore>,
                    Arc::clone(&env) as Arc<dyn PassEnv>,
                    Arc::new(LocalSources::default()),
                    &source,
                    &manifest,
                    &owned,
                    Cursor::default(),
                    &cfg,
                    5,
                    fresh_metrics(),
                )
                .await;
                assert_eq!(s.records, total_records);
                assert_eq!(s.candidates, expected.len() as u64);
                let mut fetched = env.fetched.lock().unwrap().clone();
                fetched.sort_unstable();
                assert_eq!(fetched, expected, "same candidates as the baseline");
                let secs = s.discovery_ms.max(1) as f64 / 1000.0;
                lines.push(format!(
                    "latency {latency_us:>3} us | new (c={concurrency}): {secs:7.3} s, {:>10.0} records/s, {:6.2} PGs/s, x{:.1}",
                    s.records as f64 / secs,
                    f64::from(PGS) / secs,
                    legacy_secs / secs
                ));
            }
        }
        println!(
            "discovery benchmark: {PGS} lists x {RECORDS} records, 1/{OWN_EVERY} own, {} absent, inventory {} rows",
            expected.len(),
            FILLER_ROWS + PGS * RECORDS / (OWN_EVERY * 2)
        );
        for line in lines {
            println!("{line}");
        }
    }

    // ------------------------------------------------------------------
    // BACKFILL_LOCAL_SOURCE_DELETE (move semantics)
    // ------------------------------------------------------------------

    /// A set-aside root plus a durable (packed) live store for the move
    /// tests.
    struct MoveRig {
        aside: tempfile::TempDir,
        live_dir: tempfile::TempDir,
        live: Arc<crate::packed_store::PackedStore>,
    }

    fn move_rig() -> MoveRig {
        let aside = tempfile::tempdir().unwrap();
        let live_dir = tempfile::tempdir().unwrap();
        let live = crate::packed_store::PackedStore::open(live_dir.path().join("packed")).unwrap();
        MoveRig {
            aside,
            live_dir,
            live,
        }
    }

    impl MoveRig {
        fn sharded_path(&self, hash: &[u8; 32]) -> std::path::PathBuf {
            let h = hex::encode(hash);
            self.aside
                .path()
                .join(&h[0..2])
                .join(&h[2..4])
                .join(format!("{h}.bin"))
        }
        fn legacy_path(&self, hash: &[u8; 32]) -> std::path::PathBuf {
            self.aside.path().join(format!("{}.bin", hex::encode(hash)))
        }
        fn put_sharded(&self, hash: &[u8; 32], data: &[u8]) -> std::path::PathBuf {
            let path = self.sharded_path(hash);
            std::fs::create_dir_all(path.parent().unwrap()).unwrap();
            std::fs::write(&path, data).unwrap();
            path
        }
        fn put_legacy(&self, hash: &[u8; 32], data: &[u8]) -> std::path::PathBuf {
            let path = self.legacy_path(hash);
            std::fs::write(&path, data).unwrap();
            path
        }
        fn mode(&self) -> SourceMode {
            SourceMode::Move {
                live_root: self.live_dir.path().to_path_buf(),
            }
        }
        fn sources(&self, mode: &SourceMode) -> LocalSources {
            LocalSources::open(&[self.aside.path().to_path_buf()], mode)
        }
    }

    async fn run_live(
        rig: &Rig,
        live: Arc<dyn BlobStore>,
        env: &Arc<FakeEnv>,
        owned: &[u32],
        local: LocalSources,
    ) -> PassSummary {
        let env_dyn: Arc<dyn PassEnv> = Arc::clone(env) as Arc<dyn PassEnv>;
        run_pass(
            live,
            env_dyn,
            Arc::new(local),
            &rig.source,
            &rig.manifest,
            owned,
            Cursor::default(),
            &fast_cfg(),
            5,
            rig.metrics,
        )
        .await
    }

    /// Move mode: each verified local copy (sharded and legacy layouts) is
    /// unlinked once the durable live store holds it and its inventory row
    /// is written; the shard directories stay; the live copies read back.
    #[tokio::test]
    async fn local_move_removes_the_source_after_store_and_inventory() {
        let pgs = [(4u32, 2u32)];
        let rig = rig(&pgs).await;
        let env = Arc::new(FakeEnv::new(vec![peer(1)], HashMap::new(), &pgs));
        let m = move_rig();
        let sharded = m.put_sharded(&blob(4, 0).1, &blob(4, 0).0);
        let legacy = m.put_legacy(&blob(4, 1).1, &blob(4, 1).0);
        let local = m.sources(&m.mode());
        assert_eq!(local.removable_roots(), 1);

        let s = run_live(&rig, m.live.clone(), &env, &[4], local).await;
        assert_eq!(
            (s.local_hit, s.local_deleted, s.local_delete_errors),
            (2, 2, 0),
            "{s:?}"
        );
        assert_eq!(rig.metrics.local_deleted.load(Ordering::Relaxed), 2);
        assert!(!sharded.exists() && !legacy.exists(), "sources unlinked");
        assert!(
            sharded.parent().unwrap().is_dir(),
            "directories are left alone"
        );
        for i in 0..2 {
            let (data, hash) = blob(4, i);
            assert_eq!(m.live.read(&hex::encode(hash)).await.unwrap(), data);
            assert!(env.live.lock().unwrap().contains(&hex::encode(hash)));
        }
        assert!(env.fetches.lock().unwrap().is_empty(), "no peer dialled");
    }

    /// Flag off (read-only mode): the copy lands in the live store and
    /// the source file stays.
    #[tokio::test]
    async fn local_move_off_keeps_the_source() {
        let pgs = [(4u32, 1u32)];
        let rig = rig(&pgs).await;
        let env = Arc::new(FakeEnv::new(vec![peer(1)], HashMap::new(), &pgs));
        let m = move_rig();
        let src = m.put_sharded(&blob(4, 0).1, &blob(4, 0).0);
        let local = m.sources(&SourceMode::ReadOnly);
        assert_eq!(local.removable_roots(), 0);

        let s = run_live(&rig, m.live.clone(), &env, &[4], local).await;
        assert_eq!(
            (s.local_hit, s.local_deleted, s.local_delete_errors),
            (1, 0, 0)
        );
        assert!(m.live.has(&hex::encode(blob(4, 0).1)));
        assert_eq!(std::fs::read(&src).unwrap(), blob(4, 0).0, "source kept");
    }

    /// Copies that fail verification (wrong bytes, longer than listed)
    /// are never removed, even in move mode; the peers serve them.
    #[tokio::test]
    async fn local_move_never_removes_a_bad_copy() {
        let pgs = [(4u32, 2u32)];
        let rig = rig(&pgs).await;
        let env = Arc::new(FakeEnv::new(
            vec![peer(1)],
            HashMap::from([(1, Serve::Honest)]),
            &pgs,
        ));
        let m = move_rig();
        let rotten = m.put_sharded(&blob(4, 0).1, b"bit rot");
        let mut longer_bytes = blob(4, 1).0;
        longer_bytes.push(0);
        let longer = m.put_legacy(&blob(4, 1).1, &longer_bytes);

        let s = run_live(&rig, m.live.clone(), &env, &[4], m.sources(&m.mode())).await;
        assert_eq!((s.local_bad, s.fetched), (2, 2), "{s:?}");
        assert_eq!((s.local_deleted, s.local_delete_errors), (0, 0));
        assert_eq!(std::fs::read(&rotten).unwrap(), b"bit rot");
        assert_eq!(std::fs::read(&longer).unwrap(), longer_bytes);
    }

    /// The live store already holds the blob: the local duplicate is
    /// removed only when the live store has it with a live inventory row
    /// and the live copy reads back and verifies; without the row the
    /// source is kept (counted).
    #[tokio::test]
    async fn local_move_removes_a_duplicate_only_when_the_live_store_has_it() {
        let pgs = [(4u32, 2u32)];
        let rig = rig(&pgs).await;
        let env = Arc::new(FakeEnv::new(vec![peer(1)], HashMap::new(), &pgs));
        let m = move_rig();
        let (good, good_h) = blob(4, 0);
        let (other, other_h) = blob(4, 1);
        // Both in the live store; only blob 0 has its live inventory row
        // (blob 1 stands for a copy the inventory does not know). Driven
        // through `local_one` directly: discovery would not emit blob 0.
        m.live.store(&hex::encode(good_h), &good).await.unwrap();
        m.live.store(&hex::encode(other_h), &other).await.unwrap();
        let dup = m.put_sharded(&good_h, &good);
        let kept = m.put_legacy(&other_h, &other);
        let local = m.sources(&m.mode());
        let blob0 = Candidate {
            pg_id: 4,
            hash: good_h,
            shard_length: good.len() as u64,
            listed_holders: Vec::new(),
        };
        let blob1 = Candidate {
            pg_id: 4,
            hash: other_h,
            shard_length: other.len() as u64,
            listed_holders: Vec::new(),
        };
        env.record_stored(&hex::encode(good_h)).unwrap();

        let a = local_one(m.live.as_ref(), env.as_ref(), &local, blob0, rig.metrics).await;
        assert!(a.unresolved.is_none());
        assert_eq!(
            (
                a.outcome.already_present,
                a.outcome.local_deleted,
                a.outcome.local_delete_errors
            ),
            (1, 1, 0)
        );
        assert!(
            !dup.exists(),
            "duplicate of a recorded, verified live copy removed"
        );

        let b = local_one(m.live.as_ref(), env.as_ref(), &local, blob1, rig.metrics).await;
        assert_eq!(
            (
                b.outcome.already_present,
                b.outcome.local_deleted,
                b.outcome.local_delete_errors
            ),
            (1, 0, 1)
        );
        assert_eq!(
            std::fs::read(&kept).unwrap(),
            other,
            "no live inventory row: source kept"
        );
    }

    /// A live store whose answers may come from unsynced flat files or a
    /// mover that re-trashes (the migrating store) is not durable: no move.
    #[tokio::test]
    async fn local_move_is_off_on_a_migrating_store() {
        let m = move_rig();
        let flat = Arc::new(FlatBlobStore::new(m.live_dir.path()).unwrap());
        let migrating = crate::migrating_store::MigratingStore {
            flat,
            packed: m.live.clone(),
        };
        let mut cfg = fast_cfg();
        cfg.local_source_delete = true;
        assert!(m.live.store_is_durable());
        assert!(!migrating.store_is_durable());
        assert_eq!(
            source_mode(&cfg, &migrating, m.live_dir.path()),
            SourceMode::ReadOnly
        );
    }

    /// A failed unlink (here the source is a symlink, which the move
    /// refuses to touch) and a failed inventory insert are counted, keep
    /// the source, and do not stop the pass.
    #[tokio::test]
    async fn local_move_errors_are_counted_and_do_not_fail_the_pass() {
        let pgs = [(4u32, 3u32)];
        let rig = rig(&pgs).await;
        let env = Arc::new(FakeEnv::new(vec![peer(1)], HashMap::new(), &pgs));
        let m = move_rig();
        let elsewhere = tempfile::tempdir().unwrap();
        let target = elsewhere.path().join("target.bin");
        std::fs::write(&target, blob(4, 0).0).unwrap();
        let link = m.sharded_path(&blob(4, 0).1);
        std::fs::create_dir_all(link.parent().unwrap()).unwrap();
        std::os::unix::fs::symlink(&target, &link).unwrap();
        let fine = m.put_sharded(&blob(4, 1).1, &blob(4, 1).0);

        let s = run_live(&rig, m.live.clone(), &env, &[4], m.sources(&m.mode())).await;
        assert_eq!(s.local_hit, 2);
        assert_eq!((s.local_deleted, s.local_delete_errors), (1, 1), "{s:?}");
        assert_eq!(rig.metrics.local_delete_errors.load(Ordering::Relaxed), 1);
        assert!(
            link.symlink_metadata().is_ok() && target.exists(),
            "symlink and target kept"
        );
        assert!(!fine.exists());
        assert_eq!(s.local_miss, 1, "the pass went on to the third blob");

        // Inventory insert failure: stored, but the source is kept.
        let rig2 = rig_held(&[(5u32, 1u32)], &|_, _| MY_UID).await;
        let env2 = Arc::new(FakeEnv::new(vec![peer(1)], HashMap::new(), &[(5, 1)]));
        env2.fail_record.store(true, Ordering::Relaxed);
        let src = m.put_sharded(&blob(5, 0).1, &blob(5, 0).0);
        let s2 = run_live(&rig2, m.live.clone(), &env2, &[5], m.sources(&m.mode())).await;
        assert_eq!(
            (s2.local_hit, s2.local_deleted, s2.local_delete_errors),
            (1, 0, 1),
            "{s2:?}"
        );
        assert!(m.live.has(&hex::encode(blob(5, 0).1)));
        assert!(src.exists(), "no inventory row: source kept");
    }

    /// The flag is honoured only on a durable live store.
    #[tokio::test]
    async fn local_move_requires_a_durable_live_store() {
        let dir = tempfile::tempdir().unwrap();
        let flat = FlatBlobStore::new(dir.path()).unwrap();
        let mut cfg = fast_cfg();
        assert_eq!(source_mode(&cfg, &flat, dir.path()), SourceMode::ReadOnly);
        cfg.local_source_delete = true;
        assert_eq!(
            source_mode(&cfg, &flat, dir.path()),
            SourceMode::ReadOnly,
            "flat store: no sync before the ACK"
        );
        let packed = crate::packed_store::PackedStore::open(dir.path().join("packed")).unwrap();
        assert_eq!(
            source_mode(&cfg, packed.as_ref(), dir.path()),
            SourceMode::Move {
                live_root: dir.path().to_path_buf()
            }
        );
    }
}

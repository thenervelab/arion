use anyhow::Context;
use anyhow::Result;
use common::{ClusterMap, P2PStateSyncRequest};
use std::collections::HashSet;
use std::net::SocketAddr;
use tracing::{debug, error, info, warn};

#[derive(Debug, Clone, PartialEq, Eq)]
enum SyncSourceKind {
    Validator,
    HistoricalSeeder,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct SyncSource {
    node_id: String,
    addr: SocketAddr,
    kind: SyncSourceKind,
}

/// Default number of most recent epochs kept in `epoch_archive/`.
///
/// Every epoch writes one cluster map (a few hundred KB) and nothing ever
/// removed them: observed on a test bench, ~26 000 maps (~6 GB) accumulated
/// per node since epoch 0, enough to fill the disk of a small node, where
/// the miner then cannot even persist its own state. 2 000 epochs cover
/// weeks at the current epoch rate; placement reads of older epochs fall
/// back to the validator (`rebalance::get_or_fetch_cluster_map`), which
/// keeps the full history.
pub const DEFAULT_EPOCH_ARCHIVE_KEEP: u64 = 2_000;

/// Directory of the archive, under the data directory.
pub const EPOCH_ARCHIVE_DIR: &str = "epoch_archive";

/// Number of epochs kept: `EPOCH_ARCHIVE_KEEP` (a positive integer) or
/// [`DEFAULT_EPOCH_ARCHIVE_KEEP`]. Resolved once per process.
pub fn epoch_archive_keep() -> u64 {
    static KEEP: std::sync::OnceLock<u64> = std::sync::OnceLock::new();
    *KEEP.get_or_init(|| parse_archive_keep(std::env::var("EPOCH_ARCHIVE_KEEP").ok().as_deref()))
}

fn parse_archive_keep(raw: Option<&str>) -> u64 {
    let Some(raw) = raw else {
        return DEFAULT_EPOCH_ARCHIVE_KEEP;
    };
    match raw.trim().parse::<u64>() {
        Ok(keep) if keep > 0 => keep,
        _ => {
            error!(
                value = raw,
                default = DEFAULT_EPOCH_ARCHIVE_KEEP,
                "EPOCH_ARCHIVE_KEEP must be a positive integer, using the default"
            );
            DEFAULT_EPOCH_ARCHIVE_KEEP
        }
    }
}

/// Epoch number of an archive file name (`epoch_<n>.json`).
fn parse_epoch_file_name(name: &str) -> Option<u64> {
    name.strip_prefix("epoch_")?
        .strip_suffix(".json")?
        .parse()
        .ok()
}

pub fn epoch_file_name(epoch: u64) -> String {
    format!("epoch_{epoch}.json")
}

/// First epoch to request: the one after the highest archived, but never
/// before the retention window ending at `target_epoch`, so a fresh node
/// (or one that was down longer than the window) does not download (and
/// then prune) the whole history from epoch 0. `keep` is at least 1.
fn sync_start_epoch(highest_on_disk: Option<u64>, target_epoch: u64, keep: u64) -> u64 {
    let window_start = target_epoch.saturating_add(1).saturating_sub(keep.max(1));
    highest_on_disk
        .map_or(0, |h| h.saturating_add(1))
        .max(window_start)
}

/// In-memory view of the epochs present in `epoch_archive/`, built by one
/// directory scan at startup and kept in step by the sync (which records
/// every file it writes) and the pruning (which removes what it deletes).
/// Bounded by the retention window, so the sync never lists the directory
/// again and the server knows which epochs it can answer with.
#[derive(Debug, Default, Clone, PartialEq, Eq)]
struct ArchiveIndex {
    epochs: std::collections::BTreeSet<u64>,
}

impl ArchiveIndex {
    fn highest(&self) -> Option<u64> {
        self.epochs.last().copied()
    }

    /// Highest archived epoch not above `target`.
    fn highest_at_most(&self, target: u64) -> Option<u64> {
        self.epochs.range(..=target).next_back().copied()
    }

    fn record(&mut self, epoch: u64) {
        self.epochs.insert(epoch);
    }

    /// Remove from the index, and return, every epoch outside the window
    /// of the `keep` most recent epoch numbers ending at the highest one
    /// not above `target` (the epoch of the held map), and every epoch
    /// above `target` (the files still have to be deleted). Anchored on
    /// the held map, never on the highest file: an epoch above it (left
    /// by an older build that did not bound what it wrote) must not push
    /// the window past every legitimate map.
    fn take_prunable(&mut self, keep: u64, target: u64) -> Vec<u64> {
        let above = self.epochs.split_off(&target.saturating_add(1));
        let Some(highest) = self.highest() else {
            return above.into_iter().collect();
        };
        let cutoff = highest.saturating_add(1).saturating_sub(keep.max(1));
        let kept = self.epochs.split_off(&cutoff);
        let pruned = std::mem::replace(&mut self.epochs, kept);
        pruned.into_iter().chain(above).collect()
    }

    /// Archived epochs at or after `start` (ascending).
    fn epochs_from(&self, start: u64) -> Vec<u64> {
        self.epochs.range(start..).copied().collect()
    }
}

/// `None` until the startup scan of the archive has completed.
static ARCHIVE_INDEX: std::sync::Mutex<Option<ArchiveIndex>> = std::sync::Mutex::new(None);

fn with_index<R>(f: impl FnOnce(&mut Option<ArchiveIndex>) -> R) -> R {
    let mut guard = ARCHIVE_INDEX
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    f(&mut guard)
}

/// Archived epochs at or after `start`, for the state-sync server. Empty
/// until the startup scan has completed. A request for an epoch older than
/// the retention window is answered from the oldest epoch kept: the
/// requester sees the jump as a gap and skips the hash-chain check for it.
pub fn archived_epochs_from(start: u64) -> Vec<u64> {
    with_index(|index| {
        index
            .as_ref()
            .map_or_else(Vec::new, |i| i.epochs_from(start))
    })
}

fn record_archived_epoch(epoch: u64) {
    with_index(|index| {
        if let Some(i) = index.as_mut() {
            i.record(epoch);
        }
    });
}

/// One streaming pass over `dir` (never recursive): every `epoch_<n>.json`
/// is indexed, every leftover `epoch_<n>.json.tmp` (a write interrupted by
/// a crash) is removed.
fn scan_archive(dir: &std::path::Path) -> std::io::Result<ArchiveIndex> {
    let mut index = ArchiveIndex::default();
    for entry in std::fs::read_dir(dir)? {
        let entry = entry?;
        let name = entry.file_name();
        let Some(name) = name.to_str() else {
            continue;
        };
        if let Some(epoch) = parse_epoch_file_name(name) {
            index.record(epoch);
        } else if name
            .strip_suffix(".tmp")
            .and_then(parse_epoch_file_name)
            .is_some()
            && let Err(e) = std::fs::remove_file(entry.path())
        {
            warn!(file = name, error = %e, "epoch archive: cannot remove an interrupted write");
        }
    }
    Ok(index)
}

/// Delete the archive files of `epochs`. A file already gone counts as
/// deleted; returns the epochs whose file could not be deleted.
fn remove_epoch_files(dir: &std::path::Path, epochs: &[u64]) -> Vec<u64> {
    let mut failed = Vec::new();
    for &epoch in epochs {
        match std::fs::remove_file(dir.join(epoch_file_name(epoch))) {
            Ok(()) => {}
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
            Err(e) => {
                warn!(epoch, error = %e, "epoch archive: cannot delete a pruned epoch");
                failed.push(epoch);
            }
        }
    }
    failed
}

/// Scan `dir` once and delete every epoch outside the retention window.
/// Returns the index of what is kept and the number of files deleted.
/// What a startup load did.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct LoadOutcome {
    /// Files outside the window deleted.
    pruned: usize,
    /// Files inside the window that failed verification, deleted.
    unverified: usize,
}

/// Scan `dir` once, delete every epoch outside the retention window, then
/// verify every kept map (`parse_verified_map`: an earlier build wrote
/// them without any check) and delete those that fail. Returns the index
/// of what is kept.
fn load_and_prune(
    dir: &std::path::Path,
    keep: u64,
    target: u64,
    validator_pk: &str,
) -> Result<(ArchiveIndex, LoadOutcome)> {
    if validator_pk.is_empty() {
        anyhow::bail!("validator key unknown, cannot verify the archive");
    }
    std::fs::create_dir_all(dir).with_context(|| format!("create {}", dir.display()))?;
    let mut index = scan_archive(dir).with_context(|| format!("scan {}", dir.display()))?;
    let prunable = index.take_prunable(keep, target);
    let failed = remove_epoch_files(dir, &prunable);
    let pruned = prunable.len() - failed.len();
    let mut unverified = Vec::new();
    for &epoch in &index.epochs {
        let verdict = std::fs::read(dir.join(epoch_file_name(epoch)))
            .map_err(anyhow::Error::from)
            .and_then(|bytes| parse_verified_map(&bytes, epoch, validator_pk));
        if let Err(e) = verdict {
            warn!(epoch, error = %e, "epoch archive: archived map fails verification, deleted");
            unverified.push(epoch);
        }
    }
    for epoch in &unverified {
        index.epochs.remove(epoch);
    }
    remove_epoch_files(dir, &unverified);
    // Kept in the index so the next prune retries them.
    for epoch in failed {
        index.record(epoch);
    }
    Ok((
        index,
        LoadOutcome {
            pruned,
            unverified: unverified.len(),
        },
    ))
}

/// Startup: load and prune the archive, then publish the index.
async fn load_archive(dir: std::path::PathBuf, keep: u64, target: u64) -> Result<()> {
    let validator_pk = crate::state::get_validator_node_id_global()
        .read()
        .await
        .clone();
    let (index, outcome) =
        tokio::task::spawn_blocking(move || load_and_prune(&dir, keep, target, &validator_pk))
            .await
            .context("epoch archive scan task")??;
    info!(
        kept = index.epochs.len(),
        highest = ?index.highest(),
        pruned = outcome.pruned,
        unverified = outcome.unverified,
        keep,
        "epoch archive loaded"
    );
    with_index(|slot| *slot = Some(index));
    Ok(())
}

/// Delete every epoch older than the `keep` most recent ones. Cheap in the
/// steady state: the index says which files to delete, no directory scan.
async fn prune_archive(dir: &std::path::Path, keep: u64, target: u64) {
    let prunable = with_index(|index| index.as_mut().map(|i| i.take_prunable(keep, target)))
        .unwrap_or_default();
    if prunable.is_empty() {
        return;
    }
    let dir = dir.to_path_buf();
    let count = prunable.len();
    match tokio::task::spawn_blocking(move || remove_epoch_files(&dir, &prunable)).await {
        Ok(failed) => {
            debug!(
                pruned = count - failed.len(),
                failed = failed.len(),
                "epoch archive pruned"
            );
            // Kept in the index so the next prune retries them.
            for epoch in failed {
                record_archived_epoch(epoch);
            }
        }
        Err(e) => error!(error = %e, "epoch archive: prune task failed"),
    }
}

pub async fn run_state_sync_loop() {
    let keep = epoch_archive_keep();
    let mut interval = tokio::time::interval(tokio::time::Duration::from_secs(60));

    loop {
        interval.tick().await;

        let archive_dir = match crate::state::get_data_dir() {
            Some(dir) => dir.join(EPOCH_ARCHIVE_DIR),
            None => continue,
        };

        // Target: the epoch of the held cluster map. Nothing above it is
        // archived, and the retention window is anchored on it.
        let target_epoch = {
            let map_lock = crate::state::get_cluster_map().read().await;
            if let Some(map) = &*map_lock {
                map.epoch
            } else {
                debug!("State sync: waiting for cluster map...");
                continue;
            }
        };

        if with_index(|index| index.is_none())
            && let Err(e) = load_archive(archive_dir.clone(), keep, target_epoch).await
        {
            error!(error = %e, "Failed to load the epoch archive, retrying next tick");
            continue;
        }

        let highest_on_disk =
            with_index(|index| index.as_ref().and_then(|i| i.highest_at_most(target_epoch)));
        let first_missing_epoch = sync_start_epoch(highest_on_disk, target_epoch, keep);

        if first_missing_epoch >= target_epoch {
            // Fully synced!
            crate::state::get_is_historical_seeder()
                .store(true, std::sync::atomic::Ordering::Relaxed);
            debug!(
                first_missing_epoch,
                target_epoch, "State sync: already up to date"
            );
            continue;
        }

        info!(
            ?highest_on_disk,
            first_missing_epoch,
            target_epoch,
            keep,
            "Missing recent epochs. Starting state sync..."
        );

        if let Err(e) = perform_state_sync(first_missing_epoch, target_epoch, &archive_dir).await {
            error!("State sync failed: {}", e);
        }
        prune_archive(&archive_dir, keep, target_epoch).await;
    }
}

async fn perform_state_sync(
    start_epoch: u64,
    target_epoch: u64,
    archive_dir: &std::path::Path,
) -> Result<()> {
    let sources = find_sync_sources().await.context("find_sync_sources")?;
    let endpoint = crate::p2p::get_state_sync_client_endpoint().context("get_endpoint")?;
    let mut last_error = None;
    for source in sources {
        info!(
            source_kind = ?source.kind,
            source_node_id = %source.node_id,
            source_addr = %source.addr,
            "Connecting to state sync source"
        );
        match perform_state_sync_from_source(
            endpoint,
            &source,
            start_epoch,
            target_epoch,
            archive_dir,
        )
        .await
        {
            Ok(()) => return Ok(()),
            Err(err) => {
                warn!(
                    source_kind = ?source.kind,
                    source_node_id = %source.node_id,
                    source_addr = %source.addr,
                    error = %err,
                    "State sync source failed, trying next candidate"
                );
                last_error = Some(err);
            }
        }
    }

    Err(last_error.unwrap_or_else(|| anyhow::anyhow!("No usable state sync source found")))
}

async fn perform_state_sync_from_source(
    endpoint: &quinn::Endpoint,
    source: &SyncSource,
    start_epoch: u64,
    target_epoch: u64,
    archive_dir: &std::path::Path,
) -> Result<()> {
    let validator_pk = crate::state::get_validator_node_id_global()
        .read()
        .await
        .clone();
    let bounds = SyncBounds {
        start_epoch,
        target_epoch,
        validator_pk: &validator_pk,
    };
    let conn = common::transport::connect(endpoint, source.addr, &source.node_id)
        .await
        .context("connect")?;

    let (mut send, mut recv) = conn.open_bi().await.context("open_bi")?;

    let req = P2PStateSyncRequest { start_epoch };
    let req_bytes = serde_json::to_vec(&req).context("to_vec")?;
    send.write_all(&(req_bytes.len() as u32).to_be_bytes())
        .await
        .context("write_len")?;
    send.write_all(&req_bytes).await.context("write_req")?;

    receive_epochs(&mut recv, source, &bounds, archive_dir).await?;
    Ok(())
}

/// Largest map a source may send in one frame, checked before allocating.
/// A 16 384-PG cluster map is a few hundred KB.
const MAX_MAP_BYTES: u32 = 64 * 1024 * 1024;

const FRAME_SYNC: u32 = 0x594E4353; // "SYNC"
const FRAME_EOF: u32 = 0x454F4621; // "EOF!"

/// What a sync session may write: the requested range, bounded by the
/// epoch of the map this node holds, and maps signed by the validator.
#[derive(Debug, Clone)]
struct SyncBounds<'a> {
    start_epoch: u64,
    /// Epoch of the held cluster map: nothing above it is written.
    target_epoch: u64,
    /// Hex Ed25519 key the maps must be signed with.
    validator_pk: &'a str,
}

/// Verify `map`'s validator signature over its hash. A missing signature
/// is a failure.
fn verify_map_signature(map: &ClusterMap, validator_pk: &str) -> Result<()> {
    use ed25519_dalek::Verifier;
    let sig_hex = map
        .signature
        .as_deref()
        .ok_or_else(|| anyhow::anyhow!("map is not signed"))?;
    let sig_bytes = hex::decode(sig_hex).context("signature hex")?;
    let sig = ed25519_dalek::Signature::from_slice(&sig_bytes).context("signature format")?;
    let pk_bytes = hex::decode(validator_pk).context("validator key hex")?;
    let pk = ed25519_dalek::VerifyingKey::try_from(pk_bytes.as_slice())
        .map_err(|e| anyhow::anyhow!("validator key: {e}"))?;
    pk.verify(map.compute_hash().as_bytes(), &sig)
        .map_err(|e| anyhow::anyhow!("signature does not verify: {e}"))
}

/// Parse an archived or received map of `epoch` and verify it: its
/// embedded epoch is `epoch` and it carries a valid signature of
/// `validator_pk`.
fn parse_verified_map(bytes: &[u8], epoch: u64, validator_pk: &str) -> Result<ClusterMap> {
    let map: ClusterMap = serde_json::from_slice(bytes).context("parse map")?;
    if map.epoch != epoch {
        anyhow::bail!("map of epoch {} stored as epoch {epoch}", map.epoch);
    }
    verify_map_signature(&map, validator_pk)?;
    Ok(map)
}

/// Read the verified archived map of `epoch`, for the rebalance. `None`
/// when it is not archived; an archived map that fails verification
/// (written by an earlier build, which checked nothing, or signed by a
/// key no longer in force) is deleted and also `None`: the caller falls
/// back to the validator, as on a miss.
pub async fn read_verified_archived_map(epoch: u64, validator_pk: &str) -> Option<ClusterMap> {
    let dir = crate::state::get_data_dir()?.join(EPOCH_ARCHIVE_DIR);
    read_verified_map_in(&dir, epoch, validator_pk).await
}

async fn read_verified_map_in(
    dir: &std::path::Path,
    epoch: u64,
    validator_pk: &str,
) -> Option<ClusterMap> {
    let path = dir.join(epoch_file_name(epoch));
    let bytes = match tokio::fs::read(&path).await {
        Ok(bytes) => bytes,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return None,
        Err(e) => {
            warn!(epoch, error = %e, "epoch archive: cannot read an archived map");
            return None;
        }
    };
    match parse_verified_map(&bytes, epoch, validator_pk) {
        Ok(map) => Some(map),
        Err(e) => {
            warn!(epoch, error = %e, "epoch archive: archived map fails verification, deleted");
            with_index(|index| {
                if let Some(i) = index.as_mut() {
                    i.epochs.remove(&epoch);
                }
            });
            if let Err(e) = tokio::fs::remove_file(&path).await
                && e.kind() != std::io::ErrorKind::NotFound
            {
                warn!(epoch, error = %e, "epoch archive: cannot delete an unverified map");
            }
            None
        }
    }
}

/// Read the epochs a source streams (`SYNC` frames, then `EOF!`) into
/// `archive_dir`; returns how many were written.
///
/// Nothing unverified is written: a map that does not parse, whose
/// validator signature is missing or invalid, or whose embedded epoch
/// differs from its frame is skipped (`parse_verified_map`; the session
/// goes on); a `previous_hash` that does not chain to the archived
/// predecessor is logged only, see below. An
/// epoch above the held map's ends the session before its body is read:
/// such a frame would otherwise become the highest archived epoch and the
/// pruning, which keeps the window below the highest, would delete every
/// legitimate map. Frames are capped in size ([`MAX_MAP_BYTES`], before
/// allocating) and in number (the requested range). A source that holds
/// nothing at or after `start_epoch` is an error, so the caller moves on
/// to the next source.
async fn receive_epochs<R: tokio::io::AsyncRead + Unpin>(
    recv: &mut R,
    source: &SyncSource,
    bounds: &SyncBounds<'_>,
    archive_dir: &std::path::Path,
) -> Result<u64> {
    use tokio::io::AsyncReadExt;

    let start_epoch = bounds.start_epoch;
    let target_epoch = bounds.target_epoch;
    if bounds.validator_pk.is_empty() {
        anyhow::bail!("validator key unknown, cannot verify synced maps");
    }
    if start_epoch > target_epoch {
        anyhow::bail!("start epoch {start_epoch} is above the held map's {target_epoch}");
    }
    let max_frames = target_epoch - start_epoch + 1;
    let mut current_epoch = start_epoch;
    let mut downloaded_count: u64 = 0;
    let mut frames: u64 = 0;
    let mut refused: u64 = 0;
    // Hash of the epoch before the first one requested, when archived: a
    // node starting at the retention window (or after a pruned gap) has
    // none, and the chain check of the first received epoch is skipped.
    let mut expected_previous_hash = previous_epoch_hash(archive_dir, current_epoch).await?;

    loop {
        let magic = recv.read_u32().await.context("read_magic")?;
        if magic == FRAME_EOF {
            info!(
                source_kind = ?source.kind,
                source_node_id = %source.node_id,
                downloaded_count,
                "Received EOF from state sync source"
            );
            break;
        } else if magic != FRAME_SYNC {
            anyhow::bail!("Invalid magic header from state sync source: {magic:x}");
        }

        let epoch = recv.read_u64().await.context("read_epoch")?;
        if epoch < current_epoch {
            anyhow::bail!("Expected epoch {current_epoch}, but received older epoch {epoch}");
        }
        if epoch > target_epoch {
            warn!(
                source_kind = ?source.kind,
                source_node_id = %source.node_id,
                epoch,
                target_epoch,
                "State sync source sent an epoch above the held map, ending the session"
            );
            break;
        }
        if frames >= max_frames {
            anyhow::bail!("State sync source sent more than {max_frames} epochs");
        }
        frames += 1;
        let skip_hash_check = epoch > current_epoch;
        if skip_hash_check {
            warn!(
                expected_epoch = current_epoch,
                received_epoch = epoch,
                "Gap in state sync, skipping missing epochs"
            );
            current_epoch = epoch;
        }

        let len = recv.read_u32().await.context("read_len")?;
        if len > MAX_MAP_BYTES {
            anyhow::bail!("Map too large: {len} bytes (max {MAX_MAP_BYTES})");
        }
        let mut map_bytes = vec![0u8; len as usize];
        recv.read_exact(&mut map_bytes).await.context("read_map")?;

        // A frame that fails verification is skipped, never written, and
        // the session goes on: after a validator key rotation the older
        // maps of the window no longer verify, and ending the session
        // there would restart the sync at the same epoch every tick.
        let map = match parse_verified_map(&map_bytes, epoch, bounds.validator_pk) {
            Ok(map) => map,
            Err(e) => {
                warn!(
                    source_kind = ?source.kind,
                    source_node_id = %source.node_id,
                    epoch,
                    error = %e,
                    "State sync: map refused, not written"
                );
                refused += 1;
                expected_previous_hash = None;
                current_epoch = epoch + 1;
                continue;
            }
        };
        if let Some(expected) = expected_previous_hash
            .as_ref()
            .filter(|_| epoch > 0 && !skip_hash_check)
            && map.previous_hash.as_ref() != Some(expected)
        {
            // Logged, not refused: the validator re-signs an epoch in place
            // when a durable snapshot changes hash-covered fields
            // (`Seal::Resign`), its archive keeps the first version of that
            // epoch, and the next epoch chains to the re-signed one. A
            // refusal here would stop the sync for good at the first such
            // epoch; the signature above is what authenticates the map.
            warn!(
                epoch,
                expected_previous_hash = %expected,
                received_previous_hash = ?map.previous_hash,
                "Hash chain inconsistency during historical sync (map signature valid)"
            );
        }

        let path = archive_dir.join(epoch_file_name(epoch));
        let mut tmp_path = path.clone();
        tmp_path.set_extension("json.tmp");
        tokio::fs::write(&tmp_path, &map_bytes)
            .await
            .context("write_map")?;
        tokio::fs::rename(&tmp_path, &path)
            .await
            .context("rename_map")?;
        record_archived_epoch(epoch);

        expected_previous_hash = Some(map.compute_hash());
        current_epoch += 1;
        downloaded_count += 1;

        if downloaded_count.is_multiple_of(1000) {
            info!(downloaded_count, "Downloaded historical epochs");
        }
    }

    if refused > 0 {
        warn!(
            source_kind = ?source.kind,
            source_node_id = %source.node_id,
            refused,
            downloaded_count,
            "State sync: maps refused in this session"
        );
    }
    if downloaded_count == 0 {
        // The source holds nothing usable from `start_epoch` on (it keeps a
        // shorter window, or lags behind): try the next one instead of
        // reporting a sync that did not happen.
        anyhow::bail!("source has no epoch at or after {start_epoch}");
    }
    Ok(downloaded_count)
}

/// Hash of the archived map of `epoch - 1`, if any. A missing file (not
/// archived, or pruned) is `None`; an unparseable one is logged and `None`.
async fn previous_epoch_hash(archive_dir: &std::path::Path, epoch: u64) -> Result<Option<String>> {
    let Some(previous) = epoch.checked_sub(1) else {
        return Ok(None);
    };
    let bytes = match tokio::fs::read(archive_dir.join(epoch_file_name(previous))).await {
        Ok(bytes) => bytes,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(e) => return Err(e).context("read_prev"),
    };
    match serde_json::from_slice::<ClusterMap>(&bytes) {
        Ok(map) => Ok(Some(map.compute_hash())),
        Err(e) => {
            warn!(epoch = previous, error = %e, "Unparseable archived epoch, hash chain check skipped for the next one");
            Ok(None)
        }
    }
}

async fn find_sync_sources() -> Result<Vec<SyncSource>> {
    let map_lock = crate::state::get_cluster_map().read().await;
    let map = match &*map_lock {
        Some(m) => m,
        None => anyhow::bail!("No cluster map available"),
    };
    let val_addr = *crate::state::get_validator_addr().read().await;
    let val_id = crate::state::get_validator_node_id_global()
        .read()
        .await
        .clone();
    let sources = build_sync_sources(map, &val_id, val_addr);
    if sources.is_empty() {
        anyhow::bail!("No seeders available and validator unreachable");
    }
    Ok(sources)
}

fn build_sync_sources(
    map: &common::ClusterMap,
    validator_node_id: &str,
    validator_addr: Option<SocketAddr>,
) -> Vec<SyncSource> {
    let mut sources = Vec::new();
    let mut seen = HashSet::new();

    if let Some(addr) = validator_addr
        && !validator_node_id.is_empty()
    {
        seen.insert((validator_node_id.to_string(), addr));
        sources.push(SyncSource {
            node_id: validator_node_id.to_string(),
            addr,
            kind: SyncSourceKind::Validator,
        });
    }

    let mut seeders = map
        .miners
        .iter()
        .filter(|m| m.is_historical_seeder)
        .collect::<Vec<_>>();
    use rand::seq::SliceRandom;
    let mut rng = rand::rng();
    seeders.shuffle(&mut rng);

    for seeder in seeders {
        if let Some(addr) = crate::state::socket_addr_from_endpoint(&seeder.endpoint) {
            let key = (seeder.public_key.clone(), addr);
            if seen.insert(key.clone()) {
                sources.push(SyncSource {
                    node_id: key.0,
                    addr: key.1,
                    kind: SyncSourceKind::HistoricalSeeder,
                });
            }
        }
    }
    sources
}

#[cfg(test)]
mod tests {
    use super::*;
    use iroh::TransportAddr;

    fn test_miner(
        uid: u32,
        pubkey: &str,
        node_id: &str,
        addr: &str,
        is_historical_seeder: bool,
    ) -> common::MinerNode {
        common::MinerNode {
            uid,
            endpoint: iroh::EndpointAddr::from_parts(
                node_id.parse().unwrap(),
                vec![TransportAddr::Ip(addr.parse().unwrap())],
            ),
            is_historical_seeder,
            weight: 1,
            ip_subnet: "0.0.0.0/0".to_string(),
            ip_address: Some(addr.split(':').next().unwrap().to_string()),
            http_addr: "http://127.0.0.1:3001".to_string(),
            public_key: pubkey.to_string(),
            base_weight: 1,
            total_storage: 0,
            available_storage: 0,
            family_id: "f".to_string(),
            last_seen: 0,
            strikes: 0,
            heartbeat_count: 0,
            registration_time: 0,
            bandwidth_total: 0,
            bandwidth_window_start: 0,
            weight_manual_override: false,
            reputation: 0.0,
            consecutive_audit_passes: 0,
            integrity_fails: 0,
            version: "0.1.23".to_string(),
            warden_challenges_total: 0,
            warden_challenges_passed: 0,
            fetch_timeout_count: 0,
            expected_shards: 0,
            actual_shards: 0,
            trust_score: 0.0,
            earned_capacity_bytes: 0,
            draining: false,
            drained_for_offline: false,
            placement_hold: false,
            placement_hold_base_hb: 0,
            p2p_reliability_score: 1.0,
            incarnation: None,
            balancer_reweight: 1.0,
        }
    }

    #[test]
    fn archive_keep_parses_positive_integers_only() {
        assert_eq!(parse_archive_keep(None), DEFAULT_EPOCH_ARCHIVE_KEEP);
        assert_eq!(parse_archive_keep(Some(" 500 ")), 500);
        assert_eq!(parse_archive_keep(Some("0")), DEFAULT_EPOCH_ARCHIVE_KEEP);
        assert_eq!(parse_archive_keep(Some("-3")), DEFAULT_EPOCH_ARCHIVE_KEEP);
        assert_eq!(parse_archive_keep(Some("lots")), DEFAULT_EPOCH_ARCHIVE_KEEP);
    }

    #[test]
    fn epoch_file_names_round_trip() {
        assert_eq!(
            parse_epoch_file_name(&epoch_file_name(41_933)),
            Some(41_933)
        );
        assert_eq!(parse_epoch_file_name("epoch_0.json"), Some(0));
        assert_eq!(parse_epoch_file_name("epoch_12.json.tmp"), None);
        assert_eq!(parse_epoch_file_name("epoch_x.json"), None);
        assert_eq!(parse_epoch_file_name("other_12.json"), None);
    }

    #[test]
    fn start_epoch_is_bounded_by_the_window() {
        // Fresh node: the window ending at the target, not epoch 0.
        assert_eq!(sync_start_epoch(None, 26_000, 2_000), 24_001);
        // Young network: the window reaches back past genesis.
        assert_eq!(sync_start_epoch(None, 500, 2_000), 0);
        // Caught up, a few epochs behind: resume after the highest.
        assert_eq!(sync_start_epoch(Some(25_990), 26_000, 2_000), 25_991);
        // Down longer than the window: skip what would be pruned anyway.
        assert_eq!(sync_start_epoch(Some(10_000), 26_000, 2_000), 24_001);
        // Epoch 0 alone on disk is an archived epoch, not "nothing".
        assert_eq!(sync_start_epoch(Some(0), 10, 2_000), 1);
        // Up to date: the start is past the target, nothing to request.
        assert!(sync_start_epoch(Some(26_000), 26_000, 2_000) > 26_000);
        // A zero window is read as one epoch.
        assert_eq!(sync_start_epoch(None, 26_000, 0), 26_000);
    }

    #[test]
    fn index_prunes_all_but_the_most_recent_epochs() {
        let mut index = ArchiveIndex::default();
        assert!(index.take_prunable(3, 100).is_empty());
        for e in [1, 2, 5, 7, 8, 9, 10] {
            index.record(e);
        }
        // Keep epochs 8..=10 (the three most recent epoch numbers).
        assert_eq!(index.take_prunable(3, 100), vec![1, 2, 5, 7]);
        assert_eq!(index.epochs_from(0), vec![8, 9, 10]);
        assert_eq!(index.highest(), Some(10));
        assert!(index.take_prunable(3, 100).is_empty());
        // A start older than the window is served from the oldest kept.
        assert_eq!(index.epochs_from(2), vec![8, 9, 10]);
        assert_eq!(index.epochs_from(9), vec![9, 10]);
        // Nothing at or after the start: an empty answer (immediate EOF).
        assert!(index.epochs_from(11).is_empty());
    }

    #[test]
    fn epoch_above_the_held_map_never_moves_the_window() {
        // An epoch far above the held map (a forged frame, or a file an
        // older build wrote without bounds) is dropped; the window stays
        // anchored on the held map and no legitimate epoch is pruned.
        let mut index = ArchiveIndex::default();
        for e in 90..=100 {
            index.record(e);
        }
        index.record(1_000_000_000_000);
        assert_eq!(index.highest_at_most(100), Some(100));
        assert_eq!(
            sync_start_epoch(index.highest_at_most(100), 100, 20),
            101,
            "the forged epoch does not make the node look synced"
        );
        assert_eq!(index.take_prunable(20, 100), vec![1_000_000_000_000]);
        assert_eq!(index.epochs_from(0), (90..=100).collect::<Vec<u64>>());
    }

    fn write_map(dir: &std::path::Path, name_epoch: u64, map: &common::ClusterMap) {
        std::fs::write(
            dir.join(epoch_file_name(name_epoch)),
            serde_json::to_vec(map).unwrap(),
        )
        .unwrap();
    }

    #[test]
    fn load_and_prune_keeps_the_window_and_removes_leftovers() {
        let dir = tempfile::tempdir().unwrap();
        let archive = dir.path().join(EPOCH_ARCHIVE_DIR);
        std::fs::create_dir_all(&archive).unwrap();
        for e in 0..50u64 {
            write_map(&archive, e, &signed_map(e, None, &validator_key()));
        }
        std::fs::write(archive.join(epoch_file_name(1_000_000)), b"{}").unwrap();
        std::fs::write(archive.join("epoch_50.json.tmp"), b"partial").unwrap();
        std::fs::write(archive.join("unrelated.txt"), b"keep me").unwrap();
        std::fs::create_dir(archive.join("epoch_1.json.d")).unwrap();
        let pk = validator_pk();

        let (index, outcome) = load_and_prune(&archive, 10, 49, &pk).unwrap();
        assert_eq!(
            outcome,
            LoadOutcome {
                pruned: 41,
                unverified: 0
            }
        );
        assert_eq!(index.epochs_from(0), (40..50).collect::<Vec<u64>>());
        let mut expected: Vec<String> = (40..50).map(epoch_file_name).collect();
        expected.push("epoch_1.json.d".to_string());
        expected.push("unrelated.txt".to_string());
        expected.sort();
        assert_eq!(archived(&archive), expected);

        // A second load is a no-op; a missing directory is created.
        let (again, outcome) = load_and_prune(&archive, 10, 49, &pk).unwrap();
        assert_eq!(again, index);
        assert_eq!(outcome.pruned + outcome.unverified, 0);
        let fresh = dir.path().join("fresh").join(EPOCH_ARCHIVE_DIR);
        let (empty, outcome) = load_and_prune(&fresh, 10, 49, &pk).unwrap();
        assert!(empty.highest().is_none() && outcome.pruned == 0 && fresh.is_dir());

        // Without the validator key nothing can be verified: refused.
        assert!(load_and_prune(&archive, 10, 49, "").is_err());
    }

    #[test]
    fn load_deletes_archived_maps_that_fail_verification() {
        // Files an earlier build wrote without any check: unsigned,
        // signed by another key, stored under the wrong epoch, garbage.
        let dir = tempfile::tempdir().unwrap();
        let other = ed25519_dalek::SigningKey::from_bytes(&[9u8; 32]);
        for e in 10..=20u64 {
            write_map(dir.path(), e, &signed_map(e, None, &validator_key()));
        }
        write_map(dir.path(), 12, &empty_map(12));
        write_map(dir.path(), 13, &signed_map(13, None, &other));
        write_map(dir.path(), 14, &signed_map(99, None, &validator_key()));
        std::fs::write(dir.path().join(epoch_file_name(15)), b"garbage").unwrap();

        let (index, outcome) = load_and_prune(dir.path(), 100, 20, &validator_pk()).unwrap();
        assert_eq!(
            outcome,
            LoadOutcome {
                pruned: 0,
                unverified: 4
            }
        );
        let kept: Vec<u64> = vec![10, 11, 16, 17, 18, 19, 20];
        assert_eq!(index.epochs_from(0), kept);
        let mut expected: Vec<String> = kept.into_iter().map(epoch_file_name).collect();
        expected.sort();
        assert_eq!(archived(dir.path()), expected);
    }

    #[tokio::test]
    async fn rebalance_read_verifies_and_deletes_a_bad_archived_map() {
        let dir = tempfile::tempdir().unwrap();
        let pk = validator_pk();
        let good = signed_map(30, None, &validator_key());
        write_map(dir.path(), 30, &good);
        write_map(dir.path(), 31, &empty_map(31));
        write_map(dir.path(), 32, &signed_map(33, None, &validator_key()));

        assert_eq!(
            read_verified_map_in(dir.path(), 30, &pk)
                .await
                .map(|m| m.compute_hash()),
            Some(good.compute_hash())
        );
        // Unsigned and wrong-epoch maps: a miss (the caller asks the
        // validator), and the file is gone.
        assert!(read_verified_map_in(dir.path(), 31, &pk).await.is_none());
        assert!(read_verified_map_in(dir.path(), 32, &pk).await.is_none());
        assert_eq!(archived(dir.path()), vec![epoch_file_name(30)]);
        // Not archived at all: a plain miss.
        assert!(read_verified_map_in(dir.path(), 40, &pk).await.is_none());
    }

    #[tokio::test]
    async fn refused_frames_are_skipped_and_the_session_goes_on() {
        // After a key rotation the older maps no longer verify: they are
        // skipped, the later ones are written, and the next sync starts
        // after the highest written epoch instead of retrying the same one.
        let other = ed25519_dalek::SigningKey::from_bytes(&[9u8; 32]);
        let dir = tempfile::tempdir().unwrap();
        let mut bytes = Vec::new();
        for e in 100..=102u64 {
            bytes.extend(frame_for(e, &signed_map(e, None, &other)));
        }
        bytes.extend(frame_for(103, &empty_map(103)));
        bytes.extend(frame_for(104, &signed_map(999, None, &validator_key())));
        bytes.extend(chain_frames(105..=106));
        bytes.extend(EOF_FRAME);
        assert_eq!(receive(&bytes, 100, 110, dir.path()).await.unwrap(), 2);
        assert_eq!(
            archived(dir.path()),
            vec![epoch_file_name(105), epoch_file_name(106)]
        );
        let mut index = ArchiveIndex::default();
        index.record(105);
        index.record(106);
        assert_eq!(
            sync_start_epoch(index.highest_at_most(110), 110, 2_000),
            107
        );
    }

    #[test]
    fn remove_epoch_files_treats_missing_files_as_deleted() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join(epoch_file_name(3)), b"{}").unwrap();
        assert!(remove_epoch_files(dir.path(), &[3, 4]).is_empty());
        assert!(!dir.path().join(epoch_file_name(3)).exists());
    }

    #[tokio::test]
    async fn previous_hash_is_optional_at_the_window_start() {
        let dir = tempfile::tempdir().unwrap();
        // Genesis has no predecessor; a pruned or never-archived
        // predecessor is not an error (the first chain check is skipped).
        assert_eq!(previous_epoch_hash(dir.path(), 0).await.unwrap(), None);
        assert_eq!(previous_epoch_hash(dir.path(), 24_001).await.unwrap(), None);
        std::fs::write(dir.path().join(epoch_file_name(9)), b"not json").unwrap();
        assert_eq!(previous_epoch_hash(dir.path(), 10).await.unwrap(), None);

        let map = empty_map(11);
        std::fs::write(
            dir.path().join(epoch_file_name(11)),
            serde_json::to_vec(&map).unwrap(),
        )
        .unwrap();
        assert_eq!(
            previous_epoch_hash(dir.path(), 12).await.unwrap(),
            Some(map.compute_hash())
        );
    }

    fn empty_map(epoch: u64) -> common::ClusterMap {
        common::ClusterMap {
            miners: Vec::new(),
            epoch,
            previous_hash: None,
            signature: None,
            pg_count: 16384,
            ec_k: 10,
            ec_m: 20,
            pg_upmap: std::collections::HashMap::new(),
        }
    }

    fn validator_key() -> ed25519_dalek::SigningKey {
        ed25519_dalek::SigningKey::from_bytes(&[7u8; 32])
    }

    fn validator_pk() -> String {
        hex::encode(validator_key().verifying_key().to_bytes())
    }

    /// Map of `epoch` chained to `previous`, signed by `key`.
    fn signed_map(
        epoch: u64,
        previous: Option<&common::ClusterMap>,
        key: &ed25519_dalek::SigningKey,
    ) -> common::ClusterMap {
        use ed25519_dalek::Signer;
        let mut map = empty_map(epoch);
        map.previous_hash = previous.map(common::ClusterMap::compute_hash);
        map.signature = Some(hex::encode(
            key.sign(map.compute_hash().as_bytes()).to_bytes(),
        ));
        map
    }

    fn frame_for(epoch: u64, map: &common::ClusterMap) -> Vec<u8> {
        let body = serde_json::to_vec(map).unwrap();
        let mut frame = Vec::new();
        frame.extend_from_slice(&FRAME_SYNC.to_be_bytes());
        frame.extend_from_slice(&epoch.to_be_bytes());
        frame.extend_from_slice(&(body.len() as u32).to_be_bytes());
        frame.extend_from_slice(&body);
        frame
    }

    /// Signed, chained frames for `epochs` (consecutive).
    fn chain_frames(epochs: std::ops::RangeInclusive<u64>) -> Vec<u8> {
        let mut out = Vec::new();
        let mut previous: Option<common::ClusterMap> = None;
        for e in epochs {
            let map = signed_map(e, previous.as_ref(), &validator_key());
            out.extend(frame_for(e, &map));
            previous = Some(map);
        }
        out
    }

    const EOF_FRAME: [u8; 4] = FRAME_EOF.to_be_bytes();

    fn test_source() -> SyncSource {
        SyncSource {
            node_id: "peer".to_string(),
            addr: "127.0.0.1:11220".parse().unwrap(),
            kind: SyncSourceKind::HistoricalSeeder,
        }
    }

    async fn receive(
        bytes: &[u8],
        start_epoch: u64,
        target_epoch: u64,
        dir: &std::path::Path,
    ) -> Result<u64> {
        let pk = validator_pk();
        let bounds = SyncBounds {
            start_epoch,
            target_epoch,
            validator_pk: &pk,
        };
        let mut stream: &[u8] = bytes;
        receive_epochs(&mut stream, &test_source(), &bounds, dir).await
    }

    fn archived(dir: &std::path::Path) -> Vec<String> {
        let mut names: Vec<String> = std::fs::read_dir(dir)
            .unwrap()
            .map(|e| e.unwrap().file_name().into_string().unwrap())
            .collect();
        names.sort();
        names
    }

    #[tokio::test]
    async fn signed_chain_within_the_target_is_written() {
        let dir = tempfile::tempdir().unwrap();
        let mut bytes = chain_frames(100..=102);
        bytes.extend(EOF_FRAME);
        assert_eq!(receive(&bytes, 100, 102, dir.path()).await.unwrap(), 3);
        assert_eq!(
            archived(dir.path()),
            (100..=102).map(epoch_file_name).collect::<Vec<_>>()
        );
    }

    #[tokio::test]
    async fn source_without_the_requested_epochs_is_a_failure() {
        // A source whose window no longer holds `start_epoch` (or anything
        // after it) answers EOF at once: that is not a completed sync, the
        // caller must try the next source.
        let dir = tempfile::tempdir().unwrap();
        let err = receive(&EOF_FRAME, 24_001, 26_000, dir.path())
            .await
            .unwrap_err();
        assert!(
            err.to_string().contains("no epoch at or after 24001"),
            "{err}"
        );
    }

    #[tokio::test]
    async fn source_answering_from_a_later_epoch_is_a_gap() {
        // The requested start is older than the source's window: it
        // answers from its oldest kept epoch, which is written as is (the
        // chain check needs the predecessor, the signature does not).
        let dir = tempfile::tempdir().unwrap();
        let mut bytes = chain_frames(150..=151);
        bytes.extend(EOF_FRAME);
        assert_eq!(receive(&bytes, 100, 200, dir.path()).await.unwrap(), 2);
        assert_eq!(
            archived(dir.path()),
            vec![epoch_file_name(150), epoch_file_name(151)]
        );
    }

    #[tokio::test]
    async fn source_answering_an_older_epoch_is_refused() {
        let dir = tempfile::tempdir().unwrap();
        let mut bytes = chain_frames(99..=99);
        bytes.extend(EOF_FRAME);
        assert!(receive(&bytes, 100, 200, dir.path()).await.is_err());
        assert!(archived(dir.path()).is_empty());
    }

    #[tokio::test]
    async fn forged_epoch_above_the_held_map_is_not_written() {
        // Even validly signed, a frame above the held map ends the session
        // before its body is read; the epochs before it are kept.
        let dir = tempfile::tempdir().unwrap();
        let far = 1_000_000_000_000u64;
        let mut bytes = chain_frames(100..=101);
        bytes.extend(frame_for(far, &signed_map(far, None, &validator_key())));
        bytes.extend(EOF_FRAME);
        assert_eq!(receive(&bytes, 100, 110, dir.path()).await.unwrap(), 2);
        assert_eq!(
            archived(dir.path()),
            vec![epoch_file_name(100), epoch_file_name(101)]
        );

        // Alone, it is a failed session and nothing is written.
        let dir = tempfile::tempdir().unwrap();
        let mut bytes = frame_for(far, &signed_map(far, None, &validator_key()));
        bytes.extend(EOF_FRAME);
        assert!(receive(&bytes, 100, 110, dir.path()).await.is_err());
        assert!(archived(dir.path()).is_empty());
    }

    #[tokio::test]
    async fn unsigned_or_badly_signed_maps_are_not_written() {
        let other = ed25519_dalek::SigningKey::from_bytes(&[9u8; 32]);
        let mut unsigned = empty_map(100);
        unsigned.signature = None;
        let mut garbage = empty_map(100);
        garbage.signature = Some("zz".to_string());
        let mut tampered = signed_map(100, None, &validator_key());
        tampered.pg_count = 1;
        for (what, map) in [
            ("unsigned", unsigned),
            ("signed by another key", signed_map(100, None, &other)),
            ("garbage signature", garbage),
            ("tampered after signing", tampered),
        ] {
            let dir = tempfile::tempdir().unwrap();
            let mut bytes = frame_for(100, &map);
            bytes.extend(EOF_FRAME);
            assert!(
                receive(&bytes, 100, 110, dir.path()).await.is_err(),
                "{what} accepted"
            );
            assert!(archived(dir.path()).is_empty(), "{what} written");
        }

        // No validator key: nothing can be verified, nothing is written.
        let dir = tempfile::tempdir().unwrap();
        let mut bytes = chain_frames(100..=100);
        bytes.extend(EOF_FRAME);
        let bounds = SyncBounds {
            start_epoch: 100,
            target_epoch: 110,
            validator_pk: "",
        };
        let mut stream: &[u8] = &bytes;
        assert!(
            receive_epochs(&mut stream, &test_source(), &bounds, dir.path())
                .await
                .is_err()
        );
        assert!(archived(dir.path()).is_empty());
    }

    #[tokio::test]
    async fn frame_epoch_must_match_the_map_chain_mismatch_is_logged() {
        // A signed map replayed under another epoch number.
        let dir = tempfile::tempdir().unwrap();
        let mut bytes = frame_for(101, &signed_map(100, None, &validator_key()));
        bytes.extend(EOF_FRAME);
        assert!(receive(&bytes, 101, 110, dir.path()).await.is_err());
        assert!(archived(dir.path()).is_empty());

        // A signed map that does not chain to the archived predecessor
        // (the validator re-signs an epoch in place, its archive keeps the
        // first version): logged, written, the signature authenticates it.
        let dir = tempfile::tempdir().unwrap();
        let before = signed_map(99, None, &validator_key());
        std::fs::write(
            dir.path().join(epoch_file_name(99)),
            serde_json::to_vec(&before).unwrap(),
        )
        .unwrap();
        let resigned = signed_map(100, Some(&empty_map(42)), &validator_key());
        let chained = signed_map(101, Some(&resigned), &validator_key());
        let mut bytes = frame_for(100, &resigned);
        bytes.extend(frame_for(101, &chained));
        bytes.extend(EOF_FRAME);
        assert_eq!(receive(&bytes, 100, 110, dir.path()).await.unwrap(), 2);
        let mut expected: Vec<String> = (99..=101).map(epoch_file_name).collect();
        expected.sort();
        assert_eq!(archived(dir.path()), expected);
    }

    #[tokio::test]
    async fn oversized_frame_is_refused_before_allocating() {
        let dir = tempfile::tempdir().unwrap();
        let mut bytes = Vec::new();
        bytes.extend_from_slice(&FRAME_SYNC.to_be_bytes());
        bytes.extend_from_slice(&100u64.to_be_bytes());
        bytes.extend_from_slice(&(MAX_MAP_BYTES + 1).to_be_bytes());
        // No body: a reader that allocated and read would fail on EOF,
        // not on the size.
        let err = receive(&bytes, 100, 110, dir.path()).await.unwrap_err();
        assert!(err.to_string().contains("Map too large"), "{err}");
        assert!(archived(dir.path()).is_empty());
    }

    #[tokio::test]
    async fn start_above_the_target_is_refused() {
        let dir = tempfile::tempdir().unwrap();
        assert!(receive(&EOF_FRAME, 111, 110, dir.path()).await.is_err());
    }

    #[test]
    fn build_sync_sources_prefers_validator_over_seeders() {
        let map = common::ClusterMap {
            miners: vec![
                test_miner(
                    1,
                    "peer-pub-1",
                    "372af6558dd5d388d739c9b2f3e34cd1c78fa10c23ceb77221d5eb3869eadb88",
                    "141.94.253.155:11220",
                    true,
                ),
                test_miner(
                    2,
                    "peer-pub-2",
                    "6d6ce0a9f8e0f5aaf7fa6f4cffb4d2a5068374d36d5e40b355748dcbf0fe8cf5",
                    "51.178.74.105:11220",
                    true,
                ),
            ],
            epoch: 1,
            previous_hash: None,
            signature: None,
            pg_count: 16384,
            ec_k: 10,
            ec_m: 20,
            pg_upmap: std::collections::HashMap::new(),
        };
        let validator_addr: SocketAddr = "51.210.230.161:11220".parse().unwrap();
        let sources = build_sync_sources(
            &map,
            "185651f2fb19c919d40c3c58660cf463ebe7ded1c1a326eef4dad28292171cdb",
            Some(validator_addr),
        );

        assert_eq!(sources.first().unwrap().kind, SyncSourceKind::Validator);
        assert_eq!(sources.first().unwrap().addr, validator_addr);
        assert_eq!(sources.len(), 3);
    }

    #[test]
    fn build_sync_sources_falls_back_to_seeders_when_validator_missing() {
        let map = common::ClusterMap {
            miners: vec![test_miner(
                1,
                "peer-pub-1",
                "372af6558dd5d388d739c9b2f3e34cd1c78fa10c23ceb77221d5eb3869eadb88",
                "141.94.253.155:11220",
                true,
            )],
            epoch: 1,
            previous_hash: None,
            signature: None,
            pg_count: 16384,
            ec_k: 10,
            ec_m: 20,
            pg_upmap: std::collections::HashMap::new(),
        };
        let sources = build_sync_sources(&map, "", None);

        assert_eq!(sources.len(), 1);
        assert_eq!(sources[0].kind, SyncSourceKind::HistoricalSeeder);
        assert_eq!(sources[0].addr, "141.94.253.155:11220".parse().unwrap());
    }
}

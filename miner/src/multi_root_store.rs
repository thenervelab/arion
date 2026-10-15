//! Multi-root blob store: one independent backend per disk.
//!
//! A node with several disks can aggregate them into one mount point
//! (a FUSE union) and run a single store on it: one packed volume being
//! appended, one writer thread, one `fdatasync` per batch for the whole
//! node, and a dead disk silently takes its share of the shards with it
//! while the store keeps answering for the rest. [`MultiRootStore`] instead
//! runs one complete backend per root (`STORAGE_PATHS`): each root has its
//! own volumes, writer, index, journal and trash, and the roots share
//! nothing but this routing layer.
//!
//! ## Routing
//!
//! - **Writes**: a blob already present on a usable root (live or in its
//!   trash) is written there again, so a re-store never creates a second
//!   copy. Otherwise the root is chosen by smooth weighted round-robin over
//!   the writable roots, weighted by free bytes above the reserve
//!   (`STORAGE_ROOT_RESERVE_BYTES`): equal disks take turns (concurrent
//!   stores spread over every writer, which is the throughput gain), an
//!   emptier disk (a replacement) takes proportionally more until the fill
//!   evens out. Roots whose in-flight write budget cannot admit the
//!   payload right now are passed over while another one can. A write
//!   that fails on a root is retried on the next one, unless the failed
//!   root now holds the blob (its batch may have reached the volume).
//! - **Reads / CheckBlob / FetchBlob**: the usable roots in configuration
//!   order, first hit wins; an I/O or integrity error on one root falls
//!   through to the next copy, if any.
//! - **Delete / remove / purge**: applied on every usable root holding the
//!   blob, and recorded durably for every unusable root (below).
//! - **Restore**: the first usable root holding the blob in its trash.
//!
//! ## One copy per blob
//!
//! The write rule keeps a single copy. A second one can still appear: a
//! write lands on root B while root A, which may hold the blob, is
//! unusable (only a blob the inventory already listed live can be on A),
//! or after a failed attempt on A. Such writes are logged as suspects; once every root is usable again, [`MultiRootStore::resolve_suspects`]
//! keeps the copy of the first root (configuration order) whose bytes
//! verify against the name and removes the others. Until then a duplicate
//! is harmless: the copies are identical (content-addressed), reads take
//! the first, a delete trashes both.
//!
//! ## Root health
//!
//! States: `healthy` (reads, writes, mutations), `full` (free space under
//! the reserve or `ENOSPC`: reads and mutations, no new writes), `down`
//! (opened, then failed: device gone, read-only remount, repeated I/O
//! errors, failed probes; nothing is read from it, not even its index, so a
//! dead disk's blobs answer absent and the network re-places them),
//! `offline` (could not be opened at startup, e.g. not mounted). A probe
//! every `STORAGE_ROOT_PROBE_SECS` (15 s) stats the root, checks that its
//! device id did not change, measures its free space and writes then
//! removes a small file. A full root becomes healthy again with twice the
//! reserve free; a down root whose probe passes on the same device is
//! reintegrated with the same store; an offline root is opened then
//! reintegrated. A root remounted on another device stays down until the
//! next start (its open file handles and index mapping belong to the old
//! mount).
//!
//! Mutations for an unusable root are appended to
//! `{data_dir}/storage-roots.pending` and `fdatasync`ed before the
//! mutation is applied anywhere, keyed by the root path as configured.
//! Reintegration replays them on that root (a delete that happened while
//! the disk was away is never undone by its return), then, with every
//! mutation drained (`mutation_gate`), replays the tail, rewrites the file
//! without them and only then makes the root usable, so a crash in between
//! replays them again on a root nothing could have written to meanwhile.
//!
//! Capacity reported to the validator ([`BlobStore::disk_space`]) is the
//! sum over the usable roots, each filesystem counted once; free space
//! counts only on writable roots, minus the reserve. `confirmed_absent` is
//! `false` while any root is unusable: the purge never drops an inventory
//! row for a blob a missing disk may hold.

use std::io::{BufRead, Seek, Write};
use std::os::unix::fs::MetadataExt;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, AtomicU8, AtomicU32, AtomicU64, Ordering};
use std::sync::{Arc, Mutex, RwLock};
use std::time::Duration;

use bytes::Bytes;

use crate::store::{BlobStore, DiskSpace, InflightHeadroom};

/// File at the top of every root of a multi-root set (see [`RootMarker`]).
pub(crate) const ROOT_MARKER: &str = ".arion-root";
/// Written then removed by the health probe.
const PROBE_FILE: &str = ".arion-probe";
/// Deferred mutations and duplicate suspects, in the data directory.
pub(crate) const PENDING_FILE: &str = "storage-roots.pending";

/// Consecutive I/O errors (no success in between) that take a root down.
/// One unreadable sector must not hide a whole disk; a dying disk fails
/// every request and crosses this within seconds.
const DOWN_AFTER_IO_ERRORS: u32 = 8;
/// Consecutive failed probes that take a root down (a busy disk may miss
/// one probe deadline).
const DOWN_AFTER_PROBE_FAILURES: u32 = 2;
pub(crate) const DEFAULT_PROBE_INTERVAL: Duration = Duration::from_secs(15);
const PROBE_TIMEOUT: Duration = Duration::from_secs(30);
/// Free bytes a root keeps out of new writes: room for the journal, the
/// index growth and the volume being sealed.
pub(crate) const DEFAULT_RESERVE_BYTES: u64 = 4 << 30;
/// Suspect lines kept at most (~68 bytes each, ~1 GiB): about the share
/// of one disk's shards on a large node, all re-stored here while that disk
/// was away. Beyond, duplicates are still served correctly, only no longer
/// cleaned up automatically (logged once).
const MAX_SUSPECTS: u64 = 16_000_000;
/// Unresolved suspects one resolution pass keeps in memory at most.
const MAX_KEPT_SUSPECTS: usize = 100_000;
/// Pending lines read per chunk during a replay.
const REPLAY_CHUNK: usize = 10_000;
/// Interval of the per-root summary log line.
const SUMMARY_EVERY: Duration = Duration::from_secs(600);

// ---------------------------------------------------------------------------
// Root marker
// ---------------------------------------------------------------------------

/// Content of `{root}/.arion-root`: this root belongs to a multi-root set
/// and its packed index (if any) describes only the volumes of this root.
/// Created for an empty root on first use, or by `split-union-index` for a
/// branch of a former union mount (`split` = the split run id). A
/// single-path store (`STORAGE_PATH`) refuses a root that carries one:
/// through a union mount it would see one branch's index over every
/// branch's volumes.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct RootMarker {
    pub id: String,
    pub split: Option<String>,
}

impl RootMarker {
    pub(crate) fn fresh(split: Option<String>) -> Self {
        Self {
            id: new_id(),
            split,
        }
    }

    fn encode(&self) -> String {
        format!(
            "arion-root v1 id={} split={}\n",
            self.id,
            self.split.as_deref().unwrap_or("-")
        )
    }

    fn decode(s: &str) -> Option<Self> {
        let mut it = s.split_whitespace();
        if it.next()? != "arion-root" || it.next()? != "v1" {
            return None;
        }
        let id = it.next()?.strip_prefix("id=")?.to_string();
        let split = it.next()?.strip_prefix("split=")?;
        Some(Self {
            id,
            split: (split != "-").then(|| split.to_string()),
        })
    }
}

/// 16 random hex digits.
pub(crate) fn new_id() -> String {
    format!("{:016x}", rand::random::<u64>())
}

/// The marker of `root`, `None` when it has none. A marker that does not
/// parse is an error (`InvalidData`), never ignored.
pub(crate) fn read_marker(root: &Path) -> std::io::Result<Option<RootMarker>> {
    match std::fs::read_to_string(root.join(ROOT_MARKER)) {
        Ok(s) => RootMarker::decode(&s).map(Some).ok_or_else(|| {
            std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                format!("{}: unreadable {ROOT_MARKER}", root.display()),
            )
        }),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(e) => Err(e),
    }
}

/// Write the marker durably (tmp + fsync + rename + fsync of the root).
pub(crate) fn write_marker(root: &Path, marker: &RootMarker) -> std::io::Result<()> {
    let tmp = root.join(format!("{ROOT_MARKER}.tmp"));
    {
        let mut f = std::fs::File::create(&tmp)?;
        f.write_all(marker.encode().as_bytes())?;
        f.sync_all()?;
    }
    std::fs::rename(&tmp, root.join(ROOT_MARKER))?;
    sync_dir(root)
}

pub(crate) fn sync_dir(dir: &Path) -> std::io::Result<()> {
    std::fs::File::open(dir)?.sync_all()
}

/// Whether `root/packed` holds packed data: a volume file or an index
/// file. One `read_dir` of the volumes directory (a few thousand entries
/// at most) and three `stat`s.
pub(crate) fn packed_data_present(root: &Path) -> std::io::Result<bool> {
    let packed = root.join("packed");
    match std::fs::read_dir(packed.join("volumes")) {
        Ok(entries) => {
            for e in entries {
                if e?.file_name().to_string_lossy().starts_with("vol-") {
                    return Ok(true);
                }
            }
        }
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
        Err(e) => return Err(e),
    }
    for name in ["live.idx", "snapshot.bin", "journal.log"] {
        if packed.join("index").join(name).exists() {
            return Ok(true);
        }
    }
    Ok(false)
}

/// Admit `root` into a multi-root set: its marker, written now for a root
/// holding no packed data. A root holding packed data without a marker
/// comes from a single-path layout (possibly one branch of a union mount,
/// whose index lives elsewhere): refused with `InvalidData`, the operator
/// runs `split-union-index` first.
pub(crate) fn admit_root(root: &Path) -> std::io::Result<RootMarker> {
    if let Some(m) = read_marker(root)? {
        return Ok(m);
    }
    if packed_data_present(root)? {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            format!(
                "{}: holds a packed store from a single-path layout; run `miner split-union-index` before using it in STORAGE_PATHS (see README, \"Multiple storage roots\")",
                root.display()
            ),
        ));
    }
    let marker = RootMarker::fresh(None);
    write_marker(root, &marker)?;
    Ok(marker)
}

/// Single-path mode (`STORAGE_PATH`) refuses a member of a multi-root set.
pub(crate) fn refuse_member_root(blobs_dir: &Path) -> std::io::Result<()> {
    match read_marker(blobs_dir)? {
        None => Ok(()),
        Some(m) => Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            format!(
                "{} belongs to a multi-root set (id {}): list it in STORAGE_PATHS instead of STORAGE_PATH (a union mount over split roots would serve one root's index over every root's volumes)",
                blobs_dir.display(),
                m.id
            ),
        )),
    }
}

// ---------------------------------------------------------------------------
// Error classification
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ErrClass {
    /// About one blob (absent, corrupt, too large): not the root's health.
    Blob,
    /// No space: stop placing writes here.
    Full,
    /// The device or the backend's writer is gone: down at once.
    Gone,
    /// Anything else: counts toward [`DOWN_AFTER_IO_ERRORS`].
    Io,
}

fn classify(e: &std::io::Error) -> ErrClass {
    use std::io::ErrorKind as K;
    match e.raw_os_error() {
        Some(libc::ENOSPC) | Some(libc::EDQUOT) => return ErrClass::Full,
        Some(libc::ENODEV) | Some(libc::ENXIO) | Some(libc::ENOTCONN) | Some(libc::ESTALE)
        | Some(libc::EROFS) => return ErrClass::Gone,
        Some(libc::EIO) => return ErrClass::Io,
        _ => {}
    }
    match e.kind() {
        K::NotFound | K::InvalidData | K::FileTooLarge | K::InvalidInput | K::UnexpectedEof => {
            ErrClass::Blob
        }
        K::StorageFull | K::QuotaExceeded => ErrClass::Full,
        // BrokenPipe: the packed writer thread is gone (it stops on a
        // failed volume open or roll), no store on this root can succeed.
        K::ReadOnlyFilesystem | K::StaleNetworkFileHandle | K::BrokenPipe => ErrClass::Gone,
        _ => ErrClass::Io,
    }
}

// ---------------------------------------------------------------------------
// Roots
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub(crate) enum RootState {
    Healthy = 0,
    Full = 1,
    Down = 2,
    Offline = 3,
}

impl RootState {
    fn from_u8(v: u8) -> Self {
        match v {
            0 => Self::Healthy,
            1 => Self::Full,
            2 => Self::Down,
            _ => Self::Offline,
        }
    }

    pub(crate) fn as_str(self) -> &'static str {
        match self {
            Self::Healthy => "healthy",
            Self::Full => "full",
            Self::Down => "down",
            Self::Offline => "offline",
        }
    }

    fn usable(self) -> bool {
        matches!(self, Self::Healthy | Self::Full)
    }
}

/// Opens one root's backend (flat, packed or migrating). Called on a
/// blocking thread, at startup and when an offline root comes back.
pub(crate) type RootFactory =
    dyn Fn(&Path) -> std::io::Result<Arc<dyn BlobStore>> + Send + Sync + 'static;

struct Root {
    path: PathBuf,
    /// Key of this root in the pending file: the path as configured.
    key: String,
    id: Mutex<Option<String>>,
    store: RwLock<Option<Arc<dyn BlobStore>>>,
    state: AtomicU8,
    /// `st_dev` of the root directory when it was opened (0 = unknown).
    dev: AtomicU64,
    total_bytes: AtomicU64,
    free_bytes: AtomicU64,
    consecutive_errors: AtomicU32,
    probe_failures: AtomicU32,
    errors_total: AtomicU64,
    writes_total: AtomicU64,
    /// The backend's writer stopped: reads and mutations still work, new
    /// writes need a restart.
    writer_stopped: AtomicBool,
    probing: AtomicBool,
    /// A recovery task (open and/or reintegration) is running.
    recovering: AtomicBool,
    reason: Mutex<String>,
}

impl Root {
    fn new(path: PathBuf) -> Self {
        // Normalized (no trailing slash, no `.`): the pending file keys
        // must not change with cosmetic edits of STORAGE_PATHS.
        let key = path.components().collect::<PathBuf>().display().to_string();
        Self {
            path,
            key,
            id: Mutex::new(None),
            store: RwLock::new(None),
            state: AtomicU8::new(RootState::Offline as u8),
            dev: AtomicU64::new(0),
            total_bytes: AtomicU64::new(0),
            free_bytes: AtomicU64::new(0),
            consecutive_errors: AtomicU32::new(0),
            probe_failures: AtomicU32::new(0),
            errors_total: AtomicU64::new(0),
            writes_total: AtomicU64::new(0),
            writer_stopped: AtomicBool::new(false),
            probing: AtomicBool::new(false),
            recovering: AtomicBool::new(false),
            reason: Mutex::new("not opened yet".to_string()),
        }
    }

    fn state(&self) -> RootState {
        RootState::from_u8(self.state.load(Ordering::Acquire))
    }

    fn store(&self) -> Option<Arc<dyn BlobStore>> {
        self.store.read().unwrap().clone()
    }

    /// The backend, if this root may be read and mutated now.
    fn usable(&self) -> Option<Arc<dyn BlobStore>> {
        if self.state().usable() {
            self.store()
        } else {
            None
        }
    }

    fn set_state(&self, to: RootState, reason: &str) {
        let from = RootState::from_u8(self.state.swap(to as u8, Ordering::AcqRel));
        *self.reason.lock().unwrap() = reason.to_string();
        if from == to {
            return;
        }
        match to {
            RootState::Healthy => {
                tracing::info!(root = %self.key, from = from.as_str(), reason, "storage root: healthy")
            }
            RootState::Full => {
                tracing::warn!(root = %self.key, from = from.as_str(), reason, "storage root: full, no new writes")
            }
            RootState::Down | RootState::Offline => tracing::error!(
                root = %self.key,
                from = from.as_str(),
                to = to.as_str(),
                reason,
                "storage root: unusable, its blobs are reported absent"
            ),
        }
    }
}

/// Outcome of one health probe.
#[derive(Debug)]
enum Probe {
    Ok {
        dev: u64,
        total: u64,
        free: u64,
        writable: bool,
    },
    Failed {
        reason: String,
        gone: bool,
    },
}

fn probe_root(path: &Path, expected_dev: u64) -> Probe {
    let meta = match std::fs::metadata(path) {
        Ok(m) => m,
        Err(e) => {
            return Probe::Failed {
                reason: format!("stat: {e}"),
                gone: true,
            };
        }
    };
    if !meta.is_dir() {
        return Probe::Failed {
            reason: "not a directory".into(),
            gone: true,
        };
    }
    if expected_dev != 0 && meta.dev() != expected_dev {
        return Probe::Failed {
            reason: format!(
                "device changed ({} -> {}): remounted or unmounted",
                expected_dev,
                meta.dev()
            ),
            gone: true,
        };
    }
    let (total, free) = match (fs2::total_space(path), fs2::available_space(path)) {
        (Ok(t), Ok(f)) => (t, f),
        (Err(e), _) | (_, Err(e)) => {
            return Probe::Failed {
                reason: format!("statvfs: {e}"),
                gone: false,
            };
        }
    };
    let probe = path.join(PROBE_FILE);
    let written = std::fs::File::create(&probe)
        .and_then(|mut f| f.write_all(b"arion-probe\n"))
        .and_then(|()| std::fs::remove_file(&probe));
    match written {
        Ok(()) => Probe::Ok {
            dev: meta.dev(),
            total,
            free,
            writable: true,
        },
        Err(e) => match classify(&e) {
            ErrClass::Full => Probe::Ok {
                dev: meta.dev(),
                total,
                free,
                writable: false,
            },
            class => Probe::Failed {
                reason: format!("probe write: {e}"),
                gone: class == ErrClass::Gone,
            },
        },
    }
}

/// What opening one root yields.
struct Opened {
    store: Arc<dyn BlobStore>,
    marker: RootMarker,
    dev: u64,
    total: u64,
    free: u64,
}

fn open_root_blocking(path: &Path, factory: &RootFactory) -> std::io::Result<Opened> {
    let meta = std::fs::metadata(path).map_err(|e| {
        std::io::Error::new(
            e.kind(),
            format!("{}: {e} (disk not mounted?)", path.display()),
        )
    })?;
    if !meta.is_dir() {
        return Err(std::io::Error::other(format!(
            "{}: not a directory",
            path.display()
        )));
    }
    let marker = admit_root(path)?;
    let store = factory(path)?;
    Ok(Opened {
        store,
        marker,
        dev: meta.dev(),
        total: fs2::total_space(path).unwrap_or(0),
        free: fs2::available_space(path).unwrap_or(0),
    })
}

// ---------------------------------------------------------------------------
// Pending file: deferred mutations and duplicate suspects
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum PendingOp {
    /// Trash the blob on the root.
    Delete,
    /// Remove the blob for good on the root (live and trash).
    Remove,
    /// Drop the blob from the root's trash.
    Purge,
    /// The blob was written while a copy may exist elsewhere.
    Suspect,
}

impl PendingOp {
    fn code(self) -> char {
        match self {
            Self::Delete => 'D',
            Self::Remove => 'R',
            Self::Purge => 'P',
            Self::Suspect => 'S',
        }
    }

    fn parse(c: &str) -> Option<Self> {
        match c {
            "D" => Some(Self::Delete),
            "R" => Some(Self::Remove),
            "P" => Some(Self::Purge),
            "S" => Some(Self::Suspect),
            _ => None,
        }
    }
}

/// One line: `<op> <hash> <root path as configured, or '-'>`.
#[derive(Debug, Clone, PartialEq, Eq)]
struct PendingLine {
    op: PendingOp,
    hash: String,
    root: String,
}

fn parse_line(line: &str) -> Option<PendingLine> {
    let mut it = line.splitn(3, ' ');
    let op = PendingOp::parse(it.next()?)?;
    let hash = it.next()?.to_string();
    let root = it.next()?.to_string();
    (!hash.is_empty() && !root.is_empty()).then_some(PendingLine { op, hash, root })
}

struct PendingLog {
    path: PathBuf,
    file: std::fs::File,
    suspects: u64,
    suspects_capped: bool,
}

impl PendingLog {
    fn open(path: &Path) -> std::io::Result<Self> {
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)?;
        }
        let file = std::fs::OpenOptions::new()
            .create(true)
            .read(true)
            .append(true)
            .open(path)?;
        let mut log = Self {
            path: path.to_path_buf(),
            file,
            suspects: 0,
            suspects_capped: false,
        };
        log.drop_torn_tail()?;
        log.suspects = log.count(|l| l.op == PendingOp::Suspect)?;
        Ok(log)
    }

    /// A last line without its newline is an append a crash cut: that
    /// operation returned an error, drop it (else the next append would be
    /// glued to it).
    fn drop_torn_tail(&mut self) -> std::io::Result<()> {
        let len = self.file.metadata()?.len();
        if len == 0 {
            return Ok(());
        }
        let mut f = std::fs::File::open(&self.path)?;
        let mut keep = len;
        let mut buf = vec![0u8; 4096];
        loop {
            let start = keep.saturating_sub(buf.len() as u64);
            let n = (keep - start) as usize;
            f.seek(std::io::SeekFrom::Start(start))?;
            std::io::Read::read_exact(&mut f, &mut buf[..n])?;
            if keep == len && buf[n - 1] == b'\n' {
                return Ok(());
            }
            if let Some(pos) = buf[..n].iter().rposition(|&b| b == b'\n') {
                keep = start + pos as u64 + 1;
                break;
            }
            keep = start;
            if start == 0 {
                break;
            }
        }
        tracing::warn!(path = %self.path.display(), len, keep, "storage roots: dropping a torn pending line");
        self.file.set_len(keep)?;
        self.file.sync_data()
    }

    fn len(&self) -> std::io::Result<u64> {
        Ok(self.file.metadata()?.len())
    }

    fn append(&mut self, line: &PendingLine, durable: bool) -> std::io::Result<()> {
        let text = format!("{} {} {}\n", line.op.code(), line.hash, line.root);
        self.file.write_all(text.as_bytes())?;
        if durable {
            self.file.sync_data()?;
        }
        if line.op == PendingOp::Suspect {
            self.suspects += 1;
        }
        Ok(())
    }

    fn count(&self, mut pred: impl FnMut(&PendingLine) -> bool) -> std::io::Result<u64> {
        let mut n = 0u64;
        let mut off = 0u64;
        let end = self.len()?;
        loop {
            let (lines, next) = read_chunk(&self.path, off, end, REPLAY_CHUNK)?;
            n += lines.iter().filter(|(_, l)| pred(l)).count() as u64;
            if next == off {
                return Ok(n);
            }
            off = next;
        }
    }

    /// Rewrite the file keeping the lines `keep` accepts (streamed through
    /// a tmp file, fsynced, renamed, directory fsynced).
    fn rewrite(&mut self, mut keep: impl FnMut(u64, &PendingLine) -> bool) -> std::io::Result<()> {
        let tmp = self.path.with_extension("tmp");
        let end = self.len()?;
        {
            let mut out = std::io::BufWriter::new(std::fs::File::create(&tmp)?);
            let mut off = 0u64;
            loop {
                let (lines, next) = read_chunk(&self.path, off, end, REPLAY_CHUNK)?;
                for (at, l) in &lines {
                    if keep(*at, l) {
                        writeln!(out, "{} {} {}", l.op.code(), l.hash, l.root)?;
                    }
                }
                if next == off {
                    break;
                }
                off = next;
            }
            out.into_inner().map_err(|e| e.into_error())?.sync_all()?;
        }
        std::fs::rename(&tmp, &self.path)?;
        if let Some(parent) = self.path.parent() {
            sync_dir(parent)?;
        }
        self.file = std::fs::OpenOptions::new()
            .read(true)
            .append(true)
            .open(&self.path)?;
        self.suspects = self.count(|l| l.op == PendingOp::Suspect)?;
        self.suspects_capped = false;
        Ok(())
    }
}

/// Up to `max` complete lines of `path` in `[from, to)`, with their
/// offsets, and the offset after the last one returned (`from` when there
/// is none). A malformed line is skipped (logged).
fn read_chunk(
    path: &Path,
    from: u64,
    to: u64,
    max: usize,
) -> std::io::Result<(Vec<(u64, PendingLine)>, u64)> {
    let mut f = std::io::BufReader::new(std::fs::File::open(path)?);
    f.seek(std::io::SeekFrom::Start(from))?;
    let mut out = Vec::new();
    let mut off = from;
    let mut buf = String::new();
    while off < to && out.len() < max {
        buf.clear();
        let n = f.read_line(&mut buf)?;
        if n == 0 || !buf.ends_with('\n') || off + n as u64 > to {
            break;
        }
        match parse_line(buf.trim_end_matches('\n')) {
            Some(l) => out.push((off, l)),
            None => tracing::warn!(
                offset = off,
                "storage roots: malformed pending line skipped"
            ),
        }
        off += n as u64;
    }
    Ok((out, off))
}

// ---------------------------------------------------------------------------
// The store
// ---------------------------------------------------------------------------

/// See the module docs.
pub(crate) struct MultiRootStore {
    roots: Vec<Root>,
    factory: Arc<RootFactory>,
    pending: tokio::sync::Mutex<PendingLog>,
    /// Smooth weighted round-robin state, one slot per root.
    picker: Mutex<Vec<i64>>,
    reserve_bytes: u64,
    /// [`held_before`]; replaceable by tests (the inventory is a process
    /// global shared by every test).
    held_before: Mutex<fn(&str) -> bool>,
    /// Shared by every delete/remove/purge for its whole duration,
    /// exclusive while a root turns usable: a mutation that saw a root
    /// unusable has recorded it in the pending file before that root's
    /// last replay pass reads the file (else the root could come back
    /// between the check and the record and serve a blob just deleted).
    mutation_gate: tokio::sync::RwLock<()>,
}

impl std::fmt::Debug for MultiRootStore {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("MultiRootStore")
            .field(
                "roots",
                &self.roots.iter().map(|r| &r.key).collect::<Vec<_>>(),
            )
            .finish()
    }
}

/// Per-root summary (logs, metrics, tests).
#[derive(Debug, Clone)]
pub(crate) struct RootStatus {
    pub path: String,
    pub id: Option<String>,
    pub state: RootState,
    pub reason: String,
    pub total_bytes: u64,
    pub free_bytes: u64,
    pub used_bytes: u64,
    pub errors_total: u64,
    pub writes_total: u64,
}

/// Outcome of [`MultiRootStore::resolve_suspects`].
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub(crate) struct SuspectReport {
    pub checked: u64,
    pub duplicates_removed: u64,
    pub kept_for_later: u64,
    pub skipped_roots_unusable: bool,
}

impl MultiRootStore {
    /// Open every root (concurrently, on blocking threads), replay the
    /// pending mutations of each opened root, and return the store. A root
    /// that cannot be opened (missing, I/O error) starts offline; a root
    /// whose layout needs an operator step (`InvalidData`: packed data
    /// without a marker, a bad marker) fails the whole open, and so does a
    /// configuration with duplicate roots or no usable root.
    pub(crate) async fn open(
        paths: Vec<PathBuf>,
        factory: Arc<RootFactory>,
        state_dir: &Path,
        reserve_bytes: u64,
    ) -> std::io::Result<Arc<Self>> {
        check_distinct(&paths)?;
        let pending = PendingLog::open(&state_dir.join(PENDING_FILE))?;
        let n = paths.len();
        let this = Arc::new(Self {
            roots: paths.iter().cloned().map(Root::new).collect(),
            factory,
            pending: tokio::sync::Mutex::new(pending),
            picker: Mutex::new(vec![0; n]),
            reserve_bytes,
            held_before: Mutex::new(held_before),
            mutation_gate: tokio::sync::RwLock::new(()),
        });

        let opens = paths.iter().cloned().map(|path| {
            let factory = Arc::clone(&this.factory);
            tokio::task::spawn_blocking(move || open_root_blocking(&path, factory.as_ref()))
        });
        let results = futures::future::join_all(opens).await;
        for (i, res) in results.into_iter().enumerate() {
            let res = res.map_err(|e| std::io::Error::other(format!("root open panicked: {e}")))?;
            match res {
                Ok(opened) => this.install(i, opened),
                Err(e) if e.kind() == std::io::ErrorKind::InvalidData => return Err(e),
                Err(e) => this.roots[i].set_state(RootState::Offline, &format!("open: {e}")),
            }
        }
        for i in 0..n {
            if this.roots[i].store().is_some()
                && let Err(e) = this.reintegrate(i).await
            {
                this.roots[i].set_state(RootState::Down, &format!("pending replay: {e}"));
            }
        }
        let mut devs: Vec<(u64, &str)> = Vec::new();
        for r in &this.roots {
            let dev = r.dev.load(Ordering::Acquire);
            if dev == 0 {
                continue;
            }
            if let Some((_, other)) = devs.iter().find(|(d, _)| *d == dev) {
                tracing::warn!(
                    root = %r.key,
                    other = %other,
                    "storage roots on the same filesystem: no separate failure domain, capacity counted once"
                );
            }
            devs.push((dev, &r.key));
        }
        if !this.roots.iter().any(|r| r.state().usable()) {
            return Err(std::io::Error::other(
                "no storage root is usable (every STORAGE_PATHS entry failed to open)",
            ));
        }
        for s in this.status() {
            tracing::info!(
                root = %s.path,
                id = ?s.id,
                state = s.state.as_str(),
                reason = %s.reason,
                total_bytes = s.total_bytes,
                free_bytes = s.free_bytes,
                used_bytes = s.used_bytes,
                "storage root opened"
            );
        }
        Ok(this)
    }

    /// Record an opened backend. The root stays unusable until
    /// [`reintegrate`](Self::reintegrate) has replayed its pending
    /// mutations.
    fn install(&self, i: usize, opened: Opened) {
        let root = &self.roots[i];
        *root.store.write().unwrap() = Some(opened.store);
        *root.id.lock().unwrap() = Some(opened.marker.id);
        root.dev.store(opened.dev, Ordering::Release);
        root.total_bytes.store(opened.total, Ordering::Relaxed);
        root.free_bytes.store(opened.free, Ordering::Relaxed);
        root.consecutive_errors.store(0, Ordering::Relaxed);
        root.probe_failures.store(0, Ordering::Relaxed);
        root.writer_stopped.store(false, Ordering::Relaxed);
        if root.state() != RootState::Down {
            root.state
                .store(RootState::Offline as u8, Ordering::Release);
        }
    }

    pub(crate) fn root_count(&self) -> usize {
        self.roots.len()
    }

    pub(crate) fn status(&self) -> Vec<RootStatus> {
        self.roots
            .iter()
            .map(|r| RootStatus {
                path: r.key.clone(),
                id: r.id.lock().unwrap().clone(),
                state: r.state(),
                reason: r.reason.lock().unwrap().clone(),
                total_bytes: r.total_bytes.load(Ordering::Relaxed),
                free_bytes: r.free_bytes.load(Ordering::Relaxed),
                used_bytes: r.usable().map(|s| s.used_bytes()).unwrap_or(0),
                errors_total: r.errors_total.load(Ordering::Relaxed),
                writes_total: r.writes_total.load(Ordering::Relaxed),
            })
            .collect()
    }

    /// Prometheus text exposition of the per-root gauges and counters
    /// (no scrape endpoint in the miner yet; logged in the summary line).
    pub(crate) fn render_prometheus(&self) -> String {
        let mut out = String::new();
        for s in self.status() {
            let l = s.path.replace('\\', "\\\\").replace('"', "\\\"");
            out.push_str(&format!(
                "miner_storage_root_state{{root=\"{l}\",state=\"{}\"}} {}\n\
                 miner_storage_root_total_bytes{{root=\"{l}\"}} {}\n\
                 miner_storage_root_free_bytes{{root=\"{l}\"}} {}\n\
                 miner_storage_root_used_bytes{{root=\"{l}\"}} {}\n\
                 miner_storage_root_errors_total{{root=\"{l}\"}} {}\n\
                 miner_storage_root_writes_total{{root=\"{l}\"}} {}\n",
                s.state.as_str(),
                s.state as u8,
                s.total_bytes,
                s.free_bytes,
                s.used_bytes,
                s.errors_total,
                s.writes_total,
            ));
        }
        out
    }

    fn any_unusable(&self) -> bool {
        self.roots.iter().any(|r| !r.state().usable())
    }

    fn writable(&self, i: usize) -> bool {
        let r = &self.roots[i];
        r.state() == RootState::Healthy
            && !r.writer_stopped.load(Ordering::Relaxed)
            && r.store().is_some()
    }

    fn weight(&self, i: usize) -> i64 {
        let free = self.roots[i].free_bytes.load(Ordering::Relaxed);
        ((free.saturating_sub(self.reserve_bytes) >> 20).max(1)).min(i64::MAX as u64) as i64
    }

    /// Next root for a new blob: smooth weighted round-robin over the
    /// writable roots not in `tried`, restricted to those whose write
    /// budget admits `len` now when at least one does.
    fn pick(&self, tried: &[bool], len: u64) -> Option<usize> {
        let cands: Vec<usize> = (0..self.roots.len())
            .filter(|&i| !tried[i] && self.writable(i))
            .collect();
        if cands.is_empty() {
            return None;
        }
        let admitting: Vec<usize> = cands
            .iter()
            .copied()
            .filter(|&i| {
                self.roots[i]
                    .store()
                    .and_then(|s| s.inflight_headroom(len))
                    .is_none_or(|h| h.admits())
            })
            .collect();
        let pool = if admitting.is_empty() {
            cands
        } else {
            admitting
        };
        let weights: Vec<i64> = pool.iter().map(|&i| self.weight(i)).collect();
        let total: i64 = weights.iter().sum();
        let mut cur = self.picker.lock().unwrap();
        let mut best = pool[0];
        for (&i, &w) in pool.iter().zip(&weights) {
            cur[i] += w;
            if cur[i] > cur[best] {
                best = i;
            }
        }
        cur[best] -= total;
        Some(best)
    }

    fn on_success(&self, i: usize) {
        self.roots[i].consecutive_errors.store(0, Ordering::Relaxed);
    }

    /// Account an error of root `i` and move it to `full`/`down` when the
    /// error says so.
    fn on_error(&self, i: usize, e: &std::io::Error) {
        let root = &self.roots[i];
        let class = classify(e);
        if class == ErrClass::Blob {
            return;
        }
        root.errors_total.fetch_add(1, Ordering::Relaxed);
        match class {
            ErrClass::Blob => {}
            ErrClass::Full => {
                if root.state() == RootState::Healthy {
                    root.set_state(RootState::Full, &format!("write: {e}"));
                }
            }
            ErrClass::Gone => {
                if e.kind() == std::io::ErrorKind::BrokenPipe {
                    root.writer_stopped.store(true, Ordering::Relaxed);
                }
                if root.state().usable() {
                    root.set_state(RootState::Down, &format!("{e}"));
                }
            }
            ErrClass::Io => {
                let n = root.consecutive_errors.fetch_add(1, Ordering::Relaxed) + 1;
                tracing::warn!(root = %root.key, consecutive = n, error = %e, "storage root: I/O error");
                if n >= DOWN_AFTER_IO_ERRORS && root.state().usable() {
                    root.set_state(
                        RootState::Down,
                        &format!("{n} consecutive I/O errors, last: {e}"),
                    );
                }
            }
        }
    }

    async fn append_pending(&self, line: PendingLine, durable: bool) -> std::io::Result<()> {
        let mut log = self.pending.lock().await;
        if line.op == PendingOp::Suspect && log.suspects >= MAX_SUSPECTS {
            if !log.suspects_capped {
                log.suspects_capped = true;
                tracing::warn!(
                    max = MAX_SUSPECTS,
                    "storage roots: duplicate suspect list full, further duplicates are served but not cleaned up automatically"
                );
            }
            return Ok(());
        }
        crate::helpers::blocking(|| log.append(&line, durable))
    }

    /// The routing of one delete/remove/purge, decided once: the usable
    /// roots' backends, the others recorded durably in the pending file
    /// first. Call under a read guard of `mutation_gate`, held until the
    /// mutation is applied. A crash after the record and before the
    /// mutation only leaves an unacknowledged operation recorded.
    async fn route_mutation(
        &self,
        op: PendingOp,
        hash: &str,
    ) -> std::io::Result<Vec<(usize, Arc<dyn BlobStore>)>> {
        let mut usable = Vec::with_capacity(self.roots.len());
        for (i, r) in self.roots.iter().enumerate() {
            match r.usable() {
                Some(s) => usable.push((i, s)),
                None => {
                    self.append_pending(
                        PendingLine {
                            op,
                            hash: hash.to_string(),
                            root: r.key.clone(),
                        },
                        true,
                    )
                    .await?
                }
            }
        }
        Ok(usable)
    }

    async fn note_suspect(&self, hash: &str) {
        let line = PendingLine {
            op: PendingOp::Suspect,
            hash: hash.to_string(),
            root: "-".to_string(),
        };
        if let Err(e) = self.append_pending(line, true).await {
            tracing::warn!(hash, error = %e, "storage roots: cannot record a duplicate suspect");
        }
    }

    /// First usable root holding `hash` live or in its trash.
    fn home_of(&self, hash: &str) -> Option<usize> {
        self.roots.iter().position(|r| {
            r.usable()
                .is_some_and(|s| s.has(hash) || s.has_trashed(hash))
        })
    }

    async fn store_on(&self, i: usize, hash: &str, data: &[u8]) -> std::io::Result<()> {
        let root = &self.roots[i];
        let Some(s) = root.store() else {
            return Err(std::io::Error::other("storage root not open"));
        };
        match s.store(hash, data).await {
            Ok(()) => {
                self.on_success(i);
                root.writes_total.fetch_add(1, Ordering::Relaxed);
                let len = data.len() as u64;
                let _ = root
                    .free_bytes
                    .fetch_update(Ordering::Relaxed, Ordering::Relaxed, |f| {
                        Some(f.saturating_sub(len))
                    });
                Ok(())
            }
            Err(e) => {
                tracing::warn!(root = %root.key, hash, error = %e, "storage root: store failed");
                self.on_error(i, &e);
                Err(e)
            }
        }
    }

    /// Replay root `i`'s pending mutations, remove them from the file, then
    /// make the root usable. The bulk is replayed without the file lock
    /// (mutations of other roots keep flowing); the tail appended meanwhile
    /// is replayed under it, and the file is rewritten before the lock is
    /// released and the root becomes usable.
    async fn reintegrate(&self, i: usize) -> std::io::Result<()> {
        let root = &self.roots[i];
        let store = root
            .store()
            .ok_or_else(|| std::io::Error::other("storage root not open"))?;
        let path = self.pending.lock().await.path.clone();
        let end = self.pending.lock().await.len()?;
        let mut applied = replay_root(&path, &root.key, store.as_ref(), 0, end).await?;
        // No mutation in flight from here on: every one that saw this root
        // unusable has its record in the file.
        let _gate = self.mutation_gate.write().await;
        let mut log = self.pending.lock().await;
        let end2 = log.len()?;
        applied += replay_root(&path, &root.key, store.as_ref(), end, end2).await?;
        if applied > 0 {
            let key = root.key.clone();
            crate::helpers::blocking(|| {
                log.rewrite(|_, l| l.op == PendingOp::Suspect || l.root != key)
            })?;
            tracing::info!(root = %root.key, applied, "storage root: pending mutations replayed");
        }
        root.consecutive_errors.store(0, Ordering::Relaxed);
        root.probe_failures.store(0, Ordering::Relaxed);
        let free = root.free_bytes.load(Ordering::Relaxed);
        if root.writer_stopped.load(Ordering::Relaxed) {
            root.set_state(
                RootState::Full,
                "writer stopped: reads only until the next start",
            );
        } else if free < self.reserve_bytes {
            root.set_state(RootState::Full, "free space under the reserve");
        } else {
            root.set_state(RootState::Healthy, "reintegrated");
        }
        drop(log);
        Ok(())
    }

    /// Remove the extra copies of the suspect blobs once every root is
    /// usable: keep the first root (configuration order) whose copy
    /// verifies, `remove` the others. A blob being written right now (its
    /// per-hash write lock is held) or with no verifying copy stays listed.
    pub(crate) async fn resolve_suspects(&self) -> std::io::Result<SuspectReport> {
        let mut report = SuspectReport::default();
        if self.any_unusable() {
            report.skipped_roots_unusable = true;
            return Ok(report);
        }
        let (path, end) = {
            let log = self.pending.lock().await;
            if log.suspects == 0 {
                return Ok(report);
            }
            (log.path.clone(), log.len()?)
        };
        // Hashes left for a later pass, bounded: past the bound the pass
        // stops and the rest of the file is kept as is.
        let mut keep: std::collections::HashSet<String> = std::collections::HashSet::new();
        let mut off = 0u64;
        let mut done_upto = end;
        'pass: loop {
            let (lines, next) =
                crate::helpers::blocking(|| read_chunk(&path, off, end, REPLAY_CHUNK))?;
            for (at, l) in lines.iter().filter(|(_, l)| l.op == PendingOp::Suspect) {
                if keep.len() >= MAX_KEPT_SUSPECTS {
                    done_upto = *at;
                    break 'pass;
                }
                report.checked += 1;
                if !self.resolve_one(&l.hash, &mut report).await {
                    keep.insert(l.hash.clone());
                }
            }
            if next == off {
                break;
            }
            off = next;
        }
        report.kept_for_later = keep.len() as u64;
        let mut log = self.pending.lock().await;
        crate::helpers::blocking(|| {
            log.rewrite(|at, l| {
                l.op != PendingOp::Suspect || at >= done_upto || keep.contains(&l.hash)
            })
        })?;
        if report.duplicates_removed > 0 || report.kept_for_later > 0 {
            tracing::info!(
                checked = report.checked,
                removed = report.duplicates_removed,
                kept = report.kept_for_later,
                "storage roots: duplicate suspects resolved"
            );
        }
        Ok(report)
    }

    /// `true` when `hash` needs no further attention.
    async fn resolve_one(&self, hash: &str, report: &mut SuspectReport) -> bool {
        let Some(_lock) = crate::state::try_lock_hash_write(hash) else {
            return false;
        };
        let holders: Vec<(usize, Arc<dyn BlobStore>)> = self
            .roots
            .iter()
            .enumerate()
            .filter_map(|(i, r)| r.usable().map(|s| (i, s)))
            .filter(|(_, s)| s.has(hash))
            .collect();
        if holders.len() <= 1 {
            return true;
        }
        let mut keeper = None;
        for (i, s) in &holders {
            if let Ok(b) = s.read(hash).await
                && blake3::hash(&b).to_hex().as_str() == hash
            {
                keeper = Some(*i);
                break;
            }
        }
        let Some(keeper) = keeper else {
            tracing::warn!(
                hash,
                copies = holders.len(),
                "storage roots: no copy of a duplicated blob verifies, keeping them all"
            );
            return false;
        };
        let mut done = true;
        for (i, s) in holders.iter().filter(|(i, _)| *i != keeper) {
            match s.remove(hash).await {
                Ok(()) => report.duplicates_removed += 1,
                Err(e) => {
                    self.on_error(*i, &e);
                    tracing::warn!(root = %self.roots[*i].key, hash, error = %e, "storage roots: duplicate removal failed");
                    done = false;
                }
            }
        }
        done
    }

    /// One probe round over every root (each on its own blocking thread,
    /// bounded by [`PROBE_TIMEOUT`]; a root whose previous probe is still
    /// blocked is skipped), then the state transitions.
    pub(crate) async fn probe_all(self: &Arc<Self>) {
        let mut handles = Vec::new();
        for i in 0..self.roots.len() {
            let root = &self.roots[i];
            if root.probing.swap(true, Ordering::AcqRel) {
                continue;
            }
            let this = Arc::clone(self);
            let expected = root.dev.load(Ordering::Acquire);
            let path = root.path.clone();
            let task = tokio::task::spawn_blocking(move || {
                let p = probe_root(&path, expected);
                this.roots[i].probing.store(false, Ordering::Release);
                p
            });
            handles.push((i, task));
        }
        for (i, task) in handles {
            let probe = match tokio::time::timeout(PROBE_TIMEOUT, task).await {
                Ok(Ok(p)) => p,
                Ok(Err(e)) => Probe::Failed {
                    reason: format!("probe panicked: {e}"),
                    gone: false,
                },
                Err(_) => Probe::Failed {
                    reason: format!("probe blocked for more than {PROBE_TIMEOUT:?}"),
                    gone: false,
                },
            };
            self.apply_probe(i, probe).await;
        }
    }

    async fn apply_probe(self: &Arc<Self>, i: usize, probe: Probe) {
        let root = &self.roots[i];
        match probe {
            Probe::Failed { reason, gone } => {
                let n = root.probe_failures.fetch_add(1, Ordering::Relaxed) + 1;
                if root.state().usable() && (gone || n >= DOWN_AFTER_PROBE_FAILURES) {
                    root.set_state(RootState::Down, &reason);
                } else if !root.state().usable() {
                    *root.reason.lock().unwrap() = reason;
                }
            }
            Probe::Ok {
                dev,
                total,
                free,
                writable,
            } => {
                root.probe_failures.store(0, Ordering::Relaxed);
                root.total_bytes.store(total, Ordering::Relaxed);
                root.free_bytes.store(free, Ordering::Relaxed);
                match root.state() {
                    RootState::Healthy => {
                        if !writable {
                            root.set_state(RootState::Full, "probe write: no space");
                        } else if free < self.reserve_bytes {
                            root.set_state(RootState::Full, "free space under the reserve");
                        }
                    }
                    RootState::Full => {
                        if writable
                            && free >= self.reserve_bytes.saturating_mul(2)
                            && !root.writer_stopped.load(Ordering::Relaxed)
                        {
                            root.set_state(RootState::Healthy, "free space recovered");
                        }
                    }
                    RootState::Down => {
                        if root.store().is_some() && dev == root.dev.load(Ordering::Acquire) {
                            self.spawn_recovery(i, false);
                        }
                    }
                    RootState::Offline => self.spawn_recovery(i, true),
                }
            }
        }
    }

    /// Bring root `i` back in a task of its own (`open` first for an
    /// offline root), so a disk that blocks in its open or its replay never
    /// stalls the probes of the other roots. At most one per root.
    fn spawn_recovery(self: &Arc<Self>, i: usize, open: bool) {
        if self.roots[i].recovering.swap(true, Ordering::AcqRel) {
            return;
        }
        let this = Arc::clone(self);
        tokio::spawn(async move {
            let root = &this.roots[i];
            if open {
                let opener = Arc::clone(&this);
                let path = root.path.clone();
                let opened = tokio::task::spawn_blocking(move || {
                    open_root_blocking(&path, opener.factory.as_ref())
                })
                .await;
                match opened {
                    Ok(Ok(o)) => this.install(i, o),
                    Ok(Err(e)) => {
                        *root.reason.lock().unwrap() = format!("open: {e}");
                        root.recovering.store(false, Ordering::Release);
                        return;
                    }
                    Err(e) => {
                        *root.reason.lock().unwrap() = format!("open panicked: {e}");
                        root.recovering.store(false, Ordering::Release);
                        return;
                    }
                }
            }
            if let Err(e) = this.reintegrate(i).await {
                root.set_state(RootState::Down, &format!("pending replay: {e}"));
            }
            root.recovering.store(false, Ordering::Release);
        });
    }

    /// Test hook: wait until no recovery task runs.
    #[cfg(test)]
    pub(crate) async fn settle(&self) {
        for _ in 0..1000 {
            if self
                .roots
                .iter()
                .all(|r| !r.recovering.load(Ordering::Acquire))
            {
                return;
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
        panic!("recovery did not settle");
    }

    /// Background loop: probes every `interval`, resolves the duplicate
    /// suspects whenever every root is usable, logs a per-root summary
    /// every 10 minutes.
    pub(crate) fn spawn_health_loop(self: &Arc<Self>, interval: Duration) {
        let this = Arc::clone(self);
        tokio::spawn(async move {
            let mut last_summary = tokio::time::Instant::now();
            loop {
                tokio::time::sleep(interval).await;
                this.probe_all().await;
                if !this.any_unusable()
                    && let Err(e) = this.resolve_suspects().await
                {
                    tracing::warn!(error = %e, "storage roots: duplicate suspect resolution failed");
                }
                if last_summary.elapsed() >= SUMMARY_EVERY {
                    last_summary = tokio::time::Instant::now();
                    tracing::debug!(metrics = %this.render_prometheus(), "storage roots: metrics");
                    for s in this.status() {
                        tracing::info!(
                            root = %s.path,
                            state = s.state.as_str(),
                            reason = %s.reason,
                            free_bytes = s.free_bytes,
                            used_bytes = s.used_bytes,
                            errors_total = s.errors_total,
                            writes_total = s.writes_total,
                            "storage root: summary"
                        );
                    }
                }
            }
        });
    }
}

/// Whether this node held `hash` live before this write, per the
/// inventory (a read-only connection of its own, no shared lock): only such
/// a blob can also sit on a root that is unusable right now, so only its
/// write is a duplicate suspect. Any doubt (not a hash, inventory error or
/// not initialized) answers `true`.
fn held_before(hash: &str) -> bool {
    let mut key = [0u8; 32];
    if hex::decode_to_slice(hash, &mut key).is_err() {
        return true;
    }
    crate::helpers::blocking(|| crate::inventory::live_among(&[key]))
        .ok()
        .and_then(|v| v.first().copied())
        .unwrap_or(true)
}

/// Apply root `key`'s pending mutations in `[from, to)` to `store`, in
/// file order. Returns how many were applied.
async fn replay_root(
    path: &Path,
    key: &str,
    store: &dyn BlobStore,
    from: u64,
    to: u64,
) -> std::io::Result<u64> {
    let mut applied = 0u64;
    let mut off = from;
    while off < to {
        let (lines, next) = crate::helpers::blocking(|| read_chunk(path, off, to, REPLAY_CHUNK))?;
        for (_, l) in lines.iter().filter(|(_, l)| l.root == key) {
            match l.op {
                PendingOp::Delete => {
                    if store.has(&l.hash) {
                        store.delete(&l.hash).await?;
                    }
                }
                PendingOp::Remove => store.remove(&l.hash).await?,
                PendingOp::Purge => store.purge_trashed(&l.hash).await?,
                PendingOp::Suspect => continue,
            }
            applied += 1;
        }
        if next == off {
            break;
        }
        off = next;
    }
    Ok(applied)
}

/// Refuse a root listed twice: the same directory (after resolving
/// symlinks) or the same inode under two names would run two stores, two
/// writers, over one set of files.
fn check_distinct(paths: &[PathBuf]) -> std::io::Result<()> {
    if paths.is_empty() {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "STORAGE_PATHS is empty",
        ));
    }
    let mut seen: Vec<(PathBuf, Option<(u64, u64)>)> = Vec::new();
    for p in paths {
        let canon = std::fs::canonicalize(p).unwrap_or_else(|_| p.clone());
        let ident = std::fs::metadata(p).ok().map(|m| (m.dev(), m.ino()));
        if let Some((other, _)) = seen
            .iter()
            .find(|(c, id)| *c == canon || (ident.is_some() && *id == ident))
        {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                format!(
                    "storage root {} is listed twice (same directory as {})",
                    p.display(),
                    other.display()
                ),
            ));
        }
        seen.push((canon, ident));
    }
    Ok(())
}

#[async_trait::async_trait]
impl BlobStore for MultiRootStore {
    async fn store(&self, hash_hex: &str, data: &[u8]) -> std::io::Result<()> {
        let n = self.roots.len();
        let home = self.home_of(hash_hex);
        if let Some(h) = home
            && self.writable(h)
        {
            // Single-copy rule: the root that has it gets it again; a
            // failure is returned as is (the caller retries, and lands
            // elsewhere if this root is no longer writable).
            return self.store_on(h, hash_hex, data).await;
        }
        let mut tried = vec![false; n];
        let mut suspect = self.any_unusable() && (*self.held_before.lock().unwrap())(hash_hex);
        let mut last_err = None;
        while let Some(i) = self.pick(&tried, data.len() as u64) {
            tried[i] = true;
            match self.store_on(i, hash_hex, data).await {
                Ok(()) => {
                    if let Some(h) = home
                        && h != i
                        && !self.drop_old_copy(h, hash_hex).await
                    {
                        suspect = true;
                    }
                    if suspect {
                        self.note_suspect(hash_hex).await;
                    }
                    return Ok(());
                }
                Err(e) => {
                    if self.roots[i].store().is_some_and(|s| s.has(hash_hex)) {
                        // The batch may be in the volume: no second copy.
                        return Err(e);
                    }
                    suspect = true;
                    last_err = Some(e);
                }
            }
        }
        Err(last_err.unwrap_or_else(|| {
            std::io::Error::new(
                std::io::ErrorKind::StorageFull,
                "no writable storage root (all full or unusable)",
            )
        }))
    }

    fn inflight_headroom(&self, payload_len: u64) -> Option<InflightHeadroom> {
        (0..self.roots.len())
            .filter(|&i| self.writable(i))
            .filter_map(|i| self.roots[i].store()?.inflight_headroom(payload_len))
            .max_by_key(|h| h.available)
    }

    async fn read(&self, hash_hex: &str) -> std::io::Result<Bytes> {
        let mut first_err = None;
        for (i, r) in self.roots.iter().enumerate() {
            let Some(s) = r.usable() else { continue };
            match s.read(hash_hex).await {
                Ok(b) => {
                    self.on_success(i);
                    return Ok(b);
                }
                Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
                Err(e) => {
                    self.on_error(i, &e);
                    first_err.get_or_insert(e);
                }
            }
        }
        Err(first_err.unwrap_or_else(|| std::io::ErrorKind::NotFound.into()))
    }

    async fn read_at_most(&self, hash_hex: &str, max_len: u64) -> std::io::Result<Bytes> {
        let mut first_err = None;
        for (i, r) in self.roots.iter().enumerate() {
            let Some(s) = r.usable() else { continue };
            match s.read_at_most(hash_hex, max_len).await {
                Ok(b) => {
                    self.on_success(i);
                    return Ok(b);
                }
                Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
                Err(e) => {
                    self.on_error(i, &e);
                    first_err.get_or_insert(e);
                }
            }
        }
        Err(first_err.unwrap_or_else(|| std::io::ErrorKind::NotFound.into()))
    }

    fn has(&self, hash_hex: &str) -> bool {
        self.roots
            .iter()
            .any(|r| r.usable().is_some_and(|s| s.has(hash_hex)))
    }

    fn blob_len(&self, hash_hex: &str) -> Option<u64> {
        self.roots
            .iter()
            .find_map(|r| r.usable().and_then(|s| s.blob_len(hash_hex)))
    }

    fn confirmed_absent(&self, hash_hex: &str) -> bool {
        // An unusable root may hold it: never a definite absence then.
        !self.any_unusable()
            && self
                .roots
                .iter()
                .all(|r| r.store().is_some_and(|s| s.confirmed_absent(hash_hex)))
    }

    async fn delete(&self, hash_hex: &str) -> std::io::Result<()> {
        let _gate = self.mutation_gate.read().await;
        let mut first_err = None;
        for (i, s) in self.route_mutation(PendingOp::Delete, hash_hex).await? {
            if s.has(hash_hex)
                && let Err(e) = s.delete(hash_hex).await
            {
                self.on_error(i, &e);
                first_err.get_or_insert(e);
            }
        }
        first_err.map_or(Ok(()), Err)
    }

    async fn remove(&self, hash_hex: &str) -> std::io::Result<()> {
        let _gate = self.mutation_gate.read().await;
        let mut first_err = None;
        for (i, s) in self.route_mutation(PendingOp::Remove, hash_hex).await? {
            if (s.has(hash_hex) || s.has_trashed(hash_hex))
                && let Err(e) = s.remove(hash_hex).await
            {
                self.on_error(i, &e);
                first_err.get_or_insert(e);
            }
        }
        first_err.map_or(Ok(()), Err)
    }

    async fn restore(&self, hash_hex: &str) -> std::io::Result<bool> {
        for (i, r) in self.roots.iter().enumerate() {
            let Some(s) = r.usable() else { continue };
            if !s.has_trashed(hash_hex) {
                continue;
            }
            match s.restore(hash_hex).await {
                Ok(true) => return Ok(true),
                Ok(false) => {}
                Err(e) => {
                    self.on_error(i, &e);
                    return Err(e);
                }
            }
        }
        Ok(false)
    }

    async fn purge_trashed(&self, hash_hex: &str) -> std::io::Result<()> {
        let _gate = self.mutation_gate.read().await;
        let mut first_err = None;
        for (i, s) in self.route_mutation(PendingOp::Purge, hash_hex).await? {
            if s.has_trashed(hash_hex)
                && let Err(e) = s.purge_trashed(hash_hex).await
            {
                self.on_error(i, &e);
                first_err.get_or_insert(e);
            }
        }
        first_err.map_or(Ok(()), Err)
    }

    fn list_hashes(&self) -> Vec<String> {
        let mut out = Vec::new();
        self.for_each_hash(&mut |h| out.push(h.to_string()));
        out
    }

    /// Each usable root streamed in order; a hash an earlier root holds is
    /// skipped (a duplicate is listed once), with no set of names seen.
    fn for_each_hash(&self, visit: &mut dyn FnMut(&str)) {
        let usable: Vec<Arc<dyn BlobStore>> =
            self.roots.iter().filter_map(|r| r.usable()).collect();
        for (k, s) in usable.iter().enumerate() {
            let earlier = &usable[..k];
            s.for_each_hash(&mut |h| {
                if !earlier.iter().any(|e| e.has(h)) {
                    visit(h);
                }
            });
        }
    }

    fn list_trashed_hashes(&self) -> Vec<String> {
        let usable: Vec<Arc<dyn BlobStore>> =
            self.roots.iter().filter_map(|r| r.usable()).collect();
        let mut out = Vec::new();
        for (k, s) in usable.iter().enumerate() {
            for h in s.list_trashed_hashes() {
                if !usable[..k].iter().any(|e| e.has_trashed(&h)) {
                    out.push(h);
                }
            }
        }
        out
    }

    fn has_trashed(&self, hash_hex: &str) -> bool {
        self.roots
            .iter()
            .any(|r| r.usable().is_some_and(|s| s.has_trashed(hash_hex)))
    }

    fn used_bytes(&self) -> u64 {
        self.roots
            .iter()
            .filter_map(|r| r.usable())
            .map(|s| s.used_bytes())
            .sum()
    }

    fn trash_bytes(&self) -> u64 {
        self.roots
            .iter()
            .filter_map(|r| r.usable())
            .map(|s| s.trash_bytes())
            .sum()
    }

    /// One thread per root: the walks run on different disks.
    fn recompute_usage(&self) {
        let usable: Vec<Arc<dyn BlobStore>> =
            self.roots.iter().filter_map(|r| r.usable()).collect();
        std::thread::scope(|scope| {
            for s in &usable {
                scope.spawn(move || s.recompute_usage());
            }
        });
    }

    fn cleanup_stale_tmp(&self) -> usize {
        let usable: Vec<Arc<dyn BlobStore>> =
            self.roots.iter().filter_map(|r| r.usable()).collect();
        std::thread::scope(|scope| {
            let handles: Vec<_> = usable
                .iter()
                .map(|s| scope.spawn(move || s.cleanup_stale_tmp()))
                .collect();
            handles.into_iter().map(|h| h.join().unwrap_or(0)).sum()
        })
    }

    async fn migrate_legacy_layout(&self, batch: usize, pause: Duration) -> u64 {
        let usable: Vec<Arc<dyn BlobStore>> =
            self.roots.iter().filter_map(|r| r.usable()).collect();
        futures::future::join_all(usable.iter().map(|s| s.migrate_legacy_layout(batch, pause)))
            .await
            .into_iter()
            .sum()
    }

    fn persist_on_clean_shutdown(&self) -> std::io::Result<()> {
        let mut first_err = None;
        for r in &self.roots {
            if let Some(s) = r.usable()
                && let Err(e) = s.persist_on_clean_shutdown()
            {
                tracing::warn!(root = %r.key, error = %e, "storage root: clean-shutdown persist failed");
                first_err.get_or_insert(e);
            }
        }
        first_err.map_or(Ok(()), Err)
    }

    /// Durable only if every root is open and durable: a root opened later
    /// could be a non-durable backend.
    fn store_is_durable(&self) -> bool {
        self.roots
            .iter()
            .all(|r| r.store().is_some_and(|s| s.store_is_durable()))
    }

    fn disk_space(&self) -> Option<DiskSpace> {
        let mut seen_devs: Vec<u64> = Vec::new();
        let mut space = DiskSpace::default();
        for r in &self.roots {
            let state = r.state();
            if !state.usable() {
                continue;
            }
            let dev = r.dev.load(Ordering::Acquire);
            if dev != 0 && seen_devs.contains(&dev) {
                continue;
            }
            seen_devs.push(dev);
            space.total += r.total_bytes.load(Ordering::Relaxed);
            if state == RootState::Healthy && !r.writer_stopped.load(Ordering::Relaxed) {
                space.available += r
                    .free_bytes
                    .load(Ordering::Relaxed)
                    .saturating_sub(self.reserve_bytes);
            }
        }
        Some(space)
    }
}

impl MultiRootStore {
    /// After `hash` was written to another root, drop the copy its former
    /// home (full, so still mutable) holds. `false` when it could not be
    /// dropped (the duplicate is then left to the suspect resolution).
    async fn drop_old_copy(&self, home: usize, hash: &str) -> bool {
        let Some(s) = self.roots[home].usable() else {
            return false;
        };
        let res = if s.has(hash) {
            s.remove(hash).await
        } else if s.has_trashed(hash) {
            s.purge_trashed(hash).await
        } else {
            Ok(())
        };
        match res {
            Ok(()) => true,
            Err(e) => {
                self.on_error(home, &e);
                false
            }
        }
    }

    /// Test hook: force a root's state.
    #[cfg(test)]
    pub(crate) fn force_state(&self, i: usize, state: RootState) {
        self.roots[i].set_state(state, "forced by a test");
    }

    /// Test hook: replace the inventory lookup of [`held_before`].
    #[cfg(test)]
    pub(crate) fn set_held_before(&self, f: fn(&str) -> bool) {
        *self.held_before.lock().unwrap() = f;
    }

    /// Test hook: pretend the root has `free` bytes available.
    #[cfg(test)]
    pub(crate) fn set_free(&self, i: usize, free: u64) {
        self.roots[i].free_bytes.store(free, Ordering::Relaxed);
    }

    /// Test hook: the backend of root `i`.
    #[cfg(test)]
    pub(crate) fn root_store(&self, i: usize) -> Option<Arc<dyn BlobStore>> {
        self.roots[i].store()
    }
}

#[cfg(test)]
mod tests;

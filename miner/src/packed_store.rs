//! Packed blob store: append-only volumes + in-RAM index.
//!
//! The flat store pays one inode plus one directory entry per blob. With
//! reed-solomon striping the shard population is dominated by tiny shards
//! (bench measurements: median ~100 bytes, >90% under 4 KiB), so a node
//! holding tens of millions of shards drowns in filesystem metadata: every
//! store/read/enumeration is a dnode lookup storm, and the page cache fills
//! with metadata instead of data. This backend packs blobs into large
//! append-only volume files so the filesystem only ever sees a few thousand
//! inodes, a write is one sequential append, and a read is one `pread` at a
//! known offset.
//!
//! ## On-disk layout
//!
//! ```text
//! {root}/volumes/vol-000001.dat     append-only, sealed once full
//! {root}/volumes/vol-000002.dat     ... exactly one active (highest id)
//! {root}/index/snapshot.bin         periodic index snapshot (atomic rename)
//! {root}/index/journal.log          fsync'd op journal (delete/restore/purge)
//! ```
//!
//! Volume record (self-describing, 8-byte aligned):
//!
//! ```text
//! magic u32 | name_len u16 | reserved u16 | payload_len u32 | crc32 u32
//! | name bytes | payload bytes | zero padding to 8
//! ```
//!
//! The blob name (hex hash) lives in the record, so **volumes are the sole
//! source of truth**: the index is a rebuildable cache and needs no
//! transactional engine. A missing or stale snapshot only costs a longer
//! startup scan, never data.
//!
//! ## Correctness invariants
//!
//! - **A store is ACKed only after `fdatasync` of its volume.** Writes are
//!   batched naturally: the writer task drains its queue, appends every
//!   pending record, syncs once, then ACKs the whole batch — one sync
//!   amortizes many stores under load without ever ACKing unsynced data.
//! - **Torn tails are truncated before reuse.** On open, each volume is
//!   scanned from its snapshot watermark; the first invalid record marks the
//!   end, the file is truncated to that boundary, and appends resume there.
//! - **Deletes are two-phase and durable.** `delete`/`restore`/
//!   `purge_trashed` append to a small fsync'd journal (a few ops per
//!   second at most) and are replayed over the volume scan on open, so a
//!   crash cannot silently resurrect a deleted blob.
//! - **Reads verify identity.** The index key is a truncated 16-byte name
//!   digest; the full name in the record header is compared to the request
//!   before returning payload, and the payload CRC is checked, so an index
//!   collision or bit rot yields NotFound / InvalidData, never wrong bytes.
//!
//! Trashed and overwritten payloads remain in their volumes as dead bytes
//! until a future compaction pass; per-volume dead-byte counters are already
//! maintained so that pass can pick its targets.

use std::collections::HashMap;
use std::io::{Read, Seek, SeekFrom, Write};
use std::os::unix::fs::FileExt;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex, RwLock};
use std::time::Duration;

use bytes::Bytes;

const REC_MAGIC: u32 = 0x4152_4E31; // "ARN1"
const SNAP_MAGIC: u32 = 0x4152_4E53; // "ARNS"
const JOURNAL_MAGIC: u8 = 0xA7;
const REC_HEADER_LEN: usize = 16; // magic + name_len + reserved + payload_len + crc
const ALIGN: u64 = 8;

const OP_DELETE: u8 = 1;
const OP_RESTORE: u8 = 2;
const OP_PURGE: u8 = 3;

/// Default target size of a volume before rolling to the next (1 GiB).
const DEFAULT_VOLUME_TARGET: u64 = 1 << 30;

/// Snapshot is rewritten after this many index mutations since the last one.
const SNAPSHOT_EVERY_OPS: u64 = 500_000;

fn volume_target_bytes() -> u64 {
    std::env::var("PACKED_VOLUME_TARGET_BYTES")
        .ok()
        .and_then(|v| v.parse().ok())
        .filter(|v: &u64| *v >= 1 << 20)
        .unwrap_or(DEFAULT_VOLUME_TARGET)
}

/// Truncated 16-byte digest of a blob name — the in-RAM index key. The full
/// name is verified against the record header on every read, so a truncated
/// collision can only cost availability of one blob, never wrong data.
fn name_key(name: &str) -> u128 {
    let d = blake3::hash(name.as_bytes());
    u128::from_le_bytes(d.as_bytes()[..16].try_into().unwrap())
}

fn pad_to_align(n: u64) -> u64 {
    n.div_ceil(ALIGN) * ALIGN
}

fn record_len(name_len: usize, payload_len: usize) -> u64 {
    pad_to_align((REC_HEADER_LEN + name_len + payload_len) as u64)
}

/// Location of a live payload inside a volume.
#[derive(Clone, Copy, Debug, PartialEq)]
struct Loc {
    vol: u32,
    /// Offset of the record header inside the volume file.
    off: u64,
    name_len: u16,
    payload_len: u32,
}

#[derive(Clone, Debug)]
struct TrashEntry {
    loc: Loc,
    name: String,
}

#[derive(Debug, Default)]
struct IndexState {
    live: HashMap<u128, Loc>,
    trash: HashMap<u128, TrashEntry>,
    /// Bytes made dead per volume (overwrites + purges) — compaction input.
    dead_bytes: HashMap<u32, u64>,
}

struct StoreReq {
    name: String,
    data: Bytes,
    ack: tokio::sync::oneshot::Sender<std::io::Result<()>>,
}

/// Append-only packed blob store. See module docs.
pub struct PackedStore {
    root: PathBuf,
    volumes_dir: PathBuf,
    index_dir: PathBuf,
    idx: Arc<RwLock<IndexState>>,
    /// Live payload bytes (flat-store-compatible quota semantics).
    used_bytes: AtomicU64,
    trash_bytes: AtomicU64,
    /// Sum of volume file sizes — what the blobs actually cost on disk.
    volume_bytes: AtomicU64,
    /// Index mutations since the last snapshot (snapshot trigger).
    ops_since_snapshot: AtomicU64,
    writer_tx: tokio::sync::mpsc::UnboundedSender<StoreReq>,
    /// Serializes journal appends and snapshot writes.
    journal: Mutex<std::fs::File>,
    /// Read-side FD cache, one handle per volume.
    fds: RwLock<HashMap<u32, Arc<std::fs::File>>>,
    /// Bytes covered by the snapshot, per volume (persisted watermarks).
    watermarks: Mutex<HashMap<u32, u64>>,
    journal_covered: AtomicU64,
}

impl std::fmt::Debug for PackedStore {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("PackedStore")
            .field("root", &self.root)
            .finish()
    }
}

fn volume_path(dir: &Path, vol: u32) -> PathBuf {
    dir.join(format!("vol-{vol:06}.dat"))
}

fn encode_record(name: &str, payload: &[u8]) -> Vec<u8> {
    let name_b = name.as_bytes();
    let total = record_len(name_b.len(), payload.len()) as usize;
    let mut buf = Vec::with_capacity(total);
    buf.extend_from_slice(&REC_MAGIC.to_le_bytes());
    buf.extend_from_slice(&(name_b.len() as u16).to_le_bytes());
    buf.extend_from_slice(&0u16.to_le_bytes());
    buf.extend_from_slice(&(payload.len() as u32).to_le_bytes());
    buf.extend_from_slice(&crc32fast::hash(payload).to_le_bytes());
    buf.extend_from_slice(name_b);
    buf.extend_from_slice(payload);
    buf.resize(total, 0);
    buf
}

/// Parse one record header at `off`. Returns `(name, payload_len, crc)` on a
/// structurally valid record, `None` on anything torn or foreign.
fn read_record_header(f: &std::fs::File, off: u64, vol_len: u64) -> Option<(String, u32, u32)> {
    if off + REC_HEADER_LEN as u64 > vol_len {
        return None;
    }
    let mut hdr = [0u8; REC_HEADER_LEN];
    f.read_exact_at(&mut hdr, off).ok()?;
    if u32::from_le_bytes(hdr[0..4].try_into().unwrap()) != REC_MAGIC {
        return None;
    }
    let name_len = u16::from_le_bytes(hdr[4..6].try_into().unwrap()) as usize;
    let payload_len = u32::from_le_bytes(hdr[8..12].try_into().unwrap());
    let crc = u32::from_le_bytes(hdr[12..16].try_into().unwrap());
    if name_len == 0 || name_len > 4096 {
        return None;
    }
    let total = record_len(name_len, payload_len as usize);
    if off + total > vol_len {
        return None; // torn tail
    }
    let mut name_b = vec![0u8; name_len];
    f.read_exact_at(&mut name_b, off + REC_HEADER_LEN as u64)
        .ok()?;
    let name = String::from_utf8(name_b).ok()?;
    Some((name, payload_len, crc))
}

impl PackedStore {
    /// Open (or create) a packed store rooted at `root`. Loads the snapshot
    /// if present, scans volume tails from their watermarks, replays the op
    /// journal, truncates any torn tail, and spawns the writer task.
    pub fn open(root: impl AsRef<Path>) -> std::io::Result<Arc<Self>> {
        Self::open_with_target(root, volume_target_bytes())
    }

    /// [`open`](Self::open) with an explicit volume-roll threshold (tests).
    pub(crate) fn open_with_target(
        root: impl AsRef<Path>,
        volume_target: u64,
    ) -> std::io::Result<Arc<Self>> {
        let root = root.as_ref().to_path_buf();
        let volumes_dir = root.join("volumes");
        let index_dir = root.join("index");
        std::fs::create_dir_all(&volumes_dir)?;
        std::fs::create_dir_all(&index_dir)?;

        let mut idx = IndexState::default();
        let mut watermarks: HashMap<u32, u64> = HashMap::new();
        let mut journal_covered = 0u64;
        load_snapshot(
            &index_dir.join("snapshot.bin"),
            &mut idx,
            &mut watermarks,
            &mut journal_covered,
        );

        // Enumerate volumes, scan each from its watermark, truncate torn
        // tails. Records override snapshot state (they are the truth).
        let mut vol_ids: Vec<u32> = std::fs::read_dir(&volumes_dir)?
            .flatten()
            .filter_map(|e| {
                let n = e.file_name().into_string().ok()?;
                n.strip_prefix("vol-")?
                    .strip_suffix(".dat")?
                    .parse::<u32>()
                    .ok()
            })
            .collect();
        vol_ids.sort_unstable();

        let mut used = 0u64;
        let mut trashed = 0u64;
        let mut volume_bytes = 0u64;
        for &vol in &vol_ids {
            let path = volume_path(&volumes_dir, vol);
            let f = std::fs::OpenOptions::new()
                .read(true)
                .write(true)
                .open(&path)?;
            let len = f.metadata()?.len();
            let start = watermarks.get(&vol).copied().unwrap_or(0).min(len);
            let mut off = start;
            while let Some((name, payload_len, _crc)) = read_record_header(&f, off, len) {
                let name_len = name.len() as u16;
                let key = name_key(&name);
                let loc = Loc {
                    vol,
                    off,
                    name_len,
                    payload_len,
                };
                if let Some(old) = idx.live.insert(key, loc) {
                    *idx.dead_bytes.entry(old.vol).or_default() += old.payload_len as u64;
                }
                if let Some(t) = idx.trash.remove(&key) {
                    // A re-store after a delete supersedes the trash entry.
                    *idx.dead_bytes.entry(t.loc.vol).or_default() += t.loc.payload_len as u64;
                }
                off += record_len(name_len as usize, payload_len as usize);
            }
            if off < len {
                tracing::warn!(
                    vol,
                    good = off,
                    len,
                    "packed store: truncating torn volume tail"
                );
                f.set_len(off)?;
                f.sync_data()?;
            }
            watermarks.insert(vol, off);
            volume_bytes += off;
        }

        // Replay the op journal past what the snapshot already covers.
        let journal_path = index_dir.join("journal.log");
        let mut journal = std::fs::OpenOptions::new()
            .create(true)
            .read(true)
            .append(true)
            .open(&journal_path)?;
        let jlen = journal.metadata()?.len();
        if journal_covered > jlen {
            journal_covered = 0; // snapshot from a future journal: distrust
        }
        replay_journal(&mut journal, journal_covered, &mut idx);

        for loc in idx.live.values() {
            used += loc.payload_len as u64;
        }
        for t in idx.trash.values() {
            trashed += t.loc.payload_len as u64;
        }

        let (writer_tx, writer_rx) = tokio::sync::mpsc::unbounded_channel();
        let store = Arc::new(Self {
            root,
            volumes_dir,
            index_dir,
            idx: Arc::new(RwLock::new(idx)),
            used_bytes: AtomicU64::new(used),
            trash_bytes: AtomicU64::new(trashed),
            volume_bytes: AtomicU64::new(volume_bytes),
            ops_since_snapshot: AtomicU64::new(0),
            writer_tx,
            journal: Mutex::new(journal),
            fds: RwLock::new(HashMap::new()),
            watermarks: Mutex::new(watermarks),
            journal_covered: AtomicU64::new(jlen),
        });
        store.spawn_writer(
            writer_rx,
            vol_ids.last().copied().unwrap_or(0).max(1),
            volume_target,
        );
        tracing::info!(
            live = store.idx.read().unwrap().live.len(),
            trash = store.idx.read().unwrap().trash.len(),
            volumes = vol_ids.len(),
            volume_bytes,
            "packed store: opened"
        );
        Ok(store)
    }

    /// The writer task: drains the queue, appends every pending record to
    /// the active volume, `fdatasync`s once, then publishes to the index and
    /// ACKs the whole batch. ACK strictly after sync — see module docs.
    fn spawn_writer(
        self: &Arc<Self>,
        mut rx: tokio::sync::mpsc::UnboundedReceiver<StoreReq>,
        start_vol: u32,
        target: u64,
    ) {
        // Weak, not Arc: a strong reference here would cycle (writer thread
        // -> store -> sender -> receiver blocks forever), keeping the store
        // alive and the blocking thread unjoinable at runtime shutdown.
        // With Weak, dropping the last external handle drops the sender,
        // blocking_recv() returns None and the thread exits cleanly.
        let store = Arc::downgrade(self);
        let volumes_dir = self.volumes_dir.clone();
        tokio::task::spawn_blocking(move || {
            let mut vol = start_vol;
            let mut file = match std::fs::OpenOptions::new()
                .create(true)
                .read(true)
                .append(true)
                .open(volume_path(&volumes_dir, vol))
            {
                Ok(f) => f,
                Err(e) => {
                    tracing::error!(error = %e, "packed store: cannot open active volume");
                    return;
                }
            };
            let mut vol_len = file.metadata().map(|m| m.len()).unwrap_or(0);

            while let Some(first) = rx.blocking_recv() {
                let Some(store) = store.upgrade() else { return };
                let mut batch = vec![first];
                while batch.len() < 512 {
                    match rx.try_recv() {
                        Ok(req) => batch.push(req),
                        Err(_) => break,
                    }
                }

                let mut buf = Vec::new();
                let mut placed: Vec<(u128, Loc, usize)> = Vec::with_capacity(batch.len());
                for (i, req) in batch.iter().enumerate() {
                    let rec = encode_record(&req.name, &req.data);
                    placed.push((
                        name_key(&req.name),
                        Loc {
                            vol,
                            off: vol_len + buf.len() as u64,
                            name_len: req.name.len() as u16,
                            payload_len: req.data.len() as u32,
                        },
                        i,
                    ));
                    buf.extend_from_slice(&rec);
                }

                let write_res = file.write_all(&buf).and_then(|_| file.sync_data());
                match write_res {
                    Ok(()) => {
                        vol_len += buf.len() as u64;
                        store
                            .volume_bytes
                            .fetch_add(buf.len() as u64, Ordering::Relaxed);
                        {
                            let mut idx = store.idx.write().unwrap();
                            for (key, loc, _) in &placed {
                                if let Some(old) = idx.live.insert(*key, *loc) {
                                    *idx.dead_bytes.entry(old.vol).or_default() +=
                                        old.payload_len as u64;
                                    store
                                        .used_bytes
                                        .fetch_sub(old.payload_len as u64, Ordering::Relaxed);
                                }
                                if let Some(t) = idx.trash.remove(key) {
                                    *idx.dead_bytes.entry(t.loc.vol).or_default() +=
                                        t.loc.payload_len as u64;
                                    store
                                        .trash_bytes
                                        .fetch_sub(t.loc.payload_len as u64, Ordering::Relaxed);
                                }
                                store
                                    .used_bytes
                                    .fetch_add(loc.payload_len as u64, Ordering::Relaxed);
                            }
                        }
                        store
                            .ops_since_snapshot
                            .fetch_add(placed.len() as u64, Ordering::Relaxed);
                        for req in batch {
                            let _ = req.ack.send(Ok(()));
                        }
                    }
                    Err(e) => {
                        tracing::error!(error = %e, "packed store: batch append failed");
                        // Nothing was published; the file may hold a torn
                        // batch which the next open truncates away.
                        for req in batch {
                            let _ = req
                                .ack
                                .send(Err(std::io::Error::new(e.kind(), e.to_string())));
                        }
                    }
                }

                if vol_len >= target {
                    if let Err(e) = file.sync_all() {
                        tracing::error!(error = %e, vol, "packed store: seal sync failed");
                    }
                    vol += 1;
                    match std::fs::OpenOptions::new()
                        .create(true)
                        .read(true)
                        .append(true)
                        .open(volume_path(&store.volumes_dir, vol))
                    {
                        Ok(f) => {
                            file = f;
                            vol_len = 0;
                            tracing::info!(vol, "packed store: rolled to new volume");
                        }
                        Err(e) => {
                            tracing::error!(error = %e, vol, "packed store: volume roll failed");
                            return;
                        }
                    }
                }

                if store.ops_since_snapshot.load(Ordering::Relaxed) >= SNAPSHOT_EVERY_OPS {
                    store.ops_since_snapshot.store(0, Ordering::Relaxed);
                    if let Err(e) = store.write_snapshot() {
                        tracing::warn!(error = %e, "packed store: snapshot write failed");
                    }
                }
            }
        });
    }

    fn fd(&self, vol: u32) -> std::io::Result<Arc<std::fs::File>> {
        if let Some(f) = self.fds.read().unwrap().get(&vol) {
            return Ok(Arc::clone(f));
        }
        let f = Arc::new(std::fs::File::open(volume_path(&self.volumes_dir, vol))?);
        self.fds.write().unwrap().insert(vol, Arc::clone(&f));
        Ok(f)
    }

    fn read_at(&self, loc: Loc, want_name: &str) -> std::io::Result<Bytes> {
        let f = self.fd(loc.vol)?;
        let name_len = loc.name_len as usize;
        let mut buf = vec![0u8; REC_HEADER_LEN + name_len + loc.payload_len as usize];
        f.read_exact_at(&mut buf, loc.off)?;
        let stored_name = &buf[REC_HEADER_LEN..REC_HEADER_LEN + name_len];
        if stored_name != want_name.as_bytes() {
            // Truncated-key collision: not this blob.
            return Err(std::io::ErrorKind::NotFound.into());
        }
        let crc = u32::from_le_bytes(buf[12..16].try_into().unwrap());
        let payload = buf.split_off(REC_HEADER_LEN + name_len);
        if crc32fast::hash(&payload) != crc {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "packed record CRC mismatch",
            ));
        }
        Ok(Bytes::from(payload))
    }

    /// Append one op to the journal and fsync it. Op rate is a handful per
    /// second at most (deletes/restores), so per-op sync is cheap.
    fn journal_op(&self, op: u8, name: &str) -> std::io::Result<()> {
        let mut rec = Vec::with_capacity(4 + name.len());
        rec.push(JOURNAL_MAGIC);
        rec.push(op);
        rec.extend_from_slice(&(name.len() as u16).to_le_bytes());
        rec.extend_from_slice(name.as_bytes());
        rec.extend_from_slice(&crc32fast::hash(name.as_bytes()).to_le_bytes());
        let mut j = self.journal.lock().unwrap();
        j.write_all(&rec)?;
        j.sync_data()?;
        Ok(())
    }

    /// Serialize the whole index to `snapshot.bin` (atomic tmp+rename) and
    /// record the journal length it covers. Pure sequential write.
    fn write_snapshot(&self) -> std::io::Result<()> {
        let tmp = self.index_dir.join("snapshot.tmp");
        let final_path = self.index_dir.join("snapshot.bin");
        let jlen = self
            .journal
            .lock()
            .unwrap()
            .metadata()
            .map(|m| m.len())
            .unwrap_or(0);
        let watermarks: Vec<(u32, u64)> = {
            let wm = self.watermarks.lock().unwrap();
            let mut v: Vec<_> = wm.iter().map(|(k, l)| (*k, *l)).collect();
            // The active volume keeps growing past the recorded watermark;
            // refresh from disk so the snapshot skips as much as possible.
            for (vol, len) in v.iter_mut() {
                if let Ok(m) = std::fs::metadata(volume_path(&self.volumes_dir, *vol)) {
                    *len = m.len();
                }
            }
            v
        };
        {
            let idx = self.idx.read().unwrap();
            let mut w = std::io::BufWriter::new(std::fs::File::create(&tmp)?);
            w.write_all(&SNAP_MAGIC.to_le_bytes())?;
            w.write_all(&1u32.to_le_bytes())?; // version
            w.write_all(&jlen.to_le_bytes())?;
            w.write_all(&(watermarks.len() as u32).to_le_bytes())?;
            for (vol, len) in &watermarks {
                w.write_all(&vol.to_le_bytes())?;
                w.write_all(&len.to_le_bytes())?;
            }
            w.write_all(&(idx.live.len() as u64).to_le_bytes())?;
            for (key, loc) in &idx.live {
                w.write_all(&key.to_le_bytes())?;
                w.write_all(&loc.vol.to_le_bytes())?;
                w.write_all(&loc.off.to_le_bytes())?;
                w.write_all(&loc.name_len.to_le_bytes())?;
                w.write_all(&loc.payload_len.to_le_bytes())?;
            }
            w.write_all(&(idx.trash.len() as u64).to_le_bytes())?;
            for t in idx.trash.values() {
                let name_b = t.name.as_bytes();
                w.write_all(&(name_b.len() as u16).to_le_bytes())?;
                w.write_all(name_b)?;
                w.write_all(&t.loc.vol.to_le_bytes())?;
                w.write_all(&t.loc.off.to_le_bytes())?;
                w.write_all(&t.loc.name_len.to_le_bytes())?;
                w.write_all(&t.loc.payload_len.to_le_bytes())?;
            }
            let f = w.into_inner().map_err(|e| e.into_error())?;
            f.sync_data()?;
        }
        std::fs::rename(&tmp, &final_path)?;
        {
            let mut wm = self.watermarks.lock().unwrap();
            for (vol, len) in watermarks {
                wm.insert(vol, len);
            }
        }
        tracing::info!("packed store: index snapshot written");
        Ok(())
    }
}

fn load_snapshot(
    path: &Path,
    idx: &mut IndexState,
    watermarks: &mut HashMap<u32, u64>,
    journal_covered: &mut u64,
) {
    let Ok(mut f) = std::fs::File::open(path) else {
        return;
    };
    let mut parse = || -> std::io::Result<()> {
        let mut b4 = [0u8; 4];
        let mut b8 = [0u8; 8];
        let mut b2 = [0u8; 2];
        let mut b16 = [0u8; 16];
        f.read_exact(&mut b4)?;
        if u32::from_le_bytes(b4) != SNAP_MAGIC {
            return Err(std::io::ErrorKind::InvalidData.into());
        }
        f.read_exact(&mut b4)?; // version
        f.read_exact(&mut b8)?;
        *journal_covered = u64::from_le_bytes(b8);
        f.read_exact(&mut b4)?;
        let n_wm = u32::from_le_bytes(b4);
        for _ in 0..n_wm {
            f.read_exact(&mut b4)?;
            let vol = u32::from_le_bytes(b4);
            f.read_exact(&mut b8)?;
            watermarks.insert(vol, u64::from_le_bytes(b8));
        }
        f.read_exact(&mut b8)?;
        let n_live = u64::from_le_bytes(b8);
        for _ in 0..n_live {
            f.read_exact(&mut b16)?;
            let key = u128::from_le_bytes(b16);
            f.read_exact(&mut b4)?;
            let vol = u32::from_le_bytes(b4);
            f.read_exact(&mut b8)?;
            let off = u64::from_le_bytes(b8);
            f.read_exact(&mut b2)?;
            let name_len = u16::from_le_bytes(b2);
            f.read_exact(&mut b4)?;
            let payload_len = u32::from_le_bytes(b4);
            idx.live.insert(
                key,
                Loc {
                    vol,
                    off,
                    name_len,
                    payload_len,
                },
            );
        }
        f.read_exact(&mut b8)?;
        let n_trash = u64::from_le_bytes(b8);
        for _ in 0..n_trash {
            f.read_exact(&mut b2)?;
            let nl = u16::from_le_bytes(b2) as usize;
            let mut name_b = vec![0u8; nl];
            f.read_exact(&mut name_b)?;
            let name = String::from_utf8(name_b)
                .map_err(|_| std::io::Error::from(std::io::ErrorKind::InvalidData))?;
            f.read_exact(&mut b4)?;
            let vol = u32::from_le_bytes(b4);
            f.read_exact(&mut b8)?;
            let off = u64::from_le_bytes(b8);
            f.read_exact(&mut b2)?;
            let name_len = u16::from_le_bytes(b2);
            f.read_exact(&mut b4)?;
            let payload_len = u32::from_le_bytes(b4);
            let key = name_key(&name);
            idx.trash.insert(
                key,
                TrashEntry {
                    loc: Loc {
                        vol,
                        off,
                        name_len,
                        payload_len,
                    },
                    name,
                },
            );
        }
        Ok(())
    };
    if let Err(e) = parse() {
        tracing::warn!(error = %e, "packed store: snapshot unreadable, falling back to full scan");
        idx.live.clear();
        idx.trash.clear();
        watermarks.clear();
        *journal_covered = 0;
    }
}

fn replay_journal(journal: &mut std::fs::File, from: u64, idx: &mut IndexState) {
    let len = journal.metadata().map(|m| m.len()).unwrap_or(0);
    if from >= len {
        return;
    }
    if journal.seek(SeekFrom::Start(from)).is_err() {
        return;
    }
    let mut data = Vec::new();
    if journal.read_to_end(&mut data).is_err() {
        return;
    }
    let mut off = 0usize;
    while off + 4 <= data.len() {
        if data[off] != JOURNAL_MAGIC {
            tracing::warn!(
                off,
                "packed store: journal corrupt past this point, stopping replay"
            );
            break;
        }
        let op = data[off + 1];
        let nl = u16::from_le_bytes(data[off + 2..off + 4].try_into().unwrap()) as usize;
        let end = off + 4 + nl + 4;
        if end > data.len() {
            break; // torn tail of the journal — ignore
        }
        let name_b = &data[off + 4..off + 4 + nl];
        let crc = u32::from_le_bytes(data[end - 4..end].try_into().unwrap());
        if crc32fast::hash(name_b) != crc {
            break;
        }
        if let Ok(name) = std::str::from_utf8(name_b) {
            let key = name_key(name);
            match op {
                OP_DELETE => {
                    if let Some(loc) = idx.live.remove(&key) {
                        idx.trash.insert(
                            key,
                            TrashEntry {
                                loc,
                                name: name.to_string(),
                            },
                        );
                    }
                }
                OP_RESTORE => {
                    if let Some(t) = idx.trash.remove(&key) {
                        idx.live.insert(key, t.loc);
                    }
                }
                OP_PURGE => {
                    if let Some(t) = idx.trash.remove(&key) {
                        *idx.dead_bytes.entry(t.loc.vol).or_default() += t.loc.payload_len as u64;
                    }
                }
                _ => {}
            }
        }
        off = end;
    }
}

#[async_trait::async_trait]
impl crate::store::BlobStore for PackedStore {
    async fn store(&self, hash_hex: &str, data: &[u8]) -> std::io::Result<()> {
        let (tx, rx) = tokio::sync::oneshot::channel();
        self.writer_tx
            .send(StoreReq {
                name: hash_hex.to_string(),
                data: Bytes::copy_from_slice(data),
                ack: tx,
            })
            .map_err(|_| std::io::Error::from(std::io::ErrorKind::BrokenPipe))?;
        rx.await
            .map_err(|_| std::io::Error::from(std::io::ErrorKind::BrokenPipe))?
    }

    async fn read(&self, hash_hex: &str) -> std::io::Result<Bytes> {
        let loc = {
            let idx = self.idx.read().unwrap();
            idx.live
                .get(&name_key(hash_hex))
                .copied()
                .ok_or(std::io::ErrorKind::NotFound)?
        };
        // Payloads are small (median ~100B, p99 < 1 MiB): a blocking pread
        // here is cheaper than a spawn_blocking round-trip.
        self.read_at(loc, hash_hex)
    }

    fn has(&self, hash_hex: &str) -> bool {
        self.idx
            .read()
            .unwrap()
            .live
            .contains_key(&name_key(hash_hex))
    }

    async fn delete(&self, hash_hex: &str) -> std::io::Result<()> {
        let key = name_key(hash_hex);
        if !self.idx.read().unwrap().live.contains_key(&key) {
            return Ok(());
        }
        self.journal_op(OP_DELETE, hash_hex)?;
        let mut idx = self.idx.write().unwrap();
        if let Some(loc) = idx.live.remove(&key) {
            self.used_bytes
                .fetch_sub(loc.payload_len as u64, Ordering::Relaxed);
            self.trash_bytes
                .fetch_add(loc.payload_len as u64, Ordering::Relaxed);
            idx.trash.insert(
                key,
                TrashEntry {
                    loc,
                    name: hash_hex.to_string(),
                },
            );
        }
        self.ops_since_snapshot.fetch_add(1, Ordering::Relaxed);
        Ok(())
    }

    async fn remove(&self, hash_hex: &str) -> std::io::Result<()> {
        // Permanent delete = delete + purge, journaled as two ops.
        self.delete(hash_hex).await?;
        self.purge_trashed(hash_hex).await
    }

    async fn restore(&self, hash_hex: &str) -> std::io::Result<bool> {
        let key = name_key(hash_hex);
        if !self.idx.read().unwrap().trash.contains_key(&key) {
            return Ok(false);
        }
        self.journal_op(OP_RESTORE, hash_hex)?;
        let mut idx = self.idx.write().unwrap();
        if let Some(t) = idx.trash.remove(&key) {
            self.trash_bytes
                .fetch_sub(t.loc.payload_len as u64, Ordering::Relaxed);
            self.used_bytes
                .fetch_add(t.loc.payload_len as u64, Ordering::Relaxed);
            idx.live.insert(key, t.loc);
            self.ops_since_snapshot.fetch_add(1, Ordering::Relaxed);
            return Ok(true);
        }
        Ok(false)
    }

    async fn purge_trashed(&self, hash_hex: &str) -> std::io::Result<()> {
        let key = name_key(hash_hex);
        if !self.idx.read().unwrap().trash.contains_key(&key) {
            return Ok(());
        }
        self.journal_op(OP_PURGE, hash_hex)?;
        let mut idx = self.idx.write().unwrap();
        if let Some(t) = idx.trash.remove(&key) {
            self.trash_bytes
                .fetch_sub(t.loc.payload_len as u64, Ordering::Relaxed);
            *idx.dead_bytes.entry(t.loc.vol).or_default() += t.loc.payload_len as u64;
            self.ops_since_snapshot.fetch_add(1, Ordering::Relaxed);
        }
        Ok(())
    }

    /// Full enumeration walks volume record headers on disk (payloads are
    /// seeked over). Rebuild-only path — the SQLite inventory serves all
    /// steady-state listings.
    fn list_hashes(&self) -> Vec<String> {
        let mut out = Vec::new();
        let trash_keys: std::collections::HashSet<u128> = {
            let idx = self.idx.read().unwrap();
            out.reserve(idx.live.len());
            idx.trash.keys().copied().collect()
        };
        let mut seen: std::collections::HashSet<u128> = std::collections::HashSet::new();
        let Ok(entries) = std::fs::read_dir(&self.volumes_dir) else {
            return out;
        };
        let mut vols: Vec<u32> = entries
            .flatten()
            .filter_map(|e| {
                let n = e.file_name().into_string().ok()?;
                n.strip_prefix("vol-")?.strip_suffix(".dat")?.parse().ok()
            })
            .collect();
        vols.sort_unstable();
        for vol in vols {
            let Ok(f) = std::fs::File::open(volume_path(&self.volumes_dir, vol)) else {
                continue;
            };
            let len = f.metadata().map(|m| m.len()).unwrap_or(0);
            let mut off = 0u64;
            while let Some((name, payload_len, _)) = read_record_header(&f, off, len) {
                let key = name_key(&name);
                if seen.insert(key) && !trash_keys.contains(&key) {
                    // Later records supersede earlier ones for the same key,
                    // but the payload location is irrelevant for a listing —
                    // only liveness matters, and live-ness is keyed.
                    if self.idx.read().unwrap().live.contains_key(&key) {
                        out.push(name.clone());
                    }
                }
                off += record_len(name.len(), payload_len as usize);
            }
        }
        out
    }

    fn list_trashed_hashes(&self) -> Vec<String> {
        self.idx
            .read()
            .unwrap()
            .trash
            .values()
            .map(|t| t.name.clone())
            .collect()
    }

    fn has_trashed(&self, hash_hex: &str) -> bool {
        self.idx
            .read()
            .unwrap()
            .trash
            .contains_key(&name_key(hash_hex))
    }

    fn used_bytes(&self) -> u64 {
        self.used_bytes.load(Ordering::Relaxed)
    }

    fn trash_bytes(&self) -> u64 {
        self.trash_bytes.load(Ordering::Relaxed)
    }

    fn recompute_usage(&self) {
        let (mut used, mut trashed) = (0u64, 0u64);
        {
            let idx = self.idx.read().unwrap();
            for loc in idx.live.values() {
                used += loc.payload_len as u64;
            }
            for t in idx.trash.values() {
                trashed += t.loc.payload_len as u64;
            }
        }
        let mut vol_bytes = 0u64;
        if let Ok(entries) = std::fs::read_dir(&self.volumes_dir) {
            for e in entries.flatten() {
                if let Ok(m) = e.metadata() {
                    vol_bytes += m.len();
                }
            }
        }
        self.used_bytes.store(used, Ordering::Relaxed);
        self.trash_bytes.store(trashed, Ordering::Relaxed);
        self.volume_bytes.store(vol_bytes, Ordering::Relaxed);
        tracing::info!(used, trashed, vol_bytes, "packed store: usage recomputed");
    }

    fn cleanup_stale_tmp(&self) -> usize {
        // The only transient artifact is the snapshot tmp file.
        let tmp = self.index_dir.join("snapshot.tmp");
        if tmp.exists() && std::fs::remove_file(&tmp).is_ok() {
            1
        } else {
            0
        }
    }

    async fn migrate_legacy_layout(&self, _batch: usize, _pause: Duration) -> u64 {
        0 // no legacy layout of its own; flat->packed migration is separate
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::store::BlobStore;

    const H1: &str = "aa11bb22cc33dd44ee55ff6600112233445566778899aabbccddeeff00112233";
    const H2: &str = "bb22cc33dd44ee55ff6600112233445566778899aabbccddeeff001122334455";

    fn open_small(dir: &Path) -> Arc<PackedStore> {
        PackedStore::open_with_target(dir, 1 << 20).unwrap()
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn roundtrip_store_read_delete_restore_purge() {
        let dir = tempfile::tempdir().unwrap();
        let store = open_small(dir.path());

        store.store(H1, b"hello").await.unwrap();
        store.store(H2, b"world!").await.unwrap();
        assert!(store.has(H1));
        assert_eq!(store.read(H1).await.unwrap().as_ref(), b"hello");
        assert_eq!(store.read(H2).await.unwrap().as_ref(), b"world!");
        assert_eq!(store.used_bytes(), 11);

        store.delete(H1).await.unwrap();
        assert!(!store.has(H1));
        assert!(store.has_trashed(H1));
        assert!(store.read(H1).await.is_err());
        assert_eq!(store.used_bytes(), 6);
        assert_eq!(store.trash_bytes(), 5);
        assert_eq!(store.list_trashed_hashes(), vec![H1.to_string()]);

        assert!(store.restore(H1).await.unwrap());
        assert_eq!(store.read(H1).await.unwrap().as_ref(), b"hello");
        assert_eq!(store.trash_bytes(), 0);

        store.delete(H1).await.unwrap();
        store.purge_trashed(H1).await.unwrap();
        assert!(!store.has_trashed(H1));
        assert!(!store.restore(H1).await.unwrap());
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn overwrite_supersedes_and_lists_once() {
        let dir = tempfile::tempdir().unwrap();
        let store = open_small(dir.path());
        store.store(H1, b"v1").await.unwrap();
        store.store(H1, b"v2-longer").await.unwrap();
        assert_eq!(store.read(H1).await.unwrap().as_ref(), b"v2-longer");
        assert_eq!(store.used_bytes(), 9);
        let listed = store.list_hashes();
        assert_eq!(listed, vec![H1.to_string()]);
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn reopen_rebuilds_index_from_volumes() {
        let dir = tempfile::tempdir().unwrap();
        {
            let store = open_small(dir.path());
            store.store(H1, b"persist-me").await.unwrap();
            store.store(H2, b"me-too").await.unwrap();
            store.delete(H2).await.unwrap();
        } // dropped: writer exits, no snapshot written

        let store = open_small(dir.path());
        assert_eq!(store.read(H1).await.unwrap().as_ref(), b"persist-me");
        // The journaled delete must survive the reopen (no resurrection).
        assert!(!store.has(H2));
        assert!(store.has_trashed(H2));
        assert!(store.restore(H2).await.unwrap());
        assert_eq!(store.read(H2).await.unwrap().as_ref(), b"me-too");
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn torn_tail_is_truncated_on_open() {
        let dir = tempfile::tempdir().unwrap();
        {
            let store = open_small(dir.path());
            store.store(H1, b"good-data").await.unwrap();
        }
        // Simulate a crash mid-append: garbage past the last good record.
        let vol = dir.path().join("volumes/vol-000001.dat");
        let good_len = std::fs::metadata(&vol).unwrap().len();
        {
            use std::io::Write as _;
            let mut f = std::fs::OpenOptions::new().append(true).open(&vol).unwrap();
            f.write_all(&REC_MAGIC.to_le_bytes()).unwrap();
            f.write_all(b"torn").unwrap(); // header cut short
        }
        let store = open_small(dir.path());
        assert_eq!(std::fs::metadata(&vol).unwrap().len(), good_len);
        assert_eq!(store.read(H1).await.unwrap().as_ref(), b"good-data");

        // Appends continue cleanly after the truncation.
        store.store(H2, b"after-crash").await.unwrap();
        assert_eq!(store.read(H2).await.unwrap().as_ref(), b"after-crash");
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn snapshot_plus_tail_scan_plus_journal() {
        let dir = tempfile::tempdir().unwrap();
        {
            let store = open_small(dir.path());
            store.store(H1, b"before-snap").await.unwrap();
            store.write_snapshot().unwrap();
            store.store(H2, b"after-snap").await.unwrap();
            store.delete(H1).await.unwrap();
        }
        let store = open_small(dir.path());
        assert!(store.has_trashed(H1), "journaled delete after snapshot");
        assert_eq!(store.read(H2).await.unwrap().as_ref(), b"after-snap");
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn volumes_roll_at_target() {
        let dir = tempfile::tempdir().unwrap();
        let store = open_small(dir.path()); // 1 MiB target
        let payload = vec![7u8; 300 * 1024];
        for i in 0..6 {
            store
                .store(&format!("{:064x}", i + 1), &payload)
                .await
                .unwrap();
        }
        let vols = std::fs::read_dir(dir.path().join("volumes"))
            .unwrap()
            .count();
        assert!(vols >= 2, "expected a volume roll, got {vols} volume(s)");
        for i in 0..6 {
            let name = format!("{:064x}", i + 1);
            assert_eq!(store.read(&name).await.unwrap().len(), payload.len());
        }
        // Reopen re-scans all volumes correctly.
        drop(store);
        let store = open_small(dir.path());
        for i in 0..6 {
            let name = format!("{:064x}", i + 1);
            assert!(store.has(&name));
        }
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn corrupted_payload_is_refused() {
        let dir = tempfile::tempdir().unwrap();
        let store = open_small(dir.path());
        store.store(H1, b"bitrot-target").await.unwrap();
        // Flip a payload byte on disk.
        let vol = dir.path().join("volumes/vol-000001.dat");
        let data = std::fs::read(&vol).unwrap();
        let pos = data.len() - 4; // inside payload (before padding at most 7)
        let mut data = data;
        data[pos] ^= 0xFF;
        std::fs::write(&vol, &data).unwrap();
        drop(store);
        let store = open_small(dir.path());
        let err = store.read(H1).await.unwrap_err();
        assert_eq!(err.kind(), std::io::ErrorKind::InvalidData);
    }
}

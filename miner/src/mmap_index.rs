//! Disk-backed live index for the packed store: a fixed-slot open-addressing
//! table in an mmap'd file.
//!
//! Why not a HashMap: at tens of millions of blobs an in-RAM index is
//! multiple GB of *anonymous* memory — unevictable, swapped under pressure,
//! and lost on every restart. Backed by a file, the same table is page
//! cache: the kernel keeps the hot slots resident and reclaims the rest
//! when the node needs RAM for real work. Target cost: ~40 bytes of FILE
//! pages per blob, ~0 anonymous bytes.
//!
//! ## Layout
//!
//! ```text
//! header (64 B): magic u32 | version u32 | slot_count u64 | reserved
//! slot   (40 B): key u128 | off u64 | vol u32 | payload_len u32
//!              | name_len u16 | flags u16 | crc32 u32
//! ```
//!
//! - `slot_count` is a power of two; probe start is `key & (slots-1)`,
//!   linear probing (the keys are truncated blake3 digests — uniform).
//! - `flags`: 0 = empty, 1 = live, 2 = tombstone.
//! - `crc32` covers the slot's first 36 bytes. Slots are rewritten in
//!   place, and the kernel flushes pages on its own schedule, so a crash
//!   can tear a slot mid-writeback. The CRC turns silent corruption into
//!   detection at open.
//!
//! ## Crash contract (volumes stay the sole source of truth)
//!
//! The table is a rebuildable cache, exactly like the snapshot it
//! replaces. On open the whole file is swept once (sequential read):
//! live/tombstone counts and byte totals are recomputed, and every slot's
//! CRC is verified. Any bad slot means the index cannot be trusted →
//! caller wipes it and rebuilds from a full volume scan. No fsync ordering
//! is required during normal operation; `flush` (msync) is only called at
//! snapshot points to bound the post-crash rebuild window.
//!
//! Not thread-safe: the caller (packed store) already serializes access
//! through its index lock.

use std::io::Write;
use std::path::{Path, PathBuf};

const MAGIC: u32 = 0x414C_4958; // "ALIX"
const VERSION: u32 = 1;
const HEADER_LEN: usize = 64;
const SLOT_LEN: usize = 40;
const CRC_COVER: usize = 36;

const FLAG_EMPTY: u16 = 0;
const FLAG_LIVE: u16 = 1;
const FLAG_TOMB: u16 = 2;

/// Table is grown when (live + tombstones) exceeds this share of slots.
const MAX_LOAD_NUM: u64 = 3;
const MAX_LOAD_DEN: u64 = 4;

/// Initial capacity: ~1M slots = 40 MB file. Doubling reaches 128M slots
/// (enough for ~96M blobs) in 7 rehashes, each a sequential rewrite.
const INITIAL_SLOTS: u64 = 1 << 20;

/// Location of a live payload inside a volume (shared with the packed
/// store, which re-exports it).
#[derive(Clone, Copy, Debug, PartialEq)]
pub(crate) struct Loc {
    pub vol: u32,
    /// Offset of the record header inside the volume file.
    pub off: u64,
    pub name_len: u16,
    pub payload_len: u32,
}

/// Result of the open-time sweep.
pub(crate) struct SweepStats {
    pub live: u64,
    pub live_payload_bytes: u64,
    /// A slot failed its CRC — the whole table must be rebuilt.
    pub torn: bool,
}

pub(crate) struct MmapLiveIndex {
    map: memmap2::MmapMut,
    path: PathBuf,
    slots: u64,
    live: u64,
    tombs: u64,
}

impl std::fmt::Debug for MmapLiveIndex {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("MmapLiveIndex")
            .field("slots", &self.slots)
            .field("live", &self.live)
            .finish()
    }
}

fn slot_bytes(slots: u64) -> u64 {
    HEADER_LEN as u64 + slots * SLOT_LEN as u64
}

fn encode_slot(buf: &mut [u8], key: u128, loc: Loc, flags: u16) {
    buf[0..16].copy_from_slice(&key.to_le_bytes());
    buf[16..24].copy_from_slice(&loc.off.to_le_bytes());
    buf[24..28].copy_from_slice(&loc.vol.to_le_bytes());
    buf[28..32].copy_from_slice(&loc.payload_len.to_le_bytes());
    buf[32..34].copy_from_slice(&loc.name_len.to_le_bytes());
    buf[34..36].copy_from_slice(&flags.to_le_bytes());
    let crc = crc32fast::hash(&buf[..CRC_COVER]);
    buf[36..40].copy_from_slice(&crc.to_le_bytes());
}

fn decode_slot(buf: &[u8]) -> Option<(u128, Loc, u16)> {
    let crc = u32::from_le_bytes(buf[36..40].try_into().unwrap());
    if crc32fast::hash(&buf[..CRC_COVER]) != crc {
        return None;
    }
    let key = u128::from_le_bytes(buf[0..16].try_into().unwrap());
    let loc = Loc {
        off: u64::from_le_bytes(buf[16..24].try_into().unwrap()),
        vol: u32::from_le_bytes(buf[24..28].try_into().unwrap()),
        payload_len: u32::from_le_bytes(buf[28..32].try_into().unwrap()),
        name_len: u16::from_le_bytes(buf[32..34].try_into().unwrap()),
    };
    let flags = u16::from_le_bytes(buf[34..36].try_into().unwrap());
    Some((key, loc, flags))
}

/// An all-zero slot is the pristine (never written) state: flag bytes are
/// EMPTY and the stored CRC is zero, which is not the CRC of 36 zero bytes
/// — special-case it instead of pre-initializing 40 MB+ of CRCs.
fn is_pristine(buf: &[u8]) -> bool {
    buf.iter().all(|&b| b == 0)
}

impl MmapLiveIndex {
    /// Open (or create) the table and sweep it: verifies every slot CRC and
    /// recomputes counts. `stats.torn` means the caller must wipe and
    /// rebuild from the volumes.
    pub fn open(path: &Path) -> std::io::Result<(Self, SweepStats)> {
        if !path.exists() {
            let mut fresh = Self::create(path, INITIAL_SLOTS)?;
            fresh.flush()?; // stamp: an empty table is complete
            return Ok((
                fresh,
                SweepStats {
                    live: 0,
                    live_payload_bytes: 0,
                    torn: false,
                },
            ));
        }
        let file = std::fs::OpenOptions::new()
            .read(true)
            .write(true)
            .open(path)?;
        let len = file.metadata()?.len();
        let map = unsafe { memmap2::MmapMut::map_mut(&file)? };
        let hdr_ok = len >= HEADER_LEN as u64
            && u32::from_le_bytes(map[0..4].try_into().unwrap()) == MAGIC
            && u32::from_le_bytes(map[4..8].try_into().unwrap()) == VERSION;
        let slots = if hdr_ok {
            u64::from_le_bytes(map[8..16].try_into().unwrap())
        } else {
            0
        };
        if !hdr_ok || !slots.is_power_of_two() || slot_bytes(slots) != len {
            tracing::warn!(path = %path.display(), "mmap index: bad header, rebuilding");
            drop(map);
            return Self::create_fresh(path).map(|s| {
                (
                    s,
                    SweepStats {
                        live: 0,
                        live_payload_bytes: 0,
                        torn: true,
                    },
                )
            });
        }
        let mut idx = Self {
            map,
            path: path.to_path_buf(),
            slots,
            live: 0,
            tombs: 0,
        };
        let mut stats = SweepStats {
            live: 0,
            live_payload_bytes: 0,
            torn: false,
        };
        for i in 0..slots {
            let buf = idx.slot(i);
            if is_pristine(buf) {
                continue;
            }
            match decode_slot(buf) {
                Some((_, loc, FLAG_LIVE)) => {
                    stats.live += 1;
                    stats.live_payload_bytes += loc.payload_len as u64;
                }
                Some((_, _, FLAG_TOMB)) => idx.tombs += 1,
                Some((_, _, _)) => {}
                None => {
                    stats.torn = true;
                    break;
                }
            }
        }
        if stats.torn {
            tracing::warn!(path = %path.display(), "mmap index: torn slot detected, rebuilding");
            let fresh = Self::create_fresh(path)?;
            return Ok((
                fresh,
                SweepStats {
                    live: 0,
                    live_payload_bytes: 0,
                    torn: true,
                },
            ));
        }
        idx.live = stats.live;
        Ok((idx, stats))
    }

    fn create_fresh(path: &Path) -> std::io::Result<Self> {
        std::fs::remove_file(path).ok();
        Self::create(path, INITIAL_SLOTS)
    }

    /// Create a fresh table file (tmp + atomic rename). The header is
    /// written with `version = 0` — "under construction" — so a crash
    /// between this rename and [`seal`](Self::seal) is detected at the next
    /// open as an untrusted table (rebuild), never as a silently
    /// half-filled index.
    fn create(path: &Path, slots: u64) -> std::io::Result<Self> {
        let tmp = path.with_extension("tmp");
        {
            let mut f = std::fs::File::create(&tmp)?;
            let mut hdr = [0u8; HEADER_LEN];
            hdr[0..4].copy_from_slice(&MAGIC.to_le_bytes());
            hdr[4..8].copy_from_slice(&0u32.to_le_bytes()); // building
            hdr[8..16].copy_from_slice(&slots.to_le_bytes());
            f.write_all(&hdr)?;
            f.set_len(slot_bytes(slots))?; // sparse zero slots = pristine
            f.sync_all()?;
        }
        std::fs::rename(&tmp, path)?;
        let file = std::fs::OpenOptions::new()
            .read(true)
            .write(true)
            .open(path)?;
        let map = unsafe { memmap2::MmapMut::map_mut(&file)? };
        Ok(Self {
            map,
            path: path.to_path_buf(),
            slots,
            live: 0,
            tombs: 0,
        })
    }

    fn slot(&self, i: u64) -> &[u8] {
        let o = HEADER_LEN + i as usize * SLOT_LEN;
        &self.map[o..o + SLOT_LEN]
    }

    fn slot_mut(&mut self, i: u64) -> &mut [u8] {
        let o = HEADER_LEN + i as usize * SLOT_LEN;
        &mut self.map[o..o + SLOT_LEN]
    }

    /// Decode a slot, treating pristine (all-zero) as empty.
    fn read_slot(&self, i: u64) -> (u16, Option<(u128, Loc)>) {
        let buf = self.slot(i);
        if is_pristine(buf) {
            return (FLAG_EMPTY, None);
        }
        match decode_slot(buf) {
            Some((k, l, f)) if f == FLAG_LIVE || f == FLAG_TOMB => (f, Some((k, l))),
            _ => (FLAG_EMPTY, None), // torn at runtime: probe treats as empty
        }
    }

    pub fn len(&self) -> u64 {
        self.live
    }

    pub fn get(&self, key: u128) -> Option<Loc> {
        let mask = self.slots - 1;
        let mut i = (key as u64) & mask;
        loop {
            match self.read_slot(i) {
                (FLAG_EMPTY, _) => return None,
                (FLAG_LIVE, Some((k, l))) if k == key => return Some(l),
                _ => i = (i + 1) & mask,
            }
        }
    }

    pub fn contains_key(&self, key: u128) -> bool {
        self.get(key).is_some()
    }

    /// Insert or replace. Returns the previous location on replace.
    pub fn insert(&mut self, key: u128, loc: Loc) -> std::io::Result<Option<Loc>> {
        if (self.live + self.tombs + 1) * MAX_LOAD_DEN > self.slots * MAX_LOAD_NUM {
            self.grow()?;
        }
        let mask = self.slots - 1;
        let mut i = (key as u64) & mask;
        let mut reuse: Option<u64> = None;
        loop {
            match self.read_slot(i) {
                (FLAG_LIVE, Some((k, old))) if k == key => {
                    encode_slot(self.slot_mut(i), key, loc, FLAG_LIVE);
                    return Ok(Some(old));
                }
                (FLAG_TOMB, _) => {
                    // Reusable, but keep probing: a live entry for this key
                    // may sit later in the chain and must be replaced, not
                    // duplicated.
                    if reuse.is_none() {
                        reuse = Some(i);
                    }
                    i = (i + 1) & mask;
                }
                (FLAG_EMPTY, _) => {
                    let target = reuse.unwrap_or(i);
                    if reuse.is_some() {
                        self.tombs -= 1;
                    }
                    encode_slot(self.slot_mut(target), key, loc, FLAG_LIVE);
                    self.live += 1;
                    return Ok(None);
                }
                _ => i = (i + 1) & mask,
            }
        }
    }

    /// Remove a live entry (tombstoned). Returns its location.
    pub fn remove(&mut self, key: u128) -> Option<Loc> {
        let mask = self.slots - 1;
        let mut i = (key as u64) & mask;
        loop {
            match self.read_slot(i) {
                (FLAG_EMPTY, _) => return None,
                (FLAG_LIVE, Some((k, l))) if k == key => {
                    encode_slot(self.slot_mut(i), key, l, FLAG_TOMB);
                    self.live -= 1;
                    self.tombs += 1;
                    return Some(l);
                }
                _ => i = (i + 1) & mask,
            }
        }
    }

    /// Visit every live entry (sequential file scan).
    pub fn for_each(&self, mut f: impl FnMut(u128, Loc)) {
        for i in 0..self.slots {
            if let (FLAG_LIVE, Some((k, l))) = self.read_slot(i) {
                f(k, l);
            }
        }
    }

    /// Discard everything and start from an empty table (rebuild path).
    pub fn wipe(&mut self) -> std::io::Result<()> {
        let mut fresh = Self::create_fresh(&self.path)?;
        fresh.flush()?;
        *self = fresh;
        Ok(())
    }

    /// Stamp the header as complete and msync. A table whose header was
    /// never stamped (`version = 0`, i.e. created but not yet flushed) is
    /// rebuilt at open — this is what makes a crash mid-rebuild or
    /// mid-grow safe. Called at snapshot cadence, never per write.
    pub fn flush(&mut self) -> std::io::Result<()> {
        self.map[4..8].copy_from_slice(&VERSION.to_le_bytes());
        self.map.flush()
    }

    /// Double the table (drops tombstones). Sequential rewrite into a tmp
    /// file, atomic rename, remap.
    fn grow(&mut self) -> std::io::Result<()> {
        let new_slots = self.slots * 2;
        tracing::info!(
            live = self.live,
            new_slots,
            file_mb = slot_bytes(new_slots) >> 20,
            "mmap index: growing"
        );
        let mut fresh = Self::create(&self.path, new_slots)?;
        // create() renamed the new file over ours; our map still points at
        // the old (now unlinked) inode, so reads keep working.
        self.for_each(|k, l| {
            let mask = fresh.slots - 1;
            let mut i = (k as u64) & mask;
            loop {
                if matches!(fresh.read_slot(i), (FLAG_EMPTY, _)) {
                    encode_slot(fresh.slot_mut(i), k, l, FLAG_LIVE);
                    break;
                }
                i = (i + 1) & mask;
            }
        });
        fresh.live = self.live;
        fresh.tombs = 0;
        fresh.flush()?; // stamp complete — a crash before this rebuilds
        *self = fresh;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn loc(vol: u32, off: u64, len: u32) -> Loc {
        Loc {
            vol,
            off,
            name_len: 64,
            payload_len: len,
        }
    }

    #[test]
    fn insert_get_remove_replace() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("live.idx");
        let (mut idx, _) = MmapLiveIndex::open(&path).unwrap();
        assert_eq!(idx.get(7), None);
        assert_eq!(idx.insert(7, loc(1, 0, 10)).unwrap(), None);
        assert_eq!(idx.get(7), Some(loc(1, 0, 10)));
        // Replace returns the old location.
        assert_eq!(idx.insert(7, loc(2, 8, 20)).unwrap(), Some(loc(1, 0, 10)));
        assert_eq!(idx.len(), 1);
        assert_eq!(idx.remove(7), Some(loc(2, 8, 20)));
        assert_eq!(idx.get(7), None);
        assert_eq!(idx.len(), 0);
        // Tombstone reuse: re-insert after delete.
        assert_eq!(idx.insert(7, loc(3, 16, 30)).unwrap(), None);
        assert_eq!(idx.get(7), Some(loc(3, 16, 30)));
    }

    #[test]
    fn survives_reopen_with_correct_counts() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("live.idx");
        {
            let (mut idx, _) = MmapLiveIndex::open(&path).unwrap();
            for k in 0..1000u128 {
                idx.insert(k * 31 + 1, loc(1, k as u64 * 8, k as u32))
                    .unwrap();
            }
            idx.remove(1).unwrap();
            idx.flush().unwrap();
        }
        let (idx, stats) = MmapLiveIndex::open(&path).unwrap();
        assert!(!stats.torn);
        assert_eq!(stats.live, 999);
        assert_eq!(idx.len(), 999);
        assert_eq!(idx.get(31 + 1), Some(loc(1, 8, 1)));
        assert_eq!(idx.get(1), None);
    }

    #[test]
    fn grows_past_initial_capacity_collisions_intact() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("live.idx");
        let (mut idx, _) = MmapLiveIndex::open(&path).unwrap();
        // Force collisions AND growth with a tiny synthetic table: shrink
        // via direct create.
        let mut idx = MmapLiveIndex::create(&path, 8).unwrap();
        let _ = idx;
        let mut idx = MmapLiveIndex::create(&path, 8).unwrap();
        for k in 0..64u128 {
            idx.insert(k, loc(1, k as u64, 1)).unwrap();
        }
        assert_eq!(idx.len(), 64);
        assert!(idx.slots >= 64);
        for k in 0..64u128 {
            assert_eq!(idx.get(k), Some(loc(1, k as u64, 1)), "key {k}");
        }
    }

    #[test]
    fn torn_slot_is_detected_at_open() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("live.idx");
        {
            let (mut idx, _) = MmapLiveIndex::open(&path).unwrap();
            for k in 1..100u128 {
                idx.insert(k, loc(1, k as u64, 1)).unwrap();
            }
            idx.flush().unwrap();
        }
        // Flip one byte inside some occupied slot region.
        {
            use std::os::unix::fs::FileExt;
            let f = std::fs::OpenOptions::new().write(true).open(&path).unwrap();
            // Find an occupied slot by scanning raw bytes after the header.
            let data = std::fs::read(&path).unwrap();
            let mut target = None;
            for i in 0..(data.len() - HEADER_LEN) / SLOT_LEN {
                let o = HEADER_LEN + i * SLOT_LEN;
                if !data[o..o + SLOT_LEN].iter().all(|&b| b == 0) {
                    target = Some(o);
                    break;
                }
            }
            let o = target.expect("an occupied slot");
            f.write_all_at(&[data[o] ^ 0xFF], o as u64).unwrap();
        }
        let (idx, stats) = MmapLiveIndex::open(&path).unwrap();
        assert!(stats.torn, "corruption must be detected");
        assert_eq!(idx.len(), 0, "table wiped for rebuild");
    }

    /// The table's anonymous-memory cost must not scale with entries: the
    /// slots live in FILE-backed pages. Guard: RssAnon delta for 1M entries
    /// stays under 8 MB (the HashMap it replaces would take ~48 MB).
    ///
    /// `#[ignore]`: reads /proc/self/status, so the parallel suite pollutes
    /// the measurement (passes isolated, fails amid 46 concurrent tests).
    /// Run: `cargo test -p miner --release anon_memory -- --ignored`
    #[ignore]
    #[test]
    fn anon_memory_does_not_scale_with_entries() {
        fn rss_anon_kb() -> u64 {
            std::fs::read_to_string("/proc/self/status")
                .ok()
                .and_then(|s| {
                    s.lines()
                        .find(|l| l.starts_with("RssAnon:"))
                        .and_then(|l| l.split_whitespace().nth(1))
                        .and_then(|v| v.parse().ok())
                })
                .unwrap_or(0)
        }
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("live.idx");
        let (mut idx, _) = MmapLiveIndex::open(&path).unwrap();
        let before = rss_anon_kb();
        for k in 0..1_000_000u128 {
            idx.insert(k * 2 + 1, loc(1, k as u64 * 40, 100)).unwrap();
        }
        let delta_kb = rss_anon_kb().saturating_sub(before);
        assert_eq!(idx.len(), 1_000_000);
        assert!(
            delta_kb < 8 * 1024,
            "anon delta {delta_kb} KB for 1M entries — index is leaking into the heap"
        );
    }
}

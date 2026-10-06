//! Persistent SQLite inventory of stored shards.
//!
//! Tracks every blob hash stored on this miner in a WAL-mode SQLite database.
//! Read locally by `CheckBlob`, rebalance and the obligation-list purge
//! instead of scanning the filesystem, and kept in sync by `insert_shard` /
//! `trash_shard` hooks in the Store and Delete handlers. It is never served
//! whole to a peer: the `ListAllBlobs`/`ListBlobsPage` messages are refused.
//!
//! Trashed shards keep their row with `trashed_at` set: they are excluded
//! from every listing (the validator must see them as "not held") but the
//! timestamp drives the retention clock of the trash purge loop. File mtimes
//! are useless for that clock — the trash rename preserves them.

use anyhow::Result;
use std::path::Path;
use std::sync::{Mutex, OnceLock};
use tracing::{error, info, warn};

static DB: OnceLock<Mutex<rusqlite::Connection>> = OnceLock::new();

/// `data_dir/inventory.db`, set by [`init_inventory`].
static DB_PATH: OnceLock<std::path::PathBuf> = OnceLock::new();

/// Clean-stop marker next to the database, written by
/// [`seal_on_clean_shutdown`] and consumed (read, then removed) by
/// [`init_inventory`]. See [`rebuild_from_fs`].
const CLEAN_STOP_MARKER_FILE: &str = "inventory.clean";

/// Content of the clean-stop marker found at startup (`None`: absent,
/// unreadable, or it could not be removed and is therefore not trusted).
static CLEAN_STOP_FOUND: OnceLock<Option<String>> = OnceLock::new();

/// Age in seconds of `inventory.db` (its mtime) when [`init_inventory`]
/// found it, read before SQLite opens it; `None` when absent or
/// unreadable.
static DB_AGE_AT_OPEN: OnceLock<Option<u64>> = OnceLock::new();

/// `INVENTORY_STARTUP_COUNT=false` is honoured without a clean-stop
/// marker only for a database written at most this long ago: an older or
/// copied database may carry rows (and `stored_at` values) that no longer
/// describe the disk.
pub const STARTUP_COUNT_SKIP_MAX_DB_AGE_SECS: u64 = 24 * 3600;

/// Set while the one-time `idx_trashed_at` build runs on its own
/// connection ([`build_trashed_index`]). SQLite holds the write lock for
/// the whole build (one scan of the table: 5-8 minutes measured on a
/// loaded HDD node), so the writes made meanwhile go to [`DEFERRED`]
/// instead of waiting on the connection lock, and are applied in order
/// once it ends. Read and cleared only under the connection lock.
static INDEX_BUILDING: std::sync::atomic::AtomicBool = std::sync::atomic::AtomicBool::new(false);

/// Writes deferred while [`INDEX_BUILDING`], in arrival order, and the
/// journal ([`DEFERRED_FILE`]) each is appended to before it is queued,
/// so a crash during the build loses none (the next start applies the
/// journal). Taken only under the connection lock.
static DEFERRED: Mutex<Deferred> = Mutex::new(Deferred {
    ops: Vec::new(),
    journal: None,
});

struct Deferred {
    ops: Vec<DeferredWrite>,
    journal: Option<std::fs::File>,
}

/// Set once a graceful shutdown fsynced the journal: the next start
/// applies those writes, so this run must neither apply them nor write
/// past them (a later write replayed under an older one would be
/// undone). Writes then fail; the build, if it ends, leaves
/// [`INDEX_BUILDING`] set. Read and set only under the connection lock.
static DEFERRED_SAVED: std::sync::atomic::AtomicBool = std::sync::atomic::AtomicBool::new(false);

/// Bound of [`DEFERRED`]: past it a write fails (and is recorded as a
/// write failure, closing the purge until the next restart).
const MAX_DEFERRED_WRITES: usize = 1_000_000;

/// Journal of the writes deferred during the index build, next to the
/// database: removed once the build applied them, otherwise (crash or
/// stop during the build) replayed and removed by [`init_inventory`].
const DEFERRED_FILE: &str = "inventory.deferred";

/// One inventory write, as [`insert_shard`], [`trash_shard`] and
/// [`delete_shard`] make it.
#[derive(Debug, Clone, PartialEq, Eq)]
enum DeferredWrite {
    Insert { hash: String, at: i64 },
    Trash { hash: String, at: i64 },
    Delete { hash: String },
}

impl DeferredWrite {
    fn apply(&self, conn: &rusqlite::Connection) -> rusqlite::Result<()> {
        match self {
            DeferredWrite::Insert { hash, at } => conn.execute(
                "INSERT INTO shards (hash, stored_at, trashed_at) VALUES (?1, ?2, NULL)
                 ON CONFLICT(hash) DO UPDATE SET trashed_at = NULL, stored_at = excluded.stored_at",
                rusqlite::params![hash, at],
            ),
            DeferredWrite::Trash { hash, at } => conn.execute(
                "INSERT INTO shards (hash, stored_at, trashed_at) VALUES (?1, ?2, ?2)
                 ON CONFLICT(hash) DO UPDATE SET trashed_at = excluded.trashed_at",
                rusqlite::params![hash, at],
            ),
            DeferredWrite::Delete { hash } => conn.execute(
                "DELETE FROM shards WHERE hash = ?1",
                rusqlite::params![hash],
            ),
        }
        .map(|_| ())
    }

    fn to_line(&self) -> String {
        match self {
            DeferredWrite::Insert { hash, at } => format!("I {hash} {at}\n"),
            DeferredWrite::Trash { hash, at } => format!("T {hash} {at}\n"),
            DeferredWrite::Delete { hash } => format!("D {hash}\n"),
        }
    }

    fn from_line(line: &str) -> Option<Self> {
        let mut parts = line.split(' ');
        let op = parts.next()?;
        let hash = parts.next()?.to_string();
        let at = parts.next().map(str::parse::<i64>);
        let write = match (op, at) {
            ("I", Some(Ok(at))) => DeferredWrite::Insert { hash, at },
            ("T", Some(Ok(at))) => DeferredWrite::Trash { hash, at },
            ("D", None) => DeferredWrite::Delete { hash },
            _ => return None,
        };
        parts.next().is_none().then_some(write)
    }
}

/// Set once the inventory reflects what is actually on disk.
///
/// Until then the DB may be empty or half-rebuilt, and any consumer reading
/// it as complete (the obligation purge, a rebalance scan) would treat a
/// partial holding as the whole store.
static INVENTORY_READY: std::sync::atomic::AtomicBool = std::sync::atomic::AtomicBool::new(false);

/// Set when a write to the inventory failed after the blob itself was
/// written. The row then lies about the blob (age, liveness): the
/// obligation-list purge refuses to run until the next restart rebuilds.
static INVENTORY_WRITE_FAILED: std::sync::atomic::AtomicBool =
    std::sync::atomic::AtomicBool::new(false);

/// Whether an inventory write has failed since startup.
pub fn had_write_failure() -> bool {
    INVENTORY_WRITE_FAILED.load(std::sync::atomic::Ordering::Acquire)
}

/// Whether the inventory can be served to the validator.
pub fn is_ready() -> bool {
    INVENTORY_READY.load(std::sync::atomic::Ordering::Acquire)
}

/// Mark the inventory as reflecting on-disk state.
pub fn mark_ready() {
    INVENTORY_READY.store(true, std::sync::atomic::Ordering::Release);
}

/// Open (or create) the inventory database under `data_dir/inventory.db`.
pub fn init_inventory(data_dir: &Path) -> Result<()> {
    let db_path = data_dir.join("inventory.db");
    let _ = DB_AGE_AT_OPEN.set(file_age_secs(&db_path));
    let conn = rusqlite::Connection::open(&db_path)?;
    conn.execute_batch(
        "PRAGMA journal_mode=WAL;
         PRAGMA synchronous=NORMAL;
         CREATE TABLE IF NOT EXISTS shards (
           hash TEXT PRIMARY KEY,
           stored_at INTEGER NOT NULL
         );
         CREATE INDEX IF NOT EXISTS idx_stored_at ON shards(stored_at);",
    )?;
    // Idempotent migration: older databases lack the trash column.
    match conn.execute("ALTER TABLE shards ADD COLUMN trashed_at INTEGER", []) {
        Ok(_) => info!("inventory: added trashed_at column"),
        Err(e) if e.to_string().contains("duplicate column") => {}
        Err(e) => return Err(e.into()),
    }
    // Writes a graceful shutdown deferred during an unfinished index
    // build: applied before anything else reads or writes.
    replay_deferred_file(&conn, &db_path)?;
    // A missing trashed_at index is built in the background, off the
    // startup path ([`build_trashed_index`]): writes are deferred until
    // it ends. On an empty table (a new node) it is instant: built here.
    if !trashed_index_exists(&conn)? {
        if conn.prepare("SELECT 1 FROM shards LIMIT 1")?.exists([])? {
            start_deferring(&db_path)?;
        } else {
            ensure_trashed_index(&conn)?;
        }
    }
    DB.set(Mutex::new(conn))
        .map_err(|_| anyhow::anyhow!("inventory already initialized"))?;
    let _ = CLEAN_STOP_FOUND.set(consume_clean_stop_marker(&db_path));
    let _ = DB_PATH.set(db_path);
    Ok(())
}

/// Partial index over the trashed rows. Without it every query on the
/// trash (`trashed_shards_oldest`, once per batch of 1 000 in the trash
/// purge, and the trashed-row listing of `reconcile_trash`) scanned and
/// sorted the whole table, tens of millions of live rows, under the
/// connection lock. Built once on an existing database (one scan of the
/// table, logged), a no-op afterwards; it only holds the trashed rows.
fn ensure_trashed_index(conn: &rusqlite::Connection) -> Result<()> {
    if trashed_index_exists(conn)? {
        return Ok(());
    }
    info!("inventory: building the trashed_at index (one scan of the table)");
    let started = std::time::Instant::now();
    conn.execute_batch(
        "CREATE INDEX IF NOT EXISTS idx_trashed_at ON shards(trashed_at)
         WHERE trashed_at IS NOT NULL;",
    )?;
    info!(
        elapsed_ms = started.elapsed().as_millis() as u64,
        "inventory: trashed_at index built"
    );
    Ok(())
}

fn trashed_index_exists(conn: &rusqlite::Connection) -> Result<bool> {
    Ok(conn
        .prepare("SELECT 1 FROM sqlite_master WHERE type = 'index' AND name = 'idx_trashed_at'")?
        .exists([])?)
}

/// Whether the one-time trashed_at index build is still running (writes
/// deferred, trash purge paused).
pub fn index_building() -> bool {
    INDEX_BUILDING.load(std::sync::atomic::Ordering::Acquire)
}

/// Open a fresh journal and defer the writes from now on.
fn start_deferring(db_path: &Path) -> Result<()> {
    let journal = std::fs::File::create(db_path.with_file_name(DEFERRED_FILE))?;
    std::fs::File::open(db_path.parent().unwrap_or(Path::new(".")))?.sync_all()?;
    DEFERRED.lock().unwrap_or_else(|e| e.into_inner()).journal = Some(journal);
    INDEX_BUILDING.store(true, std::sync::atomic::Ordering::Release);
    Ok(())
}

/// Build the missing `idx_trashed_at` on a connection of its own, then
/// apply the writes deferred meanwhile and remove their journal; a no-op
/// when [`init_inventory`] found the index. Blocking (minutes on a large
/// table): run it from `spawn_blocking`, before the startup rebuild and
/// trash reconciliation, which write through the shared connection. A
/// failed (or panicking) build is logged and leaves the node as without
/// the index (trash queries scan the table): a performance index never
/// keeps a node from serving. A failed replay records a write failure and
/// keeps the writes deferred (journal intact) until the next start.
pub fn build_trashed_index() {
    if !index_building() {
        return;
    }
    let Some(db_path) = DB_PATH.get() else {
        return;
    };
    let built = std::panic::catch_unwind(|| {
        let conn = rusqlite::Connection::open(db_path)?;
        conn.busy_timeout(std::time::Duration::from_secs(30))?;
        ensure_trashed_index(&conn)
    })
    .unwrap_or_else(|_| Err(anyhow::anyhow!("index build panicked")));
    if let Err(e) = built {
        warn!(error = %e, "inventory: trashed_at index not built, trash queries scan the table");
    }
    let replayed = with_db(|conn| {
        if DEFERRED_SAVED.load(std::sync::atomic::Ordering::Acquire) {
            return Ok(0);
        }
        let mut deferred = DEFERRED.lock().unwrap_or_else(|e| e.into_inner());
        // A failed replay keeps deferring: the queue and its journal stay
        // whole and in order for the next start.
        apply_all(conn, &deferred.ops)?;
        // Empty the journal through its handle before removing it: a
        // journal left behind would be replayed at the next start under
        // the direct writes made from now on.
        if let Some(journal) = &deferred.journal {
            journal.set_len(0)?;
            journal.sync_all()?;
        }
        deferred.journal = None;
        let path = db_path.with_file_name(DEFERRED_FILE);
        if let Err(e) = std::fs::remove_file(&path) {
            warn!(error = %e, "inventory: emptied deferred-write journal not removed");
        }
        let n = std::mem::take(&mut deferred.ops).len();
        INDEX_BUILDING.store(false, std::sync::atomic::Ordering::Release);
        Ok(n)
    });
    match replayed {
        Ok(n) => info!(
            deferred_writes = n,
            "inventory: writes deferred during the index build applied"
        ),
        Err(e) => {
            INVENTORY_WRITE_FAILED.store(true, std::sync::atomic::Ordering::Release);
            error!(error = %e, "inventory: writes deferred during the index build could not be applied");
        }
    }
}

/// Apply `ops` in order, in one transaction.
fn apply_all(conn: &rusqlite::Connection, ops: &[DeferredWrite]) -> Result<()> {
    let tx = conn.unchecked_transaction()?;
    for op in ops {
        op.apply(&tx)?;
    }
    tx.commit()?;
    Ok(())
}

/// Make `op` now, or journal and defer it while the index build holds
/// SQLite's write lock. A write that cannot be deferred is recorded as a
/// write failure (the purge closes: a row may be missing or stale).
fn write(op: DeferredWrite) -> Result<()> {
    with_db(|conn| {
        if !index_building() {
            return Ok(op.apply(conn)?);
        }
        let deferred = defer(op);
        if deferred.is_err() {
            INVENTORY_WRITE_FAILED.store(true, std::sync::atomic::Ordering::Release);
        }
        deferred
    })
}

/// Append `op` to the journal, then to the queue. Under the connection
/// lock.
fn defer(op: DeferredWrite) -> Result<()> {
    anyhow::ensure!(
        !DEFERRED_SAVED.load(std::sync::atomic::Ordering::Acquire),
        "inventory: shutting down, deferred writes already saved"
    );
    let mut deferred = DEFERRED.lock().unwrap_or_else(|e| e.into_inner());
    anyhow::ensure!(
        deferred.ops.len() < MAX_DEFERRED_WRITES,
        "inventory: {MAX_DEFERRED_WRITES} writes already deferred during the index build"
    );
    let journal = deferred
        .journal
        .as_mut()
        .ok_or_else(|| anyhow::anyhow!("inventory: no journal for the deferred writes"))?;
    std::io::Write::write_all(journal, op.to_line().as_bytes())?;
    deferred.ops.push(op);
    Ok(())
}

/// Make the journal of an unfinished index build durable (fsync) for
/// the next start to apply, and stop this run from applying it or
/// writing past it. Called by a graceful shutdown once in-flight writes
/// drained. A journal that cannot be synced is left to this run: the
/// build may still end and apply it, else the next start replays what
/// reached the file.
fn persist_deferred() {
    let saved = with_db(|_conn| {
        // The build may have ended and applied the queue meanwhile.
        if !index_building() {
            return Ok(0);
        }
        let deferred = DEFERRED.lock().unwrap_or_else(|e| e.into_inner());
        if let Some(journal) = &deferred.journal {
            journal.sync_all()?;
        }
        DEFERRED_SAVED.store(true, std::sync::atomic::Ordering::Release);
        Ok(deferred.ops.len())
    });
    match saved {
        Ok(0) => {}
        Ok(n) => info!(
            deferred_writes = n,
            "inventory: index build unfinished at shutdown, deferred writes saved for the next start"
        ),
        Err(e) => {
            error!(error = %e, "inventory: index build unfinished at shutdown, the journal of deferred writes could not be synced")
        }
    }
}

/// Apply and remove the [`DEFERRED_FILE`] a crash or a stop during the
/// index build left. A final line without its newline is a write the
/// crash cut (never acknowledged as synced) and is skipped; any other
/// unreadable or malformed content fails the start: dropping it would
/// lose rows silently. Applying a journal twice (crash between the
/// commit and the removal) gives the same rows.
fn replay_deferred_file(conn: &rusqlite::Connection, db_path: &Path) -> Result<()> {
    let path = db_path.with_file_name(DEFERRED_FILE);
    let body = match std::fs::read_to_string(&path) {
        Ok(b) => b,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(()),
        Err(e) => {
            return Err(anyhow::anyhow!(
                "inventory: cannot read {}: {e}",
                path.display()
            ));
        }
    };
    let complete = match body.rfind('\n') {
        Some(end) => &body[..=end],
        None => "",
    };
    if complete.len() < body.len() {
        warn!("inventory: skipping a truncated last line of the deferred-write journal");
    }
    let ops = complete
        .lines()
        .map(|line| {
            DeferredWrite::from_line(line).ok_or_else(|| {
                anyhow::anyhow!("inventory: malformed line in {}: {line:?}", path.display())
            })
        })
        .collect::<Result<Vec<_>>>()?;
    apply_all(conn, &ops)?;
    std::fs::remove_file(&path)?;
    std::fs::File::open(path.parent().unwrap_or(Path::new(".")))?.sync_all()?;
    info!(
        deferred_writes = ops.len(),
        "inventory: writes deferred by the previous run applied"
    );
    Ok(())
}

fn clean_stop_marker_path(db_path: &Path) -> std::path::PathBuf {
    db_path.with_file_name(CLEAN_STOP_MARKER_FILE)
}

/// Content of the clean-stop marker for this database file and store
/// root. The database's inode ties the marker to the file it vouches for:
/// a deleted and recreated `inventory.db`, or one restored from a copy,
/// has another inode and the marker no longer matches.
fn clean_stop_marker_content(db_path: &Path, blobs_dir: &Path) -> Option<String> {
    use std::os::unix::fs::MetadataExt;
    let ino = std::fs::metadata(db_path).ok()?.ino();
    Some(format!("v1 {ino} {}\n", blobs_dir.display()))
}

/// Read the clean-stop marker and remove it, so that a crash of this run
/// leaves none behind. A marker that cannot be removed is not trusted
/// (it would survive a crash): `None`, and the next rebuild walks.
fn consume_clean_stop_marker(db_path: &Path) -> Option<String> {
    let path = clean_stop_marker_path(db_path);
    let content = match std::fs::read_to_string(&path) {
        Ok(c) => c,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return None,
        Err(e) => {
            warn!(error = %e, path = %path.display(), "inventory: clean-stop marker unreadable, the store will be counted");
            String::new()
        }
    };
    if let Err(e) = std::fs::remove_file(&path)
        && e.kind() != std::io::ErrorKind::NotFound
    {
        warn!(error = %e, path = %path.display(), "inventory: cannot remove the clean-stop marker, not trusting it (the store will be counted)");
        return None;
    }
    // The removal must survive a power loss of this run, or a crash would
    // resurrect the marker: fsync the directory, else distrust it.
    let dir = path.parent().unwrap_or(Path::new("."));
    if let Err(e) = std::fs::File::open(dir).and_then(|d| d.sync_all()) {
        warn!(error = %e, dir = %dir.display(), "inventory: cannot fsync the data directory after removing the clean-stop marker, not trusting it (the store will be counted)");
        return None;
    }
    (!content.is_empty()).then_some(content)
}

/// Whether the marker consumed at startup vouches for this database and
/// store root.
fn started_after_clean_stop(db_path: &Path, blobs_dir: &Path) -> bool {
    marker_vouches(
        CLEAN_STOP_FOUND.get().and_then(|f| f.as_deref()),
        db_path,
        blobs_dir,
    )
}

/// Whether a consumed marker `found` vouches for this database file and
/// store root.
fn marker_vouches(found: Option<&str>, db_path: &Path, blobs_dir: &Path) -> bool {
    found.is_some_and(|found| {
        clean_stop_marker_content(db_path, blobs_dir).is_some_and(|expected| found == expected)
    })
}

/// Longest a clean shutdown waits for in-flight blob writes (Store,
/// PullFromPeer, backfill: every holder of a per-hash write lock) before
/// it gives up on the clean-stop marker.
pub const CLEAN_STOP_DRAIN_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(20);

/// On a graceful shutdown, once nothing accepts new writes: wait up to
/// `drain_timeout` for the in-flight blob writes to finish, then write
/// the clean-stop marker if the inventory is in step with the disk (it
/// was ready, no inventory write failed, no write left in flight), so the
/// next start skips the filesystem count ([`rebuild_from_fs`]). Returns
/// whether the marker was written. Any doubt leaves no marker: the next
/// start counts, as after a crash.
pub async fn seal_on_clean_shutdown(blobs_dir: &Path, drain_timeout: std::time::Duration) -> bool {
    let Some(db_path) = DB_PATH.get() else {
        return false;
    };
    if index_building() {
        // Not ready either: no marker. Save what was deferred once the
        // in-flight writes landed in the queue.
        let deadline = tokio::time::Instant::now() + drain_timeout;
        while crate::state::hash_writes_in_flight() > 0 && tokio::time::Instant::now() < deadline {
            tokio::time::sleep(std::time::Duration::from_millis(100)).await;
        }
        persist_deferred();
        return false;
    }
    if !is_ready() || had_write_failure() {
        info!(
            ready = is_ready(),
            write_failed = had_write_failure(),
            "inventory: not sealing on shutdown, the next start counts the store"
        );
        return false;
    }
    let deadline = tokio::time::Instant::now() + drain_timeout;
    while crate::state::hash_writes_in_flight() > 0 {
        if tokio::time::Instant::now() >= deadline {
            warn!(
                in_flight = crate::state::hash_writes_in_flight(),
                "inventory: blob writes still in flight at shutdown, not sealing (the next start counts the store)"
            );
            return false;
        }
        tokio::time::sleep(std::time::Duration::from_millis(100)).await;
    }
    if had_write_failure() {
        return false;
    }
    let Some(content) = clean_stop_marker_content(db_path, blobs_dir) else {
        return false;
    };
    let path = clean_stop_marker_path(db_path);
    let tmp = path.with_extension("tmp");
    match std::fs::write(&tmp, content).and_then(|()| std::fs::rename(&tmp, &path)) {
        Ok(()) => {
            info!("inventory: sealed on clean shutdown, the next start skips the store count");
            true
        }
        Err(e) => {
            warn!(error = %e, path = %path.display(), "inventory: cannot write the clean-stop marker (the next start counts the store)");
            false
        }
    }
}

/// The inventory connection; an error (never a panic) before
/// [`init_inventory`], so a handler reached in a test or during a failed
/// start answers instead of aborting the process.
fn db() -> Result<&'static Mutex<rusqlite::Connection>> {
    DB.get()
        .ok_or_else(|| anyhow::anyhow!("inventory not initialized"))
}

/// Run `f` on the inventory connection. The lock wait and the query run
/// inside [`crate::helpers::blocking`]: a Store handler waiting for the
/// connection while a long query holds it must not hold a runtime worker
/// (with more concurrent handlers than workers, every worker would wait,
/// and timers, heartbeats and signal delivery with them).
fn with_db<R>(f: impl FnOnce(&rusqlite::Connection) -> Result<R>) -> Result<R> {
    crate::helpers::blocking(|| {
        let conn = db()?.lock().unwrap_or_else(|e| e.into_inner());
        f(&conn)
    })
}

/// Record a newly-stored shard (idempotent). A re-stored or restored shard
/// is live again: any pending trash mark is cleared and `stored_at` is
/// refreshed, so `stored_at` is the time of the LAST write. The
/// obligation-list purge reads it as the blob's age: a content-addressed
/// re-upload of old bytes must count as young again, otherwise a list
/// generation older than the re-upload would let the purge trash it.
pub fn insert_shard(hash: &str) -> Result<()> {
    let result = write(DeferredWrite::Insert {
        hash: hash.to_string(),
        at: now_secs(),
    });
    if result.is_err() {
        INVENTORY_WRITE_FAILED.store(true, std::sync::atomic::Ordering::Release);
    }
    result
}

fn now_secs() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs() as i64
}

/// `stored_at` of a live shard, `None` if unknown or trashed. The purge
/// re-reads it under the per-hash write lock right before a delete.
pub fn live_stored_at(hash: &str) -> Result<Option<i64>> {
    with_db(|conn| {
        let mut stmt = conn.prepare_cached(
            "SELECT stored_at FROM shards WHERE hash = ?1 AND trashed_at IS NULL",
        )?;
        let mut rows = stmt.query(rusqlite::params![hash])?;
        Ok(match rows.next()? {
            Some(row) => Some(row.get(0)?),
            None => None,
        })
    })
}

/// Read-only connections kept for [`live_among`], at most this many idle.
const MAX_IDLE_READERS: usize = 64;

/// Idle read-only connections of [`live_among`].
static READERS: Mutex<Vec<rusqlite::Connection>> = Mutex::new(Vec::new());

/// Which of `hashes` the inventory holds as LIVE (not trashed) shards, in
/// order: the batch form of `live_stored_at(..).is_some()`.
///
/// Runs on a read-only connection of its own (WAL: readers neither take
/// the connection lock of [`with_db`] nor block its writers). Each lookup
/// is its own implicit read transaction, as the point query was: no
/// reader holds a snapshot across a batch, so concurrent batches never
/// keep a checkpoint from resetting the WAL. Several callers run in
/// parallel on distinct connections, so their disk reads overlap instead
/// of queueing one point query at a time behind every other inventory
/// user. Blocking: call it from `spawn_blocking`.
pub fn live_among(hashes: &[[u8; 32]]) -> Result<Vec<bool>> {
    let conn = checkout_reader()?;
    let result = live_among_on(&conn, hashes);
    if result.is_ok() {
        let mut idle = READERS.lock().unwrap_or_else(|e| e.into_inner());
        if idle.len() < MAX_IDLE_READERS {
            idle.push(conn);
        }
    }
    result
}

fn checkout_reader() -> Result<rusqlite::Connection> {
    if let Some(conn) = READERS.lock().unwrap_or_else(|e| e.into_inner()).pop() {
        return Ok(conn);
    }
    let path = DB_PATH
        .get()
        .ok_or_else(|| anyhow::anyhow!("inventory not initialized"))?;
    open_reader(path)
}

/// A read-only connection on the inventory file.
pub(crate) fn open_reader(path: &Path) -> Result<rusqlite::Connection> {
    use rusqlite::OpenFlags;
    let conn = rusqlite::Connection::open_with_flags(
        path,
        OpenFlags::SQLITE_OPEN_READ_ONLY | OpenFlags::SQLITE_OPEN_NO_MUTEX,
    )?;
    conn.busy_timeout(std::time::Duration::from_secs(30))?;
    Ok(conn)
}

/// [`live_among`] on a given connection.
pub(crate) fn live_among_on(conn: &rusqlite::Connection, hashes: &[[u8; 32]]) -> Result<Vec<bool>> {
    let mut out = Vec::with_capacity(hashes.len());
    let mut hex_buf = [0u8; 64];
    let mut stmt =
        conn.prepare_cached("SELECT 1 FROM shards WHERE hash = ?1 AND trashed_at IS NULL")?;
    for hash in hashes {
        hex::encode_to_slice(hash, &mut hex_buf).expect("64-byte buffer for 32 bytes");
        let hex = std::str::from_utf8(&hex_buf).expect("hex is ASCII");
        out.push(stmt.exists(rusqlite::params![hex])?);
    }
    Ok(out)
}

/// Mark a shard as trashed: excluded from every listing, retention clock
/// started. Inserts the row if the DB never knew the shard.
pub fn trash_shard(hash: &str) -> Result<()> {
    write(DeferredWrite::Trash {
        hash: hash.to_string(),
        at: now_secs(),
    })
}

/// Remove the entry of a trashed shard, only while it is still trashed:
/// a Store or RestoreBlob that made the hash live again after the trash
/// purge listed it keeps its row (the purge only removes the trash copy).
fn delete_trashed_row(hash: &str) -> Result<bool> {
    with_db(|conn| {
        anyhow::ensure!(!index_building(), "inventory: index build in progress");
        let n = conn.execute(
            "DELETE FROM shards WHERE hash = ?1 AND trashed_at IS NOT NULL",
            rusqlite::params![hash],
        )?;
        Ok(n > 0)
    })
}

/// Remove a shard entry permanently (trash purge, or hard delete when the
/// trash is disabled).
pub fn delete_shard(hash: &str) -> Result<()> {
    write(DeferredWrite::Delete {
        hash: hash.to_string(),
    })
}

/// Drop the row of a live shard whose blob the store does not hold, only
/// while it is still live with `stored_at` unchanged: a write that landed
/// since the caller read the row (a re-store refreshes `stored_at`, a
/// delete trashes it) keeps it. Returns whether a row was dropped.
pub fn drop_live_row(hash: &str, stored_at: i64) -> Result<bool> {
    with_db(|conn| {
        anyhow::ensure!(!index_building(), "inventory: index build in progress");
        let n = conn.execute(
            "DELETE FROM shards WHERE hash = ?1 AND trashed_at IS NULL AND stored_at = ?2",
            rusqlite::params![hash, stored_at],
        )?;
        Ok(n > 0)
    })
}

/// Query of [`trashed_shards_oldest`]; answered from `idx_trashed_at`.
const TRASHED_OLDEST_SQL: &str = "SELECT hash, trashed_at FROM shards WHERE trashed_at IS NOT NULL
     ORDER BY trashed_at ASC LIMIT ?1";

/// Oldest trashed shards first: `(hash, trashed_at)` pages for the purge
/// loop.
pub fn trashed_shards_oldest(limit: usize) -> Result<Vec<(String, i64)>> {
    with_db(|conn| {
        let mut stmt = conn.prepare(TRASHED_OLDEST_SQL)?;
        let rows = stmt.query_map(rusqlite::params![limit as i64], |row| {
            Ok((row.get(0)?, row.get(1)?))
        })?;
        Ok(rows.flatten().collect())
    })
}

/// One keyset page of live hashes; a test oracle for the inventory's
/// contents now that the miner serves no enumeration message.
#[cfg(test)]
pub fn list_hashes_page(after_hash: Option<&str>, limit: usize) -> Result<Vec<String>> {
    with_db(|conn| {
        let mut stmt = conn.prepare(
            "SELECT hash FROM shards WHERE hash > ?1 AND trashed_at IS NULL
             ORDER BY hash LIMIT ?2",
        )?;
        let rows = stmt.query_map(
            rusqlite::params![after_hash.unwrap_or(""), limit as i64],
            |row| row.get(0),
        )?;
        Ok(rows.flatten().collect())
    })
}

/// Keyset page of live shards in hash order: `(hash, stored_at)` rows
/// strictly after `after_hash`. Drives the obligation-list purge pass,
/// which needs the age of every blob and must never walk the store.
pub fn live_shards_page(after_hash: Option<&str>, limit: usize) -> Result<Vec<(String, i64)>> {
    with_db(|conn| {
        let mut stmt = conn.prepare(
            "SELECT hash, stored_at FROM shards WHERE hash > ?1 AND trashed_at IS NULL
             ORDER BY hash LIMIT ?2",
        )?;
        let rows = stmt.query_map(
            rusqlite::params![after_hash.unwrap_or(""), limit as i64],
            |row| Ok((row.get(0)?, row.get(1)?)),
        )?;
        Ok(rows.flatten().collect())
    })
}

/// Populate the inventory from the filesystem if the DB is empty or far
/// behind it.
///
/// Returns the number of entries inserted (0 when the DB already had data).
/// Inserts are batched in chunks of 10 000 inside explicit transactions for
/// performance when millions of shards exist on disk.
///
/// Deciding needs a count of the store, one walk of every blob directory
/// entry (tens of millions of small files on large nodes: hours on HDDs,
/// measured on a test bench). The walk is skipped when the previous run
/// stopped cleanly: [`seal_on_clean_shutdown`] wrote the clean-stop
/// marker (`data_dir/inventory.clean`) after the in-flight writes drained,
/// with the inventory ready and no inventory write failed, for this very
/// database file (inode) and store root, and [`init_inventory`] consumed
/// it at this start. While a run lasts every Store/Delete keeps the
/// database in step with the disk, so the count could not tell anything
/// new. After a crash, a kill, a failed inventory write or a stop during
/// the count there is no marker and the count runs, in the background,
/// with the purge gated on [`is_ready`] as before.
///
/// `INVENTORY_STARTUP_COUNT=false` skips the count whenever the DB is not
/// empty, marker or not: for a first start on a build that predates the
/// marker, or a node whose count never finishes. The only risk is an
/// inventory that understates the disk after a crash, which hides blobs
/// from the purge (never deletes one) until a later start counts.
///
/// Without a marker the switch is honoured only when `inventory.db` was
/// written within [`STARTUP_COUNT_SKIP_MAX_DB_AGE_SECS`] (its mtime,
/// read before SQLite opened it): an old or copied database may carry
/// rows and `stored_at` values that no longer describe the disk, and the
/// count runs as usual.
pub fn rebuild_from_fs(blobs_dir: &Path) -> Result<usize> {
    let clean_stop = DB_PATH
        .get()
        .is_some_and(|db| started_after_clean_stop(db, blobs_dir));
    let db_age = DB_AGE_AT_OPEN.get().copied().flatten();
    let skip = skip_startup_count(clean_stop, startup_count_enabled(), db_age);
    if !clean_stop && !startup_count_enabled() && !skip {
        warn!(
            db_age_secs = ?db_age,
            max_age_secs = STARTUP_COUNT_SKIP_MAX_DB_AGE_SECS,
            "inventory: INVENTORY_STARTUP_COUNT=false ignored, no clean-stop marker and the database is old or its age unknown: counting the store"
        );
    }
    rebuild_from_fs_inner(blobs_dir, skip)
}

/// Whether the startup count may be skipped: after a clean stop, or when
/// the operator switched it off and the database was written within
/// [`STARTUP_COUNT_SKIP_MAX_DB_AGE_SECS`].
fn skip_startup_count(clean_stop: bool, count_enabled: bool, db_age_secs: Option<u64>) -> bool {
    clean_stop
        || (!count_enabled
            && db_age_secs.is_some_and(|age| age <= STARTUP_COUNT_SKIP_MAX_DB_AGE_SECS))
}

/// Seconds since `path` was last modified (0 for a future mtime), `None`
/// when it cannot be read.
fn file_age_secs(path: &Path) -> Option<u64> {
    let modified = std::fs::metadata(path).ok()?.modified().ok()?;
    Some(
        std::time::SystemTime::now()
            .duration_since(modified)
            .map_or(0, |d| d.as_secs()),
    )
}

/// `INVENTORY_STARTUP_COUNT` (strict boolean, default true). An
/// unparseable value keeps the count: the safe side, logged.
fn startup_count_enabled() -> bool {
    startup_count_from(std::env::var("INVENTORY_STARTUP_COUNT").ok().as_deref())
}

fn startup_count_from(raw: Option<&str>) -> bool {
    let Some(raw) = raw else { return true };
    miner::purge::parse_bool(raw).unwrap_or_else(|| {
        warn!(value = %raw, "INVENTORY_STARTUP_COUNT is not a boolean, keeping the count");
        true
    })
}

/// [`rebuild_from_fs`] once the clean-stop marker has been judged.
fn rebuild_from_fs_inner(blobs_dir: &Path, skip_count: bool) -> Result<usize> {
    if !blobs_dir.exists() {
        return Ok(0);
    }
    let existing_before: i64 = db()?.lock().unwrap_or_else(|e| e.into_inner()).query_row(
        "SELECT COUNT(*) FROM shards WHERE trashed_at IS NULL",
        [],
        |r| r.get(0),
    )?;
    if existing_before > 0 && skip_count {
        info!(
            existing = existing_before,
            "inventory: clean stop or INVENTORY_STARTUP_COUNT=false, skipping the filesystem count"
        );
        return Ok(0);
    }

    // Pass 1 — COUNT ONLY, streamed. Materializing tens of millions of
    // names is gigabytes of heap that glibc never gives back (measured on
    // 31 GB nodes: 7+ GB permanent RSS). Walks the flat legacy level AND
    // the sharded ab/cd tree; a fresh DB on a sharded-layout node must see
    // every blob or the inventory would truthfully describe an empty store.
    let mut fs_count = 0i64;
    crate::flat_store::for_each_bin(blobs_dir, &mut |h, _| {
        if h.len() == 64 {
            fs_count += 1;
        }
    });

    let conn = db()?.lock().unwrap_or_else(|e| e.into_inner());

    // Rebuild if DB is significantly out of sync with the filesystem.
    // Use a 10% threshold: if the DB has fewer than 90% of the FS entries,
    // assume the DB is stale (e.g. first boot, DB loss, or race at startup).
    // Trashed rows are out of scope on both sides: the FS scan is
    // non-recursive (trash/ is a subdirectory) and their retention clocks
    // must survive a rebuild.
    let existing: i64 = conn.query_row(
        "SELECT COUNT(*) FROM shards WHERE trashed_at IS NULL",
        [],
        |r| r.get(0),
    )?;
    let threshold = (fs_count as f64 * 0.9) as i64;
    if existing >= threshold && existing > 0 {
        info!(
            existing,
            fs_count, "inventory: DB is up to date, skipping FS rebuild"
        );
        return Ok(0);
    }
    if existing > 0 {
        info!(
            existing,
            fs_count, threshold, "inventory: DB out of sync with FS, rebuilding"
        );
        // Clear stale live entries before rebuilding
        conn.execute_batch("DELETE FROM shards WHERE trashed_at IS NULL")?;
    }

    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs() as i64;

    // Pass 2 — the rebuild itself (rare: first boot or DB loss), streamed
    // straight into batched transactions. Only one 10k batch of names is
    // ever alive.
    let mut inserted = 0usize;
    let mut batch: Vec<String> = Vec::with_capacity(10_000);
    let flush = |batch: &mut Vec<String>| -> Result<usize> {
        if batch.is_empty() {
            return Ok(0);
        }
        let mut n = 0usize;
        let tx = conn.unchecked_transaction()?;
        {
            // A file in the live directory is live: clear any stale trash
            // mark left by a crash between rename and DB update.
            let mut stmt = tx.prepare_cached(
                "INSERT INTO shards (hash, stored_at, trashed_at) VALUES (?1, ?2, NULL)
                 ON CONFLICT(hash) DO UPDATE SET trashed_at = NULL",
            )?;
            for hash in batch.iter() {
                if stmt.execute(rusqlite::params![hash, now]).is_ok() {
                    n += 1;
                }
            }
        }
        tx.commit()?;
        batch.clear();
        Ok(n)
    };
    let mut flush_err: Option<anyhow::Error> = None;
    crate::flat_store::for_each_bin(blobs_dir, &mut |h, _| {
        if flush_err.is_some() || h.len() != 64 {
            return;
        }
        batch.push(h.to_string());
        if batch.len() >= 10_000 {
            match flush(&mut batch) {
                Ok(n) => inserted += n,
                Err(e) => flush_err = Some(e),
            }
        }
    });
    if let Some(e) = flush_err {
        return Err(e);
    }
    inserted += flush(&mut batch)?;

    if inserted > 0 {
        warn!(
            inserted,
            total = fs_count,
            "inventory: rebuilt from filesystem"
        );
    }

    Ok(inserted)
}

/// Pause between two batches of 1 000 while draining the leftover trash of
/// a miner running with the trash disabled: about 50 unlinks per second,
/// the default purge rate, so a drain of a large trash never saturates the
/// disk the reads need.
pub const TRASH_DRAIN_BATCH_PAUSE: std::time::Duration = std::time::Duration::from_secs(20);

/// Background purge of the trash: enforces the retention TTL, then the
/// size cap (oldest first). One pass every 5 minutes.
///
/// Also runs when the trash is disabled (`TRASH_ENABLED=false`, deletes
/// unlink directly): a trash left by an earlier run with it enabled is
/// then drained with `ttl_secs = 0` and `max_bytes = 0`, paced by
/// `batch_pause` between batches ([`TRASH_DRAIN_BATCH_PAUSE`]); without
/// it such a trash was never purged.
pub async fn trash_purge_loop(
    store: std::sync::Arc<dyn crate::store::BlobStore>,
    ttl_secs: u64,
    max_bytes: u64,
    batch_pause: Option<std::time::Duration>,
) {
    const TICK_SECS: u64 = 300;
    loop {
        tokio::time::sleep(std::time::Duration::from_secs(TICK_SECS)).await;
        // Without the index every trash query scans the table under the
        // connection lock, and the trash rows are not current: wait.
        if index_building() {
            continue;
        }
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs() as i64;
        let (purged, cap_purged) =
            trash_purge_pass(store.as_ref(), now, ttl_secs, max_bytes, batch_pause).await;
        if purged > 0 || cap_purged > 0 {
            info!(
                ttl_purged = purged,
                cap_purged,
                trash_bytes = store.trash_bytes(),
                "trash purge: pass complete"
            );
        }
    }
}

/// One pass of [`trash_purge_loop`] at `now`: `(ttl_purged, cap_purged)`.
async fn trash_purge_pass(
    store: &dyn crate::store::BlobStore,
    now: i64,
    ttl_secs: u64,
    max_bytes: u64,
    batch_pause: Option<std::time::Duration>,
) -> (usize, usize) {
    const BATCH: usize = 1_000;
    let pause = || async {
        if let Some(p) = batch_pause {
            tokio::time::sleep(p).await;
        }
    };

    let mut purged = 0usize;
    // Phase 1 — TTL: entries are ordered oldest-first, so the first
    // unexpired one ends the phase.
    'ttl: loop {
        let batch = match trashed_shards_oldest(BATCH) {
            Ok(b) => b,
            Err(e) => {
                warn!(error = %e, "trash purge: DB query failed");
                break;
            }
        };
        if batch.is_empty() {
            break;
        }
        let mut progressed = false;
        for (hash, trashed_at) in &batch {
            if now.saturating_sub(*trashed_at) < ttl_secs as i64 {
                break 'ttl;
            }
            store.purge_trashed(hash).await.ok();
            if delete_trashed_row(hash).is_ok() {
                purged += 1;
                progressed = true;
            }
        }
        if !progressed {
            break;
        }
        pause().await;
    }

    // Phase 2 — size cap: keep purging oldest until under the cap.
    let mut cap_purged = 0usize;
    while store.trash_bytes() > max_bytes {
        let batch = match trashed_shards_oldest(BATCH) {
            Ok(b) => b,
            Err(_) => break,
        };
        if batch.is_empty() {
            // Trash files unknown to the DB cannot be aged fairly;
            // reconciliation at next startup will adopt them.
            break;
        }
        let mut progressed = false;
        for (hash, _) in &batch {
            if store.trash_bytes() <= max_bytes {
                break;
            }
            store.purge_trashed(hash).await.ok();
            if delete_trashed_row(hash).is_ok() {
                cap_purged += 1;
                progressed = true;
            }
        }
        if !progressed {
            break;
        }
        pause().await;
    }
    (purged, cap_purged)
}

/// Whether the DB holds `hash` as trashed.
fn is_trashed_row(hash: &str) -> Result<bool> {
    with_db(|conn| {
        let mut stmt =
            conn.prepare_cached("SELECT 1 FROM shards WHERE hash = ?1 AND trashed_at IS NOT NULL")?;
        Ok(stmt.exists(rusqlite::params![hash])?)
    })
}

/// Reconcile the trash directory with the DB at startup.
///
/// Conservative in both directions: a trash file the DB does not know as
/// trashed gets `trashed_at = now` (its retention clock restarts — never an
/// early purge), and a trashed row whose file is gone is dropped. A hash
/// that is live on disk AND has a leftover trash copy keeps the live row;
/// the duplicate trash file is removed.
///
/// Cost: one walk of the trash (bounded by `TRASH_TTL_SECS` and
/// `TRASH_MAX_BYTES`) and one SQLite point query per trash file. The
/// filesystem is only asked about the exceptions: a trash file whose row
/// is not marked trashed (one `has` in the live tree) and a trashed row
/// the walk did not see (one `has_trashed`, to tell a file purged outside
/// the process from one trashed by a Delete after the walk). The steady
/// state, a Delete that renamed the file and marked its row, costs no
/// `stat` at all; it cost two per trashed blob before (hours at startup
/// on a node whose trash held the previous purge pass, measured on a test
/// bench). No lock on the DB is held across a filesystem call.
pub async fn reconcile_trash(store: &dyn crate::store::BlobStore) -> Result<usize> {
    let mut trashed_files = crate::helpers::blocking(|| store.list_trashed_hashes());
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs() as i64;

    let mut reclocked = 0usize;
    for hash in &trashed_files {
        if is_trashed_row(hash)? {
            // A Delete renamed the file and marked the row: in step.
            continue;
        }
        if store.has(hash) {
            // Live copy exists — the trash copy is a redundant leftover.
            store.purge_trashed(hash).await.ok();
            continue;
        }
        reclocked += with_db(|conn| {
            Ok(conn.execute(
                "INSERT INTO shards (hash, stored_at, trashed_at) VALUES (?1, ?2, ?2)
                 ON CONFLICT(hash) DO UPDATE SET trashed_at = excluded.trashed_at
                 WHERE shards.trashed_at IS NULL",
                rusqlite::params![hash, now],
            )?)
        })?;
    }

    // Drop trashed rows whose file disappeared (purged outside the process).
    // Membership in the walk first; a row the walk did not see is checked
    // on disk once (a Delete may have trashed it after the walk).
    trashed_files.sort_unstable();
    let unseen: Vec<String> = with_db(|conn| {
        let mut stmt = conn.prepare("SELECT hash FROM shards WHERE trashed_at IS NOT NULL")?;
        let rows = stmt.query_map([], |row| row.get::<_, String>(0))?;
        Ok(rows
            .flatten()
            .filter(|h| trashed_files.binary_search(h).is_err())
            .collect())
    })?;
    let stale: Vec<String> = unseen
        .into_iter()
        .filter(|h| !store.has_trashed(h))
        .collect();
    for hash in &stale {
        // Only while still trashed: a Store or RestoreBlob may have made
        // the hash live again since the SELECT.
        delete_trashed_row(hash)?;
    }

    if reclocked > 0 || !stale.is_empty() {
        info!(
            trash_files = trashed_files.len(),
            reclocked,
            dropped_rows = stale.len(),
            "inventory: trash reconciled at startup"
        );
    }
    Ok(trashed_files.len())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;

    /// The batch lookup of the backfill answers exactly what one point
    /// query per hash answers (live, trashed, absent), on a read-only
    /// connection opened beside the writer;
    /// rows the writer commits later are seen by the next call.
    #[test]
    fn live_among_matches_point_lookups() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("inventory.db");
        let writer = rusqlite::Connection::open(&path).unwrap();
        writer
            .execute_batch(
                "PRAGMA journal_mode=WAL;
                 CREATE TABLE shards (hash TEXT PRIMARY KEY, stored_at INTEGER NOT NULL,
                 trashed_at INTEGER);",
            )
            .unwrap();
        let hash_of = |i: u32| *blake3::hash(&i.to_le_bytes()).as_bytes();
        let n = 3_000u32;
        // i % 3 == 0: live, 1: trashed, 2: absent.
        for i in (0..n).filter(|i| i % 3 != 2) {
            let trashed = (i % 3 == 1).then_some(5i64);
            writer
                .execute(
                    "INSERT INTO shards (hash, stored_at, trashed_at) VALUES (?1, 1, ?2)",
                    rusqlite::params![hex::encode(hash_of(i)), trashed],
                )
                .unwrap();
        }
        let mut hashes: Vec<[u8; 32]> = (0..n).map(hash_of).collect();
        hashes.sort_unstable();
        let point = |conn: &rusqlite::Connection, h: &[u8; 32]| -> bool {
            conn.query_row(
                "SELECT stored_at FROM shards WHERE hash = ?1 AND trashed_at IS NULL",
                rusqlite::params![hex::encode(h)],
                |r| r.get::<_, i64>(0),
            )
            .is_ok()
        };
        let reader = open_reader(&path).unwrap();
        let batch = live_among_on(&reader, &hashes).unwrap();
        let expected: Vec<bool> = hashes.iter().map(|h| point(&writer, h)).collect();
        assert_eq!(batch, expected);
        assert_eq!(
            batch.iter().filter(|b| **b).count(),
            (0..n).filter(|i| i % 3 == 0).count()
        );
        assert!(live_among_on(&reader, &[]).unwrap().is_empty());

        // A later commit is seen by the next batch on the same reader.
        let absent = hash_of(2);
        assert!(!live_among_on(&reader, &[absent]).unwrap()[0]);
        writer
            .execute(
                "INSERT INTO shards (hash, stored_at) VALUES (?1, 2)",
                rusqlite::params![hex::encode(absent)],
            )
            .unwrap();
        assert!(live_among_on(&reader, &[absent]).unwrap()[0]);
        // The reader cannot write.
        assert!(
            reader
                .execute("DELETE FROM shards", [])
                .is_err_and(|e| e.to_string().contains("readonly"))
        );
    }

    /// The trash queries read the partial index, never the whole table
    /// (a scan and a sort of every live row per batch before).
    #[test]
    fn trash_queries_use_the_trashed_at_index() {
        let conn = rusqlite::Connection::open_in_memory().unwrap();
        conn.execute_batch(
            "CREATE TABLE shards (hash TEXT PRIMARY KEY, stored_at INTEGER NOT NULL,
             trashed_at INTEGER);",
        )
        .unwrap();
        ensure_trashed_index(&conn).unwrap();
        ensure_trashed_index(&conn).unwrap();
        let plan = |sql: &str| -> String {
            let mut stmt = conn.prepare(&format!("EXPLAIN QUERY PLAN {sql}")).unwrap();
            let rows = stmt
                .query_map(rusqlite::params![1000], |r| r.get::<_, String>(3))
                .unwrap();
            rows.map(|r| r.unwrap()).collect::<Vec<_>>().join("; ")
        };
        let oldest = plan(TRASHED_OLDEST_SQL);
        assert!(oldest.contains("idx_trashed_at"), "{oldest}");
        assert!(!oldest.contains("TEMP B-TREE"), "{oldest}");
        let listing = plan("SELECT hash FROM shards WHERE trashed_at IS NOT NULL AND ?1 > 0");
        assert!(listing.contains("idx_trashed_at"), "{listing}");
    }

    #[test]
    fn startup_count_skip_needs_a_marker_or_a_recent_database() {
        let day = STARTUP_COUNT_SKIP_MAX_DB_AGE_SECS;
        assert!(skip_startup_count(true, true, None), "clean stop");
        assert!(
            skip_startup_count(true, false, Some(10 * day)),
            "clean stop"
        );
        assert!(skip_startup_count(false, false, Some(3600)));
        assert!(skip_startup_count(false, false, Some(day)));
        assert!(
            !skip_startup_count(false, false, Some(day + 1)),
            "old database"
        );
        assert!(!skip_startup_count(false, false, None), "age unknown");
        assert!(!skip_startup_count(false, true, Some(0)), "switch on");
        let dir = tempfile::tempdir().unwrap();
        let f = dir.path().join("inventory.db");
        assert_eq!(file_age_secs(&f), None);
        std::fs::write(&f, b"x").unwrap();
        assert!(file_age_secs(&f).is_some_and(|a| a < 60));
        let old = std::time::SystemTime::now() - std::time::Duration::from_secs(2 * day);
        std::fs::File::options()
            .write(true)
            .open(&f)
            .unwrap()
            .set_modified(old)
            .unwrap();
        assert!(file_age_secs(&f).is_some_and(|a| a > day));
    }

    #[test]
    fn startup_count_switch_defaults_to_counting() {
        assert!(super::startup_count_from(None));
        assert!(super::startup_count_from(Some("true")));
        assert!(!super::startup_count_from(Some("false")));
        assert!(!super::startup_count_from(Some(" OFF ")));
        assert!(super::startup_count_from(Some("maybe")));
    }

    // The inventory DB is a process-wide singleton (OnceLock), so the whole
    // trash lifecycle is exercised in a single test.
    #[tokio::test]
    async fn trash_lifecycle_marks_filters_and_reconciles() {
        let dir = tempfile::tempdir().unwrap();
        init_inventory(dir.path()).unwrap();
        let store = crate::flat_store::FlatBlobStore::new(dir.path().join("blobs")).unwrap();

        writes_during_the_index_build_are_deferred_then_applied_in_order();

        insert_shard("live1").unwrap();
        insert_shard("doomed").unwrap();
        assert_eq!(
            list_hashes_page(None, 10).unwrap(),
            vec!["doomed".to_string(), "live1".to_string()]
        );

        // Trashed shards vanish from listings but keep a retention clock.
        trash_shard("doomed").unwrap();
        assert_eq!(
            list_hashes_page(None, 10).unwrap(),
            vec!["live1".to_string()]
        );
        let trashed = trashed_shards_oldest(10).unwrap();
        assert_eq!(trashed.len(), 1);
        assert_eq!(trashed[0].0, "doomed");

        // Re-inserting (Store / RestoreBlob) clears the mark.
        insert_shard("doomed").unwrap();
        assert_eq!(list_hashes_page(None, 10).unwrap().len(), 2);
        assert!(trashed_shards_oldest(10).unwrap().is_empty());

        // Reconciliation adopts unknown trash files (clock restarts) and
        // drops rows whose trash file is gone.
        store.store("orphaned", b"x").await.unwrap();
        store.delete("orphaned").await.unwrap(); // in trash, unknown to DB
        trash_shard("ghost").unwrap(); // in DB as trashed, no file
        reconcile_trash(&store).await.unwrap();
        let after: Vec<String> = trashed_shards_oldest(10)
            .unwrap()
            .into_iter()
            .map(|(h, _)| h)
            .collect();
        assert_eq!(after, vec!["orphaned".to_string()]);

        // Purge is final.
        store.purge_trashed("orphaned").await.unwrap();
        delete_shard("orphaned").unwrap();
        assert!(trashed_shards_oldest(10).unwrap().is_empty());

        // Reconciliation, steady state and exceptions: a Delete that
        // renamed and marked is left alone; a trash copy next to a live
        // copy (Store of a trashed hash) is dropped and the live row kept;
        // a trashed row trashed after the walk (file present) is kept.
        store.store("steady", b"s").await.unwrap();
        store.delete("steady").await.unwrap();
        trash_shard("steady").unwrap();
        store.store("dup", b"d").await.unwrap();
        store.delete("dup").await.unwrap();
        trash_shard("dup").unwrap();
        store.store("dup", b"d").await.unwrap();
        insert_shard("dup").unwrap();
        reconcile_trash(&store).await.unwrap();
        assert!(store.has_trashed("steady"));
        assert_eq!(
            trashed_shards_oldest(10)
                .unwrap()
                .into_iter()
                .map(|(h, _)| h)
                .collect::<Vec<_>>(),
            vec!["steady".to_string()]
        );
        assert!(store.has("dup") && !store.has_trashed("dup"));
        assert!(live_stored_at("dup").unwrap().is_some());
        store.purge_trashed("steady").await.unwrap();
        delete_shard("steady").unwrap();
        delete_shard("dup").unwrap();

        // Trash disabled: the loop drains a leftover trash (TTL 0, cap 0)
        // that the enabled settings would still retain.
        for h in ["left1", "left2"] {
            store.store(h, b"leftover").await.unwrap();
            insert_shard(h).unwrap();
            store.delete(h).await.unwrap();
            trash_shard(h).unwrap();
        }
        let now = common::now_secs() as i64;
        assert_eq!(
            trash_purge_pass(&store, now, 14 * 86_400, u64::MAX, None).await,
            (0, 0),
            "enabled settings keep a fresh trash"
        );
        // The arguments `main` passes with the trash disabled (pacing
        // shortened for the test).
        assert_eq!(
            trash_purge_pass(&store, now, 0, 0, Some(Duration::from_millis(1))).await,
            (2, 0)
        );
        assert!(trashed_shards_oldest(10).unwrap().is_empty());
        assert!(!store.has_trashed("left1") && !store.has_trashed("left2"));
        assert_eq!(store.trash_bytes(), 0);
        // A hash stored again after it was trashed keeps its live row when
        // the drain removes the trash copy.
        store.store("back", b"b").await.unwrap();
        store.delete("back").await.unwrap();
        trash_shard("back").unwrap();
        store.store("back", b"b").await.unwrap();
        insert_shard("back").unwrap();
        assert!(!delete_trashed_row("back").unwrap());
        assert!(live_stored_at("back").unwrap().is_some());
        store.purge_trashed("back").await.unwrap();
        delete_shard("back").unwrap();

        clean_stop_skips_the_count_and_anything_else_counts(dir.path(), &store).await;
        a_stop_during_the_index_build_leaves_the_journal_to_the_next_start(dir.path()).await;
    }

    /// A graceful stop during the build syncs the journal, writes no
    /// marker, refuses later writes (recorded as a write failure) and a
    /// build ending afterwards leaves the journal to the next start.
    /// Last step of the single DB test (it leaves the inventory closed).
    async fn a_stop_during_the_index_build_leaves_the_journal_to_the_next_start(
        data_dir: &std::path::Path,
    ) {
        let blobs = data_dir.join("blobs");
        let db_path = data_dir.join("inventory.db");
        let journal = db_path.with_file_name(DEFERRED_FILE);
        with_db(|conn| {
            conn.execute_batch("DROP INDEX idx_trashed_at")?;
            Ok(())
        })
        .unwrap();
        start_deferring(&db_path).unwrap();
        insert_shard("late").unwrap();
        assert!(!seal_on_clean_shutdown(&blobs, Duration::from_millis(50)).await);
        assert!(!data_dir.join(CLEAN_STOP_MARKER_FILE).exists());
        assert!(insert_shard("after-save").is_err());
        assert!(had_write_failure());
        build_trashed_index();
        assert!(index_building(), "left to the next start");
        assert_eq!(live_stored_at("late").unwrap(), None);
        let lines = std::fs::read_to_string(&journal).unwrap();
        assert!(
            lines.starts_with("I late ") && lines.lines().count() == 1,
            "{lines}"
        );
    }

    /// An existing database without the trashed_at index: the build runs
    /// on its own connection while writes queue, then the queue is
    /// applied in arrival order. Part of the single DB test.
    fn writes_during_the_index_build_are_deferred_then_applied_in_order() {
        with_db(|conn| {
            conn.execute_batch("DROP INDEX idx_trashed_at")?;
            Ok(())
        })
        .unwrap();
        let journal = DB_PATH.get().unwrap().with_file_name(DEFERRED_FILE);
        start_deferring(DB_PATH.get().unwrap()).unwrap();
        insert_shard("early").unwrap();
        trash_shard("early").unwrap();
        insert_shard("early2").unwrap();
        delete_shard("early2").unwrap();
        insert_shard("early3").unwrap();
        assert!(list_hashes_page(None, 10).unwrap().is_empty(), "queued");
        assert!(
            drop_live_row("early3", 0).is_err(),
            "no conditional drop while queued"
        );
        assert!(delete_trashed_row("early").is_err());
        // Journaled as they arrive: a crash now loses none.
        let lines = std::fs::read_to_string(&journal).unwrap();
        assert_eq!(lines.lines().count(), 5, "{lines}");
        assert!(lines.starts_with("I early "), "{lines}");

        build_trashed_index();
        assert!(!index_building());
        assert!(with_db(|conn| trashed_index_exists(conn)).unwrap());
        assert_eq!(
            list_hashes_page(None, 10).unwrap(),
            vec!["early3".to_string()]
        );
        assert_eq!(
            trashed_shards_oldest(10)
                .unwrap()
                .into_iter()
                .map(|(h, _)| h)
                .collect::<Vec<_>>(),
            vec!["early".to_string()]
        );
        assert!(DEFERRED.lock().unwrap().ops.is_empty());
        assert!(!journal.exists(), "removed once applied");
        assert!(!had_write_failure());
        delete_shard("early").unwrap();
        delete_shard("early3").unwrap();
    }

    /// The writes a graceful shutdown saved during the build are applied
    /// at the next start, in order, and the file removed; a malformed
    /// file fails the start and is kept.
    #[test]
    fn saved_deferred_writes_are_replayed_at_start() {
        let dir = tempfile::tempdir().unwrap();
        let db_path = dir.path().join("inventory.db");
        let conn = rusqlite::Connection::open(&db_path).unwrap();
        conn.execute_batch(
            "CREATE TABLE shards (hash TEXT PRIMARY KEY, stored_at INTEGER NOT NULL,
             trashed_at INTEGER);
             INSERT INTO shards VALUES ('gone', 1, NULL);",
        )
        .unwrap();
        replay_deferred_file(&conn, &db_path).unwrap();
        let ops = [
            DeferredWrite::Insert {
                hash: "a".into(),
                at: 10,
            },
            DeferredWrite::Trash {
                hash: "a".into(),
                at: 20,
            },
            DeferredWrite::Insert {
                hash: "b".into(),
                at: 30,
            },
            DeferredWrite::Delete {
                hash: "gone".into(),
            },
        ];
        for op in &ops {
            assert_eq!(
                DeferredWrite::from_line(op.to_line().trim_end()).as_ref(),
                Some(op)
            );
        }
        let file = db_path.with_file_name(DEFERRED_FILE);
        std::fs::write(
            &file,
            ops.iter().map(DeferredWrite::to_line).collect::<String>(),
        )
        .unwrap();
        replay_deferred_file(&conn, &db_path).unwrap();
        assert!(!file.exists());
        let rows: Vec<(String, i64, Option<i64>)> = conn
            .prepare("SELECT hash, stored_at, trashed_at FROM shards ORDER BY hash")
            .unwrap()
            .query_map([], |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)))
            .unwrap()
            .map(|r| r.unwrap())
            .collect();
        assert_eq!(
            rows,
            vec![("a".to_string(), 10, Some(20)), ("b".to_string(), 30, None)]
        );

        // A crash between the commit and the removal: applied twice, same
        // rows; a final line the crash cut is skipped.
        let body: String = ops.iter().map(DeferredWrite::to_line).collect();
        std::fs::write(&file, format!("{body}I c 4")).unwrap();
        replay_deferred_file(&conn, &db_path).unwrap();
        std::fs::write(&file, &body).unwrap();
        replay_deferred_file(&conn, &db_path).unwrap();
        let again: Vec<(String, i64, Option<i64>)> = conn
            .prepare("SELECT hash, stored_at, trashed_at FROM shards ORDER BY hash")
            .unwrap()
            .query_map([], |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)))
            .unwrap()
            .map(|r| r.unwrap())
            .collect();
        assert_eq!(again, rows);

        for bad in ["X a 1\n", "I a\n", "D a 1\n", "I a 1 2\n", "T a x\n"] {
            std::fs::write(&file, bad).unwrap();
            assert!(replay_deferred_file(&conn, &db_path).is_err(), "{bad:?}");
            assert!(file.exists());
        }
    }

    /// Simulated restart: what `init_inventory` does with the marker.
    fn restart(db_path: &std::path::Path) {
        // The OnceLock was set by the real init; the test re-reads by hand.
        *RESTART_FOUND.lock().unwrap() = consume_clean_stop_marker(db_path);
    }

    static RESTART_FOUND: std::sync::Mutex<Option<String>> = std::sync::Mutex::new(None);

    /// `rebuild_from_fs` under the marker a test restart consumed.
    fn rebuild_after_restart(db_path: &std::path::Path, blobs: &std::path::Path) -> usize {
        let found = RESTART_FOUND.lock().unwrap().clone();
        rebuild_from_fs_inner(blobs, marker_vouches(found.as_deref(), db_path, blobs)).unwrap()
    }

    /// The count walk of `rebuild_from_fs` is skipped only after a clean
    /// stop sealed the inventory: the marker is consumed at start (a
    /// crash of the next run leaves none), refused while a blob write is
    /// in flight, and never written after a failed inventory write. Part
    /// of the single DB test.
    async fn clean_stop_skips_the_count_and_anything_else_counts(
        data_dir: &std::path::Path,
        store: &crate::flat_store::FlatBlobStore,
    ) {
        let blobs = data_dir.join("blobs");
        let db_path = data_dir.join("inventory.db");
        let marker = data_dir.join(CLEAN_STOP_MARKER_FILE);
        let hash = |i: u32| hex::encode(blake3::hash(&i.to_le_bytes()).as_bytes());
        // Two blobs on disk, both in the DB (plus the live rows above).
        for i in 0..2 {
            store.store(&hash(i), b"blob").await.unwrap();
            insert_shard(&hash(i)).unwrap();
        }
        // First start: no marker, the count runs, finds the DB in step.
        restart(&db_path);
        assert_eq!(rebuild_after_restart(&db_path, &blobs), 0, "up to date");
        assert!(!marker.exists(), "a count alone never vouches");

        // Not ready yet: a stop during the count leaves no marker.
        assert!(!seal_on_clean_shutdown(&blobs, Duration::from_millis(50)).await);
        mark_ready();
        // A blob write in flight at shutdown: no marker.
        let writer = crate::state::try_lock_hash_write("in-flight-at-shutdown").unwrap();
        assert!(!seal_on_clean_shutdown(&blobs, Duration::from_millis(200)).await);
        assert!(!marker.exists());
        drop(writer);
        // Clean stop: sealed.
        assert!(seal_on_clean_shutdown(&blobs, Duration::from_millis(200)).await);
        assert!(marker.exists());

        // Twenty blobs land on disk behind the DB's back (only possible
        // outside the process): after the clean stop the count is
        // skipped. Without the marker it would find 22 blobs for 4 live
        // rows and rebuild (returning 22).
        for i in 2..22 {
            store.store(&hash(i), b"blob").await.unwrap();
        }
        restart(&db_path);
        assert!(!marker.exists(), "consumed at start");
        assert_eq!(rebuild_after_restart(&db_path, &blobs), 0, "count skipped");
        assert!(
            !clean_stop_skips_elsewhere(&db_path, &data_dir.join("elsewhere")),
            "the marker names its store root"
        );

        // That run crashes (no seal): the next start counts and rebuilds.
        restart(&db_path);
        assert_eq!(
            rebuild_after_restart(&db_path, &blobs),
            22,
            "walked and rebuilt"
        );

        // An inventory write fails: that run never seals.
        db().unwrap()
            .lock()
            .unwrap()
            .execute_batch("ALTER TABLE shards RENAME TO shards_aside")
            .unwrap();
        assert!(insert_shard(&hash(99)).is_err());
        db().unwrap()
            .lock()
            .unwrap()
            .execute_batch("ALTER TABLE shards_aside RENAME TO shards")
            .unwrap();
        assert!(!seal_on_clean_shutdown(&blobs, Duration::from_millis(50)).await);
        assert!(!marker.exists());
    }

    /// A marker written for one store root does not vouch for another.
    fn clean_stop_skips_elsewhere(db_path: &std::path::Path, other: &std::path::Path) -> bool {
        let found = RESTART_FOUND.lock().unwrap().clone();
        marker_vouches(found.as_deref(), db_path, other)
    }

    /// The marker is tied to the DB file's inode: a database deleted and
    /// recreated (or restored from a copy) is not vouched for. A marker
    /// is consumed by reading it.
    #[test]
    fn clean_stop_marker_does_not_survive_a_replaced_database() {
        let dir = tempfile::tempdir().unwrap();
        let db_path = dir.path().join("inventory.db");
        let blobs = dir.path().join("blobs");
        std::fs::write(&db_path, b"db").unwrap();
        let content = clean_stop_marker_content(&db_path, &blobs).unwrap();
        std::fs::write(clean_stop_marker_path(&db_path), &content).unwrap();
        let copy = dir.path().join("copy.db");
        std::fs::copy(&db_path, &copy).unwrap();
        std::fs::remove_file(&db_path).unwrap();
        std::fs::rename(&copy, &db_path).unwrap();
        assert_ne!(
            clean_stop_marker_content(&db_path, &blobs),
            Some(content.clone())
        );
        assert_eq!(consume_clean_stop_marker(&db_path), Some(content));
        assert!(!clean_stop_marker_path(&db_path).exists());
        assert_eq!(consume_clean_stop_marker(&db_path), None);
    }
}

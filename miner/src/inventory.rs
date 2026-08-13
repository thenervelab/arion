//! Persistent SQLite inventory of stored shards.
//!
//! Tracks every blob hash stored on this miner in a WAL-mode SQLite database.
//! Used by `ListAllBlobs` instead of scanning the filesystem, and kept in sync
//! by `insert_shard` / `trash_shard` hooks in the Store and Delete handlers.
//!
//! Trashed shards keep their row with `trashed_at` set: they are excluded
//! from every listing (the validator must see them as "not held") but the
//! timestamp drives the retention clock of the trash purge loop. File mtimes
//! are useless for that clock — the trash rename preserves them.

use anyhow::Result;
use std::path::Path;
use std::sync::{Mutex, OnceLock};
use tracing::{info, warn};

static DB: OnceLock<Mutex<rusqlite::Connection>> = OnceLock::new();

/// Set once the inventory reflects what is actually on disk.
///
/// Until then the DB may be empty or half-rebuilt, and answering
/// `ListAllBlobs`/`ListBlobsPage` from it would report a partial holding as
/// a *complete, successful* scan — the validator would then read the missing
/// blobs as data loss (unfair presence penalties, spurious repair jobs).
static INVENTORY_READY: std::sync::atomic::AtomicBool = std::sync::atomic::AtomicBool::new(false);

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
    DB.set(Mutex::new(conn))
        .map_err(|_| anyhow::anyhow!("inventory already initialized"))?;
    Ok(())
}

fn db() -> &'static Mutex<rusqlite::Connection> {
    DB.get().expect("inventory not initialized")
}

/// Record a newly-stored shard (idempotent). A re-stored or restored shard
/// is live again: any pending trash mark is cleared.
pub fn insert_shard(hash: &str) -> Result<()> {
    let conn = db().lock().unwrap_or_else(|e| e.into_inner());
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs() as i64;
    conn.execute(
        "INSERT INTO shards (hash, stored_at, trashed_at) VALUES (?1, ?2, NULL)
         ON CONFLICT(hash) DO UPDATE SET trashed_at = NULL",
        rusqlite::params![hash, now],
    )?;
    Ok(())
}

/// Mark a shard as trashed: excluded from every listing, retention clock
/// started. Inserts the row if the DB never knew the shard.
pub fn trash_shard(hash: &str) -> Result<()> {
    let conn = db().lock().unwrap_or_else(|e| e.into_inner());
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs() as i64;
    conn.execute(
        "INSERT INTO shards (hash, stored_at, trashed_at) VALUES (?1, ?2, ?2)
         ON CONFLICT(hash) DO UPDATE SET trashed_at = excluded.trashed_at",
        rusqlite::params![hash, now],
    )?;
    Ok(())
}

/// Remove a shard entry permanently (trash purge, or hard delete when the
/// trash is disabled).
pub fn delete_shard(hash: &str) -> Result<()> {
    let conn = db().lock().unwrap_or_else(|e| e.into_inner());
    conn.execute(
        "DELETE FROM shards WHERE hash = ?1",
        rusqlite::params![hash],
    )?;
    Ok(())
}

/// Oldest trashed shards first: `(hash, trashed_at)` pages for the purge
/// loop.
pub fn trashed_shards_oldest(limit: usize) -> Result<Vec<(String, i64)>> {
    let conn = db().lock().unwrap_or_else(|e| e.into_inner());
    let mut stmt = conn.prepare(
        "SELECT hash, trashed_at FROM shards WHERE trashed_at IS NOT NULL
         ORDER BY trashed_at ASC LIMIT ?1",
    )?;
    let rows = stmt.query_map(rusqlite::params![limit as i64], |row| {
        Ok((row.get(0)?, row.get(1)?))
    })?;
    Ok(rows.flatten().collect())
}

/// Stream all stored hashes via a channel to bound memory usage.
/// Returns the total count of hashes that will be sent.
pub fn stream_all_hashes(tx: tokio::sync::mpsc::Sender<String>) -> Result<usize> {
    let count: usize = {
        let conn = db().lock().unwrap_or_else(|e| e.into_inner());
        conn.query_row(
            "SELECT COUNT(*) FROM shards WHERE trashed_at IS NULL",
            [],
            |row| row.get(0),
        )?
    };

    tokio::task::spawn_blocking(move || {
        // Keyset pagination on the PK index: O(log n) per batch regardless
        // of depth. The previous OFFSET loop re-skipped from the start on
        // every batch — minutes of SQL for multi-million-blob inventories,
        // which made validator-side scans time out.
        let mut after_hash = String::new();
        let batch_size = 10_000;
        loop {
            let hashes: Vec<String> = {
                let conn = db().lock().unwrap_or_else(|e| e.into_inner());
                let mut stmt = match conn.prepare(
                    "SELECT hash FROM shards WHERE hash > ?1 AND trashed_at IS NULL
                     ORDER BY hash LIMIT ?2",
                ) {
                    Ok(s) => s,
                    Err(e) => {
                        warn!("inventory: DB prepare failed: {}", e);
                        break;
                    }
                };
                match stmt.query_map(rusqlite::params![after_hash, batch_size], |row| row.get(0)) {
                    Ok(rows) => {
                        let mut batch = Vec::with_capacity(batch_size as usize);
                        for h in rows.flatten() {
                            batch.push(h);
                        }
                        batch
                    }
                    Err(e) => {
                        warn!("inventory: DB query failed: {}", e);
                        break;
                    }
                }
            };

            if hashes.is_empty() {
                break;
            }
            if let Some(last) = hashes.last() {
                after_hash = last.clone();
            }

            for hash in hashes {
                if tx.blocking_send(hash).is_err() {
                    // Receiver dropped, stop streaming
                    return;
                }
            }
        }
    });

    Ok(count)
}

/// One keyset page of hashes for `ListBlobsPage`.
pub fn list_hashes_page(after_hash: Option<&str>, limit: usize) -> Result<Vec<String>> {
    let conn = db().lock().unwrap_or_else(|e| e.into_inner());
    let mut stmt = conn.prepare(
        "SELECT hash FROM shards WHERE hash > ?1 AND trashed_at IS NULL
         ORDER BY hash LIMIT ?2",
    )?;
    let rows = stmt.query_map(
        rusqlite::params![after_hash.unwrap_or(""), limit as i64],
        |row| row.get(0),
    )?;
    Ok(rows.flatten().collect())
}

/// Populate the inventory from the filesystem if the DB is empty.
///
/// Returns the number of entries inserted (0 when the DB already had data).
/// Inserts are batched in chunks of 10 000 inside explicit transactions for
/// performance when millions of shards exist on disk.
pub fn rebuild_from_fs(blobs_dir: &Path) -> Result<usize> {
    if !blobs_dir.exists() {
        return Ok(0);
    }

    // Collect FS entries before acquiring the lock (I/O can be slow).
    let entries: Vec<String> = std::fs::read_dir(blobs_dir)?
        .filter_map(|e| e.ok())
        .filter_map(|e| {
            let name = e.file_name().into_string().ok()?;
            // Blobs are stored as "<64-char-hash>.bin"
            if name.ends_with(".bin") && name.len() == 68 {
                Some(name[..64].to_string())
            } else if name.len() == 64 {
                // Legacy: no extension
                Some(name)
            } else {
                None
            }
        })
        .collect();

    let conn = db().lock().unwrap_or_else(|e| e.into_inner());

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
    let threshold = (entries.len() as f64 * 0.9) as i64;
    if existing >= threshold && existing > 0 {
        info!(
            existing,
            fs_count = entries.len(),
            "inventory: DB is up to date, skipping FS rebuild"
        );
        return Ok(existing as usize);
    }
    if existing > 0 {
        info!(
            existing,
            fs_count = entries.len(),
            threshold,
            "inventory: DB out of sync with FS, rebuilding"
        );
        // Clear stale live entries before rebuilding
        conn.execute_batch("DELETE FROM shards WHERE trashed_at IS NULL")?;
    }

    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs() as i64;

    // Insert in batches of 10_000 for performance.
    let mut inserted = 0usize;
    for chunk in entries.chunks(10_000) {
        let tx = conn.unchecked_transaction()?;
        {
            // A file in the live directory is live: clear any stale trash
            // mark left by a crash between rename and DB update.
            let mut stmt = tx.prepare_cached(
                "INSERT INTO shards (hash, stored_at, trashed_at) VALUES (?1, ?2, NULL)
                 ON CONFLICT(hash) DO UPDATE SET trashed_at = NULL",
            )?;
            for hash in chunk {
                if stmt.execute(rusqlite::params![hash, now]).is_ok() {
                    inserted += 1;
                }
            }
        }
        tx.commit()?;
    }

    if inserted > 0 {
        warn!(
            inserted,
            total = entries.len(),
            "inventory: rebuilt from filesystem"
        );
    }

    Ok(inserted)
}

/// Background purge of the trash: enforces the retention TTL, then the
/// size cap (oldest first). One pass every 5 minutes.
pub async fn trash_purge_loop(
    store: std::sync::Arc<crate::flat_store::FlatBlobStore>,
    ttl_secs: u64,
    max_bytes: u64,
) {
    const TICK_SECS: u64 = 300;
    const BATCH: usize = 1_000;
    loop {
        tokio::time::sleep(std::time::Duration::from_secs(TICK_SECS)).await;
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs() as i64;

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
                if delete_shard(hash).is_ok() {
                    purged += 1;
                    progressed = true;
                }
            }
            if !progressed {
                break;
            }
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
                if delete_shard(hash).is_ok() {
                    cap_purged += 1;
                    progressed = true;
                }
            }
            if !progressed {
                break;
            }
        }

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

/// Reconcile the trash directory with the DB at startup.
///
/// Conservative in both directions: a trash file the DB does not know as
/// trashed gets `trashed_at = now` (its retention clock restarts — never an
/// early purge), and a trashed row whose file is gone is dropped. A hash
/// that is live on disk AND has a leftover trash copy keeps the live row;
/// the duplicate trash file is removed.
pub async fn reconcile_trash(store: &crate::flat_store::FlatBlobStore) -> Result<usize> {
    let trashed_files = store.list_trashed_hashes();
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs() as i64;

    let mut reclocked = 0usize;
    for hash in &trashed_files {
        if store.has(hash) {
            // Live copy exists — the trash copy is a redundant leftover.
            store.purge_trashed(hash).await.ok();
            continue;
        }
        let conn = db().lock().unwrap_or_else(|e| e.into_inner());
        let changed = conn.execute(
            "INSERT INTO shards (hash, stored_at, trashed_at) VALUES (?1, ?2, ?2)
             ON CONFLICT(hash) DO UPDATE SET trashed_at = excluded.trashed_at
             WHERE shards.trashed_at IS NULL",
            rusqlite::params![hash, now],
        )?;
        reclocked += changed;
    }

    // Drop trashed rows whose file disappeared (purged outside the process).
    let stale: Vec<String> = {
        let conn = db().lock().unwrap_or_else(|e| e.into_inner());
        let mut stmt = conn.prepare("SELECT hash FROM shards WHERE trashed_at IS NOT NULL")?;
        let rows = stmt.query_map([], |row| row.get::<_, String>(0))?;
        rows.flatten().filter(|h| !store.has_trashed(h)).collect()
    };
    for hash in &stale {
        delete_shard(hash)?;
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

    // The inventory DB is a process-wide singleton (OnceLock), so the whole
    // trash lifecycle is exercised in a single test.
    #[tokio::test]
    async fn trash_lifecycle_marks_filters_and_reconciles() {
        let dir = tempfile::tempdir().unwrap();
        init_inventory(dir.path()).unwrap();
        let store = crate::flat_store::FlatBlobStore::new(dir.path().join("blobs")).unwrap();

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
    }
}

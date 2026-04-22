//! Persistent SQLite inventory of stored shards.
//!
//! Tracks every blob hash stored on this miner in a WAL-mode SQLite database.
//! Used by `ListAllBlobs` instead of scanning the filesystem, and kept in sync
//! by `insert_shard` / `delete_shard` hooks in the Store and Delete handlers.

use anyhow::Result;
use std::path::Path;
use std::sync::{Mutex, OnceLock};
use tracing::{info, warn};

static DB: OnceLock<Mutex<rusqlite::Connection>> = OnceLock::new();

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
    DB.set(Mutex::new(conn))
        .map_err(|_| anyhow::anyhow!("inventory already initialized"))?;
    Ok(())
}

fn db() -> &'static Mutex<rusqlite::Connection> {
    DB.get().expect("inventory not initialized")
}

/// Record a newly-stored shard (idempotent — ignores duplicates).
pub fn insert_shard(hash: &str) -> Result<()> {
    let conn = db().lock().unwrap_or_else(|e| e.into_inner());
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs() as i64;
    conn.execute(
        "INSERT OR IGNORE INTO shards (hash, stored_at) VALUES (?1, ?2)",
        rusqlite::params![hash, now],
    )?;
    Ok(())
}

/// Remove a shard entry after deletion.
pub fn delete_shard(hash: &str) -> Result<()> {
    let conn = db().lock().unwrap_or_else(|e| e.into_inner());
    conn.execute(
        "DELETE FROM shards WHERE hash = ?1",
        rusqlite::params![hash],
    )?;
    Ok(())
}

/// Stream all stored hashes via a channel to bound memory usage.
/// Returns the total count of hashes that will be sent.
pub fn stream_all_hashes(tx: tokio::sync::mpsc::Sender<String>) -> Result<usize> {
    let count: usize = {
        let conn = db().lock().unwrap_or_else(|e| e.into_inner());
        conn.query_row("SELECT COUNT(*) FROM shards", [], |row| row.get(0))?
    };

    tokio::task::spawn_blocking(move || {
        let mut offset = 0;
        let batch_size = 10_000;
        loop {
            let hashes: Vec<String> = {
                let conn = db().lock().unwrap_or_else(|e| e.into_inner());
                let mut stmt = match conn
                    .prepare("SELECT hash FROM shards ORDER BY hash LIMIT ?1 OFFSET ?2")
                {
                    Ok(s) => s,
                    Err(e) => {
                        warn!("inventory: DB prepare failed: {}", e);
                        break;
                    }
                };
                match stmt.query_map(rusqlite::params![batch_size, offset], |row| row.get(0)) {
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
            offset += hashes.len() as i64;

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
    let existing: i64 = conn.query_row("SELECT COUNT(*) FROM shards", [], |r| r.get(0))?;
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
        // Clear stale entries before rebuilding
        conn.execute_batch("DELETE FROM shards")?;
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
            let mut stmt = tx
                .prepare_cached("INSERT OR IGNORE INTO shards (hash, stored_at) VALUES (?1, ?2)")?;
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

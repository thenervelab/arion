//! Shared helpers for opening redb databases with repair logging.

use std::mem::ManuallyDrop;
use std::path::Path;
use std::sync::{Arc, Mutex, OnceLock, Weak};

use tracing::{info, warn};

/// Global registry of database handles for emergency close during panic.
///
/// Stores `Weak` references so the registry does not prevent normal
/// graceful shutdown from succeeding via `Arc::into_inner`.
/// Uses `std::sync::Mutex` (not tokio) because panic hooks run outside
/// the async runtime.
static EMERGENCY_DBS: OnceLock<Mutex<Vec<Weak<RedbHandle>>>> = OnceLock::new();

/// Register a database handle for emergency close during panic.
///
/// Call this after opening each redb database. A `Weak` reference is
/// stored so this does not prevent `Arc::into_inner` during normal
/// graceful shutdown.
pub fn register_emergency_db(db: &Arc<RedbHandle>) {
    let dbs = EMERGENCY_DBS.get_or_init(|| Mutex::new(Vec::new()));
    // Recover from poisoned mutex -- in an emergency we need the data,
    // not consistency guarantees about the Vec.
    let mut vec = dbs.lock().unwrap_or_else(|e| e.into_inner());
    vec.push(Arc::downgrade(db));
}

/// Force-close all registered databases to write allocator state.
///
/// Intended to be called from a panic hook before `process::exit(1)`
/// to avoid expensive repair scans on restart. Upgrades each `Weak`
/// to `Arc` before closing; databases already dropped are skipped.
///
/// # Safety
///
/// Same constraints as [`emergency_close`]: caller must ensure no
/// concurrent database access is in progress and the process exits
/// immediately after this call.
pub unsafe fn emergency_close_all() {
    let Some(dbs) = EMERGENCY_DBS.get() else {
        return;
    };
    // Recover from poisoned mutex -- same rationale as register.
    let vec = dbs.lock().unwrap_or_else(|e| e.into_inner());
    for weak in vec.iter() {
        if let Some(db) = weak.upgrade() {
            unsafe { emergency_close(&db) };
        }
    }
}

/// A redb `Database` wrapped in `ManuallyDrop` so that `Database::Drop`
/// (which writes the allocator state) can be triggered explicitly during
/// shutdown rather than relying on all `Arc` references being released.
///
/// `ManuallyDrop<T>` implements `Deref<Target = T>`, so all `Database`
/// methods are available transparently.
pub type RedbHandle = ManuallyDrop<redb::Database>;

/// Force `Database::Drop` through a `ManuallyDrop` wrapper.
///
/// Call this only during emergency shutdown when normal `Arc::into_inner`
/// fails (e.g. leaked refs from a panicking `Router::Drop`). Writing the
/// allocator state avoids a slow repair scan on next startup.
///
/// # Safety
///
/// Caller must ensure no concurrent database access is in progress and
/// the process exits immediately after this call. The `Arc`'s pointee is
/// mutated in place, so any subsequent use is undefined behavior.
pub unsafe fn emergency_close(db: &Arc<RedbHandle>) {
    let ptr = Arc::as_ptr(db).cast_mut();
    unsafe { ManuallyDrop::drop(&mut *ptr) };
}

/// Open or create a redb database with repair logging.
///
/// Logs a warning if the database was not shut down cleanly and
/// requires repair. The repair itself is automatic and safe — it
/// rebuilds the allocator state by scanning committed data.
pub fn open_database(path: impl AsRef<Path>) -> Result<redb::Database, redb::DatabaseError> {
    let path = path.as_ref();
    let display_path = path.display().to_string();
    info!(path = %display_path, "Opening redb database");

    let log_path = display_path.clone();
    redb::Database::builder()
        .set_repair_callback(move |session: &mut redb::RepairSession| {
            if session.progress() < 0.01 {
                warn!(
                    path = %log_path,
                    "Database was not shut down cleanly, \
                     running repair (this may take a while for large databases)"
                );
            }
        })
        .create(path)
}

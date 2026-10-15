use super::*;
use crate::packed_store::PackedStore;
use std::collections::HashMap;

fn h(data: &[u8]) -> String {
    blake3::hash(data).to_hex().to_string()
}

fn blob(i: usize) -> Vec<u8> {
    format!("multi-root blob number {i:08}").into_bytes()
}

/// Faults a test can switch on for one root.
#[derive(Debug, Default)]
struct Faults {
    /// `read`/`read_at_most` fail with EIO.
    read_eio: AtomicBool,
    /// `store` fails with this errno.
    store_errno: Mutex<Option<i32>>,
    /// `read` returns bytes that do not match the name.
    corrupt_reads: AtomicBool,
    /// `list_hashes` panics: proves a listing streams.
    panic_on_list: AtomicBool,
}

#[derive(Debug)]
struct Faulty {
    inner: Arc<PackedStore>,
    faults: Arc<Faults>,
}

fn eio() -> std::io::Error {
    std::io::Error::from_raw_os_error(libc::EIO)
}

#[async_trait::async_trait]
impl BlobStore for Faulty {
    async fn store(&self, hash_hex: &str, data: &[u8]) -> std::io::Result<()> {
        if let Some(errno) = *self.faults.store_errno.lock().unwrap() {
            return Err(std::io::Error::from_raw_os_error(errno));
        }
        self.inner.store(hash_hex, data).await
    }
    fn inflight_headroom(&self, payload_len: u64) -> Option<InflightHeadroom> {
        self.inner.inflight_headroom(payload_len)
    }
    async fn read(&self, hash_hex: &str) -> std::io::Result<Bytes> {
        if self.faults.read_eio.load(Ordering::SeqCst) {
            return Err(eio());
        }
        if self.faults.corrupt_reads.load(Ordering::SeqCst) && self.inner.has(hash_hex) {
            return Ok(Bytes::from_static(b"rotten bytes"));
        }
        self.inner.read(hash_hex).await
    }
    async fn read_at_most(&self, hash_hex: &str, max_len: u64) -> std::io::Result<Bytes> {
        if self.faults.read_eio.load(Ordering::SeqCst) {
            return Err(eio());
        }
        self.inner.read_at_most(hash_hex, max_len).await
    }
    fn has(&self, hash_hex: &str) -> bool {
        self.inner.has(hash_hex)
    }
    fn blob_len(&self, hash_hex: &str) -> Option<u64> {
        self.inner.blob_len(hash_hex)
    }
    fn confirmed_absent(&self, hash_hex: &str) -> bool {
        self.inner.confirmed_absent(hash_hex)
    }
    async fn delete(&self, hash_hex: &str) -> std::io::Result<()> {
        self.inner.delete(hash_hex).await
    }
    async fn remove(&self, hash_hex: &str) -> std::io::Result<()> {
        self.inner.remove(hash_hex).await
    }
    async fn restore(&self, hash_hex: &str) -> std::io::Result<bool> {
        self.inner.restore(hash_hex).await
    }
    async fn purge_trashed(&self, hash_hex: &str) -> std::io::Result<()> {
        self.inner.purge_trashed(hash_hex).await
    }
    fn list_hashes(&self) -> Vec<String> {
        assert!(
            !self.faults.panic_on_list.load(Ordering::SeqCst),
            "listing materialized"
        );
        self.inner.list_hashes()
    }
    fn for_each_hash(&self, visit: &mut dyn FnMut(&str)) {
        self.inner.for_each_hash(visit)
    }
    fn list_trashed_hashes(&self) -> Vec<String> {
        self.inner.list_trashed_hashes()
    }
    fn has_trashed(&self, hash_hex: &str) -> bool {
        self.inner.has_trashed(hash_hex)
    }
    fn used_bytes(&self) -> u64 {
        self.inner.used_bytes()
    }
    fn trash_bytes(&self) -> u64 {
        self.inner.trash_bytes()
    }
    fn recompute_usage(&self) {
        self.inner.recompute_usage()
    }
    fn cleanup_stale_tmp(&self) -> usize {
        self.inner.cleanup_stale_tmp()
    }
    async fn migrate_legacy_layout(&self, batch: usize, pause: Duration) -> u64 {
        self.inner.migrate_legacy_layout(batch, pause).await
    }
    fn persist_on_clean_shutdown(&self) -> std::io::Result<()> {
        self.inner.persist_on_clean_shutdown()
    }
    fn store_is_durable(&self) -> bool {
        self.inner.store_is_durable()
    }
}

/// A set of root directories, a state dir and the faults of each root.
struct Bench {
    _tmp: tempfile::TempDir,
    roots: Vec<PathBuf>,
    state: PathBuf,
    faults: HashMap<PathBuf, Arc<Faults>>,
}

impl Bench {
    fn new(n: usize) -> Self {
        let tmp = tempfile::tempdir().unwrap();
        let roots: Vec<PathBuf> = (0..n)
            .map(|i| {
                let p = tmp.path().join(format!("disk{i:02}"));
                std::fs::create_dir_all(&p).unwrap();
                p
            })
            .collect();
        let state = tmp.path().join("data");
        let faults = roots
            .iter()
            .map(|r| (r.clone(), Arc::new(Faults::default())))
            .collect();
        Self {
            _tmp: tmp,
            roots,
            state,
            faults,
        }
    }

    fn factory(&self) -> Arc<RootFactory> {
        let faults = self.faults.clone();
        Arc::new(move |root: &Path| {
            let inner = PackedStore::open_with_limits(root.join("packed"), 1 << 20, 64 << 20)?;
            let faults = faults
                .get(root)
                .cloned()
                .unwrap_or_else(|| Arc::new(Faults::default()));
            Ok(Arc::new(Faulty { inner, faults }) as Arc<dyn BlobStore>)
        })
    }

    /// Every blob counts as held before (see `held_before`), so a write
    /// while a root is unusable is always a suspect.
    async fn open(&self) -> Arc<MultiRootStore> {
        let store = MultiRootStore::open(self.roots.clone(), self.factory(), &self.state, 0)
            .await
            .unwrap();
        store.set_held_before(|_| true);
        store
    }

    fn faults(&self, i: usize) -> &Faults {
        &self.faults[&self.roots[i]]
    }

    fn pending(&self) -> String {
        std::fs::read_to_string(self.state.join(PENDING_FILE)).unwrap_or_default()
    }
}

/// Which roots hold `hash` live.
fn holders(store: &MultiRootStore, hash: &str) -> Vec<usize> {
    (0..store.root_count())
        .filter(|&i| store.root_store(i).is_some_and(|s| s.has(hash)))
        .collect()
}

#[tokio::test]
async fn writes_spread_over_the_roots_and_read_back() {
    let bench = Bench::new(3);
    let store = bench.open().await;
    for i in 0..300 {
        store.store(&h(&blob(i)), &blob(i)).await.unwrap();
    }
    let mut per_root = [0usize; 3];
    for i in 0..300 {
        let hash = h(&blob(i));
        let at = holders(&store, &hash);
        assert_eq!(at.len(), 1, "one copy per blob");
        per_root[at[0]] += 1;
        assert!(store.has(&hash));
        assert_eq!(store.read(&hash).await.unwrap().as_ref(), &blob(i)[..]);
        assert_eq!(store.blob_len(&hash), Some(blob(i).len() as u64));
    }
    // Equal disks (same filesystem, same free space) take turns.
    for n in per_root {
        assert!((90..=110).contains(&n), "unbalanced: {per_root:?}");
    }
    let mut listed = Vec::new();
    store.for_each_hash(&mut |h| listed.push(h.to_string()));
    listed.sort();
    listed.dedup();
    assert_eq!(listed.len(), 300);
    assert_eq!(
        store.used_bytes(),
        (0..300).map(|i| blob(i).len() as u64).sum::<u64>()
    );
    assert!(store.read(&h(b"never")).await.unwrap_err().kind() == std::io::ErrorKind::NotFound);
    assert!(store.confirmed_absent(&h(b"never")));
}

#[tokio::test]
async fn delete_restore_remove_across_roots() {
    let bench = Bench::new(2);
    let store = bench.open().await;
    let data = blob(1);
    let hash = h(&data);
    store.store(&hash, &data).await.unwrap();
    let home = holders(&store, &hash)[0];

    store.delete(&hash).await.unwrap();
    assert!(!store.has(&hash) && store.has_trashed(&hash));
    assert_eq!(store.list_trashed_hashes(), vec![hash.clone()]);
    assert!(store.read(&hash).await.is_err());
    assert!(
        !store.confirmed_absent(&hash),
        "a trash copy is not absence"
    );

    assert!(store.restore(&hash).await.unwrap());
    assert_eq!(holders(&store, &hash), vec![home]);
    assert!(!store.has_trashed(&hash));

    // A re-store after a delete goes back to the root that has the trash
    // copy: never a second copy elsewhere.
    store.delete(&hash).await.unwrap();
    for _ in 0..5 {
        store.store(&hash, &data).await.unwrap();
    }
    assert_eq!(holders(&store, &hash), vec![home]);

    store.remove(&hash).await.unwrap();
    assert!(!store.has(&hash) && !store.has_trashed(&hash));
    assert!(store.confirmed_absent(&hash));
    assert!(!store.restore(&hash).await.unwrap());
}

#[tokio::test]
async fn a_full_root_takes_no_new_writes_but_still_serves() {
    let bench = Bench::new(3);
    let store = bench.open().await;
    let old = blob(0);
    store.store(&h(&old), &old).await.unwrap();
    let home = holders(&store, &h(&old))[0];
    store.force_state(home, RootState::Full);

    for i in 1..60 {
        store.store(&h(&blob(i)), &blob(i)).await.unwrap();
        assert_ne!(holders(&store, &h(&blob(i))), vec![home]);
    }
    assert_eq!(store.read(&h(&old)).await.unwrap().as_ref(), &old[..]);
    let space = store.disk_space().unwrap();
    assert!(space.total > 0);

    // A re-store of a blob whose root is full lands elsewhere and the
    // full root's copy is dropped: still one copy.
    store.store(&h(&old), &old).await.unwrap();
    let now = holders(&store, &h(&old));
    assert_eq!(now.len(), 1);
    assert_ne!(now[0], home);

    // Mutations still reach a full root.
    store.force_state(home, RootState::Full);
    let other = (1..60)
        .map(|i| h(&blob(i)))
        .find(|x| holders(&store, x) != vec![home])
        .unwrap();
    store.delete(&other).await.unwrap();
    assert!(!store.has(&other));
}

#[tokio::test]
async fn enospc_on_write_marks_the_root_full_and_falls_back() {
    let bench = Bench::new(2);
    let store = bench.open().await;
    *bench.faults(0).store_errno.lock().unwrap() = Some(libc::ENOSPC);
    for i in 0..20 {
        store.store(&h(&blob(i)), &blob(i)).await.unwrap();
        assert_eq!(holders(&store, &h(&blob(i))), vec![1]);
    }
    assert_eq!(store.status()[0].state, RootState::Full);
    // The probe sees space again: back to healthy, writes resume there.
    *bench.faults(0).store_errno.lock().unwrap() = None;
    store.probe_all().await;
    store.settle().await;
    assert_eq!(store.status()[0].state, RootState::Healthy);
    // The fallback writes were suspects; one copy each, nothing removed.
    let report = store.resolve_suspects().await.unwrap();
    assert_eq!(report.duplicates_removed, 0);
    assert!(!bench.pending().contains("S "));
}

#[tokio::test]
async fn no_writable_root_fails_the_write() {
    let bench = Bench::new(2);
    let store = bench.open().await;
    store.force_state(0, RootState::Full);
    store.force_state(1, RootState::Full);
    let err = store.store(&h(&blob(0)), &blob(0)).await.unwrap_err();
    assert_eq!(err.kind(), std::io::ErrorKind::StorageFull);
    assert_eq!(store.disk_space().unwrap().available, 0);
}

#[tokio::test]
async fn io_errors_take_a_root_down_without_crashing() {
    let bench = Bench::new(2);
    let store = bench.open().await;
    let mut on_root0 = Vec::new();
    for i in 0..40 {
        let hash = h(&blob(i));
        store.store(&hash, &blob(i)).await.unwrap();
        if holders(&store, &hash) == vec![0] {
            on_root0.push(hash);
        }
    }
    assert!(on_root0.len() >= DOWN_AFTER_IO_ERRORS as usize);
    bench.faults(0).read_eio.store(true, Ordering::SeqCst);
    for hash in on_root0.iter().take(DOWN_AFTER_IO_ERRORS as usize) {
        assert!(store.read(hash).await.is_err());
    }
    assert_eq!(store.status()[0].state, RootState::Down);

    // Down: its blobs are reported absent (the network re-places them),
    // but never as a confirmed absence, and the listing skips it.
    for hash in &on_root0 {
        assert!(!store.has(hash));
        assert_eq!(
            store.read(hash).await.unwrap_err().kind(),
            std::io::ErrorKind::NotFound
        );
        assert!(!store.confirmed_absent(hash));
    }
    let mut listed = 0usize;
    store.for_each_hash(&mut |_| listed += 1);
    assert_eq!(listed, 40 - on_root0.len());
    // Writes keep flowing to the healthy root.
    store.store(&h(b"later"), b"later").await.unwrap();
    assert_eq!(holders(&store, &h(b"later")), vec![1]);
    assert!(store.render_prometheus().contains("state=\"down\""));

    // The disk recovers (same device): the probe reintegrates it.
    bench.faults(0).read_eio.store(false, Ordering::SeqCst);
    store.probe_all().await;
    store.settle().await;
    assert_eq!(store.status()[0].state, RootState::Healthy);
    assert!(on_root0.iter().all(|x| store.has(x)));
}

#[tokio::test]
async fn deletes_while_a_root_is_down_are_replayed_on_its_return() {
    let bench = Bench::new(2);
    let store = bench.open().await;
    let mut on_root1 = Vec::new();
    for i in 0..30 {
        let hash = h(&blob(i));
        store.store(&hash, &blob(i)).await.unwrap();
        if holders(&store, &hash) == vec![1] {
            on_root1.push(hash);
        }
    }
    let (deleted, removed, kept) = (&on_root1[0], &on_root1[1], &on_root1[2]);
    store.force_state(1, RootState::Down);
    store.delete(deleted).await.unwrap();
    store.remove(removed).await.unwrap();
    let pending = bench.pending();
    assert!(pending.contains(&format!("D {deleted} ")), "{pending}");
    assert!(pending.contains(&format!("R {removed} ")), "{pending}");
    // Only the usable root's capacity is reported.
    let one = store.disk_space().unwrap();
    assert!(one.total > 0);

    store.probe_all().await;

    store.settle().await;
    assert_eq!(store.status()[1].state, RootState::Healthy);
    assert!(
        !store.has(deleted) && store.has_trashed(deleted),
        "trashed, restorable"
    );
    assert!(!store.has(removed) && !store.has_trashed(removed));
    assert!(store.has(kept));
    assert!(!bench.pending().contains(" D ") && !bench.pending().contains(&root_key(&bench, 1)));
}

fn root_key(bench: &Bench, i: usize) -> String {
    bench.roots[i].display().to_string()
}

#[tokio::test]
async fn a_deferred_delete_survives_a_restart() {
    let bench = Bench::new(2);
    let hash;
    {
        let store = bench.open().await;
        let mut found = None;
        for i in 0..30 {
            let x = h(&blob(i));
            store.store(&x, &blob(i)).await.unwrap();
            if found.is_none() && holders(&store, &x) == vec![1] {
                found = Some(x);
            }
        }
        hash = found.unwrap();
        store.force_state(1, RootState::Down);
        store.delete(&hash).await.unwrap();
        store.persist_on_clean_shutdown().unwrap();
    }
    // The root opens normally at the next start; its own index still has
    // the blob live, the pending file trashes it before it is served.
    tokio::time::sleep(Duration::from_millis(50)).await;
    let store = bench.open().await;
    assert!(!store.has(&hash));
    assert!(store.has_trashed(&hash));
    assert!(bench.pending().is_empty());
}

#[tokio::test]
async fn an_offline_root_is_opened_when_it_appears() {
    let bench = Bench::new(2);
    let missing = bench.roots[1].clone();
    std::fs::remove_dir(&missing).unwrap();
    let store = bench.open().await;
    assert_eq!(store.status()[1].state, RootState::Offline);
    assert!(!missing.exists(), "a missing root is never created");
    store.store(&h(b"a"), b"a").await.unwrap();
    store.delete(&h(b"a")).await.unwrap();
    assert!(!store.confirmed_absent(&h(b"zz")));

    std::fs::create_dir_all(&missing).unwrap();
    store.probe_all().await;
    store.settle().await;
    assert_eq!(store.status()[1].state, RootState::Healthy);
    assert!(read_marker(&missing).unwrap().is_some());
    for i in 0..20 {
        store.store(&h(&blob(i)), &blob(i)).await.unwrap();
    }
    assert!((0..20).any(|i| holders(&store, &h(&blob(i))) == vec![1]));
    // The deferred delete was replayed and dropped; the write made while
    // the root was away stays a duplicate suspect until resolved.
    assert!(!bench.pending().contains("D "), "{}", bench.pending());
    store.resolve_suspects().await.unwrap();
    assert!(bench.pending().is_empty());
}

#[tokio::test]
async fn a_duplicate_is_resolved_to_the_first_verifying_root() {
    let bench = Bench::new(2);
    let store = bench.open().await;
    let data = blob(7);
    let hash = h(&data);
    // An old copy on root 1 (the disk was away when the blob was written
    // again): root 1 down, the write lands on root 0 as a suspect.
    store
        .root_store(1)
        .unwrap()
        .store(&hash, &data)
        .await
        .unwrap();
    store.force_state(1, RootState::Down);
    store.store(&hash, &data).await.unwrap();
    assert!(bench.pending().contains(&format!("S {hash} -")));
    // While a root is unusable nothing is resolved.
    assert!(
        store
            .resolve_suspects()
            .await
            .unwrap()
            .skipped_roots_unusable
    );

    store.probe_all().await;

    store.settle().await;
    assert_eq!(holders(&store, &hash), vec![0, 1]);
    // Reads take the first; both copies are identical.
    assert_eq!(store.read(&hash).await.unwrap().as_ref(), &data[..]);
    let mut listed = 0;
    store.for_each_hash(&mut |x| listed += usize::from(x == hash));
    assert_eq!(listed, 1, "a duplicate is listed once");

    let report = store.resolve_suspects().await.unwrap();
    assert_eq!(report.duplicates_removed, 1);
    assert_eq!(holders(&store, &hash), vec![0]);
    assert!(!bench.pending().contains("S "));
}

#[tokio::test]
async fn a_blob_never_held_is_no_suspect() {
    let bench = Bench::new(2);
    let store = bench.open().await;
    store.set_held_before(|_| false);
    store.force_state(1, RootState::Down);
    store.store(&h(b"fresh"), b"fresh").await.unwrap();
    assert!(!bench.pending().contains("S "), "{}", bench.pending());
}

#[tokio::test]
async fn a_duplicate_keeps_the_copy_that_verifies() {
    let bench = Bench::new(2);
    let store = bench.open().await;
    let data = blob(8);
    let hash = h(&data);
    store
        .root_store(1)
        .unwrap()
        .store(&hash, &data)
        .await
        .unwrap();
    store.force_state(1, RootState::Down);
    store.store(&hash, &data).await.unwrap();
    store.probe_all().await;
    store.settle().await;
    bench.faults(0).corrupt_reads.store(true, Ordering::SeqCst);
    let report = store.resolve_suspects().await.unwrap();
    assert_eq!(report.duplicates_removed, 1);
    assert_eq!(holders(&store, &hash), vec![1]);
}

#[tokio::test]
async fn listing_streams_every_root_without_materializing() {
    let bench = Bench::new(3);
    let store = bench.open().await;
    for i in 0..90 {
        store.store(&h(&blob(i)), &blob(i)).await.unwrap();
    }
    for i in 0..3 {
        bench.faults(i).panic_on_list.store(true, Ordering::SeqCst);
    }
    let mut n = 0usize;
    store.for_each_hash(&mut |_| n += 1);
    assert_eq!(n, 90);
}

#[tokio::test]
async fn a_root_listed_twice_is_refused() {
    let bench = Bench::new(1);
    let link = bench._tmp.path().join("alias");
    std::os::unix::fs::symlink(&bench.roots[0], &link).unwrap();
    for paths in [
        vec![bench.roots[0].clone(), bench.roots[0].clone()],
        vec![bench.roots[0].clone(), link.clone()],
    ] {
        let err = MultiRootStore::open(paths, bench.factory(), &bench.state, 0)
            .await
            .unwrap_err();
        assert_eq!(err.kind(), std::io::ErrorKind::InvalidInput);
    }
}

#[tokio::test]
async fn an_unsplit_packed_root_is_refused() {
    let bench = Bench::new(2);
    // A packed store written in single-path mode on root 1.
    {
        let p = PackedStore::open_with_limits(bench.roots[1].join("packed"), 1 << 20, 64 << 20)
            .unwrap();
        p.store(&h(b"x"), b"x").await.unwrap();
    }
    let err = MultiRootStore::open(bench.roots.clone(), bench.factory(), &bench.state, 0)
        .await
        .unwrap_err();
    assert_eq!(err.kind(), std::io::ErrorKind::InvalidData);
    assert!(err.to_string().contains("split-union-index"), "{err}");
}

#[test]
fn markers_admit_fresh_roots_and_guard_single_path_mode() {
    let dir = tempfile::tempdir().unwrap();
    refuse_member_root(dir.path()).unwrap();
    let m = admit_root(dir.path()).unwrap();
    assert_eq!(read_marker(dir.path()).unwrap(), Some(m.clone()));
    assert_eq!(admit_root(dir.path()).unwrap(), m, "stable");
    assert_eq!(
        refuse_member_root(dir.path()).unwrap_err().kind(),
        std::io::ErrorKind::InvalidData
    );
    std::fs::write(dir.path().join(ROOT_MARKER), "garbage").unwrap();
    assert!(read_marker(dir.path()).is_err());
    let split = RootMarker::fresh(Some("abc".into()));
    assert_eq!(RootMarker::decode(&split.encode()), Some(split));
}

#[test]
fn pending_file_drops_a_torn_tail_and_rewrites() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join(PENDING_FILE);
    std::fs::write(&path, "D aa /r0\nS bb -\nP cc /r 1\nD dd /r").unwrap();
    let mut log = PendingLog::open(&path).unwrap();
    assert_eq!(
        std::fs::read_to_string(&path).unwrap(),
        "D aa /r0\nS bb -\nP cc /r 1\n"
    );
    assert_eq!(log.suspects, 1);
    let (lines, _) = read_chunk(&path, 0, log.len().unwrap(), 100).unwrap();
    assert_eq!(lines[2].1.root, "/r 1", "paths may hold spaces");
    log.append(
        &PendingLine {
            op: PendingOp::Remove,
            hash: "ee".into(),
            root: "/r0".into(),
        },
        true,
    )
    .unwrap();
    log.rewrite(|_, l| l.root != "/r0").unwrap();
    assert_eq!(
        std::fs::read_to_string(&path).unwrap(),
        "S bb -\nP cc /r 1\n"
    );
    // A file that is a single torn line is emptied.
    std::fs::write(&path, "D ff /x").unwrap();
    let log = PendingLog::open(&path).unwrap();
    assert_eq!(log.len().unwrap(), 0);
}

#[test]
fn errors_are_classified() {
    let os = std::io::Error::from_raw_os_error;
    assert_eq!(classify(&os(libc::ENOSPC)), ErrClass::Full);
    assert_eq!(classify(&os(libc::EROFS)), ErrClass::Gone);
    assert_eq!(classify(&os(libc::ENOTCONN)), ErrClass::Gone);
    assert_eq!(classify(&os(libc::EIO)), ErrClass::Io);
    assert_eq!(classify(&os(libc::ENOENT)), ErrClass::Blob);
    assert_eq!(
        classify(&std::io::Error::from(std::io::ErrorKind::BrokenPipe)),
        ErrClass::Gone
    );
    assert_eq!(
        classify(&std::io::Error::new(std::io::ErrorKind::InvalidData, "crc")),
        ErrClass::Blob
    );
}

#[tokio::test]
async fn capacity_counts_one_filesystem_once() {
    let bench = Bench::new(3);
    let store = bench.open().await;
    let space = store.disk_space().unwrap();
    let fs_total = fs2::total_space(&bench.roots[0]).unwrap();
    assert_eq!(space.total, fs_total, "three roots on one filesystem");
    store.set_free(0, 0);
    assert!(
        store.disk_space().unwrap().available <= fs2::available_space(&bench.roots[0]).unwrap()
    );
}

/// Write throughput with N roots vs 1 (`cargo test -p miner --release --
/// --ignored multi_root_write_throughput --nocapture`). Every root here
/// sits on the same filesystem, so this measures the routing and the
/// per-root writers/fsyncs running in parallel, not separate spindles.
/// `MULTI_ROOT_BENCH_DIRS` (comma separated, one directory per disk)
/// runs it on real disks instead.
#[tokio::test(flavor = "multi_thread", worker_threads = 8)]
#[ignore]
async fn multi_root_write_throughput() {
    const BLOBS: usize = 20_000;
    const BLOB_LEN: usize = 4096;
    const CONCURRENCY: usize = 64;
    let real: Vec<PathBuf> = std::env::var("MULTI_ROOT_BENCH_DIRS")
        .map(|v| v.split(',').map(PathBuf::from).collect())
        .unwrap_or_default();
    let max_roots = if real.is_empty() { 8 } else { real.len() };
    let mut n = 1;
    while n <= max_roots {
        let tmp = tempfile::tempdir().unwrap();
        let roots: Vec<PathBuf> = (0..n)
            .map(|i| {
                let base = real
                    .get(i)
                    .cloned()
                    .unwrap_or_else(|| tmp.path().to_path_buf());
                let p = base.join(format!("bench-root-{i:02}-{}", new_id()));
                std::fs::create_dir_all(&p).unwrap();
                p
            })
            .collect();
        let factory: Arc<RootFactory> = Arc::new(move |root: &Path| {
            let s = PackedStore::open_with_limits(root.join("packed"), 1 << 30, 256 << 20)?;
            Ok(s as Arc<dyn BlobStore>)
        });
        let store = MultiRootStore::open(roots.clone(), factory, &tmp.path().join("state"), 0)
            .await
            .unwrap();
        let started = std::time::Instant::now();
        let next = Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let mut tasks = Vec::new();
        for _ in 0..CONCURRENCY {
            let store = Arc::clone(&store);
            let next = Arc::clone(&next);
            tasks.push(tokio::spawn(async move {
                loop {
                    let i = next.fetch_add(1, Ordering::Relaxed);
                    if i >= BLOBS {
                        break;
                    }
                    let mut data = vec![0u8; BLOB_LEN];
                    data[..8].copy_from_slice(&(i as u64).to_le_bytes());
                    data[8..16].copy_from_slice(&(n as u64).to_le_bytes());
                    store.store(&h(&data), &data).await.unwrap();
                }
            }));
        }
        for t in tasks {
            t.await.unwrap();
        }
        let secs = started.elapsed().as_secs_f64();
        println!(
            "roots={n} blobs={BLOBS} blob_len={BLOB_LEN} concurrency={CONCURRENCY} secs={secs:.2} blobs_per_sec={:.0} mib_per_sec={:.1}",
            BLOBS as f64 / secs,
            (BLOBS * BLOB_LEN) as f64 / secs / (1 << 20) as f64
        );
        drop(store);
        for r in &roots {
            let _ = std::fs::remove_dir_all(r);
        }
        n *= 2;
    }
}

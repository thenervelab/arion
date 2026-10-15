use super::*;
use crate::multi_root_store::{MultiRootStore, RootFactory};
use crate::packed_store::PackedStore;
use crate::store::BlobStore;
use std::sync::Arc;

fn h(data: &[u8]) -> String {
    blake3::hash(data).to_hex().to_string()
}

fn blob(i: usize) -> Vec<u8> {
    let mut v = vec![(i % 251) as u8; 90 * 1024];
    v[..8].copy_from_slice(&(i as u64).to_le_bytes());
    v
}

/// What the union store holds, by hash.
struct Expected {
    live: Vec<(String, Vec<u8>)>,
    trashed: Vec<String>,
    gone: Vec<String>,
    /// Stored again after its delete: live after a clean stop, trashed
    /// when the open replays the journal tail over a rescanned volume
    /// (the single-root behaviour documented in `packed_store`, which the
    /// split preserves as is).
    restored_after_delete: String,
}

/// A union directory whose packed volumes are hard-linked into `n`
/// branch directories, round-robin by volume id: through `union` every
/// volume is visible (as through a union mount), each branch sees only
/// its own (as on the disk itself). The union's index directory is also
/// copied onto branch 1, where a union mount would have put it.
struct Layout {
    _tmp: tempfile::TempDir,
    union: PathBuf,
    branches: Vec<PathBuf>,
    expected: Expected,
}

async fn layout(n: usize, clean_shutdown: bool) -> Layout {
    let tmp = tempfile::tempdir().unwrap();
    let union = tmp.path().join("union");
    std::fs::create_dir_all(&union).unwrap();
    let mut expected = Expected {
        live: Vec::new(),
        trashed: Vec::new(),
        gone: Vec::new(),
        restored_after_delete: h(&blob(8)),
    };
    {
        let store = PackedStore::open_with_target(union.join("packed"), 1 << 20).unwrap();
        for i in 0..60 {
            store.store(&h(&blob(i)), &blob(i)).await.unwrap();
        }
        // Trashed, purged for good, restored, and re-stored after a delete
        // (the case a full rescan plus journal replay gets wrong).
        for i in 0..10 {
            store.delete(&h(&blob(i))).await.unwrap();
        }
        for i in 0..3 {
            store.purge_trashed(&h(&blob(i))).await.unwrap();
        }
        store.restore(&h(&blob(9))).await.unwrap();
        store.store(&h(&blob(8)), &blob(8)).await.unwrap();
        if clean_shutdown {
            store.write_snapshot().unwrap();
        }
        for i in 0..60 {
            let hash = h(&blob(i));
            match i {
                0..=2 => expected.gone.push(hash),
                3..=7 => expected.trashed.push(hash),
                8 if !clean_shutdown => expected.trashed.push(hash),
                _ => expected.live.push((hash, blob(i))),
            }
        }
    }
    tokio::time::sleep(std::time::Duration::from_millis(50)).await;
    let branches: Vec<PathBuf> = (0..n)
        .map(|i| {
            let b = tmp.path().join(format!("disk{i:02}"));
            std::fs::create_dir_all(b.join("packed").join("volumes")).unwrap();
            b
        })
        .collect();
    let vols = list_volume_ids(&union.join("packed").join("volumes")).unwrap();
    assert!(vols.len() >= 4, "several volumes: {vols:?}");
    for v in vols {
        let src = volume_path(&union.join("packed").join("volumes"), v);
        let dst = volume_path(&branches[v as usize % n].join("packed").join("volumes"), v);
        std::fs::hard_link(src, dst).unwrap();
    }
    if n > 1 {
        let idx = branches[1].join("packed").join("index");
        std::fs::create_dir_all(&idx).unwrap();
        for e in std::fs::read_dir(union.join("packed").join("index")).unwrap() {
            let e = e.unwrap();
            std::fs::copy(e.path(), idx.join(e.file_name())).unwrap();
        }
    }
    Layout {
        _tmp: tmp,
        union,
        branches,
        expected,
    }
}

fn factory() -> Arc<RootFactory> {
    Arc::new(|root: &Path| {
        let s = PackedStore::open_with_limits(root.join("packed"), 1 << 20, 64 << 20)?;
        Ok(s as Arc<dyn BlobStore>)
    })
}

async fn open_multi(l: &Layout) -> Arc<MultiRootStore> {
    MultiRootStore::open(
        l.branches.clone(),
        factory(),
        &l._tmp.path().join("data"),
        0,
    )
    .await
    .unwrap()
}

async fn assert_state(store: &MultiRootStore, e: &Expected) {
    for (hash, data) in &e.live {
        assert!(store.has(hash), "live {hash}");
        assert_eq!(store.read(hash).await.unwrap().as_ref(), &data[..]);
    }
    for hash in &e.trashed {
        assert!(
            !store.has(hash) && store.has_trashed(hash),
            "trashed {hash}"
        );
    }
    for hash in &e.gone {
        assert!(!store.has(hash) && !store.has_trashed(hash), "gone {hash}");
    }
    let mut n = 0;
    store.for_each_hash(&mut |_| n += 1);
    assert_eq!(n, e.live.len());
}

#[tokio::test]
async fn split_preserves_live_trash_and_deletes() {
    for clean in [true, false] {
        let l = layout(3, clean).await;
        let report = split_union_index(&l.union, &l.branches, false).unwrap();
        assert!(!report.resumed && !report.nothing_to_split);
        assert_eq!(
            report.roots.iter().map(|r| r.live).sum::<u64>(),
            l.expected.live.len() as u64
        );
        assert_eq!(
            report.roots.iter().map(|r| r.trash).sum::<u64>(),
            l.expected.trashed.len() as u64
        );
        for b in &l.branches {
            let m = read_marker(b).unwrap().unwrap();
            assert_eq!(m.split.as_deref(), Some(report.split_id.as_str()));
            assert!(!b.join("packed").join(STAGING).exists());
        }
        // The stale index copy where the union kept it is set aside.
        assert!(
            l.branches[1]
                .join("packed")
                .join(format!("index.union-{}", report.split_id))
                .is_dir()
        );
        let store = open_multi(&l).await;
        assert_state(&store, &l.expected).await;
        // Restorable after the split.
        assert!(store.restore(&l.expected.trashed[0]).await.unwrap());
        // A rerun after completion does nothing.
        drop(store);
        let again = split_union_index(&l.union, &l.branches, false).unwrap();
        assert!(again.resumed);
    }
}

#[tokio::test]
async fn split_refuses_a_missing_branch_and_a_volume_on_two_branches() {
    let l = layout(3, true).await;
    let err = split_union_index(&l.union, &l.branches[..2], false).unwrap_err();
    assert_eq!(err.kind(), std::io::ErrorKind::InvalidData);
    assert!(err.to_string().contains("no listed branch"), "{err}");
    for b in &l.branches {
        assert!(read_marker(b).unwrap().is_none(), "nothing committed");
    }

    let v0 = list_volume_ids(&l.branches[0].join("packed").join("volumes")).unwrap()[0];
    std::fs::hard_link(
        volume_path(&l.branches[0].join("packed").join("volumes"), v0),
        volume_path(&l.branches[2].join("packed").join("volumes"), v0),
    )
    .unwrap();
    let err = split_union_index(&l.union, &l.branches, false).unwrap_err();
    assert!(err.to_string().contains("two branches"), "{err}");
}

#[tokio::test]
async fn a_dry_run_writes_nothing_on_the_branches() {
    let l = layout(2, true).await;
    let report = split_union_index(&l.union, &l.branches, true).unwrap();
    assert!(report.dry_run);
    assert_eq!(
        report.roots.iter().map(|r| r.live).sum::<u64>(),
        l.expected.live.len() as u64
    );
    for b in &l.branches {
        assert!(read_marker(b).unwrap().is_none());
        assert!(!b.join("packed").join(STAGING).exists());
    }
}

#[tokio::test]
async fn an_interrupted_commit_is_finished_by_a_rerun() {
    let l = layout(3, true).await;
    let id = "deadbeefdeadbeef";
    prepare(&l.union, &l.branches, id, false).unwrap();
    // Crash after the first branch committed, and in the middle of the
    // second one (old index set aside, staging not yet renamed).
    commit_root(&l.branches[0], id).unwrap();
    let packed1 = l.branches[1].join("packed");
    std::fs::rename(
        packed1.join("index"),
        packed1.join(format!("index.union-{id}")),
    )
    .unwrap();

    let report = split_union_index(&l.union, &l.branches, false).unwrap();
    assert!(report.resumed);
    assert_eq!(report.split_id, id);
    let store = open_multi(&l).await;
    assert_state(&store, &l.expected).await;
}

#[tokio::test]
async fn a_first_commit_cut_between_its_renames_is_finished() {
    let l = layout(3, true).await;
    let id = "feedfacefeedface";
    prepare(&l.union, &l.branches, id, false).unwrap();
    // Crash in the first commit, between its two renames, on the branch
    // holding the union's index: no branch is committed yet and the union
    // view has no index any more; the rerun must finish, not report
    // "nothing to split".
    let packed1 = l.branches[1].join("packed");
    std::fs::rename(
        packed1.join("index"),
        packed1.join(format!("index.union-{id}")),
    )
    .unwrap();
    std::fs::rename(
        l.union.join("packed").join("index"),
        l.union.join("packed").join("index.gone"),
    )
    .unwrap();
    let report = split_union_index(&l.union, &l.branches, false).unwrap();
    assert!(report.resumed && !report.nothing_to_split);
    let store = open_multi(&l).await;
    assert_state(&store, &l.expected).await;
}

#[tokio::test]
async fn a_prepare_cut_short_is_redone_from_scratch() {
    let l = layout(2, true).await;
    prepare(&l.union, &l.branches, "aaaaaaaaaaaaaaaa", false).unwrap();
    // Branch 1's staging lost its READY (crash before it was written).
    std::fs::remove_file(l.branches[1].join("packed").join(STAGING).join(READY)).unwrap();
    let report = split_union_index(&l.union, &l.branches, false).unwrap();
    assert!(!report.resumed);
    assert_ne!(report.split_id, "aaaaaaaaaaaaaaaa");
    let store = open_multi(&l).await;
    assert_state(&store, &l.expected).await;
}

#[tokio::test]
async fn a_torn_branch_table_rebuilds_with_the_copied_journal() {
    let l = layout(3, true).await;
    split_union_index(&l.union, &l.branches, false).unwrap();
    for b in &l.branches {
        // Unstamp the header: the table is rebuilt from that branch's
        // volumes plus its journal at the next open.
        let p = b.join("packed").join("index").join("live.idx");
        let mut bytes = std::fs::read(&p).unwrap();
        bytes[4..8].copy_from_slice(&0u32.to_le_bytes());
        std::fs::write(&p, bytes).unwrap();
    }
    let store = open_multi(&l).await;
    for (hash, data) in &l.expected.live {
        if *hash == l.expected.restored_after_delete {
            continue; // re-trashed by the full replay, as on a single root
        }
        assert_eq!(store.read(hash).await.unwrap().as_ref(), &data[..]);
    }
    for hash in l.expected.trashed.iter().chain(&l.expected.gone) {
        assert!(!store.has(hash), "deleted blob resurrected: {hash}");
    }
}

#[tokio::test]
async fn a_single_path_store_is_adopted_in_place() {
    let l = layout(1, true).await;
    // One root that is the union itself: the plain single-disk node.
    let root = l.union.clone();
    let report = split_union_index(&root, std::slice::from_ref(&root), false).unwrap();
    assert_eq!(report.roots.len(), 1);
    let store = MultiRootStore::open(vec![root], factory(), &l._tmp.path().join("data"), 0)
        .await
        .unwrap();
    assert_state(&store, &l.expected).await;
}

#[tokio::test]
async fn nothing_to_split_without_a_packed_index() {
    let tmp = tempfile::tempdir().unwrap();
    let a = tmp.path().join("a");
    let b = tmp.path().join("b");
    let u = tmp.path().join("u");
    for d in [&a, &b, &u] {
        std::fs::create_dir_all(d).unwrap();
    }
    let report = split_union_index(&u, &[a.clone(), b.clone()], false).unwrap();
    assert!(report.nothing_to_split);
    assert!(read_marker(&a).unwrap().is_none());
    assert!(!u.join("packed").exists(), "the union is not touched");
}

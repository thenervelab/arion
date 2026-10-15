//! Split the packed index of a union mount into one index per branch.
//!
//! A union mount (a union filesystem with a create policy that puts
//! each new file wholly on one branch) presents the branches' directories
//! as one tree. A packed store run on it has its volume files spread over
//! the branches, each file on exactly one, while its index files
//! (`packed/index/{live.idx,snapshot.bin,journal.log}`) sit on whichever
//! branch received them. Listing the branches directly in `STORAGE_PATHS`
//! therefore needs no data moved, only an index per branch describing that
//! branch's volumes. That index cannot be rebuilt from the volumes alone:
//! deletions live in the journal, not in the volumes, and a full rescan
//! plus replay re-trashes blobs stored again after their delete. So the
//! split derives each branch's index from the union store's exact state:
//!
//! 1. **Check** the layout: every volume id seen through the union is on
//!    exactly one listed branch and nowhere else, with the length the
//!    union's index covers. A volume on two branches (a relocation the
//!    union filesystem left half done), a volume on no listed branch (a
//!    branch missing from the list) or an extra one refuses the split.
//! 2. **Load** the union store as a miner start would (snapshot, volume
//!    tails, journal replay; no writer).
//! 3. **Prepare** `packed/index.split/` on every branch: a fresh live table
//!    with the entries whose volume is on that branch, a snapshot with that
//!    branch's watermarks and trash entries, a full copy of the union
//!    journal (ops on names the branch never held are no-ops, and a torn
//!    table later falls back to a full scan plus this journal, exactly as
//!    on a single root), the branch's [`RootMarker`] and a `READY` file
//!    naming the split run, each fsynced.
//! 4. **Commit**, once every branch is ready: per branch, the old
//!    `packed/index` (if the branch has one) is renamed to
//!    `packed/index.union-<split>` (kept as a backup, never deleted here),
//!    `index.split` becomes `index`, and the marker is written last.
//!
//! Crash-safe and idempotent: before the first commit a rerun discards the
//! staging directories and starts over; after it, a rerun only finishes the
//! commit of the branches still staged (it never loads the union again,
//! whose view mixes old and new index files by then). Nothing is read or
//! moved in the volumes beyond the union open's tail scan.

use std::collections::HashMap;
use std::path::{Path, PathBuf};

use super::{
    IndexState, LoadedState, Loc, MmapLiveIndex, TrashEntry, list_volume_ids, load_state,
    volume_path, write_snapshot_file,
};
use crate::multi_root_store::{RootMarker, read_marker, sync_dir, write_marker};

const STAGING: &str = "index.split";
const READY: &str = "READY";

/// What a split did (or would do, on a dry run).
#[derive(Debug, Clone, Default)]
pub(crate) struct SplitReport {
    pub split_id: String,
    pub roots: Vec<SplitRootReport>,
    /// The run only finished an interrupted commit.
    pub resumed: bool,
    /// The union holds no packed index: nothing to split.
    pub nothing_to_split: bool,
    pub dry_run: bool,
    /// Volume bytes the union open had to rescan: 0 after a clean stop of
    /// the miner. More means the union index was older than its volumes,
    /// and the open replayed the journal tail over the rescanned records,
    /// which trashes a blob stored again after its delete (the documented
    /// single-root behaviour, carried over as is).
    pub union_scanned_bytes: u64,
}

#[derive(Debug, Clone, Default)]
pub(crate) struct SplitRootReport {
    pub root: PathBuf,
    pub volumes: usize,
    pub live: u64,
    pub trash: u64,
    pub live_bytes: u64,
}

fn invalid(msg: String) -> std::io::Error {
    std::io::Error::new(std::io::ErrorKind::InvalidData, msg)
}

fn read_ready(dir: &Path) -> std::io::Result<Option<String>> {
    match std::fs::read_to_string(dir.join(READY)) {
        Ok(s) => Ok(Some(s.trim().to_string())),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(e) => Err(e),
    }
}

/// Where one branch stands with respect to a split run.
#[derive(Debug, PartialEq, Eq)]
enum BranchState {
    /// Nothing of a split here.
    Untouched,
    /// Prepared for run `.0`, not committed.
    Staged(String),
    /// Committed for run `.0` (index swapped, marker maybe not yet written).
    Committed(String),
    /// Member of a multi-root set created without a split.
    FreshMember,
}

fn branch_state(root: &Path) -> std::io::Result<BranchState> {
    let packed = root.join("packed");
    if let Some(m) = read_marker(root)? {
        return Ok(match m.split {
            Some(s) => BranchState::Committed(s),
            None => BranchState::FreshMember,
        });
    }
    if let Some(s) = read_ready(&packed.join("index"))? {
        return Ok(BranchState::Committed(s));
    }
    if let Some(s) = read_ready(&packed.join(STAGING))? {
        // The old index already set aside: the commit of this branch had
        // started (a crash between its two renames).
        if packed.join(format!("index.union-{s}")).exists() {
            return Ok(BranchState::Committed(s));
        }
        return Ok(BranchState::Staged(s));
    }
    Ok(BranchState::Untouched)
}

fn check_roots(union: &Path, roots: &[PathBuf]) -> std::io::Result<()> {
    if roots.is_empty() {
        return Err(invalid("no branch root given".into()));
    }
    let canon_union = std::fs::canonicalize(union)?;
    let mut seen = Vec::new();
    for r in roots {
        let c = std::fs::canonicalize(r)
            .map_err(|e| std::io::Error::new(e.kind(), format!("{}: {e}", r.display())))?;
        if !c.is_dir() {
            return Err(invalid(format!("{}: not a directory", r.display())));
        }
        if seen.contains(&c) {
            return Err(invalid(format!("{} is listed twice", r.display())));
        }
        if roots.len() > 1 && c == canon_union {
            return Err(invalid(format!(
                "{} is the union path itself, list the branches",
                r.display()
            )));
        }
        seen.push(c);
    }
    Ok(())
}

/// Split the packed index of the store at `union` (the blob directory as
/// seen through the union mount, i.e. the former `STORAGE_PATH`) into one
/// index per branch blob directory in `roots`. With a single root equal to
/// `union`, adopts a plain single-path store into a one-root set. The
/// miner must be stopped. See the module docs.
pub(crate) fn split_union_index(
    union: &Path,
    roots: &[PathBuf],
    dry_run: bool,
) -> std::io::Result<SplitReport> {
    check_roots(union, roots)?;
    let states: Vec<BranchState> = roots
        .iter()
        .map(|r| branch_state(r))
        .collect::<std::io::Result<_>>()?;
    if let Some(i) = states.iter().position(|s| *s == BranchState::FreshMember) {
        return Err(invalid(format!(
            "{} is already a member of a multi-root set (created without a split), refusing",
            roots[i].display()
        )));
    }
    let committed: Vec<&String> = states
        .iter()
        .filter_map(|s| match s {
            BranchState::Committed(id) => Some(id),
            _ => None,
        })
        .collect();
    if let Some(&id) = committed.first() {
        let id = id.clone();
        for (r, s) in roots.iter().zip(&states) {
            match s {
                BranchState::Committed(x) | BranchState::Staged(x) if *x == id => {}
                other => {
                    return Err(invalid(format!(
                        "{}: inconsistent with split {id} in progress ({other:?}); restore the branch or finish by hand",
                        r.display()
                    )));
                }
            }
        }
        let mut report = SplitReport {
            split_id: id.clone(),
            resumed: true,
            dry_run,
            ..Default::default()
        };
        if !dry_run {
            commit_all(roots, &id)?;
        }
        report.roots = roots
            .iter()
            .map(|r| SplitRootReport {
                root: r.clone(),
                ..Default::default()
            })
            .collect();
        return Ok(report);
    }

    let split_id = crate::multi_root_store::new_id();
    let mut report = prepare(union, roots, &split_id, dry_run)?;
    if report.nothing_to_split || dry_run {
        return Ok(report);
    }
    commit_all(roots, &split_id)?;
    report.split_id = split_id;
    Ok(report)
}

/// Phases 1 to 3 (module docs). On a dry run, checks and counts only.
pub(crate) fn prepare(
    union: &Path,
    roots: &[PathBuf],
    split_id: &str,
    dry_run: bool,
) -> std::io::Result<SplitReport> {
    let union_packed = union.join("packed");
    let mut report = SplitReport {
        split_id: split_id.to_string(),
        dry_run,
        ..Default::default()
    };
    if !union_packed.join("index").is_dir() {
        report.nothing_to_split = true;
        return Ok(report);
    }

    // Phase 1: who holds which volume.
    let mut owner: HashMap<u32, usize> = HashMap::new();
    let mut per_root_vols: Vec<Vec<u32>> = Vec::with_capacity(roots.len());
    for (i, r) in roots.iter().enumerate() {
        let vdir = r.join("packed").join("volumes");
        let vols = match list_volume_ids(&vdir) {
            Ok(v) => v,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Vec::new(),
            Err(e) => return Err(e),
        };
        for &v in &vols {
            if let Some(&j) = owner.get(&v) {
                return Err(invalid(format!(
                    "volume {v} is on two branches: {} and {} (an interrupted relocation by the union filesystem?); keep the complete copy, remove the other, rerun",
                    volume_path(&roots[j].join("packed").join("volumes"), v).display(),
                    volume_path(&vdir, v).display(),
                )));
            }
            owner.insert(v, i);
        }
        per_root_vols.push(vols);
    }

    if !dry_run {
        for r in roots {
            let staging = r.join("packed").join(STAGING);
            if staging.exists() {
                std::fs::remove_dir_all(&staging)?;
            }
        }
    }

    // Phase 2: the union's exact state.
    let st: LoadedState = load_state(&union_packed)?;
    report.union_scanned_bytes = st.scanned_on_open;
    if st.scanned_on_open > 0 {
        tracing::warn!(
            scanned_bytes = st.scanned_on_open,
            "split: the union store was not stopped cleanly (volume tails rescanned); a clean stop of the miner before the split avoids it"
        );
    }
    let union_vols: std::collections::BTreeSet<u32> = st.vol_ids.iter().copied().collect();
    let branch_vols: std::collections::BTreeSet<u32> = owner.keys().copied().collect();
    let missing: Vec<u32> = union_vols.difference(&branch_vols).copied().collect();
    let extra: Vec<u32> = branch_vols.difference(&union_vols).copied().collect();
    if !missing.is_empty() || !extra.is_empty() {
        return Err(invalid(format!(
            "branch list does not match the union: volumes on no listed branch {:?}, volumes on a branch but not in the union {:?} (first 10 of each)",
            &missing[..missing.len().min(10)],
            &extra[..extra.len().min(10)]
        )));
    }
    for (&v, &i) in &owner {
        let path = volume_path(&roots[i].join("packed").join("volumes"), v);
        let len = std::fs::metadata(&path)?.len();
        let covered = st.idx.indexed_len.get(&v).copied().unwrap_or(0);
        if len != covered {
            return Err(invalid(format!(
                "{}: {len} bytes on the branch, the union index covers {covered}",
                path.display()
            )));
        }
    }

    report.roots = roots
        .iter()
        .zip(&per_root_vols)
        .map(|(r, v)| SplitRootReport {
            root: r.clone(),
            volumes: v.len(),
            ..Default::default()
        })
        .collect();
    let idx: &IndexState = &st.idx;
    let mut dropped = 0u64;
    idx.live.for_each(|_, loc| match owner.get(&loc.vol) {
        Some(&i) => {
            report.roots[i].live += 1;
            report.roots[i].live_bytes += loc.payload_len as u64;
        }
        None => dropped += 1,
    });
    let mut trash_of: Vec<Vec<&TrashEntry>> = vec![Vec::new(); roots.len()];
    for t in idx.trash.values() {
        if let Some(&i) = owner.get(&t.loc.vol) {
            trash_of[i].push(t);
        } else {
            dropped += 1;
        }
    }
    for (i, t) in trash_of.iter().enumerate() {
        report.roots[i].trash = t.len() as u64;
    }
    if dropped > 0 {
        // Only reachable for an index entry whose volume file exists
        // nowhere, which the union store could not read either.
        tracing::warn!(
            dropped,
            "split: index entries pointing at no volume file, left out"
        );
    }
    if dry_run {
        return Ok(report);
    }

    // Phase 3: staging on every branch.
    let mut tables: Vec<MmapLiveIndex> = Vec::with_capacity(roots.len());
    for r in roots {
        let staging = r.join("packed").join(STAGING);
        std::fs::create_dir_all(&staging)?;
        let (table, _) = MmapLiveIndex::open(&staging.join("live.idx"))?;
        tables.push(table);
    }
    let mut insert_err: Option<std::io::Error> = None;
    idx.live.for_each(|key, loc: Loc| {
        if insert_err.is_some() {
            return;
        }
        if let Some(&i) = owner.get(&loc.vol)
            && let Err(e) = tables[i].insert(key, loc)
        {
            insert_err = Some(e);
        }
    });
    if let Some(e) = insert_err {
        return Err(e);
    }
    let union_journal = union_packed.join("index").join("journal.log");
    for (i, r) in roots.iter().enumerate() {
        let packed = r.join("packed");
        let staging = packed.join(STAGING);
        let jlen = copy_journal(&union_journal, &staging.join("journal.log"))?;
        let mut watermarks: Vec<(u32, u64)> = per_root_vols[i]
            .iter()
            .map(|v| (*v, idx.indexed_len.get(v).copied().unwrap_or(0)))
            .collect();
        watermarks.sort_unstable();
        write_snapshot_file(
            &staging.join("snapshot.bin"),
            jlen,
            &watermarks,
            trash_of[i].iter().copied(),
        )?;
        tables[i].flush()?;
        std::fs::create_dir_all(packed.join("volumes"))?;
        write_file_synced(&staging.join(READY), split_id.as_bytes())?;
        sync_dir(&staging)?;
        sync_dir(&packed)?;
    }
    drop(tables);
    drop(st);
    Ok(report)
}

/// Phase 4 on every branch (module docs).
pub(crate) fn commit_all(roots: &[PathBuf], split_id: &str) -> std::io::Result<()> {
    for r in roots {
        commit_root(r, split_id)?;
    }
    Ok(())
}

pub(crate) fn commit_root(root: &Path, split_id: &str) -> std::io::Result<()> {
    if let Some(m) = read_marker(root)? {
        if m.split.as_deref() == Some(split_id) {
            return Ok(());
        }
        return Err(invalid(format!(
            "{}: marker of another set ({m:?})",
            root.display()
        )));
    }
    let packed = root.join("packed");
    let index = packed.join("index");
    let staging = packed.join(STAGING);
    if read_ready(&index)?.as_deref() != Some(split_id) {
        if read_ready(&staging)?.as_deref() != Some(split_id) {
            return Err(invalid(format!(
                "{}: not prepared for split {split_id}",
                root.display()
            )));
        }
        if index.exists() {
            let backup = packed.join(format!("index.union-{split_id}"));
            if backup.exists() {
                return Err(invalid(format!(
                    "{} and {} both exist, refusing to guess",
                    index.display(),
                    backup.display()
                )));
            }
            std::fs::rename(&index, &backup)?;
        }
        std::fs::rename(&staging, &index)?;
        sync_dir(&packed)?;
    }
    write_marker(root, &RootMarker::fresh(Some(split_id.to_string())))
}

/// Copy the union journal (never truncated, a few ops per second) and
/// fsync the copy. Returns its length.
fn copy_journal(from: &Path, to: &Path) -> std::io::Result<u64> {
    let mut out = std::fs::File::create(to)?;
    let n = match std::fs::File::open(from) {
        Ok(mut src) => std::io::copy(&mut src, &mut out)?,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => 0,
        Err(e) => return Err(e),
    };
    out.sync_all()?;
    Ok(n)
}

fn write_file_synced(path: &Path, data: &[u8]) -> std::io::Result<()> {
    use std::io::Write;
    let mut f = std::fs::File::create(path)?;
    f.write_all(data)?;
    f.sync_all()
}

#[cfg(test)]
mod tests;

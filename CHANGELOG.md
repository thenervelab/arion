# Changelog

All notable changes to this project will be documented in this file.

## [0.1.30] - 2026-08-24

### Miner

- **Fix auto-update on split-volume installs**: the updater staged the
  downloaded binary in the service working directory, then `rename(2)`d it
  over the installed executable. When the data directory and the executable
  live on different filesystems the rename fails with `EXDEV` (os error 18)
  and the node retries forever — downloading and discarding the full binary
  every cycle without ever updating. The download is now staged in the
  executable's own directory (same-filesystem, atomic rename), with a
  durable copy + fsync + rename fallback if the rename still crosses
  filesystems. Version verification before the swap and backup/restore on
  failure are unchanged; staging files are removed on any failure instead of
  being left behind.
- **Fix flat→packed mover stall on giant flat roots**: the mover listed the
  data root to discover the shard directories before moving anything. On
  nodes still mid-way through the 0.1.28 flat→sharded migration that root
  can hold tens of millions of flat `.bin` entries, so the mover blocked in
  that enumeration indefinitely — zero blobs drained, and no log output to
  show it. Shard directories are now discovered by probing the 256 possible
  names per level (one `stat` each, no root listing) and the small `ab/cd`
  leaf directories are drained first for immediate progress; the legacy
  flat roots are drained last, streamed in bounded pages from a held
  readdir cursor so the listing is never materialized. The mover logs its
  progress every 60 s (phase, moved, bytes, skipped, blobs/s) and announces
  each phase. Throttle defaults raised to `PACKED_MIGRATE_BATCH=1000` /
  `PACKED_MIGRATE_PAUSE_MS=100` (~10k blobs/s ceiling; the filesystem is
  the real limiter — a node holding tens of millions of blobs drains in
  hours, not years).

## [0.1.29] - 2026-08-24

### Miner

- **Packed blob store (opt-in, dormant by default)**: new `STORE_BACKEND=packed`
  backend storing blobs in large append-only volume files instead of one file
  per blob. Reed-Solomon striping makes the shard population dominated by tiny
  shards (bench measurements: median ~100 bytes, >90% under 4 KiB), so nodes
  holding tens of millions of shards drown in filesystem metadata — the packed
  layout reduces the store to a few thousand inodes: one sequential append per
  write, one `pread` per read.
  - A store is acknowledged only after `fdatasync` of its volume (group
    commit): an acked shard is durable.
  - Records are self-describing (name + CRC in the header): volumes are the
    sole source of truth and the in-RAM index is a rebuildable cache. Torn
    tails from crashes are detected and truncated on open.
  - Two-phase deletes (trash / restore / purge) are preserved via a small
    fsync'd op journal; per-volume dead-byte counters are maintained for a
    future compaction pass.
- **Flat → packed background migration**: selecting the packed backend on a
  data dir with existing per-file blobs serves reads through a hybrid (packed
  first, flat fallback) while a throttled background task drains the flat
  layout — 100% local (read local, append local, unlink local), resumable,
  idempotent, with a `blake3(payload) == name` integrity check before every
  move (corrupt files are left in place and logged, never carried forward).
  Emptied shard directories are removed. Throttle via `PACKED_MIGRATE_BATCH` /
  `PACKED_MIGRATE_PAUSE_MS`.
- **`BlobStore` trait**: consumers no longer name the storage backend;
  `FlatBlobStore` (default, unchanged behavior) and `PackedStore` both
  implement it. Rollback note: volumes written by the packed backend cannot be
  read by older binaries — keep `STORE_BACKEND=flat` (the default) unless
  opting a node in deliberately.

## [0.1.28] - 2026-08-15

### Miner

- **Sharded blob layout**: blobs now live under `storage/<h[0:2]>/<h[2:4]>/`
  (65,536 leaf directories) instead of one flat directory. Fixes the ext4
  `dir_index` ENOSPC at ~10M entries and the ZFS dnode-read storms that made
  every enumeration and restart walk prohibitively slow on large nodes.
  Reads fall back to the legacy flat path; writes always go sharded; a
  throttled background migrator renames legacy entries into the sharded tree
  (same-filesystem renames — metadata-only, no data copied; resumable).
  The trash uses the same sharded layout.
- **Stale write artifacts are cleaned at startup**: crash-leftover `.tmp.*`
  files at the store root and day-old `.tmp/*.part` entries are removed.
- Inventory rebuild and usage accounting walk both layouts.

## [0.1.27] - 2026-08-14

### Miner

- **Restarts are no longer blocked by a full store walk**. `FlatBlobStore::new`
  used to `stat` every blob to compute disk usage — a dnode read per file on
  ZFS, so on nodes holding millions of blobs it ran for hours *after* logging
  "Ready for P2P connections", during which the miner never registered, never
  heartbeated and stored nothing. Sizing now runs in the background
  (`recompute_usage`), and it only feeds storage reporting.
- **Inventory reconciliation moved off the startup path**: the filesystem
  rebuild and trash reconciliation run in a background task, so registration
  and heartbeats start immediately.
- **`ListAllBlobs` / `ListBlobsPage` answer `WARMING_UP` until the inventory
  reflects what is on disk**, so a partial holding is never recorded as a
  complete, successful scan (which would look like data loss to the validator).

## [0.1.26] - 2026-08-13

### Miner

- **Two-phase deletes (trash)**: `Delete` now renames blobs into a local
  `trash/` directory instead of unlinking. Trashed blobs stop being listed,
  served, or counted against the quota, but stay restorable for
  `TRASH_TTL_SECS` (default 14 days, cap `TRASH_MAX_BYTES`, opt out with
  `TRASH_ENABLED=false`). A background loop purges expired entries; the
  SQLite inventory carries the retention clock (`trashed_at`) and is
  reconciled with the trash directory at startup.
- **New `RestoreBlob` control message** (validator-signed, like `Delete`):
  brings a trashed blob back into the live store with no data transfer —
  a wrongly deleted shard can be repopulated instantly instead of waiting
  for a full repair.

## [0.1.25] - 2026-07-21

### Miner

- **Keyset inventory pagination**: `stream_all_hashes` now pages its SQLite
  inventory with keyset pagination (`WHERE hash > ? ORDER BY hash`) instead of
  `LIMIT/OFFSET` — O(log n) per batch. Fixes validator-side inventory scans
  timing out on multi-million-blob inventories (OFFSET was O(n²) over depth).
- **New `ListBlobsPage` control message**: serves ONE bounded keyset page of
  blob hashes per request (limit clamped to 200k). Enables resumable,
  per-page-bounded inventory scans; per-request miner cost is a single
  indexed range query.

### Common

- **v3 (straw2) placement now auto-filters draining miners**, matching v1/v2
  and the validator write path. Fixes miner self-rebalance (and any caller
  passing a raw cluster map) converging shards toward a placement the writer
  never used whenever draining miners existed.

## [0.1.9] - 2026-03-06

### Miner

#### Reliability

- Extracted hardcoded timeouts and magic numbers into `constants.rs` (`VERSION_CHECK_TIMEOUT_SECS`, `CONNECTION_POOL_EVICTION_FRACTION`, `MANIFEST_RESPONSE_MAX_SIZE`, `POOLED_CONN_DEFAULT_TIMEOUT_SECS`, etc.)
- Improved handling of manifest stream timeouts and limits (`MANIFEST_STREAM_OPEN_TIMEOUT_SECS`, `MANIFEST_READ_TIMEOUT_SECS`, `MANIFEST_RESPONSE_MAX_SIZE`)
- Manifest fetching gracefully handles `NOT_FOUND` instead of throwing an error
- Rebalance task aborts if consecutive manifest failures exceed `MAX_CONSECUTIVE_MANIFEST_FAILURES`
- Improved robustness in orphan garbage collection (accumulates and logs `tag_delete_failures` and `file_delete_failures`)

## [0.1.3] - 2026-02-20

### Miner

#### Performance

- Connection reuse in heartbeat loop (persistent QUIC connection cached across heartbeats)
- Tag map for O(1) shard deletion (new TAG_MAP DashMap eliminates full tag scan on Delete)
- PoS commitment cache (LRU, 100 entries) avoids rebuilding Poseidon2 Merkle trees
- Miner UID computed once at startup (stored in OnceLock)
- PG assignment caching (recomputed only on epoch change)
- V1 JSON parsing uses from_slice (SIMD-enabled) instead of from_reader chain
- Send window reduced 64MB to 16MB, receive window bounded to 64MB

#### Reliability

- Direct UDP path enforcement on Store, FetchBlob, PullFromPeer (relay-only rejected)
- Hole-punching wait before registration (configurable p2p_direct_wait_secs, default 30s)
- Exponential backoff with jitter on heartbeat failures (30s/60s/120s cap)
- Validator warmup handling (short 5s retry when validator returns WARMING_UP)
- Validator reachability flag gates rebalance loop

#### Networking

- IPv4/IPv6 bind support (bind_ipv4/bind_ipv6 config + P2P_BIND_IPV4/P2P_BIND_IPV6 env vars)
- Hostname-to-IP resolution for registration (sends resolved IP in endpoint hints)

#### Rebalance

- Pre-built local hash set (single directory walk, O(1) lookups)
- Connection-multiplexed manifest fetches (single QUIC conn, 16 concurrent streams)
- Chunked PG batch queries (500 PGs per request, prevents validator OOM)
- Randomized startup jitter + inter-tick jitter to desynchronize miners
- Orphan tracking uses typed Hash keys instead of String

#### Removed

- HTTP server (handlers.rs, axum/axum-server/openssl deps, MINER_HTTP_ENABLED flag)
- HTTP port config (network.port field, PORT env var)
- AppState struct (was for HTTP handlers)

#### Config

- store_concurrency default: 64 to 1024
- New: p2p_direct_wait_secs (default 30s)
- Warden node IDs now auto-distributed via heartbeat (no manual config)

### Common

- New `CheckBlob` variant in `MinerControlMessage` for lightweight metadata-only existence checks

### pos-circuits

- Edition bump to 2024, version 0.1.2

## [0.1.2] - 2025-02-12

### Miner

#### Concurrency

- Raised `MAX_CONCURRENT_HANDLERS` from 1000 to 2048
- Default `store_concurrency` increased from 64 to 1024

#### P2P Transport

- QUIC transport tuning: 120s idle timeout, 16384 concurrent bidirectional streams, 64MB send window
- Rate-limited handler now sends error response instead of silently dropping
- Detailed peer context added to timeout error messages
- Registration flow refactored into standalone `build_validator_addr()` helper

#### Recovery

- Full rewrite of rebalance module with epoch lookback
- Active shard recovery via peer P2P pulling
- HTTP cluster map fetching as fallback

#### Misc

- `decode_ticket` binary uses `anyhow::Result` instead of unwrap
- Connection pool cleanup uses imperative loop instead of `retain()`
- Added `MINER_ONBOARDING.md` deployment guide
- Added `run-miner.sh` and `run-30-miners.sh` helper scripts

### Common

- `MinerNode`: added `ip_address` and `integrity_fails` fields
- `ClusterMap`: derived `Default`, added `ensure_defaults()` validation
- New `GatewayUploadHeader` type for streaming uploads
- New `SubmitterControlMessage::SyncEpoch` variant
- CRUSH placement: added tries parameter to sharding placement (default 3)
- Audit loop cleanup and map misalignment fixes

## [0.1.1] - 2025-01-15

Initial public release with miner, gateway, validator, warden, chain-submitter,
and common crate.

# Miner

Storage node for Hippius Arion. Receives shards from validators via P2P, stores them locally, and serves them to gateways and other miners.

## Quick Start

```bash
# Build
cargo build -p miner --release

# Run (requires validator to be running)
cargo run --bin miner -- --validator-node-id <node_id> --hostname <your-public-ipv4>

# Run with config file
cp miner.example.toml miner.toml
cargo run --bin miner

# Generate keypair for new miner identity
cargo run --bin generate_keypair -- --output data/miner
```

## Networking

The miner uses **UDP port 11220** for iroh P2P communication. This port **must be open for inbound UDP traffic** in your firewall and hosting provider.

**`--hostname` must be your server's public IPv4 address.** The validator uses this address to establish direct P2P connections. Setting it to `0.0.0.0`, `localhost`, or a private/Docker IP means the validator cannot reach your miner and it will not receive shards.

STUN-based auto-detection is enabled by default and discovers your public IP automatically. If auto-detection works for your network, you can omit `--hostname`. For servers with multiple interfaces or Docker installed, set it explicitly.

```bash
# Find your public IP
curl -4 ifconfig.me

# Verify UDP port is reachable (from another machine)
echo test | nc -u -w2 <your-public-ip> 11220
```

Docker bridge networking is **not supported**. Run the miner directly on the host. If Docker is installed but the miner runs natively, set `P2P_BIND_IPV4` to your public IP to avoid advertising the `docker0` address.

### Firewall & Conntrack (UFW / iptables)

If your server uses a firewall with `INPUT DROP` policy (e.g. UFW), you **must** ensure the Linux conntrack UDP timeout is high enough to keep QUIC connections alive.

The miner communicates with the validator over QUIC (UDP). Linux conntrack tracks outbound UDP flows and allows return traffic. By default, the conntrack timeout for "unreplied" UDP flows is **30 seconds**, which is too short — QUIC path probing will consider the path dead and abandon the connection.

**Required sysctl setting:**

```bash
# Check current values
sysctl net.netfilter.nf_conntrack_udp_timeout
sysctl net.netfilter.nf_conntrack_udp_timeout_stream

# Set both to 120 seconds (must be >= QUIC idle timeout)
sudo sysctl -w net.netfilter.nf_conntrack_udp_timeout=120
sudo sysctl -w net.netfilter.nf_conntrack_udp_timeout_stream=120

# Persist across reboots
echo 'net.netfilter.nf_conntrack_udp_timeout=120' | sudo tee -a /etc/sysctl.conf
echo 'net.netfilter.nf_conntrack_udp_timeout_stream=120' | sudo tee -a /etc/sysctl.conf
```

**Symptoms of a too-low timeout:**
- Miner registers successfully but loses connection ~30s later
- Logs show: `[DISCONNECTED] Lost connection to validator` or `no viable network path exists: last path abandoned by peer`
- Re-registration attempts fail with `connect timeout` or `server refused to accept a new connection`

> **Note:** This primarily affects miners on networks outside the validator's local network (e.g. different hosting providers). Miners on the same network (e.g. same vRack/VLAN) are typically unaffected.

## Configuration

Copy `miner.example.toml` to `miner.toml`:

```toml
[network]
hostname = "203.0.113.10"  # YOUR public IPv4 - not 0.0.0.0 or localhost
p2p_port = 11220
family_id = "default"

[storage]
path = "data/miner/blobs"
max_storage_gb = 0  # unlimited

[validator]
node_id = "<validator_node_id>"

[tuning]
store_concurrency = 64
pull_concurrency = 32
fetch_concurrency = 256
```

## Auto-Update

The miner includes a built-in auto-update mechanism that checks GitHub releases every 5 minutes and automatically upgrades to newer versions.

**How it works:**
1. Every 5 minutes, the miner queries `https://api.github.com/repos/thenervelab/arion/releases/latest`
2. Compares the latest release tag (semver) with the running version
3. If a newer version is available, downloads the `miner-linux-x86_64` asset
4. Verifies the downloaded binary by running `--version`
5. Stops the service, replaces the binary, restarts
6. If the service fails to start, automatically rolls back to the previous binary

**Downgrade protection:** The miner will never downgrade. If the running version is higher than the latest release (e.g. dev builds), the update is skipped.

**Disable auto-update:**

```bash
# Option 1: Environment variable (in systemd service file)
Environment="AUTO_UPDATE_DISABLED=true"

# Option 2: Sentinel file (in data directory)
touch /var/lib/hippius/miner/data/miner/.no-auto-update
```

**Service name:** The update mechanism restarts via `systemctl restart arion-miner`. Override with `MINER_SERVICE_NAME` env var if your service has a different name.

## Environment Variables

| Variable | Default | Purpose |
|----------|---------|---------|
| `HOSTNAME` | auto-detected via STUN | Public IPv4 address (must be routable) |
| `P2P_PORT` | 11220 | UDP port for QUIC P2P |
| `P2P_BIND_IPV4` | 0.0.0.0 | IPv4 address to bind to |
| `FAMILY_ID` | default | Miner family ID |
| `VALIDATOR_NODE_ID` | required | Validator's node ID (hex-encoded Ed25519 public key) |
| `VALIDATOR_DIRECT_ADDRS` | - | Validator socket address for quinn transport (e.g. `51.210.230.161:11220`) |
| `WARDEN_NODE_ID` | - | Warden node ID for PoS challenges |
| `IROH_RELAY_URL` | iroh defaults | Relay server URL |
| `STUN_ENABLED` | true | Auto-detect public IP via STUN |
| `AUTO_UPDATE_DISABLED` | false | Set to `true` to disable auto-update |
| `MINER_SERVICE_NAME` | arion-miner | Systemd service name for restart |
| `MINER_STORE_CONCURRENCY` | 1024 | Concurrent store operations |
| `MINER_PULL_CONCURRENCY` | 32 | Concurrent pull operations |
| `MINER_FETCH_CONCURRENCY` | 256 | Concurrent fetch operations |
| `PACKED_INFLIGHT_MAX_BYTES` | RAM/8, 256 MiB..4 GiB | In-flight write budget of the packed store (see "Resource limits"); with several storage roots, each root gets an equal share (at least 8 MiB) |
| `STORAGE_PATHS` | - | Comma-separated absolute paths, one storage root per disk; overrides `STORAGE_PATH` (see "Multiple storage roots") |
| `STORAGE_ROOT_RESERVE_BYTES` | 4294967296 (4 GiB) | Free bytes a storage root keeps out of new writes (multi-root only) |
| `STORAGE_ROOT_PROBE_SECS` | 15 | Health probe interval of the storage roots (multi-root only) |
| `MINER_MAX_CONCURRENT_HANDLERS` | budget/3 MiB, 256..8192 | Cap on concurrent inbound P2P stream handlers (see "Resource limits") |
| `MINER_QUIC_MAX_INCOMING` | 1024 | Inbound QUIC connection attempts queued before the miner handles them; beyond it new attempts get an immediate CONNECTION_REFUSED (>= 1) |
| `MINER_QUIC_STALE_INCOMING_SECS` | 5 | An attempt that waited this long before being handled is refused (CONNECTION_REFUSED) instead of being dropped silently at the 30 s QUIC idle timeout (1..29); invalid values stop the miner at startup |
| `PG_LISTS_BASE_URL` | `https://s3.hippius.com/pg-inventory` | Root URL of the obligation lists (`current.json`, `gen/<g>/...`); set it empty to leave purge and backfill without a source (off) |
| `PURGE_ENABLED` | true | Obligation-list purge loop (see "Operator guide"); deletes (two-phase trash) unless `PURGE_DRY_RUN=true` |
| `PURGE_DRY_RUN` | false | `true`: census only, count and log, delete nothing. Default `false` since 0.1.36 (was `true`) |
| `BACKFILL_ENABLED` | false | Obligation-list backfill loop (see "Operator guide") |
| `BACKFILL_LOCAL_SOURCE_DIRS` | - | Comma-separated absolute paths of flat store roots set aside on this node; the backfill reads each missing shard there (direct path, never a directory listing) before asking peers (see "Importing a set-aside flat store") |
| `BACKFILL_LOCAL_SOURCE_DELETE` | false | Move instead of copy: unlink each set-aside file once its blob is durably in the live store, reads back verified and has its inventory row (or was already held with one); honoured only on a pure packed store (`STORE_BACKEND=packed`, no flat data left to migrate; strict boolean, a typo fails startup) |
| `BACKFILL_LOCAL_CONCURRENCY` | 64 | Local lookups in flight (1..256); disk-bound, not charged to `BACKFILL_MAX_BYTES_PER_SEC` |
| `BACKFILL_DISCOVERY_CONCURRENCY` | 8 | PG lists fetched, verified and looked up in the inventory at once during backfill discovery (1..64); results are still consumed in PG order |
| `EPOCH_ARCHIVE_KEEP` | 2000 | Most recent cluster-map epochs kept in `data_dir/epoch_archive/`; older ones are deleted (placement reads of an older epoch ask the validator) |

## Operator guide: obligation lists (0.1.34)

The validator publishes, per placement group (PG), the list of shards every
holder of that PG is obliged to keep (`PG_LISTS_BASE_URL/current.json` →
`gen/<generation>/manifest.json`, signed with the validator key, → one binary
list per PG). From those lists the miner derives two background loops:

- **purge** — trash every live blob that is in none of the lists of the PGs
  this miner owns or owned within the last 6 h (an orphan: its file was deleted, or the shard moved
  elsewhere long ago). Two-phase: the blob goes to the local trash and stays
  restorable for `TRASH_TTL_SECS` (14 days by default).
- **backfill** — fetch from peer miners every blob a list says this miner
  should hold but its inventory lacks.

0.1.33 carried only the counting half of the purge and no backfill at all.
**0.1.34 is the first release whose binary can act**, and it still does
nothing until told to: `PURGE_ENABLED` and `BACKFILL_ENABLED` default to
`false`, and an enabled purge defaults to `PURGE_DRY_RUN=true`. Booleans take
exactly `1`/`true`/`yes`/`on` or `0`/`false`/`no`/`off`; any other spelling
refuses to start the miner rather than guess.

**From 0.1.35 the census runs by default**: `PURGE_ENABLED` defaults to
`true` and `PG_LISTS_BASE_URL` to the public bucket, while `PURGE_DRY_RUN`
stays `true`. Every miner classifies its blobs and reports what it would
reclaim; nothing is deleted until the operator sets `PURGE_DRY_RUN=false`.
The census downloads this miner's holder sets and the live filter (a few GB
per generation, cached under `data_dir/pg-lists-cache/`). `PURGE_ENABLED=false`
turns it off.

**From 0.1.36 the purge deletes by default**: `PURGE_DRY_RUN` defaults to
`false`. Every gate below still applies (14-day minimum age, 6 h per-PG
ownership window, complete coverage, generation and view freshness), and a
deleted blob goes to the local trash, restorable for `TRASH_TTL_SECS` (14
days) before it is gone. To keep the census only, set `PURGE_DRY_RUN=true`;
to turn the loop off, `PURGE_ENABLED=false`. Either takes effect at the next
restart.

### Before the purge deletes anything

Every one of these must hold, in this order, or the pass keeps everything
and logs why:

0. the node's uid is listed in the cluster map it holds, and not as
   draining nor under a placement hold. A node at weight 0 (quarantined,
   declared full) is still listed and follows the same rules as every
   other node: what it owned in the last 6 h stays protected, and after
   that its old unlisted blobs can be purged, which is how a node
   declared full frees space. A node that was down (or whose clock
   jumped) for more than a few minutes treats everything it owned as
   owned until its restart and waits a full 6 h before purging;
1. a generation is loaded and its manifest signature verifies against
   `VALIDATOR_NODE_ID`;
2. the generation is at most `PURGE_GENERATION_MAX_AGE_SECS` old (7 days),
   and the view is fresh: the newest signed cut folded into it (the last
   applied delta's end, else the base's signed cut; never a field of the
   unsigned `current.json`) is at most `PURGE_VIEW_MAX_LAG_SECS` old
   (2 h, checked at pass start and before every delete). Deltas are
   hourly, so a healthy node always runs on a view up to about an hour
   old; the 14-day age rule, the moved class and the trash are what make
   that lag safe. A stale or replayed pointer is just an older view, and
   past the bound nothing is deleted. The purge state in the data
   directory (`purge_generation`, `purge_ownership`) must also be readable
   and writable: a failed write or a malformed file closes the purge until
   a write succeeds;
3. every PG of the **protected set** (item 4) is covered by the loaded
   lists and the delta chain is whole (`coverage incomplete for the
   protected set` otherwise). A pass re-checks this before every delete and
   stops as soon as it no longer holds (a PG gained, a chain broken); it
   resumes from where it stopped once coverage is back;
4. the per-PG ownership window has been tracked for
   `PURGE_OWNERSHIP_STABLE_SECS` (6 h). Ownership for the purge is the v3
   (straw2) placement only: v2 data is no longer readable and the v2
   placement reshuffles most of a node's PGs at every epoch. For every PG
   the node records when it first and last owned it (persisted in the data
   directory, `purge_ownership`); the protected set is every PG owned now
   plus every PG owned at any time in the last `PURGE_OWNERSHIP_STABLE_SECS`.
   Its lists are all loaded, so a blob listed in a PG lost five hours ago
   (under this node or another holder) is kept, and a PG just gained is
   protected at once: no pass deletes before its list is loaded. An epoch
   change never resets a clock and never aborts a pass. The former
   whole-set stability clock never opens on the network (the validator
   publishes an epoch about every 15 minutes, each one moves some PGs of
   every node); `PURGE_EPOCH_STABLE_SECS` is accepted, logged as deprecated
   and ignored. A first start, or an unreadable or pre-window state file,
   restarts the tracking: no pass for one window. The protected set is
   logged at every change (`purge: owned PGs (v3) and protected set`) and
   exported as `purge_protected_pgs`;
5. the blob is not in this node's holder set (nor in a delta record naming
   it), not a live filter hit (listed anywhere under another holder or
   withheld: retained as "moved"), and not in a tombstone list — or it is
   tombstoned, which skips the age rule;
6. the blob was written at least `PURGE_MIN_AGE_SECS` (14 days) before the
   generation's scan started;
7. no Store/PullFromPeer for that hash is in flight;
8. epochs: a pass starts when the map its ownership comes from is at
   most 3 epochs behind the validator's current epoch (heartbeat), but a
   delete happens only on the map the node holds, and only while the
   validator is on that same epoch. Otherwise the delete waits for the
   map (up to 180 s) and the pass resumes a minute later.

Passes and the dry-run census run in the background: the list poll, the
delta extension (retried with backoff from 30 s up to `PG_LISTS_POLL_SECS`
when a GET fails) and the ownership window keep running while an inventory
walk takes hours.

Deltas are published as range bundles (delta manifest `format` 2, one
`bundle/<b>.added` per 256 PGs, see `pg-lists/README.md`): applying one
costs at most one GET per bundle holding a protected PG with additions (64
at most), instead of one GET per protected PG. A miner built before
format 2 cannot read such a delta: its chain stays broken, coverage stays
incomplete and it deletes nothing until upgraded.

Membership is not built locally any more. Each base generation publishes,
per holder uid, the sorted set of its shard keys (`holders/<uid>/<part>.hashes`)
and a global 256-shard Bloom filter of every listed shard hash plus the
shards of files withheld from the lists (`live/<shard>.bloom`, ~5 %
false positives). The miner downloads only its own set and the 256 shards
(checked against the signed manifest), keeps them in
`<data_dir>/pg-lists-cache/gen-<generation>/` (reused after a restart
without a download, a damaged file is fetched again, older generations are
removed) and maps them from disk: no base list is downloaded and no filter
is built in RAM. A blob in its set (or in a delta record naming it) is an
obligation; otherwise a live filter hit (or a delta record naming another
holder in a protected PG, or a shard hash a delta withheld from the lists)
is the moved class. A generation that does not publish the sets, or does
not declare this miner's uid in them, loads but never purges. Before each
pass the mapped files are re-hashed against the signed manifest; a file
damaged since the load drops the generation until it is reloaded and the
file fetched again. `PURGE_FILTER_FP`,
`PURGE_FILTER_MAX_BYTES` and `PURGE_OTHERS_FILTER_MAX_BYTES` are gone: set,
they are logged as ignored.

### Restarts, trash

A graceful stop (SIGTERM, `systemctl stop/restart`) writes
`inventory.clean` next to `inventory.db` once in-flight writes have
drained; the next start then skips counting the blob store and is ready
in minutes instead of hours on large HDD nodes (log: `inventory: previous
run stopped cleanly, skipping the filesystem count`). After a crash, a
`kill -9`, a failed inventory write or a stop before the inventory was
ready, there is no marker and the start counts the store in the
background as before; the purge waits for it (`inventory: ready to
serve`). Deleting `inventory.clean` forces the count.

The first start of this version on an existing inventory builds a SQLite
index over the trashed rows in the background (one scan of the table,
5-8 minutes on a large HDD node; log `inventory: trashed_at index built`).
The node registers and serves meanwhile; inventory writes are queued and
applied when the build ends, and the trash purge waits. They are also
journaled to `inventory.deferred`: after a stop or a crash during the
build, the next start applies that file first. Do not delete it.

A census or pass that finds an inventory row without its blob on disk
counts it in `absent_from_store` and removes the row once the store
confirms the absence (`absent_rows_dropped`), so the next census no longer
reports it.

With `TRASH_ENABLED=false` deletes unlink directly, and whatever an earlier
run left in the trash directory is drained in the background (about 50
files/s, first batch 5 minutes after start).

### Rollout order

1. **Dry run first.** Since 0.1.36 the default deletes: set
   `PURGE_DRY_RUN=true` for the census on the public bucket. Watch for `purge: owned PGs`, `purge:
   pass finished` and `purge[census]: would delete` lines. Compare the
   `would_purge` count and bytes with what you expect to be reclaimable
   (`miner_purge_coverage_complete` must be 1; a 0 means the generation does
   not cover every protected PG and nothing would be deleted anyway).
2. **Enable by waves.** Remove `PURGE_DRY_RUN=true` (or set it to `false`) on a few nodes, wait a
   full pass interval (`PURGE_PASS_INTERVAL_SECS`, 1 h) plus the trash TTL
   margin you are comfortable with, check `purged`/`purged_bytes` match the
   census, then widen. Deletions are paced (`PURGE_RATE_PER_SEC` 50/s,
   `PURGE_MAX_BYTES_PER_SEC` 50 MiB/s) and reversible for `TRASH_TTL_SECS`
   through `RestoreBlob`.
3. **Backfill last**, and only once the purge census on that node is clean:
   `BACKFILL_ENABLED=true`. It pauses while a purge pass runs and while the
   blob filesystem has less than `BACKFILL_MIN_FREE_BYTES` (50 GiB) free;
   fetches are bounded by `BACKFILL_MAX_BYTES_PER_SEC` (20 MiB/s).
4. **Rollback** at any step: set `PURGE_DRY_RUN=true` (back to the census),
   `PURGE_ENABLED=false` or `BACKFILL_ENABLED=false`, and restart. Nothing already trashed is lost before `TRASH_TTL_SECS` elapses.

### Importing a set-aside flat store

An operator who resets a node to the packed store (`STORE_BACKEND=packed`
on an empty storage directory) after renaming its old flat store directory
aside on the same disks can import the shards the node still holds from
there instead of fetching them from peers (a shard usually has no other
holder with the same bytes, so a peer-only backfill finds almost nothing):

```bash
BACKFILL_ENABLED=true
BACKFILL_LOCAL_SOURCE_DIRS=/srv/miner/storage.flat-old-1   # the renamed --storage-path
```

Each candidate of a pass is looked up in every listed root by direct path
(`ab/cd/<hash>.bin`, then `<hash>.bin`), read up to its listed length,
verified (blake3, then length) and stored like a peer fetch. By default
the roots are only read; nothing is created or removed in them, so the
directory can be deleted by hand once `miner_backfill_local_total{outcome="hit"}`
stops growing. The `backfill: pass finished` line reports `local_hit`,
`local_miss` and `local_bad`; misses and bad copies go to the peers.

A copy doubles the disk usage until the old directory is deleted. With
`BACKFILL_LOCAL_SOURCE_DELETE=true` the import moves instead: once a blob is
stored in the packed store (which syncs a write before acknowledging it), its
inventory row is written and the live copy reads back and verifies, the exact
file it was read from (`ab/cd/<hash>.bin` or `<hash>.bin`) is unlinked; a file
whose blob the live store already holds (verified the same way) is unlinked
as a duplicate when its inventory row is live too. Copies that fail
verification, store or inventory errors and anything uncertain keep the file;
directories are never removed (empty ones stay), nothing outside the listed
roots is touched (a symlinked shard directory or a file replaced since it was
read is refused), and a root that overlaps the live storage directory is never
deleted from. The flag is ignored, with a warning, on the flat backend (no
sync before the acknowledgement) and while a flat-to-packed migration is
running (answers may come from unsynced flat files). The pass
line adds `local_deleted` and `local_delete_errors`
(`miner_backfill_local_source_deleted_total`,
`miner_backfill_local_source_delete_errors_total`).
Imports start as soon as the first lists are scanned (discovery and fetch
overlap); the `backfill: discovery progress` / `discovery finished` lines
give the discovery rate (`pgs_per_sec`, `records_per_sec`), also exported as
`miner_backfill_discovery_pgs_total` and `miner_backfill_discovery_records_total`.

The full knob list (`PURGE_*`, `BACKFILL_*`, `PG_LISTS_*`) is documented
where it is parsed: `purge::PurgeConfig::from_env` (`src/purge.rs`) and
`backfill::BackfillConfig` (`src/backfill.rs`); the defaults above are the
production values. All are environment-only, there is no TOML section.

### Rescue mode

Rescue mode is the obligation-list purge run **without the inventory index
and without serving**, for a miner whose disk is so full that SQLite cannot
even open the index and the normal start fails before the purge loop could
free anything. It reads the same lists, computes the same ownership, and
unlinks only filter misses older than `PURGE_MIN_AGE_SECS` until a free-space
target is reached, then exits so systemd restarts the normal miner.

**Rescue mode is not part of 0.1.34.** It was removed before 0.1.33 because
it deleted without the inventory index, and it has not been re-admitted; `PURGE_RESCUE` is not read by this binary. A
miner that cannot open its inventory index exits non-zero, as 0.1.32 did.
Free space by hand on such a node (start with the trash directory under the
blob store, whose contents are already deleted blobs).

### Resource limits

Since 0.1.34 two limits are derived once at boot from the machine's total
RAM instead of being fixed at 128 MiB and 2048:

- in-flight write budget of the packed store = `clamp(RAM / 8, 256 MiB, 4 GiB)`
  (`PACKED_INFLIGHT_MAX_BYTES` overrides, 8 MiB..4 GiB);
- concurrent inbound P2P stream handlers = `clamp(budget / 3 MiB, 256, 8192)`
  (`MINER_MAX_CONCURRENT_HANDLERS` overrides, 16..65536).

The resolved values are logged at startup (`resource limits`, with the
origin `ram`, `floor` or `env` of each). When the write budget cannot admit a
shard, the Store handler answers `RATE_LIMITED {"kind":"Busy","retry_after_ms":N}`
(N in 500..5000, longer the fuller the queue) instead of buffering the shard
and stalling; gateways that predate 0.1.34 see a `RATE_LIMITED` reply and
retry with their own backoff as before.

## Multiple storage roots

A node with several disks can give each disk its own store instead of
aggregating them into one mount point (a union filesystem or a stripe). Listing the disks in `STORAGE_PATHS` makes the miner run one
complete store per disk, like one OSD per disk in Ceph:

```bash
STORAGE_PATHS=/data/d1/arion,/data/d2/arion,...
```

Why it matters to the network:

- **Write throughput.** Every root has its own packed volume, writer thread
  and `fdatasync`; concurrent stores are spread over all of them instead of
  queueing behind one writer and one sync for the whole node.
- **Failure domain per disk.** A disk that fails, disappears or turns
  read-only is taken out on its own: its shards are reported absent (so the
  network re-places them) and the node keeps serving and storing on the
  other disks. Behind one aggregated mount, a dead disk silently loses its
  share of the shards while the node keeps claiming them.

Rules and behaviour:

- Every entry must be an absolute path to an **existing** directory on the
  mounted disk. The miner never creates a root: a missing directory means
  the disk is not mounted, and the root starts offline instead of becoming
  an empty store on the system disk. Create each one once, after mounting:
  `mkdir -p /data/dN/arion`.
- A root used for the first time gets a `.arion-root` marker. A root that
  already holds packed data without a marker (a former `STORAGE_PATH`
  store, or a branch of a union mount) is refused at startup until
  `miner split-union-index` has run (below). A single `STORAGE_PATH` store
  refuses a directory carrying a marker.
- Writes go to the root that already has the blob (live or in its trash),
  else to the next writable root by smooth weighted round-robin on free
  space above `STORAGE_ROOT_RESERVE_BYTES`. Reads try the roots in the
  order of `STORAGE_PATHS`.
- Root states: `healthy`; `full` (free space under the reserve or a write
  failed with no space: still read, no new writes, healthy again with twice
  the reserve free); `down` (device gone, read-only, repeated I/O errors or
  two failed probes: not read at all); `offline` (could not be opened, e.g.
  not mounted). A probe every `STORAGE_ROOT_PROBE_SECS` brings a `down` root
  back when it answers on the same device, and opens an `offline` root once
  its directory is there. A root remounted on another device comes back at
  the next restart.
- Deletes, removals and trash purges that reach the node while a root is
  `down` or `offline` are written to `{data_dir}/storage-roots.pending`
  (synced before the reply) and applied to that root before it serves
  again, so a returning disk never brings deleted shards back.
- Capacity sent to the validator is the sum over the usable roots, each
  filesystem counted once, available space only on writable roots and minus
  the reserve. The purge never drops an inventory row as absent while a
  root is unusable.
- A shard written while a root was away may exist twice once that root
  returns; both copies are identical. Once every root is usable the miner
  keeps the copy of the first root whose bytes verify and removes the
  others (logged as `duplicate suspects resolved`).
- Per-root status is logged at startup (`storage root opened`), on every
  state change (`storage root: healthy|full|unusable`) and every 10 minutes
  (`storage root: summary`).

### Moving from a union mount to one root per disk

With a union filesystem whose create policy puts each new file wholly on
one branch (no striping of a file across branches), each branch already holds its share of the volume files, e.g.
`/data/d3/arion/packed/volumes/vol-000123.dat`. Only the
packed index (`packed/index/`) is shared: it describes every branch's
volumes and sits on whichever branch received it. The migration therefore
moves no data: `miner split-union-index` derives one index per branch from
the union store's exact state (live entries, trash, delete journal), then
the branches are listed in `STORAGE_PATHS`. Flat-layout files (`ab/cd/*.bin`,
`trash/`) are already self-contained per branch.

Runbook, as an example, for a 4-disk node whose union is mounted at
`/data/union/arion` over `/data/d1/arion` .. `/data/d4/arion` (adapt the
paths, the disk count and the service name):

1. **Upgrade first.** Run this miner version on the union as before
   (`STORAGE_PATH` unchanged) and check it is healthy. Nothing changes in
   single-path mode.
2. **Data directory.** If `storage.data_dir` is on the union mount, its
   files (`keypair.bin`, `inventory.db`, purge state) are spread over the
   branches and vanish with the union. Back up the identity
   (`miner backup --data-dir ...`), and plan to copy the directory off the
   union in step 4.
3. **Stop the miner cleanly** and keep it stopped:
   `systemctl stop arion-miner && systemctl disable arion-miner` (any
   watchdog or auto-restart included). Wait for `Shutdown complete` in the
   journal: the clean stop writes the index snapshot the split relies on.
4. While the union is still mounted, copy the data directory off it if
   needed (`cp -a /data/union/arion-data /var/lib/arion-miner/data`)
   and point `storage.data_dir` there.
5. **Dry run**, union mounted:

   ```bash
   ROOTS=/data/d1/arion,/data/d2/arion,/data/d3/arion,/data/d4/arion
   miner split-union-index --union /data/union/arion --roots "$ROOTS" --dry-run
   ```

   Expect one `split-union-index: branch` line per disk (volumes, live and
   trashed blobs) and `union_scanned_bytes=0` (a clean stop). It refuses,
   writing nothing, when a volume sits on two branches (an interrupted
   relocation by the union filesystem: keep the complete copy, usually the
   larger, after `cmp -n <smaller size>` shows the smaller is its prefix;
   remove the other; rerun), when a volume is on no listed branch (a disk
   missing from `--roots`), or when a branch file is not the length the
   index covers.
6. **Split**: the same command without `--dry-run`. It reads the union
   index once (about 40 bytes per blob) and writes, on every branch,
   `packed/index/` (live table, snapshot, a copy of the delete journal) and
   `.arion-root`; the former index directory is kept as
   `packed/index.union-<id>` on the branch that held it. No volume data is
   read or moved. Interrupted, it can be rerun: before the first branch is
   committed it starts over, after it only finishes the remaining branches.
7. **Unmount the union** and remove it from `/etc/fstab` or its mount unit,
   so it never comes back: the per-branch indexes and volume ids no longer
   form a valid union store (a single-path miner refuses it anyway).
8. **Configure** `STORAGE_PATHS="$ROOTS"`, remove `STORAGE_PATH`, keep
   `STORE_BACKEND=packed`.
9. **Start** (`systemctl enable --now arion-miner`). Check for one
   `storage root opened` line per disk with `state=healthy`,
   `Initialized multi-root blob storage`, then registration and heartbeats.
   The first start after the change counts the flat layout once in the
   background (the inventory's clean-stop marker names the store roots).
10. After some days of normal operation, delete the backup:
    `rm -r /data/dN/arion/packed/index.union-<id>`.

**Rollback.** Until the miner has started with `STORAGE_PATHS` (step 9),
the union store can be restored: on every branch remove `.arion-root` and
the new `packed/index`, rename `packed/index.union-<id>` back to
`packed/index` where it exists, remount the union. After the miner has
written in multi-root mode there is no way back to the union: each root
numbers its volumes on its own.

**Residual risks.**

- The split copies the union's state as is. After an unclean stop the union
  open rescans volume tails and replays the delete journal over them, which
  trashes a shard stored again after its delete (the single-root behaviour
  of the packed store); hence the clean stop in step 3.
- The live index of each root is memory-mapped from that root's disk. A
  disk that dies between two probes can fault a mapped page and stop the
  process; the next start finds the root unopenable and runs without it.
- Deferred deletes are keyed by the configured path. Swapping two disks
  between mount points while one is away applies its deferred deletes to
  the other disk (they trash, restorably, shards that were deleted network
  wide, or copies held twice).
- Roots on the same filesystem are allowed (logged): they share capacity
  (counted once) and one failure domain.

**What to measure on real disks.** `cargo test -p miner --release --
--ignored multi_root_write_throughput --nocapture` with
`MULTI_ROOT_BENCH_DIRS=/data/d1/bench,/data/d2/bench,...` writes
20 000 blobs of 4 KiB from 64 concurrent writers with 1, 2, 4, ... roots
(one per listed directory) and prints blobs/s and MiB/s. On the node itself,
compare before and after the change: stores per second and their ACK
latency, `fdatasync` time per disk, iowait, read latency under write load,
and time to `ready to serve` after a restart.

## Identity

Miner identity is an Ed25519 keypair stored in `data/miner/keypair.bin`.

```bash
# Backup identity
cargo run --bin miner -- backup --data-dir data/miner

# Restore identity
cargo run --bin miner -- restore backup.tar.gz --data-dir data/miner
```

## P2P Protocol

Miners respond to commands from the validator via `hippius/miner-control`:

- `Store`: Receive shard from validator or pull from peer
- `Delete`: Delete shard from storage
- `FetchBlob`: Return shard data (open to any peer)
- `CheckBlob`: Metadata-only existence check (no semaphore)
- `PullFromPeer`: Pull shard from another miner
- `ClusterMapUpdate`: Receive topology updates
- `PosChallenge`: Proof-of-storage audit from warden

### Blob enumeration is refused (0.1.33)

Third-party enumeration of a miner's store (`ListAllBlobs`, `ListBlobsPage`)
is refused: since 0.1.33 the miner answers both messages with
`ERROR: unsupported message`, whoever sends them, and never walks its
inventory for a remote peer. Existence checks (`CheckBlob`) and shard reads
(`FetchBlob`) are unchanged.

The validator-side inventory collector (`INVENTORY_SCAN_ENABLED`) drove those
messages. It must stay disabled against a fleet running 0.1.33: every scan it
starts fails at the first reply. It is removed in the next validator release.

## Running Multiple Miners

Each miner needs a unique data directory and P2P port:

```bash
# Miner 1
STORAGE_PATH=data1 P2P_PORT=11220 cargo run --bin miner -- \
    --family-id family_1 --validator-node-id <id> --hostname <your-public-ipv4>

# Miner 2
STORAGE_PATH=data2 P2P_PORT=11221 cargo run --bin miner -- \
    --family-id family_2 --validator-node-id <id> --hostname <your-public-ipv4>
```

See [Miner Onboarding Guide](MINER_ONBOARDING.md) for detailed setup instructions.

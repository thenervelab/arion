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
| `PACKED_INFLIGHT_MAX_BYTES` | RAM/8, 256 MiB..4 GiB | In-flight write budget of the packed store (see "Resource limits") |
| `MINER_MAX_CONCURRENT_HANDLERS` | budget/3 MiB, 256..8192 | Cap on concurrent inbound P2P stream handlers (see "Resource limits") |
| `PG_LISTS_BASE_URL` | - | Root URL of the obligation lists (`current.json`, `gen/<g>/...`); purge and backfill stay off without it |
| `PURGE_ENABLED` | false | Obligation-list purge loop (see "Operator guide") |
| `PURGE_DRY_RUN` | true | When the purge is enabled: count and log, delete nothing |
| `BACKFILL_ENABLED` | false | Obligation-list backfill loop (see "Operator guide") |

## Operator guide: obligation lists (0.1.34)

The validator publishes, per placement group (PG), the list of shards every
holder of that PG is obliged to keep (`PG_LISTS_BASE_URL/current.json` →
`gen/<generation>/manifest.json`, signed with the validator key, → one binary
list per PG). From those lists the miner derives two background loops:

- **purge** — trash every live blob that is in none of the lists of the PGs
  this miner owns (an orphan: its file was deleted, or the shard moved
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

### Before the purge deletes anything

Every one of these must hold, in this order, or the pass keeps everything
and logs why:

1. a generation is loaded and its manifest signature verifies against
   `VALIDATOR_NODE_ID`;
2. the generation is at most `PURGE_GENERATION_MAX_AGE_SECS` old (7 days);
3. every PG this miner owns is covered by the generation
   (`coverage incomplete: N of M PGs listed` otherwise);
4. the set of PGs this miner owns has been identical for
   `PURGE_OWNERSHIP_STABLE_SECS` (6 h). The clock is this node's own
   ownership, not the cluster epoch: the epoch moves every few minutes in
   production while most nodes' owned set does not, so the former
   `PURGE_EPOCH_STABLE_SECS` gate never opened (it is now accepted, logged
   as deprecated and ignored). The set and the time it last changed are
   persisted in the data directory (`purge_ownership`), so a restart does
   not reset the clock. Every poll logs `purge: owned set stable for Ns
   (required M)` or `purge: owned set changed (added=N removed=N),
   stability clock reset`; a change during a real pass still aborts it;
5. the blob is a filter miss (not listed for any owned PG under this holder),
   not listed under another holder of an owned PG (retained as "moved"), and
   not in a tombstone list — or it is tombstoned, which skips the age rule;
6. the blob was written at least `PURGE_MIN_AGE_SECS` (14 days) before the
   generation's scan started;
7. no Store/PullFromPeer for that hash is in flight.

### Rollout order

1. **Dry run first.** Set `PG_LISTS_BASE_URL`, `PURGE_ENABLED=true`, leave
   `PURGE_DRY_RUN` unset. Restart. Watch for `purge: owned PGs`, `purge:
   pass finished` and `purge[census]: would delete` lines. Compare the
   `would_purge` count and bytes with what you expect to be reclaimable
   (`miner_purge_coverage_complete` must be 1; a 0 means the generation does
   not cover every owned PG and nothing would be deleted anyway).
2. **Enable by waves.** Set `PURGE_DRY_RUN=false` on a few nodes, wait a
   full pass interval (`PURGE_PASS_INTERVAL_SECS`, 1 h) plus the trash TTL
   margin you are comfortable with, check `purged`/`purged_bytes` match the
   census, then widen. Deletions are paced (`PURGE_RATE_PER_SEC` 50/s,
   `PURGE_MAX_BYTES_PER_SEC` 50 MiB/s) and reversible for `TRASH_TTL_SECS`
   through `RestoreBlob`.
3. **Backfill last**, and only once the purge census on that node is clean:
   `BACKFILL_ENABLED=true`. It pauses while a purge pass runs and while the
   blob filesystem has less than `BACKFILL_MIN_FREE_BYTES` (50 GiB) free;
   fetches are bounded by `BACKFILL_MAX_BYTES_PER_SEC` (20 MiB/s).
4. **Rollback** at any step: unset the switch (or set it to `false`) and
   restart. Nothing already trashed is lost before `TRASH_TTL_SECS` elapses.

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
it deleted without the index and defaulted `PURGE_DRY_RUN` to `false`, and
it has not been re-admitted; `PURGE_RESCUE` is not read by this binary. A
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

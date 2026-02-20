# Miner

Storage node for Hippius Arion. Miners receive shards from validators via P2P, store them persistently using Iroh's FsStore, and serve them to gateways and other miners on request. The miner operates primarily over P2P (QUIC) and registers with the validator to join the storage cluster.

## Overview

The miner is a storage node that:
- Receives erasure-coded shards from the validator via the `hippius/miner-control` P2P protocol
- Stores shards persistently using Iroh's FsStore (content-addressed blob storage)
- Serves shards to gateways and other miners via FetchBlob requests
- Sends periodic heartbeats to the validator to maintain cluster membership
- Optionally performs self-rebalancing to pull missing shards after epoch changes
- Responds to proof-of-storage (PoS) challenges from wardens with ZK proofs
- Automatically receives authorized warden node IDs from the validator (no manual configuration needed)

## Quick Start

```bash
# Build
cargo build -p miner --release

# Run (requires validator to be running)
cargo run --bin miner -- --validator-node-id <validator_node_id>

# Run with config file
cp miner.example.toml miner.toml
cargo run --bin miner

# Generate keypair for new miner identity
cargo run --bin generate_keypair -- --output data/miner
```

## Binaries

| Binary | Purpose |
|--------|---------|
| `miner` | Main storage node daemon |
| `generate_keypair` | Generate Ed25519 keypair for miner identity |

## Configuration

The miner loads configuration in the following priority order (highest wins):
1. CLI arguments
2. Environment variables
3. TOML config file (`miner.toml`)
4. Built-in defaults

Copy `miner.example.toml` to `miner.toml`:

```toml
[network]
# Public hostname/IP for other nodes to reach this miner
hostname = "your-miner-hostname.example.com"

# Iroh relay URL for P2P connectivity (NAT traversal)
relay_url = "https://relay.hippius.com"

# P2P bind port (UDP)
p2p_port = 11230

# Family ID for CRUSH placement grouping
# Miners in the same family won't hold duplicate shards
family_id = "SS58"

[storage]
# Directory for blob storage
path = "data/miner/blobs"

# Data directory for keypair and state
data_dir = "data/miner"

# Maximum storage to use in GB (0 = unlimited)
max_storage_gb = 0

[validator]
# Validator Node ID (Ed25519 public key) for P2P registration
# Get this from validator startup logs
node_id = "your-validator-node-id"

# Heartbeat interval in seconds
heartbeat_interval_secs = 30

# Registration retry delay in seconds
registration_retry_secs = 60

[tuning]
# Concurrency limits (backpressure)
store_concurrency = 64   # Max concurrent Store operations
pull_concurrency = 32    # Max concurrent PullFromPeer operations
fetch_concurrency = 256  # Max concurrent FetchBlob serving
# pos_concurrency = 2    # Max concurrent PoS proof generation (CPU-intensive)

# Connection timeouts
connect_timeout_secs = 20
read_timeout_secs = 30

# Exponential backoff for retries
initial_backoff_secs = 5
max_backoff_secs = 60

# Self-rebalancing (miner pulls missing shards after epoch changes)
rebalance_enabled = true
rebalance_tick_secs = 300
```

## Environment Variables

| Variable | Default | Purpose |
|----------|---------|---------|
| `PORT` | 3001 | HTTP port (if HTTP enabled) |
| `P2P_PORT` | 11230 | P2P bind port (UDP) |
| `HOSTNAME` | - | Public hostname/IP |
| `FAMILY_ID` | default | Miner family ID for CRUSH grouping |
| `STORAGE_PATH` | data/miner/blobs | Blob storage directory |
| `MAX_STORAGE_GB` | 0 (unlimited) | Storage limit in GB |
| `VALIDATOR_NODE_ID` | **required** | Validator's Iroh node ID |
| `IROH_RELAY_URL` | - | Custom relay URL for P2P |
| `MINER_STORE_CONCURRENCY` | 64 | Concurrent store operations |
| `MINER_PULL_CONCURRENCY` | 32 | Concurrent peer pull operations |
| `MINER_FETCH_CONCURRENCY` | 256 | Concurrent FetchBlob serving |
| `MINER_REBALANCE_ENABLED` | true | Enable self-rebalancing |
| `MINER_REBALANCE_TICK_SECS` | 300 | Rebalance check interval |
| `MINER_HTTP_ENABLED` | false | Enable HTTP server (dev only) |
| `VALIDATOR_URL` | - | Validator HTTP URL for fallback epoch map fetches |
| `EPOCH_LOOKBACK` | 3 | Number of past epochs to check when pulling shards |

## CLI Arguments

```bash
miner [OPTIONS] [COMMAND]

Options:
      --port <PORT>                   Port to listen on [env: PORT]
      --hostname <HOSTNAME>           Hostname of this miner [env: HOSTNAME]
      --storage-path <STORAGE_PATH>   Storage path [env: STORAGE_PATH]
      --family-id <FAMILY_ID>         Family ID [env: FAMILY_ID]
      --validator-node-id <ID>        Validator Node ID [env: VALIDATOR_NODE_ID]
  -h, --help                          Print help
  -V, --version                       Print version

Commands:
  backup   Backup miner identity to archive
  restore  Restore miner identity from archive
```

## Identity Management

Miner identity is an Ed25519 keypair stored in `data/miner/keypair.txt`. The public key serves as the miner's node ID for P2P communication.

### Generate New Identity

```bash
cargo run --bin generate_keypair -- --output data/miner
# Outputs the node ID (public key in hex format)
```

### Backup Identity

```bash
# Creates miner-backup-{timestamp}.tar.gz
cargo run --bin miner -- backup --data-dir data/miner

# Specify output file
cargo run --bin miner -- backup --data-dir data/miner --output my-backup.tar.gz
```

### Restore Identity

```bash
cargo run --bin miner -- restore backup.tar.gz --data-dir data/miner
# Warning: This will overwrite existing identity after 5-second delay
```

## P2P Protocols

The miner handles two Iroh P2P protocols:

### `hippius/miner-control`

Commands received from the validator (or peer miners):

| Message | Direction | Purpose |
|---------|-----------|---------|
| `Store` | Validator -> Miner | Receive and store a shard (push or pull from peer) |
| `Delete` | Validator -> Miner | Delete a shard from storage |
| `FetchBlob` | Any -> Miner | Return shard data to requester |
| `PullFromPeer` | Validator -> Miner | Pull shard from another miner |
| `ClusterMapUpdate` | Validator -> Miner | Receive cluster map and peer addresses |
| `PosChallenge` | Warden/Validator -> Miner | Generate ZK proof of storage |

### `hippius/validator-control`

Messages sent from the miner to the validator:

| Message | Purpose |
|---------|---------|
| `Register` | Initial registration with storage stats and endpoint info |
| `Heartbeat` | Periodic heartbeat with available storage |
| `QueryPgFilesBatch` | Query files in assigned placement groups (rebalancing) |
| `QueryManifest` | Request file manifest for shard verification |

### `iroh_blobs::ALPN`

Standard Iroh blob protocol for content-addressed data transfer.

## Registration Flow

1. Miner starts and binds Iroh endpoint with its Ed25519 keypair
2. Waits for relay connection to establish (NAT traversal)
3. Connects to validator via `hippius/validator-control` protocol
4. Sends `Register` message with:
   - Public key (node ID)
   - HTTP address (legacy)
   - Total and available storage
   - Family ID
   - Signed timestamp (prevents replay attacks)
   - Endpoint address with relay hints
5. Validator responds with `OK`, `RATE_LIMITED`, or `FAMILY_REJECTED`
6. After successful registration, miner starts heartbeat loop (every 30s)

If the validator returns `UNKNOWN` to a heartbeat, the miner triggers re-registration.

## Self-Rebalancing

When enabled (`rebalance_enabled = true`), miners periodically:
1. Calculate which placement groups (PGs) they are responsible for using CRUSH
2. Query the validator for all files in those PGs
3. Check which shards are missing locally
4. Pull missing shards from peer miners (with epoch lookback)
5. Garbage collect orphan shards after a 1-hour grace period

This ensures data availability after epoch changes or miner failures.

## Proof-of-Storage (PoS)

Miners respond to PoS challenges from wardens:
1. Receive `PosChallenge` with shard hash, chunk indices, nonce, and expected Merkle root
2. Read shard from local storage
3. Generate commitment with Merkle tree
4. Verify expected root matches computed root
5. Generate ZK proof using Plonky3
6. Return `PosProofResponse` with proof bytes and public inputs

Authorization: Only requests from the validator or its authorized wardens are accepted. Warden node IDs are automatically distributed by the validator via heartbeat responses and cluster map updates — no manual configuration is needed.

## Running Multiple Miners

```bash
# Miner 1
cargo run --bin miner -- \
  --port 3001 \
  --storage-path data1 \
  --family-id family_1 \
  --validator-node-id <validator_id>

# Miner 2 (different port and family)
cargo run --bin miner -- \
  --port 3003 \
  --storage-path data2 \
  --family-id family_2 \
  --validator-node-id <validator_id>
```

Note: Miners in the same family won't hold duplicate shards (CRUSH placement diversity).

## HTTP Endpoints (Development Only)

HTTP is disabled by default. Enable with `MINER_HTTP_ENABLED=true`:

| Endpoint | Method | Purpose |
|----------|--------|---------|
| `/status` | GET | Health check |
| `/blobs/:hash` | GET | Get blob by hash (supports Range header) |
| `/blobs/add` | POST | Add blob via multipart upload |

## Performance Tuning

### Concurrency Limits

All operations use semaphores for backpressure:
- `store_concurrency`: Bounds validator pushes and peer pulls
- `pull_concurrency`: Bounds concurrent peer downloads
- `fetch_concurrency`: Bounds concurrent FetchBlob serving
- `pos_concurrency`: Bounds CPU-intensive proof generation (default: 2)

### Caching

- **Blob Cache**: LRU cache (10k entries) for FetchBlob responses
- **Peer Cache**: DashMap for miner endpoint addresses
- **Connection Pool**: Pooled P2P connections with 60s TTL

### Constants

Key limits defined in `constants.rs`:
- `MAX_MESSAGE_SIZE`: 1 MB
- `MAX_FETCH_RESPONSE_SIZE`: 4 MB
- `BLOB_CACHE_SIZE`: 10,000 entries
- `MAX_CONCURRENT_HANDLERS`: 1,000 (prevents connection flood)
- `ORPHAN_GRACE_PERIOD_SECS`: 3,600 (1 hour before GC)

## Logging

Enable debug logging with:

```bash
RUST_LOG=debug cargo run --bin miner -- --validator-node-id <id>

# Component-specific logging
RUST_LOG=miner::p2p=debug cargo run --bin miner -- --validator-node-id <id>
```

## See Also

- [How to Run a Miner](../docs/guides/HOW_TO_RUN_MINER.md) for detailed deployment instructions
- [miner.example.toml](./miner.example.toml) for full configuration template

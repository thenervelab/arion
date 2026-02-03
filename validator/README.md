# Validator

The validator is the **metadata authority** and **orchestration engine** for Hippius Arion. It handles Reed-Solomon encoding, CRUSH placement, cluster map management, and automated recovery for the decentralized storage subnet.

## Architecture Overview

```
                                   ┌─────────────────────────────────────┐
                                   │           VALIDATOR                  │
                                   │  (Metadata authority & orchestrator) │
                                   └─────────────────────────────────────┘
                                                   │
                   ┌───────────────────────────────┼───────────────────────────────┐
                   │                               │                               │
                   ▼                               ▼                               ▼
           ┌──────────────┐               ┌──────────────┐               ┌──────────────┐
           │   Gateway    │               │    Miners    │               │    Warden    │
           │ (HTTP proxy) │               │  (storage)   │               │  (auditor)   │
           └──────────────┘               └──────────────┘               └──────────────┘
```

## Core Responsibilities

### 1. File Upload & Erasure Coding
- Receives files from gateways via HTTP multipart upload
- Splits files into **stripes** (default 2 MiB each)
- Encodes each stripe using **Reed-Solomon erasure coding** (k=10 data, m=20 parity shards)
- Creates a `FileManifest` containing file metadata and shard hashes

### 2. CRUSH Placement Algorithm
- Determines which miners store each shard using the **CRUSH** algorithm
- Ensures **family diversity** (shards spread across different failure domains)
- Supports **Placement Groups (PGs)** for efficient rebalancing (default 16,384 PGs)

### 3. Cluster Map Management
- Maintains the authoritative `ClusterMap` of all registered miners
- Tracks miner weights, capacity, uptime, and strike counts
- Broadcasts map updates to miners when topology changes
- Persists maps to iroh-docs for durability and gateway replication

### 4. Automatic Recovery
- Continuously monitors miner health via heartbeats
- Detects when miners go offline (configurable threshold, default 10 minutes)
- Reconstructs missing shards using Reed-Solomon decoding
- Re-places recovered shards on healthy miners

### 5. Rebalancing (Ceph-style)
- When miners join/leave, detects which PGs have changed ownership
- Coordinates shard migration via `PullFromPeer` messages
- Tracks rebalance status per PG for gateway epoch lookback

### 6. Miner Reputation System
- Receives audit results from wardens via P2P
- Updates miner reputation based on proof-of-storage audit results
- Reputation affects CRUSH placement weight (exponential decay)
- Bans miners when reputation exceeds threshold (default 3.0)

## Quick Start

```bash
# Build
cargo build -p validator --release

# Run with required API keys
export API_KEY_ADMIN="your-admin-key"
export API_KEY_GATEWAY="gateway-key"
cargo run --bin validator -- --port 3002

# Run with config file
cargo run --bin validator -- --config validator.toml
```

## CLI Arguments

| Argument | Environment Variable | Default | Description |
|----------|---------------------|---------|-------------|
| `--gateway-url` | `GATEWAY_URL` | `http://gateway:3000` | Gateway URL for audit callbacks |
| `--port` | `PORT` | `3002` | HTTP port to listen on |

## Configuration

Copy `validator.example.toml` to `validator.toml` and customize:

```toml
[network]
port = 3002
relay_url = "https://relay.hippius.com"
data_dir = "data/validator"

[tuning]
rebuild_enabled = true
rebuild_tick_secs = 10
rebuild_files_per_tick = 5
miner_out_threshold_secs = 600

[chain_registry]
enabled = false  # Require on-chain miner registration

[p2p]
authorized_gateways = []
authorized_wardens = []
authorized_submitters = []
```

## Environment Variables

### Required

| Variable | Description |
|----------|-------------|
| `API_KEY_ADMIN` | Admin authentication for protected endpoints |
| `API_KEY_GATEWAY` | Gateway authentication for telemetry endpoints |

### Network Configuration

| Variable | Default | Description |
|----------|---------|-------------|
| `PORT` | `3002` | HTTP API port |
| `GATEWAY_URL` | `http://gateway:3000` | Gateway URL for callbacks |
| `IROH_RELAY_URL` | - | Iroh relay URL for P2P connectivity |

### Rebuild Agent Tuning

| Variable | Default | Description |
|----------|---------|-------------|
| `REBUILD_ENABLED` | `true` | Enable automatic recovery loop |
| `REBUILD_TICK_SECS` | `10` | Rebuild loop tick interval |
| `REBUILD_FILES_PER_TICK` | `5` | Max files to rebuild per tick |
| `REBUILD_STRIPES_PER_FILE` | `25` | Max stripes per file per tick |
| `REBUILD_CONCURRENCY` | `2` | Max concurrent file rebuilds |
| `MINER_OUT_THRESHOLD_SECS` | `600` | Seconds before miner considered offline |

### Rebalancing

| Variable | Default | Description |
|----------|---------|-------------|
| `REBALANCE_ENABLED` | `true` | Enable PG-based rebalancing |
| `REBALANCE_MAX_PGS` | `2000` | Max PGs to process per epoch change |
| `REBALANCE_WORKERS` | `4` | Parallel migration workers |
| `REBALANCE_CONCURRENCY` | `100` | Max concurrent file migrations per worker |
| `REBALANCE_FILES_PER_PG` | `100` | Max files to process per PG per pass |

### Weight Updates

| Variable | Default | Description |
|----------|---------|-------------|
| `WEIGHT_UPDATE_ENABLED` | `false` | Enable periodic weight recomputation |
| `WEIGHT_UPDATE_TICK_SECS` | `3600` | Weight update interval |
| `WEIGHT_UPDATE_MIN_CHANGE_PCT` | `20` | Minimum change to trigger epoch bump |

### Upload Redundancy

| Variable | Default | Description |
|----------|---------|-------------|
| `UPLOAD_MIN_REDUNDANCY_BUFFER` | `10` | Minimum shards above k required for upload success |

### Chain Registry

| Variable | Default | Description |
|----------|---------|-------------|
| `CHAIN_REGISTRY_ENABLED` | `false` | Require on-chain miner registration |
| `CHAIN_REGISTRY_CACHE_PATH` | `arion-registry-cache.json` | Path to registry cache |
| `CHAIN_REGISTRY_REFRESH_SECS` | `30` | Cache refresh interval |
| `CHAIN_REGISTRY_FAIL_OPEN` | `false` | Allow registration if cache unavailable |

### Reputation System

| Variable | Default | Description |
|----------|---------|-------------|
| `REPUTATION_ALLOWED_WARDENS` | - | Comma-separated allowed warden public keys |
| `REPUTATION_STRIKE_WEIGHT_FAILED` | `1.0` | Penalty for failed audit |
| `REPUTATION_STRIKE_WEIGHT_TIMEOUT` | `0.3` | Penalty for timeout |
| `REPUTATION_RECOVERY_RATE` | `0.05` | Recovery per successful audit |
| `REPUTATION_MIN_PASSES_FOR_RECOVERY` | `10` | Min passes before recovery starts |
| `REPUTATION_BAN_THRESHOLD` | `3.0` | Reputation threshold for ban |

### P2P Authorization

| Variable | Description |
|----------|-------------|
| `P2P_AUTHORIZED_GATEWAYS` | Comma-separated gateway node IDs |
| `P2P_AUTHORIZED_WARDENS` | Comma-separated warden node IDs |
| `P2P_AUTHORIZED_SUBMITTERS` | Comma-separated chain-submitter node IDs |
| `CHAIN_SUBMITTER_NODE_ID` | Chain-submitter node ID for attestation push |

### S3 Backup

| Variable | Default | Description |
|----------|---------|-------------|
| `BACKUP_ENABLED` | `false` | Enable S3 backup |
| `BACKUP_S3_ENDPOINT` | - | S3 endpoint URL |
| `BACKUP_S3_BUCKET` | - | S3 bucket name |
| `BACKUP_S3_ACCESS_KEY` | - | S3 access key |
| `BACKUP_S3_SECRET_KEY` | - | S3 secret key |
| `BLOB_BACKUP_ENABLED` | `false` | Enable incremental blob backup |
| `BLOB_BACKUP_SYNC_INTERVAL_MINUTES` | `15` | Blob sync interval |
| `BLOB_BACKUP_BATCH_SIZE` | `100` | Blobs per batch |
| `BLOB_BACKUP_UPLOAD_CONCURRENCY` | `8` | Concurrent S3 uploads |

### TLS Configuration

| Variable | Default | Description |
|----------|---------|-------------|
| `ARION_API_KEY` | `Hippius-Arion-Dev-01` | API key for HTTPS authentication |
| `ARION_VALIDATOR_TLS_CERT` | `/etc/arion/validator/cert.pem` | TLS certificate path |
| `ARION_VALIDATOR_TLS_KEY` | `/etc/arion/validator/key.pem` | TLS private key path |

## API Endpoints

### Public Endpoints

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/health` | GET | Health check |
| `/metrics` | GET | Prometheus metrics |
| `/node_id` | GET | Validator's P2P node ID |
| `/manifest/:hash` | GET | Fetch file manifest by hash |
| `/file/:hash/shards` | GET | Get shard details for a file |
| `/map` | GET | Current cluster map topology |
| `/map/epoch/:epoch` | GET | Cluster map at specific epoch |
| `/rebalance/status/:epoch/:pg_id` | GET | Rebalance status for a PG |
| `/files` | GET | List all tracked files |
| `/blobs/:hash` | GET | Fetch blob by hash |
| `/stats` | GET | Cluster statistics |
| `/upload/status/:hash` | GET | Upload progress status |

### Admin-Authenticated Endpoints (requires `API_KEY_ADMIN`)

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/upload` | POST | Upload and encode a file |
| `/manifest` | POST | Save a manifest directly |
| `/map` | POST | Update cluster map |
| `/repair/:hash` | POST | Manual file recovery |
| `/audit-results` | POST | Submit warden audit results |
| `/network-stats` | GET | Detailed network statistics (cached) |
| `/blobs/:hash` | DELETE | Delete a file |

### Gateway-Authenticated Endpoints (requires `API_KEY_GATEWAY`)

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/repair_hint` | POST | Submit repair hint from gateway |
| `/stats/bandwidth` | POST | Report bandwidth statistics |
| `/stats/failures` | POST | Report miner failures |

### Other Endpoints

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/audit/:hash` | POST | Audit file shards (returns audit report) |

## P2P Protocols

The validator implements several Iroh ALPN protocols for internal cluster communication:

### Inbound Protocols (Validator accepts connections)

| Protocol ALPN | Source | Description |
|---------------|--------|-------------|
| `hippius/validator-control` | Miners | Registration, heartbeats, PG queries |
| `hippius/gateway-control` | Gateway | Cluster maps, manifests, uploads, telemetry |
| `hippius/warden-control` | Warden | Audit results for reputation updates |
| `hippius/submitter-control` | Chain-Submitter | Cluster map requests, network stats |

### Outbound Protocols (Validator initiates connections)

| Protocol ALPN | Target | Description |
|---------------|--------|-------------|
| `hippius/miner-control` | Miners | Store, delete, pull commands |
| `hippius/commitment-push` | Chain-Submitter | Attestation commitments at epoch boundaries |

### Message Types

**hippius/validator-control** (from miners):
- `Register`: New miner registration with capacity/family info
- `Heartbeat`: Periodic liveness signal with storage stats
- `QueryPgFiles`: Request files in a specific PG (for rebalancing)
- `Ping`: Health check

**hippius/miner-control** (to miners):
- `Store`: Push shard data to miner
- `Delete`: Remove shard from miner
- `PullFromPeer`: Instruct miner to pull shard from another miner
- `ClusterMapUpdate`: Broadcast new cluster topology

**hippius/gateway-control** (from gateways):
- `GetClusterMap`: Request current cluster map
- `GetManifest`: Request file manifest
- `UploadFile`: Coordinate file upload
- `DeleteFile`: Coordinate file deletion
- `ReportBandwidth`: Bandwidth telemetry
- `ReportFailures`: Miner failure reports
- `RepairHint`: Request stripe repair

**hippius/warden-control** (from wardens):
- `PushAuditResults`: Batch of signed audit attestations

## Background Tasks

The validator runs several background loops:

| Task | Interval | Purpose |
|------|----------|---------|
| **Rebuild loop** | `REBUILD_TICK_SECS` (10s) | Scans for files with offline shards, reconstructs via RS |
| **Rebalance loop** | 15s | Detects epoch changes, migrates shards to new owners |
| **Weight update loop** | `WEIGHT_UPDATE_TICK_SECS` (1h) | Recomputes miner weights (optional) |
| **Blob backup loop** | `BLOB_BACKUP_SYNC_INTERVAL_MINUTES` (15m) | Syncs blobs to S3 (optional) |
| **Backup scheduler** | Configurable | Full/differential/incremental backups |

## Startup States

The validator goes through these readiness states during startup:

| State | Description | Operations Allowed |
|-------|-------------|-------------------|
| `WarmingUp` | P2P is up, storage loading | Ping, GetClusterMap |
| `IndexingInProgress` | Storage loaded, building indexes | Read-only operations |
| `Ready` | Fully operational | All operations |

## Data Persistence

| Path | Purpose |
|------|---------|
| `data/validator/docs.db` | Iroh-docs distributed metadata |
| `data/validator/blobs/` | Local blob store |
| `upload_progress.redb` | Persistent upload progress tracking |

## Prometheus Metrics

Key metrics exported at `/metrics`:

### Miner Stats
- `miner_count{status}` - Number of miners (online/offline)
- `cluster_storage_capacity_bytes` - Total cluster storage
- `cluster_storage_used_bytes` - Used cluster storage
- `total_bandwidth_bytes` - Total bandwidth served

### Operations
- `recovery_operations_total{result}` - Recovery attempts (success/fail)
- `rebalance_operations_total` - Rebalance triggers
- `rebalance_queue_depth` - PGs queued for rebalance
- `rebuild_stripes_recovered_total` - Stripes successfully rebuilt
- `rebuild_stripes_failed_total` - Failed stripe rebuilds
- `rebuild_shards_pushed_total` - Reconstructed shards pushed
- `rebuild_inflight` - Active rebuild tasks

### P2P
- `p2p_requests_total{protocol,message}` - P2P requests by type
- `p2p_request_errors_total{protocol}` - P2P errors
- `p2p_connections_active{protocol}` - Active connections

### Blob Backup
- `blob_backup_blobs_total` - Blobs backed up
- `blob_backup_bytes_total` - Bytes backed up
- `blob_backup_errors_total` - Backup errors
- `blob_backup_last_sync_timestamp` - Last successful sync
- `blob_backup_sync_duration_seconds` - Sync cycle duration

### System
- `active_files_count` - Tracked files
- `active_data_stored_bytes` - Total stored data

## Key Constants

| Constant | Default | Description |
|----------|---------|-------------|
| Stripe size | 2 MiB | Size of each erasure-coded stripe |
| k (data shards) | 10 | Number of data shards per stripe |
| m (parity shards) | 20 | Number of parity shards per stripe |
| PG count | 16,384 | Number of placement groups |
| Cache max entries | 10,000 | LRU cache size for manifests/repair hints |
| Miner connect timeout | 15s | P2P connection timeout |
| Miner ACK timeout | 10s | Wait time for miner acknowledgement |
| Registration rate limit | 10s | Minimum interval between miner registrations |

## Module Structure

| Module | Purpose |
|--------|---------|
| `main.rs` | HTTP routes, P2P protocols, background loops, core logic |
| `config.rs` | TOML configuration with env var overrides |
| `state.rs` | Application state types and helpers |
| `constants.rs` | Tunable constants (cache sizes, timeouts, etc.) |
| `metrics.rs` | Prometheus metrics definitions |
| `backup.rs` | S3 backup/restore (full, differential, incremental) |
| `blob_backup.rs` | Incremental blob backup to S3 |
| `families.rs` | Miner family whitelist verification |
| `chain_registry.rs` | On-chain pallet-arion registry cache |
| `reputation.rs` | Warden audit result processing |
| `attestation_aggregator.rs` | Epoch attestation bundling |
| `upload_progress.rs` | ReDB-based persistent upload tracking |
| `helpers.rs` | Utility functions |
| `index_cache.rs` | Index caching for fast startup |
| `warden_client.rs` | Outbound warden communication |
| `p2p/` | P2P protocol handlers |

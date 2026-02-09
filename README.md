# Hippius Arion

![Hippius Arion](hippius-arion.png)

Decentralized storage subnet built on [Iroh](https://iroh.computer/) with Reed-Solomon erasure coding, CRUSH placement, and automated recovery. Part of the Hippius infrastructure on Bittensor.

> [!CAUTION]
> **Active Development**: This project is currently in active development. Features, APIs, and storage formats are subject to change without notice. Use at your own risk.


## Architecture

```
User (HTTP) --> Gateway (:3000) --P2P--> Validator (:3002) --> Miners (:3001+)
                    ^                         |
              ClusterMap sync           RS encode + CRUSH placement
              (P2P preferred,                 |
               HTTP fallback)         P2P Store commands (hippius/miner-control)

Warden (:3003) --P2P--> Validator (audit results, reputation updates)
Chain-Submitter (:3004) --P2P--> Validator (cluster maps, network stats)
```

**Upload flow**: User -> Gateway -> Validator encodes with Reed-Solomon (k=10, m=20, 2 MiB stripes) -> CRUSH places shards -> P2P push to miners

**Download flow**: Gateway fetches k shards from miners via Iroh FetchBlob -> reconstructs original data

**Recovery**: Validator's rebuild agent detects offline miners -> fetches k shards -> reconstructs missing -> places on new miners

## Workspace Structure

| Crate | Binary | Purpose |
|-------|--------|---------|
| `common` | - | Shared types, CRUSH placement, RS codec, TLS helpers |
| `validator` | `validator` | Metadata authority, encoding, placement, recovery |
| `gateway` | `gateway` | HTTP ingress for uploads/downloads |
| `miner` | `miner`, `generate_keypair` | Storage node (Iroh blob store) |
| `warden` | `warden` | Proof-of-storage audit service |
| `listener` | `listener` | Read-only P2P replica for cluster map/manifests |
| `chain-submitter` | `chain-submitter`, `chain-registry-cache` | Blockchain integration |
| `miner-cli` | `miner-cli` | Miner on-chain registration CLI |
| `tools` | `generate_registration_data`, `verify_attestations` | Utility tools |
| `pos-circuits` | - | Plonky3 proof-of-storage circuits |
| `proptests` | - | Property-based tests |
| `arion-pallet` | - | Substrate pallet for on-chain registry (not in workspace) |

## Build Commands

```bash
cargo build --release              # Build all workspace crates
cargo test --workspace --all-targets   # Run all tests
cargo test -p <crate_name>         # Test specific crate (e.g., cargo test -p validator)
cargo test <test_name> -- --nocapture  # Run single test with output
cargo fmt --all -- --check         # Check formatting (CI BLOCKING)
cargo clippy --workspace --all-targets  # Lint
RUST_LOG=debug cargo run --bin <binary>  # Run with debug logging
```

**Rust Edition**: 2024

## Quick Start

### Running Locally

```bash
# Terminal 1: Validator
cargo run --bin validator -- --gateway-url http://localhost:3000 --port 3002

# Terminal 2: Gateway (note the validator_node_id from validator startup logs)
VALIDATOR_NODE_ID=<validator_node_id> \
cargo run --bin gateway -- --validator-url http://localhost:3002 --port 3000

# Terminal 3: Miner (get validator_node_id from validator startup logs)
cargo run --bin miner -- \
  --port 3001 --hostname 127.0.0.1 --storage-path data1 \
  --family-id family_1 --validator-node-id <validator_node_id>
```

### Test Upload/Download

```bash
# Upload a file (requires API key)
curl -X POST -H "Authorization: Bearer ${API_KEY_ADMIN}" \
  -F "file=@test.txt" http://localhost:3000/upload

# Download a file
curl -L -o out.txt http://localhost:3000/download/<file_hash>
```

## Component Details

### Gateway

HTTP ingress for client uploads and downloads.

**CLI Arguments / Environment Variables:**

| Variable | Default | Description |
|----------|---------|-------------|
| `VALIDATOR_URL` | `http://validator:3002` | Validator HTTP URL (fallback) |
| `VALIDATOR_NODE_ID` | - | Validator's Iroh node ID for P2P |
| `USE_P2P` | `true` if `VALIDATOR_NODE_ID` set | Enable P2P communication |
| `HTTP_FALLBACK` | `true` | Fall back to HTTP when P2P fails |
| `DOC_TICKET` | - | Optional doc ticket for P2P metadata replication |
| `PORT` | `3000` | HTTP port to listen on |
| `GATEWAY_GLOBAL_FETCH_CONCURRENCY` | `512` | Global FetchBlob limit |
| `GATEWAY_REQUEST_FETCH_CONCURRENCY` | `64` | Per-request parallelism |
| `GATEWAY_FETCH_PERMIT_TIMEOUT_MS` | `20000` | Permit acquisition timeout |
| `GATEWAY_FETCH_CONNECT_TIMEOUT_SECS` | `20` | Connection timeout |
| `GATEWAY_FETCH_READ_TIMEOUT_SECS` | `15` | Read timeout |
| `GATEWAY_AUTO_REPAIR_HINT_ENABLED` | `true` | Enable automatic repair hints |
| `VALIDATOR_GATEWAY_KEY` | - | Gateway-to-validator authentication |

**API Endpoints:**

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/upload` | POST | Upload a file (multipart, requires auth) |
| `/download/:hash` | GET | Download a file by hash |
| `/stats` | GET | Miner latency statistics |
| `/metrics` | GET | Prometheus metrics |
| `/health` | GET | Health check |

### Validator

Metadata authority that handles encoding, placement, and recovery.

**CLI Arguments / Environment Variables:**

| Variable | Default | Description |
|----------|---------|-------------|
| `GATEWAY_URL` | `http://gateway:3000` | Gateway URL for callbacks |
| `PORT` | `3002` | HTTP port to listen on |

**API Endpoints:**

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/upload` | POST | Internal upload endpoint |
| `/upload/status/:hash` | GET | Check upload status |
| `/blobs/:hash` | GET | Get blob metadata |
| `/blobs/:hash` | DELETE | Delete a file |
| `/files` | GET | List all files |
| `/manifest/:hash` | GET | Get file manifest |
| `/file/:hash/shards` | GET | Get file shard info |
| `/map` | GET | Get current cluster map |
| `/map/epoch/:epoch` | GET | Get cluster map for specific epoch |
| `/repair/:hash` | POST | Emergency repair for stranded files |
| `/audit/:hash` | POST | Trigger audit for a file |
| `/stats` | GET | Validator statistics |
| `/node_id` | GET | Get validator's Iroh node ID |
| `/health` | GET | Health check |
| `/metrics` | GET | Prometheus metrics |

### Miner

Storage node that stores shards via Iroh blob store.

**CLI Arguments / Environment Variables:**

| Variable | Default | Description |
|----------|---------|-------------|
| `PORT` | - | HTTP port (required) |
| `HOSTNAME` | - | Hostname for registration |
| `STORAGE_PATH` | - | Path to store data |
| `FAMILY_ID` | - | Family ID for CRUSH diversity |
| `VALIDATOR_NODE_ID` | - | Validator's Iroh node ID |

**Additional Binaries:**

- `generate_keypair`: Generate Ed25519 keypair for miner identity

### Warden

Proof-of-storage audit service that verifies miners are storing data correctly.

**Configuration:** Uses TOML config file (`--config` flag)

**Features:**
- Audits miners using Plonky3 proof-of-storage circuits
- Pushes audit results to validator for reputation updates
- Supports both P2P and HTTP communication

### Listener

Read-only replica that syncs cluster map and manifests from validator.

**CLI Arguments / Environment Variables:**

| Variable | Default | Description |
|----------|---------|-------------|
| `PORT` | `3005` | HTTP port to listen on |
| `VALIDATOR_NODE_ID` | - | Validator's Iroh node ID (required) |

### Chain Submitter

Blockchain integration service that submits cluster maps and attestations on-chain.

**CLI Arguments / Environment Variables:**

| Variable | Default | Description |
|----------|---------|-------------|
| `CHAIN_WS_URL` | - | Substrate WebSocket endpoint (required) |
| `VALIDATOR_HTTP_URL` | - | Validator HTTP URL (required) |
| `SUBMITTER_MNEMONIC` | - | Whitelisted account seed phrase (required) |
| `ARION_PALLET_NAME` | `""` | Pallet name on chain |
| `SUBMITTER_POLL_SECS` | `6` | Polling interval |
| `SUBMITTER_BUCKET_BLOCKS` | `300` | Blocks per bucket |
| `SUBMITTER_UPTIME_OFFLINE_SECS` | `120` | Offline threshold |
| `VALIDATOR_NODE_ID` | - | Validator's Iroh node ID for P2P |
| `USE_P2P` | `true` | Enable P2P communication |
| `HTTP_FALLBACK` | `true` | Fall back to HTTP when P2P fails |
| `SUBMITTER_HTTP_PORT` | `3004` | HTTP server port |
| `SUBMITTER_ENABLE_ATTESTATIONS` | `true` | Enable attestation submission |
| `SUBMITTER_ENABLE_ATTESTATION_COMMITMENTS` | `true` | Enable commitment submission |

**Additional Binaries:**

- `chain-registry-cache`: Cache on-chain registry to local JSON file

### Miner CLI

CLI tool for on-chain miner registration.

**Usage:**
```bash
cargo run --bin miner-cli -- register-child --help
```

### Tools

Utility tools for development and operations.

**Binaries:**

- `generate_registration_data`: Generate miner registration data
- `verify_attestations`: Verify attestation bundles against on-chain commitments

## HTTPS Configuration

All Arion services support HTTPS with automatic TLS certificate management.

### TLS Certificate Loading Order

1. **Environment variables** (highest priority):
   - `ARION_{SERVICE}_TLS_CERT` - Path to certificate file
   - `ARION_{SERVICE}_TLS_KEY` - Path to private key file

2. **Default system paths**:
   - `/etc/arion/{service}/cert.pem`
   - `/etc/arion/{service}/key.pem`

3. **Auto-generated self-signed certificates** (development fallback):
   - `/tmp/arion-{service}-cert.pem`
   - `/tmp/arion-{service}-key.pem`

### API Key Authentication

All HTTPS endpoints require API key authentication via the `X-API-Key` header.

| Variable | Default | Description |
|----------|---------|-------------|
| `ARION_API_KEY` | `Hippius-Arion-Dev-01` | Shared API key for all services |

## P2P Communication

All Arion components communicate primarily via Iroh P2P. HTTPS endpoints are for external client access and legacy fallback.

### Protocol Table

| Protocol ALPN | Direction | Purpose |
|---------------|-----------|---------|
| `hippius/gateway-control` | Gateway <-> Validator | Cluster maps, manifests, uploads |
| `hippius/warden-control` | Warden -> Validator | Audit results for reputation |
| `hippius/submitter-control` | Chain-Submitter -> Validator | Cluster maps, network stats |
| `hippius/commitment-push` | Validator -> Chain-Submitter | Attestation commitments |
| `hippius/miner-control` | Validator <-> Miners | Store, delete, pull commands |
| `hippius/validator-control` | Miners -> Validator | Registration, heartbeats |

## Key Data Structures

- `FileManifest`: Maps file hash to shards with stripe config and placement epoch
- `ClusterMap`: Epoch-scoped miner topology with weights, family IDs, PG count
- `MinerNode`: Miner identity, endpoint, weight, strikes, bandwidth stats, reputation
- `StripeConfig`: Default k=10 data shards, m=20 parity shards, 2 MiB stripe size
- `AttestationBundle`: Full epoch attestation bundle with merkle proofs
- `EpochAttestationCommitment`: Compact on-chain commitment with merkle roots

## Erasure Coding

Default configuration (configurable via `StripeConfig`):
- **k = 10**: Data shards per stripe
- **m = 20**: Parity shards per stripe
- **Stripe size**: 2 MiB
- **Fault tolerance**: 66% (can lose up to 20 of 30 shards)

## Placement Algorithm

Two placement versions exist (controlled by `FileManifest.placement_version`):
- **Version 1 (legacy)**: Per-stripe CRUSH with seed = `hash(file_hash + stripe_index)`
- **Version 2 (PG-based)**: File->PG mapping, then CRUSH on PG ID with stripe rotation

## Miner Reputation System

Reputation affects CRUSH placement weight, determining how many new shards a miner receives.

| Audit Result | Penalty | Scenario |
|--------------|---------|----------|
| `Passed` | 0 | Proof verified; after 10 consecutive passes, recover 0.05 |
| `Failed` | +1.0 | Proof verification failed |
| `InvalidProof` | +1.0 | Malformed proof data |
| `Timeout` | +0.3 | No response within deadline |

**CRUSH Weight Multiplier:** `exp(-0.767 * reputation)` clamped to [0.1, 1.0]

| Reputation | Multiplier | Status |
|------------|------------|--------|
| 0.0 | 1.00 | Perfect |
| 1.0 | 0.46 | 1 failed audit |
| 2.0 | 0.22 | 2 failed audits |
| 3.0+ | **BANNED** | Removed from cluster |

## Testing

```bash
# Run all workspace tests
cargo test --workspace --all-targets

# Run specific crate tests
cargo test -p validator
cargo test -p gateway
cargo test -p common

# Run with output
cargo test <test_name> -- --nocapture

# Property-based tests
cargo test -p proptests
```

## License

AGPL-3.0

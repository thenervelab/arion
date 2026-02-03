# Chain Submitter

Service that bridges off-chain validator state to the Hippius blockchain (Substrate/Polkadot). It polls the validator for cluster topology and network statistics, then submits this data on-chain via extrinsics to `pallet-arion`.

## Overview

The chain-submitter performs five key functions:

1. **CRUSH Map Submission** (`submit_crush_map`) - Submits cluster topology when epoch changes, including miner endpoints, weights, and placement parameters
2. **Miner Stats** (`submit_miner_stats`) - Submits per-miner storage and bandwidth statistics, aggregated per time bucket
3. **Node Quality** (`submit_node_quality`) - Submits uptime and reliability metrics used for reward calculations
4. **Attestation Commitments** (`submit_attestation_commitment`) - Submits epoch attestation summaries with merkle roots for verifiable proof-of-storage
5. **Individual Attestations** (`submit_attestations`) - Submits warden audit results for miner reputation tracking

## Architecture

```
                           P2P (preferred)
Validator (:3002) ─────────────────────────▶ Chain Submitter (:3004)
         │                                           │
         │  HTTP fallback                            │
         └─────────────────────────────────────────▶ │
                                                     │
                                                     ▼
                                          Substrate RPC (WebSocket)
                                                     │
                                                     ▼
                                             pallet-arion
                                          ┌──────────────────┐
                                          │  CurrentEpoch    │
                                          │  CrushMap        │
                                          │  MinerStats      │
                                          │  NodeIdToChild   │
                                          │  EpochAttestations│
                                          └──────────────────┘
```

### Communication Modes

The chain-submitter supports two communication modes with the validator:

- **P2P (preferred)**: Uses the `hippius/submitter-control` Iroh protocol for fetching cluster maps and network stats
- **HTTP fallback**: Falls back to HTTP endpoints when P2P is unavailable

Additionally, the chain-submitter runs a P2P server to receive attestation commitments from the validator via the `hippius/commitment-push` protocol.

## Binaries

This crate produces two binaries:

| Binary | Purpose |
|--------|---------|
| `chain-submitter` | Main service that submits validator data to blockchain |
| `chain-registry-cache` | Daemon that caches on-chain miner registry data to JSON |

## Build

```bash
cargo build --release -p chain-submitter
```

## Configuration

Copy the example environment file and configure:

```bash
cd chain-submitter
cp chain-submitter.example.env .env
```

### Required Environment Variables

| Variable | Description |
|----------|-------------|
| `CHAIN_WS_URL` | Substrate WebSocket URL (e.g., `wss://your-node:9944`) |
| `VALIDATOR_HTTP_URL` | Validator HTTP endpoint (e.g., `http://127.0.0.1:3002`) |
| `SUBMITTER_MNEMONIC` | BIP39 mnemonic for the whitelisted submitter account |

### P2P Configuration

| Variable | Default | Description |
|----------|---------|-------------|
| `VALIDATOR_NODE_ID` | - | Validator's Iroh node ID (hex public key) for P2P communication |
| `USE_P2P` | `true` | Enable P2P communication with validator |
| `HTTP_FALLBACK` | `true` | Fall back to HTTP if P2P fails |
| `SUBMITTER_P2P_SERVER_ENABLED` | `true` | Enable P2P server for receiving attestation commitments |
| `P2P_AUTHORIZED_VALIDATORS` | - | Comma-separated list of authorized validator node IDs (empty = allow all) |

### Submission Settings

| Variable | Default | Description |
|----------|---------|-------------|
| `SUBMITTER_POLL_SECS` | `6` | Polling interval in seconds |
| `SUBMITTER_BUCKET_BLOCKS` | `300` | Blocks per bucket for stats aggregation |
| `SUBMITTER_UPTIME_OFFLINE_SECS` | `120` | Seconds before considering a miner offline |
| `SUBMITTER_ENABLE_CRUSH_MAP` | `true` | Enable CRUSH map submission |
| `SUBMITTER_ENABLE_MINER_STATS` | `true` | Enable miner stats submission |
| `SUBMITTER_ENABLE_NODE_QUALITY` | `true` | Enable node quality submission |
| `SUBMITTER_MAX_ENDPOINT_BYTES` | `256` | Max bytes for miner endpoint (truncated if exceeded) |
| `SUBMITTER_MAX_HTTP_ADDR_BYTES` | `128` | Max bytes for HTTP address (truncated if exceeded) |

### Attestation Settings

| Variable | Default | Description |
|----------|---------|-------------|
| `SUBMITTER_HTTP_PORT` | `3004` | HTTP server port for receiving attestations from warden |
| `SUBMITTER_ENABLE_ATTESTATIONS` | `true` | Enable individual attestation submission |
| `SUBMITTER_ATTESTATION_BATCH_SIZE` | `100` | Max attestations per extrinsic |
| `SUBMITTER_ATTESTATION_DRY_RUN` | `false` | Log attestations instead of submitting |
| `SUBMITTER_ENABLE_ATTESTATION_COMMITMENTS` | `true` | Enable epoch attestation commitment submission |
| `SUBMITTER_ATTESTATION_COMMITMENT_DRY_RUN` | `false` | Log commitments instead of submitting |
| `ARION_API_KEY` | `Hippius-Arion-Dev-01` | API key for warden authentication |
| `VALIDATOR_ADMIN_API_KEY` | - | API key for validator HTTP endpoints (if protected) |

### Pallet Configuration

| Variable | Default | Description |
|----------|---------|-------------|
| `ARION_PALLET_NAME` | (auto-detected) | Override pallet name if auto-detection fails |

## Running

### Chain Submitter

```bash
# Using environment file
cd chain-submitter
cargo run --release

# Or with explicit arguments
cargo run --release --bin chain-submitter -- \
  --chain-ws-url wss://your-node:9944 \
  --validator-http-url http://127.0.0.1:3002 \
  --submitter-mnemonic "your mnemonic phrase here"
```

### Chain Registry Cache

The registry cache daemon polls the blockchain and builds a local JSON snapshot of the miner registry. The validator uses this cache to verify miner registrations without querying the blockchain directly.

```bash
# Using environment file
cp chain-registry-cache.env.example .env
cargo run --release --bin chain-registry-cache

# Or with explicit arguments
cargo run --release --bin chain-registry-cache -- \
  --chain-ws-url ws://127.0.0.1:9944 \
  --out arion-registry-cache.json \
  --poll-secs 30

# One-shot mode (write once and exit)
cargo run --release --bin chain-registry-cache -- \
  --chain-ws-url ws://127.0.0.1:9944 \
  --once
```

#### Registry Cache Output Format

```json
{
  "at_block": 12345,
  "pallet": "Arion",
  "family_children": {"0x...": ["0x..."]},
  "child_registrations": {"0x...": {...}},
  "node_id_to_child": {"0x...": "0x..."}
}
```

## On-Chain Permissions

The submitter account requires specific permissions on the blockchain:

| Permission | Extrinsics |
|------------|------------|
| `MapAuthorityOrigin` | `submit_crush_map` |
| `StatsAuthorityOrigin` | `submit_miner_stats`, `submit_node_quality` |
| `AttestationAuthorityOrigin` | `submit_attestations`, `submit_attestation_commitment` |

The account also needs sufficient balance for transaction fees.

## HTTP Endpoints

The chain-submitter runs an HTTP server (default port 3004) for receiving attestations from the warden:

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/attestations` | POST | Queue a signed attestation for on-chain submission |
| `/health` | GET | Health check with queue status and version |

### Authentication

The `/attestations` endpoint requires an `X-API-Key` header matching the `ARION_API_KEY` environment variable.

### Example Request

```bash
# Health check
curl http://localhost:3004/health

# Submit attestation (from warden)
curl -X POST http://localhost:3004/attestations \
  -H "Content-Type: application/json" \
  -H "X-API-Key: your-api-key" \
  -d '{"attestation": {...}, "warden_pubkey": "...", "signature": "..."}'
```

## Bucket System

Miner stats and node quality are grouped into "buckets" based on block height:

```
bucket = best_block / bucket_blocks
```

With the default `bucket_blocks=300`, a new bucket is created approximately every 30 minutes (assuming 6-second blocks). This aggregates metrics over time windows and prevents duplicate submissions.

## Transaction Handling

- All transactions have a 2-minute timeout for submission and finalization
- Failed submissions trigger exponential backoff (up to 5 minutes)
- Connection errors automatically trigger reconnection attempts
- The submitter continues operating even if individual submission types fail

## Logging

Enable debug logging with:

```bash
RUST_LOG=debug cargo run --release --bin chain-submitter
```

Component-specific logging:

```bash
RUST_LOG=chain_submitter::attestation=debug cargo run --release --bin chain-submitter
```

# Gateway

HTTP/HTTPS ingress point for Hippius Arion. Handles file uploads, downloads, and deletions by communicating with the validator and fetching erasure-coded shards from miners via Iroh P2P.

## Features

- Streaming uploads to validator with exponential backoff retry
- Parallel shard fetching from miners with Reed-Solomon reconstruction
- HTTP Range header support for partial content downloads
- P2P communication with validator (with HTTP fallback)
- LRU blob cache (50k entries) for frequently accessed shards
- Prometheus metrics for observability
- Automatic repair hints for unrecoverable stripes
- HTTPS with auto-generated self-signed certificates for development

## Quick Start

```bash
# Build
cargo build -p gateway --release

# Run (requires API key and validator node ID for P2P)
export API_KEY_ADMIN="your-admin-key"
export VALIDATOR_NODE_ID="<validator-hex-pubkey>"
cargo run --bin gateway -- --validator-url http://localhost:3002 --port 3000
```

## Configuration

### CLI Arguments

| Argument | Env Variable | Default | Description |
|----------|--------------|---------|-------------|
| `--validator-url` | `VALIDATOR_URL` | `http://validator:3002` | Validator HTTP URL (fallback) |
| `--validator-node-id` | `VALIDATOR_NODE_ID` | - | Validator's Iroh node ID for P2P |
| `--use-p2p` | `USE_P2P` | `true` if node ID set | Enable P2P communication |
| `--http-fallback` | `HTTP_FALLBACK` | `true` | Fall back to HTTP when P2P fails |
| `--port` | `PORT` | `3000` | HTTPS port to listen on |
| `--doc-ticket` | `DOC_TICKET` | - | Optional doc ticket for local manifest replica |

### Environment Variables

#### Required

```bash
API_KEY_ADMIN=<secret>              # Required for upload authentication
```

#### P2P Communication

```bash
VALIDATOR_NODE_ID=<hex-pubkey>      # Validator's Iroh node ID (required for P2P)
USE_P2P=true                        # Enable P2P (default: true if node ID set)
HTTP_FALLBACK=true                  # Fall back to HTTP on P2P failure
```

#### Download Tuning

```bash
GATEWAY_GLOBAL_FETCH_CONCURRENCY=512      # Total in-flight FetchBlob tasks
GATEWAY_REQUEST_FETCH_CONCURRENCY=64      # Per-request FetchBlob parallelism
GATEWAY_FETCH_PERMIT_TIMEOUT_MS=0         # Permit wait timeout (0 = infinite)
GATEWAY_FETCH_CONNECT_TIMEOUT_SECS=20     # Miner connection timeout
GATEWAY_FETCH_READ_TIMEOUT_SECS=15        # Miner read timeout
EPOCH_LOOKBACK=3                          # Epochs to search for shards during rebalance
```

#### Repair Hints

```bash
GATEWAY_AUTO_REPAIR_HINT_ENABLED=true     # Send hints for failed stripes
GATEWAY_REPAIR_HINT_MIN_INTERVAL_SECS=600 # Min seconds between hints
GATEWAY_REPAIR_HINT_COUNT=2               # Stripes per hint request
GATEWAY_REPAIR_HINT_ALLOW_SCAN=false      # Allow expensive legacy scan
VALIDATOR_GATEWAY_KEY=<secret>            # Auth for repair hint endpoint
```

#### TLS Configuration

```bash
ARION_GATEWAY_TLS_CERT=/etc/arion/gateway/cert.pem  # TLS certificate path
ARION_GATEWAY_TLS_KEY=/etc/arion/gateway/key.pem    # TLS private key path
ACCEPT_INVALID_CERTS=true                            # Accept self-signed certs (dev)
```

See `gateway.example.env` for a complete template.

## API Endpoints

| Method | Path | Auth | Description |
|--------|------|------|-------------|
| POST | `/upload` | `X-API-Key` header | Upload file (multipart/form-data) |
| GET | `/download/:hash` | None | Download file by BLAKE3 hash |
| GET | `/blobs/:hash` | None | Alias for download |
| DELETE | `/blobs/:hash` | Forwarded | Delete file (proxied to validator) |
| GET | `/stats` | None | Miner latency rankings and bandwidth stats |
| GET | `/metrics` | None | Prometheus metrics |

### Upload

Uploads a file via multipart/form-data. The file is streamed to disk, then forwarded to the validator which handles Reed-Solomon encoding and CRUSH placement.

```bash
curl -k -X POST \
  -H "X-API-Key: ${API_KEY_ADMIN}" \
  -F "file=@test.txt" \
  https://localhost:3000/upload
```

Response:
```json
{"hash": "abc123..."}
```

### Download

Downloads a file by its BLAKE3 hash. The gateway fetches the manifest, calculates CRUSH placement, fetches k shards in parallel from miners, and reconstructs the original data using Reed-Solomon decoding.

```bash
curl -k -L -o out.txt https://localhost:3000/download/<file_hash>
```

Supports HTTP Range headers for partial content:
```bash
curl -k -H "Range: bytes=0-999" https://localhost:3000/download/<file_hash>
```

### Delete

Deletes a file by hash. The request is proxied to the validator via P2P (preferred) or HTTP.

```bash
curl -k -X DELETE \
  -H "Authorization: Bearer ${API_KEY}" \
  https://localhost:3000/blobs/<file_hash>
```

### Stats

Returns miner latency rankings and bandwidth statistics:

```bash
curl -k https://localhost:3000/stats
```

Response:
```json
{
  "miner_latency": [
    {"miner_uid": 1, "latency_ms": "12.5"},
    {"miner_uid": 2, "latency_ms": "18.3"}
  ],
  "bandwidth": [
    {"miner_uid": "1", "bytes": 1048576}
  ],
  "total_miners_tracked": 2
}
```

### Metrics

Prometheus metrics endpoint:

```bash
curl -k https://localhost:3000/metrics
```

Key metrics:
- `gateway_http_requests_total` - Total requests by method/status
- `gateway_request_duration_seconds` - Request latency histogram
- `gateway_upload_bytes_total` - Total bytes uploaded
- `gateway_download_bytes_total` - Total bytes downloaded
- `gateway_active_uploads` - Current in-flight uploads
- `gateway_active_downloads` - Current in-flight downloads
- `gateway_cache_hits_total` - Blob cache hits
- `gateway_cache_misses_total` - Blob cache misses
- `gateway_connection_pool_size` - P2P connection pool size

## Architecture

### Upload Flow

```
Client (HTTP POST multipart)
    |
    v
Gateway (stream to temp file)
    |
    v
Validator (HTTP POST multipart)
    |
    v
RS encode + CRUSH placement
    |
    v
P2P Store to Miners
```

### Download Flow

```
Client (HTTP GET)
    |
    v
Gateway
    |-- Fetch manifest (doc replica > P2P > HTTP)
    |-- Snapshot cluster map
    |-- Calculate CRUSH placement per stripe
    |
    v
Parallel FetchBlob to miners (P2P)
    |-- Sort by latency (fastest first)
    |-- LRU cache check
    |-- Fallback to alternate epochs during rebalance
    |
    v
RS decode (k shards required)
    |
    v
Stream to client
```

### P2P Communication

The gateway uses the `hippius/gateway-control` protocol for validator communication:
- `GetClusterMap` - Fetch current cluster topology
- `GetManifest` - Fetch file metadata
- `GetRebalanceStatus` - Check if PG rebalancing is complete
- `ReportBandwidth` - Report miner bandwidth stats
- `ReportFailures` - Report miner fetch failures
- `RepairHint` - Request repair for failed stripes
- `DeleteFile` - Delete a file

For shard fetching, the gateway uses `hippius/miner-control` protocol:
- `FetchBlob` - Retrieve a shard by hash

### Background Tasks

Three background loops run continuously:
1. **Map sync** (2s interval) - Syncs cluster map from validator, cleans up expired blacklist/cache entries
2. **Bandwidth reporting** (30s interval) - Reports miner bandwidth stats to validator
3. **Failure reporting** (30s interval) - Reports miner fetch failures to validator

## Scalability

The gateway uses lock-free data structures for high concurrency:

| Component | Type | Purpose |
|-----------|------|---------|
| `blob_cache` | `quick_cache::Cache` | LRU cache (50k entries) |
| `miner_latency` | `DashMap<u32, f64>` | Lock-free latency tracking |
| `bandwidth_stats` | `DashMap<String, u64>` | Lock-free bandwidth tracking |
| `connection_pool` | `RwLock<HashMap>` | P2P connection reuse (60s TTL) |
| `miner_blacklist` | `DashMap` | Byzantine miner blacklist (5min TTL) |

Backpressure controls:
- `upload_semaphore` - Max 500 concurrent uploads
- `download_global_semaphore` - Bounds total FetchBlob tasks (default 512)
- Per-request parallelism limit (default 64)

## Security

- API key authentication for uploads (`X-API-Key` header)
- BLAKE3 hash verification on all fetched shards
- Byzantine miner blacklisting (5 minutes per blob hash)
- Filename sanitization for Content-Disposition headers
- TLS encryption for all HTTP traffic
- Constant-time API key comparison to prevent timing attacks

## Development

```bash
# Run with debug logging
RUST_LOG=debug cargo run --bin gateway -- --port 3000

# Run tests
cargo test -p gateway

# Format code
cargo fmt -p gateway

# Lint
cargo clippy -p gateway
```

For development, the gateway auto-generates self-signed TLS certificates at `/tmp/arion-gateway-{cert,key}.pem`. Use `curl -k` or set `ACCEPT_INVALID_CERTS=true` to skip verification.

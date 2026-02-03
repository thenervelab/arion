# Listener

Read-only replica service for Hippius Arion. Connects to a validator via P2P (`hippius/gateway-control` protocol) and serves lightweight HTTPS endpoints for cluster map and file manifests.

## Overview

The listener acts as a read-only proxy that:
- Connects to the validator using P2P (Iroh endpoint)
- Periodically syncs the cluster map (every 5 seconds)
- Fetches file manifests on-demand via P2P
- Serves cached data over HTTPS with API key authentication

## Quick Start

```bash
# Build
cargo build -p listener --release

# Run (minimal configuration)
export VALIDATOR_NODE_ID="<validator-hex-pubkey>"
cargo run --bin listener -- --port 3005

# With custom data directory
export LISTENER_DATA_DIR="/var/lib/arion/listener"
cargo run --bin listener
```

## Architecture

```
Validator                    Listener (reads)          Clients
     |                            |                       |
     |<-- P2P gateway-control ----|                       |
     |    (GetClusterMap,         |                       |
     |     GetManifest)           |<---- GET /map --------|
     |                            |<---- GET /manifest ---|
     |                            |<---- GET /health -----|
```

## Configuration

### CLI Arguments

| Argument | Environment Variable | Default | Description |
|----------|---------------------|---------|-------------|
| `--port` | `PORT` | `3005` | HTTPS server port |
| `--validator-node-id` | `VALIDATOR_NODE_ID` | **required** | Validator's Iroh node ID (hex-encoded Ed25519 public key) |

### Environment Variables

| Variable | Default | Description |
|----------|---------|-------------|
| `VALIDATOR_NODE_ID` | **required** | Validator's Iroh node ID for P2P connection |
| `PORT` | `3005` | HTTPS server port |
| `LISTENER_DATA_DIR` | `data/listener` | Directory for keypair and local data |
| `RUST_LOG` | `info` | Logging level (e.g., `debug`, `info`, `warn`) |
| `ARION_API_KEY` | `Hippius-Arion-Dev-01` | API key for protected endpoints |
| `ARION_LISTENER_TLS_CERT` | `/etc/arion/listener/cert.pem` | TLS certificate path |
| `ARION_LISTENER_TLS_KEY` | `/etc/arion/listener/key.pem` | TLS private key path |

### TLS Configuration

The listener serves HTTPS with automatic TLS certificate management:

1. **Environment variables** (highest priority): Set `ARION_LISTENER_TLS_CERT` and `ARION_LISTENER_TLS_KEY`
2. **Default system paths**: `/etc/arion/listener/cert.pem` and `/etc/arion/listener/key.pem`
3. **Auto-generated self-signed** (development fallback): `/tmp/arion-listener-cert.pem` and `/tmp/arion-listener-key.pem`

## API Endpoints

All endpoints except `/health` require the `X-API-Key` header for authentication.

| Method | Path | Auth | Description |
|--------|------|------|-------------|
| GET | `/health` | No | Health check (returns version info) |
| GET | `/map` | Yes | Current cluster map JSON (cached, synced every 5s) |
| GET | `/manifest/{hash}` | Yes | File manifest by BLAKE3 hash (fetched on-demand) |

### Response Codes

| Endpoint | Code | Description |
|----------|------|-------------|
| `/health` | 200 | Service is running |
| `/map` | 200 | Cluster map returned |
| `/map` | 503 | Cluster map not yet synced |
| `/manifest/{hash}` | 200 | Manifest found |
| `/manifest/{hash}` | 400 | Invalid hash format (must be 64 hex chars) |
| `/manifest/{hash}` | 404 | Manifest not found |
| `/manifest/{hash}` | 500 | Failed to fetch from validator |

## Use Cases

- **Gateway read offload**: Reduce load on validator for manifest lookups
- **Monitoring**: Lightweight read access to cluster state without validator privileges
- **Multi-region**: Deploy listeners close to users for faster reads
- **High availability**: Multiple listeners can serve cached cluster maps

## Example Usage

```bash
# Health check (no auth required)
curl -k https://localhost:3005/health

# Get cluster map (requires API key)
curl -k -H "X-API-Key: Hippius-Arion-Dev-01" https://localhost:3005/map

# Get file manifest (requires API key)
curl -k -H "X-API-Key: Hippius-Arion-Dev-01" \
  https://localhost:3005/manifest/abc123...  # 64-char hex hash
```

## Sync Behavior

- **Initial sync**: Retries up to 100 times with exponential backoff (max 60s)
- **Background sync**: Cluster map refreshed every 5 seconds
- **Manifests**: Fetched on-demand from validator (not cached locally)

## Data Directory

The listener stores its Ed25519 keypair in the data directory:

```
$LISTENER_DATA_DIR/
  keypair.bin    # Ed25519 private key (0600 permissions on Unix)
```

The keypair is auto-generated on first run and persists across restarts.

## Docker

Build and run using the provided Dockerfile:

```bash
docker build -f listener/dockerfile -t listener .
docker run -p 3005:3005 \
  -e VALIDATOR_NODE_ID="<validator-node-id>" \
  -e ARION_API_KEY="your-api-key" \
  listener
```

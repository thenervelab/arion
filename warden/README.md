# Warden

Proof-of-storage audit service for Hippius Arion. The warden periodically challenges miners to prove they still store the data they claim to store using Plonky3 zero-knowledge proofs. Audit results are signed and submitted both to the chain (via chain-submitter) and to the validator (for reputation updates).

## Features

- **Proof-of-Storage Audits**: Challenges miners with random chunk indices and verifies their Plonky3 ZK proofs
- **Epoch-Based Sampling**: Shards are cleared and re-sampled at configurable epoch boundaries (default: 1 hour)
- **Ed25519 Attestation Signing**: All audit results are signed using SCALE encoding compatible with on-chain verification
- **P2P Communication**: Primary communication with validator and miners via Iroh P2P protocols
- **Persistent State**: Sled database for shard tracking and retry queue across restarts
- **Retry Queue**: Failed attestation submissions are queued with exponential backoff for later retry

## Quick Start

```bash
# Build
cargo build -p warden --release

# Run with default configuration
cargo run --bin warden

# Run with custom config file
cp warden.example.toml warden.toml
cargo run --bin warden -- --config warden.toml
```

## Configuration

Copy `warden.example.toml` to `warden.toml` and customize:

```toml
# Data directory for warden state (P2P keypair, node_id, etc.)
data_dir = "data/warden"

# Path to Ed25519 keypair for signing attestations
keypair_path = "data/warden/keypair.bin"

# Sled database path for persistent shard storage
db_path = "data/warden/shards.db"

# HTTPS listen address (validator push, health)
listen_addr = "0.0.0.0:3003"

# Chain submitter service URL
chain_submitter_url = "http://localhost:3004"

# Audit interval in seconds
audit_interval_secs = 30

# Number of shards to audit per interval
shards_per_audit = 10

# Challenge timeout in seconds (after which Timeout attestation is created)
challenge_timeout_secs = 60

# Number of chunk indices per challenge
chunks_per_challenge = 4
```

## Environment Variables

All configuration options can be overridden via environment variables:

| Variable | Default | Description |
|----------|---------|-------------|
| `WARDEN_DATA_DIR` | `data/warden` | Directory for warden state files |
| `WARDEN_KEYPAIR_PATH` | `data/warden/keypair.bin` | Ed25519 signing keypair path |
| `WARDEN_DB_PATH` | `data/warden/shards.db` | Sled database for persistent storage |
| `WARDEN_LISTEN_ADDR` | `0.0.0.0:3003` | HTTPS listen address |
| `CHAIN_SUBMITTER_URL` | `http://localhost:3004` | Chain submitter endpoint |
| `CHAIN_SUBMITTER_INSECURE_TLS` | `false` | Skip TLS verification (dev only) |
| `WARDEN_AUDIT_INTERVAL_SECS` | `30` | Seconds between audit batches |
| `WARDEN_SHARDS_PER_AUDIT` | `10` | Shards to challenge per interval |
| `WARDEN_CHALLENGE_TIMEOUT_SECS` | `60` | Seconds before challenge times out |
| `WARDEN_CHUNKS_PER_CHALLENGE` | `4` | Random chunk indices per challenge |
| `WARDEN_MAX_SHARDS` | `5000` | Maximum shards to track per epoch |
| `WARDEN_MAX_PENDING_CHALLENGES` | `10000` | Maximum concurrent pending challenges |
| `AUDIT_EPOCH_SECS` | `3600` | Epoch duration (shards cleared at boundary) |
| `WARDEN_VALIDATOR_URL` | - | Validator HTTP URL (fallback) |
| `WARDEN_VALIDATOR_API_KEY` | - | API key for validator authentication |
| `WARDEN_VALIDATOR_INSECURE_TLS` | `false` | Skip validator TLS verification (dev only) |
| `WARDEN_VALIDATOR_NODE_ID` | - | Validator's Iroh node ID for P2P communication |
| `ARION_API_KEY` | - | API key for chain-submitter authentication |

### TLS Configuration

The warden runs HTTPS by default. TLS certificates are loaded in the following order:

1. **Environment variables**: `ARION_WARDEN_TLS_CERT` and `ARION_WARDEN_TLS_KEY`
2. **Default system paths**: `/etc/arion/warden/cert.pem` and `/etc/arion/warden/key.pem`
3. **Auto-generated self-signed**: `/tmp/arion-warden-cert.pem` (development fallback, logs warning)

## Architecture

```
                                P2P (hippius/warden-control)
Validator ───────────────────────────────────────────────────▶ Warden
           (pushes shard commitments at epoch start)             │
                                                                 │
                                                     ┌───────────┴───────────┐
                                                     │                       │
                                          P2P (hippius/miner-control)       │
                                                     │                       │
                                                     ▼                       │
                                                  Miners                     │
                                                     │                       │
                                        (prove storage with                  │
                                         Plonky3 ZK proofs)                  │
                                                     │                       │
                                                     ▼                       │
                                              ┌──────┴──────┐                │
                                              │             │                │
                                              │   Verify    │                │
                                              │   Proof     │                │
                                              │             │                │
                                              └──────┬──────┘                │
                                                     │                       │
                           ┌─────────────────────────┼───────────────────────┘
                           │                         │
                           ▼                         ▼
              P2P (hippius/warden-control)    HTTPS POST /attestations
                           │                         │
                           ▼                         ▼
                       Validator              Chain-Submitter
                  (reputation updates)         (on-chain slashing)
```

## Audit Flow

1. **Epoch Start**: Validator samples shards and pushes commitments to warden via P2P
2. **Challenge Generation**: Warden generates deterministic challenges using:
   - Shard hash (what is being audited)
   - Block hash (freshness, prevents replay)
   - Warden ID (prevents cross-warden replay)
3. **Challenge Dispatch**: Warden sends `PosChallenge` to miner via P2P (`hippius/miner-control`)
4. **Proof Response**: Miner computes and returns Plonky3 proof within timeout
5. **Verification**: Warden verifies proof against expected Merkle root
6. **Attestation**: Warden signs result and submits to:
   - Chain-submitter (for on-chain storage/slashing)
   - Validator (for real-time reputation updates)
7. **Epoch End**: Shards cleared, validator pushes new sample for next epoch

## Audit Results

| Result | Meaning | Reputation Effect |
|--------|---------|-------------------|
| `Passed` | Proof verified successfully | Recovery after 10 consecutive passes |
| `Failed` | Proof failed verification | +1.0 strike |
| `Timeout` | No response within deadline | +0.3 strike |
| `InvalidProof` | Malformed proof data | +1.0 strike |

Miners with reputation >= 3.0 are banned from the cluster.

## Attestation Signing

Attestations use SCALE encoding with a domain separator for cross-component verification:

```rust
const ATTESTATION_DOMAIN_SEPARATOR: &[u8] = b"ARION_ATTESTATION_V1";

// Signed data structure (must match pallet-arion verification)
(
    ATTESTATION_DOMAIN_SEPARATOR,
    shard_hash.as_bytes(),
    miner_uid,                    // u32
    result.as_u8(),               // 0=Passed, 1=Failed, 2=Timeout, 3=InvalidProof
    challenge_seed,               // [u8; 32]
    block_number,                 // u64
    timestamp,                    // u64
    &merkle_proof_sig_hash,       // Vec<u8> - BLAKE3 hash of proof bytes
    warden_id.as_bytes(),         // Hex-encoded warden Ed25519 pubkey
).encode()
```

The Ed25519 keypair is automatically generated on first run and persisted to `keypair_path`. The keypair file is created with mode 0600 on Unix systems.

## API Endpoints

### Protected Routes (require `X-API-Key` header)

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/shards` | POST | Validator pushes shard commitment |
| `/shards/{shard_hash}` | DELETE | Validator notifies shard deletion |

### Open Routes

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/health` | GET | Health check with version and stats |

### Health Response

```json
{
  "status": "healthy",
  "version": "0.1.0",
  "shards_tracked": 150,
  "pending_challenges": 5
}
```

## P2P Protocols

The warden uses two P2P protocols:

### `hippius/miner-control` (Outbound to Miners)

Sends `PosChallenge` messages and receives `PosProofResponse`:

```rust
// Challenge sent to miner
MinerControlMessage::PosChallenge {
    shard_hash: String,
    chunk_indices: Vec<u32>,
    nonce: [u8; 32],
    expected_root: [u32; 8],
    expires_at: u64,
}

// Response from miner
ValidatorControlMessage::PosProofResponse {
    nonce: [u8; 32],
    proof_bytes: Vec<u8>,
    proving_time_ms: u64,
}
```

### `hippius/warden-control` (Bidirectional with Validator)

Receives shard commitments from validator, pushes audit results:

```rust
// From validator
WardenControlMessage::PushShardCommitment { ... }
WardenControlMessage::DeleteShard { shard_hash }

// To validator
WardenControlMessage::PushAuditResults { batch }
```

## Persistent State

The warden maintains state across restarts using Sled:

| Tree | Contents |
|------|----------|
| `shards` | Shard commitments (hash, Merkle root, chunk count, miner info) |
| `meta` | Audit cursor position, current epoch number |
| `retry_queue` | Failed attestations awaiting retry (exponential backoff) |

The P2P node ID is also persisted to `data_dir/p2p_keypair.bin` ensuring stable identity.

## Retry Queue

Failed attestation submissions (both to validator and chain-submitter) are queued for retry:

- **Exponential backoff**: `30s * 2^retry_count`, capped at 1 hour
- **Max retries**: 10 attempts before dropping
- **Epoch transition**: Retry queue is drained before clearing shards for new epoch

## Testing

```bash
# Run all tests
cargo test -p warden

# Run with output
cargo test -p warden -- --nocapture

# Run specific test
cargo test -p warden test_verify_valid_proof
```

## Logging

Use `RUST_LOG` for component-specific logging:

```bash
# Debug all warden logs
RUST_LOG=warden=debug cargo run --bin warden

# Debug specific modules
RUST_LOG=warden::audit=debug,warden::p2p=trace cargo run --bin warden
```

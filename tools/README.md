# tools

Utility tools for Hippius Arion development and operations.

## Building

```bash
cargo build -p tools --release
```

## Binaries

### generate_registration_data

Generates miner registration data for on-chain submission to `pallet-arion`. This tool reads the miner's Ed25519 keypair and produces a signed registration message for the `register_child` extrinsic.

**Registration Message Format:**

The message is SCALE-encoded and matches pallet-arion's verification:
```
(b"ARION_NODE_REG_V1", family_account, child_account, node_id, nonce).encode()
```

**Usage:**

```bash
# Human-readable output (for Polkadot.js Apps)
cargo run --bin generate_registration_data -- \
  --family 5GrwvaEF... \
  --child 5FHneW46... \
  --miner-id 1 \
  --keypair data/miner-1/keypair.bin

# Machine-readable JSON output (for scripts)
cargo run --bin generate_registration_data -- \
  --family 5GrwvaEF... \
  --child 5FHneW46... \
  --miner-id 1 \
  --keypair data/miner-1/keypair.bin \
  --output-json
```

**Arguments:**

| Argument | Required | Description |
|----------|----------|-------------|
| `--family` | Yes | Family account SS58 address (parent that manages the miner) |
| `--child` | Yes | Child account SS58 address (receives rewards for this miner) |
| `--miner-id` | Yes | Miner ID for display purposes (e.g., 1 for miner-1) |
| `--keypair` | Yes | Path to miner keypair file (32-byte Ed25519 secret key) |
| `--nonce` | No | Node ID nonce for replay protection (default: 0) |
| `--output-json` | No | Output as JSON instead of human-readable format |

**Output:**

Human-readable format:
```
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
MINER-1
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
family:    5GrwvaEF...
child:     5FHneW46...

node_id:   0x...
node_sig:  0x...

WARNING: These values are for one-time registration. Do not share publicly.
```

JSON format:
```json
{"miner_id":1,"family":"5Grw...","child":"5FHn...","node_id":"0x...","node_sig":"0x..."}
```

**Security Notes:**

- The keypair file contains the miner's secret key - ensure restrictive permissions (`chmod 600`)
- The generated signature should only be used once and not shared publicly

---

### verify_attestations

Verifies warden attestation bundles against on-chain commitments. This tool enables anyone to independently verify that audit attestations are valid and match what was committed to the blockchain.

**Verification Steps:**

1. Query chain for `EpochAttestationCommitments[epoch]`
2. Download bundle from Arion gateway using `arion_content_hash`
3. Verify `BLAKE3(bundle_bytes) == arion_content_hash`
4. Recompute attestation merkle root and compare
5. Recompute warden pubkey merkle root and compare
6. Verify Ed25519 signature on each attestation

**Usage:**

```bash
# Basic verification
cargo run --bin verify_attestations -- \
  --epoch 42 \
  --chain-ws-url wss://node:9944 \
  --gateway-url http://gateway:3000

# With API key for authenticated gateway
cargo run --bin verify_attestations -- \
  --epoch 42 \
  --chain-ws-url wss://node:9944 \
  --gateway-url http://gateway:3000 \
  --api-key your-api-key

# JSON output for scripts
cargo run --bin verify_attestations -- \
  --epoch 42 \
  --json-output

# Skip signature verification (faster, less thorough)
cargo run --bin verify_attestations -- \
  --epoch 42 \
  --skip-signatures
```

**Arguments:**

| Argument | Required | Default | Description |
|----------|----------|---------|-------------|
| `--epoch` | Yes | - | Epoch to verify (env: `VERIFY_EPOCH`) |
| `--chain-ws-url` | No | `wss://127.0.0.1:9944` | Substrate/Polkadot chain WebSocket URL (env: `CHAIN_WS_URL`) |
| `--gateway-url` | No | `http://127.0.0.1:3000` | Gateway URL for downloading bundles (env: `GATEWAY_URL`) |
| `--pallet-name` | No | `Arion` | Pallet name for storage queries |
| `--skip-signatures` | No | `false` | Skip signature verification (faster) |
| `--json-output` | No | `false` | Output detailed verification results as JSON |
| `--api-key` | No | - | API key for gateway authentication (env: `ARION_API_KEY`) |

**Output:**

Human-readable format:
```
=== Attestation Verification Result ===
Epoch: 42
Status: PASSED
Attestation count: 100
Content hash: OK
Attestation merkle root: OK
Warden pubkey merkle root: OK
Signatures verified: 100/100
```

JSON format:
```json
{
  "epoch": 42,
  "success": true,
  "attestation_count": 100,
  "verified_signatures": 100,
  "failed_signatures": 0,
  "content_hash_valid": true,
  "attestation_root_valid": true,
  "warden_root_valid": true,
  "errors": []
}
```

**Exit Codes:**

- `0`: Verification passed
- `1`: Verification failed or error occurred

**Logging:**

Use the `RUST_LOG` environment variable to control log verbosity:
```bash
RUST_LOG=debug cargo run --bin verify_attestations -- --epoch 42
```

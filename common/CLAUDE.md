# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Overview

The common crate provides shared types and algorithms used across all Hippius Arion components. It includes the CRUSH placement algorithm, Reed-Solomon codec, P2P protocol messages, and utility functions.

See the parent `../CLAUDE.md` for workspace-level commands and architecture.

## Build & Test

```bash
# Build
cargo build -p common

# Test
cargo test -p common

# Check
cargo check -p common
```

## Module Structure

| File | Purpose |
|------|---------|
| `lib.rs` | Core types (MinerNode, ClusterMap, FileManifest), CRUSH algorithm, RS codec, P2P messages |
| `attestation_bundle.rs` | Verifiable proof types (AttestationBundle, AttestationLeaf, MerkleProof, EpochAttestationCommitment) |
| `merkle.rs` | BLAKE3-based merkle tree construction and verification for attestation proofs |
| `middleware.rs` | Axum middleware for API key validation (constant-time comparison) |
| `tls.rs` | TLS certificate loading with self-signed fallback for development |

## Key Types

### MinerNode
Storage miner in the network with UID, endpoint, weight, family, storage stats, and reputation.

Key fields:
- `uid`: Unique miner identifier
- `endpoint`: Iroh endpoint address for P2P
- `weight`: CRUSH placement weight
- `family_id`: For fault domain diversity
- `strikes`: Legacy integer strikes (derived from reputation)
- `reputation`: Fractional reputation score (0.0 = perfect, 3.0+ = ban)
- `consecutive_audit_passes`: Counter for reputation recovery

### ClusterMap
Epoch-scoped cluster topology: miners, PG count (16384 default), stripe config.

### FileManifest
Maps file hash to stripes with placement version and epoch for deterministic shard location.

### StripeConfig
Erasure coding parameters: k=10 data, m=20 parity, 2 MiB stripe size.

### Protocol Messages
- `MinerControlMessage`: Validator→Miner (Store, Delete, FetchBlob, PullFromPeer, CheckBlob)
- `ValidatorControlMessage`: Miner→Validator (Register, Heartbeat, QueryPgFiles)
- `GatewayControlMessage`: Gateway↔Validator (GetClusterMap, GetManifest, UploadFile, etc.)
- `WardenControlMessage`: Warden→Validator (PushAuditResults)
- `SubmitterControlMessage`: ChainSubmitter→Validator (GetClusterMap, GetNetworkStats)

### Audit Types (Reputation System)

```rust
// Audit result classification
pub enum AuditResultType {
    Passed,       // Proof verified successfully
    Failed,       // Proof verification failed
    Timeout,      // No response within deadline
    InvalidProof, // Malformed proof data
}

// Single audit report from warden (used for validator reputation updates)
pub struct WardenAuditReport {
    pub audit_id: String,                    // Hex-encoded challenge_seed
    pub warden_pubkey: String,               // Iroh PublicKey format or hex
    pub miner_uid: u32,
    pub shard_hash: String,
    pub result: AuditResultType,
    pub timestamp: u64,
    pub signature: Vec<u8>,                  // 64-byte Ed25519 signature
    // Fields for SCALE signature verification (matches on-chain format)
    pub block_number: u64,                   // Block at challenge time
    pub merkle_proof_sig_hash: Vec<u8>,      // BLAKE3 hash of proof bytes (empty for timeout)
    pub warden_id: String,                   // Hex-encoded warden Ed25519 pubkey
}

// Batch of reports for HTTP/P2P push
pub struct WardenAuditBatch {
    pub reports: Vec<WardenAuditReport>,
}
```

### Verifiable Proof Types (On-Chain Attestation Bundles)

These types support the verifiable proofs system where attestation bundles are stored in Arion
and verified against on-chain commitments:

```rust
/// A single attestation leaf in the merkle tree
pub struct AttestationLeaf {
    pub audit_id: String,           // Unique audit identifier
    pub shard_hash: String,         // BLAKE3 hash of audited shard
    pub miner_uid: u32,             // Miner that was audited
    pub result: AuditResultType,    // Passed/Failed/Timeout/InvalidProof
    pub timestamp: u64,             // When audit was performed
    pub block_number: u64,          // Block number at audit time
    pub warden_pubkey: [u8; 32],    // Ed25519 public key of warden
    pub signature: [u8; 64],        // Ed25519 signature
    pub merkle_proof_sig_hash: Vec<u8>, // BLAKE3 hash of proof bytes
    pub warden_id: String,          // Hex-encoded warden ID
}

/// Merkle proof for verifying leaf inclusion
pub struct MerkleProof {
    pub leaf_index: u32,            // Index of leaf in tree
    pub siblings: Vec<[u8; 32]>,    // Sibling hashes along path
    pub directions: Vec<bool>,      // true = sibling is on right
}

/// Full bundle stored in Arion (SCALE-encoded)
pub struct AttestationBundle {
    pub version: u8,                        // Bundle format version
    pub epoch: u64,                         // Epoch this bundle covers
    pub attestation_merkle_root: [u8; 32],  // Merkle root of attestations
    pub warden_pubkey_merkle_root: [u8; 32],// Merkle root of warden pubkeys
    pub attestations: Vec<AttestationWithProof>, // Attestations with proofs
    pub warden_pubkeys: Vec<[u8; 32]>,      // Unique warden public keys
}

/// Compact commitment stored on-chain
pub struct EpochAttestationCommitment {
    pub epoch: u64,
    pub arion_content_hash: [u8; 32],       // BLAKE3 hash of bundle
    pub attestation_merkle_root: [u8; 32],  // For verification
    pub warden_pubkey_merkle_root: [u8; 32],
    pub attestation_count: u32,
}
```

### Merkle Tree Functions

```rust
use common::{build_merkle_tree, verify_merkle_proof, blake3_hash};

// Build a merkle tree from SCALE-encoded leaves
let (root, proofs) = build_merkle_tree(&attestation_leaves);

// Verify a single leaf against the root
let valid = verify_merkle_proof(&leaf, &proof, &root);

// Hash raw bytes (for arion_content_hash)
let hash = blake3_hash(&bundle_bytes);
```

Design notes:
- Uses BLAKE3 for all hashing (fast, cryptographically secure)
- Domain-separated: leaf hash = `BLAKE3(0x00 || SCALE(leaf))`
- Internal nodes: `BLAKE3(0x01 || left || right)`
- Non-power-of-two leaves padded by duplicating last leaf

### Signature Format

Warden signatures use **SCALE encoding** with domain separator `ARION_ATTESTATION_V1` for verification alignment across:
- Warden (signing)
- Validator (real-time reputation verification)
- Chain-submitter (pre-submission verification)
- Pallet-arion (on-chain slashing verification)

```rust
use parity_scale_codec::Encode;

const ATTESTATION_DOMAIN_SEPARATOR: &[u8] = b"ARION_ATTESTATION_V1";

let sign_data = (
    ATTESTATION_DOMAIN_SEPARATOR,
    shard_hash.as_bytes(),
    miner_uid,
    result.as_u8(),           // 0=Passed, 1=Failed, 2=Timeout, 3=InvalidProof
    challenge_seed,
    block_number,
    timestamp,
    &merkle_proof_sig_hash,
    warden_id.as_bytes(),
).encode();
```

## Placement Algorithm

Two versions controlled by `FileManifest.placement_version`:

**Version 1 (legacy)**: Per-stripe CRUSH with seed = `hash(file_hash + stripe_index)`

**Version 2 (PG-based)**: File→PG mapping, then CRUSH on PG ID with stripe rotation

### Key Functions

```rust
// Dispatcher based on placement version
calculate_stripe_placement(&cluster_map, file_hash, stripe_idx, version) -> Vec<(u32, String)>

// Core CRUSH with family diversity
calculate_placement_for_stripe(&miners, seed, replica_count, stripe_idx) -> Vec<(u32, String)>

// Maps file hash to Placement Group
calculate_pg(file_hash, pg_count) -> u32
```

## Reed-Solomon Codec

```rust
// Encode data stripe into k+m shards
encode_stripe(data: &[u8], config: &StripeConfig) -> Result<Vec<Vec<u8>>>

// Decode from any k shards
decode_stripe(shards: &[Option<Vec<u8>>], config: &StripeConfig) -> Result<Vec<u8>>
```

## IP and Path Helpers

```rust
// Check if IP is suitable for self-advertisement (rejects loopback,
// unspecified, link-local, broadcast, multicast; allows private/CGNAT/ULA)
pub fn is_advertisable_ip(ip: IpAddr) -> bool

// Check if endpoint has at least one direct IP address (not relay-only).
// Does NOT filter by IP routability — Iroh handles path selection.
pub fn has_direct_addr(addr: &EndpointAddr) -> bool

// Check if a live connection has a direct IP path (not relay-only)
pub fn has_direct_ip_path(conn: &Connection) -> bool

// Wait for a direct IP path within timeout (watcher-based, no polling)
pub async fn wait_for_direct_ip_path(conn: &Connection, timeout: Duration) -> bool

// Legacy: check if IP is publicly routable (retained for diagnostics)
pub fn is_routable_ip(ip: IpAddr) -> bool
```

## Utility Functions

```rust
// Safe timestamp - returns 0 on clock skew instead of panicking
pub fn now_secs() -> u64

// EMA update for latency smoothing
pub fn update_ema_latency(current: f64, sample: f64, alpha: f64) -> f64

// Alpha constant for EMA (20% new, 80% old)
pub const LATENCY_EMA_ALPHA: f64 = 0.2;

// Tombstone marker for deleted manifests in cache
pub const MANIFEST_TOMBSTONE: &str = "DELETED";
```

## P2P Protocol Constants

```rust
pub const MINER_CONTROL_ALPN: &[u8] = b"hippius/miner-control";
pub const GATEWAY_CONTROL_ALPN: &[u8] = b"hippius/gateway-control";
pub const WARDEN_CONTROL_ALPN: &[u8] = b"hippius/warden-control";
pub const SUBMITTER_CONTROL_ALPN: &[u8] = b"hippius/submitter-control";

// Message size limits
pub const P2P_MAX_MESSAGE_SIZE: usize = 1024 * 1024;        // 1 MiB
pub const P2P_MAX_RESPONSE_SIZE: usize = 10 * 1024 * 1024;  // 10 MiB
pub const P2P_MAX_UPLOAD_SIZE: usize = 100 * 1024 * 1024;   // 100 MiB

// Timeouts and connection pooling
pub const P2P_DEFAULT_TIMEOUT_SECS: u64 = 30;
pub const P2P_CONNECTION_TTL_SECS: u64 = 60;

// Retry configuration
pub const P2P_MAX_CONNECT_RETRIES: u32 = 3;
pub const P2P_INITIAL_BACKOFF_MS: u64 = 100;
pub const P2P_MAX_BACKOFF_MS: u64 = 5000;
```

## P2P Connection Manager

The `P2pConnectionManager` provides reusable connection pooling with:
- Connection caching with TTL (60 seconds default)
- Health checking before reuse
- Exponential backoff retries (100ms → 200ms → 400ms, capped at 5s)
- Metrics tracking for unhealthy connections

```rust
use common::{P2pConnectionManager, GATEWAY_CONTROL_ALPN};

// Create a connection manager
let manager = P2pConnectionManager::new(endpoint, target_node_id, GATEWAY_CONTROL_ALPN);

// Get or create a connection (cached within TTL)
let conn = manager.get_connection().await?;

// Check metrics
let unhealthy_count = manager.unhealthy_connection_count();
```

Used by all P2P clients (gateway, warden, chain-submitter) for validator communication.

## Design Principles

1. **Stable placement**: All miners in CRUSH input (no filtering) for Validator/Gateway agreement
2. **Family diversity**: Shards spread across different family_ids for fault tolerance
3. **Deterministic ordering**: Miners sorted by UID before placement to avoid HashMap shuffle
4. **Safe timestamps**: Use `now_secs()` to avoid panics on clock skew

## TLS Configuration

The `tls` module provides certificate loading with fallback order:
1. Environment variables (`ARION_{SERVICE}_TLS_CERT/KEY`)
2. Default paths (`/etc/arion/{service}/cert.pem`)
3. Auto-generated self-signed (development only)

## Middleware

The `middleware` module provides Axum middleware for API key validation:
- Extracts `X-API-Key` header
- Validates against configured key
- Returns 401 on mismatch
- Constant-time comparison to prevent timing attacks

## P2P Response Helper

```rust
/// Send a length-prefixed response on a P2P stream
pub async fn p2p_send_response(
    send: &mut iroh::endpoint::SendStream,
    response_bytes: &[u8],
) -> anyhow::Result<()>
```

Used by all P2P handlers to send responses with proper framing.

## Reputation System Constants

The reputation system uses the following default values (configurable in `validator.toml`):

| Constant | Default | Purpose |
|----------|---------|---------|
| `STRIKE_WEIGHT_FAILED` | 1.0 | Reputation penalty for failed audit |
| `STRIKE_WEIGHT_INVALID_PROOF` | 1.0 | Penalty for invalid proof |
| `STRIKE_WEIGHT_TIMEOUT` | 0.3 | Penalty for timeout |
| `RECOVERY_RATE` | 0.05 | Recovery per pass after threshold |
| `MIN_PASSES_FOR_RECOVERY` | 10 | Consecutive passes before recovery |
| `BAN_THRESHOLD` | 3.0 | Reputation at which miner is banned |

## CRUSH Weight Calculation

The reputation score affects CRUSH placement weight through an exponential decay function:

```rust
// In validator/src/helpers.rs
const REPUTATION_DECAY_RATE: f32 = 0.767;
const MIN_REPUTATION_MULTIPLIER: f32 = 0.1;
const MAX_REPUTATION_MULTIPLIER: f32 = 1.0;

fn calculate_reputation_multiplier(reputation: f32) -> f32 {
    (-REPUTATION_DECAY_RATE * reputation)
        .exp()
        .clamp(MIN_REPUTATION_MULTIPLIER, MAX_REPUTATION_MULTIPLIER)
}
```

| Reputation | Multiplier | Scenario |
|------------|------------|----------|
| 0.0 | 1.00 | Perfect |
| 0.3 | 0.79 | 1 timeout |
| 1.0 | 0.46 | 1 failed audit |
| 2.0 | 0.22 | 2 failed audits |
| 3.0+ | 0.10 | Ban threshold |

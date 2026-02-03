# common

Shared library providing core types and algorithms for all Hippius Arion components.

## Features

- **CRUSH placement algorithm**: Deterministic shard distribution with family diversity
- **Reed-Solomon codec**: Erasure coding (10+20 default = 66% fault tolerance)
- **Protocol messages**: P2P communication types for validators, miners, gateways, wardens, and chain-submitter
- **Placement Groups (PGs)**: File-to-miner mapping for efficient rebalancing
- **TLS configuration**: Certificate loading with self-signed fallback
- **API key middleware**: X-API-Key authentication for HTTP endpoints
- **Attestation bundles**: Verifiable merkle tree proofs for warden audit results
- **P2P connection management**: Connection pooling with TTL and exponential backoff retries

## Usage

Add to your `Cargo.toml`:

```toml
[dependencies]
common = { path = "../common" }

# Enable Ed25519 signature verification for attestations
common = { path = "../common", features = ["verify"] }
```

## Key Types

### MinerNode

Represents a storage miner in the network:

```rust
pub struct MinerNode {
    pub uid: u32,                    // Unique identifier
    pub endpoint: iroh::EndpointAddr, // P2P endpoint with relay hints
    pub weight: u32,                 // CRUSH weight (affects shard distribution)
    pub family_id: String,           // Failure domain grouping
    pub total_storage: u64,          // Total capacity in bytes
    pub available_storage: u64,      // Available capacity in bytes
    pub reputation: f32,             // Warden audit reputation (0.0 = perfect, 3.0+ = banned)
    pub last_seen: u64,              // Unix timestamp of last heartbeat
    // ... additional fields for tracking
}
```

### ClusterMap

The authoritative view of the storage network:

```rust
pub struct ClusterMap {
    pub epoch: u64,           // Version number (increments on topology changes)
    pub miners: Vec<MinerNode>, // All registered miners
    pub pg_count: u32,        // Placement Groups (default: 16384)
    pub ec_k: usize,          // Data shards (default: 10)
    pub ec_m: usize,          // Parity shards (default: 20)
}
```

### FileManifest

Describes a stored file and its erasure-coded shards:

```rust
pub struct FileManifest {
    pub file_hash: String,        // BLAKE3 hash (64 hex chars)
    pub placement_version: u8,    // Algorithm version (1=legacy, 2=PG-based)
    pub placement_epoch: u64,     // Cluster map epoch when stored
    pub size: u64,                // Original file size
    pub stripe_config: StripeConfig,
    pub shards: Vec<ShardInfo>,   // All shard hashes grouped by stripe
    pub filename: Option<String>,
    pub content_type: Option<String>,
}
```

### StripeConfig

Configuration for Reed-Solomon erasure coding:

```rust
pub struct StripeConfig {
    pub size: u64,   // Stripe size in bytes (default: 2 MiB)
    pub k: usize,    // Data shards (default: 10)
    pub m: usize,    // Parity shards (default: 20)
}
```

### ShardInfo

Information about a single erasure-coded shard:

```rust
pub struct ShardInfo {
    pub index: usize,           // Shard index within stripe (0 to k+m-1)
    pub blob_hash: String,      // BLAKE3 hash of shard data
    pub miner_uid: Option<u32>, // Optional: miner where stored
}
```

## Placement Algorithm

Arion supports two placement versions:

- **Version 1 (legacy)**: Per-stripe CRUSH with seed = `hash(file_hash + stripe_index)`
- **Version 2 (PG-based)**: File -> PG mapping, then CRUSH on PG ID with stripe rotation

```rust
use common::{calculate_stripe_placement, ClusterMap};

// Calculate which miners should hold a stripe's shards
let placements = calculate_stripe_placement(
    file_hash,
    stripe_index,
    shards_per_stripe,  // typically k + m = 30
    &cluster_map,
    placement_version,  // 1 or 2
)?;

// For single shard lookup
let miner = calculate_shard_placement(file_hash, stripe_index, shard_index, &cluster_map);
```

### Placement Group Functions

```rust
use common::{calculate_pg, calculate_pg_placement, calculate_my_pgs};

// Map file to PG
let pg_id = calculate_pg(file_hash, cluster_map.pg_count);

// Get miners responsible for a PG
let miners = calculate_pg_placement(pg_id, shards_per_file, &cluster_map)?;

// Find which PGs a miner is responsible for (expensive - cache results)
let my_pgs = calculate_my_pgs(miner_uid, &cluster_map);
```

## Erasure Coding

```rust
use common::{encode_stripe, decode_stripe, calculate_stripe_data_len, StripeConfig};

let config = StripeConfig::default(); // k=10, m=20, size=2MiB

// Encode data into shards
let shards = encode_stripe(&data, &config)?;

// Calculate actual data length for a stripe
let stripe_data_len = calculate_stripe_data_len(file_size, stripe_index, config.size);

// Decode from any k shards (None for missing shards)
let mut shard_opts: Vec<Option<Vec<u8>>> = shards.into_iter().map(Some).collect();
shard_opts[5] = None; // Simulate missing shard
let recovered = decode_stripe(&mut shard_opts, &config, stripe_data_len)?;
```

## P2P Protocol Messages

### MinerControlMessage

Validator/Gateway -> Miner communication (`hippius/miner-control`):

```rust
pub enum MinerControlMessage {
    Store { hash: String, data: Option<Vec<u8>>, source_miner: Option<String> },
    Delete { hash: String },
    FetchBlob { hash: String },
    ClusterMapUpdate { epoch: u64, peers: Vec<(String, String)>, cluster_map_json: Option<String> },
    QueryPgFiles { pg_id: u32 },
    PgFilesResponse { pg_id: u32, files: Vec<String> },
    PullFromPeer { hash: String, peer_endpoint: String },
    PosChallenge { shard_hash: String, chunk_indices: Vec<u32>, nonce: [u8; 32], ... },
}
```

### ValidatorControlMessage

Miner -> Validator communication (`hippius/validator-control`):

```rust
pub enum ValidatorControlMessage {
    Register { public_key: String, http_addr: String, family_id: String, ... },
    Heartbeat { miner_uid: u32, timestamp: u64, available_storage: u64, ... },
    Ping { timestamp: u64 },
    QueryPgFiles { pg_id: u32 },
    QueryPgFilesBatch { pg_ids: Vec<u32> },
    QueryManifest { file_hash: String },
    PosProofResponse { nonce: [u8; 32], proof_bytes: Vec<u8>, ... },
}
```

### GatewayControlMessage

Gateway <-> Validator communication (`hippius/gateway-control`):

```rust
pub enum GatewayControlMessage {
    // Requests
    GetClusterMap,
    GetClusterMapEpoch { epoch: u64 },
    GetManifest { file_hash: String },
    UploadFile { filename: String, size: u64, data: Vec<u8>, content_type: Option<String> },
    DeleteFile { file_hash: String },
    ReportBandwidth { reports: Vec<BandwidthReport> },
    ReportFailures { reports: Vec<MinerFailureReport> },
    RepairHint { file_hash: String, stripe_idx: Option<u64>, count: Option<usize> },

    // Responses
    ClusterMapResponse { map: Option<ClusterMap>, error: Option<String> },
    ManifestResponse { manifest: Option<FileManifest>, error: Option<String> },
    UploadResponse { file_hash: Option<String>, error: Option<String> },
    Ack { success: bool, message: Option<String> },
}
```

### WardenControlMessage

Warden <-> Validator communication (`hippius/warden-control`):

```rust
pub enum WardenControlMessage {
    // Validator -> Warden
    PushShardCommitment { shard_hash: String, merkle_root: [u32; 8], chunk_count: u32, miner_uid: u32, miner_endpoint: String },
    DeleteShard { shard_hash: String },

    // Warden -> Validator
    PushAuditResults { batch: WardenAuditBatch },

    // Response
    Ack { success: bool, message: Option<String> },
}
```

### SubmitterControlMessage

Chain-Submitter <-> Validator communication (`hippius/submitter-control`):

```rust
pub enum SubmitterControlMessage {
    // Requests
    GetClusterMap,
    GetNetworkStats,

    // Responses
    ClusterMapResponse { map: Option<ClusterMap>, error: Option<String> },
    NetworkStatsResponse { total_files: usize, miner_stats: HashMap<String, [u64; 2]>, bandwidth_stats: HashMap<String, u64> },

    // Notifications
    AttestationCommitmentReady { commitment: EpochAttestationCommitment },
    AttestationCommitmentAck { success: bool, message: Option<String> },
}
```

## Attestation Bundle Types

For verifiable proof-of-storage audit results:

```rust
use common::{AttestationBundle, AttestationLeaf, EpochAttestationCommitment, MerkleProof};
use common::{build_merkle_tree, verify_merkle_proof, blake3_hash};

// Build merkle tree from attestations
let (root, proofs) = build_merkle_tree(&attestation_leaves);

// Verify a single attestation
let valid = verify_merkle_proof(&leaf, &proof, &root);

// Compute content hash for Arion storage
let bundle_bytes = bundle.encode(); // SCALE encode
let content_hash = blake3_hash(&bundle_bytes);
```

### AttestationLeaf

```rust
pub struct AttestationLeaf {
    pub audit_id: String,
    pub shard_hash: String,
    pub miner_uid: u32,
    pub result: AttestationAuditResult, // Passed, Failed, Timeout, InvalidProof
    pub challenge_seed: [u8; 32],
    pub block_number: u64,
    pub timestamp: u64,
    pub merkle_proof_sig_hash: Vec<u8>,
    pub warden_pubkey: [u8; 32],
    pub signature: [u8; 64],
}
```

## Utility Functions

```rust
use common::{now_secs, update_ema_latency, LATENCY_EMA_ALPHA};
use common::{validate_file_hash, is_valid_file_hash};
use common::{current_epoch, epoch_sampling_seed, sample_indices};

// Safe timestamp (returns 0 on clock skew)
let ts = now_secs();

// EMA latency update (20% new, 80% old)
let new_latency = update_ema_latency(current, sample, LATENCY_EMA_ALPHA);

// File hash validation
validate_file_hash(hash)?;  // Returns Result
let valid = is_valid_file_hash(hash);  // Returns bool

// Epoch-based audit sampling
let epoch = current_epoch(now_secs(), DEFAULT_AUDIT_EPOCH_SECS);
let seed = epoch_sampling_seed(epoch, validator_node_id);
let indices = sample_indices(&seed, total_shards, sample_size);
```

## P2P Connection Management

```rust
use common::{P2pConnectionManager, GATEWAY_CONTROL_ALPN};

let manager = P2pConnectionManager::new(endpoint, target_node_id, GATEWAY_CONTROL_ALPN);

// Get or create connection (with caching and retry)
let conn = manager.get_connection().await?;

// Send response helper
use common::p2p_send_response;
p2p_send_response(&mut send_stream, &response_bytes).await?;
```

## TLS Configuration

```rust
use common::tls::TlsConfig;

// Auto-loads from env vars, default paths, or generates self-signed
let tls = TlsConfig::new("gateway")?;
// Uses: ARION_GATEWAY_TLS_CERT, ARION_GATEWAY_TLS_KEY
// Fallback: /etc/arion/gateway/cert.pem, /etc/arion/gateway/key.pem
// Dev fallback: /tmp/arion-gateway-cert.pem (auto-generated)
```

## API Key Middleware

```rust
use common::middleware::{validate_api_key, get_expected_api_key, API_KEY_HEADER};
use axum::{Router, middleware};

let protected = Router::new()
    .route("/upload", post(handle_upload))
    .layer(middleware::from_fn(validate_api_key));

// API key from ARION_API_KEY env var (default: "Hippius-Arion-Dev-01")
```

## Constants

```rust
// P2P message size limits
pub const P2P_MAX_MESSAGE_SIZE: usize = 1024 * 1024;        // 1 MiB
pub const P2P_MAX_RESPONSE_SIZE: usize = 10 * 1024 * 1024;  // 10 MiB
pub const P2P_MAX_UPLOAD_SIZE: usize = 100 * 1024 * 1024;   // 100 MiB

// P2P timeouts and retries
pub const P2P_DEFAULT_TIMEOUT_SECS: u64 = 30;
pub const P2P_CONNECTION_TTL_SECS: u64 = 60;
pub const P2P_MAX_CONNECT_RETRIES: u32 = 3;

// Audit epochs
pub const DEFAULT_AUDIT_EPOCH_SECS: u64 = 3600;             // 1 hour
pub const DEFAULT_SHARDS_PER_MINER_PER_EPOCH: usize = 100;

// Relay configuration
pub const DEFAULT_RELAY_URL: &str = "https://relay.hippius.com";
```

## Warden Audit Types

```rust
use common::{AuditResultType, WardenAuditReport, WardenAuditBatch};

pub enum AuditResultType {
    Passed,       // Proof verified
    Failed,       // Proof verification failed
    Timeout,      // No response within deadline
    InvalidProof, // Malformed proof data
}
```

## Modules

- `lib.rs` - Core types, CRUSH placement, RS codec, P2P messages, utilities
- `attestation_bundle.rs` - Verifiable attestation types with SCALE encoding
- `merkle.rs` - BLAKE3-based merkle tree for attestation proofs
- `middleware.rs` - X-API-Key authentication middleware
- `tls.rs` - TLS certificate loading and self-signed generation

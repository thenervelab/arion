# common

Shared library providing core types and algorithms for all Hippius Arion components.

## Features

- **CRUSH placement algorithm**: Deterministic shard distribution with family diversity
- **Reed-Solomon codec**: Erasure coding (10+20 default = 66% fault tolerance)
- **Protocol messages**: P2P communication types for validators, miners, gateways
- **Placement Groups (PGs)**: File-to-miner mapping for efficient rebalancing
- **TLS configuration**: Certificate loading with self-signed fallback

## Usage

Add to your `Cargo.toml`:

```toml
[dependencies]
common = { path = "../common" }
```

## Key Types

### MinerNode

```rust
pub struct MinerNode {
    pub uid: u32,
    pub endpoint: iroh::EndpointAddr,
    pub weight: u32,
    pub family_id: String,
    pub total_storage: u64,
    pub available_storage: u64,
    // ...
}
```

### ClusterMap

```rust
pub struct ClusterMap {
    pub epoch: u64,
    pub miners: HashMap<u32, MinerNode>,
    pub pg_count: u32,  // Default 16384
    pub stripe_config: StripeConfig,
}
```

### StripeConfig

```rust
pub struct StripeConfig {
    pub data_shards: usize,    // k=10 default
    pub parity_shards: usize,  // m=20 default
    pub stripe_size: usize,    // 2 MiB default
}
```

## Placement Algorithm

```rust
use common::{calculate_stripe_placement, ClusterMap};

// Calculate which miners should hold a stripe's shards
let placements = calculate_stripe_placement(
    &cluster_map,
    file_hash,
    stripe_index,
    placement_version,
);
```

## Erasure Coding

```rust
use common::{encode_stripe, decode_stripe, StripeConfig};

// Encode data into shards
let shards = encode_stripe(&data, &config)?;

// Decode from any k shards
let recovered = decode_stripe(&shards, &config)?;
```

## Utilities

```rust
use common::{now_secs, update_ema_latency, LATENCY_EMA_ALPHA};

// Safe timestamp (returns 0 on clock skew)
let ts = now_secs();

// EMA latency update
let new_latency = update_ema_latency(current, sample, LATENCY_EMA_ALPHA);
```

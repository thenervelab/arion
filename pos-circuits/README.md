# pos-circuits

Plonky3-based zero-knowledge proof-of-storage library for Hippius Arion. Enables miners to prove data possession without revealing the actual data.

## Quick Start

```bash
# Build
cargo build -p pos-circuits --release

# Run tests
cargo test -p pos-circuits

# Run benchmarks
cargo bench -p pos-circuits
```

## Overview

The library provides:
- **Commitment generation**: Split shard into chunks, hash with Poseidon2, build Merkle tree
- **Proof generation**: STARK proof that miner possesses specific chunks
- **Proof verification**: Verify proof matches expected Merkle root

## Data Flow

```
STORE (on upload):
  Shard → Split chunks → Poseidon2 hash → Merkle tree → Commitment

PROVE (on challenge):
  Challenge indices → Extract chunks → Merkle proofs → STARK proof

VERIFY (on response):
  Proof + Challenge → STARK verify → Check Merkle root
```

## API Usage

### Generate Commitment (Validator)

```rust
use pos_circuits::{CommitmentWithTree, DEFAULT_CHUNK_SIZE};

let cwt = CommitmentWithTree::generate(&shard_data, DEFAULT_CHUNK_SIZE)?;
let merkle_root = cwt.commitment.merkle_root;
```

### Generate Proof (Miner)

```rust
use pos_circuits::{generate_proof, CommitmentWithTree, Challenge};

let cwt = CommitmentWithTree::generate(&shard_data, DEFAULT_CHUNK_SIZE)?;
let proof = generate_proof(&cwt, &challenge)?;
```

### Verify Proof (Warden)

```rust
use pos_circuits::{verify_proof, Proof};

let proof = Proof::from_bytes(&proof_bytes)?;
let valid = verify_proof(&proof, &challenge)?;
```

## Constants

| Constant | Value | Description |
|----------|-------|-------------|
| `DEFAULT_CHUNK_SIZE` | 1024 | Bytes per chunk |
| `DEFAULT_NUM_CHALLENGES` | 4 | Chunk indices per challenge |
| `DIGEST_ELEMS` | 8 | Elements in Poseidon2 hash |

## Cryptographic Stack

- **Field**: BabyBear (p = 2^31 - 2^27 + 1)
- **Hash**: Poseidon2 (width=16, 8 digest elements)
- **Proofs**: STARK with FRI (Plonky3)

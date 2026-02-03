# pos-circuits

Plonky3-based proof-of-storage library for Hippius Arion. Enables miners to cryptographically prove data possession using Merkle proofs with Poseidon2 hashing.

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
- **Commitment generation**: Split shard into chunks, hash each with Poseidon2, build Merkle tree
- **Proof generation**: Create Merkle proofs for challenged chunk indices
- **Proof verification**: Verify Merkle proofs against the expected root
- **AIR circuit definitions**: Plonky3 STARK constraints for future ZK verification

## Architecture

```
STORE (on upload):
  Shard Data
      │
      ▼
  Split into 1KB chunks
      │
      ▼
  Poseidon2 hash each chunk → [H0, H1, H2, ..., Hn]
      │
      ▼
  Build Merkle tree (binary, Poseidon2 internal nodes)
      │
      ▼
  Commitment { merkle_root, chunk_count, shard_hash }

PROVE (on challenge):
  Challenge { chunk_indices: [3, 17, 42], nonce, expires_at }
      │
      ▼
  For each index, extract chunk hash + Merkle siblings
      │
      ▼
  Serialize to Proof { proof_bytes, public_inputs }

VERIFY (on response):
  Proof + Commitment
      │
      ▼
  Deserialize proof_bytes → PosProofData
      │
      ▼
  For each challenged chunk:
    - Recompute path from leaf to root
    - Verify against expected merkle_root
      │
      ▼
  Return true if all proofs valid
```

## Module Structure

| Module | Purpose |
|--------|---------|
| `commitment` | `Commitment` and `CommitmentWithTree` types for storage commitments |
| `merkle` | Binary Merkle tree with Poseidon2 internal hashing |
| `hash` | Poseidon2 hash functions for bytes and hash pairs |
| `prover` | Proof generation from commitment and challenge |
| `verifier` | Proof verification against commitment |
| `circuit` | Plonky3 AIR definitions for STARK-based verification |
| `types` | Core types: `Challenge`, `Proof`, `PublicInputs`, `MerkleProof` |
| `error` | Error types with `thiserror` |

## API Usage

### Generate Commitment (Validator)

```rust
use pos_circuits::{generate_commitment, DEFAULT_CHUNK_SIZE};

let shard_data = vec![0u8; 68 * 1024]; // 68 KB shard
let commitment = generate_commitment(&shard_data, DEFAULT_CHUNK_SIZE)?;
println!("Merkle root: {:?}", commitment.merkle_root);
println!("Chunk count: {}", commitment.chunk_count);
```

For miners who need to generate proofs later, use `CommitmentWithTree` to retain the full tree:

```rust
use pos_circuits::commitment::CommitmentWithTree;

let cwt = CommitmentWithTree::generate(&shard_data, 1024)?;
// cwt.tree holds the full Merkle tree for proof generation
// cwt.commitment holds the public commitment data
```

### Create Challenge (Warden)

```rust
use pos_circuits::types::Challenge;

let challenge = Challenge::new(
    &commitment.shard_hash,        // Which shard to prove
    vec![3, 17, 42, 61],           // Random chunk indices
    commitment.merkle_root,         // Expected root
    expires_at,                     // Unix timestamp for freshness
);
```

### Generate Proof (Miner)

```rust
use pos_circuits::generate_proof;

let proof = generate_proof(&shard_data, &cwt, &challenge)?;
println!("Proving time: {}ms", proof.proving_time_ms);
```

### Verify Proof (Warden)

```rust
use pos_circuits::verify_proof;

let valid = verify_proof(&proof, &commitment, Some(&challenge))?;
assert!(valid);
```

### Batch Verification

```rust
use pos_circuits::verifier::{Verifier, batch_verify};

let mut verifier = Verifier::new();
let proofs = vec![
    (&proof1, &commitment1, Some(&challenge1)),
    (&proof2, &commitment2, Some(&challenge2)),
];
let result = batch_verify(&mut verifier, &proofs);
println!("Passed: {}, Failed: {}", result.passed, result.failed);
```

### Proof Serialization

```rust
// Serialize for transmission
let bytes = proof.to_bytes()?;

// Deserialize
let proof = Proof::from_bytes(&bytes)?;
```

## Key Types

### Commitment

```rust
pub struct Commitment {
    pub merkle_root: Poseidon2Hash,  // [u32; 8] - root of chunk hash tree
    pub chunk_count: u32,             // Number of chunks in shard
    pub chunk_size: usize,            // Bytes per chunk (default: 1024)
    pub data_size: usize,             // Original shard size
    pub shard_hash: String,           // BLAKE3 hash for identification
    pub tree_depth: usize,            // Merkle tree depth
}
```

### Challenge

```rust
pub struct Challenge {
    pub shard_hash: String,           // Which shard to prove
    pub chunk_indices: Vec<u32>,      // Random indices to prove possession
    pub nonce: [u8; 32],              // Freshness nonce (prevents replay)
    pub expected_root: Poseidon2Hash, // Expected Merkle root
    pub expires_at: u64,              // Unix timestamp expiry
}
```

### Proof

```rust
pub struct Proof {
    pub proof_bytes: Vec<u8>,         // Serialized Merkle proofs
    pub public_inputs: PublicInputs,  // Root + indices + chunk hashes
    pub num_challenges: usize,        // Number of chunks proven
    pub proving_time_ms: u64,         // Generation time
}
```

## Constants

| Constant | Value | Description |
|----------|-------|-------------|
| `DEFAULT_CHUNK_SIZE` | 1024 | Bytes per chunk |
| `DEFAULT_NUM_CHALLENGES` | 4 | Recommended chunks per challenge |
| `DIGEST_ELEMS` | 8 | Field elements in Poseidon2 hash (~248 bits) |
| `POSEIDON2_WIDTH` | 16 | Poseidon2 permutation width |
| `MERKLE_AIR_WIDTH` | 18 | Trace width for STARK AIR |

## Cryptographic Stack

| Component | Implementation |
|-----------|---------------|
| **Field** | BabyBear (p = 2^31 - 2^27 + 1) with degree-4 extension for FRI |
| **Hash** | Poseidon2 (width=16, 8 digest elements, sponge construction) |
| **Merkle Tree** | Binary tree with Poseidon2 two-to-one compression |
| **Byte Packing** | 3 bytes per BabyBear element (24 bits < 31-bit modulus) |
| **Identification** | BLAKE3 for shard identification (not in proof) |
| **Serialization** | wincode for compact proof encoding |

## Plonky3 AIR Circuit

The `circuit` module defines an AIR (Algebraic Intermediate Representation) for STARK-based verification:

```rust
pub struct MerkleProofAir {
    pub expected_root: Poseidon2Hash,
    pub tree_depth: usize,
}
```

**Trace Layout** (per row):
- `current_hash`: 8 field elements - hash at current tree level
- `sibling_hash`: 8 field elements - sibling for this level
- `path_bit`: 1 element - 0 if left child, 1 if right
- `is_active`: 1 element - 1 for proof rows, 0 for padding

**Constraints**:
1. `is_active` must be boolean
2. `path_bit` must be boolean when active
3. Final row `current_hash` must equal `expected_root`

Note: The current implementation uses native Merkle verification. The AIR is defined for future STARK-based ZK proof integration.

## Error Handling

```rust
pub enum PosError {
    EmptyData,                    // Cannot process empty shard
    InvalidChunkSize(String),     // Chunk size must be > 0
    ChunkIndexOutOfBounds { index, max },
    MerkleRootMismatch { expected, actual },
    ChallengeExpired { expires_at, current },
    InvalidProofFormat(String),
    ProofGenerationError(String),
    ProofVerificationError(String),
    SerializationError(String),
    // ...
}
```

## Benchmarks

Run benchmarks with `cargo bench -p pos-circuits`. Benchmarked operations:

| Benchmark | Description |
|-----------|-------------|
| `poseidon2_hash` | Hash throughput for 64B-4KB data |
| `poseidon2_two_to_one` | Internal node hashing |
| `merkle_tree_build` | Tree construction for 8-128 chunks |
| `merkle_proof_generate` | Single proof generation |
| `commitment` | Full commitment for 4KB-128KB shards |
| `proof_generation` | Proof for 1-8 challenges |
| `proof_verification` | Verification for 1-4 challenges |
| `end_to_end` | Full flow: commit -> prove -> verify |

## Dependencies

Key Plonky3 crates:
- `p3-baby-bear`: BabyBear field implementation
- `p3-poseidon2`: Poseidon2 permutation
- `p3-air`, `p3-uni-stark`: AIR and STARK definitions
- `p3-merkle-tree`: Merkle tree utilities
- `p3-fri`: FRI commitment scheme

# Arion Pallet (FRAME) - `pallet-arion`

A Substrate/FRAME pallet for the Arion decentralized storage network. This pallet provides on-chain state management for CRUSH placement maps, miner registration, proof-of-storage attestations, and incentive weight computation.

## Overview

This pallet is designed to be integrated into a Substrate-based blockchain and provides:

- **CRUSH Map Management**: Deterministic placement maps per epoch for shard distribution
- **Miner Registration**: Anti-sybil child/node registration with adaptive deposit pricing
- **Proof-of-Storage Attestations**: On-chain verification of warden audit results
- **Incentive Weights**: Validator-reported quality metrics for fair reward distribution
- **Periodic Miner Stats**: Aggregated storage and bandwidth statistics

## Installation

This pallet is **not included in the hippius-arion workspace** to avoid pulling Substrate dependencies into the storage node workspace. To use it:

1. Copy this folder into your Substrate node repository (or add as a git submodule)
2. Add to your runtime `Cargo.toml`:
   ```toml
   pallet-arion = { path = "../arion-pallet", default-features = false }
   ```
3. Include in `construct_runtime!`:
   ```rust
   Arion: pallet_arion,
   ```

## Extrinsics (Dispatchables)

### CRUSH Map Management

| Call Index | Extrinsic | Origin | Description |
|------------|-----------|--------|-------------|
| 0 | `submit_crush_map` | `MapAuthorityOrigin` | Publish a new CRUSH placement map for an epoch |

### Miner Stats

| Call Index | Extrinsic | Origin | Description |
|------------|-----------|--------|-------------|
| 1 | `submit_miner_stats` | `StatsAuthorityOrigin` | Submit aggregated miner stats for a reporting bucket |

### Attestations

| Call Index | Extrinsic | Origin | Description |
|------------|-----------|--------|-------------|
| 2 | `submit_attestations` | `AttestationAuthorityOrigin` | Submit warden proof-of-storage attestations with Ed25519 signature verification |
| 3 | `submit_attestation_commitment` | `AttestationAuthorityOrigin` | Submit epoch attestation commitment for third-party verification |

### Child Registration

| Call Index | Extrinsic | Origin | Description |
|------------|-----------|--------|-------------|
| 10 | `register_child` | Signed (family) | Register a miner node under a family with Ed25519 signature proof |
| 11 | `deregister_child` | Signed (family) | Deregister a child node, initiating unbonding period |
| 12 | `claim_unbonded` | Signed (family) | Claim deposit after unbonding period completes |

### Incentive Weights

| Call Index | Extrinsic | Origin | Description |
|------------|-----------|--------|-------------|
| 20 | `submit_node_quality` | `WeightAuthorityOrigin` | Submit validator-observed quality metrics; pallet computes weights on-chain |

### Admin (Sudo) Extrinsics

| Call Index | Extrinsic | Origin | Description |
|------------|-----------|--------|-------------|
| 30 | `set_lockup_enabled` | `ArionAdminOrigin` | Enable/disable registration deposit lockup |
| 31 | `set_base_child_deposit` | `ArionAdminOrigin` | Set base deposit floor for registration fee curve |
| 32 | `register_warden` | `ArionAdminOrigin` | Register a warden authorized to submit attestations |
| 33 | `deregister_warden` | `ArionAdminOrigin` | Deregister a warden |
| 34 | `prune_attestation_buckets` | Signed (any) | Prune old attestation data outside retention period |

## Storage Items

### CRUSH Map State

| Storage | Type | Description |
|---------|------|-------------|
| `CurrentEpoch` | `u64` | Current CRUSH epoch number |
| `EpochParams` | `Map<u64, CrushParams>` | CRUSH parameters (pg_count, ec_k, ec_m) per epoch |
| `EpochMiners` | `Map<u64, Vec<MinerRecord>>` | Miner list per epoch |
| `EpochRoot` | `Map<u64, H256>` | Root hash commitment of epoch map |

### Miner Stats State

| Storage | Type | Description |
|---------|------|-------------|
| `CurrentStatsBucket` | `u32` | Current stats reporting bucket |
| `CurrentNetworkTotals` | `NetworkTotals` | Network-wide storage/bandwidth totals |
| `MinerStatsByUid` | `Map<u32, MinerStats>` | Per-miner stats by UID |

### Attestation State

| Storage | Type | Description |
|---------|------|-------------|
| `CurrentAttestationBucket` | `u32` | Current attestation bucket |
| `AttestationsByBucket` | `Map<u32, Vec<AttestationRecord>>` | Attestations per bucket |
| `EpochAttestationCommitments` | `Map<u64, EpochAttestationCommitment>` | Compact commitments for verification |
| `RegisteredWardens` | `Map<[u8; 32], WardenInfo>` | Registered warden public keys |
| `ActiveWardenCount` | `u32` | Count of active wardens |

### Registration State

| Storage | Type | Description |
|---------|------|-------------|
| `LockupEnabled` | `bool` | Whether deposit lockup is active |
| `BaseChildDepositValue` | `Balance` | Base deposit floor |
| `FamilyCount` | `u32` | Number of families with registrations |
| `FamilyUsedFreeSlot` | `Map<AccountId, bool>` | Whether family used free registration |
| `FamilyActiveChildren` | `Map<AccountId, u32>` | Active child count per family |
| `TotalActiveChildren` | `u32` | Total active children network-wide |
| `GlobalNextDeposit` | `Balance` | Next required deposit (adaptive pricing) |
| `GlobalLastPaidRegistrationBlock` | `BlockNumber` | Block of last paid registration (for halving) |
| `ChildRegistrations` | `Map<AccountId, ChildRegistration>` | Child registration records |
| `NodeIdToChild` | `Map<[u8; 32], AccountId>` | Node ID to child account mapping |
| `NodeIdNonce` | `Map<[u8; 32], u64>` | Nonce per node ID (replay protection) |
| `ChildCooldownUntil` | `Map<AccountId, BlockNumber>` | Cooldown end block per child |
| `NodeIdCooldownUntil` | `Map<[u8; 32], BlockNumber>` | Cooldown end block per node ID |
| `FamilyChildren` | `Map<AccountId, Vec<AccountId>>` | Active children list per family |

### Incentive Weight State

| Storage | Type | Description |
|---------|------|-------------|
| `CurrentWeightBucket` | `u32` | Current weight computation bucket |
| `NodeWeightByChild` | `Map<AccountId, u16>` | Per-node weight |
| `NodeWeightLastBucket` | `Map<AccountId, u32>` | Last bucket when weight was updated |
| `NodeQualityByChild` | `Map<AccountId, NodeQuality>` | Validator-reported quality metrics |
| `FamilyWeightRaw` | `Map<AccountId, u16>` | Raw (unsmoothed) family weight |
| `FamilyWeight` | `Map<AccountId, u16>` | Smoothed family weight (EMA + delta clamp) |
| `FamilyFirstSeenBucket` | `Map<AccountId, u32>` | First bucket family became active |

## Events

| Event | Description |
|-------|-------------|
| `CrushMapPublished` | New CRUSH epoch published with miner count and root hash |
| `MinerStatsUpdated` | Miner stats updated for a bucket |
| `AttestationsSubmitted` | Attestations submitted for a bucket |
| `AttestationCommitmentSubmitted` | Epoch attestation commitment stored |
| `ChildRegistered` | Child node registered under family |
| `ChildDeregistered` | Child node deregistered, entered unbonding |
| `ChildUnbonded` | Child deposit released after unbonding |
| `NodeWeightsUpdated` | Node weights updated for a bucket |
| `FamilyWeightsComputed` | Family weights recomputed |
| `LockupEnabledSet` | Lockup enabled/disabled by admin |
| `BaseChildDepositSet` | Base deposit floor changed |
| `WardenRegistered` | Warden authorized to submit attestations |
| `WardenDeregistered` | Warden deauthorized |
| `AttestationBucketsPruned` | Old attestation buckets removed |

## Errors

| Error | Description |
|-------|-------------|
| `EpochRegression` | Epoch must be strictly increasing |
| `EpochAlreadyExists` | Epoch already has a map |
| `MinerListNotSortedOrNotUnique` | Miners must be sorted by UID and unique |
| `TooManyMiners` | Exceeded `MaxMiners` limit |
| `TooManyStatsUpdates` | Exceeded `MaxStatsUpdates` limit |
| `StatsBucketRegression` | Stats bucket cannot decrease |
| `FamilyNotRegistered` | Family not in `FamilyRegistry` |
| `ProxyVerificationFailed` | `ProxyVerifier` check failed |
| `TooManyFamilies` | Exceeded `MaxFamilies` limit |
| `TooManyChildrenTotal` | Exceeded `MaxChildrenTotal` limit |
| `TooManyChildrenInFamily` | Exceeded `MaxChildrenPerFamily` limit |
| `ChildAlreadyRegistered` | Child account already registered |
| `ChildNotRegistered` | Child account not found |
| `ChildInCooldown` | Child in cooldown period |
| `NodeIdAlreadyRegistered` | Node ID already registered |
| `NodeIdInCooldown` | Node ID in cooldown period |
| `InvalidNodeSignature` | Ed25519 signature verification failed |
| `ChildNotActive` | Child not in Active status |
| `NotUnbonding` | Child not in Unbonding status |
| `UnbondingNotReady` | Unbonding period not complete |
| `InsufficientDeposit` | Cannot reserve required deposit |
| `MinerNotRegistered` | Miner not in on-chain registry (when enforced) |
| `WeightBucketRegression` | Weight bucket cannot decrease |
| `TooManyNodeWeightUpdates` | Exceeded update limit |
| `AttestationBucketRegression` | Attestation bucket cannot decrease |
| `TooManyAttestations` | Exceeded attestation limit |
| `AttestationBucketFull` | Attestation bucket at capacity |
| `InvalidAttestationSignature` | Attestation Ed25519 signature invalid |
| `AttestationCommitmentAlreadyExists` | Commitment exists for epoch |
| `InvalidContentHashLength` | Content hash not 32 bytes |
| `WardenAlreadyRegistered` | Warden pubkey already registered |
| `WardenNotRegistered` | Warden pubkey not found |
| `UnregisteredWarden` | Attestation from unregistered warden |
| `PruningWithinRetentionPeriod` | Cannot prune recent buckets |

## Chain-Submitter Integration

The `chain-submitter` service (in the hippius-arion workspace) is the primary off-chain component that interacts with this pallet. It:

1. **Polls the Validator**: Retrieves cluster maps, attestations, and network stats via P2P (`hippius/submitter-control` protocol)

2. **Submits CRUSH Maps**: When epoch changes, submits the new cluster map via `submit_crush_map`

3. **Submits Attestations**: Collects signed attestation bundles from the validator and submits them via `submit_attestations` and `submit_attestation_commitment`

4. **Submits Stats**: Periodically submits aggregated miner stats via `submit_miner_stats`

### P2P Protocol

The chain-submitter receives data from the validator using the `hippius/commitment-push` protocol for attestation commitments at epoch boundaries, and `hippius/submitter-control` for on-demand queries.

### Attestation Signature Format

Attestations use **SCALE encoding** with a domain separator for cross-component verification:

```rust
const ATTESTATION_DOMAIN_SEPARATOR: &[u8] = b"ARION_ATTESTATION_V1";

let sign_data = (
    ATTESTATION_DOMAIN_SEPARATOR,
    shard_hash.as_bytes(),      // BLAKE3 hash of audited shard
    miner_uid,                   // u32
    result.as_u8(),              // 0=Passed, 1=Failed, 2=Timeout, 3=InvalidProof
    challenge_seed,              // [u8; 32]
    block_number,                // u64
    timestamp,                   // u64
    &merkle_proof_sig_hash,      // Vec<u8>
    warden_id.as_bytes(),        // Warden identifier
).encode();
```

## Configuration

### Required Config Items

```rust
pub trait Config: frame_system::Config + pallet_proxy::Config + pallet_registration::Config {
    // Origins
    type ArionAdminOrigin: EnsureOrigin;     // Sudo/admin for parameters
    type MapAuthorityOrigin: EnsureOrigin;   // Who can publish CRUSH maps
    type StatsAuthorityOrigin: EnsureOrigin; // Who can submit stats
    type AttestationAuthorityOrigin: EnsureOrigin; // Who can submit attestations
    type WeightAuthorityOrigin: EnsureOrigin; // Who can submit weights

    // External integrations
    type DepositCurrency: ReservableCurrency; // For registration deposits
    type FamilyRegistry: FamilyRegistry;      // Validates family accounts
    type ProxyVerifier: ProxyVerifier;        // Validates proxy relationships

    // Limits
    type MaxMiners: Get<u32>;           // Max miners per epoch map
    type MaxEndpointLen: Get<u32>;      // Max endpoint bytes
    type MaxHttpAddrLen: Get<u32>;      // Max HTTP address bytes
    type MaxStatsUpdates: Get<u32>;     // Max stats updates per call
    type MaxAttestations: Get<u32>;     // Max attestations per call
    type MaxFamilies: Get<u32>;         // Max distinct families
    type MaxChildrenTotal: Get<u32>;    // Max total children
    type MaxChildrenPerFamily: Get<u32>; // Max children per family

    // Registration economics
    type BaseChildDeposit: Get<Balance>;
    type GlobalDepositHalvingPeriodBlocks: Get<BlockNumber>;
    type UnregisterCooldownBlocks: Get<BlockNumber>;
    type UnbondingPeriodBlocks: Get<BlockNumber>;

    // Weight computation
    type MaxNodeWeight: Get<u16>;
    type MaxFamilyWeight: Get<u16>;
    type FamilyTopN: Get<u32>;
    type FamilyRankDecayPermille: Get<u32>;
    type FamilyWeightEmaAlphaPermille: Get<u32>;
    type MaxFamilyWeightDeltaPerBucket: Get<u16>;
    type NewcomerGraceBuckets: Get<u32>;
    type NewcomerFloorWeight: Get<u16>;
    type NodeBandwidthWeightPermille: Get<u32>;
    type NodeStorageWeightPermille: Get<u32>;
    type NodeScoreScale: Get<u16>;
    type StrikePenalty: Get<u16>;
    type IntegrityFailPenalty: Get<u16>;

    // Attestation config
    type MaxShardHashLen: Get<u32>;
    type MaxWardenPubkeyLen: Get<u32>;
    type MaxSignatureLen: Get<u32>;
    type MaxMerkleProofLen: Get<u32>;
    type MaxWardenIdLen: Get<u32>;
    type MaxContentHashLen: Get<u32>;
    type AttestationRetentionBuckets: Get<u32>;

    // Enforcement
    type EnforceRegisteredMinersInMap: Get<bool>;

    type WeightInfo: WeightInfo;
}
```

### Hook Traits

**`FamilyRegistry`**: Validates that a family account is authorized to register children. Wire to `pallet_registration::Pallet<Runtime>` or implement custom logic. Default `()` implementation returns `false` (deny-by-default).

**`ProxyVerifier`**: Validates family-child proxy relationships. Wire to `pallet_proxy::Pallet<Runtime>`. Default `()` implementation returns `false` (deny-by-default).

## Registration Economics

### Anti-Sybil Pricing

- **First child free**: Each family gets one free registration
- **Adaptive global fee**: After free slot, deposit doubles after each paid registration
- **Lazy halving**: Fee halves after `GlobalDepositHalvingPeriodBlocks` of inactivity

### Anti-Yoyo Protection

- **Deregistration cooldown**: `UnregisterCooldownBlocks` before re-registration
- **Unbonding period**: `UnbondingPeriodBlocks` before deposit release

### Signature Requirement

Registration requires proving ownership of `node_id` via Ed25519 signature over:
```
SCALE(b"ARION_NODE_REG_V1", family, child, node_id, nonce)
```

## Incentive Weight Computation

### Node Weight Formula

Uses concave `log2(1+x)` scoring to prevent "rich get richer" dynamics:

```
score = (log2(1+bandwidth) * bw_weight + log2(1+storage) * st_weight) / (bw_weight + st_weight)
score *= uptime_permille / 1000
score -= strikes * StrikePenalty
score -= integrity_fails * IntegrityFailPenalty
```

### Family Weight Aggregation

Per-family weight uses top-N nodes with rank decay:
```
family_weight = node1 + node2 * decay + node3 * decay^2 + ...
```

With EMA smoothing and delta clamping for stability.

### Newcomer Grace Period

During `NewcomerGraceBuckets`, families with non-zero computed weight receive at least `NewcomerFloorWeight` to enable scheduling.

## Genesis Configuration

```rust
#[pallet::genesis_config]
pub struct GenesisConfig<T: Config> {
    pub base_child_deposit: Option<Balance>,
    pub lockup_enabled: bool,
}
```

## License

Apache-2.0

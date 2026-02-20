# Changelog

All notable changes to this project will be documented in this file.

## [0.1.3] - 2026-02-20

### Miner

#### Performance

- Connection reuse in heartbeat loop (persistent QUIC connection cached across heartbeats)
- Tag map for O(1) shard deletion (new TAG_MAP DashMap eliminates full tag scan on Delete)
- PoS commitment cache (LRU, 100 entries) avoids rebuilding Poseidon2 Merkle trees
- Miner UID computed once at startup (stored in OnceLock)
- PG assignment caching (recomputed only on epoch change)
- V1 JSON parsing uses from_slice (SIMD-enabled) instead of from_reader chain
- Send window reduced 64MB to 16MB, receive window bounded to 64MB

#### Reliability

- Direct UDP path enforcement on Store, FetchBlob, PullFromPeer (relay-only rejected)
- Hole-punching wait before registration (configurable p2p_direct_wait_secs, default 30s)
- Exponential backoff with jitter on heartbeat failures (30s/60s/120s cap)
- Validator warmup handling (short 5s retry when validator returns WARMING_UP)
- Validator reachability flag gates rebalance loop

#### Networking

- IPv4/IPv6 bind support (bind_ipv4/bind_ipv6 config + P2P_BIND_IPV4/P2P_BIND_IPV6 env vars)
- Hostname-to-IP resolution for registration (sends resolved IP in endpoint hints)

#### Rebalance

- Pre-built local hash set (single directory walk, O(1) lookups)
- Connection-multiplexed manifest fetches (single QUIC conn, 16 concurrent streams)
- Chunked PG batch queries (500 PGs per request, prevents validator OOM)
- Randomized startup jitter + inter-tick jitter to desynchronize miners
- Orphan tracking uses typed Hash keys instead of String

#### Removed

- HTTP server (handlers.rs, axum/axum-server/openssl deps, MINER_HTTP_ENABLED flag)
- HTTP port config (network.port field, PORT env var)
- AppState struct (was for HTTP handlers)

#### Config

- store_concurrency default: 64 to 1024
- New: p2p_direct_wait_secs (default 30s)
- Warden node IDs now auto-distributed via heartbeat (no manual config)

### Common

- New `CheckBlob` variant in `MinerControlMessage` for lightweight metadata-only existence checks

### pos-circuits

- Edition bump to 2024, version 0.1.2

## [0.1.2] - 2025-02-12

### Miner

#### Concurrency

- Raised `MAX_CONCURRENT_HANDLERS` from 1000 to 2048
- Default `store_concurrency` increased from 64 to 1024

#### P2P Transport

- QUIC transport tuning: 120s idle timeout, 16384 concurrent bidirectional streams, 64MB send window
- Rate-limited handler now sends error response instead of silently dropping
- Detailed peer context added to timeout error messages
- Registration flow refactored into standalone `build_validator_addr()` helper

#### Recovery

- Full rewrite of rebalance module with epoch lookback
- Active shard recovery via peer P2P pulling
- HTTP cluster map fetching as fallback

#### Misc

- `decode_ticket` binary uses `anyhow::Result` instead of unwrap
- Connection pool cleanup uses imperative loop instead of `retain()`
- Added `MINER_ONBOARDING.md` deployment guide
- Added `run-miner.sh` and `run-30-miners.sh` helper scripts

### Common

- `MinerNode`: added `ip_address` and `integrity_fails` fields
- `ClusterMap`: derived `Default`, added `ensure_defaults()` validation
- New `GatewayUploadHeader` type for streaming uploads
- New `SubmitterControlMessage::SyncEpoch` variant
- CRUSH placement: added tries parameter to sharding placement (default 3)
- Audit loop cleanup and map misalignment fixes

## [0.1.1] - 2025-01-15

Initial public release with miner, gateway, validator, warden, chain-submitter,
and common crate.

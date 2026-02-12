# Changelog

All notable changes to this project will be documented in this file.

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

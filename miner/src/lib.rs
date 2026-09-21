//! Miner library: the standalone modules of the storage node, usable
//! without the full application context (P2P server, registration,
//! rebalance). The `miner` binary consumes them through this crate; the
//! warden's integration tests drive the storage-proof handler against the
//! real verifier through it, so the miner never depends on the warden.
//!
//! - `store`: the [`store::BlobStore`] backend abstraction
//! - `pg_lists`, `purge`: obligation-list reader and purge policy
//! - `flat_store`: sharded flat-file backend
//! - `storage_proof`: storage chunk proof handler, protocol v1
//! - `validator_pin`: identity check of the validator on the miner's
//!   control connections to it
//! - `constants`, `helpers`: shared limits and small utilities
//! - `limits`: boot-time limits derived from the machine's RAM

pub mod backfill;
pub mod constants;
pub mod flat_store;
pub mod helpers;
pub mod limits;
pub mod pg_lists;
pub mod purge;
pub mod storage_proof;
pub mod store;
pub mod validator_pin;

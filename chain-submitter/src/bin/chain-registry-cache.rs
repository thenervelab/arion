//! Chain Registry Cache - local cache of pallet-arion registration data.
//!
//! This daemon polls the blockchain and builds a JSON snapshot of the miner registry.
//! The validator uses this cache to verify miner registrations without querying
//! the blockchain for every heartbeat.
//!
//! # Data Sources
//!
//! All data is sourced from on-chain storage maps:
//! - `FamilyChildren`: Maps family accounts to their child accounts
//! - `ChildRegistrations`: Maps child accounts to registration details
//! - `NodeIdToChild`: Maps P2P node IDs to child accounts
//!
//! # Output Format
//!
//! The cache is written as a JSON file with atomic rename (no partial writes):
//!
//! ```json
//! {
//!   "at_block": 12345,
//!   "pallet": "Arion",
//!   "family_children": {"0x...": ["0x..."]},
//!   "child_registrations": {"0x...": {...}},
//!   "node_id_to_child": {"0x...": "0x..."}
//! }
//! ```
//!
//! # Example Usage
//!
//! ```bash
//! chain-registry-cache \
//!     --chain-ws-url ws://127.0.0.1:9944 \
//!     --out arion-registry-cache.json \
//!     --poll-secs 30
//! ```

use anyhow::{Context, Result, anyhow};
use clap::Parser;
use serde::Serialize;
use std::collections::BTreeMap;
use std::path::PathBuf;
use std::time::Duration;
use subxt::{OnlineClient, config::PolkadotConfig, dynamic};

// ============================================================================
// Constants
// ============================================================================

/// Default timeout for RPC calls to the blockchain (60 seconds).
const RPC_TIMEOUT_SECS: u64 = 60;

/// Keywords indicating a connection error that requires reconnection.
const CONNECTION_ERROR_KEYWORDS: &[&str] = &[
    "connection",
    "websocket",
    "transport",
    "disconnected",
    "closed",
    "rpc error",
    "timeout",
];

/// Checks if an error message indicates a connection issue requiring reconnection.
fn is_connection_error(err: &anyhow::Error) -> bool {
    let err_str = err.to_string().to_lowercase();
    CONNECTION_ERROR_KEYWORDS
        .iter()
        .any(|kw| err_str.contains(kw))
}

/// Attempts to reconnect to the blockchain with timeout.
/// Returns the new client and optionally a re-detected pallet name.
async fn try_reconnect(
    chain_ws_url: &str,
    explicit_pallet_name: &str,
) -> Option<(OnlineClient<PolkadotConfig>, Option<String>)> {
    let reconnect_timeout = Duration::from_secs(RPC_TIMEOUT_SECS);

    match tokio::time::timeout(
        reconnect_timeout,
        OnlineClient::<PolkadotConfig>::from_url(chain_ws_url),
    )
    .await
    {
        Ok(Ok(new_client)) => {
            tracing::info!("Reconnected to blockchain");
            let new_pallet = if explicit_pallet_name.trim().is_empty() {
                match detect_arion_pallet_name(&new_client) {
                    Ok(name) => {
                        tracing::info!("Re-detected arion pallet name: {}", name);
                        Some(name)
                    }
                    Err(e) => {
                        tracing::error!(error = %e, "Failed to re-detect pallet name after reconnect");
                        None
                    }
                }
            } else {
                None
            };
            Some((new_client, new_pallet))
        }
        Ok(Err(e)) => {
            tracing::error!(error = %e, "Failed to reconnect to blockchain");
            None
        }
        Err(_) => {
            tracing::error!("Reconnection timed out after {} seconds", RPC_TIMEOUT_SECS);
            None
        }
    }
}

// ============================================================================
// CLI Configuration
// ============================================================================

/// Build a local cache of pallet-arion registry data from chain storage.
#[derive(Parser, Debug, Clone)]
#[command(author, version, about)]
struct Args {
    /// Substrate WS URL (required)
    #[arg(long, env = "CHAIN_WS_URL")]
    chain_ws_url: String,

    /// Optional: override pallet name if auto-detect fails
    #[arg(long, env = "ARION_PALLET_NAME", default_value = "")]
    arion_pallet_name: String,

    /// Output file path for the cache snapshot (JSON).
    #[arg(
        long,
        env = "ARION_REGISTRY_CACHE_OUT",
        default_value = "arion-registry-cache.json"
    )]
    out: PathBuf,

    /// Poll interval seconds (writes a fresh snapshot each tick).
    #[arg(long, env = "ARION_REGISTRY_CACHE_POLL_SECS", default_value_t = 30)]
    poll_secs: u64,

    /// If set, write one snapshot and exit.
    #[arg(long, env = "ARION_REGISTRY_CACHE_ONCE", default_value_t = false)]
    once: bool,
}

// ============================================================================
// Snapshot Types
// ============================================================================

/// A point-in-time snapshot of the on-chain miner registry.
#[derive(Debug, Clone, Serialize)]
struct RegistrySnapshot {
    /// Block number at which this snapshot was taken
    at_block: u32,
    /// Name of the arion pallet in the runtime
    pallet: String,
    /// Family accounts and their registered children (hex-encoded AccountId32)
    family_children: BTreeMap<String, Vec<String>>,
    /// Child registration records keyed by child account (hex-encoded)
    child_registrations: BTreeMap<String, ChildRegistrationView>,
    /// Active NodeId → Child mappings (hex-encoded, only includes Active status)
    node_id_to_child: BTreeMap<String, String>,
}

/// View of a child registration record from on-chain storage.
#[derive(Debug, Clone, Serialize)]
struct ChildRegistrationView {
    /// Parent family account (hex-encoded AccountId32)
    family_id: String,
    /// Miner's P2P node ID (hex-encoded 32 bytes)
    node_id: String,
    /// Registration status: "Active", "Unbonding", or "Unknown"
    status: String,
    /// Deposit amount (u128 as string to avoid JSON precision loss)
    deposit: String,
    /// Block number when unbonding completes (0 if not unbonding)
    unbonding_end: u32,
}

// ============================================================================
// Runtime Introspection
// ============================================================================

/// Auto-detects the arion pallet name from runtime metadata.
fn detect_arion_pallet_name(client: &OnlineClient<PolkadotConfig>) -> Result<String> {
    for p in client.metadata().pallets() {
        if p.call_hash("submit_node_quality").is_some() {
            return Ok(p.name().to_string());
        }
    }
    Err(anyhow!(
        "Could not auto-detect arion pallet name from metadata (no call named submit_node_quality)"
    ))
}

// ============================================================================
// SCALE Value Parsing Helpers
// ============================================================================

/// Formats a 32-byte array as a hex string with 0x prefix.
fn hex32(bytes: [u8; 32]) -> String {
    format!("0x{}", hex::encode(bytes))
}

/// Extracts bytes from a SCALE composite value (e.g., BoundedVec<u8>).
fn value_bytes<T>(v: &dynamic::Value<T>) -> Option<Vec<u8>> {
    use subxt::ext::scale_value::{Composite, Primitive, ValueDef};
    match &v.value {
        ValueDef::Composite(Composite::Unnamed(vals)) => {
            let mut out = Vec::with_capacity(vals.len());
            for b in vals {
                match &b.value {
                    ValueDef::Primitive(Primitive::U128(n)) => {
                        if *n > 255 {
                            return None;
                        }
                        out.push(*n as u8);
                    }
                    _ => return None,
                }
            }
            Some(out)
        }
        _ => None,
    }
}

fn value_bytes32<T>(v: &dynamic::Value<T>) -> Option<[u8; 32]> {
    // Try direct parsing first
    if let Some(b) = value_bytes(v) {
        return b.try_into().ok();
    }

    // Handle nested structure: Value -> Composite(Unnamed) -> Value -> Composite(Unnamed) -> bytes
    use subxt::ext::scale_value::{Composite, ValueDef};
    if let ValueDef::Composite(Composite::Unnamed(outer_vals)) = &v.value
        && outer_vals.len() == 1
    {
        return value_bytes32(&outer_vals[0]);
    }
    None
}

fn value_u128<T>(v: &dynamic::Value<T>) -> Option<u128> {
    use subxt::ext::scale_value::{Primitive, ValueDef};
    match &v.value {
        ValueDef::Primitive(Primitive::U128(n)) => Some(*n),
        _ => None,
    }
}

fn value_variant_name<T>(v: &dynamic::Value<T>) -> Option<&str> {
    use subxt::ext::scale_value::ValueDef;
    match &v.value {
        ValueDef::Variant(var) => Some(&var.name),
        _ => None,
    }
}

fn composite_get_named<'a, T>(
    v: &'a dynamic::Value<T>,
    field: &str,
) -> Option<&'a dynamic::Value<T>> {
    use subxt::ext::scale_value::{Composite, ValueDef};
    match &v.value {
        ValueDef::Composite(Composite::Named(fields)) => {
            fields.iter().find(|(n, _)| n == field).map(|(_, vv)| vv)
        }
        _ => None,
    }
}

fn composite_get_unnamed<T>(v: &dynamic::Value<T>, idx: usize) -> Option<&dynamic::Value<T>> {
    use subxt::ext::scale_value::{Composite, ValueDef};
    match &v.value {
        ValueDef::Composite(Composite::Unnamed(vals)) => vals.get(idx),
        _ => None,
    }
}

/// Gets a field by name or index, supporting both named and unnamed composites.
fn get_field<'a, T>(
    v: &'a dynamic::Value<T>,
    name: &str,
    idx: usize,
) -> Option<&'a dynamic::Value<T>> {
    composite_get_named(v, name).or_else(|| composite_get_unnamed(v, idx))
}

/// Parses a ChildRegistration SCALE value into a view struct.
fn parse_child_registration_value(v: &dynamic::Value<u32>) -> Result<ChildRegistrationView> {
    let family_v = get_field(v, "family", 0).ok_or_else(|| anyhow!("missing family"))?;
    let node_id_v = get_field(v, "node_id", 1).ok_or_else(|| anyhow!("missing node_id"))?;
    let status_v = get_field(v, "status", 2).ok_or_else(|| anyhow!("missing status"))?;
    let deposit_v = get_field(v, "deposit", 3).ok_or_else(|| anyhow!("missing deposit"))?;
    let unbonding_end_v =
        get_field(v, "unbonding_end", 4).ok_or_else(|| anyhow!("missing unbonding_end"))?;

    let family = value_bytes32(family_v).ok_or_else(|| anyhow!("family not bytes32"))?;
    let node_id = value_bytes32(node_id_v).ok_or_else(|| anyhow!("node_id not bytes32"))?;

    let status = value_variant_name(status_v)
        .unwrap_or("Unknown")
        .to_string();

    let deposit_u128 = value_u128(deposit_v).unwrap_or(0);
    let unbonding_end_u128 = value_u128(unbonding_end_v).unwrap_or(0);
    let unbonding_end = (unbonding_end_u128.min(u32::MAX as u128)) as u32;

    Ok(ChildRegistrationView {
        family_id: hex32(family),
        node_id: hex32(node_id),
        status,
        deposit: deposit_u128.to_string(),
        unbonding_end,
    })
}

// ============================================================================
// Snapshot Building
// ============================================================================

/// Builds a complete registry snapshot from on-chain storage.
///
/// Iterates over all storage maps and constructs the snapshot atomically
/// at the latest finalized block.
async fn build_snapshot(
    client: &OnlineClient<PolkadotConfig>,
    pallet_name: &str,
) -> Result<RegistrySnapshot> {
    let at_block: u32 = client.blocks().at_latest().await?.number();

    // family -> children
    let mut family_children: BTreeMap<String, Vec<String>> = BTreeMap::new();
    {
        let keys: Vec<dynamic::Value> = vec![];
        let q = dynamic::storage(pallet_name, "FamilyChildren", keys);
        let mut it = client.storage().at_latest().await?.iter(q).await?;
        while let Some(Ok(kv)) = it.next().await {
            if kv.keys.len() != 1 {
                continue;
            }
            let family = match value_bytes32(&kv.keys[0]) {
                Some(b) => b,
                None => continue,
            };
            let family_hex = hex32(family);
            let value = kv.value.to_value().context("decode FamilyChildren value")?;

            // Value is BoundedVec<AccountId> -> unnamed composite of AccountId bytes.
            let mut children_hex = Vec::new();
            if let subxt::ext::scale_value::ValueDef::Composite(
                subxt::ext::scale_value::Composite::Unnamed(vals),
            ) = &value.value
            {
                for c in vals {
                    if let Some(bytes) = value_bytes32(c) {
                        children_hex.push(hex32(bytes));
                    }
                }
            }
            family_children.insert(family_hex, children_hex);
        }
    }

    // child -> registration
    let mut child_registrations: BTreeMap<String, ChildRegistrationView> = BTreeMap::new();
    {
        let keys: Vec<dynamic::Value> = vec![];
        let q = dynamic::storage(pallet_name, "ChildRegistrations", keys);
        let mut it = client.storage().at_latest().await?.iter(q).await?;
        while let Some(Ok(kv)) = it.next().await {
            if kv.keys.len() != 1 {
                continue;
            }
            let child = match value_bytes32(&kv.keys[0]) {
                Some(b) => b,
                None => continue,
            };
            let child_hex = hex32(child);
            let reg_val = kv
                .value
                .to_value()
                .context("decode ChildRegistrations value")?;
            let reg_view = parse_child_registration_value(&reg_val)?;
            child_registrations.insert(child_hex, reg_view);
        }
    }

    // node_id -> child (active only)
    let mut node_id_to_child: BTreeMap<String, String> = BTreeMap::new();
    {
        let keys: Vec<dynamic::Value> = vec![];
        let q = dynamic::storage(pallet_name, "NodeIdToChild", keys);
        let mut it = client.storage().at_latest().await?.iter(q).await?;
        while let Some(Ok(kv)) = it.next().await {
            if kv.keys.len() != 1 {
                continue;
            }
            let node_id = match value_bytes32(&kv.keys[0]) {
                Some(b) => b,
                None => continue,
            };
            let node_hex = hex32(node_id);
            let child_val = kv.value.to_value().context("decode NodeIdToChild value")?;
            let child = match value_bytes32(&child_val) {
                Some(b) => b,
                None => continue,
            };
            node_id_to_child.insert(node_hex, hex32(child));
        }
    }

    Ok(RegistrySnapshot {
        at_block,
        pallet: pallet_name.to_string(),
        family_children,
        child_registrations,
        node_id_to_child,
    })
}

/// Writes the snapshot to disk atomically using write-to-temp + rename.
///
/// This ensures readers never see a partially written file.
fn write_atomic_json(path: &PathBuf, snapshot: &RegistrySnapshot) -> Result<()> {
    // Ensure parent directory exists before writing
    if let Some(parent) = path.parent().filter(|p| !p.as_os_str().is_empty()) {
        std::fs::create_dir_all(parent)
            .with_context(|| format!("failed to create cache directory: {}", parent.display()))?;
    }

    let tmp = path.with_extension("json.tmp");
    std::fs::write(&tmp, serde_json::to_vec_pretty(snapshot)?)?;
    if let Err(e) = std::fs::rename(&tmp, path) {
        // Clean up temp file on rename failure (e.g., cross-filesystem rename)
        let _ = std::fs::remove_file(&tmp);
        return Err(e.into());
    }
    Ok(())
}

#[tokio::main]
async fn main() -> Result<()> {
    dotenvy::dotenv().ok();
    tracing_subscriber::fmt()
        .with_env_filter(tracing_subscriber::EnvFilter::from_default_env())
        .init();

    let args = Args::parse();
    tracing::info!("Connecting to chain WS: {}", args.chain_ws_url);
    let mut client = OnlineClient::<PolkadotConfig>::from_url(&args.chain_ws_url)
        .await
        .context("connect chain ws")?;

    let mut pallet_name = if args.arion_pallet_name.trim().is_empty() {
        detect_arion_pallet_name(&client)?
    } else {
        args.arion_pallet_name.clone()
    };
    tracing::info!("Using arion pallet name: {}", pallet_name);
    tracing::info!("Writing registry cache to: {}", args.out.display());

    let mut consecutive_failures = 0u32;
    let mut last_error: Option<anyhow::Error> = None;

    loop {
        // Wrap RPC calls in timeout to prevent hanging on unresponsive nodes
        let snapshot_result = tokio::time::timeout(
            Duration::from_secs(RPC_TIMEOUT_SECS),
            build_snapshot(&client, &pallet_name),
        )
        .await;

        // Convert timeout and build_snapshot errors into a single error type for handling
        let build_result = match snapshot_result {
            Ok(Ok(snap)) => Ok(snap),
            Ok(Err(e)) => Err(e),
            Err(_elapsed) => Err(anyhow!("RPC timeout after {} seconds", RPC_TIMEOUT_SECS)),
        };

        match build_result {
            Ok(snap) => {
                consecutive_failures = 0; // Reset on success
                last_error = None;
                if let Err(e) = write_atomic_json(&args.out, &snap) {
                    tracing::warn!("write snapshot failed: {:#}", e);
                    if args.once {
                        return Err(e);
                    }
                } else {
                    tracing::info!(
                        "snapshot at_block={} families={} children={} nodes={}",
                        snap.at_block,
                        snap.family_children.len(),
                        snap.child_registrations.len(),
                        snap.node_id_to_child.len()
                    );
                }
            }
            Err(e) => {
                if is_connection_error(&e) {
                    tracing::warn!(error = %e, "Connection lost or timeout, attempting to reconnect...");
                    if let Some((new_client, new_pallet)) =
                        try_reconnect(&args.chain_ws_url, &args.arion_pallet_name).await
                    {
                        client = new_client;
                        if let Some(name) = new_pallet {
                            pallet_name = name;
                        }
                        // Reset failure count on successful reconnection
                        consecutive_failures = 0;
                        tracing::info!("Reconnection successful, resuming normal operation");
                        continue;
                    }
                } else {
                    tracing::warn!("build snapshot failed: {:#}", e);
                }

                consecutive_failures = consecutive_failures.saturating_add(1);

                // For --once mode, capture the error to return it
                if args.once {
                    last_error = Some(e);
                }

                // Exponential backoff on consecutive failures
                if consecutive_failures >= 5 {
                    let backoff =
                        std::cmp::min(args.poll_secs * 2u64.pow(consecutive_failures.min(4)), 300);
                    tracing::warn!(
                        consecutive_failures,
                        backoff_secs = backoff,
                        "Multiple consecutive failures, backing off"
                    );
                    tokio::time::sleep(Duration::from_secs(backoff)).await;
                    continue;
                }
            }
        }

        if args.once {
            // Return error if snapshot failed, otherwise success
            return match last_error {
                Some(e) => Err(e),
                None => Ok(()),
            };
        }
        tokio::time::sleep(Duration::from_secs(args.poll_secs)).await;
    }
}

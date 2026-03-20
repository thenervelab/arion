//! Background task that maintains persistent QUIC connections to gateways.
//!
//! Gateways prefer inbound miner-initiated connections (they bypass NAT and
//! are immediately marked Healthy). The validator distributes gateway endpoints
//! in [`ClusterMapUpdate`] broadcasts; this module reads them from global state
//! and periodically connects to each gateway using the `hippius/gateway-inbound`
//! ALPN, sending the miner UID so the gateway can add the connection to its pool.
//!
//! # Protocol
//!
//! 1. Connect to gateway on `GATEWAY_INBOUND_ALPN`
//! 2. Open a bidirectional stream
//! 3. Send miner UID as 4-byte little-endian u32
//! 4. Finish the send side (signals end of miner→gateway data)
//! 5. Read gateway ACK (`b"OK"` or `b"ERR:..."`)
//! 6. Keep the connection alive — drop only on error or next cycle replacement

use crate::constants;
use crate::helpers::truncate_for_log;
use crate::state;
use anyhow::Result;
use dashmap::DashMap;
use std::sync::Arc;
use tokio_util::sync::CancellationToken;
use tracing::{debug, info, warn};

/// Tracks the state of a gateway connection.
struct GatewayConn {
    /// The live QUIC connection (kept alive across cycles).
    conn: quinn::Connection,
}

/// Spawn the gateway keepalive background loop.
///
/// The task runs until `shutdown` is cancelled. On each tick it iterates over
/// known gateway endpoints (populated by `ClusterMapUpdate` handler) and
/// ensures a live connection exists to each one.
pub fn spawn_gateway_keepalive(endpoint: quinn::Endpoint, shutdown: CancellationToken) {
    let interval_secs: u64 = std::env::var("MINER_GATEWAY_KEEPALIVE_INTERVAL_SECS")
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(constants::DEFAULT_GATEWAY_KEEPALIVE_INTERVAL_SECS);

    let connect_timeout_secs: u64 = std::env::var("MINER_GATEWAY_CONNECT_TIMEOUT_SECS")
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(constants::DEFAULT_GATEWAY_CONNECT_TIMEOUT_SECS);

    tokio::spawn(async move {
        info!(
            interval_secs,
            connect_timeout_secs, "Gateway keepalive loop started"
        );

        // Local map of node_id -> live connection
        let live_conns: Arc<DashMap<String, GatewayConn>> = Arc::new(DashMap::new());

        loop {
            tokio::select! {
                () = tokio::time::sleep(std::time::Duration::from_secs(interval_secs)) => {}
                () = shutdown.cancelled() => {
                    info!("Gateway keepalive loop received shutdown signal");
                    break;
                }
            }

            let gw_endpoints = state::get_gateway_endpoints();
            if gw_endpoints.is_empty() {
                debug!("No gateway endpoints known, skipping keepalive cycle");
                continue;
            }

            // Collect snapshot to avoid holding DashMap refs across await points
            let endpoints: Vec<common::GatewayEndpoint> =
                gw_endpoints.iter().map(|e| e.value().clone()).collect();

            // Remove connections to gateways no longer in the endpoint list
            let known_ids: std::collections::HashSet<String> =
                endpoints.iter().map(|e| e.node_id.clone()).collect();
            let before = live_conns.len();
            live_conns.retain(|k, _| known_ids.contains(k));
            let pruned = before.saturating_sub(live_conns.len());
            if pruned > 0 {
                debug!(
                    pruned,
                    remaining = live_conns.len(),
                    "Pruned stale gateway connections"
                );
            }

            let miner_uid = state::get_miner_uid();

            for gw in &endpoints {
                let gw_short = truncate_for_log(&gw.node_id, 16);

                // Check if existing connection is still alive
                if let Some(entry) = live_conns.get(&gw.node_id) {
                    if !is_conn_closed(&entry.conn) {
                        debug!(
                            miner_uid,
                            gateway_node_id = %gw_short,
                            "Gateway connection still alive, skipping"
                        );
                        continue;
                    }
                    // Connection is dead, remove it
                    drop(entry);
                    live_conns.remove(&gw.node_id);
                    debug!(
                        miner_uid,
                        gateway_node_id = %gw_short,
                        "Removed dead gateway connection, will reconnect"
                    );
                }

                // Parse gateway direct_addr to SocketAddr
                let gw_addr = match gw.direct_addr.as_ref() {
                    Some(addr_str) => match addr_str.parse::<std::net::SocketAddr>() {
                        Ok(addr) => addr,
                        Err(e) => {
                            warn!(
                                miner_uid,
                                gateway_node_id = %gw_short,
                                direct_addr = %addr_str,
                                error = %e,
                                "Failed to parse gateway direct_addr as SocketAddr"
                            );
                            continue;
                        }
                    },
                    None => {
                        warn!(
                            miner_uid,
                            gateway_node_id = %gw_short,
                            "Gateway has no direct_addr, skipping"
                        );
                        continue;
                    }
                };

                match connect_and_handshake(&endpoint, &gw.node_id, gw_addr, miner_uid, connect_timeout_secs)
                    .await
                {
                    Ok(conn) => {
                        info!(
                            miner_uid,
                            gateway_node_id = %gw_short,
                            active_gateways = live_conns.len() + 1,
                            "Gateway keepalive connection established"
                        );
                        live_conns.insert(gw.node_id.clone(), GatewayConn { conn });
                    }
                    Err(e) => {
                        warn!(
                            miner_uid,
                            gateway_node_id = %gw_short,
                            error = %e,
                            "Failed to connect to gateway for keepalive"
                        );
                    }
                }
            }
        }
    });
}

/// Connect to a gateway and perform the inbound handshake.
///
/// Mirrors the protocol expected by `MinerInboundHandler` on the gateway side:
/// send UID as 4-byte LE u32, finish the send side, then read ACK.
///
/// Important: `send.finish()` is called *after* `write_all` to signal
/// end-of-data to the gateway's `recv.read_exact()`. The gateway reads
/// exactly 4 bytes, then writes back `b"OK"` or `b"ERR:..."` and finishes
/// its send side. The miner reads the ACK from `recv`.
async fn connect_and_handshake(
    endpoint: &quinn::Endpoint,
    gw_node_id: &str,
    gw_addr: std::net::SocketAddr,
    miner_uid: u32,
    connect_timeout_secs: u64,
) -> Result<quinn::Connection> {
    let timeout = std::time::Duration::from_secs(connect_timeout_secs);

    // Connect using quinn transport
    let conn = tokio::time::timeout(
        timeout,
        common::transport::connect(endpoint, gw_addr, gw_node_id),
    )
    .await
    .map_err(|_| {
        anyhow::anyhow!(
            "Timeout connecting to gateway after {}s",
            connect_timeout_secs
        )
    })??;

    // Open bidirectional stream for the handshake
    let (mut send, mut recv) =
        tokio::time::timeout(std::time::Duration::from_secs(5), conn.open_bi())
            .await
            .map_err(|_| anyhow::anyhow!("Timeout opening bi stream to gateway"))??;

    // Send miner UID as 4-byte little-endian, then finish the send side.
    // finish() signals FIN to the gateway so its read_exact(4) completes cleanly.
    send.write_all(&miner_uid.to_le_bytes()).await?;
    send.finish()?;

    // Read gateway ACK (up to 32 bytes).
    // The gateway writes b"OK" or b"ERR:..." then finishes its send side,
    // so recv.read_to_end() will return once the gateway finishes.
    let ack_buf = tokio::time::timeout(
        std::time::Duration::from_secs(5),
        recv.read_to_end(32),
    )
    .await
    .map_err(|_| anyhow::anyhow!("Timeout reading gateway ACK after 5s"))??;
    let n = ack_buf.len();

    let ack = &ack_buf[..];
    if ack.starts_with(b"OK") {
        debug!(miner_uid, ack_bytes = n, "Gateway ACK received");
        Ok(conn)
    } else if n == 0 {
        anyhow::bail!(
            "Gateway closed stream without ACK (0 bytes read) — \
             gateway may not have this miner (uid={miner_uid}) in its cluster map, \
             or the handshake stream was reset before the ACK was sent"
        )
    } else {
        let msg = String::from_utf8_lossy(ack);
        anyhow::bail!("Gateway rejected keepalive (uid={miner_uid}): {msg}");
    }
}

/// Check if a QUIC connection is closed (non-blocking).
fn is_conn_closed(conn: &quinn::Connection) -> bool {
    conn.close_reason().is_some()
}

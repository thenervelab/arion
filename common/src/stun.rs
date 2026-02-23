//! Minimal RFC 5389 STUN Binding Request client for public IP auto-detection.
//!
//! Sends a 20-byte STUN Binding Request to multiple servers concurrently and
//! returns the first successful XOR-MAPPED-ADDRESS (with MAPPED-ADDRESS fallback).
//! No new crate dependencies beyond `tokio` (UDP + timeout) and `rand` (txn ID).

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr, UdpSocket};
use std::time::Duration;

use tokio::net::UdpSocket as TokioUdpSocket;
use tracing::debug;

/// Result of a successful STUN query.
#[derive(Debug, Clone)]
pub struct StunResult {
    pub ip: IpAddr,
    pub port: u16,
}

/// STUN message constants (RFC 5389).
const STUN_BINDING_REQUEST: u16 = 0x0001;
const STUN_MAGIC_COOKIE: u32 = 0x2112_A442;
const ATTR_MAPPED_ADDRESS: u16 = 0x0001;
const ATTR_XOR_MAPPED_ADDRESS: u16 = 0x0020;
const STUN_HEADER_LEN: usize = 20;
const STUN_FAMILY_IPV4: u8 = 0x01;
const STUN_FAMILY_IPV6: u8 = 0x02;

/// Public STUN servers used for detection.
const STUN_SERVERS: &[&str] = &[
    "stun.l.google.com:19302",
    "stun1.l.google.com:19302",
    "stun.cloudflare.com:3478",
];

/// Build a 20-byte STUN Binding Request (no attributes).
fn build_binding_request() -> [u8; STUN_HEADER_LEN] {
    let mut buf = [0u8; STUN_HEADER_LEN];

    // Message type: Binding Request (0x0001)
    let msg_type = STUN_BINDING_REQUEST.to_be_bytes();
    buf[0] = msg_type[0];
    buf[1] = msg_type[1];

    // Message length: 0 (no attributes)
    // buf[2..4] already zeroed

    // Magic cookie
    let cookie = STUN_MAGIC_COOKIE.to_be_bytes();
    buf[4..8].copy_from_slice(&cookie);

    // 12-byte transaction ID (random)
    let mut rng = rand::rng();
    rand::Fill::fill(&mut buf[8..20], &mut rng);

    buf
}

/// Find a STUN attribute by type in a response body (after the 20-byte header).
/// Returns the attribute value bytes if found.
fn find_attribute(attrs: &[u8], attr_type: u16) -> Option<&[u8]> {
    let mut offset = 0;
    while offset + 4 <= attrs.len() {
        let typ = u16::from_be_bytes([attrs[offset], attrs[offset + 1]]);
        let len = u16::from_be_bytes([attrs[offset + 2], attrs[offset + 3]]) as usize;

        if offset + 4 + len > attrs.len() {
            break;
        }

        if typ == attr_type {
            return Some(&attrs[offset + 4..offset + 4 + len]);
        }

        // Advance past value + padding to 4-byte boundary
        let padded = (len + 3) & !3;
        offset += 4 + padded;
    }
    None
}

/// Parse an XOR-MAPPED-ADDRESS attribute value into IP + port.
fn parse_xor_mapped_address(value: &[u8], txn_id: &[u8; 12]) -> Option<StunResult> {
    if value.len() < 8 {
        return None;
    }

    let family = value[1];
    let xored_port = u16::from_be_bytes([value[2], value[3]]);
    let port = xored_port ^ (STUN_MAGIC_COOKIE >> 16) as u16;

    match family {
        STUN_FAMILY_IPV4 if value.len() >= 8 => {
            let cookie_bytes = STUN_MAGIC_COOKIE.to_be_bytes();
            let ip = Ipv4Addr::new(
                value[4] ^ cookie_bytes[0],
                value[5] ^ cookie_bytes[1],
                value[6] ^ cookie_bytes[2],
                value[7] ^ cookie_bytes[3],
            );
            Some(StunResult {
                ip: IpAddr::V4(ip),
                port,
            })
        }
        STUN_FAMILY_IPV6 if value.len() >= 20 => {
            // XOR with magic cookie (4 bytes) + transaction ID (12 bytes)
            let mut xor_key = [0u8; 16];
            xor_key[..4].copy_from_slice(&STUN_MAGIC_COOKIE.to_be_bytes());
            xor_key[4..16].copy_from_slice(txn_id);

            let mut ip_bytes = [0u8; 16];
            for i in 0..16 {
                ip_bytes[i] = value[4 + i] ^ xor_key[i];
            }
            let ip = Ipv6Addr::from(ip_bytes);
            Some(StunResult {
                ip: IpAddr::V6(ip),
                port,
            })
        }
        _ => None,
    }
}

/// Parse a MAPPED-ADDRESS attribute value (non-XOR fallback).
fn parse_mapped_address(value: &[u8]) -> Option<StunResult> {
    if value.len() < 8 {
        return None;
    }

    let family = value[1];
    let port = u16::from_be_bytes([value[2], value[3]]);

    match family {
        STUN_FAMILY_IPV4 if value.len() >= 8 => {
            let ip = Ipv4Addr::new(value[4], value[5], value[6], value[7]);
            Some(StunResult {
                ip: IpAddr::V4(ip),
                port,
            })
        }
        STUN_FAMILY_IPV6 if value.len() >= 20 => {
            let mut ip_bytes = [0u8; 16];
            ip_bytes.copy_from_slice(&value[4..20]);
            let ip = Ipv6Addr::from(ip_bytes);
            Some(StunResult {
                ip: IpAddr::V6(ip),
                port,
            })
        }
        _ => None,
    }
}

/// Parse a STUN Binding Response and extract the mapped address.
fn parse_binding_response(response: &[u8], expected_txn_id: &[u8; 12]) -> Option<StunResult> {
    if response.len() < STUN_HEADER_LEN {
        return None;
    }

    // Validate magic cookie
    let cookie = u32::from_be_bytes(response[4..8].try_into().ok()?);
    if cookie != STUN_MAGIC_COOKIE {
        return None;
    }

    // Validate transaction ID
    if response[8..20] != expected_txn_id[..] {
        return None;
    }

    let attrs = &response[STUN_HEADER_LEN..];

    // Prefer XOR-MAPPED-ADDRESS, fall back to MAPPED-ADDRESS
    if let Some(value) = find_attribute(attrs, ATTR_XOR_MAPPED_ADDRESS)
        && let Some(result) = parse_xor_mapped_address(value, expected_txn_id)
    {
        return Some(result);
    }

    if let Some(value) = find_attribute(attrs, ATTR_MAPPED_ADDRESS) {
        return parse_mapped_address(value);
    }

    None
}

/// Resolve a STUN server hostname and return the first address matching
/// the desired address family. On dual-stack hosts, `getaddrinfo` may
/// return AAAA records before A records, which causes `send_to` on an
/// IPv4 socket to fail with EAFNOSUPPORT. Filtering explicitly avoids this.
async fn resolve_matching_addr(
    server: &str,
    want_ipv4: bool,
) -> Option<SocketAddr> {
    let addrs = tokio::net::lookup_host(server).await.ok()?;
    for addr in addrs {
        if want_ipv4 && addr.is_ipv4() {
            return Some(addr);
        }
        if !want_ipv4 && addr.is_ipv6() {
            return Some(addr);
        }
    }
    None
}

/// Query a single STUN server and return the mapped address.
async fn query_stun_server(
    server: &str,
    bind_addr: SocketAddr,
    timeout: Duration,
) -> Option<StunResult> {
    let want_ipv4 = bind_addr.is_ipv4();

    // Resolve hostname and pick an address matching our socket's family.
    let target = match resolve_matching_addr(server, want_ipv4).await {
        Some(addr) => addr,
        None => {
            debug!(
                server,
                want_ipv4, "No DNS record matching address family"
            );
            return None;
        }
    };

    let request = build_binding_request();
    let txn_id: [u8; 12] = request[8..20].try_into().ok()?;

    let socket = match TokioUdpSocket::bind(bind_addr).await {
        Ok(s) => s,
        Err(e) => {
            debug!(server, error = %e, "STUN bind failed");
            return None;
        }
    };

    if let Err(e) = socket.send_to(&request, target).await {
        debug!(server, error = %e, "STUN send failed");
        return None;
    }

    let mut buf = [0u8; 512];
    match tokio::time::timeout(timeout, socket.recv_from(&mut buf)).await {
        Ok(Ok((len, _))) => parse_binding_response(&buf[..len], &txn_id),
        Ok(Err(e)) => {
            debug!(server, error = %e, "STUN recv failed");
            None
        }
        Err(_) => {
            debug!(server, "STUN query timed out");
            None
        }
    }
}

/// Detect the public IPv4 address by racing queries to multiple STUN servers.
/// Returns the first successful result within `timeout`.
pub async fn detect_public_ipv4(timeout: Duration) -> Option<StunResult> {
    let bind_addr: SocketAddr = SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), 0);

    let (tx, mut rx) = tokio::sync::mpsc::channel(STUN_SERVERS.len());

    for server in STUN_SERVERS {
        let tx = tx.clone();
        let server = (*server).to_string();
        let per_server_timeout = timeout;
        tokio::spawn(async move {
            if let Some(result) = query_stun_server(&server, bind_addr, per_server_timeout).await
                && result.ip.is_ipv4()
            {
                let _ = tx.send(result).await;
            }
        });
    }
    drop(tx);

    // Return first successful result or None if all fail/timeout
    tokio::time::timeout(timeout, rx.recv())
        .await
        .ok()
        .flatten()
}

/// Detect the public IPv6 address by racing queries to multiple STUN servers.
/// Returns the first successful result within `timeout`.
pub async fn detect_public_ipv6(timeout: Duration) -> Option<StunResult> {
    let bind_addr: SocketAddr = SocketAddr::new(IpAddr::V6(Ipv6Addr::UNSPECIFIED), 0);

    let (tx, mut rx) = tokio::sync::mpsc::channel(STUN_SERVERS.len());

    for server in STUN_SERVERS {
        let tx = tx.clone();
        let server = (*server).to_string();
        let per_server_timeout = timeout;
        tokio::spawn(async move {
            if let Some(result) = query_stun_server(&server, bind_addr, per_server_timeout).await
                && result.ip.is_ipv6()
            {
                let _ = tx.send(result).await;
            }
        });
    }
    drop(tx);

    tokio::time::timeout(timeout, rx.recv())
        .await
        .ok()
        .flatten()
}

/// Check whether an IP address is bound to a local network interface.
///
/// Tries to bind a UDP socket to `ip:0`. If the OS accepts it, the IP
/// belongs to a local interface. This is used to decide whether a
/// STUN-detected IP can be used as a bind address (bare metal with
/// public IP) or only as an advertised hostname (behind NAT).
pub fn is_local_interface_ip(ip: IpAddr) -> bool {
    UdpSocket::bind(SocketAddr::new(ip, 0)).is_ok()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn build_binding_request_format() {
        let req = build_binding_request();
        assert_eq!(req.len(), 20);

        // Message type: Binding Request
        assert_eq!(u16::from_be_bytes([req[0], req[1]]), STUN_BINDING_REQUEST);
        // Message length: 0
        assert_eq!(u16::from_be_bytes([req[2], req[3]]), 0);
        // Magic cookie
        assert_eq!(
            u32::from_be_bytes(req[4..8].try_into().unwrap()),
            STUN_MAGIC_COOKIE
        );
        // Transaction ID is 12 bytes (non-zero with overwhelming probability)
        assert_eq!(req[8..20].len(), 12);
    }

    #[test]
    fn parse_xor_mapped_address_ipv4() {
        // Craft a STUN response with XOR-MAPPED-ADDRESS for 203.0.113.5:12345
        let ip = Ipv4Addr::new(203, 0, 113, 5);
        let port: u16 = 12345;
        let txn_id: [u8; 12] = [1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12];

        // XOR the port with top 16 bits of magic cookie
        let xored_port = port ^ (STUN_MAGIC_COOKIE >> 16) as u16;
        let cookie_bytes = STUN_MAGIC_COOKIE.to_be_bytes();
        let ip_octets = ip.octets();
        let xored_ip = [
            ip_octets[0] ^ cookie_bytes[0],
            ip_octets[1] ^ cookie_bytes[1],
            ip_octets[2] ^ cookie_bytes[2],
            ip_octets[3] ^ cookie_bytes[3],
        ];

        // Build response: header + XOR-MAPPED-ADDRESS attribute
        let mut response = Vec::new();

        // Header: Binding Success Response (0x0101)
        response.extend_from_slice(&0x0101u16.to_be_bytes());
        // Message length: 12 bytes (4 attr header + 8 attr value)
        response.extend_from_slice(&12u16.to_be_bytes());
        // Magic cookie
        response.extend_from_slice(&STUN_MAGIC_COOKIE.to_be_bytes());
        // Transaction ID
        response.extend_from_slice(&txn_id);

        // XOR-MAPPED-ADDRESS attribute
        response.extend_from_slice(&ATTR_XOR_MAPPED_ADDRESS.to_be_bytes());
        response.extend_from_slice(&8u16.to_be_bytes()); // length
        response.push(0x00); // reserved
        response.push(STUN_FAMILY_IPV4);
        response.extend_from_slice(&xored_port.to_be_bytes());
        response.extend_from_slice(&xored_ip);

        let result = parse_binding_response(&response, &txn_id).unwrap();
        assert_eq!(result.ip, IpAddr::V4(ip));
        assert_eq!(result.port, port);
    }

    #[test]
    fn find_attribute_skips_non_matching() {
        // Two attributes: type 0x0006 (USERNAME, 4 bytes) then 0x0020 (XOR-MAPPED-ADDRESS, 8 bytes)
        let mut attrs = Vec::new();

        // First attr: type=0x0006, length=4, value=[0xAA; 4]
        attrs.extend_from_slice(&0x0006u16.to_be_bytes());
        attrs.extend_from_slice(&4u16.to_be_bytes());
        attrs.extend_from_slice(&[0xAA, 0xAA, 0xAA, 0xAA]);

        // Second attr: type=0x0020, length=8, value=[0xBB; 8]
        attrs.extend_from_slice(&ATTR_XOR_MAPPED_ADDRESS.to_be_bytes());
        attrs.extend_from_slice(&8u16.to_be_bytes());
        attrs.extend_from_slice(&[0xBB; 8]);

        let found = find_attribute(&attrs, ATTR_XOR_MAPPED_ADDRESS);
        assert!(found.is_some());
        assert_eq!(found.unwrap(), &[0xBB; 8]);

        // Non-existent attribute
        let missing = find_attribute(&attrs, 0x9999);
        assert!(missing.is_none());
    }

    #[test]
    fn is_local_interface_loopback() {
        assert!(is_local_interface_ip(IpAddr::V4(Ipv4Addr::LOCALHOST)));
    }

    #[test]
    fn is_local_interface_non_local() {
        // TEST-NET-2 (198.51.100.0/24) — never assigned to a real interface
        assert!(!is_local_interface_ip(IpAddr::V4(Ipv4Addr::new(
            198, 51, 100, 1
        ))));
    }

    #[tokio::test]
    #[ignore] // Requires internet connectivity
    async fn stun_detects_public_ipv4() {
        let result = detect_public_ipv4(Duration::from_secs(5)).await;
        assert!(result.is_some(), "STUN should detect a public IPv4 address");
        let stun = result.unwrap();
        match stun.ip {
            IpAddr::V4(v4) => {
                assert!(
                    !v4.is_loopback() && !v4.is_private() && !v4.is_unspecified(),
                    "Detected IP should be a public address: {}",
                    v4
                );
            }
            IpAddr::V6(_) => {
                panic!("Expected IPv4 address from IPv4 STUN query")
            }
        }
    }
}

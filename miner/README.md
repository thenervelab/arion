# Miner

Storage node for Hippius Arion. Receives shards from validators via P2P, stores them locally, and serves them to gateways and other miners.

## Quick Start

```bash
# Build
cargo build -p miner --release

# Run (requires validator to be running)
cargo run --bin miner -- --validator-node-id <node_id> --hostname <your-public-ipv4>

# Run with config file
cp miner.example.toml miner.toml
cargo run --bin miner

# Generate keypair for new miner identity
cargo run --bin generate_keypair -- --output data/miner
```

## Networking

The miner uses **UDP port 11220** for iroh P2P communication. This port **must be open for inbound UDP traffic** in your firewall and hosting provider.

**`--hostname` must be your server's public IPv4 address.** The validator uses this address to establish direct P2P connections. Setting it to `0.0.0.0`, `localhost`, or a private/Docker IP means the validator cannot reach your miner and it will not receive shards.

STUN-based auto-detection is enabled by default and discovers your public IP automatically. If auto-detection works for your network, you can omit `--hostname`. For servers with multiple interfaces or Docker installed, set it explicitly.

```bash
# Find your public IP
curl -4 ifconfig.me

# Verify UDP port is reachable (from another machine)
echo test | nc -u -w2 <your-public-ip> 11220
```

Docker bridge networking is **not supported**. Run the miner directly on the host. If Docker is installed but the miner runs natively, set `P2P_BIND_IPV4` to your public IP to avoid advertising the `docker0` address.

### Firewall & Conntrack (UFW / iptables)

If your server uses a firewall with `INPUT DROP` policy (e.g. UFW), you **must** ensure the Linux conntrack UDP timeout is high enough to keep QUIC connections alive.

The miner communicates with the validator over QUIC (UDP). Linux conntrack tracks outbound UDP flows and allows return traffic. By default, the conntrack timeout for "unreplied" UDP flows is **30 seconds**, which is too short — QUIC path probing will consider the path dead and abandon the connection.

**Required sysctl setting:**

```bash
# Check current values
sysctl net.netfilter.nf_conntrack_udp_timeout
sysctl net.netfilter.nf_conntrack_udp_timeout_stream

# Set both to 120 seconds (must be >= QUIC idle timeout)
sudo sysctl -w net.netfilter.nf_conntrack_udp_timeout=120
sudo sysctl -w net.netfilter.nf_conntrack_udp_timeout_stream=120

# Persist across reboots
echo 'net.netfilter.nf_conntrack_udp_timeout=120' | sudo tee -a /etc/sysctl.conf
echo 'net.netfilter.nf_conntrack_udp_timeout_stream=120' | sudo tee -a /etc/sysctl.conf
```

**Symptoms of a too-low timeout:**
- Miner registers successfully but loses connection ~30s later
- Logs show: `[DISCONNECTED] Lost connection to validator` or `no viable network path exists: last path abandoned by peer`
- Re-registration attempts fail with `connect timeout` or `server refused to accept a new connection`

> **Note:** This primarily affects miners on networks outside the validator's local network (e.g. different hosting providers). Miners on the same network (e.g. same vRack/VLAN) are typically unaffected.

## Configuration

Copy `miner.example.toml` to `miner.toml`:

```toml
[network]
hostname = "203.0.113.10"  # YOUR public IPv4 - not 0.0.0.0 or localhost
p2p_port = 11220
family_id = "default"

[storage]
path = "data/miner/blobs"
max_storage_gb = 0  # unlimited

[validator]
node_id = "<validator_node_id>"

[tuning]
store_concurrency = 64
pull_concurrency = 32
fetch_concurrency = 256
```

## Auto-Update

The miner includes a built-in auto-update mechanism that checks GitHub releases every 5 minutes and automatically upgrades to newer versions.

**How it works:**
1. Every 5 minutes, the miner queries `https://api.github.com/repos/thenervelab/arion/releases/latest`
2. Compares the latest release tag (semver) with the running version
3. If a newer version is available, downloads the `miner-linux-x86_64` asset
4. Verifies the downloaded binary by running `--version`
5. Stops the service, replaces the binary, restarts
6. If the service fails to start, automatically rolls back to the previous binary

**Downgrade protection:** The miner will never downgrade. If the running version is higher than the latest release (e.g. dev builds), the update is skipped.

**Disable auto-update:**

```bash
# Option 1: Environment variable (in systemd service file)
Environment="AUTO_UPDATE_DISABLED=true"

# Option 2: Sentinel file (in data directory)
touch /var/lib/hippius/miner/data/miner/.no-auto-update
```

**Service name:** The update mechanism restarts via `systemctl restart arion-miner`. Override with `MINER_SERVICE_NAME` env var if your service has a different name.

## Environment Variables

| Variable | Default | Purpose |
|----------|---------|---------|
| `HOSTNAME` | auto-detected via STUN | Public IPv4 address (must be routable) |
| `P2P_PORT` | 11220 | UDP port for QUIC P2P |
| `P2P_BIND_IPV4` | 0.0.0.0 | IPv4 address to bind to |
| `FAMILY_ID` | default | Miner family ID |
| `VALIDATOR_NODE_ID` | required | Validator's node ID (hex-encoded Ed25519 public key) |
| `VALIDATOR_DIRECT_ADDRS` | - | Validator socket address for quinn transport (e.g. `51.210.230.161:11220`) |
| `WARDEN_NODE_ID` | - | Warden node ID for PoS challenges |
| `IROH_RELAY_URL` | iroh defaults | Relay server URL |
| `STUN_ENABLED` | true | Auto-detect public IP via STUN |
| `AUTO_UPDATE_DISABLED` | false | Set to `true` to disable auto-update |
| `MINER_SERVICE_NAME` | arion-miner | Systemd service name for restart |
| `MINER_STORE_CONCURRENCY` | 1024 | Concurrent store operations |
| `MINER_PULL_CONCURRENCY` | 32 | Concurrent pull operations |
| `MINER_FETCH_CONCURRENCY` | 256 | Concurrent fetch operations |

## Identity

Miner identity is an Ed25519 keypair stored in `data/miner/keypair.bin`.

```bash
# Backup identity
cargo run --bin miner -- backup --data-dir data/miner

# Restore identity
cargo run --bin miner -- restore backup.tar.gz --data-dir data/miner
```

## P2P Protocol

Miners respond to commands from the validator via `hippius/miner-control`:

- `Store`: Receive shard from validator or pull from peer
- `Delete`: Delete shard from storage
- `FetchBlob`: Return shard data (open to any peer)
- `CheckBlob`: Metadata-only existence check (no semaphore)
- `PullFromPeer`: Pull shard from another miner
- `ClusterMapUpdate`: Receive topology updates
- `PosChallenge`: Proof-of-storage audit from warden

## Running Multiple Miners

Each miner needs a unique data directory and P2P port:

```bash
# Miner 1
STORAGE_PATH=data1 P2P_PORT=11220 cargo run --bin miner -- \
    --family-id family_1 --validator-node-id <id> --hostname <your-public-ipv4>

# Miner 2
STORAGE_PATH=data2 P2P_PORT=11221 cargo run --bin miner -- \
    --family-id family_2 --validator-node-id <id> --hostname <your-public-ipv4>
```

See [Miner Onboarding Guide](MINER_ONBOARDING.md) for detailed setup instructions.

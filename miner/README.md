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

## Environment Variables

| Variable | Default | Purpose |
|----------|---------|---------|
| `HOSTNAME` | auto-detected via STUN | Public IPv4 address (must be routable) |
| `P2P_PORT` | 11220 | UDP port for Iroh P2P |
| `P2P_BIND_IPV4` | 0.0.0.0 | IPv4 address to bind to |
| `FAMILY_ID` | default | Miner family ID |
| `VALIDATOR_NODE_ID` | required | Validator's Iroh node ID |
| `WARDEN_NODE_ID` | - | Warden node ID for PoS challenges |
| `IROH_RELAY_URL` | iroh defaults | Relay server URL |
| `STUN_ENABLED` | true | Auto-detect public IP via STUN |
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

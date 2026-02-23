# Hippius Arion Miner Onboarding Guide

Complete guide for setting up and running a Hippius Arion storage miner.

## Table of Contents

1. [Overview](#overview)
2. [Prerequisites](#prerequisites)
3. [Step 1: Install Dependencies](#step-1-install-dependencies)
4. [Step 2: Clone Repository](#step-2-clone-repository)
5. [Step 3: Generate Miner Identity](#step-3-generate-miner-identity)
6. [Step 4: On-Chain Registration](#step-4-on-chain-registration)
7. [Step 5: Run Miner](#step-5-run-miner)
8. [Troubleshooting](#troubleshooting)
9. [Advanced Configuration](#advanced-configuration)

---

## Overview

The Hippius Arion network uses a validator/gateway/miner architecture:

- **Validator**: Orchestrates file placement and miner coordination (Kubernetes)
- **Gateway**: Ingress for uploads/downloads (Kubernetes)
- **Miners**: Store erasure-coded shards and serve them on request (Your machine)

As a miner, you will:

1. Generate a unique P2P identity (Ed25519 keypair)
2. Register on-chain via the Arion pallet
3. Connect to the validator via P2P
4. Store shards and earn rewards

---

## Prerequisites

### System Requirements

- **OS**: Linux, macOS, or Windows (WSL2)
- **RAM**: 4GB minimum, 8GB+ recommended
- **Storage**: 100GB+ free space (depends on network size)
- **Network**: Stable internet connection, public IP required, **UDP port 11220 open inbound**

### Networking: Critical Requirements

The miner communicates over **UDP port 11220** using the iroh P2P protocol. This port **must be open for inbound UDP traffic** in your firewall and hosting provider's security group/network rules.

**Verify your port is open** from another machine:

```bash
echo test | nc -u -w2 <your-public-ip> 11220
```

**The `--hostname` flag (or `HOSTNAME` env var) must be set to your server's public IPv4 address.** This is the address the validator uses to establish direct P2P connections to your miner. If you set it to `0.0.0.0`, `localhost`, a private IP, or a non-routable address, the validator cannot reach you and your miner will not receive shards.

The miner has STUN-based auto-detection enabled by default, which discovers your public IP automatically. If auto-detection works for your setup, you can omit `--hostname` entirely. However, if your network has multiple interfaces, Docker installed, or unusual NAT, set it explicitly:

```bash
# Find your public IP
curl -4 ifconfig.me

# Set it explicitly
export HOSTNAME="203.0.113.10"  # YOUR public IPv4 here
```

### Docker Is Not Supported

Running the miner inside a Docker container with bridge networking is **not supported**. Docker assigns a private `172.17.x.x` IP that is not routable from the internet, so the validator cannot establish direct P2P connections and the miner will never receive shards.

Run the miner directly on the host (bare-metal or systemd service).

If Docker is installed on the host but the miner runs natively, set `P2P_BIND_IPV4` to your public IP to prevent iroh from advertising the `docker0` bridge address:

```bash
export P2P_BIND_IPV4="<your-public-ipv4>"
```

### Required Information

You'll need these details from the network operator:

- **VALIDATOR_NODE_ID**: `185651f2fb19c919d40c3c58660cf463ebe7ded1c1a326eef4dad28292171cdb`
- **CHAIN_WS_URL**: `wss://rpc.hippius.network`
- **IROH_RELAY_URL**: `https://relay.hippius.com`

### Accounts

You'll need two Substrate accounts:

- **Family Account**: Signs registration transactions, holds deposit
- **Child Account**: Receives mining rewards (delegate account)

---

## Step 1: Install Dependencies

### Rust Toolchain

```bash
# Install Rust (if not already installed)
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh
source $HOME/.cargo/env

# Verify installation
rustc --version  # Should be 1.85+
```

### System Dependencies

**Ubuntu/Debian:**

```bash
sudo apt update
sudo apt install -y build-essential pkg-config libssl-dev perl make gcc g++
```

**macOS:**

```bash
brew install openssl pkg-config
```

---

## Step 2: Clone Repository

```bash
# Clone the Hippius Arion repository
git clone https://github.com/your-org/hippius-arion.git
cd hippius-arion

# Build the miner binaries
cargo build --release --bin miner
cargo build --release --bin miner-cli

# Verify binaries
./target/release/miner --version
./target/release/miner-cli --version
```

---

## Step 3: Generate Miner Identity

Each miner has a unique Ed25519 keypair for P2P communication.

```bash
# Generate keypair
cargo run --release --bin generate_keypair -- --output data/miner

# This creates: data/miner/keypair.bin
# BACKUP THIS FILE - it's your miner identity!
```

**Get your Node ID:**

```bash
cargo run --release --bin miner-cli -- show-node-id --miner-data-dir data/miner
```

**Output:**

```text
Miner Node ID: a1b2c3d4e5f6789012345678901234567890123456789012345678901234abcd
```

**Save this Node ID - you'll need it for registration!**

---

## Step 4: On-Chain Registration

Use the `miner-cli` to register your miner with the Arion pallet.

### Step 4.1: Prepare Your Accounts

Make sure you have:
- **Family Account** seed phrase or private key
- **Child Account** public address (this receives rewards)
- Sufficient balance for the deposit (check with network operator)

### Step 4.2: Register via miner-cli

```bash
cargo run --release --bin miner-cli -- register \
    --miner-data-dir data/miner \
    --ws-url wss://rpc.hippius.network \
    --family-seed "your family account seed phrase here" \
    --child-address "5ChildAccountPublicAddressHere..."
```

**Expected Output:**

```text
Miner registered successfully!
   Family: 5FamilyAccountAddress...
   Child: 5ChildAccountAddress...
   Node ID: a1b2c3d4e5f6789012345678901234567890123456789012345678901234abcd
   Transaction hash: 0x123abc...
```

### Step 4.3: Verify Registration

```bash
cargo run --release --bin miner-cli -- status \
    --ws-url wss://rpc.hippius.network \
    --miner-data-dir data/miner
```

**Output:**

```text
Miner Status:
  Node ID: a1b2c3d4e5f6789012345678901234567890123456789012345678901234abcd
  Family: 5FamilyAccountAddress...
  Child: 5ChildAccountAddress...
  Status: Active
  Storage: 0 GB / 1000 GB
  Reputation: 100
```

---

## Step 5: Run Miner

### Step 5.1: Configure

Set the required environment variables:

```bash
export VALIDATOR_NODE_ID="185651f2fb19c919d40c3c58660cf463ebe7ded1c1a326eef4dad28292171cdb"
export IROH_RELAY_URL="https://relay.hippius.com"
export HOSTNAME="<your-public-ipv4>"  # MUST be your public IP, e.g. 203.0.113.10
export RUST_LOG="info"
```

### Step 5.2: Start the Miner

```bash
cargo run --release --bin miner -- \
    --validator-node-id "$VALIDATOR_NODE_ID" \
    --hostname "$HOSTNAME"
```

**Expected Output:**

```text
INFO miner: Starting Hippius Miner
INFO miner: Node ID: a1b2c3d4e5f6789012345678901234567890123456789012345678901234abcd
INFO miner: Connected to relay: https://relay.hippius.com
INFO miner: Registered with validator via P2P
```

### Step 5.3: Keep Running (systemd recommended)

```bash
sudo nano /etc/systemd/system/hippius-miner.service
```

```ini
[Unit]
Description=Hippius Arion Miner
After=network.target

[Service]
Type=simple
User=youruser
WorkingDirectory=/home/youruser/hippius-arion/miner
Environment="VALIDATOR_NODE_ID=185651f2fb19c919d40c3c58660cf463ebe7ded1c1a326eef4dad28292171cdb"
Environment="IROH_RELAY_URL=https://relay.hippius.com"
Environment="HOSTNAME=<your-public-ipv4>"
Environment="RUST_LOG=info"
ExecStart=/home/youruser/hippius-arion/target/release/miner \
    --validator-node-id 185651f2fb19c919d40c3c58660cf463ebe7ded1c1a326eef4dad28292171cdb \
    --hostname <your-public-ipv4>
Restart=always
RestartSec=10

[Install]
WantedBy=multi-user.target
```

```bash
sudo systemctl daemon-reload
sudo systemctl enable hippius-miner
sudo systemctl start hippius-miner
sudo systemctl status hippius-miner
```

---

## Troubleshooting

### Issue: "Connection refused" to validator

**Symptoms:**
```text
ERROR: Failed to connect to validator: Connection refused
```

**Solution:**
- Verify the validator is reachable via P2P (check `VALIDATOR_NODE_ID` is correct)
- Check firewall rules

### Issue: "Invalid node ID"

**Symptoms:**
```text
ERROR: Validator rejected connection: Invalid node ID
```

**Solution:**
- Ensure you've registered on-chain via `miner-cli register`
- Verify registration: `miner-cli status`
- Check that you're using the correct `data/miner/keypair.bin`

### Issue: "Failed to join iroh network"

**Symptoms:**
```text
WARN: Cannot reach relay server
```

**Solution:**
- Check internet connectivity
- Verify `IROH_RELAY_URL` is accessible: `curl https://relay.hippius.com`
- Try alternative relay servers

### Issue: Miner registered but not receiving shards

**Symptoms:**
- Miner connects to validator, heartbeats succeed
- No `Store` commands received
- Validator logs show `mixed` or `relay` connection type for this miner

**Solution:**
- The miner must have a **direct** P2P connection (not mixed/relay) to receive shards
- **Verify `--hostname` is your public IP**, not `0.0.0.0`, `localhost`, or a private/Docker IP
- Verify **UDP port 11220** is open inbound in your firewall and hosting provider
- If running in Docker: stop and run directly on the host instead
- If Docker is installed on the host: set `P2P_BIND_IPV4` to your public IP
- Test port connectivity: `echo test | nc -u -w2 <your-public-ip> 11220`

### Issue: Low reputation score

**Symptoms:**
- Reputation dropping over time
- Not receiving shard assignments

**Solution:**
- Ensure miner has stable uptime
- Check disk space: `df -h`
- Verify network connectivity
- Monitor logs for failed shard retrievals

---

## Advanced Configuration

### Custom Storage Location

```bash
export MINER_DATA_DIR="/mnt/storage/miner"
cargo run --release --bin miner -- \
    --data-dir "$MINER_DATA_DIR" \
    --validator-node-id "$VALIDATOR_NODE_ID" \
    --hostname "$HOSTNAME"
```

### Adjust Storage Capacity

Edit your miner configuration to advertise a specific capacity:

```bash
cargo run --release --bin miner -- \
    --validator-node-id "$VALIDATOR_NODE_ID" \
    --hostname "$HOSTNAME" \
    --max-storage-gb 500
```

### Multiple Miners on Same Machine

Run multiple miners with unique data directories and P2P ports:

```bash
# Miner 1 (default P2P port 11220)
STORAGE_PATH=data/miner1/blobs P2P_PORT=11220 cargo run --release --bin miner -- \
    --validator-node-id "$VALIDATOR_NODE_ID" --hostname "$HOSTNAME" --family-id family_1

# Miner 2 (different P2P port)
STORAGE_PATH=data/miner2/blobs P2P_PORT=11221 cargo run --release --bin miner -- \
    --validator-node-id "$VALIDATOR_NODE_ID" --hostname "$HOSTNAME" --family-id family_2
```

Each miner needs its own keypair and on-chain registration.

### Monitoring and Metrics

Check miner status:

```bash
# Via miner-cli
cargo run --release --bin miner-cli -- stats --miner-data-dir data/miner
```

---

## Support

For issues or questions:
- GitHub Issues: https://github.com/your-org/hippius-arion/issues
- Discord: https://discord.gg/your-server
- Docs: https://docs.hippius.network

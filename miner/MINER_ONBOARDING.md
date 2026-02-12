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
- **Gateway**: HTTP ingress for uploads/downloads (Kubernetes)
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
- **Network**: Stable internet connection, public IP preferred

### Required Information

You'll need these details from the network operator:

- **VALIDATOR_NODE_ID**: `e921faeb79ee0567ea531176d61f14e1129a9e8094395f1e61ba47ba6888f4bf`
- **DOC_TICKET**: `docaaatddw2ojzkbk2teh2gu27ib53ftutc5mnewp2ev43g6qhck6xxhjib5eq7v23z5ycwp2stcf3nmhyu4ejjvhuasq4v6htbxjd3u2ei6s7qeabpnb2hi4dthixs6zlvmmys2mjoojswyylzfzxdaltjojxwqlldmfxgc4tzfzuxe33ifzwgs3tlfyxqcaakflvcvvcx`
- **CHAIN_WS_URL**: Substrate blockchain WebSocket endpoint (e.g., `ws://127.0.0.1:9944`)
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
# ⚠️ BACKUP THIS FILE - it's your miner identity!
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
    --ws-url ws://127.0.0.1:9944 \
    --family-seed "your family account seed phrase here" \
    --child-address "5ChildAccountPublicAddressHere..." \
    --doc-ticket docaaatddw2ojzkbk2teh2gu27ib53ftutc5mnewp2ev43g6qhck6xxhjib5eq7v23z5ycwp2stcf3nmhyu4ejjvhuasq4v6htbxjd3u2ei6s7qeabpnb2hi4dthixs6zlvmmys2mjoojswyylzfzxdaltjojxwqlldmfxgc4tzfzuxe33ifzwgs3tlfyxqcaakflvcvvcx
```

**Expected Output:**

```text
✅ Miner registered successfully!
   Family: 5FamilyAccountAddress...
   Child: 5ChildAccountAddress...
   Node ID: a1b2c3d4e5f6789012345678901234567890123456789012345678901234abcd
   Transaction hash: 0x123abc...
```

### Step 4.3: Verify Registration

```bash
cargo run --release --bin miner-cli -- status \
    --ws-url ws://127.0.0.1:9944 \
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

### Step 5.1: Update run-miner.sh Script

The `miner/run-miner.sh` script is pre-configured to connect to the K8s validator. Update it if needed:

```bash
cd miner
nano run-miner.sh
```

**Make sure these values are correct:**

```bash
export VALIDATOR_NODE_ID="e921faeb79ee0567ea531176d61f14e1129a9e8094395f1e61ba47ba6888f4bf"
export IROH_RELAY_URL="https://relay.hippius.com"
export ARION_API_KEY="Arion"
```

### Step 5.2: Start the Miner

```bash
cd miner
chmod +x run-miner.sh
./run-miner.sh
```

**Expected Output:**

```text
🚀 Starting miner...
   Validator URL: https://192.168.1.199:30202
   Validator Node ID: e921faeb79ee056...
   Miner Hostname: 192.168.1.100
   Port: 3001

Compiling miner...
    Finished release [optimized] target(s) in 2.34s
     Running `target/release/miner --validator-node-id e921faeb... --port 3001 --hostname 192.168.1.100`
2026-01-28T10:00:00Z INFO miner: Starting Hippius Miner
2026-01-28T10:00:00Z INFO miner: Node ID: a1b2c3d4e5f6789012345678901234567890123456789012345678901234abcd
2026-01-28T10:00:01Z INFO miner: Connected to relay: https://relay.hippius.com
2026-01-28T10:00:02Z INFO miner: Registered with validator: e921faeb79ee0567...
2026-01-28T10:00:02Z INFO miner: Listening on 0.0.0.0:3001
2026-01-28T10:00:02Z INFO miner: ✅ Miner ready to accept shards
```

### Step 5.3: Keep Running

To run the miner in the background:

```bash
# Using screen
screen -S miner
./run-miner.sh
# Press Ctrl+A, then D to detach

# Reattach later with:
screen -r miner
```

Or use **systemd** (recommended for production):

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
Environment="VALIDATOR_NODE_ID=e921faeb79ee0567ea531176d61f14e1129a9e8094395f1e61ba47ba6888f4bf"
Environment="IROH_RELAY_URL=https://relay.hippius.com"
Environment="ARION_API_KEY=Arion"
Environment="RUST_LOG=info"
ExecStart=/home/youruser/hippius-arion/target/release/miner --validator-node-id e921faeb79ee0567ea531176d61f14e1129a9e8094395f1e61ba47ba6888f4bf --port 3001
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
    --validator-node-id "$VALIDATOR_NODE_ID"
```

### Adjust Storage Capacity

Edit your miner configuration to advertise a specific capacity:

```bash
cargo run --release --bin miner -- \
    --validator-node-id "$VALIDATOR_NODE_ID" \
    --max-storage-gb 500
```

### Multiple Miners on Same Machine

Run multiple miners on different ports:

```bash
# Miner 1
MINER_DATA_DIR=data/miner1 PORT=3001 ./run-miner.sh

# Miner 2
MINER_DATA_DIR=data/miner2 PORT=3002 ./run-miner.sh
```

Each miner needs its own keypair and on-chain registration.

### Monitoring and Metrics

Check miner status:

```bash
# Via HTTP API
curl http://localhost:3001/metrics

# Via miner-cli
cargo run --release --bin miner-cli -- stats --miner-data-dir data/miner
```

---

## Support

For issues or questions:
- GitHub Issues: https://github.com/your-org/hippius-arion/issues
- Discord: https://discord.gg/your-server
- Docs: https://docs.hippius.network

**Happy Mining! 🚀**
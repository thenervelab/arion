#!/bin/bash
# Miner startup script - connects to K8s validator

# K8s Validator Node ID (for P2P data transfer)
export VALIDATOR_NODE_ID="e921faeb79ee0567ea531176d61f14e1129a9e8094395f1e61ba47ba6888f4bf"

# Miner configuration
export PORT="${PORT:-3001}"
export RUST_LOG="${RUST_LOG:-info}"

# Optional: Set your miner's hostname (use your actual IP or hostname)
export MINER_HOSTNAME="${MINER_HOSTNAME:-$(hostname -I | awk '{print $1}')}"

# Optional: Family ID (if you're using families)
export FAMILY_ID="${FAMILY_ID:-default}"

# API Key (should match validator's ARION_API_KEY)
export ARION_API_KEY="${ARION_API_KEY:-Arion}"

# Relay URL (same as validator and gateway)
export IROH_RELAY_URL="${IROH_RELAY_URL:-https://relay.hippius.com}"

echo "🚀 Starting miner..."
echo "   Validator Node ID: ${VALIDATOR_NODE_ID:0:16}..."
echo "   Miner Hostname: $MINER_HOSTNAME"
echo "   Port: $PORT"

# Run miner
cd "$(dirname "$0")"
cargo run --release --bin miner -- \
    --validator-node-id "$VALIDATOR_NODE_ID" \
    --port "$PORT" \
    --hostname "$MINER_HOSTNAME"
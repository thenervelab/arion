#!/bin/bash
# Script to start 30 miners with unique configurations

set -e

# Colors
GREEN='\033[0;32m'
RED='\033[0;31m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

echo -e "${BLUE}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
echo -e "${BLUE}  Starting 30 Miners for Arion Testing${NC}"
echo -e "${BLUE}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
echo ""

# Get script directory and project root
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"

echo "DEBUG: Script dir: $SCRIPT_DIR"
echo "DEBUG: Project root: $PROJECT_ROOT"

# Get validator node ID
VALIDATOR_NODE_ID=$(cat "$PROJECT_ROOT/validator/data/validator/node_id.txt" 2>/dev/null)

if [ -z "$VALIDATOR_NODE_ID" ]; then
    echo -e "${RED}✗ Error: Validator node ID not found!${NC}"
    echo -e "${YELLOW}  Please start the validator first:${NC}"
    echo -e "  cd $PROJECT_ROOT/validator && ./run-validator.sh"
    exit 1
fi

echo -e "${GREEN}✓ Validator node ID:${NC} ${VALIDATOR_NODE_ID:0:32}..."
echo ""

# Check if validator is running
if ! curl -s --max-time 2 http://localhost:3002/health > /dev/null 2>&1; then
    echo -e "${RED}✗ Validator is not responding!${NC}"
    echo -e "${YELLOW}  Please start the validator first${NC}"
    exit 1
fi

echo -e "${GREEN}✓ Validator is running${NC}"
echo ""

# Create data directory for miners in miner/ folder
mkdir -p "$SCRIPT_DIR/data/miners"

# Base port for miners (using a range that's less likely to conflict)
BASE_PORT=12000

echo -e "${YELLOW}Starting 30 miners...${NC}"
echo ""

# Start each miner
for i in $(seq 1 30); do
    MINER_PORT=$((BASE_PORT + i))
    # Assign unique P2P port for each miner to avoid conflicts (11221 + i)
    MINER_P2P_PORT=$((11221 + i))
    MINER_DIR="$SCRIPT_DIR/data/miners/miner-$i"
    FAMILY_ID="family-$((i % 5))"
    
    # Create miner data directory
    mkdir -p "$MINER_DIR"
    
    # Create miner.toml with ABSOLUTE path to avoid nested data folders
    # The miner will create: $MINER_DIR/blobs/data/... (iroh-blobs internal structure)
    #                   and: $MINER_DIR/keypair.bin
    cat > "$MINER_DIR/miner.toml" <<EOF
[network]
port = $MINER_PORT
p2p_port = $MINER_P2P_PORT
family_id = "$FAMILY_ID"
hostname = "localhost"

[storage]
max_storage_gb = 100
data_dir = "$MINER_DIR"

[validator]

[tuning]
EOF
    
    # Start miner from its own directory so it loads its miner.toml
    # Using absolute data_dir prevents recursive data/ nesting
    (
        cd "$MINER_DIR"
        PORT="$MINER_PORT" \
        P2P_PORT="$MINER_P2P_PORT" \
        HOSTNAME="localhost" \
        FAMILY_ID="$FAMILY_ID" \
        VALIDATOR_NODE_ID="$VALIDATOR_NODE_ID" \
            cargo run --release --manifest-path "$PROJECT_ROOT/miner/Cargo.toml" --bin miner \
            > miner.log 2>&1 &
        MINER_PID=$!
        echo "$MINER_PID" > miner.pid
    ) &
    
    echo -e "  ${GREEN}✓ Miner $i${NC} started (Port: $MINER_PORT, P2P Port: $MINER_P2P_PORT, Family: $FAMILY_ID)"
    
    # Small delay to avoid overwhelming the system
    sleep 0.1
done

# Wait for all background processes
wait

echo ""
echo -e "${GREEN}✅ All 30 miners started!${NC}"
echo ""
echo -e "${BLUE}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
echo -e "${BLUE}  Next Steps${NC}"
echo -e "${BLUE}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
echo ""
echo -e "  1. Wait ~30 seconds for miners to register with validator"
echo -e "  2. Check miner status: ${YELLOW}cd $PROJECT_ROOT && ./check-miners.sh${NC}"
echo -e "  3. Run upload/download test: ${YELLOW}cd $PROJECT_ROOT && ./test-30-miners.sh${NC}"
echo -e "  4. Stop all miners: ${YELLOW}cd $PROJECT_ROOT && ./stop-miners.sh${NC}"
echo ""
echo -e "${YELLOW}Logs are in:${NC} $SCRIPT_DIR/data/miners/miner-*/miner.log"
echo ""

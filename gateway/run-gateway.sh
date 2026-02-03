#!/bin/bash
# Gateway startup script with required environment variables

# Set API keys and validator URL
export VALIDATOR_URL="http://localhost:3002"
export PORT="3000"
export API_KEY_ADMIN="local-admin-secret-key-change-me"
export VALIDATOR_GATEWAY_KEY="local-gateway-secret-key-change-me"

# Run gateway
cd "$(dirname "$0")"
cargo run --release


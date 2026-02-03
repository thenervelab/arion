# miner-cli

Command-line tool for on-chain miner registration with `pallet-arion`.

## Overview

This tool manages the lifecycle of miner registration on the Hippius blockchain. Miners must be registered on-chain to participate in the storage network and receive rewards when `CHAIN_REGISTRY_ENABLED=true` is set on the validator.

### Registration Model

The pallet uses a family/child hierarchy:

```
Family Account (signs transactions, holds deposit)
    └── Child Account (receives rewards)
            └── NodeId (miner P2P identity - Ed25519 pubkey)
```

- **Family**: Parent account that registers and manages miners. Signs all on-chain transactions.
- **Child**: Delegate account that receives rewards for a specific miner.
- **NodeId**: Ed25519 public key (Iroh identity) linking the P2P node to the on-chain registration.

## Quick Start

```bash
# Build
cargo build -p miner-cli --release

# Copy and configure environment file
cp miner-cli.example.env .env
# Edit .env with your values

# Run with environment file
cargo run --bin miner-cli -- <command>

# Or run with explicit arguments
cargo run --bin miner-cli -- --chain-ws-url ws://127.0.0.1:9944 <command>
```

## Commands

### show-node-id

Display the miner's Iroh node ID (Ed25519 public key) from its keypair file:

```bash
miner-cli show-node-id --miner-data-dir data/miner
```

Output:
```
node_id (iroh string): <base32-encoded-node-id>
node_id (hex32): 0x<64-character-hex>
```

### register-child

Register a miner's node ID on-chain under a family account. The command performs several pre-registration checks:

- Verifies child account is not already registered
- Verifies node ID is not already mapped to another child
- Checks for child account cooldown period
- Checks for node ID cooldown period

```bash
# Using mnemonic file (recommended for security)
miner-cli --chain-ws-url ws://127.0.0.1:9944 \
  --family-mnemonic-file /secure/mnemonic.txt \
  register-child \
  --child-ss58 "5ChildAccountAddress..." \
  --miner-data-dir data/miner

# Using mnemonic directly (avoid in production - exposes to shell history)
miner-cli --chain-ws-url ws://127.0.0.1:9944 \
  --family-mnemonic "your twelve or twenty-four word mnemonic phrase" \
  register-child \
  --child-ss58 "5ChildAccountAddress..." \
  --miner-data-dir data/miner
```

### deregister-child

Remove a miner from the on-chain registry. This begins an unbonding process with a cooldown period before the deposit can be reclaimed:

```bash
miner-cli --chain-ws-url ws://127.0.0.1:9944 \
  --family-mnemonic-file /secure/mnemonic.txt \
  deregister-child \
  --child-ss58 "5ChildAccountAddress..."
```

### claim-unbonded

Reclaim the bonded deposit after the cooldown period expires following deregistration:

```bash
miner-cli --chain-ws-url ws://127.0.0.1:9944 \
  --family-mnemonic-file /secure/mnemonic.txt \
  claim-unbonded \
  --child-ss58 "5ChildAccountAddress..."
```

## Configuration

### Global Arguments

| Argument | Environment Variable | Required | Description |
|----------|---------------------|----------|-------------|
| `--chain-ws-url` | `CHAIN_WS_URL` | Yes | Substrate WebSocket endpoint (e.g., `ws://127.0.0.1:9944`) |
| `--family-mnemonic` | `FAMILY_MNEMONIC` | Yes* | BIP39 mnemonic phrase for family account |
| `--family-mnemonic-file` | `FAMILY_MNEMONIC_FILE` | Yes* | Path to file containing the mnemonic (more secure) |
| `--arion-pallet-name` | `ARION_PALLET_NAME` | No | Override pallet name if auto-detection fails (default: auto-detect) |

*One of `--family-mnemonic` or `--family-mnemonic-file` is required.

### Command Arguments

| Command | Argument | Environment Variable | Default | Description |
|---------|----------|---------------------|---------|-------------|
| `show-node-id` | `--miner-data-dir` | `MINER_DATA_DIR` | `data/miner` | Directory containing `keypair.bin` |
| `register-child` | `--child-ss58` | `CHILD_SS58` | - | Child account SS58 address |
| `register-child` | `--miner-data-dir` | `MINER_DATA_DIR` | `data/miner` | Directory containing `keypair.bin` |
| `deregister-child` | `--child-ss58` | `CHILD_SS58` | - | Child account SS58 address |
| `claim-unbonded` | `--child-ss58` | `CHILD_SS58` | - | Child account SS58 address |

### Example Environment File

See `miner-cli.example.env`:

```bash
# Chain websocket endpoint
CHAIN_WS_URL=wss://your-node:9944

# Optional: pallet name if auto-detect fails
ARION_PALLET_NAME=

# Family account mnemonic (sr25519) - use FAMILY_MNEMONIC_FILE in production
FAMILY_MNEMONIC="your twelve word mnemonic phrase here"

# Child account SS58 (delegate that receives rewards)
CHILD_SS58="5YourChildAccountAddress..."

# Miner node data dir containing keypair.bin (ed25519)
MINER_DATA_DIR=data/miner
```

## Security Considerations

1. **Use `--family-mnemonic-file` in production**: The family mnemonic controls registration and deposits. Using `--family-mnemonic` directly exposes it to shell history.

2. **Set restrictive file permissions**: The mnemonic file should have mode 600 (owner read/write only):
   ```bash
   chmod 600 /secure/mnemonic.txt
   ```
   The CLI will warn if permissions are too permissive.

3. **Protect `keypair.bin`**: The miner's Ed25519 keypair should also have restricted permissions:
   ```bash
   chmod 600 data/miner/keypair.bin
   ```

## Registration Flow

1. **Generate miner keypair** (if not already done):
   ```bash
   cargo run --bin generate_keypair -- --output data/miner/keypair.bin
   ```

2. **Get the node ID**:
   ```bash
   miner-cli show-node-id --miner-data-dir data/miner
   ```

3. **Register on-chain**:
   ```bash
   miner-cli --chain-ws-url ws://127.0.0.1:9944 \
     --family-mnemonic-file /secure/mnemonic.txt \
     register-child \
     --child-ss58 "5ChildAccountAddress..." \
     --miner-data-dir data/miner
   ```

4. **Verify registration** on Polkadot.js Apps:
   - Chain State > arion > childRegistrations(`<child-ss58>`)

5. **Start miner** with chain registry enabled on the validator:
   ```bash
   CHAIN_REGISTRY_ENABLED=true cargo run --bin validator -- ...
   ```

## Troubleshooting

### Common Registration Errors

| Error | Cause | Solution |
|-------|-------|----------|
| Child account is already registered | The child SS58 is already linked to a miner | Deregister the existing registration first |
| Node ID is already mapped | This keypair is registered to another child | Use a different keypair or deregister the old child |
| Child/Node ID is in cooldown | Recently deregistered | Wait for the cooldown period to expire |
| Insufficient balance | Family account lacks funds | Top up family account for deposit + fees |
| Transaction timed out | Network congestion or node issues | Retry; check chain connection |

### Verifying On-Chain State

Use Polkadot.js Apps (or similar) to query:

- `arion.childRegistrations(<child-ss58>)` - Check if child is registered
- `arion.nodeIdToChild(<node-id-hex>)` - Check node ID mapping
- `arion.childCooldownUntil(<child-ss58>)` - Check cooldown block number
- `arion.nodeIdCooldownUntil(<node-id-hex>)` - Check node ID cooldown

## Dependencies

- **subxt**: Substrate client for chain interaction
- **subxt-signer**: Sr25519 signing for transactions
- **bip39**: Mnemonic phrase parsing
- **iroh-base**: Ed25519 key handling for miner identity
- **clap**: CLI argument parsing with environment variable support

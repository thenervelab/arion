FROM rust:1.80-slim-bookworm as builder

WORKDIR /app

# Install build dependencies
RUN apt-get update && apt-get install -y \
    pkg-config \
    libssl-dev \
    build-essential \
    git \
    clang \
    && rm -rf /var/lib/apt/lists/*

# Pre-install iroh-relay since it's an external tool needed in docker-compose
RUN cargo install iroh-relay

# Build the workspace
# Copy manifests first for caching (optional but good practice)
COPY Cargo.toml Cargo.lock ./
COPY common ./common
COPY gateway ./gateway
COPY miner ./miner
COPY validator ./validator
COPY listener ./listener
COPY scripts ./scripts
# Copy any other crates if they exist (e.g. temp_key_test, but maybe not needed for release)

# Build all binaries in the workspace
RUN cargo build --release --workspace

# Runtime Stage
FROM debian:bookworm-slim

WORKDIR /app

# Install runtime dependencies
RUN apt-get update && apt-get install -y \
    ca-certificates \
    libssl3 \
    openssl \
    curl \
    && rm -rf /var/lib/apt/lists/*

# Copy binaries from builder
COPY --from=builder /app/target/release/validator /usr/local/bin/
COPY --from=builder /app/target/release/gateway /usr/local/bin/
COPY --from=builder /app/target/release/miner /usr/local/bin/
COPY --from=builder /app/target/release/listener /usr/local/bin/
# Copy iroh-relay
COPY --from=builder /usr/local/cargo/bin/iroh-relay /usr/local/bin/

# Copy scripts just in case
COPY --from=builder /app/scripts /app/scripts

# Create data directories
RUN mkdir -p /app/data

# Default command (overridden by docker-compose)
CMD ["/bin/bash"]

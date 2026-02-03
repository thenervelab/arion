# ---------- Builder stage ----------
FROM rust:1.90-slim-bookworm AS builder

WORKDIR /build

# Install build dependencies
RUN apt-get update && apt-get install -y \
    pkg-config \
    libssl-dev \
    perl \
    make \
    && rm -rf /var/lib/apt/lists/*

# Copy workspace files
COPY Cargo.toml Cargo.lock ./
COPY common ./common
COPY pos-circuits ./pos-circuits
COPY chain-submitter ./chain-submitter

# Create dummy crates for unused workspace members (must have UNIQUE names)
RUN for c in miner gateway validator admin-cli listener miner-cli tools warden proptests; do \
      mkdir -p $c/src && \
      printf '[package]\nname = "%s-dummy"\nversion = "0.1.0"\nedition = "2021"\n' "$c" > $c/Cargo.toml && \
      echo 'fn main() {}' > $c/src/main.rs ; \
    done

# Build only the chain-submitter binary
RUN cargo build --release -p chain-submitter


# ---------- Runtime stage ----------
FROM debian:bookworm-slim

# Install runtime dependencies
RUN apt-get update && apt-get install -y \
    ca-certificates \
    libssl3 \
    && rm -rf /var/lib/apt/lists/*

# Copy the compiled binary
COPY --from=builder /build/target/release/chain-submitter /usr/local/bin/chain-submitter

# Create non-root user
RUN useradd -m -u 1000 chain-submitter
USER chain-submitter

WORKDIR /home/chain-submitter

EXPOSE 3004

ENTRYPOINT ["chain-submitter"]

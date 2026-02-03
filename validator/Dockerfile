FROM rust:1.90-slim-bookworm AS builder

WORKDIR /build

# Install comprehensive build dependencies
RUN apt-get update && apt-get install -y \
    pkg-config \
    libssl-dev \
    perl \
    make \
    gcc \
    g++ \
    && rm -rf /var/lib/apt/lists/*

# Copy workspace
COPY . .

# Build validator
RUN cargo build --release --bin validator

# Runtime image
FROM debian:bookworm-slim

RUN apt-get update && apt-get install -y \
    ca-certificates \
    libssl3 \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

# Copy binary
COPY --from=builder /build/target/release/validator /app/validator

# Create data directory
RUN mkdir -p /data/validator

EXPOSE 3002 11204/udp

ENTRYPOINT ["/app/validator"]
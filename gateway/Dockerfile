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

# Build gateway
RUN cargo build --release --bin gateway

# Runtime image
FROM debian:bookworm-slim

RUN apt-get update && apt-get install -y \
    ca-certificates \
    libssl3 \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

# Copy binary
COPY --from=builder /build/target/release/gateway /app/gateway

# Create data directory
RUN mkdir -p /data/gateway

EXPOSE 3000 11205/udp

ENTRYPOINT ["/app/gateway"]
# Stage 1: Planner - Extract dependency recipe
FROM lukemathwalker/cargo-chef:latest-rust-1 AS planner

WORKDIR /app
COPY Cargo.toml Cargo.lock ./
COPY crates ./crates
COPY ironpost-cli ./ironpost-cli
COPY ironpost-daemon ./ironpost-daemon
COPY xtask ./xtask

# Generate recipe.json with dependency metadata
RUN cargo chef prepare --recipe-path recipe.json

# Stage 2: Cacher - Build dependencies only (cached layer)
FROM lukemathwalker/cargo-chef:latest-rust-1 AS cacher

WORKDIR /app
COPY --from=planner /app/recipe.json recipe.json

# Build dependencies only - this layer is cached unless dependencies change
# workspace 전체 빌드 (eBPF 유저스페이스 라이브러리 포함)
# 참고: eBPF 커널 프로그램(crates/ebpf-engine/ebpf)은 workspace exclude로 자동 제외됨
RUN cargo chef cook --release --recipe-path recipe.json

# Stage 3: Builder - Build application with source code
FROM rust:1-bookworm AS builder

WORKDIR /app

# Copy dependency artifacts from cacher stage
COPY --from=cacher /app/target target
COPY --from=cacher /usr/local/cargo /usr/local/cargo

# Copy source code
COPY Cargo.toml Cargo.lock ./
COPY crates ./crates
COPY ironpost-cli ./ironpost-cli
COPY ironpost-daemon ./ironpost-daemon
COPY xtask ./xtask

# Build only the application code (dependencies already compiled)
RUN cargo build --release

# Stage 4: Runtime - Minimal production image
FROM debian:bookworm-slim AS runtime

# Metadata labels following OCI image spec
LABEL maintainer="Ironpost Project <noreply@example.com>" \
      version="0.1.0" \
      description="Ironpost - Integrated Security Monitoring Platform" \
      org.opencontainers.image.title="Ironpost" \
      org.opencontainers.image.description="eBPF-based network detection, log analysis, container isolation, and SBOM vulnerability scanning" \
      org.opencontainers.image.version="0.1.0" \
      org.opencontainers.image.vendor="Ironpost Project" \
      org.opencontainers.image.licenses="MIT" \
      org.opencontainers.image.source="https://github.com/dongwonkwak/ironpost"

# Install runtime dependencies only
RUN apt-get update && apt-get install -y \
    ca-certificates \
    libssl3 \
    && rm -rf /var/lib/apt/lists/*

# Create non-root user with minimal privileges
RUN useradd --create-home --shell /bin/bash ironpost

# Copy binaries from builder stage
COPY --from=builder /app/target/release/ironpost-daemon /usr/local/bin/
COPY --from=builder /app/target/release/ironpost-cli /usr/local/bin/

# Create necessary directories with proper ownership
RUN mkdir -p /var/lib/ironpost /var/log/ironpost /var/run/ironpost \
    && chown -R ironpost:ironpost /var/lib/ironpost /var/log/ironpost /var/run/ironpost \
    && chmod 755 /usr/local/bin/ironpost-daemon /usr/local/bin/ironpost-cli

# Switch to non-root user
USER ironpost

# Expose ports (UDP syslog on unprivileged port 1514, HTTP API on 8080)
# External port 514 is mapped to internal 1514 via docker-compose port mapping
EXPOSE 1514/udp 8080

# Health check using CLI status command
# Check if daemon process is running and responding
HEALTHCHECK --interval=30s --timeout=10s --start-period=5s --retries=3 \
    CMD ironpost-cli --config /etc/ironpost/ironpost.toml status --output json > /dev/null || exit 1

# Set entrypoint and default command
ENTRYPOINT ["ironpost-daemon"]
CMD ["--config", "/etc/ironpost/ironpost.toml"]

# Stage 1: Builder
FROM rust:latest AS builder

WORKDIR /app
COPY . .

# workspace 전체 빌드 (eBPF 유저스페이스 라이브러리 포함)
# 참고: eBPF 커널 프로그램(crates/ebpf-engine/ebpf)은 workspace exclude로 자동 제외됨
RUN cargo build --release

# Stage 2: Runner
FROM debian:bookworm-slim AS runner

RUN apt-get update && apt-get install -y \
    ca-certificates \
    libssl3 \
    && rm -rf /var/lib/apt/lists/*

RUN useradd --create-home --shell /bin/bash ironpost

COPY --from=builder /app/target/release/ironpost-daemon /usr/local/bin/
COPY --from=builder /app/target/release/ironpost-cli /usr/local/bin/
COPY --from=builder /app/ironpost.toml /etc/ironpost/ironpost.toml

RUN mkdir -p /var/lib/ironpost /var/log/ironpost \
    && chown -R ironpost:ironpost /var/lib/ironpost /var/log/ironpost

USER ironpost
EXPOSE 514/udp 8080

ENTRYPOINT ["ironpost-daemon"]
CMD ["--config", "/etc/ironpost/ironpost.toml"]

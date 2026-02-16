# Phase 9 Review - Collector Spawn (Re-review v2)

- Date: 2026-02-16
- Scope: `git diff main`
- Reviewed files:
  - `crates/core/src/config.rs`
  - `crates/log-pipeline/Cargo.toml`
  - `crates/log-pipeline/src/collector/event_receiver.rs`
  - `crates/log-pipeline/src/collector/file.rs`
  - `crates/log-pipeline/src/collector/mod.rs`
  - `crates/log-pipeline/src/collector/syslog_tcp.rs`
  - `crates/log-pipeline/src/collector/syslog_udp.rs`
  - `crates/log-pipeline/src/config.rs`
  - `crates/log-pipeline/src/pipeline.rs`

## Build Verification
- `cargo test --workspace`: PASS
- `cargo clippy --workspace -- -D warnings`: PASS
- `cargo doc --workspace --no-deps`: PASS

## Findings

### Critical
- 없음

### High
- 없음

### Medium

1. 이전 Medium-1: 기본 `"syslog"`가 TCP listener까지 자동 활성화되는 노출면 이슈는 여전히 열려 있습니다. (미해결)
- Evidence: `"syslog"`가 UDP+TCP로 확장됩니다 (`crates/log-pipeline/src/pipeline.rs:319`).
- Evidence: 기본값이 `sources=["syslog","file"]`, `syslog_tcp_bind=0.0.0.0:601`입니다 (`crates/core/src/config.rs:414`, `crates/core/src/config.rs:416`, `crates/log-pipeline/src/config.rs:70`, `crates/log-pipeline/src/config.rs:72`).

2. 이전 Medium-2: collector 상태 관측성 부족 이슈는 해결되었습니다.
- Evidence: collector runtime 상태를 `collector_statuses`로 추적합니다 (`crates/log-pipeline/src/pipeline.rs:87`, `crates/log-pipeline/src/pipeline.rs:110`).
- Evidence: `health_check`가 collector `Error`를 `Unhealthy`, `Stopped`를 `Degraded`로 반영합니다 (`crates/log-pipeline/src/pipeline.rs:654`).
- Evidence: bind 실패 상황이 health에 반영되는 회귀 테스트가 추가되었습니다 (`crates/log-pipeline/src/pipeline.rs:1124`).

3. 이전 Medium-3: 테스트 검증력 이슈는 해결되었습니다.
- Evidence: H1 경합(send blocking + cancel) 회귀 테스트가 추가되었습니다 (`crates/log-pipeline/src/collector/event_receiver.rs:258`).
- Evidence: spawn failure 테스트가 실제 실패 입력(`invalid-bind-address`) + health 반영 검증으로 강화되었습니다 (`crates/log-pipeline/src/pipeline.rs:1124`).
- Evidence: TCP connection handler의 cancellation 종료를 직접 검증하는 테스트가 추가되었습니다 (`crates/log-pipeline/src/collector/syslog_tcp.rs:353`).

### Low
- 없음

## Requested Focus Check

1. H1(packet_rx 재시작) / H2(TCP cleanup)
- H1: **해결됨**. `EventReceiver`의 `tx.send(...)` 경로가 cancellation-aware로 변경되어, shutdown 경쟁 상황에서도 `packet_rx` 복구 가능성이 보장됩니다 (`crates/log-pipeline/src/collector/event_receiver.rs:77`).
- H2: **해결됨**. cancellation token이 accept loop와 connection handler 모두에 전파되며(`crates/log-pipeline/src/collector/syslog_tcp.rs:159`, `crates/log-pipeline/src/collector/syslog_tcp.rs:279`), cancellation 종료 테스트가 추가되었습니다 (`crates/log-pipeline/src/collector/syslog_tcp.rs:353`).

2. 이전 Medium 이슈 3개 상태
- Medium-1(기본 syslog 노출면): 미해결
- Medium-2(관측성 부족): 해결
- Medium-3(테스트 검증력): 해결

3. 새로운 Critical/High 이슈
- Critical: 없음
- High: 없음

4. 빌드/품질 게이트
- `cargo test --workspace`: PASS
- `cargo clippy --workspace -- -D warnings`: PASS
- `cargo doc --workspace --no-deps`: PASS
- 추가 검증
  - `cargo test -p ironpost-log-pipeline packet_rx_survives_restart`: PASS
  - `cargo test -p ironpost-log-pipeline receiver_cancels_while_send_is_blocked_and_returns_packet_rx`: PASS
  - `cargo test -p ironpost-log-pipeline collector_spawn_failure_does_not_prevent_pipeline_start`: PASS
  - `cargo test -p ironpost-log-pipeline tcp_connection_handlers_cleanup_on_stop`: PASS
  - `cargo test -p ironpost-log-pipeline connection_handler_exits_on_cancellation_without_socket_io`: PASS
  - `cargo clippy -p ironpost-log-pipeline -- -D warnings`: PASS

## Severity Summary
- Critical: 0
- High: 0
- Medium: 1
- Low: 0

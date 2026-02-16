# Phase 9 Review - Collector Spawn

- Date: 2026-02-16
- Scope: `git diff main`
- Reviewed files:
  - `crates/core/src/config.rs`
  - `crates/log-pipeline/src/collector/mod.rs`
  - `crates/log-pipeline/src/config.rs`
  - `crates/log-pipeline/src/pipeline.rs`

## Build Verification
- `cargo test --workspace`: PASS
- `cargo clippy --workspace -- -D warnings`: PASS
- `cargo doc --workspace --no-deps`: PASS

## Findings

### High

1. `packet_rx`가 1회 start 이후 영구 소실되어 restart 시 eBPF 수집이 비활성화됨
- Evidence: `self.packet_rx.take()`로 receiver를 start 시 소비 (`crates/log-pipeline/src/pipeline.rs:331`)
- Evidence: stop 시 `raw_log` 채널만 재생성하고 `packet_rx`는 복구하지 않음 (`crates/log-pipeline/src/pipeline.rs:535`)
- Impact: `Pipeline::start -> stop -> start` 이후 `event_receiver`가 다시 spawn되지 않아 eBPF 이벤트 유입이 끊깁니다.
- Why this matters: 코드가 명시적으로 "재시작 지원"을 목표로 하는데, collector lifecycle이 source별로 비대칭이 됩니다.

2. TCP collector의 connection task가 shutdown 경로에 포함되지 않아 누수 가능성
- Evidence: collector 본체는 `self.tasks`로 추적/abort (`crates/log-pipeline/src/pipeline.rs:515`)
- Evidence: TCP 연결별 task는 detached spawn이며 핸들 추적 없음 (`crates/log-pipeline/src/collector/syslog_tcp.rs:144`)
- Impact: stop 이후에도 기존 연결 task가 timeout/연결 종료 전까지 남아 소켓/메모리/스케줄러 리소스를 점유할 수 있습니다.
- Why this matters: 반복 restart 또는 장시간 idle TCP 연결에서 lifecycle 누수가 발생합니다.

### Medium

1. 기본 source `"syslog"`가 TCP listener까지 자동 활성화하여 네트워크 노출면이 확대됨
- Evidence: `"syslog" => syslog_udp + syslog_tcp` 매핑 (`crates/log-pipeline/src/pipeline.rs:300`)
- Evidence: core 기본값이 `sources=["syslog","file"]`, `syslog_tcp_bind=0.0.0.0:601` (`crates/core/src/config.rs:414`)
- Impact: 기존 설정 사용자도 업그레이드 후 TCP 601 포트가 추가로 열릴 수 있습니다.
- Note: 의도된 변경일 수 있으나, 보안/운영 관점에서 명시적 마이그레이션 안내가 필요합니다.

2. fault isolation은 있으나 상태 관측성이 부족함 (실패 collector도 health가 Healthy로 보일 수 있음)
- Evidence: collector 등록 상태는 `Idle`로만 기록되고 runtime error 반영 경로가 없음 (`crates/log-pipeline/src/collector/mod.rs:107`)
- Evidence: health check는 buffer utilization만 평가 (`crates/log-pipeline/src/pipeline.rs:544`)
- Impact: bind 실패/collector 종료 상황을 health/status에서 놓칠 수 있습니다.

3. 핵심 실패 시나리오 테스트가 실질적으로 검증되지 않음
- Evidence: 실패 테스트 명과 달리 `127.0.0.1:0` 사용으로 bind 실패를 유도하지 않음 (`crates/log-pipeline/src/pipeline.rs:981`)
- Evidence: `packet_rx` 포함 restart 회귀 테스트가 없음 (신규 테스트 구간 전반)
- Impact: High-1 회귀가 테스트에서 탐지되지 않았습니다.

### Low

1. CLAUDE.md 금지 항목 위반 없음
- 확인 범위(변경분): `unwrap/println/unsafe/std::sync::Mutex/as/panic/todo/unimplemented`
- 결과: 프로덕션 변경분 위반 없음. 로깅은 `tracing` 매크로 사용.

2. clone/allocation 최적화 여지는 있으나 현재 영향 낮음
- Evidence: start 시 `sources.clone()` (`crates/log-pipeline/src/pipeline.rs:296`)
- Impact: startup 경로의 소규모 allocation으로 실효 영향은 낮음.

## Checklist by Requested Items

1. CLAUDE.md 규칙 준수
- `unwrap(), println!, unsafe, std::sync::Mutex, as, panic!/todo!`: 변경 프로덕션 코드 기준 위반 없음
- tracing 매크로 사용: 준수

2. 코드 품질
- 에러 처리: collector run 에러 로깅은 존재하나 health 반영 부족 (Medium)
- 불필요한 clone/allocation: 경미한 clone 1건 (Low)
- dead code: 신규 dead code는 확인되지 않음

3. 설계 일관성
- source 문자열 매핑: 구현은 일관적이나 기본 동작 변경 리스크 존재 (Medium)
- fault isolation: start 전파 차단은 잘 됨, 관측성/상태 동기화 미흡 (Medium)
- lifecycle(spawn/shutdown): restart packet_rx 소실 및 TCP child task 누수 가능성 (High)

4. 테스트
- 기본 spawn 시나리오는 다수 추가됨
- 실패 유도/재시작(packet_rx)/shutdown 누수 검증은 미흡 (Medium)

5. 빌드
- 3개 명령 모두 PASS

## Severity Summary
- Critical: 0
- High: 2
- Medium: 3
- Low: 2

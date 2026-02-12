# Phase 7: E2E Tests, Docker Demo, CI Enhancement

## 목표
Phase 6에서 미완료된 고도화 태스크(T6-7, T6-8, T6-9)를 Phase 7로 승격하여 완성합니다.
Mock 기반 E2E 시나리오 테스트로 모듈 간 이벤트 흐름을 검증하고,
Docker Compose 원클릭 데모 환경을 구축하며,
GitHub Actions CI를 강화하여 프로젝트 품질 게이트를 자동화합니다.

## 선행 조건
- [x] Phase 0: 프로젝트 스캐폴딩
- [x] Phase 1: Core 크레이트 (64 tests)
- [x] Phase 2: eBPF 엔진 (74 tests)
- [x] Phase 3: 로그 파이프라인 (280 tests)
- [x] Phase 4: 컨테이너 가드 (202 tests)
- [x] Phase 5: SBOM 스캐너 (183 tests)
- [x] Phase 6: 통합 & 폴리시 (1063+ tests, clippy clean)

## 브랜치
- `phase/7-e2e`

## 환경
- 개발: MacBook (macOS) -- 주 개발 환경
- 테스트: Manjaro (SSH) -- Docker/eBPF 실행 환경

---

## 태스크 요약

| ID | 태스크 | Part | 담당 | 예상 | 의존성 | 상태 |
|----|--------|------|------|------|--------|------|
| T7.1 | E2E 테스트 인프라 셋업 | A | architect + tester | 1.5h | 없음 | ⏳ |
| T7.2 | S1: 이벤트 파이프라인 E2E | A | tester | 2h | T7.1 | ⏳ |
| T7.3 | S2: SBOM 스캔 -> AlertEvent E2E | A | tester | 1.5h | T7.1 | ⏳ |
| T7.4 | S3: 설정 로딩 -> 모듈 초기화 E2E | A | tester | 1h | T7.1 | ⏳ |
| T7.5 | S4: Graceful shutdown 순서 검증 | A | tester | 1.5h | T7.1 | ⏳ |
| T7.6 | S5: 잘못된 설정 -> 에러 검증 | A | tester | 1h | T7.1 | ⏳ |
| T7.7 | S6: 모듈 장애 격리 검증 | A | tester | 1.5h | T7.1 | ⏳ |
| T7.8 | Dockerfile 개선 (multi-stage) | B | implementer | 1.5h | 없음 | ⏳ |
| T7.9 | docker-compose.yml 개선 | B | implementer | 1h | T7.8 | ⏳ |
| T7.10 | docker-compose.demo.yml 작성 | B | implementer + writer | 1.5h | T7.9 | ⏳ |
| T7.11 | docs/demo.md 데모 가이드 | B | writer | 1h | T7.10 | ⏳ |
| T7.12 | GitHub Actions CI 강화 | C | implementer | 2h | 없음 | ⏳ |
| T7.13 | dependabot.yml 추가 | C | implementer | 0.5h | 없음 | ⏳ |
| T7.14 | Phase 7 리뷰 | - | reviewer | 2h | T7.1~T7.13 | ⏳ |

**예상 총 소요**: 약 20h (Part A: 10h, Part B: 5h, Part C: 2.5h, 리뷰: 2h)

---

## Part A: E2E Scenario Tests (Mock-based, Docker 불필요)

### T7.1: E2E 테스트 인프라 셋업
- **담당 에이전트**: architect (구조 설계) + tester (구현)
- **예상 소요**: 1.5h
- **의존성**: 없음 (첫 번째 태스크)
- **상태**: [ ]

**설명**:
E2E 테스트를 위한 테스트 인프라를 구축합니다. workspace 루트에 `tests/e2e/` 디렉토리를 생성하거나,
`ironpost-daemon` 크레이트의 통합 테스트로 배치합니다. 공통 테스트 헬퍼(MockPipeline, 채널 팩토리,
설정 빌더, 이벤트 팩토리)를 정의합니다.

**구현 항목**:
- [ ] 테스트 배치 위치 결정: `ironpost-daemon/tests/e2e/` (daemon의 `pub mod`을 직접 참조 가능)
- [ ] `ironpost-daemon/tests/e2e/mod.rs` -- 공통 테스트 헬퍼 모듈
- [ ] `TestOrchestrator` 헬퍼: `Orchestrator::build_from_config()`를 감싸서 테스트용 설정으로 빌드
- [ ] `MockDockerClient` 재사용: `container-guard` 크레이트의 mock Docker API 활용
- [ ] `create_test_config()`: 모든 모듈 비활성화된 기본 설정 + 개별 모듈 활성화 옵션
- [ ] `create_test_log_event()`, `create_test_alert_event()`: 이벤트 팩토리 함수
- [ ] `assert_received_within()`: 채널 수신 + 타임아웃 assertion 헬퍼
- [ ] `tempfile` 기반 설정 파일 생성 헬퍼

**주요 파일**:
- `ironpost-daemon/tests/e2e/mod.rs` -- 공통 헬퍼 (신규)
- `ironpost-daemon/tests/e2e/helpers.rs` -- 팩토리 함수 (신규)
- `ironpost-daemon/Cargo.toml` -- dev-dependencies 추가 (tempfile, tokio-test)

**Acceptance Criteria**:
- 공통 헬퍼 모듈이 컴파일 성공
- `create_test_config()` 로 최소한의 유효한 `IronpostConfig` 생성 가능
- 이벤트 팩토리 함수가 올바른 타입의 이벤트 생성
- `cargo test -p ironpost-daemon` 기존 테스트 regression 없음

---

### T7.2: S1 -- LogEvent 주입 -> RuleEngine 매칭 -> AlertEvent 생성 -> ContainerGuard 격리
- **담당 에이전트**: tester
- **예상 소요**: 2h
- **의존성**: T7.1
- **상태**: [ ]

**설명**:
전체 이벤트 파이프라인의 핵심 흐름을 검증합니다. 로그 이벤트를 log-pipeline에 주입하고,
규칙 매칭을 거쳐 AlertEvent가 생성되며, 이 알림이 container-guard로 전달되어
Mock Docker API를 통해 격리 액션이 실행되는 전체 흐름을 테스트합니다.

**테스트 시나리오**:
- [ ] `test_e2e_log_to_alert_to_isolation`: LogEvent -> RuleEngine match -> AlertEvent -> ContainerGuard isolate (mock)
- [ ] `test_e2e_log_no_match_no_alert`: 규칙에 매칭되지 않는 로그 -> AlertEvent 미생성 확인
- [ ] `test_e2e_alert_below_threshold_no_action`: 심각도 낮은 알림 -> 격리 미실행 확인
- [ ] `test_e2e_multiple_alerts_sequential`: 연속 알림 -> 순서대로 처리 확인
- [ ] `test_e2e_channel_backpressure`: 채널 가득 찼을 때 생산자 블록 확인

**검증 포인트**:
- mpsc 채널을 통한 이벤트 전달 (packet_tx -> log-pipeline -> alert_tx -> container-guard)
- AlertEvent의 trace_id가 원본 LogEvent와 동일
- Mock Docker API의 `stop_container()` 호출 확인
- ActionEvent가 올바르게 생성되어 action_rx로 수신됨

**주요 파일**:
- `ironpost-daemon/tests/e2e/pipeline_flow.rs` (신규)

**Acceptance Criteria**:
- 최소 5개 테스트 시나리오
- 모든 테스트가 Mock 기반 (Docker 불필요)
- 이벤트 trace_id 체인 검증
- `cargo test -p ironpost-daemon --test e2e_pipeline_flow` 통과

---

### T7.3: S2 -- SBOM 스캔 -> 취약점 발견 -> ScanAlert -> AlertEvent 변환
- **담당 에이전트**: tester
- **예상 소요**: 1.5h
- **의존성**: T7.1
- **상태**: [ ]

**설명**:
SBOM 스캐너가 취약점을 발견했을 때 AlertEvent가 올바르게 생성되고
alert_tx 채널로 전달되는 흐름을 검증합니다.

**테스트 시나리오**:
- [ ] `test_e2e_sbom_scan_vuln_found_alert`: 취약한 Cargo.lock -> 스캔 -> AlertEvent 생성
- [ ] `test_e2e_sbom_scan_clean_no_alert`: 취약점 없는 프로젝트 -> AlertEvent 미생성
- [ ] `test_e2e_sbom_scan_multiple_vulns`: 복수 취약점 -> 각각 AlertEvent 생성
- [ ] `test_e2e_sbom_alert_severity_mapping`: VulnDb severity -> AlertEvent severity 매핑 검증

**검증 포인트**:
- SbomScanner가 alert_tx를 통해 AlertEvent 전송
- AlertEvent에 CVE ID, 패키지 정보 포함
- 심각도 매핑 (CRITICAL/HIGH -> AlertEvent severity)

**주요 파일**:
- `ironpost-daemon/tests/e2e/sbom_flow.rs` (신규)

**Acceptance Criteria**:
- 최소 4개 테스트 시나리오
- tempfile로 테스트용 Cargo.lock/package-lock.json 생성
- Mock VulnDb 사용
- `cargo test -p ironpost-daemon --test e2e_sbom_flow` 통과

---

### T7.4: S3 -- ironpost.toml 로딩 -> Orchestrator 초기화 -> 모듈 health_check 성공
- **담당 에이전트**: tester
- **예상 소요**: 1h
- **의존성**: T7.1
- **상태**: [ ]

**설명**:
설정 파일 로딩부터 Orchestrator 빌드, 모듈 초기화, health_check 성공까지의
전체 라이프사이클 시작 단계를 검증합니다.

**테스트 시나리오**:
- [ ] `test_e2e_config_load_and_init`: 유효한 ironpost.toml -> Orchestrator 빌드 성공
- [ ] `test_e2e_all_modules_health_check`: 모든 모듈 시작 후 health_check == Healthy
- [ ] `test_e2e_partial_config_defaults`: 일부 섹션만 있는 설정 -> 기본값으로 빌드 성공
- [ ] `test_e2e_env_override_config`: 환경변수로 설정 오버라이드 -> 올바르게 반영

**검증 포인트**:
- `IronpostConfig::load()` -> `validate()` 성공
- `Orchestrator::build_from_config()` 성공
- 각 모듈 `health_check()` 결과 확인
- `DaemonHealth` 집계 결과 = Healthy

**주요 파일**:
- `ironpost-daemon/tests/e2e/lifecycle.rs` (신규)

**Acceptance Criteria**:
- 최소 4개 테스트 시나리오
- tempfile 기반 설정 파일 사용
- `cargo test -p ironpost-daemon --test e2e_lifecycle` 통과

---

### T7.5: S4 -- Graceful Shutdown 순서 검증 (producer -> consumer, 타임아웃)
- **담당 에이전트**: tester
- **예상 소요**: 1.5h
- **의존성**: T7.1
- **상태**: [ ]

**설명**:
Orchestrator의 graceful shutdown이 올바른 순서로 실행되는지 검증합니다.
생산자(eBPF, LogPipeline)가 먼저 정지하고, 소비자(ContainerGuard)가 나중에 정지하여
채널 드레인이 가능한지 확인합니다.

**테스트 시나리오**:
- [ ] `test_e2e_shutdown_order_producers_first`: 정지 순서 = eBPF -> LogPipeline -> SBOM -> ContainerGuard
- [ ] `test_e2e_shutdown_drains_pending_events`: 셧다운 중 채널의 잔여 이벤트 처리 확인
- [ ] `test_e2e_shutdown_timeout_handling`: 모듈 정지 지연 시 타임아웃 동작 검증
- [ ] `test_e2e_shutdown_partial_failure_continues`: 한 모듈 정지 실패 -> 나머지 모듈 정지 계속
- [ ] `test_e2e_pid_file_cleanup_after_shutdown`: PID 파일이 셧다운 후 삭제됨

**검증 포인트**:
- ModuleRegistry의 stop_all() 호출 순서 (순방향)
- 채널에 남은 이벤트가 소비자에 의해 처리됨
- stop 에러가 다른 모듈 정지를 방해하지 않음
- PID 파일 정리

**주요 파일**:
- `ironpost-daemon/tests/e2e/shutdown.rs` (신규)

**Acceptance Criteria**:
- 최소 5개 테스트 시나리오
- 정지 순서를 `AtomicUsize` 카운터 또는 `Vec<String>` 로그로 검증
- `cargo test -p ironpost-daemon --test e2e_shutdown` 통과

---

### T7.6: S5 -- 잘못된 설정 -> 적절한 에러 메시지 + 비정상 종료
- **담당 에이전트**: tester
- **예상 소요**: 1h
- **의존성**: T7.1
- **상태**: [ ]

**설명**:
유효하지 않은 설정 파일로 Orchestrator를 빌드할 때 적절한 에러 메시지가
생성되고 올바른 종료 코드를 반환하는지 검증합니다.

**테스트 시나리오**:
- [ ] `test_e2e_invalid_toml_syntax`: 잘못된 TOML 문법 -> 파싱 에러
- [ ] `test_e2e_invalid_log_level`: 유효하지 않은 log_level 값 -> ConfigError
- [ ] `test_e2e_invalid_port_range`: 포트 번호 범위 초과 -> 검증 에러
- [ ] `test_e2e_missing_required_field`: 필수 필드 누락 -> 명확한 에러 메시지
- [ ] `test_e2e_nonexistent_config_path`: 존재하지 않는 설정 파일 경로 -> IO 에러
- [ ] `test_e2e_empty_config_uses_defaults`: 빈 설정 파일 -> 기본값으로 동작

**검증 포인트**:
- 에러 메시지가 사용자 친화적 (문제 위치 + 해결 방안 힌트)
- `IronpostConfig::load()` 또는 `validate()` 에서 적절한 에러 반환
- 설정 파일 경로 오류 시 명확한 IO 에러

**주요 파일**:
- `ironpost-daemon/tests/e2e/config_error.rs` (신규)

**Acceptance Criteria**:
- 최소 6개 테스트 시나리오
- 에러 메시지에 문제 필드/값이 포함되어 있는지 assertion
- `cargo test -p ironpost-daemon --test e2e_config_error` 통과

---

### T7.7: S6 -- 모듈 장애 격리 (한 모듈 실패 -> 나머지 계속 동작)
- **담당 에이전트**: tester
- **예상 소요**: 1.5h
- **의존성**: T7.1
- **상태**: [ ]

**설명**:
하나의 모듈이 실패하더라도 나머지 모듈이 계속 동작하는 장애 격리를 검증합니다.
특히 start_all() 중 부분 실패 시 이미 시작된 모듈의 정리,
그리고 런타임 중 한 모듈의 health 저하가 다른 모듈에 영향을 미치지 않는지 확인합니다.

**테스트 시나리오**:
- [ ] `test_e2e_one_module_start_failure_others_stop`: 모듈 하나 시작 실패 -> 나머지 정리
- [ ] `test_e2e_runtime_module_degraded_others_healthy`: 한 모듈 Degraded -> 나머지 Healthy 유지
- [ ] `test_e2e_channel_sender_dropped_receiver_handles`: 생산자 채널 닫힘 -> 소비자 graceful 처리
- [ ] `test_e2e_stop_failure_continues_others`: 한 모듈 정지 실패 -> 나머지 모듈 정지 계속
- [ ] `test_e2e_health_aggregation_worst_case`: Unhealthy + Degraded + Healthy -> 전체 Unhealthy

**검증 포인트**:
- ModuleRegistry가 start 실패 시 적절히 반응
- stop_all()이 개별 모듈 에러를 로깅하고 계속 진행
- DaemonHealth 집계가 worst-case 기반
- 채널 닫힘 시 수신자 측 panic 없음

**주요 파일**:
- `ironpost-daemon/tests/e2e/fault_isolation.rs` (신규)

**Acceptance Criteria**:
- 최소 5개 테스트 시나리오
- FailingPipeline mock (start/stop에서 에러 반환)
- `cargo test -p ironpost-daemon --test e2e_fault_isolation` 통과

---

## Part B: Docker Compose One-Click Demo

### T7.8: Dockerfile 개선 (Multi-stage Build 최적화)
- **담당 에이전트**: implementer
- **예상 소요**: 1.5h
- **의존성**: 없음 (독립 작업)
- **상태**: [ ]

**설명**:
기존 `docker/Dockerfile`을 개선합니다. 빌드 캐싱을 최적화하고,
최종 이미지 크기를 최소화하며, 보안 베스트 프랙티스를 적용합니다.

**구현 항목**:
- [ ] Stage 1 (planner): `cargo chef prepare` -- 의존성 레시피 추출
- [ ] Stage 2 (cacher): `cargo chef cook` -- 의존성만 사전 빌드 (소스 변경 시 캐시 유지)
- [ ] Stage 3 (builder): 소스 복사 + `cargo build --release`
- [ ] Stage 4 (runtime): `debian:bookworm-slim` 또는 `gcr.io/distroless/cc-debian12`
- [ ] 불필요한 파일 제외 (`.dockerignore` 추가: target/, .git/, docs/)
- [ ] 비루트 사용자 (ironpost:ironpost) + 최소 권한
- [ ] HEALTHCHECK 명령 추가 (`ironpost-cli health` 또는 단순 프로세스 체크)
- [ ] 메타데이터 LABEL 추가 (maintainer, version, description)

**주요 파일**:
- `docker/Dockerfile` -- 개선 (기존 파일 수정)
- `.dockerignore` -- 신규 생성

**Acceptance Criteria**:
- `docker build -f docker/Dockerfile .` 성공 (Manjaro 환경)
- 최종 이미지 크기 < 100MB (distroless 사용 시)
- 비루트 사용자로 실행
- HEALTHCHECK 동작

---

### T7.9: docker-compose.yml 개선
- **담당 에이전트**: implementer
- **예상 소요**: 1h
- **의존성**: T7.8
- **상태**: [ ]

**설명**:
기존 `docker/docker-compose.yml`을 개선합니다. 서비스 의존성, 헬스체크,
리소스 제한, 네트워크 격리를 추가합니다.

**구현 항목**:
- [ ] ironpost 서비스: 환경변수 오버라이드 (`IRONPOST_*`), 리소스 제한 (mem/cpu)
- [ ] 서비스별 healthcheck 추가 (postgresql, redis, ironpost)
- [ ] `depends_on` + `condition: service_healthy` (서비스 준비 대기)
- [ ] 전용 네트워크 정의 (`ironpost-net`) -- 외부 노출 최소화
- [ ] `.env.example` 작성 -- 환경변수 템플릿 (POSTGRES_PASSWORD 등)
- [ ] 볼륨 마운트 최적화 (read-only 설정 파일, named volumes)
- [ ] Prometheus/Grafana 서비스 정리 (주석 + 선택적 프로파일)

**주요 파일**:
- `docker/docker-compose.yml` -- 개선 (기존 파일 수정)
- `docker/.env.example` -- 신규 생성

**Acceptance Criteria**:
- `docker compose -f docker/docker-compose.yml config` 유효
- 서비스 간 healthcheck 의존성 동작
- 환경변수 오버라이드 동작
- `docker compose up -d` 로 전체 스택 실행 가능 (Manjaro)

---

### T7.10: docker-compose.demo.yml 작성
- **담당 에이전트**: implementer + writer
- **예상 소요**: 1.5h
- **의존성**: T7.9
- **상태**: [ ]

**설명**:
데모 시나리오를 실행하는 별도의 docker-compose override 파일을 작성합니다.
nginx와 redis를 데모 워크로드로 실행하고, 로그 생성 및 공격 시뮬레이션을 포함합니다.

**구현 항목**:
- [ ] `docker/docker-compose.demo.yml` -- 데모 오버라이드 파일
- [ ] nginx 서비스: 데모 워크로드 (격리 대상)
- [ ] redis 서비스: 데모 워크로드 (격리 대상)
- [ ] log-generator 서비스: syslog 메시지 생성 (bash 스크립트 또는 경량 컨테이너)
- [ ] attack-simulator 서비스: 의심스러운 로그 패턴 생성 (알림 트리거)
- [ ] `docker/demo/` 디렉토리: 데모 설정 파일, 규칙 파일, 공격 패턴 스크립트
- [ ] `docker/demo/ironpost-demo.toml`: 데모용 설정 (낮은 임계값, 빠른 스캔 주기)
- [ ] `docker/demo/rules/`: 데모용 탐지 규칙 YAML 파일
- [ ] `docker/demo/generate-logs.sh`: 로그 생성 스크립트

**주요 파일**:
- `docker/docker-compose.demo.yml` -- 신규
- `docker/demo/ironpost-demo.toml` -- 신규
- `docker/demo/rules/demo-rules.yml` -- 신규
- `docker/demo/generate-logs.sh` -- 신규

**Acceptance Criteria**:
- `docker compose -f docker/docker-compose.yml -f docker/docker-compose.demo.yml up -d` 실행 성공
- nginx/redis 컨테이너가 데모 워크로드로 실행
- 로그 생성기가 syslog 메시지를 ironpost에 전송
- 공격 시뮬레이션 실행 시 AlertEvent 생성 확인
- `ironpost-cli container list` 로 모니터링 대상 확인 가능

---

### T7.11: docs/demo.md 데모 실행 가이드
- **담당 에이전트**: writer
- **예상 소요**: 1h
- **의존성**: T7.10
- **상태**: [ ]

**설명**:
3분 이내에 데모를 체험할 수 있는 실행 가이드를 작성합니다.
Docker Compose 데모의 실행부터 주요 기능 체험까지의 단계를 안내합니다.

**포함 항목**:
- [ ] 사전 요구 사항 (Docker, Docker Compose)
- [ ] 1단계: 환경 준비 (`cp .env.example .env`, 설정 확인)
- [ ] 2단계: 스택 실행 (`docker compose up -d`)
- [ ] 3단계: 상태 확인 (`docker compose ps`, `ironpost-cli health`)
- [ ] 4단계: 로그 모니터링 (`docker compose logs -f ironpost`)
- [ ] 5단계: 공격 시뮬레이션 실행 + 알림 확인
- [ ] 6단계: 컨테이너 격리/해제 체험
- [ ] 7단계: SBOM 스캔 실행
- [ ] 정리 (`docker compose down -v`)
- [ ] 트러블슈팅 섹션 (포트 충돌, 권한 문제 등)
- [ ] 아키텍처 다이어그램 (데모 환경 구성도)

**주요 파일**:
- `docs/demo.md` -- 신규

**Acceptance Criteria**:
- 200줄 이상
- 모든 명령이 copy-paste 실행 가능
- 단계별 예상 출력 포함
- 3분 이내 체험 가능한 경로 명시

---

## Part C: GitHub Actions CI Enhancement

### T7.12: GitHub Actions CI 강화
- **담당 에이전트**: implementer
- **예상 소요**: 2h
- **의존성**: 없음 (독립 작업)
- **상태**: [ ]

**설명**:
기존 `.github/workflows/ci.yml`을 강화합니다. 크로스 플랫폼 매트릭스,
cargo audit, 캐싱 최적화, eBPF 조건부 빌드를 추가합니다.

**구현 항목**:
- [ ] 매트릭스 확장: `ubuntu-latest` + `macos-latest`, stable Rust
- [ ] fmt 잡: 크로스 플랫폼 불필요 (ubuntu-latest만)
- [ ] clippy 잡: 매트릭스 적용 (macOS에서도 clippy 통과 확인)
- [ ] test 잡: 매트릭스 적용 + `cargo test --workspace`
- [ ] doc 잡: ubuntu-latest만 (문서 빌드는 한 번이면 충분)
- [ ] security 잡 추가: `cargo audit` (advisory-db 기반 취약점 검사)
  - `actions-rs/audit-check@v1` 또는 `rustsec/audit-check` 액션 활용
- [ ] 캐싱 최적화: `Swatinem/rust-cache@v2` 적용 (이미 일부 적용됨, 일관성 확보)
- [ ] build 잡: eBPF 포함 빌드는 ubuntu-latest만 (`#[cfg(target_os = "linux")]`)
- [ ] 테스트 결과 요약: `test-reporter` 액션 또는 `cargo-nextest` 도입 검토
- [ ] concurrency group 추가 (동일 PR의 중복 CI 실행 취소)
- [ ] README.md CI 뱃지 업데이트

**주요 파일**:
- `.github/workflows/ci.yml` -- 개선 (기존 파일 수정)

**Acceptance Criteria**:
- macOS + Linux 매트릭스에서 fmt/clippy/test 성공
- `cargo audit` 잡이 취약한 의존성 발견 시 경고 (fail 아닌 warn)
- 캐싱으로 재빌드 시간 단축 (캐시 히트 시 50%+ 단축)
- concurrency group으로 중복 CI 방지
- README.md에 CI 상태 뱃지 표시

---

### T7.13: dependabot.yml 추가
- **담당 에이전트**: implementer
- **예상 소요**: 0.5h
- **의존성**: 없음 (독립 작업)
- **상태**: [ ]

**설명**:
Dependabot을 설정하여 Rust 의존성과 GitHub Actions 의존성의
자동 업데이트 PR을 받을 수 있도록 합니다.

**구현 항목**:
- [ ] `.github/dependabot.yml` -- Dependabot 설정 파일
- [ ] cargo 패키지 업데이트: 주간 체크, PR 최대 5개
- [ ] GitHub Actions 업데이트: 주간 체크
- [ ] Docker 이미지 업데이트: 월간 체크 (docker/Dockerfile에서 사용하는 이미지)
- [ ] 레이블 자동 지정 (`dependencies`, `rust`, `github-actions`)
- [ ] 리뷰어 자동 지정 (선택)

**주요 파일**:
- `.github/dependabot.yml` -- 신규

**Acceptance Criteria**:
- Dependabot 설정이 유효한 YAML
- cargo, github-actions, docker 3개 에코시스템 설정
- 주간/월간 업데이트 주기 설정

---

## 리뷰

### T7.14: Phase 7 코드 리뷰
- **담당 에이전트**: reviewer
- **예상 소요**: 2h
- **의존성**: T7.1 ~ T7.13 전체 완료 후
- **상태**: [ ]

**설명**:
Phase 7의 모든 산출물을 리뷰합니다.

**리뷰 항목**:
- [ ] E2E 테스트: 시나리오 커버리지, assertion 충분성, 테스트 격리
- [ ] Docker: 보안 (비루트, 최소 이미지), 빌드 효율성, 네트워크 격리
- [ ] CI: 매트릭스 커버리지, 캐싱 효율, 보안 잡 동작
- [ ] 코드 품질: CLAUDE.md 규칙 준수, clippy/fmt 통과

**주요 파일**:
- `.reviews/phase-7-e2e.md` -- 리뷰 결과 (신규)

**Acceptance Criteria**:
- 리뷰 파일 작성 완료
- Critical 0건, High 3건 이하
- 모든 Critical/High 수정 후 머지 가능

---

## 태스크 의존성 그래프

```text
        Part A (E2E Tests)                Part B (Docker)           Part C (CI)
        ================                  ===============           ===========

        T7.1 (인프라 셋업)                T7.8 (Dockerfile)         T7.12 (CI 강화)
        /  |  |  \   \   \                    |                     T7.13 (dependabot)
      T7.2 T7.3 T7.4 T7.5 T7.6 T7.7     T7.9 (compose)
      (S1) (S2) (S3) (S4) (S5) (S6)          |
                                          T7.10 (demo compose)
                                              |
                                          T7.11 (demo docs)

                          \       |       /
                           T7.14 (리뷰)
```

## 병렬 작업 가능 그룹

| 그룹 | 태스크 | 설명 |
|------|--------|------|
| 1 (동시) | T7.1, T7.8, T7.12, T7.13 | 의존성 없는 초기 태스크 |
| 2 (동시) | T7.2~T7.7, T7.9 | T7.1 완료 후 E2E 전체 + Docker compose |
| 3 | T7.10 | T7.9 완료 후 |
| 4 | T7.11 | T7.10 완료 후 |
| 5 | T7.14 | 전체 완료 후 리뷰 |

## 예상 총 소요 시간

| 구분 | 태스크 수 | 예상 소요 |
|------|-----------|-----------|
| Part A: E2E Tests | 7건 | 10h |
| Part B: Docker Demo | 4건 | 5h |
| Part C: CI Enhancement | 2건 | 2.5h |
| 리뷰 | 1건 | 2h |
| **합계** | **14건** | **19.5h** |

**최적 경로 (병렬 활용 시)**: 약 8h (그룹 1~5 순차, 그룹 내 병렬)

## 완료 기준

### Part A 완료 기준
- [ ] E2E 테스트 6개 시나리오 (S1~S6) 모두 구현
- [ ] 최소 30개 E2E 테스트 케이스
- [ ] 모든 테스트 Mock 기반 (Docker 불필요)
- [ ] `cargo test -p ironpost-daemon` 전체 통과 (기존 + E2E)
- [ ] `cargo clippy -p ironpost-daemon -- -D warnings` 통과

### Part B 완료 기준
- [ ] `docker compose up -d` 한 번으로 전체 스택 실행
- [ ] 데모 시나리오 (로그 생성 + 공격 시뮬레이션 + 격리) 동작
- [ ] docs/demo.md 가이드 200줄 이상
- [ ] Manjaro 환경에서 검증 완료

### Part C 완료 기준
- [ ] macOS + Linux CI 매트릭스 동작
- [ ] cargo audit 잡 추가
- [ ] Dependabot 설정 완료
- [ ] README.md CI 뱃지 업데이트

### 전체 완료 기준
- [ ] `cargo test --workspace` 전체 통과 (1063 + E2E 30+ = 1093+ tests)
- [ ] `cargo clippy --workspace -- -D warnings` 통과
- [ ] `cargo fmt --all --check` 통과
- [ ] `cargo doc --workspace --no-deps` 통과
- [ ] Phase 7 리뷰 완료, Critical 0건

# Phase 6: Integration & Polish

## 목표
모든 모듈(ebpf-engine, log-pipeline, container-guard, sbom-scanner)을 ironpost-daemon에서 통합 조립하고,
ironpost-cli로 운영 인터페이스를 제공하며, 이전 Phase에서 미뤄둔 리뷰 수정 사항을 반영하고,
프로젝트 문서를 완성하여 v0.1.0 릴리스 준비를 마무리합니다.

## 선행 조건
- [x] Phase 0: 프로젝트 스캐폴딩
- [x] Phase 1: Core 크레이트 (64 tests)
- [x] Phase 2: eBPF 엔진 (74 tests)
- [x] Phase 3: 로그 파이프라인 (280 tests)
- [x] Phase 4: 컨테이너 가드 (202 tests)
- [x] Phase 5: SBOM 스캐너 (183 tests)

## 브랜치
- `phase/6-integration`

---

## 필수 태스크 (Required)

### T6-1: ironpost-daemon 통합 구현
- **담당 에이전트**: architect (설계) + implementer (구현)
- **예상 소요**: 4h (설계 1h + 구현 3h)
- **의존성**: 없음 (첫 번째 태스크)
- **상태**: [ ]

**설명**:
ironpost-daemon을 완전한 오케스트레이터로 구현합니다. 현재 main.rs는 log-pipeline과 container-guard만
조립하는 스켈레톤 상태입니다. 모든 모듈의 라이프사이클을 관리하고 이벤트 버스를 연결합니다.

**구현 항목**:
- [ ] `ironpost.toml` 통합 설정 파일 로딩 (IronpostConfig)
- [ ] 모듈 간 이벤트 채널 조립 (ebpf -> log-pipeline -> container-guard)
- [ ] sbom-scanner 모듈 통합 (주기적 스캔 태스크)
- [ ] eBPF 엔진 조건부 로딩 (`#[cfg(target_os = "linux")]`)
- [ ] graceful shutdown 순서 보장 (producer -> consumer 역순)
- [ ] UNIX 시그널 핸들링 (SIGTERM, SIGINT, SIGHUP for reload)
- [ ] health check 통합 엔드포인트 (각 모듈 상태 집계)
- [ ] 구조화된 JSON 로깅 초기화 (tracing-subscriber)
- [ ] PID 파일 관리 (중복 실행 방지)
- [ ] 설정 파일 경로 CLI 인자 (`--config`)

**주요 파일**:
- `ironpost-daemon/src/main.rs` -- 진입점 + 시그널 핸들링
- `ironpost-daemon/src/orchestrator.rs` -- 모듈 조립 + 라이프사이클 관리 (신규)
- `ironpost-daemon/src/health.rs` -- 통합 헬스 체크 (신규)
- `ironpost-daemon/Cargo.toml` -- 의존성 업데이트

**Acceptance Criteria**:
- `cargo build -p ironpost-daemon` 성공
- 설정 파일 로딩 -> 모듈 초기화 -> 시작 -> Ctrl+C -> graceful shutdown 동작
- 각 모듈의 health_check() 결과를 통합 보고
- 모든 모듈 간 이벤트 채널이 올바르게 연결됨

---

### T6-2: ironpost-cli 통합 구현
- **담당 에이전트**: implementer
- **예상 소요**: 3h
- **의존성**: T6-1 (daemon 설계 완료 후)
- **상태**: [ ]

**설명**:
현재 CLI는 컨테이너 명령만 동작하며 나머지는 "not yet implemented" 상태입니다.
모든 서브커맨드를 구현하여 각 모듈의 pub API를 직접 호출합니다.

**구현 항목**:
- [ ] `ironpost config validate` -- 설정 파일 검증
- [ ] `ironpost config show` -- 현재 설정 출력
- [ ] `ironpost log status` -- 로그 파이프라인 상태
- [ ] `ironpost log rules` -- 규칙 목록 출력
- [ ] `ironpost sbom generate <path>` -- SBOM 생성 (CycloneDX/SPDX)
- [ ] `ironpost sbom scan <path>` -- 취약점 스캔 실행
- [ ] `ironpost container list` -- 개선 (status, created 추가)
- [ ] `ironpost container isolate/release` -- 기존 유지 + 에러 메시지 개선
- [ ] `ironpost health` -- daemon 헬스 체크 (로컬 소켓 연결)
- [ ] `ironpost version` -- 버전 정보 (빌드 시간, git hash)
- [ ] `println!` -> `tracing` 변경 (CLAUDE.md 규칙 준수) 또는 CLI 출력용 예외 처리
- [ ] 출력 포맷 옵션 (`--format json|table|plain`)

**주요 파일**:
- `ironpost-cli/src/main.rs` -- CLI 진입점 + 서브커맨드 라우팅
- `ironpost-cli/src/commands/` -- 서브커맨드 모듈 (신규 디렉토리)
- `ironpost-cli/Cargo.toml` -- 의존성 업데이트

**Acceptance Criteria**:
- 모든 서브커맨드가 `--help` 출력
- `ironpost sbom generate ./` 가 SBOM JSON 파일을 생성
- `ironpost sbom scan ./` 가 취약점 리포트 출력
- `ironpost config validate ironpost.toml` 가 설정 검증 결과 출력
- `cargo clippy -p ironpost-cli -- -D warnings` 통과

---

### T6-3: ironpost.toml 통합 설정 파일
- **담당 에이전트**: architect (스키마 설계) + implementer (구현)
- **예상 소요**: 2h
- **의존성**: T6-1과 병행 가능
- **상태**: [ ]

**설명**:
모든 모듈의 설정을 통합하는 ironpost.toml 샘플 파일을 작성하고,
각 모듈의 `from_core()` 변환이 올바르게 동작하는지 검증합니다.

**구현 항목**:
- [ ] `ironpost.toml.example` 작성 (전체 설정 + 주석)
- [ ] 각 모듈 섹션: `[general]`, `[ebpf]`, `[log_pipeline]`, `[container]`, `[sbom]`
- [ ] 환경변수 오버라이드 매핑 문서화
- [ ] 설정 로딩 통합 테스트 (부분 설정, 빈 파일, 환경변수 우선순위)
- [ ] 설정 마이그레이션 가이드 (docs/configuration.md)

**주요 파일**:
- `ironpost.toml.example` -- 샘플 설정 (루트)
- `docs/configuration.md` -- 설정 가이드 (신규)
- 통합 테스트 추가

**Acceptance Criteria**:
- `ironpost.toml.example`에 모든 모듈 섹션과 기본값, 주석 포함
- 각 환경변수(`IRONPOST_*`)가 올바르게 오버라이드
- 부분 설정(일부 섹션만)으로도 daemon 시작 가능

---

### T6-4: 리뷰 미반영 수정 사항 (Phase 2~5 High/Medium)
- **담당 에이전트**: implementer
- **예상 소요**: 6h
- **의존성**: 없음 (독립 작업 가능)
- **상태**: [ ]

**설명**:
Phase 2~5 코드 리뷰에서 발견되었으나 미수정 상태인 High/Medium 이슈를 일괄 반영합니다.
Critical은 이미 해결되었으므로 High + 선별 Medium 위주로 작업합니다.

#### Phase 3 (log-pipeline) 미반영 -- 6건
| ID | 심각도 | 설명 | 우선순위 |
|----|--------|------|----------|
| H1 | High | Detector trait `&self` vs `&mut self` 불일치 -- 내부 Mutex 패턴 적용 | 1 |
| H4 | High | Syslog PRI 값 범위 검증 (0-191) | 2 |
| H5 | High | 타임스탬프 휴리스틱 불완전 (micro/nanosecond) | 3 |
| H6 | High | 파일 경로 순회(path traversal) 검증 | 4 |
| H7 | High | SystemTime -> Instant 변경 (시계 역행 방어) | 5 |
| M2 | Medium | cleanup 주기를 시간 기반으로 변경 | 6 |

#### Phase 4 (container-guard) 미반영 -- 8건
| ID | 심각도 | 설명 | 우선순위 |
|----|--------|------|----------|
| NEW-C1 | Critical | stop()/start() 재시작 불가 -- Stopped 상태에서 명시적 에러 반환 | 1 |
| NEW-C2 | Critical | canonicalize() TOCTOU -- 루프 밖으로 이동 | 2 |
| H3 | High | 와일드카드 필터 임의 컨테이너 격리 -- 예시 정책 수정 + 경고 | 3 |
| NEW-H1 | High | 잘못된 에러 variant (ContainerNotFound -> InvalidInput) | 4 |
| NEW-H2 | High | Processing task 별도 DockerMonitor -- self.monitor 공유 | 5 |
| NEW-H3 | High | `all: true` -> 실행 중인 컨테이너만 필터 | 6 |
| H6 | High | labels 필드 미평가 -- 구현 또는 deprecated 표시 | 7 |
| M5 | Medium | 불필요한 enforcer.rs 파일 삭제 | 8 |

#### Phase 5 (sbom-scanner) 미반영 -- 6건
| ID | 심각도 | 설명 | 우선순위 |
|----|--------|------|----------|
| NEW-C1 | Critical | VulnDb lookup String 할당 -- 인덱스 구조 변경 | 1 |
| H2 | High | Graceful shutdown (CancellationToken 도입) | 2 |
| NEW-H1 | High | 주기적 태스크 취소 메커니즘 (CancellationToken) | 3 |
| NEW-H2 | High | discover_lockfiles TOCTOU -- File::open 후 metadata | 4 |
| NEW-H3 | High | unix_to_rfc3339 55줄 중복 -> 공유 모듈 추출 | 5 |
| M9 | Medium | Path traversal 검증 개선 (Component::ParentDir) | 6 |

#### Phase 2 (ebpf-engine) 미반영 -- 선별 2건
| ID | 심각도 | 설명 | 우선순위 |
|----|--------|------|----------|
| H3 | High | RingBuf busy-wait -> adaptive backoff | 1 |
| M7 | Medium | AlertEvent source_module이 항상 "log-pipeline" | 2 |

**구현 순서**:
1. Critical 4건 우선 (P4-NEW-C1, P4-NEW-C2, P5-NEW-C1, P3-H1)
2. High 보안 관련 (P3-H6 path traversal, P4-NEW-H3 stopped containers)
3. High 안정성 관련 (P5-H2 graceful shutdown, P5-NEW-H1 cancellation)
4. 나머지 High + Medium

**주요 파일**:
- `crates/log-pipeline/src/` -- parser, rule, alert, pipeline 수정
- `crates/container-guard/src/` -- guard, policy, docker, isolation 수정
- `crates/sbom-scanner/src/` -- vuln/db, scanner, sbom 수정
- `crates/ebpf-engine/src/` -- engine, detector 수정
- `crates/core/src/` -- trait 수정이 필요한 경우 (Detector trait)

**Acceptance Criteria**:
- Critical 4건 모두 수정 완료
- High 12건 중 최소 10건 수정 완료
- `cargo test --workspace` 전체 통과
- `cargo clippy --workspace -- -D warnings` 통과
- 리뷰 파일에 수정 상태 업데이트

---

### T6-5: 루트 README.md 재작성 (L1 문서)
- **담당 에이전트**: writer
- **예상 소요**: 2h
- **의존성**: T6-1, T6-2 완료 후 (정확한 사용법 반영)
- **상태**: [ ]

**설명**:
현재 README.md는 기본 스켈레톤 수준입니다. 프로젝트 소개, 아키텍처 다이어그램,
빠른 시작 가이드, 기능 목록, 테스트 수행 방법 등을 포함하는 완성된 문서로 재작성합니다.

**포함 항목**:
- [ ] 프로젝트 개요 (한줄 설명 + 상세 소개)
- [ ] 기능 하이라이트 (eBPF, 로그 파이프라인, 컨테이너 격리, SBOM 스캔)
- [ ] 아키텍처 다이어그램 (Mermaid + 텍스트 설명)
- [ ] 크레이트 구성표 (경로, 설명, 테스트 수)
- [ ] 빌드 방법 (prerequisites, cargo build, eBPF 빌드)
- [ ] 빠른 시작 가이드 (3단계: 설정 -> daemon 실행 -> CLI 사용)
- [ ] 설정 파일 예시 (ironpost.toml 핵심 섹션)
- [ ] CLI 사용 예시 (주요 커맨드)
- [ ] 테스트 수행 (`cargo test --workspace`)
- [ ] 문서 링크 목록
- [ ] 라이선스 정보
- [ ] 기여 가이드 링크 (있는 경우)

**주요 파일**:
- `README.md` -- 루트 README 재작성

**Acceptance Criteria**:
- README.md 300줄 이상
- 모든 모듈의 기능과 링크 포함
- 빌드/테스트 명령이 실제 동작하는지 검증
- Mermaid 다이어그램 포함

---

### T6-6: CHANGELOG.md 작성
- **담당 에이전트**: writer
- **예상 소요**: 1h
- **의존성**: T6-4 완료 후 (전체 변경 사항 확정)
- **상태**: [ ]

**설명**:
Phase 0~6까지의 모든 주요 변경 사항을 Keep a Changelog 형식으로 정리합니다.
현재 CHANGELOG.md는 "프로젝트 초기 스캐폴딩"만 있습니다.

**포함 항목**:
- [ ] [0.1.0] 릴리스 섹션 (모든 Phase 통합)
- [ ] Added: core 크레이트, ebpf-engine, log-pipeline, container-guard, sbom-scanner, daemon, cli
- [ ] 각 모듈의 핵심 기능 요약
- [ ] Security: 리뷰에서 발견/수정된 보안 이슈 요약
- [ ] Phase별 테스트 수 통계

**주요 파일**:
- `CHANGELOG.md`

**Acceptance Criteria**:
- Keep a Changelog 1.1.0 형식 준수
- Phase 0~6 주요 변경 사항 모두 포함
- Added/Changed/Fixed/Security 카테고리 활용

---

## 고도화 태스크 (Enhancement)

### T6-7: Docker Compose 원클릭 데모
- **담당 에이전트**: implementer + writer
- **예상 소요**: 3h
- **의존성**: T6-1 완료 후
- **상태**: [ ]

**설명**:
`docker compose up` 한 번으로 ironpost-daemon + 모니터링 스택(Prometheus, Grafana) +
데모 워크로드를 실행하는 환경을 구성합니다.

**구현 항목**:
- [ ] `docker-compose.yml` 작성
  - ironpost-daemon 컨테이너 (multi-stage build)
  - 데모용 nginx/redis 컨테이너 (격리 대상)
  - (선택) Prometheus + Grafana
- [ ] `Dockerfile` 작성 (ironpost-daemon + ironpost-cli)
- [ ] `docker-compose.demo.yml` -- 데모 시나리오 포함
- [ ] `.env.example` -- 환경변수 설정 템플릿
- [ ] `docs/demo.md` -- 데모 실행 가이드

**주요 파일**:
- `Dockerfile` (신규)
- `docker-compose.yml` (신규)
- `docker-compose.demo.yml` (신규)
- `.env.example` (신규)
- `docs/demo.md` (신규)

**Acceptance Criteria**:
- `docker compose up -d` 로 전체 스택 실행 가능
- ironpost-cli 명령으로 컨테이너 목록 조회 가능
- 데모 시나리오 문서화

---

### T6-8: GitHub Actions CI 워크플로우 + 뱃지
- **담당 에이전트**: implementer
- **예상 소요**: 2h
- **의존성**: 없음 (독립 작업)
- **상태**: [ ]

**설명**:
CI 파이프라인을 구성하여 PR/push마다 자동 빌드, 테스트, 린트를 실행합니다.

**구현 항목**:
- [ ] `.github/workflows/ci.yml` 작성
  - 트리거: push (main), PR
  - 매트릭스: stable Rust, macOS + Linux
  - 단계: fmt check, clippy, test (--workspace), doc test
  - 캐싱: cargo registry + target 디렉토리
- [ ] `.github/workflows/security.yml` -- cargo audit (선택)
- [ ] README.md에 CI 뱃지 추가
- [ ] Dependabot 설정 (`dependabot.yml`)

**주요 파일**:
- `.github/workflows/ci.yml` (신규)
- `.github/workflows/security.yml` (선택, 신규)
- `.github/dependabot.yml` (선택, 신규)
- `README.md` -- 뱃지 추가

**Acceptance Criteria**:
- GitHub Actions에서 빌드 + 테스트 + 린트 성공
- PR에 CI 결과 자동 표시
- README.md에 빌드 상태 뱃지

---

### T6-9: E2E 시나리오 테스트
- **담당 에이전트**: tester
- **예상 소요**: 4h
- **의존성**: T6-1, T6-4 완료 후
- **상태**: [ ]

**설명**:
모듈 간 이벤트 흐름을 검증하는 통합 E2E 테스트를 작성합니다.
Mock 기반으로 Docker 없이 실행 가능하도록 설계합니다.

**테스트 시나리오**:
- [ ] S1: 로그 주입 -> 규칙 매칭 -> AlertEvent 생성 -> 컨테이너 격리 (mock)
- [ ] S2: SBOM 스캔 -> 취약점 발견 -> AlertEvent 생성
- [ ] S3: 설정 파일 로딩 -> 각 모듈 초기화 -> health_check 성공
- [ ] S4: graceful shutdown 순서 검증 (producer -> consumer)
- [ ] S5: 잘못된 설정 파일 -> 적절한 에러 메시지
- [ ] S6: 모듈 장애 격리 (한 모듈 실패해도 나머지 동작)

**주요 파일**:
- `tests/e2e/` (신규 디렉토리)
- `tests/e2e/pipeline_flow.rs` -- S1, S2
- `tests/e2e/lifecycle.rs` -- S3, S4, S6
- `tests/e2e/config.rs` -- S5

**Acceptance Criteria**:
- 최소 6개 E2E 테스트 시나리오
- Mock 기반으로 Docker 불필요
- `cargo test --test e2e` 전체 통과
- 모듈 간 이벤트 흐름 검증 (sender -> receiver 확인)

---

## 보너스 태스크 (Bonus)

### T6-10: 데모 GIF / 공격 시뮬레이션
- **담당 에이전트**: writer
- **예상 소요**: 2h
- **의존성**: T6-7 (Docker Compose 데모)
- **상태**: [ ]

**설명**:
README.md에 포함할 터미널 데모 GIF를 제작합니다.
asciinema 또는 VHS를 사용하여 주요 사용 시나리오를 녹화합니다.

**포함 시나리오**:
- [ ] ironpost-daemon 시작 + 로그 출력
- [ ] ironpost-cli container list / isolate / release
- [ ] ironpost-cli sbom generate / scan
- [ ] 공격 시뮬레이션: 의심스러운 로그 주입 -> 알림 생성 -> 자동 격리

**주요 파일**:
- `docs/demo.tape` (VHS 스크립트) 또는 asciinema 녹화
- `docs/assets/demo.gif` (결과물)
- `README.md` -- GIF 임베드

**Acceptance Criteria**:
- 30초 이내 데모 GIF
- 핵심 기능 3가지 이상 시연

---

### T6-11: 벤치마크 문서화
- **담당 에이전트**: tester + writer
- **예상 소요**: 3h
- **의존성**: T6-4 완료 후 (성능 수정 반영)
- **상태**: [ ]

**설명**:
각 모듈의 핵심 경로에 대한 벤치마크를 작성하고 결과를 문서화합니다.

**벤치마크 항목**:
- [ ] log-pipeline: 파싱 throughput (syslog, JSON) -- ops/sec
- [ ] log-pipeline: 규칙 매칭 속도 (단일 규칙, 100 규칙)
- [ ] sbom-scanner: Cargo.lock 파싱 (100/1000/10000 패키지)
- [ ] sbom-scanner: VulnDb lookup (1K/10K/100K 엔트리)
- [ ] container-guard: 정책 평가 속도 (10/100/1000 정책)

**주요 파일**:
- `benches/` (신규 디렉토리)
- `benches/log_parser.rs`
- `benches/sbom_scan.rs`
- `benches/policy_eval.rs`
- `docs/benchmarks.md` -- 결과 문서화

**Acceptance Criteria**:
- `cargo bench` 실행 가능
- criterion 기반 벤치마크
- docs/benchmarks.md에 결과 표 + 분석 포함

---

## 태스크 의존성 그래프

```text
T6-3 (설정파일) ----+
                    |
T6-1 (daemon) ------+---> T6-2 (CLI) ---> T6-5 (README)
                    |                         |
T6-4 (리뷰수정) ----+---> T6-9 (E2E) ----+---> T6-6 (CHANGELOG)
                                          |
T6-8 (CI) -----> (독립)                   |
                                          |
T6-7 (Docker) ---------> T6-10 (데모GIF)  |
                                          |
T6-11 (벤치마크) <------------------------+
```

## 예상 총 소요 시간

| 구분 | 태스크 수 | 예상 소요 |
|------|-----------|-----------|
| 필수 | 6건 | 18h |
| 고도화 | 3건 | 9h |
| 보너스 | 2건 | 5h |
| **합계** | **11건** | **32h** |

## 완료 기준

### v0.1.0 릴리스 기준 (필수 태스크 완료)
- [ ] ironpost-daemon이 모든 모듈을 조립하여 실행
- [ ] ironpost-cli로 모든 서브커맨드 동작
- [ ] ironpost.toml.example 완비
- [ ] Phase 2~5 Critical/High 리뷰 이슈 모두 해결
- [ ] README.md 완성 (300줄+)
- [ ] CHANGELOG.md 작성
- [ ] `cargo test --workspace` 전체 통과
- [ ] `cargo clippy --workspace -- -D warnings` 전체 통과
- [ ] `cargo fmt --check` 통과

### 고도화 완료 기준
- [ ] Docker Compose로 원클릭 데모 실행 가능
- [ ] GitHub Actions CI 녹색
- [ ] E2E 테스트 6건+ 통과

### 보너스 완료 기준
- [ ] 데모 GIF 포함 README
- [ ] 벤치마크 결과 문서화

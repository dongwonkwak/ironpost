# Ironpost 태스크 보드
> 최종 업데이트: 2026-02-11

## 진행 요약
| Phase | 전체 | 완료 | 진행중 | 대기 | 진행률 |
|-------|------|------|--------|------|--------|
| 0-setup | 1 | 1 | 0 | 0 | ✅ |
| 1-core | 6 | 6 | 0 | 0 | ✅ |
| 2-ebpf | 5 | 5 | 0 | 6 | ✅ (설계+구현+리뷰+수정 완료) |
| 3-log | 12 | 13 | 0 | 5 | ✅ (설계+구현+리뷰+수정 완료) |
| 4-container | 17 | 17 | 0 | 0 | ✅ (설계+구현+테스트+리뷰 완료, 202 tests) |
| 5-sbom | 28 | 28 | 0 | 0 | ✅ (Phase 5-E 문서화 완료, 183 tests, README 580+ lines) |
| 6-polish | 12 | 9 | 0 | 3 | ✅ T6-14 ironpost-cli 문서화 완료, 다음: T6-3 설정 파일 |
| 7-e2e | 14 | 3 | 0 | 11 | T7.8 Dockerfile 개선 완료 |

## 블로커
- 없음

## 현재 진행중
- 없음

---

## Phase 7: E2E Tests, Docker Demo, CI Enhancement

### Part A: E2E Scenario Tests -- 7건
| ID | 태스크 | 담당 | 예상 | 상태 | 의존성 |
|----|--------|------|------|------|--------|
| T7.1 | E2E 테스트 인프라 셋업 | architect + tester | 1.5h | 🔄 (2026-02-11 시작) | 없음 |
| T7.2 | S1: 이벤트 파이프라인 E2E (LogEvent -> Rule -> Alert -> Isolate) | tester | 2h | ⏳ | T7.1 |
| T7.3 | S2: SBOM 스캔 -> AlertEvent E2E | tester | 1.5h | ⏳ | T7.1 |
| T7.4 | S3: 설정 로딩 -> Orchestrator 초기화 -> health_check | tester | 1h | ⏳ | T7.1 |
| T7.5 | S4: Graceful shutdown 순서 검증 (producer first, timeout) | tester | 1.5h | ⏳ | T7.1 |
| T7.6 | S5: 잘못된 설정 -> 에러 메시지 + 비정상 종료 | tester | 1h | ⏳ | T7.1 |
| T7.7 | S6: 모듈 장애 격리 (한 모듈 실패 -> 나머지 계속) | tester | 1.5h | ⏳ | T7.1 |

### Part B: Docker Compose One-Click Demo -- 4건
| ID | 태스크 | 담당 | 예상 | 상태 | 의존성 |
|----|--------|------|------|------|--------|
| T7.8 | Dockerfile 개선 (multi-stage, cargo-chef, distroless) | implementer | 1.5h | ✅ (2026-02-11 완료, 15분) | 없음 |
| T7.9 | docker-compose.yml 개선 (healthcheck, network, resources) | implementer | 1h | ⏳ | T7.8 |
| T7.10 | docker-compose.demo.yml (nginx, redis, log-generator, attack-sim) | implementer + writer | 1.5h | ⏳ | T7.9 |
| T7.11 | docs/demo.md 데모 실행 가이드 (3분 체험) | writer | 1h | ⏳ | T7.10 |

### Part C: GitHub Actions CI Enhancement -- 2건
| ID | 태스크 | 담당 | 예상 | 상태 | 의존성 |
|----|--------|------|------|------|--------|
| T7.12 | CI 강화 (matrix, cargo audit, caching, concurrency) | implementer | 2h | ✅ (2026-02-11 완료, 15분) | 없음 |
| T7.13 | dependabot.yml (cargo, github-actions, docker) | implementer | 0.5h | ✅ (2026-02-11 완료, 5분) | 없음 |

### 리뷰 -- 1건
| ID | 태스크 | 담당 | 예상 | 상태 | 의존성 |
|----|--------|------|------|------|--------|
| T7.14 | Phase 7 코드 리뷰 | reviewer | 2h | ⏳ | T7.1~T7.13 |

---

## Phase 6: Integration & Polish

### 필수 (Required) -- 7건
| ID | 태스크 | 담당 | 예상 | 상태 | 의존성 |
|----|--------|------|------|------|--------|
| T6-1 | ironpost-daemon 통합 구현 | architect + implementer | 4h | ✅ (2026-02-10 완료) | 없음 |
| T6-2 | ironpost-cli 통합 구현 | implementer | 3h | ✅ (2026-02-10 완료) | T6-1 |
| T6-3 | ironpost.toml 통합 설정 파일 | architect + implementer | 2h | ⏳ | T6-1 병행 |
| T6-4 | 리뷰 미반영 수정 (Phase 2~5 C/H/M) | implementer | 6h | ✅ (2026-02-11 완료, 1.5h, 10/10 fixed) | 없음 |
| T6-5 | 루트 README.md 재작성 | writer | 2h | ✅ (2026-02-11 완료, 614 lines, L1 doc) | T6-1, T6-2 |
| T6-6 | CHANGELOG.md 작성 | writer | 1h | ✅ (2026-02-11 완료, 286 lines, Keep a Changelog 1.1.0) | T6-4 |
| T6-12 | Phase 6 리뷰 수정 (C2, H5) | implementer | 2h | ✅ (2026-02-11 완료, 1h, 7/7 fixed) | T6-1, T6-2 |
| T6-13 | ironpost-daemon 문서화 | writer | 1h | ✅ (2026-02-11 완료, 3분, README 439 lines) | T6-1 |
| T6-14 | ironpost-cli 문서화 | writer | 1.5h | ✅ (2026-02-11 완료, 1h, README 782 lines + doc comments) | T6-2 |

### T6-4 상세: 리뷰 미반영 수정 사항 (2026-02-11 완료)

#### 수정 완료 항목 (10건)

##### Critical -- 3건
| 출처 | ID | 설명 | 상태 | 커밋 |
|------|----|------|------|------|
| P3 | H1 | Detector trait &self vs &mut self 불일치 | ✅ Already fixed (Arc<Mutex> 패턴, rule/mod.rs:179) | 이전 |
| P4 | NEW-C2 | canonicalize() TOCTOU -- 루프 밖으로 이동 | ✅ Already fixed (policy.rs:334-339) | 이전 |
| P5 | NEW-C1 | VulnDb lookup String 할당 (핫 패스 성능) | ✅ Already fixed (2단계 HashMap, db.rs:356-369) | 이전 |

##### High -- 6건
| 출처 | ID | 설명 | 상태 | 커밋 |
|------|----|------|------|------|
| P3 | H4 | Syslog PRI 값 범위 검증 (0-191) | ✅ Already fixed (syslog.rs:31,142-149) | 이전 |
| P3 | H6 | 파일 경로 순회(path traversal) 검증 | ✅ Already fixed (config.rs:99-168,219-221) | 이전 |
| P4 | H3 | 와일드카드 필터 임의 컨테이너 격리 | ✅ Fixed (containers.sort_by ID, guard.rs:212-215) | 이번 |
| P4 | NEW-H3 | `all: true` 실행 중인 컨테이너만 필터 | ✅ Already fixed (all:false, docker.rs:268) | 이전 |
| P5 | NEW-H2 | discover_lockfiles TOCTOU (File::open 패턴) | ✅ Already fixed (scanner.rs:668-694) | 이전 |
| P5 | M9 | Path traversal 검증 (Component::ParentDir) | ✅ Already fixed (config.rs:170-174) | 이전 |

##### Won't Fix -- 1건
| 출처 | ID | 설명 | 이유 |
|------|----|------|------|
| P4 | NEW-C1 | container-guard stop()/start() 재시작 불가 | 설계상 제약: alert_rx는 외부 주입, daemon이 재생성 |

#### 기존 수정 완료 (검증만 수행)
- P3-H5: 타임스탬프 휴리스틱 (json.rs:265-285)
- P3-H7: SystemTime → Instant (alert.rs)
- P4-NEW-H1: 에러 variant (docker.rs:70-84)
- P4-NEW-H2: DockerMonitor Arc::clone (guard.rs:179)
- P4-H6: labels 검증 (policy.rs:150-159)
- P5-H2/NEW-H1: CancellationToken (scanner.rs:27,81)
- P5-NEW-H3: unix_to_rfc3339 공유 (sbom/util.rs:42-111)
- P2-H3: adaptive backoff (engine.rs:440-470)
- P3-M2: cleanup 주기 (pipeline.rs:234-354)
- P4-M5: enforcer.rs 삭제 완료
- P2-M7: source_module 동적 설정 (event.rs:275)

### T6-12 상세: Phase 6 Integration 리뷰 수정 사항 (2026-02-11 완료)

#### 수정 완료 항목 (7건)

##### Critical -- 2건
| ID | 설명 | 파일 | 상태 |
|----|------|------|------|
| P6-C1 | TOCTOU in PID File Creation | orchestrator.rs:268-293 | ✅ Fixed (OpenOptions create_new) |
| P6-C2 | Signal Handler expect() | orchestrator.rs:246-259 | ✅ Fixed (return Result) |

##### High -- 5건
| ID | 설명 | 파일 | 상태 |
|----|------|------|------|
| P6-H1 | as Cast Without Overflow Check | status.rs:161-179 | ✅ Fixed (try_from) |
| P6-H2 | Incomplete unsafe SAFETY Comment | status.rs:161-179 | ✅ Fixed (expanded) |
| P6-H3 | expect() in Container Guard | container_guard.rs:67-71 | ✅ Fixed (ok_or_else) |
| P6-H4 | Shutdown Order Backwards | mod.rs:102-135, orchestrator.rs:14-19 | ✅ Fixed (removed .rev()) |
| P6-H5 | Credential Exposure in config show | config.rs:54-116 | ✅ Fixed (redact URLs) |

#### 수정 내용

**C1: TOCTOU 제거**
- `path.exists()` 체크 제거
- `OpenOptions::new().write(true).create_new(true).open(path)` 사용
- `ErrorKind::AlreadyExists`에서 기존 PID 읽어 에러 메시지 구성

**C2: expect() 제거**
- `wait_for_shutdown_signal() -> Result<&'static str>` 시그니처 변경
- `.expect()` → `.map_err()` + `?` 연산자로 에러 전파
- 호출자가 Result 반환하므로 graceful handling 가능

**H1: as 캐스팅 제거**
- `pid as libc::pid_t` → `libc::pid_t::try_from(pid)`
- 변환 실패 시 (pid > i32::MAX) 경고 로그 + false 반환
- 음수 PID 발생 (process group signal) 방지

**H2: SAFETY 주석 보강**
- try_from 바운드 체크 유효성
- signal 0 존재 확인만 수행
- PID 재사용 가능성 (정확성 이슈)
- extern C 메모리 안전성

**H3: expect() 제거**
- `action_rx.expect()` → `action_rx.ok_or_else(|| anyhow!())?`
- builder가 action_rx 반환 안 할 경우 명확한 에러

**H4: 셧다운 순서 수정**
- `stop_all()` 역순 반복 제거 (`.rev()` 삭제)
- 등록 순서대로 정지: eBPF → LogPipeline → SBOM → ContainerGuard
- 생산자 먼저 정지하여 소비자가 채널 드레인 가능
- orchestrator.rs, modules/mod.rs 주석 정확성 개선

**H5: 자격증명 노출 방지**
- `redact_credentials()` 함수 추가
- postgres_url, redis_url에서 user:password 마스킹
- 출력 예: `postgresql://***REDACTED***@host:5432/db`
- 전체/섹션별 config show 모두 적용

#### 테스트
```bash
cargo test -p ironpost-daemon orchestrator  # 7 passed
cargo test -p ironpost-cli commands::status  # 15 passed
cargo test -p ironpost-cli commands::config  # 12 passed
cargo clippy -p ironpost-daemon -p ironpost-cli -- -D warnings  # clean
```

#### 산출물
- 커밋: 8dc6a33 (fix(review): resolve Phase 6 Critical and High severity issues)
- 변경 파일: 6개 (orchestrator.rs, mod.rs, container_guard.rs, status.rs, config.rs, phase-6-integration.md)
- 추가: 525 lines, 삭제: 47 lines
- 소요 시간: 약 1시간

### 고도화 (Enhancement) -- 3건
| ID | 태스크 | 담당 | 예상 | 상태 | 의존성 |
|----|--------|------|------|------|--------|
| T6-7 | Docker Compose 원클릭 데모 | implementer + writer | 3h | ⏳ | T6-1 |
| T6-8 | GitHub Actions CI + 뱃지 | implementer | 2h | ⏳ | 없음 |
| T6-9 | E2E 시나리오 테스트 | tester | 4h | ⏳ | T6-1, T6-4 |

### 보너스 (Bonus) -- 2건
| ID | 태스크 | 담당 | 예상 | 상태 | 의존성 |
|----|--------|------|------|------|--------|
| T6-10 | 데모 GIF / 공격 시뮬레이션 | writer | 2h | ⏳ | T6-7 |
| T6-11 | 벤치마크 문서화 | tester + writer | 3h | ⏳ | T6-4 |

### 문서화 (Documentation) -- 2건
| ID | 태스크 | 담당 | 예상 | 상태 | 의존성 |
|----|--------|------|------|------|--------|
| T6-13 | ironpost-daemon 문서화 | writer | 1h | ✅ (2026-02-11 완료, 3분, README 439 lines) | T6-1 |
| T6-14 | ironpost-cli 문서화 | writer | 1.5h | ✅ (2026-02-11 완료, 1h, README 782 lines + doc comments) | T6-2 |

---

## Phase 5 리뷰 완료
- [x] T5-D1: sbom-scanner 코드 리뷰 (2026-02-10) -- `.reviews/phase-5-sbom-scanner.md`
  - Critical 3건, High 5건, Medium 8건, Low 7건 (총 23건)
  - 주요: VulnDb 파일 크기 미제한(C1), VulnDb O(n) 선형 조회(C2), TOCTOU exists() 검사(C3)
- [x] T5-D2: sbom-scanner 리뷰 지적사항 반영 (2026-02-10, 22:00-23:15, 75분) -- Critical 3건 + High 4건 수정 완료
  - ✅ C1: VulnDb 파일 크기 제한 (50MB) + 엔트리 수 제한 (1M)
  - ✅ C2: VulnDb HashMap 인덱싱 (O(1) lookup)
  - ✅ C3: TOCTOU 제거 (exists() 체크 제거)
  - ✅ H1: scan_directory 공유 함수 추출 (130줄 중복 제거)
  - ✅ H3: Stopped 상태에서 start() 거부
  - ✅ H4: scan_dirs 경로 검증 (".." 패턴 거부)
  - ✅ H5: VulnDb 엔트리 수 상한 (C1에 포함)
  - ⚠️ H2: graceful shutdown -> Phase 6로 연기
- [x] T5-D3: sbom-scanner 재리뷰 (2026-02-10) -- `.reviews/phase-5-sbom-scanner.md` (덮어씀)
  - 이전 수정 7건 모두 검증 완료 (C1-C3, H1, H3-H5)
  - 새로운 발견 21건: Critical 1건, High 3건, Medium 9건, Low 8건
  - NEW-C1: VulnDb lookup 호출마다 String 할당 (핫 패스 성능)
  - NEW-H1: 주기적 태스크 취소 메커니즘 부재
  - NEW-H2: metadata-to-read TOCTOU 갭
  - NEW-H3: unix_to_rfc3339 55줄 중복 (cyclonedx/spdx)

## Phase 3 설계 완료 항목
- [x] `.knowledge/log-pipeline-design.md` -- 전체 설계 문서
- [x] `error.rs`: LogPipelineError (Parse, RuleLoad, RuleValidation, Collector, Buffer, Config, Channel, Io, Regex)
- [x] `config.rs`: PipelineConfig + PipelineConfigBuilder + DropPolicy
- [x] `parser/mod.rs`: ParserRouter (자동 감지 + 형식 지정 파싱)
- [x] `parser/syslog.rs`: SyslogParser (RFC 5424 + RFC 3164 fallback, LogParser trait)
- [x] `parser/json.rs`: JsonLogParser (필드 매핑, 중첩 필드, LogParser trait)
- [x] `collector/mod.rs`: RawLog, CollectorSet, CollectorStatus
- [x] `collector/file.rs`: FileCollector (파일 감시 + 로테이션 감지)
- [x] `collector/syslog_udp.rs`: SyslogUdpCollector (UDP syslog 수신)
- [x] `collector/syslog_tcp.rs`: SyslogTcpCollector (TCP syslog 수신 + 프레이밍)
- [x] `collector/event_receiver.rs`: EventReceiver (PacketEvent -> RawLog 변환)
- [x] `rule/types.rs`: DetectionRule, DetectionCondition, FieldCondition, ConditionModifier, ThresholdConfig, RuleStatus
- [x] `rule/loader.rs`: RuleLoader (YAML 디렉토리 스캔 + 파싱 + 검증)
- [x] `rule/matcher.rs`: RuleMatcher (조건 평가 + 정규식 캐싱)
- [x] `rule/mod.rs`: RuleEngine (매칭 코디네이터 + threshold 카운터 + Detector trait 구현)
- [x] `buffer.rs`: LogBuffer (VecDeque + 드롭 정책 + 배치 드레인)
- [x] `alert.rs`: AlertGenerator (중복 제거 + 속도 제한 + AlertEvent 생성)
- [x] `pipeline.rs`: LogPipeline + LogPipelineBuilder (Pipeline trait 구현)
- [x] `lib.rs`: pub API re-export

## Phase 3 구현 완료 항목
- [x] T3-1: 파서 구현 (2026-02-09, 48 tests)
- [x] T3-2: 수집기 구현 (2026-02-09, 24 tests - file/UDP/TCP/event)
- [x] T3-3: 규칙 엔진 완성 (2026-02-09, 9 tests + 5 example rules)
- [x] T3-4: 버퍼/알림 검증 (2026-02-09, 완료 - 이미 구현됨)
- [x] T3-5: 파이프라인 오케스트레이션 (2026-02-09, timer-based flush + full processing loop)

## Phase 3 구현 완료 항목 (추가)
- [x] T3-6: 테스트 강화 (2026-02-09, 266 total tests - 253 unit + 13 integration)

## Phase 3 리뷰 완료
- [x] 코드 리뷰 (2026-02-09) -- `.reviews/phase-3-log-pipeline.md`
  - Critical 10건, High 8건, Medium 11건, Low 9건 (총 38건)
  - ✅ Critical 10건 수정 완료 (C1-C10)
  - ✅ High 3건 수정 완료 (H2, H3, H8)
  - 주요 수정: Arc<Mutex> -> AtomicU64, 배치 처리 중복 제거, as 캐스팅 제거, OOM 방어, ReDoS 방어, HashMap 자동 정리

## Phase 3 구현 완료 항목 (추가)
- [x] T3-7: 리뷰 지적사항 반영 (2026-02-09, Critical 10건 + High 3건 수정 완료)
- [x] T3-8: 추가 수정 사항 (2026-02-09, H-NEW-1/2, M-NEW-1 - 로그 주입/재시작/IP 추출, 25분 소요)
- [x] T3-9: 통합 테스트 추가 (2026-02-09, 6개 통합 테스트 추가 - collector->pipeline flow/restart/JSON, 총 280 tests)

## Phase 2 설계 완료 항목
- [x] ebpf-common: 공유 `#[repr(C)]` 타입 (BlocklistValue, ProtoStats, PacketEventData)
- [x] ebpf/main.rs: XDP 패킷 파싱 (Eth->IPv4->TCP/UDP) + HashMap 조회 + PerCpuArray 통계 + RingBuf 이벤트
- [x] config.rs: FilterRule, RuleAction, EngineConfig (from_core, add/remove_rule, ip_rules)
- [x] engine.rs: EbpfEngine + EbpfEngineBuilder + Pipeline trait (start/stop/health_check)
- [x] stats.rs: TrafficStats + ProtoMetrics + RawTrafficSnapshot (update, reset, to_prometheus)
- [x] detector.rs: SynFloodDetector + PortScanDetector (Detector trait) + PacketDetector 코디네이터

## Phase 2 리뷰 완료
- [x] 코드 리뷰 (2026-02-09) -- `.reviews/phase-2-ebpf.md`
  - Critical 5건, High 6건, Medium 9건, Low 8건 (총 28건)
  - 주요: unsafe 정렬 미보장, 메모리 DoS, 입력 검증 부재, as 캐스팅 위반
  - ✅ Critical 5건 수정 완료 (C1-C6)
  - ✅ High 3건 수정 완료 (H1, H2, H4, H5 중 핵심 4건)
  - ✅ Medium 1건 수정 완료 (M3)

## Phase 4 설계+스캐폴딩 완료 항목 (Phase 4-A)
- [x] T4-A1: `.knowledge/container-guard-design.md` -- 전체 설계 문서
- [x] T4-A2: `Cargo.toml` -- bollard, ironpost-core, tokio, thiserror, tracing, serde, uuid
- [x] T4-A3: `error.rs` -- ContainerGuardError (8 variants) + IronpostError 변환
- [x] T4-A4: `config.rs` -- ContainerGuardConfig + Builder + from_core() + validate()
- [x] T4-A5: `event.rs` -- ContainerEvent + ContainerEventKind + Event trait 구현
- [x] T4-A6: `docker.rs` -- DockerClient trait + BollardDockerClient + MockDockerClient
- [x] T4-A7: `policy.rs` -- SecurityPolicy + TargetFilter + PolicyEngine + glob 매칭
- [x] T4-A8: `isolation.rs` -- IsolationAction + IsolationExecutor (재시도 + 타임아웃)
- [x] T4-A9: `monitor.rs` -- DockerMonitor (폴링 + 캐싱 + partial ID 조회)
- [x] T4-A10: `guard.rs` -- ContainerGuard (Pipeline trait) + ContainerGuardBuilder
- [x] T4-A11: `lib.rs` -- 모듈 re-export

## Phase 4 구현 완료 (Phase 4-B)
- [x] T4-B1: TOML 정책 파일 로딩 (2026-02-10, load_policy_from_file + load_policies_from_dir)
- [x] T4-B2: 컨테이너 모니터링 (2026-02-10, poll-based monitoring with cache)
- [x] T4-B3: 컨테이너-알림 매핑 (2026-02-10, policy evaluation in guard loop)
- [x] T4-B4: 통합 테스트 (2026-02-10, 98 unit/integration tests)
- [x] T4-B5: 기본 구현 완료 (2026-02-10, retry + timeout + action events)

## Phase 4 테스트 강화 (Phase 4-C)
- [x] T4-C1: 엣지 케이스, 통합 테스트, 격리 엔진 테스트 추가 (2026-02-10, 75분, 174 tests total)
- [x] T4-C2: 추가 엣지 케이스 및 통합 테스트 (2026-02-10, 18:20-19:15, 55분, 202 tests total)

## Phase 4 리뷰
- [x] T4-D1: 초기 코드 리뷰 (2026-02-10) -- `.reviews/phase-4-container-guard.md`
  - Critical 5건, High 7건, Medium 8건, Low 9건 (총 29건)
  - 주요: 무제한 캐시(C1), 파일 크기 미제한(C2), 정책 수 미제한(C3), 재시작 불가(C4), 전체 컨테이너 격리 위험(H3)
- [x] T4-D2: rustc/clippy 경고 제거 + 초기 리뷰 수정 반영 (2026-02-10)
  - C1, C2, C3, C5, H1, H2, H5 수정 완료
- [x] T4-D3: 재리뷰 (2026-02-10) -- `.reviews/phase-4-container-guard.md` (덮어씀)
  - 초기 리뷰 11건 resolved, 새로운 발견 16건
  - Critical 2건 (NEW-C1: stop/restart 불가, NEW-C2: canonicalize TOCTOU)
  - High 6건 (H3,H4,H6,NEW-H1,NEW-H2,NEW-H3)
  - Medium 11건, Low 10건 (총 27건)
  - 수정 대기

## Phase 4 문서화 (Phase 4-E)
- [x] T4-E1: container-guard 문서화 (2026-02-10, 19:45-21:30, 105분)
  - Doc comments 작성 (config, error, event, docker 모듈)
  - README.md 재작성 (480+ 라인, 아키텍처/정책/예시/제한사항 전체 포함)
  - docs/architecture.md 업데이트 (container-guard 섹션 추가)

## Phase 5 테스트 강화 완료 (Phase 5-C)
- [x] T5-C1: SBOM scanner 테스트 강화 (2026-02-10, 15:27-15:35, 8분, 183 total tests)
  - Cargo parser edge cases (11 new tests): malformed TOML, very long names/versions, duplicates, unicode, special chars
  - NPM parser edge cases (13 new tests): malformed JSON, missing fields, scoped packages, lockfile v2/v3
  - VulnDb edge cases (13 new tests): malformed JSON, invalid severity, large entry count, multiple vulns
  - Version matching edge cases (14 new tests): wildcards, very long versions, build metadata, unicode, gaps
  - VulnMatcher edge cases (9 new tests): empty graph/db, wrong ecosystem, multiple vulns, large graphs
  - Integration tests (10 new CVE tests): exact match, range match, no fixed version, severity filtering, clean scan
  - Total: 165 unit + 10 CVE integration + 6 existing integration + 2 doc tests = 183 tests
  - All tests passing, no clippy warnings
  - commit: (will be added after commit)

## Phase 5 설계+스캐폴딩 완료 항목 (Phase 5-A)
- [x] T5-A1: 설계 문서 (`.knowledge/sbom-scanner-design.md`, 14 sections)
- [x] T5-A2: `Cargo.toml` -- ironpost-core, tokio, serde, serde_json, toml, tracing, thiserror, uuid (workspace), semver
- [x] T5-A3: `error.rs` -- SbomScannerError (9 variants) + IronpostError 변환 (13 tests)
- [x] T5-A4: `config.rs` -- SbomScannerConfig + Builder + from_core() + validate() (16 tests)
- [x] T5-A5: `event.rs` -- ScanEvent + Event trait impl (4 tests)
- [x] T5-A6: `types.rs` -- Ecosystem, Package, PackageGraph, SbomFormat, SbomDocument (12 tests)
- [x] T5-A7: `parser/mod.rs` -- LockfileParser trait + LockfileDetector (5 tests)
- [x] T5-A8: `parser/cargo.rs` -- CargoLockParser (Cargo.lock TOML 파싱, 6 tests)
- [x] T5-A9: `parser/npm.rs` -- NpmLockParser (package-lock.json v2/v3, 8 tests)
- [x] T5-A10: `sbom/mod.rs` -- SbomGenerator (3 tests)
- [x] T5-A11: `sbom/cyclonedx.rs` -- CycloneDX 1.5 JSON 생성 (5 tests)
- [x] T5-A12: `sbom/spdx.rs` -- SPDX 2.3 JSON 생성 (6 tests)
- [x] T5-A13: `vuln/mod.rs` -- VulnMatcher + ScanFinding + ScanResult + SeverityCounts (5 tests)
- [x] T5-A14: `vuln/db.rs` -- VulnDb + VulnDbEntry + VersionRange (8 tests)
- [x] T5-A15: `vuln/version.rs` -- SemVer 버전 범위 비교 (10 tests)
- [x] T5-A16: `scanner.rs` -- SbomScanner (Pipeline impl) + SbomScannerBuilder (8 tests)
- [x] T5-A17: `lib.rs` -- 모듈 선언 + pub API re-export
- [x] T5-A18: `README.md` -- 크레이트 문서 (아키텍처 다이어그램, 설정 예시, DB 구조)
- [x] T5-A19: Core 크레이트 업데이트 (MODULE_SBOM_SCANNER, EVENT_TYPE_SCAN 상수 추가)

## 최근 완료
- [P6] T6-TEST-FIX: daemon & CLI 테스트 컴파일 에러 수정 완료 (2026-02-10, 45분)
  - ✅ config_tests.rs 수정 (16 tests, core 필드명 업데이트, 환경변수 race condition 해결)
  - ✅ orchestrator_tests.rs 수정 (11 tests, Debug trait 의존성 제거)
  - ✅ channel_integration_tests.rs 수정 (13 tests, PacketEvent/PacketInfo 구조 변경, bytes 추가)
  - ✅ module_init_tests.rs 수정 (10 tests, SBOM validation 에러 해결)
  - ✅ 전체 198개 테스트 통과 (daemon 79 + cli 119)
  - ✅ clippy 통과 (no warnings)
  - 📝 산출물: 5개 파일 수정, 50개 테스트 수정
- [P6] T6-CLI-TEST: ironpost-daemon & CLI 테스트 작성 완료 (2026-02-10 23:10-00:00, 50분)
  - ✅ ironpost-daemon 컴파일 에러 수정 (uuid, BoxFuture import, ActionEvent 구조)
  - ✅ PID 파일 테스트 13개 추가 (생성, 삭제, 동시성, 경계값, 유니코드, symlink)
  - ✅ 채널 통합 테스트 작성 (PacketEvent, AlertEvent, ActionEvent)
  - ✅ CLI 설정 커맨드 테스트 11개 추가 (TOML 파싱, 엣지 케이스, 유니코드)
  - ✅ ironpost-cli 전체 108개 테스트 통과
  - ✅ 새 테스트 24개 (daemon 13 + CLI 11) 추가
  - 📝 산출물: pid_file_tests.rs, channel_integration_tests.rs, config_command_tests.rs
- [P6] T6-2: ironpost-cli 구현 완료 (5 commands, colored output, 수정 포함 ~1시간 30분, 2026-02-10 20:50-22:30, 100분)
- [P6] T6-C: ironpost-daemon 구현 완료 (8 files, 923 lines, graceful shutdown, 2026-02-10 20:30-22:00, 90분)
- [P6] T6-B: ironpost-daemon 스캐폴딩 생성 (2026-02-10 19:44, 45분)
- [P6] T6-A: ironpost-daemon 설계 문서 작성 (419 lines, 2026-02-10 19:14, 30분)
- [P5] T5-E1: sbom-scanner 문서화 완료 (README 580+ lines + architecture + module-guide, 2026-02-10 16:58, 4분)
- [P5] T5-D3: sbom-scanner 재리뷰 완료 (21건 발견, 이전 수정 7건 검증, 2026-02-10)
- [P5] T5-D2: sbom-scanner 리뷰 수정 완료 (C3+H4 완료, 183 tests passing, 2026-02-10 23:15, 75분)
- [P5] T5-D1: sbom-scanner 코드 리뷰 완료 (23건 발견, 2026-02-10)
- [P5] T5-C1: SBOM scanner 테스트 강화 완료 (60 new tests, 183 total, 2026-02-10 15:35, 8분)
- [P5] Phase 5-A: sbom-scanner 설계+스캐폴딩 완료 (19 tasks, 16 source files, 109 tests, 2026-02-10)
- [P4] T4-E1: container-guard 문서화 완료 (doc comments + 480+ lines README + architecture.md, 2026-02-10 21:30, 105분)
- [P4] T4-D3: container-guard 재리뷰 완료 (27건 발견, 11건 resolved, 2026-02-10)
- [P4] T4-D2: container-guard 초기 리뷰 수정 반영 (C1-C5,H1,H2,H5 수정, 2026-02-10)
- [P4] T4-D1: container-guard 코드 리뷰 완료 (29건 발견, 2026-02-10)
- [P4] T4-C2: container-guard 추가 엣지 케이스 테스트 (28 new tests, 202 total, 2026-02-10 19:15, 55분)
- [P4] T4-C1: container-guard 테스트 강화 완료 (76 new tests, 174 total, 2026-02-10 16:45, 75분)
- [P4] Phase 4-B: container-guard 구현 완료 (TOML 정책 로딩, 98 tests, 2026-02-10)
- [P3] T3-9: 통합 테스트 추가 완료 (6개 통합 시나리오, 280 total tests, 2026-02-09 14:10)
- [P3] T3-8: 추가 수정 사항 완료 (로그 주입 경로 + 재시작 지원 + IP 추출, 2026-02-09 23:55)
- [P3] T3-7: 리뷰 지적사항 반영 완료 (Critical 10건 + High 3건 수정, 2026-02-09)
- [P3] 리뷰: phase-3-log-pipeline 코드 리뷰 완료 (38건 발견, 2026-02-09 22:45)
- [P3] T3-6: 테스트 강화 완료 (266 total tests, 2026-02-09)
- [P3] T3-5: 파이프라인 오케스트레이션 완료 (timer-based flush, Arc/Mutex 공유, 2026-02-09)
- [P3] T3-3: 규칙 엔진 완성 (5 example YAML rules + integration tests, 2026-02-09)
- [P3] T3-2: 수집기 구현 완료 (file/syslog UDP/TCP/event, 24 tests, commit 37b4031, 2026-02-09)
- [P3] T3-1: 파서 구현 완료 (RFC 5424/3164 syslog + JSON, 48 tests, commit e80e91d, 2026-02-09)
- [P3] 설계: log-pipeline 스캐폴딩 완료 (설계 문서 + 12개 소스 파일 + 타입/trait 스켈레톤)
- [P2] 구현: phase-2-ebpf 리뷰 지적사항 수정 완료 (Critical 5건, High 4건, Medium 1건)
- [P2] 리뷰: phase-2-ebpf 코드 리뷰 완료 (28건 발견)
- [P2] 설계: ebpf-common 크레이트 + 커널 XDP 프로그램 + 유저스페이스 API 시그니처
- [P1] error.rs: IronpostError + 7개 도메인 에러
- [P1] event.rs: EventMetadata + Event trait + 4개 이벤트 타입
- [P1] pipeline.rs: Pipeline trait + HealthStatus + Detector/LogParser/PolicyEnforcer
- [P1] config.rs: IronpostConfig TOML 파싱 + 환경변수 오버라이드 + 유효성 검증
- [P1] types.rs: PacketInfo/LogEntry/Alert/Severity/ContainerInfo/Vulnerability

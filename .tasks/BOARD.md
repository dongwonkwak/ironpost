# Ironpost 태스크 보드
> 최종 업데이트: 2026-02-10

## 진행 요약
| Phase | 전체 | 완료 | 진행중 | 대기 | 진행률 |
|-------|------|------|--------|------|--------|
| 0-setup | 1 | 1 | 0 | 0 | ✅ |
| 1-core | 6 | 6 | 0 | 0 | ✅ |
| 2-ebpf | 5 | 5 | 0 | 6 | ✅ (설계+구현+리뷰+수정 완료) |
| 3-log | 12 | 13 | 0 | 5 | ✅ (설계+구현+리뷰+수정 완료) |
| 4-container | 17 | 17 | 0 | 0 | ✅ (설계+구현+테스트+리뷰 완료, 202 tests) |
| 5-sbom | 24 | 24 | 0 | 4 | 🔄 (Phase 5-B 구현 완료, 118 tests) |
| 6-polish | - | - | - | - | ⏳ |

## 블로커
- 없음

## 현재 진행중
- 없음 (Phase 5-B 완료, Phase 5-C 대기)

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
  - 주요 수정: Arc<Mutex> → AtomicU64, 배치 처리 중복 제거, as 캐스팅 제거, OOM 방어, ReDoS 방어, HashMap 자동 정리

## Phase 3 구현 완료 항목 (추가)
- [x] T3-7: 리뷰 지적사항 반영 (2026-02-09, Critical 10건 + High 3건 수정 완료)
- [x] T3-8: 추가 수정 사항 (2026-02-09, H-NEW-1/2, M-NEW-1 - 로그 주입/재시작/IP 추출, 25분 소요)
- [x] T3-9: 통합 테스트 추가 (2026-02-09, 6개 통합 테스트 추가 - collector→pipeline flow/restart/JSON, 총 280 tests)

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

## Phase 5 설계+스캐폴딩 완료 항목 (Phase 5-A)
- [x] T5-A1: 설계 문서 (`.knowledge/sbom-scanner-design.md`, 14 sections)
- [x] T5-A2: `Cargo.toml` -- ironpost-core, tokio, serde, serde_json, toml, tracing, thiserror, uuid, semver
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

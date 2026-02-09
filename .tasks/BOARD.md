# Ironpost 태스크 보드
> 최종 업데이트: 2026-02-09

## 진행 요약
| Phase | 전체 | 완료 | 진행중 | 대기 | 진행률 |
|-------|------|------|--------|------|--------|
| 0-setup | 1 | 1 | 0 | 0 | ✅ |
| 1-core | 6 | 6 | 0 | 0 | ✅ |
| 2-ebpf | 5 | 5 | 0 | 6 | ✅ (설계+구현+리뷰 완료) |
| 3-log | 12 | 12 | 0 | 6 | 🔄 (스캐폴딩 완료, 구현 대기) |
| 4-container | - | - | - | - | ⏳ |
| 5-sbom | - | - | - | - | ⏳ |
| 6-polish | - | - | - | - | ⏳ |

## 블로커
- 없음

## 현재 진행중
- Phase 3 T3-1 완료, T3-2 대기 중

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

## Phase 3 구현 대기 항목
- [ ] T3-7: 리뷰 지적사항 반영

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

## 최근 완료
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

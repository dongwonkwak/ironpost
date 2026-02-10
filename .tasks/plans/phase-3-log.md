# Phase 3: 로그 파이프라인 구현

## 목표
로그 수집, 파싱, YAML 규칙 매칭, 알림 생성 파이프라인을 구현합니다.
core 크레이트의 Pipeline, LogParser, Detector trait을 구현하며,
ebpf-engine 이벤트를 tokio::mpsc로 수신하여 처리합니다.

## 선행 조건
- [x] Phase 0: 프로젝트 스캐폴딩
- [x] Phase 1: Core 크레이트 (Pipeline, Event, Error, Config, Types)
- [x] Phase 2: eBPF 엔진 (PacketEvent 생성, mpsc 채널 출력)

## 설계 산출물 (Phase 3-A: 스캐폴딩)
- [x] `.knowledge/log-pipeline-design.md` -- 전체 설계 문서
- [x] `crates/log-pipeline/Cargo.toml` -- 의존성 설정
- [x] `crates/log-pipeline/src/error.rs` -- LogPipelineError 도메인 에러
- [x] `crates/log-pipeline/src/config.rs` -- PipelineConfig + 빌더
- [x] `crates/log-pipeline/src/parser/` -- ParserRouter, SyslogParser, JsonLogParser
- [x] `crates/log-pipeline/src/collector/` -- RawLog, FileCollector, SyslogUdp/Tcp, EventReceiver
- [x] `crates/log-pipeline/src/rule/` -- RuleEngine, DetectionRule, RuleMatcher, RuleLoader
- [x] `crates/log-pipeline/src/buffer.rs` -- LogBuffer (VecDeque, 드롭 정책)
- [x] `crates/log-pipeline/src/alert.rs` -- AlertGenerator (중복 제거, 속도 제한)
- [x] `crates/log-pipeline/src/pipeline.rs` -- LogPipeline + LogPipelineBuilder (Pipeline trait)
- [x] `crates/log-pipeline/src/lib.rs` -- pub API 및 re-export

## 구현 태스크 (Phase 3-B: 구현)

### T3-1: 파서 구현 (예상: 3h) ✅
- [x] `parser/syslog.rs`: RFC 5424 완전 파싱 (PRI, VERSION, TIMESTAMP, HOSTNAME, APP-NAME, PROCID, MSGID, SD, MSG)
- [x] `parser/syslog.rs`: RFC 3164 (BSD) fallback 파싱
- [x] `parser/syslog.rs`: Structured Data 추출 (SD-ID, SD-PARAM)
- [x] `parser/syslog.rs`: chrono 기반 타임스탬프 파싱 (RFC 3339, BSD format)
- [x] `parser/json.rs`: 중첩 JSON 필드 추출 (dot notation + 재귀 평탄화)
- [x] `parser/json.rs`: chrono 기반 타임스탬프 파싱 (RFC 3339, Unix seconds/milliseconds)
- [x] `parser/mod.rs`: 자동 감지 로직 (등록된 파서 순차 시도)
- [x] 단위 테스트: 48개 테스트 (syslog: 28개, json: 20개)

### T3-2: 수집기 구현 (예상: 4h) ✅
- [x] `collector/file.rs`: 비동기 파일 읽기 + offset 추적
- [x] `collector/file.rs`: inode 기반 로테이션 감지
- [x] `collector/file.rs`: truncation 감지
- [x] `collector/syslog_udp.rs`: tokio::net::UdpSocket 바인드 + recv_from 루프
- [x] `collector/syslog_tcp.rs`: tokio::net::TcpListener + 연결 핸들링
- [x] `collector/syslog_tcp.rs`: newline 프레이밍 + 연결 타임아웃
- [x] `collector/event_receiver.rs`: PacketEvent -> RawLog 변환 + 채널 루프
- [x] 단위 테스트: 24개 테스트 (file: 11, udp: 4, tcp: 4, event: 5)

### T3-3: 규칙 엔진 구현 (예상: 3h) ✅
- [x] `rule/loader.rs`: 디렉토리 스캔 + 비동기 파일 로드 (이미 완료)
- [x] `rule/matcher.rs`: 모든 ConditionModifier 구현 (이미 완료)
- [x] `rule/mod.rs`: threshold 카운터 윈도우 관리 (이미 완료)
- [x] `rule/mod.rs`: Detector trait 구현 확인 (완료)
- [x] 실제 YAML 규칙 파일 예시 작성 (examples/rules/) -- 5개 규칙 작성
- [x] 단위 테스트: 매칭 로직 + threshold + 경계 케이스 -- 9개 테스트 (기존 4 + 신규 5)

### T3-4: 버퍼/알림 검증 (예상: 1h) ✅
- [x] `buffer.rs`: 검증 완료 - 이미 타이머 로직용 메서드 제공 (should_flush, drain_batch)
- [x] `alert.rs`: 검증 완료 - dedup + rate limit 완전 구현됨

### T3-5: 파이프라인 오케스트레이션 (예상: 4h) ✅
- [x] `pipeline.rs`: start() -- 메인 처리 루프 스폰 (Arc/Mutex 공유)
- [x] `pipeline.rs`: 메인 처리 루프 (recv -> buffer -> parse -> match -> alert)
- [x] `pipeline.rs`: 타이머 기반 플러시 (tokio::time::interval + elapsed 체크)
- [x] `pipeline.rs`: stop() -- graceful drain + 태스크 취소
- [x] `pipeline.rs`: health_check() -- 버퍼 사용률 기반
- [x] `alert.rs`: AlertEvent 생성 + mpsc 전송 (완료)
- [x] 모든 accessor 메서드를 async로 변경 (Arc/Mutex 때문)

### T3-6: 리뷰 지적사항 반영 (예상: 2h)
- [ ] Phase 1 W2: Detector trait이 LogEntry만 입력 -- RuleEngine에서 적절히 대응
- [ ] Phase 1 W7: LogEntry.fields Vec<(String,String)> -> 성능 고려 (이터레이터 기반 검색)
- [ ] Phase 2 M7: AlertEvent source_module 이슈 대응
- [ ] Phase 2 M13: core Detector trait의 LogEntry 입력 제한 대응
- [x] cargo fmt + cargo clippy -- -D warnings 통과 확인 ✅

### T3-7: 테스트 강화 (예상: 2h)
- [ ] 경계 케이스 테스트 (빈 입력, 최대 크기, 유니코드 등)
- [ ] 성능 벤치마크 (파싱 throughput, 규칙 매칭 속도)
- [ ] 통합 테스트: ebpf-engine -> log-pipeline 채널 연결 시뮬레이션

## 산출물 체크리스트
- [x] 모든 public API에 doc comment (스캐폴딩 단계에서 완료)
- [x] cargo fmt 통과 ✅
- [x] cargo clippy -- -D warnings 통과 ✅
- [x] cargo test 통과 (143+ tests expected)
- [ ] 설계 문서 최신화 (구현 완료 후 필요시)

## 소요 시간 (실제)
- T3-1: 파서 구현 (3h)
- T3-2: 수집기 구현 (4h)
- T3-3: 규칙 엔진 + 예시 (1.5h)
- T3-4: 버퍼/알림 검증 (0.5h)
- T3-5: 파이프라인 오케스트레이션 (4h)
- **총 소요: ~13h** (예상 18h 대비 효율적)

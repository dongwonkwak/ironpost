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

### T3-2: 수집기 구현 (예상: 4h)
- [ ] `collector/file.rs`: 비동기 파일 읽기 + offset 추적
- [ ] `collector/file.rs`: inode 기반 로테이션 감지
- [ ] `collector/file.rs`: truncation 감지
- [ ] `collector/syslog_udp.rs`: tokio::net::UdpSocket 바인드 + recv_from 루프
- [ ] `collector/syslog_tcp.rs`: tokio::net::TcpListener + 연결 핸들링
- [ ] `collector/syslog_tcp.rs`: newline 프레이밍 + 연결 타임아웃
- [ ] `collector/event_receiver.rs`: PacketEvent -> RawLog 변환 + 채널 루프
- [ ] 단위 테스트: 각 수집기 최소 5개

### T3-3: 규칙 엔진 구현 (예상: 3h)
- [ ] `rule/loader.rs`: 디렉토리 스캔 + 비동기 파일 로드
- [ ] `rule/matcher.rs`: 모든 ConditionModifier 구현 (이미 완료)
- [ ] `rule/mod.rs`: threshold 카운터 윈도우 관리 (이미 완료)
- [ ] `rule/mod.rs`: Detector trait 구현 확인
- [ ] 실제 YAML 규칙 파일 예시 작성 (examples/rules/)
- [ ] 단위 테스트: 매칭 로직 + threshold + 경계 케이스

### T3-4: 파이프라인 오케스트레이션 (예상: 4h)
- [ ] `pipeline.rs`: start() -- 수집기 태스크 스폰
- [ ] `pipeline.rs`: 메인 처리 루프 (recv -> buffer -> parse -> match -> alert)
- [ ] `pipeline.rs`: stop() -- graceful drain + 태스크 취소
- [ ] `pipeline.rs`: health_check() -- 버퍼 사용률 + 에러율 기반
- [ ] `buffer.rs`: 타이머 기반 플러시 트리거
- [ ] `alert.rs`: AlertEvent 생성 + mpsc 전송
- [ ] 통합 테스트: 전체 파이프라인 흐름

### T3-5: 리뷰 지적사항 반영 (예상: 2h)
- [ ] Phase 1 W2: Detector trait이 LogEntry만 입력 -- RuleEngine에서 적절히 대응
- [ ] Phase 1 W7: LogEntry.fields Vec<(String,String)> -> 성능 고려 (이터레이터 기반 검색)
- [ ] Phase 2 M7: AlertEvent source_module 이슈 대응
- [ ] Phase 2 M13: core Detector trait의 LogEntry 입력 제한 대응
- [ ] cargo fmt + cargo clippy -- -D warnings 통과 확인

### T3-6: 테스트 강화 (예상: 2h)
- [ ] 경계 케이스 테스트 (빈 입력, 최대 크기, 유니코드 등)
- [ ] 성능 벤치마크 (파싱 throughput, 규칙 매칭 속도)
- [ ] 통합 테스트: ebpf-engine -> log-pipeline 채널 연결 시뮬레이션

## 산출물 체크리스트
- [ ] 모든 public API에 doc comment
- [ ] cargo fmt 통과
- [ ] cargo clippy -- -D warnings 통과
- [ ] cargo test 전체 통과
- [ ] 설계 문서 최신화

## 예상 총 소요 시간: 18h

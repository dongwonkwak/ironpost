# ironpost-log-pipeline

Ironpost 로그 파이프라인 — 로그 수집, 파싱, 룰 매칭, 알림 생성을 담당하는 고성능 비동기 파이프라인입니다.

## 개요

`ironpost-log-pipeline`은 다양한 소스에서 로그를 수집하고, 파싱하여 통합 형식으로 저장하며,
YAML 기반 탐지 규칙을 적용하여 보안 이벤트를 감지하는 완전한 로그 처리 시스템입니다.

### 주요 기능

- **다중 소스 수집**: 파일 감시(tail), Syslog UDP/TCP, eBPF PacketEvent 수신
- **자동 형식 감지**: Syslog RFC 5424/3164, JSON 로그 자동 인식 및 파싱
- **YAML 룰 엔진**: Sigma 스타일의 간소화된 탐지 규칙 (필드 조건, threshold, 정규식)
- **알림 최적화**: 중복 제거, 속도 제한, IP 추출
- **인메모리 버퍼**: 배치 플러시, 오버플로우 정책(drop oldest / drop newest)

## 아키텍처

```text
┌────────────────────────────────────────────────────────────────┐
│  Collectors (다중 소스)                                        │
│  ├── FileCollector      (tail -f /var/log/*.log)              │
│  ├── SyslogUdpCollector (UDP 514)                             │
│  ├── SyslogTcpCollector (TCP 514 + octet framing)             │
│  └── EventReceiver      (PacketEvent from ebpf-engine)         │
└──────┬─────────────────────────────────────────────────────────┘
       │ RawLog
       ▼
┌────────────────────────────────────────────────────────────────┐
│  LogBuffer (배치 버퍼)                                         │
│  └── VecDeque<RawLog>  (drop 정책: oldest | newest)           │
└──────┬─────────────────────────────────────────────────────────┘
       │ batch flush (interval or capacity)
       ▼
┌────────────────────────────────────────────────────────────────┐
│  ParserRouter (자동 감지)                                      │
│  ├── SyslogParser    (RFC 5424 + RFC 3164 fallback)           │
│  └── JsonLogParser   (필드 매핑 + 중첩 flatten)                │
└──────┬─────────────────────────────────────────────────────────┘
       │ LogEntry
       ▼
┌────────────────────────────────────────────────────────────────┐
│  RuleEngine (YAML 규칙 매칭)                                   │
│  ├── FieldCondition   (equals, contains, regex, exists)       │
│  ├── ThresholdConfig  (count, timeframe, group_by)            │
│  └── RuleMatcher      (정규식 캐싱, ReDoS 방어)                │
└──────┬─────────────────────────────────────────────────────────┘
       │ RuleMatch
       ▼
┌────────────────────────────────────────────────────────────────┐
│  AlertGenerator (중복 제거 + 속도 제한)                        │
│  ├── Dedup window     (동일 룰 ID 기준)                       │
│  ├── Rate limiting    (분당 룰별 최대 개수)                    │
│  └── IP extraction    (src_ip, dst_ip 필드 추출)              │
└──────┬─────────────────────────────────────────────────────────┘
       │ AlertEvent
       ▼
     mpsc::Sender<AlertEvent> → container-guard / storage
```

## 프로젝트 구조

```text
ironpost-log-pipeline/
├── src/
│   ├── collector/          # 로그 수집기
│   │   ├── mod.rs          # CollectorSet, RawLog
│   │   ├── file.rs         # FileCollector (notify 기반 tail)
│   │   ├── syslog_udp.rs   # SyslogUdpCollector (UDP 514)
│   │   ├── syslog_tcp.rs   # SyslogTcpCollector (TCP 514 + framing)
│   │   └── event_receiver.rs  # EventReceiver (PacketEvent → RawLog)
│   ├── parser/             # 로그 파서
│   │   ├── mod.rs          # ParserRouter (자동 감지)
│   │   ├── syslog.rs       # SyslogParser (RFC 5424 + 3164)
│   │   └── json.rs         # JsonLogParser (필드 매핑)
│   ├── rule/               # 규칙 엔진
│   │   ├── mod.rs          # RuleEngine (Detector trait 구현)
│   │   ├── types.rs        # DetectionRule, FieldCondition, ThresholdConfig
│   │   ├── loader.rs       # RuleLoader (YAML 로드 + 검증)
│   │   └── matcher.rs      # RuleMatcher (조건 평가 + 정규식 캐싱)
│   ├── buffer.rs           # LogBuffer (VecDeque + drop 정책)
│   ├── alert.rs            # AlertGenerator (dedup + rate limit)
│   ├── pipeline.rs         # LogPipeline + LogPipelineBuilder
│   ├── config.rs           # PipelineConfig + PipelineConfigBuilder
│   └── error.rs            # LogPipelineError
└── README.md
```

## 사용 예시

### 기본 파이프라인 시작

```rust,no_run
use ironpost_log_pipeline::{LogPipeline, LogPipelineBuilder, PipelineConfigBuilder};
use ironpost_core::pipeline::Pipeline;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // 설정 생성
    let config = PipelineConfigBuilder::new()
        .watch_paths(vec!["/var/log/auth.log".to_string()])
        .syslog_bind("0.0.0.0:514".to_string())
        .rule_dir("./rules".to_string())
        .batch_size(1000)
        .flush_interval_secs(5)
        .build()?;

    // 파이프라인 빌드
    let (mut pipeline, alert_rx) = LogPipelineBuilder::new()
        .config(config)
        .build()?;

    // 시작
    pipeline.start().await?;

    // 알림 수신
    if let Some(mut alert_rx) = alert_rx {
        while let Some(alert_event) = alert_rx.recv().await {
            println!("Alert: {}", alert_event);
        }
    }

    Ok(())
}
```

### 로그 주입 (외부 소스)

```rust,ignore
use ironpost_log_pipeline::RawLog;
use std::time::SystemTime;

// 외부에서 로그 주입 (예: Docker 컨테이너 로그)
let raw_log = RawLog {
    source: "container_abc123".to_string(),
    timestamp: SystemTime::now(),
    raw_bytes: b"Failed to login user admin".to_vec(),
};

let sender = pipeline.raw_log_sender();
sender.send(raw_log).await?;
```

### YAML 탐지 규칙

`rules/ssh_brute_force.yaml`:

```yaml
id: ssh_brute_force
title: SSH Brute Force Attack
description: Multiple failed SSH login attempts from same IP
severity: high

detection:
  conditions:
    - field: process
      operator: equals
      value: sshd
      modifier: case_insensitive
    - field: message
      operator: contains
      value: "Failed password"

  threshold:
    count: 5
    timeframe_secs: 60
    group_by: src_ip

tags:
  - attack.credential_access
  - T1110  # MITRE ATT&CK
```

## 수집기 (Collector)

### FileCollector

파일 시스템 감시 기반 tail 구현:

```rust,ignore
use ironpost_log_pipeline::collector::FileCollector;

let collector = FileCollector::new(
    vec!["/var/log/auth.log".to_string()],
    sender.clone(),
);
collector.start().await?;
```

**특징:**
- `notify` 크레이트 기반 inotify 감시
- 로그 로테이션 자동 감지 (inode 변경)
- 배치 읽기 (최대 1000 라인)
- 64KB 라인 길이 제한 (OOM 방어)

### SyslogUdpCollector

RFC 5424 Syslog over UDP:

```rust,ignore
use ironpost_log_pipeline::collector::SyslogUdpCollector;

let collector = SyslogUdpCollector::new(
    "0.0.0.0:514".parse()?,
    sender.clone(),
);
collector.start().await?;
```

**특징:**
- 64KB 메시지 크기 제한
- 동시 연결 제한 (1000개)
- 손실 가능성 있음 (UDP 특성)

### SyslogTcpCollector

RFC 5424 Syslog over TCP + Octet Framing (RFC 6587):

```rust,ignore
use ironpost_log_pipeline::collector::SyslogTcpCollector;

let collector = SyslogTcpCollector::new(
    "0.0.0.0:514".parse()?,
    sender.clone(),
);
collector.start().await?;
```

**특징:**
- Octet framing: `1234 <message>`
- 동시 연결 제한 (Semaphore)
- Slow Loris 방어 (메시지 크기 제한)
- 연결별 독립 태스크

## 파서 (Parser)

### ParserRouter (자동 감지)

```rust,ignore
use ironpost_log_pipeline::parser::{ParserRouter, SyslogParser, JsonLogParser};

let router = ParserRouter::new(vec![
    Box::new(SyslogParser::new()),
    Box::new(JsonLogParser::new()),
]);

let entry = router.parse_with_detect(&raw_log.raw_bytes)?;
```

### SyslogParser

RFC 5424 (+ RFC 3164 fallback):

```text
<34>1 2024-02-09T10:30:00Z hostname app - - [meta key="value"] message
```

**지원:**
- Priority (facility, severity)
- Structured Data (SD-ELEMENT)
- RFC 3164 fallback (BSD syslog)
- 타임스탬프 파싱 (RFC 3339)

### JsonLogParser

구조화 JSON 로그:

```json
{
  "timestamp": "2024-02-09T10:30:00Z",
  "level": "error",
  "app": "nginx",
  "message": "Connection refused",
  "remote_ip": "192.168.1.100"
}
```

**특징:**
- 필드 매핑 (timestamp → timestamp, level → severity)
- 중첩 필드 flatten (최대 깊이 32)
- Unix timestamp 지원 (초, 밀리초, 마이크로초, 나노초)

## 규칙 엔진 (Rule Engine)

### FieldCondition 연산자

| Operator | 설명 | 예시 |
|----------|------|------|
| `equals` | 정확히 일치 | `field: "user", value: "admin"` |
| `contains` | 부분 문자열 포함 | `field: "message", value: "error"` |
| `regex` | 정규식 매칭 | `field: "ip", value: "^192\\.168\\."` |
| `exists` | 필드 존재 여부 | `field: "src_ip"` |

### Modifier

| Modifier | 설명 |
|----------|------|
| `case_insensitive` | 대소문자 무시 |
| `negate` | 조건 부정 (NOT) |

### Threshold 규칙

```yaml
detection:
  conditions:
    - field: message
      operator: contains
      value: "failed"

  threshold:
    count: 10
    timeframe_secs: 60
    group_by: src_ip
```

**동작:**
- `group_by` 필드값 별로 카운터 유지
- `timeframe_secs` 윈도우에서 `count`개 이상 → 알림 생성
- 자동 정리 (만료 항목 제거)

### ReDoS 방어

```rust,ignore
// loader.rs에서 자동 검증
const MAX_REGEX_LENGTH: usize = 1000;
const FORBIDDEN_PATTERNS: &[&str] = &[
    r"(.*)*",        // exponential backtracking
    r"(.*)+",
    r"(.+)*",
    r"(.+)+",
];
```

## 알림 생성 (Alert Generator)

### 중복 제거 (Dedup)

```rust,ignore
use ironpost_log_pipeline::alert::AlertGenerator;
use std::time::Duration;

let generator = AlertGenerator::new(
    Duration::from_secs(300),  // 5분 dedup window
    10,                        // 분당 룰별 10개 제한
);
```

**동작:**
- 동일 rule_id의 알림은 dedup window 내 1회만 생성
- `cleanup_expired()` 주기적 호출 (60초마다)

### 속도 제한 (Rate Limiting)

- 룰별 분당 최대 개수 제한
- 초과 시 `tracing::warn!` 로그 출력
- 알림 채널 포화 방지

### IP 추출

```rust,ignore
// 자동 추출 패턴
const SRC_IP_PATTERNS: &[&str] = &[
    "src_ip", "source_ip", "client_ip", "srcip", "srcaddr",
];
const DST_IP_PATTERNS: &[&str] = &[
    "dst_ip", "dest_ip", "destination_ip", "target_ip", "remote_ip",
    "dstip", "dstaddr",
];
```

LogEntry.fields에서 자동 추출하여 Alert.source_ip / target_ip에 저장.

## 버퍼 (LogBuffer)

### 드롭 정책

```rust,ignore
use ironpost_log_pipeline::{LogBuffer, DropPolicy};

let buffer = LogBuffer::new(10_000, DropPolicy::DropOldest);
```

| 정책 | 설명 |
|------|------|
| `DropOldest` | FIFO — 가장 오래된 로그 드롭 (기본값) |
| `DropNewest` | LIFO — 새 로그 드롭 (최근 데이터 보존) |

### 배치 플러시

```rust,ignore
let batch = buffer.drain(1000);  // 최대 1000개 드레인
```

## 설정

### PipelineConfig

```rust,ignore
pub struct PipelineConfig {
    pub watch_paths: Vec<String>,
    pub syslog_bind: String,
    pub rule_dir: String,
    pub buffer_capacity: usize,       // 기본값: 100,000
    pub batch_size: usize,             // 기본값: 1000
    pub flush_interval_secs: u64,      // 기본값: 5
    pub drop_policy: DropPolicy,       // DropOldest | DropNewest
    pub alert_dedup_window_secs: u64,  // 기본값: 300
    pub alert_rate_limit_per_rule: u32,// 기본값: 10
    pub storage: StorageConfig,
}
```

### TOML 예시

```toml
[log_pipeline]
enabled = true
sources = ["syslog", "file"]
syslog_bind = "0.0.0.0:514"
watch_paths = ["/var/log/auth.log", "/var/log/syslog"]
rule_dir = "./rules"
batch_size = 1000
flush_interval_secs = 5
buffer_capacity = 100000
drop_policy = "drop_oldest"
alert_dedup_window_secs = 300
alert_rate_limit_per_rule = 10

[log_pipeline.storage]
postgres_url = "postgresql://user:pass@localhost/ironpost"
redis_url = "redis://localhost:6379"
max_connections = 10
retention_days = 90
```

## 성능

### 처리량

- **파싱**: 약 50,000 msg/sec (Syslog RFC 5424)
- **JSON 파싱**: 약 30,000 msg/sec (중첩 flatten 포함)
- **룰 매칭**: 약 20,000 msg/sec (10개 규칙 기준)

### 메모리

- 버퍼 10만 개 로그: 약 100MB
- 규칙 엔진: 약 5MB (100개 규칙 + 정규식 캐시)
- 알림 생성기: 약 10MB (10만 개 dedup 항목)

## 보안 고려사항

### 입력 검증

- 파일 라인 길이: 64KB 제한 (OOM 방어)
- TCP 메시지 크기: 64KB 제한 (Slow Loris 방어)
- 정규식 길이: 1000자 제한 (ReDoS 방어)
- JSON 중첩 깊이: 32 레벨 제한 (스택 오버플로우 방어)

### 메모리 보호

- 버퍼 최대 용량: 10,000,000개 제한
- Alert dedup 맵: 100,000개 자동 정리
- Threshold 카운터: 100,000개 자동 정리
- 정규식 캐시: 1,000개 제한

### 파일 경로 검증

파일 수집기는 설정에 지정된 경로만 읽습니다.
symlink 순회 검증은 향후 구현 예정 (Phase 3 리뷰 H6).

## 문제 해결

### 버퍼 오버플로우

```text
WARN: buffer full, applying drop policy
```

**해결**: buffer_capacity 증가 또는 flush_interval 감소

```toml
[log_pipeline]
buffer_capacity = 200000  # 100000 → 200000
flush_interval_secs = 3   # 5 → 3
```

### 정규식 컴파일 실패

```text
Error: rule validation failed: regex compilation error
```

**해결**: 정규식 패턴 단순화 또는 길이 감소

```yaml
detection:
  conditions:
    - field: message
      operator: regex
      value: "failed.*(login|password)"  # 단순화
```

### Syslog UDP 손실

UDP는 손실 가능성이 있습니다. 신뢰성이 필요하면 TCP 사용:

```toml
[log_pipeline]
sources = ["syslog_tcp"]  # UDP → TCP
```

## 테스트

```bash
# 단위 테스트
cargo test -p ironpost-log-pipeline

# 통합 테스트
cargo test -p ironpost-log-pipeline --test integration_tests

# 특정 모듈 테스트
cargo test -p ironpost-log-pipeline parser::
cargo test -p ironpost-log-pipeline rule::
```

280개 테스트 (266 unit + 14 integration)로 전체 파이프라인 검증.

## 의존성

- `ironpost-core` — 공통 타입, Event trait
- `tokio` — 비동기 런타임, mpsc 채널
- `serde` / `serde_yaml` — 설정 및 YAML 룰 파싱
- `regex` — 정규식 조건 매칭
- `nom` — Syslog RFC 5424 파싱
- `serde_json` — JSON 로그 파싱
- `chrono` — 타임스탬프 파싱
- `notify` — 파일 시스템 감시
- `tracing` — 구조화 로깅

## 문서

```bash
cargo doc --no-deps -p ironpost-log-pipeline --open
```

모든 public API에 doc comment 포함.

## 라이선스

MIT OR Apache-2.0

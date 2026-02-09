# ironpost-core

Ironpost의 공통 타입, 에러 정의, trait 인터페이스를 제공하는 핵심 라이브러리입니다.
모든 Ironpost 모듈은 이 크레이트에 의존하며, 모듈 간 통신과 확장을 위한 기반 인프라를 제공합니다.

## 개요

`ironpost-core`는 다음 역할을 수행합니다:

- **공통 타입 정의**: `PacketInfo`, `LogEntry`, `Alert`, `Severity` 등
- **이벤트 시스템**: 모듈 간 메시지 패싱을 위한 `Event` trait 및 구현체
- **에러 계층**: 도메인별 에러 타입 및 `IronpostError` 통합
- **설정 관리**: TOML 파싱, 환경변수 오버라이드, 검증
- **확장 인터페이스**: `Pipeline`, `Detector`, `LogParser`, `PolicyEnforcer` trait

## 모듈 구조

```text
ironpost-core/
├── config.rs      # IronpostConfig — TOML 파싱 및 환경변수 오버라이드
├── error.rs       # 도메인별 에러 타입 (ConfigError, PipelineError, ...)
├── event.rs       # 이벤트 시스템 (PacketEvent, LogEvent, AlertEvent, ActionEvent)
├── pipeline.rs    # Pipeline trait, Detector/LogParser/PolicyEnforcer trait
└── types.rs       # 도메인 타입 (PacketInfo, LogEntry, Alert, Severity, ...)
```

## 핵심 개념

### 이벤트 기반 통신

모든 모듈 간 통신은 `Event` trait을 통한 메시지 패싱으로 수행됩니다:

```text
ebpf-engine ──PacketEvent──> log-pipeline ──LogEvent──> rule-engine
                                   │
                               AlertEvent
                                   │
                                   v
                            container-guard
```

#### 4가지 이벤트 타입

| 이벤트 타입 | 생성 모듈 | 설명 |
|------------|----------|------|
| `PacketEvent` | ebpf-engine | eBPF XDP에서 캡처한 패킷 정보 |
| `LogEvent` | log-pipeline | 파싱된 로그 엔트리 |
| `AlertEvent` | log-pipeline, ebpf-engine | 탐지 규칙 매칭 시 생성 |
| `ActionEvent` | container-guard | 격리/차단 액션 실행 결과 |

### 에러 계층

```text
IronpostError
  ├── ConfigError
  ├── PipelineError
  ├── DetectionError
  ├── ParseError
  ├── StorageError
  ├── ContainerError
  └── SbomError
```

각 모듈은 자체 에러 타입을 정의하고 `From<ModuleError> for IronpostError` 구현으로 통합됩니다.

### 확장 포인트

#### Pipeline trait

모든 모듈이 구현하는 생명주기 인터페이스:

```rust,no_run
use ironpost_core::{IronpostError, HealthStatus};

pub trait Pipeline: Send + Sync {
    async fn start(&mut self) -> Result<(), IronpostError>;
    async fn stop(&mut self) -> Result<(), IronpostError>;
    async fn health_check(&self) -> HealthStatus;
}
```

#### Detector trait

새로운 탐지 로직 추가를 위한 trait:

```rust,no_run
use ironpost_core::{LogEntry, Alert, IronpostError};

pub trait Detector: Send + Sync {
    fn name(&self) -> &str;
    fn detect(&self, entry: &LogEntry) -> Result<Option<Alert>, IronpostError>;
}
```

#### LogParser trait

새로운 로그 형식 파서 추가를 위한 trait:

```rust,no_run
use ironpost_core::{LogEntry, IronpostError};

pub trait LogParser: Send + Sync {
    fn format_name(&self) -> &str;
    fn parse(&self, raw: &[u8]) -> Result<LogEntry, IronpostError>;
}
```

## 사용 예시

### 설정 로드

```rust,ignore
use ironpost_core::IronpostConfig;

// 파일에서 로드 (async)
let config = IronpostConfig::from_file("ironpost.toml").await?;

// TOML 문자열에서 직접 파싱
let config = IronpostConfig::parse(r#"
[general]
log_level = "info"
"#)?;
```

### 이벤트 생성 및 전송

```rust,ignore
use ironpost_core::{PacketEvent, PacketInfo};
use std::net::IpAddr;
use std::time::SystemTime;
use bytes::Bytes;

let packet_info = PacketInfo {
    src_ip: IpAddr::V4([192, 168, 1, 100].into()),
    dst_ip: IpAddr::V4([10, 0, 0, 1].into()),
    src_port: 54321,
    dst_port: 80,
    protocol: 6, // TCP
    size: 1024,
    timestamp: SystemTime::now(),
};

let event = PacketEvent::new(packet_info, Bytes::from_static(b"..."));
tx.send(event).await?;
```

### 탐지기 구현

```rust,ignore
use ironpost_core::{Detector, LogEntry, Alert, Severity, IronpostError};
use std::time::SystemTime;

struct BruteForceDetector;

impl Detector for BruteForceDetector {
    fn name(&self) -> &str {
        "brute_force"
    }

    fn detect(&self, entry: &LogEntry) -> Result<Option<Alert>, IronpostError> {
        if entry.message.contains("Failed password") {
            Ok(Some(Alert {
                id: uuid::Uuid::new_v4().to_string(),
                title: "SSH Brute Force Attempt".to_string(),
                description: format!("Failed login from {}", entry.hostname),
                severity: Severity::High,
                rule_name: "ssh_brute_force".to_string(),
                source_ip: None,
                target_ip: None,
                created_at: SystemTime::now(),
            }))
        } else {
            Ok(None)
        }
    }
}
```

### 파이프라인 구현

```rust
use ironpost_core::{Pipeline, HealthStatus, IronpostError};
use std::sync::atomic::{AtomicBool, Ordering};

struct MyPipeline {
    running: AtomicBool,
}

impl Pipeline for MyPipeline {
    async fn start(&mut self) -> Result<(), IronpostError> {
        self.running.store(true, Ordering::Release);
        // 워커 스폰, 채널 연결 등
        Ok(())
    }

    async fn stop(&mut self) -> Result<(), IronpostError> {
        self.running.store(false, Ordering::Release);
        // Graceful shutdown
        Ok(())
    }

    async fn health_check(&self) -> HealthStatus {
        if self.running.load(Ordering::Acquire) {
            HealthStatus::Healthy
        } else {
            HealthStatus::Unhealthy("not running".to_string())
        }
    }
}
```

## 설정 파일 예시

```toml
[general]
log_level = "info"           # trace, debug, info, warn, error
log_format = "json"          # json, text
data_dir = "/var/lib/ironpost"
pid_file = "/var/run/ironpost.pid"

[ebpf]
enabled = true
interface = "eth0"
xdp_mode = "native"          # native, skb, offload
ring_buffer_size = 256       # KiB
blocklist_max_entries = 10000

[log_pipeline]
enabled = true
sources = ["syslog", "file"]
syslog_bind = "0.0.0.0:514"
watch_paths = ["/var/log/auth.log"]
batch_size = 1000
flush_interval_secs = 5

[log_pipeline.storage]
postgres_url = "postgresql://user:pass@localhost/ironpost"
redis_url = "redis://localhost:6379"
max_connections = 10

[container]
enabled = true
docker_endpoint = "unix:///var/run/docker.sock"
default_action = "isolate"   # isolate, stop, pause

[sbom]
enabled = true
scan_interval_hours = 24
vulnerability_sources = ["nvd", "ghsa"]
```

## 환경변수 오버라이드

설정 파일 대신 환경변수로 값을 오버라이드할 수 있습니다.
네이밍 규칙: `IRONPOST_{SECTION}_{FIELD}`

```bash
export IRONPOST_GENERAL_LOG_LEVEL=debug
export IRONPOST_EBPF_INTERFACE=eth1
export IRONPOST_LOG_PIPELINE_BATCH_SIZE=2000
```

## 아키텍처 노트

### dyn-compatible Pipeline

`Pipeline` trait은 RPITIT(Return Position Impl Trait In Trait)를 사용하므로
기본적으로 `dyn Pipeline`이 불가합니다. 동적 관리가 필요한 경우
`DynPipeline` trait을 사용하세요:

```rust,ignore
use ironpost_core::{DynPipeline, Pipeline};

let modules: Vec<Box<dyn DynPipeline>> = vec![
    Box::new(ebpf_pipeline),
    Box::new(log_pipeline),
];

for module in &mut modules {
    module.start().await?;
}
```

### 설정 로딩 우선순위

1. CLI 인자 (최고 우선)
2. 환경변수 (`IRONPOST_*`)
3. 설정 파일 (`ironpost.toml`)
4. 기본값 (`Default` impl)

### 에러 전파

라이브러리 크레이트는 `Result<T, ModuleError>` 반환, 바이너리는 `anyhow::Result<T>` 사용:

```rust,ignore
// 라이브러리 (ironpost-log-pipeline)
pub fn parse_syslog(raw: &[u8]) -> Result<LogEntry, LogPipelineError> { ... }

// 바이너리 (ironpost-cli)
fn main() -> anyhow::Result<()> {
    let entry = parse_syslog(data)?;  // anyhow로 자동 변환
    Ok(())
}
```

## 의존성

- `serde` — 직렬화/역직렬화
- `toml` — 설정 파일 파싱
- `thiserror` — 에러 타입 derive
- `uuid` — 이벤트 ID 생성
- `bytes` — 제로카피 패킷 버퍼
- `tracing` — 구조화 로깅
- `tokio` — 비동기 런타임 (fs 등)

## 테스트

```bash
cargo test -p ironpost-core
```

64개 테스트로 모든 public API와 에러 처리 검증.

## 문서

```bash
cargo doc --no-deps -p ironpost-core --open
```

모든 public API에 doc comment 포함.

## 라이선스

MIT OR Apache-2.0

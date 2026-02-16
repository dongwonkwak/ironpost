# Collector Spawn 설계: pipeline.rs TODO 해결

**날짜**: 2026-02-16
**브랜치**: feat/pipeline-collector-spawn
**상태**: 설계 완료, 구현 대기

## 1. 현황 분석

### 1.1 TODO 위치
`crates/log-pipeline/src/pipeline.rs:206-208`:
```rust
// TODO: spawn collector tasks based on config.sources
// Each collector gets a clone of raw_log_tx
// This will be implemented when integrating with actual data sources
```

### 1.2 기존 구조
- `PipelineConfig.sources: Vec<String>` — 기본값 `["syslog", "file"]`
- `PipelineConfig.syslog_bind: String` — 기본값 `"0.0.0.0:514"`
- `PipelineConfig.watch_paths: Vec<String>` — 기본값 `["/var/log/syslog"]`
- `LogPipeline.raw_log_tx: mpsc::Sender<RawLog>` — 수집기에 전달할 채널
- `LogPipeline.tasks: Vec<JoinHandle<()>>` — 이미 존재, 메인 처리 루프가 여기에 저장됨
- `LogPipeline.collectors: CollectorSet` — 현재 이름/상태만 추적, `#[allow(dead_code)]`

### 1.3 구현된 수집기
| 수집기 | 생성자 | 실행 메서드 |
|--------|--------|-------------|
| `SyslogUdpCollector` | `new(SyslogUdpConfig, Sender<RawLog>)` | `run(&mut self) -> Result<(), LogPipelineError>` |
| `SyslogTcpCollector` | `new(SyslogTcpConfig, Sender<RawLog>)` | `run(&mut self) -> Result<(), LogPipelineError>` |
| `FileCollector` | `new(FileCollectorConfig, Sender<RawLog>)` | `run(&mut self) -> Result<(), LogPipelineError>` |
| `EventReceiver` | `new(Receiver<PacketEvent>, Sender<RawLog>)` | `run(&mut self) -> Result<(), LogPipelineError>` |

모든 수집기의 `run()`은 무한 루프 — 취소(`abort`) 또는 채널 닫힘으로만 종료.

---

## 2. 설계

### 2.1 Source 문자열 → Collector 매핑

`config.sources`의 각 문자열을 다음과 같이 매핑:

| source 문자열 | 생성되는 수집기 | 비고 |
|---------------|----------------|------|
| `"syslog_udp"` | `SyslogUdpCollector` | UDP syslog 수신 |
| `"syslog_tcp"` | `SyslogTcpCollector` | TCP syslog 수신 |
| `"syslog"` | `SyslogUdpCollector` + `SyslogTcpCollector` | 편의 별칭: UDP/TCP 동시 활성화 |
| `"file"` | `FileCollector` | 파일 tail 감시 |

**미지원 소스 처리**: `warn!` 로그 후 해당 소스 무시 (fail-open). 파이프라인 시작 자체를 실패시키지 않는다.
이는 설정 오타나 향후 확장 소스를 안전하게 무시하기 위함.

**EventReceiver**: `config.sources`에서 관리하지 않음. `packet_rx`가 `Some`일 때
별도로 spawn. 이는 `ironpost-daemon`이 채널을 주입하는 구조이므로
source 문자열 기반 설정과 분리되어야 한다.

### 2.2 Config 변환 방법

각 수집기별 config를 `PipelineConfig`에서 파생:

```rust
// SyslogUdpCollector용
let udp_config = SyslogUdpConfig {
    bind_addr: self.config.syslog_bind.clone(),
    ..SyslogUdpConfig::default()
};

// SyslogTcpCollector용 — 같은 주소의 포트+87 (관례: UDP 514 → TCP 601)
// 또는 PipelineConfig에 syslog_tcp_bind 필드 추가
let tcp_config = SyslogTcpConfig {
    bind_addr: self.config.syslog_tcp_bind.clone(), // 새 필드 필요
    ..SyslogTcpConfig::default()
};

// FileCollector용
let file_config = FileCollectorConfig {
    watch_paths: self.config.watch_paths.iter().map(PathBuf::from).collect(),
    ..FileCollectorConfig::default()
};
```

**설정 필드 추가 필요 (PipelineConfig)**:
- `syslog_tcp_bind: String` — TCP syslog 바인드 주소 (기본값 `"0.0.0.0:601"`)

이 필드는 `PipelineConfig`(`crates/log-pipeline/src/config.rs`)에 추가하고,
core의 `LogPipelineConfig`에도 동기화한다.

**대안 (필드 추가 없이)**: `syslog_bind`를 UDP/TCP 모두에 사용하되, TCP는 포트를
+87 오프셋으로 계산. 그러나 이는 비직관적이므로 **명시적 필드 추가를 권장**한다.

### 2.3 raw_log_tx 채널 공유 방식

`mpsc::Sender<RawLog>`는 `Clone` — 각 수집기에 `self.raw_log_tx.clone()` 전달.

```rust
let tx = self.raw_log_tx.clone();
let mut collector = SyslogUdpCollector::new(udp_config, tx);
```

모든 수집기가 같은 `mpsc` 채널로 전송하므로 downstream 처리 루프에서
별도 처리 없이 통합 수신.

### 2.4 Spawn 패턴 및 Lifecycle 관리

#### 2.4.1 Spawn 패턴

각 수집기를 `tokio::spawn`으로 개별 태스크에서 실행:

```rust
fn spawn_collector<F, Fut>(&mut self, name: &str, task_fn: F)
where
    F: FnOnce() -> Fut + Send + 'static,
    Fut: std::future::Future<Output = Result<(), LogPipelineError>> + Send,
{
    let collector_name = name.to_owned();
    let handle = tokio::spawn(async move {
        if let Err(e) = task_fn().await {
            tracing::error!(
                collector = %collector_name,
                error = %e,
                "collector task failed"
            );
        }
    });
    self.collectors.register(name);
    self.tasks.push(handle);
}
```

그러나 `run(&mut self)`이 `&mut self`를 요구하므로, 수집기는 spawn 시
소유권을 이동해야 한다:

```rust
// 실제 spawn 코드
let tx = self.raw_log_tx.clone();
let udp_config = SyslogUdpConfig { /* ... */ };

let handle = tokio::spawn(async move {
    let mut collector = SyslogUdpCollector::new(udp_config, tx);
    if let Err(e) = collector.run().await {
        tracing::error!(
            collector = "syslog_udp",
            error = %e,
            "collector task terminated with error"
        );
    }
});
self.collectors.register("syslog_udp");
self.tasks.push(handle);
```

#### 2.4.2 Shutdown 처리

현재 `stop()` 구현이 이미 `tasks.drain(..)` → `abort()` → `await`를 수행:
```rust
for task in self.tasks.drain(..) {
    task.abort();
    let _ = task.await;
}
```

수집기 태스크도 `self.tasks`에 push되므로, 별도 shutdown 로직 불필요.
`abort()`가 호출되면 수집기의 `run()` 루프가 취소됨.

**주의**: `abort()` 시 수집기 내부 상태(file offset 등)가 저장되지 않는다.
현재 스코프에서는 이를 허용 (상태 영속화는 향후 과제).

#### 2.4.3 EventReceiver Spawn

`packet_rx`가 `Some`일 때만 spawn:

```rust
if let Some(packet_rx) = self.packet_rx.take() {
    let tx = self.raw_log_tx.clone();
    let handle = tokio::spawn(async move {
        let mut receiver = EventReceiver::new(packet_rx, tx);
        if let Err(e) = receiver.run().await {
            tracing::error!(
                collector = "event_receiver",
                error = %e,
                "event receiver task terminated with error"
            );
        }
    });
    self.collectors.register("event_receiver");
    self.tasks.push(handle);
}
```

### 2.5 Fault Isolation 전략

#### 원칙: 개별 수집기 실패가 파이프라인 전체를 중단시키지 않는다.

1. **독립 태스크**: 각 수집기가 별도 `tokio::spawn` — 하나가 panic해도 다른 태스크에 영향 없음
2. **에러 로깅**: `run()` 실패 시 `tracing::error!`로 기록, 태스크는 조용히 종료
3. **채널 탄력성**: `raw_log_tx`의 한 clone이 drop되어도 다른 수집기의 clone은 유효
4. **시작 실패 허용**: 개별 수집기 바인드 실패(포트 충돌 등)는 해당 수집기만 실패

#### 시작 시 검증 (fail-fast)

바인드 실패를 조기에 감지하고 싶다면, 수집기 생성과 바인드를 분리하는 two-phase 패턴:

```rust
// Phase 1: Validate (선택적)
// 소켓 바인드 테스트 등 — 현재 구현에서는 run() 진입 후 바인드하므로
// 즉각적인 실패 감지가 어려움

// Phase 2: Spawn
```

**현재 수집기 구현의 한계**: `run()`이 바인드와 수신을 한 메서드에서 처리.
시작 실패를 동기적으로 보고하려면 수집기 인터페이스를 변경해야 하나,
이는 현재 스코프 밖. **현 구현에서는 비동기 에러 로깅으로 충분**.

향후 개선: `Collector` trait에 `async fn bind(&mut self) -> Result<()>` 분리.

#### 선택적: 자동 재시작

현재 스코프에서는 구현하지 않으나, 향후 확장점:
```rust
// 재시작 래퍼 (향후)
async fn run_with_retry<F, Fut>(name: &str, max_retries: u32, factory: F)
where
    F: Fn() -> Fut,
    Fut: Future<Output = Result<(), LogPipelineError>>,
{
    for attempt in 0..max_retries {
        match factory().await {
            Ok(()) => break,
            Err(e) => {
                tracing::warn!(collector = name, attempt, error = %e, "retrying...");
                tokio::time::sleep(Duration::from_secs(1 << attempt)).await;
            }
        }
    }
}
```

---

## 3. 수정 위치 및 구체적 방법

### 3.1 `crates/log-pipeline/src/config.rs`

**변경**: `PipelineConfig`에 `syslog_tcp_bind` 필드 추가

```rust
pub struct PipelineConfig {
    // ... 기존 필드 ...
    /// TCP Syslog 수신 바인드 주소
    pub syslog_tcp_bind: String,  // 추가
}

impl Default for PipelineConfig {
    fn default() -> Self {
        Self {
            // ... 기존 ...
            syslog_tcp_bind: "0.0.0.0:601".to_owned(),  // 추가
        }
    }
}

impl PipelineConfig {
    pub fn from_core(core: &LogPipelineConfig) -> Self {
        // syslog_tcp_bind는 core에 없으면 기본값 사용
        // 또는 core에도 추가
    }
}
```

`PipelineConfigBuilder`에도 `.syslog_tcp_bind()` 메서드 추가.

### 3.2 `crates/core/src/config.rs`

**변경**: `LogPipelineConfig`에 `syslog_tcp_bind` 필드 추가

```rust
pub struct LogPipelineConfig {
    // ... 기존 필드 ...
    /// TCP Syslog 수신 주소
    pub syslog_tcp_bind: String,
}
```

환경변수 오버라이드도 추가: `IRONPOST_LOG_PIPELINE_SYSLOG_TCP_BIND`.

### 3.3 `crates/log-pipeline/src/pipeline.rs` — 핵심 변경

**수정 위치**: `Pipeline::start()` 내 206~208줄 (TODO 주석 위치)

**교체 코드**:

```rust
// 2. 수집기 태스크 스폰
let mut spawned_collectors: Vec<&str> = Vec::new();

for source in &self.config.sources {
    match source.as_str() {
        "syslog" => {
            // syslog = syslog_udp + syslog_tcp 동시 활성화
            self.spawn_syslog_udp();
            self.spawn_syslog_tcp();
            spawned_collectors.push("syslog_udp");
            spawned_collectors.push("syslog_tcp");
        }
        "syslog_udp" => {
            self.spawn_syslog_udp();
            spawned_collectors.push("syslog_udp");
        }
        "syslog_tcp" => {
            self.spawn_syslog_tcp();
            spawned_collectors.push("syslog_tcp");
        }
        "file" => {
            self.spawn_file_collector();
            spawned_collectors.push("file");
        }
        unknown => {
            tracing::warn!(
                source = unknown,
                "unknown collector source, skipping"
            );
        }
    }
}

// EventReceiver spawn (packet_rx가 있을 때만)
if let Some(packet_rx) = self.packet_rx.take() {
    self.spawn_event_receiver(packet_rx);
    spawned_collectors.push("event_receiver");
}

tracing::info!(
    collectors = ?spawned_collectors,
    count = spawned_collectors.len(),
    "spawned collector tasks"
);
```

**추가할 private 헬퍼 메서드** (LogPipeline impl 블록):

```rust
impl LogPipeline {
    /// UDP syslog 수집기를 spawn합니다.
    fn spawn_syslog_udp(&mut self) {
        let tx = self.raw_log_tx.clone();
        let config = SyslogUdpConfig {
            bind_addr: self.config.syslog_bind.clone(),
            ..SyslogUdpConfig::default()
        };

        let handle = tokio::spawn(async move {
            let mut collector = SyslogUdpCollector::new(config, tx);
            if let Err(e) = collector.run().await {
                tracing::error!(
                    collector = "syslog_udp",
                    error = %e,
                    "syslog UDP collector terminated with error"
                );
            }
        });
        self.collectors.register("syslog_udp");
        self.tasks.push(handle);
    }

    /// TCP syslog 수집기를 spawn합니다.
    fn spawn_syslog_tcp(&mut self) {
        let tx = self.raw_log_tx.clone();
        let config = SyslogTcpConfig {
            bind_addr: self.config.syslog_tcp_bind.clone(),
            ..SyslogTcpConfig::default()
        };

        let handle = tokio::spawn(async move {
            let mut collector = SyslogTcpCollector::new(config, tx);
            if let Err(e) = collector.run().await {
                tracing::error!(
                    collector = "syslog_tcp",
                    error = %e,
                    "syslog TCP collector terminated with error"
                );
            }
        });
        self.collectors.register("syslog_tcp");
        self.tasks.push(handle);
    }

    /// 파일 수집기를 spawn합니다.
    fn spawn_file_collector(&mut self) {
        let tx = self.raw_log_tx.clone();
        let config = FileCollectorConfig {
            watch_paths: self.config.watch_paths.iter().map(PathBuf::from).collect(),
            ..FileCollectorConfig::default()
        };

        let handle = tokio::spawn(async move {
            let mut collector = FileCollector::new(config, tx);
            if let Err(e) = collector.run().await {
                tracing::error!(
                    collector = "file",
                    error = %e,
                    "file collector terminated with error"
                );
            }
        });
        self.collectors.register("file");
        self.tasks.push(handle);
    }

    /// eBPF EventReceiver를 spawn합니다.
    fn spawn_event_receiver(&mut self, packet_rx: mpsc::Receiver<PacketEvent>) {
        let tx = self.raw_log_tx.clone();

        let handle = tokio::spawn(async move {
            let mut receiver = EventReceiver::new(packet_rx, tx);
            if let Err(e) = receiver.run().await {
                tracing::error!(
                    collector = "event_receiver",
                    error = %e,
                    "event receiver terminated with error"
                );
            }
        });
        self.collectors.register("event_receiver");
        self.tasks.push(handle);
    }
}
```

**추가 import** (`pipeline.rs` 상단):

```rust
use std::path::PathBuf;

use crate::collector::{
    EventReceiver, FileCollector, SyslogTcpCollector, SyslogUdpCollector,
};
use crate::collector::file::FileCollectorConfig;
use crate::collector::syslog_tcp::SyslogTcpConfig;
use crate::collector::syslog_udp::SyslogUdpConfig;
```

### 3.4 `crates/log-pipeline/src/pipeline.rs` — `#[allow(dead_code)]` 제거

수집기가 실제로 사용되므로 다음 attribute 제거:
- `collectors` 필드의 `#[allow(dead_code)]` (line 77)
- `packet_rx` 필드의 `#[allow(dead_code)]` (line 86-87)

### 3.5 `crates/log-pipeline/src/pipeline.rs` — stop() 수정

현재 `stop()`이 `tasks.drain(..).abort()`로 모든 태스크를 중단하므로,
수집기 태스크도 자동으로 정리됨. **추가 변경 불필요**.

단, `collectors` 상태를 `Stopped`로 업데이트하려면 `CollectorSet`에
상태 업데이트 메서드를 추가해야 한다:

```rust
// collector/mod.rs에 추가
impl CollectorSet {
    /// 모든 수집기 상태를 Stopped로 설정합니다.
    pub fn stop_all(&mut self) {
        for (_, status) in &mut self.collectors {
            *status = CollectorStatus::Stopped;
        }
    }

    /// 수집기 세트를 초기화합니다 (재시작 지원).
    pub fn clear(&mut self) {
        self.collectors.clear();
    }
}
```

그리고 `Pipeline::stop()`에서:
```rust
self.collectors.stop_all();
self.collectors.clear(); // 재시작 시 다시 등록
```

---

## 4. 중복 spawn 방지

`"syslog"`가 `"syslog_udp"` + `"syslog_tcp"`로 확장되므로,
`sources`에 `["syslog", "syslog_udp"]`가 동시에 있으면 UDP가 두 번 spawn된다.

**해결**: spawn 전에 중복 제거:

```rust
let mut seen_collectors: std::collections::HashSet<String> = std::collections::HashSet::new();

for source in &self.config.sources {
    match source.as_str() {
        "syslog" => {
            if seen_collectors.insert("syslog_udp".to_owned()) {
                self.spawn_syslog_udp();
            }
            if seen_collectors.insert("syslog_tcp".to_owned()) {
                self.spawn_syslog_tcp();
            }
        }
        "syslog_udp" => {
            if seen_collectors.insert("syslog_udp".to_owned()) {
                self.spawn_syslog_udp();
            }
        }
        // ... 동일 패턴
    }
}
```

---

## 5. 기존 테스트 영향 분석

### 5.1 영향 없는 테스트

| 테스트 | 이유 |
|--------|------|
| `builder_creates_pipeline` | start() 호출 안 함 |
| `builder_with_external_alert_sender` | start() 호출 안 함 |
| `builder_with_invalid_config_fails` | start() 호출 안 함 |
| `pipeline_lifecycle` | stop을 먼저 호출 (start 안 함) |
| `pipeline_accessors` | start() 호출 안 함 |
| `raw_log_sender_is_accessible` | start() 호출 안 함 |

### 5.2 영향 있는 테스트

| 테스트 | 영향 | 대응 |
|--------|------|------|
| `pipeline_can_restart_after_stop` | `start()`를 호출하므로 수집기 spawn 시도 | 수집기가 바인드 실패하더라도 파이프라인 start 자체는 성공해야 함 (fault isolation) |

`pipeline_can_restart_after_stop`는 `PipelineConfig::default()` 사용:
- `sources: ["syslog", "file"]`
- syslog 바인드: `0.0.0.0:514` (권한 필요, 테스트 환경에서 실패)
- watch_paths: `/var/log/syslog` (존재하지 않을 수 있음)

**대응**: 테스트에서 `sources: vec![]` (빈 소스) 사용하거나,
테스트용 config에서 소스를 비워야 함. 그러나 `enabled: true && sources.is_empty()`는
validate에서 거부됨.

**해결 방안**:
1. 테스트 config에 `enabled: false` 설정 → validate 통과, 수집기 spawn 스킵
2. 또는 start() 내에서 `enabled` 체크 추가: `if !self.config.enabled { skip collectors }`
3. 또는 테스트 config에 sources를 설정하되, 실패가 파이프라인을 중단시키지 않음을 확인

**권장**: 옵션 3 — fault isolation에 의해 수집기 바인드 실패가 start()를
실패시키지 않으므로 기존 테스트 수정 불필요. 수집기 에러는 비동기 로그만 남김.

### 5.3 추가 필요한 테스트

#### Unit Tests (pipeline.rs)

```rust
#[tokio::test]
async fn pipeline_spawns_collectors_from_config() {
    let temp_dir = std::env::temp_dir().join("ironpost_test_spawn");
    std::fs::create_dir_all(&temp_dir).ok();

    let config = PipelineConfig {
        rule_dir: temp_dir.to_string_lossy().to_string(),
        sources: vec!["syslog_udp".to_owned()],
        syslog_bind: "127.0.0.1:0".to_owned(), // 자동 포트
        ..Default::default()
    };

    let (mut pipeline, _) = LogPipelineBuilder::new().config(config).build().unwrap();
    Pipeline::start(&mut pipeline).await.unwrap();

    // 수집기가 등록되었는지 확인
    assert!(!pipeline.collectors.is_empty());
    assert_eq!(pipeline.collectors.len(), 1);

    Pipeline::stop(&mut pipeline).await.unwrap();
}

#[tokio::test]
async fn pipeline_skips_unknown_source() {
    let temp_dir = std::env::temp_dir().join("ironpost_test_unknown");
    std::fs::create_dir_all(&temp_dir).ok();

    let config = PipelineConfig {
        rule_dir: temp_dir.to_string_lossy().to_string(),
        sources: vec!["unknown_source".to_owned(), "syslog_udp".to_owned()],
        syslog_bind: "127.0.0.1:0".to_owned(),
        ..Default::default()
    };

    let (mut pipeline, _) = LogPipelineBuilder::new().config(config).build().unwrap();
    // unknown_source가 있어도 start 성공
    Pipeline::start(&mut pipeline).await.unwrap();
    // syslog_udp만 등록됨
    assert_eq!(pipeline.collectors.len(), 1);

    Pipeline::stop(&mut pipeline).await.unwrap();
}

#[tokio::test]
async fn pipeline_no_duplicate_collectors() {
    let temp_dir = std::env::temp_dir().join("ironpost_test_dedup");
    std::fs::create_dir_all(&temp_dir).ok();

    let config = PipelineConfig {
        rule_dir: temp_dir.to_string_lossy().to_string(),
        sources: vec!["syslog".to_owned(), "syslog_udp".to_owned()],
        syslog_bind: "127.0.0.1:0".to_owned(),
        syslog_tcp_bind: "127.0.0.1:0".to_owned(),
        ..Default::default()
    };

    let (mut pipeline, _) = LogPipelineBuilder::new().config(config).build().unwrap();
    Pipeline::start(&mut pipeline).await.unwrap();

    // syslog = udp + tcp, syslog_udp 중복 → 총 2개 (udp, tcp)
    assert_eq!(pipeline.collectors.len(), 2);

    Pipeline::stop(&mut pipeline).await.unwrap();
}

#[tokio::test]
async fn pipeline_spawns_event_receiver_when_packet_rx_present() {
    let temp_dir = std::env::temp_dir().join("ironpost_test_event_rx");
    std::fs::create_dir_all(&temp_dir).ok();

    let (packet_tx, packet_rx) = mpsc::channel(10);

    let config = PipelineConfig {
        rule_dir: temp_dir.to_string_lossy().to_string(),
        sources: vec![],
        enabled: false, // sources 빈 상태 허용
        ..Default::default()
    };

    let (mut pipeline, _) = LogPipelineBuilder::new()
        .config(config)
        .packet_receiver(packet_rx)
        .build()
        .unwrap();

    Pipeline::start(&mut pipeline).await.unwrap();

    // event_receiver가 등록되었는지 확인
    let has_event_receiver = pipeline.collectors.statuses()
        .iter()
        .any(|(name, _)| name == "event_receiver");
    assert!(has_event_receiver);

    drop(packet_tx);
    Pipeline::stop(&mut pipeline).await.unwrap();
}
```

#### Integration Tests

```rust
#[tokio::test]
async fn collector_sends_logs_to_pipeline() {
    // 1. 파이프라인 start (syslog_udp 소스)
    // 2. UDP 소켓으로 syslog 메시지 전송
    // 3. alert_rx 또는 processed_count로 수신 확인
    // 4. stop
}
```

이 테스트는 실제 네트워크 I/O가 필요하므로
`#[cfg(test)]` integration test로 별도 파일에 작성 권장.

---

## 6. 구현 순서 (체크리스트)

1. [ ] `crates/core/src/config.rs` — `LogPipelineConfig`에 `syslog_tcp_bind` 추가
2. [ ] `crates/log-pipeline/src/config.rs` — `PipelineConfig`에 `syslog_tcp_bind` 추가
       + `from_core()` 업데이트 + `PipelineConfigBuilder` 메서드 추가
3. [ ] `crates/log-pipeline/src/collector/mod.rs` — `CollectorSet`에 `stop_all()`, `clear()` 추가
4. [ ] `crates/log-pipeline/src/pipeline.rs` — 수집기 spawn 헬퍼 메서드 4개 추가
5. [ ] `crates/log-pipeline/src/pipeline.rs` — `start()` TODO 교체
6. [ ] `crates/log-pipeline/src/pipeline.rs` — `stop()`에 `collectors.stop_all()` + `clear()` 추가
7. [ ] `crates/log-pipeline/src/pipeline.rs` — `#[allow(dead_code)]` 제거
8. [ ] 테스트 작성 및 기존 테스트 통과 확인
9. [ ] `cargo fmt --all --check && cargo clippy --workspace -- -D warnings && cargo test --workspace`

---

## 7. 리스크 및 미해결 사항

| 항목 | 리스크 | 완화 |
|------|--------|------|
| 포트 바인드 권한 | 514/udp, 601/tcp는 특권 포트 | 테스트에서 `127.0.0.1:0` 사용 |
| 수집기 무한 재시작 | 현재 미구현 | 1차에서는 미구현, 향후 retry 래퍼 추가 |
| 파일 감시 경로 미존재 | `FileCollector.run()` 내부에서 에러 처리 | fault isolation으로 커버 |
| `CollectorSet` 상태 동기화 | spawn된 태스크의 실제 상태와 괴리 | `CollectorSet`을 Arc<Mutex<>>로 공유 (향후) |
| config 변경 시 수집기 재구성 | 현재 미지원 | watch 채널 기반 hot reload (향후) |

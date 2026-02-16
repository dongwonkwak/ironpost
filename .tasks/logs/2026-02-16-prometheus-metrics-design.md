# Phase 10: Prometheus Metrics + Grafana Dashboard 설계 문서

> 작성일: 2026-02-16
> 작성자: architect
> 브랜치: `feat/prometheus-metrics`

---

## 1. 개요

### 1.1 목표

Ironpost 플랫폼의 운영 가시성(observability)을 확보하기 위해 Prometheus 메트릭 수집 및 Grafana 대시보드를 구현한다. 모든 모듈(ebpf-engine, log-pipeline, container-guard, sbom-scanner)의 핵심 지표를 표준 Prometheus exposition format으로 노출하고, Grafana를 통해 실시간 모니터링 대시보드를 제공한다.

### 1.2 범위

| 항목 | 포함 여부 |
|------|-----------|
| `crates/core/src/metrics.rs` 메트릭 상수 및 헬퍼 | O |
| `IronpostConfig`에 `MetricsConfig` 섹션 추가 | O |
| 각 모듈의 `Arc<AtomicU64>` 카운터를 `metrics` crate로 교체 | O |
| `ironpost-daemon`에 `/metrics` HTTP 엔드포인트 추가 | O |
| Docker Compose에 Prometheus/Grafana 프로비저닝 연결 | O |
| Grafana 대시보드 JSON 작성 | O |
| 커스텀 Alertmanager 규칙 | X (향후 Phase) |
| OpenTelemetry 통합 | X (향후 Phase) |

### 1.3 설계 원칙

1. **모듈 독립성 유지**: 각 모듈은 `core`의 메트릭 상수만 참조하여 자체 계측. 모듈 간 직접 의존 금지.
2. **최소 의존성**: `metrics` + `metrics-exporter-prometheus` 크레이트의 내장 HTTP 리스너 사용. `axum`/`warp` 추가 불필요.
3. **기존 패턴과의 호환**: `Arc<AtomicU64>` 카운터를 `metrics::counter!()` 호출로 점진적 교체. 공개 getter 메서드는 `metrics` recorder에서 조회.
4. **크로스 플랫폼**: 메트릭 수집/노출은 Linux/macOS/Windows 모두 동작. eBPF 전용 메트릭만 `#[cfg(target_os = "linux")]`.

---

## 2. 아키텍처

### 2.1 메트릭 데이터 흐름

```text
+-------------------+     +-------------------+     +-------------------+
|   ebpf-engine     |     |   log-pipeline    |     | container-guard   |
|                   |     |                   |     |                   |
| counter!()        |     | counter!()        |     | counter!()        |
| histogram!()      |     | histogram!()      |     | gauge!()          |
+--------+----------+     +--------+----------+     +--------+----------+
         |                         |                          |
         v                         v                          v
+-------------------------------------------------------------------------+
|                     metrics crate (Global Recorder)                     |
|                 PrometheusBuilder::new().install_recorder()              |
+-----------------------------------+-------------------------------------+
                                    |
                                    v
+-----------------------------------+-------------------------------------+
|          metrics-exporter-prometheus (Built-in HTTP Listener)            |
|                        0.0.0.0:9100 /metrics                            |
+-----------------------------------+-------------------------------------+
                                    |
                                    v
+-----------------------------------+-------------------------------------+
|                         Prometheus Server                               |
|               scrape_configs: ironpost:9100/metrics                     |
+-----------------------------------+-------------------------------------+
                                    |
                                    v
+-----------------------------------+-------------------------------------+
|                         Grafana Dashboards                              |
|             Datasource: http://prometheus:9090                          |
+-------------------------------------------------------------------------+
```

### 2.2 컴포넌트 역할

| 컴포넌트 | 역할 |
|----------|------|
| `crates/core/src/metrics.rs` | 메트릭 이름 상수, 레이블 키 상수, 초기화 헬퍼 |
| 각 모듈 (`pipeline.rs`, `guard.rs`, `scanner.rs`, `engine.rs`) | `metrics::counter!()`, `metrics::gauge!()`, `metrics::histogram!()` 호출 |
| `ironpost-daemon/src/metrics_server.rs` | `PrometheusBuilder` 설정 + HTTP 리스너 시작 |
| `docker/prometheus/prometheus.yml` | Prometheus scrape 설정 |
| `docker/grafana/provisioning/` | Grafana datasource + dashboard 자동 프로비저닝 |

### 2.3 의존성 방향 (변경 없음)

```text
ironpost-daemon
    +-- crates/core (metrics.rs 상수 참조)
    +-- crates/ebpf-engine --> core
    +-- crates/log-pipeline --> core
    +-- crates/container-guard --> core
    +-- crates/sbom-scanner --> core
```

모듈 간 직접 의존은 없다. `metrics` crate의 전역 레코더(global recorder)를 통해 모든 모듈이 동일한 레지스트리에 메트릭을 기록한다.

---

## 3. 의존성 (새로 추가되는 크레이트)

### 3.1 Workspace 레벨 (`Cargo.toml`)

```toml
[workspace.dependencies]
# 기존 의존성 유지...
metrics = "0.24"
metrics-exporter-prometheus = { version = "0.16", features = ["http-listener"] }
```

### 3.2 크레이트별 의존성

| 크레이트 | 추가 의존성 | 용도 |
|----------|------------|------|
| `crates/core` | `metrics = { workspace = true }` | 메트릭 상수 정의, `describe_*!()` 매크로 |
| `crates/log-pipeline` | `metrics = { workspace = true }` | `counter!()`, `histogram!()` 호출 |
| `crates/container-guard` | `metrics = { workspace = true }` | `counter!()`, `gauge!()` 호출 |
| `crates/sbom-scanner` | `metrics = { workspace = true }` | `counter!()`, `gauge!()`, `histogram!()` 호출 |
| `crates/ebpf-engine` | `metrics = { workspace = true }` | `counter!()`, `histogram!()` 호출 |
| `ironpost-daemon` | `metrics = { workspace = true }`, `metrics-exporter-prometheus = { workspace = true }` | 전역 레코더 설치 + HTTP 리스너 |

### 3.3 버전 선택 근거

- **`metrics` 0.24**: 2025년 안정 릴리스. `counter!()`, `gauge!()`, `histogram!()` 매크로 제공. 전역 레코더 패턴으로 어디서든 메트릭 기록 가능.
- **`metrics-exporter-prometheus` 0.16**: `metrics` 0.24와 호환. `http-listener` 피처로 별도 HTTP 서버 없이 `/metrics` 엔드포인트 자동 생성. 내부적으로 `hyper`를 사용하므로 추가 웹 프레임워크 불필요.

---

## 4. 설정 (MetricsConfig)

### 4.1 TOML 설정 예시

```toml
[metrics]
enabled = true
listen_addr = "0.0.0.0"
port = 9100
endpoint = "/metrics"
```

### 4.2 Rust 구조체 정의

`crates/core/src/config.rs`에 추가:

```rust
/// 메트릭 수집 및 Prometheus 노출 설정
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct MetricsConfig {
    /// 메트릭 엔드포인트 활성화 여부
    pub enabled: bool,
    /// HTTP 리스너 바인드 주소
    pub listen_addr: String,
    /// HTTP 리스너 포트
    pub port: u16,
    /// 메트릭 엔드포인트 경로
    pub endpoint: String,
}

impl Default for MetricsConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            listen_addr: "0.0.0.0".to_owned(),
            port: 9100,
            endpoint: "/metrics".to_owned(),
        }
    }
}

impl MetricsConfig {
    /// Validate metrics configuration values.
    pub fn validate(&self) -> Result<(), IronpostError> {
        if self.port == 0 {
            return Err(ConfigError::InvalidValue {
                field: "metrics.port".to_owned(),
                reason: "must be greater than 0".to_owned(),
            }
            .into());
        }
        if self.listen_addr.is_empty() {
            return Err(ConfigError::InvalidValue {
                field: "metrics.listen_addr".to_owned(),
                reason: "must not be empty".to_owned(),
            }
            .into());
        }
        if !self.endpoint.starts_with('/') {
            return Err(ConfigError::InvalidValue {
                field: "metrics.endpoint".to_owned(),
                reason: "must start with '/'".to_owned(),
            }
            .into());
        }
        Ok(())
    }
}
```

### 4.3 IronpostConfig 변경

```rust
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct IronpostConfig {
    #[serde(default)]
    pub general: GeneralConfig,
    #[serde(default)]
    pub metrics: MetricsConfig,       // <-- 신규 추가
    #[serde(default)]
    pub ebpf: EbpfConfig,
    #[serde(default)]
    pub log_pipeline: LogPipelineConfig,
    #[serde(default)]
    pub container: ContainerConfig,
    #[serde(default)]
    pub sbom: SbomConfig,
}
```

### 4.4 환경변수 오버라이드

`apply_env_overrides()` 메서드에 추가:

```rust
// Metrics
override_bool(&mut self.metrics.enabled, "IRONPOST_METRICS_ENABLED");
override_string(&mut self.metrics.listen_addr, "IRONPOST_METRICS_LISTEN_ADDR");
override_u16(&mut self.metrics.port, "IRONPOST_METRICS_PORT");
override_string(&mut self.metrics.endpoint, "IRONPOST_METRICS_ENDPOINT");
```

`override_u16` 헬퍼 함수를 추가해야 한다:

```rust
fn override_u16(target: &mut u16, env_key: &str) {
    if let Ok(val) = std::env::var(env_key) {
        match val.parse::<u16>() {
            Ok(parsed) => *target = parsed,
            Err(_) => warn!(
                env_key,
                value = val.as_str(),
                "failed to parse u16 from env var, ignoring"
            ),
        }
    }
}
```

### 4.5 validate() 변경

`IronpostConfig::validate()`에 추가:

```rust
if self.metrics.enabled {
    self.metrics.validate()?;
}
```

---

## 5. Core 메트릭 모듈 (`crates/core/src/metrics.rs`)

### 5.1 설계 철학

`core/metrics.rs`는 메트릭 **이름 상수**와 **설명 등록 함수**만 정의한다. 실제 계측(instrumentation)은 각 모듈이 `metrics::counter!()` 등의 매크로를 직접 호출한다. 이렇게 하면:

1. 메트릭 이름의 일관성을 보장 (오타 방지)
2. 각 모듈은 core 상수만 참조 (결합도 최소화)
3. 전역 레코더 설치는 daemon에서만 수행

### 5.2 파일 내용

```rust
//! 메트릭 상수 및 설명 등록
//!
//! 모든 Prometheus 메트릭의 이름과 설명을 중앙에서 정의합니다.
//! 각 모듈은 이 상수를 사용하여 `metrics::counter!()`, `metrics::gauge!()`,
//! `metrics::histogram!()` 매크로를 호출합니다.
//!
//! # 네이밍 컨벤션
//!
//! - 접두어: `ironpost_`
//! - 모듈명: `ebpf_`, `log_pipeline_`, `container_guard_`, `sbom_scanner_`
//! - 접미어: `_total` (counter), `_seconds` (histogram/latency), 없음 (gauge)
//!
//! # 사용 예시
//!
//! ```ignore
//! use ironpost_core::metrics;
//! use metrics::counter;
//!
//! counter!(ironpost_core::metrics::LOG_PIPELINE_LOGS_PROCESSED_TOTAL).increment(1);
//! ```

// ─── 레이블 키 상수 ────────────────────────────────────────────────

/// 프로토콜 레이블 키 (TCP, UDP, ICMP, other)
pub const LABEL_PROTOCOL: &str = "protocol";

/// 심각도 레이블 키 (info, low, medium, high, critical)
pub const LABEL_SEVERITY: &str = "severity";

/// 모듈 레이블 키
pub const LABEL_MODULE: &str = "module";

/// 파서 형식 레이블 키 (syslog, json)
pub const LABEL_PARSER_FORMAT: &str = "format";

/// 격리 액션 레이블 키 (disconnect, pause, stop)
pub const LABEL_ACTION: &str = "action";

/// 에코시스템 레이블 키 (cargo, npm)
pub const LABEL_ECOSYSTEM: &str = "ecosystem";

/// 결과 레이블 키 (success, failure)
pub const LABEL_RESULT: &str = "result";

// ─── eBPF Engine 메트릭 ────────────────────────────────────────────

/// eBPF: 처리된 전체 패킷 수 (counter)
pub const EBPF_PACKETS_TOTAL: &str = "ironpost_ebpf_packets_total";

/// eBPF: 차단된 패킷 수 (counter)
pub const EBPF_PACKETS_BLOCKED_TOTAL: &str = "ironpost_ebpf_packets_blocked_total";

/// eBPF: 전송 바이트 수 (counter)
pub const EBPF_BYTES_TOTAL: &str = "ironpost_ebpf_bytes_total";

/// eBPF: XDP 처리 지연 시간 (histogram, 초)
pub const EBPF_XDP_PROCESSING_DURATION_SECONDS: &str =
    "ironpost_ebpf_xdp_processing_duration_seconds";

/// eBPF: 프로토콜별 패킷 수 (counter, label: protocol)
pub const EBPF_PROTOCOL_PACKETS_TOTAL: &str = "ironpost_ebpf_protocol_packets_total";

/// eBPF: 초당 패킷 처리량 (gauge)
pub const EBPF_PACKETS_PER_SECOND: &str = "ironpost_ebpf_packets_per_second";

/// eBPF: 초당 비트 처리량 (gauge)
pub const EBPF_BITS_PER_SECOND: &str = "ironpost_ebpf_bits_per_second";

// ─── Log Pipeline 메트릭 ────────────────────────────────────────────

/// Log Pipeline: 수집된 전체 로그 수 (counter)
pub const LOG_PIPELINE_LOGS_COLLECTED_TOTAL: &str = "ironpost_log_pipeline_logs_collected_total";

/// Log Pipeline: 처리된 로그 수 (counter)
pub const LOG_PIPELINE_LOGS_PROCESSED_TOTAL: &str = "ironpost_log_pipeline_logs_processed_total";

/// Log Pipeline: 파싱 에러 수 (counter)
pub const LOG_PIPELINE_PARSE_ERRORS_TOTAL: &str = "ironpost_log_pipeline_parse_errors_total";

/// Log Pipeline: 규칙 매칭 수 (counter)
pub const LOG_PIPELINE_RULE_MATCHES_TOTAL: &str = "ironpost_log_pipeline_rule_matches_total";

/// Log Pipeline: 전송된 알림 수 (counter)
pub const LOG_PIPELINE_ALERTS_SENT_TOTAL: &str = "ironpost_log_pipeline_alerts_sent_total";

/// Log Pipeline: 로그 처리 지연 시간 (histogram, 초)
pub const LOG_PIPELINE_PROCESSING_DURATION_SECONDS: &str =
    "ironpost_log_pipeline_processing_duration_seconds";

/// Log Pipeline: 버퍼 내 로그 수 (gauge)
pub const LOG_PIPELINE_BUFFER_SIZE: &str = "ironpost_log_pipeline_buffer_size";

/// Log Pipeline: 드롭된 로그 수 (counter)
pub const LOG_PIPELINE_LOGS_DROPPED_TOTAL: &str = "ironpost_log_pipeline_logs_dropped_total";

// ─── Container Guard 메트릭 ─────────────────────────────────────────

/// Container Guard: 모니터링 중인 컨테이너 수 (gauge)
pub const CONTAINER_GUARD_MONITORED_CONTAINERS: &str =
    "ironpost_container_guard_monitored_containers";

/// Container Guard: 정책 위반 수 (counter)
pub const CONTAINER_GUARD_POLICY_VIOLATIONS_TOTAL: &str =
    "ironpost_container_guard_policy_violations_total";

/// Container Guard: 격리 실행 수 (counter)
pub const CONTAINER_GUARD_ISOLATIONS_TOTAL: &str = "ironpost_container_guard_isolations_total";

/// Container Guard: 격리 실패 수 (counter)
pub const CONTAINER_GUARD_ISOLATION_FAILURES_TOTAL: &str =
    "ironpost_container_guard_isolation_failures_total";

/// Container Guard: 처리된 알림 수 (counter)
pub const CONTAINER_GUARD_ALERTS_PROCESSED_TOTAL: &str =
    "ironpost_container_guard_alerts_processed_total";

/// Container Guard: 로드된 정책 수 (gauge)
pub const CONTAINER_GUARD_POLICIES_LOADED: &str = "ironpost_container_guard_policies_loaded";

// ─── SBOM Scanner 메트릭 ────────────────────────────────────────────

/// SBOM Scanner: 완료된 스캔 수 (counter)
pub const SBOM_SCANNER_SCANS_COMPLETED_TOTAL: &str =
    "ironpost_sbom_scanner_scans_completed_total";

/// SBOM Scanner: 발견된 CVE 수 (gauge, label: severity)
pub const SBOM_SCANNER_CVES_FOUND: &str = "ironpost_sbom_scanner_cves_found";

/// SBOM Scanner: 스캔 소요 시간 (histogram, 초)
pub const SBOM_SCANNER_SCAN_DURATION_SECONDS: &str =
    "ironpost_sbom_scanner_scan_duration_seconds";

/// SBOM Scanner: 스캔된 패키지 수 (counter)
pub const SBOM_SCANNER_PACKAGES_SCANNED_TOTAL: &str =
    "ironpost_sbom_scanner_packages_scanned_total";

/// SBOM Scanner: 취약점 DB 마지막 업데이트 시각 (gauge, Unix epoch)
pub const SBOM_SCANNER_VULNDB_LAST_UPDATE: &str =
    "ironpost_sbom_scanner_vulndb_last_update_timestamp";

// ─── Daemon 메트릭 ──────────────────────────────────────────────────

/// Daemon: 가동 시간 (gauge, 초)
pub const DAEMON_UPTIME_SECONDS: &str = "ironpost_daemon_uptime_seconds";

/// Daemon: 등록된 플러그인 수 (gauge)
pub const DAEMON_PLUGINS_REGISTERED: &str = "ironpost_daemon_plugins_registered";

/// Daemon: 빌드 정보 (gauge, 항상 1, labels: version, commit, rust_version)
pub const DAEMON_BUILD_INFO: &str = "ironpost_daemon_build_info";

// ─── 히스토그램 버킷 정의 ────────────────────────────────────────────

/// 로그 처리 지연 시간 히스토그램 버킷 (초)
///
/// 100us ~ 10s 범위, 로그 단위 분포
pub const PROCESSING_DURATION_BUCKETS: [f64; 10] = [
    0.0001, 0.0005, 0.001, 0.005, 0.01, 0.05, 0.1, 0.5, 1.0, 10.0,
];

/// 스캔 소요 시간 히스토그램 버킷 (초)
///
/// 100ms ~ 300s 범위 (SBOM 스캔은 디스크 I/O 포함)
pub const SCAN_DURATION_BUCKETS: [f64; 9] = [
    0.1, 0.5, 1.0, 5.0, 10.0, 30.0, 60.0, 120.0, 300.0,
];

// ─── 설명 등록 함수 ─────────────────────────────────────────────────

/// 모든 메트릭의 설명(description)을 등록합니다.
///
/// `metrics::describe_counter!()`, `describe_gauge!()`, `describe_histogram!()`을
/// 호출하여 Prometheus HELP 텍스트를 설정합니다.
///
/// 이 함수는 전역 레코더 설치 후 한 번만 호출해야 합니다.
/// 일반적으로 `ironpost-daemon`의 시작 시점에서 호출합니다.
pub fn describe_all() {
    use metrics::{describe_counter, describe_gauge, describe_histogram};

    // eBPF Engine
    describe_counter!(
        EBPF_PACKETS_TOTAL,
        "Total number of packets processed by eBPF XDP"
    );
    describe_counter!(
        EBPF_PACKETS_BLOCKED_TOTAL,
        "Total number of packets blocked (XDP_DROP) by eBPF"
    );
    describe_counter!(
        EBPF_BYTES_TOTAL,
        "Total bytes processed by eBPF XDP"
    );
    describe_histogram!(
        EBPF_XDP_PROCESSING_DURATION_SECONDS,
        "XDP packet processing latency in seconds"
    );
    describe_counter!(
        EBPF_PROTOCOL_PACKETS_TOTAL,
        "Packets processed per protocol (TCP, UDP, ICMP, other)"
    );
    describe_gauge!(
        EBPF_PACKETS_PER_SECOND,
        "Current packet processing rate (packets/sec)"
    );
    describe_gauge!(
        EBPF_BITS_PER_SECOND,
        "Current throughput rate (bits/sec)"
    );

    // Log Pipeline
    describe_counter!(
        LOG_PIPELINE_LOGS_COLLECTED_TOTAL,
        "Total number of raw log lines collected from all sources"
    );
    describe_counter!(
        LOG_PIPELINE_LOGS_PROCESSED_TOTAL,
        "Total number of log entries successfully parsed and processed"
    );
    describe_counter!(
        LOG_PIPELINE_PARSE_ERRORS_TOTAL,
        "Total number of log parsing failures"
    );
    describe_counter!(
        LOG_PIPELINE_RULE_MATCHES_TOTAL,
        "Total number of detection rule matches"
    );
    describe_counter!(
        LOG_PIPELINE_ALERTS_SENT_TOTAL,
        "Total number of alert events sent to downstream consumers"
    );
    describe_histogram!(
        LOG_PIPELINE_PROCESSING_DURATION_SECONDS,
        "Time to process a single log batch in seconds"
    );
    describe_gauge!(
        LOG_PIPELINE_BUFFER_SIZE,
        "Current number of log entries in the processing buffer"
    );
    describe_counter!(
        LOG_PIPELINE_LOGS_DROPPED_TOTAL,
        "Total number of log entries dropped due to buffer overflow"
    );

    // Container Guard
    describe_gauge!(
        CONTAINER_GUARD_MONITORED_CONTAINERS,
        "Number of containers currently being monitored"
    );
    describe_counter!(
        CONTAINER_GUARD_POLICY_VIOLATIONS_TOTAL,
        "Total number of security policy violations detected"
    );
    describe_counter!(
        CONTAINER_GUARD_ISOLATIONS_TOTAL,
        "Total number of container isolation actions executed"
    );
    describe_counter!(
        CONTAINER_GUARD_ISOLATION_FAILURES_TOTAL,
        "Total number of failed container isolation attempts"
    );
    describe_counter!(
        CONTAINER_GUARD_ALERTS_PROCESSED_TOTAL,
        "Total number of alert events processed by container guard"
    );
    describe_gauge!(
        CONTAINER_GUARD_POLICIES_LOADED,
        "Number of security policies currently loaded"
    );

    // SBOM Scanner
    describe_counter!(
        SBOM_SCANNER_SCANS_COMPLETED_TOTAL,
        "Total number of SBOM scans completed"
    );
    describe_gauge!(
        SBOM_SCANNER_CVES_FOUND,
        "Number of CVEs found by severity level"
    );
    describe_histogram!(
        SBOM_SCANNER_SCAN_DURATION_SECONDS,
        "Time to complete a single SBOM scan in seconds"
    );
    describe_counter!(
        SBOM_SCANNER_PACKAGES_SCANNED_TOTAL,
        "Total number of packages scanned across all SBOM scans"
    );
    describe_gauge!(
        SBOM_SCANNER_VULNDB_LAST_UPDATE,
        "Unix timestamp of the last vulnerability database update"
    );

    // Daemon
    describe_gauge!(
        DAEMON_UPTIME_SECONDS,
        "Ironpost daemon uptime in seconds"
    );
    describe_gauge!(
        DAEMON_PLUGINS_REGISTERED,
        "Number of plugins registered in the daemon"
    );
    describe_gauge!(
        DAEMON_BUILD_INFO,
        "Build information (always 1, with version/commit labels)"
    );
}
```

### 5.3 `crates/core/src/lib.rs` 변경

```rust
pub mod metrics;  // 추가
```

re-export 블록에 추가:

```rust
// 메트릭 상수
pub use metrics as metric_names;
```

---

## 6. 모듈별 계측 (Module Instrumentation)

### 6.1 eBPF Engine (`crates/ebpf-engine/src/engine.rs`, `stats.rs`)

#### 교체 대상

`stats.rs`의 `to_prometheus()` 메서드를 `metrics` crate 호출로 교체.

#### 메트릭 상세

| 메트릭 이름 | 타입 | 레이블 | 설명 |
|------------|------|--------|------|
| `ironpost_ebpf_packets_total` | counter | - | 처리된 전체 패킷 수 |
| `ironpost_ebpf_packets_blocked_total` | counter | - | XDP_DROP된 패킷 수 |
| `ironpost_ebpf_bytes_total` | counter | - | 처리된 전체 바이트 수 |
| `ironpost_ebpf_protocol_packets_total` | counter | `protocol`=`tcp\|udp\|icmp\|other` | 프로토콜별 패킷 수 |
| `ironpost_ebpf_xdp_processing_duration_seconds` | histogram | - | XDP 처리 지연 시간 |
| `ironpost_ebpf_packets_per_second` | gauge | `protocol`=`tcp\|udp\|icmp\|other\|total` | 초당 패킷 수 |
| `ironpost_ebpf_bits_per_second` | gauge | `protocol`=`tcp\|udp\|icmp\|other\|total` | 초당 비트 수 |

#### 계측 코드 예시

```rust
use ironpost_core::metrics as m;

// stats.rs update() 내부
fn update(&mut self, raw: RawTrafficSnapshot) {
    // 기존 rate 계산 로직 유지...

    // Prometheus 메트릭 업데이트
    metrics::counter!(m::EBPF_PACKETS_TOTAL).absolute(raw.total.packets);
    metrics::counter!(m::EBPF_BYTES_TOTAL).absolute(raw.total.bytes);
    metrics::counter!(m::EBPF_PACKETS_BLOCKED_TOTAL).absolute(raw.total.drops);

    for (proto, stats) in [
        ("tcp", &raw.tcp),
        ("udp", &raw.udp),
        ("icmp", &raw.icmp),
        ("other", &raw.other),
    ] {
        metrics::counter!(
            m::EBPF_PROTOCOL_PACKETS_TOTAL,
            m::LABEL_PROTOCOL => proto
        ).absolute(stats.packets);
    }

    // Rate 메트릭 (gauge)
    metrics::gauge!(m::EBPF_PACKETS_PER_SECOND, m::LABEL_PROTOCOL => "total")
        .set(self.total.pps);
    metrics::gauge!(m::EBPF_BITS_PER_SECOND, m::LABEL_PROTOCOL => "total")
        .set(self.total.bps);
}
```

**주의**: `to_prometheus()` 메서드는 제거하지 않고 `#[deprecated]`로 마킹한다. 하위 호환성을 유지하되, 새로운 코드는 `metrics` crate를 사용하도록 안내한다.

### 6.2 Log Pipeline (`crates/log-pipeline/src/pipeline.rs`)

#### 교체 대상

- `processed_count: Arc<AtomicU64>` --> `metrics::counter!()`
- `parse_error_count: Arc<AtomicU64>` --> `metrics::counter!()`

#### 메트릭 상세

| 메트릭 이름 | 타입 | 레이블 | 설명 |
|------------|------|--------|------|
| `ironpost_log_pipeline_logs_collected_total` | counter | - | 수집된 원시 로그 수 |
| `ironpost_log_pipeline_logs_processed_total` | counter | - | 파싱 성공한 로그 수 |
| `ironpost_log_pipeline_parse_errors_total` | counter | `format`=`syslog\|json\|unknown` | 파싱 실패 수 |
| `ironpost_log_pipeline_rule_matches_total` | counter | - | 규칙 매칭 수 |
| `ironpost_log_pipeline_alerts_sent_total` | counter | - | 전송된 알림 수 |
| `ironpost_log_pipeline_processing_duration_seconds` | histogram | - | 배치 처리 지연 시간 |
| `ironpost_log_pipeline_buffer_size` | gauge | - | 현재 버퍼 내 로그 수 |
| `ironpost_log_pipeline_logs_dropped_total` | counter | - | 드롭된 로그 수 |

#### 계측 코드 예시 (배치 처리 루프)

```rust
use ironpost_core::metrics as m;

// 배치 처리 함수 내부
fn process_batch(&self, batch: &[RawLog]) {
    let start = std::time::Instant::now();

    for raw in batch {
        metrics::counter!(m::LOG_PIPELINE_LOGS_COLLECTED_TOTAL).increment(1);

        match self.parser_router.parse(raw) {
            Ok(entry) => {
                metrics::counter!(m::LOG_PIPELINE_LOGS_PROCESSED_TOTAL).increment(1);

                if let Some(alert) = self.rule_engine.evaluate(&entry) {
                    metrics::counter!(m::LOG_PIPELINE_RULE_MATCHES_TOTAL).increment(1);
                    if self.alert_tx.try_send(alert).is_ok() {
                        metrics::counter!(m::LOG_PIPELINE_ALERTS_SENT_TOTAL).increment(1);
                    }
                }
            }
            Err(_) => {
                metrics::counter!(m::LOG_PIPELINE_PARSE_ERRORS_TOTAL).increment(1);
            }
        }
    }

    let elapsed = start.elapsed().as_secs_f64();
    metrics::histogram!(m::LOG_PIPELINE_PROCESSING_DURATION_SECONDS).record(elapsed);
}
```

#### `Arc<AtomicU64>` 제거 전략

`processed_count`와 `parse_error_count` 필드를 제거하고, `metrics::counter!()` 호출로 완전히 대체한다. 기존 공개 getter 메서드(`processed_count()`, `parse_error_count()`)는 유지하되 내부적으로 `metrics` recorder에서 조회하도록 변경한다.

다만, `metrics` 0.24 API에서는 recorder에서 현재 값을 직접 조회하는 기능이 제한적이므로, getter 메서드가 필요한 경우(테스트 등) 두 가지 선택지가 있다:

**선택 A (권장)**: `Arc<AtomicU64>`를 유지하면서 `metrics::counter!()`도 동시에 호출. getter는 `AtomicU64`에서 읽음.

```rust
// 기존 Arc<AtomicU64> 유지 + metrics crate 동시 업데이트
self.processed_count.fetch_add(1, Ordering::Relaxed);
metrics::counter!(m::LOG_PIPELINE_LOGS_PROCESSED_TOTAL).increment(1);
```

**선택 B**: `Arc<AtomicU64>`를 완전히 제거하고 getter도 삭제. 테스트는 `metrics` test recorder 사용.

**결정**: 선택 A를 채택한다. 기존 공개 API를 유지하면서 `metrics` crate 계측을 추가하는 방식이 가장 안전하다. 향후 v0.2에서 `AtomicU64` 제거를 검토한다.

### 6.3 Container Guard (`crates/container-guard/src/guard.rs`)

#### 교체 대상

- `alerts_processed: Arc<AtomicU64>`
- `isolations_executed: Arc<AtomicU64>`
- `isolation_failures: Arc<AtomicU64>`

#### 메트릭 상세

| 메트릭 이름 | 타입 | 레이블 | 설명 |
|------------|------|--------|------|
| `ironpost_container_guard_monitored_containers` | gauge | - | 모니터링 중인 컨테이너 수 |
| `ironpost_container_guard_policy_violations_total` | counter | - | 정책 위반 수 |
| `ironpost_container_guard_isolations_total` | counter | `action`=`disconnect\|pause\|stop`, `result`=`success\|failure` | 격리 실행 수 |
| `ironpost_container_guard_isolation_failures_total` | counter | - | 격리 실패 수 |
| `ironpost_container_guard_alerts_processed_total` | counter | - | 처리된 알림 수 |
| `ironpost_container_guard_policies_loaded` | gauge | - | 로드된 정책 수 |

#### 계측 코드 예시

```rust
use ironpost_core::metrics as m;

// guard.rs의 메인 루프 내부
async fn process_alert(&self, alert: &AlertEvent) {
    self.alerts_processed.fetch_add(1, Ordering::Relaxed);
    metrics::counter!(m::CONTAINER_GUARD_ALERTS_PROCESSED_TOTAL).increment(1);

    // ... 정책 평가 ...

    if policy_matched {
        metrics::counter!(m::CONTAINER_GUARD_POLICY_VIOLATIONS_TOTAL).increment(1);

        match self.executor.execute(action).await {
            Ok(()) => {
                self.isolations_executed.fetch_add(1, Ordering::Relaxed);
                metrics::counter!(
                    m::CONTAINER_GUARD_ISOLATIONS_TOTAL,
                    m::LABEL_ACTION => action_name,
                    m::LABEL_RESULT => "success"
                ).increment(1);
            }
            Err(e) => {
                self.isolation_failures.fetch_add(1, Ordering::Relaxed);
                metrics::counter!(
                    m::CONTAINER_GUARD_ISOLATIONS_TOTAL,
                    m::LABEL_ACTION => action_name,
                    m::LABEL_RESULT => "failure"
                ).increment(1);
                metrics::counter!(m::CONTAINER_GUARD_ISOLATION_FAILURES_TOTAL).increment(1);
            }
        }
    }
}

// 모니터링 루프에서 gauge 업데이트
fn update_container_count(&self, count: usize) {
    #[allow(clippy::cast_precision_loss)]
    metrics::gauge!(m::CONTAINER_GUARD_MONITORED_CONTAINERS).set(count as f64);
}
```

### 6.4 SBOM Scanner (`crates/sbom-scanner/src/scanner.rs`)

#### 교체 대상

- `scans_completed: Arc<AtomicU64>`
- `vulns_found: Arc<AtomicU64>`

#### 메트릭 상세

| 메트릭 이름 | 타입 | 레이블 | 설명 |
|------------|------|--------|------|
| `ironpost_sbom_scanner_scans_completed_total` | counter | - | 완료된 스캔 수 |
| `ironpost_sbom_scanner_cves_found` | gauge | `severity`=`info\|low\|medium\|high\|critical` | 심각도별 CVE 수 |
| `ironpost_sbom_scanner_scan_duration_seconds` | histogram | - | 스캔 소요 시간 |
| `ironpost_sbom_scanner_packages_scanned_total` | counter | `ecosystem`=`cargo\|npm` | 스캔된 패키지 수 |
| `ironpost_sbom_scanner_vulndb_last_update_timestamp` | gauge | - | VulnDb 마지막 업데이트 시각 |

#### 계측 코드 예시

```rust
use ironpost_core::metrics as m;

// scan_directory 함수 내부
async fn scan_directory(&self, dir: &Path, params: &ScanParams<'_>) -> Result<ScanResult, SbomScannerError> {
    let start = std::time::Instant::now();

    let result = self.perform_scan(dir, params).await?;

    let elapsed = start.elapsed().as_secs_f64();
    metrics::histogram!(m::SBOM_SCANNER_SCAN_DURATION_SECONDS).record(elapsed);

    params.scans_completed.fetch_add(1, Ordering::Relaxed);
    metrics::counter!(m::SBOM_SCANNER_SCANS_COMPLETED_TOTAL).increment(1);

    // 패키지 수
    let package_count: u64 = u64::try_from(result.packages.len()).unwrap_or(u64::MAX);
    metrics::counter!(
        m::SBOM_SCANNER_PACKAGES_SCANNED_TOTAL,
        m::LABEL_ECOSYSTEM => result.ecosystem.as_str()
    ).increment(package_count);

    // 심각도별 CVE gauge 업데이트
    #[allow(clippy::cast_precision_loss)]
    {
        metrics::gauge!(m::SBOM_SCANNER_CVES_FOUND, m::LABEL_SEVERITY => "critical")
            .set(result.severity_counts.critical as f64);
        metrics::gauge!(m::SBOM_SCANNER_CVES_FOUND, m::LABEL_SEVERITY => "high")
            .set(result.severity_counts.high as f64);
        metrics::gauge!(m::SBOM_SCANNER_CVES_FOUND, m::LABEL_SEVERITY => "medium")
            .set(result.severity_counts.medium as f64);
        metrics::gauge!(m::SBOM_SCANNER_CVES_FOUND, m::LABEL_SEVERITY => "low")
            .set(result.severity_counts.low as f64);
        metrics::gauge!(m::SBOM_SCANNER_CVES_FOUND, m::LABEL_SEVERITY => "info")
            .set(result.severity_counts.info as f64);
    }

    Ok(result)
}
```

---

## 7. HTTP 엔드포인트

### 7.1 위치

`ironpost-daemon/src/metrics_server.rs` (신규 파일)

### 7.2 구현

`metrics-exporter-prometheus`의 `PrometheusBuilder`를 사용한다. 이 빌더는 내부적으로 `hyper` 기반 HTTP 서버를 시작하여 `/metrics` 엔드포인트를 제공한다.

```rust
//! Prometheus 메트릭 HTTP 서버
//!
//! `metrics-exporter-prometheus`의 내장 HTTP 리스너를 사용하여
//! Prometheus scrape 엔드포인트를 노출합니다.
//!
//! # 사용
//!
//! ```ignore
//! let config = MetricsConfig::default();
//! install_metrics_recorder(&config)?;
//! // 이후 metrics::counter!() 등 호출 가능
//! ```

use std::net::SocketAddr;

use anyhow::Result;
use ironpost_core::config::MetricsConfig;
use metrics_exporter_prometheus::PrometheusBuilder;

/// 전역 메트릭 레코더를 설치하고 HTTP 리스너를 시작합니다.
///
/// 이 함수는 프로세스당 한 번만 호출해야 합니다.
/// 호출 후 모든 `metrics::counter!()`, `metrics::gauge!()`, `metrics::histogram!()`
/// 매크로가 Prometheus 형식으로 수집됩니다.
///
/// # Arguments
///
/// * `config` - 메트릭 설정 (listen_addr, port)
///
/// # Errors
///
/// - 소켓 바인딩 실패 시
/// - 전역 레코더가 이미 설치된 경우
pub fn install_metrics_recorder(config: &MetricsConfig) -> Result<()> {
    let addr: SocketAddr = format!("{}:{}", config.listen_addr, config.port)
        .parse()
        .map_err(|e| anyhow::anyhow!("invalid metrics listen address: {}", e))?;

    tracing::info!(
        listen_addr = %addr,
        endpoint = %config.endpoint,
        "installing Prometheus metrics recorder"
    );

    PrometheusBuilder::new()
        .with_http_listener(addr)
        .install()
        .map_err(|e| anyhow::anyhow!("failed to install metrics recorder: {}", e))?;

    // 메트릭 설명 등록
    ironpost_core::metrics::describe_all();

    tracing::info!(
        listen_addr = %addr,
        "Prometheus metrics endpoint active"
    );

    Ok(())
}
```

### 7.3 Orchestrator 통합

`ironpost-daemon/src/orchestrator.rs`의 `build_from_config()` 또는 `run()` 메서드에서 메트릭 서버를 시작한다.

```rust
// orchestrator.rs build_from_config() 내부, 플러그인 등록 전에 호출
if config.metrics.enabled {
    crate::metrics_server::install_metrics_recorder(&config.metrics)?;
    tracing::info!(port = config.metrics.port, "metrics endpoint enabled");
}
```

메트릭 레코더는 전역이므로, 설치 후 모든 모듈에서 `metrics::counter!()` 등의 매크로를 호출하면 자동으로 해당 레코더에 기록된다.

### 7.4 모듈 등록

`ironpost-daemon/src/lib.rs` 또는 `mod.rs`에 추가:

```rust
pub mod metrics_server;
```

---

## 8. Docker 및 Grafana 설정

### 8.1 docker-compose.yml 변경

#### 8.1.1 Ironpost 서비스에 메트릭 포트 추가

```yaml
ironpost:
  # ... 기존 설정 ...
  ports:
    - "${IRONPOST_SYSLOG_PORT:-514}:1514/udp"
    - "${IRONPOST_API_PORT:-8080}:8080"
    - "${IRONPOST_METRICS_PORT:-9100}:9100"    # <-- 추가
  environment:
    # ... 기존 환경변수 ...
    # Metrics
    IRONPOST_METRICS_ENABLED: ${IRONPOST_METRICS_ENABLED:-true}
    IRONPOST_METRICS_PORT: ${IRONPOST_METRICS_PORT:-9100}
    IRONPOST_METRICS_LISTEN_ADDR: "0.0.0.0"
```

#### 8.1.2 Prometheus 볼륨 마운트 활성화

```yaml
prometheus:
  # ... 기존 설정 ...
  volumes:
    - prometheus-data:/prometheus
    - ./prometheus/prometheus.yml:/etc/prometheus/prometheus.yml:ro  # 주석 해제 + 경로 변경
```

#### 8.1.3 Grafana 프로비저닝 볼륨 추가

```yaml
grafana:
  # ... 기존 설정 ...
  volumes:
    - grafana-data:/var/lib/grafana
    - ./grafana/provisioning:/etc/grafana/provisioning:ro             # 추가
    - ./grafana/dashboards:/var/lib/grafana/dashboards:ro             # 추가
```

### 8.2 Prometheus 설정

#### 파일: `docker/prometheus/prometheus.yml`

```yaml
# Ironpost Prometheus Configuration
global:
  scrape_interval: 15s
  evaluation_interval: 15s
  scrape_timeout: 10s

scrape_configs:
  # Ironpost daemon metrics
  - job_name: 'ironpost'
    static_configs:
      - targets: ['ironpost:9100']
        labels:
          instance: 'ironpost-daemon'
    metrics_path: '/metrics'
    scheme: 'http'

  # Prometheus self-monitoring
  - job_name: 'prometheus'
    static_configs:
      - targets: ['localhost:9090']
```

### 8.3 Grafana Datasource 프로비저닝

#### 파일: `docker/grafana/provisioning/datasources/prometheus.yml`

```yaml
apiVersion: 1

datasources:
  - name: Prometheus
    type: prometheus
    access: proxy
    url: http://prometheus:9090
    isDefault: true
    editable: false
    jsonData:
      timeInterval: '15s'
      httpMethod: POST
```

### 8.4 Grafana Dashboard 프로비저닝

#### 파일: `docker/grafana/provisioning/dashboards/dashboards.yml`

```yaml
apiVersion: 1

providers:
  - name: 'Ironpost'
    orgId: 1
    folder: 'Ironpost'
    type: file
    disableDeletion: false
    editable: true
    updateIntervalSeconds: 30
    allowUiUpdates: true
    options:
      path: /var/lib/grafana/dashboards
      foldersFromFilesStructure: false
```

### 8.5 Grafana 대시보드 JSON

3개의 대시보드 JSON 파일을 생성한다.

#### 8.5.1 Overview Dashboard (`docker/grafana/dashboards/ironpost-overview.json`)

**패널 구성:**

| 패널 | 타입 | PromQL 쿼리 | 위치 |
|------|------|------------|------|
| Daemon Uptime | Stat | `ironpost_daemon_uptime_seconds` | Row 1, Col 1 |
| Active Plugins | Stat | `ironpost_daemon_plugins_registered` | Row 1, Col 2 |
| Total Events/min | Stat | `rate(ironpost_log_pipeline_logs_collected_total[1m]) * 60` | Row 1, Col 3 |
| Total Alerts/min | Stat | `rate(ironpost_log_pipeline_alerts_sent_total[1m]) * 60` | Row 1, Col 4 |
| Monitored Containers | Stat | `ironpost_container_guard_monitored_containers` | Row 1, Col 5 |
| Event Rate | Time Series | `rate(ironpost_log_pipeline_logs_collected_total[5m])` | Row 2, Col 1-2 |
| Alert Rate | Time Series | `rate(ironpost_log_pipeline_alerts_sent_total[5m])` | Row 2, Col 2-3 |
| Isolation Actions | Time Series | `rate(ironpost_container_guard_isolations_total[5m])` | Row 3, Col 1 |
| CVE Distribution | Pie Chart | `ironpost_sbom_scanner_cves_found` (by severity) | Row 3, Col 2 |
| eBPF Throughput | Time Series | `ironpost_ebpf_bits_per_second{protocol="total"}` | Row 3, Col 3 |

#### 8.5.2 Log Pipeline Dashboard (`docker/grafana/dashboards/ironpost-log-pipeline.json`)

**패널 구성:**

| 패널 | 타입 | PromQL 쿼리 |
|------|------|------------|
| Collection Rate | Time Series | `rate(ironpost_log_pipeline_logs_collected_total[5m])` |
| Processing Rate | Time Series | `rate(ironpost_log_pipeline_logs_processed_total[5m])` |
| Error Rate | Time Series | `rate(ironpost_log_pipeline_parse_errors_total[5m])` |
| Error Ratio | Gauge | `rate(ironpost_log_pipeline_parse_errors_total[5m]) / rate(ironpost_log_pipeline_logs_collected_total[5m])` |
| Rule Match Rate | Time Series | `rate(ironpost_log_pipeline_rule_matches_total[5m])` |
| Alert Send Rate | Time Series | `rate(ironpost_log_pipeline_alerts_sent_total[5m])` |
| Buffer Size | Time Series | `ironpost_log_pipeline_buffer_size` |
| Dropped Logs | Time Series | `rate(ironpost_log_pipeline_logs_dropped_total[5m])` |
| Processing Latency (p50) | Time Series | `histogram_quantile(0.50, rate(ironpost_log_pipeline_processing_duration_seconds_bucket[5m]))` |
| Processing Latency (p95) | Time Series | `histogram_quantile(0.95, rate(ironpost_log_pipeline_processing_duration_seconds_bucket[5m]))` |
| Processing Latency (p99) | Time Series | `histogram_quantile(0.99, rate(ironpost_log_pipeline_processing_duration_seconds_bucket[5m]))` |

#### 8.5.3 Security Dashboard (`docker/grafana/dashboards/ironpost-security.json`)

**패널 구성:**

| 패널 | 타입 | PromQL 쿼리 |
|------|------|------------|
| CVEs by Severity | Bar Gauge | `ironpost_sbom_scanner_cves_found` (by severity label) |
| Critical CVEs | Stat (red bg) | `ironpost_sbom_scanner_cves_found{severity="critical"}` |
| High CVEs | Stat (orange bg) | `ironpost_sbom_scanner_cves_found{severity="high"}` |
| Scan Duration (p95) | Gauge | `histogram_quantile(0.95, rate(ironpost_sbom_scanner_scan_duration_seconds_bucket[5m]))` |
| Scans/Hour | Time Series | `rate(ironpost_sbom_scanner_scans_completed_total[1h]) * 3600` |
| Policy Violations | Time Series | `rate(ironpost_container_guard_policy_violations_total[5m])` |
| Isolation Success Rate | Gauge | `sum(rate(ironpost_container_guard_isolations_total{result="success"}[5m])) / sum(rate(ironpost_container_guard_isolations_total[5m]))` |
| Isolation Actions by Type | Time Series | `rate(ironpost_container_guard_isolations_total[5m])` (by action label) |
| eBPF Blocked Packets | Time Series | `rate(ironpost_ebpf_packets_blocked_total[5m])` |
| Protocol Distribution | Pie Chart | `ironpost_ebpf_protocol_packets_total` (by protocol label) |
| Packets/sec by Protocol | Time Series | `ironpost_ebpf_packets_per_second` (by protocol label) |
| VulnDB Last Update | Stat | `time() - ironpost_sbom_scanner_vulndb_last_update_timestamp` (초 단위, stale 경고) |

---

## 9. 파일 변경 요약

### 9.1 신규 생성 파일

| 파일 경로 | 설명 |
|----------|------|
| `crates/core/src/metrics.rs` | 메트릭 이름 상수, 레이블 키, 히스토그램 버킷, `describe_all()` |
| `ironpost-daemon/src/metrics_server.rs` | `install_metrics_recorder()` 함수 |
| `docker/prometheus/prometheus.yml` | Prometheus scrape 설정 |
| `docker/grafana/provisioning/datasources/prometheus.yml` | Grafana 데이터소스 프로비저닝 |
| `docker/grafana/provisioning/dashboards/dashboards.yml` | Grafana 대시보드 프로비저닝 |
| `docker/grafana/dashboards/ironpost-overview.json` | Overview 대시보드 |
| `docker/grafana/dashboards/ironpost-log-pipeline.json` | Log Pipeline 대시보드 |
| `docker/grafana/dashboards/ironpost-security.json` | Security 대시보드 |

### 9.2 수정 파일

| 파일 경로 | 변경 내용 |
|----------|----------|
| `Cargo.toml` (workspace) | `metrics`, `metrics-exporter-prometheus` 추가 |
| `crates/core/Cargo.toml` | `metrics` 의존성 추가 |
| `crates/core/src/lib.rs` | `pub mod metrics;` 추가, re-export |
| `crates/core/src/config.rs` | `MetricsConfig` 구조체 추가, `IronpostConfig`에 `metrics` 필드 추가, `override_u16()` 헬퍼, `validate()` 확장 |
| `crates/log-pipeline/Cargo.toml` | `metrics` 의존성 추가 |
| `crates/log-pipeline/src/pipeline.rs` | `metrics::counter!()`, `metrics::histogram!()` 호출 추가 |
| `crates/container-guard/Cargo.toml` | `metrics` 의존성 추가 |
| `crates/container-guard/src/guard.rs` | `metrics::counter!()`, `metrics::gauge!()` 호출 추가 |
| `crates/sbom-scanner/Cargo.toml` | `metrics` 의존성 추가 |
| `crates/sbom-scanner/src/scanner.rs` | `metrics::counter!()`, `metrics::gauge!()`, `metrics::histogram!()` 호출 추가 |
| `crates/ebpf-engine/Cargo.toml` | `metrics` 의존성 추가 |
| `crates/ebpf-engine/src/stats.rs` | `metrics::counter!()`, `metrics::gauge!()` 호출 추가, `to_prometheus()` deprecated |
| `crates/ebpf-engine/src/engine.rs` | `metrics::histogram!()` 호출 추가 (XDP 처리 지연) |
| `ironpost-daemon/Cargo.toml` | `metrics`, `metrics-exporter-prometheus` 의존성 추가 |
| `ironpost-daemon/src/lib.rs` | `pub mod metrics_server;` 추가 |
| `ironpost-daemon/src/orchestrator.rs` | `install_metrics_recorder()` 호출 추가, daemon 메트릭 계측 |
| `docker/docker-compose.yml` | 메트릭 포트 노출, prometheus.yml 마운트 활성화, grafana 프로비저닝 볼륨 |
| `ironpost.toml` (예시) | `[metrics]` 섹션 추가 |
| `ironpost.toml.example` | `[metrics]` 섹션 추가 |

### 9.3 테스트 파일 (신규/수정)

| 파일 경로 | 설명 |
|----------|------|
| `crates/core/tests/metrics_tests.rs` | 상수 이름 검증, `describe_all()` 호출 테스트 |
| `crates/core/tests/config_integration.rs` | `MetricsConfig` 파싱/검증 테스트 추가 |
| `ironpost-daemon/tests/metrics_server_tests.rs` | 레코더 설치/HTTP 응답 테스트 |

---

## 10. 구현 순서 (Implementation Plan)

### Phase 10-A: Core 인프라 (예상 2h)

| 순서 | 태스크 | 파일 | 설명 |
|------|--------|------|------|
| 1 | workspace 의존성 추가 | `Cargo.toml` | `metrics`, `metrics-exporter-prometheus` |
| 2 | `MetricsConfig` 구조체 작성 | `crates/core/src/config.rs` | 구조체, Default, validate, 환경변수 오버라이드 |
| 3 | `IronpostConfig`에 `metrics` 필드 추가 | `crates/core/src/config.rs` | 기존 테스트 호환성 확인 |
| 4 | `crates/core/src/metrics.rs` 작성 | 신규 | 상수, 버킷, `describe_all()` |
| 5 | `core/lib.rs`에 `pub mod metrics` 추가 | `crates/core/src/lib.rs` | re-export |
| 6 | `core` 테스트 작성 + 검증 | 테스트 파일 | config 파싱, 상수 네이밍 |

**검증**: `cargo test -p ironpost-core` + `cargo clippy -p ironpost-core -- -D warnings`

### Phase 10-B: Daemon 메트릭 서버 (예상 1h)

| 순서 | 태스크 | 파일 | 설명 |
|------|--------|------|------|
| 7 | `metrics_server.rs` 작성 | `ironpost-daemon/src/metrics_server.rs` | `install_metrics_recorder()` |
| 8 | `orchestrator.rs`에 메트릭 서버 시작 통합 | `ironpost-daemon/src/orchestrator.rs` | `config.metrics.enabled` 체크 |
| 9 | daemon `Cargo.toml` 의존성 추가 | `ironpost-daemon/Cargo.toml` | `metrics`, `metrics-exporter-prometheus` |
| 10 | daemon 메트릭 계측 (uptime, plugins) | `orchestrator.rs` | `DAEMON_UPTIME_SECONDS`, `DAEMON_PLUGINS_REGISTERED` |
| 11 | 테스트 작성 | 테스트 파일 | 레코더 설치, HTTP 응답 |

**검증**: `cargo test -p ironpost-daemon` + `cargo clippy -p ironpost-daemon -- -D warnings`

### Phase 10-C: 모듈 계측 (예상 3h)

| 순서 | 태스크 | 파일 | 설명 |
|------|--------|------|------|
| 12 | log-pipeline 계측 | `crates/log-pipeline/src/pipeline.rs` | counter, histogram 추가 |
| 13 | container-guard 계측 | `crates/container-guard/src/guard.rs` | counter, gauge 추가 |
| 14 | sbom-scanner 계측 | `crates/sbom-scanner/src/scanner.rs` | counter, gauge, histogram 추가 |
| 15 | ebpf-engine 계측 | `crates/ebpf-engine/src/stats.rs`, `engine.rs` | counter, gauge 추가, `to_prometheus()` deprecated |
| 16 | 각 모듈 테스트 업데이트 | 기존 테스트 파일 | `metrics` crate test recorder 사용 |

**검증**: `cargo test --workspace` + `cargo clippy --workspace -- -D warnings`

### Phase 10-D: Docker/Grafana 설정 (예상 2h)

| 순서 | 태스크 | 파일 | 설명 |
|------|--------|------|------|
| 17 | `docker-compose.yml` 수정 | `docker/docker-compose.yml` | 포트, 볼륨, 환경변수 |
| 18 | `prometheus.yml` 작성 | `docker/prometheus/prometheus.yml` | scrape config |
| 19 | Grafana datasource 프로비저닝 | `docker/grafana/provisioning/datasources/prometheus.yml` | |
| 20 | Grafana dashboard 프로비저닝 | `docker/grafana/provisioning/dashboards/dashboards.yml` | |
| 21 | Overview 대시보드 JSON | `docker/grafana/dashboards/ironpost-overview.json` | |
| 22 | Log Pipeline 대시보드 JSON | `docker/grafana/dashboards/ironpost-log-pipeline.json` | |
| 23 | Security 대시보드 JSON | `docker/grafana/dashboards/ironpost-security.json` | |

**검증**: `docker compose --profile monitoring up -d` + `curl localhost:9100/metrics` + Grafana UI

### Phase 10-E: 문서 및 마무리 (예상 1h)

| 순서 | 태스크 | 파일 | 설명 |
|------|--------|------|------|
| 24 | `ironpost.toml.example` 업데이트 | `ironpost.toml.example` | `[metrics]` 섹션 |
| 25 | `docs/configuration.md` 업데이트 | `docs/configuration.md` | 메트릭 설정 문서 |
| 26 | `CHANGELOG.md` 업데이트 | `CHANGELOG.md` | Phase 10 내용 |
| 27 | `docs/demo.md` 업데이트 | `docs/demo.md` | Grafana 접속 안내 |
| 28 | 전체 검증 | - | 모든 pre-commit 체크 통과 |

**최종 검증**:
```bash
cargo fmt --all --check
cargo clippy --workspace -- -D warnings
cargo test --workspace
cargo doc --workspace --no-deps
```

---

## 부록 A: 전체 메트릭 이름 목록

| 모듈 | 메트릭 이름 | 타입 | 레이블 |
|------|------------|------|--------|
| ebpf | `ironpost_ebpf_packets_total` | counter | - |
| ebpf | `ironpost_ebpf_packets_blocked_total` | counter | - |
| ebpf | `ironpost_ebpf_bytes_total` | counter | - |
| ebpf | `ironpost_ebpf_protocol_packets_total` | counter | `protocol` |
| ebpf | `ironpost_ebpf_xdp_processing_duration_seconds` | histogram | - |
| ebpf | `ironpost_ebpf_packets_per_second` | gauge | `protocol` |
| ebpf | `ironpost_ebpf_bits_per_second` | gauge | `protocol` |
| log-pipeline | `ironpost_log_pipeline_logs_collected_total` | counter | - |
| log-pipeline | `ironpost_log_pipeline_logs_processed_total` | counter | - |
| log-pipeline | `ironpost_log_pipeline_parse_errors_total` | counter | `format` |
| log-pipeline | `ironpost_log_pipeline_rule_matches_total` | counter | - |
| log-pipeline | `ironpost_log_pipeline_alerts_sent_total` | counter | - |
| log-pipeline | `ironpost_log_pipeline_processing_duration_seconds` | histogram | - |
| log-pipeline | `ironpost_log_pipeline_buffer_size` | gauge | - |
| log-pipeline | `ironpost_log_pipeline_logs_dropped_total` | counter | - |
| container-guard | `ironpost_container_guard_monitored_containers` | gauge | - |
| container-guard | `ironpost_container_guard_policy_violations_total` | counter | - |
| container-guard | `ironpost_container_guard_isolations_total` | counter | `action`, `result` |
| container-guard | `ironpost_container_guard_isolation_failures_total` | counter | - |
| container-guard | `ironpost_container_guard_alerts_processed_total` | counter | - |
| container-guard | `ironpost_container_guard_policies_loaded` | gauge | - |
| sbom-scanner | `ironpost_sbom_scanner_scans_completed_total` | counter | - |
| sbom-scanner | `ironpost_sbom_scanner_cves_found` | gauge | `severity` |
| sbom-scanner | `ironpost_sbom_scanner_scan_duration_seconds` | histogram | - |
| sbom-scanner | `ironpost_sbom_scanner_packages_scanned_total` | counter | `ecosystem` |
| sbom-scanner | `ironpost_sbom_scanner_vulndb_last_update_timestamp` | gauge | - |
| daemon | `ironpost_daemon_uptime_seconds` | gauge | - |
| daemon | `ironpost_daemon_plugins_registered` | gauge | - |
| daemon | `ironpost_daemon_build_info` | gauge | `version`, `commit` |

총 28개 메트릭.

---

## 부록 B: 위험 요소 및 완화

| 위험 | 영향 | 완화 방안 |
|------|------|----------|
| `metrics::counter!()` 매크로가 전역 레코더 없이 호출 시 no-op | 단위 테스트에서 메트릭 미기록 | 테스트에서 `metrics::with_local_recorder()` 또는 test recorder 사용 |
| 포트 9100이 node_exporter와 충돌 | Prometheus scrape 실패 | 기본 포트를 9100으로 하되 `IRONPOST_METRICS_PORT`로 변경 가능하도록 설정 |
| `metrics-exporter-prometheus` HTTP 서버가 tokio 런타임 점유 | 메인 이벤트 루프 영향 | 내장 리스너는 별도 스레드에서 실행되므로 영향 없음 |
| `Arc<AtomicU64>` + `metrics::counter!()` 이중 업데이트 | 미미한 성능 오버헤드 | v0.2에서 `AtomicU64` 제거로 단일화. 현재 오버헤드는 무시할 수준 |
| 대시보드 JSON이 Grafana 버전에 종속 | 11.3.1 이외 버전에서 호환 문제 | schemaVersion 필드로 호환성 관리, Grafana 11.x 검증 |
| `IronpostConfig`에 `metrics` 필드 추가 시 기존 TOML 파싱 | `#[serde(default)]`로 이전 TOML과 호환 | 단위 테스트에서 검증 |

---

## 부록 C: 향후 확장 계획

| 항목 | 설명 | 우선순위 |
|------|------|---------|
| Alertmanager 통합 | Prometheus alerting rules + Alertmanager 라우팅 | Medium |
| OpenTelemetry 지원 | `metrics-exporter-prometheus` 대신 `opentelemetry-prometheus` | Low |
| Push Gateway | 단기 실행 작업(스캔 등)의 메트릭 push | Low |
| Custom Collector | `/metrics` 엔드포인트에 시스템 메트릭(CPU, memory) 추가 | Medium |
| `Arc<AtomicU64>` 제거 | v0.2에서 이중 업데이트 제거 | High |
| Health 엔드포인트 | `/health` JSON API 추가 (기존 `DaemonHealth` 노출) | High |

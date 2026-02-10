//! 이벤트 시스템 — 모듈 간 통신의 기본 단위
//!
//! 모든 모듈 간 통신은 이벤트 기반 메시지 패싱으로 수행됩니다.
//! [`EventMetadata`]는 모든 이벤트에 공통으로 포함되는 메타데이터이며,
//! [`Event`] trait은 모든 이벤트 타입이 구현해야 하는 인터페이스입니다.

use std::fmt;
use std::time::SystemTime;

use bytes::Bytes;
use serde::{Deserialize, Serialize};

use crate::types::{Alert, LogEntry, PacketInfo, Severity};

// --- 모듈명 상수 ---

/// eBPF 엔진 모듈명
pub const MODULE_EBPF: &str = "ebpf-engine";
/// 로그 파이프라인 모듈명
pub const MODULE_LOG_PIPELINE: &str = "log-pipeline";
/// 컨테이너 가드 모듈명
pub const MODULE_CONTAINER_GUARD: &str = "container-guard";
/// SBOM 스캐너 모듈명
pub const MODULE_SBOM_SCANNER: &str = "sbom-scanner";

// --- 이벤트 타입 상수 ---

/// 패킷 이벤트 타입
pub const EVENT_TYPE_PACKET: &str = "packet";
/// 로그 이벤트 타입
pub const EVENT_TYPE_LOG: &str = "log";
/// 알림 이벤트 타입
pub const EVENT_TYPE_ALERT: &str = "alert";
/// 액션 이벤트 타입
pub const EVENT_TYPE_ACTION: &str = "action";
/// 스캔 이벤트 타입
pub const EVENT_TYPE_SCAN: &str = "scan";

/// 이벤트 메타데이터 — 모든 이벤트에 공통으로 포함되는 추적 정보
///
/// 각 이벤트의 발생 시각, 생성 모듈, 분산 추적 ID를 담고 있어
/// 이벤트 흐름을 추적하고 디버깅할 수 있습니다.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EventMetadata {
    /// 이벤트 발생 시각
    pub timestamp: SystemTime,
    /// 이벤트를 생성한 모듈명 (예: "ebpf-engine", "log-pipeline")
    pub source_module: String,
    /// 분산 추적 ID — 같은 흐름의 이벤트를 연결합니다
    pub trace_id: String,
}

impl EventMetadata {
    /// 기존 trace_id를 사용하여 새 메타데이터를 생성합니다.
    ///
    /// 이벤트 체인에서 동일한 추적 ID를 유지할 때 사용합니다.
    pub fn new(source_module: impl Into<String>, trace_id: impl Into<String>) -> Self {
        Self {
            timestamp: SystemTime::now(),
            source_module: source_module.into(),
            trace_id: trace_id.into(),
        }
    }

    /// 새로운 UUID v4 trace_id를 생성하여 메타데이터를 만듭니다.
    ///
    /// 새로운 이벤트 체인의 시작점에서 사용합니다.
    pub fn with_new_trace(source_module: impl Into<String>) -> Self {
        Self {
            timestamp: SystemTime::now(),
            source_module: source_module.into(),
            trace_id: uuid::Uuid::new_v4().to_string(),
        }
    }
}

impl fmt::Display for EventMetadata {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "[{}] source={} trace={}",
            unix_timestamp_str(self.timestamp),
            self.source_module,
            self.trace_id,
        )
    }
}

/// 모든 이벤트가 구현해야 하는 기본 trait
///
/// 각 모듈은 자체 이벤트 타입을 정의하고 이 trait을 구현합니다.
/// `Send + Sync + 'static` 바운드로 `tokio::mpsc` 채널을 통한
/// 안전한 전송을 보장합니다.
pub trait Event: Send + Sync + 'static {
    /// 이벤트 고유 ID (UUID v4)
    fn event_id(&self) -> &str;

    /// 이벤트 메타데이터 (timestamp, source_module, trace_id)
    fn metadata(&self) -> &EventMetadata;

    /// 이벤트 타입명 (로깅 및 라우팅에 사용)
    fn event_type(&self) -> &str;
}

/// eBPF에서 탐지한 패킷 이벤트
///
/// eBPF XDP 프로그램에서 캡처한 네트워크 패킷 정보를 담습니다.
/// 원시 패킷 데이터는 `bytes::Bytes`로 제로카피 슬라이싱이 가능합니다.
#[derive(Debug, Clone)]
pub struct PacketEvent {
    /// 이벤트 고유 ID
    pub id: String,
    /// 이벤트 메타데이터
    pub metadata: EventMetadata,
    /// 패킷 정보 (IP, 포트, 프로토콜 등)
    pub packet_info: PacketInfo,
    /// 원시 패킷 데이터
    pub raw_data: Bytes,
}

impl PacketEvent {
    /// 새로운 trace를 시작하는 패킷 이벤트를 생성합니다.
    pub fn new(packet_info: PacketInfo, raw_data: Bytes) -> Self {
        Self {
            id: uuid::Uuid::new_v4().to_string(),
            metadata: EventMetadata::with_new_trace(MODULE_EBPF),
            packet_info,
            raw_data,
        }
    }

    /// 기존 trace에 연결된 패킷 이벤트를 생성합니다.
    pub fn with_trace(
        packet_info: PacketInfo,
        raw_data: Bytes,
        trace_id: impl Into<String>,
    ) -> Self {
        Self {
            id: uuid::Uuid::new_v4().to_string(),
            metadata: EventMetadata::new(MODULE_EBPF, trace_id),
            packet_info,
            raw_data,
        }
    }
}

impl Event for PacketEvent {
    fn event_id(&self) -> &str {
        &self.id
    }

    fn metadata(&self) -> &EventMetadata {
        &self.metadata
    }

    fn event_type(&self) -> &str {
        EVENT_TYPE_PACKET
    }
}

impl fmt::Display for PacketEvent {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "PacketEvent[{}] {}:{} -> {}:{} proto={} size={}",
            &self.id[..8.min(self.id.len())],
            self.packet_info.src_ip,
            self.packet_info.src_port,
            self.packet_info.dst_ip,
            self.packet_info.dst_port,
            self.packet_info.protocol,
            self.packet_info.size,
        )
    }
}

/// 파싱된 로그 이벤트
///
/// 로그 파이프라인에서 원시 로그를 파싱한 결과를 담습니다.
#[derive(Debug, Clone)]
pub struct LogEvent {
    /// 이벤트 고유 ID
    pub id: String,
    /// 이벤트 메타데이터
    pub metadata: EventMetadata,
    /// 파싱된 로그 엔트리
    pub entry: LogEntry,
}

impl LogEvent {
    /// 새로운 trace를 시작하는 로그 이벤트를 생성합니다.
    pub fn new(entry: LogEntry) -> Self {
        Self {
            id: uuid::Uuid::new_v4().to_string(),
            metadata: EventMetadata::with_new_trace(MODULE_LOG_PIPELINE),
            entry,
        }
    }

    /// 기존 trace에 연결된 로그 이벤트를 생성합니다.
    pub fn with_trace(entry: LogEntry, trace_id: impl Into<String>) -> Self {
        Self {
            id: uuid::Uuid::new_v4().to_string(),
            metadata: EventMetadata::new(MODULE_LOG_PIPELINE, trace_id),
            entry,
        }
    }
}

impl Event for LogEvent {
    fn event_id(&self) -> &str {
        &self.id
    }

    fn metadata(&self) -> &EventMetadata {
        &self.metadata
    }

    fn event_type(&self) -> &str {
        EVENT_TYPE_LOG
    }
}

impl fmt::Display for LogEvent {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "LogEvent[{}] source={} host={} severity={}",
            &self.id[..8.min(self.id.len())],
            self.entry.source,
            self.entry.hostname,
            self.entry.severity,
        )
    }
}

/// 룰 매칭으로 생성된 알림 이벤트
///
/// 탐지 규칙에 매칭되어 보안 알림이 발생했을 때 생성됩니다.
#[derive(Debug, Clone)]
pub struct AlertEvent {
    /// 이벤트 고유 ID
    pub id: String,
    /// 이벤트 메타데이터
    pub metadata: EventMetadata,
    /// 알림 상세 정보
    pub alert: Alert,
    /// 알림 심각도
    pub severity: Severity,
}

impl AlertEvent {
    /// 새로운 trace를 시작하는 알림 이벤트를 생성합니다.
    pub fn new(alert: Alert, severity: Severity) -> Self {
        Self {
            id: uuid::Uuid::new_v4().to_string(),
            metadata: EventMetadata::with_new_trace(MODULE_LOG_PIPELINE),
            alert,
            severity,
        }
    }

    /// 기존 trace에 연결된 알림 이벤트를 생성합니다.
    pub fn with_trace(alert: Alert, severity: Severity, trace_id: impl Into<String>) -> Self {
        Self {
            id: uuid::Uuid::new_v4().to_string(),
            metadata: EventMetadata::new(MODULE_LOG_PIPELINE, trace_id),
            alert,
            severity,
        }
    }
}

impl Event for AlertEvent {
    fn event_id(&self) -> &str {
        &self.id
    }

    fn metadata(&self) -> &EventMetadata {
        &self.metadata
    }

    fn event_type(&self) -> &str {
        EVENT_TYPE_ALERT
    }
}

impl fmt::Display for AlertEvent {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "AlertEvent[{}] rule={} severity={} title={}",
            &self.id[..8.min(self.id.len())],
            self.alert.rule_name,
            self.severity,
            self.alert.title,
        )
    }
}

/// 실행된 액션 이벤트 (컨테이너 격리 등)
///
/// 알림에 대한 대응 조치가 실행되었을 때 생성됩니다.
#[derive(Debug, Clone)]
pub struct ActionEvent {
    /// 이벤트 고유 ID
    pub id: String,
    /// 이벤트 메타데이터
    pub metadata: EventMetadata,
    /// 액션 타입 (예: "container_isolate", "block_ip")
    pub action_type: String,
    /// 대상 (예: 컨테이너 ID, IP 주소)
    pub target: String,
    /// 성공 여부
    pub success: bool,
}

impl ActionEvent {
    /// 새로운 trace를 시작하는 액션 이벤트를 생성합니다.
    pub fn new(action_type: impl Into<String>, target: impl Into<String>, success: bool) -> Self {
        Self {
            id: uuid::Uuid::new_v4().to_string(),
            metadata: EventMetadata::with_new_trace(MODULE_CONTAINER_GUARD),
            action_type: action_type.into(),
            target: target.into(),
            success,
        }
    }

    /// 기존 trace에 연결된 액션 이벤트를 생성합니다.
    pub fn with_trace(
        action_type: impl Into<String>,
        target: impl Into<String>,
        success: bool,
        trace_id: impl Into<String>,
    ) -> Self {
        Self {
            id: uuid::Uuid::new_v4().to_string(),
            metadata: EventMetadata::new(MODULE_CONTAINER_GUARD, trace_id),
            action_type: action_type.into(),
            target: target.into(),
            success,
        }
    }
}

impl Event for ActionEvent {
    fn event_id(&self) -> &str {
        &self.id
    }

    fn metadata(&self) -> &EventMetadata {
        &self.metadata
    }

    fn event_type(&self) -> &str {
        EVENT_TYPE_ACTION
    }
}

impl fmt::Display for ActionEvent {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let status = if self.success { "OK" } else { "FAILED" };
        write!(
            f,
            "ActionEvent[{}] type={} target={} status={}",
            &self.id[..8.min(self.id.len())],
            self.action_type,
            self.target,
            status,
        )
    }
}

/// SystemTime을 사람이 읽을 수 있는 형태로 변환합니다.
fn unix_timestamp_str(time: SystemTime) -> String {
    match time.duration_since(SystemTime::UNIX_EPOCH) {
        Ok(duration) => {
            let secs = duration.as_secs();
            format!("{secs}")
        }
        Err(_) => "unknown".to_owned(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::IpAddr;

    fn sample_packet_info() -> PacketInfo {
        PacketInfo {
            src_ip: "192.168.1.1".parse::<IpAddr>().unwrap(),
            dst_ip: "10.0.0.1".parse::<IpAddr>().unwrap(),
            src_port: 12345,
            dst_port: 80,
            protocol: 6,
            size: 1500,
            timestamp: SystemTime::now(),
        }
    }

    fn sample_log_entry() -> LogEntry {
        LogEntry {
            source: "/var/log/syslog".to_owned(),
            timestamp: SystemTime::now(),
            hostname: "server-01".to_owned(),
            process: "sshd".to_owned(),
            message: "Failed password for root".to_owned(),
            severity: Severity::High,
            fields: vec![("pid".to_owned(), "1234".to_owned())],
        }
    }

    fn sample_alert() -> Alert {
        Alert {
            id: "alert-001".to_owned(),
            title: "Brute force detected".to_owned(),
            description: "Multiple failed SSH login attempts".to_owned(),
            severity: Severity::High,
            rule_name: "ssh_brute_force".to_owned(),
            source_ip: Some("192.168.1.100".parse().unwrap()),
            target_ip: Some("10.0.0.1".parse().unwrap()),
            created_at: SystemTime::now(),
        }
    }

    #[test]
    fn event_metadata_new_preserves_trace_id() {
        let meta = EventMetadata::new("test-module", "trace-abc-123");
        assert_eq!(meta.source_module, "test-module");
        assert_eq!(meta.trace_id, "trace-abc-123");
        assert!(meta.timestamp <= SystemTime::now());
    }

    #[test]
    fn event_metadata_with_new_trace_generates_uuid() {
        let meta = EventMetadata::with_new_trace("test-module");
        assert_eq!(meta.source_module, "test-module");
        assert!(!meta.trace_id.is_empty());
        // UUID v4 형식 확인: 8-4-4-4-12
        assert_eq!(meta.trace_id.len(), 36);
        assert_eq!(meta.trace_id.chars().filter(|c| *c == '-').count(), 4);
    }

    #[test]
    fn event_metadata_display() {
        let meta = EventMetadata::new("ebpf-engine", "trace-xyz");
        let display = meta.to_string();
        assert!(display.contains("ebpf-engine"));
        assert!(display.contains("trace-xyz"));
    }

    #[test]
    fn packet_event_implements_event_trait() {
        let event = PacketEvent::new(sample_packet_info(), Bytes::from_static(b"raw-data"));
        assert_eq!(event.event_type(), "packet");
        assert!(!event.event_id().is_empty());
        assert_eq!(event.metadata().source_module, "ebpf-engine");
    }

    #[test]
    fn packet_event_with_trace_preserves_trace_id() {
        let event = PacketEvent::with_trace(
            sample_packet_info(),
            Bytes::from_static(b"data"),
            "my-trace-id",
        );
        assert_eq!(event.metadata().trace_id, "my-trace-id");
    }

    #[test]
    fn packet_event_display() {
        let event = PacketEvent::new(sample_packet_info(), Bytes::from_static(b"data"));
        let display = event.to_string();
        assert!(display.contains("192.168.1.1"));
        assert!(display.contains("10.0.0.1"));
        assert!(display.contains("PacketEvent"));
    }

    #[test]
    fn log_event_implements_event_trait() {
        let event = LogEvent::new(sample_log_entry());
        assert_eq!(event.event_type(), "log");
        assert!(!event.event_id().is_empty());
        assert_eq!(event.metadata().source_module, "log-pipeline");
    }

    #[test]
    fn log_event_with_trace() {
        let event = LogEvent::with_trace(sample_log_entry(), "existing-trace");
        assert_eq!(event.metadata().trace_id, "existing-trace");
    }

    #[test]
    fn alert_event_implements_event_trait() {
        let event = AlertEvent::new(sample_alert(), Severity::High);
        assert_eq!(event.event_type(), "alert");
        assert_eq!(event.severity, Severity::High);
        assert!(!event.event_id().is_empty());
    }

    #[test]
    fn alert_event_display() {
        let event = AlertEvent::new(sample_alert(), Severity::High);
        let display = event.to_string();
        assert!(display.contains("ssh_brute_force"));
        assert!(display.contains("High"));
    }

    #[test]
    fn action_event_implements_event_trait() {
        let event = ActionEvent::new("container_isolate", "container-abc", true);
        assert_eq!(event.event_type(), "action");
        assert_eq!(event.action_type, "container_isolate");
        assert_eq!(event.target, "container-abc");
        assert!(event.success);
    }

    #[test]
    fn action_event_with_trace() {
        let event = ActionEvent::with_trace("block_ip", "192.168.1.100", false, "trace-from-alert");
        assert_eq!(event.metadata().trace_id, "trace-from-alert");
        assert!(!event.success);
    }

    #[test]
    fn action_event_display_success() {
        let event = ActionEvent::new("container_isolate", "abc", true);
        assert!(event.to_string().contains("OK"));
    }

    #[test]
    fn action_event_display_failure() {
        let event = ActionEvent::new("container_isolate", "abc", false);
        assert!(event.to_string().contains("FAILED"));
    }

    #[test]
    fn events_are_send_sync() {
        fn assert_send_sync<T: Send + Sync + 'static>() {}
        assert_send_sync::<PacketEvent>();
        assert_send_sync::<LogEvent>();
        assert_send_sync::<AlertEvent>();
        assert_send_sync::<ActionEvent>();
    }
}

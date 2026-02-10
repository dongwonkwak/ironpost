//! SBOM 스캔 이벤트
//!
//! [`ScanEvent`]는 SBOM 스캔 결과를 나타내는 이벤트입니다.
//! core의 [`Event`] trait을 구현하여 `tokio::mpsc` 채널을 통한 전송이 가능합니다.
//!
//! # 사용 예시
//!
//! ```
//! use ironpost_sbom_scanner::ScanEvent;
//! use ironpost_sbom_scanner::vuln::ScanResult;
//! use ironpost_sbom_scanner::types::Ecosystem;
//! use ironpost_core::event::Event;
//! use std::time::SystemTime;
//!
//! let result = ScanResult {
//!     scan_id: "scan-001".to_owned(),
//!     source_file: "Cargo.lock".to_owned(),
//!     ecosystem: Ecosystem::Cargo,
//!     total_packages: 42,
//!     findings: vec![],
//!     sbom_document: None,
//!     scanned_at: SystemTime::now(),
//! };
//!
//! let event = ScanEvent::new(result);
//! assert_eq!(event.event_type(), "scan");
//! ```

use std::fmt;

use ironpost_core::event::{EVENT_TYPE_SCAN, Event, EventMetadata, MODULE_SBOM_SCANNER};

use crate::vuln::ScanResult;

/// SBOM 스캔 결과 이벤트
///
/// 스캔 완료 시 생성되어 모듈 간 통신에 사용됩니다.
/// `Send + Sync + 'static` 바운드를 만족하여 `tokio::mpsc` 전송이 가능합니다.
#[derive(Debug, Clone)]
pub struct ScanEvent {
    /// 이벤트 고유 ID
    pub id: String,
    /// 이벤트 메타데이터
    pub metadata: EventMetadata,
    /// 스캔 결과
    pub scan_result: ScanResult,
}

impl ScanEvent {
    /// 새로운 trace를 시작하는 스캔 이벤트를 생성합니다.
    pub fn new(scan_result: ScanResult) -> Self {
        Self {
            id: uuid::Uuid::new_v4().to_string(),
            metadata: EventMetadata::with_new_trace(MODULE_SBOM_SCANNER),
            scan_result,
        }
    }

    /// 기존 trace에 연결된 스캔 이벤트를 생성합니다.
    pub fn with_trace(scan_result: ScanResult, trace_id: impl Into<String>) -> Self {
        Self {
            id: uuid::Uuid::new_v4().to_string(),
            metadata: EventMetadata::new(MODULE_SBOM_SCANNER, trace_id),
            scan_result,
        }
    }
}

impl Event for ScanEvent {
    fn event_id(&self) -> &str {
        &self.id
    }

    fn metadata(&self) -> &EventMetadata {
        &self.metadata
    }

    fn event_type(&self) -> &str {
        EVENT_TYPE_SCAN
    }
}

impl fmt::Display for ScanEvent {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "ScanEvent[{}] source={} packages={} findings={}",
            &self.id[..8.min(self.id.len())],
            self.scan_result.source_file,
            self.scan_result.total_packages,
            self.scan_result.findings.len(),
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::Ecosystem;
    use std::time::SystemTime;

    fn sample_scan_result() -> ScanResult {
        ScanResult {
            scan_id: "test-scan".to_owned(),
            source_file: "Cargo.lock".to_owned(),
            ecosystem: Ecosystem::Cargo,
            total_packages: 42,
            findings: vec![],
            sbom_document: None,
            scanned_at: SystemTime::now(),
        }
    }

    #[test]
    fn scan_event_implements_event_trait() {
        let event = ScanEvent::new(sample_scan_result());
        assert_eq!(event.event_type(), "scan");
        assert!(!event.event_id().is_empty());
        assert_eq!(event.metadata().source_module, "sbom-scanner");
    }

    #[test]
    fn scan_event_with_trace_preserves_trace_id() {
        let event = ScanEvent::with_trace(sample_scan_result(), "my-trace-id");
        assert_eq!(event.metadata().trace_id, "my-trace-id");
    }

    #[test]
    fn scan_event_display() {
        let event = ScanEvent::new(sample_scan_result());
        let display = event.to_string();
        assert!(display.contains("ScanEvent"));
        assert!(display.contains("Cargo.lock"));
        assert!(display.contains("42"));
    }

    #[test]
    fn scan_event_is_send_sync() {
        fn assert_send_sync<T: Send + Sync + 'static>() {}
        assert_send_sync::<ScanEvent>();
    }
}

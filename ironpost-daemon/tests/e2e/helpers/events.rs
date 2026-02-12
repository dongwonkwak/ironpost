//! Event factory functions for E2E tests.
//!
//! Provides convenient constructors for creating test events
//! with sensible defaults.

use std::time::SystemTime;

use ironpost_core::event::{AlertEvent, LogEvent, MODULE_SBOM_SCANNER};
use ironpost_core::types::{Alert, LogEntry, Severity};

/// Create a test `LogEvent` with configurable message and severity.
///
/// Uses "test-host" as hostname and "test-process" as process name.
#[allow(dead_code)]
pub fn create_test_log_event(message: &str, severity: Severity) -> LogEvent {
    LogEvent::new(LogEntry {
        source: "/var/log/test".to_owned(),
        timestamp: SystemTime::now(),
        hostname: "test-host".to_owned(),
        process: "test-process".to_owned(),
        message: message.to_owned(),
        severity,
        fields: vec![],
    })
}

/// Create a test `LogEvent` that should trigger a brute-force detection rule.
#[allow(dead_code)]
pub fn create_test_ssh_brute_force_log() -> LogEvent {
    create_test_log_event(
        "Failed password for root from 192.168.1.100 port 22",
        Severity::High,
    )
}

/// Create a test `AlertEvent` with configurable title and severity.
///
/// Uses `MODULE_LOG_PIPELINE` as the source module.
#[allow(dead_code)]
pub fn create_test_alert_event(title: &str, severity: Severity) -> AlertEvent {
    AlertEvent::new(
        Alert {
            id: uuid::Uuid::new_v4().to_string(),
            title: title.to_owned(),
            description: format!("Test alert: {title}"),
            severity,
            rule_name: "test-rule".to_owned(),
            source_ip: Some("192.168.1.100".parse().expect("valid IP")),
            target_ip: Some("10.0.0.1".parse().expect("valid IP")),
            created_at: SystemTime::now(),
        },
        severity,
    )
}

/// Create a test `AlertEvent` originating from the SBOM scanner.
#[allow(dead_code)]
pub fn create_test_sbom_alert(cve_id: &str, severity: Severity) -> AlertEvent {
    AlertEvent::with_source(
        Alert {
            id: uuid::Uuid::new_v4().to_string(),
            title: format!("Vulnerability found: {cve_id}"),
            description: format!("CVE {cve_id} detected in dependency"),
            severity,
            rule_name: format!("sbom-{cve_id}"),
            source_ip: None,
            target_ip: None,
            created_at: SystemTime::now(),
        },
        severity,
        MODULE_SBOM_SCANNER,
    )
}

/// Create a high-severity alert suitable for triggering container isolation.
#[allow(dead_code)]
pub fn create_test_isolation_alert() -> AlertEvent {
    create_test_alert_event("Critical security violation", Severity::Critical)
}

/// Create a low-severity alert that should NOT trigger container isolation.
#[allow(dead_code)]
pub fn create_test_low_severity_alert() -> AlertEvent {
    create_test_alert_event("Informational log event", Severity::Info)
}

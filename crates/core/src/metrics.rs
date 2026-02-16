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
pub const SBOM_SCANNER_SCANS_COMPLETED_TOTAL: &str = "ironpost_sbom_scanner_scans_completed_total";

/// SBOM Scanner: 발견된 CVE 수 (gauge, label: severity)
pub const SBOM_SCANNER_CVES_FOUND: &str = "ironpost_sbom_scanner_cves_found";

/// SBOM Scanner: 스캔 소요 시간 (histogram, 초)
pub const SBOM_SCANNER_SCAN_DURATION_SECONDS: &str = "ironpost_sbom_scanner_scan_duration_seconds";

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
pub const SCAN_DURATION_BUCKETS: [f64; 9] = [0.1, 0.5, 1.0, 5.0, 10.0, 30.0, 60.0, 120.0, 300.0];

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
    describe_counter!(EBPF_BYTES_TOTAL, "Total bytes processed by eBPF XDP");
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
    describe_gauge!(EBPF_BITS_PER_SECOND, "Current throughput rate (bits/sec)");

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
    describe_gauge!(DAEMON_UPTIME_SECONDS, "Ironpost daemon uptime in seconds");
    describe_gauge!(
        DAEMON_PLUGINS_REGISTERED,
        "Number of plugins registered in the daemon"
    );
    describe_gauge!(
        DAEMON_BUILD_INFO,
        "Build information (always 1, with version/commit labels)"
    );
}

#[cfg(test)]
mod tests {
    use super::*;

    // メトリック名の一覧（テスト用）
    const ALL_METRIC_NAMES: &[&str] = &[
        EBPF_PACKETS_TOTAL,
        EBPF_PACKETS_BLOCKED_TOTAL,
        EBPF_BYTES_TOTAL,
        EBPF_XDP_PROCESSING_DURATION_SECONDS,
        EBPF_PROTOCOL_PACKETS_TOTAL,
        EBPF_PACKETS_PER_SECOND,
        EBPF_BITS_PER_SECOND,
        LOG_PIPELINE_LOGS_COLLECTED_TOTAL,
        LOG_PIPELINE_LOGS_PROCESSED_TOTAL,
        LOG_PIPELINE_PARSE_ERRORS_TOTAL,
        LOG_PIPELINE_RULE_MATCHES_TOTAL,
        LOG_PIPELINE_ALERTS_SENT_TOTAL,
        LOG_PIPELINE_PROCESSING_DURATION_SECONDS,
        LOG_PIPELINE_BUFFER_SIZE,
        LOG_PIPELINE_LOGS_DROPPED_TOTAL,
        CONTAINER_GUARD_MONITORED_CONTAINERS,
        CONTAINER_GUARD_POLICY_VIOLATIONS_TOTAL,
        CONTAINER_GUARD_ISOLATIONS_TOTAL,
        CONTAINER_GUARD_ISOLATION_FAILURES_TOTAL,
        CONTAINER_GUARD_ALERTS_PROCESSED_TOTAL,
        CONTAINER_GUARD_POLICIES_LOADED,
        SBOM_SCANNER_SCANS_COMPLETED_TOTAL,
        SBOM_SCANNER_CVES_FOUND,
        SBOM_SCANNER_SCAN_DURATION_SECONDS,
        SBOM_SCANNER_PACKAGES_SCANNED_TOTAL,
        SBOM_SCANNER_VULNDB_LAST_UPDATE,
        DAEMON_UPTIME_SECONDS,
        DAEMON_PLUGINS_REGISTERED,
        DAEMON_BUILD_INFO,
    ];

    #[test]
    fn all_metrics_start_with_ironpost_prefix() {
        for name in ALL_METRIC_NAMES {
            assert!(
                name.starts_with("ironpost_"),
                "Metric '{}' does not start with 'ironpost_' prefix",
                name
            );
        }
    }

    #[test]
    fn all_metrics_have_29_entries() {
        // Design document mentions 28 but actually defines 29 metrics
        // (7 eBPF + 8 Log Pipeline + 6 Container Guard + 5 SBOM Scanner + 3 Daemon)
        assert_eq!(
            ALL_METRIC_NAMES.len(),
            29,
            "Expected 29 metrics (7 eBPF + 8 Log Pipeline + 6 Container Guard + 5 SBOM + 3 Daemon)"
        );
    }

    #[test]
    fn describe_all_does_not_panic() {
        // describe_all() should not panic even without a recorder installed
        describe_all();
    }

    #[test]
    fn label_keys_are_lowercase() {
        let labels = [
            LABEL_PROTOCOL,
            LABEL_SEVERITY,
            LABEL_MODULE,
            LABEL_PARSER_FORMAT,
            LABEL_ACTION,
            LABEL_ECOSYSTEM,
            LABEL_RESULT,
        ];
        for label in &labels {
            assert_eq!(
                label.to_lowercase(),
                *label,
                "Label key '{}' should be lowercase",
                label
            );
        }
    }

    #[test]
    fn processing_duration_buckets_are_sorted() {
        let buckets = PROCESSING_DURATION_BUCKETS;
        for i in 1..buckets.len() {
            assert!(
                buckets[i] > buckets[i - 1],
                "Bucket values must be in ascending order"
            );
        }
    }

    #[test]
    fn scan_duration_buckets_are_sorted() {
        let buckets = SCAN_DURATION_BUCKETS;
        for i in 1..buckets.len() {
            assert!(
                buckets[i] > buckets[i - 1],
                "Bucket values must be in ascending order"
            );
        }
    }
}

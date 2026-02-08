//! 탐지 로직 — 패킷 기반 위협 탐지
//!
//! SYN flood, 포트 스캔 등 네트워크 레벨 이상 탐지를 수행합니다.
//! [`core::Detector`] trait을 구현하여 통합 탐지 파이프라인에 참여합니다.
//!
//! # 탐지 전략
//! - **SYN Flood**: SYN 패킷 비율이 임계값을 초과하면 알림
//! - **포트 스캔**: 단일 IP에서 N개 이상의 포트에 접근하면 알림
//!
//! # 아키텍처
//! ```text
//! PacketEventData ──▶ PacketDetector ──▶ AlertEvent ──▶ mpsc::Sender
//!                        │
//!                        ├── SynFloodDetector (impl Detector)
//!                        └── PortScanDetector (impl Detector)
//! ```

use std::collections::{HashMap, HashSet};
use std::net::{IpAddr, Ipv4Addr};
use std::time::{Instant, SystemTime};

use tokio::sync::mpsc;

use ironpost_core::error::{IronpostError, PipelineError};
use ironpost_core::event::AlertEvent;
use ironpost_core::pipeline::Detector;
use ironpost_core::types::{Alert, LogEntry, Severity};

use ironpost_ebpf_common::{PacketEventData, TCP_ACK, TCP_SYN};

// =============================================================================
// 탐지 설정
// =============================================================================

/// SYN flood 탐지 설정
#[derive(Debug, Clone)]
pub struct SynFloodConfig {
    /// SYN-only 패킷 비율 임계값 (0.0~1.0, 예: 0.7 = 70% 이상이면 탐지)
    pub threshold_ratio: f64,
    /// 측정 윈도우 크기 (초)
    pub window_secs: u64,
    /// 최소 패킷 수 (이 이상이어야 탐지 활성화, 오탐 방지)
    pub min_packets: u64,
}

impl Default for SynFloodConfig {
    fn default() -> Self {
        Self {
            threshold_ratio: 0.7,
            window_secs: 10,
            min_packets: 100,
        }
    }
}

/// 포트 스캔 탐지 설정
#[derive(Debug, Clone)]
pub struct PortScanConfig {
    /// 동일 IP에서 접근한 고유 포트 수 임계값
    pub port_threshold: usize,
    /// 측정 윈도우 크기 (초)
    pub window_secs: u64,
}

impl Default for PortScanConfig {
    fn default() -> Self {
        Self {
            port_threshold: 20,
            window_secs: 60,
        }
    }
}

// =============================================================================
// 내부 추적 상태
// =============================================================================

/// IP별 SYN 패킷 추적 상태
struct SynCounter {
    /// 전체 TCP 패킷 수
    total_tcp: u64,
    /// SYN-only 패킷 수 (SYN=1, ACK=0)
    syn_only: u64,
    /// 윈도우 시작 시각
    window_start: Instant,
}

/// IP별 포트 접근 추적 상태
struct PortTracker {
    /// 접근한 고유 포트 집합
    ports: HashSet<u16>,
    /// 윈도우 시작 시각
    window_start: Instant,
}

// =============================================================================
// SYN Flood 탐지기 (core::Detector trait 구현)
// =============================================================================

/// SYN flood 탐지기
///
/// 단일 IP에서 오는 SYN-only 패킷(SYN=1, ACK=0)의 비율이
/// 임계값을 초과하면 알림을 생성합니다.
///
/// # Interior Mutability
/// `Detector::detect()`이 `&self`를 받으므로 내부 상태 변경에
/// `tokio::sync::Mutex`의 `try_lock()`을 사용합니다 (non-blocking).
pub struct SynFloodDetector {
    config: SynFloodConfig,
    /// IP별 SYN 카운터 (tokio::sync::Mutex + try_lock으로 sync 컨텍스트에서 사용)
    state: tokio::sync::Mutex<HashMap<IpAddr, SynCounter>>,
}

impl SynFloodDetector {
    /// 새 SYN flood 탐지기를 생성합니다.
    pub fn new(config: SynFloodConfig) -> Self {
        Self {
            config,
            state: tokio::sync::Mutex::new(HashMap::new()),
        }
    }

    /// 내부 상태에서 만료된 윈도우를 정리합니다.
    pub fn cleanup_stale(&self) {
        if let Ok(mut state) = self.state.try_lock() {
            let now = Instant::now();
            state.retain(|_, counter| {
                now.duration_since(counter.window_start).as_secs() < self.config.window_secs
            });
        }
    }
}

impl Detector for SynFloodDetector {
    fn name(&self) -> &str {
        "syn_flood"
    }

    /// LogEntry를 분석하여 SYN flood 여부를 판단합니다.
    ///
    /// LogEntry의 fields에서 패킷 메타데이터를 추출합니다:
    /// - `src_ip`: 출발지 IP
    /// - `protocol`: 프로토콜 번호 (6=TCP)
    /// - `tcp_flags`: TCP 플래그 값
    fn detect(&self, entry: &LogEntry) -> Result<Option<Alert>, IronpostError> {
        use ironpost_ebpf_common::PROTO_TCP;

        // LogEntry fields에서 필요한 값 추출
        let src_ip = entry
            .fields
            .iter()
            .find(|(k, _)| k == "src_ip")
            .and_then(|(_, v)| v.parse::<IpAddr>().ok());

        let protocol = entry
            .fields
            .iter()
            .find(|(k, _)| k == "protocol")
            .and_then(|(_, v)| v.parse::<u8>().ok());

        let tcp_flags = entry
            .fields
            .iter()
            .find(|(k, _)| k == "tcp_flags")
            .and_then(|(_, v)| v.parse::<u8>().ok());

        // TCP 패킷이 아니면 스킵
        let Some(proto) = protocol else {
            return Ok(None);
        };
        if proto != PROTO_TCP {
            return Ok(None);
        }

        let Some(src_ip) = src_ip else {
            return Ok(None);
        };
        let Some(flags) = tcp_flags else {
            return Ok(None);
        };

        // SYN-only 패킷 여부 확인 (SYN=1, ACK=0)
        let is_syn_only = (flags & TCP_SYN != 0) && (flags & TCP_ACK == 0);

        // try_lock으로 non-blocking 상태 업데이트
        let mut state = match self.state.try_lock() {
            Ok(s) => s,
            Err(_) => return Ok(None), // 락 획득 실패 시 스킵
        };

        let now = Instant::now();

        // 엔트리 획득 또는 생성
        let counter = state.entry(src_ip).or_insert_with(|| SynCounter {
            total_tcp: 0,
            syn_only: 0,
            window_start: now,
        });

        // 윈도우 만료 확인
        if now.duration_since(counter.window_start).as_secs() >= self.config.window_secs {
            // 윈도우 리셋
            counter.total_tcp = 0;
            counter.syn_only = 0;
            counter.window_start = now;
        }

        // 카운터 업데이트
        counter.total_tcp += 1;
        if is_syn_only {
            counter.syn_only += 1;
        }

        // 탐지 조건 확인
        if counter.total_tcp >= self.config.min_packets {
            let ratio = counter.syn_only as f64 / counter.total_tcp as f64;
            if ratio > self.config.threshold_ratio {
                // Alert 생성
                let alert = Alert {
                    id: uuid::Uuid::new_v4().to_string(),
                    title: format!("SYN flood detected from {}", src_ip),
                    description: format!(
                        "SYN-only packet ratio ({:.2}%) exceeds threshold ({:.2}%) in {} seconds window",
                        ratio * 100.0,
                        self.config.threshold_ratio * 100.0,
                        self.config.window_secs,
                    ),
                    severity: Severity::High,
                    rule_name: "syn_flood".to_owned(),
                    source_ip: Some(src_ip),
                    target_ip: None,
                    created_at: SystemTime::now(),
                };

                return Ok(Some(alert));
            }
        }

        Ok(None)
    }
}

// =============================================================================
// 포트 스캔 탐지기 (core::Detector trait 구현)
// =============================================================================

/// 포트 스캔 탐지기
///
/// 단일 IP에서 설정된 윈도우 내에 N개 이상의 고유 포트에
/// 접근하면 알림을 생성합니다.
pub struct PortScanDetector {
    config: PortScanConfig,
    /// IP별 포트 접근 추적 (tokio::sync::Mutex + try_lock)
    state: tokio::sync::Mutex<HashMap<IpAddr, PortTracker>>,
}

impl PortScanDetector {
    /// 새 포트 스캔 탐지기를 생성합니다.
    pub fn new(config: PortScanConfig) -> Self {
        Self {
            config,
            state: tokio::sync::Mutex::new(HashMap::new()),
        }
    }

    /// 내부 상태에서 만료된 윈도우를 정리합니다.
    pub fn cleanup_stale(&self) {
        if let Ok(mut state) = self.state.try_lock() {
            let now = Instant::now();
            state.retain(|_, tracker| {
                now.duration_since(tracker.window_start).as_secs() < self.config.window_secs
            });
        }
    }
}

impl Detector for PortScanDetector {
    fn name(&self) -> &str {
        "port_scan"
    }

    /// LogEntry를 분석하여 포트 스캔 여부를 판단합니다.
    ///
    /// LogEntry의 fields에서 패킷 메타데이터를 추출합니다:
    /// - `src_ip`: 출발지 IP
    /// - `dst_port`: 목적지 포트
    fn detect(&self, entry: &LogEntry) -> Result<Option<Alert>, IronpostError> {
        // LogEntry fields에서 필요한 값 추출
        let src_ip = entry
            .fields
            .iter()
            .find(|(k, _)| k == "src_ip")
            .and_then(|(_, v)| v.parse::<IpAddr>().ok());

        let dst_port = entry
            .fields
            .iter()
            .find(|(k, _)| k == "dst_port")
            .and_then(|(_, v)| v.parse::<u16>().ok());

        let Some(src_ip) = src_ip else {
            return Ok(None);
        };
        let Some(dst_port) = dst_port else {
            return Ok(None);
        };

        // try_lock으로 non-blocking 상태 업데이트
        let mut state = match self.state.try_lock() {
            Ok(s) => s,
            Err(_) => return Ok(None), // 락 획득 실패 시 스킵
        };

        let now = Instant::now();

        // 엔트리 획득 또는 생성
        let tracker = state.entry(src_ip).or_insert_with(|| PortTracker {
            ports: HashSet::new(),
            window_start: now,
        });

        // 윈도우 만료 확인
        if now.duration_since(tracker.window_start).as_secs() >= self.config.window_secs {
            // 윈도우 리셋
            tracker.ports.clear();
            tracker.window_start = now;
        }

        // 포트 추가
        tracker.ports.insert(dst_port);

        // 탐지 조건 확인
        if tracker.ports.len() >= self.config.port_threshold {
            // Alert 생성
            let alert = Alert {
                id: uuid::Uuid::new_v4().to_string(),
                title: format!("Port scan detected from {}", src_ip),
                description: format!(
                    "Single IP accessed {} unique ports within {} seconds (threshold: {})",
                    tracker.ports.len(),
                    self.config.window_secs,
                    self.config.port_threshold,
                ),
                severity: Severity::Medium,
                rule_name: "port_scan".to_owned(),
                source_ip: Some(src_ip),
                target_ip: None,
                created_at: SystemTime::now(),
            };

            return Ok(Some(alert));
        }

        Ok(None)
    }
}

// =============================================================================
// 패킷 탐지 코디네이터
// =============================================================================

/// 패킷 기반 위협 탐지 코디네이터
///
/// eBPF RingBuf에서 수신한 PacketEventData를 분석하여 위협을 탐지하고,
/// AlertEvent를 이벤트 채널로 전송합니다.
///
/// 내부적으로 [`SynFloodDetector`]와 [`PortScanDetector`]를 관리합니다.
pub struct PacketDetector {
    /// 알림 이벤트 전송 채널
    alert_tx: Option<mpsc::Sender<AlertEvent>>,
    /// SYN flood 탐지기
    syn_flood: SynFloodDetector,
    /// 포트 스캔 탐지기
    port_scan: PortScanDetector,
}

impl PacketDetector {
    /// 새 패킷 탐지 코디네이터를 생성합니다.
    pub fn new(
        alert_tx: mpsc::Sender<AlertEvent>,
        syn_flood_config: SynFloodConfig,
        port_scan_config: PortScanConfig,
    ) -> Self {
        Self {
            alert_tx: Some(alert_tx),
            syn_flood: SynFloodDetector::new(syn_flood_config),
            port_scan: PortScanDetector::new(port_scan_config),
        }
    }

    /// PacketEventData를 분석하여 위협을 탐지합니다.
    ///
    /// 내부 탐지기들에게 이벤트를 전달하고, 알림이 생성되면
    /// AlertEvent로 변환하여 채널로 전송합니다.
    pub fn analyze(&self, event: &PacketEventData) -> Result<(), IronpostError> {
        // PacketEventData를 LogEntry로 변환
        let log_entry = packet_event_to_log_entry(event);

        // SYN flood 탐지
        if let Some(alert) = self.syn_flood.detect(&log_entry)? {
            let severity = alert.severity;
            let alert_event = AlertEvent::new(alert, severity);

            // 채널이 있으면 전송
            if let Some(ref tx) = self.alert_tx {
                // blocking_send 대신 try_send 사용 (async context 아님)
                tx.try_send(alert_event).map_err(|e| {
                    PipelineError::ChannelSend(format!("failed to send alert: {}", e))
                })?;
            }
        }

        // 포트 스캔 탐지
        if let Some(alert) = self.port_scan.detect(&log_entry)? {
            let severity = alert.severity;
            let alert_event = AlertEvent::new(alert, severity);

            // 채널이 있으면 전송
            if let Some(ref tx) = self.alert_tx {
                tx.try_send(alert_event).map_err(|e| {
                    PipelineError::ChannelSend(format!("failed to send alert: {}", e))
                })?;
            }
        }

        Ok(())
    }

    /// 오래된 추적 데이터를 정리합니다.
    ///
    /// 주기적으로 호출하여 만료된 윈도우의 상태를 제거합니다.
    pub fn cleanup_stale(&self) {
        self.syn_flood.cleanup_stale();
        self.port_scan.cleanup_stale();
    }

    /// SYN flood 탐지기에 대한 참조를 반환합니다.
    pub fn syn_flood_detector(&self) -> &SynFloodDetector {
        &self.syn_flood
    }

    /// 포트 스캔 탐지기에 대한 참조를 반환합니다.
    pub fn port_scan_detector(&self) -> &PortScanDetector {
        &self.port_scan
    }
}

impl Default for PacketDetector {
    fn default() -> Self {
        Self {
            alert_tx: None,
            syn_flood: SynFloodDetector::new(SynFloodConfig::default()),
            port_scan: PortScanDetector::new(PortScanConfig::default()),
        }
    }
}

// =============================================================================
// 유틸리티: PacketEventData → LogEntry 변환
// =============================================================================

/// PacketEventData를 LogEntry 형태로 변환합니다.
///
/// Detector trait이 LogEntry를 받으므로, 패킷 이벤트의 메타데이터를
/// LogEntry의 fields에 key-value 쌍으로 저장합니다.
///
/// # 필드 매핑
/// - `src_ip` → IPv4 주소 문자열
/// - `dst_ip` → IPv4 주소 문자열
/// - `src_port` → 포트 번호 문자열
/// - `dst_port` → 포트 번호 문자열
/// - `protocol` → 프로토콜 번호 문자열
/// - `tcp_flags` → TCP 플래그 값 문자열
/// - `action` → 액션 코드 문자열
pub fn packet_event_to_log_entry(event: &PacketEventData) -> LogEntry {
    let src_ip = Ipv4Addr::from(u32::from_be(event.src_ip));
    let dst_ip = Ipv4Addr::from(u32::from_be(event.dst_ip));
    let src_port = u16::from_be(event.src_port);
    let dst_port = u16::from_be(event.dst_port);

    LogEntry {
        source: "ebpf-xdp".to_owned(),
        timestamp: SystemTime::now(),
        hostname: String::new(),
        process: "ironpost-xdp".to_owned(),
        message: format!(
            "{src_ip}:{src_port} -> {dst_ip}:{dst_port} proto={}",
            event.protocol,
        ),
        severity: Severity::Info,
        fields: vec![
            ("src_ip".to_owned(), src_ip.to_string()),
            ("dst_ip".to_owned(), dst_ip.to_string()),
            ("src_port".to_owned(), src_port.to_string()),
            ("dst_port".to_owned(), dst_port.to_string()),
            ("protocol".to_owned(), event.protocol.to_string()),
            ("tcp_flags".to_owned(), event.tcp_flags.to_string()),
            ("action".to_owned(), event.action.to_string()),
        ],
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // =============================================================================
    // packet_event_to_log_entry 테스트
    // =============================================================================

    #[test]
    fn test_packet_event_to_log_entry_basic() {
        // u32::from_be는 호스트 → 네트워크 바이트 오더 변환이 아니라
        // 바이트 배열을 u32로 읽는 함수입니다.
        // 네트워크 바이트 오더(빅엔디안)로 저장하려면 u32::to_be() 또는
        // 바이트 배열을 빅엔디안 순서로 작성해야 합니다.
        let event = PacketEventData {
            src_ip: u32::from_be_bytes([192, 168, 1, 100]).to_be(),
            dst_ip: u32::from_be_bytes([10, 0, 0, 1]).to_be(),
            src_port: u16::to_be(12345),
            dst_port: u16::to_be(443),
            pkt_len: 64,
            protocol: ironpost_ebpf_common::PROTO_TCP,
            action: ironpost_ebpf_common::ACTION_PASS,
            tcp_flags: TCP_SYN,
            _pad: [0; 3],
        };

        let log_entry = packet_event_to_log_entry(&event);

        assert_eq!(log_entry.source, "ebpf-xdp");
        assert_eq!(log_entry.process, "ironpost-xdp");

        // fields 검증
        let fields_map: HashMap<&str, &str> = log_entry
            .fields
            .iter()
            .map(|(k, v)| (k.as_str(), v.as_str()))
            .collect();

        assert_eq!(fields_map.get("src_ip"), Some(&"192.168.1.100"));
        assert_eq!(fields_map.get("dst_ip"), Some(&"10.0.0.1"));
        assert_eq!(fields_map.get("src_port"), Some(&"12345"));
        assert_eq!(fields_map.get("dst_port"), Some(&"443"));
        assert_eq!(fields_map.get("protocol"), Some(&"6"));
        assert_eq!(fields_map.get("tcp_flags"), Some(&"2"));
        assert_eq!(fields_map.get("action"), Some(&"0"));
    }

    #[test]
    fn test_packet_event_to_log_entry_udp() {
        let event = PacketEventData {
            src_ip: u32::from_be_bytes([10, 0, 0, 1]).to_be(),
            dst_ip: u32::from_be_bytes([8, 8, 8, 8]).to_be(),
            src_port: u16::to_be(53),
            dst_port: u16::to_be(53),
            pkt_len: 128,
            protocol: ironpost_ebpf_common::PROTO_UDP,
            action: ironpost_ebpf_common::ACTION_PASS,
            tcp_flags: 0,
            _pad: [0; 3],
        };

        let log_entry = packet_event_to_log_entry(&event);

        let fields_map: HashMap<&str, &str> = log_entry
            .fields
            .iter()
            .map(|(k, v)| (k.as_str(), v.as_str()))
            .collect();

        assert_eq!(fields_map.get("protocol"), Some(&"17"));
        assert_eq!(fields_map.get("tcp_flags"), Some(&"0"));
    }

    // =============================================================================
    // SynFloodDetector 테스트
    // =============================================================================

    #[test]
    fn test_syn_flood_detector_normal_traffic_no_alert() {
        let config = SynFloodConfig {
            threshold_ratio: 0.7,
            window_secs: 10,
            min_packets: 100,
        };

        let detector = SynFloodDetector::new(config);

        // 정상 TCP 핸드셰이크 트래픽 (SYN-ACK 등이 섞임)
        for i in 0..150 {
            let tcp_flags = if i % 2 == 0 {
                TCP_SYN // SYN only
            } else {
                TCP_SYN | TCP_ACK // SYN-ACK
            };

            let log_entry = create_test_log_entry("192.168.1.100", tcp_flags);
            let result = detector.detect(&log_entry).unwrap();
            assert!(result.is_none()); // SYN 비율이 50%이므로 탐지 안 됨
        }
    }

    #[test]
    fn test_syn_flood_detector_attack_pattern_alerts() {
        let config = SynFloodConfig {
            threshold_ratio: 0.7,
            window_secs: 10,
            min_packets: 100,
        };

        let detector = SynFloodDetector::new(config);

        // SYN flood 공격 패턴 (SYN-only 패킷만 전송)
        let mut alert_generated = false;
        for _ in 0..150 {
            let log_entry = create_test_log_entry("10.0.0.50", TCP_SYN);
            if let Some(alert) = detector.detect(&log_entry).unwrap() {
                assert_eq!(alert.rule_name, "syn_flood");
                assert_eq!(alert.severity, Severity::High);
                assert!(alert.title.contains("SYN flood detected"));
                alert_generated = true;
            }
        }

        assert!(alert_generated);
    }

    #[test]
    fn test_syn_flood_detector_below_min_packets_no_alert() {
        let config = SynFloodConfig {
            threshold_ratio: 0.7,
            window_secs: 10,
            min_packets: 100,
        };

        let detector = SynFloodDetector::new(config);

        // 임계값 이하의 패킷만 전송
        for _ in 0..50 {
            let log_entry = create_test_log_entry("10.0.0.50", TCP_SYN);
            let result = detector.detect(&log_entry).unwrap();
            assert!(result.is_none()); // min_packets 미달
        }
    }

    #[test]
    fn test_syn_flood_detector_window_reset() {
        let config = SynFloodConfig {
            threshold_ratio: 0.7,
            window_secs: 1, // 1초 윈도우
            min_packets: 50,
        };

        let detector = SynFloodDetector::new(config);

        // 첫 번째 윈도우에서 공격 패턴
        for _ in 0..60 {
            let log_entry = create_test_log_entry("10.0.0.50", TCP_SYN);
            let _ = detector.detect(&log_entry);
        }

        // 윈도우 만료 대기
        std::thread::sleep(std::time::Duration::from_secs(2));

        // 새 윈도우에서 정상 트래픽
        for i in 0..60 {
            let tcp_flags = if i % 2 == 0 {
                TCP_SYN
            } else {
                TCP_SYN | TCP_ACK
            };

            let log_entry = create_test_log_entry("10.0.0.50", tcp_flags);
            let result = detector.detect(&log_entry).unwrap();

            // 새 윈도우에서는 SYN 비율이 50%이므로 탐지 안 됨
            // (마지막 패킷에서 체크)
            if i == 59 {
                assert!(result.is_none());
            }
        }
    }

    #[test]
    fn test_syn_flood_detector_ip_isolation() {
        let config = SynFloodConfig {
            threshold_ratio: 0.7,
            window_secs: 10,
            min_packets: 100,
        };

        let detector = SynFloodDetector::new(config);

        // IP1에서 공격 패턴
        for _ in 0..150 {
            let log_entry = create_test_log_entry("10.0.0.50", TCP_SYN);
            let _ = detector.detect(&log_entry);
        }

        // IP2에서 정상 트래픽 (영향 받지 않아야 함)
        for _ in 0..150 {
            let log_entry = create_test_log_entry("10.0.0.51", TCP_SYN | TCP_ACK);
            let result = detector.detect(&log_entry).unwrap();
            assert!(result.is_none()); // IP2는 SYN-ACK만 전송하므로 비율 0%
        }
    }

    #[test]
    fn test_syn_flood_detector_non_tcp_ignored() {
        let config = SynFloodConfig::default();
        let detector = SynFloodDetector::new(config);

        let log_entry = LogEntry {
            source: "test".to_owned(),
            timestamp: SystemTime::now(),
            hostname: "test".to_owned(),
            process: "test".to_owned(),
            message: "test".to_owned(),
            severity: Severity::Info,
            fields: vec![
                ("src_ip".to_owned(), "10.0.0.1".to_owned()),
                ("protocol".to_owned(), "17".to_owned()), // UDP
            ],
        };

        let result = detector.detect(&log_entry).unwrap();
        assert!(result.is_none());
    }

    // =============================================================================
    // PortScanDetector 테스트
    // =============================================================================

    #[test]
    fn test_port_scan_detector_normal_traffic_no_alert() {
        let config = PortScanConfig {
            port_threshold: 20,
            window_secs: 60,
        };

        let detector = PortScanDetector::new(config);

        // 정상 트래픽 (소수 포트만 접근)
        for port in 80..=85 {
            let log_entry = create_port_scan_log_entry("192.168.1.100", port);
            let result = detector.detect(&log_entry).unwrap();
            assert!(result.is_none());
        }
    }

    #[test]
    fn test_port_scan_detector_scan_pattern_alerts() {
        let config = PortScanConfig {
            port_threshold: 20,
            window_secs: 60,
        };

        let detector = PortScanDetector::new(config);

        // 포트 스캔 패턴 (많은 포트 순차 접근)
        let mut alert_generated = false;
        for port in 1..=30 {
            let log_entry = create_port_scan_log_entry("10.0.0.50", port);
            if let Some(alert) = detector.detect(&log_entry).unwrap() {
                assert_eq!(alert.rule_name, "port_scan");
                assert_eq!(alert.severity, Severity::Medium);
                assert!(alert.title.contains("Port scan detected"));
                alert_generated = true;
            }
        }

        assert!(alert_generated);
    }

    #[test]
    fn test_port_scan_detector_below_threshold_no_alert() {
        let config = PortScanConfig {
            port_threshold: 20,
            window_secs: 60,
        };

        let detector = PortScanDetector::new(config);

        // 임계값 미만의 포트만 접근
        for port in 1..=15 {
            let log_entry = create_port_scan_log_entry("10.0.0.50", port);
            let result = detector.detect(&log_entry).unwrap();
            assert!(result.is_none());
        }
    }

    #[test]
    fn test_port_scan_detector_window_reset() {
        let config = PortScanConfig {
            port_threshold: 20,
            window_secs: 1, // 1초 윈도우
        };

        let detector = PortScanDetector::new(config);

        // 첫 번째 윈도우에서 많은 포트 접근
        for port in 1..=25 {
            let log_entry = create_port_scan_log_entry("10.0.0.50", port);
            let _ = detector.detect(&log_entry);
        }

        // 윈도우 만료 대기
        std::thread::sleep(std::time::Duration::from_secs(2));

        // 새 윈도우에서 소수 포트만 접근
        for port in 80..=85 {
            let log_entry = create_port_scan_log_entry("10.0.0.50", port);
            let result = detector.detect(&log_entry).unwrap();
            assert!(result.is_none()); // 새 윈도우에서는 6개 포트만 접근
        }
    }

    #[test]
    fn test_port_scan_detector_ip_isolation() {
        let config = PortScanConfig {
            port_threshold: 20,
            window_secs: 60,
        };

        let detector = PortScanDetector::new(config);

        // IP1에서 포트 스캔
        for port in 1..=25 {
            let log_entry = create_port_scan_log_entry("10.0.0.50", port);
            let _ = detector.detect(&log_entry);
        }

        // IP2에서 정상 트래픽 (영향 받지 않아야 함)
        for port in 80..=85 {
            let log_entry = create_port_scan_log_entry("10.0.0.51", port);
            let result = detector.detect(&log_entry).unwrap();
            assert!(result.is_none());
        }
    }

    #[test]
    fn test_port_scan_detector_duplicate_ports_counted_once() {
        let config = PortScanConfig {
            port_threshold: 20,
            window_secs: 60,
        };

        let detector = PortScanDetector::new(config);

        // 같은 포트를 여러 번 접근 (고유 포트 수는 적음)
        for _ in 0..100 {
            let log_entry = create_port_scan_log_entry("10.0.0.50", 80);
            let result = detector.detect(&log_entry).unwrap();
            assert!(result.is_none()); // 고유 포트 수는 1개
        }
    }

    // =============================================================================
    // PacketDetector 테스트
    // =============================================================================

    #[test]
    fn test_packet_detector_creation() {
        let (alert_tx, _alert_rx) = mpsc::channel(100);
        let syn_config = SynFloodConfig::default();
        let port_config = PortScanConfig::default();

        let detector = PacketDetector::new(alert_tx, syn_config, port_config);

        assert_eq!(detector.syn_flood_detector().name(), "syn_flood");
        assert_eq!(detector.port_scan_detector().name(), "port_scan");
    }

    #[test]
    fn test_packet_detector_analyze_syn_flood() {
        let (alert_tx, mut alert_rx) = mpsc::channel(100);

        let syn_config = SynFloodConfig {
            threshold_ratio: 0.7,
            window_secs: 10,
            min_packets: 100,
        };
        let port_config = PortScanConfig::default();

        let detector = PacketDetector::new(alert_tx, syn_config, port_config);

        // SYN flood 패턴 생성
        for _ in 0..150 {
            let event = PacketEventData {
                src_ip: u32::from_be_bytes([10, 0, 0, 50]).to_be(),
                dst_ip: u32::from_be_bytes([192, 168, 1, 1]).to_be(),
                src_port: u16::to_be(12345),
                dst_port: u16::to_be(80),
                pkt_len: 64,
                protocol: ironpost_ebpf_common::PROTO_TCP,
                action: ironpost_ebpf_common::ACTION_PASS,
                tcp_flags: TCP_SYN,
                _pad: [0; 3],
            };

            detector.analyze(&event).unwrap();
        }

        // 알림이 생성되었는지 확인 (non-blocking)
        let mut alert_found = false;
        while let Ok(alert_event) = alert_rx.try_recv() {
            if alert_event.alert.rule_name == "syn_flood" {
                alert_found = true;
                break;
            }
        }

        assert!(alert_found);
    }

    #[test]
    fn test_packet_detector_analyze_port_scan() {
        let (alert_tx, mut alert_rx) = mpsc::channel(100);

        let syn_config = SynFloodConfig::default();
        let port_config = PortScanConfig {
            port_threshold: 20,
            window_secs: 60,
        };

        let detector = PacketDetector::new(alert_tx, syn_config, port_config);

        // 포트 스캔 패턴 생성
        for port in 1..=30 {
            let event = PacketEventData {
                src_ip: u32::from_be_bytes([10, 0, 0, 50]).to_be(),
                dst_ip: u32::from_be_bytes([192, 168, 1, 1]).to_be(),
                src_port: u16::to_be(12345),
                dst_port: u16::to_be(port),
                pkt_len: 64,
                protocol: ironpost_ebpf_common::PROTO_TCP,
                action: ironpost_ebpf_common::ACTION_PASS,
                tcp_flags: TCP_SYN,
                _pad: [0; 3],
            };

            detector.analyze(&event).unwrap();
        }

        // 알림이 생성되었는지 확인
        let mut alert_found = false;
        while let Ok(alert_event) = alert_rx.try_recv() {
            if alert_event.alert.rule_name == "port_scan" {
                alert_found = true;
                break;
            }
        }

        assert!(alert_found);
    }

    #[test]
    fn test_packet_detector_default() {
        let detector = PacketDetector::default();

        // 기본 생성자는 alert_tx가 None이어야 함
        assert!(detector.alert_tx.is_none());
    }

    #[test]
    fn test_packet_detector_cleanup_stale() {
        let (alert_tx, _alert_rx) = mpsc::channel(100);
        let detector = PacketDetector::new(
            alert_tx,
            SynFloodConfig::default(),
            PortScanConfig::default(),
        );

        // cleanup은 내부 상태를 정리하므로 panic이 발생하지 않아야 함
        detector.cleanup_stale();
    }

    // =============================================================================
    // 헬퍼 함수
    // =============================================================================

    fn create_test_log_entry(src_ip: &str, tcp_flags: u8) -> LogEntry {
        LogEntry {
            source: "test".to_owned(),
            timestamp: SystemTime::now(),
            hostname: "test".to_owned(),
            process: "test".to_owned(),
            message: "test".to_owned(),
            severity: Severity::Info,
            fields: vec![
                ("src_ip".to_owned(), src_ip.to_owned()),
                ("protocol".to_owned(), "6".to_owned()), // TCP
                ("tcp_flags".to_owned(), tcp_flags.to_string()),
            ],
        }
    }

    fn create_port_scan_log_entry(src_ip: &str, dst_port: u16) -> LogEntry {
        LogEntry {
            source: "test".to_owned(),
            timestamp: SystemTime::now(),
            hostname: "test".to_owned(),
            process: "test".to_owned(),
            message: "test".to_owned(),
            severity: Severity::Info,
            fields: vec![
                ("src_ip".to_owned(), src_ip.to_owned()),
                ("dst_port".to_owned(), dst_port.to_string()),
            ],
        }
    }
}

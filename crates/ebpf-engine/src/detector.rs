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

use ironpost_core::error::{DetectionError, IronpostError};
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
        todo!("SYN flood 탐지: LogEntry fields에서 패킷 정보 추출 후 SYN 비율 분석")
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
        todo!("포트 스캔 탐지: LogEntry fields에서 src_ip + dst_port 추출 후 고유 포트 수 분석")
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
        todo!("PacketEventData → LogEntry 변환 후 SynFlood/PortScan 탐지기 호출")
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

    LogEntry {
        source: "ebpf-xdp".to_owned(),
        timestamp: SystemTime::now(),
        hostname: String::new(),
        process: "ironpost-xdp".to_owned(),
        message: format!(
            "{src_ip}:{} -> {dst_ip}:{} proto={}",
            event.src_port, event.dst_port, event.protocol,
        ),
        severity: Severity::Info,
        fields: vec![
            ("src_ip".to_owned(), src_ip.to_string()),
            ("dst_ip".to_owned(), dst_ip.to_string()),
            ("src_port".to_owned(), event.src_port.to_string()),
            ("dst_port".to_owned(), event.dst_port.to_string()),
            ("protocol".to_owned(), event.protocol.to_string()),
            ("tcp_flags".to_owned(), event.tcp_flags.to_string()),
            ("action".to_owned(), event.action.to_string()),
        ],
    }
}

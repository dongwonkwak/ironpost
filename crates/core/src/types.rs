//! 도메인 타입 — 시스템 전역에서 사용되는 공통 타입
//!
//! 모든 모듈이 공유하는 데이터 구조를 정의합니다.
//! 각 모듈은 이 타입들을 사용하여 이벤트와 데이터를 교환합니다.

use std::fmt;
use std::net::IpAddr;
use std::time::SystemTime;

use serde::{Deserialize, Serialize};

/// 네트워크 패킷 정보
///
/// eBPF XDP 프로그램에서 캡처한 패킷의 메타데이터를 담습니다.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PacketInfo {
    /// 출발지 IP
    pub src_ip: IpAddr,
    /// 목적지 IP
    pub dst_ip: IpAddr,
    /// 출발지 포트
    pub src_port: u16,
    /// 목적지 포트
    pub dst_port: u16,
    /// 프로토콜 (TCP=6, UDP=17 등)
    pub protocol: u8,
    /// 패킷 크기 (바이트)
    pub size: usize,
    /// 캡처 시각
    pub timestamp: SystemTime,
}

impl fmt::Display for PacketInfo {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "{}:{} -> {}:{} proto={} size={}",
            self.src_ip, self.src_port, self.dst_ip, self.dst_port, self.protocol, self.size,
        )
    }
}

/// 로그 엔트리
///
/// 파싱된 로그 레코드를 나타냅니다.
/// 다양한 소스(syslog, 파일, journald)에서 수집된 로그를 통합 형식으로 저장합니다.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LogEntry {
    /// 원본 소스 (파일 경로, syslog 등)
    pub source: String,
    /// 타임스탬프
    pub timestamp: SystemTime,
    /// 호스트명
    pub hostname: String,
    /// 프로세스명
    pub process: String,
    /// 로그 메시지
    pub message: String,
    /// 심각도
    pub severity: Severity,
    /// 추가 필드 (key-value 쌍)
    pub fields: Vec<(String, String)>,
}

impl fmt::Display for LogEntry {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "[{}] {} {}: {}",
            self.severity, self.hostname, self.process, self.message,
        )
    }
}

/// 보안 알림
///
/// 탐지 규칙에 매칭되어 생성된 보안 알림을 나타냅니다.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Alert {
    /// 알림 ID
    pub id: String,
    /// 알림 제목
    pub title: String,
    /// 상세 설명
    pub description: String,
    /// 심각도
    pub severity: Severity,
    /// 탐지 규칙명
    pub rule_name: String,
    /// 관련 소스 IP (있을 경우)
    pub source_ip: Option<IpAddr>,
    /// 관련 대상 IP (있을 경우)
    pub target_ip: Option<IpAddr>,
    /// 생성 시각
    pub created_at: SystemTime,
}

impl fmt::Display for Alert {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "[{}] {} (rule: {})",
            self.severity, self.title, self.rule_name,
        )
    }
}

/// 심각도 레벨
///
/// 보안 이벤트의 심각도를 나타냅니다.
/// `Ord` 구현으로 심각도 비교가 가능합니다 (`Info < Low < Medium < High < Critical`).
#[derive(
    Debug, Clone, Copy, Default, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize,
)]
pub enum Severity {
    /// 정보성 이벤트
    #[default]
    Info,
    /// 낮은 심각도
    Low,
    /// 중간 심각도
    Medium,
    /// 높은 심각도
    High,
    /// 치명적 — 즉시 대응 필요
    Critical,
}

impl Severity {
    /// 문자열에서 심각도를 파싱합니다.
    ///
    /// 대소문자를 구분하지 않습니다.
    pub fn from_str_loose(s: &str) -> Option<Self> {
        match s.to_lowercase().as_str() {
            "info" | "informational" => Some(Self::Info),
            "low" => Some(Self::Low),
            "medium" | "med" => Some(Self::Medium),
            "high" => Some(Self::High),
            "critical" | "crit" => Some(Self::Critical),
            _ => None,
        }
    }
}

impl fmt::Display for Severity {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Info => write!(f, "Info"),
            Self::Low => write!(f, "Low"),
            Self::Medium => write!(f, "Medium"),
            Self::High => write!(f, "High"),
            Self::Critical => write!(f, "Critical"),
        }
    }
}

/// 컨테이너 정보
///
/// 모니터링 대상 컨테이너의 메타데이터를 나타냅니다.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ContainerInfo {
    /// 컨테이너 ID
    pub id: String,
    /// 컨테이너 이름
    pub name: String,
    /// 이미지명
    pub image: String,
    /// 상태 (running, stopped 등)
    pub status: String,
    /// 생성 시각
    pub created_at: SystemTime,
}

impl fmt::Display for ContainerInfo {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "{} ({}) image={} status={}",
            self.name,
            &self.id[..12.min(self.id.len())],
            self.image,
            self.status,
        )
    }
}

/// SBOM 취약점 정보
///
/// 취약점 데이터베이스에서 매칭된 CVE 정보를 나타냅니다.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Vulnerability {
    /// CVE ID (예: CVE-2024-1234)
    pub cve_id: String,
    /// 영향받는 패키지명
    pub package: String,
    /// 영향받는 버전
    pub affected_version: String,
    /// 수정된 버전 (있을 경우)
    pub fixed_version: Option<String>,
    /// 심각도
    pub severity: Severity,
    /// 취약점 설명
    pub description: String,
}

impl fmt::Display for Vulnerability {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "{} [{}] {} {} (fixed: {})",
            self.cve_id,
            self.severity,
            self.package,
            self.affected_version,
            self.fixed_version.as_deref().unwrap_or("N/A"),
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn severity_ordering() {
        assert!(Severity::Info < Severity::Low);
        assert!(Severity::Low < Severity::Medium);
        assert!(Severity::Medium < Severity::High);
        assert!(Severity::High < Severity::Critical);
    }

    #[test]
    fn severity_default_is_info() {
        assert_eq!(Severity::default(), Severity::Info);
    }

    #[test]
    fn severity_display() {
        assert_eq!(Severity::Info.to_string(), "Info");
        assert_eq!(Severity::Low.to_string(), "Low");
        assert_eq!(Severity::Medium.to_string(), "Medium");
        assert_eq!(Severity::High.to_string(), "High");
        assert_eq!(Severity::Critical.to_string(), "Critical");
    }

    #[test]
    fn severity_from_str_loose() {
        assert_eq!(Severity::from_str_loose("info"), Some(Severity::Info));
        assert_eq!(
            Severity::from_str_loose("CRITICAL"),
            Some(Severity::Critical)
        );
        assert_eq!(Severity::from_str_loose("Med"), Some(Severity::Medium));
        assert_eq!(
            Severity::from_str_loose("informational"),
            Some(Severity::Info)
        );
        assert_eq!(Severity::from_str_loose("crit"), Some(Severity::Critical));
        assert_eq!(Severity::from_str_loose("unknown"), None);
    }

    #[test]
    fn severity_serialize_deserialize() {
        let severity = Severity::High;
        let json = serde_json::to_string(&severity).unwrap();
        let deserialized: Severity = serde_json::from_str(&json).unwrap();
        assert_eq!(severity, deserialized);
    }

    #[test]
    fn packet_info_display() {
        let info = PacketInfo {
            src_ip: "192.168.1.1".parse().unwrap(),
            dst_ip: "10.0.0.1".parse().unwrap(),
            src_port: 12345,
            dst_port: 80,
            protocol: 6,
            size: 1500,
            timestamp: SystemTime::now(),
        };
        let display = info.to_string();
        assert!(display.contains("192.168.1.1:12345"));
        assert!(display.contains("10.0.0.1:80"));
    }

    #[test]
    fn log_entry_display() {
        let entry = LogEntry {
            source: "syslog".to_owned(),
            timestamp: SystemTime::now(),
            hostname: "server-01".to_owned(),
            process: "sshd".to_owned(),
            message: "session opened".to_owned(),
            severity: Severity::Info,
            fields: vec![],
        };
        let display = entry.to_string();
        assert!(display.contains("Info"));
        assert!(display.contains("server-01"));
        assert!(display.contains("sshd"));
    }

    #[test]
    fn alert_display() {
        let alert = Alert {
            id: "alert-001".to_owned(),
            title: "Brute force".to_owned(),
            description: "desc".to_owned(),
            severity: Severity::High,
            rule_name: "ssh_brute".to_owned(),
            source_ip: None,
            target_ip: None,
            created_at: SystemTime::now(),
        };
        let display = alert.to_string();
        assert!(display.contains("High"));
        assert!(display.contains("Brute force"));
        assert!(display.contains("ssh_brute"));
    }

    #[test]
    fn container_info_display() {
        let info = ContainerInfo {
            id: "abc123def456".to_owned(),
            name: "web-server".to_owned(),
            image: "nginx:latest".to_owned(),
            status: "running".to_owned(),
            created_at: SystemTime::now(),
        };
        let display = info.to_string();
        assert!(display.contains("web-server"));
        assert!(display.contains("nginx:latest"));
    }

    #[test]
    fn vulnerability_display() {
        let vuln = Vulnerability {
            cve_id: "CVE-2024-1234".to_owned(),
            package: "openssl".to_owned(),
            affected_version: "1.1.1".to_owned(),
            fixed_version: Some("1.1.1t".to_owned()),
            severity: Severity::Critical,
            description: "Buffer overflow".to_owned(),
        };
        let display = vuln.to_string();
        assert!(display.contains("CVE-2024-1234"));
        assert!(display.contains("Critical"));
        assert!(display.contains("1.1.1t"));
    }

    #[test]
    fn vulnerability_display_no_fix() {
        let vuln = Vulnerability {
            cve_id: "CVE-2024-5678".to_owned(),
            package: "libxml2".to_owned(),
            affected_version: "2.9.0".to_owned(),
            fixed_version: None,
            severity: Severity::Medium,
            description: "XXE vulnerability".to_owned(),
        };
        assert!(vuln.to_string().contains("N/A"));
    }

    #[test]
    fn packet_info_serialize_roundtrip() {
        let info = PacketInfo {
            src_ip: "::1".parse().unwrap(),
            dst_ip: "::1".parse().unwrap(),
            src_port: 443,
            dst_port: 54321,
            protocol: 6,
            size: 64,
            timestamp: SystemTime::now(),
        };
        let json = serde_json::to_string(&info).unwrap();
        let deserialized: PacketInfo = serde_json::from_str(&json).unwrap();
        assert_eq!(info.src_ip, deserialized.src_ip);
        assert_eq!(info.dst_port, deserialized.dst_port);
    }
}

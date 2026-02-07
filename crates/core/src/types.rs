//! 도메인 타입 — 시스템 전역에서 사용되는 공통 타입

use std::net::IpAddr;
use std::time::SystemTime;

use serde::{Deserialize, Serialize};

/// 네트워크 패킷 정보
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

/// 로그 엔트리
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
    /// 추가 필드
    pub fields: Vec<(String, String)>,
}

/// 보안 알림
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

/// 심각도 레벨
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub enum Severity {
    /// 정보
    Info,
    /// 낮음
    Low,
    /// 중간
    Medium,
    /// 높음
    High,
    /// 치명적
    Critical,
}

/// 컨테이너 정보
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

/// SBOM 취약점 정보
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Vulnerability {
    /// CVE ID
    pub cve_id: String,
    /// 패키지명
    pub package: String,
    /// 영향받는 버전
    pub affected_version: String,
    /// 수정된 버전 (있을 경우)
    pub fixed_version: Option<String>,
    /// 심각도
    pub severity: Severity,
    /// 설명
    pub description: String,
}

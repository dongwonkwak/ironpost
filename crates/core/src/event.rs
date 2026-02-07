//! 이벤트 시스템 — 모듈 간 통신의 기본 단위

use bytes::Bytes;
use std::time::SystemTime;

use crate::types::{Alert, LogEntry, PacketInfo, Severity};

/// 모든 이벤트가 구현해야 하는 기본 trait
pub trait Event: Send + Sync + 'static {
    /// 이벤트 고유 ID
    fn id(&self) -> &str;

    /// 이벤트 발생 시각
    fn timestamp(&self) -> SystemTime;

    /// 이벤트 소스 모듈명
    fn source(&self) -> &str;

    /// 이벤트를 바이트로 직렬화
    fn to_bytes(&self) -> Bytes;
}

/// eBPF에서 탐지한 패킷 이벤트
#[derive(Debug, Clone)]
pub struct PacketEvent {
    pub id: String,
    pub timestamp: SystemTime,
    pub packet_info: PacketInfo,
    pub raw_data: Bytes,
}

/// 파싱된 로그 이벤트
#[derive(Debug, Clone)]
pub struct LogEvent {
    pub id: String,
    pub timestamp: SystemTime,
    pub entry: LogEntry,
}

/// 룰 매칭으로 생성된 알림 이벤트
#[derive(Debug, Clone)]
pub struct AlertEvent {
    pub id: String,
    pub timestamp: SystemTime,
    pub alert: Alert,
    pub severity: Severity,
}

/// 실행된 액션 이벤트 (컨테이너 격리 등)
#[derive(Debug, Clone)]
pub struct ActionEvent {
    pub id: String,
    pub timestamp: SystemTime,
    pub action_type: String,
    pub target: String,
    pub success: bool,
}

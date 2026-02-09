//! TCP Syslog 수집기
//!
//! RFC 5424 형식의 syslog 메시지를 TCP 소켓으로 수신합니다.
//! Octet-counting 또는 newline framing을 지원합니다.

use tokio::sync::mpsc;

use super::{CollectorStatus, RawLog};
use crate::error::LogPipelineError;

/// TCP syslog 수집기 설정
#[derive(Debug, Clone)]
pub struct SyslogTcpConfig {
    /// 바인드 주소 (예: "0.0.0.0:601")
    pub bind_addr: String,
    /// 최대 동시 연결 수
    pub max_connections: usize,
    /// 연결당 수신 버퍼 크기 (바이트)
    pub recv_buffer_size: usize,
    /// 최대 메시지 크기 (바이트)
    pub max_message_size: usize,
    /// 연결 타임아웃 (초)
    pub connection_timeout_secs: u64,
    /// 프레이밍 방식
    pub framing: TcpFraming,
}

/// TCP syslog 프레이밍 방식
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub enum TcpFraming {
    /// Octet-counting (RFC 5425): 메시지 길이 접두사
    OctetCounting,
    /// 개행 문자로 메시지 구분 (기본값, 호환성 높음)
    #[default]
    NewlineDelimited,
}

impl Default for SyslogTcpConfig {
    fn default() -> Self {
        Self {
            bind_addr: "0.0.0.0:601".to_owned(),
            max_connections: 256,
            recv_buffer_size: 64 * 1024,   // 64KB
            max_message_size: 1024 * 1024, // 1MB
            connection_timeout_secs: 300,  // 5 minutes
            framing: TcpFraming::default(),
        }
    }
}

/// TCP Syslog 수집기
///
/// TCP 소켓에서 syslog 메시지를 수신합니다.
/// 각 TCP 연결은 별도의 tokio 태스크에서 처리됩니다.
#[allow(dead_code)]
pub struct SyslogTcpCollector {
    /// 수집기 설정
    #[allow(dead_code)]
    config: SyslogTcpConfig,
    /// 수집된 로그 전송 채널
    #[allow(dead_code)]
    tx: mpsc::Sender<RawLog>,
    /// 현재 상태
    status: CollectorStatus,
    /// 현재 활성 연결 수
    active_connections: usize,
}

impl SyslogTcpCollector {
    /// 새 TCP syslog 수집기를 생성합니다.
    pub fn new(config: SyslogTcpConfig, tx: mpsc::Sender<RawLog>) -> Self {
        Self {
            config,
            tx,
            status: CollectorStatus::Idle,
            active_connections: 0,
        }
    }

    /// 수집기를 시작합니다.
    ///
    /// TCP 소켓에 바인드하고 연결 수락 루프를 실행합니다.
    /// 각 연결은 별도 태스크에서 처리됩니다.
    pub async fn run(&mut self) -> Result<(), LogPipelineError> {
        self.status = CollectorStatus::Running;
        todo!("implement TCP syslog receiver: bind, accept loop, per-connection handler")
    }

    /// 바인드 주소를 반환합니다.
    pub fn bind_addr(&self) -> &str {
        &self.config.bind_addr
    }

    /// 현재 활성 연결 수를 반환합니다.
    pub fn active_connections(&self) -> usize {
        self.active_connections
    }

    /// 현재 상태를 반환합니다.
    pub fn status(&self) -> &CollectorStatus {
        &self.status
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_config() {
        let config = SyslogTcpConfig::default();
        assert_eq!(config.bind_addr, "0.0.0.0:601");
        assert_eq!(config.max_connections, 256);
        assert_eq!(config.framing, TcpFraming::NewlineDelimited);
    }

    #[test]
    fn collector_starts_idle() {
        let (tx, _rx) = mpsc::channel(10);
        let collector = SyslogTcpCollector::new(SyslogTcpConfig::default(), tx);
        assert_eq!(*collector.status(), CollectorStatus::Idle);
        assert_eq!(collector.active_connections(), 0);
    }
}

//! UDP Syslog 수집기
//!
//! RFC 5424 형식의 syslog 메시지를 UDP 소켓으로 수신합니다.
//! 표준 syslog 포트(514/udp)에서 수신하거나, 설정된 주소에 바인드합니다.

use tokio::sync::mpsc;

use super::{CollectorStatus, RawLog};
use crate::error::LogPipelineError;

/// UDP syslog 수집기 설정
#[derive(Debug, Clone)]
pub struct SyslogUdpConfig {
    /// 바인드 주소 (예: "0.0.0.0:514")
    pub bind_addr: String,
    /// 수신 버퍼 크기 (바이트)
    pub recv_buffer_size: usize,
    /// 최대 메시지 크기 (바이트, UDP이므로 일반적으로 65535 이하)
    pub max_message_size: usize,
}

impl Default for SyslogUdpConfig {
    fn default() -> Self {
        Self {
            bind_addr: "0.0.0.0:514".to_owned(),
            recv_buffer_size: 256 * 1024, // 256KB
            max_message_size: 65535,
        }
    }
}

/// UDP Syslog 수집기
///
/// UDP 소켓에서 syslog 메시지를 수신하여 파이프라인으로 전달합니다.
/// 각 UDP 데이터그램을 하나의 로그 메시지로 취급합니다.
#[allow(dead_code)]
pub struct SyslogUdpCollector {
    /// 수집기 설정
    #[allow(dead_code)]
    config: SyslogUdpConfig,
    /// 수집된 로그 전송 채널
    #[allow(dead_code)]
    tx: mpsc::Sender<RawLog>,
    /// 현재 상태
    status: CollectorStatus,
}

impl SyslogUdpCollector {
    /// 새 UDP syslog 수집기를 생성합니다.
    pub fn new(config: SyslogUdpConfig, tx: mpsc::Sender<RawLog>) -> Self {
        Self {
            config,
            tx,
            status: CollectorStatus::Idle,
        }
    }

    /// 수집기를 시작합니다.
    ///
    /// UDP 소켓에 바인드하고 메시지 수신 루프를 실행합니다.
    /// 취소될 때까지 실행됩니다.
    pub async fn run(&mut self) -> Result<(), LogPipelineError> {
        self.status = CollectorStatus::Running;
        todo!("implement UDP syslog receiver: bind socket, recv_from loop")
    }

    /// 바인드 주소를 반환합니다.
    pub fn bind_addr(&self) -> &str {
        &self.config.bind_addr
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
        let config = SyslogUdpConfig::default();
        assert_eq!(config.bind_addr, "0.0.0.0:514");
        assert_eq!(config.max_message_size, 65535);
    }

    #[test]
    fn collector_starts_idle() {
        let (tx, _rx) = mpsc::channel(10);
        let collector = SyslogUdpCollector::new(SyslogUdpConfig::default(), tx);
        assert_eq!(*collector.status(), CollectorStatus::Idle);
    }
}

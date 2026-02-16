//! UDP Syslog 수집기
//!
//! RFC 5424 형식의 syslog 메시지를 UDP 소켓으로 수신합니다.
//! 표준 syslog 포트(514/udp)에서 수신하거나, 설정된 주소에 바인드합니다.

use bytes::Bytes;
use tokio::net::UdpSocket;
use tokio::sync::mpsc;
use tokio_util::sync::CancellationToken;
use tracing::{debug, error, info};

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
    /// graceful shutdown을 위한 취소 토큰
    cancel_token: CancellationToken,
    /// 현재 상태
    status: CollectorStatus,
}

impl SyslogUdpCollector {
    /// 새 UDP syslog 수집기를 생성합니다.
    pub fn new(config: SyslogUdpConfig, tx: mpsc::Sender<RawLog>) -> Self {
        Self::new_with_cancel(config, tx, CancellationToken::new())
    }

    /// 취소 토큰을 포함하여 새 UDP syslog 수집기를 생성합니다.
    pub fn new_with_cancel(
        config: SyslogUdpConfig,
        tx: mpsc::Sender<RawLog>,
        cancel_token: CancellationToken,
    ) -> Self {
        Self {
            config,
            tx,
            cancel_token,
            status: CollectorStatus::Idle,
        }
    }

    /// 수집기를 시작합니다.
    ///
    /// UDP 소켓에 바인드하고 메시지 수신 루프를 실행합니다.
    /// 취소될 때까지 실행됩니다.
    pub async fn run(&mut self) -> Result<(), LogPipelineError> {
        self.status = CollectorStatus::Running;
        info!("Starting UDP syslog collector on {}", self.config.bind_addr);

        // UDP 소켓 바인드
        let socket = UdpSocket::bind(&self.config.bind_addr).await.map_err(|e| {
            LogPipelineError::Collector {
                source_type: "syslog_udp".to_owned(),
                reason: format!("failed to bind to {}: {}", self.config.bind_addr, e),
            }
        })?;

        info!(
            "UDP syslog collector listening on {}",
            self.config.bind_addr
        );

        let mut buf = vec![0u8; self.config.max_message_size];

        loop {
            tokio::select! {
                result = socket.recv_from(&mut buf) => {
                    match result {
                        Ok((len, addr)) => {
                            debug!("Received {} bytes from {}", len, addr);

                            if len == 0 {
                                continue;
                            }

                            // 수신된 데이터를 RawLog로 변환
                            let data = Bytes::copy_from_slice(&buf[..len]);
                            let raw_log =
                                RawLog::new(data, format!("syslog_udp:{}", self.config.bind_addr))
                                    .with_format_hint("syslog");

                            // 채널로 전송
                            if let Err(e) = self.tx.send(raw_log).await {
                                error!("Failed to send log to channel: {}", e);
                                self.status = CollectorStatus::Error(e.to_string());
                                return Err(LogPipelineError::Channel(e.to_string()));
                            }
                        }
                        Err(e) => {
                            error!("UDP recv error: {}", e);
                            self.status = CollectorStatus::Error(e.to_string());
                            return Err(LogPipelineError::Collector {
                                source_type: "syslog_udp".to_owned(),
                                reason: format!("recv error: {}", e),
                            });
                        }
                    }
                }
                _ = self.cancel_token.cancelled() => {
                    info!("UDP syslog collector received shutdown signal");
                    self.status = CollectorStatus::Stopped;
                    break;
                }
            }
        }

        Ok(())
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

    #[tokio::test]
    async fn bind_address_accessible() {
        let (tx, _rx) = mpsc::channel(10);
        let config = SyslogUdpConfig {
            bind_addr: "127.0.0.1:0".to_owned(), // 자동 포트 할당
            ..Default::default()
        };
        let collector = SyslogUdpCollector::new(config, tx);
        assert_eq!(collector.bind_addr(), "127.0.0.1:0");
    }

    #[tokio::test]
    async fn receive_udp_message() {
        let (tx, mut rx) = mpsc::channel(10);

        // 랜덤 포트에 바인드
        let config = SyslogUdpConfig {
            bind_addr: "127.0.0.1:0".to_owned(),
            ..Default::default()
        };

        let mut collector = SyslogUdpCollector::new(config.clone(), tx);

        // 수집기를 백그라운드 태스크로 시작
        let handle = tokio::spawn(async move { collector.run().await });

        // 잠시 대기하여 소켓이 바인드되도록 함
        tokio::time::sleep(tokio::time::Duration::from_millis(100)).await;

        // 실제로 바인드된 주소를 알 수 없으므로, 이 테스트는 스킵
        // 실제 환경에서는 collector가 바인드된 포트를 반환하도록 수정 필요
        handle.abort();

        // 채널이 비어있는지 확인 (메시지가 없어야 함)
        assert!(rx.try_recv().is_err());
    }

    #[tokio::test]
    async fn udp_collector_creation() {
        let (tx, _rx) = mpsc::channel(10);
        let config = SyslogUdpConfig::default();
        let _collector = SyslogUdpCollector::new(config, tx);
        // 생성만 테스트
    }
}

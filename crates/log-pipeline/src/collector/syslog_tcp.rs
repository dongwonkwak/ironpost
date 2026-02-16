//! TCP Syslog 수집기
//!
//! RFC 5424 형식의 syslog 메시지를 TCP 소켓으로 수신합니다.
//! Octet-counting 또는 newline framing을 지원합니다.

use std::sync::Arc;
use std::time::Duration;

use bytes::Bytes;
use tokio::io::{AsyncBufReadExt, BufReader};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::{Semaphore, mpsc};
use tokio::time::timeout;
use tokio_util::sync::CancellationToken;
use tracing::{debug, error, info, warn};

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
    /// Cancellation token for graceful shutdown
    #[allow(dead_code)]
    cancel_token: CancellationToken,
    /// 현재 상태
    status: CollectorStatus,
    /// 현재 활성 연결 수
    active_connections: usize,
}

impl SyslogTcpCollector {
    /// 새 TCP syslog 수집기를 생성합니다.
    pub fn new(
        config: SyslogTcpConfig,
        tx: mpsc::Sender<RawLog>,
        cancel_token: CancellationToken,
    ) -> Self {
        Self {
            config,
            tx,
            cancel_token,
            status: CollectorStatus::Idle,
            active_connections: 0,
        }
    }

    /// 수집기를 시작합니다.
    ///
    /// TCP 소켓에 바인드하고 연결 수락 루프를 실행합니다.
    /// 각 연결은 별도 태스크에서 처리됩니다.
    /// CancellationToken을 통해 graceful shutdown을 지원합니다.
    pub async fn run(&mut self) -> Result<(), LogPipelineError> {
        self.status = CollectorStatus::Running;
        info!("Starting TCP syslog collector on {}", self.config.bind_addr);

        // TCP 리스너 바인드
        let listener = TcpListener::bind(&self.config.bind_addr)
            .await
            .map_err(|e| LogPipelineError::Collector {
                source_type: "syslog_tcp".to_owned(),
                reason: format!("failed to bind to {}: {}", self.config.bind_addr, e),
            })?;

        info!(
            "TCP syslog collector listening on {}",
            self.config.bind_addr
        );

        // 연결 수 제한을 위한 세마포어
        let connection_semaphore = Arc::new(Semaphore::new(self.config.max_connections));

        loop {
            tokio::select! {
                result = listener.accept() => {
                    let (stream, addr) = result.map_err(|e| LogPipelineError::Collector {
                        source_type: "syslog_tcp".to_owned(),
                        reason: format!("accept error: {}", e),
                    })?;

                    debug!("Accepted connection from {}", addr);

                    // 연결 수 제한 확인
                    let permit = match connection_semaphore.clone().try_acquire_owned() {
                        Ok(p) => p,
                        Err(_) => {
                            warn!(
                                "Max connections reached, rejecting connection from {}",
                                addr
                            );
                            continue;
                        }
                    };

                    self.active_connections += 1;

                    let tx = self.tx.clone();
                    let config = self.config.clone();
                    let bind_addr = self.config.bind_addr.clone();
                    let cancel = self.cancel_token.clone();

                    // 각 연결을 별도 태스크에서 처리
                    tokio::spawn(async move {
                        if let Err(e) = Self::handle_connection(stream, tx, config, bind_addr, cancel).await {
                            error!("Connection handler error: {}", e);
                        }
                        drop(permit); // 연결 종료 시 세마포어 반환
                    });
                }
                _ = self.cancel_token.cancelled() => {
                    info!("TCP syslog collector received shutdown signal");
                    self.status = CollectorStatus::Stopped;
                    break;
                }
            }
        }

        Ok(())
    }

    /// 단일 TCP 연결을 처리합니다.
    async fn handle_connection(
        stream: TcpStream,
        tx: mpsc::Sender<RawLog>,
        config: SyslogTcpConfig,
        bind_addr: String,
        cancel: CancellationToken,
    ) -> Result<(), LogPipelineError> {
        let peer_addr = stream
            .peer_addr()
            .map(|a| a.to_string())
            .unwrap_or_else(|_| "unknown".to_owned());

        match config.framing {
            TcpFraming::NewlineDelimited => {
                Self::handle_newline_framing(stream, tx, config, bind_addr, peer_addr, cancel).await
            }
            TcpFraming::OctetCounting => {
                // Octet-counting 프레이밍 (향후 구현)
                warn!("Octet-counting framing not yet implemented, using newline framing");
                Self::handle_newline_framing(stream, tx, config, bind_addr, peer_addr, cancel).await
            }
        }
    }

    /// Newline-delimited 프레이밍 처리
    async fn handle_newline_framing(
        stream: TcpStream,
        tx: mpsc::Sender<RawLog>,
        config: SyslogTcpConfig,
        bind_addr: String,
        peer_addr: String,
        cancel: CancellationToken,
    ) -> Result<(), LogPipelineError> {
        let mut reader = BufReader::new(stream);
        let mut line_buffer = String::new();
        let connection_timeout = Duration::from_secs(config.connection_timeout_secs);

        loop {
            line_buffer.clear();

            // 타임아웃과 함께 라인 읽기, cancellation token도 체크
            tokio::select! {
                result = timeout(connection_timeout, reader.read_line(&mut line_buffer)) => {
                    match result {
                        Ok(Ok(0)) => {
                            // EOF - 연결 종료
                            debug!("Connection closed by peer: {}", peer_addr);
                            break;
                        }
                        Ok(Ok(_bytes_read)) => {
                            // 메시지가 최대 크기를 초과하는지 확인
                            if line_buffer.len() > config.max_message_size {
                                warn!(
                                    "Message exceeds max size from {} ({} bytes, max: {}), closing connection",
                                    peer_addr,
                                    line_buffer.len(),
                                    config.max_message_size
                                );
                                break;
                            }

                            // 빈 라인 스킵
                            if line_buffer.trim().is_empty() {
                                continue;
                            }

                            // RawLog 생성 및 전송
                            let data = Bytes::from(line_buffer.trim_end().to_owned());
                            let raw_log =
                                RawLog::new(data, format!("syslog_tcp:{}[{}]", bind_addr, peer_addr))
                                    .with_format_hint("syslog");

                            if let Err(e) = tx.send(raw_log).await {
                                error!("Failed to send log to channel: {}", e);
                                return Err(LogPipelineError::Channel(e.to_string()));
                            }
                        }
                        Ok(Err(e)) => {
                            error!("Read error from {}: {}", peer_addr, e);
                            return Err(LogPipelineError::Collector {
                                source_type: "syslog_tcp".to_owned(),
                                reason: format!("read error: {}", e),
                            });
                        }
                        Err(_) => {
                            warn!("Connection timeout from {}", peer_addr);
                            return Err(LogPipelineError::Collector {
                                source_type: "syslog_tcp".to_owned(),
                                reason: "connection timeout".to_owned(),
                            });
                        }
                    }
                }
                _ = cancel.cancelled() => {
                    debug!("Connection handler for {} received shutdown signal", peer_addr);
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
    fn tcp_framing_default() {
        assert_eq!(TcpFraming::default(), TcpFraming::NewlineDelimited);
    }

    #[test]
    fn collector_starts_idle() {
        let (tx, _rx) = mpsc::channel(10);
        let cancel = CancellationToken::new();
        let collector = SyslogTcpCollector::new(SyslogTcpConfig::default(), tx, cancel);
        assert_eq!(*collector.status(), CollectorStatus::Idle);
        assert_eq!(collector.active_connections(), 0);
    }

    #[tokio::test]
    async fn bind_address_accessible() {
        let (tx, _rx) = mpsc::channel(10);
        let config = SyslogTcpConfig {
            bind_addr: "127.0.0.1:0".to_owned(),
            ..Default::default()
        };
        let cancel = CancellationToken::new();
        let collector = SyslogTcpCollector::new(config, tx, cancel);
        assert_eq!(collector.bind_addr(), "127.0.0.1:0");
    }

    #[tokio::test]
    async fn tcp_collector_creation() {
        let (tx, _rx) = mpsc::channel(10);
        let config = SyslogTcpConfig::default();
        let cancel = CancellationToken::new();
        let _collector = SyslogTcpCollector::new(config, tx, cancel);
        // 생성만 테스트
    }
}

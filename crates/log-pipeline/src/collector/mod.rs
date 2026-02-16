//! 로그 수집 모듈 -- 다양한 소스에서 원시 로그를 수집합니다.
//!
//! # 수집 소스
//! - [`FileCollector`]: 파일 감시 (tail -f 방식)
//! - [`SyslogUdpCollector`]: UDP syslog 수신 (RFC 5424)
//! - [`SyslogTcpCollector`]: TCP syslog 수신 (RFC 5424)
//! - [`EventReceiver`]: eBPF 엔진에서 `PacketEvent`를 mpsc 채널로 수신
//!
//! # 아키텍처
//! 각 수집기는 자체 tokio 태스크에서 실행되며, 수집된 원시 로그를
//! `tokio::mpsc::Sender<RawLog>` 채널을 통해 파이프라인으로 전달합니다.

pub mod event_receiver;
pub mod file;
pub mod syslog_tcp;
pub mod syslog_udp;

pub use event_receiver::EventReceiver;
pub use file::FileCollector;
pub use syslog_tcp::SyslogTcpCollector;
pub use syslog_udp::SyslogUdpCollector;

use bytes::Bytes;

/// 수집된 원시 로그 데이터
///
/// 수집기가 생성하고, 파서가 소비하는 중간 데이터 형식입니다.
#[derive(Debug, Clone)]
pub struct RawLog {
    /// 원시 로그 바이트
    pub data: Bytes,
    /// 수집 소스 식별자 (예: "file:/var/log/syslog", "syslog_udp:0.0.0.0:514")
    pub source: String,
    /// 수집 시각
    pub received_at: std::time::SystemTime,
    /// 파서 힌트 (알려진 경우). None이면 자동 감지.
    pub format_hint: Option<String>,
}

impl RawLog {
    /// 새 RawLog를 생성합니다.
    pub fn new(data: Bytes, source: impl Into<String>) -> Self {
        Self {
            data,
            source: source.into(),
            received_at: std::time::SystemTime::now(),
            format_hint: None,
        }
    }

    /// 파서 형식 힌트를 설정합니다.
    pub fn with_format_hint(mut self, hint: impl Into<String>) -> Self {
        self.format_hint = Some(hint.into());
        self
    }
}

/// 수집기 상태
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CollectorStatus {
    /// 실행 대기 중
    Idle,
    /// 실행 중
    Running,
    /// 에러로 중단됨
    Error(String),
    /// 정상 종료됨
    Stopped,
}

/// 수집기 세트 -- 여러 수집기를 관리합니다.
///
/// `ironpost-daemon`에서 설정에 따라 수집기를 조립하고,
/// 파이프라인 시작 시 모든 수집기를 일괄 시작합니다.
pub struct CollectorSet {
    /// 활성화된 수집기 이름과 상태 목록
    collectors: Vec<(String, CollectorStatus)>,
    /// 수집된 로그를 전송할 채널 용량
    channel_capacity: usize,
}

impl CollectorSet {
    /// 새 수집기 세트를 생성합니다.
    pub fn new(channel_capacity: usize) -> Self {
        Self {
            collectors: Vec::new(),
            channel_capacity,
        }
    }

    /// 채널 용량을 반환합니다.
    pub fn channel_capacity(&self) -> usize {
        self.channel_capacity
    }

    /// 등록된 수집기 수를 반환합니다.
    pub fn len(&self) -> usize {
        self.collectors.len()
    }

    /// 수집기가 하나도 없는지 확인합니다.
    pub fn is_empty(&self) -> bool {
        self.collectors.is_empty()
    }

    /// 수집기를 등록합니다.
    pub fn register(&mut self, name: impl Into<String>) {
        self.collectors.push((name.into(), CollectorStatus::Idle));
    }

    /// 모든 수집기의 상태를 반환합니다.
    pub fn statuses(&self) -> &[(String, CollectorStatus)] {
        &self.collectors
    }

    /// 모든 수집기 상태를 Stopped로 설정합니다.
    pub fn stop_all(&mut self) {
        for (_, status) in &mut self.collectors {
            *status = CollectorStatus::Stopped;
        }
    }

    /// 수집기 세트를 초기화합니다 (재시작 지원).
    pub fn clear(&mut self) {
        self.collectors.clear();
    }
}

impl Default for CollectorSet {
    fn default() -> Self {
        Self::new(1024)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn raw_log_creation() {
        let raw = RawLog::new(Bytes::from_static(b"test log"), "file:/var/log/syslog");
        assert_eq!(raw.source, "file:/var/log/syslog");
        assert!(raw.format_hint.is_none());
    }

    #[test]
    fn raw_log_with_format_hint() {
        let raw = RawLog::new(Bytes::from_static(b"test"), "test").with_format_hint("syslog");
        assert_eq!(raw.format_hint, Some("syslog".to_owned()));
    }

    #[test]
    fn collector_set_management() {
        let mut set = CollectorSet::new(512);
        assert!(set.is_empty());

        set.register("syslog_udp");
        set.register("file_watcher");
        assert_eq!(set.len(), 2);
        assert!(!set.is_empty());

        let statuses = set.statuses();
        assert_eq!(statuses[0].1, CollectorStatus::Idle);
    }
}

//! 파일 기반 로그 수집기
//!
//! 로그 파일을 감시하며 새로운 라인이 추가되면 수집합니다.
//! `tail -f`와 유사한 동작을 비동기 방식으로 구현합니다.
//!
//! # 로테이션 감지
//! - inode 변경 감지 (logrotate 등)
//! - 파일 크기 축소 감지 (truncation)
//! - 새 파일 자동 열기

use std::path::{Path, PathBuf};

use tokio::sync::mpsc;

use super::{CollectorStatus, RawLog};
use crate::error::LogPipelineError;

/// 파일 수집기 설정
#[derive(Debug, Clone)]
pub struct FileCollectorConfig {
    /// 감시할 파일 경로 목록
    pub watch_paths: Vec<PathBuf>,
    /// 파일 상태 체크 주기 (밀리초)
    pub poll_interval_ms: u64,
    /// 한 번에 읽을 최대 라인 수
    pub max_lines_per_read: usize,
    /// 최대 라인 길이 (바이트)
    pub max_line_length: usize,
}

impl Default for FileCollectorConfig {
    fn default() -> Self {
        Self {
            watch_paths: vec![PathBuf::from("/var/log/syslog")],
            poll_interval_ms: 1000,
            max_lines_per_read: 1000,
            max_line_length: 64 * 1024, // 64KB
        }
    }
}

/// 파일별 추적 상태
#[derive(Debug)]
#[allow(dead_code)]
struct FileState {
    /// 파일 경로
    #[allow(dead_code)]
    path: PathBuf,
    /// 마지막 읽기 위치 (바이트 오프셋)
    #[allow(dead_code)]
    offset: u64,
    /// 현재 파일의 inode (Unix 전용)
    #[cfg(unix)]
    #[allow(dead_code)]
    inode: Option<u64>,
}

/// 파일 기반 로그 수집기
///
/// 지정된 파일 목록을 주기적으로 폴링하여 새로운 로그 라인을 수집합니다.
/// 파일 로테이션(inode 변경, truncation)을 자동 감지합니다.
#[allow(dead_code)]
pub struct FileCollector {
    /// 수집기 설정
    #[allow(dead_code)]
    config: FileCollectorConfig,
    /// 수집된 로그 전송 채널
    #[allow(dead_code)]
    tx: mpsc::Sender<RawLog>,
    /// 파일별 추적 상태
    #[allow(dead_code)]
    file_states: Vec<FileState>,
    /// 현재 상태
    status: CollectorStatus,
}

#[allow(dead_code)]
impl FileCollector {
    /// 새 파일 수집기를 생성합니다.
    pub fn new(config: FileCollectorConfig, tx: mpsc::Sender<RawLog>) -> Self {
        let file_states = config
            .watch_paths
            .iter()
            .map(|path| FileState {
                path: path.clone(),
                offset: 0,
                #[cfg(unix)]
                inode: None,
            })
            .collect();

        Self {
            config,
            tx,
            file_states,
            status: CollectorStatus::Idle,
        }
    }

    /// 수집기를 시작합니다.
    ///
    /// 이 메서드는 취소될 때까지 실행됩니다.
    /// `tokio::spawn`으로 별도 태스크에서 호출하세요.
    pub async fn run(&mut self) -> Result<(), LogPipelineError> {
        self.status = CollectorStatus::Running;
        todo!("implement file watching loop with rotation detection")
    }

    /// 단일 파일에서 새로운 라인을 읽습니다.
    async fn read_new_lines(
        &self,
        _path: &Path,
        _offset: u64,
    ) -> Result<(Vec<bytes::Bytes>, u64), LogPipelineError> {
        todo!("implement file reading from offset")
    }

    /// 파일 로테이션 여부를 확인합니다.
    #[cfg(unix)]
    async fn check_rotation(
        &self,
        _path: &Path,
        _last_inode: Option<u64>,
    ) -> Result<bool, LogPipelineError> {
        todo!("implement inode-based rotation detection")
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
        let config = FileCollectorConfig::default();
        assert_eq!(config.poll_interval_ms, 1000);
        assert_eq!(config.max_lines_per_read, 1000);
    }

    #[test]
    fn collector_starts_idle() {
        let (tx, _rx) = mpsc::channel(10);
        let collector = FileCollector::new(FileCollectorConfig::default(), tx);
        assert_eq!(*collector.status(), CollectorStatus::Idle);
    }
}

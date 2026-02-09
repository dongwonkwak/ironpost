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
use std::time::Duration;

use bytes::Bytes;
use tokio::fs::{File, metadata};
use tokio::io::{AsyncBufReadExt, AsyncSeekExt, BufReader};
use tokio::sync::mpsc;
use tokio::time::sleep;
use tracing::{debug, error, info, warn};

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
        info!(
            "Starting file collector for {} files",
            self.file_states.len()
        );

        let poll_interval = Duration::from_millis(self.config.poll_interval_ms);

        loop {
            for i in 0..self.file_states.len() {
                let path = self.file_states[i].path.clone();
                let mut offset = self.file_states[i].offset;
                #[cfg(unix)]
                let mut inode = self.file_states[i].inode;

                // 파일 로테이션 확인
                #[cfg(unix)]
                {
                    if let Ok(rotated) = Self::check_rotation(&path, inode).await
                        && rotated
                    {
                        info!("File rotation detected: {:?}", path);
                        offset = 0;
                        inode = Self::get_inode(&path).await.ok();
                    }
                }

                // Truncation 감지
                if let Ok(meta) = metadata(&path).await {
                    let file_size = meta.len();
                    if file_size < offset {
                        warn!(
                            "File truncation detected: {:?} (size: {}, offset: {})",
                            path, file_size, offset
                        );
                        offset = 0;
                    }
                }

                // 새 라인 읽기
                match Self::read_new_lines(&path, offset).await {
                    Ok((lines, new_offset)) => {
                        // 상태 업데이트
                        self.file_states[i].offset = new_offset;
                        #[cfg(unix)]
                        {
                            self.file_states[i].inode = inode;
                        }

                        // 읽은 라인을 RawLog로 변환하여 전송
                        for line_bytes in lines {
                            let raw_log =
                                RawLog::new(line_bytes, format!("file:{}", path.display()))
                                    .with_format_hint("syslog");

                            if let Err(e) = self.tx.send(raw_log).await {
                                error!("Failed to send log: {}", e);
                                self.status = CollectorStatus::Error(e.to_string());
                                return Err(LogPipelineError::Channel(e.to_string()));
                            }
                        }
                    }
                    Err(e) => {
                        error!("Failed to read file {:?}: {}", path, e);
                        // 에러 발생 시 백오프 후 계속 진행
                        sleep(Duration::from_secs(1)).await;
                    }
                }
            }

            // 폴링 간격 대기
            sleep(poll_interval).await;
        }
    }

    /// 단일 파일에서 새로운 라인을 읽습니다.
    ///
    /// 주어진 오프셋부터 파일을 읽어 새로운 라인들을 반환합니다.
    /// 반환값: (읽은 라인들, 새로운 오프셋)
    async fn read_new_lines(
        path: &Path,
        offset: u64,
    ) -> Result<(Vec<Bytes>, u64), LogPipelineError> {
        let file = File::open(path)
            .await
            .map_err(|e| LogPipelineError::Collector {
                source_type: "file".to_owned(),
                reason: format!("failed to open {:?}: {}", path, e),
            })?;

        let mut reader = BufReader::new(file);

        // 오프셋으로 이동
        reader
            .seek(std::io::SeekFrom::Start(offset))
            .await
            .map_err(|e| LogPipelineError::Collector {
                source_type: "file".to_owned(),
                reason: format!("failed to seek to offset {}: {}", offset, e),
            })?;

        let mut lines = Vec::new();
        let mut current_offset = offset;
        let mut line_buffer = String::new();
        const MAX_LINE_LENGTH: usize = 64 * 1024; // 64KB default

        loop {
            line_buffer.clear();

            // 라인 길이 제한을 적용하며 읽기
            let bytes_read = reader.read_line(&mut line_buffer).await.map_err(|e| {
                LogPipelineError::Collector {
                    source_type: "file".to_owned(),
                    reason: format!("failed to read line: {}", e),
                }
            })?;

            // 라인이 최대 길이를 초과하는지 확인
            if line_buffer.len() > MAX_LINE_LENGTH {
                return Err(LogPipelineError::Collector {
                    source_type: "file".to_owned(),
                    reason: format!("line exceeds max length: {} (max: {})", line_buffer.len(), MAX_LINE_LENGTH),
                });
            }

            if bytes_read == 0 {
                // EOF 도달
                break;
            }

            current_offset = current_offset
                .checked_add(
                    u64::try_from(bytes_read).map_err(|_| LogPipelineError::Collector {
                        source_type: "file".to_owned(),
                        reason: format!("offset overflow: {}", bytes_read),
                    })?,
                )
                .ok_or_else(|| LogPipelineError::Collector {
                    source_type: "file".to_owned(),
                    reason: "offset overflow".to_owned(),
                })?;

            // 빈 라인이 아니면 추가
            if !line_buffer.trim().is_empty() {
                lines.push(Bytes::from(line_buffer.trim_end().to_owned()));
            }

            // 한 번에 너무 많은 라인을 읽지 않도록 제한
            if lines.len() >= 1000 {
                debug!("Read batch limit reached (1000 lines), will continue in next iteration");
                break;
            }
        }

        Ok((lines, current_offset))
    }

    /// 파일 로테이션 여부를 확인합니다.
    ///
    /// Unix 시스템에서 inode를 비교하여 로테이션을 감지합니다.
    #[cfg(unix)]
    async fn check_rotation(
        path: &Path,
        last_inode: Option<u64>,
    ) -> Result<bool, LogPipelineError> {
        let current_inode = Self::get_inode(path).await?;

        if let Some(last) = last_inode {
            Ok(current_inode != last)
        } else {
            // 첫 번째 체크, 로테이션 아님
            Ok(false)
        }
    }

    /// 파일의 inode를 가져옵니다 (Unix 전용).
    #[cfg(unix)]
    async fn get_inode(path: &Path) -> Result<u64, LogPipelineError> {
        use std::os::unix::fs::MetadataExt;

        let meta = metadata(path)
            .await
            .map_err(|e| LogPipelineError::Collector {
                source_type: "file".to_owned(),
                reason: format!("failed to get metadata for {:?}: {}", path, e),
            })?;

        Ok(meta.ino())
    }

    /// 현재 상태를 반환합니다.
    pub fn status(&self) -> &CollectorStatus {
        &self.status
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::{Seek, Write};
    use tempfile::NamedTempFile;
    use tokio::fs;

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

    #[tokio::test]
    async fn read_new_lines_from_file() {
        // 테스트 파일 생성
        let mut temp_file = NamedTempFile::new().unwrap();
        writeln!(temp_file, "line 1").unwrap();
        writeln!(temp_file, "line 2").unwrap();
        writeln!(temp_file, "line 3").unwrap();
        temp_file.flush().unwrap();

        let (tx, _rx) = mpsc::channel(10);
        let _collector = FileCollector::new(FileCollectorConfig::default(), tx);

        // 오프셋 0부터 읽기
        let (lines, new_offset) = FileCollector::read_new_lines(temp_file.path(), 0)
            .await
            .unwrap();

        assert_eq!(lines.len(), 3);
        assert_eq!(lines[0].as_ref(), b"line 1");
        assert_eq!(lines[1].as_ref(), b"line 2");
        assert_eq!(lines[2].as_ref(), b"line 3");
        assert!(new_offset > 0);
    }

    #[tokio::test]
    async fn read_new_lines_with_offset() {
        let mut temp_file = NamedTempFile::new().unwrap();
        writeln!(temp_file, "line 1").unwrap();
        let first_offset = temp_file.stream_position().unwrap();
        writeln!(temp_file, "line 2").unwrap();
        writeln!(temp_file, "line 3").unwrap();
        temp_file.flush().unwrap();

        let (tx, _rx) = mpsc::channel(10);
        let _collector = FileCollector::new(FileCollectorConfig::default(), tx);

        // 첫 번째 라인 이후부터 읽기
        let (lines, _) = FileCollector::read_new_lines(temp_file.path(), first_offset)
            .await
            .unwrap();

        assert_eq!(lines.len(), 2);
        assert_eq!(lines[0].as_ref(), b"line 2");
        assert_eq!(lines[1].as_ref(), b"line 3");
    }

    #[tokio::test]
    async fn read_empty_file() {
        let temp_file = NamedTempFile::new().unwrap();

        let (tx, _rx) = mpsc::channel(10);
        let _collector = FileCollector::new(FileCollectorConfig::default(), tx);

        let (lines, new_offset) = FileCollector::read_new_lines(temp_file.path(), 0)
            .await
            .unwrap();

        assert_eq!(lines.len(), 0);
        assert_eq!(new_offset, 0);
    }

    #[tokio::test]
    async fn skip_empty_lines() {
        let mut temp_file = NamedTempFile::new().unwrap();
        writeln!(temp_file, "line 1").unwrap();
        writeln!(temp_file).unwrap(); // 빈 라인
        writeln!(temp_file, "line 2").unwrap();
        temp_file.flush().unwrap();

        let (tx, _rx) = mpsc::channel(10);
        let _collector = FileCollector::new(FileCollectorConfig::default(), tx);

        let (lines, _) = FileCollector::read_new_lines(temp_file.path(), 0)
            .await
            .unwrap();

        // 빈 라인은 제외되어야 함
        assert_eq!(lines.len(), 2);
        assert_eq!(lines[0].as_ref(), b"line 1");
        assert_eq!(lines[1].as_ref(), b"line 2");
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn get_inode_returns_valid_inode() {
        let temp_file = NamedTempFile::new().unwrap();
        let inode = FileCollector::get_inode(temp_file.path()).await.unwrap();
        assert!(inode > 0);
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn check_rotation_detects_no_change() {
        let temp_file = NamedTempFile::new().unwrap();
        let inode = FileCollector::get_inode(temp_file.path()).await.unwrap();

        let (tx, _rx) = mpsc::channel(10);
        let _collector = FileCollector::new(FileCollectorConfig::default(), tx);

        let rotated = FileCollector::check_rotation(temp_file.path(), Some(inode))
            .await
            .unwrap();
        assert!(!rotated);
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn check_rotation_detects_change() {
        // 원본 파일 생성
        let temp_file = NamedTempFile::new().unwrap();
        let old_inode = FileCollector::get_inode(temp_file.path()).await.unwrap();

        // 파일을 새로 만들어서 inode 변경 시뮬레이션
        let path = temp_file.path().to_owned();
        drop(temp_file); // 기존 파일 삭제
        fs::write(&path, b"new content").await.unwrap();

        let new_inode = FileCollector::get_inode(&path).await.unwrap();
        assert_ne!(old_inode, new_inode);

        let (tx, _rx) = mpsc::channel(10);
        let _collector = FileCollector::new(FileCollectorConfig::default(), tx);

        let rotated = FileCollector::check_rotation(&path, Some(old_inode))
            .await
            .unwrap();
        assert!(rotated);
    }
}

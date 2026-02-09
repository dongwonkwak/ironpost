//! 로그 파이프라인 설정
//!
//! [`PipelineConfig`]는 core의 [`LogPipelineConfig`](ironpost_core::config::LogPipelineConfig)를
//! 기반으로 로그 파이프라인 전용 설정을 제공합니다.
//!
//! # 사용 예시
//! ```ignore
//! use ironpost_core::config::IronpostConfig;
//! use ironpost_log_pipeline::config::PipelineConfig;
//!
//! let core_config = IronpostConfig::default();
//! let config = PipelineConfig::from_core(&core_config.log_pipeline);
//! ```

use serde::{Deserialize, Serialize};

use crate::error::LogPipelineError;

/// 버퍼 오버플로우 시 드롭 정책
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub enum DropPolicy {
    /// 가장 오래된 엔트리를 드롭 (기본값)
    #[default]
    Oldest,
    /// 가장 최신 엔트리를 드롭 (새 유입 거부)
    Newest,
}

/// 로그 파이프라인 설정
///
/// core의 `LogPipelineConfig`에서 파생되며, 파이프라인 내부에서
/// 사용하는 추가 설정을 포함합니다.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PipelineConfig {
    /// 활성화 여부
    pub enabled: bool,
    /// 수집 소스 목록 (syslog, file 등)
    pub sources: Vec<String>,
    /// Syslog 수신 바인드 주소
    pub syslog_bind: String,
    /// 파일 감시 경로 목록
    pub watch_paths: Vec<String>,
    /// 배치 크기 (이 개수만큼 모이면 플러시)
    pub batch_size: usize,
    /// 배치 플러시 간격 (초)
    pub flush_interval_secs: u64,

    // --- 확장 설정 (core에 없는 추가 필드) ---
    /// 탐지 룰 디렉토리 경로
    pub rule_dir: String,
    /// 룰 리로드 주기 (초)
    pub rule_reload_secs: u64,
    /// 인메모리 버퍼 최대 용량
    pub buffer_capacity: usize,
    /// 버퍼 오버플로우 드롭 정책
    pub drop_policy: DropPolicy,
    /// 알림 중복 제거 윈도우 (초)
    pub alert_dedup_window_secs: u64,
    /// 룰당 분당 최대 알림 수
    pub alert_rate_limit_per_rule: u32,
}

impl Default for PipelineConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            sources: vec!["syslog".to_owned(), "file".to_owned()],
            syslog_bind: "0.0.0.0:514".to_owned(),
            watch_paths: vec!["/var/log/syslog".to_owned()],
            batch_size: 100,
            flush_interval_secs: 5,
            rule_dir: "/etc/ironpost/rules".to_owned(),
            rule_reload_secs: 30,
            buffer_capacity: 10_000,
            drop_policy: DropPolicy::Oldest,
            alert_dedup_window_secs: 60,
            alert_rate_limit_per_rule: 10,
        }
    }
}

impl PipelineConfig {
    /// core의 `LogPipelineConfig`에서 파이프라인 설정을 생성합니다.
    ///
    /// core 설정에 없는 확장 필드는 기본값이 적용됩니다.
    pub fn from_core(core: &ironpost_core::config::LogPipelineConfig) -> Self {
        Self {
            enabled: core.enabled,
            sources: core.sources.clone(),
            syslog_bind: core.syslog_bind.clone(),
            watch_paths: core.watch_paths.clone(),
            batch_size: core.batch_size,
            flush_interval_secs: core.flush_interval_secs,
            ..Self::default()
        }
    }

    /// 설정값의 유효성을 검증합니다.
    pub fn validate(&self) -> Result<(), LogPipelineError> {
        if self.batch_size == 0 {
            return Err(LogPipelineError::Config {
                field: "batch_size".to_owned(),
                reason: "must be greater than 0".to_owned(),
            });
        }

        if self.flush_interval_secs == 0 {
            return Err(LogPipelineError::Config {
                field: "flush_interval_secs".to_owned(),
                reason: "must be greater than 0".to_owned(),
            });
        }

        if self.buffer_capacity == 0 {
            return Err(LogPipelineError::Config {
                field: "buffer_capacity".to_owned(),
                reason: "must be greater than 0".to_owned(),
            });
        }

        if self.enabled && self.sources.is_empty() {
            return Err(LogPipelineError::Config {
                field: "sources".to_owned(),
                reason: "at least one source must be configured when enabled".to_owned(),
            });
        }

        Ok(())
    }
}

/// 파이프라인 설정 빌더
///
/// 3개 이상의 설정 필드가 있으므로 빌더 패턴을 사용합니다.
#[derive(Default)]
pub struct PipelineConfigBuilder {
    config: PipelineConfig,
}

impl PipelineConfigBuilder {
    /// 새 빌더를 생성합니다.
    pub fn new() -> Self {
        Self::default()
    }

    /// 활성화 여부를 설정합니다.
    pub fn enabled(mut self, enabled: bool) -> Self {
        self.config.enabled = enabled;
        self
    }

    /// 수집 소스를 설정합니다.
    pub fn sources(mut self, sources: Vec<String>) -> Self {
        self.config.sources = sources;
        self
    }

    /// Syslog 바인드 주소를 설정합니다.
    pub fn syslog_bind(mut self, bind: impl Into<String>) -> Self {
        self.config.syslog_bind = bind.into();
        self
    }

    /// 파일 감시 경로를 설정합니다.
    pub fn watch_paths(mut self, paths: Vec<String>) -> Self {
        self.config.watch_paths = paths;
        self
    }

    /// 배치 크기를 설정합니다.
    pub fn batch_size(mut self, size: usize) -> Self {
        self.config.batch_size = size;
        self
    }

    /// 플러시 간격(초)을 설정합니다.
    pub fn flush_interval_secs(mut self, secs: u64) -> Self {
        self.config.flush_interval_secs = secs;
        self
    }

    /// 룰 디렉토리를 설정합니다.
    pub fn rule_dir(mut self, dir: impl Into<String>) -> Self {
        self.config.rule_dir = dir.into();
        self
    }

    /// 버퍼 용량을 설정합니다.
    pub fn buffer_capacity(mut self, capacity: usize) -> Self {
        self.config.buffer_capacity = capacity;
        self
    }

    /// 드롭 정책을 설정합니다.
    pub fn drop_policy(mut self, policy: DropPolicy) -> Self {
        self.config.drop_policy = policy;
        self
    }

    /// 설정을 검증하고 `PipelineConfig`를 생성합니다.
    pub fn build(self) -> Result<PipelineConfig, LogPipelineError> {
        self.config.validate()?;
        Ok(self.config)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_config_is_valid() {
        let config = PipelineConfig::default();
        config.validate().unwrap();
    }

    #[test]
    fn from_core_preserves_values() {
        let core = ironpost_core::config::LogPipelineConfig {
            enabled: true,
            sources: vec!["syslog".to_owned()],
            syslog_bind: "127.0.0.1:5140".to_owned(),
            watch_paths: vec!["/var/log/auth.log".to_owned()],
            batch_size: 200,
            flush_interval_secs: 10,
            ..Default::default()
        };
        let config = PipelineConfig::from_core(&core);
        assert_eq!(config.syslog_bind, "127.0.0.1:5140");
        assert_eq!(config.batch_size, 200);
        // 확장 필드는 기본값
        assert_eq!(config.buffer_capacity, 10_000);
    }

    #[test]
    fn validate_rejects_zero_batch_size() {
        let mut config = PipelineConfig::default();
        config.batch_size = 0;
        assert!(config.validate().is_err());
    }

    #[test]
    fn validate_rejects_empty_sources_when_enabled() {
        let mut config = PipelineConfig::default();
        config.sources.clear();
        assert!(config.validate().is_err());
    }

    #[test]
    fn builder_creates_valid_config() {
        let config = PipelineConfigBuilder::new()
            .batch_size(50)
            .buffer_capacity(5000)
            .rule_dir("/custom/rules")
            .build()
            .unwrap();
        assert_eq!(config.batch_size, 50);
        assert_eq!(config.buffer_capacity, 5000);
        assert_eq!(config.rule_dir, "/custom/rules");
    }

    #[test]
    fn builder_rejects_invalid_config() {
        let result = PipelineConfigBuilder::new().batch_size(0).build();
        assert!(result.is_err());
    }

    #[test]
    fn drop_policy_default_is_oldest() {
        assert_eq!(DropPolicy::default(), DropPolicy::Oldest);
    }
}

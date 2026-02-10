//! 컨테이너 가드 설정
//!
//! [`ContainerGuardConfig`]는 core의 [`ContainerConfig`](ironpost_core::config::ContainerConfig)를
//! 기반으로 컨테이너 가드 전용 설정을 제공합니다.
//!
//! # 사용 예시
//! ```ignore
//! use ironpost_core::config::IronpostConfig;
//! use ironpost_container_guard::config::ContainerGuardConfig;
//!
//! let core_config = IronpostConfig::default();
//! let config = ContainerGuardConfig::from_core(&core_config.container);
//! ```

use serde::{Deserialize, Serialize};

use crate::error::ContainerGuardError;

/// 컨테이너 가드 설정
///
/// core의 `ContainerConfig`에서 파생되며, 가드 내부에서
/// 사용하는 추가 설정을 포함합니다.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ContainerGuardConfig {
    /// 활성화 여부
    pub enabled: bool,
    /// Docker 소켓 경로
    pub docker_socket: String,
    /// 컨테이너 이벤트 폴링 주기 (초)
    pub poll_interval_secs: u64,
    /// 격리 정책 파일 디렉토리
    pub policy_path: String,
    /// 자동 격리 활성화
    pub auto_isolate: bool,

    // --- 확장 설정 (core에 없는 추가 필드) ---
    /// 동시 격리 액션 최대 수
    pub max_concurrent_actions: usize,
    /// 격리 액션 타임아웃 (초)
    pub action_timeout_secs: u64,
    /// 격리 실패 시 재시도 최대 횟수
    pub retry_max_attempts: u32,
    /// 재시도 백오프 기본 간격 (밀리초)
    pub retry_backoff_base_ms: u64,
    /// 컨테이너 정보 캐시 TTL (초)
    pub container_cache_ttl_secs: u64,
}

impl Default for ContainerGuardConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            docker_socket: "/var/run/docker.sock".to_owned(),
            poll_interval_secs: 10,
            policy_path: "/etc/ironpost/policies".to_owned(),
            auto_isolate: false,
            max_concurrent_actions: 10,
            action_timeout_secs: 30,
            retry_max_attempts: 3,
            retry_backoff_base_ms: 500,
            container_cache_ttl_secs: 60,
        }
    }
}

/// 설정 상한값 상수
const MAX_POLL_INTERVAL_SECS: u64 = 3600;
const MAX_ACTION_TIMEOUT_SECS: u64 = 300;
const MAX_RETRY_ATTEMPTS: u32 = 10;
const MAX_CONCURRENT_ACTIONS: usize = 100;
const MAX_CACHE_TTL_SECS: u64 = 3600;
const MAX_RETRY_BACKOFF_BASE_MS: u64 = 30_000;

impl ContainerGuardConfig {
    /// core의 `ContainerConfig`에서 가드 설정을 생성합니다.
    ///
    /// core 설정에 없는 확장 필드는 기본값이 적용됩니다.
    pub fn from_core(core: &ironpost_core::config::ContainerConfig) -> Self {
        Self {
            enabled: core.enabled,
            docker_socket: core.docker_socket.clone(),
            poll_interval_secs: core.poll_interval_secs,
            policy_path: core.policy_path.clone(),
            auto_isolate: core.auto_isolate,
            ..Self::default()
        }
    }

    /// 설정값의 유효성을 검증합니다.
    pub fn validate(&self) -> Result<(), ContainerGuardError> {
        if self.poll_interval_secs == 0 || self.poll_interval_secs > MAX_POLL_INTERVAL_SECS {
            return Err(ContainerGuardError::Config {
                field: "poll_interval_secs".to_owned(),
                reason: format!("must be 1-{MAX_POLL_INTERVAL_SECS}"),
            });
        }

        if self.action_timeout_secs == 0 || self.action_timeout_secs > MAX_ACTION_TIMEOUT_SECS {
            return Err(ContainerGuardError::Config {
                field: "action_timeout_secs".to_owned(),
                reason: format!("must be 1-{MAX_ACTION_TIMEOUT_SECS}"),
            });
        }

        if self.retry_max_attempts > MAX_RETRY_ATTEMPTS {
            return Err(ContainerGuardError::Config {
                field: "retry_max_attempts".to_owned(),
                reason: format!("must be 0-{MAX_RETRY_ATTEMPTS}"),
            });
        }

        if self.max_concurrent_actions == 0 || self.max_concurrent_actions > MAX_CONCURRENT_ACTIONS
        {
            return Err(ContainerGuardError::Config {
                field: "max_concurrent_actions".to_owned(),
                reason: format!("must be 1-{MAX_CONCURRENT_ACTIONS}"),
            });
        }

        if self.container_cache_ttl_secs == 0 || self.container_cache_ttl_secs > MAX_CACHE_TTL_SECS
        {
            return Err(ContainerGuardError::Config {
                field: "container_cache_ttl_secs".to_owned(),
                reason: format!("must be 1-{MAX_CACHE_TTL_SECS}"),
            });
        }

        if self.retry_backoff_base_ms > MAX_RETRY_BACKOFF_BASE_MS {
            return Err(ContainerGuardError::Config {
                field: "retry_backoff_base_ms".to_owned(),
                reason: format!("must be 0-{MAX_RETRY_BACKOFF_BASE_MS}"),
            });
        }

        if self.enabled && self.docker_socket.is_empty() {
            return Err(ContainerGuardError::Config {
                field: "docker_socket".to_owned(),
                reason: "docker_socket must not be empty when enabled".to_owned(),
            });
        }

        Ok(())
    }
}

/// 컨테이너 가드 설정 빌더
///
/// 3개 이상의 설정 필드가 있으므로 빌더 패턴을 사용합니다.
#[derive(Default)]
pub struct ContainerGuardConfigBuilder {
    config: ContainerGuardConfig,
}

impl ContainerGuardConfigBuilder {
    /// 새 빌더를 생성합니다.
    pub fn new() -> Self {
        Self::default()
    }

    /// 활성화 여부를 설정합니다.
    pub fn enabled(mut self, enabled: bool) -> Self {
        self.config.enabled = enabled;
        self
    }

    /// Docker 소켓 경로를 설정합니다.
    pub fn docker_socket(mut self, socket: impl Into<String>) -> Self {
        self.config.docker_socket = socket.into();
        self
    }

    /// 폴링 주기(초)를 설정합니다.
    pub fn poll_interval_secs(mut self, secs: u64) -> Self {
        self.config.poll_interval_secs = secs;
        self
    }

    /// 정책 디렉토리 경로를 설정합니다.
    pub fn policy_path(mut self, path: impl Into<String>) -> Self {
        self.config.policy_path = path.into();
        self
    }

    /// 자동 격리 활성화 여부를 설정합니다.
    pub fn auto_isolate(mut self, auto: bool) -> Self {
        self.config.auto_isolate = auto;
        self
    }

    /// 동시 격리 액션 최대 수를 설정합니다.
    pub fn max_concurrent_actions(mut self, max: usize) -> Self {
        self.config.max_concurrent_actions = max;
        self
    }

    /// 액션 타임아웃(초)을 설정합니다.
    pub fn action_timeout_secs(mut self, secs: u64) -> Self {
        self.config.action_timeout_secs = secs;
        self
    }

    /// 재시도 최대 횟수를 설정합니다.
    pub fn retry_max_attempts(mut self, attempts: u32) -> Self {
        self.config.retry_max_attempts = attempts;
        self
    }

    /// 재시도 백오프 기본 간격(밀리초)을 설정합니다.
    pub fn retry_backoff_base_ms(mut self, ms: u64) -> Self {
        self.config.retry_backoff_base_ms = ms;
        self
    }

    /// 컨테이너 캐시 TTL(초)을 설정합니다.
    pub fn container_cache_ttl_secs(mut self, secs: u64) -> Self {
        self.config.container_cache_ttl_secs = secs;
        self
    }

    /// 설정을 검증하고 `ContainerGuardConfig`를 생성합니다.
    pub fn build(self) -> Result<ContainerGuardConfig, ContainerGuardError> {
        self.config.validate()?;
        Ok(self.config)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_config_is_valid() {
        let config = ContainerGuardConfig::default();
        config.validate().unwrap();
    }

    #[test]
    fn from_core_preserves_values() {
        let core = ironpost_core::config::ContainerConfig {
            enabled: true,
            docker_socket: "/run/docker.sock".to_owned(),
            poll_interval_secs: 5,
            policy_path: "/custom/policies".to_owned(),
            auto_isolate: true,
        };
        let config = ContainerGuardConfig::from_core(&core);
        assert!(config.enabled);
        assert_eq!(config.docker_socket, "/run/docker.sock");
        assert_eq!(config.poll_interval_secs, 5);
        assert_eq!(config.policy_path, "/custom/policies");
        assert!(config.auto_isolate);
        // extended fields use defaults
        assert_eq!(config.max_concurrent_actions, 10);
        assert_eq!(config.action_timeout_secs, 30);
    }

    #[test]
    fn validate_rejects_zero_poll_interval() {
        let config = ContainerGuardConfig {
            poll_interval_secs: 0,
            ..Default::default()
        };
        assert!(config.validate().is_err());
    }

    #[test]
    fn validate_rejects_excessive_poll_interval() {
        let config = ContainerGuardConfig {
            poll_interval_secs: 7200,
            ..Default::default()
        };
        assert!(config.validate().is_err());
    }

    #[test]
    fn validate_rejects_zero_action_timeout() {
        let config = ContainerGuardConfig {
            action_timeout_secs: 0,
            ..Default::default()
        };
        assert!(config.validate().is_err());
    }

    #[test]
    fn validate_rejects_excessive_retry_attempts() {
        let config = ContainerGuardConfig {
            retry_max_attempts: 20,
            ..Default::default()
        };
        assert!(config.validate().is_err());
    }

    #[test]
    fn validate_rejects_zero_concurrent_actions() {
        let config = ContainerGuardConfig {
            max_concurrent_actions: 0,
            ..Default::default()
        };
        assert!(config.validate().is_err());
    }

    #[test]
    fn validate_rejects_empty_socket_when_enabled() {
        let config = ContainerGuardConfig {
            enabled: true,
            docker_socket: String::new(),
            ..Default::default()
        };
        assert!(config.validate().is_err());
    }

    #[test]
    fn validate_accepts_empty_socket_when_disabled() {
        let config = ContainerGuardConfig {
            enabled: false,
            docker_socket: String::new(),
            ..Default::default()
        };
        // docker_socket empty is fine when disabled
        config.validate().unwrap();
    }

    #[test]
    fn builder_creates_valid_config() {
        let config = ContainerGuardConfigBuilder::new()
            .poll_interval_secs(5)
            .max_concurrent_actions(20)
            .action_timeout_secs(60)
            .build()
            .unwrap();
        assert_eq!(config.poll_interval_secs, 5);
        assert_eq!(config.max_concurrent_actions, 20);
        assert_eq!(config.action_timeout_secs, 60);
    }

    #[test]
    fn builder_rejects_invalid_config() {
        let result = ContainerGuardConfigBuilder::new()
            .poll_interval_secs(0)
            .build();
        assert!(result.is_err());
    }

    #[test]
    fn config_serialize_roundtrip() {
        let config = ContainerGuardConfig::default();
        let json = serde_json::to_string(&config).unwrap();
        let deserialized: ContainerGuardConfig = serde_json::from_str(&json).unwrap();
        assert_eq!(config.poll_interval_secs, deserialized.poll_interval_secs);
        assert_eq!(config.docker_socket, deserialized.docker_socket);
    }

    // --- Edge Case Tests ---

    #[test]
    fn validate_boundary_max_poll_interval() {
        let config = ContainerGuardConfig {
            poll_interval_secs: 3600, // 1 hour - valid
            ..Default::default()
        };
        assert!(config.validate().is_ok());
    }

    #[test]
    fn validate_boundary_max_poll_interval_exceeded() {
        let config = ContainerGuardConfig {
            poll_interval_secs: 3601,
            ..Default::default()
        };
        assert!(config.validate().is_err());
    }

    #[test]
    fn validate_boundary_retry_attempts() {
        let config = ContainerGuardConfig {
            retry_max_attempts: 10, // Max allowed
            ..Default::default()
        };
        assert!(config.validate().is_ok());
    }

    #[test]
    fn validate_min_values() {
        let config = ContainerGuardConfig {
            poll_interval_secs: 1,
            max_concurrent_actions: 1,
            action_timeout_secs: 1,
            retry_max_attempts: 0,
            retry_backoff_base_ms: 1,
            container_cache_ttl_secs: 1,
            ..Default::default()
        };
        assert!(config.validate().is_ok());
    }

    #[test]
    fn validate_zero_action_timeout_rejected() {
        let config = ContainerGuardConfig {
            action_timeout_secs: 0,
            ..Default::default()
        };
        assert!(config.validate().is_err());
    }

    #[test]
    fn validate_zero_cache_ttl_rejected() {
        let config = ContainerGuardConfig {
            container_cache_ttl_secs: 0,
            ..Default::default()
        };
        assert!(config.validate().is_err());
    }

    #[test]
    fn builder_all_setters() {
        let config = ContainerGuardConfigBuilder::new()
            .enabled(true)
            .docker_socket("/custom/docker.sock")
            .poll_interval_secs(15)
            .policy_path("/custom/policies")
            .auto_isolate(true)
            .max_concurrent_actions(25)
            .action_timeout_secs(45)
            .retry_max_attempts(5)
            .retry_backoff_base_ms(200)
            .container_cache_ttl_secs(120)
            .build()
            .unwrap();

        assert!(config.enabled);
        assert_eq!(config.docker_socket, "/custom/docker.sock");
        assert_eq!(config.poll_interval_secs, 15);
        assert_eq!(config.policy_path, "/custom/policies");
        assert!(config.auto_isolate);
        assert_eq!(config.max_concurrent_actions, 25);
        assert_eq!(config.action_timeout_secs, 45);
        assert_eq!(config.retry_max_attempts, 5);
        assert_eq!(config.retry_backoff_base_ms, 200);
        assert_eq!(config.container_cache_ttl_secs, 120);
    }

    #[test]
    fn builder_partial_setters_uses_defaults() {
        let config = ContainerGuardConfigBuilder::new()
            .poll_interval_secs(7)
            .enabled(true) // Need to enable explicitly
            .docker_socket("/var/run/docker.sock")
            .build()
            .unwrap();

        assert_eq!(config.poll_interval_secs, 7);
        // Others should be defaults
        assert!(config.enabled);
        assert_eq!(config.max_concurrent_actions, 10);
    }

    #[test]
    fn from_core_with_disabled() {
        let core = ironpost_core::config::ContainerConfig {
            enabled: false,
            docker_socket: "".to_owned(),
            poll_interval_secs: 10,
            policy_path: "/etc/policies".to_owned(),
            auto_isolate: false,
        };
        let config = ContainerGuardConfig::from_core(&core);
        assert!(!config.enabled);
        assert!(!config.auto_isolate);
        config.validate().unwrap(); // Empty socket OK when disabled
    }

    #[test]
    fn from_core_extreme_values() {
        let core = ironpost_core::config::ContainerConfig {
            enabled: true,
            docker_socket: "/var/run/docker.sock".to_owned(),
            poll_interval_secs: 3600, // Max
            policy_path: "/policies".to_owned(),
            auto_isolate: true,
        };
        let config = ContainerGuardConfig::from_core(&core);
        assert_eq!(config.poll_interval_secs, 3600);
        config.validate().unwrap();
    }

    #[test]
    fn validate_empty_policy_path_allowed() {
        let config = ContainerGuardConfig {
            policy_path: "".to_owned(),
            ..Default::default()
        };
        // Empty policy path is allowed (might use built-in policies)
        config.validate().unwrap();
    }

    #[test]
    fn builder_chaining() {
        let result = ContainerGuardConfigBuilder::new()
            .enabled(false)
            .enabled(true) // Override
            .poll_interval_secs(5)
            .poll_interval_secs(10) // Override
            .build();

        let config = result.unwrap();
        assert!(config.enabled);
        assert_eq!(config.poll_interval_secs, 10);
    }
}

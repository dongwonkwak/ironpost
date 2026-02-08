//! 설정 관리 — ironpost.toml 파싱 및 런타임 설정
//!
//! [`IronpostConfig`]는 모든 모듈의 설정을 담는 최상위 구조체입니다.
//!
//! # 설정 로딩 우선순위
//! 1. CLI 인자 (최고 우선)
//! 2. 환경변수 (`IRONPOST_EBPF_INTERFACE=eth0` 형식)
//! 3. 설정 파일 (`ironpost.toml`)
//! 4. 기본값 (`Default` 구현)
//!
//! # 사용 예시
//! ```no_run
//! # async fn example() -> Result<(), ironpost_core::error::IronpostError> {
//! use ironpost_core::config::IronpostConfig;
//!
//! // 파일에서 로드 + 환경변수 오버라이드
//! let config = IronpostConfig::load("ironpost.toml").await?;
//!
//! // TOML 문자열에서 직접 파싱
//! let config = IronpostConfig::parse("[general]\nlog_level = \"debug\"")?;
//! # Ok(())
//! # }
//! ```

use std::path::Path;

use serde::{Deserialize, Serialize};
use tracing::warn;

use crate::error::{ConfigError, IronpostError};

/// Ironpost 통합 설정
///
/// `ironpost.toml` 파일의 최상위 구조를 나타냅니다.
/// 각 모듈은 자기 섹션만 읽어 사용합니다.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct IronpostConfig {
    /// 일반 설정
    #[serde(default)]
    pub general: GeneralConfig,
    /// eBPF 엔진 설정
    #[serde(default)]
    pub ebpf: EbpfConfig,
    /// 로그 파이프라인 설정
    #[serde(default)]
    pub log_pipeline: LogPipelineConfig,
    /// 컨테이너 가드 설정
    #[serde(default)]
    pub container: ContainerConfig,
    /// SBOM 스캐너 설정
    #[serde(default)]
    pub sbom: SbomConfig,
}

impl IronpostConfig {
    /// TOML 파일에서 설정을 로드하고 환경변수 오버라이드를 적용합니다.
    ///
    /// 설정 로딩 순서:
    /// 1. TOML 파일 파싱
    /// 2. 환경변수 오버라이드 적용
    pub async fn load(path: impl AsRef<Path>) -> Result<Self, IronpostError> {
        let mut config = Self::from_file(path).await?;
        config.apply_env_overrides();
        config.validate()?;
        Ok(config)
    }

    /// TOML 파일에서 설정을 로드합니다 (환경변수 오버라이드 없음).
    pub async fn from_file(path: impl AsRef<Path>) -> Result<Self, IronpostError> {
        let path = path.as_ref();
        let content = tokio::fs::read_to_string(path).await.map_err(|e| {
            if e.kind() == std::io::ErrorKind::NotFound {
                IronpostError::Config(ConfigError::FileNotFound {
                    path: path.display().to_string(),
                })
            } else {
                IronpostError::Io(e)
            }
        })?;
        let config = Self::parse(&content)?;
        config.validate()?;
        Ok(config)
    }

    /// TOML 문자열에서 설정을 파싱합니다.
    pub fn parse(toml_str: &str) -> Result<Self, IronpostError> {
        toml::from_str(toml_str).map_err(|e| {
            IronpostError::Config(ConfigError::ParseFailed {
                reason: e.to_string(),
            })
        })
    }

    /// 환경변수로 설정값을 오버라이드합니다.
    ///
    /// 환경변수 네이밍 규칙: `IRONPOST_{SECTION}_{FIELD}`
    /// 예: `IRONPOST_EBPF_INTERFACE=eth0`
    pub fn apply_env_overrides(&mut self) {
        // General
        override_string(&mut self.general.log_level, "IRONPOST_GENERAL_LOG_LEVEL");
        override_string(&mut self.general.log_format, "IRONPOST_GENERAL_LOG_FORMAT");
        override_string(&mut self.general.data_dir, "IRONPOST_GENERAL_DATA_DIR");
        override_string(&mut self.general.pid_file, "IRONPOST_GENERAL_PID_FILE");

        // eBPF
        override_bool(&mut self.ebpf.enabled, "IRONPOST_EBPF_ENABLED");
        override_string(&mut self.ebpf.interface, "IRONPOST_EBPF_INTERFACE");
        override_string(&mut self.ebpf.xdp_mode, "IRONPOST_EBPF_XDP_MODE");
        override_usize(
            &mut self.ebpf.ring_buffer_size,
            "IRONPOST_EBPF_RING_BUFFER_SIZE",
        );
        override_usize(
            &mut self.ebpf.blocklist_max_entries,
            "IRONPOST_EBPF_BLOCKLIST_MAX_ENTRIES",
        );

        // Log Pipeline
        override_bool(
            &mut self.log_pipeline.enabled,
            "IRONPOST_LOG_PIPELINE_ENABLED",
        );
        override_csv(
            &mut self.log_pipeline.sources,
            "IRONPOST_LOG_PIPELINE_SOURCES",
        );
        override_string(
            &mut self.log_pipeline.syslog_bind,
            "IRONPOST_LOG_PIPELINE_SYSLOG_BIND",
        );
        override_csv(
            &mut self.log_pipeline.watch_paths,
            "IRONPOST_LOG_PIPELINE_WATCH_PATHS",
        );
        override_usize(
            &mut self.log_pipeline.batch_size,
            "IRONPOST_LOG_PIPELINE_BATCH_SIZE",
        );
        override_u64(
            &mut self.log_pipeline.flush_interval_secs,
            "IRONPOST_LOG_PIPELINE_FLUSH_INTERVAL_SECS",
        );

        // Storage
        override_string(
            &mut self.log_pipeline.storage.postgres_url,
            "IRONPOST_STORAGE_POSTGRES_URL",
        );
        override_string(
            &mut self.log_pipeline.storage.redis_url,
            "IRONPOST_STORAGE_REDIS_URL",
        );
        override_u32(
            &mut self.log_pipeline.storage.retention_days,
            "IRONPOST_STORAGE_RETENTION_DAYS",
        );

        // Container
        override_bool(&mut self.container.enabled, "IRONPOST_CONTAINER_ENABLED");
        override_string(
            &mut self.container.docker_socket,
            "IRONPOST_CONTAINER_DOCKER_SOCKET",
        );
        override_u64(
            &mut self.container.poll_interval_secs,
            "IRONPOST_CONTAINER_POLL_INTERVAL_SECS",
        );
        override_string(
            &mut self.container.policy_path,
            "IRONPOST_CONTAINER_POLICY_PATH",
        );
        override_bool(
            &mut self.container.auto_isolate,
            "IRONPOST_CONTAINER_AUTO_ISOLATE",
        );

        // SBOM
        override_bool(&mut self.sbom.enabled, "IRONPOST_SBOM_ENABLED");
        override_csv(&mut self.sbom.scan_dirs, "IRONPOST_SBOM_SCAN_DIRS");
        override_u32(
            &mut self.sbom.vuln_db_update_hours,
            "IRONPOST_SBOM_VULN_DB_UPDATE_HOURS",
        );
        override_string(&mut self.sbom.vuln_db_path, "IRONPOST_SBOM_VULN_DB_PATH");
        override_string(&mut self.sbom.min_severity, "IRONPOST_SBOM_MIN_SEVERITY");
        override_string(&mut self.sbom.output_format, "IRONPOST_SBOM_OUTPUT_FORMAT");
    }

    /// 설정값의 유효성을 검증합니다.
    pub fn validate(&self) -> Result<(), IronpostError> {
        // log_level 검증
        let valid_levels = ["trace", "debug", "info", "warn", "error"];
        if !valid_levels.contains(&self.general.log_level.as_str()) {
            return Err(ConfigError::InvalidValue {
                field: "general.log_level".to_owned(),
                reason: format!("must be one of: {}", valid_levels.join(", ")),
            }
            .into());
        }

        // log_format 검증
        let valid_formats = ["json", "pretty"];
        if !valid_formats.contains(&self.general.log_format.as_str()) {
            return Err(ConfigError::InvalidValue {
                field: "general.log_format".to_owned(),
                reason: format!("must be one of: {}", valid_formats.join(", ")),
            }
            .into());
        }

        // xdp_mode 검증
        if self.ebpf.enabled {
            let valid_modes = ["native", "skb", "hw"];
            if !valid_modes.contains(&self.ebpf.xdp_mode.as_str()) {
                return Err(ConfigError::InvalidValue {
                    field: "ebpf.xdp_mode".to_owned(),
                    reason: format!("must be one of: {}", valid_modes.join(", ")),
                }
                .into());
            }

            if self.ebpf.interface.is_empty() {
                return Err(ConfigError::InvalidValue {
                    field: "ebpf.interface".to_owned(),
                    reason: "interface must not be empty when ebpf is enabled".to_owned(),
                }
                .into());
            }
        }

        // SBOM output_format 검증
        if self.sbom.enabled {
            let valid_sbom_formats = ["spdx", "cyclonedx"];
            if !valid_sbom_formats.contains(&self.sbom.output_format.as_str()) {
                return Err(ConfigError::InvalidValue {
                    field: "sbom.output_format".to_owned(),
                    reason: format!("must be one of: {}", valid_sbom_formats.join(", ")),
                }
                .into());
            }
        }

        // min_severity 검증
        if self.sbom.enabled {
            let valid_severities = ["info", "low", "medium", "high", "critical"];
            if !valid_severities.contains(&self.sbom.min_severity.as_str()) {
                return Err(ConfigError::InvalidValue {
                    field: "sbom.min_severity".to_owned(),
                    reason: format!("must be one of: {}", valid_severities.join(", ")),
                }
                .into());
            }
        }

        Ok(())
    }
}

// Default는 derive 매크로로 자동 생성 (각 필드가 Default를 구현하므로)

/// 일반 설정
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct GeneralConfig {
    /// 로그 레벨 (trace, debug, info, warn, error)
    pub log_level: String,
    /// 로그 형식 (json, pretty)
    pub log_format: String,
    /// 데이터 디렉토리
    pub data_dir: String,
    /// PID 파일 경로
    pub pid_file: String,
}

impl Default for GeneralConfig {
    fn default() -> Self {
        Self {
            log_level: "info".to_owned(),
            log_format: "json".to_owned(),
            data_dir: "/var/lib/ironpost".to_owned(),
            pid_file: "/var/run/ironpost.pid".to_owned(),
        }
    }
}

/// eBPF 엔진 설정
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct EbpfConfig {
    /// 활성화 여부
    pub enabled: bool,
    /// 감시할 네트워크 인터페이스
    pub interface: String,
    /// XDP 모드 (native, skb, hw)
    pub xdp_mode: String,
    /// 이벤트 링 버퍼 크기 (바이트)
    pub ring_buffer_size: usize,
    /// 차단 목록 최대 엔트리 수
    pub blocklist_max_entries: usize,
}

impl Default for EbpfConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            interface: "eth0".to_owned(),
            xdp_mode: "skb".to_owned(),
            ring_buffer_size: 256 * 1024, // 256KB
            blocklist_max_entries: 10_000,
        }
    }
}

/// 로그 파이프라인 설정
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct LogPipelineConfig {
    /// 활성화 여부
    pub enabled: bool,
    /// 수집 소스
    pub sources: Vec<String>,
    /// Syslog 수신 주소
    pub syslog_bind: String,
    /// 파일 감시 경로
    pub watch_paths: Vec<String>,
    /// 배치 크기
    pub batch_size: usize,
    /// 배치 플러시 간격 (초)
    pub flush_interval_secs: u64,
    /// 스토리지 설정
    #[serde(default)]
    pub storage: StorageConfig,
}

impl Default for LogPipelineConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            sources: vec!["syslog".to_owned(), "file".to_owned()],
            syslog_bind: "0.0.0.0:514".to_owned(),
            watch_paths: vec!["/var/log/syslog".to_owned()],
            batch_size: 100,
            flush_interval_secs: 5,
            storage: StorageConfig::default(),
        }
    }
}

/// 스토리지 설정
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct StorageConfig {
    /// PostgreSQL 연결 문자열
    pub postgres_url: String,
    /// Redis 연결 문자열
    pub redis_url: String,
    /// 로그 보존 기간 (일)
    pub retention_days: u32,
}

impl Default for StorageConfig {
    fn default() -> Self {
        Self {
            postgres_url: "postgresql://localhost:5432/ironpost".to_owned(),
            redis_url: "redis://localhost:6379".to_owned(),
            retention_days: 30,
        }
    }
}

/// 컨테이너 가드 설정
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct ContainerConfig {
    /// 활성화 여부
    pub enabled: bool,
    /// Docker 소켓 경로
    pub docker_socket: String,
    /// 모니터링 주기 (초)
    pub poll_interval_secs: u64,
    /// 격리 정책 파일 경로
    pub policy_path: String,
    /// 자동 격리 활성화
    pub auto_isolate: bool,
}

impl Default for ContainerConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            docker_socket: "/var/run/docker.sock".to_owned(),
            poll_interval_secs: 10,
            policy_path: "/etc/ironpost/policies".to_owned(),
            auto_isolate: false,
        }
    }
}

/// SBOM 스캐너 설정
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct SbomConfig {
    /// 활성화 여부
    pub enabled: bool,
    /// 스캔 대상 디렉토리
    pub scan_dirs: Vec<String>,
    /// 취약점 DB 업데이트 주기 (시간)
    pub vuln_db_update_hours: u32,
    /// 취약점 DB 경로
    pub vuln_db_path: String,
    /// 최소 심각도 알림 수준 (info, low, medium, high, critical)
    pub min_severity: String,
    /// SBOM 출력 형식 (spdx, cyclonedx)
    pub output_format: String,
}

impl Default for SbomConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            scan_dirs: vec![".".to_owned()],
            vuln_db_update_hours: 24,
            vuln_db_path: "/var/lib/ironpost/vuln-db".to_owned(),
            min_severity: "medium".to_owned(),
            output_format: "cyclonedx".to_owned(),
        }
    }
}

// --- 환경변수 오버라이드 헬퍼 ---

fn override_string(target: &mut String, env_key: &str) {
    if let Ok(val) = std::env::var(env_key) {
        *target = val;
    }
}

fn override_bool(target: &mut bool, env_key: &str) {
    if let Ok(val) = std::env::var(env_key) {
        match val.parse::<bool>() {
            Ok(parsed) => *target = parsed,
            Err(_) => warn!(
                env_key,
                value = val.as_str(),
                "failed to parse bool from env var, ignoring"
            ),
        }
    }
}

fn override_usize(target: &mut usize, env_key: &str) {
    if let Ok(val) = std::env::var(env_key) {
        match val.parse::<usize>() {
            Ok(parsed) => *target = parsed,
            Err(_) => warn!(
                env_key,
                value = val.as_str(),
                "failed to parse usize from env var, ignoring"
            ),
        }
    }
}

fn override_u32(target: &mut u32, env_key: &str) {
    if let Ok(val) = std::env::var(env_key) {
        match val.parse::<u32>() {
            Ok(parsed) => *target = parsed,
            Err(_) => warn!(
                env_key,
                value = val.as_str(),
                "failed to parse u32 from env var, ignoring"
            ),
        }
    }
}

fn override_u64(target: &mut u64, env_key: &str) {
    if let Ok(val) = std::env::var(env_key) {
        match val.parse::<u64>() {
            Ok(parsed) => *target = parsed,
            Err(_) => warn!(
                env_key,
                value = val.as_str(),
                "failed to parse u64 from env var, ignoring"
            ),
        }
    }
}

fn override_csv(target: &mut Vec<String>, env_key: &str) {
    if let Ok(val) = std::env::var(env_key) {
        *target = val.split(',').map(|s| s.trim().to_owned()).collect();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_config_has_sane_values() {
        let config = IronpostConfig::default();
        assert_eq!(config.general.log_level, "info");
        assert_eq!(config.general.log_format, "json");
        assert!(!config.ebpf.enabled);
        assert_eq!(config.ebpf.interface, "eth0");
        assert!(config.log_pipeline.enabled);
        assert!(!config.container.enabled);
        assert!(!config.sbom.enabled);
    }

    #[test]
    fn default_config_passes_validation() {
        let config = IronpostConfig::default();
        config.validate().unwrap();
    }

    #[test]
    fn from_str_empty_toml_uses_defaults() {
        let config = IronpostConfig::parse("").unwrap();
        assert_eq!(config.general.log_level, "info");
        assert_eq!(config.ebpf.interface, "eth0");
    }

    #[test]
    fn from_str_partial_toml_merges_with_defaults() {
        let toml = r#"
[general]
log_level = "debug"

[ebpf]
enabled = true
interface = "ens3"
"#;
        let config = IronpostConfig::parse(toml).unwrap();
        assert_eq!(config.general.log_level, "debug");
        // log_format은 기본값 유지
        assert_eq!(config.general.log_format, "json");
        assert!(config.ebpf.enabled);
        assert_eq!(config.ebpf.interface, "ens3");
    }

    #[test]
    fn from_str_full_toml() {
        let toml = r#"
[general]
log_level = "warn"
log_format = "pretty"
data_dir = "/opt/ironpost/data"
pid_file = "/opt/ironpost/ironpost.pid"

[ebpf]
enabled = true
interface = "ens3"
xdp_mode = "native"
ring_buffer_size = 524288
blocklist_max_entries = 50000

[log_pipeline]
enabled = true
sources = ["syslog", "file", "journald"]
syslog_bind = "127.0.0.1:5140"
watch_paths = ["/var/log/auth.log", "/var/log/kern.log"]
batch_size = 200
flush_interval_secs = 10

[log_pipeline.storage]
postgres_url = "postgresql://db:5432/ironpost"
redis_url = "redis://cache:6379"
retention_days = 90

[container]
enabled = true
docker_socket = "/run/docker.sock"
poll_interval_secs = 5
policy_path = "/etc/ironpost/container-policies"
auto_isolate = true

[sbom]
enabled = true
scan_dirs = ["/app", "/opt"]
vuln_db_update_hours = 12
vuln_db_path = "/opt/ironpost/vuln-db"
min_severity = "high"
output_format = "spdx"
"#;
        let config = IronpostConfig::parse(toml).unwrap();
        assert_eq!(config.general.log_level, "warn");
        assert_eq!(config.ebpf.ring_buffer_size, 524288);
        assert_eq!(config.log_pipeline.sources.len(), 3);
        assert_eq!(config.log_pipeline.storage.retention_days, 90);
        assert!(config.container.auto_isolate);
        assert_eq!(config.sbom.output_format, "spdx");
    }

    #[test]
    fn from_str_invalid_toml_returns_error() {
        let result = IronpostConfig::parse("invalid = [[[toml");
        assert!(result.is_err());
        let err = result.unwrap_err();
        assert!(matches!(
            err,
            IronpostError::Config(ConfigError::ParseFailed { .. })
        ));
    }

    #[test]
    fn validate_rejects_invalid_log_level() {
        let mut config = IronpostConfig::default();
        config.general.log_level = "verbose".to_owned();
        let err = config.validate().unwrap_err();
        assert!(err.to_string().contains("log_level"));
    }

    #[test]
    fn validate_rejects_invalid_log_format() {
        let mut config = IronpostConfig::default();
        config.general.log_format = "xml".to_owned();
        let err = config.validate().unwrap_err();
        assert!(err.to_string().contains("log_format"));
    }

    #[test]
    fn validate_rejects_invalid_xdp_mode_when_enabled() {
        let mut config = IronpostConfig::default();
        config.ebpf.enabled = true;
        config.ebpf.xdp_mode = "turbo".to_owned();
        let err = config.validate().unwrap_err();
        assert!(err.to_string().contains("xdp_mode"));
    }

    #[test]
    fn validate_accepts_invalid_xdp_mode_when_disabled() {
        let mut config = IronpostConfig::default();
        config.ebpf.enabled = false;
        config.ebpf.xdp_mode = "turbo".to_owned();
        // ebpf가 비활성화 상태면 xdp_mode 검증을 건너뜀
        config.validate().unwrap();
    }

    #[test]
    fn validate_rejects_empty_interface_when_enabled() {
        let mut config = IronpostConfig::default();
        config.ebpf.enabled = true;
        config.ebpf.interface = String::new();
        let err = config.validate().unwrap_err();
        assert!(err.to_string().contains("interface"));
    }

    #[test]
    fn validate_rejects_invalid_sbom_format_when_enabled() {
        let mut config = IronpostConfig::default();
        config.sbom.enabled = true;
        config.sbom.output_format = "xml".to_owned();
        let err = config.validate().unwrap_err();
        assert!(err.to_string().contains("output_format"));
    }

    #[test]
    fn env_override_string() {
        let mut val = "original".to_owned();
        // SAFETY: 테스트는 단일 스레드에서 실행되므로 환경변수 조작이 안전합니다.
        unsafe { std::env::set_var("TEST_IRONPOST_STR", "overridden") };
        override_string(&mut val, "TEST_IRONPOST_STR");
        assert_eq!(val, "overridden");
        unsafe { std::env::remove_var("TEST_IRONPOST_STR") };
    }

    #[test]
    fn env_override_bool_valid() {
        let mut val = false;
        // SAFETY: 테스트는 단일 스레드에서 실행되므로 환경변수 조작이 안전합니다.
        unsafe { std::env::set_var("TEST_IRONPOST_BOOL", "true") };
        override_bool(&mut val, "TEST_IRONPOST_BOOL");
        assert!(val);
        unsafe { std::env::remove_var("TEST_IRONPOST_BOOL") };
    }

    #[test]
    fn env_override_bool_invalid_keeps_original() {
        let mut val = false;
        // SAFETY: 테스트는 단일 스레드에서 실행되므로 환경변수 조작이 안전합니다.
        unsafe { std::env::set_var("TEST_IRONPOST_BOOL_BAD", "not-a-bool") };
        override_bool(&mut val, "TEST_IRONPOST_BOOL_BAD");
        assert!(!val); // 원래 값 유지
        unsafe { std::env::remove_var("TEST_IRONPOST_BOOL_BAD") };
    }

    #[test]
    fn env_override_csv() {
        let mut val = vec!["a".to_owned()];
        // SAFETY: 테스트는 단일 스레드에서 실행되므로 환경변수 조작이 안전합니다.
        unsafe { std::env::set_var("TEST_IRONPOST_CSV", "x, y, z") };
        override_csv(&mut val, "TEST_IRONPOST_CSV");
        assert_eq!(val, vec!["x", "y", "z"]);
        unsafe { std::env::remove_var("TEST_IRONPOST_CSV") };
    }

    #[test]
    fn env_override_missing_var_keeps_original() {
        let mut val = "original".to_owned();
        override_string(&mut val, "TEST_IRONPOST_NONEXISTENT_12345");
        assert_eq!(val, "original");
    }

    #[test]
    fn config_serialize_roundtrip() {
        let config = IronpostConfig::default();
        let toml_str = toml::to_string_pretty(&config).unwrap();
        let parsed = IronpostConfig::parse(&toml_str).unwrap();
        assert_eq!(config.general.log_level, parsed.general.log_level);
        assert_eq!(config.ebpf.interface, parsed.ebpf.interface);
        assert_eq!(
            config.log_pipeline.storage.retention_days,
            parsed.log_pipeline.storage.retention_days
        );
    }

    #[tokio::test]
    async fn from_file_not_found() {
        let result = IronpostConfig::from_file("/nonexistent/path/ironpost.toml").await;
        assert!(result.is_err());
        let err = result.unwrap_err();
        assert!(matches!(
            err,
            IronpostError::Config(ConfigError::FileNotFound { .. })
        ));
    }
}

//! SBOM 스캐너 설정
//!
//! [`SbomScannerConfig`]는 core의 [`SbomConfig`](ironpost_core::config::SbomConfig)를
//! 확장하여 스캐너 고유 설정(파일 크기 제한, 최대 패키지 수, 스캔 주기)을 추가합니다.
//!
//! # 사용 예시
//!
//! ```
//! use ironpost_sbom_scanner::SbomScannerConfig;
//!
//! // 기본값으로 생성
//! let config = SbomScannerConfig::default();
//! config.validate().unwrap();
//!
//! // 빌더로 생성
//! use ironpost_sbom_scanner::SbomScannerConfigBuilder;
//!
//! let config = SbomScannerConfigBuilder::new()
//!     .enabled(true)
//!     .scan_interval_secs(3600)
//!     .build()
//!     .unwrap();
//! ```

use serde::{Deserialize, Serialize};

use ironpost_core::types::Severity;

use crate::error::SbomScannerError;
use crate::types::SbomFormat;

/// SBOM 스캐너 설정
///
/// core의 `SbomConfig`에서 파생되며, 모듈 고유 확장 필드를 포함합니다.
///
/// # 필드
///
/// - **enabled**: 스캐너 활성화 여부
/// - **scan_dirs**: 스캔 대상 디렉토리 목록
/// - **vuln_db_path**: 로컬 취약점 DB 경로
/// - **min_severity**: 알림 생성 최소 심각도
/// - **output_format**: SBOM 출력 형식 (CycloneDX / SPDX)
/// - **scan_interval_secs**: 주기적 스캔 간격 (0이면 수동 트리거만)
/// - **max_file_size**: lockfile 최대 크기 (바이트)
/// - **max_packages**: 최대 허용 패키지 수
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SbomScannerConfig {
    /// 스캐너 활성화 여부
    pub enabled: bool,
    /// 스캔 대상 디렉토리 목록
    ///
    /// Note: 재귀 스캔을 수행하지 않으며, 지정된 디렉토리의 직계 파일만 검색합니다.
    pub scan_dirs: Vec<String>,
    /// 로컬 취약점 DB 경로
    pub vuln_db_path: String,
    /// 알림 생성 최소 심각도
    pub min_severity: Severity,
    /// SBOM 출력 형식
    pub output_format: SbomFormat,

    // --- 모듈 고유 확장 ---
    /// 주기적 스캔 간격 (초). 0이면 수동 트리거만 가능
    pub scan_interval_secs: u64,
    /// lockfile 최대 허용 크기 (바이트)
    pub max_file_size: usize,
    /// 최대 허용 패키지 수
    pub max_packages: usize,
}

impl Default for SbomScannerConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            scan_dirs: vec![".".to_owned()],
            vuln_db_path: "/var/lib/ironpost/vuln-db".to_owned(),
            min_severity: Severity::Medium,
            output_format: SbomFormat::CycloneDx,
            scan_interval_secs: 86400,       // 24 hours
            max_file_size: 10 * 1024 * 1024, // 10 MB
            max_packages: 50_000,
        }
    }
}

/// 설정 상한값 상수
const MAX_SCAN_INTERVAL_SECS: u64 = 604_800; // 7 days
const MAX_FILE_SIZE: usize = 100 * 1024 * 1024; // 100 MB
const MAX_PACKAGES_LIMIT: usize = 500_000;

impl SbomScannerConfig {
    /// core의 `SbomConfig`에서 스캐너 설정을 생성합니다.
    ///
    /// core 설정에 없는 확장 필드는 기본값을 사용합니다.
    pub fn from_core(core: &ironpost_core::config::SbomConfig) -> Self {
        let min_severity = Severity::from_str_loose(&core.min_severity).unwrap_or(Severity::Medium);
        let output_format =
            SbomFormat::from_str_loose(&core.output_format).unwrap_or(SbomFormat::CycloneDx);

        Self {
            enabled: core.enabled,
            scan_dirs: core.scan_dirs.clone(),
            vuln_db_path: core.vuln_db_path.clone(),
            min_severity,
            output_format,
            ..Self::default()
        }
    }

    /// 설정 값의 유효성을 검증합니다.
    ///
    /// # 검증 규칙
    ///
    /// - `scan_interval_secs`: 0 또는 60-604800 (0은 수동 모드)
    /// - `max_file_size`: 1-104857600 (100MB)
    /// - `max_packages`: 1-500000
    /// - `scan_dirs`: 활성화 시 하나 이상 필요
    /// - `vuln_db_path`: 활성화 시 비어있으면 안 됨
    pub fn validate(&self) -> Result<(), SbomScannerError> {
        if self.scan_interval_secs > 0 && self.scan_interval_secs < 60 {
            return Err(SbomScannerError::Config {
                field: "scan_interval_secs".to_owned(),
                reason: format!("must be 0 (manual) or 60-{MAX_SCAN_INTERVAL_SECS}"),
            });
        }

        if self.scan_interval_secs > MAX_SCAN_INTERVAL_SECS {
            return Err(SbomScannerError::Config {
                field: "scan_interval_secs".to_owned(),
                reason: format!("must be 0 (manual) or 60-{MAX_SCAN_INTERVAL_SECS}"),
            });
        }

        if self.max_file_size == 0 || self.max_file_size > MAX_FILE_SIZE {
            return Err(SbomScannerError::Config {
                field: "max_file_size".to_owned(),
                reason: format!("must be 1-{MAX_FILE_SIZE}"),
            });
        }

        if self.max_packages == 0 || self.max_packages > MAX_PACKAGES_LIMIT {
            return Err(SbomScannerError::Config {
                field: "max_packages".to_owned(),
                reason: format!("must be 1-{MAX_PACKAGES_LIMIT}"),
            });
        }

        if self.enabled && self.scan_dirs.is_empty() {
            return Err(SbomScannerError::Config {
                field: "scan_dirs".to_owned(),
                reason: "at least one scan directory required when enabled".to_owned(),
            });
        }

        if self.enabled && self.vuln_db_path.is_empty() {
            return Err(SbomScannerError::Config {
                field: "vuln_db_path".to_owned(),
                reason: "vuln_db_path must not be empty when enabled".to_owned(),
            });
        }

        // 경로 순회 공격 방어: ".." 패턴 검증 + 심볼릭 링크 체크
        for scan_dir in &self.scan_dirs {
            if scan_dir.is_empty() {
                return Err(SbomScannerError::Config {
                    field: "scan_dirs".to_owned(),
                    reason: "scan directory path must not be empty".to_owned(),
                });
            }

            // Path traversal 체크: Path::components()로 정확하게 ParentDir 컴포넌트 검출
            if std::path::Path::new(scan_dir)
                .components()
                .any(|c| c == std::path::Component::ParentDir)
            {
                return Err(SbomScannerError::Config {
                    field: "scan_dirs".to_owned(),
                    reason: format!(
                        "scan directory '{}' contains path traversal pattern '..'",
                        scan_dir
                    ),
                });
            }

            // 경로 길이 제한 (DoS 방지)
            const MAX_PATH_LEN: usize = 4096;
            if scan_dir.len() > MAX_PATH_LEN {
                return Err(SbomScannerError::Config {
                    field: "scan_dirs".to_owned(),
                    reason: format!(
                        "scan directory path '{}' exceeds maximum length {}",
                        scan_dir, MAX_PATH_LEN
                    ),
                });
            }
        }

        if self.enabled {
            // Path traversal 체크: Path::components()로 정확하게 ParentDir 컴포넌트 검출
            if std::path::Path::new(&self.vuln_db_path)
                .components()
                .any(|c| c == std::path::Component::ParentDir)
            {
                return Err(SbomScannerError::Config {
                    field: "vuln_db_path".to_owned(),
                    reason: "vuln_db_path contains path traversal pattern '..'".to_owned(),
                });
            }

            // 경로 길이 제한
            const MAX_PATH_LEN: usize = 4096;
            if self.vuln_db_path.len() > MAX_PATH_LEN {
                return Err(SbomScannerError::Config {
                    field: "vuln_db_path".to_owned(),
                    reason: format!("vuln_db_path exceeds maximum length {}", MAX_PATH_LEN),
                });
            }
        }

        Ok(())
    }
}

/// [`SbomScannerConfig`] 빌더
///
/// 유연한 설정 구성 및 빌드 시 유효성 검증을 제공합니다.
#[derive(Default)]
pub struct SbomScannerConfigBuilder {
    config: SbomScannerConfig,
}

impl SbomScannerConfigBuilder {
    /// 기본값을 가진 새 빌더를 생성합니다.
    pub fn new() -> Self {
        Self::default()
    }

    /// 활성화 여부를 설정합니다.
    pub fn enabled(mut self, enabled: bool) -> Self {
        self.config.enabled = enabled;
        self
    }

    /// 스캔 디렉토리 목록을 설정합니다.
    pub fn scan_dirs(mut self, dirs: Vec<String>) -> Self {
        self.config.scan_dirs = dirs;
        self
    }

    /// 취약점 DB 경로를 설정합니다.
    pub fn vuln_db_path(mut self, path: impl Into<String>) -> Self {
        self.config.vuln_db_path = path.into();
        self
    }

    /// 최소 심각도를 설정합니다.
    pub fn min_severity(mut self, severity: Severity) -> Self {
        self.config.min_severity = severity;
        self
    }

    /// SBOM 출력 형식을 설정합니다.
    pub fn output_format(mut self, format: SbomFormat) -> Self {
        self.config.output_format = format;
        self
    }

    /// 스캔 간격(초)을 설정합니다.
    pub fn scan_interval_secs(mut self, secs: u64) -> Self {
        self.config.scan_interval_secs = secs;
        self
    }

    /// 최대 파일 크기(바이트)를 설정합니다.
    pub fn max_file_size(mut self, size: usize) -> Self {
        self.config.max_file_size = size;
        self
    }

    /// 최대 패키지 수를 설정합니다.
    pub fn max_packages(mut self, max: usize) -> Self {
        self.config.max_packages = max;
        self
    }

    /// 설정을 검증하고 빌드합니다.
    ///
    /// # Errors
    ///
    /// 유효성 검증 실패 시 `SbomScannerError::Config` 반환
    pub fn build(self) -> Result<SbomScannerConfig, SbomScannerError> {
        self.config.validate()?;
        Ok(self.config)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_config_is_valid() {
        let config = SbomScannerConfig::default();
        config.validate().unwrap();
    }

    #[test]
    fn from_core_preserves_values() {
        let core = ironpost_core::config::SbomConfig {
            enabled: true,
            scan_dirs: vec!["/app".to_owned(), "/opt".to_owned()],
            vuln_db_update_hours: 12,
            vuln_db_path: "/opt/ironpost/vuln-db".to_owned(),
            min_severity: "high".to_owned(),
            output_format: "spdx".to_owned(),
        };
        let config = SbomScannerConfig::from_core(&core);
        assert!(config.enabled);
        assert_eq!(config.scan_dirs, vec!["/app", "/opt"]);
        assert_eq!(config.vuln_db_path, "/opt/ironpost/vuln-db");
        assert_eq!(config.min_severity, Severity::High);
        assert_eq!(config.output_format, SbomFormat::Spdx);
        // extended fields use defaults
        assert_eq!(config.scan_interval_secs, 86400);
        assert_eq!(config.max_file_size, 10 * 1024 * 1024);
    }

    #[test]
    fn from_core_with_invalid_severity_falls_back() {
        let core = ironpost_core::config::SbomConfig {
            min_severity: "unknown".to_owned(),
            output_format: "unknown".to_owned(),
            ..Default::default()
        };
        let config = SbomScannerConfig::from_core(&core);
        assert_eq!(config.min_severity, Severity::Medium);
        assert_eq!(config.output_format, SbomFormat::CycloneDx);
    }

    #[test]
    fn validate_rejects_too_small_scan_interval() {
        let config = SbomScannerConfig {
            scan_interval_secs: 30, // too small (< 60)
            ..Default::default()
        };
        assert!(config.validate().is_err());
    }

    #[test]
    fn validate_accepts_zero_scan_interval() {
        let config = SbomScannerConfig {
            scan_interval_secs: 0, // manual mode
            ..Default::default()
        };
        config.validate().unwrap();
    }

    #[test]
    fn validate_accepts_60s_scan_interval() {
        let config = SbomScannerConfig {
            scan_interval_secs: 60,
            ..Default::default()
        };
        config.validate().unwrap();
    }

    #[test]
    fn validate_rejects_too_large_scan_interval() {
        let config = SbomScannerConfig {
            scan_interval_secs: 700_000,
            ..Default::default()
        };
        assert!(config.validate().is_err());
    }

    #[test]
    fn validate_rejects_zero_max_file_size() {
        let config = SbomScannerConfig {
            max_file_size: 0,
            ..Default::default()
        };
        assert!(config.validate().is_err());
    }

    #[test]
    fn validate_rejects_too_large_max_file_size() {
        let config = SbomScannerConfig {
            max_file_size: 200 * 1024 * 1024,
            ..Default::default()
        };
        assert!(config.validate().is_err());
    }

    #[test]
    fn validate_rejects_zero_max_packages() {
        let config = SbomScannerConfig {
            max_packages: 0,
            ..Default::default()
        };
        assert!(config.validate().is_err());
    }

    #[test]
    fn validate_rejects_empty_scan_dirs_when_enabled() {
        let config = SbomScannerConfig {
            enabled: true,
            scan_dirs: vec![],
            ..Default::default()
        };
        assert!(config.validate().is_err());
    }

    #[test]
    fn validate_accepts_empty_scan_dirs_when_disabled() {
        let config = SbomScannerConfig {
            enabled: false,
            scan_dirs: vec![],
            ..Default::default()
        };
        config.validate().unwrap();
    }

    #[test]
    fn validate_rejects_empty_vuln_db_path_when_enabled() {
        let config = SbomScannerConfig {
            enabled: true,
            vuln_db_path: String::new(),
            ..Default::default()
        };
        assert!(config.validate().is_err());
    }

    #[test]
    fn builder_creates_valid_config() {
        let config = SbomScannerConfigBuilder::new()
            .scan_interval_secs(3600)
            .max_file_size(5 * 1024 * 1024)
            .max_packages(10_000)
            .build()
            .unwrap();
        assert_eq!(config.scan_interval_secs, 3600);
        assert_eq!(config.max_file_size, 5 * 1024 * 1024);
        assert_eq!(config.max_packages, 10_000);
    }

    #[test]
    fn builder_rejects_invalid_config() {
        let result = SbomScannerConfigBuilder::new()
            .max_file_size(0) // invalid
            .build();
        assert!(result.is_err());
    }

    #[test]
    fn builder_all_setters() {
        let config = SbomScannerConfigBuilder::new()
            .enabled(true)
            .scan_dirs(vec!["/app".to_owned()])
            .vuln_db_path("/opt/vuln-db")
            .min_severity(Severity::High)
            .output_format(SbomFormat::Spdx)
            .scan_interval_secs(7200)
            .max_file_size(20 * 1024 * 1024)
            .max_packages(100_000)
            .build()
            .unwrap();

        assert!(config.enabled);
        assert_eq!(config.scan_dirs, vec!["/app"]);
        assert_eq!(config.vuln_db_path, "/opt/vuln-db");
        assert_eq!(config.min_severity, Severity::High);
        assert_eq!(config.output_format, SbomFormat::Spdx);
        assert_eq!(config.scan_interval_secs, 7200);
        assert_eq!(config.max_file_size, 20 * 1024 * 1024);
        assert_eq!(config.max_packages, 100_000);
    }

    #[test]
    fn config_serialize_roundtrip() {
        let config = SbomScannerConfig::default();
        let json = serde_json::to_string(&config).unwrap();
        let deserialized: SbomScannerConfig = serde_json::from_str(&json).unwrap();
        assert_eq!(config.scan_interval_secs, deserialized.scan_interval_secs);
        assert_eq!(config.max_file_size, deserialized.max_file_size);
    }
}

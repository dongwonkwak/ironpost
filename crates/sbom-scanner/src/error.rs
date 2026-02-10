//! SBOM 스캐너 에러 타입
//!
//! [`SbomScannerError`]는 SBOM 스캐너 모듈 내에서 발생할 수 있는 모든 에러를 나타냅니다.
//! `From<SbomScannerError> for IronpostError` 구현을 통해 `?` 연산자로
//! 상위 에러 타입으로 자연스럽게 전파됩니다.
//!
//! # 에러 카테고리
//!
//! - **Lockfile 파싱**: `LockfileParse`
//! - **SBOM 생성**: `SbomGeneration`
//! - **취약점 DB**: `VulnDbLoad`, `VulnDbParse`
//! - **버전 비교**: `VersionParse`
//! - **설정**: `Config`
//! - **채널 통신**: `Channel`
//! - **파일 I/O**: `Io`, `FileTooBig`

use ironpost_core::error::{IronpostError, SbomError};

/// SBOM 스캐너 도메인 에러
///
/// 스캐너 내부의 모든 에러 시나리오를 포함합니다.
///
/// # 에러 변환
///
/// `From<SbomScannerError> for IronpostError` 구현으로
/// `ironpost-daemon`에서 사용하는 최상위 에러 타입으로 자동 변환됩니다.
#[derive(Debug, thiserror::Error)]
pub enum SbomScannerError {
    /// Lockfile 파싱 실패
    #[error("lockfile parse error: {path}: {reason}")]
    LockfileParse {
        /// 파싱 대상 파일 경로
        path: String,
        /// 파싱 실패 사유
        reason: String,
    },

    /// SBOM 문서 생성 실패
    #[error("sbom generation error: {0}")]
    SbomGeneration(String),

    /// 취약점 DB 로딩 실패
    #[error("vulnerability db load error: {path}: {reason}")]
    VulnDbLoad {
        /// DB 파일 경로
        path: String,
        /// 로딩 실패 사유
        reason: String,
    },

    /// 취약점 DB 파싱 실패
    #[error("vulnerability db parse error: {0}")]
    VulnDbParse(String),

    /// 버전 문자열 파싱 실패
    #[error("version parse error: '{version}': {reason}")]
    VersionParse {
        /// 파싱 대상 버전 문자열
        version: String,
        /// 파싱 실패 사유
        reason: String,
    },

    /// 설정 에러
    #[error("config error: {field}: {reason}")]
    Config {
        /// 설정 필드명
        field: String,
        /// 에러 사유
        reason: String,
    },

    /// 채널 통신 에러
    #[error("channel error: {0}")]
    Channel(String),

    /// 파일 I/O 에러
    #[error("io error: {path}: {source}")]
    Io {
        /// 관련 파일 경로
        path: String,
        /// 원본 I/O 에러
        source: std::io::Error,
    },

    /// 파일 크기 초과
    #[error("file too large: {path}: {size} bytes (max: {max})")]
    FileTooBig {
        /// 파일 경로
        path: String,
        /// 실제 파일 크기 (바이트)
        size: usize,
        /// 최대 허용 크기 (바이트)
        max: usize,
    },
}

impl From<SbomScannerError> for IronpostError {
    fn from(err: SbomScannerError) -> Self {
        match err {
            SbomScannerError::LockfileParse { path, reason } => IronpostError::Sbom(
                SbomError::ParseFailed(format!("lockfile parse error: {path}: {reason}")),
            ),
            SbomScannerError::SbomGeneration(msg) => {
                IronpostError::Sbom(SbomError::ScanFailed(msg))
            }
            SbomScannerError::VulnDbLoad { path, reason } => IronpostError::Sbom(
                SbomError::VulnDb(format!("vulnerability db load error: {path}: {reason}")),
            ),
            SbomScannerError::VulnDbParse(msg) => IronpostError::Sbom(SbomError::VulnDb(msg)),
            SbomScannerError::VersionParse { version, reason } => IronpostError::Sbom(
                SbomError::ParseFailed(format!("version parse error: '{version}': {reason}")),
            ),
            SbomScannerError::Config { field, reason } => IronpostError::Sbom(
                SbomError::ScanFailed(format!("config error: {field}: {reason}")),
            ),
            SbomScannerError::Channel(msg) => IronpostError::Sbom(SbomError::ScanFailed(msg)),
            SbomScannerError::Io { path, source } => {
                IronpostError::Sbom(SbomError::ScanFailed(format!("io error: {path}: {source}")))
            }
            SbomScannerError::FileTooBig { path, size, max } => IronpostError::Sbom(
                SbomError::ScanFailed(format!("file too large: {path}: {size} bytes (max: {max})")),
            ),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn lockfile_parse_error_display() {
        let err = SbomScannerError::LockfileParse {
            path: "Cargo.lock".to_owned(),
            reason: "invalid TOML".to_owned(),
        };
        let msg = err.to_string();
        assert!(msg.contains("Cargo.lock"));
        assert!(msg.contains("invalid TOML"));
    }

    #[test]
    fn sbom_generation_error_display() {
        let err = SbomScannerError::SbomGeneration("serialization failed".to_owned());
        assert!(err.to_string().contains("serialization failed"));
    }

    #[test]
    fn vuln_db_load_error_display() {
        let err = SbomScannerError::VulnDbLoad {
            path: "/var/lib/ironpost/vuln-db/cargo.json".to_owned(),
            reason: "file not found".to_owned(),
        };
        let msg = err.to_string();
        assert!(msg.contains("cargo.json"));
        assert!(msg.contains("file not found"));
    }

    #[test]
    fn vuln_db_parse_error_display() {
        let err = SbomScannerError::VulnDbParse("invalid JSON at line 42".to_owned());
        assert!(err.to_string().contains("invalid JSON"));
    }

    #[test]
    fn version_parse_error_display() {
        let err = SbomScannerError::VersionParse {
            version: "not.a.version".to_owned(),
            reason: "unexpected character".to_owned(),
        };
        let msg = err.to_string();
        assert!(msg.contains("not.a.version"));
        assert!(msg.contains("unexpected character"));
    }

    #[test]
    fn config_error_display() {
        let err = SbomScannerError::Config {
            field: "scan_interval_secs".to_owned(),
            reason: "must be greater than 0".to_owned(),
        };
        let msg = err.to_string();
        assert!(msg.contains("scan_interval_secs"));
        assert!(msg.contains("must be greater than 0"));
    }

    #[test]
    fn channel_error_display() {
        let err = SbomScannerError::Channel("receiver dropped".to_owned());
        assert!(err.to_string().contains("receiver dropped"));
    }

    #[test]
    fn io_error_display() {
        let io_err = std::io::Error::new(std::io::ErrorKind::NotFound, "no such file");
        let err = SbomScannerError::Io {
            path: "/tmp/test".to_owned(),
            source: io_err,
        };
        assert!(err.to_string().contains("/tmp/test"));
    }

    #[test]
    fn file_too_big_error_display() {
        let err = SbomScannerError::FileTooBig {
            path: "Cargo.lock".to_owned(),
            size: 20_000_000,
            max: 10_000_000,
        };
        let msg = err.to_string();
        assert!(msg.contains("20000000"));
        assert!(msg.contains("10000000"));
    }

    #[test]
    fn converts_to_ironpost_error_lockfile_parse() {
        let err = SbomScannerError::LockfileParse {
            path: "test".to_owned(),
            reason: "bad".to_owned(),
        };
        let ironpost_err: IronpostError = err.into();
        assert!(matches!(
            ironpost_err,
            IronpostError::Sbom(SbomError::ParseFailed(_))
        ));
    }

    #[test]
    fn converts_to_ironpost_error_vuln_db() {
        let err = SbomScannerError::VulnDbLoad {
            path: "db.json".to_owned(),
            reason: "missing".to_owned(),
        };
        let ironpost_err: IronpostError = err.into();
        assert!(matches!(
            ironpost_err,
            IronpostError::Sbom(SbomError::VulnDb(_))
        ));
    }

    #[test]
    fn converts_to_ironpost_error_generation() {
        let err = SbomScannerError::SbomGeneration("fail".to_owned());
        let ironpost_err: IronpostError = err.into();
        assert!(matches!(
            ironpost_err,
            IronpostError::Sbom(SbomError::ScanFailed(_))
        ));
    }

    #[test]
    fn converts_to_ironpost_error_version() {
        let err = SbomScannerError::VersionParse {
            version: "x".to_owned(),
            reason: "bad".to_owned(),
        };
        let ironpost_err: IronpostError = err.into();
        assert!(matches!(
            ironpost_err,
            IronpostError::Sbom(SbomError::ParseFailed(_))
        ));
    }

    #[test]
    fn converts_to_ironpost_error_channel() {
        let err = SbomScannerError::Channel("dropped".to_owned());
        let ironpost_err: IronpostError = err.into();
        assert!(matches!(
            ironpost_err,
            IronpostError::Sbom(SbomError::ScanFailed(_))
        ));
    }
}

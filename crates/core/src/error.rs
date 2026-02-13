//! 에러 타입 — 도메인별 에러 정의
//!
//! 각 모듈은 자체 에러 타입을 정의하고, `From` 구현을 통해
//! [`IronpostError`]로 변환합니다.

/// Ironpost 최상위 에러 타입
///
/// 모든 도메인 에러를 포함하는 최상위 enum입니다.
/// 각 모듈의 에러는 `From` 변환을 통해 이 타입으로 변환됩니다.
#[derive(Debug, thiserror::Error)]
pub enum IronpostError {
    /// 설정 관련 에러
    #[error("config error: {0}")]
    Config(#[from] ConfigError),

    /// 파이프라인 처리 에러
    #[error("pipeline error: {0}")]
    Pipeline(#[from] PipelineError),

    /// 탐지 엔진 에러
    #[error("detection error: {0}")]
    Detection(#[from] DetectionError),

    /// 파싱 에러
    #[error("parse error: {0}")]
    Parse(#[from] ParseError),

    /// 스토리지 에러
    #[error("storage error: {0}")]
    Storage(#[from] StorageError),

    /// 컨테이너 관련 에러
    #[error("container error: {0}")]
    Container(#[from] ContainerError),

    /// SBOM 관련 에러
    #[error("sbom error: {0}")]
    Sbom(#[from] SbomError),

    /// 플러그인 에러
    #[error("plugin error: {0}")]
    Plugin(#[from] PluginError),

    /// I/O 에러
    #[error("io error: {0}")]
    Io(#[from] std::io::Error),
}

/// 설정 관련 에러
#[derive(Debug, thiserror::Error)]
pub enum ConfigError {
    /// 설정 파일을 찾을 수 없음
    #[error("config file not found: {path}")]
    FileNotFound {
        /// 찾으려 했던 파일 경로
        path: String,
    },

    /// 설정 파싱 실패
    #[error("failed to parse config: {reason}")]
    ParseFailed {
        /// 파싱 실패 사유
        reason: String,
    },

    /// 유효하지 않은 설정 값
    #[error("invalid config value for '{field}': {reason}")]
    InvalidValue {
        /// 설정 필드명
        field: String,
        /// 유효하지 않은 사유
        reason: String,
    },
}

/// 파이프라인 처리 에러
#[derive(Debug, thiserror::Error)]
pub enum PipelineError {
    /// 채널 전송 실패
    #[error("channel send failed: {0}")]
    ChannelSend(String),

    /// 채널 수신 실패
    #[error("channel receive failed: {0}")]
    ChannelRecv(String),

    /// 파이프라인 초기화 실패
    #[error("pipeline init failed: {0}")]
    InitFailed(String),

    /// 파이프라인이 이미 실행 중
    #[error("pipeline already running")]
    AlreadyRunning,

    /// 파이프라인이 실행 중이 아님
    #[error("pipeline not running")]
    NotRunning,
}

/// 탐지 엔진 에러
#[derive(Debug, thiserror::Error)]
pub enum DetectionError {
    /// eBPF 프로그램 로드 실패
    #[error("ebpf load failed: {0}")]
    EbpfLoad(String),

    /// eBPF 맵 접근 실패
    #[error("ebpf map error: {0}")]
    EbpfMap(String),

    /// 탐지 규칙 에러
    #[error("rule error: {0}")]
    Rule(String),
}

/// 파싱 에러
#[derive(Debug, thiserror::Error)]
pub enum ParseError {
    /// 지원하지 않는 형식
    #[error("unsupported format: {0}")]
    UnsupportedFormat(String),

    /// 파싱 실패
    #[error("parse failed at offset {offset}: {reason}")]
    Failed {
        /// 실패 위치 (바이트 오프셋)
        offset: usize,
        /// 실패 사유
        reason: String,
    },

    /// 입력 데이터 초과
    #[error("input too large: {size} bytes (max: {max})")]
    TooLarge {
        /// 입력 크기
        size: usize,
        /// 최대 허용 크기
        max: usize,
    },
}

/// 스토리지 에러
#[derive(Debug, thiserror::Error)]
pub enum StorageError {
    /// 연결 실패
    #[error("connection failed: {0}")]
    Connection(String),

    /// 쿼리 실패
    #[error("query failed: {0}")]
    Query(String),
}

/// 컨테이너 관련 에러
#[derive(Debug, thiserror::Error)]
pub enum ContainerError {
    /// Docker API 호출 실패
    #[error("docker api error: {0}")]
    DockerApi(String),

    /// 컨테이너 격리 실패
    #[error("isolation failed for container '{container_id}': {reason}")]
    IsolationFailed {
        /// 대상 컨테이너 ID
        container_id: String,
        /// 격리 실패 사유
        reason: String,
    },

    /// 정책 위반
    #[error("policy violation: {0}")]
    PolicyViolation(String),

    /// 컨테이너를 찾을 수 없음
    #[error("container not found: {0}")]
    NotFound(String),
}

/// SBOM 관련 에러
#[derive(Debug, thiserror::Error)]
pub enum SbomError {
    /// SBOM 스캔 실패
    #[error("scan failed: {0}")]
    ScanFailed(String),

    /// 취약점 DB 에러
    #[error("vulnerability database error: {0}")]
    VulnDb(String),

    /// 지원하지 않는 SBOM 형식
    #[error("unsupported sbom format: {0}")]
    UnsupportedFormat(String),

    /// SBOM 파싱 실패
    #[error("sbom parse failed: {0}")]
    ParseFailed(String),
}

/// 플러그인 에러
#[derive(Debug, thiserror::Error)]
pub enum PluginError {
    /// 이미 등록된 플러그인
    #[error("plugin already registered: {name}")]
    AlreadyRegistered {
        /// 중복된 플러그인 이름
        name: String,
    },

    /// 플러그인을 찾을 수 없음
    #[error("plugin not found: {name}")]
    NotFound {
        /// 찾으려 했던 플러그인 이름
        name: String,
    },

    /// 잘못된 상태 전환
    #[error("invalid state for plugin '{name}': current={current}, expected={expected}")]
    InvalidState {
        /// 플러그인 이름
        name: String,
        /// 현재 상태
        current: String,
        /// 기대 상태
        expected: String,
    },

    /// 정지 중 에러 발생 (복수 에러)
    #[error("errors stopping plugins: {0}")]
    StopFailed(String),
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn config_error_display() {
        let err = ConfigError::FileNotFound {
            path: "/etc/ironpost.toml".to_owned(),
        };
        assert_eq!(err.to_string(), "config file not found: /etc/ironpost.toml");

        let err = ConfigError::InvalidValue {
            field: "log_level".to_owned(),
            reason: "must be one of: trace, debug, info, warn, error".to_owned(),
        };
        assert!(err.to_string().contains("log_level"));
    }

    #[test]
    fn pipeline_error_display() {
        let err = PipelineError::AlreadyRunning;
        assert_eq!(err.to_string(), "pipeline already running");

        let err = PipelineError::ChannelSend("buffer full".to_owned());
        assert!(err.to_string().contains("buffer full"));
    }

    #[test]
    fn detection_error_display() {
        let err = DetectionError::EbpfLoad("permission denied".to_owned());
        assert!(err.to_string().contains("permission denied"));
    }

    #[test]
    fn parse_error_display() {
        let err = ParseError::TooLarge {
            size: 2048,
            max: 1024,
        };
        assert!(err.to_string().contains("2048"));
        assert!(err.to_string().contains("1024"));
    }

    #[test]
    fn container_error_display() {
        let err = ContainerError::IsolationFailed {
            container_id: "abc123".to_owned(),
            reason: "network disconnect failed".to_owned(),
        };
        assert!(err.to_string().contains("abc123"));
        assert!(err.to_string().contains("network disconnect failed"));
    }

    #[test]
    fn sbom_error_display() {
        let err = SbomError::UnsupportedFormat("unknown-format".to_owned());
        assert!(err.to_string().contains("unknown-format"));
    }

    #[test]
    fn ironpost_error_from_config() {
        let config_err = ConfigError::FileNotFound {
            path: "test.toml".to_owned(),
        };
        let err: IronpostError = config_err.into();
        assert!(matches!(err, IronpostError::Config(_)));
        assert!(err.to_string().contains("test.toml"));
    }

    #[test]
    fn ironpost_error_from_container() {
        let container_err = ContainerError::NotFound("xyz".to_owned());
        let err: IronpostError = container_err.into();
        assert!(matches!(err, IronpostError::Container(_)));
    }

    #[test]
    fn ironpost_error_from_sbom() {
        let sbom_err = SbomError::ScanFailed("timeout".to_owned());
        let err: IronpostError = sbom_err.into();
        assert!(matches!(err, IronpostError::Sbom(_)));
    }

    #[test]
    fn ironpost_error_from_io() {
        let io_err = std::io::Error::new(std::io::ErrorKind::NotFound, "file missing");
        let err: IronpostError = io_err.into();
        assert!(matches!(err, IronpostError::Io(_)));
    }
}

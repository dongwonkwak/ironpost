//! 에러 타입 — 도메인별 에러 정의

/// Ironpost 최상위 에러 타입
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

    /// I/O 에러
    #[error("io error: {0}")]
    Io(#[from] std::io::Error),
}

/// 설정 관련 에러
#[derive(Debug, thiserror::Error)]
pub enum ConfigError {
    /// 설정 파일을 찾을 수 없음
    #[error("config file not found: {path}")]
    FileNotFound { path: String },

    /// 설정 파싱 실패
    #[error("failed to parse config: {reason}")]
    ParseFailed { reason: String },

    /// 유효하지 않은 설정 값
    #[error("invalid config value for '{field}': {reason}")]
    InvalidValue { field: String, reason: String },
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
    Failed { offset: usize, reason: String },

    /// 입력 데이터 초과
    #[error("input too large: {size} bytes (max: {max})")]
    TooLarge { size: usize, max: usize },
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

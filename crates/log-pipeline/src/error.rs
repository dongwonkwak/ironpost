//! 로그 파이프라인 에러 타입
//!
//! [`LogPipelineError`]는 로그 파이프라인 내부에서 발생하는 모든 에러를 표현합니다.
//! `From<LogPipelineError> for IronpostError` 변환이 구현되어 있어
//! 상위 레이어에서 `?` 연산자로 자연스럽게 전파할 수 있습니다.

use ironpost_core::error::{IronpostError, PipelineError};

/// 로그 파이프라인 도메인 에러
///
/// 파싱, 룰 로딩, 수집, 버퍼링, 채널 통신 등 파이프라인 내부의
/// 모든 에러 상황을 포괄합니다.
#[derive(Debug, thiserror::Error)]
pub enum LogPipelineError {
    /// 로그 파싱 실패
    #[error("parse error: {format} at offset {offset}: {reason}")]
    Parse {
        /// 파서 형식 (syslog, json 등)
        format: String,
        /// 실패 위치 (바이트 오프셋)
        offset: usize,
        /// 실패 사유
        reason: String,
    },

    /// 지원하지 않는 로그 형식
    #[error("unsupported log format: {0}")]
    UnsupportedFormat(String),

    /// 룰 파일 로딩 실패
    #[error("rule load error: {path}: {reason}")]
    RuleLoad {
        /// 룰 파일 경로
        path: String,
        /// 로딩 실패 사유
        reason: String,
    },

    /// 룰 유효성 검증 실패
    #[error("rule validation error: rule '{rule_id}': {reason}")]
    RuleValidation {
        /// 문제가 된 룰 ID
        rule_id: String,
        /// 검증 실패 사유
        reason: String,
    },

    /// 룰 매칭 중 에러 (정규식 컴파일 실패 등)
    #[error("rule match error: {0}")]
    RuleMatch(String),

    /// 수집기 에러 (파일 I/O, 네트워크 등)
    #[error("collector error: {source_type}: {reason}")]
    Collector {
        /// 수집 소스 유형 (file, syslog_udp, syslog_tcp 등)
        source_type: String,
        /// 에러 사유
        reason: String,
    },

    /// 버퍼 오버플로우
    #[error("buffer overflow: capacity {capacity}, dropped {dropped} entries")]
    BufferOverflow {
        /// 버퍼 최대 용량
        capacity: usize,
        /// 드롭된 엔트리 수
        dropped: usize,
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

    /// I/O 에러
    #[error("io error: {0}")]
    Io(#[from] std::io::Error),

    /// 정규식 컴파일 에러
    #[error("regex error: {0}")]
    Regex(#[from] regex::Error),
}

impl From<LogPipelineError> for IronpostError {
    fn from(err: LogPipelineError) -> Self {
        IronpostError::Pipeline(PipelineError::InitFailed(err.to_string()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_error_display() {
        let err = LogPipelineError::Parse {
            format: "syslog".to_owned(),
            offset: 42,
            reason: "unexpected character".to_owned(),
        };
        let msg = err.to_string();
        assert!(msg.contains("syslog"));
        assert!(msg.contains("42"));
        assert!(msg.contains("unexpected character"));
    }

    #[test]
    fn rule_load_error_display() {
        let err = LogPipelineError::RuleLoad {
            path: "/etc/ironpost/rules/test.yml".to_owned(),
            reason: "invalid YAML".to_owned(),
        };
        assert!(err.to_string().contains("test.yml"));
    }

    #[test]
    fn converts_to_ironpost_error() {
        let err = LogPipelineError::Channel("receiver closed".to_owned());
        let ironpost_err: IronpostError = err.into();
        assert!(matches!(ironpost_err, IronpostError::Pipeline(_)));
    }

    #[test]
    fn buffer_overflow_display() {
        let err = LogPipelineError::BufferOverflow {
            capacity: 10000,
            dropped: 5,
        };
        let msg = err.to_string();
        assert!(msg.contains("10000"));
        assert!(msg.contains("5"));
    }
}

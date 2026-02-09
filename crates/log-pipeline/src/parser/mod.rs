//! 로그 파싱 모듈 -- Syslog RFC 5424, JSON 등 형식별 파서
//!
//! [`ParserRouter`]는 원시 로그 데이터의 형식을 판별하여 적절한 파서를 선택합니다.
//! 각 파서는 core의 [`LogParser`](ironpost_core::pipeline::LogParser) trait을 구현합니다.
//!
//! # 지원 형식
//! - Syslog RFC 5424 ([`SyslogParser`])
//! - 구조화 JSON ([`JsonLogParser`])
//!
//! # 사용 예시
//! ```ignore
//! use ironpost_log_pipeline::parser::{ParserRouter, SyslogParser, JsonLogParser};
//!
//! let router = ParserRouter::new()
//!     .register(Box::new(SyslogParser::new()))
//!     .register(Box::new(JsonLogParser::default()));
//!
//! let entry = router.parse(b"<34>1 2024-01-15T12:00:00Z host app - - - message")?;
//! ```

pub mod json;
pub mod syslog;

pub use json::JsonLogParser;
pub use syslog::SyslogParser;

use ironpost_core::error::IronpostError;
use ironpost_core::pipeline::LogParser;
use ironpost_core::types::LogEntry;

use crate::error::LogPipelineError;

/// 파서 라우터 -- 로그 형식을 자동 감지하여 적절한 파서를 선택합니다.
///
/// 등록된 파서 목록을 순회하며, 첫 번째로 파싱에 성공한 파서의 결과를 반환합니다.
/// 모든 파서가 실패하면 `UnsupportedFormat` 에러를 반환합니다.
pub struct ParserRouter {
    /// 등록된 파서 목록 (순서대로 시도)
    parsers: Vec<Box<dyn LogParser>>,
}

impl ParserRouter {
    /// 새 파서 라우터를 생성합니다.
    pub fn new() -> Self {
        Self {
            parsers: Vec::new(),
        }
    }

    /// 기본 파서 세트 (Syslog + JSON)로 라우터를 생성합니다.
    pub fn with_defaults() -> Self {
        let mut router = Self::new();
        router.parsers.push(Box::new(SyslogParser::new()));
        router.parsers.push(Box::new(JsonLogParser::default()));
        router
    }

    /// 파서를 등록합니다. 등록 순서대로 시도됩니다.
    pub fn register(mut self, parser: Box<dyn LogParser>) -> Self {
        self.parsers.push(parser);
        self
    }

    /// 원시 로그 데이터를 파싱합니다.
    ///
    /// 등록된 파서를 순서대로 시도하여 첫 번째 성공 결과를 반환합니다.
    /// 모든 파서가 실패하면 마지막 에러를 반환합니다.
    pub fn parse(&self, raw: &[u8]) -> Result<LogEntry, IronpostError> {
        if self.parsers.is_empty() {
            return Err(
                LogPipelineError::UnsupportedFormat("no parsers registered".to_owned()).into(),
            );
        }

        let mut last_error = None;

        for parser in &self.parsers {
            match parser.parse(raw) {
                Ok(entry) => return Ok(entry),
                Err(e) => {
                    last_error = Some(e);
                    continue;
                }
            }
        }

        Err(last_error.unwrap_or_else(|| {
            LogPipelineError::UnsupportedFormat("all parsers failed".to_owned()).into()
        }))
    }

    /// 특정 형식 이름의 파서로 직접 파싱합니다.
    pub fn parse_with(&self, format_name: &str, raw: &[u8]) -> Result<LogEntry, IronpostError> {
        for parser in &self.parsers {
            if parser.format_name() == format_name {
                return parser.parse(raw);
            }
        }
        Err(LogPipelineError::UnsupportedFormat(format_name.to_owned()).into())
    }

    /// 등록된 파서 형식 이름 목록을 반환합니다.
    pub fn registered_formats(&self) -> Vec<&str> {
        self.parsers.iter().map(|p| p.format_name()).collect()
    }
}

impl Default for ParserRouter {
    fn default() -> Self {
        Self::with_defaults()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn empty_router_returns_error() {
        let router = ParserRouter::new();
        let result = router.parse(b"some log data");
        assert!(result.is_err());
    }

    #[test]
    fn with_defaults_has_parsers() {
        let router = ParserRouter::with_defaults();
        let formats = router.registered_formats();
        assert!(formats.contains(&"syslog"));
        assert!(formats.contains(&"json"));
    }

    #[test]
    fn parse_with_unknown_format_returns_error() {
        let router = ParserRouter::with_defaults();
        let result = router.parse_with("xml", b"<root/>");
        assert!(result.is_err());
    }
}

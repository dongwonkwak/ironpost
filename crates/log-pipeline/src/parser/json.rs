//! JSON 로그 파서
//!
//! 구조화된 JSON 형식의 로그를 파싱합니다. 필드 이름 매핑을 통해
//! 다양한 JSON 로그 형식을 지원합니다.
//!
//! # 지원 형식
//! - 평탄(flat) JSON 객체
//! - 중첩(nested) JSON 객체 (dot notation으로 필드 접근)
//!
//! # 사용 예시
//! ```ignore
//! use ironpost_log_pipeline::parser::JsonLogParser;
//! use ironpost_core::pipeline::LogParser;
//!
//! let parser = JsonLogParser::default();
//! let raw = br#"{"timestamp":"2024-01-15T12:00:00Z","host":"web-01","message":"request processed"}"#;
//! let entry = parser.parse(raw)?;
//! assert_eq!(entry.hostname, "web-01");
//! ```

use std::time::SystemTime;

use chrono::DateTime;
use ironpost_core::error::IronpostError;
use ironpost_core::pipeline::LogParser;
use ironpost_core::types::{LogEntry, Severity};

use crate::error::LogPipelineError;

/// JSON 로그 필드 매핑 설정
///
/// JSON 로그의 필드 이름을 `LogEntry` 필드에 매핑합니다.
/// 다양한 로그 라이브러리(serde_json tracing, bunyan, pino 등)가
/// 서로 다른 필드 이름을 사용하므로, 매핑을 통해 통합합니다.
#[derive(Debug, Clone)]
pub struct JsonFieldMapping {
    /// 타임스탬프 필드명 (기본: "timestamp")
    pub timestamp_field: String,
    /// 호스트명 필드명 (기본: "host")
    pub hostname_field: String,
    /// 프로세스명 필드명 (기본: "process")
    pub process_field: String,
    /// 메시지 필드명 (기본: "message")
    pub message_field: String,
    /// 심각도 필드명 (기본: "level")
    pub severity_field: String,
}

impl Default for JsonFieldMapping {
    fn default() -> Self {
        Self {
            timestamp_field: "timestamp".to_owned(),
            hostname_field: "host".to_owned(),
            process_field: "process".to_owned(),
            message_field: "message".to_owned(),
            severity_field: "level".to_owned(),
        }
    }
}

/// JSON 로그 파서
///
/// 구조화된 JSON 로그를 `LogEntry`로 변환합니다.
/// [`JsonFieldMapping`]을 통해 다양한 JSON 로그 형식을 지원합니다.
pub struct JsonLogParser {
    /// 필드 매핑 설정
    mapping: JsonFieldMapping,
    /// 최대 허용 입력 크기 (바이트)
    max_input_size: usize,
}

impl JsonLogParser {
    /// 커스텀 필드 매핑으로 새 파서를 생성합니다.
    pub fn new(mapping: JsonFieldMapping) -> Self {
        Self {
            mapping,
            max_input_size: 1024 * 1024, // 1MB
        }
    }

    /// 최대 입력 크기를 설정합니다.
    pub fn with_max_input_size(mut self, size: usize) -> Self {
        self.max_input_size = size;
        self
    }

    /// JSON 객체에서 문자열 필드를 추출합니다.
    ///
    /// dot notation을 지원합니다 (예: "metadata.host").
    fn extract_string(value: &serde_json::Value, field: &str) -> Option<String> {
        // dot notation 처리
        let parts: Vec<&str> = field.split('.').collect();
        let mut current = value;

        for part in &parts {
            current = current.get(*part)?;
        }

        match current {
            serde_json::Value::String(s) => Some(s.clone()),
            serde_json::Value::Number(n) => Some(n.to_string()),
            serde_json::Value::Bool(b) => Some(b.to_string()),
            _ => None,
        }
    }

    /// JSON 로그 레벨 문자열을 Severity로 변환합니다.
    fn level_to_severity(level: &str) -> Severity {
        match level.to_lowercase().as_str() {
            "trace" | "debug" => Severity::Info,
            "info" | "information" => Severity::Info,
            "warn" | "warning" => Severity::Low,
            "error" | "err" => Severity::Medium,
            "fatal" | "critical" | "crit" | "emergency" | "emerg" => Severity::High,
            _ => Severity::Info,
        }
    }

    /// JSON 바이트를 파싱하여 `LogEntry`를 생성합니다.
    fn parse_json(&self, raw: &[u8]) -> Result<LogEntry, LogPipelineError> {
        if raw.len() > self.max_input_size {
            return Err(LogPipelineError::Parse {
                format: "json".to_owned(),
                offset: 0,
                reason: format!(
                    "input too large: {} bytes (max: {})",
                    raw.len(),
                    self.max_input_size
                ),
            });
        }

        let value: serde_json::Value =
            serde_json::from_slice(raw).map_err(|e| LogPipelineError::Parse {
                format: "json".to_owned(),
                offset: e.column(),
                reason: e.to_string(),
            })?;

        // 최상위가 JSON 객체여야 합니다
        if !value.is_object() {
            return Err(LogPipelineError::Parse {
                format: "json".to_owned(),
                offset: 0,
                reason: "expected JSON object at top level".to_owned(),
            });
        }

        let timestamp_str = Self::extract_string(&value, &self.mapping.timestamp_field);
        let timestamp = if let Some(ts) = timestamp_str {
            Self::parse_timestamp(&ts).unwrap_or_else(|_| SystemTime::now())
        } else {
            SystemTime::now()
        };

        let hostname =
            Self::extract_string(&value, &self.mapping.hostname_field).unwrap_or_default();
        let process = Self::extract_string(&value, &self.mapping.process_field).unwrap_or_default();
        let message = Self::extract_string(&value, &self.mapping.message_field).unwrap_or_default();
        let severity_str =
            Self::extract_string(&value, &self.mapping.severity_field).unwrap_or_default();
        let severity = Self::level_to_severity(&severity_str);

        // 매핑된 필드 이외의 모든 필드를 추가 필드로 수집
        let known_fields = [
            &self.mapping.timestamp_field,
            &self.mapping.hostname_field,
            &self.mapping.process_field,
            &self.mapping.message_field,
            &self.mapping.severity_field,
        ];

        let fields: Vec<(String, String)> = Self::flatten_object(&value, "", &known_fields);

        Ok(LogEntry {
            source: "json".to_owned(),
            timestamp,
            hostname,
            process,
            message,
            severity,
            fields,
        })
    }

    /// JSON 객체를 평탄화하여 dot notation 필드 목록으로 변환합니다.
    ///
    /// 매핑된 필드는 제외합니다.
    fn flatten_object(
        value: &serde_json::Value,
        prefix: &str,
        exclude: &[&String],
    ) -> Vec<(String, String)> {
        let mut fields = Vec::new();

        if let Some(obj) = value.as_object() {
            for (key, val) in obj {
                let field_name = if prefix.is_empty() {
                    key.clone()
                } else {
                    format!("{}.{}", prefix, key)
                };

                // 제외 목록에 있는 최상위 필드는 스킵
                if prefix.is_empty() && exclude.contains(&key) {
                    continue;
                }

                match val {
                    serde_json::Value::Object(_) => {
                        // 재귀적으로 중첩 객체 평탄화
                        fields.extend(Self::flatten_object(val, &field_name, &[]));
                    }
                    serde_json::Value::Array(arr) => {
                        // 배열은 JSON 문자열로 직렬화
                        if let Ok(s) = serde_json::to_string(arr) {
                            fields.push((field_name, s));
                        }
                    }
                    serde_json::Value::Null => {
                        // null 값은 스킵
                    }
                    serde_json::Value::String(s) => {
                        fields.push((field_name, s.clone()));
                    }
                    serde_json::Value::Number(n) => {
                        fields.push((field_name, n.to_string()));
                    }
                    serde_json::Value::Bool(b) => {
                        fields.push((field_name, b.to_string()));
                    }
                }
            }
        }

        fields
    }

    /// 타임스탬프 문자열을 파싱합니다.
    ///
    /// 지원 형식:
    /// - RFC 3339 (ISO 8601): `2024-01-15T12:00:00Z`
    /// - Unix timestamp (초): `1705320000`
    /// - Unix timestamp (밀리초): `1705320000000`
    fn parse_timestamp(timestamp: &str) -> Result<SystemTime, LogPipelineError> {
        // RFC 3339 시도
        if let Ok(dt) = DateTime::parse_from_rfc3339(timestamp) {
            return Ok(SystemTime::from(dt));
        }

        // Unix timestamp (초 또는 밀리초) 시도
        if let Ok(ts_num) = timestamp.parse::<i64>() {
            // 밀리초인지 초인지 판단 (10자리 = 초, 13자리 = 밀리초)
            let ts_secs = if ts_num > 9_999_999_999 {
                // 밀리초
                ts_num / 1000
            } else {
                // 초
                ts_num
            };

            if let Some(dt) = DateTime::from_timestamp(ts_secs, 0) {
                return Ok(SystemTime::from(dt));
            }
        }

        Err(LogPipelineError::Parse {
            format: "json".to_owned(),
            offset: 0,
            reason: format!("invalid timestamp format: '{}'", timestamp),
        })
    }
}

impl Default for JsonLogParser {
    fn default() -> Self {
        Self::new(JsonFieldMapping::default())
    }
}

impl LogParser for JsonLogParser {
    fn format_name(&self) -> &str {
        "json"
    }

    fn parse(&self, raw: &[u8]) -> Result<LogEntry, IronpostError> {
        self.parse_json(raw).map_err(IronpostError::from)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn format_name_is_json() {
        let parser = JsonLogParser::default();
        assert_eq!(parser.format_name(), "json");
    }

    #[test]
    fn parse_basic_json() {
        let parser = JsonLogParser::default();
        let raw =
            br#"{"host":"web-01","process":"nginx","message":"GET /index.html","level":"info"}"#;
        let entry = parser.parse(raw).unwrap();
        assert_eq!(entry.hostname, "web-01");
        assert_eq!(entry.process, "nginx");
        assert_eq!(entry.message, "GET /index.html");
        assert_eq!(entry.severity, Severity::Info);
    }

    #[test]
    fn parse_json_with_extra_fields() {
        let parser = JsonLogParser::default();
        let raw = br#"{"host":"web-01","message":"test","request_id":"abc-123","status":200}"#;
        let entry = parser.parse(raw).unwrap();
        assert!(!entry.fields.is_empty());
        assert!(entry.fields.iter().any(|(k, _)| k == "request_id"));
    }

    #[test]
    fn parse_non_object_fails() {
        let parser = JsonLogParser::default();
        let raw = br#"["not","an","object"]"#;
        assert!(parser.parse(raw).is_err());
    }

    #[test]
    fn parse_invalid_json_fails() {
        let parser = JsonLogParser::default();
        assert!(parser.parse(b"not json at all").is_err());
    }

    #[test]
    fn level_to_severity_mapping() {
        assert_eq!(JsonLogParser::level_to_severity("info"), Severity::Info);
        assert_eq!(JsonLogParser::level_to_severity("warn"), Severity::Low);
        assert_eq!(JsonLogParser::level_to_severity("ERROR"), Severity::Medium);
        assert_eq!(JsonLogParser::level_to_severity("FATAL"), Severity::High);
        assert_eq!(JsonLogParser::level_to_severity("unknown"), Severity::Info);
    }

    #[test]
    fn custom_field_mapping() {
        let mapping = JsonFieldMapping {
            hostname_field: "server".to_owned(),
            message_field: "msg".to_owned(),
            severity_field: "severity".to_owned(),
            ..Default::default()
        };
        let parser = JsonLogParser::new(mapping);
        let raw = br#"{"server":"db-01","msg":"query slow","severity":"warn"}"#;
        let entry = parser.parse(raw).unwrap();
        assert_eq!(entry.hostname, "db-01");
        assert_eq!(entry.message, "query slow");
    }

    #[test]
    fn extract_nested_field() {
        let value: serde_json::Value =
            serde_json::from_str(r#"{"metadata":{"host":"nested-host"},"message":"test"}"#)
                .unwrap();
        let result = JsonLogParser::extract_string(&value, "metadata.host");
        assert_eq!(result, Some("nested-host".to_owned()));
    }

    #[test]
    fn parse_too_large_input_fails() {
        let parser = JsonLogParser::default().with_max_input_size(10);
        let raw = br#"{"message":"this is way too long for the limit"}"#;
        assert!(parser.parse_json(raw).is_err());
    }

    #[test]
    fn parse_timestamp_rfc3339() {
        let ts = JsonLogParser::parse_timestamp("2024-01-15T12:00:00Z").unwrap();
        assert!(ts > SystemTime::UNIX_EPOCH);
    }

    #[test]
    fn parse_timestamp_unix_seconds() {
        let ts = JsonLogParser::parse_timestamp("1705320000").unwrap();
        assert!(ts > SystemTime::UNIX_EPOCH);
    }

    #[test]
    fn parse_timestamp_unix_milliseconds() {
        let ts = JsonLogParser::parse_timestamp("1705320000000").unwrap();
        assert!(ts > SystemTime::UNIX_EPOCH);
    }

    #[test]
    fn parse_timestamp_invalid() {
        let result = JsonLogParser::parse_timestamp("not-a-timestamp");
        assert!(result.is_err());
    }

    #[test]
    fn parse_json_with_timestamp() {
        let parser = JsonLogParser::default();
        let raw = br#"{"timestamp":"2024-01-15T12:00:00Z","host":"web-01","message":"test"}"#;
        let entry = parser.parse(raw).unwrap();
        assert!(entry.timestamp > SystemTime::UNIX_EPOCH);
    }

    #[test]
    fn parse_json_with_unix_timestamp() {
        let parser = JsonLogParser::default();
        let raw = br#"{"timestamp":"1705320000","host":"web-01","message":"test"}"#;
        let entry = parser.parse(raw).unwrap();
        assert!(entry.timestamp > SystemTime::UNIX_EPOCH);
    }

    #[test]
    fn flatten_nested_object() {
        let value: serde_json::Value =
            serde_json::from_str(r#"{"top":"value","nested":{"field1":"a","field2":"b"}}"#)
                .unwrap();
        let fields = JsonLogParser::flatten_object(&value, "", &[]);
        assert!(fields.iter().any(|(k, v)| k == "top" && v == "value"));
        assert!(fields.iter().any(|(k, v)| k == "nested.field1" && v == "a"));
        assert!(fields.iter().any(|(k, v)| k == "nested.field2" && v == "b"));
    }

    #[test]
    fn flatten_deeply_nested() {
        let value: serde_json::Value = serde_json::from_str(r#"{"a":{"b":{"c":"deep"}}}"#).unwrap();
        let fields = JsonLogParser::flatten_object(&value, "", &[]);
        assert!(fields.iter().any(|(k, v)| k == "a.b.c" && v == "deep"));
    }

    #[test]
    fn flatten_with_array() {
        let value: serde_json::Value =
            serde_json::from_str(r#"{"items":[1,2,3],"name":"test"}"#).unwrap();
        let fields = JsonLogParser::flatten_object(&value, "", &[]);
        assert!(fields.iter().any(|(k, _)| k == "items"));
        assert!(fields.iter().any(|(k, v)| k == "name" && v == "test"));
    }

    #[test]
    fn flatten_excludes_known_fields() {
        let value: serde_json::Value =
            serde_json::from_str(r#"{"host":"excluded","custom":"included"}"#).unwrap();
        let exclude = vec!["host".to_owned()];
        let exclude_refs: Vec<&String> = exclude.iter().collect();
        let fields = JsonLogParser::flatten_object(&value, "", &exclude_refs);
        assert!(!fields.iter().any(|(k, _)| k == "host"));
        assert!(fields.iter().any(|(k, _)| k == "custom"));
    }

    #[test]
    fn parse_json_with_null_values() {
        let parser = JsonLogParser::default();
        let raw = br#"{"host":"web-01","message":"test","null_field":null}"#;
        let entry = parser.parse(raw).unwrap();
        // null 필드는 제외되어야 함
        assert!(!entry.fields.iter().any(|(k, _)| k == "null_field"));
    }

    #[test]
    fn parse_json_with_number_field() {
        let parser = JsonLogParser::default();
        let raw = br#"{"host":"web-01","message":"test","count":42,"ratio":3.14}"#;
        let entry = parser.parse(raw).unwrap();
        assert!(entry.fields.iter().any(|(k, v)| k == "count" && v == "42"));
        assert!(
            entry
                .fields
                .iter()
                .any(|(k, v)| k == "ratio" && v == "3.14")
        );
    }

    #[test]
    fn parse_json_with_bool_field() {
        let parser = JsonLogParser::default();
        let raw = br#"{"host":"web-01","message":"test","active":true}"#;
        let entry = parser.parse(raw).unwrap();
        assert!(
            entry
                .fields
                .iter()
                .any(|(k, v)| k == "active" && v == "true")
        );
    }
}

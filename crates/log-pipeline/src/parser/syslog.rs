//! Syslog RFC 5424 파서
//!
//! [RFC 5424](https://tools.ietf.org/html/rfc5424) 형식의 syslog 메시지를 파싱합니다.
//!
//! # RFC 5424 메시지 형식
//! ```text
//! <PRI>VERSION TIMESTAMP HOSTNAME APP-NAME PROCID MSGID STRUCTURED-DATA MSG
//! ```
//!
//! # 사용 예시
//! ```ignore
//! use ironpost_log_pipeline::parser::SyslogParser;
//! use ironpost_core::pipeline::LogParser;
//!
//! let parser = SyslogParser::new();
//! let entry = parser.parse(b"<34>1 2024-01-15T12:00:00Z host sshd 1234 - - Failed password")?;
//! assert_eq!(entry.process, "sshd");
//! ```

use std::time::SystemTime;

use chrono::{DateTime, Datelike, NaiveDateTime, Utc};
use ironpost_core::error::IronpostError;
use ironpost_core::pipeline::LogParser;
use ironpost_core::types::{LogEntry, Severity};

use crate::error::LogPipelineError;

/// Syslog RFC 5424 파서
///
/// core의 [`LogParser`] trait을 구현하여 syslog 메시지를 `LogEntry`로 변환합니다.
///
/// ## 지원 기능
/// - PRI 필드에서 facility/severity 디코딩
/// - RFC 3339 타임스탬프 파싱
/// - Structured Data (SD) 추출
/// - NILVALUE (`-`) 처리
pub struct SyslogParser {
    /// 최대 허용 입력 크기 (바이트)
    max_input_size: usize,
}

impl SyslogParser {
    /// 기본 설정으로 새 파서를 생성합니다.
    pub fn new() -> Self {
        Self {
            max_input_size: 64 * 1024, // 64KB
        }
    }

    /// 최대 입력 크기를 설정합니다.
    pub fn with_max_input_size(mut self, size: usize) -> Self {
        self.max_input_size = size;
        self
    }

    /// PRI 필드에서 syslog severity를 추출하여 Ironpost Severity로 매핑합니다.
    ///
    /// Syslog severity (RFC 5424 Section 6.2.1):
    /// - 0 Emergency -> Critical
    /// - 1 Alert -> Critical
    /// - 2 Critical -> Critical
    /// - 3 Error -> High
    /// - 4 Warning -> Medium
    /// - 5 Notice -> Low
    /// - 6 Informational -> Info
    /// - 7 Debug -> Info
    fn syslog_severity_to_ironpost(syslog_severity: u8) -> Severity {
        match syslog_severity {
            0..=2 => Severity::Critical,
            3 => Severity::High,
            4 => Severity::Medium,
            5 => Severity::Low,
            _ => Severity::Info,
        }
    }

    /// PRI 값에서 facility와 severity를 분리합니다.
    ///
    /// PRI = facility * 8 + severity
    fn decode_pri(pri: u8) -> (u8, u8) {
        let facility = pri / 8;
        let severity = pri % 8;
        (facility, severity)
    }

    /// 원시 syslog 메시지를 파싱합니다.
    ///
    /// 이 메서드는 RFC 5424 형식을 기대하지만, BSD syslog (RFC 3164) 형식도
    /// 최선 노력(best-effort) 방식으로 파싱을 시도합니다.
    fn parse_syslog(&self, raw: &[u8]) -> Result<LogEntry, LogPipelineError> {
        if raw.len() > self.max_input_size {
            return Err(LogPipelineError::Parse {
                format: "syslog".to_owned(),
                offset: 0,
                reason: format!(
                    "input too large: {} bytes (max: {})",
                    raw.len(),
                    self.max_input_size
                ),
            });
        }

        let input = String::from_utf8_lossy(raw);
        let input = input.trim();

        if input.is_empty() {
            return Err(LogPipelineError::Parse {
                format: "syslog".to_owned(),
                offset: 0,
                reason: "empty input".to_owned(),
            });
        }

        // PRI 파싱: <NNN>
        if !input.starts_with('<') {
            return Err(LogPipelineError::Parse {
                format: "syslog".to_owned(),
                offset: 0,
                reason: "missing PRI field (expected '<')".to_owned(),
            });
        }

        let pri_end = input.find('>').ok_or_else(|| LogPipelineError::Parse {
            format: "syslog".to_owned(),
            offset: 0,
            reason: "unterminated PRI field".to_owned(),
        })?;

        let pri_str = &input[1..pri_end];
        let pri: u8 = pri_str.parse().map_err(|_| LogPipelineError::Parse {
            format: "syslog".to_owned(),
            offset: 1,
            reason: format!("invalid PRI value: '{pri_str}'"),
        })?;

        let (facility, syslog_severity) = Self::decode_pri(pri);
        let severity = Self::syslog_severity_to_ironpost(syslog_severity);

        // PRI 이후의 나머지 부분 파싱
        let remainder = &input[pri_end + 1..];

        // VERSION 확인 (RFC 5424: "1 ")
        let (timestamp, hostname, process, message, fields) =
            if let Some(body) = remainder.strip_prefix("1 ") {
                self.parse_rfc5424_body(body, facility)?
            } else {
                // BSD syslog (RFC 3164) fallback
                self.parse_rfc3164_body(remainder, facility)?
            };

        Ok(LogEntry {
            source: "syslog".to_owned(),
            timestamp,
            hostname,
            process,
            message,
            severity,
            fields,
        })
    }

    /// RFC 5424 메시지 본문을 파싱합니다.
    ///
    /// 형식: `TIMESTAMP HOSTNAME APP-NAME PROCID MSGID STRUCTURED-DATA MSG`
    #[allow(clippy::type_complexity)]
    fn parse_rfc5424_body(
        &self,
        body: &str,
        facility: u8,
    ) -> Result<(SystemTime, String, String, String, Vec<(String, String)>), LogPipelineError> {
        // 공백으로 토큰 분리 (최소 5개 토큰: timestamp hostname app procid msgid, 그 다음 SD+MSG)
        let parts: Vec<&str> = body.splitn(6, ' ').collect();

        if parts.len() < 6 {
            return Err(LogPipelineError::Parse {
                format: "syslog".to_owned(),
                offset: 0,
                reason: format!(
                    "RFC 5424 requires at least 6 fields after version, got {}",
                    parts.len()
                ),
            });
        }

        let timestamp_str = Self::nilvalue_to_empty(parts[0]);
        let timestamp = if timestamp_str.is_empty() {
            SystemTime::now()
        } else {
            Self::parse_rfc3339(timestamp_str)?
        };

        let hostname = Self::nilvalue_to_empty(parts[1]).to_owned();
        let app_name = Self::nilvalue_to_empty(parts[2]).to_owned();
        let proc_id = Self::nilvalue_to_empty(parts[3]);
        let msg_id = Self::nilvalue_to_empty(parts[4]);

        let mut fields = vec![("facility".to_owned(), facility.to_string())];

        if !proc_id.is_empty() {
            fields.push(("pid".to_owned(), proc_id.to_owned()));
        }
        if !msg_id.is_empty() {
            fields.push(("msgid".to_owned(), msg_id.to_owned()));
        }

        // Structured Data + Message
        // parts[5] contains SD and the message
        let sd_and_msg = parts[5];
        let (message, sd_fields) = if sd_and_msg.starts_with('[') {
            // Need to find where SD ends and message begins
            // SD can contain multiple elements: [id1 ...][id2 ...]
            let (sd_part, msg_part) = Self::split_sd_and_message(sd_and_msg);
            let sd_fields = Self::parse_structured_data(&sd_part)?;
            (msg_part, sd_fields)
        } else if let Some(msg) = sd_and_msg.strip_prefix("- ") {
            // NILVALUE for SD, rest is message
            (msg.to_owned(), Vec::new())
        } else if sd_and_msg == "-" {
            // NILVALUE for SD, no message
            (String::new(), Vec::new())
        } else {
            // Not SD format, treat as message
            (sd_and_msg.to_owned(), Vec::new())
        };

        fields.extend(sd_fields);

        Ok((timestamp, hostname, app_name, message, fields))
    }

    /// RFC 3164 (BSD syslog) 메시지 본문을 최선 노력으로 파싱합니다.
    ///
    /// 형식: `MMM DD HH:MM:SS hostname tag: message`
    #[allow(clippy::type_complexity)]
    fn parse_rfc3164_body(
        &self,
        body: &str,
        facility: u8,
    ) -> Result<(SystemTime, String, String, String, Vec<(String, String)>), LogPipelineError> {
        // RFC 3164는 구조가 덜 엄격하므로 최선 노력 파싱
        let fields = vec![("facility".to_owned(), facility.to_string())];

        // 타임스탬프 부분 파싱 시도 (MMM DD HH:MM:SS)
        let parts: Vec<&str> = body.splitn(4, ' ').collect();

        if parts.len() >= 4 {
            // parts[0] = MMM, parts[1] = DD, parts[2] = HH:MM:SS, parts[3] = hostname tag: message
            let timestamp_str = format!("{} {} {}", parts[0], parts[1], parts[2]);
            let timestamp =
                Self::parse_bsd_timestamp(&timestamp_str).unwrap_or_else(|_| SystemTime::now());

            // 나머지 파싱
            let remainder = parts[3];
            let remainder_parts: Vec<&str> = remainder.splitn(2, ' ').collect();

            if remainder_parts.len() >= 2 {
                let hostname = remainder_parts[0].to_owned();
                let tag_and_msg = remainder_parts[1];

                // tag는 ':' 앞까지
                if let Some(colon_pos) = tag_and_msg.find(':') {
                    let process = tag_and_msg[..colon_pos].to_owned();
                    let message = if colon_pos + 1 < tag_and_msg.len() {
                        tag_and_msg[colon_pos + 1..].trim_start().to_owned()
                    } else {
                        String::new()
                    };
                    Ok((timestamp, hostname, process, message, fields))
                } else {
                    Ok((
                        timestamp,
                        hostname,
                        String::new(),
                        tag_and_msg.to_owned(),
                        fields,
                    ))
                }
            } else {
                Ok((
                    timestamp,
                    String::new(),
                    String::new(),
                    remainder.to_owned(),
                    fields,
                ))
            }
        } else {
            // 타임스탬프 파싱 실패, 전체를 메시지로
            Ok((
                SystemTime::now(),
                String::new(),
                String::new(),
                body.to_owned(),
                fields,
            ))
        }
    }

    /// NILVALUE (`-`)를 빈 문자열로 변환합니다.
    fn nilvalue_to_empty(value: &str) -> &str {
        if value == "-" { "" } else { value }
    }

    /// RFC 3339 타임스탬프를 파싱합니다.
    ///
    /// 예: `2024-01-15T12:00:00Z` 또는 `2024-01-15T12:00:00.123+09:00`
    fn parse_rfc3339(timestamp: &str) -> Result<SystemTime, LogPipelineError> {
        let dt = DateTime::parse_from_rfc3339(timestamp).map_err(|e| LogPipelineError::Parse {
            format: "syslog".to_owned(),
            offset: 0,
            reason: format!("invalid RFC 3339 timestamp '{}': {}", timestamp, e),
        })?;

        Ok(SystemTime::from(dt))
    }

    /// BSD syslog 타임스탬프를 파싱합니다.
    ///
    /// 형식: `MMM DD HH:MM:SS` (예: `Jan 15 12:00:00`)
    /// 연도 정보가 없으므로 현재 연도를 가정합니다.
    fn parse_bsd_timestamp(timestamp: &str) -> Result<SystemTime, LogPipelineError> {
        let current_year = Utc::now().year();
        let timestamp_with_year = format!("{} {}", current_year, timestamp);

        let dt = NaiveDateTime::parse_from_str(&timestamp_with_year, "%Y %b %d %H:%M:%S").map_err(
            |e| LogPipelineError::Parse {
                format: "syslog".to_owned(),
                offset: 0,
                reason: format!("invalid BSD timestamp '{}': {}", timestamp, e),
            },
        )?;

        let dt_utc = DateTime::<Utc>::from_naive_utc_and_offset(dt, Utc);
        Ok(SystemTime::from(dt_utc))
    }

    /// Structured Data 부분과 메시지 부분을 분리합니다.
    ///
    /// SD는 하나 이상의 `[...]` 블록으로 구성되며, 그 이후가 메시지입니다.
    /// 반환값: (sd_part, message_part)
    fn split_sd_and_message(input: &str) -> (String, String) {
        let mut sd_part = String::new();
        let mut depth = 0;
        let mut in_quote = false;
        let mut escaped = false;

        for (idx, ch) in input.chars().enumerate() {
            if escaped {
                sd_part.push(ch);
                escaped = false;
                continue;
            }

            match ch {
                '\\' if in_quote => {
                    sd_part.push(ch);
                    escaped = true;
                }
                '"' => {
                    sd_part.push(ch);
                    in_quote = !in_quote;
                }
                '[' if !in_quote => {
                    sd_part.push(ch);
                    depth += 1;
                }
                ']' if !in_quote => {
                    sd_part.push(ch);
                    depth -= 1;
                    if depth == 0 {
                        // SD 종료, 나머지는 메시지
                        let remaining = &input[idx + 1..];
                        return (sd_part, remaining.trim_start().to_owned());
                    }
                }
                _ => {
                    sd_part.push(ch);
                }
            }
        }

        // 닫히지 않은 SD가 있으면 전체를 SD로 간주
        (sd_part, String::new())
    }

    /// RFC 5424 Structured Data를 파싱합니다.
    ///
    /// 형식: `[sd-id param1="value1" param2="value2"][sd-id2 ...]`
    /// 추출된 파라미터는 `sd_{id}_{param}` 형식의 키로 반환됩니다.
    fn parse_structured_data(sd: &str) -> Result<Vec<(String, String)>, LogPipelineError> {
        let mut fields = Vec::new();
        let mut chars = sd.chars().peekable();

        while chars.peek().is_some() {
            // '[' 찾기
            if chars.next() != Some('[') {
                break;
            }

            // SD-ID 추출 (']' 또는 ' ' 전까지)
            let mut sd_id = String::new();
            while let Some(&ch) = chars.peek() {
                if ch == ']' || ch == ' ' {
                    break;
                }
                sd_id.push(ch);
                chars.next();
            }

            if sd_id.is_empty() {
                return Err(LogPipelineError::Parse {
                    format: "syslog".to_owned(),
                    offset: 0,
                    reason: "empty SD-ID in structured data".to_owned(),
                });
            }

            // SD-PARAM 파싱 (param="value" 형태)
            while let Some(&ch) = chars.peek() {
                if ch == ']' {
                    chars.next(); // consume ']'
                    break;
                }

                if ch == ' ' {
                    chars.next(); // skip space
                    continue;
                }

                // param name 추출
                let mut param_name = String::new();
                while let Some(&ch) = chars.peek() {
                    if ch == '=' {
                        break;
                    }
                    param_name.push(ch);
                    chars.next();
                }

                if chars.next() != Some('=') {
                    break;
                }

                if chars.next() != Some('"') {
                    return Err(LogPipelineError::Parse {
                        format: "syslog".to_owned(),
                        offset: 0,
                        reason: "SD-PARAM value must be quoted".to_owned(),
                    });
                }

                // value 추출 (closing quote 전까지, escape 처리)
                let mut param_value = String::new();
                let mut escaped = false;
                for ch in chars.by_ref() {
                    if escaped {
                        param_value.push(ch);
                        escaped = false;
                    } else if ch == '\\' {
                        escaped = true;
                    } else if ch == '"' {
                        break;
                    } else {
                        param_value.push(ch);
                    }
                }

                fields.push((format!("sd_{}_{}", sd_id, param_name), param_value));
            }
        }

        Ok(fields)
    }
}

impl Default for SyslogParser {
    fn default() -> Self {
        Self::new()
    }
}

impl LogParser for SyslogParser {
    fn format_name(&self) -> &str {
        "syslog"
    }

    fn parse(&self, raw: &[u8]) -> Result<LogEntry, IronpostError> {
        self.parse_syslog(raw).map_err(IronpostError::from)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn format_name_is_syslog() {
        let parser = SyslogParser::new();
        assert_eq!(parser.format_name(), "syslog");
    }

    #[test]
    fn decode_pri() {
        // facility=4 (auth), severity=2 (critical): 4*8+2 = 34
        let (facility, severity) = SyslogParser::decode_pri(34);
        assert_eq!(facility, 4);
        assert_eq!(severity, 2);
    }

    #[test]
    fn severity_mapping() {
        assert_eq!(
            SyslogParser::syslog_severity_to_ironpost(0),
            Severity::Critical
        );
        assert_eq!(SyslogParser::syslog_severity_to_ironpost(3), Severity::High);
        assert_eq!(
            SyslogParser::syslog_severity_to_ironpost(4),
            Severity::Medium
        );
        assert_eq!(SyslogParser::syslog_severity_to_ironpost(5), Severity::Low);
        assert_eq!(SyslogParser::syslog_severity_to_ironpost(6), Severity::Info);
    }

    #[test]
    fn parse_rfc5424_basic() {
        let parser = SyslogParser::new();
        let raw = b"<34>1 2024-01-15T12:00:00Z myhost sshd 1234 - - Failed password for root";
        let entry = parser.parse(raw).unwrap();
        assert_eq!(entry.hostname, "myhost");
        assert_eq!(entry.process, "sshd");
        assert!(entry.message.contains("Failed password"));
        assert_eq!(entry.severity, Severity::Critical); // pri=34 -> severity=2
    }

    #[test]
    fn parse_empty_input_fails() {
        let parser = SyslogParser::new();
        assert!(parser.parse(b"").is_err());
    }

    #[test]
    fn parse_missing_pri_fails() {
        let parser = SyslogParser::new();
        assert!(parser.parse(b"no pri here").is_err());
    }

    #[test]
    fn parse_too_large_input_fails() {
        let parser = SyslogParser::new().with_max_input_size(10);
        let large_input = b"<34>1 this is a very long syslog message that exceeds the limit";
        assert!(parser.parse_syslog(large_input).is_err());
    }

    #[test]
    fn nilvalue_handling() {
        assert_eq!(SyslogParser::nilvalue_to_empty("-"), "");
        assert_eq!(SyslogParser::nilvalue_to_empty("value"), "value");
    }

    #[test]
    fn parse_rfc3339_timestamp() {
        let ts = SyslogParser::parse_rfc3339("2024-01-15T12:00:00Z").unwrap();
        assert!(ts > SystemTime::UNIX_EPOCH);
    }

    #[test]
    fn parse_rfc3339_with_timezone() {
        let ts = SyslogParser::parse_rfc3339("2024-01-15T12:00:00+09:00").unwrap();
        assert!(ts > SystemTime::UNIX_EPOCH);
    }

    #[test]
    fn parse_rfc3339_with_fractional_seconds() {
        let ts = SyslogParser::parse_rfc3339("2024-01-15T12:00:00.123456Z").unwrap();
        assert!(ts > SystemTime::UNIX_EPOCH);
    }

    #[test]
    fn parse_bsd_timestamp() {
        let ts = SyslogParser::parse_bsd_timestamp("Jan 15 12:00:00").unwrap();
        assert!(ts > SystemTime::UNIX_EPOCH);
    }

    #[test]
    fn parse_bsd_timestamp_december() {
        let ts = SyslogParser::parse_bsd_timestamp("Dec 31 23:59:59").unwrap();
        assert!(ts > SystemTime::UNIX_EPOCH);
    }

    #[test]
    fn parse_structured_data_simple() {
        let sd = "[exampleSDID@32473 eventID=\"1011\"]";
        let fields = SyslogParser::parse_structured_data(sd).unwrap();
        assert_eq!(fields.len(), 1);
        assert_eq!(fields[0].0, "sd_exampleSDID@32473_eventID");
        assert_eq!(fields[0].1, "1011");
    }

    #[test]
    fn parse_structured_data_multiple_params() {
        let sd = "[test@123 foo=\"bar\" baz=\"qux\"]";
        let fields = SyslogParser::parse_structured_data(sd).unwrap();
        assert_eq!(fields.len(), 2);
        assert!(
            fields
                .iter()
                .any(|(k, v)| k == "sd_test@123_foo" && v == "bar")
        );
        assert!(
            fields
                .iter()
                .any(|(k, v)| k == "sd_test@123_baz" && v == "qux")
        );
    }

    #[test]
    fn parse_structured_data_multiple_elements() {
        let sd = "[id1 a=\"1\"][id2 b=\"2\"]";
        let fields = SyslogParser::parse_structured_data(sd).unwrap();
        assert_eq!(fields.len(), 2);
        assert!(fields.iter().any(|(k, _)| k == "sd_id1_a"));
        assert!(fields.iter().any(|(k, _)| k == "sd_id2_b"));
    }

    #[test]
    fn parse_structured_data_with_escaped_quote() {
        let sd = r#"[test a="value with \" quote"]"#;
        let fields = SyslogParser::parse_structured_data(sd).unwrap();
        assert_eq!(fields.len(), 1);
        assert!(fields[0].1.contains('"'));
    }

    #[test]
    fn parse_rfc5424_with_structured_data() {
        let parser = SyslogParser::new();
        let raw =
            b"<34>1 2024-01-15T12:00:00Z host app 1234 ID1 [meta user=\"admin\"] Message text";
        let entry = parser.parse(raw).unwrap();
        assert_eq!(entry.hostname, "host");
        assert_eq!(entry.process, "app");
        assert_eq!(entry.message, "Message text");
        assert!(entry.fields.iter().any(|(k, _)| k == "sd_meta_user"));
    }

    #[test]
    fn parse_rfc5424_nilvalue_fields() {
        let parser = SyslogParser::new();
        let raw = b"<34>1 2024-01-15T12:00:00Z - - - - - Message only";
        let entry = parser.parse(raw).unwrap();
        assert_eq!(entry.hostname, "");
        assert_eq!(entry.process, "");
        assert_eq!(entry.message, "Message only");
    }

    #[test]
    fn parse_rfc3164_basic() {
        let parser = SyslogParser::new();
        let raw = b"<34>Jan 15 12:00:00 myhost sshd: Failed password";
        let entry = parser.parse(raw).unwrap();
        assert_eq!(entry.hostname, "myhost");
        assert_eq!(entry.process, "sshd");
        assert!(entry.message.contains("Failed password"));
    }

    #[test]
    fn parse_rfc3164_with_pid() {
        let parser = SyslogParser::new();
        let raw = b"<34>Jan 15 12:00:00 host sshd[1234]: Connection closed";
        let entry = parser.parse(raw).unwrap();
        assert!(entry.process.contains("sshd"));
    }

    #[test]
    fn parse_invalid_pri_value() {
        let parser = SyslogParser::new();
        let result = parser.parse(b"<999>1 invalid pri");
        assert!(result.is_err());
    }

    #[test]
    fn parse_missing_required_fields() {
        let parser = SyslogParser::new();
        let result = parser.parse(b"<34>1 2024-01-15T12:00:00Z");
        assert!(result.is_err());
    }
}

//! 규칙 매칭 로직 -- 조건 평가 및 정규식 캐싱
//!
//! [`RuleMatcher`]는 규칙의 조건을 `LogEntry`에 대해 평가합니다.
//! 정규식 패턴은 규칙 로딩 시 한 번만 컴파일하여 캐싱합니다.

use std::collections::HashMap;

use regex::Regex;

use ironpost_core::types::LogEntry;

use super::types::{ConditionModifier, DetectionRule, FieldCondition};
use crate::error::LogPipelineError;

/// 규칙 매처 -- 조건 평가 및 정규식 캐싱
///
/// 규칙 로딩 시 정규식을 미리 컴파일하여 매칭 시 재컴파일 오버헤드를 제거합니다.
pub struct RuleMatcher {
    /// 컴파일된 정규식 캐시: (rule_id, condition_index) -> Regex
    regex_cache: HashMap<(String, usize), Regex>,
}

impl RuleMatcher {
    /// 새 매처를 생성합니다.
    pub fn new() -> Self {
        Self {
            regex_cache: HashMap::new(),
        }
    }

    /// 규칙의 정규식 조건을 미리 컴파일합니다.
    ///
    /// 규칙 추가 시 호출하여 정규식 패턴의 유효성을 검증하고 캐싱합니다.
    pub fn compile_rule(&mut self, rule: &DetectionRule) -> Result<(), LogPipelineError> {
        for (idx, condition) in rule.detection.conditions.iter().enumerate() {
            if condition.modifier == ConditionModifier::Regex {
                let regex =
                    Regex::new(&condition.value).map_err(|e| LogPipelineError::RuleValidation {
                        rule_id: rule.id.clone(),
                        reason: format!(
                            "invalid regex in condition[{idx}] for field '{}': {e}",
                            condition.field
                        ),
                    })?;
                self.regex_cache.insert((rule.id.clone(), idx), regex);
            }
        }
        Ok(())
    }

    /// 규칙 제거 시 캐시를 정리합니다.
    pub fn remove_rule(&mut self, rule_id: &str) {
        self.regex_cache.retain(|(id, _), _| id != rule_id);
    }

    /// 규칙의 모든 조건이 LogEntry에 매칭되는지 평가합니다.
    ///
    /// 모든 조건이 AND 결합이므로, 하나라도 실패하면 false를 반환합니다.
    /// 조건이 비어있으면 true를 반환합니다 (모든 로그에 매칭).
    pub fn matches(
        &self,
        rule: &DetectionRule,
        entry: &LogEntry,
    ) -> Result<bool, LogPipelineError> {
        for (idx, condition) in rule.detection.conditions.iter().enumerate() {
            let field_value = Self::get_field_value(entry, &condition.field);

            let matched = match field_value {
                Some(value) => self.evaluate_condition(condition, value, &rule.id, idx)?,
                None => false, // 필드가 없으면 매칭 실패
            };

            if !matched {
                return Ok(false); // AND 로직: 하나라도 실패하면 전체 실패
            }
        }

        Ok(true) // 모든 조건 통과
    }

    /// LogEntry에서 필드 값을 추출합니다.
    fn get_field_value<'a>(entry: &'a LogEntry, field: &str) -> Option<&'a str> {
        match field {
            "hostname" => Some(&entry.hostname),
            "process" => Some(&entry.process),
            "message" => Some(&entry.message),
            "source" => Some(&entry.source),
            _ => {
                // 추가 필드에서 검색
                entry
                    .fields
                    .iter()
                    .find(|(k, _)| k == field)
                    .map(|(_, v)| v.as_str())
            }
        }
    }

    /// 단일 조건을 평가합니다.
    fn evaluate_condition(
        &self,
        condition: &FieldCondition,
        field_value: &str,
        rule_id: &str,
        condition_idx: usize,
    ) -> Result<bool, LogPipelineError> {
        match condition.modifier {
            ConditionModifier::Exact => Ok(field_value == condition.value),

            ConditionModifier::Contains => Ok(field_value.contains(&condition.value)),

            ConditionModifier::StartsWith => Ok(field_value.starts_with(&condition.value)),

            ConditionModifier::EndsWith => Ok(field_value.ends_with(&condition.value)),

            ConditionModifier::Regex => {
                let regex = self
                    .regex_cache
                    .get(&(rule_id.to_owned(), condition_idx))
                    .ok_or_else(|| {
                        LogPipelineError::RuleMatch(format!(
                            "regex not compiled for rule '{rule_id}' condition[{condition_idx}]"
                        ))
                    })?;
                Ok(regex.is_match(field_value))
            }
        }
    }
}

impl Default for RuleMatcher {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::super::types::*;
    use super::*;
    use ironpost_core::types::Severity;
    use std::time::SystemTime;

    fn sample_entry() -> LogEntry {
        LogEntry {
            source: "/var/log/syslog".to_owned(),
            timestamp: SystemTime::now(),
            hostname: "web-server-01".to_owned(),
            process: "sshd".to_owned(),
            message: "Failed password for root from 192.168.1.100 port 22".to_owned(),
            severity: Severity::High,
            fields: vec![
                ("pid".to_owned(), "5678".to_owned()),
                ("source_ip".to_owned(), "192.168.1.100".to_owned()),
            ],
        }
    }

    fn make_rule(conditions: Vec<FieldCondition>) -> DetectionRule {
        DetectionRule {
            id: "test_rule".to_owned(),
            title: "Test".to_owned(),
            description: String::new(),
            severity: Severity::Medium,
            status: RuleStatus::Enabled,
            detection: DetectionCondition {
                conditions,
                threshold: None,
            },
            tags: vec![],
        }
    }

    #[test]
    fn exact_match() {
        let mut matcher = RuleMatcher::new();
        let rule = make_rule(vec![FieldCondition {
            field: "process".to_owned(),
            modifier: ConditionModifier::Exact,
            value: "sshd".to_owned(),
        }]);
        matcher.compile_rule(&rule).unwrap();
        assert!(matcher.matches(&rule, &sample_entry()).unwrap());
    }

    #[test]
    fn exact_match_fails() {
        let mut matcher = RuleMatcher::new();
        let rule = make_rule(vec![FieldCondition {
            field: "process".to_owned(),
            modifier: ConditionModifier::Exact,
            value: "nginx".to_owned(),
        }]);
        matcher.compile_rule(&rule).unwrap();
        assert!(!matcher.matches(&rule, &sample_entry()).unwrap());
    }

    #[test]
    fn contains_match() {
        let mut matcher = RuleMatcher::new();
        let rule = make_rule(vec![FieldCondition {
            field: "message".to_owned(),
            modifier: ConditionModifier::Contains,
            value: "Failed password".to_owned(),
        }]);
        matcher.compile_rule(&rule).unwrap();
        assert!(matcher.matches(&rule, &sample_entry()).unwrap());
    }

    #[test]
    fn starts_with_match() {
        let mut matcher = RuleMatcher::new();
        let rule = make_rule(vec![FieldCondition {
            field: "hostname".to_owned(),
            modifier: ConditionModifier::StartsWith,
            value: "web-".to_owned(),
        }]);
        matcher.compile_rule(&rule).unwrap();
        assert!(matcher.matches(&rule, &sample_entry()).unwrap());
    }

    #[test]
    fn ends_with_match() {
        let mut matcher = RuleMatcher::new();
        let rule = make_rule(vec![FieldCondition {
            field: "source".to_owned(),
            modifier: ConditionModifier::EndsWith,
            value: "syslog".to_owned(),
        }]);
        matcher.compile_rule(&rule).unwrap();
        assert!(matcher.matches(&rule, &sample_entry()).unwrap());
    }

    #[test]
    fn regex_match() {
        let mut matcher = RuleMatcher::new();
        let rule = make_rule(vec![FieldCondition {
            field: "message".to_owned(),
            modifier: ConditionModifier::Regex,
            value: r"Failed.*root.*\d+\.\d+\.\d+\.\d+".to_owned(),
        }]);
        matcher.compile_rule(&rule).unwrap();
        assert!(matcher.matches(&rule, &sample_entry()).unwrap());
    }

    #[test]
    fn invalid_regex_fails_compilation() {
        let mut matcher = RuleMatcher::new();
        let rule = make_rule(vec![FieldCondition {
            field: "message".to_owned(),
            modifier: ConditionModifier::Regex,
            value: r"[invalid".to_owned(),
        }]);
        assert!(matcher.compile_rule(&rule).is_err());
    }

    #[test]
    fn and_logic_all_must_match() {
        let mut matcher = RuleMatcher::new();
        let rule = make_rule(vec![
            FieldCondition {
                field: "process".to_owned(),
                modifier: ConditionModifier::Exact,
                value: "sshd".to_owned(),
            },
            FieldCondition {
                field: "message".to_owned(),
                modifier: ConditionModifier::Contains,
                value: "Failed".to_owned(),
            },
        ]);
        matcher.compile_rule(&rule).unwrap();
        assert!(matcher.matches(&rule, &sample_entry()).unwrap());
    }

    #[test]
    fn and_logic_partial_match_fails() {
        let mut matcher = RuleMatcher::new();
        let rule = make_rule(vec![
            FieldCondition {
                field: "process".to_owned(),
                modifier: ConditionModifier::Exact,
                value: "sshd".to_owned(),
            },
            FieldCondition {
                field: "hostname".to_owned(),
                modifier: ConditionModifier::Exact,
                value: "wrong-host".to_owned(),
            },
        ]);
        matcher.compile_rule(&rule).unwrap();
        assert!(!matcher.matches(&rule, &sample_entry()).unwrap());
    }

    #[test]
    fn empty_conditions_matches_all() {
        let matcher = RuleMatcher::new();
        let rule = make_rule(vec![]);
        assert!(matcher.matches(&rule, &sample_entry()).unwrap());
    }

    #[test]
    fn match_on_extra_fields() {
        let mut matcher = RuleMatcher::new();
        let rule = make_rule(vec![FieldCondition {
            field: "source_ip".to_owned(),
            modifier: ConditionModifier::Exact,
            value: "192.168.1.100".to_owned(),
        }]);
        matcher.compile_rule(&rule).unwrap();
        assert!(matcher.matches(&rule, &sample_entry()).unwrap());
    }

    #[test]
    fn missing_field_does_not_match() {
        let mut matcher = RuleMatcher::new();
        let rule = make_rule(vec![FieldCondition {
            field: "nonexistent_field".to_owned(),
            modifier: ConditionModifier::Exact,
            value: "anything".to_owned(),
        }]);
        matcher.compile_rule(&rule).unwrap();
        assert!(!matcher.matches(&rule, &sample_entry()).unwrap());
    }

    #[test]
    fn remove_rule_cleans_cache() {
        let mut matcher = RuleMatcher::new();
        let rule = make_rule(vec![FieldCondition {
            field: "message".to_owned(),
            modifier: ConditionModifier::Regex,
            value: ".*".to_owned(),
        }]);
        matcher.compile_rule(&rule).unwrap();
        assert!(!matcher.regex_cache.is_empty());

        matcher.remove_rule("test_rule");
        assert!(matcher.regex_cache.is_empty());
    }
}

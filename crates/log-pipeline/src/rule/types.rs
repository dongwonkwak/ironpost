//! 탐지 규칙 데이터 타입
//!
//! YAML 규칙 파일에서 역직렬화되는 구조체들을 정의합니다.

use ironpost_core::types::Severity;
use serde::{Deserialize, Serialize};

use crate::error::LogPipelineError;

/// 탐지 규칙 -- 하나의 YAML 규칙 파일에 대응합니다.
///
/// # YAML 스키마
/// ```yaml
/// id: ssh_brute_force
/// title: SSH Brute Force Attempt
/// description: Detects multiple failed SSH login attempts
/// severity: high
/// status: enabled
/// detection:
///   condition:
///     process: sshd
///     message|contains: "Failed password"
///   threshold:
///     field: source_ip
///     count: 5
///     timeframe: 300
/// tags:
///   - authentication
///   - brute_force
/// ```
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DetectionRule {
    /// 규칙 고유 ID (파일 내에서 유일해야 함)
    pub id: String,
    /// 규칙 제목 (알림에 표시)
    pub title: String,
    /// 규칙 설명
    #[serde(default)]
    pub description: String,
    /// 심각도
    pub severity: Severity,
    /// 규칙 상태
    #[serde(default)]
    pub status: RuleStatus,
    /// 탐지 조건
    pub detection: DetectionCondition,
    /// 분류 태그
    #[serde(default)]
    pub tags: Vec<String>,
}

impl DetectionRule {
    /// 규칙의 유효성을 검증합니다.
    pub fn validate(&self) -> Result<(), LogPipelineError> {
        if self.id.is_empty() {
            return Err(LogPipelineError::RuleValidation {
                rule_id: "(empty)".to_owned(),
                reason: "rule id must not be empty".to_owned(),
            });
        }

        if self.id.len() > 256 {
            return Err(LogPipelineError::RuleValidation {
                rule_id: self.id.clone(),
                reason: "rule id must not exceed 256 characters".to_owned(),
            });
        }

        if self.title.is_empty() {
            return Err(LogPipelineError::RuleValidation {
                rule_id: self.id.clone(),
                reason: "rule title must not be empty".to_owned(),
            });
        }

        if let Some(ref threshold) = self.detection.threshold {
            if threshold.count == 0 {
                return Err(LogPipelineError::RuleValidation {
                    rule_id: self.id.clone(),
                    reason: "threshold count must be greater than 0".to_owned(),
                });
            }
            if threshold.timeframe_secs == 0 {
                return Err(LogPipelineError::RuleValidation {
                    rule_id: self.id.clone(),
                    reason: "threshold timeframe must be greater than 0".to_owned(),
                });
            }
            if threshold.field.is_empty() {
                return Err(LogPipelineError::RuleValidation {
                    rule_id: self.id.clone(),
                    reason: "threshold field must not be empty".to_owned(),
                });
            }
        }

        Ok(())
    }
}

/// 규칙 상태
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum RuleStatus {
    /// 활성화 (기본값)
    #[default]
    Enabled,
    /// 비활성화
    Disabled,
    /// 테스트 모드 (매칭은 수행하지만 알림 생성하지 않음)
    Test,
}

/// 탐지 조건
///
/// `condition`은 AND 로직으로 결합됩니다.
/// 모든 조건이 만족해야 규칙이 매칭됩니다.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DetectionCondition {
    /// 필드 매칭 조건 목록 (AND 결합)
    #[serde(default)]
    pub conditions: Vec<FieldCondition>,
    /// 상관 분석을 위한 threshold 설정
    pub threshold: Option<ThresholdConfig>,
}

/// 필드 매칭 조건
///
/// 하나의 LogEntry 필드에 대한 매칭 조건을 나타냅니다.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FieldCondition {
    /// 대상 필드명 (hostname, process, message, 또는 fields 내의 키)
    pub field: String,
    /// 매칭 수정자
    #[serde(default)]
    pub modifier: ConditionModifier,
    /// 매칭할 값
    pub value: String,
}

/// 조건 수정자 -- 매칭 방식을 결정합니다.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum ConditionModifier {
    /// 정확히 일치
    #[default]
    Exact,
    /// 부분 문자열 포함
    Contains,
    /// 접두사 일치
    StartsWith,
    /// 접미사 일치
    EndsWith,
    /// 정규식 매칭
    Regex,
}

/// Threshold (상관 분석) 설정
///
/// 동일한 그룹 키로 N번 이상 매칭되면 알림을 생성합니다.
/// 예: 같은 IP에서 5분 내 5회 이상 로그인 실패
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ThresholdConfig {
    /// 그룹화 필드명 (예: "source_ip", "hostname")
    pub field: String,
    /// 최소 매칭 횟수
    pub count: u64,
    /// 시간 윈도우 (초)
    pub timeframe_secs: u64,
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_rule() -> DetectionRule {
        DetectionRule {
            id: "test_rule".to_owned(),
            title: "Test Rule".to_owned(),
            description: "A test rule".to_owned(),
            severity: Severity::Medium,
            status: RuleStatus::Enabled,
            detection: DetectionCondition {
                conditions: vec![FieldCondition {
                    field: "process".to_owned(),
                    modifier: ConditionModifier::Exact,
                    value: "sshd".to_owned(),
                }],
                threshold: None,
            },
            tags: vec!["test".to_owned()],
        }
    }

    #[test]
    fn valid_rule_passes_validation() {
        let rule = sample_rule();
        rule.validate().unwrap();
    }

    #[test]
    fn empty_id_fails_validation() {
        let mut rule = sample_rule();
        rule.id = String::new();
        assert!(rule.validate().is_err());
    }

    #[test]
    fn too_long_id_fails_validation() {
        let mut rule = sample_rule();
        rule.id = "x".repeat(300);
        assert!(rule.validate().is_err());
    }

    #[test]
    fn empty_title_fails_validation() {
        let mut rule = sample_rule();
        rule.title = String::new();
        assert!(rule.validate().is_err());
    }

    #[test]
    fn zero_threshold_count_fails() {
        let mut rule = sample_rule();
        rule.detection.threshold = Some(ThresholdConfig {
            field: "source_ip".to_owned(),
            count: 0,
            timeframe_secs: 300,
        });
        assert!(rule.validate().is_err());
    }

    #[test]
    fn zero_threshold_timeframe_fails() {
        let mut rule = sample_rule();
        rule.detection.threshold = Some(ThresholdConfig {
            field: "source_ip".to_owned(),
            count: 5,
            timeframe_secs: 0,
        });
        assert!(rule.validate().is_err());
    }

    #[test]
    fn rule_status_default_is_enabled() {
        assert_eq!(RuleStatus::default(), RuleStatus::Enabled);
    }

    #[test]
    fn condition_modifier_default_is_exact() {
        assert_eq!(ConditionModifier::default(), ConditionModifier::Exact);
    }

    #[test]
    fn rule_serialization_roundtrip() {
        let rule = sample_rule();
        let yaml = serde_yaml::to_string(&rule).unwrap();
        let deserialized: DetectionRule = serde_yaml::from_str(&yaml).unwrap();
        assert_eq!(deserialized.id, rule.id);
        assert_eq!(deserialized.severity, rule.severity);
    }

    #[test]
    fn rule_from_yaml() {
        let yaml = r#"
id: ssh_brute
title: SSH Brute Force
severity: High
detection:
  conditions:
    - field: process
      modifier: exact
      value: sshd
    - field: message
      modifier: contains
      value: "Failed password"
  threshold:
    field: source_ip
    count: 5
    timeframe_secs: 300
tags:
  - authentication
  - ssh
"#;
        let rule: DetectionRule = serde_yaml::from_str(yaml).unwrap();
        assert_eq!(rule.id, "ssh_brute");
        assert_eq!(rule.detection.conditions.len(), 2);
        assert!(rule.detection.threshold.is_some());
        assert_eq!(rule.tags.len(), 2);
    }
}

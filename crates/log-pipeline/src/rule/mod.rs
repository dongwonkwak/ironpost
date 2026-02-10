//! 탐지 규칙 엔진 -- YAML 기반 로그 매칭 및 알림 생성
//!
//! 간소화된 Sigma 스타일의 YAML 규칙을 로드하여
//! [`LogEntry`]에 대한 패턴 매칭을 수행합니다.
//!
//! # 규칙 형식
//! ```yaml
//! id: ssh_brute_force
//! title: SSH Brute Force Attempt
//! severity: high
//! status: enabled
//! detection:
//!   condition:
//!     process: sshd
//!     message|contains: "Failed password"
//!   threshold:
//!     field: source_ip
//!     count: 5
//!     timeframe: 300
//! ```
//!
//! # 아키텍처
//! - [`RuleEngine`]: 규칙 관리 및 매칭 코디네이터
//! - [`loader`]: YAML 파일 로딩 및 유효성 검증
//! - [`matcher`]: 조건 매칭 로직 (exact, contains, regex 등)
//! - [`types`]: 규칙 데이터 구조 정의

pub mod loader;
pub mod matcher;
pub mod types;

pub use loader::RuleLoader;
pub use matcher::RuleMatcher;
pub use types::{
    ConditionModifier, DetectionCondition, DetectionRule, RuleStatus, ThresholdConfig,
};

use std::collections::HashMap;
use std::time::SystemTime;

use ironpost_core::error::IronpostError;
use ironpost_core::types::{Alert, LogEntry};

use crate::error::LogPipelineError;

/// 규칙 매칭 결과
#[derive(Debug, Clone)]
pub struct RuleMatch {
    /// 매칭된 규칙
    pub rule: DetectionRule,
    /// 매칭된 로그 엔트리
    pub entry: LogEntry,
    /// 매칭된 로그 엔트리의 타임스탬프
    pub matched_at: SystemTime,
    /// threshold 규칙인 경우, 매칭된 횟수
    pub match_count: Option<u64>,
}

/// 규칙 엔진 -- 탐지 규칙 관리 및 매칭 코디네이터
///
/// YAML 규칙을 로드하고, `LogEntry`에 대해 모든 활성 규칙을 평가합니다.
/// threshold 기반 규칙은 내부 카운터로 관리합니다.
///
/// # 사용 예시
/// ```ignore
/// let mut engine = RuleEngine::new();
/// engine.load_rules_from_dir("/etc/ironpost/rules").await?;
///
/// let matches = engine.evaluate(&log_entry)?;
/// for m in matches {
///     // Alert 생성
/// }
/// ```
pub struct RuleEngine {
    /// 활성 규칙 목록 (ID -> 규칙)
    rules: HashMap<String, DetectionRule>,
    /// 컴파일된 매처
    matcher: RuleMatcher,
    /// threshold 카운터: (rule_id, group_key) -> (count, window_start)
    threshold_counters: HashMap<(String, String), ThresholdCounter>,
    /// threshold 카운터 최대 항목 수 (메모리 성장 제한)
    max_threshold_entries: usize,
}

/// Threshold 카운터
#[derive(Debug)]
struct ThresholdCounter {
    /// 현재 카운트
    count: u64,
    /// 윈도우 시작 시각
    window_start: SystemTime,
    /// 이 윈도우에서 이미 알림을 생성했는지
    alerted: bool,
}

impl RuleEngine {
    /// 새 규칙 엔진을 생성합니다.
    pub fn new() -> Self {
        Self {
            rules: HashMap::new(),
            matcher: RuleMatcher::new(),
            threshold_counters: HashMap::new(),
            max_threshold_entries: 100_000,
        }
    }

    /// 최대 threshold 항목 수를 설정합니다.
    pub fn with_max_threshold_entries(mut self, max: usize) -> Self {
        self.max_threshold_entries = max;
        self
    }

    /// 디렉토리에서 YAML 규칙 파일을 로드합니다.
    pub async fn load_rules_from_dir(
        &mut self,
        dir: impl AsRef<std::path::Path>,
    ) -> Result<usize, LogPipelineError> {
        let rules = RuleLoader::load_directory(dir).await?;
        let count = rules.len();
        for rule in rules {
            self.add_rule(rule)?;
        }
        Ok(count)
    }

    /// 단일 규칙을 추가합니다.
    pub fn add_rule(&mut self, rule: DetectionRule) -> Result<(), LogPipelineError> {
        rule.validate()?;
        self.matcher.compile_rule(&rule)?;
        self.rules.insert(rule.id.clone(), rule);
        Ok(())
    }

    /// 규칙을 제거합니다.
    pub fn remove_rule(&mut self, rule_id: &str) -> Option<DetectionRule> {
        self.matcher.remove_rule(rule_id);
        // 관련 threshold 카운터도 제거
        self.threshold_counters.retain(|(id, _), _| id != rule_id);
        self.rules.remove(rule_id)
    }

    /// 현재 로드된 규칙 수를 반환합니다.
    pub fn rule_count(&self) -> usize {
        self.rules.len()
    }

    /// 로그 엔트리에 대해 모든 활성 규칙을 평가합니다.
    ///
    /// 매칭된 규칙 목록을 반환합니다.
    /// threshold 규칙은 임계값에 도달한 경우에만 결과에 포함됩니다.
    pub fn evaluate(&mut self, entry: &LogEntry) -> Result<Vec<RuleMatch>, LogPipelineError> {
        let mut matches = Vec::new();

        for rule in self.rules.values() {
            if rule.status != RuleStatus::Enabled {
                continue;
            }

            // 조건 매칭
            if !self.matcher.matches(rule, entry)? {
                continue;
            }

            // threshold 처리
            if let Some(ref threshold) = rule.detection.threshold {
                // 그룹화 필드가 없으면 threshold 카운팅을 건너뜁니다
                let Some(group_key) = Self::extract_group_key(entry, &threshold.field) else {
                    continue;
                };
                let key = (rule.id.clone(), group_key);

                let counter =
                    self.threshold_counters
                        .entry(key)
                        .or_insert_with(|| ThresholdCounter {
                            count: 0,
                            window_start: SystemTime::now(),
                            alerted: false,
                        });

                // 윈도우 만료 체크
                let elapsed = counter.window_start.elapsed().unwrap_or_default().as_secs();

                if elapsed > threshold.timeframe_secs {
                    // 윈도우 리셋
                    counter.count = 0;
                    counter.window_start = SystemTime::now();
                    counter.alerted = false;
                }

                counter.count += 1;

                // 임계값 도달 + 아직 미알림
                if counter.count >= threshold.count && !counter.alerted {
                    counter.alerted = true;
                    matches.push(RuleMatch {
                        rule: rule.clone(),
                        entry: entry.clone(),
                        matched_at: SystemTime::now(),
                        match_count: Some(counter.count),
                    });
                }
            } else {
                // threshold 없는 단순 매칭
                matches.push(RuleMatch {
                    rule: rule.clone(),
                    entry: entry.clone(),
                    matched_at: SystemTime::now(),
                    match_count: None,
                });
            }
        }

        // 메모리 성장 제한
        self.enforce_threshold_limits();

        Ok(matches)
    }

    /// 규칙 매칭 결과를 Alert로 변환합니다.
    pub fn rule_match_to_alert(rule_match: &RuleMatch, _entry: &LogEntry) -> Alert {
        Alert {
            id: uuid::Uuid::new_v4().to_string(),
            title: rule_match.rule.title.clone(),
            description: rule_match.rule.description.clone(),
            severity: rule_match.rule.severity,
            rule_name: rule_match.rule.id.clone(),
            source_ip: None, // TODO: extract from entry fields if available
            target_ip: None,
            created_at: SystemTime::now(),
        }
    }

    /// LogEntry에서 그룹 키를 추출합니다.
    /// 필드가 없으면 None을 반환하여 threshold 카운팅을 건너뜁니다.
    fn extract_group_key(entry: &LogEntry, field: &str) -> Option<String> {
        match field {
            "hostname" => Some(entry.hostname.clone()),
            "process" => Some(entry.process.clone()),
            "source" => Some(entry.source.clone()),
            "message" => Some(entry.message.clone()),
            _ => {
                // fields에서 검색
                entry
                    .fields
                    .iter()
                    .find(|(k, _)| k == field)
                    .map(|(_, v)| v.clone())
            }
        }
    }

    /// threshold 카운터의 메모리 성장을 제한합니다.
    fn enforce_threshold_limits(&mut self) {
        if self.threshold_counters.len() > self.max_threshold_entries {
            // 만료된 엔트리 제거
            let now = SystemTime::now();
            self.threshold_counters.retain(|_, counter| {
                let elapsed = now
                    .duration_since(counter.window_start)
                    .unwrap_or_default()
                    .as_secs();
                elapsed < 3600 // 1시간 이내 엔트리만 유지
            });

            if self.threshold_counters.len() > self.max_threshold_entries {
                tracing::warn!(
                    count = self.threshold_counters.len(),
                    max = self.max_threshold_entries,
                    "threshold counter limit exceeded after cleanup, clearing all"
                );
                self.threshold_counters.clear();
            }
        }
    }
}

impl Default for RuleEngine {
    fn default() -> Self {
        Self::new()
    }
}

/// core의 `Detector` trait을 RuleEngine에 대해 구현합니다.
///
/// 이를 통해 `ironpost-daemon`에서 다른 `Detector` 구현체와
/// 동일한 인터페이스로 사용할 수 있습니다.
impl ironpost_core::pipeline::Detector for RuleEngine {
    fn name(&self) -> &str {
        "log-pipeline-rule-engine"
    }

    fn detect(&self, entry: &LogEntry) -> Result<Option<Alert>, IronpostError> {
        // NOTE: Detector trait은 &self (불변 참조)이므로 threshold 카운터 업데이트 불가.
        // threshold 규칙은 evaluate() (가변 참조)를 통해서만 동작합니다.
        // 여기서는 조건 매칭만 수행합니다.
        for rule in self.rules.values() {
            if rule.status != RuleStatus::Enabled {
                continue;
            }

            if rule.detection.threshold.is_some() {
                // threshold 규칙은 이 인터페이스에서 건너뜁니다
                continue;
            }

            let matched = self.matcher.matches(rule, entry).map_err(|e| {
                IronpostError::Detection(ironpost_core::error::DetectionError::Rule(e.to_string()))
            })?;

            if matched {
                return Ok(Some(Self::rule_match_to_alert(
                    &RuleMatch {
                        rule: rule.clone(),
                        entry: entry.clone(),
                        matched_at: SystemTime::now(),
                        match_count: None,
                    },
                    entry,
                )));
            }
        }

        Ok(None)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ironpost_core::types::Severity;

    fn sample_entry() -> LogEntry {
        LogEntry {
            source: "/var/log/syslog".to_owned(),
            timestamp: SystemTime::now(),
            hostname: "server-01".to_owned(),
            process: "sshd".to_owned(),
            message: "Failed password for root from 192.168.1.100".to_owned(),
            severity: Severity::High,
            fields: vec![
                ("pid".to_owned(), "1234".to_owned()),
                ("source_ip".to_owned(), "192.168.1.100".to_owned()),
            ],
        }
    }

    #[test]
    fn engine_starts_empty() {
        let engine = RuleEngine::new();
        assert_eq!(engine.rule_count(), 0);
    }

    #[test]
    fn add_and_remove_rule() {
        let mut engine = RuleEngine::new();
        let rule = DetectionRule {
            id: "test_rule".to_owned(),
            title: "Test Rule".to_owned(),
            description: "A test rule".to_owned(),
            severity: Severity::Medium,
            status: RuleStatus::Enabled,
            detection: DetectionCondition {
                conditions: vec![],
                threshold: None,
            },
            tags: vec![],
        };
        engine.add_rule(rule).unwrap();
        assert_eq!(engine.rule_count(), 1);

        engine.remove_rule("test_rule");
        assert_eq!(engine.rule_count(), 0);
    }

    #[test]
    fn extract_group_key_from_fields() {
        let entry = sample_entry();
        let key = RuleEngine::extract_group_key(&entry, "source_ip");
        assert_eq!(key, Some("192.168.1.100".to_owned()));
    }

    #[test]
    fn extract_group_key_from_builtin() {
        let entry = sample_entry();
        assert_eq!(
            RuleEngine::extract_group_key(&entry, "hostname"),
            Some("server-01".to_owned())
        );
        assert_eq!(
            RuleEngine::extract_group_key(&entry, "process"),
            Some("sshd".to_owned())
        );
    }

    #[test]
    fn extract_group_key_unknown_returns_none() {
        let entry = sample_entry();
        assert_eq!(RuleEngine::extract_group_key(&entry, "nonexistent"), None);
    }

    #[test]
    fn rule_match_to_alert_creates_alert() {
        let entry = sample_entry();
        let rule_match = RuleMatch {
            rule: DetectionRule {
                id: "test".to_owned(),
                title: "Test Alert".to_owned(),
                description: "Description".to_owned(),
                severity: Severity::High,
                status: RuleStatus::Enabled,
                detection: DetectionCondition {
                    conditions: vec![],
                    threshold: None,
                },
                tags: vec![],
            },
            entry: entry.clone(),
            matched_at: SystemTime::now(),
            match_count: None,
        };

        let alert = RuleEngine::rule_match_to_alert(&rule_match, &entry);
        assert_eq!(alert.title, "Test Alert");
        assert_eq!(alert.severity, Severity::High);
        assert_eq!(alert.rule_name, "test");
    }
}

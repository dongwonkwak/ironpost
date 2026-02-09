//! 알림 생성 및 관리 -- 규칙 매칭 결과를 AlertEvent로 변환합니다.
//!
//! [`AlertGenerator`]는 규칙 매칭 결과를 받아 중복 제거와 속도 제한을 적용한 뒤
//! [`AlertEvent`](ironpost_core::event::AlertEvent)를 생성합니다.

use std::collections::HashMap;
use std::time::{Duration, SystemTime};

use ironpost_core::event::AlertEvent;
use ironpost_core::types::Alert;

use crate::rule::RuleMatch;

/// 알림 생성기
///
/// 규칙 매칭 결과를 `AlertEvent`로 변환하며,
/// 중복 제거와 속도 제한 기능을 제공합니다.
pub struct AlertGenerator {
    /// 중복 제거 윈도우 (초)
    dedup_window: Duration,
    /// 룰당 분당 최대 알림 수
    rate_limit_per_rule: u32,
    /// 중복 제거 추적: rule_id -> 마지막 알림 시각
    dedup_tracker: HashMap<String, SystemTime>,
    /// 속도 제한 추적: rule_id -> (이 분에 생성된 알림 수, 분 시작 시각)
    rate_tracker: HashMap<String, (u32, SystemTime)>,
    /// 생성된 총 알림 수
    total_generated: u64,
    /// 중복 제거로 억제된 알림 수
    dedup_suppressed: u64,
    /// 속도 제한으로 억제된 알림 수
    rate_suppressed: u64,
}

impl AlertGenerator {
    /// 새 알림 생성기를 만듭니다.
    pub fn new(dedup_window_secs: u64, rate_limit_per_rule: u32) -> Self {
        Self {
            dedup_window: Duration::from_secs(dedup_window_secs),
            rate_limit_per_rule,
            dedup_tracker: HashMap::new(),
            rate_tracker: HashMap::new(),
            total_generated: 0,
            dedup_suppressed: 0,
            rate_suppressed: 0,
        }
    }

    /// 규칙 매칭 결과에서 알림을 생성합니다.
    ///
    /// 중복 제거와 속도 제한을 통과한 경우에만 `Some(AlertEvent)`를 반환합니다.
    pub fn generate(
        &mut self,
        rule_match: &RuleMatch,
        trace_id: Option<&str>,
    ) -> Option<AlertEvent> {
        let rule_id = &rule_match.rule.id;

        // 중복 제거 체크
        if self.is_duplicate(rule_id) {
            self.dedup_suppressed += 1;
            tracing::debug!(
                rule_id = %rule_id,
                "alert suppressed by dedup window"
            );
            return None;
        }

        // 속도 제한 체크
        if self.is_rate_limited(rule_id) {
            self.rate_suppressed += 1;
            tracing::debug!(
                rule_id = %rule_id,
                "alert suppressed by rate limit"
            );
            return None;
        }

        // Alert 생성
        let alert = Alert {
            id: uuid::Uuid::new_v4().to_string(),
            title: rule_match.rule.title.clone(),
            description: rule_match.rule.description.clone(),
            severity: rule_match.rule.severity,
            rule_name: rule_match.rule.id.clone(),
            source_ip: None, // TODO: extract from log entry
            target_ip: None,
            created_at: SystemTime::now(),
        };

        let alert_event = match trace_id {
            Some(tid) => AlertEvent::with_trace(alert, rule_match.rule.severity, tid),
            None => AlertEvent::new(alert, rule_match.rule.severity),
        };

        // 추적 정보 업데이트
        self.dedup_tracker
            .insert(rule_id.clone(), SystemTime::now());
        self.update_rate_counter(rule_id);
        self.total_generated += 1;

        Some(alert_event)
    }

    /// 중복 알림인지 확인합니다.
    fn is_duplicate(&self, rule_id: &str) -> bool {
        if let Some(last_time) = self.dedup_tracker.get(rule_id)
            && let Ok(elapsed) = last_time.elapsed()
        {
            return elapsed < self.dedup_window;
        }
        false
    }

    /// 속도 제한에 걸리는지 확인합니다.
    fn is_rate_limited(&self, rule_id: &str) -> bool {
        if let Some((count, minute_start)) = self.rate_tracker.get(rule_id)
            && let Ok(elapsed) = minute_start.elapsed()
            && elapsed < Duration::from_secs(60)
        {
            return *count >= self.rate_limit_per_rule;
        }
        false
    }

    /// 속도 제한 카운터를 업데이트합니다.
    fn update_rate_counter(&mut self, rule_id: &str) {
        let now = SystemTime::now();
        let entry = self
            .rate_tracker
            .entry(rule_id.to_owned())
            .or_insert((0, now));

        if let Ok(elapsed) = entry.1.elapsed()
            && elapsed >= Duration::from_secs(60)
        {
            // 새로운 분 시작
            *entry = (1, now);
            return;
        }

        entry.0 += 1;
    }

    /// 만료된 추적 데이터를 정리합니다.
    ///
    /// 주기적으로 호출하여 메모리 성장을 방지합니다.
    pub fn cleanup_expired(&mut self) {
        self.dedup_tracker.retain(|_, last_time| {
            last_time
                .elapsed()
                .map(|e| e < self.dedup_window * 2)
                .unwrap_or(false)
        });

        self.rate_tracker.retain(|_, (_, minute_start)| {
            minute_start
                .elapsed()
                .map(|e| e < Duration::from_secs(120))
                .unwrap_or(false)
        });
    }

    /// 생성된 총 알림 수를 반환합니다.
    pub fn total_generated(&self) -> u64 {
        self.total_generated
    }

    /// 중복 제거로 억제된 알림 수를 반환합니다.
    pub fn dedup_suppressed(&self) -> u64 {
        self.dedup_suppressed
    }

    /// 속도 제한으로 억제된 알림 수를 반환합니다.
    pub fn rate_suppressed(&self) -> u64 {
        self.rate_suppressed
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::rule::types::*;
    use ironpost_core::types::Severity;

    fn sample_rule_match() -> RuleMatch {
        RuleMatch {
            rule: DetectionRule {
                id: "test_rule".to_owned(),
                title: "Test Alert".to_owned(),
                description: "Test description".to_owned(),
                severity: Severity::High,
                status: RuleStatus::Enabled,
                detection: DetectionCondition {
                    conditions: vec![],
                    threshold: None,
                },
                tags: vec![],
            },
            matched_at: SystemTime::now(),
            match_count: None,
        }
    }

    #[test]
    fn generates_alert_on_first_match() {
        let mut generator = AlertGenerator::new(60, 10);
        let rule_match = sample_rule_match();
        let alert = generator.generate(&rule_match, None);
        assert!(alert.is_some());
        assert_eq!(generator.total_generated(), 1);
    }

    #[test]
    fn dedup_suppresses_second_alert() {
        let mut generator = AlertGenerator::new(60, 10);
        let rule_match = sample_rule_match();

        let first = generator.generate(&rule_match, None);
        assert!(first.is_some());

        let second = generator.generate(&rule_match, None);
        assert!(second.is_none());
        assert_eq!(generator.dedup_suppressed(), 1);
    }

    #[test]
    fn preserves_trace_id() {
        let mut generator = AlertGenerator::new(0, 100); // dedup window = 0 to disable
        let rule_match = sample_rule_match();
        let alert = generator
            .generate(&rule_match, Some("trace-abc-123"))
            .unwrap();
        assert_eq!(alert.metadata.trace_id, "trace-abc-123");
    }

    #[test]
    fn rate_limit_enforced() {
        let mut generator = AlertGenerator::new(0, 2); // dedup=0 (disabled), rate=2/min
        let rule_match = sample_rule_match();

        assert!(generator.generate(&rule_match, None).is_some()); // 1
        assert!(generator.generate(&rule_match, None).is_some()); // 2
        assert!(generator.generate(&rule_match, None).is_none()); // rate limited
        assert_eq!(generator.rate_suppressed(), 1);
    }

    #[test]
    fn cleanup_does_not_panic() {
        let mut generator = AlertGenerator::new(60, 10);
        let rule_match = sample_rule_match();
        generator.generate(&rule_match, None);
        generator.cleanup_expired(); // should not panic
    }

    #[test]
    fn different_rules_tracked_independently() {
        let mut generator = AlertGenerator::new(60, 10);

        let mut match1 = sample_rule_match();
        match1.rule.id = "rule_a".to_owned();

        let mut match2 = sample_rule_match();
        match2.rule.id = "rule_b".to_owned();

        assert!(generator.generate(&match1, None).is_some());
        assert!(generator.generate(&match2, None).is_some());
        assert_eq!(generator.total_generated(), 2);

        // Duplicate of rule_a is suppressed, but rule_b is independent
        assert!(generator.generate(&match1, None).is_none());
        assert!(generator.generate(&match2, None).is_none());
    }
}

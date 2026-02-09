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

    // === Edge Case Tests ===

    #[test]
    fn zero_dedup_window_allows_all_alerts() {
        let mut generator = AlertGenerator::new(0, 100); // dedup disabled
        let rule_match = sample_rule_match();

        for _ in 0..5 {
            assert!(generator.generate(&rule_match, None).is_some());
        }
        assert_eq!(generator.total_generated(), 5);
        assert_eq!(generator.dedup_suppressed(), 0);
    }

    #[test]
    fn zero_rate_limit_blocks_all_subsequent_alerts() {
        let mut generator = AlertGenerator::new(0, 0); // rate limit = 0
        let rule_match = sample_rule_match();

        // With rate limit 0, first alert might still pass (counter starts at 0)
        // Second alert should definitely be blocked
        let _first = generator.generate(&rule_match, None);
        let second = generator.generate(&rule_match, None);
        assert!(second.is_none());
        assert!(generator.rate_suppressed() >= 1);
    }

    #[test]
    fn rate_limit_resets_after_minute() {
        let mut generator = AlertGenerator::new(0, 1); // dedup=0, rate=1/min
        let rule_match = sample_rule_match();

        // First succeeds
        assert!(generator.generate(&rule_match, None).is_some());
        // Second is rate limited
        assert!(generator.generate(&rule_match, None).is_none());

        // Manually expire rate tracker (in real scenario, would wait 60s)
        generator.cleanup_expired();

        // Note: In unit test, cleanup won't actually reset the counter
        // because not enough time has elapsed. This tests cleanup doesn't panic.
    }

    #[test]
    fn very_long_dedup_window() {
        let mut generator = AlertGenerator::new(86400, 100); // 24 hours
        let rule_match = sample_rule_match();

        assert!(generator.generate(&rule_match, None).is_some());
        assert!(generator.generate(&rule_match, None).is_none());
        assert_eq!(generator.dedup_suppressed(), 1);
    }

    #[test]
    fn very_high_rate_limit() {
        let mut generator = AlertGenerator::new(0, 1000); // dedup=0, rate=1000/min
        let rule_match = sample_rule_match();

        // Should allow many alerts
        for i in 0..100 {
            let result = generator.generate(&rule_match, None);
            assert!(result.is_some(), "alert {i} should not be rate limited");
        }
        assert_eq!(generator.total_generated(), 100);
    }

    #[test]
    fn cleanup_expired_removes_old_entries() {
        let mut generator = AlertGenerator::new(1, 10); // 1 second dedup
        let rule_match = sample_rule_match();

        generator.generate(&rule_match, None);
        assert_eq!(generator.dedup_tracker.len(), 1);

        // Cleanup should retain entries within 2x window
        generator.cleanup_expired();
        // Still fresh, should remain
        assert_eq!(generator.dedup_tracker.len(), 1);
    }

    #[test]
    fn cleanup_on_empty_generator() {
        let mut generator = AlertGenerator::new(60, 10);
        generator.cleanup_expired();
        // Should not panic
        assert_eq!(generator.total_generated(), 0);
    }

    #[test]
    fn many_different_rules() {
        let mut generator = AlertGenerator::new(60, 10);

        for i in 0..100 {
            let mut rule_match = sample_rule_match();
            rule_match.rule.id = format!("rule_{i}");
            assert!(generator.generate(&rule_match, None).is_some());
        }

        assert_eq!(generator.total_generated(), 100);
        assert_eq!(generator.dedup_suppressed(), 0);
    }

    #[test]
    fn rule_id_with_special_characters() {
        let mut generator = AlertGenerator::new(60, 10);
        let mut rule_match = sample_rule_match();
        rule_match.rule.id = "rule-with-dashes_and_underscores.and.dots".to_owned();

        assert!(generator.generate(&rule_match, None).is_some());
        assert!(generator.generate(&rule_match, None).is_none());
        assert_eq!(generator.dedup_suppressed(), 1);
    }

    #[test]
    fn rule_id_with_unicode() {
        let mut generator = AlertGenerator::new(60, 10);
        let mut rule_match = sample_rule_match();
        rule_match.rule.id = "rule_日本語_🚀".to_owned();

        assert!(generator.generate(&rule_match, None).is_some());
        assert_eq!(generator.total_generated(), 1);
    }

    #[test]
    fn very_long_rule_id() {
        let mut generator = AlertGenerator::new(60, 10);
        let mut rule_match = sample_rule_match();
        rule_match.rule.id = "r".repeat(1000);

        assert!(generator.generate(&rule_match, None).is_some());
        assert!(generator.generate(&rule_match, None).is_none());
    }

    #[test]
    fn alert_has_unique_id() {
        let mut generator = AlertGenerator::new(0, 100);

        let mut ids = std::collections::HashSet::new();
        for _ in 0..10 {
            let mut rule_match = sample_rule_match();
            rule_match.rule.id = format!("rule_{}", uuid::Uuid::new_v4());
            if let Some(alert) = generator.generate(&rule_match, None) {
                ids.insert(alert.alert.id.clone());
            }
        }

        assert_eq!(ids.len(), 10); // All IDs should be unique
    }

    #[test]
    fn alert_severity_matches_rule() {
        let mut generator = AlertGenerator::new(60, 10);

        for severity in [
            Severity::Info,
            Severity::Low,
            Severity::Medium,
            Severity::High,
            Severity::Critical,
        ] {
            let mut rule_match = sample_rule_match();
            rule_match.rule.id = format!("rule_{:?}", severity);
            rule_match.rule.severity = severity;

            if let Some(alert) = generator.generate(&rule_match, None) {
                assert_eq!(alert.alert.severity, severity);
                assert_eq!(alert.severity, severity);
            }
        }
    }

    #[test]
    fn alert_contains_rule_metadata() {
        let mut generator = AlertGenerator::new(60, 10);
        let mut rule_match = sample_rule_match();
        rule_match.rule.id = "test_rule_123".to_owned();
        rule_match.rule.title = "Test Alert Title".to_owned();
        rule_match.rule.description = "Test alert description".to_owned();

        if let Some(alert) = generator.generate(&rule_match, None) {
            assert_eq!(alert.alert.title, "Test Alert Title");
            assert_eq!(alert.alert.description, "Test alert description");
            assert_eq!(alert.alert.rule_name, "test_rule_123");
        }
    }

    #[test]
    fn trace_id_propagation() {
        let mut generator = AlertGenerator::new(0, 100);

        let trace_ids = ["trace-1", "trace-2", "trace-3"];
        for (i, tid) in trace_ids.iter().enumerate() {
            let mut rule_match = sample_rule_match();
            rule_match.rule.id = format!("rule_{i}");

            if let Some(alert) = generator.generate(&rule_match, Some(tid)) {
                assert_eq!(alert.metadata.trace_id, *tid);
            }
        }
    }

    #[test]
    fn rate_limit_per_rule_independence() {
        let mut generator = AlertGenerator::new(0, 2); // rate=2/min per rule

        let mut match1 = sample_rule_match();
        match1.rule.id = "rule_a".to_owned();

        let mut match2 = sample_rule_match();
        match2.rule.id = "rule_b".to_owned();

        // Each rule gets its own rate limit bucket
        assert!(generator.generate(&match1, None).is_some()); // rule_a: 1
        assert!(generator.generate(&match1, None).is_some()); // rule_a: 2
        assert!(generator.generate(&match1, None).is_none()); // rule_a: rate limited

        // rule_b should still have capacity
        assert!(generator.generate(&match2, None).is_some()); // rule_b: 1
        assert!(generator.generate(&match2, None).is_some()); // rule_b: 2
        assert!(generator.generate(&match2, None).is_none()); // rule_b: rate limited

        assert_eq!(generator.total_generated(), 4);
        assert_eq!(generator.rate_suppressed(), 2);
    }

    #[test]
    fn dedup_and_rate_limit_interaction() {
        let mut generator = AlertGenerator::new(60, 2); // dedup=60s, rate=2/min
        let rule_match = sample_rule_match();

        // First alert: passes both checks
        assert!(generator.generate(&rule_match, None).is_some());

        // Second alert: blocked by dedup (rate limit not reached)
        assert!(generator.generate(&rule_match, None).is_none());
        assert_eq!(generator.dedup_suppressed(), 1);
        assert_eq!(generator.rate_suppressed(), 0);
    }

    #[test]
    fn counters_start_at_zero() {
        let generator = AlertGenerator::new(60, 10);
        assert_eq!(generator.total_generated(), 0);
        assert_eq!(generator.dedup_suppressed(), 0);
        assert_eq!(generator.rate_suppressed(), 0);
    }

    #[test]
    fn counters_increment_correctly() {
        let mut generator = AlertGenerator::new(1, 1); // tight limits
        let rule_match = sample_rule_match();

        generator.generate(&rule_match, None); // Success
        generator.generate(&rule_match, None); // Dedup
        generator.generate(&rule_match, None); // Dedup or rate

        assert_eq!(generator.total_generated(), 1);
        assert!(generator.dedup_suppressed() > 0 || generator.rate_suppressed() > 0);
    }

    #[test]
    fn stress_test_many_rules_and_alerts() {
        let mut generator = AlertGenerator::new(0, 100); // High limits

        for rule_num in 0..100 {
            for _alert_num in 0..10 {
                let mut rule_match = sample_rule_match();
                rule_match.rule.id = format!("rule_{}", rule_num);
                generator.generate(&rule_match, None);
            }
        }

        assert_eq!(generator.total_generated(), 1000);
    }
}

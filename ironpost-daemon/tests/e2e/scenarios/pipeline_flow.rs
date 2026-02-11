//! S1: LogEvent -> RuleEngine match -> AlertEvent -> ContainerGuard isolation.
//!
//! Validates the complete event pipeline flow from log injection
//! through rule matching to alert generation and container isolation.

use crate::helpers::assertions::*;
use crate::helpers::events::*;

use ironpost_core::event::{ActionEvent, AlertEvent, Event, MODULE_CONTAINER_GUARD};
use ironpost_core::types::Severity;
use ironpost_log_pipeline::rule::RuleEngine;
use ironpost_log_pipeline::rule::types::{
    ConditionModifier, DetectionCondition, DetectionRule, FieldCondition, RuleStatus,
};
use tokio::sync::mpsc;
use tokio::time::Duration;

// ---------------------------------------------------------------------------
// T7.2: E2E Pipeline Flow Tests
// ---------------------------------------------------------------------------

/// LogEvent -> RuleEngine match -> AlertEvent -> ContainerGuard isolate (mock).
///
/// Validates the complete event pipeline flow:
/// 1. LogEvent is evaluated by RuleEngine
/// 2. Matching rule generates AlertEvent with preserved trace_id
/// 3. High-severity AlertEvent triggers ActionEvent (mock container isolation)
#[tokio::test]
async fn test_e2e_log_to_alert_to_isolation() {
    // 1. Create alert channel
    let (alert_tx, mut alert_rx) = mpsc::channel::<AlertEvent>(10);

    // 2. Create RuleEngine with brute-force detection rule
    let mut engine = RuleEngine::new();
    let rule = DetectionRule {
        id: "e2e_ssh_brute_force".to_owned(),
        title: "E2E SSH Brute Force Attempt".to_owned(),
        description: "Detects failed SSH password attempts".to_owned(),
        severity: Severity::High,
        status: RuleStatus::Enabled,
        detection: DetectionCondition {
            conditions: vec![FieldCondition {
                field: "message".to_owned(),
                modifier: ConditionModifier::Contains,
                value: "Failed password".to_owned(),
            }],
            threshold: None,
        },
        tags: vec!["authentication".to_owned(), "test".to_owned()],
    };
    engine.add_rule(rule).expect("failed to add rule");

    // 3. Inject LogEvent matching brute-force rule
    // Note: create_test_ssh_brute_force_log uses process="test-process", not "sshd"
    // So we match on message content only
    let log_event = create_test_ssh_brute_force_log();
    let original_trace_id = log_event.metadata().trace_id.clone();

    // 4. Evaluate log against rule engine
    let matches = engine
        .evaluate(&log_event.entry)
        .expect("rule evaluation failed");
    assert_eq!(matches.len(), 1, "expected exactly one rule match");

    // 5. Convert match to AlertEvent (simulating log-pipeline behavior)
    let rule_match = &matches[0];
    let alert = RuleEngine::rule_match_to_alert(rule_match, &log_event.entry);
    let alert_event = AlertEvent::with_trace(alert, Severity::High, original_trace_id.clone());

    // 6. Send AlertEvent to downstream channel
    alert_tx
        .send(alert_event)
        .await
        .expect("failed to send alert");

    // 7. Assert AlertEvent received on alert_rx
    let received_alert = assert_received_within(&mut alert_rx, DEFAULT_TIMEOUT).await;
    assert_eq!(received_alert.severity, Severity::High);
    assert_eq!(received_alert.metadata().trace_id, original_trace_id);
    assert_eq!(received_alert.alert.rule_name, "e2e_ssh_brute_force");

    // 8. Simulate ContainerGuard receiving high-severity alert and generating ActionEvent
    let (action_tx, mut action_rx) = mpsc::channel::<ActionEvent>(10);

    // Mock: Container-guard evaluates alert severity and decides to isolate
    if received_alert.severity >= Severity::High {
        let action_event = ActionEvent::with_trace(
            "container_isolate",
            "mock-container-id",
            true,
            received_alert.metadata().trace_id.clone(),
        );
        action_tx
            .send(action_event)
            .await
            .expect("failed to send action");
    }

    // 9. Assert ActionEvent generated
    let received_action = assert_received_within(&mut action_rx, DEFAULT_TIMEOUT).await;
    assert!(received_action.success);
    assert_eq!(received_action.action_type, "container_isolate");
    assert_eq!(received_action.target, "mock-container-id");
    assert_eq!(received_action.metadata().trace_id, original_trace_id);
    assert_eq!(
        received_action.metadata().source_module,
        MODULE_CONTAINER_GUARD
    );
}

/// Rule에 매칭되지 않는 로그 -> AlertEvent 미생성 확인.
///
/// Validates that benign logs do not trigger alerts.
#[tokio::test]
async fn test_e2e_log_no_match_no_alert() {
    // 1. Create alert channel
    let (_alert_tx, mut alert_rx) = mpsc::channel::<AlertEvent>(10);

    // 2. Create RuleEngine with strict brute-force rule
    let mut engine = RuleEngine::new();
    let rule = DetectionRule {
        id: "strict_ssh_rule".to_owned(),
        title: "Strict SSH Rule".to_owned(),
        description: "Only matches exact pattern".to_owned(),
        severity: Severity::High,
        status: RuleStatus::Enabled,
        detection: DetectionCondition {
            conditions: vec![
                FieldCondition {
                    field: "process".to_owned(),
                    modifier: ConditionModifier::Exact,
                    value: "sshd".to_owned(),
                },
                FieldCondition {
                    field: "message".to_owned(),
                    modifier: ConditionModifier::Contains,
                    value: "VERY_SPECIFIC_ATTACK_PATTERN".to_owned(),
                },
            ],
            threshold: None,
        },
        tags: vec![],
    };
    engine.add_rule(rule).expect("failed to add rule");

    // 3. Inject benign LogEvent (won't match the strict pattern)
    let log_event = create_test_log_event("User logged in successfully", Severity::Info);

    // 4. Evaluate log against rule engine
    let matches = engine
        .evaluate(&log_event.entry)
        .expect("rule evaluation failed");
    assert_eq!(matches.len(), 0, "benign log should not match any rules");

    // 5. Since no match, no alert should be sent
    // (we don't send anything to alert_tx)

    // 6. Assert no AlertEvent received within SHORT_TIMEOUT
    assert_not_received_within(&mut alert_rx, SHORT_TIMEOUT).await;
}

/// 심각도 낮은 알림 -> 격리 미실행 확인.
///
/// Validates that low-severity alerts do not trigger container isolation.
#[tokio::test]
async fn test_e2e_alert_below_threshold_no_action() {
    // 1. Create action channel
    let (action_tx, mut action_rx) = mpsc::channel::<ActionEvent>(10);

    // 2. Create low-severity AlertEvent
    let low_alert = create_test_low_severity_alert();
    assert_eq!(low_alert.severity, Severity::Info);

    // 3. Simulate ContainerGuard policy: only High/Critical trigger isolation
    let isolation_threshold = Severity::High;

    if low_alert.severity >= isolation_threshold {
        // This branch should NOT execute for Info severity
        let action_event = ActionEvent::new("container_isolate", "should-not-happen", true);
        action_tx
            .send(action_event)
            .await
            .expect("failed to send action");
    }

    // 4. Assert no ActionEvent generated (below threshold)
    assert_not_received_within(&mut action_rx, SHORT_TIMEOUT).await;
}

/// 연속 알림 -> 순서대로 처리 확인.
///
/// Validates that multiple alerts are processed in FIFO order with trace_id preservation.
#[tokio::test]
async fn test_e2e_multiple_alerts_sequential() {
    // 1. Create alert channel
    let (alert_tx, mut alert_rx) = mpsc::channel::<AlertEvent>(10);

    // 2. Send 5 AlertEvents in order with unique trace_ids
    let expected_trace_ids: Vec<String> = (0..5).map(|i| format!("trace-{}", i)).collect();

    for (i, trace_id) in expected_trace_ids.iter().enumerate() {
        let alert = create_test_alert_event(&format!("Alert {}", i), Severity::Medium);
        // Replace trace_id to track ordering
        let custom_alert = AlertEvent::with_trace(alert.alert, alert.severity, trace_id.clone());
        alert_tx
            .send(custom_alert)
            .await
            .expect("failed to send alert");
    }

    // 3. Assert all 5 received in correct order
    let mut received_trace_ids = Vec::new();
    for _ in 0..5 {
        let alert = assert_received_within(&mut alert_rx, DEFAULT_TIMEOUT).await;
        received_trace_ids.push(alert.metadata().trace_id.clone());
    }

    // 4. Assert trace_ids are preserved and in order
    assert_eq!(received_trace_ids, expected_trace_ids);
}

/// 채널 가득 찼을 때 생산자 블록 확인.
///
/// Validates that sending to a full bounded channel blocks (not fails)
/// and unblocks when space becomes available.
#[tokio::test]
async fn test_e2e_channel_backpressure() {
    // 1. Create small-capacity channel (capacity=2)
    let (alert_tx, mut alert_rx) = mpsc::channel::<AlertEvent>(2);

    // 2. Send 2 AlertEvents to fill channel
    for i in 0..2 {
        let alert = create_test_alert_event(&format!("Alert {}", i), Severity::Info);
        alert_tx.send(alert).await.expect("failed to send alert");
    }

    // 3. Attempt third send in background (should block, not fail)
    let alert_tx_clone = alert_tx.clone();
    let send_task = tokio::spawn(async move {
        let alert = create_test_alert_event("Alert 2 (blocked)", Severity::Info);
        alert_tx_clone
            .send(alert)
            .await
            .expect("failed to send blocked alert");
        "third_send_completed"
    });

    // 4. Give the background task time to attempt send (it should block)
    tokio::time::sleep(Duration::from_millis(50)).await;
    assert!(
        !send_task.is_finished(),
        "send should be blocked on full channel"
    );

    // 5. Receive one event to unblock
    let _first = assert_received_within(&mut alert_rx, DEFAULT_TIMEOUT).await;

    // 6. Assert third event now sendable (background task completes)
    let result = tokio::time::timeout(Duration::from_secs(1), send_task)
        .await
        .expect("send task should complete after unblocking")
        .expect("send task should not panic");
    assert_eq!(result, "third_send_completed");

    // 7. Verify we can receive the remaining events
    let _second = assert_received_within(&mut alert_rx, DEFAULT_TIMEOUT).await;
    let _third = assert_received_within(&mut alert_rx, DEFAULT_TIMEOUT).await;
}

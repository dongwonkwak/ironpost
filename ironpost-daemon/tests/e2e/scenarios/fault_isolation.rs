//! S6: Module fault isolation E2E tests.
//!
//! Validates that individual module failures do not cascade to
//! other modules, and that health reporting correctly reflects
//! degraded states.

use crate::helpers::mock_pipeline::*;

use ironpost_core::pipeline::HealthStatus;
use ironpost_daemon::health::{ModuleHealth, aggregate_status};
use ironpost_daemon::modules::{ModuleHandle, ModuleRegistry};

// ---------------------------------------------------------------------------
// T7.7: Module Start/Stop Failure Isolation Tests
// ---------------------------------------------------------------------------

/// One module fails to start -> start_all() returns error.
/// Already-started modules should be cleaned up by caller.
#[tokio::test]
async fn test_e2e_one_module_start_failure_others_stop() {
    // Given: Registry with healthy, failing_start, healthy modules
    let mut registry = ModuleRegistry::new();

    let pipeline1 = Box::new(MockPipeline::healthy("module1"));
    let handle1 = ModuleHandle::new("module1", true, pipeline1);
    registry.register(handle1);

    let pipeline2 = Box::new(MockPipeline::failing_start(
        "module2",
        "intentional failure",
    ));
    let handle2 = ModuleHandle::new("module2", true, pipeline2);
    registry.register(handle2);

    let pipeline3 = Box::new(MockPipeline::healthy("module3"));
    let handle3 = ModuleHandle::new("module3", true, pipeline3);
    registry.register(handle3);

    // When: Starting all modules
    let result = registry.start_all().await;

    // Then: Should fail due to module2
    assert!(result.is_err(), "start_all should return error");
    let err_msg = result.unwrap_err().to_string();
    assert!(
        err_msg.contains("module2") && err_msg.contains("intentional failure"),
        "error should mention failing module: {}",
        err_msg
    );

    // Note: Module1 was started, module3 was not (early return).
    // Caller should invoke stop_all() for cleanup.
}

/// One module fails to stop -> stop_all() logs error and continues.
#[tokio::test]
async fn test_e2e_stop_failure_continues_others() {
    // Given: Registry with healthy, failing_stop, healthy modules
    let mut registry = ModuleRegistry::new();

    let pipeline1 = Box::new(MockPipeline::healthy("module1"));
    let handle1 = ModuleHandle::new("module1", true, pipeline1);
    registry.register(handle1);

    let pipeline2 = Box::new(MockPipeline::failing_stop("module2", "stop failed"));
    let handle2 = ModuleHandle::new("module2", true, pipeline2);
    registry.register(handle2);

    let pipeline3 = MockPipeline::healthy("module3");
    let stopped3 = pipeline3.stopped.clone();
    let handle3 = ModuleHandle::new("module3", true, Box::new(pipeline3));
    registry.register(handle3);

    // When: Starting all modules (should succeed)
    registry.start_all().await.expect("start should succeed");

    // When: Stopping all modules
    let result = registry.stop_all().await;

    // Then: Should fail due to module2, but module3 should still be stopped
    assert!(result.is_err(), "stop_all should return error");
    let err_msg = result.unwrap_err().to_string();
    assert!(
        err_msg.contains("module2") && err_msg.contains("stop failed"),
        "error should mention failing module: {}",
        err_msg
    );

    // Assert: Module3 was stopped despite module2 failing
    assert!(
        stopped3.load(std::sync::atomic::Ordering::SeqCst),
        "module3 should be stopped despite module2 failure"
    );
}

// ---------------------------------------------------------------------------
// T7.7: Runtime Health Isolation Tests
// ---------------------------------------------------------------------------

/// One module Degraded -> other modules remain Healthy.
/// DaemonHealth aggregates to Degraded.
#[tokio::test]
async fn test_e2e_runtime_module_degraded_others_healthy() {
    // Given: Registry with 3 modules: healthy, degraded, healthy
    let mut registry = ModuleRegistry::new();

    let pipeline1 = Box::new(MockPipeline::healthy("module1"));
    let handle1 = ModuleHandle::new("module1", true, pipeline1);
    registry.register(handle1);

    let pipeline2 = Box::new(MockPipeline::with_health(
        "module2",
        HealthStatus::Degraded("slow response".to_string()),
    ));
    let handle2 = ModuleHandle::new("module2", true, pipeline2);
    registry.register(handle2);

    let pipeline3 = Box::new(MockPipeline::healthy("module3"));
    let handle3 = ModuleHandle::new("module3", true, pipeline3);
    registry.register(handle3);

    // When: Getting health statuses
    let statuses = registry.health_statuses().await;

    // Then: Should have 3 statuses
    assert_eq!(statuses.len(), 3, "should have 3 module statuses");

    // Assert: Individual health statuses
    let (name1, enabled1, status1) = &statuses[0];
    assert_eq!(name1, "module1");
    assert!(enabled1);
    assert!(status1.is_healthy(), "module1 should be healthy");

    let (name2, enabled2, status2) = &statuses[1];
    assert_eq!(name2, "module2");
    assert!(enabled2);
    assert!(
        matches!(status2, HealthStatus::Degraded(_)),
        "module2 should be degraded"
    );

    let (name3, enabled3, status3) = &statuses[2];
    assert_eq!(name3, "module3");
    assert!(enabled3);
    assert!(status3.is_healthy(), "module3 should be healthy");

    // Assert: Aggregate status should be Degraded
    let module_healths: Vec<ModuleHealth> = statuses
        .into_iter()
        .map(|(name, enabled, status)| ModuleHealth {
            name,
            enabled,
            status,
        })
        .collect();

    let aggregate = aggregate_status(&module_healths);
    assert!(
        matches!(aggregate, HealthStatus::Degraded(_)),
        "aggregate should be degraded when one module is degraded"
    );
}

// ---------------------------------------------------------------------------
// T7.7: Channel Failure Handling Tests
// ---------------------------------------------------------------------------

/// Producer channel closes (sender dropped) -> consumer handles gracefully.
#[tokio::test]
async fn test_e2e_channel_sender_dropped_receiver_handles() {
    use ironpost_core::event::AlertEvent;
    use tokio::sync::mpsc;

    // Given: Alert channel
    let (alert_tx, mut alert_rx) = mpsc::channel::<AlertEvent>(10);

    // When: Dropping the sender
    drop(alert_tx);

    // Then: recv() should return None (channel closed) without panic
    let result = alert_rx.recv().await;
    assert!(
        result.is_none(),
        "receiver should return None when sender is dropped"
    );
}

// ---------------------------------------------------------------------------
// T7.7: Health Aggregation Tests
// ---------------------------------------------------------------------------

/// Health aggregation: Unhealthy + Degraded + Healthy -> Unhealthy.
#[tokio::test]
async fn test_e2e_health_aggregation_worst_case() {
    // Given: Module health list with mixed statuses
    let modules = vec![
        ModuleHealth {
            name: "healthy-module".to_string(),
            enabled: true,
            status: HealthStatus::Healthy,
        },
        ModuleHealth {
            name: "degraded-module".to_string(),
            enabled: true,
            status: HealthStatus::Degraded("slow".to_string()),
        },
        ModuleHealth {
            name: "unhealthy-module".to_string(),
            enabled: true,
            status: HealthStatus::Unhealthy("broken".to_string()),
        },
    ];

    // When: Aggregating status
    let aggregate = aggregate_status(&modules);

    // Then: Should be Unhealthy (worst case)
    assert!(
        matches!(aggregate, HealthStatus::Unhealthy(_)),
        "aggregate should be unhealthy when any module is unhealthy"
    );

    // Assert: Reason should contain the unhealthy module's name
    if let HealthStatus::Unhealthy(reason) = aggregate {
        assert!(
            reason.contains("unhealthy-module"),
            "reason should mention unhealthy module: {}",
            reason
        );
    }
}

/// Health aggregation: all Healthy -> Healthy.
#[tokio::test]
async fn test_e2e_health_aggregation_all_healthy() {
    // Given: Module health list with all healthy
    let modules = vec![
        ModuleHealth {
            name: "module1".to_string(),
            enabled: true,
            status: HealthStatus::Healthy,
        },
        ModuleHealth {
            name: "module2".to_string(),
            enabled: true,
            status: HealthStatus::Healthy,
        },
        ModuleHealth {
            name: "module3".to_string(),
            enabled: true,
            status: HealthStatus::Healthy,
        },
    ];

    // When: Aggregating status
    let aggregate = aggregate_status(&modules);

    // Then: Should be Healthy
    assert!(
        aggregate.is_healthy(),
        "aggregate should be healthy when all modules are healthy"
    );
}

/// Disabled modules do not affect health aggregation.
#[tokio::test]
async fn test_e2e_disabled_modules_excluded_from_health() {
    // Given: Module health list with disabled unhealthy module
    let modules = vec![
        ModuleHealth {
            name: "enabled-healthy".to_string(),
            enabled: true,
            status: HealthStatus::Healthy,
        },
        ModuleHealth {
            name: "disabled-unhealthy".to_string(),
            enabled: false,
            status: HealthStatus::Unhealthy("broken".to_string()),
        },
    ];

    // When: Aggregating status
    let aggregate = aggregate_status(&modules);

    // Then: Should be Healthy (disabled modules ignored)
    assert!(
        aggregate.is_healthy(),
        "aggregate should be healthy when only disabled modules are unhealthy"
    );
}

// ---------------------------------------------------------------------------
// T7.7: Additional Edge Cases
// ---------------------------------------------------------------------------

/// Health aggregation: Degraded without Unhealthy -> Degraded.
#[tokio::test]
async fn test_e2e_health_aggregation_degraded_wins_over_healthy() {
    // Given: Module health list with Healthy and Degraded (no Unhealthy)
    let modules = vec![
        ModuleHealth {
            name: "module1".to_string(),
            enabled: true,
            status: HealthStatus::Healthy,
        },
        ModuleHealth {
            name: "module2".to_string(),
            enabled: true,
            status: HealthStatus::Degraded("minor issue".to_string()),
        },
    ];

    // When: Aggregating status
    let aggregate = aggregate_status(&modules);

    // Then: Should be Degraded
    assert!(
        matches!(aggregate, HealthStatus::Degraded(_)),
        "aggregate should be degraded when any module is degraded (and none unhealthy)"
    );

    if let HealthStatus::Degraded(reason) = aggregate {
        assert!(
            reason.contains("module2"),
            "reason should mention degraded module: {}",
            reason
        );
    }
}

/// Health aggregation: multiple Degraded -> all reasons included.
#[tokio::test]
async fn test_e2e_health_aggregation_multiple_degraded() {
    // Given: Module health list with multiple degraded modules
    let modules = vec![
        ModuleHealth {
            name: "module1".to_string(),
            enabled: true,
            status: HealthStatus::Degraded("issue1".to_string()),
        },
        ModuleHealth {
            name: "module2".to_string(),
            enabled: true,
            status: HealthStatus::Degraded("issue2".to_string()),
        },
    ];

    // When: Aggregating status
    let aggregate = aggregate_status(&modules);

    // Then: Should be Degraded with both reasons
    assert!(
        matches!(aggregate, HealthStatus::Degraded(_)),
        "aggregate should be degraded"
    );

    if let HealthStatus::Degraded(reason) = aggregate {
        assert!(
            reason.contains("module1") && reason.contains("issue1"),
            "reason should include module1: {}",
            reason
        );
        assert!(
            reason.contains("module2") && reason.contains("issue2"),
            "reason should include module2: {}",
            reason
        );
    }
}

/// Health aggregation: empty module list -> Healthy.
#[tokio::test]
async fn test_e2e_health_aggregation_empty_list() {
    // Given: Empty module health list
    let modules: Vec<ModuleHealth> = vec![];

    // When: Aggregating status
    let aggregate = aggregate_status(&modules);

    // Then: Should be Healthy (no unhealthy modules)
    assert!(
        aggregate.is_healthy(),
        "aggregate should be healthy when no modules are registered"
    );
}

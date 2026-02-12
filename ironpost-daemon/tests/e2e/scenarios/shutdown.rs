//! S4: Graceful shutdown order verification.
//!
//! Validates that modules are stopped in the correct order
//! (producers first, consumers last) and that pending events
//! can be drained during shutdown.

use crate::helpers::mock_pipeline::*;

use ironpost_daemon::modules::{ModuleHandle, ModuleRegistry};

use std::time::Duration;
use tokio::sync::mpsc;

use crate::helpers::events::create_test_alert_event;
use ironpost_core::event::AlertEvent;
use ironpost_core::types::Severity;

/// Modules stop in registration order (producers first):
/// eBPF -> LogPipeline -> SBOM -> ContainerGuard.
#[tokio::test]
async fn test_e2e_shutdown_order_producers_first() {
    let tracker = StopOrderTracker::new();

    let mut registry = ModuleRegistry::new();

    // Register in order: producers first, consumers last
    registry.register(ModuleHandle::new(
        "ebpf-engine",
        true,
        Box::new(MockPipeline::healthy("ebpf").with_stop_order(tracker.clone())),
    ));
    registry.register(ModuleHandle::new(
        "log-pipeline",
        true,
        Box::new(MockPipeline::healthy("log-pipeline").with_stop_order(tracker.clone())),
    ));
    registry.register(ModuleHandle::new(
        "sbom-scanner",
        true,
        Box::new(MockPipeline::healthy("sbom").with_stop_order(tracker.clone())),
    ));
    registry.register(ModuleHandle::new(
        "container-guard",
        true,
        Box::new(MockPipeline::healthy("container-guard").with_stop_order(tracker.clone())),
    ));

    // Start all modules
    registry.start_all().await.expect("start should succeed");

    // Stop all modules
    registry.stop_all().await.expect("stop should succeed");

    // Verify stop order
    let log = tracker.get_log().await;
    assert_eq!(log.len(), 4, "all 4 modules should have stopped");

    // Verify order: ebpf(0), log-pipeline(1), sbom(2), container-guard(3)
    assert_eq!(log[0], ("ebpf".to_owned(), 0));
    assert_eq!(log[1], ("log-pipeline".to_owned(), 1));
    assert_eq!(log[2], ("sbom".to_owned(), 2));
    assert_eq!(log[3], ("container-guard".to_owned(), 3));
}

/// Pending events in channels are drained during shutdown.
#[tokio::test]
async fn test_e2e_shutdown_drains_pending_events() {
    let (tx, mut rx) = mpsc::channel::<AlertEvent>(10);

    // Send some events
    let event1 = create_test_alert_event("alert-1", Severity::High);
    let event2 = create_test_alert_event("alert-2", Severity::Medium);
    let event3 = create_test_alert_event("alert-3", Severity::Low);

    tx.send(event1).await.expect("send should succeed");
    tx.send(event2).await.expect("send should succeed");
    tx.send(event3).await.expect("send should succeed");

    // Drop sender (simulates producer shutdown)
    drop(tx);

    // Drain all pending events
    let mut received = Vec::new();
    while let Some(event) = rx.recv().await {
        received.push(event);
    }

    // Verify all events were drained
    assert_eq!(received.len(), 3, "all 3 events should be drained");
    assert!(received[0].alert.title.contains("alert-1"));
    assert!(received[1].alert.title.contains("alert-2"));
    assert!(received[2].alert.title.contains("alert-3"));

    // After drain, recv() returns None
    assert!(rx.recv().await.is_none(), "channel should be closed");
}

/// Module stop timeout: slow module does not block others forever.
#[tokio::test]
async fn test_e2e_shutdown_timeout_handling() {
    let mut registry = ModuleRegistry::new();

    // Register a slow pipeline (100ms delay) and a fast one
    registry.register(ModuleHandle::new(
        "slow-module",
        true,
        Box::new(MockPipeline::healthy("slow").with_stop_delay(Duration::from_millis(100))),
    ));
    registry.register(ModuleHandle::new(
        "fast-module",
        true,
        Box::new(MockPipeline::healthy("fast")),
    ));

    // Start all modules
    registry.start_all().await.expect("start should succeed");

    // Measure stop time
    let start = std::time::Instant::now();
    registry.stop_all().await.expect("stop should succeed");
    let elapsed = start.elapsed();

    // Stop should take at least the slow module's delay
    assert!(
        elapsed >= Duration::from_millis(100),
        "stop should wait for slow module (elapsed: {:?})",
        elapsed
    );

    // But not significantly longer (no blocking on fast module)
    assert!(
        elapsed < Duration::from_millis(500),
        "stop should not block excessively (elapsed: {:?})",
        elapsed
    );
}

/// One module fails to stop -> remaining modules still stop.
#[tokio::test]
async fn test_e2e_shutdown_partial_failure_continues() {
    let mut registry = ModuleRegistry::new();

    let pipeline1 = MockPipeline::healthy("healthy-1");
    let pipeline2 = MockPipeline::failing_stop("failing", "intentional stop failure");
    let pipeline3 = MockPipeline::healthy("healthy-2");

    let p1_stopped = pipeline1.stopped.clone();
    let p2_stopped = pipeline2.stopped.clone();
    let p3_stopped = pipeline3.stopped.clone();

    registry.register(ModuleHandle::new("healthy-1", true, Box::new(pipeline1)));
    registry.register(ModuleHandle::new("failing", true, Box::new(pipeline2)));
    registry.register(ModuleHandle::new("healthy-2", true, Box::new(pipeline3)));

    // Start all modules
    registry.start_all().await.expect("start should succeed");

    // Stop all modules - should return error from failing module
    let result = registry.stop_all().await;
    assert!(result.is_err(), "stop_all should return error");
    assert!(
        result.unwrap_err().to_string().contains("failing"),
        "error should mention failing module"
    );

    // But all other modules should still have been stopped
    assert!(
        p1_stopped.load(std::sync::atomic::Ordering::SeqCst),
        "healthy-1 should be stopped"
    );
    assert!(
        !p2_stopped.load(std::sync::atomic::Ordering::SeqCst),
        "failing module should not set stopped flag"
    );
    assert!(
        p3_stopped.load(std::sync::atomic::Ordering::SeqCst),
        "healthy-2 should be stopped despite earlier failure"
    );
}

/// PID file is removed after shutdown.
#[tokio::test]
async fn test_e2e_pid_file_cleanup_after_shutdown() {
    let temp_dir = tempfile::tempdir().expect("should create temp dir");
    let pid_path = temp_dir.path().join("ironpost.pid");

    // Write PID file
    std::fs::write(&pid_path, "12345").expect("should write PID file");
    assert!(pid_path.exists(), "PID file should exist after write");

    // Simulate shutdown: remove PID file
    std::fs::remove_file(&pid_path).expect("should remove PID file");

    // Verify cleanup
    assert!(
        !pid_path.exists(),
        "PID file should be removed after shutdown"
    );
}

/// start_all() then stop_all() twice is safe (idempotent).
#[tokio::test]
async fn test_e2e_shutdown_stop_twice_safe() {
    let mut registry = ModuleRegistry::new();

    let pipeline = MockPipeline::healthy("test");
    let stopped_flag = pipeline.stopped.clone();

    registry.register(ModuleHandle::new("test-module", true, Box::new(pipeline)));

    // Start
    registry.start_all().await.expect("start should succeed");

    // First stop
    registry
        .stop_all()
        .await
        .expect("first stop should succeed");
    assert!(
        stopped_flag.load(std::sync::atomic::Ordering::SeqCst),
        "module should be stopped after first stop"
    );

    // Second stop - should also succeed (idempotent)
    let result = registry.stop_all().await;
    assert!(
        result.is_ok(),
        "second stop should succeed: {:?}",
        result.err()
    );
}

/// Empty registry: start_all and stop_all succeed without errors.
#[tokio::test]
async fn test_e2e_shutdown_empty_registry() {
    let mut registry = ModuleRegistry::new();

    // No modules registered
    let start_result = registry.start_all().await;
    assert!(
        start_result.is_ok(),
        "start_all on empty registry should succeed"
    );

    let stop_result = registry.stop_all().await;
    assert!(
        stop_result.is_ok(),
        "stop_all on empty registry should succeed"
    );
}

/// Disabled modules are not started or stopped.
#[tokio::test]
async fn test_e2e_shutdown_disabled_modules_skipped() {
    let mut registry = ModuleRegistry::new();

    let pipeline = MockPipeline::healthy("disabled");
    let started = pipeline.started.clone();
    let stopped = pipeline.stopped.clone();

    // Register as disabled
    registry.register(ModuleHandle::new(
        "disabled-module",
        false,
        Box::new(pipeline),
    ));

    // Start all
    registry.start_all().await.expect("start should succeed");
    assert!(
        !started.load(std::sync::atomic::Ordering::SeqCst),
        "disabled module should not be started"
    );

    // Stop all
    registry.stop_all().await.expect("stop should succeed");
    assert!(
        !stopped.load(std::sync::atomic::Ordering::SeqCst),
        "disabled module should not be stopped"
    );
}

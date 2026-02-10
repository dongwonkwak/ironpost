//! 통합 테스트 -- 전체 파이프라인 플로우 검증
//!
//! Alert 수신 → Policy 매칭 → Isolation 실행 → ActionEvent 생성
//! 시나리오를 실제 채널 통신을 사용하여 테스트합니다.

use std::sync::Arc;
use std::time::{Duration, SystemTime};

use ironpost_container_guard::{
    ContainerGuardBuilder, ContainerGuardConfig, IsolationAction, SecurityPolicy, TargetFilter,
};
use ironpost_core::event::AlertEvent;
use ironpost_core::pipeline::{HealthStatus, Pipeline};
use ironpost_core::types::{Alert, ContainerInfo, Severity};
use tokio::sync::mpsc;

// Mock Docker client for integration tests
mod mock {
    use super::*;
    use ironpost_container_guard::DockerClient;
    use tokio::sync::Mutex;

    pub struct TestDockerClient {
        containers: Arc<Mutex<Vec<ContainerInfo>>>,
        fail_actions: Arc<Mutex<bool>>,
        ping_fails: Arc<Mutex<bool>>,
    }

    impl TestDockerClient {
        pub fn new() -> Self {
            Self {
                containers: Arc::new(Mutex::new(Vec::new())),
                fail_actions: Arc::new(Mutex::new(false)),
                ping_fails: Arc::new(Mutex::new(false)),
            }
        }

        pub async fn add_container(&self, container: ContainerInfo) {
            self.containers.lock().await.push(container);
        }

        pub async fn set_fail_actions(&self, fail: bool) {
            *self.fail_actions.lock().await = fail;
        }

        pub async fn set_ping_fails(&self, fail: bool) {
            *self.ping_fails.lock().await = fail;
        }
    }

    impl DockerClient for TestDockerClient {
        async fn list_containers(
            &self,
        ) -> Result<Vec<ContainerInfo>, ironpost_container_guard::ContainerGuardError> {
            Ok(self.containers.lock().await.clone())
        }

        async fn inspect_container(
            &self,
            id: &str,
        ) -> Result<ContainerInfo, ironpost_container_guard::ContainerGuardError> {
            self.containers
                .lock()
                .await
                .iter()
                .find(|c| c.id == id || c.id.starts_with(id))
                .cloned()
                .ok_or_else(|| {
                    ironpost_container_guard::ContainerGuardError::ContainerNotFound(id.to_owned())
                })
        }

        async fn stop_container(
            &self,
            id: &str,
        ) -> Result<(), ironpost_container_guard::ContainerGuardError> {
            if *self.fail_actions.lock().await {
                return Err(
                    ironpost_container_guard::ContainerGuardError::IsolationFailed {
                        container_id: id.to_owned(),
                        reason: "test failure".to_owned(),
                    },
                );
            }
            self.inspect_container(id).await?;
            Ok(())
        }

        async fn pause_container(
            &self,
            id: &str,
        ) -> Result<(), ironpost_container_guard::ContainerGuardError> {
            if *self.fail_actions.lock().await {
                return Err(
                    ironpost_container_guard::ContainerGuardError::IsolationFailed {
                        container_id: id.to_owned(),
                        reason: "test failure".to_owned(),
                    },
                );
            }
            self.inspect_container(id).await?;
            Ok(())
        }

        async fn unpause_container(
            &self,
            id: &str,
        ) -> Result<(), ironpost_container_guard::ContainerGuardError> {
            if *self.fail_actions.lock().await {
                return Err(
                    ironpost_container_guard::ContainerGuardError::IsolationFailed {
                        container_id: id.to_owned(),
                        reason: "test failure".to_owned(),
                    },
                );
            }
            self.inspect_container(id).await?;
            Ok(())
        }

        async fn disconnect_network(
            &self,
            container_id: &str,
            _network: &str,
        ) -> Result<(), ironpost_container_guard::ContainerGuardError> {
            if *self.fail_actions.lock().await {
                return Err(
                    ironpost_container_guard::ContainerGuardError::IsolationFailed {
                        container_id: container_id.to_owned(),
                        reason: "test failure".to_owned(),
                    },
                );
            }
            self.inspect_container(container_id).await?;
            Ok(())
        }

        async fn ping(&self) -> Result<(), ironpost_container_guard::ContainerGuardError> {
            if *self.ping_fails.lock().await {
                return Err(
                    ironpost_container_guard::ContainerGuardError::DockerConnection(
                        "ping failed".to_owned(),
                    ),
                );
            }
            Ok(())
        }
    }
}

fn sample_container(id: &str, name: &str, image: &str) -> ContainerInfo {
    ContainerInfo {
        id: id.to_owned(),
        name: name.to_owned(),
        image: image.to_owned(),
        status: "running".to_owned(),
        created_at: SystemTime::now(),
    }
}

fn sample_alert(severity: Severity, container_hint: Option<&str>) -> AlertEvent {
    let description = if let Some(hint) = container_hint {
        format!("Alert from container {hint}")
    } else {
        "Generic alert".to_owned()
    };

    AlertEvent::new(
        Alert {
            id: uuid::Uuid::new_v4().to_string(),
            title: "Test Alert".to_owned(),
            description,
            severity,
            rule_name: "test_rule".to_owned(),
            source_ip: None,
            target_ip: None,
            created_at: SystemTime::now(),
        },
        severity,
    )
}

fn sample_policy(severity: Severity, action: IsolationAction) -> SecurityPolicy {
    SecurityPolicy {
        id: uuid::Uuid::new_v4().to_string(),
        name: "Test Policy".to_owned(),
        description: "Test policy for integration test".to_owned(),
        enabled: true,
        severity_threshold: severity,
        target_filter: TargetFilter::default(),
        action,
        priority: 1,
    }
}

#[tokio::test]
async fn test_full_pipeline_alert_to_action() {
    // Setup
    let docker = Arc::new(mock::TestDockerClient::new());
    docker
        .add_container(sample_container("abc123", "web-server", "nginx:latest"))
        .await;

    let (alert_tx, alert_rx) = mpsc::channel(16);

    let policy = sample_policy(Severity::High, IsolationAction::Pause);

    let config = ContainerGuardConfig {
        enabled: true,
        auto_isolate: true,
        poll_interval_secs: 1,
        action_timeout_secs: 5,
        retry_max_attempts: 1,
        ..Default::default()
    };

    let (mut guard, action_rx) = ContainerGuardBuilder::new()
        .docker_client(docker)
        .config(config)
        .alert_receiver(alert_rx)
        .add_policy(policy)
        .build()
        .unwrap();

    let mut action_rx = action_rx.unwrap();

    // Start guard
    guard.start().await.unwrap();
    tokio::time::sleep(Duration::from_millis(100)).await;

    // Send alert
    let alert = sample_alert(Severity::Critical, None);
    alert_tx.send(alert).await.unwrap();

    // Wait for action
    let action_event = tokio::time::timeout(Duration::from_secs(2), action_rx.recv())
        .await
        .expect("timeout waiting for action event")
        .expect("action channel closed");

    assert!(action_event.success);
    assert_eq!(action_event.target, "abc123");

    // Cleanup
    guard.stop().await.unwrap();
}

#[tokio::test]
async fn test_no_policy_match_no_action() {
    let docker = Arc::new(mock::TestDockerClient::new());
    docker
        .add_container(sample_container("abc123", "web-server", "nginx:latest"))
        .await;

    let (alert_tx, alert_rx) = mpsc::channel(16);

    // Policy requires Critical, but we'll send Low alert
    let policy = sample_policy(Severity::Critical, IsolationAction::Stop);

    let config = ContainerGuardConfig {
        enabled: true,
        auto_isolate: true,
        poll_interval_secs: 1,
        ..Default::default()
    };

    let (mut guard, action_rx) = ContainerGuardBuilder::new()
        .docker_client(docker)
        .config(config)
        .alert_receiver(alert_rx)
        .add_policy(policy)
        .build()
        .unwrap();

    let mut action_rx = action_rx.unwrap();

    guard.start().await.unwrap();
    tokio::time::sleep(Duration::from_millis(100)).await;

    // Send low severity alert
    let alert = sample_alert(Severity::Low, None);
    alert_tx.send(alert).await.unwrap();

    // Should not receive action
    let result = tokio::time::timeout(Duration::from_millis(500), action_rx.recv()).await;
    assert!(result.is_err()); // Timeout means no action was sent

    guard.stop().await.unwrap();
}

#[tokio::test]
async fn test_auto_isolate_disabled_no_action() {
    let docker = Arc::new(mock::TestDockerClient::new());
    docker
        .add_container(sample_container("abc123", "web-server", "nginx:latest"))
        .await;

    let (alert_tx, alert_rx) = mpsc::channel(16);

    let policy = sample_policy(Severity::High, IsolationAction::Pause);

    let config = ContainerGuardConfig {
        enabled: true,
        auto_isolate: false, // Disabled
        poll_interval_secs: 1,
        ..Default::default()
    };

    let (mut guard, action_rx) = ContainerGuardBuilder::new()
        .docker_client(docker)
        .config(config)
        .alert_receiver(alert_rx)
        .add_policy(policy)
        .build()
        .unwrap();

    let mut action_rx = action_rx.unwrap();

    guard.start().await.unwrap();
    tokio::time::sleep(Duration::from_millis(100)).await;

    let alert = sample_alert(Severity::Critical, None);
    alert_tx.send(alert).await.unwrap();

    // Should not receive action
    let result = tokio::time::timeout(Duration::from_millis(500), action_rx.recv()).await;
    assert!(result.is_err());

    guard.stop().await.unwrap();
}

#[tokio::test]
async fn test_isolation_failure_sends_failed_action_event() {
    let docker = Arc::new(mock::TestDockerClient::new());
    docker
        .add_container(sample_container("abc123", "web-server", "nginx:latest"))
        .await;
    docker.set_fail_actions(true).await; // Make actions fail

    let (alert_tx, alert_rx) = mpsc::channel(16);

    let policy = sample_policy(Severity::High, IsolationAction::Stop);

    let config = ContainerGuardConfig {
        enabled: true,
        auto_isolate: true,
        poll_interval_secs: 1,
        retry_max_attempts: 1,
        ..Default::default()
    };

    let (mut guard, action_rx) = ContainerGuardBuilder::new()
        .docker_client(docker)
        .config(config)
        .alert_receiver(alert_rx)
        .add_policy(policy)
        .build()
        .unwrap();

    let mut action_rx = action_rx.unwrap();

    guard.start().await.unwrap();
    tokio::time::sleep(Duration::from_millis(100)).await;

    let alert = sample_alert(Severity::Critical, None);
    alert_tx.send(alert).await.unwrap();

    // Should receive failed action event
    let action_event = tokio::time::timeout(Duration::from_secs(2), action_rx.recv())
        .await
        .expect("timeout")
        .expect("channel closed");

    assert!(!action_event.success);

    guard.stop().await.unwrap();
}

#[tokio::test]
async fn test_concurrent_alerts_processing() {
    let docker = Arc::new(mock::TestDockerClient::new());
    docker
        .add_container(sample_container("abc123", "web-1", "nginx:latest"))
        .await;
    docker
        .add_container(sample_container("def456", "web-2", "nginx:latest"))
        .await;
    docker
        .add_container(sample_container("ghi789", "web-3", "nginx:latest"))
        .await;

    let (alert_tx, alert_rx) = mpsc::channel(16);

    let policy = sample_policy(Severity::Medium, IsolationAction::Pause);

    let config = ContainerGuardConfig {
        enabled: true,
        auto_isolate: true,
        poll_interval_secs: 1,
        ..Default::default()
    };

    let (mut guard, action_rx) = ContainerGuardBuilder::new()
        .docker_client(docker)
        .config(config)
        .alert_receiver(alert_rx)
        .add_policy(policy)
        .build()
        .unwrap();

    let mut action_rx = action_rx.unwrap();

    guard.start().await.unwrap();
    tokio::time::sleep(Duration::from_millis(100)).await;

    // Send multiple alerts
    for _ in 0..3 {
        alert_tx
            .send(sample_alert(Severity::High, None))
            .await
            .unwrap();
    }

    // Should receive multiple actions
    let mut action_count = 0;
    for _ in 0..3 {
        if tokio::time::timeout(Duration::from_secs(1), action_rx.recv())
            .await
            .is_ok()
        {
            action_count += 1;
        }
    }

    assert!(action_count >= 3);

    guard.stop().await.unwrap();
}

#[tokio::test]
async fn test_graceful_shutdown_with_in_progress_actions() {
    let docker = Arc::new(mock::TestDockerClient::new());
    docker
        .add_container(sample_container("abc123", "web-server", "nginx:latest"))
        .await;

    let (alert_tx, alert_rx) = mpsc::channel(16);

    let policy = sample_policy(Severity::High, IsolationAction::Pause);

    let config = ContainerGuardConfig {
        enabled: true,
        auto_isolate: true,
        poll_interval_secs: 1,
        ..Default::default()
    };

    let (mut guard, _action_rx) = ContainerGuardBuilder::new()
        .docker_client(docker)
        .config(config)
        .alert_receiver(alert_rx)
        .add_policy(policy)
        .build()
        .unwrap();

    guard.start().await.unwrap();
    tokio::time::sleep(Duration::from_millis(100)).await;

    // Send alert
    alert_tx
        .send(sample_alert(Severity::Critical, None))
        .await
        .unwrap();

    // Immediately stop - should handle gracefully
    let result = guard.stop().await;
    assert!(result.is_ok());

    assert_eq!(guard.state_name(), "stopped");
}

#[tokio::test]
async fn test_health_check_states() {
    let docker = Arc::new(mock::TestDockerClient::new());

    let (_alert_tx, alert_rx) = mpsc::channel(16);

    let (mut guard, _action_rx) = ContainerGuardBuilder::new()
        .docker_client(docker)
        .config(ContainerGuardConfig::default())
        .alert_receiver(alert_rx)
        .build()
        .unwrap();

    // Before start: Unhealthy
    assert!(guard.health_check().await.is_unhealthy());

    // After start: Healthy
    guard.start().await.unwrap();
    tokio::time::sleep(Duration::from_millis(100)).await;
    assert!(guard.health_check().await.is_healthy());

    // After stop: Unhealthy
    guard.stop().await.unwrap();
    assert!(guard.health_check().await.is_unhealthy());
}

#[tokio::test]
async fn test_health_check_degraded_when_docker_unreachable() {
    let docker = Arc::new(mock::TestDockerClient::new());
    docker.set_ping_fails(true).await; // Make Docker unreachable

    let (_alert_tx, alert_rx) = mpsc::channel(16);

    let (mut guard, _action_rx) = ContainerGuardBuilder::new()
        .docker_client(docker)
        .config(ContainerGuardConfig::default())
        .alert_receiver(alert_rx)
        .build()
        .unwrap();

    guard.start().await.unwrap();
    tokio::time::sleep(Duration::from_millis(100)).await;

    let health = guard.health_check().await;
    match health {
        HealthStatus::Degraded(_) => {
            // Expected
        }
        _ => panic!("Expected Degraded health status"),
    }

    guard.stop().await.unwrap();
}

#[tokio::test]
async fn test_metrics_tracking() {
    let docker = Arc::new(mock::TestDockerClient::new());
    docker
        .add_container(sample_container("abc123", "web-server", "nginx:latest"))
        .await;

    let (alert_tx, alert_rx) = mpsc::channel(16);

    let policy = sample_policy(Severity::Medium, IsolationAction::Pause);

    let config = ContainerGuardConfig {
        enabled: true,
        auto_isolate: true,
        poll_interval_secs: 1,
        ..Default::default()
    };

    let (mut guard, _action_rx) = ContainerGuardBuilder::new()
        .docker_client(docker)
        .config(config)
        .alert_receiver(alert_rx)
        .add_policy(policy)
        .build()
        .unwrap();

    assert_eq!(guard.alerts_processed(), 0);
    assert_eq!(guard.isolations_executed(), 0);

    guard.start().await.unwrap();
    tokio::time::sleep(Duration::from_millis(100)).await;

    // Send alerts
    alert_tx
        .send(sample_alert(Severity::High, None))
        .await
        .unwrap();
    alert_tx
        .send(sample_alert(Severity::High, None))
        .await
        .unwrap();

    tokio::time::sleep(Duration::from_millis(500)).await;

    // Metrics should be updated
    assert!(guard.alerts_processed() >= 2);
    assert!(guard.isolations_executed() >= 2);

    guard.stop().await.unwrap();
}

// --- Additional Integration Tests ---

/// Test Alert with no containers: Alert arrives but no containers in monitor (no action)
#[tokio::test]
async fn test_alert_with_no_containers_no_action() {
    let docker = Arc::new(mock::TestDockerClient::new());
    // No containers added

    let (alert_tx, alert_rx) = mpsc::channel(16);

    let policy = sample_policy(Severity::Medium, IsolationAction::Pause);

    let config = ContainerGuardConfig {
        enabled: true,
        auto_isolate: true,
        poll_interval_secs: 1,
        ..Default::default()
    };

    let (mut guard, action_rx) = ContainerGuardBuilder::new()
        .docker_client(docker)
        .config(config)
        .alert_receiver(alert_rx)
        .add_policy(policy)
        .build()
        .unwrap();

    let mut action_rx = action_rx.unwrap();

    guard.start().await.unwrap();
    tokio::time::sleep(Duration::from_millis(100)).await;

    // Send alert
    alert_tx
        .send(sample_alert(Severity::High, None))
        .await
        .unwrap();

    // Should not receive action (no containers to match)
    let result = tokio::time::timeout(Duration::from_millis(500), action_rx.recv()).await;
    assert!(result.is_err()); // Timeout means no action

    guard.stop().await.unwrap();
}

/// Test Multiple policies priority ordering: Alert matches multiple policies, only first by priority executes
#[tokio::test]
async fn test_multiple_policies_priority_ordering() {
    let docker = Arc::new(mock::TestDockerClient::new());
    docker
        .add_container(sample_container("abc123", "web-server", "nginx:latest"))
        .await;

    let (alert_tx, alert_rx) = mpsc::channel(16);

    // Low priority policy (should execute first due to lower priority number)
    let policy_high_priority = SecurityPolicy {
        id: "high-priority".to_owned(),
        name: "High Priority Policy".to_owned(),
        description: "Test".to_owned(),
        enabled: true,
        severity_threshold: Severity::Medium,
        target_filter: TargetFilter::default(),
        action: IsolationAction::Pause,
        priority: 1,
    };

    // High priority value (should not execute)
    let policy_low_priority = SecurityPolicy {
        id: "low-priority".to_owned(),
        name: "Low Priority Policy".to_owned(),
        description: "Test".to_owned(),
        enabled: true,
        severity_threshold: Severity::Medium,
        target_filter: TargetFilter::default(),
        action: IsolationAction::Stop,
        priority: 10,
    };

    let config = ContainerGuardConfig {
        enabled: true,
        auto_isolate: true,
        poll_interval_secs: 1,
        ..Default::default()
    };

    let (mut guard, action_rx) = ContainerGuardBuilder::new()
        .docker_client(docker)
        .config(config)
        .alert_receiver(alert_rx)
        .add_policy(policy_low_priority) // Add low priority first
        .add_policy(policy_high_priority) // Add high priority second
        .build()
        .unwrap();

    let mut action_rx = action_rx.unwrap();

    guard.start().await.unwrap();
    tokio::time::sleep(Duration::from_millis(100)).await;

    // Send alert that matches both policies
    alert_tx
        .send(sample_alert(Severity::High, None))
        .await
        .unwrap();

    // Should receive exactly one action (from priority=1 policy)
    let action_event = tokio::time::timeout(Duration::from_secs(1), action_rx.recv())
        .await
        .expect("timeout")
        .expect("channel closed");

    assert!(action_event.success);
    // Only one action should be executed (first match)
    let result = tokio::time::timeout(Duration::from_millis(200), action_rx.recv()).await;
    assert!(result.is_err()); // No second action

    guard.stop().await.unwrap();
}

/// Test Action channel full: What happens when action channel is full (use capacity=1)
#[tokio::test]
async fn test_action_channel_full() {
    let docker = Arc::new(mock::TestDockerClient::new());
    docker
        .add_container(sample_container("abc123", "web-server", "nginx:latest"))
        .await;

    let (alert_tx, alert_rx) = mpsc::channel(16);

    let policy = sample_policy(Severity::Medium, IsolationAction::Pause);

    let config = ContainerGuardConfig {
        enabled: true,
        auto_isolate: true,
        poll_interval_secs: 1,
        ..Default::default()
    };

    let (mut guard, action_rx) = ContainerGuardBuilder::new()
        .docker_client(docker)
        .config(config)
        .alert_receiver(alert_rx)
        .add_policy(policy)
        .action_channel_capacity(1) // Very small capacity
        .build()
        .unwrap();

    let mut action_rx = action_rx.unwrap();

    guard.start().await.unwrap();
    tokio::time::sleep(Duration::from_millis(100)).await;

    // Send multiple alerts rapidly
    for _ in 0..5 {
        alert_tx
            .send(sample_alert(Severity::High, None))
            .await
            .unwrap();
    }

    tokio::time::sleep(Duration::from_millis(200)).await;

    // Drain all available actions
    let mut action_count = 0;
    while tokio::time::timeout(Duration::from_millis(100), action_rx.recv())
        .await
        .is_ok()
    {
        action_count += 1;
    }

    // Should receive at least some actions (channel might have blocked some)
    assert!(action_count >= 1);

    guard.stop().await.unwrap();
}

/// Test Rapid start/stop cycles: Start and stop quickly multiple times
#[tokio::test]
async fn test_rapid_start_stop_cycles() {
    let docker = Arc::new(mock::TestDockerClient::new());
    let (_alert_tx, alert_rx) = mpsc::channel(16);

    let (mut guard, _action_rx) = ContainerGuardBuilder::new()
        .docker_client(docker)
        .config(ContainerGuardConfig::default())
        .alert_receiver(alert_rx)
        .build()
        .unwrap();

    // Start
    guard.start().await.unwrap();
    assert_eq!(guard.state_name(), "running");
    tokio::time::sleep(Duration::from_millis(50)).await;

    // Stop
    guard.stop().await.unwrap();
    assert_eq!(guard.state_name(), "stopped");

    // Cannot stop again (not running)
    let result = guard.stop().await;
    assert!(result.is_err());

    // Cannot restart (alert_rx consumed; must rebuild guard)
    let result = guard.start().await;
    assert!(result.is_err());
}

/// Test Failure metrics tracking: Verify isolation_failures counter after failed isolation
#[tokio::test]
async fn test_failure_metrics_tracking() {
    let docker = Arc::new(mock::TestDockerClient::new());
    docker
        .add_container(sample_container("abc123", "web-server", "nginx:latest"))
        .await;
    docker.set_fail_actions(true).await; // Make actions fail

    let (alert_tx, alert_rx) = mpsc::channel(16);

    let policy = sample_policy(Severity::Medium, IsolationAction::Stop);

    let config = ContainerGuardConfig {
        enabled: true,
        auto_isolate: true,
        poll_interval_secs: 1,
        retry_max_attempts: 0, // No retries
        ..Default::default()
    };

    let (mut guard, _action_rx) = ContainerGuardBuilder::new()
        .docker_client(docker)
        .config(config)
        .alert_receiver(alert_rx)
        .add_policy(policy)
        .build()
        .unwrap();

    assert_eq!(guard.isolation_failures(), 0);

    guard.start().await.unwrap();
    tokio::time::sleep(Duration::from_millis(100)).await;

    // Send multiple alerts
    for _ in 0..3 {
        alert_tx
            .send(sample_alert(Severity::High, None))
            .await
            .unwrap();
    }

    tokio::time::sleep(Duration::from_millis(500)).await;

    // isolation_failures should be incremented
    assert!(guard.isolation_failures() >= 3);

    guard.stop().await.unwrap();
}

/// Test Docker connection lost mid-processing: Docker works initially, then ping starts failing
#[tokio::test]
async fn test_docker_connection_lost_mid_processing() {
    let docker = Arc::new(mock::TestDockerClient::new());
    docker
        .add_container(sample_container("abc123", "web-server", "nginx:latest"))
        .await;

    let (_alert_tx, alert_rx) = mpsc::channel(16);

    let policy = sample_policy(Severity::Medium, IsolationAction::Pause);

    let config = ContainerGuardConfig {
        enabled: true,
        auto_isolate: true,
        poll_interval_secs: 1,
        ..Default::default()
    };

    let (mut guard, _action_rx) = ContainerGuardBuilder::new()
        .docker_client(Arc::clone(&docker))
        .config(config)
        .alert_receiver(alert_rx)
        .add_policy(policy)
        .build()
        .unwrap();

    guard.start().await.unwrap();
    tokio::time::sleep(Duration::from_millis(100)).await;

    // Health should be healthy
    assert!(guard.health_check().await.is_healthy());

    // Make Docker ping fail
    docker.set_ping_fails(true).await;

    tokio::time::sleep(Duration::from_millis(100)).await;

    // Health should now be degraded
    let health = guard.health_check().await;
    assert!(matches!(health, HealthStatus::Degraded(_)));

    guard.stop().await.unwrap();
}

/// Test Empty policies: Alert arrives but no policies configured (no action)
#[tokio::test]
async fn test_empty_policies_no_action() {
    let docker = Arc::new(mock::TestDockerClient::new());
    docker
        .add_container(sample_container("abc123", "web-server", "nginx:latest"))
        .await;

    let (alert_tx, alert_rx) = mpsc::channel(16);

    // No policies added

    let config = ContainerGuardConfig {
        enabled: true,
        auto_isolate: true,
        poll_interval_secs: 1,
        ..Default::default()
    };

    let (mut guard, action_rx) = ContainerGuardBuilder::new()
        .docker_client(docker)
        .config(config)
        .alert_receiver(alert_rx)
        .build()
        .unwrap();

    let mut action_rx = action_rx.unwrap();

    guard.start().await.unwrap();
    tokio::time::sleep(Duration::from_millis(100)).await;

    // Send alert
    alert_tx
        .send(sample_alert(Severity::Critical, None))
        .await
        .unwrap();

    // Should not receive action (no policies)
    let result = tokio::time::timeout(Duration::from_millis(500), action_rx.recv()).await;
    assert!(result.is_err());

    guard.stop().await.unwrap();
}

/// Test Network disconnect action through pipeline: Full flow with NetworkDisconnect action type
#[tokio::test]
async fn test_network_disconnect_action_full_flow() {
    let docker = Arc::new(mock::TestDockerClient::new());
    docker
        .add_container(sample_container("abc123", "web-server", "nginx:latest"))
        .await;

    let (alert_tx, alert_rx) = mpsc::channel(16);

    let policy = sample_policy(
        Severity::Medium,
        IsolationAction::NetworkDisconnect {
            networks: vec!["bridge".to_owned(), "custom".to_owned()],
        },
    );

    let config = ContainerGuardConfig {
        enabled: true,
        auto_isolate: true,
        poll_interval_secs: 1,
        ..Default::default()
    };

    let (mut guard, action_rx) = ContainerGuardBuilder::new()
        .docker_client(docker)
        .config(config)
        .alert_receiver(alert_rx)
        .add_policy(policy)
        .build()
        .unwrap();

    let mut action_rx = action_rx.unwrap();

    guard.start().await.unwrap();
    tokio::time::sleep(Duration::from_millis(100)).await;

    // Send alert
    alert_tx
        .send(sample_alert(Severity::High, None))
        .await
        .unwrap();

    // Should receive action event
    let action_event = tokio::time::timeout(Duration::from_secs(1), action_rx.recv())
        .await
        .expect("timeout")
        .expect("channel closed");

    assert!(action_event.success);
    assert_eq!(action_event.target, "abc123");

    guard.stop().await.unwrap();
}

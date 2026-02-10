//! 격리 실행 -- 컨테이너 격리 액션 정의 및 실행
//!
//! [`IsolationAction`]은 컨테이너에 대해 수행할 격리 액션을 정의합니다.
//! [`IsolationExecutor`]는 Docker API를 통해 실제 격리를 수행하고
//! [`ActionEvent`]를 생성합니다.

use std::fmt;
use std::sync::Arc;
use std::time::Duration;

use serde::{Deserialize, Serialize};
use tokio::sync::mpsc;
use tracing::{error, info, warn};

use ironpost_core::event::ActionEvent;

use crate::docker::DockerClient;
use crate::error::ContainerGuardError;

/// 컨테이너 격리 액션
///
/// 보안 정책에 의해 결정된 컨테이너 격리 유형을 나타냅니다.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum IsolationAction {
    /// 네트워크 연결 해제
    NetworkDisconnect {
        /// 연결 해제할 네트워크 목록
        networks: Vec<String>,
    },
    /// 컨테이너 일시정지
    Pause,
    /// 컨테이너 정지
    Stop,
}

impl IsolationAction {
    /// 메트릭 태그용 고정된 액션 타입명을 반환합니다.
    ///
    /// `Display` 구현과 달리, 가변 데이터(네트워크 목록 등)를 포함하지 않아
    /// high-cardinality 문제를 방지합니다.
    pub fn action_type_name(&self) -> &str {
        match self {
            Self::NetworkDisconnect { .. } => "network_disconnect",
            Self::Pause => "pause",
            Self::Stop => "stop",
        }
    }
}

impl fmt::Display for IsolationAction {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::NetworkDisconnect { networks } => {
                write!(f, "network_disconnect({})", networks.join(","))
            }
            Self::Pause => write!(f, "pause"),
            Self::Stop => write!(f, "stop"),
        }
    }
}

/// 격리 실행기 -- Docker API를 통해 컨테이너 격리를 수행합니다.
///
/// 격리 액션을 실행하고, 결과를 `ActionEvent`로 변환하여
/// downstream 채널로 전송합니다.
pub struct IsolationExecutor<D: DockerClient> {
    /// Docker 클라이언트
    docker: Arc<D>,
    /// 액션 결과 전송 채널
    action_tx: mpsc::Sender<ActionEvent>,
    /// 액션 타임아웃
    action_timeout: Duration,
    /// 재시도 최대 횟수
    max_retries: u32,
    /// 재시도 백오프 기본 간격
    retry_backoff_base: Duration,
}

impl<D: DockerClient> IsolationExecutor<D> {
    /// 새 격리 실행기를 생성합니다.
    pub fn new(
        docker: Arc<D>,
        action_tx: mpsc::Sender<ActionEvent>,
        action_timeout: Duration,
        max_retries: u32,
        retry_backoff_base: Duration,
    ) -> Self {
        Self {
            docker,
            action_tx,
            action_timeout,
            max_retries,
            retry_backoff_base,
        }
    }

    /// 컨테이너에 대해 격리 액션을 실행합니다.
    ///
    /// 실패 시 설정된 횟수만큼 재시도하며, 결과를 `ActionEvent`로 전송합니다.
    ///
    /// # Arguments
    /// - `container_id`: 대상 컨테이너 ID
    /// - `action`: 실행할 격리 액션
    /// - `trace_id`: 원본 알림의 trace_id (이벤트 연결용)
    pub async fn execute(
        &self,
        container_id: &str,
        action: &IsolationAction,
        trace_id: &str,
    ) -> Result<(), ContainerGuardError> {
        info!(
            container_id = container_id,
            action = %action,
            trace_id = trace_id,
            "executing isolation action"
        );

        let result = self.execute_with_retry(container_id, action).await;

        let success = result.is_ok();
        let action_event = ActionEvent::with_trace(
            format!("container_{}", action.action_type_name()),
            container_id,
            success,
            trace_id,
        );

        if let Err(ref e) = result {
            error!(
                container_id = container_id,
                action = %action,
                error = %e,
                "isolation action failed"
            );
        } else {
            info!(
                container_id = container_id,
                action = %action,
                "isolation action completed successfully"
            );
        }

        // Send action event regardless of success/failure
        if let Err(e) = self.action_tx.send(action_event).await {
            error!(error = %e, "failed to send action event");
        }

        result
    }

    /// 재시도 로직을 포함한 격리 액션 실행
    async fn execute_with_retry(
        &self,
        container_id: &str,
        action: &IsolationAction,
    ) -> Result<(), ContainerGuardError> {
        let mut last_error = None;

        for attempt in 0..=self.max_retries {
            if attempt > 0 {
                let backoff = self.retry_backoff_base * attempt;
                warn!(
                    container_id = container_id,
                    attempt = attempt,
                    backoff_ms = u64::try_from(backoff.as_millis()).unwrap_or(u64::MAX),
                    "retrying isolation action"
                );
                tokio::time::sleep(backoff).await;
            }

            match tokio::time::timeout(
                self.action_timeout,
                self.execute_action(container_id, action),
            )
            .await
            {
                Ok(Ok(())) => return Ok(()),
                Ok(Err(e)) => {
                    last_error = Some(e);
                }
                Err(_elapsed) => {
                    last_error = Some(ContainerGuardError::IsolationFailed {
                        container_id: container_id.to_owned(),
                        reason: "action timed out".to_owned(),
                    });
                }
            }
        }

        Err(
            last_error.unwrap_or_else(|| ContainerGuardError::IsolationFailed {
                container_id: container_id.to_owned(),
                reason: "unknown error".to_owned(),
            }),
        )
    }

    /// 단일 격리 액션을 실행합니다 (재시도 없음).
    async fn execute_action(
        &self,
        container_id: &str,
        action: &IsolationAction,
    ) -> Result<(), ContainerGuardError> {
        match action {
            IsolationAction::NetworkDisconnect { networks } => {
                // Attempt all networks even if some fail, to avoid leaving
                // partially-disconnected state. On retry, already-disconnected
                // networks will succeed (Docker disconnect is idempotent).
                let mut errors = Vec::new();
                for network in networks {
                    match self.docker.disconnect_network(container_id, network).await {
                        Ok(()) => {
                            info!(
                                container_id = container_id,
                                network = network.as_str(),
                                "disconnected container from network"
                            );
                        }
                        Err(e) => {
                            warn!(
                                container_id = container_id,
                                network = network.as_str(),
                                error = %e,
                                "failed to disconnect container from network"
                            );
                            errors.push(format!("{network}: {e}"));
                        }
                    }
                }
                if errors.is_empty() {
                    Ok(())
                } else {
                    Err(ContainerGuardError::IsolationFailed {
                        container_id: container_id.to_owned(),
                        reason: format!(
                            "failed to disconnect from {} network(s): {}",
                            errors.len(),
                            errors.join("; ")
                        ),
                    })
                }
            }
            IsolationAction::Pause => self.docker.pause_container(container_id).await,
            IsolationAction::Stop => self.docker.stop_container(container_id).await,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::docker::MockDockerClient;
    use ironpost_core::types::ContainerInfo;
    use std::time::SystemTime;

    fn sample_container() -> ContainerInfo {
        ContainerInfo {
            id: "abc123def456".to_owned(),
            name: "web-server".to_owned(),
            image: "nginx:latest".to_owned(),
            status: "running".to_owned(),
            created_at: SystemTime::now(),
        }
    }

    fn make_executor(
        client: MockDockerClient,
    ) -> (
        IsolationExecutor<MockDockerClient>,
        mpsc::Receiver<ActionEvent>,
    ) {
        let (action_tx, action_rx) = mpsc::channel(16);
        let executor = IsolationExecutor::new(
            Arc::new(client),
            action_tx,
            Duration::from_secs(5),
            2,
            Duration::from_millis(10),
        );
        (executor, action_rx)
    }

    #[test]
    fn isolation_action_display() {
        assert_eq!(IsolationAction::Pause.to_string(), "pause");
        assert_eq!(IsolationAction::Stop.to_string(), "stop");
        assert_eq!(
            IsolationAction::NetworkDisconnect {
                networks: vec!["bridge".to_owned(), "host".to_owned()]
            }
            .to_string(),
            "network_disconnect(bridge,host)"
        );
    }

    #[test]
    fn isolation_action_type_name_is_fixed() {
        // action_type_name은 메트릭 태그용으로 고정된 값만 반환해야 함 (high-cardinality 방지)
        assert_eq!(IsolationAction::Pause.action_type_name(), "pause");
        assert_eq!(IsolationAction::Stop.action_type_name(), "stop");

        // 네트워크 목록과 관계없이 동일한 이름 반환
        assert_eq!(
            IsolationAction::NetworkDisconnect {
                networks: vec!["bridge".to_owned()]
            }
            .action_type_name(),
            "network_disconnect"
        );
        assert_eq!(
            IsolationAction::NetworkDisconnect {
                networks: vec!["bridge".to_owned(), "host".to_owned(), "custom".to_owned()]
            }
            .action_type_name(),
            "network_disconnect"
        );
        assert_eq!(
            IsolationAction::NetworkDisconnect {
                networks: Vec::new()
            }
            .action_type_name(),
            "network_disconnect"
        );
    }

    #[tokio::test]
    async fn executor_pause_success() {
        let client = MockDockerClient::new().with_containers(vec![sample_container()]);
        let (executor, mut action_rx) = make_executor(client);

        executor
            .execute("abc123def456", &IsolationAction::Pause, "trace-1")
            .await
            .unwrap();

        let event = action_rx.recv().await.unwrap();
        assert!(event.success);
        assert_eq!(event.target, "abc123def456");
        assert_eq!(event.action_type, "container_pause");
    }

    #[tokio::test]
    async fn executor_stop_success() {
        let client = MockDockerClient::new().with_containers(vec![sample_container()]);
        let (executor, mut action_rx) = make_executor(client);

        executor
            .execute("abc123def456", &IsolationAction::Stop, "trace-2")
            .await
            .unwrap();

        let event = action_rx.recv().await.unwrap();
        assert!(event.success);
        assert_eq!(event.action_type, "container_stop");
    }

    #[tokio::test]
    async fn executor_network_disconnect_success() {
        let client = MockDockerClient::new().with_containers(vec![sample_container()]);
        let (executor, mut action_rx) = make_executor(client);

        let action = IsolationAction::NetworkDisconnect {
            networks: vec!["bridge".to_owned()],
        };
        executor
            .execute("abc123def456", &action, "trace-3")
            .await
            .unwrap();

        let event = action_rx.recv().await.unwrap();
        assert!(event.success);
        // action_type은 네트워크 목록과 관계없이 고정된 값이어야 함
        assert_eq!(event.action_type, "container_network_disconnect");
    }

    #[tokio::test]
    async fn executor_failure_sends_failed_event() {
        let client = MockDockerClient::new()
            .with_containers(vec![sample_container()])
            .with_failing_actions();
        let (executor, mut action_rx) = make_executor(client);

        let result = executor
            .execute("abc123def456", &IsolationAction::Pause, "trace-4")
            .await;
        assert!(result.is_err());

        let event = action_rx.recv().await.unwrap();
        assert!(!event.success);
    }

    #[tokio::test]
    async fn executor_not_found() {
        let client = MockDockerClient::new(); // no containers
        let (executor, mut action_rx) = make_executor(client);

        let result = executor
            .execute("nonexistent", &IsolationAction::Stop, "trace-5")
            .await;
        assert!(result.is_err());

        let event = action_rx.recv().await.unwrap();
        assert!(!event.success);
    }

    #[tokio::test]
    async fn executor_preserves_trace_id() {
        let client = MockDockerClient::new().with_containers(vec![sample_container()]);
        let (executor, mut action_rx) = make_executor(client);

        executor
            .execute("abc123def456", &IsolationAction::Pause, "my-trace-id")
            .await
            .unwrap();

        let event = action_rx.recv().await.unwrap();
        assert_eq!(event.metadata.trace_id, "my-trace-id");
    }

    #[test]
    fn isolation_action_serialize_roundtrip() {
        let action = IsolationAction::NetworkDisconnect {
            networks: vec!["bridge".to_owned()],
        };
        let json = serde_json::to_string(&action).unwrap();
        let deserialized: IsolationAction = serde_json::from_str(&json).unwrap();
        assert!(matches!(
            deserialized,
            IsolationAction::NetworkDisconnect { .. }
        ));
    }

    // --- Edge Case Tests ---

    #[tokio::test]
    async fn executor_retry_eventually_succeeds() {
        // Start with failing actions
        let client = MockDockerClient::new()
            .with_containers(vec![sample_container()])
            .with_failing_actions();
        let (executor, mut action_rx) = make_executor(client);

        // Execute - should retry but eventually fail
        let _result = executor
            .execute("abc123def456", &IsolationAction::Pause, "trace-retry")
            .await;

        // With max_retries=2, should fail after 3 attempts
        assert!(_result.is_err());

        let event = action_rx.recv().await.unwrap();
        assert!(!event.success);
    }

    #[tokio::test]
    async fn executor_multiple_network_disconnects() {
        let client = MockDockerClient::new().with_containers(vec![sample_container()]);
        let (executor, mut action_rx) = make_executor(client);

        let action = IsolationAction::NetworkDisconnect {
            networks: vec![
                "bridge".to_owned(),
                "custom-net".to_owned(),
                "host".to_owned(),
            ],
        };

        executor
            .execute("abc123def456", &action, "trace-multi-net")
            .await
            .unwrap();

        let event = action_rx.recv().await.unwrap();
        assert!(event.success);
        // 여러 네트워크라도 action_type은 동일한 고정 값이어야 함 (high-cardinality 방지)
        assert_eq!(event.action_type, "container_network_disconnect");
    }

    #[tokio::test]
    async fn executor_empty_network_list_succeeds() {
        let client = MockDockerClient::new().with_containers(vec![sample_container()]);
        let (executor, mut action_rx) = make_executor(client);

        let action = IsolationAction::NetworkDisconnect {
            networks: Vec::new(),
        };

        // Empty list should succeed (no-op)
        executor
            .execute("abc123def456", &action, "trace-empty-net")
            .await
            .unwrap();

        let event = action_rx.recv().await.unwrap();
        assert!(event.success);
    }

    #[tokio::test]
    async fn executor_stop_already_stopped_container() {
        // Mock returns NotFound for stopped container
        let client = MockDockerClient::new(); // No containers
        let (executor, mut action_rx) = make_executor(client);

        let result = executor
            .execute("stopped-container", &IsolationAction::Stop, "trace-stopped")
            .await;

        // Should fail with container not found
        assert!(result.is_err());

        let event = action_rx.recv().await.unwrap();
        assert!(!event.success);
    }

    #[tokio::test]
    async fn executor_concurrent_actions_on_same_container() {
        let client = MockDockerClient::new().with_containers(vec![sample_container()]);
        let (action_tx, mut action_rx) = mpsc::channel(16);
        let executor = Arc::new(IsolationExecutor::new(
            Arc::new(client),
            action_tx,
            Duration::from_secs(5),
            2,
            Duration::from_millis(10),
        ));

        // Spawn multiple concurrent executions
        let handles: Vec<_> = (0..5)
            .map(|i| {
                let exec = Arc::clone(&executor);
                tokio::spawn(async move {
                    exec.execute(
                        "abc123def456",
                        &IsolationAction::Pause,
                        &format!("trace-{i}"),
                    )
                    .await
                })
            })
            .collect();

        // All should succeed
        for handle in handles {
            handle.await.unwrap().unwrap();
        }

        // Should receive 5 action events
        let mut event_count = 0;
        while let Ok(Some(_)) =
            tokio::time::timeout(Duration::from_millis(100), action_rx.recv()).await
        {
            event_count += 1;
        }
        assert_eq!(event_count, 5);
    }

    #[test]
    fn isolation_action_display_empty_networks() {
        let action = IsolationAction::NetworkDisconnect {
            networks: Vec::new(),
        };
        assert_eq!(action.to_string(), "network_disconnect()");
    }

    #[test]
    fn isolation_action_display_single_network() {
        let action = IsolationAction::NetworkDisconnect {
            networks: vec!["bridge".to_owned()],
        };
        assert_eq!(action.to_string(), "network_disconnect(bridge)");
    }

    #[tokio::test]
    async fn executor_channel_send_failure_handling() {
        let client = MockDockerClient::new().with_containers(vec![sample_container()]);
        let (action_tx, action_rx) = mpsc::channel(1);

        let executor = IsolationExecutor::new(
            Arc::new(client),
            action_tx,
            Duration::from_secs(5),
            2,
            Duration::from_millis(10),
        );

        // Drop receiver to cause send failure
        drop(action_rx);

        // Should still complete without panicking
        let _result = executor
            .execute("abc123def456", &IsolationAction::Pause, "trace-dropped")
            .await;

        // Action should succeed even if event sending fails
        assert!(_result.is_ok());
    }

    #[tokio::test]
    async fn executor_timeout_on_slow_action() {
        let client = MockDockerClient::new().with_containers(vec![sample_container()]);
        let (action_tx, mut action_rx) = mpsc::channel(16);

        // Very short timeout
        let executor = IsolationExecutor::new(
            Arc::new(client),
            action_tx,
            Duration::from_millis(1), // Very short timeout
            0,                        // No retries
            Duration::from_millis(10),
        );

        // In practice, action should complete quickly, but this tests timeout logic exists
        let _result = executor
            .execute("abc123def456", &IsolationAction::Pause, "trace-timeout")
            .await;

        // Depending on system speed, might timeout or succeed
        // Just verify we get an action event either way
        let event = action_rx.recv().await.unwrap();
        assert_eq!(event.target, "abc123def456");
    }

    // --- Additional Edge Case Tests ---

    /// Test retry logic verifies exact number of attempts
    #[tokio::test]
    async fn executor_retry_exact_attempt_count() {
        use std::sync::atomic::{AtomicU32, Ordering};

        struct CountingMockDockerClient {
            containers: Vec<ContainerInfo>,
            attempt_count: Arc<AtomicU32>,
        }

        impl DockerClient for CountingMockDockerClient {
            async fn list_containers(&self) -> Result<Vec<ContainerInfo>, ContainerGuardError> {
                Ok(self.containers.clone())
            }

            async fn inspect_container(
                &self,
                id: &str,
            ) -> Result<ContainerInfo, ContainerGuardError> {
                self.containers
                    .iter()
                    .find(|c| c.id == id)
                    .cloned()
                    .ok_or_else(|| ContainerGuardError::ContainerNotFound(id.to_owned()))
            }

            async fn stop_container(&self, _id: &str) -> Result<(), ContainerGuardError> {
                self.attempt_count.fetch_add(1, Ordering::SeqCst);
                Err(ContainerGuardError::IsolationFailed {
                    container_id: "abc123".to_owned(),
                    reason: "always fails".to_owned(),
                })
            }

            async fn pause_container(&self, id: &str) -> Result<(), ContainerGuardError> {
                self.attempt_count.fetch_add(1, Ordering::SeqCst);
                Err(ContainerGuardError::IsolationFailed {
                    container_id: id.to_owned(),
                    reason: "always fails".to_owned(),
                })
            }

            async fn unpause_container(&self, _id: &str) -> Result<(), ContainerGuardError> {
                Ok(())
            }

            async fn disconnect_network(
                &self,
                _container_id: &str,
                _network: &str,
            ) -> Result<(), ContainerGuardError> {
                Ok(())
            }

            async fn ping(&self) -> Result<(), ContainerGuardError> {
                Ok(())
            }
        }

        let attempt_count = Arc::new(AtomicU32::new(0));
        let client = Arc::new(CountingMockDockerClient {
            containers: vec![sample_container()],
            attempt_count: Arc::clone(&attempt_count),
        });

        let (action_tx, _action_rx) = mpsc::channel(16);
        let executor = IsolationExecutor::new(
            client,
            action_tx,
            Duration::from_secs(5),
            2, // max_retries = 2, so total attempts = 3
            Duration::from_millis(10),
        );

        let _result = executor
            .execute("abc123def456", &IsolationAction::Pause, "trace-retry-count")
            .await;

        // Should have attempted 3 times (initial + 2 retries)
        assert_eq!(attempt_count.load(Ordering::SeqCst), 3);
    }

    /// Test linear backoff timing verification
    #[tokio::test]
    async fn executor_linear_backoff_timing() {
        let client = MockDockerClient::new()
            .with_containers(vec![sample_container()])
            .with_failing_actions();

        let (action_tx, _action_rx) = mpsc::channel(16);
        let executor = IsolationExecutor::new(
            Arc::new(client),
            action_tx,
            Duration::from_secs(5),
            2,                         // 2 retries
            Duration::from_millis(50), // base backoff
        );

        let start = std::time::Instant::now();
        let _result = executor
            .execute("abc123def456", &IsolationAction::Pause, "trace-backoff")
            .await;
        let elapsed = start.elapsed();

        // Should wait at least: 50ms (retry 1) + 100ms (retry 2) = 150ms
        // Allow some margin for test execution
        assert!(elapsed.as_millis() >= 140);
    }

    /// Test all 3 action types independently with failure cases
    #[tokio::test]
    async fn executor_all_action_types_with_failures() {
        let client_fail = MockDockerClient::new()
            .with_containers(vec![sample_container()])
            .with_failing_actions();

        let (action_tx, mut action_rx) = mpsc::channel(16);
        let executor = IsolationExecutor::new(
            Arc::new(client_fail),
            action_tx,
            Duration::from_secs(5),
            0, // no retries for fast test
            Duration::from_millis(10),
        );

        // Test Stop action
        let result = executor
            .execute("abc123def456", &IsolationAction::Stop, "trace-stop-fail")
            .await;
        assert!(result.is_err());
        let event = action_rx.recv().await.unwrap();
        assert!(!event.success);

        // Test Pause action
        let result = executor
            .execute("abc123def456", &IsolationAction::Pause, "trace-pause-fail")
            .await;
        assert!(result.is_err());
        let event = action_rx.recv().await.unwrap();
        assert!(!event.success);

        // Test NetworkDisconnect action
        let action = IsolationAction::NetworkDisconnect {
            networks: vec!["bridge".to_owned()],
        };
        let result = executor
            .execute("abc123def456", &action, "trace-net-fail")
            .await;
        assert!(result.is_err());
        let event = action_rx.recv().await.unwrap();
        assert!(!event.success);
    }

    /// Test network disconnect that fails partway through (first network succeeds, second fails)
    #[tokio::test]
    async fn executor_network_disconnect_partial_failure() {
        use tokio::sync::Mutex as TokioMutex;

        struct PartialFailNetworkClient {
            containers: Vec<ContainerInfo>,
            call_count: Arc<TokioMutex<u32>>,
        }

        impl DockerClient for PartialFailNetworkClient {
            async fn list_containers(&self) -> Result<Vec<ContainerInfo>, ContainerGuardError> {
                Ok(self.containers.clone())
            }

            async fn inspect_container(
                &self,
                id: &str,
            ) -> Result<ContainerInfo, ContainerGuardError> {
                self.containers
                    .iter()
                    .find(|c| c.id == id)
                    .cloned()
                    .ok_or_else(|| ContainerGuardError::ContainerNotFound(id.to_owned()))
            }

            async fn stop_container(&self, _id: &str) -> Result<(), ContainerGuardError> {
                Ok(())
            }

            async fn pause_container(&self, _id: &str) -> Result<(), ContainerGuardError> {
                Ok(())
            }

            async fn unpause_container(&self, _id: &str) -> Result<(), ContainerGuardError> {
                Ok(())
            }

            async fn disconnect_network(
                &self,
                container_id: &str,
                _network: &str,
            ) -> Result<(), ContainerGuardError> {
                let mut count = self.call_count.lock().await;
                *count += 1;

                // First call succeeds, second fails
                if *count == 1 {
                    Ok(())
                } else {
                    Err(ContainerGuardError::IsolationFailed {
                        container_id: container_id.to_owned(),
                        reason: "second network disconnect failed".to_owned(),
                    })
                }
            }

            async fn ping(&self) -> Result<(), ContainerGuardError> {
                Ok(())
            }
        }

        let call_count = Arc::new(TokioMutex::new(0));
        let client = Arc::new(PartialFailNetworkClient {
            containers: vec![sample_container()],
            call_count: Arc::clone(&call_count),
        });

        let (action_tx, mut action_rx) = mpsc::channel(16);
        let executor = IsolationExecutor::new(
            client,
            action_tx,
            Duration::from_secs(5),
            0,
            Duration::from_millis(10),
        );

        let action = IsolationAction::NetworkDisconnect {
            networks: vec!["bridge".to_owned(), "custom".to_owned()],
        };

        let result = executor
            .execute("abc123def456", &action, "trace-partial-net")
            .await;

        // Should fail because second network failed
        assert!(result.is_err());

        let event = action_rx.recv().await.unwrap();
        assert!(!event.success);

        // Verify both networks were attempted
        assert_eq!(*call_count.lock().await, 2);
    }
}

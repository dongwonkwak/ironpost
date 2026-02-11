//! 컨테이너 가드 오케스트레이터 -- 알림 수신/정책 평가/격리 실행 전체 흐름 관리
//!
//! [`ContainerGuard`]는 core의 [`Pipeline`] trait을 구현하여
//! `ironpost-daemon`에서 다른 모듈과 동일한 생명주기로 관리됩니다.
//!
//! # 내부 아키텍처
//! ```text
//! AlertEvent ──mpsc──> ContainerGuard
//!                          |
//!                     PolicyEngine.evaluate()
//!                          |
//!                     IsolationExecutor.execute()
//!                          |
//!                     ActionEvent ──mpsc──> downstream
//! ```

use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;

use tokio::sync::{Mutex, mpsc};
use tracing::{debug, error, info, warn};

use ironpost_core::error::IronpostError;
use ironpost_core::event::{ActionEvent, AlertEvent};
use ironpost_core::pipeline::{HealthStatus, Pipeline};

use crate::config::ContainerGuardConfig;
use crate::docker::DockerClient;
use crate::error::ContainerGuardError;
use crate::isolation::IsolationExecutor;
use crate::monitor::DockerMonitor;
use crate::policy::PolicyEngine;

/// 가드 실행 상태
#[derive(Debug, Clone, PartialEq, Eq)]
enum GuardState {
    /// 초기화됨, 아직 시작하지 않음
    Initialized,
    /// 실행 중
    Running,
    /// 정지됨
    Stopped,
}

/// 컨테이너 가드 -- 알림 수신, 정책 평가, 격리 실행의 전체 흐름을 관리합니다.
///
/// core의 `Pipeline` trait을 구현하여 `ironpost-daemon`에서
/// 다른 모듈과 동일한 생명주기(start/stop/health_check)로 관리됩니다.
///
/// # 사용 예시
/// ```ignore
/// use ironpost_container_guard::{ContainerGuard, ContainerGuardBuilder};
///
/// let (guard, action_rx) = ContainerGuardBuilder::new()
///     .config(config)
///     .alert_receiver(alert_rx)  // from log-pipeline
///     .build()?;
///
/// // Pipeline trait으로 시작
/// guard.start().await?;
/// ```
pub struct ContainerGuard<D: DockerClient> {
    /// 가드 설정
    config: ContainerGuardConfig,
    /// 현재 상태
    state: GuardState,
    /// Docker 클라이언트 (공유)
    docker: Arc<D>,
    /// 정책 엔진 (공유, 런타임 변경 반영)
    policy_engine: Arc<Mutex<PolicyEngine>>,
    /// Docker 모니터 (가드와 처리 태스크가 공유)
    monitor: Arc<Mutex<DockerMonitor<D>>>,
    /// 알림 수신 채널
    alert_rx: Option<mpsc::Receiver<AlertEvent>>,
    /// 액션 전송 채널
    action_tx: mpsc::Sender<ActionEvent>,
    /// 백그라운드 태스크 핸들
    tasks: Vec<tokio::task::JoinHandle<()>>,
    /// 처리된 알림 카운터
    alerts_processed: Arc<AtomicU64>,
    /// 실행된 격리 카운터
    isolations_executed: Arc<AtomicU64>,
    /// 격리 실패 카운터
    isolation_failures: Arc<AtomicU64>,
}

impl<D: DockerClient> ContainerGuard<D> {
    /// 현재 상태명을 반환합니다.
    pub fn state_name(&self) -> &str {
        match self.state {
            GuardState::Initialized => "initialized",
            GuardState::Running => "running",
            GuardState::Stopped => "stopped",
        }
    }

    /// 처리된 알림 수를 반환합니다.
    pub fn alerts_processed(&self) -> u64 {
        self.alerts_processed.load(Ordering::Relaxed)
    }

    /// 실행된 격리 수를 반환합니다.
    pub fn isolations_executed(&self) -> u64 {
        self.isolations_executed.load(Ordering::Relaxed)
    }

    /// 격리 실패 수를 반환합니다.
    pub fn isolation_failures(&self) -> u64 {
        self.isolation_failures.load(Ordering::Relaxed)
    }

    /// 등록된 정책 수를 반환합니다.
    pub async fn policy_count(&self) -> usize {
        self.policy_engine.lock().await.policy_count()
    }

    /// 캐시된 컨테이너 수를 반환합니다.
    pub async fn container_count(&self) -> usize {
        self.monitor.lock().await.container_count()
    }

    /// 정책 엔진에 대한 Arc 참조를 반환합니다.
    ///
    /// 정책을 동적으로 추가/제거할 때 사용합니다.
    /// 런타임 중 정책 변경이 실행 중인 태스크에도 반영됩니다.
    pub fn policy_engine_arc(&self) -> Arc<Mutex<PolicyEngine>> {
        Arc::clone(&self.policy_engine)
    }

    /// 설정의 auto_isolate 여부를 반환합니다.
    pub fn auto_isolate_enabled(&self) -> bool {
        self.config.auto_isolate
    }
}

impl<D: DockerClient> Pipeline for ContainerGuard<D> {
    async fn start(&mut self) -> Result<(), IronpostError> {
        if self.state == GuardState::Running {
            return Err(ironpost_core::error::PipelineError::AlreadyRunning.into());
        }

        info!("starting container guard");

        // 1. Docker 연결 확인
        if self.docker.ping().await.is_err() {
            warn!("docker daemon not available, container guard will run in degraded mode");
        }

        // 2. 초기 컨테이너 목록 새로고침
        match self.monitor.lock().await.refresh().await {
            Ok(count) => {
                info!(containers = count, "initial container inventory loaded");
            }
            Err(e) => {
                warn!(error = %e, "failed to load initial container inventory, will retry");
            }
        }

        // 3. 알림 처리 루프 스폰
        let mut alert_rx = self.alert_rx.take().ok_or(IronpostError::Pipeline(
            ironpost_core::error::PipelineError::InitFailed(
                "alert receiver not available (was it consumed by a previous start? rebuild the guard to restart)".to_owned(),
            ),
        ))?;

        let docker = Arc::clone(&self.docker);
        let action_tx = self.action_tx.clone();
        let alerts_processed = Arc::clone(&self.alerts_processed);
        let isolations_executed = Arc::clone(&self.isolations_executed);
        let isolation_failures = Arc::clone(&self.isolation_failures);
        let auto_isolate = self.config.auto_isolate;
        let action_timeout = Duration::from_secs(self.config.action_timeout_secs);
        let retry_max = self.config.retry_max_attempts;
        let retry_backoff = Duration::from_millis(self.config.retry_backoff_base_ms);

        // Share policy engine and monitor with spawned task
        let policy_engine = Arc::clone(&self.policy_engine);
        let monitor = Arc::clone(&self.monitor);

        let processing_task = tokio::spawn(async move {
            let executor = IsolationExecutor::new(
                Arc::clone(&docker),
                action_tx.clone(),
                action_timeout,
                retry_max,
                retry_backoff,
            );

            loop {
                tokio::select! {
                    Some(alert) = alert_rx.recv() => {
                        alerts_processed.fetch_add(1, Ordering::Relaxed);
                        debug!(
                            alert_id = %alert.alert.id,
                            severity = %alert.severity,
                            "received alert event"
                        );

                        if !auto_isolate {
                            debug!("auto_isolate disabled, skipping isolation");
                            continue;
                        }

                        // Refresh and snapshot containers under the lock, then release
                        let containers: Vec<_> = {
                            let mut mon = monitor.lock().await;
                            if let Err(e) = mon.refresh_if_needed().await {
                                warn!(error = %e, "failed to refresh container list");
                            }
                            mon.all_containers().into_iter().cloned().collect()
                        };

                        // Evaluate policies for all containers using a single snapshot/lock
                        let engine = policy_engine.lock().await;

                        for container in &containers {
                            if let Some(policy_match) = engine.evaluate(&alert, container) {
                                info!(
                                    container_id = %container.id,
                                    container_name = %container.name,
                                    policy = %policy_match.policy_name,
                                    action = %policy_match.action,
                                    "policy matched, executing isolation"
                                );

                                let trace_id = alert.metadata.trace_id.clone();
                                match executor
                                    .execute(
                                        &container.id,
                                        &policy_match.action,
                                        &trace_id,
                                    )
                                    .await
                                {
                                    Ok(()) => {
                                        isolations_executed.fetch_add(1, Ordering::Relaxed);
                                    }
                                    Err(e) => {
                                        isolation_failures.fetch_add(1, Ordering::Relaxed);
                                        error!(
                                            container_id = %container.id,
                                            error = %e,
                                            "isolation execution failed"
                                        );
                                    }
                                }
                                break; // Only apply first matching policy
                            }
                        }
                    }
                    else => {
                        info!("alert channel closed, stopping guard processing loop");
                        break;
                    }
                }
            }
        });

        self.tasks.push(processing_task);
        self.state = GuardState::Running;
        info!("container guard started");
        Ok(())
    }

    async fn stop(&mut self) -> Result<(), IronpostError> {
        if self.state != GuardState::Running {
            return Err(ironpost_core::error::PipelineError::NotRunning.into());
        }

        info!("stopping container guard");

        // Abort tasks and wait
        for task in self.tasks.drain(..) {
            task.abort();
            let _ = task.await;
        }

        // alert_rx가 이미 None이므로 start() 재호출 시 명시적 에러를 반환하게 됨
        // restart를 위해서는 ContainerGuardBuilder로 새 인스턴스를 생성해야 함
        // (alert_rx는 start()에서 이미 소비되었음)

        self.state = GuardState::Stopped;
        info!("container guard stopped");
        Ok(())
    }

    async fn health_check(&self) -> HealthStatus {
        match self.state {
            GuardState::Running => {
                if self.docker.ping().await.is_ok() {
                    HealthStatus::Healthy
                } else {
                    HealthStatus::Degraded("docker daemon not reachable".to_owned())
                }
            }
            GuardState::Initialized => HealthStatus::Unhealthy("not started".to_owned()),
            GuardState::Stopped => HealthStatus::Unhealthy("stopped".to_owned()),
        }
    }
}

/// 컨테이너 가드 빌더
///
/// 가드를 구성하고 필요한 채널을 생성합니다.
pub struct ContainerGuardBuilder<D: DockerClient> {
    config: ContainerGuardConfig,
    docker: Option<Arc<D>>,
    alert_rx: Option<mpsc::Receiver<AlertEvent>>,
    action_tx: Option<mpsc::Sender<ActionEvent>>,
    action_channel_capacity: usize,
    policies: Vec<crate::policy::SecurityPolicy>,
}

impl<D: DockerClient> ContainerGuardBuilder<D> {
    /// 새 빌더를 생성합니다.
    pub fn new() -> Self {
        Self {
            config: ContainerGuardConfig::default(),
            docker: None,
            alert_rx: None,
            action_tx: None,
            action_channel_capacity: 256,
            policies: Vec::new(),
        }
    }

    /// 가드 설정을 지정합니다.
    pub fn config(mut self, config: ContainerGuardConfig) -> Self {
        self.config = config;
        self
    }

    /// Docker 클라이언트를 설정합니다.
    pub fn docker_client(mut self, docker: Arc<D>) -> Self {
        self.docker = Some(docker);
        self
    }

    /// 알림 수신 채널을 설정합니다.
    ///
    /// `ironpost-daemon`에서 log-pipeline의 알림 출력 채널을 여기에 연결합니다.
    pub fn alert_receiver(mut self, rx: mpsc::Receiver<AlertEvent>) -> Self {
        self.alert_rx = Some(rx);
        self
    }

    /// 외부 액션 전송 채널을 설정합니다.
    ///
    /// 설정하지 않으면 빌더가 새 채널을 생성합니다.
    pub fn action_sender(mut self, tx: mpsc::Sender<ActionEvent>) -> Self {
        self.action_tx = Some(tx);
        self
    }

    /// 액션 채널 용량을 설정합니다 (외부 채널 미사용 시).
    pub fn action_channel_capacity(mut self, capacity: usize) -> Self {
        self.action_channel_capacity = capacity;
        self
    }

    /// 초기 보안 정책을 추가합니다.
    pub fn add_policy(mut self, policy: crate::policy::SecurityPolicy) -> Self {
        self.policies.push(policy);
        self
    }

    /// 가드를 빌드합니다.
    ///
    /// # Returns
    /// - `ContainerGuard`: 가드 인스턴스
    /// - `Option<mpsc::Receiver<ActionEvent>>`: 액션 수신 채널
    ///   (외부 action_sender를 설정한 경우 None)
    pub fn build(
        self,
    ) -> Result<(ContainerGuard<D>, Option<mpsc::Receiver<ActionEvent>>), ContainerGuardError> {
        self.config.validate()?;

        let docker = self.docker.ok_or_else(|| ContainerGuardError::Config {
            field: "docker_client".to_owned(),
            reason: "docker client must be provided".to_owned(),
        })?;

        let (action_tx, action_rx) = if let Some(tx) = self.action_tx {
            (tx, None)
        } else {
            let (tx, rx) = mpsc::channel(self.action_channel_capacity);
            (tx, Some(rx))
        };

        let mut policy_engine_inner = PolicyEngine::new();
        for policy in self.policies {
            policy_engine_inner.add_policy(policy)?;
        }
        let policy_engine = Arc::new(Mutex::new(policy_engine_inner));

        let poll_interval = Duration::from_secs(self.config.poll_interval_secs);
        let cache_ttl = Duration::from_secs(self.config.container_cache_ttl_secs);
        let monitor = Arc::new(Mutex::new(DockerMonitor::new(
            Arc::clone(&docker),
            poll_interval,
            cache_ttl,
        )));

        let guard = ContainerGuard {
            config: self.config,
            state: GuardState::Initialized,
            docker,
            policy_engine,
            monitor,
            alert_rx: self.alert_rx,
            action_tx,
            tasks: Vec::new(),
            alerts_processed: Arc::new(AtomicU64::new(0)),
            isolations_executed: Arc::new(AtomicU64::new(0)),
            isolation_failures: Arc::new(AtomicU64::new(0)),
        };

        Ok((guard, action_rx))
    }
}

impl<D: DockerClient> Default for ContainerGuardBuilder<D> {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::docker::MockDockerClient;
    use crate::isolation::IsolationAction;
    use crate::policy::{SecurityPolicy, TargetFilter};
    use ironpost_core::event::AlertEvent;
    use ironpost_core::types::{ContainerInfo, Severity};
    use std::time::SystemTime;

    fn make_builder() -> ContainerGuardBuilder<MockDockerClient> {
        let client = Arc::new(MockDockerClient::new());
        ContainerGuardBuilder::new().docker_client(client)
    }

    fn sample_policy() -> SecurityPolicy {
        SecurityPolicy {
            id: "test-policy".to_owned(),
            name: "Test Policy".to_owned(),
            description: "Test".to_owned(),
            enabled: true,
            severity_threshold: Severity::High,
            target_filter: TargetFilter::default(),
            action: IsolationAction::Pause,
            priority: 1,
        }
    }

    #[test]
    fn builder_creates_guard() {
        let (guard, action_rx) = make_builder().build().unwrap();
        assert_eq!(guard.state_name(), "initialized");
        assert!(action_rx.is_some());
    }

    #[test]
    fn builder_with_external_action_sender() {
        let (action_tx, _action_rx) = mpsc::channel(10);
        let (_guard, rx) = make_builder().action_sender(action_tx).build().unwrap();
        assert!(rx.is_none());
    }

    #[tokio::test]
    async fn builder_with_policies() {
        let (guard, _) = make_builder().add_policy(sample_policy()).build().unwrap();
        assert_eq!(guard.policy_count().await, 1);
    }

    #[test]
    fn builder_rejects_no_docker_client() {
        let result: Result<(ContainerGuard<MockDockerClient>, _), _> =
            ContainerGuardBuilder::new().build();
        assert!(result.is_err());
    }

    #[test]
    fn builder_rejects_invalid_config() {
        let client = Arc::new(MockDockerClient::new());
        let result = ContainerGuardBuilder::new()
            .docker_client(client)
            .config(ContainerGuardConfig {
                poll_interval_secs: 0, // invalid
                ..Default::default()
            })
            .build();
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn guard_lifecycle_health_check() {
        let (guard, _) = make_builder().build().unwrap();
        // Before start
        assert!(guard.health_check().await.is_unhealthy());
    }

    #[tokio::test]
    async fn guard_double_stop_fails() {
        let (mut guard, _) = make_builder().build().unwrap();
        let err = guard.stop().await;
        assert!(err.is_err());
    }

    #[tokio::test]
    async fn guard_accessors() {
        let (guard, _) = make_builder().add_policy(sample_policy()).build().unwrap();
        assert_eq!(guard.alerts_processed(), 0);
        assert_eq!(guard.isolations_executed(), 0);
        assert_eq!(guard.isolation_failures(), 0);
        assert_eq!(guard.policy_count().await, 1);
        assert_eq!(guard.container_count().await, 0);
        assert!(!guard.auto_isolate_enabled());
    }

    #[tokio::test]
    async fn guard_policy_engine_access() {
        let (guard, _) = make_builder().build().unwrap();
        guard
            .policy_engine_arc()
            .lock()
            .await
            .add_policy(sample_policy())
            .unwrap();
        assert_eq!(guard.policy_count().await, 1);
    }

    #[tokio::test]
    async fn guard_start_stop_lifecycle() {
        let (alert_tx, alert_rx) = mpsc::channel(16);
        let client = Arc::new(MockDockerClient::new());

        let (mut guard, _) = ContainerGuardBuilder::new()
            .docker_client(client)
            .alert_receiver(alert_rx)
            .build()
            .unwrap();

        // Start should succeed
        guard.start().await.unwrap();
        assert_eq!(guard.state_name(), "running");

        // Double start should fail
        let err = guard.start().await;
        assert!(err.is_err());

        // Stop
        guard.stop().await.unwrap();
        assert_eq!(guard.state_name(), "stopped");

        // Restart after stop should fail with InitFailed (alert_rx consumed)
        let err = guard.start().await;
        assert!(err.is_err());
        let err_msg = format!("{err:?}");
        assert!(err_msg.contains("alert receiver not available"));

        // Clean up
        drop(alert_tx);
    }

    #[tokio::test]
    async fn guard_start_without_alert_rx_returns_init_failed() {
        let client = Arc::new(MockDockerClient::new());

        let (mut guard, _) = ContainerGuardBuilder::new()
            .docker_client(client)
            .build()
            .unwrap();

        // Start without alert_rx should fail with InitFailed
        let err = guard.start().await;
        assert!(err.is_err());
        let err_msg = format!("{err:?}");
        assert!(err_msg.contains("alert receiver not available"));
    }

    // --- Additional Edge Case Tests ---

    /// Test Guard start with Docker ping failing (degraded mode)
    #[tokio::test]
    async fn guard_start_with_docker_ping_failing() {
        use tokio::sync::Mutex as TokioMutex;

        struct FailingPingDockerClient {
            ping_fails: Arc<TokioMutex<bool>>,
        }

        impl crate::docker::DockerClient for FailingPingDockerClient {
            async fn list_containers(
                &self,
            ) -> Result<Vec<ironpost_core::types::ContainerInfo>, ContainerGuardError> {
                Ok(Vec::new())
            }

            async fn inspect_container(
                &self,
                id: &str,
            ) -> Result<ironpost_core::types::ContainerInfo, ContainerGuardError> {
                Err(ContainerGuardError::ContainerNotFound(id.to_owned()))
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
                _container_id: &str,
                _network: &str,
            ) -> Result<(), ContainerGuardError> {
                Ok(())
            }

            async fn ping(&self) -> Result<(), ContainerGuardError> {
                if *self.ping_fails.lock().await {
                    Err(ContainerGuardError::DockerConnection(
                        "ping failed".to_owned(),
                    ))
                } else {
                    Ok(())
                }
            }
        }

        let client = Arc::new(FailingPingDockerClient {
            ping_fails: Arc::new(TokioMutex::new(true)),
        });

        let (_alert_tx, alert_rx) = mpsc::channel(16);

        let (mut guard, _) = ContainerGuardBuilder::new()
            .docker_client(client)
            .alert_receiver(alert_rx)
            .build()
            .unwrap();

        // Should start successfully in degraded mode
        let result = guard.start().await;
        assert!(result.is_ok());
        assert_eq!(guard.state_name(), "running");

        guard.stop().await.unwrap();
    }

    /// Test Guard with multiple policies of different priorities
    #[tokio::test]
    async fn guard_with_multiple_policy_priorities() {
        let client = Arc::new(MockDockerClient::new());
        let (_alert_tx, alert_rx) = mpsc::channel(16);

        let policy1 = SecurityPolicy {
            id: "high-priority".to_owned(),
            name: "High Priority".to_owned(),
            description: "Test".to_owned(),
            enabled: true,
            severity_threshold: Severity::Medium,
            target_filter: TargetFilter::default(),
            action: IsolationAction::Pause,
            priority: 1,
        };

        let policy2 = SecurityPolicy {
            id: "low-priority".to_owned(),
            name: "Low Priority".to_owned(),
            description: "Test".to_owned(),
            enabled: true,
            severity_threshold: Severity::Medium,
            target_filter: TargetFilter::default(),
            action: IsolationAction::Stop,
            priority: 10,
        };

        let (guard, _) = ContainerGuardBuilder::new()
            .docker_client(client)
            .alert_receiver(alert_rx)
            .add_policy(policy2) // Add low priority first
            .add_policy(policy1) // Add high priority second
            .build()
            .unwrap();

        // Policies should be sorted by priority
        let policies = guard.policy_engine_arc().lock().await.policies().to_vec();
        assert_eq!(policies.len(), 2);
        assert_eq!(policies[0].priority, 1); // High priority first
        assert_eq!(policies[1].priority, 10);
    }

    /// Test metrics tracking for isolation_failures counter
    #[tokio::test]
    async fn guard_metrics_isolation_failures() {
        let client = Arc::new(
            MockDockerClient::new()
                .with_containers(vec![ContainerInfo {
                    id: "abc123".to_owned(),
                    name: "web".to_owned(),
                    image: "nginx:latest".to_owned(),
                    status: "running".to_owned(),
                    created_at: SystemTime::now(),
                }])
                .with_failing_actions(),
        );

        let (alert_tx, alert_rx) = mpsc::channel(16);

        let policy = SecurityPolicy {
            id: "test-policy".to_owned(),
            name: "Test Policy".to_owned(),
            description: "Test".to_owned(),
            enabled: true,
            severity_threshold: Severity::Medium,
            target_filter: TargetFilter::default(),
            action: IsolationAction::Pause,
            priority: 1,
        };

        let config = ContainerGuardConfig {
            enabled: true,
            auto_isolate: true,
            poll_interval_secs: 1,
            retry_max_attempts: 0, // No retries for fast test
            ..Default::default()
        };

        let (mut guard, _action_rx) = ContainerGuardBuilder::new()
            .docker_client(client)
            .config(config)
            .alert_receiver(alert_rx)
            .add_policy(policy)
            .build()
            .unwrap();

        assert_eq!(guard.isolation_failures(), 0);

        guard.start().await.unwrap();
        tokio::time::sleep(Duration::from_millis(100)).await;

        // Send alert that will trigger isolation (which will fail)
        let alert = AlertEvent::new(
            ironpost_core::types::Alert {
                id: "alert-1".to_owned(),
                title: "Test".to_owned(),
                description: "Test".to_owned(),
                severity: Severity::High,
                rule_name: "test".to_owned(),
                source_ip: None,
                target_ip: None,
                created_at: SystemTime::now(),
            },
            Severity::High,
        );
        alert_tx.send(alert).await.unwrap();

        tokio::time::sleep(Duration::from_millis(500)).await;

        // isolation_failures should be incremented
        assert!(guard.isolation_failures() >= 1);

        guard.stop().await.unwrap();
    }

    /// Test state transitions: Initialized -> Running -> Stopped
    #[tokio::test]
    async fn guard_state_transitions() {
        let client = Arc::new(MockDockerClient::new());
        let (_alert_tx, alert_rx) = mpsc::channel(16);

        let (mut guard, _) = ContainerGuardBuilder::new()
            .docker_client(client)
            .alert_receiver(alert_rx)
            .build()
            .unwrap();

        // Initial state
        assert_eq!(guard.state_name(), "initialized");

        // Start
        guard.start().await.unwrap();
        assert_eq!(guard.state_name(), "running");

        // Cannot start again
        assert!(guard.start().await.is_err());
        assert_eq!(guard.state_name(), "running");

        // Stop
        guard.stop().await.unwrap();
        assert_eq!(guard.state_name(), "stopped");

        // Cannot stop again
        assert!(guard.stop().await.is_err());
        assert_eq!(guard.state_name(), "stopped");
    }
}

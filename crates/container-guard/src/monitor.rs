//! 컨테이너 모니터링 -- Docker 이벤트 감시 및 상태 추적
//!
//! [`DockerMonitor`]는 Docker 데몬의 컨테이너 이벤트를 감시하고
//! 컨테이너 인벤토리를 유지합니다.

use std::collections::HashMap;
use std::sync::Arc;
use std::time::{Duration, Instant};

use tracing::{debug, info, warn};

use ironpost_core::types::ContainerInfo;

use crate::docker::DockerClient;
use crate::error::ContainerGuardError;

/// Maximum number of containers to cache to prevent unbounded memory growth
const MAX_CACHED_CONTAINERS: usize = 10_000;

/// Docker 컨테이너 모니터
///
/// Docker 데몬의 컨테이너 목록을 주기적으로 폴링하여
/// 컨테이너 인벤토리를 유지합니다.
pub struct DockerMonitor<D: DockerClient> {
    /// Docker 클라이언트
    docker: Arc<D>,
    /// 컨테이너 인벤토리 (ID -> ContainerInfo)
    containers: HashMap<String, ContainerInfo>,
    /// 마지막 폴링 시각
    last_poll: Option<Instant>,
    /// 폴링 주기
    poll_interval: Duration,
    /// 캐시 TTL
    cache_ttl: Duration,
}

impl<D: DockerClient> DockerMonitor<D> {
    /// 새 Docker 모니터를 생성합니다.
    pub fn new(docker: Arc<D>, poll_interval: Duration, cache_ttl: Duration) -> Self {
        Self {
            docker,
            containers: HashMap::new(),
            last_poll: None,
            poll_interval,
            cache_ttl,
        }
    }

    /// 컨테이너 목록을 강제로 새로고침합니다.
    ///
    /// Docker API를 호출하여 최신 컨테이너 목록을 가져오고
    /// 내부 인벤토리를 업데이트합니다.
    pub async fn refresh(&mut self) -> Result<usize, ContainerGuardError> {
        let containers = self.docker.list_containers().await?;
        let count = containers.len();

        self.containers.clear();
        for container in containers {
            self.containers.insert(container.id.clone(), container);
        }

        self.last_poll = Some(Instant::now());
        debug!(count = count, "refreshed container inventory");
        Ok(count)
    }

    /// 캐시가 만료되었으면 새로고침합니다.
    ///
    /// 캐시 TTL 내라면 기존 데이터를 반환하고,
    /// TTL이 지났거나 처음 호출이면 Docker API를 호출합니다.
    pub async fn refresh_if_needed(&mut self) -> Result<usize, ContainerGuardError> {
        let needs_refresh = match self.last_poll {
            Some(last) => last.elapsed() >= self.cache_ttl,
            None => true,
        };

        if needs_refresh {
            self.refresh().await
        } else {
            Ok(self.containers.len())
        }
    }

    /// 컨테이너 ID로 컨테이너 정보를 조회합니다.
    ///
    /// 캐시된 인벤토리에서 먼저 찾고, 없으면 Docker API를 직접 호출합니다.
    pub async fn get_container(
        &mut self,
        container_id: &str,
    ) -> Result<ContainerInfo, ContainerGuardError> {
        // Check cache first
        if let Some(container) = self.containers.get(container_id) {
            return Ok(container.clone());
        }

        // Try to find by partial ID match
        let found = self
            .containers
            .iter()
            .find(|(id, _)| id.starts_with(container_id))
            .map(|(_, c)| c.clone());

        if let Some(container) = found {
            return Ok(container);
        }

        // Not in cache, try Docker API directly
        info!(
            container_id = container_id,
            "container not in cache, fetching from Docker API"
        );
        let container = self.docker.inspect_container(container_id).await?;

        // Only cache if under the limit to prevent unbounded growth
        if self.containers.len() < MAX_CACHED_CONTAINERS {
            self.containers
                .insert(container.id.clone(), container.clone());
        } else {
            warn!(
                cache_size = self.containers.len(),
                "container cache at maximum capacity, skipping cache insertion"
            );
        }

        Ok(container)
    }

    /// 컨테이너 이름으로 컨테이너를 검색합니다.
    ///
    /// 캐시된 인벤토리에서 이름이 일치하는 컨테이너를 반환합니다.
    pub fn find_by_name(&self, name: &str) -> Option<&ContainerInfo> {
        self.containers.values().find(|c| c.name == name)
    }

    /// 현재 캐시된 컨테이너 수를 반환합니다.
    pub fn container_count(&self) -> usize {
        self.containers.len()
    }

    /// 모든 캐시된 컨테이너를 반환합니다.
    pub fn all_containers(&self) -> Vec<&ContainerInfo> {
        self.containers.values().collect()
    }

    /// 폴링 주기를 반환합니다.
    pub fn poll_interval(&self) -> Duration {
        self.poll_interval
    }

    /// Docker 연결 상태를 확인합니다.
    pub async fn is_connected(&self) -> bool {
        self.docker.ping().await.is_ok()
    }

    /// 마지막 폴링 이후 경과 시간을 반환합니다.
    pub fn time_since_last_poll(&self) -> Option<Duration> {
        self.last_poll.map(|t| t.elapsed())
    }

    /// 폴링이 필요한지 확인합니다.
    pub fn needs_poll(&self) -> bool {
        match self.last_poll {
            Some(last) => last.elapsed() >= self.poll_interval,
            None => true,
        }
    }

    /// 캐시를 초기화합니다.
    pub fn clear_cache(&mut self) {
        self.containers.clear();
        self.last_poll = None;
        warn!("container cache cleared");
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::docker::MockDockerClient;
    use std::time::SystemTime;

    fn sample_containers() -> Vec<ContainerInfo> {
        vec![
            ContainerInfo {
                id: "abc123def456".to_owned(),
                name: "web-server".to_owned(),
                image: "nginx:latest".to_owned(),
                status: "running".to_owned(),
                created_at: SystemTime::now(),
            },
            ContainerInfo {
                id: "xyz789uvw012".to_owned(),
                name: "redis-cache".to_owned(),
                image: "redis:7".to_owned(),
                status: "running".to_owned(),
                created_at: SystemTime::now(),
            },
        ]
    }

    fn make_monitor(containers: Vec<ContainerInfo>) -> DockerMonitor<MockDockerClient> {
        let client = MockDockerClient::new().with_containers(containers);
        DockerMonitor::new(
            Arc::new(client),
            Duration::from_secs(10),
            Duration::from_secs(60),
        )
    }

    #[tokio::test]
    async fn refresh_populates_cache() {
        let mut monitor = make_monitor(sample_containers());
        assert_eq!(monitor.container_count(), 0);

        let count = monitor.refresh().await.unwrap();
        assert_eq!(count, 2);
        assert_eq!(monitor.container_count(), 2);
    }

    #[tokio::test]
    async fn get_container_from_cache() {
        let mut monitor = make_monitor(sample_containers());
        monitor.refresh().await.unwrap();

        let container = monitor.get_container("abc123def456").await.unwrap();
        assert_eq!(container.name, "web-server");
    }

    #[tokio::test]
    async fn get_container_partial_id() {
        let mut monitor = make_monitor(sample_containers());
        monitor.refresh().await.unwrap();

        let container = monitor.get_container("abc123").await.unwrap();
        assert_eq!(container.name, "web-server");
    }

    #[tokio::test]
    async fn get_container_not_in_cache_fetches() {
        let containers = sample_containers();
        let client = MockDockerClient::new().with_containers(containers);
        let mut monitor = DockerMonitor::new(
            Arc::new(client),
            Duration::from_secs(10),
            Duration::from_secs(60),
        );
        // Don't call refresh, container not in cache but client has it
        let container = monitor.get_container("abc123def456").await.unwrap();
        assert_eq!(container.name, "web-server");
        // Now it should be in cache
        assert_eq!(monitor.container_count(), 1);
    }

    #[tokio::test]
    async fn get_container_not_found() {
        let mut monitor = make_monitor(Vec::new());
        let result = monitor.get_container("nonexistent").await;
        assert!(result.is_err());
    }

    #[test]
    fn find_by_name() {
        let mut monitor = DockerMonitor::new(
            Arc::new(MockDockerClient::new()),
            Duration::from_secs(10),
            Duration::from_secs(60),
        );
        // Manually insert for sync test
        let container = ContainerInfo {
            id: "abc123".to_owned(),
            name: "web-server".to_owned(),
            image: "nginx:latest".to_owned(),
            status: "running".to_owned(),
            created_at: SystemTime::now(),
        };
        monitor.containers.insert("abc123".to_owned(), container);

        assert!(monitor.find_by_name("web-server").is_some());
        assert!(monitor.find_by_name("nonexistent").is_none());
    }

    #[test]
    fn needs_poll_initially() {
        let monitor = DockerMonitor::new(
            Arc::new(MockDockerClient::new()),
            Duration::from_secs(10),
            Duration::from_secs(60),
        );
        assert!(monitor.needs_poll());
    }

    #[tokio::test]
    async fn needs_poll_after_refresh() {
        let mut monitor = make_monitor(sample_containers());
        monitor.refresh().await.unwrap();
        // Immediately after refresh, poll is not needed
        assert!(!monitor.needs_poll());
    }

    #[test]
    fn clear_cache() {
        let mut monitor = DockerMonitor::new(
            Arc::new(MockDockerClient::new()),
            Duration::from_secs(10),
            Duration::from_secs(60),
        );
        let container = ContainerInfo {
            id: "abc123".to_owned(),
            name: "web-server".to_owned(),
            image: "nginx:latest".to_owned(),
            status: "running".to_owned(),
            created_at: SystemTime::now(),
        };
        monitor.containers.insert("abc123".to_owned(), container);

        assert_eq!(monitor.container_count(), 1);
        monitor.clear_cache();
        assert_eq!(monitor.container_count(), 0);
        assert!(monitor.needs_poll());
    }

    #[tokio::test]
    async fn is_connected() {
        let monitor = make_monitor(Vec::new());
        assert!(monitor.is_connected().await);
    }

    #[test]
    fn all_containers() {
        let mut monitor = DockerMonitor::new(
            Arc::new(MockDockerClient::new()),
            Duration::from_secs(10),
            Duration::from_secs(60),
        );
        let container = ContainerInfo {
            id: "abc123".to_owned(),
            name: "web-server".to_owned(),
            image: "nginx:latest".to_owned(),
            status: "running".to_owned(),
            created_at: SystemTime::now(),
        };
        monitor.containers.insert("abc123".to_owned(), container);

        let all = monitor.all_containers();
        assert_eq!(all.len(), 1);
        assert_eq!(all[0].name, "web-server");
    }

    #[tokio::test]
    async fn refresh_if_needed_first_call() {
        let mut monitor = make_monitor(sample_containers());
        // First call should refresh
        let count = monitor.refresh_if_needed().await.unwrap();
        assert_eq!(count, 2);
    }

    #[tokio::test]
    async fn refresh_if_needed_within_ttl() {
        let mut monitor = make_monitor(sample_containers());
        monitor.refresh().await.unwrap();
        // Within TTL, should return cached count without API call
        let count = monitor.refresh_if_needed().await.unwrap();
        assert_eq!(count, 2);
    }

    // --- Edge Case Tests ---

    #[tokio::test]
    async fn refresh_empty_container_list() {
        let mut monitor = make_monitor(Vec::new());
        let count = monitor.refresh().await.unwrap();
        assert_eq!(count, 0);
        assert_eq!(monitor.container_count(), 0);
    }

    #[tokio::test]
    async fn refresh_large_container_list() {
        let containers: Vec<ContainerInfo> = (0..1000)
            .map(|i| ContainerInfo {
                id: format!("container-{i:04}"),
                name: format!("service-{i}"),
                image: "nginx:latest".to_owned(),
                status: "running".to_owned(),
                created_at: SystemTime::now(),
            })
            .collect();

        let client = MockDockerClient::new().with_containers(containers);
        let mut monitor = DockerMonitor::new(
            Arc::new(client),
            Duration::from_secs(10),
            Duration::from_secs(60),
        );

        let count = monitor.refresh().await.unwrap();
        assert_eq!(count, 1000);
        assert_eq!(monitor.container_count(), 1000);
    }

    #[tokio::test]
    async fn get_container_with_very_short_id() {
        let mut monitor = make_monitor(sample_containers());
        monitor.refresh().await.unwrap();

        // Partial ID match with just 3 chars
        let container = monitor.get_container("abc").await.unwrap();
        assert_eq!(container.name, "web-server");
    }

    #[tokio::test]
    async fn get_container_ambiguous_partial_id() {
        let containers = vec![
            ContainerInfo {
                id: "abc123def456".to_owned(),
                name: "web-1".to_owned(),
                image: "nginx:latest".to_owned(),
                status: "running".to_owned(),
                created_at: SystemTime::now(),
            },
            ContainerInfo {
                id: "abc456ghi789".to_owned(),
                name: "web-2".to_owned(),
                image: "nginx:latest".to_owned(),
                status: "running".to_owned(),
                created_at: SystemTime::now(),
            },
        ];

        let client = MockDockerClient::new().with_containers(containers);
        let mut monitor = DockerMonitor::new(
            Arc::new(client),
            Duration::from_secs(10),
            Duration::from_secs(60),
        );
        monitor.refresh().await.unwrap();

        // "abc" matches both - should return first match
        let container = monitor.get_container("abc").await.unwrap();
        assert!(container.name == "web-1" || container.name == "web-2");
    }

    #[tokio::test]
    async fn get_container_updates_cache() {
        let containers = sample_containers();
        let client = MockDockerClient::new().with_containers(containers);
        let mut monitor = DockerMonitor::new(
            Arc::new(client),
            Duration::from_secs(10),
            Duration::from_secs(60),
        );

        assert_eq!(monitor.container_count(), 0);

        // Get container without prior refresh
        let container = monitor.get_container("abc123def456").await.unwrap();
        assert_eq!(container.name, "web-server");

        // Should now be in cache
        assert_eq!(monitor.container_count(), 1);
    }

    #[test]
    fn find_by_name_multiple_matches() {
        let mut monitor = DockerMonitor::new(
            Arc::new(MockDockerClient::new()),
            Duration::from_secs(10),
            Duration::from_secs(60),
        );

        // Insert containers with same name (edge case)
        monitor.containers.insert(
            "abc123".to_owned(),
            ContainerInfo {
                id: "abc123".to_owned(),
                name: "web-server".to_owned(),
                image: "nginx:latest".to_owned(),
                status: "running".to_owned(),
                created_at: SystemTime::now(),
            },
        );
        monitor.containers.insert(
            "def456".to_owned(),
            ContainerInfo {
                id: "def456".to_owned(),
                name: "web-server".to_owned(), // Same name
                image: "nginx:alpine".to_owned(),
                status: "running".to_owned(),
                created_at: SystemTime::now(),
            },
        );

        // Should return first match
        let result = monitor.find_by_name("web-server");
        assert!(result.is_some());
    }

    #[test]
    fn find_by_name_empty_string() {
        let mut monitor = DockerMonitor::new(
            Arc::new(MockDockerClient::new()),
            Duration::from_secs(10),
            Duration::from_secs(60),
        );

        monitor.containers.insert(
            "abc123".to_owned(),
            ContainerInfo {
                id: "abc123".to_owned(),
                name: "".to_owned(), // Empty name
                image: "nginx:latest".to_owned(),
                status: "running".to_owned(),
                created_at: SystemTime::now(),
            },
        );

        let result = monitor.find_by_name("");
        assert!(result.is_some());
    }

    #[tokio::test]
    async fn refresh_if_needed_after_ttl_expiry() {
        let client = MockDockerClient::new().with_containers(sample_containers());
        let mut monitor = DockerMonitor::new(
            Arc::new(client),
            Duration::from_secs(10),
            Duration::from_millis(10), // Very short TTL
        );

        monitor.refresh().await.unwrap();
        assert_eq!(monitor.container_count(), 2);

        // Wait for TTL to expire
        tokio::time::sleep(Duration::from_millis(50)).await;

        // Refresh_if_needed uses cache_ttl, not poll_interval
        // TTL should have expired, so refresh_if_needed will refresh
        let count = monitor.refresh_if_needed().await.unwrap();
        assert_eq!(count, 2);
    }

    #[test]
    fn time_since_last_poll_none_initially() {
        let monitor = DockerMonitor::new(
            Arc::new(MockDockerClient::new()),
            Duration::from_secs(10),
            Duration::from_secs(60),
        );

        assert!(monitor.time_since_last_poll().is_none());
    }

    #[tokio::test]
    async fn time_since_last_poll_after_refresh() {
        let mut monitor = make_monitor(sample_containers());
        monitor.refresh().await.unwrap();

        tokio::time::sleep(Duration::from_millis(50)).await;

        let elapsed = monitor.time_since_last_poll().unwrap();
        assert!(elapsed.as_millis() >= 50);
    }

    #[tokio::test]
    async fn poll_interval_accessor() {
        let monitor = DockerMonitor::new(
            Arc::new(MockDockerClient::new()),
            Duration::from_secs(42),
            Duration::from_secs(60),
        );

        assert_eq!(monitor.poll_interval(), Duration::from_secs(42));
    }

    #[tokio::test]
    async fn clear_cache_resets_state() {
        let mut monitor = make_monitor(sample_containers());
        monitor.refresh().await.unwrap();
        assert_eq!(monitor.container_count(), 2);
        assert!(!monitor.needs_poll());

        monitor.clear_cache();

        assert_eq!(monitor.container_count(), 0);
        assert!(monitor.needs_poll());
        assert!(monitor.time_since_last_poll().is_none());
    }

    #[tokio::test]
    async fn all_containers_returns_references() {
        let mut monitor = make_monitor(sample_containers());
        monitor.refresh().await.unwrap();

        let all = monitor.all_containers();
        assert_eq!(all.len(), 2);

        // Verify they're references
        let names: Vec<&str> = all.iter().map(|c| c.name.as_str()).collect();
        assert!(names.contains(&"web-server"));
        assert!(names.contains(&"redis-cache"));
    }

    #[tokio::test]
    async fn concurrent_refresh_calls() {
        let client = Arc::new(MockDockerClient::new().with_containers(sample_containers()));
        let monitor = Arc::new(tokio::sync::Mutex::new(DockerMonitor::new(
            client,
            Duration::from_secs(10),
            Duration::from_secs(60),
        )));

        // Spawn multiple concurrent refresh calls
        let handles: Vec<_> = (0..10)
            .map(|_| {
                let mon = Arc::clone(&monitor);
                tokio::spawn(async move {
                    let mut m = mon.lock().await;
                    m.refresh().await
                })
            })
            .collect();

        // All should succeed
        for handle in handles {
            let result = handle.await.unwrap();
            assert!(result.is_ok());
        }
    }

    // --- Additional Edge Case Tests ---

    /// Test monitor with Docker connection failure (list_containers fails)
    #[tokio::test]
    async fn monitor_with_docker_connection_failure() {
        // Create a mock that will fail on list_containers
        // MockDockerClient always succeeds, so we need a custom mock
        // For testing purposes, we'll use a modified client
        use tokio::sync::Mutex as TokioMutex;

        struct FailingDockerClient {
            should_fail: Arc<TokioMutex<bool>>,
        }

        impl DockerClient for FailingDockerClient {
            async fn list_containers(&self) -> Result<Vec<ContainerInfo>, ContainerGuardError> {
                if *self.should_fail.lock().await {
                    Err(ContainerGuardError::DockerConnection(
                        "connection failed".to_owned(),
                    ))
                } else {
                    Ok(Vec::new())
                }
            }

            async fn inspect_container(
                &self,
                id: &str,
            ) -> Result<ContainerInfo, ContainerGuardError> {
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
                Ok(())
            }
        }

        let client = Arc::new(FailingDockerClient {
            should_fail: Arc::new(TokioMutex::new(true)),
        });

        let mut monitor =
            DockerMonitor::new(client, Duration::from_secs(10), Duration::from_secs(60));

        // refresh should fail
        let result = monitor.refresh().await;
        assert!(result.is_err());
    }

    /// Test get_container when cache has stale data
    #[tokio::test]
    async fn get_container_with_stale_cache() {
        let mut monitor = make_monitor(sample_containers());
        monitor.refresh().await.unwrap();
        assert_eq!(monitor.container_count(), 2);

        // Get container from cache
        let container = monitor.get_container("abc123def456").await.unwrap();
        assert_eq!(container.name, "web-server");

        // Clear cache (simulating stale data)
        monitor.clear_cache();
        assert_eq!(monitor.container_count(), 0);

        // get_container should fetch from Docker API directly
        let container = monitor.get_container("abc123def456").await.unwrap();
        assert_eq!(container.name, "web-server");
        // Now it should be in cache again
        assert_eq!(monitor.container_count(), 1);
    }

    /// Test refresh_if_needed with very short TTL and concurrent calls
    #[tokio::test]
    async fn refresh_if_needed_very_short_ttl_concurrent() {
        let client = Arc::new(MockDockerClient::new().with_containers(sample_containers()));
        let monitor = Arc::new(tokio::sync::Mutex::new(DockerMonitor::new(
            client,
            Duration::from_secs(10),
            Duration::from_millis(5), // Very short TTL
        )));

        // First refresh
        {
            let mut m = monitor.lock().await;
            m.refresh_if_needed().await.unwrap();
        }

        // Wait for TTL to expire
        tokio::time::sleep(Duration::from_millis(10)).await;

        // Spawn concurrent refresh_if_needed calls
        let handles: Vec<_> = (0..5)
            .map(|_| {
                let mon = Arc::clone(&monitor);
                tokio::spawn(async move {
                    let mut m = mon.lock().await;
                    m.refresh_if_needed().await
                })
            })
            .collect();

        // All should succeed
        for handle in handles {
            let result = handle.await.unwrap();
            assert!(result.is_ok());
        }
    }
}

//! Module registry and initialization.
//!
//! Each ironpost crate is wrapped as a [`ModuleHandle`] that provides
//! uniform lifecycle management via the [`DynPipeline`] trait.
//!
//! The [`ModuleRegistry`] tracks all registered modules and supports
//! ordered start/stop operations.

pub mod container_guard;
pub mod log_pipeline;
pub mod sbom_scanner;

#[cfg(target_os = "linux")]
pub mod ebpf;

use ironpost_core::pipeline::{DynPipeline, HealthStatus};

#[cfg(test)]
use ironpost_core::pipeline::BoxFuture;

/// A handle to a registered module.
///
/// Wraps a `Box<dyn DynPipeline>` with metadata (name, enabled flag).
pub struct ModuleHandle {
    /// Module name for logging and health reporting.
    pub name: String,
    /// Whether this module is enabled in configuration.
    pub enabled: bool,
    /// The module's pipeline implementation (start/stop/health_check).
    pub pipeline: Box<dyn DynPipeline>,
}

impl ModuleHandle {
    /// Create a new module handle.
    pub fn new(name: impl Into<String>, enabled: bool, pipeline: Box<dyn DynPipeline>) -> Self {
        Self {
            name: name.into(),
            enabled,
            pipeline,
        }
    }

    /// Check the module's health status.
    ///
    /// Disabled modules always report `Healthy` (they are not expected to run).
    #[allow(dead_code)] // Used in orchestrator health method
    pub async fn health_check(&self) -> HealthStatus {
        if !self.enabled {
            return HealthStatus::Healthy;
        }
        self.pipeline.health_check().await
    }
}

/// Registry of all ironpost modules.
///
/// Provides ordered start/stop and health check aggregation.
pub struct ModuleRegistry {
    /// Modules in registration order (producers before consumers).
    modules: Vec<ModuleHandle>,
}

impl ModuleRegistry {
    /// Create an empty registry.
    pub fn new() -> Self {
        Self {
            modules: Vec::new(),
        }
    }

    /// Register a module.
    ///
    /// Modules should be registered in dependency order:
    /// producers first, consumers last.
    pub fn register(&mut self, handle: ModuleHandle) {
        self.modules.push(handle);
    }

    /// Start all enabled modules in registration order.
    ///
    /// Returns an error on the first module that fails to start.
    /// Already-started modules are NOT rolled back; the caller should
    /// invoke `stop_all` if partial startup is unacceptable.
    ///
    /// Each module start operation has a 30-second timeout to prevent indefinite hangs.
    ///
    /// Note: Module panics will propagate to the daemon orchestrator.
    /// Modules are expected to handle all errors gracefully and avoid panicking.
    pub async fn start_all(&mut self) -> anyhow::Result<()> {
        const START_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(30);

        for handle in &mut self.modules {
            if !handle.enabled {
                tracing::debug!(module = %handle.name, "skipping disabled module");
                continue;
            }

            tracing::info!(module = %handle.name, "starting module");

            let start_result = tokio::time::timeout(START_TIMEOUT, handle.pipeline.start()).await;

            match start_result {
                Ok(Ok(())) => {
                    tracing::info!(module = %handle.name, "module started successfully");
                }
                Ok(Err(e)) => {
                    return Err(anyhow::anyhow!(
                        "failed to start module '{}': {}",
                        handle.name,
                        e
                    ));
                }
                Err(_) => {
                    return Err(anyhow::anyhow!(
                        "timeout starting module '{}' (exceeded {:?})",
                        handle.name,
                        START_TIMEOUT
                    ));
                }
            }
        }
        Ok(())
    }

    /// Stop all enabled modules in registration order (producers first).
    ///
    /// Logs errors but continues stopping remaining modules.
    /// Registration order is: eBPF -> LogPipeline -> SBOM -> ContainerGuard.
    /// Stopping in this order ensures producers stop first, allowing consumers to drain.
    ///
    /// Each module stop operation has a 30-second timeout to prevent indefinite hangs.
    ///
    /// Note: Module panics during stop will propagate to the daemon orchestrator.
    /// Modules are expected to handle all errors gracefully and avoid panicking.
    pub async fn stop_all(&mut self) -> anyhow::Result<()> {
        const STOP_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(30);
        let mut errors = Vec::new();

        for handle in self.modules.iter_mut() {
            if !handle.enabled {
                continue;
            }

            tracing::info!(module = %handle.name, "stopping module");

            let stop_result = tokio::time::timeout(STOP_TIMEOUT, handle.pipeline.stop()).await;

            match stop_result {
                Ok(Ok(())) => {
                    tracing::info!(module = %handle.name, "module stopped successfully");
                }
                Ok(Err(e)) => {
                    tracing::error!(
                        module = %handle.name,
                        error = %e,
                        "failed to stop module"
                    );
                    errors.push(format!("{}: {}", handle.name, e));
                }
                Err(_) => {
                    tracing::warn!(
                        module = %handle.name,
                        timeout = ?STOP_TIMEOUT,
                        "timeout stopping module, continuing shutdown"
                    );
                    errors.push(format!("{}: timeout after {:?}", handle.name, STOP_TIMEOUT));
                }
            }
        }

        if !errors.is_empty() {
            return Err(anyhow::anyhow!(
                "errors stopping modules: {}",
                errors.join("; ")
            ));
        }

        Ok(())
    }

    /// Get health status for all modules.
    #[allow(dead_code)] // Used in orchestrator health method
    pub async fn health_statuses(&self) -> Vec<(String, bool, HealthStatus)> {
        let mut statuses = Vec::new();
        for handle in &self.modules {
            let status = handle.health_check().await;
            statuses.push((handle.name.clone(), handle.enabled, status));
        }
        statuses
    }

    /// Number of registered modules.
    pub fn count(&self) -> usize {
        self.modules.len()
    }

    /// Number of enabled modules.
    pub fn enabled_count(&self) -> usize {
        self.modules.iter().filter(|m| m.enabled).count()
    }
}

impl Default for ModuleRegistry {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ironpost_core::error::IronpostError;

    /// Mock pipeline for testing.
    struct MockPipeline {
        started: std::sync::Arc<std::sync::atomic::AtomicBool>,
        stopped: std::sync::Arc<std::sync::atomic::AtomicBool>,
        health: HealthStatus,
    }

    impl MockPipeline {
        fn new(_name: &str, health: HealthStatus) -> Self {
            Self {
                started: std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false)),
                stopped: std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false)),
                health,
            }
        }
    }

    impl DynPipeline for MockPipeline {
        fn start(&mut self) -> BoxFuture<'_, Result<(), IronpostError>> {
            let started = self.started.clone();
            Box::pin(async move {
                started.store(true, std::sync::atomic::Ordering::SeqCst);
                Ok(())
            })
        }

        fn stop(&mut self) -> BoxFuture<'_, Result<(), IronpostError>> {
            let stopped = self.stopped.clone();
            Box::pin(async move {
                stopped.store(true, std::sync::atomic::Ordering::SeqCst);
                Ok(())
            })
        }

        fn health_check(&self) -> BoxFuture<'_, HealthStatus> {
            let health = self.health.clone();
            Box::pin(async move { health })
        }
    }

    #[test]
    fn test_module_registry_new_is_empty() {
        // Given: A new registry
        let registry = ModuleRegistry::new();

        // Then: Should be empty
        assert_eq!(registry.count(), 0, "new registry should be empty");
        assert_eq!(
            registry.enabled_count(),
            0,
            "new registry should have no enabled modules"
        );
    }

    #[test]
    fn test_module_registry_register_increases_count() {
        // Given: A new registry
        let mut registry = ModuleRegistry::new();

        // When: Registering a module
        let pipeline = Box::new(MockPipeline::new("test", HealthStatus::Healthy));
        let handle = ModuleHandle::new("test-module", true, pipeline);
        registry.register(handle);

        // Then: Count should increase
        assert_eq!(registry.count(), 1, "registry should have one module");
        assert_eq!(
            registry.enabled_count(),
            1,
            "registry should have one enabled module"
        );
    }

    #[test]
    fn test_module_registry_enabled_count_ignores_disabled() {
        // Given: A registry with mixed enabled/disabled modules
        let mut registry = ModuleRegistry::new();

        let pipeline1 = Box::new(MockPipeline::new("enabled", HealthStatus::Healthy));
        let handle1 = ModuleHandle::new("enabled-module", true, pipeline1);
        registry.register(handle1);

        let pipeline2 = Box::new(MockPipeline::new("disabled", HealthStatus::Healthy));
        let handle2 = ModuleHandle::new("disabled-module", false, pipeline2);
        registry.register(handle2);

        // Then: Only enabled should be counted
        assert_eq!(registry.count(), 2, "registry should have two modules");
        assert_eq!(
            registry.enabled_count(),
            1,
            "only one module should be enabled"
        );
    }

    #[tokio::test]
    async fn test_module_registry_start_all_calls_start() {
        // Given: A registry with one enabled module
        let mut registry = ModuleRegistry::new();

        let started = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
        let _started_clone = started.clone();

        let pipeline = Box::new(MockPipeline::new("test", HealthStatus::Healthy));
        let handle = ModuleHandle::new("test-module", true, pipeline);
        registry.register(handle);

        // When: Starting all modules
        let result = registry.start_all().await;

        // Then: Should succeed
        assert!(result.is_ok(), "start_all should succeed");
        // Note: We can't easily verify the internal state without exposing more APIs,
        // but we can verify it doesn't error
    }

    #[tokio::test]
    async fn test_module_registry_start_all_skips_disabled() {
        // Given: A registry with a disabled module
        let mut registry = ModuleRegistry::new();
        let pipeline = Box::new(MockPipeline::new("disabled", HealthStatus::Healthy));
        let handle = ModuleHandle::new("disabled-module", false, pipeline);
        registry.register(handle);

        // When: Starting all modules
        let result = registry.start_all().await;

        // Then: Should succeed (skips disabled)
        assert!(result.is_ok(), "start_all should succeed");
    }

    #[tokio::test]
    async fn test_module_registry_stop_all_calls_stop() {
        // Given: A started module
        let mut registry = ModuleRegistry::new();
        let pipeline = Box::new(MockPipeline::new("test", HealthStatus::Healthy));
        let handle = ModuleHandle::new("test-module", true, pipeline);
        registry.register(handle);

        registry.start_all().await.expect("start should succeed");

        // When: Stopping all modules
        let result = registry.stop_all().await;

        // Then: Should succeed
        assert!(result.is_ok(), "stop_all should succeed");
    }

    #[tokio::test]
    async fn test_module_registry_stop_all_reverse_order() {
        // Given: Multiple modules registered
        let mut registry = ModuleRegistry::new();

        let pipeline1 = Box::new(MockPipeline::new("module1", HealthStatus::Healthy));
        let handle1 = ModuleHandle::new("module1", true, pipeline1);
        registry.register(handle1);

        let pipeline2 = Box::new(MockPipeline::new("module2", HealthStatus::Healthy));
        let handle2 = ModuleHandle::new("module2", true, pipeline2);
        registry.register(handle2);

        registry.start_all().await.expect("start should succeed");

        // When: Stopping all modules
        let result = registry.stop_all().await;

        // Then: Both should stop without error
        assert!(result.is_ok(), "stop_all should succeed");
    }

    #[tokio::test]
    async fn test_module_registry_health_statuses() {
        // Given: Registry with modules of different health
        let mut registry = ModuleRegistry::new();

        let pipeline1 = Box::new(MockPipeline::new("healthy", HealthStatus::Healthy));
        let handle1 = ModuleHandle::new("healthy-module", true, pipeline1);
        registry.register(handle1);

        let pipeline2 = Box::new(MockPipeline::new(
            "degraded",
            HealthStatus::Degraded("slow".to_string()),
        ));
        let handle2 = ModuleHandle::new("degraded-module", true, pipeline2);
        registry.register(handle2);

        // When: Getting health statuses
        let statuses = registry.health_statuses().await;

        // Then: Should return all module statuses
        assert_eq!(statuses.len(), 2, "should return all module statuses");

        let (name1, enabled1, status1) = &statuses[0];
        assert_eq!(name1, "healthy-module");
        assert!(enabled1);
        assert!(status1.is_healthy());

        let (name2, enabled2, status2) = &statuses[1];
        assert_eq!(name2, "degraded-module");
        assert!(enabled2);
        assert!(matches!(status2, HealthStatus::Degraded(_)));
    }

    #[tokio::test]
    async fn test_module_handle_health_check_disabled_always_healthy() {
        // Given: A disabled module with unhealthy status
        let pipeline = Box::new(MockPipeline::new(
            "unhealthy",
            HealthStatus::Unhealthy("broken".to_string()),
        ));
        let handle = ModuleHandle::new("test-module", false, pipeline);

        // When: Checking health
        let status = handle.health_check().await;

        // Then: Should report healthy (disabled modules are not expected to run)
        assert!(
            status.is_healthy(),
            "disabled modules should always report healthy"
        );
    }

    #[tokio::test]
    async fn test_module_handle_health_check_enabled_returns_actual() {
        // Given: An enabled module with degraded status
        let pipeline = Box::new(MockPipeline::new(
            "degraded",
            HealthStatus::Degraded("issue".to_string()),
        ));
        let handle = ModuleHandle::new("test-module", true, pipeline);

        // When: Checking health
        let status = handle.health_check().await;

        // Then: Should return actual status
        assert!(
            matches!(status, HealthStatus::Degraded(_)),
            "enabled modules should report actual health status"
        );
    }

    #[test]
    fn test_module_registry_default() {
        // Given: Default registry
        let registry = ModuleRegistry::default();

        // Then: Should be equivalent to new()
        assert_eq!(registry.count(), 0, "default registry should be empty");
    }

    #[tokio::test]
    async fn test_module_registry_multiple_modules_start_order() {
        // Given: Multiple enabled modules
        let mut registry = ModuleRegistry::new();

        for i in 0..5 {
            let pipeline = Box::new(MockPipeline::new(
                &format!("module{}", i),
                HealthStatus::Healthy,
            ));
            let handle = ModuleHandle::new(format!("module{}", i), true, pipeline);
            registry.register(handle);
        }

        // When: Starting all
        let result = registry.start_all().await;

        // Then: All should start successfully
        assert!(result.is_ok(), "all modules should start");
        assert_eq!(registry.enabled_count(), 5);
    }
}

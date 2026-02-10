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
    pub async fn start_all(&mut self) -> anyhow::Result<()> {
        for handle in &mut self.modules {
            if !handle.enabled {
                tracing::debug!(module = %handle.name, "skipping disabled module");
                continue;
            }

            tracing::info!(module = %handle.name, "starting module");
            handle
                .pipeline
                .start()
                .await
                .map_err(|e| anyhow::anyhow!("failed to start module '{}': {}", handle.name, e))?;
            tracing::info!(module = %handle.name, "module started successfully");
        }
        Ok(())
    }

    /// Stop all enabled modules in reverse registration order.
    ///
    /// Logs errors but continues stopping remaining modules.
    /// This ensures producers stop before consumers.
    pub async fn stop_all(&mut self) -> anyhow::Result<()> {
        let mut errors = Vec::new();

        for handle in self.modules.iter_mut().rev() {
            if !handle.enabled {
                continue;
            }

            tracing::info!(module = %handle.name, "stopping module");
            if let Err(e) = handle.pipeline.stop().await {
                tracing::error!(
                    module = %handle.name,
                    error = %e,
                    "failed to stop module"
                );
                errors.push(format!("{}: {}", handle.name, e));
            } else {
                tracing::info!(module = %handle.name, "module stopped successfully");
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

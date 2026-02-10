//! Aggregated health check reporting.
//!
//! Periodically polls each module's `health_check()` and produces
//! a unified [`DaemonHealth`] report. The overall daemon status is
//! the worst status among all enabled modules.
//!
//! # Aggregation Rule
//!
//! - All Healthy -> Healthy
//! - Any Degraded, none Unhealthy -> Degraded(reason)
//! - Any Unhealthy -> Unhealthy(reason)

use serde::Serialize;

use ironpost_core::pipeline::HealthStatus;

/// Aggregated health report for the entire daemon.
#[derive(Debug, Clone, Serialize)]
#[allow(dead_code)] // Used in API
pub struct DaemonHealth {
    /// Overall daemon health status (worst of all modules).
    pub status: HealthStatus,
    /// Daemon uptime in seconds since start.
    pub uptime_secs: u64,
    /// Per-module health reports.
    pub modules: Vec<ModuleHealth>,
}

/// Health status for a single module.
#[derive(Debug, Clone, Serialize)]
#[allow(dead_code)] // Used in API
pub struct ModuleHealth {
    /// Module name (e.g., "ebpf-engine", "log-pipeline").
    pub name: String,
    /// Whether the module is enabled in configuration.
    pub enabled: bool,
    /// Current health status of the module.
    pub status: HealthStatus,
}

/// Aggregate multiple module health statuses into a single status.
///
/// Returns the worst status found: Unhealthy > Degraded > Healthy.
/// Only considers enabled modules.
#[allow(dead_code)] // Used in orchestrator
pub fn aggregate_status(modules: &[ModuleHealth]) -> HealthStatus {
    let enabled_modules = modules.iter().filter(|m| m.enabled);

    let mut worst = HealthStatus::Healthy;
    let mut reasons = Vec::new();

    for module in enabled_modules {
        match &module.status {
            HealthStatus::Healthy => {}
            HealthStatus::Degraded(reason) => {
                if !worst.is_unhealthy() {
                    reasons.push(format!("{}: {}", module.name, reason));
                    worst = HealthStatus::Degraded(String::new());
                }
            }
            HealthStatus::Unhealthy(reason) => {
                reasons.push(format!("{}: {}", module.name, reason));
                worst = HealthStatus::Unhealthy(String::new());
            }
        }
    }

    match worst {
        HealthStatus::Healthy => HealthStatus::Healthy,
        HealthStatus::Degraded(_) => HealthStatus::Degraded(reasons.join("; ")),
        HealthStatus::Unhealthy(_) => HealthStatus::Unhealthy(reasons.join("; ")),
    }
}

/// Spawn a background task that periodically checks module health
/// and logs the aggregated result.
///
/// # Arguments
///
/// * `modules` - Module registry providing access to module pipelines
/// * `interval_secs` - Seconds between health check cycles
/// * `shutdown_rx` - Broadcast receiver for shutdown signal
///
/// # Returns
///
/// A `JoinHandle` for the health check task.
#[allow(dead_code)] // Future implementation
pub fn spawn_health_check_task(
    interval_secs: u64,
    mut shutdown_rx: tokio::sync::broadcast::Receiver<()>,
) -> tokio::task::JoinHandle<()> {
    tokio::spawn(async move {
        let mut interval = tokio::time::interval(tokio::time::Duration::from_secs(interval_secs));

        loop {
            tokio::select! {
                _ = interval.tick() => {
                    // Health check logic would go here, but we can't access modules
                    // from this task. The actual health check should be done in the
                    // orchestrator's run loop. This is just a placeholder for future
                    // implementation where we might want a separate health check task.
                    tracing::debug!("health check tick");
                }
                _ = shutdown_rx.recv() => {
                    tracing::debug!("health check task shutting down");
                    break;
                }
            }
        }
    })
}

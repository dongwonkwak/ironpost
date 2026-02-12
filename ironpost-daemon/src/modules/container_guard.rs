//! Container guard module initialization.
//!
//! Converts `IronpostConfig.container` into a `ContainerGuardConfig`,
//! creates a Docker client, builds the `ContainerGuard`, and wraps
//! it in a `ModuleHandle`.
//!
//! # Channel Wiring
//!
//! ```text
//! log-pipeline + sbom-scanner --AlertEvent--> alert_rx --> ContainerGuard
//! ContainerGuard --ActionEvent--> action_tx --> daemon (logging/audit)
//! ```

use std::sync::Arc;

use anyhow::Result;
use tokio::sync::mpsc;

use ironpost_core::config::IronpostConfig;
use ironpost_core::event::{ActionEvent, AlertEvent};

use ironpost_container_guard::{
    BollardDockerClient, ContainerGuardBuilder, ContainerGuardConfig, load_policies_from_dir,
};

use super::ModuleHandle;

/// Initialize the container guard module.
///
/// Returns `None` if the container guard is disabled in configuration.
///
/// # Arguments
///
/// * `config` - The full ironpost configuration
/// * `alert_rx` - Receiver for AlertEvents from log-pipeline and sbom-scanner
///
/// # Returns
///
/// * `Ok(Some((ModuleHandle, Receiver<ActionEvent>)))` - Guard initialized
/// * `Ok(None)` - Module disabled in configuration
/// * `Err(_)` - Initialization failed (e.g., Docker connection failure)
pub fn init(
    config: &IronpostConfig,
    mut alert_rx: mpsc::Receiver<AlertEvent>,
) -> Result<Option<(ModuleHandle, mpsc::Receiver<ActionEvent>)>> {
    if !config.container.enabled {
        tracing::warn!(
            "container guard disabled, alert channel will be drained (alerts logged but not acted upon)"
        );

        // Spawn a background task to drain the alert channel to prevent producers from blocking
        tokio::spawn(async move {
            while let Some(alert) = alert_rx.recv().await {
                tracing::warn!(
                    alert_id = %alert.id,
                    severity = %alert.severity,
                    source = %alert.metadata.source_module,
                    "alert discarded (container-guard disabled)"
                );
            }
            tracing::debug!("alert drain task terminated (channel closed)");
        });

        return Ok(None);
    }

    tracing::info!("initializing container guard");

    let guard_config = ContainerGuardConfig::from_core(&config.container);
    let policy_path = guard_config.policy_path.clone();

    // Create Docker client
    let docker = Arc::new(BollardDockerClient::connect_with_socket(
        &guard_config.docker_socket,
    )?);

    // Load policies from configured directory if path is non-empty.
    // Empty policy_path means "no policies loaded" (monitor-only mode).
    let policies = if policy_path.trim().is_empty() {
        tracing::info!("container.policy_path is empty, no policies will be loaded");
        Vec::new()
    } else {
        load_policies_from_dir(std::path::Path::new(&policy_path)).map_err(|e| {
            anyhow::anyhow!("failed to load container policies from {policy_path}: {e}")
        })?
    };

    tracing::info!(
        policy_path = %policy_path,
        count = policies.len(),
        "loaded container guard policies"
    );

    let mut builder = ContainerGuardBuilder::new()
        .config(guard_config)
        .docker_client(docker)
        .alert_receiver(alert_rx);

    for policy in policies {
        builder = builder.add_policy(policy);
    }

    let (guard, action_rx) = builder
        .build()
        .map_err(|e| anyhow::anyhow!("failed to build container guard: {}", e))?;

    let handle = ModuleHandle::new("container-guard", true, Box::new(guard));

    let action_receiver = action_rx
        .ok_or_else(|| anyhow::anyhow!("container guard builder did not produce action_rx"))?;

    Ok(Some((handle, action_receiver)))
}

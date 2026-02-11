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

use ironpost_container_guard::{BollardDockerClient, ContainerGuardBuilder, ContainerGuardConfig};

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
    alert_rx: mpsc::Receiver<AlertEvent>,
) -> Result<Option<(ModuleHandle, mpsc::Receiver<ActionEvent>)>> {
    if !config.container.enabled {
        tracing::info!("container guard disabled in configuration");
        return Ok(None);
    }

    tracing::info!("initializing container guard");

    let guard_config = ContainerGuardConfig::from_core(&config.container);

    // Create Docker client
    let docker = Arc::new(BollardDockerClient::connect_with_socket(
        &guard_config.docker_socket,
    )?);

    let (guard, action_rx) = ContainerGuardBuilder::new()
        .config(guard_config)
        .docker_client(docker)
        .alert_receiver(alert_rx)
        .build()
        .map_err(|e| anyhow::anyhow!("failed to build container guard: {}", e))?;

    let handle = ModuleHandle::new("container-guard", true, Box::new(guard));

    let action_receiver = action_rx.ok_or_else(|| {
        anyhow::anyhow!("container guard builder did not produce action_rx")
    })?;

    Ok(Some((handle, action_receiver)))
}

//! SBOM scanner module initialization.
//!
//! Converts `IronpostConfig.sbom` into a `SbomScannerConfig`,
//! builds the `SbomScanner`, and wraps it in a `ModuleHandle`.
//!
//! # Channel Wiring
//!
//! ```text
//! SbomScanner --AlertEvent--> alert_tx --> container-guard
//! ```
//!
//! The SBOM scanner shares the same `alert_tx` as the log pipeline,
//! so both feed into the container guard's single `alert_rx`.

use anyhow::Result;
use tokio::sync::mpsc;

use ironpost_core::config::IronpostConfig;
use ironpost_core::event::AlertEvent;

use ironpost_sbom_scanner::{SbomScannerBuilder, SbomScannerConfig};

use super::ModuleHandle;

/// Initialize the SBOM scanner module.
///
/// Returns `None` if the SBOM scanner is disabled in configuration.
///
/// # Arguments
///
/// * `config` - The full ironpost configuration
/// * `alert_tx` - Sender for AlertEvents (shared with log-pipeline)
///
/// # Returns
///
/// * `Ok(Some(ModuleHandle))` - Scanner initialized and ready to start
/// * `Ok(None)` - Module disabled in configuration
/// * `Err(_)` - Initialization failed
pub fn init(
    config: &IronpostConfig,
    alert_tx: mpsc::Sender<AlertEvent>,
) -> Result<Option<ModuleHandle>> {
    if !config.sbom.enabled {
        tracing::info!("SBOM scanner disabled in configuration");
        return Ok(None);
    }

    tracing::info!("initializing SBOM scanner");

    let scanner_config = SbomScannerConfig::from_core(&config.sbom);

    let (scanner, _) = SbomScannerBuilder::new()
        .config(scanner_config)
        .alert_sender(alert_tx)
        .build()
        .map_err(|e| anyhow::anyhow!("failed to build SBOM scanner: {}", e))?;

    let handle = ModuleHandle::new("sbom-scanner", true, Box::new(scanner));

    Ok(Some(handle))
}

//! Log pipeline module initialization.
//!
//! Converts `IronpostConfig.log_pipeline` into a `PipelineConfig`,
//! builds the `LogPipeline` with appropriate channel wiring, and
//! wraps it in a `ModuleHandle`.
//!
//! # Channel Wiring
//!
//! ```text
//! ebpf-engine --PacketEvent--> packet_rx --> LogPipeline
//! LogPipeline --AlertEvent--> alert_tx --> container-guard
//! ```

use anyhow::Result;
use tokio::sync::mpsc;

use ironpost_core::config::IronpostConfig;
use ironpost_core::event::{AlertEvent, PacketEvent};

use ironpost_log_pipeline::{LogPipelineBuilder, PipelineConfig};

use super::ModuleHandle;

/// Initialize the log pipeline module.
///
/// Returns `None` if the log pipeline is disabled in configuration.
///
/// # Arguments
///
/// * `config` - The full ironpost configuration
/// * `packet_rx` - Optional receiver for PacketEvents from ebpf-engine
/// * `alert_tx` - Sender for AlertEvents (shared with container-guard)
///
/// # Returns
///
/// * `Ok(Some(ModuleHandle))` - Pipeline initialized and ready to start
/// * `Ok(None)` - Module disabled in configuration
/// * `Err(_)` - Initialization failed
pub fn init(
    config: &IronpostConfig,
    packet_rx: Option<mpsc::Receiver<PacketEvent>>,
    alert_tx: mpsc::Sender<AlertEvent>,
) -> Result<Option<ModuleHandle>> {
    if !config.log_pipeline.enabled {
        tracing::info!("log pipeline disabled in configuration");
        return Ok(None);
    }

    tracing::info!("initializing log pipeline");

    let pipeline_config = PipelineConfig::from_core(&config.log_pipeline);

    let mut builder = LogPipelineBuilder::new()
        .config(pipeline_config)
        .alert_sender(alert_tx);

    if let Some(rx) = packet_rx {
        builder = builder.packet_receiver(rx);
    }

    let (pipeline, _) = builder
        .build()
        .map_err(|e| anyhow::anyhow!("failed to build log pipeline: {}", e))?;

    let handle = ModuleHandle::new("log-pipeline", true, Box::new(pipeline));

    Ok(Some(handle))
}

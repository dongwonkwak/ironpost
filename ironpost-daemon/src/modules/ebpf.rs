//! eBPF engine module initialization (Linux only).
//!
//! This module is conditionally compiled only on Linux targets.
//! On non-Linux platforms, the eBPF engine is simply not available.
//!
//! # Channel Wiring
//!
//! ```text
//! EbpfEngine --PacketEvent--> packet_tx --> log-pipeline (packet_rx)
//! ```

use anyhow::Result;
use tokio::sync::mpsc;

use ironpost_core::config::IronpostConfig;
use ironpost_core::event::PacketEvent;

use ironpost_ebpf_engine::EngineConfig;

use super::ModuleHandle;

/// Initialize the eBPF engine module.
///
/// Returns `None` if the eBPF module is disabled in configuration.
///
/// # Arguments
///
/// * `config` - The full ironpost configuration
/// * `packet_tx` - Sender for PacketEvents (consumed by log-pipeline)
///
/// # Returns
///
/// * `Ok(Some(ModuleHandle))` - Engine initialized and ready to start
/// * `Ok(None)` - Module disabled in configuration
/// * `Err(_)` - Initialization failed
pub fn init(
    config: &IronpostConfig,
    packet_tx: mpsc::Sender<PacketEvent>,
) -> Result<Option<(ModuleHandle, Option<mpsc::Receiver<PacketEvent>>)>> {
    if !config.ebpf.enabled {
        tracing::info!("eBPF engine disabled in configuration");
        return Ok(None);
    }

    tracing::info!("initializing eBPF engine");

    let engine_config = EngineConfig::from_core(&config.ebpf);

    let (engine, packet_rx) = ironpost_ebpf_engine::EbpfEngine::builder()
        .config(engine_config)
        .event_sender(packet_tx)
        .build()
        .map_err(|e| anyhow::anyhow!("failed to build eBPF engine: {}", e))?;

    let handle = ModuleHandle::new("ebpf-engine", true, Box::new(engine));

    Ok(Some((handle, packet_rx)))
}

//! Ironpost daemon -- main entry point.
//!
//! The daemon orchestrates all ironpost security monitoring modules:
//! - eBPF network packet engine (Linux only)
//! - Log collection and detection pipeline
//! - Container guard (automatic isolation)
//! - SBOM vulnerability scanner
//!
//! # Usage
//!
//! ```text
//! ironpost-daemon --config /etc/ironpost/ironpost.toml
//! ironpost-daemon --validate    # validate config and exit
//! ironpost-daemon --log-level debug --log-format pretty
//! ```

mod cli;
mod health;
mod logging;
mod modules;
mod orchestrator;

use anyhow::Result;
use clap::Parser;

use crate::cli::DaemonCli;
use crate::orchestrator::Orchestrator;

#[tokio::main]
async fn main() -> Result<()> {
    let cli = DaemonCli::parse();

    // Load configuration
    let mut config = if cli.config.exists() {
        ironpost_core::config::IronpostConfig::load(&cli.config)
            .await
            .map_err(|e| {
                anyhow::anyhow!("failed to load config from {}: {}", cli.config.display(), e)
            })?
    } else {
        tracing::warn!(
            path = %cli.config.display(),
            "config file not found, using defaults"
        );
        ironpost_core::config::IronpostConfig::default()
    };

    // Apply CLI overrides
    if let Some(ref level) = cli.log_level {
        config.general.log_level = level.clone();
    }
    if let Some(ref format) = cli.log_format {
        config.general.log_format = format.clone();
    }

    // Validate-only mode
    if cli.validate {
        match config.validate() {
            Ok(()) => {
                // Note: Using tracing here since println! is forbidden.
                // However tracing may not be initialized yet. In validate-only
                // mode, we initialize a minimal subscriber first.
                let _guard = tracing_subscriber::fmt().with_env_filter("info").try_init();
                tracing::info!("configuration is valid");
                return Ok(());
            }
            Err(e) => {
                return Err(anyhow::anyhow!("configuration validation failed: {}", e));
            }
        }
    }

    // Initialize logging
    logging::init_tracing(&config.general)?;

    tracing::info!(
        version = env!("CARGO_PKG_VERSION"),
        config_path = %cli.config.display(),
        "ironpost-daemon starting"
    );

    // Build and run the orchestrator
    let mut orchestrator = Orchestrator::build_from_config(config).await?;
    orchestrator.run().await?;

    tracing::info!("ironpost-daemon shut down cleanly");
    Ok(())
}

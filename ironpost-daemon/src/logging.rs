//! Logging initialization for ironpost-daemon.
//!
//! Configures `tracing-subscriber` based on the `[general]` section
//! of `IronpostConfig`. Supports JSON structured logging and
//! human-readable pretty format.

use anyhow::Result;
use tracing_subscriber::EnvFilter;
use tracing_subscriber::layer::SubscriberExt;
use tracing_subscriber::util::SubscriberInitExt;

use ironpost_core::config::GeneralConfig;

/// Initialize the global tracing subscriber.
///
/// Must be called exactly once, before any tracing macros are used.
///
/// # Arguments
///
/// * `config` - General configuration (log_level, log_format)
///
/// # Formats
///
/// * `"json"` - Machine-parseable JSON lines (default for production)
/// * `"pretty"` - Human-readable colored output (for development)
pub fn init_tracing(config: &GeneralConfig) -> Result<()> {
    let env_filter =
        EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new(&config.log_level));

    match config.log_format.as_str() {
        "json" => {
            tracing_subscriber::registry()
                .with(env_filter)
                .with(tracing_subscriber::fmt::layer().json())
                .try_init()
                .map_err(|e| {
                    anyhow::anyhow!("failed to initialize JSON tracing subscriber: {}", e)
                })?;
        }
        "pretty" => {
            tracing_subscriber::registry()
                .with(env_filter)
                .with(tracing_subscriber::fmt::layer().pretty())
                .try_init()
                .map_err(|e| {
                    anyhow::anyhow!("failed to initialize pretty tracing subscriber: {}", e)
                })?;
        }
        _ => {
            return Err(anyhow::anyhow!(
                "unknown log format '{}', expected 'json' or 'pretty'",
                config.log_format
            ));
        }
    }

    Ok(())
}

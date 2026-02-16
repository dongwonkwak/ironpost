//! Prometheus metrics HTTP server.
//!
//! Uses the built-in HTTP listener from `metrics-exporter-prometheus`
//! to expose Prometheus scrape endpoints.
//!
//! # Usage
//!
//! ```ignore
//! let config = MetricsConfig::default();
//! install_metrics_recorder(&config)?;
//! // After this, all metrics::counter!(), metrics::gauge!(), metrics::histogram!() calls are recorded
//! ```

use std::net::SocketAddr;

use anyhow::Result;
use ironpost_core::config::MetricsConfig;
use metrics_exporter_prometheus::PrometheusBuilder;

/// Install the global metrics recorder and start the HTTP listener.
///
/// This function should be called once per process.
/// After calling this, all `metrics::counter!()`, `metrics::gauge!()`, `metrics::histogram!()`
/// macros will record to the Prometheus format.
///
/// # Arguments
///
/// * `config` - Metrics configuration (listen_addr, port)
///
/// # Errors
///
/// - Socket binding fails
/// - Global recorder is already installed
pub fn install_metrics_recorder(config: &MetricsConfig) -> Result<()> {
    if config.endpoint != "/metrics" {
        return Err(anyhow::anyhow!(
            "unsupported metrics endpoint '{}': only '/metrics' is currently supported",
            config.endpoint
        ));
    }

    let addr: SocketAddr = format!("{}:{}", config.listen_addr, config.port)
        .parse()
        .map_err(|e| anyhow::anyhow!("invalid metrics listen address: {}", e))?;

    if addr.ip().is_unspecified() {
        tracing::warn!(
            listen_addr = %addr,
            "metrics endpoint is exposed on all interfaces; restrict listen_addr in untrusted networks"
        );
    }

    tracing::info!(
        listen_addr = %addr,
        "installing Prometheus metrics recorder"
    );

    PrometheusBuilder::new()
        .with_http_listener(addr)
        .install()
        .map_err(|e| anyhow::anyhow!("failed to install metrics recorder: {}", e))?;

    // Register metric descriptions
    ironpost_core::metrics::describe_all();

    tracing::info!(
        listen_addr = %addr,
        "Prometheus metrics endpoint active"
    );

    Ok(())
}

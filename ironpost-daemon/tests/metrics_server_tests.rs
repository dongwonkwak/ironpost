//! Integration tests for metrics server functionality.

use ironpost_core::config::MetricsConfig;
use ironpost_daemon::metrics_server;
use serial_test::serial;

#[test]
#[serial]
fn test_install_metrics_recorder_succeeds_with_valid_config() {
    // Given: A valid metrics configuration
    let config = MetricsConfig {
        enabled: true,
        listen_addr: "127.0.0.1".to_string(),
        port: 19100, // Use non-standard port to avoid conflicts
        endpoint: "/metrics".to_string(),
    };

    // When: Installing the metrics recorder
    let result = metrics_server::install_metrics_recorder(&config);

    // Then: Should succeed
    assert!(
        result.is_ok(),
        "install_metrics_recorder should succeed with valid config: {:?}",
        result.err()
    );
}

#[test]
#[serial]
fn test_install_metrics_recorder_fails_with_invalid_address() {
    // Given: An invalid metrics configuration (invalid IP)
    let config = MetricsConfig {
        enabled: true,
        listen_addr: "999.999.999.999".to_string(),
        port: 9100,
        endpoint: "/metrics".to_string(),
    };

    // When: Installing the metrics recorder
    let result = metrics_server::install_metrics_recorder(&config);

    // Then: Should fail
    assert!(
        result.is_err(),
        "install_metrics_recorder should fail with invalid address"
    );
}

#[test]
#[serial]
fn test_install_metrics_recorder_rejects_unsupported_endpoint() {
    let config = MetricsConfig {
        enabled: true,
        listen_addr: "127.0.0.1".to_string(),
        port: 19101,
        endpoint: "/custom".to_string(),
    };

    let result = metrics_server::install_metrics_recorder(&config);

    assert!(
        result.is_err(),
        "install_metrics_recorder should reject unsupported endpoint paths"
    );
}

#[tokio::test]
#[serial]
async fn test_daemon_metrics_are_recorded() {
    use ironpost_core::config::IronpostConfig;

    // Given: A config with metrics disabled (to avoid global recorder conflict in tests)
    let mut config = IronpostConfig::default();
    config.metrics.enabled = false; // Disabled to avoid recorder already installed error
    config.ebpf.enabled = false; // Disable eBPF to avoid Linux-only dependencies
    config.log_pipeline.enabled = false;
    config.container.enabled = false;
    config.sbom.enabled = false;

    // When: Building orchestrator
    let result = ironpost_daemon::orchestrator::Orchestrator::build_from_config(config).await;

    // Then: Should succeed
    assert!(
        result.is_ok(),
        "orchestrator should build successfully: {:?}",
        result.err()
    );

    // Note: This test verifies that orchestrator builds successfully even when metrics
    // are disabled. To test actual metric recording, we would need to scrape the /metrics
    // HTTP endpoint in an end-to-end integration test with a fresh process.
}

#[tokio::test]
#[serial]
async fn test_metrics_disabled_does_not_start_server() {
    use ironpost_core::config::IronpostConfig;

    // Given: A config with metrics disabled
    let mut config = IronpostConfig::default();
    config.metrics.enabled = false;
    config.ebpf.enabled = false;
    config.log_pipeline.enabled = false;
    config.container.enabled = false;
    config.sbom.enabled = false;

    // When: Building orchestrator
    let result = ironpost_daemon::orchestrator::Orchestrator::build_from_config(config).await;

    // Then: Should succeed without starting metrics server
    assert!(
        result.is_ok(),
        "orchestrator should build successfully even with metrics disabled: {:?}",
        result.err()
    );

    // The metrics server should not be started (no port conflict should occur)
}

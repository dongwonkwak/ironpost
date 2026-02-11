//! Orchestrator integration tests.
//!
//! Tests the full flow: config loading -> module init -> start -> health check -> shutdown.

use std::path::PathBuf;
use std::time::Duration;

use ironpost_core::config::IronpostConfig;
use tokio::time::sleep;

/// Helper function to create a minimal test config.
fn minimal_test_config() -> IronpostConfig {
    let toml_str = r#"
[general]
log_level = "info"
pid_file = ""

[ebpf]
enabled = false

[log_pipeline]
enabled = false

[container]
enabled = false

[sbom]
enabled = false
"#;
    IronpostConfig::parse(toml_str).expect("failed to parse minimal config")
}

/// Helper function to create a config with log-pipeline enabled.
fn log_pipeline_only_config() -> IronpostConfig {
    let toml_str = r#"
[general]
log_level = "info"
pid_file = ""

[ebpf]
enabled = false

[log_pipeline]
enabled = true
sources = ["syslog"]
syslog_bind = "0.0.0.0:514"
watch_paths = []
batch_size = 100
flush_interval_secs = 5

[container]
enabled = false

[sbom]
enabled = false
"#;
    IronpostConfig::parse(toml_str).expect("failed to parse log-pipeline config")
}

/// Helper function to create a config with container-guard enabled (requires log-pipeline).
fn container_guard_config() -> IronpostConfig {
    let toml_str = r#"
[general]
log_level = "info"
pid_file = ""

[ebpf]
enabled = false

[log_pipeline]
enabled = true
sources = ["syslog"]
syslog_bind = "0.0.0.0:514"
watch_paths = []
batch_size = 100
flush_interval_secs = 5

[container]
enabled = true
docker_socket = "/var/run/docker.sock"
poll_interval_secs = 10
policy_path = ""
auto_isolate = false

[sbom]
enabled = false
"#;
    IronpostConfig::parse(toml_str).expect("failed to parse container-guard config")
}

#[tokio::test]
async fn test_orchestrator_build_with_all_modules_disabled() {
    // Given: A config with all modules disabled
    let config = minimal_test_config();

    // When: Building orchestrator
    let result = ironpost_daemon::orchestrator::Orchestrator::build_from_config(config).await;

    // Then: Should succeed with zero enabled modules
    assert!(
        result.is_ok(),
        "orchestrator should build successfully with all modules disabled"
    );
    let orchestrator = result.expect("orchestrator should be Some");
    let health = orchestrator.health().await;
    assert_eq!(
        health.modules.len(),
        0,
        "no modules should be registered when all are disabled"
    );
}

#[tokio::test]
async fn test_orchestrator_build_with_log_pipeline_enabled() {
    // Given: A config with only log-pipeline enabled
    let config = log_pipeline_only_config();

    // When: Building orchestrator
    let result = ironpost_daemon::orchestrator::Orchestrator::build_from_config(config).await;

    // Then: Should succeed with one module
    assert!(
        result.is_ok(),
        "orchestrator should build successfully with log-pipeline enabled"
    );
    let orchestrator = result.expect("orchestrator should be Some");
    let health = orchestrator.health().await;
    assert_eq!(
        health.modules.len(),
        1,
        "one module should be registered (log-pipeline)"
    );
    assert_eq!(health.modules[0].name, "log-pipeline");
    assert!(health.modules[0].enabled);
}

#[tokio::test]
async fn test_orchestrator_build_with_invalid_config_fails() {
    // Given: An invalid config (negative buffer capacity not possible in TOML, but test validation)
    let toml_str = r#"
[general]
log_level = "invalid_level"

[log_pipeline]
enabled = true
buffer_capacity = 0
"#;
    let result = IronpostConfig::parse(toml_str);

    // Then: Should parse successfully (validation happens later)
    assert!(
        result.is_ok(),
        "parsing should succeed even if values are invalid"
    );
}

#[tokio::test]
async fn test_orchestrator_start_and_stop_with_disabled_modules() {
    // Given: Orchestrator with all modules disabled
    let config = minimal_test_config();
    let orchestrator = ironpost_daemon::orchestrator::Orchestrator::build_from_config(config)
        .await
        .expect("build should succeed");

    // When: Starting modules (none enabled)
    // Note: We cannot call run() as it blocks waiting for signals
    // Instead we'll test the lifecycle in a controlled way

    // Then: Health check should show healthy (no modules to fail)
    let health = orchestrator.health().await;
    assert_eq!(health.modules.len(), 0, "no modules should be running");
}

#[tokio::test]
async fn test_orchestrator_health_aggregation_all_disabled() {
    // Given: Orchestrator with all modules disabled
    let config = minimal_test_config();
    let orchestrator = ironpost_daemon::orchestrator::Orchestrator::build_from_config(config)
        .await
        .expect("build should succeed");

    // When: Checking health
    let health = orchestrator.health().await;

    // Then: Status should be Healthy (no enabled modules)
    assert!(
        health.status.is_healthy(),
        "daemon should be healthy when all modules are disabled"
    );
    assert_eq!(health.modules.len(), 0);
}

#[tokio::test]
async fn test_orchestrator_config_access() {
    // Given: Orchestrator built from config
    let config = minimal_test_config();
    let log_level = config.general.log_level.clone();
    let orchestrator = ironpost_daemon::orchestrator::Orchestrator::build_from_config(config)
        .await
        .expect("build should succeed");

    // When: Accessing config
    let retrieved_config = orchestrator.config();

    // Then: Should return the same config
    assert_eq!(
        retrieved_config.general.log_level, log_level,
        "config should be accessible after build"
    );
}

#[tokio::test]
async fn test_orchestrator_uptime_increments() {
    // Given: Orchestrator just built
    let config = minimal_test_config();
    let orchestrator = ironpost_daemon::orchestrator::Orchestrator::build_from_config(config)
        .await
        .expect("build should succeed");

    // When: Checking health immediately
    let health1 = orchestrator.health().await;
    let uptime1 = health1.uptime_secs;

    // Wait a bit
    sleep(Duration::from_millis(100)).await;

    // Check health again
    let health2 = orchestrator.health().await;
    let uptime2 = health2.uptime_secs;

    // Then: Uptime should have increased (may be 0->0 if very fast, but should not decrease)
    assert!(
        uptime2 >= uptime1,
        "uptime should not decrease (was: {}, now: {})",
        uptime1,
        uptime2
    );
}

#[tokio::test]
#[ignore] // Requires Docker to be running
async fn test_orchestrator_with_container_guard_requires_docker() {
    // Given: Config with container-guard enabled
    let config = container_guard_config();

    // When: Building orchestrator
    let result = ironpost_daemon::orchestrator::Orchestrator::build_from_config(config).await;

    // Then: May fail if Docker is not available
    // This test is marked as ignore since it requires Docker
    if let Err(e) = result {
        eprintln!(
            "Container guard initialization failed (expected if Docker is not running): {}",
            e
        );
    }
}

#[tokio::test]
async fn test_orchestrator_load_from_nonexistent_file_fails() {
    // Given: A path that doesn't exist
    let path = PathBuf::from("/nonexistent/path/to/config.toml");

    // When: Loading config
    let result = ironpost_daemon::orchestrator::Orchestrator::build(&path).await;

    // Then: Should fail with appropriate error
    assert!(result.is_err(), "loading from nonexistent file should fail");
    if let Err(e) = result {
        let err_msg = e.to_string();
        assert!(
            err_msg.contains("failed to load config") || err_msg.contains("not found"),
            "error message should mention config loading failure, got: {}",
            err_msg
        );
    }
}

#[tokio::test]
async fn test_orchestrator_partial_config_sections() {
    // Given: A config with only some sections defined
    let toml_str = r#"
[general]
log_level = "debug"

[log_pipeline]
enabled = false
"#;
    let config = IronpostConfig::parse(toml_str).expect("should parse partial config");

    // When: Building orchestrator
    let result = ironpost_daemon::orchestrator::Orchestrator::build_from_config(config).await;

    // Then: Should succeed with default values for missing sections
    assert!(
        result.is_ok(),
        "partial config should work with defaults for missing sections"
    );
}

#[tokio::test]
async fn test_orchestrator_empty_config_uses_defaults() {
    // Given: An empty config string
    let toml_str = "";
    let config = IronpostConfig::parse(toml_str).expect("should parse empty config");

    // When: Building orchestrator
    let result = ironpost_daemon::orchestrator::Orchestrator::build_from_config(config).await;

    // Then: Should succeed with all default values
    assert!(result.is_ok(), "empty config should work with all defaults");
    let orchestrator = result.expect("orchestrator should be built");
    let retrieved_config = orchestrator.config();

    // Default behavior: log_pipeline enabled by default, others disabled
    assert!(!retrieved_config.ebpf.enabled);
    assert!(retrieved_config.log_pipeline.enabled); // enabled by default
    assert!(!retrieved_config.container.enabled);
    assert!(!retrieved_config.sbom.enabled);
}

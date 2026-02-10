//! Integration tests for `ironpost config` command.
//!
//! Tests config validation and display functionality with real TOML files.

use std::fs;
use tempfile::TempDir;

#[tokio::test]
async fn test_config_validate_valid_toml() {
    // Given: A valid config file
    let temp_dir = TempDir::new().expect("should create temp dir");
    let config_path = temp_dir.path().join("ironpost.toml");

    let valid_config = r#"
[general]
log_level = "info"
log_format = "json"

[ebpf]
enabled = false

[log_pipeline]
enabled = false

[container]
enabled = false

[sbom]
enabled = false
"#;

    fs::write(&config_path, valid_config).expect("should write config");

    // When: Loading the config
    let result = ironpost_core::config::IronpostConfig::load(&config_path).await;

    // Then: Should succeed
    assert!(result.is_ok(), "valid config should load successfully");
}

#[tokio::test]
async fn test_config_validate_malformed_toml() {
    // Given: A malformed TOML file
    let temp_dir = TempDir::new().expect("should create temp dir");
    let config_path = temp_dir.path().join("bad.toml");

    let malformed_config = r#"
[general
log_level = "info"
"#;

    fs::write(&config_path, malformed_config).expect("should write bad config");

    // When: Loading the config
    let result = ironpost_core::config::IronpostConfig::load(&config_path).await;

    // Then: Should fail
    assert!(result.is_err(), "malformed TOML should fail to load");
}

#[tokio::test]
async fn test_config_validate_missing_file() {
    // Given: A nonexistent file path
    let config_path = std::path::PathBuf::from("/nonexistent/ironpost.toml");

    // When: Loading the config
    let result = ironpost_core::config::IronpostConfig::load(&config_path).await;

    // Then: Should fail
    assert!(result.is_err(), "missing file should fail to load");
}

#[tokio::test]
async fn test_config_validate_empty_file() {
    // Given: An empty config file
    let temp_dir = TempDir::new().expect("should create temp dir");
    let config_path = temp_dir.path().join("empty.toml");

    fs::write(&config_path, "").expect("should write empty file");

    // When: Loading the config
    let result = ironpost_core::config::IronpostConfig::load(&config_path).await;

    // Then: Should succeed with defaults
    assert!(result.is_ok(), "empty config should use defaults");
    let config = result.expect("config should load");
    assert!(!config.ebpf.enabled, "ebpf should be disabled by default");
}

#[tokio::test]
async fn test_config_show_full_config() {
    // Given: A full config file
    let temp_dir = TempDir::new().expect("should create temp dir");
    let config_path = temp_dir.path().join("ironpost.toml");

    let full_config = r#"
[general]
log_level = "debug"
log_format = "pretty"

[ebpf]
enabled = true
interface = "eth0"
block_mode = "log"
metrics_interval_secs = 30

[log_pipeline]
enabled = true
sources = ["file", "syslog"]
syslog_bind = "127.0.0.1:514"
watch_paths = ["/var/log"]
batch_size = 100
flush_interval_secs = 5

[container]
enabled = true
docker_socket = "/var/run/docker.sock"
poll_interval_secs = 10
policy_path = "/etc/ironpost/policies"
auto_isolate = true

[sbom]
enabled = true
scan_dirs = ["/app", "/opt"]
vuln_db_update_hours = 24
vuln_db_path = "/var/lib/ironpost/vulndb.json"
min_severity = "medium"
output_format = "cyclonedx"
"#;

    fs::write(&config_path, full_config).expect("should write config");

    // When: Loading the config
    let result = ironpost_core::config::IronpostConfig::load(&config_path).await;

    // Then: Should succeed and contain all sections
    assert!(result.is_ok(), "full config should load");
    let config = result.expect("config should load");

    assert_eq!(config.general.log_level, "debug");
    assert!(config.ebpf.enabled);
    assert_eq!(config.ebpf.interface, "eth0");
    assert!(config.log_pipeline.enabled);
    assert_eq!(config.log_pipeline.batch_size, 100);
    assert!(config.container.enabled);
    assert_eq!(config.container.poll_interval_secs, 10);
    assert!(config.sbom.enabled);
    assert_eq!(config.sbom.min_severity, "medium");
}

#[tokio::test]
async fn test_config_unicode_values() {
    // Given: A config with unicode values
    let temp_dir = TempDir::new().expect("should create temp dir");
    let config_path = temp_dir.path().join("unicode.toml");

    let unicode_config = r#"
[general]
log_level = "info"

[sbom]
enabled = false
vuln_db_path = "/경로/데이터베이스.json"
"#;

    fs::write(&config_path, unicode_config).expect("should write unicode config");

    // When: Loading the config
    let result = ironpost_core::config::IronpostConfig::load(&config_path).await;

    // Then: Should handle unicode in paths
    assert!(result.is_ok(), "unicode config should load: {:?}", result);
    let config = result.expect("config should load");
    assert_eq!(config.general.log_level, "info");
    assert!(config.sbom.vuln_db_path.contains("데이터베이스"));
}

#[tokio::test]
async fn test_config_boundary_values() {
    // Given: A config with boundary values
    let temp_dir = TempDir::new().expect("should create temp dir");
    let config_path = temp_dir.path().join("boundary.toml");

    let boundary_config = r#"
[general]
log_level = "trace"

[log_pipeline]
enabled = true
batch_size = 1
flush_interval_secs = 1

[container]
enabled = true
poll_interval_secs = 1

[sbom]
enabled = true
vuln_db_update_hours = 1
"#;

    fs::write(&config_path, boundary_config).expect("should write config");

    // When: Loading the config
    let result = ironpost_core::config::IronpostConfig::load(&config_path).await;

    // Then: Should accept boundary values
    assert!(result.is_ok(), "boundary values should be accepted");
    let config = result.expect("config should load");
    assert_eq!(config.log_pipeline.batch_size, 1);
    assert_eq!(config.log_pipeline.flush_interval_secs, 1);
    assert_eq!(config.container.poll_interval_secs, 1);
    assert_eq!(config.sbom.vuln_db_update_hours, 1);
}

#[tokio::test]
async fn test_config_special_characters_in_paths() {
    // Given: Config with special characters in paths
    let temp_dir = TempDir::new().expect("should create temp dir");
    let config_path = temp_dir.path().join("special.toml");

    let special_config = r#"
[container]
enabled = true
docker_socket = "unix:///var/run/docker.sock"
policy_path = "/etc/ironpost/policies@v1.0"

[sbom]
enabled = true
vuln_db_path = "/var/lib/ironpost-db/vulndb-2024-02.json"
"#;

    fs::write(&config_path, special_config).expect("should write config");

    // When: Loading the config
    let result = ironpost_core::config::IronpostConfig::load(&config_path).await;

    // Then: Should preserve special characters
    assert!(result.is_ok(), "special chars should be preserved");
    let config = result.expect("config should load");
    assert!(config.container.docker_socket.contains("unix://"));
    assert!(config.container.policy_path.contains("@v1.0"));
    assert!(config.sbom.vuln_db_path.contains("2024-02"));
}

#[tokio::test]
async fn test_config_very_long_paths() {
    // Given: Config with very long paths
    let temp_dir = TempDir::new().expect("should create temp dir");
    let config_path = temp_dir.path().join("long.toml");

    let long_path = "/".to_string() + &"a".repeat(200);
    let long_config = format!(
        r#"
[sbom]
enabled = true
vuln_db_path = "{}"
"#,
        long_path
    );

    fs::write(&config_path, long_config).expect("should write config");

    // When: Loading the config
    let result = ironpost_core::config::IronpostConfig::load(&config_path).await;

    // Then: Should handle long paths
    assert!(result.is_ok(), "long paths should be handled");
    let config = result.expect("config should load");
    assert_eq!(config.sbom.vuln_db_path, long_path);
}

#[tokio::test]
async fn test_config_empty_arrays() {
    // Given: Config with empty arrays
    let temp_dir = TempDir::new().expect("should create temp dir");
    let config_path = temp_dir.path().join("empty-arrays.toml");

    let empty_array_config = r#"
[log_pipeline]
enabled = true
sources = []
watch_paths = []

[sbom]
enabled = true
scan_dirs = []
"#;

    fs::write(&config_path, empty_array_config).expect("should write config");

    // When: Loading the config
    let result = ironpost_core::config::IronpostConfig::load(&config_path).await;

    // Then: Should handle empty arrays
    assert!(result.is_ok(), "empty arrays should be accepted");
    let config = result.expect("config should load");
    assert!(config.log_pipeline.sources.is_empty());
    assert!(config.log_pipeline.watch_paths.is_empty());
    assert!(config.sbom.scan_dirs.is_empty());
}

#[tokio::test]
async fn test_config_multiline_arrays() {
    // Given: Config with multiline arrays
    let temp_dir = TempDir::new().expect("should create temp dir");
    let config_path = temp_dir.path().join("multiline.toml");

    let multiline_config = r#"
[log_pipeline]
enabled = true
watch_paths = [
    "/var/log/app1",
    "/var/log/app2",
    "/var/log/app3"
]

[sbom]
enabled = true
scan_dirs = [
    "/app",
    "/opt",
    "/usr/local"
]
"#;

    fs::write(&config_path, multiline_config).expect("should write config");

    // When: Loading the config
    let result = ironpost_core::config::IronpostConfig::load(&config_path).await;

    // Then: Should parse multiline arrays
    assert!(result.is_ok(), "multiline arrays should be parsed");
    let config = result.expect("config should load");
    assert_eq!(config.log_pipeline.watch_paths.len(), 3);
    assert_eq!(config.sbom.scan_dirs.len(), 3);
}

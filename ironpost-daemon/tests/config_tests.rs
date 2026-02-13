//! Configuration loading and validation tests.
//!
//! Tests TOML parsing, environment variable overrides, partial configs, and validation.

use ironpost_core::config::IronpostConfig;
use std::env;

#[test]
fn test_parse_full_config() {
    // Given: A complete TOML config
    let toml_str = r#"
[general]
log_level = "debug"
log_format = "json"
pid_file = "/var/run/ironpost.pid"

[ebpf]
enabled = true
interface = "eth0"
xdp_mode = "native"
ring_buffer_size = 524288
blocklist_max_entries = 10000

[log_pipeline]
enabled = true
sources = ["syslog", "file"]
syslog_bind = "0.0.0.0:514"
watch_paths = ["/var/log/syslog"]
batch_size = 200
flush_interval_secs = 10

[log_pipeline.storage]
postgres_url = "postgresql://localhost:5432/ironpost"
redis_url = "redis://localhost:6379"
retention_days = 30

[container]
enabled = true
docker_socket = "/var/run/docker.sock"
poll_interval_secs = 15
policy_path = "/etc/ironpost/policies"
auto_isolate = false

[sbom]
enabled = true
scan_dirs = ["/app", "/opt"]
vuln_db_update_hours = 48
vuln_db_path = "/var/lib/ironpost/vuln-db"
min_severity = "high"
output_format = "cyclonedx"
"#;

    // When: Parsing config
    let result = IronpostConfig::parse(toml_str);

    // Then: Should succeed
    assert!(result.is_ok(), "full config should parse successfully");
    let config = result.expect("config should parse");

    // Verify general section
    assert_eq!(config.general.log_level, "debug");
    assert_eq!(config.general.log_format, "json");
    assert_eq!(config.general.pid_file, "/var/run/ironpost.pid");

    // Verify module sections
    assert!(config.ebpf.enabled);
    assert_eq!(config.ebpf.interface, "eth0");

    assert!(config.log_pipeline.enabled);
    assert_eq!(config.log_pipeline.batch_size, 200);

    assert!(config.container.enabled);
    assert_eq!(config.container.poll_interval_secs, 15);

    assert!(config.sbom.enabled);
    assert_eq!(config.sbom.scan_dirs, vec!["/app", "/opt"]);
}

#[test]
fn test_parse_partial_config_with_defaults() {
    // Given: A partial config (only general section)
    let toml_str = r#"
[general]
log_level = "info"
"#;

    // When: Parsing config
    let result = IronpostConfig::parse(toml_str);

    // Then: Should use defaults for missing sections
    assert!(result.is_ok(), "partial config should parse with defaults");
    let config = result.expect("config should parse");

    assert_eq!(config.general.log_level, "info");

    // Default values for missing sections
    assert!(!config.ebpf.enabled, "ebpf should be disabled by default");
    assert!(
        config.log_pipeline.enabled,
        "log_pipeline should be enabled by default"
    );
    assert!(
        !config.container.enabled,
        "container should be disabled by default"
    );
    assert!(!config.sbom.enabled, "sbom should be disabled by default");
}

#[test]
fn test_parse_empty_config() {
    // Given: An empty config string
    let toml_str = "";

    // When: Parsing config
    let result = IronpostConfig::parse(toml_str);

    // Then: Should succeed with all defaults
    assert!(result.is_ok(), "empty config should parse successfully");
    let config = result.expect("config should parse");

    // All modules should have their default values (log_pipeline enabled by default)
    assert!(!config.ebpf.enabled);
    assert!(config.log_pipeline.enabled); // log_pipeline is enabled by default
    assert!(!config.container.enabled);
    assert!(!config.sbom.enabled);
}

#[test]
fn test_parse_malformed_toml_fails() {
    // Given: Malformed TOML
    let toml_str = r#"
[general
log_level = "info"
"#;

    // When: Parsing config
    let result = IronpostConfig::parse(toml_str);

    // Then: Should fail
    assert!(result.is_err(), "malformed TOML should fail to parse");
}

#[test]
fn test_parse_invalid_section_fails() {
    // Given: TOML with invalid field type
    let toml_str = r#"
[log_pipeline]
enabled = true
batch_size = "not_a_number"
"#;

    // When: Parsing config
    let result = IronpostConfig::parse(toml_str);

    // Then: Should fail
    assert!(result.is_err(), "invalid field type should fail to parse");
}

#[test]
#[serial_test::serial]
fn test_env_override_general_log_level() {
    // Given: A base config and environment variable
    let toml_str = r#"
[general]
log_level = "info"
"#;

    // SAFETY: Test isolation - we set and clean up env vars
    // Store original value if it exists
    let original_value = env::var("IRONPOST_GENERAL_LOG_LEVEL").ok();
    unsafe {
        env::set_var("IRONPOST_GENERAL_LOG_LEVEL", "debug");
    }

    // When: Loading config with env overrides
    let mut config = IronpostConfig::parse(toml_str).expect("should parse");
    config.apply_env_overrides();

    // Then: Environment variable should override TOML value
    let result = config.general.log_level.clone();

    // Cleanup (restore original or remove)
    // SAFETY: Test cleanup
    unsafe {
        match original_value {
            Some(val) => env::set_var("IRONPOST_GENERAL_LOG_LEVEL", val),
            None => env::remove_var("IRONPOST_GENERAL_LOG_LEVEL"),
        }
    }

    assert_eq!(result, "debug", "env var should override TOML value");
}

#[test]
#[serial_test::serial]
fn test_env_override_ebpf_interface() {
    // Given: Config with eBPF interface
    let toml_str = r#"
[ebpf]
enabled = true
interface = "eth0"
"#;

    // SAFETY: Test isolation
    let original_value = env::var("IRONPOST_EBPF_INTERFACE").ok();
    unsafe {
        env::set_var("IRONPOST_EBPF_INTERFACE", "wlan0");
    }

    // When: Applying env overrides
    let mut config = IronpostConfig::parse(toml_str).expect("should parse");
    config.apply_env_overrides();

    // Then: Should use env var value
    let result = config.ebpf.interface.clone();

    // Cleanup
    // SAFETY: Test cleanup
    unsafe {
        match original_value {
            Some(val) => env::set_var("IRONPOST_EBPF_INTERFACE", val),
            None => env::remove_var("IRONPOST_EBPF_INTERFACE"),
        }
    }

    assert_eq!(result, "wlan0", "env var should override interface");
}

#[test]
#[serial_test::serial]
fn test_env_override_takes_precedence_over_empty_toml() {
    // Given: Empty config and environment variable
    let toml_str = "";

    // SAFETY: Test isolation
    let original_value = env::var("IRONPOST_GENERAL_LOG_LEVEL").ok();
    unsafe {
        env::set_var("IRONPOST_GENERAL_LOG_LEVEL", "trace");
    }

    // When: Loading with env overrides
    let mut config = IronpostConfig::parse(toml_str).expect("should parse");
    config.apply_env_overrides();

    // Then: Environment variable should set value
    let result = config.general.log_level.clone();

    // Cleanup
    // SAFETY: Test cleanup
    unsafe {
        match original_value {
            Some(val) => env::set_var("IRONPOST_GENERAL_LOG_LEVEL", val),
            None => env::remove_var("IRONPOST_GENERAL_LOG_LEVEL"),
        }
    }

    assert_eq!(result, "trace", "env var should work even with empty TOML");
}

#[test]
#[serial_test::serial]
fn test_env_override_no_env_var_keeps_toml() {
    // Given: Config without corresponding env var
    let toml_str = r#"
[general]
log_level = "warn"
"#;

    // SAFETY: Ensure no env var is set for this test
    let original_value = env::var("IRONPOST_GENERAL_LOG_LEVEL").ok();
    unsafe {
        env::remove_var("IRONPOST_GENERAL_LOG_LEVEL");
    }

    // When: Applying env overrides (no env vars set)
    let mut config = IronpostConfig::parse(toml_str).expect("should parse");
    config.apply_env_overrides();

    // Then: TOML value should remain
    let result = config.general.log_level.clone();

    // Cleanup - restore original value if it existed
    // SAFETY: Test cleanup
    if let Some(val) = original_value {
        unsafe {
            env::set_var("IRONPOST_GENERAL_LOG_LEVEL", val);
        }
    }

    assert_eq!(
        result, "warn",
        "TOML value should remain when no env var is set"
    );
}

#[test]
fn test_parse_config_with_empty_arrays() {
    // Given: Config with empty arrays
    let toml_str = r#"
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
"#;

    // When: Parsing config
    let result = IronpostConfig::parse(toml_str);

    // Then: Should succeed with empty arrays
    assert!(result.is_ok(), "config with empty arrays should parse");
    let config = result.expect("config should parse");

    assert!(config.log_pipeline.watch_paths.is_empty());
    assert!(config.container.policy_path.is_empty());
}

#[test]
fn test_parse_config_with_multiple_array_items() {
    // Given: Config with multiple array items
    let toml_str = r#"
[sbom]
enabled = true
scan_dirs = ["/app", "/opt", "/usr/local"]
vuln_db_update_hours = 24
vuln_db_path = "/var/lib/ironpost/vuln-db"
min_severity = "medium"
output_format = "cyclonedx"
"#;

    // When: Parsing config
    let result = IronpostConfig::parse(toml_str);

    // Then: Should parse all array items
    assert!(result.is_ok(), "config with arrays should parse");
    let config = result.expect("config should parse");

    assert_eq!(config.sbom.scan_dirs.len(), 3);
    assert_eq!(config.sbom.scan_dirs[0], "/app");
    assert_eq!(config.sbom.scan_dirs[1], "/opt");
    assert_eq!(config.sbom.scan_dirs[2], "/usr/local");
}

#[test]
fn test_validation_succeeds_for_valid_config() {
    // Given: A valid config
    let toml_str = r#"
[general]
log_level = "info"

[log_pipeline]
enabled = true
sources = ["syslog"]
syslog_bind = "0.0.0.0:514"
watch_paths = []
batch_size = 100
flush_interval_secs = 5
"#;

    let config = IronpostConfig::parse(toml_str).expect("should parse");

    // When: Validating config
    let result = config.validate();

    // Then: Should succeed
    assert!(result.is_ok(), "valid config should pass validation");
}

#[test]
fn test_parse_unicode_in_strings() {
    // Given: Config with unicode characters
    let toml_str = r#"
[general]
log_level = "정보"
pid_file = "/var/run/아이언포스트.pid"
"#;

    // When: Parsing config
    let result = IronpostConfig::parse(toml_str);

    // Then: Should handle unicode
    assert!(result.is_ok(), "config with unicode should parse");
    let config = result.expect("config should parse");
    assert_eq!(config.general.log_level, "정보");
}

#[test]
fn test_parse_very_long_strings() {
    // Given: Config with very long strings
    let long_path = "/".to_string() + &"a".repeat(1000);
    let toml_str = format!(
        r#"
[general]
pid_file = "{}"
"#,
        long_path
    );

    // When: Parsing config
    let result = IronpostConfig::parse(&toml_str);

    // Then: Should handle long strings
    assert!(result.is_ok(), "config with long strings should parse");
    let config = result.expect("config should parse");
    assert_eq!(config.general.pid_file, long_path);
}

#[test]
fn test_parse_special_characters_in_paths() {
    // Given: Config with special characters
    let toml_str = r#"
[general]
pid_file = "/var/run/ironpost-daemon@1.0.pid"

[container]
enabled = true
docker_socket = "unix:///var/run/docker.sock"
poll_interval_secs = 10
policy_path = ""
auto_isolate = false
"#;

    // When: Parsing config
    let result = IronpostConfig::parse(toml_str);

    // Then: Should preserve special characters
    assert!(result.is_ok(), "config with special chars should parse");
    let config = result.expect("config should parse");
    assert!(config.general.pid_file.contains('@'));
    assert!(config.container.docker_socket.contains("unix://"));
}

#[test]
fn test_parse_boundary_values() {
    // Given: Config with boundary values
    let toml_str = r#"
[log_pipeline]
enabled = true
sources = ["syslog"]
syslog_bind = "0.0.0.0:514"
watch_paths = []
batch_size = 1
flush_interval_secs = 1

[sbom]
enabled = true
scan_dirs = []
vuln_db_update_hours = 1
vuln_db_path = "/tmp/vuln-db"
min_severity = "critical"
output_format = "cyclonedx"
"#;

    // When: Parsing config
    let result = IronpostConfig::parse(toml_str);

    // Then: Should accept boundary values
    assert!(result.is_ok(), "config with boundary values should parse");
    let config = result.expect("config should parse");

    assert_eq!(config.log_pipeline.batch_size, 1);
    assert_eq!(config.log_pipeline.flush_interval_secs, 1);
}

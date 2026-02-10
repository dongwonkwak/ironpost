//! Module initialization tests.
//!
//! Tests the initialization of individual modules and their channel wiring.

use ironpost_core::config::IronpostConfig;
use tokio::sync::mpsc;

#[tokio::test]
async fn test_log_pipeline_init_disabled() {
    // Given: Config with log-pipeline disabled
    let config = IronpostConfig::parse(
        r#"
[log_pipeline]
enabled = false
"#,
    )
    .expect("should parse config");

    let (_alert_tx, _alert_rx) = mpsc::channel(16);

    // When: Initializing log-pipeline
    let result = ironpost_daemon::modules::log_pipeline::init(&config, None, _alert_tx);

    // Then: Should return None (module disabled)
    assert!(result.is_ok(), "init should succeed");
    assert!(
        result.expect("result should be Ok").is_none(),
        "disabled module should return None"
    );
}

#[tokio::test]
async fn test_log_pipeline_init_enabled() {
    // Given: Config with log-pipeline enabled
    let config = IronpostConfig::parse(
        r#"
[log_pipeline]
enabled = true
buffer_capacity = 1000
batch_size = 100
flush_interval_secs = 5
alert_dedup_window_secs = 60
alert_rate_limit = 100
rule_dirs = []
log_collectors = []
"#,
    )
    .expect("should parse config");

    let (_alert_tx, _alert_rx) = mpsc::channel(16);

    // When: Initializing log-pipeline
    let result = ironpost_daemon::modules::log_pipeline::init(&config, None, _alert_tx);

    // Then: Should return a module handle
    assert!(result.is_ok(), "init should succeed");
    let handle = result.expect("result should be Ok");
    assert!(
        handle.is_some(),
        "enabled module should return Some(handle)"
    );

    let handle = handle.expect("handle should be Some");
    assert_eq!(handle.name, "log-pipeline");
    assert!(handle.enabled);
}

#[tokio::test]
async fn test_log_pipeline_init_with_packet_receiver() {
    // Given: Config with log-pipeline enabled and a packet receiver
    let config = IronpostConfig::parse(
        r#"
[log_pipeline]
enabled = true
buffer_capacity = 1000
batch_size = 100
flush_interval_secs = 5
alert_dedup_window_secs = 60
alert_rate_limit = 100
rule_dirs = []
log_collectors = []
"#,
    )
    .expect("should parse config");

    let (_packet_tx, packet_rx) = mpsc::channel(16);
    let (_alert_tx, _alert_rx) = mpsc::channel(16);

    // When: Initializing with packet receiver
    let result = ironpost_daemon::modules::log_pipeline::init(&config, Some(packet_rx), _alert_tx);

    // Then: Should succeed
    assert!(result.is_ok(), "init with packet_rx should succeed");
    let handle = result
        .expect("result should be Ok")
        .expect("handle should be Some");
    assert_eq!(handle.name, "log-pipeline");
}

#[tokio::test]
async fn test_sbom_scanner_init_disabled() {
    // Given: Config with SBOM scanner disabled
    let config = IronpostConfig::parse(
        r#"
[sbom]
enabled = false
"#,
    )
    .expect("should parse config");

    let (_alert_tx, _alert_rx) = mpsc::channel(16);

    // When: Initializing SBOM scanner
    let result = ironpost_daemon::modules::sbom_scanner::init(&config, _alert_tx);

    // Then: Should return None
    assert!(result.is_ok(), "init should succeed");
    assert!(
        result.expect("result should be Ok").is_none(),
        "disabled module should return None"
    );
}

#[tokio::test]
async fn test_sbom_scanner_init_enabled() {
    // Given: Config with SBOM scanner enabled
    let config = IronpostConfig::parse(
        r#"
[sbom]
enabled = true
scan_interval_secs = 3600
scan_dirs = ["/tmp/test"]
db_url = "https://example.com/vulndb.json"
db_update_interval_secs = 86400
report_output_dir = "/tmp/reports"
report_formats = ["cyclonedx"]
severity_threshold = "Medium"
"#,
    )
    .expect("should parse config");

    let (_alert_tx, _alert_rx) = mpsc::channel(16);

    // When: Initializing SBOM scanner
    let result = ironpost_daemon::modules::sbom_scanner::init(&config, _alert_tx);

    // Then: Should return a module handle
    assert!(result.is_ok(), "init should succeed");
    let handle = result.expect("result should be Ok");
    assert!(
        handle.is_some(),
        "enabled module should return Some(handle)"
    );

    let handle = handle.expect("handle should be Some");
    assert_eq!(handle.name, "sbom-scanner");
    assert!(handle.enabled);
}

#[tokio::test]
#[ignore] // Requires Docker to be running
async fn test_container_guard_init_enabled_requires_docker() {
    // Given: Config with container-guard enabled
    let config = IronpostConfig::parse(
        r#"
[container]
enabled = true
docker_socket = "/var/run/docker.sock"
monitor_interval_secs = 10
policy_dirs = []
"#,
    )
    .expect("should parse config");

    let (_alert_tx, alert_rx) = mpsc::channel(16);

    // When: Initializing container-guard
    let result = ironpost_daemon::modules::container_guard::init(&config, alert_rx);

    // Then: May fail if Docker is not available
    match result {
        Ok(Some((handle, _action_rx))) => {
            assert_eq!(handle.name, "container-guard");
            assert!(handle.enabled);
        }
        Ok(None) => {
            panic!("enabled module should not return None");
        }
        Err(e) => {
            eprintln!(
                "Container guard init failed (expected if Docker not running): {:?}",
                e
            );
        }
    }
}

#[tokio::test]
async fn test_container_guard_init_disabled() {
    // Given: Config with container-guard disabled
    let config = IronpostConfig::parse(
        r#"
[container]
enabled = false
"#,
    )
    .expect("should parse config");

    let (_alert_tx, alert_rx) = mpsc::channel(16);

    // When: Initializing container-guard
    let result = ironpost_daemon::modules::container_guard::init(&config, alert_rx);

    // Then: Should return None
    assert!(result.is_ok(), "init should succeed");
    assert!(
        result.expect("result should be Ok").is_none(),
        "disabled module should return None"
    );
}

#[cfg(target_os = "linux")]
#[tokio::test]
#[ignore] // Requires root privileges and network interface
async fn test_ebpf_engine_init_enabled_linux_only() {
    use ironpost_core::event::PacketEvent;

    // Given: Config with eBPF engine enabled
    let config = IronpostConfig::parse(
        r#"
[ebpf]
enabled = true
interface = "lo"
block_mode = "drop"
metrics_interval_secs = 10
rules = []
"#,
    )
    .expect("should parse config");

    let (packet_tx, _packet_rx) = mpsc::channel::<PacketEvent>(16);

    // When: Initializing eBPF engine
    let result = ironpost_daemon::modules::ebpf::init(&config, packet_tx);

    // Then: May fail if not running as root or interface doesn't exist
    match result {
        Ok(Some((handle, _rx))) => {
            assert_eq!(handle.name, "ebpf-engine");
            assert!(handle.enabled);
        }
        Ok(None) => {
            eprintln!("eBPF engine returned None (disabled or unavailable)");
        }
        Err(e) => {
            eprintln!(
                "eBPF engine init failed (expected if not root or no interface): {:?}",
                e
            );
        }
    }
}

#[cfg(target_os = "linux")]
#[tokio::test]
async fn test_ebpf_engine_init_disabled() {
    use ironpost_core::event::PacketEvent;

    // Given: Config with eBPF engine disabled
    let config = IronpostConfig::parse(
        r#"
[ebpf]
enabled = false
"#,
    )
    .expect("should parse config");

    let (packet_tx, _packet_rx) = mpsc::channel::<PacketEvent>(16);

    // When: Initializing eBPF engine
    let result = ironpost_daemon::modules::ebpf::init(&config, packet_tx);

    // Then: Should return None
    assert!(result.is_ok(), "init should succeed");
    assert!(
        result.expect("result should be Ok").is_none(),
        "disabled module should return None"
    );
}

#[tokio::test]
async fn test_module_init_with_invalid_config_paths() {
    // Given: Config with non-existent directories
    let config = IronpostConfig::parse(
        r#"
[log_pipeline]
enabled = true
buffer_capacity = 1000
batch_size = 100
flush_interval_secs = 5
alert_dedup_window_secs = 60
alert_rate_limit = 100
rule_dirs = ["/nonexistent/rules/path"]
log_collectors = []
"#,
    )
    .expect("should parse config");

    let (_alert_tx, _alert_rx) = mpsc::channel(16);

    // When: Initializing with invalid paths
    let result = ironpost_daemon::modules::log_pipeline::init(&config, None, _alert_tx);

    // Then: Should still succeed (directories are just empty)
    assert!(
        result.is_ok(),
        "init should succeed even with non-existent rule dirs"
    );
}

#[tokio::test]
async fn test_multiple_modules_share_alert_channel() {
    // Given: Config with multiple modules enabled
    let config = IronpostConfig::parse(
        r#"
[log_pipeline]
enabled = true
buffer_capacity = 1000
batch_size = 100
flush_interval_secs = 5
alert_dedup_window_secs = 60
alert_rate_limit = 100
rule_dirs = []
log_collectors = []

[sbom]
enabled = true
scan_interval_secs = 3600
scan_dirs = ["/tmp"]
db_url = "https://example.com/db.json"
db_update_interval_secs = 86400
report_output_dir = "/tmp/reports"
report_formats = ["cyclonedx"]
severity_threshold = "Medium"
"#,
    )
    .expect("should parse config");

    let (alert_tx, _alert_rx) = mpsc::channel(16);

    // When: Initializing both modules with the same alert_tx (cloned)
    let log_result =
        ironpost_daemon::modules::log_pipeline::init(&config, None, alert_tx.clone());
    let sbom_result = ironpost_daemon::modules::sbom_scanner::init(&config, alert_tx.clone());

    // Then: Both should succeed
    assert!(log_result.is_ok(), "log-pipeline init should succeed");
    assert!(sbom_result.is_ok(), "sbom-scanner init should succeed");

    assert!(
        log_result.expect("log result").is_some(),
        "log-pipeline should be enabled"
    );
    assert!(
        sbom_result.expect("sbom result").is_some(),
        "sbom-scanner should be enabled"
    );
}

#[tokio::test]
async fn test_module_init_with_minimal_config() {
    // Given: Minimal config for each module type
    let configs = vec![
        r#"[log_pipeline]
enabled = true
buffer_capacity = 100
batch_size = 10
flush_interval_secs = 1
alert_dedup_window_secs = 10
alert_rate_limit = 10
rule_dirs = []
log_collectors = []"#,
        r#"[sbom]
enabled = true
scan_interval_secs = 60
scan_dirs = []
db_url = "http://localhost/db.json"
db_update_interval_secs = 3600
report_output_dir = "/tmp"
report_formats = ["cyclonedx"]
severity_threshold = "Low""#,
    ];

    for config_str in configs {
        let config = IronpostConfig::parse(config_str).expect("should parse minimal config");

        // When: Initializing modules
        let (alert_tx, _alert_rx) = mpsc::channel(1);

        // Try log-pipeline if enabled
        if config.log_pipeline.enabled {
            let result = ironpost_daemon::modules::log_pipeline::init(&config, None, alert_tx);
            assert!(result.is_ok(), "minimal config should work for log-pipeline");
        }

        // Try sbom-scanner if enabled
        let (alert_tx2, _) = mpsc::channel(1);
        if config.sbom.enabled {
            let result = ironpost_daemon::modules::sbom_scanner::init(&config, alert_tx2);
            assert!(result.is_ok(), "minimal config should work for sbom-scanner");
        }
    }
}

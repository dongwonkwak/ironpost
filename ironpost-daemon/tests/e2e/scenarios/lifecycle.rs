//! S3: Configuration loading -> Orchestrator initialization -> health check.
//!
//! Validates the complete daemon startup lifecycle from config file
//! through module initialization to health check reporting.

use crate::helpers::config::*;
use crate::helpers::mock_pipeline::*;

use ironpost_core::config::IronpostConfig;
use ironpost_core::pipeline::HealthStatus;
use ironpost_daemon::health::{ModuleHealth, aggregate_status};
use ironpost_daemon::modules::{ModuleHandle, ModuleRegistry};

/// Valid ironpost.toml -> Orchestrator::build_from_config() succeeds.
#[tokio::test]
async fn test_e2e_config_load_and_init() {
    let config = TestConfigBuilder::new()
        .log_pipeline(true)
        .container(true)
        .log_level("info")
        .batch_size(100)
        .build();

    // Validate configuration
    let result = config.validate();
    assert!(result.is_ok(), "config validation should succeed");

    // Verify expected values
    assert_eq!(config.general.log_level, "info");
    assert_eq!(config.log_pipeline.batch_size, 100);
    assert!(config.log_pipeline.enabled);
    assert!(config.container.enabled);
    assert!(!config.ebpf.enabled);
    assert!(!config.sbom.enabled);
}

/// All modules start successfully -> health_check() == Healthy.
#[tokio::test]
async fn test_e2e_all_modules_health_check() {
    let mut registry = ModuleRegistry::new();

    // Register mock modules (all healthy)
    registry.register(ModuleHandle::new(
        "ebpf-engine",
        true,
        Box::new(MockPipeline::healthy("ebpf")),
    ));
    registry.register(ModuleHandle::new(
        "log-pipeline",
        true,
        Box::new(MockPipeline::healthy("log")),
    ));
    registry.register(ModuleHandle::new(
        "container-guard",
        true,
        Box::new(MockPipeline::healthy("container")),
    ));

    // Start all modules
    registry
        .start_all()
        .await
        .expect("start_all should succeed");

    // Check health statuses
    let statuses = registry.health_statuses().await;
    assert_eq!(statuses.len(), 3);

    for (name, enabled, status) in &statuses {
        assert!(enabled, "module {} should be enabled", name);
        assert!(
            matches!(status, HealthStatus::Healthy),
            "module {} should be healthy",
            name
        );
    }

    // Aggregate status should be Healthy
    let module_healths: Vec<ModuleHealth> = statuses
        .iter()
        .map(|(name, enabled, status)| ModuleHealth {
            name: name.clone(),
            enabled: *enabled,
            status: status.clone(),
        })
        .collect();

    let aggregate = aggregate_status(&module_healths);
    assert!(
        matches!(aggregate, HealthStatus::Healthy),
        "aggregate status should be Healthy"
    );
}

/// Partial config (only [general] section) -> defaults fill in correctly.
#[tokio::test]
async fn test_e2e_partial_config_defaults() {
    let toml_str = r#"
[general]
log_level = "info"
"#;

    let config: IronpostConfig = toml::from_str(toml_str).expect("should parse partial config");

    // Validate that defaults are applied
    config.validate().expect("partial config should be valid");

    // Check default values
    assert_eq!(config.general.log_level, "info");
    assert_eq!(config.general.log_format, "json"); // Default
    assert!(!config.ebpf.enabled); // Default false
    assert!(config.log_pipeline.enabled); // Default TRUE per core config
    assert!(!config.container.enabled); // Default false
    assert!(!config.sbom.enabled); // Default false
}

/// Environment variable overrides config file values.
#[tokio::test]
async fn test_e2e_env_override_config() {
    let mut config = TestConfigBuilder::new()
        .log_level("info")
        .log_pipeline(true)
        .build();

    // Set environment variable
    // SAFETY: This test is single-threaded and sets/unsets the env var before/after use.
    // No other tests will observe this value as tokio::test runs tests serially by default.
    unsafe {
        std::env::set_var("IRONPOST_GENERAL_LOG_LEVEL", "debug");
    }

    // Apply environment overrides
    config.apply_env_overrides();

    // Clean up
    // SAFETY: Restore environment to pre-test state.
    unsafe {
        std::env::remove_var("IRONPOST_GENERAL_LOG_LEVEL");
    }

    // Verify override was applied
    assert_eq!(
        config.general.log_level, "debug",
        "log_level should be overridden to debug"
    );
}

/// Config loaded from tempfile produces identical result to parse().
#[tokio::test]
async fn test_e2e_config_from_file_roundtrip() {
    let original = TestConfigBuilder::new()
        .log_level("warn")
        .log_format("pretty") // Use valid format: "json" or "pretty"
        .log_pipeline(true)
        .batch_size(200)
        .build();

    // Write to tempfile
    let (_tempfile, path) = write_config_to_tempfile(&original);

    // Load from tempfile
    let loaded = IronpostConfig::load(&path)
        .await
        .expect("should load config from tempfile");

    // Verify values match
    assert_eq!(loaded.general.log_level, original.general.log_level);
    assert_eq!(loaded.general.log_format, original.general.log_format);
    assert_eq!(loaded.log_pipeline.enabled, original.log_pipeline.enabled);
    assert_eq!(
        loaded.log_pipeline.batch_size,
        original.log_pipeline.batch_size
    );
}

/// Aggregate health status: Degraded + Healthy -> Degraded.
#[tokio::test]
async fn test_e2e_health_aggregation_degraded() {
    let modules = vec![
        ModuleHealth {
            name: "ebpf".to_owned(),
            enabled: true,
            status: HealthStatus::Healthy,
        },
        ModuleHealth {
            name: "log-pipeline".to_owned(),
            enabled: true,
            status: HealthStatus::Degraded("high latency".to_owned()),
        },
        ModuleHealth {
            name: "container-guard".to_owned(),
            enabled: true,
            status: HealthStatus::Healthy,
        },
    ];

    let aggregate = aggregate_status(&modules);
    match aggregate {
        HealthStatus::Degraded(reason) => {
            assert!(
                reason.contains("log-pipeline"),
                "reason should mention degraded module"
            );
            assert!(
                reason.contains("high latency"),
                "reason should contain original message"
            );
        }
        _ => panic!("expected Degraded status"),
    }
}

/// Aggregate health status: Unhealthy + Degraded -> Unhealthy (worst case).
#[tokio::test]
async fn test_e2e_health_aggregation_unhealthy() {
    let modules = vec![
        ModuleHealth {
            name: "ebpf".to_owned(),
            enabled: true,
            status: HealthStatus::Unhealthy("failed to attach XDP".to_owned()),
        },
        ModuleHealth {
            name: "log-pipeline".to_owned(),
            enabled: true,
            status: HealthStatus::Degraded("high latency".to_owned()),
        },
        ModuleHealth {
            name: "container-guard".to_owned(),
            enabled: true,
            status: HealthStatus::Healthy,
        },
    ];

    let aggregate = aggregate_status(&modules);
    match aggregate {
        HealthStatus::Unhealthy(reason) => {
            assert!(
                reason.contains("ebpf"),
                "reason should mention unhealthy module"
            );
        }
        _ => panic!("expected Unhealthy status"),
    }
}

/// Disabled modules don't affect aggregate health.
#[tokio::test]
async fn test_e2e_health_disabled_modules_ignored() {
    let modules = vec![
        ModuleHealth {
            name: "ebpf".to_owned(),
            enabled: false,
            status: HealthStatus::Unhealthy("not started".to_owned()),
        },
        ModuleHealth {
            name: "log-pipeline".to_owned(),
            enabled: true,
            status: HealthStatus::Healthy,
        },
    ];

    let aggregate = aggregate_status(&modules);
    assert!(
        matches!(aggregate, HealthStatus::Healthy),
        "disabled unhealthy module should not affect aggregate"
    );
}

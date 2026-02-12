//! S5: Invalid configuration -> appropriate error messages.
//!
//! Validates that bad configuration is rejected with clear,
//! actionable error messages pointing to the problematic field.

use crate::helpers::config::*;

use ironpost_core::config::IronpostConfig;

/// Malformed TOML syntax -> parse error with location info.
#[tokio::test]
async fn test_e2e_invalid_toml_syntax() {
    let invalid_toml = r#"
[general]
log_level = "info"
invalid = [[[toml
"#;

    let result = toml::from_str::<IronpostConfig>(invalid_toml);
    assert!(result.is_err(), "should fail to parse invalid TOML");

    let err_msg = result.unwrap_err().to_string();
    // TOML parser typically includes location information
    assert!(
        err_msg.contains("expected") || err_msg.contains("invalid"),
        "error should describe the syntax problem: {}",
        err_msg
    );
}

/// Invalid log_level value -> validation error naming the field.
#[tokio::test]
async fn test_e2e_invalid_log_level() {
    let mut config = TestConfigBuilder::new().build();
    config.general.log_level = "verbose".to_owned(); // Invalid value

    let result = config.validate();
    assert!(
        result.is_err(),
        "should fail validation with invalid log_level"
    );

    let err_msg = result.unwrap_err().to_string();
    assert!(
        err_msg.contains("log_level") || err_msg.contains("invalid"),
        "error should mention log_level: {}",
        err_msg
    );
}

/// Zero batch_size -> validation error.
#[tokio::test]
async fn test_e2e_invalid_batch_size() {
    let mut config = TestConfigBuilder::new().log_pipeline(true).build();
    config.log_pipeline.batch_size = 0; // Invalid: must be > 0

    let result = config.validate();
    assert!(
        result.is_err(),
        "should fail validation with batch_size = 0"
    );

    let err_msg = result.unwrap_err().to_string();
    assert!(
        err_msg.contains("batch_size") || err_msg.contains("must be greater than"),
        "error should mention batch_size: {}",
        err_msg
    );
}

/// Required field missing when module is enabled -> clear error.
#[tokio::test]
async fn test_e2e_missing_required_field() {
    let mut config = TestConfigBuilder::new().build();
    config.ebpf.enabled = true;
    config.ebpf.interface = String::new(); // Empty interface

    let result = config.validate();
    assert!(
        result.is_err(),
        "should fail validation with empty interface when eBPF enabled"
    );

    let err_msg = result.unwrap_err().to_string();
    assert!(
        err_msg.contains("interface") || err_msg.contains("eBPF"),
        "error should mention interface: {}",
        err_msg
    );
}

/// Non-existent config file path -> IO/FileNotFound error.
#[tokio::test]
async fn test_e2e_nonexistent_config_path() {
    let path = std::path::Path::new("/nonexistent/ironpost.toml");

    let result = IronpostConfig::load(path).await;
    assert!(result.is_err(), "should fail to load non-existent file");

    let err = result.unwrap_err();
    // Check if it's an IO error (file not found)
    match err {
        ironpost_core::error::IronpostError::Config(cfg_err) => {
            let msg = cfg_err.to_string();
            assert!(
                msg.contains("No such file")
                    || msg.contains("not found")
                    || msg.contains("cannot open"),
                "error should indicate file not found: {}",
                msg
            );
        }
        _ => panic!("expected Config error, got: {:?}", err),
    }
}

/// Empty config file -> all defaults applied, validation passes.
#[tokio::test]
async fn test_e2e_empty_config_uses_defaults() {
    let empty_toml = "";

    let config: IronpostConfig =
        toml::from_str(empty_toml).expect("should parse empty config and use defaults");

    // Validate should succeed
    config.validate().expect("empty config should be valid");

    // Check default values
    assert_eq!(config.general.log_level, "info");
    assert_eq!(config.general.log_format, "json");
    assert!(!config.ebpf.enabled);
    assert!(config.log_pipeline.enabled); // Default TRUE per core config
    assert!(!config.container.enabled);
    assert!(!config.sbom.enabled);
}

/// Invalid SBOM output_format when sbom.enabled = true -> error.
#[tokio::test]
async fn test_e2e_invalid_sbom_format() {
    let mut config = TestConfigBuilder::new().sbom(true).build();
    config.sbom.output_format = "xml".to_owned(); // Invalid: only "cyclonedx" or "spdx"

    let result = config.validate();
    assert!(
        result.is_err(),
        "should fail validation with invalid SBOM format"
    );

    let err_msg = result.unwrap_err().to_string();
    assert!(
        err_msg.contains("output_format") || err_msg.contains("SBOM"),
        "error should mention output_format: {}",
        err_msg
    );
}

/// Invalid XDP mode when ebpf.enabled = true -> error.
#[tokio::test]
async fn test_e2e_invalid_xdp_mode() {
    let mut config = TestConfigBuilder::new().build();
    config.ebpf.enabled = true;
    config.ebpf.interface = "eth0".to_owned();
    config.ebpf.xdp_mode = "turbo".to_owned(); // Invalid: only "skb", "native", "offload"

    let result = config.validate();
    assert!(
        result.is_err(),
        "should fail validation with invalid xdp_mode"
    );

    let err_msg = result.unwrap_err().to_string();
    assert!(
        err_msg.contains("xdp_mode") || err_msg.contains("eBPF"),
        "error should mention xdp_mode: {}",
        err_msg
    );
}

/// Very large batch_size exceeds reasonable limit -> validation error.
#[tokio::test]
async fn test_e2e_batch_size_too_large() {
    let mut config = TestConfigBuilder::new().log_pipeline(true).build();
    config.log_pipeline.batch_size = usize::MAX; // Unreasonably large

    let result = config.validate();
    assert!(
        result.is_err(),
        "batch_size validation should reject unreasonably large values"
    );

    let err_msg = result.unwrap_err().to_string();
    assert!(
        err_msg.contains("batch_size") || err_msg.contains("too large"),
        "error should mention batch_size limit: {}",
        err_msg
    );
}

/// Invalid min_severity for SBOM scanner -> validation error.
#[tokio::test]
async fn test_e2e_invalid_sbom_severity() {
    let mut config = TestConfigBuilder::new().sbom(true).build();
    config.sbom.min_severity = "extreme".to_owned(); // Invalid: not a valid severity

    let result = config.validate();
    assert!(
        result.is_err(),
        "should fail validation with invalid min_severity"
    );

    let err_msg = result.unwrap_err().to_string();
    assert!(
        err_msg.contains("severity") || err_msg.contains("SBOM"),
        "error should mention severity: {}",
        err_msg
    );
}

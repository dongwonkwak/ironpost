//! S5: Invalid configuration -> appropriate error messages.
//!
//! Validates that bad configuration is rejected with clear,
//! actionable error messages pointing to the problematic field.

// Helpers will be used when tests are implemented in T7.6
#[allow(unused_imports)]
use crate::helpers::config::*;

#[allow(unused_imports)]
use ironpost_core::config::IronpostConfig;
#[allow(unused_imports)]
use ironpost_core::error::{ConfigError, IronpostError};

// ---------------------------------------------------------------------------
// T7.6 will implement the following test functions.
// ---------------------------------------------------------------------------

/// Malformed TOML syntax -> parse error with location info.
#[tokio::test]
#[ignore] // T7.6: implementation pending
async fn test_e2e_invalid_toml_syntax() {
    // 1. Parse string with invalid TOML: "invalid = [[[toml"
    // 2. Assert Err(IronpostError::Config(ConfigError::ParseFailed))
    // 3. Assert error message contains location hint
}

/// Invalid log_level value -> validation error naming the field.
#[tokio::test]
#[ignore] // T7.6: implementation pending
async fn test_e2e_invalid_log_level() {
    // 1. Create config with log_level = "verbose"
    // 2. Call validate()
    // 3. Assert error mentions "log_level"
    // 4. Assert error mentions valid options
}

/// Zero batch_size -> validation error.
#[tokio::test]
#[ignore] // T7.6: implementation pending
async fn test_e2e_invalid_batch_size() {
    // 1. Create config with batch_size = 0
    // 2. validate() -> Err
    // 3. Assert error mentions the field name "batch_size"
}

/// Required field missing when module is enabled -> clear error.
#[tokio::test]
#[ignore] // T7.6: implementation pending
async fn test_e2e_missing_required_field() {
    // 1. Enable ebpf with empty interface
    // 2. validate() -> Err mentioning "interface"
}

/// Non-existent config file path -> IO/FileNotFound error.
#[tokio::test]
#[ignore] // T7.6: implementation pending
async fn test_e2e_nonexistent_config_path() {
    // 1. IronpostConfig::load("/nonexistent/ironpost.toml")
    // 2. Assert FileNotFound error
}

/// Empty config file -> all defaults applied, validation passes.
#[tokio::test]
#[ignore] // T7.6: implementation pending
async fn test_e2e_empty_config_uses_defaults() {
    // 1. Parse empty string ""
    // 2. validate() -> Ok
    // 3. Assert default values
}

/// Invalid SBOM output_format when sbom.enabled = true -> error.
#[tokio::test]
#[ignore] // T7.6: implementation pending
async fn test_e2e_invalid_sbom_format() {
    // 1. Enable SBOM with output_format = "xml"
    // 2. validate() -> Err mentioning "output_format"
}

/// Invalid XDP mode when ebpf.enabled = true -> error.
#[tokio::test]
#[ignore] // T7.6: implementation pending
async fn test_e2e_invalid_xdp_mode() {
    // 1. Enable eBPF with xdp_mode = "turbo"
    // 2. validate() -> Err mentioning "xdp_mode"
}

//! `ironpost config` command handler

use std::io::Write;
use std::path::Path;

use serde::Serialize;
use tracing::info;

use ironpost_core::config::IronpostConfig;

use crate::cli::{ConfigAction, ConfigArgs};
use crate::error::CliError;
use crate::output::{OutputWriter, Render};

/// Execute the `config` command.
pub async fn execute(
    args: ConfigArgs,
    config_path: &Path,
    writer: &OutputWriter,
) -> Result<(), CliError> {
    match args.action {
        ConfigAction::Validate => execute_validate(config_path, writer).await,
        ConfigAction::Show { section } => execute_show(config_path, section, writer).await,
    }
}

/// Execute the config validate subcommand.
///
/// Attempts to load and validate the configuration file, reporting any errors.
///
/// # Arguments
///
/// * `config_path` - Path to ironpost.toml configuration file
/// * `writer` - Output writer for rendering results
///
/// # Errors
///
/// Returns `CliError::Config` if validation fails (missing fields, invalid values, parse errors).
async fn execute_validate(config_path: &Path, writer: &OutputWriter) -> Result<(), CliError> {
    info!(path = %config_path.display(), "validating configuration");

    let result = IronpostConfig::load(config_path).await;

    let report = match result {
        Ok(_) => ConfigValidationReport {
            source: config_path.display().to_string(),
            valid: true,
            errors: Vec::new(),
        },
        Err(e) => ConfigValidationReport {
            source: config_path.display().to_string(),
            valid: false,
            errors: vec![e.to_string()],
        },
    };

    writer.render(&report)?;

    if !report.valid {
        return Err(CliError::Config("configuration is invalid".to_owned()));
    }

    Ok(())
}

/// Execute the config show subcommand.
///
/// Loads and displays the effective configuration (file + env overrides + defaults).
/// Automatically redacts sensitive credentials from database and Redis URLs.
///
/// # Arguments
///
/// * `config_path` - Path to ironpost.toml configuration file
/// * `section` - Optional section name to display (general, ebpf, log_pipeline, container, sbom)
/// * `writer` - Output writer for rendering results
///
/// # Errors
///
/// Returns `CliError::Config` if loading fails or `CliError::Command` if section name is invalid.
async fn execute_show(
    config_path: &Path,
    section: Option<String>,
    writer: &OutputWriter,
) -> Result<(), CliError> {
    info!(path = %config_path.display(), "loading configuration");

    let mut config = IronpostConfig::load(config_path).await?;

    // Redact sensitive credentials from storage URLs
    redact_credentials(&mut config);

    let report = if let Some(section_name) = section {
        // Filter to specific section
        match section_name.as_str() {
            "general" => ConfigReport {
                source: config_path.display().to_string(),
                section: Some("general".to_owned()),
                config_toml: toml::to_string_pretty(&config.general)
                    .unwrap_or_else(|e| format!("(serialization error: {})", e)),
            },
            "ebpf" => ConfigReport {
                source: config_path.display().to_string(),
                section: Some("ebpf".to_owned()),
                config_toml: toml::to_string_pretty(&config.ebpf)
                    .unwrap_or_else(|e| format!("(serialization error: {})", e)),
            },
            "log_pipeline" => ConfigReport {
                source: config_path.display().to_string(),
                section: Some("log_pipeline".to_owned()),
                config_toml: toml::to_string_pretty(&config.log_pipeline)
                    .unwrap_or_else(|e| format!("(serialization error: {})", e)),
            },
            "container" => ConfigReport {
                source: config_path.display().to_string(),
                section: Some("container".to_owned()),
                config_toml: toml::to_string_pretty(&config.container)
                    .unwrap_or_else(|e| format!("(serialization error: {})", e)),
            },
            "sbom" => ConfigReport {
                source: config_path.display().to_string(),
                section: Some("sbom".to_owned()),
                config_toml: toml::to_string_pretty(&config.sbom)
                    .unwrap_or_else(|e| format!("(serialization error: {})", e)),
            },
            _ => {
                return Err(CliError::Command(format!(
                    "unknown section: {} (expected: general, ebpf, log_pipeline, container, sbom)",
                    section_name
                )));
            }
        }
    } else {
        // Show full config
        ConfigReport {
            source: config_path.display().to_string(),
            section: None,
            config_toml: toml::to_string_pretty(&config)
                .unwrap_or_else(|e| format!("(serialization error: {})", e)),
        }
    };

    writer.render(&report)?;

    Ok(())
}

/// Redact sensitive credentials from database and Redis URLs.
///
/// Replaces credentials in URLs like `postgresql://user:password@host:5432/db`
/// with `postgresql://***REDACTED***@host:5432/db`.
fn redact_credentials(config: &mut IronpostConfig) {
    config.log_pipeline.storage.postgres_url =
        redact_url(&config.log_pipeline.storage.postgres_url);
    config.log_pipeline.storage.redis_url = redact_url(&config.log_pipeline.storage.redis_url);
}

/// Redact credentials from a connection URL.
///
/// Preserves the scheme and host while replacing user:password with ***REDACTED***.
fn redact_url(url: &str) -> String {
    if url.is_empty() {
        return url.to_owned();
    }

    // Parse URL to find credentials
    if let Some(scheme_end) = url.find("://") {
        let scheme = &url[..scheme_end + 3]; // Include "://"
        let rest = &url[scheme_end + 3..];

        // Check if there are credentials (indicated by @ before the first /)
        if let Some(at_pos) = rest.find('@') {
            if let Some(slash_pos) = rest.find('/') {
                // Credentials exist if @ comes before /
                if at_pos < slash_pos {
                    let after_at = &rest[at_pos..];
                    return format!("{}***REDACTED***{}", scheme, after_at);
                }
            } else {
                // No path, just host:port - check if @ is part of credentials
                let after_at = &rest[at_pos..];
                return format!("{}***REDACTED***{}", scheme, after_at);
            }
        }
    }

    // No credentials found, return as-is
    url.to_owned()
}

/// Configuration display report.
///
/// Contains the source file path and serialized TOML configuration.
/// The `config_toml` field is skipped during JSON serialization (only used for text rendering).
#[derive(Serialize)]
pub struct ConfigReport {
    /// Configuration file path
    pub source: String,
    /// Optional section name (None = full config)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub section: Option<String>,
    /// Serialized TOML configuration (with redacted credentials)
    #[serde(skip)]
    pub config_toml: String,
}

impl Render for ConfigReport {
    fn render_text(&self, w: &mut dyn Write) -> std::io::Result<()> {
        use colored::Colorize;

        if let Some(ref section) = self.section {
            let section_label = format!("[{}]", section);
            writeln!(
                w,
                "Configuration {} (source: {})",
                section_label.bold(),
                self.source
            )?;
        } else {
            writeln!(w, "Configuration (source: {})", self.source.bold())?;
        }

        writeln!(w)?;
        write!(w, "{}", self.config_toml)?;

        Ok(())
    }
}

/// Configuration validation report.
///
/// Contains validation result and any error messages encountered.
#[derive(Serialize)]
pub struct ConfigValidationReport {
    /// Configuration file path
    pub source: String,
    /// Whether the configuration is valid
    pub valid: bool,
    /// Validation error messages (empty if valid)
    pub errors: Vec<String>,
}

impl Render for ConfigValidationReport {
    fn render_text(&self, w: &mut dyn Write) -> std::io::Result<()> {
        use colored::Colorize;

        writeln!(w, "Config Validation: {}", self.source.bold())?;

        if self.valid {
            writeln!(w, "  Result: {}", "VALID".green().bold())?;
        } else {
            writeln!(w, "  Result: {}", "INVALID".red().bold())?;
            for err in &self.errors {
                writeln!(w, "  Error: {}", err.red())?;
            }
        }

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_config_report_render_text_full_config() {
        let report = ConfigReport {
            source: "test.toml".to_owned(),
            section: None,
            config_toml: "[general]\nlog_level = \"info\"".to_owned(),
        };

        let mut buffer = Vec::new();
        report
            .render_text(&mut buffer)
            .expect("text rendering should succeed");

        let output = String::from_utf8(buffer).expect("valid UTF-8");
        assert!(output.contains("Configuration"), "should contain header");
        assert!(
            output.contains("test.toml"),
            "should contain source filename"
        );
        assert!(
            output.contains("log_level"),
            "should contain config content"
        );
    }

    #[test]
    fn test_config_report_render_text_specific_section() {
        let report = ConfigReport {
            source: "/etc/ironpost.toml".to_owned(),
            section: Some("ebpf".to_owned()),
            config_toml: "interface = \"eth0\"".to_owned(),
        };

        let mut buffer = Vec::new();
        report
            .render_text(&mut buffer)
            .expect("text rendering should succeed");

        let output = String::from_utf8(buffer).expect("valid UTF-8");
        assert!(output.contains("[ebpf]"), "should show section name");
        assert!(output.contains("interface"), "should show config content");
    }

    #[test]
    fn test_config_report_json_serialization() {
        let report = ConfigReport {
            source: "test.toml".to_owned(),
            section: Some("log_pipeline".to_owned()),
            config_toml: "enabled = true".to_owned(),
        };

        let json = serde_json::to_string(&report).expect("JSON serialization should succeed");
        let parsed: serde_json::Value = serde_json::from_str(&json).expect("should parse JSON");

        assert_eq!(parsed["source"].as_str(), Some("test.toml"));
        assert_eq!(parsed["section"].as_str(), Some("log_pipeline"));
        // config_toml is skipped in serialization
        assert!(
            parsed.get("config_toml").is_none(),
            "config_toml should be skipped"
        );
    }

    #[test]
    fn test_config_validation_report_valid() {
        let report = ConfigValidationReport {
            source: "ironpost.toml".to_owned(),
            valid: true,
            errors: Vec::new(),
        };

        let mut buffer = Vec::new();
        report
            .render_text(&mut buffer)
            .expect("text rendering should succeed");

        let output = String::from_utf8(buffer).expect("valid UTF-8");
        assert!(output.contains("VALID"), "should show valid status");
        assert!(!output.contains("Error:"), "should not show errors");
    }

    #[test]
    fn test_config_validation_report_invalid_single_error() {
        let report = ConfigValidationReport {
            source: "bad.toml".to_owned(),
            valid: false,
            errors: vec!["missing required field: interface".to_owned()],
        };

        let mut buffer = Vec::new();
        report
            .render_text(&mut buffer)
            .expect("text rendering should succeed");

        let output = String::from_utf8(buffer).expect("valid UTF-8");
        assert!(output.contains("INVALID"), "should show invalid status");
        assert!(
            output.contains("missing required field"),
            "should show error message"
        );
    }

    #[test]
    fn test_config_validation_report_invalid_multiple_errors() {
        let report = ConfigValidationReport {
            source: "bad.toml".to_owned(),
            valid: false,
            errors: vec![
                "error 1: invalid port".to_owned(),
                "error 2: missing section".to_owned(),
                "error 3: invalid type".to_owned(),
            ],
        };

        let mut buffer = Vec::new();
        report
            .render_text(&mut buffer)
            .expect("text rendering should succeed");

        let output = String::from_utf8(buffer).expect("valid UTF-8");
        assert!(output.contains("error 1"), "should show first error");
        assert!(output.contains("error 2"), "should show second error");
        assert!(output.contains("error 3"), "should show third error");
    }

    #[test]
    fn test_config_validation_report_json_valid() {
        let report = ConfigValidationReport {
            source: "test.toml".to_owned(),
            valid: true,
            errors: Vec::new(),
        };

        let json = serde_json::to_string(&report).expect("JSON serialization should succeed");
        let parsed: serde_json::Value = serde_json::from_str(&json).expect("should parse JSON");

        assert_eq!(parsed["valid"].as_bool(), Some(true));
        assert_eq!(
            parsed["errors"].as_array().expect("should be array").len(),
            0
        );
    }

    #[test]
    fn test_config_validation_report_json_invalid() {
        let report = ConfigValidationReport {
            source: "bad.toml".to_owned(),
            valid: false,
            errors: vec!["error message".to_owned()],
        };

        let json = serde_json::to_string(&report).expect("JSON serialization should succeed");
        let parsed: serde_json::Value = serde_json::from_str(&json).expect("should parse JSON");

        assert_eq!(parsed["valid"].as_bool(), Some(false));
        assert_eq!(
            parsed["errors"].as_array().expect("should be array").len(),
            1
        );
    }

    #[test]
    fn test_config_report_empty_section() {
        let report = ConfigReport {
            source: "test.toml".to_owned(),
            section: None,
            config_toml: String::new(),
        };

        let mut buffer = Vec::new();
        report
            .render_text(&mut buffer)
            .expect("empty config should render");

        let output = String::from_utf8(buffer).expect("valid UTF-8");
        assert!(output.contains("Configuration"), "should have header");
    }

    #[test]
    fn test_config_report_unicode_in_source_path() {
        let report = ConfigReport {
            source: "/path/to/設定.toml".to_owned(),
            section: None,
            config_toml: "test = true".to_owned(),
        };

        let mut buffer = Vec::new();
        report
            .render_text(&mut buffer)
            .expect("unicode path should render");

        let output = String::from_utf8(buffer).expect("valid UTF-8");
        assert!(output.contains("設定.toml"), "should handle unicode paths");
    }

    #[test]
    fn test_config_validation_report_long_error_message() {
        let long_error = "a".repeat(500);
        let report = ConfigValidationReport {
            source: "test.toml".to_owned(),
            valid: false,
            errors: vec![long_error.clone()],
        };

        let mut buffer = Vec::new();
        report
            .render_text(&mut buffer)
            .expect("long error should render");

        let output = String::from_utf8(buffer).expect("valid UTF-8");
        assert!(
            output.contains(&long_error),
            "should handle long error messages"
        );
    }

    #[test]
    fn test_config_report_multiline_toml() {
        let multiline_toml = r#"
[general]
log_level = "info"

[ebpf]
enabled = true
interface = "eth0"
"#;
        let report = ConfigReport {
            source: "test.toml".to_owned(),
            section: None,
            config_toml: multiline_toml.to_owned(),
        };

        let mut buffer = Vec::new();
        report
            .render_text(&mut buffer)
            .expect("multiline config should render");

        let output = String::from_utf8(buffer).expect("valid UTF-8");
        assert!(output.contains("[general]"), "should show all sections");
        assert!(output.contains("[ebpf]"), "should show all sections");
    }
}

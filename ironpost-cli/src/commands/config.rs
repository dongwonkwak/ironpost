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

async fn execute_show(
    config_path: &Path,
    section: Option<String>,
    writer: &OutputWriter,
) -> Result<(), CliError> {
    info!(path = %config_path.display(), "loading configuration");

    let config = IronpostConfig::load(config_path).await?;

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

#[derive(Serialize)]
pub struct ConfigReport {
    pub source: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub section: Option<String>,
    #[serde(skip)]
    pub config_toml: String,
}

impl Render for ConfigReport {
    fn render_text(&self, w: &mut dyn Write) -> std::io::Result<()> {
        use colored::Colorize;

        if let Some(ref section) = self.section {
            writeln!(
                w,
                "Configuration [{}] (source: {})",
                section.bold(),
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

#[derive(Serialize)]
pub struct ConfigValidationReport {
    pub source: String,
    pub valid: bool,
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

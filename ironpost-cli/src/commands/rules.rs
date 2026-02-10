//! `ironpost rules` command handler

use std::io::Write;
use std::path::Path;

use serde::Serialize;
use tracing::info;

use ironpost_core::config::IronpostConfig;
use ironpost_log_pipeline::rule::RuleLoader;

use crate::cli::{RulesAction, RulesArgs};
use crate::error::CliError;
use crate::output::{OutputWriter, Render};

/// Execute the `rules` command.
pub async fn execute(
    args: RulesArgs,
    config_path: &Path,
    writer: &OutputWriter,
) -> Result<(), CliError> {
    match args.action {
        RulesAction::List { status } => execute_list(config_path, status, writer).await,
        RulesAction::Validate { path } => execute_validate(&path, writer).await,
    }
}

async fn execute_list(
    config_path: &Path,
    status_filter: Option<String>,
    writer: &OutputWriter,
) -> Result<(), CliError> {
    let _config = IronpostConfig::load(config_path).await?;

    // Default rules directory (hardcoded for now, should come from config in future)
    let rules_dir = "/etc/ironpost/rules";

    info!(rules_dir, "loading detection rules");

    // Load rules from directory
    let rules = RuleLoader::load_directory(rules_dir)
        .await
        .map_err(|e| CliError::Rule(format!("failed to load rules: {}", e)))?;

    // Filter by status if provided
    let filtered_rules: Vec<_> = if let Some(ref filter) = status_filter {
        rules
            .into_iter()
            .filter(|r| {
                let rule_status = match r.status {
                    ironpost_log_pipeline::rule::RuleStatus::Enabled => "enabled",
                    ironpost_log_pipeline::rule::RuleStatus::Disabled => "disabled",
                    ironpost_log_pipeline::rule::RuleStatus::Test => "test",
                };
                rule_status == filter
            })
            .collect()
    } else {
        rules
    };

    let report = RuleListReport {
        total: filtered_rules.len(),
        rules: filtered_rules
            .into_iter()
            .map(|r| RuleEntry {
                id: r.id,
                title: r.title,
                severity: format!("{:?}", r.severity),
                status: match r.status {
                    ironpost_log_pipeline::rule::RuleStatus::Enabled => "enabled".to_owned(),
                    ironpost_log_pipeline::rule::RuleStatus::Disabled => "disabled".to_owned(),
                    ironpost_log_pipeline::rule::RuleStatus::Test => "test".to_owned(),
                },
                tags: r.tags,
            })
            .collect(),
    };

    writer.render(&report)?;

    Ok(())
}

async fn execute_validate(path: &Path, writer: &OutputWriter) -> Result<(), CliError> {
    info!(path = %path.display(), "validating detection rules");

    // Attempt to load all rules and collect errors
    let result = RuleLoader::load_directory(path).await;

    let (valid, invalid, errors) = match result {
        Ok(rules) => (rules.len(), 0, Vec::new()),
        Err(e) => {
            // Try to parse directory and collect per-file errors
            // For now, report a single error
            (
                0,
                1,
                vec![RuleError {
                    file: path.display().to_string(),
                    error: e.to_string(),
                }],
            )
        }
    };

    let report = RuleValidationReport {
        path: path.display().to_string(),
        total_files: valid + invalid,
        valid,
        invalid,
        errors,
    };

    writer.render(&report)?;

    if invalid > 0 {
        return Err(CliError::Rule(format!("{} invalid rules", invalid)));
    }

    Ok(())
}

#[derive(Serialize)]
pub struct RuleListReport {
    pub total: usize,
    pub rules: Vec<RuleEntry>,
}

#[derive(Serialize)]
pub struct RuleEntry {
    pub id: String,
    pub title: String,
    pub severity: String,
    pub status: String,
    pub tags: Vec<String>,
}

impl Render for RuleListReport {
    fn render_text(&self, w: &mut dyn Write) -> std::io::Result<()> {
        use colored::Colorize;

        writeln!(
            w,
            "Detection Rules ({} total)",
            self.total.to_string().bold()
        )?;
        writeln!(w)?;
        writeln!(
            w,
            "{:<25} {:<30} {:<10} {:<10} Tags",
            "ID", "Title", "Severity", "Status"
        )?;
        writeln!(w, "{}", "-".repeat(90))?;

        for r in &self.rules {
            let status_colored = match r.status.as_str() {
                "enabled" => r.status.green(),
                "disabled" => r.status.yellow(),
                _ => r.status.normal(),
            };

            writeln!(
                w,
                "{:<25} {:<30} {:<10} {:<10} {}",
                r.id,
                r.title,
                r.severity,
                status_colored,
                r.tags.join(", ")
            )?;
        }

        Ok(())
    }
}

#[derive(Serialize)]
pub struct RuleValidationReport {
    pub path: String,
    pub total_files: usize,
    pub valid: usize,
    pub invalid: usize,
    pub errors: Vec<RuleError>,
}

#[derive(Serialize)]
pub struct RuleError {
    pub file: String,
    pub error: String,
}

impl Render for RuleValidationReport {
    fn render_text(&self, w: &mut dyn Write) -> std::io::Result<()> {
        use colored::Colorize;

        writeln!(w, "Rule Validation: {}", self.path.bold())?;
        writeln!(
            w,
            "  Files: {} total, {} valid, {} invalid",
            self.total_files,
            self.valid.to_string().green(),
            if self.invalid > 0 {
                self.invalid.to_string().red()
            } else {
                self.invalid.to_string().normal()
            }
        )?;

        if !self.errors.is_empty() {
            writeln!(w)?;
            writeln!(w, "Errors:")?;
            for e in &self.errors {
                writeln!(w, "  {}: {}", e.file.red(), e.error)?;
            }
        }

        Ok(())
    }
}

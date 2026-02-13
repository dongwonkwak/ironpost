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

/// Execute the rules list subcommand.
///
/// Loads detection rules from the rules directory and optionally filters by status.
///
/// # Arguments
///
/// * `config_path` - Path to ironpost.toml configuration file
/// * `status_filter` - Optional status filter (enabled, disabled, test)
/// * `writer` - Output writer for rendering results
///
/// # Errors
///
/// Returns `CliError::Rule` if rule loading fails (directory not found, invalid YAML, etc.)
async fn execute_list(
    config_path: &Path,
    status_filter: Option<String>,
    writer: &OutputWriter,
) -> Result<(), CliError> {
    let config = IronpostConfig::load(config_path).await?;

    // Use data_dir as base for rules directory
    // Rules are stored in {data_dir}/rules by convention
    let rules_dir = std::path::Path::new(&config.general.data_dir).join("rules");
    let rules_dir_str = rules_dir
        .to_str()
        .ok_or_else(|| CliError::Rule("rules directory path contains invalid UTF-8".to_string()))?;

    info!(rules_dir = rules_dir_str, "loading detection rules");

    // Load rules from directory
    let rules = RuleLoader::load_directory(rules_dir_str)
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

/// Execute the rules validate subcommand.
///
/// Validates all YAML rule files in the specified directory without loading them into the engine.
///
/// # Arguments
///
/// * `path` - Directory containing YAML rule files
/// * `writer` - Output writer for rendering results
///
/// # Errors
///
/// Returns `CliError::Rule` if one or more rules are invalid (exits with code 1).
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

/// Rule listing report.
///
/// Contains the total count and list of loaded rules (optionally filtered).
#[derive(Serialize)]
pub struct RuleListReport {
    /// Total number of rules (after filtering)
    pub total: usize,
    /// List of rule entries
    pub rules: Vec<RuleEntry>,
}

/// Individual detection rule entry.
#[derive(Serialize)]
pub struct RuleEntry {
    /// Unique rule identifier
    pub id: String,
    /// Human-readable rule title
    pub title: String,
    /// Detection severity level
    pub severity: String,
    /// Rule status (enabled, disabled, test)
    pub status: String,
    /// Rule tags for categorization
    pub tags: Vec<String>,
}

impl Render for RuleListReport {
    fn render_text(&self, w: &mut dyn Write) -> std::io::Result<()> {
        use colored::Colorize;

        writeln!(
            w,
            "Detection Rules ({} total)",
            format!("{} total", self.total).bold()
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

/// Rule validation report.
///
/// Contains validation summary and detailed error information for invalid rules.
#[derive(Serialize)]
pub struct RuleValidationReport {
    /// Rules directory path
    pub path: String,
    /// Total number of rule files processed
    pub total_files: usize,
    /// Count of valid rules
    pub valid: usize,
    /// Count of invalid rules
    pub invalid: usize,
    /// Validation errors (one per invalid rule)
    pub errors: Vec<RuleError>,
}

/// Rule validation error entry.
#[derive(Serialize)]
pub struct RuleError {
    /// Rule filename
    pub file: String,
    /// Error message
    pub error: String,
}

impl Render for RuleValidationReport {
    fn render_text(&self, w: &mut dyn Write) -> std::io::Result<()> {
        use colored::Colorize;

        writeln!(w, "Rule Validation: {}", self.path.bold())?;
        writeln!(
            w,
            "  Files: {}, {}, {}",
            self.total_files,
            format!("{} valid", self.valid).green(),
            if self.invalid > 0 {
                format!("{} invalid", self.invalid).red()
            } else {
                format!("{} invalid", self.invalid).normal()
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_rule_list_report_render_text_empty() {
        let report = RuleListReport {
            total: 0,
            rules: Vec::new(),
        };

        let mut buffer = Vec::new();
        report
            .render_text(&mut buffer)
            .expect("text rendering should succeed");

        let output = String::from_utf8(buffer).expect("valid UTF-8");
        assert!(output.contains("Detection Rules"), "should have header");
        assert!(output.contains("0 total"), "should show zero count");
    }

    #[test]
    fn test_rule_list_report_render_text_single_rule() {
        let report = RuleListReport {
            total: 1,
            rules: vec![RuleEntry {
                id: "rule-001".to_owned(),
                title: "Test Rule".to_owned(),
                severity: "High".to_owned(),
                status: "enabled".to_owned(),
                tags: vec!["test".to_owned(), "security".to_owned()],
            }],
        };

        let mut buffer = Vec::new();
        report
            .render_text(&mut buffer)
            .expect("text rendering should succeed");

        let output = String::from_utf8(buffer).expect("valid UTF-8");
        assert!(output.contains("rule-001"), "should show rule ID");
        assert!(output.contains("Test Rule"), "should show title");
        assert!(output.contains("High"), "should show severity");
        assert!(output.contains("enabled"), "should show status");
        assert!(output.contains("test"), "should show tags");
    }

    #[test]
    fn test_rule_list_report_render_text_multiple_rules() {
        let report = RuleListReport {
            total: 3,
            rules: vec![
                RuleEntry {
                    id: "rule-001".to_owned(),
                    title: "Rule 1".to_owned(),
                    severity: "Critical".to_owned(),
                    status: "enabled".to_owned(),
                    tags: vec![],
                },
                RuleEntry {
                    id: "rule-002".to_owned(),
                    title: "Rule 2".to_owned(),
                    severity: "Medium".to_owned(),
                    status: "disabled".to_owned(),
                    tags: vec!["test".to_owned()],
                },
                RuleEntry {
                    id: "rule-003".to_owned(),
                    title: "Rule 3".to_owned(),
                    severity: "Low".to_owned(),
                    status: "test".to_owned(),
                    tags: vec!["experimental".to_owned()],
                },
            ],
        };

        let mut buffer = Vec::new();
        report
            .render_text(&mut buffer)
            .expect("text rendering should succeed");

        let output = String::from_utf8(buffer).expect("valid UTF-8");
        assert!(output.contains("rule-001"), "should show first rule");
        assert!(output.contains("rule-002"), "should show second rule");
        assert!(output.contains("rule-003"), "should show third rule");
    }

    #[test]
    fn test_rule_list_report_json_serialization() {
        let report = RuleListReport {
            total: 1,
            rules: vec![RuleEntry {
                id: "test-id".to_owned(),
                title: "Test".to_owned(),
                severity: "High".to_owned(),
                status: "enabled".to_owned(),
                tags: vec!["tag1".to_owned()],
            }],
        };

        let json = serde_json::to_string(&report).expect("JSON serialization should succeed");
        let parsed: serde_json::Value = serde_json::from_str(&json).expect("should parse JSON");

        assert_eq!(parsed["total"].as_u64(), Some(1));
        assert_eq!(
            parsed["rules"].as_array().expect("should be array").len(),
            1
        );
    }

    #[test]
    fn test_rule_entry_json_structure() {
        let entry = RuleEntry {
            id: "rule-id".to_owned(),
            title: "Rule Title".to_owned(),
            severity: "Critical".to_owned(),
            status: "enabled".to_owned(),
            tags: vec!["tag1".to_owned(), "tag2".to_owned()],
        };

        let json = serde_json::to_string(&entry).expect("JSON serialization should succeed");
        let parsed: serde_json::Value = serde_json::from_str(&json).expect("should parse JSON");

        assert_eq!(parsed["id"].as_str(), Some("rule-id"));
        assert_eq!(parsed["title"].as_str(), Some("Rule Title"));
        assert_eq!(parsed["severity"].as_str(), Some("Critical"));
        assert_eq!(parsed["status"].as_str(), Some("enabled"));
        assert_eq!(parsed["tags"].as_array().expect("should be array").len(), 2);
    }

    #[test]
    fn test_rule_validation_report_render_text_valid() {
        let report = RuleValidationReport {
            path: "/etc/ironpost/rules".to_owned(),
            total_files: 5,
            valid: 5,
            invalid: 0,
            errors: Vec::new(),
        };

        let mut buffer = Vec::new();
        report
            .render_text(&mut buffer)
            .expect("text rendering should succeed");

        let output = String::from_utf8(buffer).expect("valid UTF-8");
        assert!(output.contains("Rule Validation"), "should have header");
        assert!(output.contains("5 valid"), "should show valid count");
        assert!(output.contains("0 invalid"), "should show invalid count");
    }

    #[test]
    fn test_rule_validation_report_render_text_invalid() {
        let report = RuleValidationReport {
            path: "/rules".to_owned(),
            total_files: 3,
            valid: 1,
            invalid: 2,
            errors: vec![
                RuleError {
                    file: "rule1.yaml".to_owned(),
                    error: "missing field: title".to_owned(),
                },
                RuleError {
                    file: "rule2.yaml".to_owned(),
                    error: "invalid severity level".to_owned(),
                },
            ],
        };

        let mut buffer = Vec::new();
        report
            .render_text(&mut buffer)
            .expect("text rendering should succeed");

        let output = String::from_utf8(buffer).expect("valid UTF-8");
        assert!(output.contains("2 invalid"), "should show invalid count");
        assert!(output.contains("rule1.yaml"), "should show error file");
        assert!(
            output.contains("missing field"),
            "should show error message"
        );
        assert!(output.contains("rule2.yaml"), "should show second error");
    }

    #[test]
    fn test_rule_validation_report_json_valid() {
        let report = RuleValidationReport {
            path: "/rules".to_owned(),
            total_files: 10,
            valid: 10,
            invalid: 0,
            errors: Vec::new(),
        };

        let json = serde_json::to_string(&report).expect("JSON serialization should succeed");
        let parsed: serde_json::Value = serde_json::from_str(&json).expect("should parse JSON");

        assert_eq!(parsed["total_files"].as_u64(), Some(10));
        assert_eq!(parsed["valid"].as_u64(), Some(10));
        assert_eq!(parsed["invalid"].as_u64(), Some(0));
        assert_eq!(
            parsed["errors"].as_array().expect("should be array").len(),
            0
        );
    }

    #[test]
    fn test_rule_validation_report_json_invalid() {
        let report = RuleValidationReport {
            path: "/rules".to_owned(),
            total_files: 2,
            valid: 0,
            invalid: 2,
            errors: vec![RuleError {
                file: "bad.yaml".to_owned(),
                error: "parse error".to_owned(),
            }],
        };

        let json = serde_json::to_string(&report).expect("JSON serialization should succeed");
        let parsed: serde_json::Value = serde_json::from_str(&json).expect("should parse JSON");

        assert_eq!(parsed["invalid"].as_u64(), Some(2));
        assert_eq!(
            parsed["errors"].as_array().expect("should be array").len(),
            1
        );
    }

    #[test]
    fn test_rule_error_json_structure() {
        let error = RuleError {
            file: "test.yaml".to_owned(),
            error: "test error message".to_owned(),
        };

        let json = serde_json::to_string(&error).expect("JSON serialization should succeed");
        let parsed: serde_json::Value = serde_json::from_str(&json).expect("should parse JSON");

        assert_eq!(parsed["file"].as_str(), Some("test.yaml"));
        assert_eq!(parsed["error"].as_str(), Some("test error message"));
    }

    #[test]
    fn test_rule_entry_empty_tags() {
        let entry = RuleEntry {
            id: "rule-1".to_owned(),
            title: "No Tags Rule".to_owned(),
            severity: "Medium".to_owned(),
            status: "enabled".to_owned(),
            tags: Vec::new(),
        };

        let mut buffer = Vec::new();
        let report = RuleListReport {
            total: 1,
            rules: vec![entry],
        };

        report
            .render_text(&mut buffer)
            .expect("should render empty tags");

        let output = String::from_utf8(buffer).expect("valid UTF-8");
        assert!(output.contains("rule-1"), "should show rule");
    }

    #[test]
    fn test_rule_entry_long_title() {
        let long_title = "a".repeat(100);
        let entry = RuleEntry {
            id: "rule-long".to_owned(),
            title: long_title.clone(),
            severity: "Low".to_owned(),
            status: "enabled".to_owned(),
            tags: vec![],
        };

        let json = serde_json::to_string(&entry).expect("should serialize long title");
        assert!(json.contains(&long_title), "should preserve long title");
    }

    #[test]
    fn test_rule_validation_report_many_errors() {
        let errors: Vec<RuleError> = (0..50)
            .map(|i| RuleError {
                file: format!("rule{}.yaml", i),
                error: format!("error {}", i),
            })
            .collect();

        let report = RuleValidationReport {
            path: "/rules".to_owned(),
            total_files: 50,
            valid: 0,
            invalid: 50,
            errors,
        };

        let mut buffer = Vec::new();
        report
            .render_text(&mut buffer)
            .expect("should render many errors");

        let output = String::from_utf8(buffer).expect("valid UTF-8");
        assert!(output.contains("50 invalid"), "should show count");
        assert!(output.contains("rule0.yaml"), "should show first error");
        assert!(output.contains("rule49.yaml"), "should show last error");
    }

    #[test]
    fn test_rule_list_report_unicode_content() {
        let report = RuleListReport {
            total: 1,
            rules: vec![RuleEntry {
                id: "unicode-rule".to_owned(),
                title: "検出ルール 日本語".to_owned(),
                severity: "High".to_owned(),
                status: "enabled".to_owned(),
                tags: vec!["日本".to_owned()],
            }],
        };

        let mut buffer = Vec::new();
        report
            .render_text(&mut buffer)
            .expect("should render unicode");

        let output = String::from_utf8(buffer).expect("valid UTF-8");
        assert!(output.contains("検出ルール"), "should handle unicode");
    }

    #[test]
    fn test_rule_entry_all_status_values() {
        let statuses = ["enabled", "disabled", "test"];
        for status in statuses {
            let entry = RuleEntry {
                id: format!("rule-{}", status),
                title: "Test".to_owned(),
                severity: "Medium".to_owned(),
                status: status.to_owned(),
                tags: vec![],
            };

            let json = serde_json::to_string(&entry).expect("should serialize");
            assert!(json.contains(status), "should preserve status: {}", status);
        }
    }
}

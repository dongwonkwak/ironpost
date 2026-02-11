//! CLI argument parsing using clap derive API
//!
//! This module defines the command-line interface structure using clap's derive macros.
//! It is purely declarative with no side effects or I/O.

use std::path::PathBuf;

use clap::{Args, Parser, Subcommand, ValueEnum};

/// Ironpost -- integrated security monitoring platform.
///
/// Use `ironpost <COMMAND> --help` for subcommand details.
#[derive(Parser, Debug)]
#[command(name = "ironpost", version, about, long_about = None)]
pub struct Cli {
    /// Path to the ironpost.toml configuration file.
    #[arg(short, long, default_value = "ironpost.toml")]
    pub config: PathBuf,

    /// Override log level (trace, debug, info, warn, error).
    #[arg(long, global = true)]
    pub log_level: Option<String>,

    /// Output format.
    #[arg(long, global = true, default_value = "text")]
    pub output: OutputFormat,

    #[command(subcommand)]
    pub command: Commands,
}

/// Supported output formats.
#[derive(Debug, Clone, Copy, ValueEnum)]
pub enum OutputFormat {
    /// Human-readable table / text output.
    Text,
    /// Machine-readable JSON.
    Json,
}

#[derive(Subcommand, Debug)]
pub enum Commands {
    /// Start the ironpost daemon.
    Start(StartArgs),

    /// Check status of each module.
    Status(StatusArgs),

    /// Run a one-shot SBOM vulnerability scan.
    Scan(ScanArgs),

    /// Manage detection rules.
    Rules(RulesArgs),

    /// Manage configuration.
    Config(ConfigArgs),
}

// ---- start ----

/// Start the ironpost daemon.
#[derive(Args, Debug)]
pub struct StartArgs {
    /// Run as a background daemon (default: foreground).
    #[arg(short = 'd', long)]
    pub daemonize: bool,

    /// Override PID file location (daemon mode only).
    #[arg(long)]
    pub pid_file: Option<PathBuf>,
}

// ---- status ----

/// Display module health and uptime.
#[derive(Args, Debug)]
pub struct StatusArgs {
    /// Show detailed per-module metrics.
    #[arg(short, long)]
    pub verbose: bool,
}

// ---- scan ----

/// Run a one-shot SBOM scan on a project directory.
#[derive(Args, Debug)]
pub struct ScanArgs {
    /// Path to scan (default: current directory).
    #[arg(default_value = ".")]
    pub path: PathBuf,

    /// Minimum severity to report (info, low, medium, high, critical).
    #[arg(long, default_value = "medium")]
    pub min_severity: String,

    /// SBOM output format (cyclonedx, spdx).
    #[arg(long, default_value = "cyclonedx")]
    pub sbom_format: String,
}

// ---- rules ----

/// Manage detection rules.
#[derive(Args, Debug)]
pub struct RulesArgs {
    #[command(subcommand)]
    pub action: RulesAction,
}

#[derive(Subcommand, Debug)]
pub enum RulesAction {
    /// List all loaded detection rules.
    List {
        /// Filter by status (enabled, disabled, test).
        #[arg(long)]
        status: Option<String>,
    },
    /// Validate rule files without loading them into the engine.
    Validate {
        /// Directory containing YAML rule files.
        #[arg(default_value = "/etc/ironpost/rules")]
        path: PathBuf,
    },
}

// ---- config ----

/// Manage ironpost configuration.
#[derive(Args, Debug)]
pub struct ConfigArgs {
    #[command(subcommand)]
    pub action: ConfigAction,
}

#[derive(Subcommand, Debug)]
pub enum ConfigAction {
    /// Validate the configuration file and report errors.
    Validate,
    /// Show the effective configuration (file + env overrides + defaults).
    Show {
        /// Show only a specific section (general, ebpf, log_pipeline, container, sbom).
        #[arg(long)]
        section: Option<String>,
    },
}

#[cfg(test)]
mod tests {
    use super::*;
    use clap::CommandFactory;

    #[test]
    fn test_cli_parse_start_foreground() {
        let args = Cli::try_parse_from(["ironpost", "start"]);
        assert!(args.is_ok(), "should parse 'start' subcommand");
        let cli = args.expect("parse succeeded");
        match cli.command {
            Commands::Start(start_args) => {
                assert!(!start_args.daemonize, "daemonize should default to false");
                assert!(start_args.pid_file.is_none(), "pid_file should be None");
            }
            _ => panic!("expected Start command"),
        }
    }

    #[test]
    fn test_cli_parse_start_daemonize() {
        let args = Cli::try_parse_from(["ironpost", "start", "-d"]);
        assert!(args.is_ok(), "should parse 'start -d' subcommand");
        let cli = args.expect("parse succeeded");
        match cli.command {
            Commands::Start(start_args) => {
                assert!(start_args.daemonize, "daemonize should be true");
            }
            _ => panic!("expected Start command"),
        }
    }

    #[test]
    fn test_cli_parse_start_with_pid_file() {
        let args = Cli::try_parse_from(["ironpost", "start", "-d", "--pid-file", "/tmp/test.pid"]);
        assert!(args.is_ok(), "should parse start with pid-file");
        let cli = args.expect("parse succeeded");
        match cli.command {
            Commands::Start(start_args) => {
                assert_eq!(
                    start_args.pid_file,
                    Some(std::path::PathBuf::from("/tmp/test.pid")),
                    "pid_file should match"
                );
            }
            _ => panic!("expected Start command"),
        }
    }

    #[test]
    fn test_cli_parse_status_basic() {
        let args = Cli::try_parse_from(["ironpost", "status"]);
        assert!(args.is_ok(), "should parse 'status' subcommand");
        let cli = args.expect("parse succeeded");
        match cli.command {
            Commands::Status(status_args) => {
                assert!(!status_args.verbose, "verbose should default to false");
            }
            _ => panic!("expected Status command"),
        }
    }

    #[test]
    fn test_cli_parse_status_verbose() {
        let args = Cli::try_parse_from(["ironpost", "status", "-v"]);
        assert!(args.is_ok(), "should parse 'status -v' subcommand");
        let cli = args.expect("parse succeeded");
        match cli.command {
            Commands::Status(status_args) => {
                assert!(status_args.verbose, "verbose should be true");
            }
            _ => panic!("expected Status command"),
        }
    }

    #[test]
    fn test_cli_parse_scan_defaults() {
        let args = Cli::try_parse_from(["ironpost", "scan"]);
        assert!(args.is_ok(), "should parse 'scan' subcommand");
        let cli = args.expect("parse succeeded");
        match cli.command {
            Commands::Scan(scan_args) => {
                assert_eq!(scan_args.path, std::path::PathBuf::from("."));
                assert_eq!(scan_args.min_severity, "medium");
                assert_eq!(scan_args.sbom_format, "cyclonedx");
            }
            _ => panic!("expected Scan command"),
        }
    }

    #[test]
    fn test_cli_parse_scan_custom_path() {
        let args = Cli::try_parse_from(["ironpost", "scan", "/path/to/project"]);
        assert!(args.is_ok(), "should parse scan with custom path");
        let cli = args.expect("parse succeeded");
        match cli.command {
            Commands::Scan(scan_args) => {
                assert_eq!(scan_args.path, std::path::PathBuf::from("/path/to/project"));
            }
            _ => panic!("expected Scan command"),
        }
    }

    #[test]
    fn test_cli_parse_scan_min_severity() {
        let args = Cli::try_parse_from(["ironpost", "scan", "--min-severity", "critical"]);
        assert!(args.is_ok(), "should parse scan with min-severity");
        let cli = args.expect("parse succeeded");
        match cli.command {
            Commands::Scan(scan_args) => {
                assert_eq!(scan_args.min_severity, "critical");
            }
            _ => panic!("expected Scan command"),
        }
    }

    #[test]
    fn test_cli_parse_scan_sbom_format() {
        let args = Cli::try_parse_from(["ironpost", "scan", "--sbom-format", "spdx"]);
        assert!(args.is_ok(), "should parse scan with sbom-format");
        let cli = args.expect("parse succeeded");
        match cli.command {
            Commands::Scan(scan_args) => {
                assert_eq!(scan_args.sbom_format, "spdx");
            }
            _ => panic!("expected Scan command"),
        }
    }

    #[test]
    fn test_cli_parse_rules_list() {
        let args = Cli::try_parse_from(["ironpost", "rules", "list"]);
        assert!(args.is_ok(), "should parse 'rules list' subcommand");
        let cli = args.expect("parse succeeded");
        match cli.command {
            Commands::Rules(rules_args) => match rules_args.action {
                RulesAction::List { status } => {
                    assert!(status.is_none(), "status filter should be None");
                }
                _ => panic!("expected List action"),
            },
            _ => panic!("expected Rules command"),
        }
    }

    #[test]
    fn test_cli_parse_rules_list_with_status_filter() {
        let args = Cli::try_parse_from(["ironpost", "rules", "list", "--status", "enabled"]);
        assert!(args.is_ok(), "should parse rules list with status filter");
        let cli = args.expect("parse succeeded");
        match cli.command {
            Commands::Rules(rules_args) => match rules_args.action {
                RulesAction::List { status } => {
                    assert_eq!(status, Some("enabled".to_owned()));
                }
                _ => panic!("expected List action"),
            },
            _ => panic!("expected Rules command"),
        }
    }

    #[test]
    fn test_cli_parse_rules_validate() {
        let args = Cli::try_parse_from(["ironpost", "rules", "validate"]);
        assert!(args.is_ok(), "should parse 'rules validate' subcommand");
        let cli = args.expect("parse succeeded");
        match cli.command {
            Commands::Rules(rules_args) => match rules_args.action {
                RulesAction::Validate { path } => {
                    assert_eq!(path, std::path::PathBuf::from("/etc/ironpost/rules"));
                }
                _ => panic!("expected Validate action"),
            },
            _ => panic!("expected Rules command"),
        }
    }

    #[test]
    fn test_cli_parse_rules_validate_custom_path() {
        let args =
            Cli::try_parse_from(["ironpost", "rules", "validate", "/custom/rules/directory"]);
        assert!(args.is_ok(), "should parse rules validate with custom path");
        let cli = args.expect("parse succeeded");
        match cli.command {
            Commands::Rules(rules_args) => match rules_args.action {
                RulesAction::Validate { path } => {
                    assert_eq!(path, std::path::PathBuf::from("/custom/rules/directory"));
                }
                _ => panic!("expected Validate action"),
            },
            _ => panic!("expected Rules command"),
        }
    }

    #[test]
    fn test_cli_parse_config_validate() {
        let args = Cli::try_parse_from(["ironpost", "config", "validate"]);
        assert!(args.is_ok(), "should parse 'config validate' subcommand");
        let cli = args.expect("parse succeeded");
        match cli.command {
            Commands::Config(config_args) => match config_args.action {
                ConfigAction::Validate => {}
                _ => panic!("expected Validate action"),
            },
            _ => panic!("expected Config command"),
        }
    }

    #[test]
    fn test_cli_parse_config_show() {
        let args = Cli::try_parse_from(["ironpost", "config", "show"]);
        assert!(args.is_ok(), "should parse 'config show' subcommand");
        let cli = args.expect("parse succeeded");
        match cli.command {
            Commands::Config(config_args) => match config_args.action {
                ConfigAction::Show { section } => {
                    assert!(section.is_none(), "section should be None");
                }
                _ => panic!("expected Show action"),
            },
            _ => panic!("expected Config command"),
        }
    }

    #[test]
    fn test_cli_parse_config_show_section() {
        let args = Cli::try_parse_from(["ironpost", "config", "show", "--section", "ebpf"]);
        assert!(args.is_ok(), "should parse config show with section");
        let cli = args.expect("parse succeeded");
        match cli.command {
            Commands::Config(config_args) => match config_args.action {
                ConfigAction::Show { section } => {
                    assert_eq!(section, Some("ebpf".to_owned()));
                }
                _ => panic!("expected Show action"),
            },
            _ => panic!("expected Config command"),
        }
    }

    #[test]
    fn test_cli_parse_custom_config_path() {
        let args = Cli::try_parse_from(["ironpost", "-c", "/custom/config.toml", "status"]);
        assert!(args.is_ok(), "should parse with custom config path");
        let cli = args.expect("parse succeeded");
        assert_eq!(cli.config, std::path::PathBuf::from("/custom/config.toml"));
    }

    #[test]
    fn test_cli_parse_log_level() {
        let args = Cli::try_parse_from(["ironpost", "--log-level", "debug", "status"]);
        assert!(args.is_ok(), "should parse with custom log level");
        let cli = args.expect("parse succeeded");
        assert_eq!(cli.log_level, Some("debug".to_owned()));
    }

    #[test]
    fn test_cli_parse_output_format_json() {
        let args = Cli::try_parse_from(["ironpost", "--output", "json", "status"]);
        assert!(args.is_ok(), "should parse with json output format");
        let cli = args.expect("parse succeeded");
        match cli.output {
            OutputFormat::Json => {}
            _ => panic!("expected Json output format"),
        }
    }

    #[test]
    fn test_cli_parse_output_format_text() {
        let args = Cli::try_parse_from(["ironpost", "--output", "text", "status"]);
        assert!(args.is_ok(), "should parse with text output format");
        let cli = args.expect("parse succeeded");
        match cli.output {
            OutputFormat::Text => {}
            _ => panic!("expected Text output format"),
        }
    }

    #[test]
    fn test_cli_parse_invalid_command_fails() {
        let args = Cli::try_parse_from(["ironpost", "invalid-command"]);
        assert!(args.is_err(), "should fail on invalid command");
    }

    #[test]
    fn test_cli_parse_missing_command_fails() {
        let args = Cli::try_parse_from(["ironpost"]);
        assert!(args.is_err(), "should fail when no command provided");
    }

    #[test]
    fn test_cli_verify_command_structure() {
        // Verify CLI command compiles and has expected structure
        let cmd = Cli::command();
        assert_eq!(cmd.get_name(), "ironpost");

        let subcommands: Vec<_> = cmd.get_subcommands().map(|s| s.get_name()).collect();
        assert!(
            subcommands.contains(&"start"),
            "should have 'start' subcommand"
        );
        assert!(
            subcommands.contains(&"status"),
            "should have 'status' subcommand"
        );
        assert!(
            subcommands.contains(&"scan"),
            "should have 'scan' subcommand"
        );
        assert!(
            subcommands.contains(&"rules"),
            "should have 'rules' subcommand"
        );
        assert!(
            subcommands.contains(&"config"),
            "should have 'config' subcommand"
        );
    }
}

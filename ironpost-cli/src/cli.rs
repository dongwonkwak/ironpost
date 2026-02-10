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

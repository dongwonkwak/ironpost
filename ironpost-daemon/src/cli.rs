//! CLI argument definitions for ironpost-daemon.
//!
//! Uses `clap` v4 derive macros to parse command-line arguments.

use std::path::PathBuf;

use clap::Parser;

/// Ironpost security monitoring daemon.
///
/// Orchestrates all ironpost modules (eBPF engine, log pipeline,
/// container guard, SBOM scanner) and manages their lifecycles.
#[derive(Parser, Debug)]
#[command(name = "ironpost-daemon")]
#[command(version, about, long_about = None)]
pub struct DaemonCli {
    /// Path to ironpost.toml configuration file.
    #[arg(short, long, default_value = "/etc/ironpost/ironpost.toml")]
    pub config: PathBuf,

    /// Override log level (trace, debug, info, warn, error).
    ///
    /// Takes precedence over the config file and environment variables.
    #[arg(long)]
    pub log_level: Option<String>,

    /// Override log format (json, pretty).
    ///
    /// Takes precedence over the config file and environment variables.
    #[arg(long)]
    pub log_format: Option<String>,

    /// Validate configuration file and exit without starting the daemon.
    #[arg(long)]
    pub validate: bool,

    /// Override PID file path (takes precedence over config file).
    #[arg(long)]
    pub pid_file: Option<String>,
}

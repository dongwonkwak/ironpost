//! ironpost-cli -- Command-line interface for Ironpost security monitoring platform
//!
//! This CLI provides commands to manage the Ironpost daemon, run one-shot scans,
//! validate rules and configuration, and more.

use clap::Parser;
use tracing_subscriber::EnvFilter;

mod cli;
mod commands;
mod error;
mod output;

use cli::{Cli, Commands};
use error::CliError;
use output::OutputWriter;

#[tokio::main]
async fn main() {
    let cli = Cli::parse();

    // Initialize tracing with minimal subscriber for CLI
    // Structured JSON would be noisy for interactive use, so we use compact format
    // Logs go to stderr, output goes to stdout
    let log_level = cli.log_level.as_deref().unwrap_or("warn");
    let filter = EnvFilter::try_from_default_env()
        .or_else(|_| EnvFilter::try_new(log_level))
        .unwrap_or_else(|_| EnvFilter::new("warn"));

    tracing_subscriber::fmt()
        .with_env_filter(filter)
        .with_writer(std::io::stderr)
        .with_target(false)
        .compact()
        .init();

    let writer = OutputWriter::new(cli.output);

    let result = run(cli, &writer).await;

    match result {
        Ok(()) => std::process::exit(0),
        Err(e) => {
            // Errors rendered to stderr via tracing
            tracing::error!(error = %e, "command failed");
            std::process::exit(e.exit_code());
        }
    }
}

async fn run(cli: Cli, writer: &OutputWriter) -> Result<(), CliError> {
    match cli.command {
        Commands::Start(args) => commands::start::execute(args, &cli.config).await,
        Commands::Status(args) => commands::status::execute(args, &cli.config, writer).await,
        Commands::Scan(args) => commands::scan::execute(args, &cli.config, writer).await,
        Commands::Rules(args) => commands::rules::execute(args, &cli.config, writer).await,
        Commands::Config(args) => commands::config::execute(args, &cli.config, writer).await,
    }
}

//! CLI-specific error types and exit code mapping

use ironpost_core::error::IronpostError;

/// CLI-specific error type.
///
/// Each variant carries enough context for a user-friendly message.
/// The `exit_code()` method maps errors to standard Unix exit codes.
#[derive(Debug, thiserror::Error)]
pub enum CliError {
    /// Configuration loading or validation failure.
    #[error("configuration error: {0}")]
    Config(String),

    /// A subcommand-specific operation failed.
    #[error("{0}")]
    Command(String),

    /// Cannot connect to the daemon (e.g., for `status`).
    #[error("daemon not reachable: {0}")]
    #[allow(dead_code)] // Reserved for future use with daemon health API
    DaemonUnavailable(String),

    /// JSON serialisation failed during output rendering.
    #[error("json output error: {0}")]
    JsonSerialize(#[from] serde_json::Error),

    /// IO error (file read, stdout write, etc.).
    #[error("io error: {0}")]
    Io(#[from] std::io::Error),

    /// Wrapped domain error from ironpost-core.
    #[error("{0}")]
    Core(#[from] IronpostError),

    /// SBOM scanner domain error.
    #[error("scan error: {0}")]
    Scan(String),

    /// Rule engine domain error.
    #[error("rule error: {0}")]
    Rule(String),
}

impl CliError {
    /// Map the error to a process exit code.
    ///
    /// | Code | Meaning                              |
    /// |------|--------------------------------------|
    /// | 0    | Success                              |
    /// | 1    | General / command error               |
    /// | 2    | Configuration error                   |
    /// | 3    | Daemon unreachable                    |
    /// | 4    | Scan found vulnerabilities (non-zero) |
    /// | 10   | IO error                              |
    pub fn exit_code(&self) -> i32 {
        match self {
            Self::Config(_) => 2,
            Self::DaemonUnavailable(_) => 3,
            Self::Scan(_) => 4,
            Self::Io(_) => 10,
            Self::JsonSerialize(_) | Self::Command(_) | Self::Core(_) | Self::Rule(_) => 1,
        }
    }
}

impl From<ironpost_sbom_scanner::SbomScannerError> for CliError {
    fn from(e: ironpost_sbom_scanner::SbomScannerError) -> Self {
        Self::Scan(e.to_string())
    }
}

impl From<ironpost_log_pipeline::LogPipelineError> for CliError {
    fn from(e: ironpost_log_pipeline::LogPipelineError) -> Self {
        Self::Rule(e.to_string())
    }
}

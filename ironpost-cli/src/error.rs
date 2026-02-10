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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_exit_code_config_error() {
        let err = CliError::Config("test error".to_owned());
        assert_eq!(err.exit_code(), 2, "config error should return exit code 2");
    }

    #[test]
    fn test_exit_code_daemon_unavailable() {
        let err = CliError::DaemonUnavailable("test error".to_owned());
        assert_eq!(
            err.exit_code(),
            3,
            "daemon unavailable should return exit code 3"
        );
    }

    #[test]
    fn test_exit_code_scan_error() {
        let err = CliError::Scan("vulnerabilities found".to_owned());
        assert_eq!(err.exit_code(), 4, "scan error should return exit code 4");
    }

    #[test]
    fn test_exit_code_io_error() {
        let io_err = std::io::Error::new(std::io::ErrorKind::NotFound, "file not found");
        let err = CliError::Io(io_err);
        assert_eq!(err.exit_code(), 10, "io error should return exit code 10");
    }

    #[test]
    fn test_exit_code_command_error() {
        let err = CliError::Command("test error".to_owned());
        assert_eq!(
            err.exit_code(),
            1,
            "command error should return exit code 1"
        );
    }

    #[test]
    fn test_exit_code_json_serialize_error() {
        let json_err = serde_json::from_str::<serde_json::Value>("{invalid json")
            .expect_err("should fail parsing");
        let err = CliError::JsonSerialize(json_err);
        assert_eq!(
            err.exit_code(),
            1,
            "json serialize error should return exit code 1"
        );
    }

    #[test]
    fn test_exit_code_rule_error() {
        let err = CliError::Rule("invalid rule".to_owned());
        assert_eq!(err.exit_code(), 1, "rule error should return exit code 1");
    }

    #[test]
    fn test_error_display_config() {
        let err = CliError::Config("invalid TOML syntax".to_owned());
        let display_str = format!("{}", err);
        assert!(
            display_str.contains("configuration error"),
            "should include error context"
        );
        assert!(
            display_str.contains("invalid TOML syntax"),
            "should include error message"
        );
    }

    #[test]
    fn test_error_display_command() {
        let err = CliError::Command("execution failed".to_owned());
        let display_str = format!("{}", err);
        assert_eq!(display_str, "execution failed");
    }

    #[test]
    fn test_error_display_scan() {
        let err = CliError::Scan("found 5 vulnerabilities".to_owned());
        let display_str = format!("{}", err);
        assert!(display_str.contains("scan error"));
        assert!(display_str.contains("found 5 vulnerabilities"));
    }

    #[test]
    fn test_from_io_error() {
        let io_err = std::io::Error::new(std::io::ErrorKind::PermissionDenied, "access denied");
        let cli_err: CliError = io_err.into();
        match cli_err {
            CliError::Io(e) => {
                assert_eq!(e.kind(), std::io::ErrorKind::PermissionDenied);
            }
            _ => panic!("expected Io error variant"),
        }
    }

    #[test]
    fn test_from_core_error() {
        use ironpost_core::error::ConfigError;
        let config_err = ConfigError::FileNotFound {
            path: "test.toml".to_owned(),
        };
        let core_err = IronpostError::Config(config_err);
        let cli_err: CliError = core_err.into();
        match cli_err {
            CliError::Core(_) => {}
            _ => panic!("expected Core error variant"),
        }
    }

    #[test]
    fn test_error_debug_format() {
        let err = CliError::Config("test".to_owned());
        let debug_str = format!("{:?}", err);
        assert!(
            debug_str.contains("Config"),
            "debug format should show variant name"
        );
    }
}

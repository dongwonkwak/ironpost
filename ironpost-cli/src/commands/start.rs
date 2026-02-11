//! `ironpost start` command handler

use std::path::Path;
use std::process::{Command, Stdio};

use tracing::info;

use crate::cli::StartArgs;
use crate::error::CliError;

/// Execute the `start` command.
///
/// In foreground mode, spawns `ironpost-daemon` and replaces the current process.
/// In daemon mode (`-d`), spawns `ironpost-daemon` as a detached background process.
pub async fn execute(args: StartArgs, config_path: &Path) -> Result<(), CliError> {
    // Validate config exists
    if !config_path.exists() {
        return Err(CliError::Config(format!(
            "configuration file not found: {}",
            config_path.display()
        )));
    }

    info!(
        daemonize = args.daemonize,
        config = %config_path.display(),
        "starting ironpost"
    );

    if args.daemonize {
        start_daemon(config_path, args.pid_file.as_deref())?;
    } else {
        start_foreground(config_path)?;
    }

    Ok(())
}

/// Start daemon in foreground mode by exec-ing ironpost-daemon binary.
///
/// Replaces the current CLI process with `ironpost-daemon` using `exec(2)` on Unix.
/// On success, this function never returns (process is replaced).
/// On failure, returns an error indicating exec failed.
///
/// # Arguments
///
/// * `config_path` - Path to ironpost.toml configuration file
///
/// # Errors
///
/// Returns `CliError::Command` if exec fails (binary not found, permissions, etc.)
fn start_foreground(config_path: &Path) -> Result<(), CliError> {
    let mut cmd = Command::new("ironpost-daemon");
    cmd.arg("--config").arg(config_path);

    info!("executing ironpost-daemon in foreground mode");

    // exec() replaces the current process
    let err = CommandExecExt::exec(&mut cmd);

    // If we reach here, exec failed
    Err(CliError::Command(format!(
        "failed to execute ironpost-daemon: {}",
        err
    )))
}

/// Start daemon in background mode.
///
/// Spawns `ironpost-daemon` as a detached background process with stdio redirected to `/dev/null`.
/// Waits 200ms and checks if the child process is still alive to detect immediate crashes.
///
/// # Arguments
///
/// * `config_path` - Path to ironpost.toml configuration file
/// * `pid_file` - Optional custom PID file location (overrides config default)
///
/// # Errors
///
/// Returns `CliError::Command` if:
/// - Spawn fails (binary not found, permissions)
/// - Daemon exits immediately (configuration error, port already in use, etc.)
/// - Cannot check daemon status
fn start_daemon(config_path: &Path, pid_file: Option<&Path>) -> Result<(), CliError> {
    let mut cmd = Command::new("ironpost-daemon");
    cmd.arg("--config").arg(config_path);

    if let Some(pid_file_path) = pid_file {
        cmd.arg("--pid-file").arg(pid_file_path);
    }

    // Detach from parent by redirecting all stdio to /dev/null
    cmd.stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null());

    info!("spawning ironpost-daemon in background mode");

    let mut child = cmd
        .spawn()
        .map_err(|e| CliError::Command(format!("failed to spawn ironpost-daemon: {}", e)))?;

    let pid = child.id();
    info!(pid = pid, "daemon spawned, verifying startup");

    // Wait briefly to detect immediate crashes (e.g., argument errors)
    std::thread::sleep(std::time::Duration::from_millis(200));

    // Check if child exited immediately
    match child.try_wait() {
        Ok(Some(status)) => {
            return Err(CliError::Command(format!(
                "daemon exited immediately with status: {}",
                status
            )));
        }
        Ok(None) => {
            // Still running, success
            info!(pid = pid, "daemon started successfully");
        }
        Err(e) => {
            return Err(CliError::Command(format!(
                "failed to check daemon status: {}",
                e
            )));
        }
    }

    Ok(())
}

// Unix-specific exec trait
#[cfg(unix)]
use std::os::unix::process::CommandExt;

#[cfg(unix)]
trait CommandExecExt {
    fn exec(&mut self) -> std::io::Error;
}

#[cfg(unix)]
impl CommandExecExt for Command {
    fn exec(&mut self) -> std::io::Error {
        CommandExt::exec(self)
    }
}

// Fallback for non-Unix platforms (Windows, etc.)
#[cfg(not(unix))]
trait CommandExecExt {
    fn exec(&mut self) -> std::io::Error;
}

#[cfg(not(unix))]
impl CommandExecExt for Command {
    fn exec(&mut self) -> std::io::Error {
        std::io::Error::new(
            std::io::ErrorKind::Unsupported,
            "exec not supported on this platform",
        )
    }
}

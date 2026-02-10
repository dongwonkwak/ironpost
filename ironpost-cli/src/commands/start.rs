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

    let child = cmd
        .spawn()
        .map_err(|e| CliError::Command(format!("failed to spawn ironpost-daemon: {}", e)))?;

    info!(pid = child.id(), "daemon started successfully");

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

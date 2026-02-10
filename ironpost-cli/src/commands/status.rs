//! `ironpost status` command handler

use std::io::Write;
use std::path::Path;

use serde::Serialize;
use tracing::{debug, warn};

use ironpost_core::config::IronpostConfig;

use crate::cli::StatusArgs;
use crate::error::CliError;
use crate::output::{OutputWriter, Render};

/// Execute the `status` command.
pub async fn execute(
    args: StatusArgs,
    config_path: &Path,
    writer: &OutputWriter,
) -> Result<(), CliError> {
    let config = IronpostConfig::load(config_path).await?;

    let report = build_status_report(&config, args.verbose)?;

    writer.render(&report)?;

    Ok(())
}

fn build_status_report(config: &IronpostConfig, verbose: bool) -> Result<StatusReport, CliError> {
    // Check if daemon is running by checking PID file
    let (daemon_running, uptime_secs) = check_daemon_status(&config.general.pid_file);

    let mut modules = Vec::new();

    // eBPF module
    if config.ebpf.enabled {
        modules.push(ModuleStatus {
            name: "ebpf-engine".to_owned(),
            enabled: true,
            health: if daemon_running {
                "running".to_owned()
            } else {
                "stopped".to_owned()
            },
            details: if verbose {
                Some(format!(
                    "interface={}, mode={}",
                    config.ebpf.interface, config.ebpf.xdp_mode
                ))
            } else {
                None
            },
        });
    }

    // Log pipeline module
    if config.log_pipeline.enabled {
        modules.push(ModuleStatus {
            name: "log-pipeline".to_owned(),
            enabled: true,
            health: if daemon_running {
                "running".to_owned()
            } else {
                "stopped".to_owned()
            },
            details: if verbose {
                Some(format!(
                    "sources={}, batch_size={}",
                    config.log_pipeline.sources.join(","),
                    config.log_pipeline.batch_size
                ))
            } else {
                None
            },
        });
    }

    // Container guard module
    if config.container.enabled {
        modules.push(ModuleStatus {
            name: "container-guard".to_owned(),
            enabled: true,
            health: if daemon_running {
                "running".to_owned()
            } else {
                "stopped".to_owned()
            },
            details: if verbose {
                Some(format!(
                    "auto_isolate={}, poll_interval={}s",
                    config.container.auto_isolate, config.container.poll_interval_secs
                ))
            } else {
                None
            },
        });
    }

    // SBOM scanner module
    if config.sbom.enabled {
        modules.push(ModuleStatus {
            name: "sbom-scanner".to_owned(),
            enabled: true,
            health: if daemon_running {
                "running".to_owned()
            } else {
                "stopped".to_owned()
            },
            details: if verbose {
                Some(format!(
                    "min_severity={}, format={}",
                    config.sbom.min_severity, config.sbom.output_format
                ))
            } else {
                None
            },
        });
    }

    Ok(StatusReport {
        daemon_running,
        uptime_secs,
        modules,
    })
}

/// Check if daemon is running by reading PID file and checking process existence.
fn check_daemon_status(pid_file: &str) -> (bool, Option<u64>) {
    let pid_path = std::path::Path::new(pid_file);

    if !pid_path.exists() {
        debug!(pid_file, "pid file does not exist");
        return (false, None);
    }

    let pid_content = match std::fs::read_to_string(pid_path) {
        Ok(content) => content,
        Err(e) => {
            warn!(pid_file, error = %e, "failed to read pid file");
            return (false, None);
        }
    };

    let pid = match pid_content.trim().parse::<u32>() {
        Ok(p) => p,
        Err(e) => {
            warn!(pid_file, error = %e, "failed to parse pid");
            return (false, None);
        }
    };

    // Check if process is alive
    let is_running = is_process_alive(pid);

    // Uptime estimation is not trivial without querying the process
    // For now, just return None (future: add health API endpoint)
    (is_running, None)
}

/// Check if a process with the given PID is alive.
#[cfg(unix)]
fn is_process_alive(pid: u32) -> bool {
    use std::io::ErrorKind;

    // Send signal 0 to check if process exists
    // SAFETY: kill(2) with signal 0 is safe and does not affect the target process
    let result = unsafe { libc::kill(pid as libc::pid_t, 0) };

    if result == 0 {
        true
    } else {
        let err = std::io::Error::last_os_error();
        match err.kind() {
            ErrorKind::PermissionDenied => true, // Process exists but we can't signal it
            _ => false,
        }
    }
}

#[cfg(not(unix))]
fn is_process_alive(_pid: u32) -> bool {
    warn!("process liveness check not supported on this platform");
    false
}

#[derive(Serialize)]
pub struct StatusReport {
    pub daemon_running: bool,
    pub uptime_secs: Option<u64>,
    pub modules: Vec<ModuleStatus>,
}

#[derive(Serialize)]
pub struct ModuleStatus {
    pub name: String,
    pub enabled: bool,
    pub health: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub details: Option<String>,
}

impl Render for StatusReport {
    fn render_text(&self, w: &mut dyn Write) -> std::io::Result<()> {
        use colored::Colorize;

        if self.daemon_running {
            writeln!(
                w,
                "Daemon: {} (uptime: {})",
                "running".green().bold(),
                self.uptime_secs
                    .map(|s| format!("{}s", s))
                    .unwrap_or_else(|| "unknown".to_owned())
            )?;
        } else {
            writeln!(w, "Daemon: {}", "not running".red().bold())?;
        }

        writeln!(w)?;
        writeln!(w, "{:<20} {:<10} Health", "Module", "Enabled")?;
        writeln!(w, "{}", "-".repeat(60))?;

        for m in &self.modules {
            let enabled_str = if m.enabled { "yes" } else { "no" };
            let health_colored = match m.health.as_str() {
                "running" => m.health.green(),
                "stopped" => m.health.yellow(),
                _ => m.health.normal(),
            };

            writeln!(w, "{:<20} {:<10} {}", m.name, enabled_str, health_colored)?;

            if let Some(details) = &m.details {
                writeln!(w, "  {}", details.dimmed())?;
            }
        }

        Ok(())
    }
}

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

/// Build a status report from configuration and daemon state.
///
/// Queries daemon status via PID file and constructs module-level health information
/// based on enabled modules in the configuration.
///
/// # Arguments
///
/// * `config` - Loaded Ironpost configuration
/// * `verbose` - Include detailed per-module configuration in output
///
/// # Returns
///
/// Returns `StatusReport` containing daemon state and module health information.
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

    // Read PID file directly without exists() check to avoid TOCTOU race.
    // If the file doesn't exist, read_to_string will return an error.
    let pid_content = match std::fs::read_to_string(pid_path) {
        Ok(content) => content,
        Err(e) => {
            if e.kind() == std::io::ErrorKind::NotFound {
                debug!(pid_file, "pid file does not exist");
            } else {
                warn!(pid_file, error = %e, "failed to read pid file");
            }
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

    // Convert pid to pid_t with bounds checking
    let pid_t = match libc::pid_t::try_from(pid) {
        Ok(p) => p,
        Err(_) => {
            // PID exceeds platform pid_t range (e.g., pid > i32::MAX on most platforms)
            warn!(pid, "PID exceeds platform pid_t range");
            return false;
        }
    };

    // Send signal 0 to check if process exists
    // SAFETY: kill(2) is safe when:
    //   1. The pid_t value is valid (checked above via try_from)
    //   2. Signal 0 performs only an existence check without affecting the process
    //   3. The function is extern C and does not violate memory safety
    //   4. Note: PID recycling means this may refer to a different process than originally
    //      intended, but this is not a safety violation, only a correctness consideration
    let result = unsafe { libc::kill(pid_t, 0) };

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

/// Status report containing daemon state and module health.
///
/// This structure is serialized to JSON or rendered as text depending on output format.
#[derive(Serialize)]
pub struct StatusReport {
    /// Whether the daemon process is currently running (based on PID file check)
    pub daemon_running: bool,
    /// Daemon uptime in seconds, or None if unavailable
    pub uptime_secs: Option<u64>,
    /// Health status of each enabled module
    pub modules: Vec<ModuleStatus>,
}

/// Health status of a single module.
#[derive(Serialize)]
pub struct ModuleStatus {
    /// Module name (ebpf-engine, log-pipeline, container-guard, sbom-scanner)
    pub name: String,
    /// Whether the module is enabled in configuration
    pub enabled: bool,
    /// Health state: "running" | "stopped" | "degraded"
    pub health: String,
    /// Optional verbose configuration details (only when --verbose flag is used)
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_status_report_render_text_daemon_running() {
        let report = StatusReport {
            daemon_running: true,
            uptime_secs: Some(3600),
            modules: Vec::new(),
        };

        let mut buffer = Vec::new();
        report
            .render_text(&mut buffer)
            .expect("text rendering should succeed");

        let output = String::from_utf8(buffer).expect("valid UTF-8");
        assert!(output.contains("running"), "should show running status");
        assert!(output.contains("3600s"), "should show uptime");
    }

    #[test]
    fn test_status_report_render_text_daemon_stopped() {
        let report = StatusReport {
            daemon_running: false,
            uptime_secs: None,
            modules: Vec::new(),
        };

        let mut buffer = Vec::new();
        report
            .render_text(&mut buffer)
            .expect("text rendering should succeed");

        let output = String::from_utf8(buffer).expect("valid UTF-8");
        assert!(output.contains("not running"), "should show stopped status");
    }

    #[test]
    fn test_status_report_render_text_with_modules() {
        let report = StatusReport {
            daemon_running: true,
            uptime_secs: Some(100),
            modules: vec![
                ModuleStatus {
                    name: "ebpf-engine".to_owned(),
                    enabled: true,
                    health: "running".to_owned(),
                    details: Some("interface=eth0".to_owned()),
                },
                ModuleStatus {
                    name: "log-pipeline".to_owned(),
                    enabled: true,
                    health: "running".to_owned(),
                    details: None,
                },
            ],
        };

        let mut buffer = Vec::new();
        report
            .render_text(&mut buffer)
            .expect("text rendering should succeed");

        let output = String::from_utf8(buffer).expect("valid UTF-8");
        assert!(output.contains("ebpf-engine"), "should show first module");
        assert!(output.contains("log-pipeline"), "should show second module");
        assert!(output.contains("interface=eth0"), "should show details");
    }

    #[test]
    fn test_status_report_json_serialization() {
        let report = StatusReport {
            daemon_running: true,
            uptime_secs: Some(500),
            modules: vec![ModuleStatus {
                name: "test-module".to_owned(),
                enabled: true,
                health: "running".to_owned(),
                details: Some("test=value".to_owned()),
            }],
        };

        let json = serde_json::to_string(&report).expect("JSON serialization should succeed");
        let parsed: serde_json::Value = serde_json::from_str(&json).expect("should parse JSON");

        assert_eq!(parsed["daemon_running"].as_bool(), Some(true));
        assert_eq!(parsed["uptime_secs"].as_u64(), Some(500));
        assert_eq!(
            parsed["modules"].as_array().expect("should be array").len(),
            1
        );
    }

    #[test]
    fn test_module_status_json_structure() {
        let module = ModuleStatus {
            name: "test".to_owned(),
            enabled: true,
            health: "running".to_owned(),
            details: Some("key=value".to_owned()),
        };

        let json = serde_json::to_string(&module).expect("JSON serialization should succeed");
        let parsed: serde_json::Value = serde_json::from_str(&json).expect("should parse JSON");

        assert_eq!(parsed["name"].as_str(), Some("test"));
        assert_eq!(parsed["enabled"].as_bool(), Some(true));
        assert_eq!(parsed["health"].as_str(), Some("running"));
        assert_eq!(parsed["details"].as_str(), Some("key=value"));
    }

    #[test]
    fn test_module_status_without_details() {
        let module = ModuleStatus {
            name: "test".to_owned(),
            enabled: false,
            health: "stopped".to_owned(),
            details: None,
        };

        let json = serde_json::to_string(&module).expect("JSON serialization should succeed");
        let parsed: serde_json::Value = serde_json::from_str(&json).expect("should parse JSON");

        assert!(
            parsed.get("details").is_none(),
            "details should be skipped when None"
        );
    }

    #[test]
    fn test_status_report_daemon_running_no_uptime() {
        let report = StatusReport {
            daemon_running: true,
            uptime_secs: None,
            modules: Vec::new(),
        };

        let mut buffer = Vec::new();
        report
            .render_text(&mut buffer)
            .expect("text rendering should succeed");

        let output = String::from_utf8(buffer).expect("valid UTF-8");
        assert!(output.contains("unknown"), "should show unknown uptime");
    }

    #[test]
    fn test_status_report_all_modules_enabled() {
        let report = StatusReport {
            daemon_running: true,
            uptime_secs: Some(1000),
            modules: vec![
                ModuleStatus {
                    name: "ebpf-engine".to_owned(),
                    enabled: true,
                    health: "running".to_owned(),
                    details: None,
                },
                ModuleStatus {
                    name: "log-pipeline".to_owned(),
                    enabled: true,
                    health: "running".to_owned(),
                    details: None,
                },
                ModuleStatus {
                    name: "container-guard".to_owned(),
                    enabled: true,
                    health: "running".to_owned(),
                    details: None,
                },
                ModuleStatus {
                    name: "sbom-scanner".to_owned(),
                    enabled: true,
                    health: "running".to_owned(),
                    details: None,
                },
            ],
        };

        let mut buffer = Vec::new();
        report
            .render_text(&mut buffer)
            .expect("text rendering should succeed");

        let output = String::from_utf8(buffer).expect("valid UTF-8");
        assert!(output.contains("ebpf-engine"));
        assert!(output.contains("log-pipeline"));
        assert!(output.contains("container-guard"));
        assert!(output.contains("sbom-scanner"));
    }

    #[test]
    fn test_status_report_mixed_health_states() {
        let report = StatusReport {
            daemon_running: true,
            uptime_secs: Some(50),
            modules: vec![
                ModuleStatus {
                    name: "module1".to_owned(),
                    enabled: true,
                    health: "running".to_owned(),
                    details: None,
                },
                ModuleStatus {
                    name: "module2".to_owned(),
                    enabled: false,
                    health: "stopped".to_owned(),
                    details: None,
                },
                ModuleStatus {
                    name: "module3".to_owned(),
                    enabled: true,
                    health: "degraded".to_owned(),
                    details: Some("warning: high memory usage".to_owned()),
                },
            ],
        };

        let mut buffer = Vec::new();
        report
            .render_text(&mut buffer)
            .expect("text rendering should succeed");

        let output = String::from_utf8(buffer).expect("valid UTF-8");
        assert!(output.contains("running"));
        assert!(output.contains("stopped"));
        assert!(output.contains("degraded"));
    }

    #[test]
    fn test_check_daemon_status_no_pid_file() {
        let (running, uptime) = check_daemon_status("/nonexistent/path/to/pid/file.pid");
        assert!(!running, "should report not running when PID file missing");
        assert!(uptime.is_none(), "uptime should be None");
    }

    #[test]
    fn test_status_report_large_uptime() {
        let report = StatusReport {
            daemon_running: true,
            uptime_secs: Some(86400 * 30), // 30 days
            modules: Vec::new(),
        };

        let mut buffer = Vec::new();
        report
            .render_text(&mut buffer)
            .expect("text rendering should succeed");

        let output = String::from_utf8(buffer).expect("valid UTF-8");
        assert!(output.contains("2592000s"), "should handle large uptime");
    }

    #[test]
    fn test_module_status_long_details() {
        let long_details = "key1=value1, key2=value2, key3=value3, ".repeat(10);
        let module = ModuleStatus {
            name: "test".to_owned(),
            enabled: true,
            health: "running".to_owned(),
            details: Some(long_details.clone()),
        };

        let report = StatusReport {
            daemon_running: true,
            uptime_secs: Some(100),
            modules: vec![module],
        };

        let mut buffer = Vec::new();
        report
            .render_text(&mut buffer)
            .expect("long details should render");

        let output = String::from_utf8(buffer).expect("valid UTF-8");
        assert!(output.contains("key1=value1"), "should handle long details");
    }

    #[test]
    fn test_status_report_unicode_module_name() {
        let report = StatusReport {
            daemon_running: true,
            uptime_secs: Some(100),
            modules: vec![ModuleStatus {
                name: "モジュール-日本語".to_owned(),
                enabled: true,
                health: "running".to_owned(),
                details: None,
            }],
        };

        let mut buffer = Vec::new();
        report
            .render_text(&mut buffer)
            .expect("unicode module name should render");

        let output = String::from_utf8(buffer).expect("valid UTF-8");
        assert!(output.contains("モジュール"), "should handle unicode");
    }

    #[test]
    fn test_status_report_empty_modules() {
        let report = StatusReport {
            daemon_running: false,
            uptime_secs: None,
            modules: Vec::new(),
        };

        let json = serde_json::to_string(&report).expect("JSON serialization should succeed");
        let parsed: serde_json::Value = serde_json::from_str(&json).expect("should parse JSON");

        assert_eq!(
            parsed["modules"].as_array().expect("should be array").len(),
            0
        );
    }

    #[test]
    fn test_module_status_disabled_module() {
        let module = ModuleStatus {
            name: "disabled-module".to_owned(),
            enabled: false,
            health: "stopped".to_owned(),
            details: None,
        };

        let report = StatusReport {
            daemon_running: true,
            uptime_secs: Some(100),
            modules: vec![module],
        };

        let mut buffer = Vec::new();
        report
            .render_text(&mut buffer)
            .expect("disabled module should render");

        let output = String::from_utf8(buffer).expect("valid UTF-8");
        assert!(output.contains("no"), "should show 'no' for disabled");
    }
}

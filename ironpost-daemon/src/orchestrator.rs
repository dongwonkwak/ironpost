//! Module orchestration -- assembly, channel wiring, and lifecycle management.
//!
//! The [`Orchestrator`] is the central coordinator of `ironpost-daemon`.
//! It loads configuration, creates inter-module channels, builds enabled
//! modules, manages startup/shutdown ordering, and runs the main event loop.
//!
//! # Startup Order (producers before consumers)
//!
//! 1. eBPF Engine (produces PacketEvents)
//! 2. Log Pipeline (consumes PacketEvents, produces AlertEvents)
//! 3. SBOM Scanner (produces AlertEvents)
//! 4. Container Guard (consumes AlertEvents, produces ActionEvents)
//!
//! # Shutdown Order (same as startup - producers first)
//!
//! 1. eBPF Engine (stop producing PacketEvents)
//! 2. Log Pipeline (drain buffer, stop producing AlertEvents)
//! 3. SBOM Scanner (stop producing AlertEvents)
//! 4. Container Guard (drain remaining AlertEvents)

use std::path::Path;
use std::time::Instant;

use anyhow::Result;
use tokio::sync::{broadcast, mpsc};

use ironpost_core::config::IronpostConfig;
use ironpost_core::event::{ActionEvent, AlertEvent};

use crate::health::{DaemonHealth, ModuleHealth, aggregate_status};
use crate::modules::ModuleRegistry;

/// Channel capacity constants.
const PACKET_CHANNEL_CAPACITY: usize = 1024;
const ALERT_CHANNEL_CAPACITY: usize = 256;

/// The main daemon orchestrator.
///
/// Manages the complete lifecycle of all ironpost modules:
/// configuration loading, channel wiring, ordered startup,
/// health monitoring, and graceful shutdown.
pub struct Orchestrator {
    /// Loaded and validated configuration.
    config: IronpostConfig,
    /// Registry of all module handles (ordered for start/stop).
    modules: ModuleRegistry,
    /// Shutdown broadcast sender (signals all background tasks).
    shutdown_tx: broadcast::Sender<()>,
    /// Daemon start time (for uptime reporting).
    #[allow(dead_code)] // Used in health method
    start_time: Instant,
    /// Optional action event receiver (for logging/audit).
    action_rx: Option<mpsc::Receiver<ActionEvent>>,
}

impl Orchestrator {
    /// Load configuration and build the orchestrator.
    ///
    /// This performs the following steps:
    /// 1. Load `ironpost.toml` and apply environment variable overrides
    /// 2. Validate the configuration
    /// 3. Create inter-module channels
    /// 4. Initialize enabled modules
    ///
    /// # Arguments
    ///
    /// * `config_path` - Path to the `ironpost.toml` configuration file
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - Configuration file cannot be read or parsed
    /// - Configuration validation fails
    /// - Any enabled module fails to initialize
    #[allow(dead_code)] // Public API for tests
    pub async fn build(config_path: &Path) -> Result<Self> {
        let config = IronpostConfig::load(config_path)
            .await
            .map_err(|e| anyhow::anyhow!("failed to load config: {}", e))?;
        Self::build_from_config(config).await
    }

    /// Build from an already-loaded configuration.
    ///
    /// Useful for testing or when config has already been loaded.
    pub async fn build_from_config(config: IronpostConfig) -> Result<Self> {
        config
            .validate()
            .map_err(|e| anyhow::anyhow!("config validation failed: {}", e))?;

        tracing::debug!("creating inter-module channels");

        // Create channels
        let (packet_tx, _packet_rx_for_ebpf) =
            mpsc::channel::<ironpost_core::event::PacketEvent>(PACKET_CHANNEL_CAPACITY);
        let (alert_tx, alert_rx) = mpsc::channel::<AlertEvent>(ALERT_CHANNEL_CAPACITY);
        let (shutdown_tx, _) = broadcast::channel(16);

        let mut modules = ModuleRegistry::new();
        let mut action_rx = None;

        // Initialize eBPF engine (Linux only)
        #[cfg(target_os = "linux")]
        {
            if let Some((handle, _packet_rx)) = crate::modules::ebpf::init(&config, packet_tx)? {
                modules.register(handle);
            }
        }
        #[cfg(not(target_os = "linux"))]
        {
            let _ = packet_tx; // Silence unused warning on non-Linux
        }

        // Initialize log pipeline
        // On non-Linux, packet_rx will be None since eBPF is not available
        #[cfg(target_os = "linux")]
        let packet_rx_for_pipeline = _packet_rx_for_ebpf;
        #[cfg(not(target_os = "linux"))]
        let packet_rx_for_pipeline = None;

        if let Some(handle) = crate::modules::log_pipeline::init(
            &config,
            Some(packet_rx_for_pipeline),
            alert_tx.clone(),
        )? {
            modules.register(handle);
        }

        // Initialize SBOM scanner
        if let Some(handle) = crate::modules::sbom_scanner::init(&config, alert_tx.clone())? {
            modules.register(handle);
        }

        // Initialize container guard
        if let Some((handle, rx)) = crate::modules::container_guard::init(&config, alert_rx)? {
            modules.register(handle);
            action_rx = Some(rx);
        }

        tracing::info!(
            total_modules = modules.count(),
            enabled_modules = modules.enabled_count(),
            "orchestrator initialized"
        );

        Ok(Self {
            config,
            modules,
            shutdown_tx,
            start_time: Instant::now(),
            action_rx,
        })
    }

    /// Start all enabled modules and enter the main event loop.
    ///
    /// This method blocks until a shutdown signal is received.
    /// Modules are started in dependency order (producers first).
    ///
    /// # Shutdown Triggers
    ///
    /// - `SIGTERM` (from systemd, Docker, or `kill`)
    /// - `SIGINT` (Ctrl+C)
    pub async fn run(&mut self) -> Result<()> {
        // Write PID file if configured
        if !self.config.general.pid_file.is_empty() {
            let path = Path::new(&self.config.general.pid_file);
            write_pid_file(path)?;
        }

        // Start all modules
        tracing::info!("starting all enabled modules");
        if let Err(e) = self.modules.start_all().await {
            // Cleanup PID file on startup failure
            if !self.config.general.pid_file.is_empty() {
                let path = Path::new(&self.config.general.pid_file);
                remove_pid_file(path);
            }
            return Err(e);
        }

        // Spawn action logger task
        let mut action_logger_task = if let Some(action_rx) = self.action_rx.take() {
            let shutdown_rx = self.shutdown_tx.subscribe();
            Some(spawn_action_logger(action_rx, shutdown_rx))
        } else {
            None
        };

        // Main event loop
        tracing::info!("entering main event loop");
        let signal = wait_for_shutdown_signal().await?;
        tracing::info!(signal = signal, "shutdown signal received");

        // Initiate shutdown
        tracing::info!("broadcasting shutdown signal to all tasks");
        let _ = self.shutdown_tx.send(());

        // Wait for action logger to finish
        if let Some(task) = action_logger_task.take() {
            let _ = task.await;
        }

        // Stop all modules
        self.shutdown().await?;

        // Remove PID file
        if !self.config.general.pid_file.is_empty() {
            let path = Path::new(&self.config.general.pid_file);
            remove_pid_file(path);
        }

        Ok(())
    }

    /// Perform graceful shutdown of all modules.
    ///
    /// Stops modules in registration order (producers first, consumers last).
    /// This allows consumers to drain remaining events from their channels.
    async fn shutdown(&mut self) -> Result<()> {
        tracing::info!("stopping all modules");
        self.modules.stop_all().await
    }

    /// Get the current aggregated health status.
    #[allow(dead_code)] // Future health endpoint
    pub async fn health(&self) -> DaemonHealth {
        let statuses = self.modules.health_statuses().await;
        let modules: Vec<ModuleHealth> = statuses
            .into_iter()
            .map(|(name, enabled, status)| ModuleHealth {
                name,
                enabled,
                status,
            })
            .collect();

        let overall_status = aggregate_status(&modules);
        let uptime_secs = self.start_time.elapsed().as_secs();

        DaemonHealth {
            status: overall_status,
            uptime_secs,
            modules,
        }
    }

    /// Get a reference to the loaded configuration.
    #[allow(dead_code)] // Public API for introspection
    pub fn config(&self) -> &IronpostConfig {
        &self.config
    }
}

/// Wait for a shutdown signal (SIGTERM or SIGINT).
///
/// Returns the name of the signal that triggered the shutdown.
///
/// # Errors
///
/// Returns an error if signal handlers cannot be installed.
async fn wait_for_shutdown_signal() -> Result<&'static str> {
    use tokio::signal::unix::{SignalKind, signal};

    let mut sigterm = signal(SignalKind::terminate())
        .map_err(|e| anyhow::anyhow!("failed to install SIGTERM handler: {}", e))?;
    let mut sigint = signal(SignalKind::interrupt())
        .map_err(|e| anyhow::anyhow!("failed to install SIGINT handler: {}", e))?;

    Ok(tokio::select! {
        _ = sigterm.recv() => "SIGTERM",
        _ = sigint.recv() => "SIGINT",
    })
}

/// Write the current process PID to a file.
///
/// Used to prevent duplicate daemon instances.
///
/// # Errors
///
/// Returns an error if the PID file cannot be written.
fn write_pid_file(path: &Path) -> Result<()> {
    use std::fs::{self, OpenOptions};
    use std::io::{ErrorKind, Write};

    // Create parent directory if it doesn't exist
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)?;
    }

    let pid = std::process::id();

    // Atomically create file only if it doesn't exist (eliminates TOCTOU race)
    let mut file = match OpenOptions::new().write(true).create_new(true).open(path) {
        Ok(f) => f,
        Err(e) if e.kind() == ErrorKind::AlreadyExists => {
            // File already exists, read the existing PID for error message
            let existing_pid = fs::read_to_string(path).unwrap_or_else(|_| "unknown".to_string());
            return Err(anyhow::anyhow!(
                "PID file {} already exists with PID: {}. Is another instance running?",
                path.display(),
                existing_pid.trim()
            ));
        }
        Err(e) => return Err(e.into()),
    };

    writeln!(file, "{}", pid)?;

    tracing::info!(pid = pid, path = %path.display(), "PID file written");
    Ok(())
}

/// Remove the PID file on daemon shutdown.
///
/// Logs a warning but does not fail if the file cannot be removed.
fn remove_pid_file(path: &Path) {
    if let Err(e) = std::fs::remove_file(path) {
        tracing::warn!(
            path = %path.display(),
            error = %e,
            "failed to remove PID file"
        );
    } else {
        tracing::info!(path = %path.display(), "PID file removed");
    }
}

/// Spawn a background task that logs received ActionEvents.
///
/// ActionEvents represent completed isolation actions from container-guard.
/// This task logs them for audit purposes.
fn spawn_action_logger(
    mut action_rx: mpsc::Receiver<ActionEvent>,
    mut shutdown_rx: broadcast::Receiver<()>,
) -> tokio::task::JoinHandle<()> {
    tokio::spawn(async move {
        loop {
            tokio::select! {
                action_result = action_rx.recv() => {
                    match action_result {
                        Some(action) => {
                            tracing::info!(
                                action_id = %action.id,
                                action_type = %action.action_type,
                                target = %action.target,
                                success = action.success,
                                timestamp = ?action.metadata.timestamp,
                                "isolation action completed"
                            );
                        }
                        None => {
                            tracing::debug!("action channel closed, exiting logger");
                            break;
                        }
                    }
                }
                _ = shutdown_rx.recv() => {
                    tracing::debug!("action logger shutting down");
                    break;
                }
            }
        }
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;

    #[test]
    fn test_write_pid_file_creates_parent_directory() {
        // Given: A path with non-existent parent directory
        let temp_dir = std::env::temp_dir();
        let test_dir = temp_dir.join(format!("ironpost_test_{}", std::process::id()));
        let pid_file = test_dir.join("subdir").join("test.pid");

        // When: Writing PID file
        let result = write_pid_file(&pid_file);

        // Then: Should succeed and create parent directory
        assert!(
            result.is_ok(),
            "write_pid_file should create parent directory"
        );
        assert!(pid_file.exists(), "PID file should exist");

        // Verify content
        let content = fs::read_to_string(&pid_file).expect("should read PID file");
        let pid = std::process::id();
        assert_eq!(
            content.trim(),
            pid.to_string(),
            "PID file should contain current process ID"
        );

        // Cleanup
        let _ = fs::remove_dir_all(&test_dir);
    }

    #[test]
    fn test_write_pid_file_fails_if_already_exists() {
        // Given: An existing PID file
        let temp_dir = std::env::temp_dir();
        let pid_file = temp_dir.join(format!("ironpost_test_dup_{}.pid", std::process::id()));
        fs::write(&pid_file, "12345").expect("should write initial PID file");

        // When: Attempting to write PID file again
        let result = write_pid_file(&pid_file);

        // Then: Should fail with appropriate error
        assert!(
            result.is_err(),
            "write_pid_file should fail when file already exists"
        );
        let err_msg = result.unwrap_err().to_string();
        assert!(
            err_msg.contains("already exists"),
            "error should mention file already exists, got: {}",
            err_msg
        );
        assert!(
            err_msg.contains("12345"),
            "error should show existing PID, got: {}",
            err_msg
        );

        // Cleanup
        let _ = fs::remove_file(&pid_file);
    }

    #[test]
    fn test_remove_pid_file_succeeds() {
        // Given: An existing PID file
        let temp_dir = std::env::temp_dir();
        let pid_file = temp_dir.join(format!("ironpost_test_remove_{}.pid", std::process::id()));
        fs::write(&pid_file, "99999").expect("should write PID file");
        assert!(pid_file.exists(), "PID file should exist before removal");

        // When: Removing PID file
        remove_pid_file(&pid_file);

        // Then: File should be removed
        assert!(!pid_file.exists(), "PID file should be removed");
    }

    #[test]
    fn test_remove_pid_file_handles_nonexistent_gracefully() {
        // Given: A non-existent PID file
        let temp_dir = std::env::temp_dir();
        let pid_file = temp_dir.join(format!("ironpost_test_nonexist_{}.pid", std::process::id()));
        assert!(!pid_file.exists(), "PID file should not exist before test");

        // When: Attempting to remove non-existent file
        // Then: Should not panic (logs warning internally)
        remove_pid_file(&pid_file);
    }

    #[test]
    fn test_write_pid_file_correct_pid_format() {
        // Given: A test path
        let temp_dir = std::env::temp_dir();
        let pid_file = temp_dir.join(format!("ironpost_test_format_{}.pid", std::process::id()));

        // When: Writing PID file
        write_pid_file(&pid_file).expect("should write PID file");

        // Then: Content should be parseable as u32
        let content = fs::read_to_string(&pid_file).expect("should read PID file");
        let parsed_pid = content
            .trim()
            .parse::<u32>()
            .expect("PID should be valid u32");
        assert_eq!(
            parsed_pid,
            std::process::id(),
            "parsed PID should match current process ID"
        );

        // Cleanup
        let _ = fs::remove_file(&pid_file);
    }

    #[tokio::test]
    async fn test_spawn_action_logger_receives_events() {
        // Given: A channel and action logger
        let (action_tx, action_rx) = mpsc::channel(16);
        let (shutdown_tx, shutdown_rx) = broadcast::channel(1);

        let task = spawn_action_logger(action_rx, shutdown_rx);

        // When: Sending an action event
        let action = ActionEvent {
            id: uuid::Uuid::new_v4().to_string(),
            metadata: ironpost_core::event::EventMetadata {
                timestamp: std::time::SystemTime::now(),
                source_module: "test".to_string(),
                trace_id: uuid::Uuid::new_v4().to_string(),
            },
            action_type: "isolate".to_string(),
            target: "container123".to_string(),
            success: true,
        };
        action_tx.send(action).await.expect("should send action");

        // Give it time to process
        tokio::time::sleep(tokio::time::Duration::from_millis(10)).await;

        // Then: Shutdown gracefully
        let _ = shutdown_tx.send(());
        let _ = tokio::time::timeout(tokio::time::Duration::from_secs(1), task).await;
    }

    #[tokio::test]
    async fn test_spawn_action_logger_shutdown_signal() {
        // Given: A running action logger
        let (_action_tx, action_rx) = mpsc::channel::<ActionEvent>(16);
        let (shutdown_tx, shutdown_rx) = broadcast::channel(1);

        let task = spawn_action_logger(action_rx, shutdown_rx);

        // When: Sending shutdown signal
        let _ = shutdown_tx.send(());

        // Then: Task should complete quickly
        let result = tokio::time::timeout(tokio::time::Duration::from_millis(100), task).await;
        assert!(
            result.is_ok(),
            "action logger should shut down within timeout"
        );
    }
}

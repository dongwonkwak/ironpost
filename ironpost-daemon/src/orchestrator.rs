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
use ironpost_core::plugin::PluginRegistry;

use crate::health::{DaemonHealth, ModuleHealth, aggregate_status};
use crate::metrics_server;

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
    /// Registry of all plugins (ordered for start/stop).
    plugins: PluginRegistry,
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

        // Install metrics recorder before plugin initialization
        if config.metrics.enabled {
            metrics_server::install_metrics_recorder(&config.metrics)?;
            tracing::info!(port = config.metrics.port, "metrics endpoint enabled");
        }

        tracing::debug!("creating inter-module channels");

        // Create channels
        let (packet_tx, _packet_rx_for_ebpf) =
            mpsc::channel::<ironpost_core::event::PacketEvent>(PACKET_CHANNEL_CAPACITY);
        let (alert_tx, alert_rx) = mpsc::channel::<AlertEvent>(ALERT_CHANNEL_CAPACITY);
        let (shutdown_tx, _) = broadcast::channel(16);

        let mut plugins = PluginRegistry::new();
        let mut action_rx = None;

        // Initialize eBPF engine (Linux only)
        #[cfg(target_os = "linux")]
        {
            if config.ebpf.enabled {
                tracing::info!("initializing eBPF engine");
                let engine_config = ironpost_ebpf_engine::EngineConfig::from_core(&config.ebpf);
                let (engine, _packet_rx) = ironpost_ebpf_engine::EbpfEngine::builder()
                    .config(engine_config)
                    .event_sender(packet_tx.clone())
                    .build()
                    .map_err(|e| anyhow::anyhow!("failed to build eBPF engine: {}", e))?;
                plugins.register(Box::new(engine))?;
            }
        }
        #[cfg(not(target_os = "linux"))]
        {
            let _ = packet_tx; // Silence unused warning on non-Linux
        }

        // Initialize log pipeline
        if config.log_pipeline.enabled {
            tracing::info!("initializing log pipeline");
            let pipeline_config =
                ironpost_log_pipeline::PipelineConfig::from_core(&config.log_pipeline);

            #[cfg(target_os = "linux")]
            let builder = ironpost_log_pipeline::LogPipelineBuilder::new()
                .config(pipeline_config)
                .alert_sender(alert_tx.clone())
                .packet_receiver(_packet_rx_for_ebpf);

            #[cfg(not(target_os = "linux"))]
            let builder = {
                let (_, dummy_rx) = mpsc::channel(1);
                ironpost_log_pipeline::LogPipelineBuilder::new()
                    .config(pipeline_config)
                    .alert_sender(alert_tx.clone())
                    .packet_receiver(dummy_rx)
            };

            let (pipeline, _) = builder
                .build()
                .map_err(|e| anyhow::anyhow!("failed to build log pipeline: {}", e))?;
            plugins.register(Box::new(pipeline))?;
        }

        // Initialize SBOM scanner
        if config.sbom.enabled {
            tracing::info!("initializing SBOM scanner");
            let scanner_config = ironpost_sbom_scanner::SbomScannerConfig::from_core(&config.sbom);
            let (scanner, _) = ironpost_sbom_scanner::SbomScannerBuilder::new()
                .config(scanner_config)
                .alert_sender(alert_tx.clone())
                .build()
                .map_err(|e| anyhow::anyhow!("failed to build SBOM scanner: {}", e))?;
            plugins.register(Box::new(scanner))?;
        }

        // Initialize container guard
        if config.container.enabled {
            tracing::info!("initializing container guard");
            let guard_config =
                ironpost_container_guard::ContainerGuardConfig::from_core(&config.container);
            let docker = std::sync::Arc::new(
                ironpost_container_guard::BollardDockerClient::connect_local()?,
            );
            let (guard, rx) = ironpost_container_guard::ContainerGuardBuilder::new()
                .config(guard_config)
                .docker_client(docker)
                .alert_receiver(alert_rx)
                .build()
                .map_err(|e| anyhow::anyhow!("failed to build container guard: {}", e))?;
            plugins.register(Box::new(guard))?;
            action_rx = rx;
        } else {
            // When container guard is disabled, spawn a task to drain alerts (prevents send errors)
            tracing::debug!("container guard disabled, spawning alert drain task");
            let shutdown_rx = shutdown_tx.subscribe();
            tokio::spawn(drain_alerts(alert_rx, shutdown_rx));
        }

        tracing::info!(total_plugins = plugins.count(), "orchestrator initialized");

        // Record daemon metrics
        if config.metrics.enabled {
            record_daemon_metrics(plugins.count());
        }

        Ok(Self {
            config,
            plugins,
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

        // Initialize and start all plugins
        tracing::info!("initializing all plugins");
        if let Err(e) = self.plugins.init_all().await {
            tracing::error!(error = %e, "plugin initialization failed");
            if !self.config.general.pid_file.is_empty() {
                let path = Path::new(&self.config.general.pid_file);
                remove_pid_file(path);
            }
            return Err(e.into());
        }

        tracing::info!("starting all plugins");
        if let Err(e) = self.plugins.start_all().await {
            // Rollback: stop any plugins that were successfully started
            tracing::warn!("startup failed, rolling back already-started plugins");
            if let Err(stop_err) = self.plugins.stop_all().await {
                tracing::error!(
                    startup_error = %e,
                    rollback_error = %stop_err,
                    "rollback also failed during startup failure cleanup"
                );
            }

            // Cleanup PID file on startup failure
            if !self.config.general.pid_file.is_empty() {
                let path = Path::new(&self.config.general.pid_file);
                remove_pid_file(path);
            }
            return Err(e.into());
        }

        // Spawn action logger task
        let mut action_logger_task = if let Some(action_rx) = self.action_rx.take() {
            let shutdown_rx = self.shutdown_tx.subscribe();
            Some(spawn_action_logger(action_rx, shutdown_rx))
        } else {
            None
        };

        // Spawn uptime updater task
        let mut uptime_updater_task = if self.config.metrics.enabled {
            let shutdown_rx = self.shutdown_tx.subscribe();
            let start_time = self.start_time;
            Some(spawn_uptime_updater(start_time, shutdown_rx))
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

        // Wait for uptime updater to finish
        if let Some(task) = uptime_updater_task.take() {
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

    /// Perform graceful shutdown of all plugins.
    ///
    /// Stops plugins in registration order (producers first, consumers last).
    /// This allows consumers to drain remaining events from their channels.
    async fn shutdown(&mut self) -> Result<()> {
        tracing::info!("stopping all plugins");
        self.plugins.stop_all().await.map_err(|e| e.into())
    }

    /// Get the current aggregated health status.
    #[allow(dead_code)] // Future health endpoint
    pub async fn health(&self) -> DaemonHealth {
        let statuses = self.plugins.health_check_all().await;
        let modules: Vec<ModuleHealth> = statuses
            .into_iter()
            .map(|(name, _plugin_state, status)| ModuleHealth {
                name,
                enabled: true, // All registered plugins are enabled
                status,
            })
            .collect();

        let overall_status = aggregate_status(&modules);
        let uptime_secs = self.start_time.elapsed().as_secs();

        // Update uptime metric
        if self.config.metrics.enabled {
            use ironpost_core::metrics as m;
            #[allow(clippy::cast_precision_loss)]
            metrics::gauge!(m::DAEMON_UPTIME_SECONDS).set(uptime_secs as f64);
        }

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
/// # Security
///
/// - Uses `create_new(true)` to atomically create file (prevents TOCTOU races)
/// - Verifies the created file is a regular file (prevents symlink attacks)
/// - Creates parent directory with restrictive permissions (0o700)
///
/// # Errors
///
/// Returns an error if the PID file cannot be written.
fn write_pid_file(path: &Path) -> Result<()> {
    use std::fs::{self, OpenOptions};
    use std::io::{ErrorKind, Write};

    // Create parent directory with restrictive permissions (0o700)
    if let Some(parent) = path.parent() {
        #[cfg(unix)]
        {
            use std::os::unix::fs::DirBuilderExt;
            let mut builder = fs::DirBuilder::new();
            builder.mode(0o700).recursive(true);
            builder.create(parent)?;
        }
        #[cfg(not(unix))]
        {
            fs::create_dir_all(parent)?;
        }
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

    // Verify the created file is a regular file (not a symlink or other special file)
    let metadata = file.metadata()?;
    if !metadata.is_file() {
        // Remove the non-regular file and return error
        let _ = fs::remove_file(path);
        return Err(anyhow::anyhow!(
            "PID file {} is not a regular file (possible symlink attack)",
            path.display()
        ));
    }

    // Set restrictive permissions on the PID file (0o600)
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let permissions = std::fs::Permissions::from_mode(0o600);
        file.set_permissions(permissions)?;
    }

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

/// Drain alert events when container guard is disabled.
///
/// This prevents alert producers (log pipeline, SBOM scanner) from encountering
/// send errors when the container guard is not running. Alerts are logged but
/// not acted upon.
async fn drain_alerts(
    mut alert_rx: mpsc::Receiver<AlertEvent>,
    mut shutdown_rx: broadcast::Receiver<()>,
) {
    loop {
        tokio::select! {
            alert_result = alert_rx.recv() => {
                match alert_result {
                    Some(alert) => {
                        tracing::debug!(
                            alert_id = %alert.id,
                            alert_title = %alert.alert.title,
                            severity = %alert.severity,
                            "alert received but container guard disabled (alert dropped)"
                        );
                    }
                    None => {
                        tracing::debug!("alert channel closed, exiting drain task");
                        break;
                    }
                }
            }
            _ = shutdown_rx.recv() => {
                tracing::debug!("alert drain task shutting down");
                break;
            }
        }
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

/// Record daemon-level metrics (build info, plugins registered).
///
/// This should be called once during orchestrator initialization.
fn record_daemon_metrics(plugin_count: usize) {
    use ironpost_core::metrics as m;

    // Build info (always 1, with version label)
    // TODO: Extract version from Cargo.toml or build-time env var
    #[allow(clippy::cast_precision_loss)]
    metrics::gauge!(m::DAEMON_BUILD_INFO, "version" => env!("CARGO_PKG_VERSION")).set(1.0);

    // Registered plugins count
    #[allow(clippy::cast_precision_loss)]
    metrics::gauge!(m::DAEMON_PLUGINS_REGISTERED).set(plugin_count as f64);

    tracing::debug!(
        plugin_count = plugin_count,
        version = env!("CARGO_PKG_VERSION"),
        "daemon metrics recorded"
    );
}

/// Spawn a background task that periodically updates the uptime metric.
///
/// Updates every 10 seconds to keep the metric fresh for Prometheus scrapes.
fn spawn_uptime_updater(
    start_time: Instant,
    mut shutdown_rx: broadcast::Receiver<()>,
) -> tokio::task::JoinHandle<()> {
    use ironpost_core::metrics as m;

    tokio::spawn(async move {
        let mut interval = tokio::time::interval(tokio::time::Duration::from_secs(10));
        interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);

        loop {
            tokio::select! {
                _ = interval.tick() => {
                    let uptime_secs = start_time.elapsed().as_secs();
                    #[allow(clippy::cast_precision_loss)]
                    metrics::gauge!(m::DAEMON_UPTIME_SECONDS).set(uptime_secs as f64);
                }
                _ = shutdown_rx.recv() => {
                    tracing::debug!("uptime updater shutting down");
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

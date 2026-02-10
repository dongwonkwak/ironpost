# ironpost-daemon Design Document

## Overview

`ironpost-daemon` is the main orchestrator binary that wires all ironpost crates together.
It manages module lifecycles, connects inter-module event channels, handles configuration
loading, and provides graceful shutdown with error isolation.

## Architecture Principles

1. **Dependency Inversion**: The daemon depends on all crates; crates depend only on `core`.
2. **Event-Based Communication**: All inter-module communication uses `tokio::mpsc` channels.
3. **Error Isolation**: One module's panic/failure must not crash the entire daemon.
4. **Ordered Shutdown**: Producers stop before consumers to drain in-flight events.
5. **Config-Driven Assembly**: Modules are conditionally initialized based on `ironpost.toml`.

## Channel Topology

```
+-------------------+                          +-------------------+
|   ebpf-engine     |                          |   sbom-scanner    |
|   (Linux only)    |                          |                   |
+--------+----------+                          +--------+----------+
         |                                              |
         | PacketEvent                                  | AlertEvent
         | (mpsc, cap=1024)                             | (mpsc, cap=256)
         v                                              v
+--------+--------------------------------------------------+--------+
|                        log-pipeline                                 |
|  PacketEvent -> EventReceiver -> RawLog -> Buffer -> Parser        |
|  -> RuleEngine -> AlertGenerator                                   |
+--------+-----------------------------------------------------------+
         |
         | AlertEvent
         | (mpsc, cap=256)
         v
+--------+----------+
|  container-guard  |
|  PolicyEngine     |
|  -> Isolation     |
+--------+----------+
         |
         | ActionEvent
         | (mpsc, cap=256)
         v
+--------+----------+
|  action_collector |
|  (daemon-internal)|
|  logging / audit  |
+---------+---------+
```

### Channel Definitions

| Channel | Type | Capacity | Producer | Consumer |
|---------|------|----------|----------|----------|
| `packet_tx/rx` | `mpsc<PacketEvent>` | 1024 | ebpf-engine | log-pipeline |
| `alert_tx/rx` | `mpsc<AlertEvent>` | 256 | log-pipeline, sbom-scanner | container-guard |
| `action_tx/rx` | `mpsc<ActionEvent>` | 256 | container-guard | daemon (logging) |

### Alert Channel Merging

Both `log-pipeline` and `sbom-scanner` produce `AlertEvent`. The daemon creates a single
`alert_tx/rx` pair and passes clones of `alert_tx` to both producers. The container-guard
consumes from the shared `alert_rx`.

```
log-pipeline ----alert_tx.clone()---+
                                    +--> alert_rx --> container-guard
sbom-scanner ----alert_tx.clone()---+
```

## Module Structure

```
ironpost-daemon/
  src/
    main.rs          -- Entry point, CLI args, signal handling, tracing init
    cli.rs           -- clap CLI argument definitions
    orchestrator.rs  -- Module assembly, channel wiring, lifecycle management
    health.rs        -- Aggregated health check reporting
    logging.rs       -- tracing-subscriber initialization (JSON / pretty)
    modules/
      mod.rs         -- Module registry and ModuleHandle type
      ebpf.rs        -- eBPF engine conditional initialization (#[cfg(target_os = "linux")])
      log_pipeline.rs -- Log pipeline initialization from IronpostConfig
      container_guard.rs -- Container guard initialization from IronpostConfig
      sbom_scanner.rs -- SBOM scanner initialization from IronpostConfig
```

## Key Types

### Orchestrator

```rust
pub struct Orchestrator {
    config: IronpostConfig,
    modules: ModuleRegistry,
    shutdown_tx: broadcast::Sender<()>,
}
```

The `Orchestrator` is responsible for:
1. Loading and validating `IronpostConfig`
2. Creating inter-module channels
3. Building and initializing enabled modules
4. Starting modules in dependency order (producers first)
5. Running the main event loop (health checks, action logging)
6. Stopping modules in reverse order on shutdown signal

### ModuleRegistry

```rust
pub struct ModuleRegistry {
    modules: Vec<ModuleHandle>,
}

pub struct ModuleHandle {
    name: String,
    pipeline: Box<dyn DynPipeline>,
    enabled: bool,
}
```

The `ModuleRegistry` tracks all registered modules and provides ordered start/stop.
`DynPipeline` is the dyn-compatible wrapper from `ironpost-core::pipeline`.

### DaemonCli

```rust
#[derive(clap::Parser)]
pub struct DaemonCli {
    /// Path to ironpost.toml configuration file
    #[arg(short, long, default_value = "/etc/ironpost/ironpost.toml")]
    config: PathBuf,

    /// Override log level (trace, debug, info, warn, error)
    #[arg(long)]
    log_level: Option<String>,

    /// Override log format (json, pretty)
    #[arg(long)]
    log_format: Option<String>,

    /// Validate config and exit
    #[arg(long)]
    validate: bool,
}
```

## Startup Sequence

```
1. Parse CLI arguments (clap)
2. Load ironpost.toml (IronpostConfig::load)
3. Apply CLI overrides (log_level, log_format)
4. Initialize tracing-subscriber
5. Write PID file (if configured)
6. Create inter-module channels
7. Build enabled modules:
   a. ebpf-engine (Linux only, if enabled)
   b. log-pipeline (if enabled)
   c. sbom-scanner (if enabled)
   d. container-guard (if enabled)
8. Start modules in order:
   a. ebpf-engine (producer)
   b. log-pipeline (producer -> consumer)
   c. sbom-scanner (producer)
   d. container-guard (consumer)
9. Spawn health check task
10. Spawn action logging task
11. Wait for shutdown signal (SIGTERM / SIGINT)
```

## Shutdown Sequence

```
1. Receive SIGTERM or SIGINT
2. Send shutdown broadcast to all tasks
3. Stop modules in reverse order:
   a. ebpf-engine (stop producing packets)
   b. sbom-scanner (stop producing alerts)
   c. log-pipeline (drain buffer, stop producing alerts)
   d. container-guard (drain remaining alerts, stop)
4. Await all background tasks
5. Remove PID file
6. Log final statistics
7. Exit
```

The key insight: **producers stop first** so consumers can drain in-flight messages.
Within producers, ebpf-engine stops first (it feeds log-pipeline), then sbom-scanner,
then log-pipeline (which feeds container-guard), and finally container-guard.

## Error Isolation Strategy

### panic!() Isolation

Since `Cargo.toml` sets `panic = "abort"`, a panic in any thread aborts the process.
To isolate module failures:

1. Each module runs in a `tokio::spawn` task.
2. The orchestrator uses `JoinHandle` to detect task termination.
3. If a module task panics (join error), the orchestrator logs the failure and
   marks the module as `Unhealthy`, but continues running other modules.
4. The health check task periodically reports degraded status.

Note: With `panic = "abort"`, `std::panic::catch_unwind` cannot catch panics.
The recommended approach for production deployment is to use a process supervisor
(systemd, Docker restart policy) as the ultimate recovery mechanism. The daemon
focuses on graceful handling of `Result::Err` returns, not `panic!()`.

### Error Recovery

- **Recoverable errors** (network timeout, Docker unavailable): Log and continue.
  The health check reports `Degraded` status.
- **Fatal errors** (config parse failure, missing required resources): Fail fast
  during startup, before entering the main loop.
- **Channel errors** (receiver dropped): The producing module detects `SendError`
  and logs a warning. The health check reports the broken channel.

## Health Check Design

```rust
pub struct DaemonHealth {
    pub status: HealthStatus,
    pub uptime_secs: u64,
    pub modules: Vec<ModuleHealth>,
}

pub struct ModuleHealth {
    pub name: String,
    pub enabled: bool,
    pub status: HealthStatus,
}
```

The health check task runs every 30 seconds (configurable) and:
1. Calls `health_check()` on each module's `DynPipeline`
2. Aggregates results into `DaemonHealth`
3. Logs the aggregated status via `tracing`
4. The overall status is the worst status among all enabled modules

Aggregation rule:
- All Healthy -> Healthy
- Any Degraded, none Unhealthy -> Degraded
- Any Unhealthy -> Unhealthy

## Configuration Flow

```
ironpost.toml
     |
     v
IronpostConfig (core)
     |
     +---> EbpfConfig ----------> EngineConfig::from_core()
     |
     +---> LogPipelineConfig ----> PipelineConfig::from_core()
     |
     +---> ContainerConfig ------> ContainerGuardConfig::from_core()
     |
     +---> SbomConfig -----------> SbomScannerConfig::from_core()
```

Each module's `from_core()` method converts the core config section into its
module-specific config struct, applying defaults for extended fields not present
in the core config.

## Module Initialization Details

### eBPF Engine (Linux only)

```rust
#[cfg(target_os = "linux")]
fn init_ebpf(config: &IronpostConfig, packet_tx: mpsc::Sender<PacketEvent>)
    -> anyhow::Result<Option<EbpfEngine>>
```

- Conditionally compiled with `#[cfg(target_os = "linux")]`
- On non-Linux platforms, returns `None` (module skipped)
- Creates `EngineConfig::from_core(&config.ebpf)`
- Builds engine with external `packet_tx` sender

### Log Pipeline

```rust
fn init_log_pipeline(
    config: &IronpostConfig,
    packet_rx: Option<mpsc::Receiver<PacketEvent>>,
    alert_tx: mpsc::Sender<AlertEvent>,
) -> anyhow::Result<LogPipeline>
```

- Creates `PipelineConfig::from_core(&config.log_pipeline)`
- Connects packet_rx from ebpf-engine (if available)
- Uses shared alert_tx for downstream alert delivery

### SBOM Scanner

```rust
fn init_sbom_scanner(
    config: &IronpostConfig,
    alert_tx: mpsc::Sender<AlertEvent>,
) -> anyhow::Result<SbomScanner>
```

- Creates `SbomScannerConfig::from_core(&config.sbom)`
- Uses cloned alert_tx for alert delivery

### Container Guard

```rust
fn init_container_guard(
    config: &IronpostConfig,
    alert_rx: mpsc::Receiver<AlertEvent>,
) -> anyhow::Result<ContainerGuard<BollardDockerClient>>
```

- Creates `ContainerGuardConfig::from_core(&config.container)`
- Receives alert_rx (consuming end of the shared alert channel)
- Creates BollardDockerClient for Docker API access

## PID File Management

```rust
fn write_pid_file(path: &Path) -> anyhow::Result<()>
fn remove_pid_file(path: &Path)
```

- Writes current PID to file at startup
- Checks for existing PID file (duplicate instance prevention)
- Removes PID file on clean shutdown

## Signal Handling

```rust
async fn wait_for_shutdown() -> &'static str
```

- `SIGTERM`: Graceful shutdown (from systemd, Docker)
- `SIGINT`: Graceful shutdown (Ctrl+C)
- Returns the signal name for logging

## ironpost.toml Schema

See the `ironpost.toml.example` file at the project root for the complete schema
with comments. The schema is defined by `IronpostConfig` in `crates/core/src/config.rs`.

### Sections

| Section | Struct | Module |
|---------|--------|--------|
| `[general]` | `GeneralConfig` | daemon |
| `[ebpf]` | `EbpfConfig` | ebpf-engine |
| `[log_pipeline]` | `LogPipelineConfig` | log-pipeline |
| `[log_pipeline.storage]` | `StorageConfig` | log-pipeline |
| `[container]` | `ContainerConfig` | container-guard |
| `[sbom]` | `SbomConfig` | sbom-scanner |

### Environment Variable Override Map

| Env Variable | Config Field |
|---|---|
| `IRONPOST_GENERAL_LOG_LEVEL` | `general.log_level` |
| `IRONPOST_GENERAL_LOG_FORMAT` | `general.log_format` |
| `IRONPOST_GENERAL_DATA_DIR` | `general.data_dir` |
| `IRONPOST_GENERAL_PID_FILE` | `general.pid_file` |
| `IRONPOST_EBPF_ENABLED` | `ebpf.enabled` |
| `IRONPOST_EBPF_INTERFACE` | `ebpf.interface` |
| `IRONPOST_EBPF_XDP_MODE` | `ebpf.xdp_mode` |
| `IRONPOST_EBPF_RING_BUFFER_SIZE` | `ebpf.ring_buffer_size` |
| `IRONPOST_EBPF_BLOCKLIST_MAX_ENTRIES` | `ebpf.blocklist_max_entries` |
| `IRONPOST_LOG_PIPELINE_ENABLED` | `log_pipeline.enabled` |
| `IRONPOST_LOG_PIPELINE_SOURCES` | `log_pipeline.sources` (CSV) |
| `IRONPOST_LOG_PIPELINE_SYSLOG_BIND` | `log_pipeline.syslog_bind` |
| `IRONPOST_LOG_PIPELINE_WATCH_PATHS` | `log_pipeline.watch_paths` (CSV) |
| `IRONPOST_LOG_PIPELINE_BATCH_SIZE` | `log_pipeline.batch_size` |
| `IRONPOST_LOG_PIPELINE_FLUSH_INTERVAL_SECS` | `log_pipeline.flush_interval_secs` |
| `IRONPOST_STORAGE_POSTGRES_URL` | `log_pipeline.storage.postgres_url` |
| `IRONPOST_STORAGE_REDIS_URL` | `log_pipeline.storage.redis_url` |
| `IRONPOST_STORAGE_RETENTION_DAYS` | `log_pipeline.storage.retention_days` |
| `IRONPOST_CONTAINER_ENABLED` | `container.enabled` |
| `IRONPOST_CONTAINER_DOCKER_SOCKET` | `container.docker_socket` |
| `IRONPOST_CONTAINER_POLL_INTERVAL_SECS` | `container.poll_interval_secs` |
| `IRONPOST_CONTAINER_POLICY_PATH` | `container.policy_path` |
| `IRONPOST_CONTAINER_AUTO_ISOLATE` | `container.auto_isolate` |
| `IRONPOST_SBOM_ENABLED` | `sbom.enabled` |
| `IRONPOST_SBOM_SCAN_DIRS` | `sbom.scan_dirs` (CSV) |
| `IRONPOST_SBOM_VULN_DB_UPDATE_HOURS` | `sbom.vuln_db_update_hours` |
| `IRONPOST_SBOM_VULN_DB_PATH` | `sbom.vuln_db_path` |
| `IRONPOST_SBOM_MIN_SEVERITY` | `sbom.min_severity` |
| `IRONPOST_SBOM_OUTPUT_FORMAT` | `sbom.output_format` |

## Testing Strategy

### Unit Tests
- `orchestrator.rs`: Test module registration, ordered start/stop
- `health.rs`: Test health aggregation logic
- `modules/*.rs`: Test config conversion and builder wiring

### Integration Tests
- Config loading with partial TOML
- Startup with all modules disabled (no-op daemon)
- Channel wiring verification (send event, receive at other end)
- Graceful shutdown ordering

### E2E Tests (Phase T6-9)
- Full pipeline flow: log injection -> rule match -> alert -> isolation (mock)
- SBOM scan -> vulnerability -> alert
- Module failure isolation

## Future Considerations

1. **SIGHUP for config reload**: Hot-reload config via `tokio::watch` channel
2. **Unix domain socket for CLI**: Local IPC for `ironpost-cli` to query daemon status
3. **Metrics endpoint**: Prometheus-compatible `/metrics` HTTP endpoint
4. **Plugin system**: Dynamic module loading via `dylib`

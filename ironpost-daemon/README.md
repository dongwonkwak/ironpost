# ironpost-daemon

The main orchestrator binary for the Ironpost security monitoring platform.

## Overview

`ironpost-daemon` is the central coordinator that assembles and manages the lifecycle of all Ironpost modules:

- **eBPF Engine** (Linux only) - Real-time network packet filtering and detection
- **Log Pipeline** - Multi-source log collection, parsing, and rule-based detection
- **Container Guard** - Alert-driven Docker container isolation
- **SBOM Scanner** - Periodic vulnerability scanning of software dependencies

The daemon loads configuration from a single TOML file (`/etc/ironpost/ironpost.toml`), creates inter-module communication channels, starts enabled modules in dependency order, and orchestrates graceful shutdown on `SIGTERM` or `SIGINT`.

## Architecture

### Module Communication

All modules communicate exclusively through **typed `tokio::mpsc` channels**. No module directly depends on another—they are wired together by the orchestrator at startup.

```text
┌────────────────────────────────────────────────────────────┐
│                    Orchestrator                            │
│  (Channel Wiring + Lifecycle Management)                   │
└───────────┬─────────────┬─────────────┬─────────────┬──────┘
            │             │             │             │
            ▼             ▼             ▼             ▼
     ┌──────────┐  ┌──────────┐  ┌──────────┐  ┌──────────┐
     │  eBPF    │  │   Log    │  │   SBOM   │  │Container │
     │ Engine   │  │ Pipeline │  │ Scanner  │  │  Guard   │
     └────┬─────┘  └────┬─────┘  └────┬─────┘  └────┬─────┘
          │             │             │             │
          │PacketEvent  │AlertEvent   │AlertEvent   │ActionEvent
          └────────────▶│             │             │
                        └─────────────┴────────────▶│
                                                     └───────▶ (audit log)
```

### Event Flow

1. **eBPF Engine** detects suspicious network packets → emits `PacketEvent`
2. **Log Pipeline** receives `PacketEvent`, parses logs, applies rules → emits `AlertEvent`
3. **SBOM Scanner** finds vulnerabilities → emits `AlertEvent`
4. **Container Guard** consumes `AlertEvent`, evaluates policies, isolates containers → emits `ActionEvent`
5. **Orchestrator** logs `ActionEvent` for audit trail

### Startup Order (Producers First)

Modules are started in this order to ensure data producers are ready before consumers:

1. eBPF Engine (produces `PacketEvent`)
2. Log Pipeline (consumes `PacketEvent`, produces `AlertEvent`)
3. SBOM Scanner (produces `AlertEvent`)
4. Container Guard (consumes `AlertEvent`, produces `ActionEvent`)

### Shutdown Order (Same as Startup)

The orchestrator stops modules in **registration order** (producers first), allowing consumers to drain remaining events from their channels before shutting down. This prevents event loss during graceful shutdown.

## Configuration

The daemon loads configuration from a single TOML file with sections for each module:

```toml
# /etc/ironpost/ironpost.toml

[general]
log_level = "info"          # trace, debug, info, warn, error
log_format = "json"         # json, pretty
pid_file = "/var/run/ironpost/ironpost.pid"

[ebpf]
enabled = true
interface = "eth0"
mode = "xdp"                # xdp, tc

[log_pipeline]
enabled = true
file_paths = ["/var/log/syslog", "/var/log/auth.log"]
syslog_udp_addr = "0.0.0.0:514"
syslog_tcp_addr = "0.0.0.0:514"
rules_dir = "/etc/ironpost/rules"
flush_interval_secs = 5
buffer_capacity = 10000

[container]
enabled = true
docker_socket = "/var/run/docker.sock"
policy_dir = "/etc/ironpost/policies"
cache_ttl_secs = 60
retry_attempts = 3
retry_backoff_secs = 2

[sbom]
enabled = true
scan_dirs = ["/opt/app", "/usr/local"]
scan_interval_secs = 3600
vuln_db_path = "/var/lib/ironpost/vulndb.json"
min_severity = "medium"     # critical, high, medium, low

[storage]
postgres_url = "postgresql://ironpost:password@localhost:5432/ironpost"
redis_url = "redis://localhost:6379/0"
```

### Configuration Precedence

1. **CLI arguments** (highest priority)
2. **Environment variables** (`IRONPOST_EBPF_INTERFACE=eth0`)
3. **TOML file** (`ironpost.toml`)
4. **Default values** (lowest priority)

## Usage

### Starting the Daemon

```bash
# Use default config path
ironpost-daemon

# Specify custom config
ironpost-daemon --config /etc/ironpost/ironpost.toml

# Override log settings
ironpost-daemon --log-level debug --log-format pretty

# Validate config and exit
ironpost-daemon --validate

# Custom PID file
ironpost-daemon --pid-file /tmp/ironpost.pid
```

### Systemd Service

```ini
[Unit]
Description=Ironpost Security Monitoring Daemon
After=network.target docker.service
Requires=docker.service

[Service]
Type=simple
User=root
ExecStart=/usr/local/bin/ironpost-daemon --config /etc/ironpost/ironpost.toml
Restart=on-failure
RestartSec=5s
StandardOutput=journal
StandardError=journal

[Install]
WantedBy=multi-user.target
```

```bash
sudo systemctl enable ironpost-daemon
sudo systemctl start ironpost-daemon
sudo systemctl status ironpost-daemon
```

### Signals

- **SIGTERM** - Graceful shutdown (stops modules in order, drains channels)
- **SIGINT** (`Ctrl+C`) - Same as SIGTERM

## CLI Commands

Use `ironpost-cli` for runtime management:

```bash
# Check daemon status
ironpost-cli status

# View configuration
ironpost-cli config show

# Validate configuration
ironpost-cli config validate

# List detection rules
ironpost-cli rules list

# Validate rule files
ironpost-cli rules validate

# Trigger on-demand SBOM scan
ironpost-cli scan --dir /opt/myapp

# Start daemon (background process)
ironpost-cli start
```

## Logging

The daemon uses structured logging via `tracing`:

### JSON Format (Production)

```bash
ironpost-daemon --log-format json
```

```json
{"timestamp":"2026-02-11T07:03:00Z","level":"INFO","fields":{"message":"ironpost-daemon starting","version":"0.1.0","config_path":"/etc/ironpost/ironpost.toml"},"target":"ironpost_daemon"}
{"timestamp":"2026-02-11T07:03:01Z","level":"INFO","fields":{"message":"module started successfully","module":"ebpf-engine"},"target":"ironpost_daemon::modules"}
```

### Pretty Format (Development)

```bash
ironpost-daemon --log-format pretty
```

```text
2026-02-11T07:03:00Z  INFO ironpost_daemon: ironpost-daemon starting version="0.1.0" config_path="/etc/ironpost/ironpost.toml"
2026-02-11T07:03:01Z  INFO ironpost_daemon::modules: module started successfully module="ebpf-engine"
```

## PID File

The daemon writes its process ID to a PID file to prevent duplicate instances:

```bash
# Default location
/var/run/ironpost/ironpost.pid

# Custom location
ironpost-daemon --pid-file /tmp/ironpost.pid
```

If the PID file already exists, the daemon will refuse to start and display the existing PID.

## Health Checks

The orchestrator periodically polls each module's `health_check()` method and aggregates the status:

- **Healthy** - All enabled modules are operational
- **Degraded** - One or more modules report degraded status (e.g., high latency, buffer full)
- **Unhealthy** - One or more modules are not responding or have failed

Health status can be queried via `ironpost-cli status` (future: HTTP health endpoint at `/health`).

## Error Handling

### Module Initialization Errors

If any enabled module fails to initialize, the daemon logs the error and exits with a non-zero status code. This prevents partial startup where some modules are running while others have failed.

### Module Start Errors

If a module fails to start during `start_all()`, the daemon does **not** automatically roll back. The caller (orchestrator) is responsible for calling `stop_all()` to clean up any successfully started modules.

### Module Stop Errors

If a module fails to stop during `stop_all()`, the orchestrator logs the error but continues stopping remaining modules. After all modules have been processed, if any stop operation failed, the orchestrator returns an aggregated error.

### Signal Handler Errors

If signal handlers (`SIGTERM`, `SIGINT`) cannot be installed, the daemon returns an error immediately. This is critical because without signal handling, the daemon cannot perform graceful shutdown.

## Development

### Building eBPF Programs

The eBPF engine requires building kernel-side BPF programs before the daemon can load them:

```bash
# Build daemon + all modules including eBPF (recommended)
cargo run -p xtask -- build --all
cargo run -p xtask -- build --all --release

# Build eBPF programs only (development)
cargo run -p xtask -- build-ebpf

# Build eBPF programs only (release)
cargo run -p xtask -- build-ebpf --release
```

This compiles the BPF bytecode in `crates/ebpf-engine/ebpf/` and generates artifacts in `target/bpfel-unknown-none/`. The daemon will load these programs at runtime when the eBPF engine module is enabled.

**Note**: eBPF builds require:
- Linux kernel headers (`kernel-headers` package)
- `bpf-linker` (`cargo install bpf-linker`)
- Nightly Rust toolchain (automatically used by `xtask`)

### Running Tests

```bash
# Run all daemon tests
cargo test -p ironpost-daemon

# Run orchestrator tests only
cargo test -p ironpost-daemon orchestrator

# Run module registry tests
cargo test -p ironpost-daemon modules::tests

# Run with logging
cargo test -p ironpost-daemon -- --nocapture
```

### Integration Testing

The daemon exposes internal modules via `lib.rs` for integration testing:

```rust
use ironpost_daemon::{orchestrator::Orchestrator, health::aggregate_status};

#[tokio::test]
async fn test_orchestrator_build() {
    let config = ironpost_core::config::IronpostConfig::default();
    let orchestrator = Orchestrator::build_from_config(config).await;
    assert!(orchestrator.is_ok());
}
```

### Mocking Modules

Each module initializer (`ebpf::init`, `log_pipeline::init`, etc.) accepts channels and returns a `ModuleHandle` wrapping a `Box<dyn DynPipeline>`. For testing, you can inject mock implementations of the `DynPipeline` trait.

## Dependencies

### Runtime Dependencies

- **Rust 2024 edition** (stable toolchain)
- **Linux kernel 5.10+** (for eBPF engine; optional on other platforms)
- **Docker Engine** (for container guard; optional if disabled)

### Crate Dependencies

```toml
[dependencies]
ironpost-core = { path = "../crates/core" }
ironpost-ebpf-engine = { path = "../crates/ebpf-engine", optional = true }
ironpost-log-pipeline = { path = "../crates/log-pipeline" }
ironpost-container-guard = { path = "../crates/container-guard" }
ironpost-sbom-scanner = { path = "../crates/sbom-scanner" }

tokio = { version = "1", features = ["full"] }
anyhow = "1"
clap = { version = "4", features = ["derive"] }
tracing = "0.1"
tracing-subscriber = { version = "0.3", features = ["json", "env-filter"] }
serde = { version = "1", features = ["derive"] }
```

## Related Crates

- [`ironpost-core`](../crates/core) - Shared types, configuration, and traits
- [`ironpost-ebpf-engine`](../crates/ebpf-engine) - XDP/TC network packet filtering
- [`ironpost-log-pipeline`](../crates/log-pipeline) - Log collection and rule engine
- [`ironpost-container-guard`](../crates/container-guard) - Container isolation enforcement
- [`ironpost-sbom-scanner`](../crates/sbom-scanner) - Software vulnerability scanning
- [`ironpost-cli`](../ironpost-cli) - Command-line interface

## Security Considerations

### Privilege Requirements

The daemon typically requires **root** or `CAP_NET_ADMIN` for:

- eBPF XDP program loading (requires `CAP_SYS_ADMIN` or `CAP_BPF`)
- Binding to privileged ports (syslog UDP/TCP 514)
- Docker container operations

### PID File Security

The PID file is created with `OpenOptions::create_new(true)` to atomically prevent TOCTOU race conditions. If the parent directory does not exist, it will be created with default permissions.

### Credential Exposure

The daemon loads database URLs (PostgreSQL, Redis) from the configuration file, which may contain embedded credentials. Ensure the config file has restrictive permissions:

```bash
sudo chown root:root /etc/ironpost/ironpost.toml
sudo chmod 600 /etc/ironpost/ironpost.toml
```

The `ironpost-cli config show` command redacts credentials by default (replaces `user:password` with `***REDACTED***`).

### Module Isolation

Modules communicate exclusively via typed channels. No shared mutable state exists between modules, preventing data races and ensuring that a panic in one module does not directly corrupt another module's state. However, a panic in a module will still propagate to the orchestrator and crash the daemon.

## Troubleshooting

### Daemon Won't Start

1. **PID file already exists**
   ```
   PID file /var/run/ironpost/ironpost.pid already exists with PID: 1234. Is another instance running?
   ```
   - Check if the process is running: `ps -p 1234`
   - If not running, remove the stale PID file: `sudo rm /var/run/ironpost/ironpost.pid`

2. **Configuration validation failed**
   ```
   configuration validation failed: invalid log_level 'verbose'
   ```
   - Run `ironpost-daemon --validate` to see detailed errors
   - Check valid values in the config documentation

3. **Module initialization failed**
   ```
   failed to build eBPF engine: permission denied
   ```
   - Ensure the daemon is running as root or with `CAP_NET_ADMIN`
   - Check kernel version: `uname -r` (requires 5.10+)

### High Memory Usage

- Check buffer sizes in config:
  - `log_pipeline.buffer_capacity` (default 10000)
  - `sbom.scan_dirs` (large directories increase memory usage)
- Monitor per-module health: `ironpost-cli status`

### Module Not Starting

- Check if the module is enabled in config: `ironpost-cli config show`
- Review daemon logs for initialization errors
- Verify dependencies (e.g., Docker socket for container-guard)

### Shutdown Hangs

- Modules may be waiting for channels to drain
- Increase shutdown timeout (default 30s) - currently not configurable
- Check for stuck background tasks (future: add timeout to `stop_all()`)

## Performance

### Channel Capacities

The orchestrator configures bounded channels with fixed capacities:

- `PACKET_CHANNEL_CAPACITY = 1024` (eBPF → Log Pipeline)
- `ALERT_CHANNEL_CAPACITY = 256` (Log Pipeline/SBOM → Container Guard)

If a producer sends faster than the consumer can process, the send operation will block until capacity is available. This provides backpressure and prevents unbounded memory growth.

### Module Start/Stop Time

Typical startup times:

- eBPF Engine: ~100-300ms (loading BPF programs)
- Log Pipeline: ~50-100ms (loading rules)
- Container Guard: ~50-100ms (Docker connection)
- SBOM Scanner: ~10-50ms (config validation)

Total startup time: **<500ms** for all modules.

## License

See the root [LICENSE](../LICENSE) file for licensing information.

## Contributing

See the root [CONTRIBUTING.md](../CONTRIBUTING.md) for contribution guidelines.

## Changelog

See [CHANGELOG.md](../CHANGELOG.md) for version history and release notes.

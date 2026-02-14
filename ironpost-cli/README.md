# ironpost-cli

Command-line interface for managing the Ironpost security monitoring platform.

## Overview

`ironpost-cli` is the primary user interface for Ironpost, providing a unified command-line tool to:

- Start and manage the `ironpost-daemon` process (foreground or background mode)
- Query module status and health information
- Validate and display configuration files
- Manage detection rules (list, validate)
- Run one-shot SBOM vulnerability scans

All subcommands support both human-readable text output (with colors) and machine-readable JSON output for scripting and automation.

### Key Features

- **Daemon Management**: Start daemon in foreground or background mode with PID file management
- **Health Monitoring**: Check status of all enabled modules (eBPF, log-pipeline, container-guard, SBOM scanner)
- **Configuration Management**: Validate and display effective configuration (with environment variable overrides)
- **Rule Management**: List and validate detection rules for the log-pipeline module
- **SBOM Scanning**: Execute one-shot vulnerability scans on project directories
- **Flexible Output**: Text (colored, human-readable) or JSON (machine-readable) formats
- **Credential Redaction**: Automatically masks sensitive credentials in configuration output

## Architecture

### Component Structure

```text
ironpost-cli
    |
    +-- cli.rs          # Clap command-line argument parsing
    |
    +-- main.rs         # Entry point, tracing setup, exit code handling
    |
    +-- error.rs        # CliError type with exit code mapping
    |
    +-- output.rs       # OutputWriter abstraction (Text/JSON)
    |
    +-- commands/
         |
         +-- start.rs   # Start daemon (foreground / background)
         +-- status.rs  # Query module health
         +-- scan.rs    # One-shot SBOM scan
         +-- rules.rs   # List / validate detection rules
         +-- config.rs  # Validate / show configuration
```

### Command Flow

```text
User Input
    |
    v
Clap Parser (cli.rs)
    |
    v
main.rs::run() dispatcher
    |
    v
Subcommand Handler (commands/*)
    |
    +-- Load IronpostConfig (from config_path)
    |
    +-- Execute domain logic
    |       |
    |       +-- start: Spawn ironpost-daemon process
    |       +-- status: Read PID file, check process liveness
    |       +-- scan: Build SbomScanner, run scan_once()
    |       +-- rules: Load rules via RuleLoader
    |       +-- config: Validate/display config with redaction
    |
    v
Build Report Struct (Serialize + Render)
    |
    v
OutputWriter::render()
    |
    +-- Text: Render::render_text() (colored output)
    +-- JSON: serde_json::to_writer_pretty()
    |
    v
stdout (data) / stderr (logs)
    |
    v
Exit code (0 = success, 1-10 = specific errors)
```

## Commands

### `ironpost start` — Start Daemon

Start the Ironpost daemon in foreground or background mode.

```bash
# Foreground mode (replaces current process via exec)
ironpost start

# Background mode (detached process)
ironpost start --daemonize

# Custom PID file location
ironpost start -d --pid-file /tmp/ironpost.pid

# Custom config file
ironpost --config /etc/ironpost.toml start -d
```

**Options:**
- `-d, --daemonize`: Run as background daemon (default: foreground)
- `--pid-file <PATH>`: Override PID file location (daemon mode only)

**Behavior:**
- Foreground: Executes `ironpost-daemon` via `exec(2)`, replacing the CLI process
- Background: Spawns `ironpost-daemon` as detached child, verifies startup (200ms check)
- Exit codes:
  - `0`: Daemon started successfully
  - `1`: Execution failed or daemon crashed immediately
  - `2`: Configuration file not found

### `ironpost status` — Query Module Status

Display health status and runtime information for all enabled modules.

```bash
# Basic status
ironpost status

# Verbose mode (show per-module configuration details)
ironpost status --verbose

# JSON output
ironpost --output json status
```

**Options:**
- `-v, --verbose`: Show detailed per-module configuration

**Output Fields:**
- `daemon_running`: Boolean (based on PID file and process liveness check)
- `uptime_secs`: Daemon uptime in seconds (or `null` if unavailable)
- `modules`: Array of enabled module statuses:
  - `name`: Module identifier (ebpf-engine, log-pipeline, container-guard, sbom-scanner)
  - `enabled`: Boolean from configuration
  - `health`: "running" | "stopped" | "degraded"
  - `details`: Optional verbose configuration details (e.g., "interface=eth0, mode=native")

**Example Output (Text):**

```text
Daemon: running (uptime: 3600s)

Module               Enabled    Health
------------------------------------------------------------
ebpf-engine          yes        running
  interface=eth0, mode=native
log-pipeline         yes        running
  sources=file,syslog_udp, batch_size=100
container-guard      yes        running
  auto_isolate=true, poll_interval=10s
sbom-scanner         yes        running
  min_severity=medium, format=cyclonedx
```

**Example Output (JSON):**

```json
{
  "daemon_running": true,
  "uptime_secs": 3600,
  "modules": [
    {
      "name": "ebpf-engine",
      "enabled": true,
      "health": "running",
      "details": "interface=eth0, mode=native"
    }
  ]
}
```

### `ironpost scan` — SBOM Vulnerability Scan

Run a one-shot SBOM generation and CVE vulnerability scan on a project directory.

```bash
# Scan current directory
ironpost scan

# Scan specific path
ironpost scan /path/to/project

# Filter by minimum severity
ironpost scan --min-severity critical

# Choose SBOM output format
ironpost scan --sbom-format spdx

# JSON output for CI/CD pipelines
ironpost --output json scan . > scan-results.json
```

**Options:**
- `<PATH>`: Directory to scan (default: current directory `.`)
- `--min-severity <LEVEL>`: Minimum severity to report (default: `medium`)
  - Valid levels: `info`, `low`, `medium`, `high`, `critical`
- `--sbom-format <FORMAT>`: SBOM output format (default: `cyclonedx`)
  - Valid formats: `cyclonedx`, `spdx`

**Exit Codes:**
- `0`: Scan completed with no vulnerabilities
- `4`: Scan completed but vulnerabilities found
- `2`: Configuration error
- `1`: Scan execution failed

**Output Fields:**
- `path`: Scanned directory path
- `lockfiles_scanned`: Number of lockfiles found (Cargo.lock, package-lock.json)
- `total_packages`: Total dependency count across all lockfiles
- `vulnerabilities`: Severity breakdown (`critical`, `high`, `medium`, `low`, `info`, `total`)
- `findings`: Array of CVE findings:
  - `cve_id`: CVE identifier (e.g., "CVE-2024-1234")
  - `package`: Package name
  - `version`: Installed version
  - `severity`: Vulnerability severity level
  - `fixed_version`: Patched version (or `null` if no fix available)
  - `description`: CVE description text

**Example Output (Text):**

```text
Scan: /home/user/project
Lockfiles scanned: 2
Total packages: 145

Vulnerabilities: 3 total (C:1 H:2 M:0 L:0 I:0)

CVE                Severity   Package                   Version      Fixed
--------------------------------------------------------------------------------
CVE-2024-1234      Critical   vulnerable-crate          1.0.0        1.0.1
CVE-2024-5678      High       another-package           2.3.0        N/A
CVE-2024-9999      High       old-dependency            0.5.0        1.0.0
```

**Example Output (JSON):**

```json
{
  "path": "/home/user/project",
  "lockfiles_scanned": 2,
  "total_packages": 145,
  "vulnerabilities": {
    "critical": 1,
    "high": 2,
    "medium": 0,
    "low": 0,
    "info": 0,
    "total": 3
  },
  "findings": [
    {
      "cve_id": "CVE-2024-1234",
      "package": "vulnerable-crate",
      "version": "1.0.0",
      "severity": "Critical",
      "fixed_version": "1.0.1",
      "description": "Remote code execution vulnerability..."
    }
  ]
}
```

### `ironpost rules` — Manage Detection Rules

List and validate detection rules for the log-pipeline module.

#### `rules list` — List Loaded Rules

```bash
# List all rules
ironpost rules list

# Filter by status
ironpost rules list --status enabled
ironpost rules list --status disabled
ironpost rules list --status test

# JSON output
ironpost --output json rules list > rules-inventory.json
```

**Options:**
- `--status <STATUS>`: Filter by rule status (`enabled`, `disabled`, `test`)

**Output Fields:**
- `total`: Total number of rules (after filtering)
- `rules`: Array of rule entries:
  - `id`: Unique rule identifier
  - `title`: Human-readable rule title
  - `severity`: Detection severity level
  - `status`: Rule status (`enabled`, `disabled`, `test`)
  - `tags`: Array of tags (e.g., `["authentication", "brute-force"]`)

**Example Output (Text):**

```text
Detection Rules (5 total)

ID                       Title                          Severity   Status     Tags
------------------------------------------------------------------------------------------
rule-ssh-bruteforce      SSH Brute Force Attempt        High       enabled    ssh, auth
rule-sql-injection       SQL Injection Pattern          Critical   enabled    sqli, web
rule-port-scan-detect    Port Scan Detection            Medium     enabled    network
rule-test-experimental   Experimental Detection         Low        test       experimental
rule-deprecated          Deprecated Old Rule            Medium     disabled   deprecated
```

#### `rules validate` — Validate Rule Files

Validate YAML rule files without loading them into the engine.

```bash
# Validate rules in default directory
ironpost rules validate

# Validate rules in custom directory
ironpost rules validate /path/to/rules

# JSON output with detailed errors
ironpost --output json rules validate > validation-report.json
```

**Options:**
- `<PATH>`: Directory containing YAML rule files (default: `/etc/ironpost/rules`)

**Exit Codes:**
- `0`: All rules are valid
- `1`: One or more rules are invalid
- `2`: Configuration error

**Output Fields:**
- `path`: Rules directory path
- `total_files`: Total number of rule files processed
- `valid`: Count of valid rules
- `invalid`: Count of invalid rules
- `errors`: Array of validation errors:
  - `file`: Rule filename
  - `error`: Error message

**Example Output (Text):**

```text
Rule Validation: /etc/ironpost/rules
  Files: 10, 8 valid, 2 invalid

Errors:
  broken-rule.yaml: missing required field: title
  malformed.yaml: YAML parse error: invalid syntax at line 5
```

### `ironpost config` — Manage Configuration

Validate and display effective configuration with environment variable overrides.

#### `config validate` — Validate Configuration

```bash
# Validate default config file (ironpost.toml)
ironpost config validate

# Validate custom config file
ironpost --config /etc/ironpost-prod.toml config validate
```

**Exit Codes:**
- `0`: Configuration is valid
- `2`: Configuration is invalid

**Output Fields:**
- `source`: Configuration file path
- `valid`: Boolean validation result
- `errors`: Array of error messages (empty if valid)

**Example Output (Text):**

```text
Config Validation: ironpost.toml
  Result: VALID
```

**Example Output (Invalid):**

```text
Config Validation: bad-config.toml
  Result: INVALID
  Error: missing required field: interface
  Error: invalid port number: -1
```

#### `config show` — Display Effective Configuration

Display the effective configuration after merging file, environment variables, and defaults.

```bash
# Show full configuration
ironpost config show

# Show specific section only
ironpost config show --section ebpf
ironpost config show --section log_pipeline
ironpost config show --section container
ironpost config show --section sbom
ironpost config show --section general

# JSON output (useful for config management tools)
ironpost --output json config show > current-config.json
```

**Options:**
- `--section <NAME>`: Show only a specific configuration section
  - Valid sections: `general`, `ebpf`, `log_pipeline`, `container`, `sbom`

**Security:**
- **Credential Redaction**: Database URLs and Redis connection strings are automatically redacted
  - Example: `postgresql://user:password@localhost:5432/db` → `postgresql://***REDACTED***@localhost:5432/db`

**Example Output (Text):**

```toml
Configuration (source: ironpost.toml)

[general]
log_level = "info"
pid_file = "/var/run/ironpost/ironpost.pid"

[ebpf]
enabled = true
interface = "eth0"
xdp_mode = "native"

[log_pipeline]
enabled = true
sources = ["file", "syslog_udp"]
batch_size = 100

[log_pipeline.storage]
postgres_url = "postgresql://***REDACTED***@localhost:5432/ironpost"
redis_url = "redis://***REDACTED***@localhost:6379"

[container]
enabled = true
auto_isolate = true
poll_interval_secs = 10

[sbom]
enabled = true
min_severity = "medium"
output_format = "cyclonedx"
```

## Global Options

These options apply to all subcommands and must be specified **before** the subcommand name.

```bash
ironpost [GLOBAL OPTIONS] <COMMAND> [COMMAND OPTIONS]
```

### `-c, --config <PATH>` — Configuration File

Specify a custom configuration file path.

```bash
ironpost --config /etc/ironpost-prod.toml status
ironpost -c ./local-config.toml start
```

**Default:** `ironpost.toml` (current directory)

### `--log-level <LEVEL>` — Override Log Level

Override the log level for CLI operations (stderr output only, does not affect daemon).

```bash
ironpost --log-level debug status
ironpost --log-level trace scan .
```

**Valid Levels:** `trace`, `debug`, `info`, `warn`, `error`

**Default:** `warn` (only warnings and errors shown)

### `--output <FORMAT>` — Output Format

Choose output format for all subcommands.

```bash
# Human-readable colored text (default)
ironpost status

# Machine-readable JSON
ironpost --output json status

# JSON for scripting
ironpost --output json scan . | jq '.vulnerabilities.total'
```

**Valid Formats:**
- `text`: Human-readable, colored terminal output (default)
- `json`: Pretty-printed JSON (suitable for piping to `jq`, parsing in scripts)

## Exit Codes

`ironpost-cli` uses standardized exit codes for reliable scripting and CI/CD integration.

| Code | Meaning | Example |
|------|---------|---------|
| `0` | Success | Command completed successfully |
| `1` | General command error | Daemon failed to start, rule validation syntax error |
| `2` | Configuration error | Config file not found, invalid TOML syntax, missing required fields |
| `3` | Daemon unavailable | Cannot connect to daemon (reserved for future health API) |
| `4` | Scan found vulnerabilities | `scan` command completed but CVEs were detected |
| `10` | I/O error | Cannot write to stdout, file read error |

**CI/CD Usage Example:**

```bash
#!/bin/bash
# Exit on scan failure (exit code 4) or errors (1, 2, 10)
ironpost --output json scan . > scan-report.json
exit_code=$?

if [ $exit_code -eq 4 ]; then
    echo "❌ Vulnerabilities found, failing build"
    exit 1
elif [ $exit_code -ne 0 ]; then
    echo "❌ Scan execution failed"
    exit $exit_code
else
    echo "✅ No vulnerabilities detected"
fi
```

## Configuration Integration

`ironpost-cli` reads the same `ironpost.toml` configuration file used by `ironpost-daemon`, ensuring consistency between CLI operations and daemon behavior.

### Configuration Precedence

1. **CLI Arguments** (highest priority)
   - Example: `ironpost scan /custom/path --min-severity critical`
2. **Environment Variables**
   - Format: `IRONPOST_<SECTION>_<KEY>=value`
   - Example: `IRONPOST_EBPF_INTERFACE=eth1`
3. **Configuration File** (`ironpost.toml`)
4. **Default Values** (lowest priority, defined in code)

### Relevant Configuration Sections

```toml
[general]
log_level = "info"              # Logging verbosity
pid_file = "/var/run/ironpost/ironpost.pid"  # Daemon PID file location

[ebpf]
enabled = true                  # Enable eBPF module
interface = "eth0"              # Network interface to monitor
xdp_mode = "native"             # XDP mode (native/generic)

[log_pipeline]
enabled = true                  # Enable log pipeline
sources = ["file", "syslog_udp"]  # Log sources
batch_size = 100                # Batch processing size
rules_dir = "/etc/ironpost/rules"  # Detection rules directory

[log_pipeline.storage]
postgres_url = "postgresql://user:password@localhost:5432/ironpost"
redis_url = "redis://localhost:6379"

[container]
enabled = true                  # Enable container guard
auto_isolate = true             # Automatic container isolation
poll_interval_secs = 10         # Container polling interval

[sbom]
enabled = true                  # Enable SBOM scanner
scan_dirs = ["/app"]            # Directories to scan
min_severity = "medium"         # Minimum CVE severity
output_format = "cyclonedx"     # SBOM format
vuln_db_path = "/var/lib/ironpost/vuln-db"  # CVE database location
```

See the root `README.md` and `docs/configuration.md` (planned) for complete configuration reference.

## Usage Examples

### Daily Operations

```bash
# Start daemon in background with custom config
ironpost -c /etc/ironpost.toml start --daemonize

# Check if all modules are running
ironpost status --verbose

# List all enabled detection rules
ironpost rules list --status enabled

# Validate configuration after editing
ironpost config validate
```

### CI/CD Pipeline

```bash
# Install ironpost in CI container
apt-get install -y ironpost

# Run vulnerability scan on project
ironpost --output json scan . > scan-results.json

# Parse results with jq
CRITICAL=$(jq '.vulnerabilities.critical' scan-results.json)
if [ "$CRITICAL" -gt 0 ]; then
    echo "❌ Critical vulnerabilities found, failing build"
    exit 1
fi

# Upload results as CI artifact
cp scan-results.json "$CI_ARTIFACTS_DIR/"
```

### Development Workflow

```bash
# Validate rules before deployment
ironpost rules validate ./new-rules/

# Test rule changes with temporary config
IRONPOST_LOG_PIPELINE_RULES_DIR=./new-rules ironpost config show --section log_pipeline

# Run daemon in foreground for debugging
ironpost --log-level debug start

# Monitor status in another terminal
watch -n 1 ironpost status
```

### Security Audit

```bash
# Generate comprehensive security report
{
    echo "=== System Status ==="
    ironpost --output json status

    echo "=== Active Rules ==="
    ironpost --output json rules list --status enabled

    echo "=== Vulnerability Scan ==="
    ironpost --output json scan /app

    echo "=== Configuration ==="
    ironpost --output json config show
} > security-audit-$(date +%Y%m%d).json
```

## Error Handling

`ironpost-cli` follows Rust best practices for error handling:

- **Library Crates** (`ironpost-core`, `ironpost-sbom-scanner`, etc.): Return `Result<T, DomainError>` with structured error types
- **CLI Binary**: Converts all errors to `CliError` with user-friendly messages and appropriate exit codes

### Error Categories

```rust
pub enum CliError {
    Config(String),         // Exit code 2: Configuration errors
    Command(String),        // Exit code 1: Command execution errors
    DaemonUnavailable(String),  // Exit code 3: Cannot reach daemon (future)
    JsonSerialize(Error),   // Exit code 1: JSON output error
    Io(std::io::Error),     // Exit code 10: File I/O error
    Core(IronpostError),    // Exit code 1: Domain errors from core crate
    Scan(String),           // Exit code 4: Vulnerabilities found
    Rule(String),           // Exit code 1: Rule validation/loading error
}
```

All errors are logged to **stderr** using `tracing`, while command output goes to **stdout**. This separation enables safe piping:

```bash
# Errors go to terminal, output to file
ironpost scan . > results.json 2>&1 | tee scan.log

# Only errors
ironpost status 2> errors.log

# Only output
ironpost --output json status > status.json 2>/dev/null
```

## Logging

The CLI uses `tracing` for structured logging with compact formatting suitable for interactive terminal use:

- **Default Level**: `warn` (only warnings and errors)
- **Override**: `--log-level <LEVEL>` global option or `RUST_LOG` environment variable
- **Output**: stderr (does not interfere with command output on stdout)

```bash
# Detailed debug logging
ironpost --log-level debug start

# Trace-level logging for troubleshooting
RUST_LOG=trace ironpost scan .

# Suppress all logs
ironpost --log-level error status
```

**Important:** The CLI log level only affects the CLI itself, not the daemon. To change daemon logging, modify the `log_level` setting in `ironpost.toml`.

## Related Crates

- [`ironpost-daemon`](../ironpost-daemon/README.md): Main daemon process that orchestrates all modules
- [`ironpost-core`](../crates/core/README.md): Shared types, traits, and configuration
- [`ironpost-ebpf-engine`](../crates/ebpf-engine/README.md): eBPF-based network packet filtering
- [`ironpost-log-pipeline`](../crates/log-pipeline/README.md): Log parsing and detection rule engine
- [`ironpost-container-guard`](../crates/container-guard/README.md): Container isolation enforcement
- [`ironpost-sbom-scanner`](../crates/sbom-scanner/README.md): SBOM generation and CVE scanning

## Development

### Building

```bash
# Build CLI binary
cargo build -p ironpost-cli --release

# Install locally
cargo install --path ironpost-cli

# Run without installing
cargo run -p ironpost-cli -- status
```

### Testing

```bash
# Run all CLI tests
cargo test -p ironpost-cli

# Test specific module
cargo test -p ironpost-cli commands::status

# Run with output
cargo test -p ironpost-cli -- --nocapture

# Check test coverage
cargo tarpaulin -p ironpost-cli
```

### Code Quality

```bash
# Format code
cargo fmt -p ironpost-cli

# Lint (must pass with zero warnings)
cargo clippy -p ironpost-cli -- -D warnings

# Check documentation
cargo doc -p ironpost-cli --no-deps --open
```

## License

This project is dual-licensed under MIT and Apache 2.0. See [LICENSE-MIT](../LICENSE-MIT) and [LICENSE-APACHE](../LICENSE-APACHE) for details.

## Contributing

Contributions are welcome. Please see [CONTRIBUTING.md](../CONTRIBUTING.md) for guidelines.

When adding new commands or modifying existing ones:

1. Update the `cli.rs` clap definitions
2. Add/modify handler in `commands/` module
3. Implement both `Serialize` (for JSON) and `Render` (for text) traits on output types
4. Add comprehensive tests covering success and error cases
5. Update this README with usage examples
6. Maintain exit code consistency

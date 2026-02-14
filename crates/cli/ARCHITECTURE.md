# ironpost-cli Subcommand Architecture

## 1. Module Structure

The CLI is a binary crate located at `ironpost-cli/`. The source tree is organized
by concern: argument parsing, subcommand execution, output formatting, and shared utilities.

```
ironpost-cli/
  Cargo.toml
  src/
    main.rs              -- entry point: parse args, init tracing, dispatch
    cli.rs               -- Cli + Commands + per-subcommand arg structs (clap derive)
    output.rs            -- OutputFormat enum, OutputWriter trait, text/JSON renderers
    error.rs             -- CliError enum, exit code mapping
    commands/
      mod.rs             -- re-exports
      start.rs           -- `ironpost start` handler
      status.rs          -- `ironpost status` handler
      scan.rs            -- `ironpost scan [path]` handler
      rules.rs           -- `ironpost rules [list|validate]` handler
      config.rs          -- `ironpost config [validate|show]` handler
```

### Rationale

- **cli.rs** is purely declarative (clap structs). No IO, no logic.
- **commands/** contains one file per subcommand. Each file exposes a single
  `pub async fn execute(args, global) -> Result<(), CliError>` function.
- **output.rs** centralises text-vs-JSON rendering so subcommands do not
  contain format-specific branches.
- **error.rs** maps domain errors to process exit codes in one place.

---

## 2. Clap Derive Structs

### 2.1 Top-level Cli

```rust
use std::path::PathBuf;
use clap::{Parser, Subcommand, ValueEnum};

/// Ironpost -- integrated security monitoring platform.
///
/// Use `ironpost <COMMAND> --help` for subcommand details.
#[derive(Parser, Debug)]
#[command(name = "ironpost", version, about, long_about = None)]
pub struct Cli {
    /// Path to the ironpost.toml configuration file.
    #[arg(short, long, default_value = "ironpost.toml")]
    pub config: PathBuf,

    /// Override log level (trace, debug, info, warn, error).
    #[arg(long, global = true)]
    pub log_level: Option<String>,

    /// Output format.
    #[arg(long, global = true, default_value = "text")]
    pub output: OutputFormat,

    #[command(subcommand)]
    pub command: Commands,
}

/// Supported output formats.
#[derive(Debug, Clone, Copy, ValueEnum)]
pub enum OutputFormat {
    /// Human-readable table / text output.
    Text,
    /// Machine-readable JSON.
    Json,
}
```

### 2.2 Commands Enum

```rust
#[derive(Subcommand, Debug)]
pub enum Commands {
    /// Start the ironpost daemon.
    Start(StartArgs),

    /// Check status of each module.
    Status(StatusArgs),

    /// Run a one-shot SBOM vulnerability scan.
    Scan(ScanArgs),

    /// Manage detection rules.
    Rules(RulesArgs),

    /// Manage configuration.
    Config(ConfigArgs),
}
```

### 2.3 Per-Subcommand Args

```rust
use clap::{Args, Subcommand};

// ---- start ----

/// Start the ironpost daemon.
#[derive(Args, Debug)]
pub struct StartArgs {
    /// Run as a background daemon (default: foreground).
    #[arg(short = 'd', long)]
    pub daemonize: bool,

    /// Override PID file location (daemon mode only).
    #[arg(long)]
    pub pid_file: Option<PathBuf>,
}

// ---- status ----

/// Display module health and uptime.
#[derive(Args, Debug)]
pub struct StatusArgs {
    /// Show detailed per-module metrics.
    #[arg(short, long)]
    pub verbose: bool,
}

// ---- scan ----

/// Run a one-shot SBOM scan on a project directory.
#[derive(Args, Debug)]
pub struct ScanArgs {
    /// Path to scan (default: current directory).
    #[arg(default_value = ".")]
    pub path: PathBuf,

    /// Minimum severity to report (info, low, medium, high, critical).
    #[arg(long, default_value = "medium")]
    pub min_severity: String,

    /// SBOM output format (cyclonedx, spdx).
    #[arg(long, default_value = "cyclonedx")]
    pub sbom_format: String,
}

// ---- rules ----

/// Manage detection rules.
#[derive(Args, Debug)]
pub struct RulesArgs {
    #[command(subcommand)]
    pub action: RulesAction,
}

#[derive(Subcommand, Debug)]
pub enum RulesAction {
    /// List all loaded detection rules.
    List {
        /// Filter by status (enabled, disabled, test).
        #[arg(long)]
        status: Option<String>,
    },
    /// Validate rule files without loading them into the engine.
    Validate {
        /// Directory containing YAML rule files.
        #[arg(default_value = "/etc/ironpost/rules")]
        path: PathBuf,
    },
}

// ---- config ----

/// Manage ironpost configuration.
#[derive(Args, Debug)]
pub struct ConfigArgs {
    #[command(subcommand)]
    pub action: ConfigAction,
}

#[derive(Subcommand, Debug)]
pub enum ConfigAction {
    /// Validate the configuration file and report errors.
    Validate,
    /// Show the effective configuration (file + env overrides + defaults).
    Show {
        /// Show only a specific section (general, ebpf, log_pipeline, container, sbom).
        #[arg(long)]
        section: Option<String>,
    },
}
```

---

## 3. Output Trait -- Text vs JSON Rendering

All subcommand output flows through a single `OutputWriter` that the `main.rs`
dispatch function constructs from the global `--output` flag. This keeps
format-specific logic out of the command handlers entirely.

### 3.1 Core Trait

```rust
// output.rs

use std::io::Write;
use serde::Serialize;

/// Abstraction for writing CLI output in different formats.
///
/// Subcommand handlers call `writer.render(&payload)` where `payload`
/// implements both `Serialize` (for JSON) and `Render` (for text).
pub struct OutputWriter {
    format: OutputFormat,
}

impl OutputWriter {
    pub fn new(format: OutputFormat) -> Self {
        Self { format }
    }

    /// Render a payload to stdout.
    ///
    /// For `Text` format, delegates to `Render::render_text()`.
    /// For `Json` format, serialises via `serde_json`.
    pub fn render<T: Render + Serialize>(&self, payload: &T) -> Result<(), CliError> {
        let stdout = std::io::stdout();
        let mut handle = stdout.lock();
        match self.format {
            OutputFormat::Text => {
                payload.render_text(&mut handle)?;
            }
            OutputFormat::Json => {
                serde_json::to_writer_pretty(&mut handle, payload)
                    .map_err(CliError::JsonSerialize)?;
                writeln!(handle).map_err(CliError::Io)?;
            }
        }
        Ok(())
    }
}

/// Trait for human-readable text rendering.
///
/// Implemented by every CLI output payload alongside `serde::Serialize`.
pub trait Render {
    fn render_text(&self, w: &mut dyn Write) -> std::io::Result<()>;
}
```

### 3.2 Output Payload Examples

Each subcommand defines a payload struct that serves as the single source of truth
for both text and JSON representations.

```rust
// commands/status.rs -- output payload

use serde::Serialize;

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
    pub health: String,  // "healthy" | "degraded: ..." | "unhealthy: ..."
}

impl Render for StatusReport {
    fn render_text(&self, w: &mut dyn Write) -> std::io::Result<()> {
        if self.daemon_running {
            writeln!(w, "Daemon: running (uptime: {}s)",
                     self.uptime_secs.unwrap_or(0))?;
        } else {
            writeln!(w, "Daemon: not running")?;
        }
        writeln!(w)?;
        writeln!(w, "{:<20} {:<10} {}", "Module", "Enabled", "Health")?;
        writeln!(w, "{}", "-".repeat(60))?;
        for m in &self.modules {
            writeln!(w, "{:<20} {:<10} {}",
                     m.name,
                     if m.enabled { "yes" } else { "no" },
                     m.health)?;
        }
        Ok(())
    }
}
```

```rust
// commands/scan.rs -- output payload

use serde::Serialize;

#[derive(Serialize)]
pub struct ScanReport {
    pub path: String,
    pub lockfiles_scanned: usize,
    pub total_packages: usize,
    pub vulnerabilities: VulnSummary,
    pub findings: Vec<FindingEntry>,
}

#[derive(Serialize)]
pub struct VulnSummary {
    pub critical: usize,
    pub high: usize,
    pub medium: usize,
    pub low: usize,
    pub info: usize,
    pub total: usize,
}

#[derive(Serialize)]
pub struct FindingEntry {
    pub cve_id: String,
    pub package: String,
    pub version: String,
    pub severity: String,
    pub fixed_version: Option<String>,
    pub description: String,
}

impl Render for ScanReport {
    fn render_text(&self, w: &mut dyn Write) -> std::io::Result<()> {
        writeln!(w, "Scan: {}", self.path)?;
        writeln!(w, "Lockfiles scanned: {}", self.lockfiles_scanned)?;
        writeln!(w, "Total packages: {}", self.total_packages)?;
        writeln!(w)?;
        writeln!(w, "Vulnerabilities: {} total (C:{} H:{} M:{} L:{} I:{})",
                 self.vulnerabilities.total,
                 self.vulnerabilities.critical,
                 self.vulnerabilities.high,
                 self.vulnerabilities.medium,
                 self.vulnerabilities.low,
                 self.vulnerabilities.info)?;
        writeln!(w)?;
        if self.findings.is_empty() {
            writeln!(w, "No vulnerabilities found.")?;
        } else {
            writeln!(w, "{:<18} {:<8} {:<25} {:<12} {}",
                     "CVE", "Severity", "Package", "Version", "Fixed")?;
            writeln!(w, "{}", "-".repeat(80))?;
            for f in &self.findings {
                writeln!(w, "{:<18} {:<8} {:<25} {:<12} {}",
                         f.cve_id,
                         f.severity,
                         f.package,
                         f.version,
                         f.fixed_version.as_deref().unwrap_or("N/A"))?;
            }
        }
        Ok(())
    }
}
```

```rust
// commands/rules.rs -- output payload

use serde::Serialize;

#[derive(Serialize)]
pub struct RuleListReport {
    pub total: usize,
    pub rules: Vec<RuleEntry>,
}

#[derive(Serialize)]
pub struct RuleEntry {
    pub id: String,
    pub title: String,
    pub severity: String,
    pub status: String,
    pub tags: Vec<String>,
}

impl Render for RuleListReport {
    fn render_text(&self, w: &mut dyn Write) -> std::io::Result<()> {
        writeln!(w, "Detection Rules ({} total)", self.total)?;
        writeln!(w)?;
        writeln!(w, "{:<25} {:<30} {:<10} {:<10} {}",
                 "ID", "Title", "Severity", "Status", "Tags")?;
        writeln!(w, "{}", "-".repeat(90))?;
        for r in &self.rules {
            writeln!(w, "{:<25} {:<30} {:<10} {:<10} {}",
                     r.id, r.title, r.severity, r.status,
                     r.tags.join(", "))?;
        }
        Ok(())
    }
}

#[derive(Serialize)]
pub struct RuleValidationReport {
    pub path: String,
    pub total_files: usize,
    pub valid: usize,
    pub invalid: usize,
    pub errors: Vec<RuleError>,
}

#[derive(Serialize)]
pub struct RuleError {
    pub file: String,
    pub error: String,
}

impl Render for RuleValidationReport {
    fn render_text(&self, w: &mut dyn Write) -> std::io::Result<()> {
        writeln!(w, "Rule Validation: {}", self.path)?;
        writeln!(w, "  Files: {} total, {} valid, {} invalid",
                 self.total_files, self.valid, self.invalid)?;
        if !self.errors.is_empty() {
            writeln!(w)?;
            writeln!(w, "Errors:")?;
            for e in &self.errors {
                writeln!(w, "  {}: {}", e.file, e.error)?;
            }
        }
        Ok(())
    }
}
```

```rust
// commands/config.rs -- output payload

use serde::Serialize;

#[derive(Serialize)]
pub struct ConfigReport {
    pub source: String,
    pub config: ironpost_core::config::IronpostConfig,
}

impl Render for ConfigReport {
    fn render_text(&self, w: &mut dyn Write) -> std::io::Result<()> {
        writeln!(w, "Configuration (source: {})", self.source)?;
        writeln!(w)?;
        // Serialize to TOML for human-readable text output
        let toml_str = toml::to_string_pretty(&self.config)
            .unwrap_or_else(|e| format!("(serialization error: {})", e));
        write!(w, "{}", toml_str)?;
        Ok(())
    }
}

#[derive(Serialize)]
pub struct ConfigValidationReport {
    pub source: String,
    pub valid: bool,
    pub errors: Vec<String>,
}

impl Render for ConfigValidationReport {
    fn render_text(&self, w: &mut dyn Write) -> std::io::Result<()> {
        writeln!(w, "Config Validation: {}", self.source)?;
        if self.valid {
            writeln!(w, "  Result: VALID")?;
        } else {
            writeln!(w, "  Result: INVALID")?;
            for err in &self.errors {
                writeln!(w, "  Error: {}", err)?;
            }
        }
        Ok(())
    }
}
```

---

## 4. Error Handling -- From Subcommands to Exit Codes

### 4.1 CliError Enum

```rust
// error.rs

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
    DaemonUnavailable(String),

    /// JSON serialisation failed during output rendering.
    #[error("json output error: {0}")]
    JsonSerialize(#[from] serde_json::Error),

    /// IO error (file read, stdout write, etc.).
    #[error("io error: {0}")]
    Io(#[from] std::io::Error),

    /// Wrapped domain error from ironpost-core.
    #[error("{0}")]
    Core(#[from] ironpost_core::error::IronpostError),

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
```

### 4.2 Conversion from Domain Errors

```rust
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
```

### 4.3 main.rs Error Flow

```rust
// main.rs

use clap::Parser;

mod cli;
mod commands;
mod error;
mod output;

use cli::{Cli, Commands};
use error::CliError;
use output::OutputWriter;

#[tokio::main]
async fn main() {
    let cli = Cli::parse();

    // Initialize tracing with minimal subscriber for CLI
    // (structured JSON would be noisy for interactive use)
    let log_level = cli.log_level.as_deref().unwrap_or("warn");
    tracing_subscriber::fmt()
        .with_env_filter(log_level)
        .with_writer(std::io::stderr)   // logs go to stderr, output to stdout
        .init();

    let writer = OutputWriter::new(cli.output);

    let result = run(cli, &writer).await;

    match result {
        Ok(()) => std::process::exit(0),
        Err(e) => {
            // Errors rendered to stderr via tracing
            tracing::error!(error = %e, "command failed");
            std::process::exit(e.exit_code());
        }
    }
}

async fn run(cli: Cli, writer: &OutputWriter) -> Result<(), CliError> {
    match cli.command {
        Commands::Start(args)  => commands::start::execute(args, &cli.config).await,
        Commands::Status(args) => commands::status::execute(args, &cli.config, writer).await,
        Commands::Scan(args)   => commands::scan::execute(args, &cli.config, writer).await,
        Commands::Rules(args)  => commands::rules::execute(args, &cli.config, writer).await,
        Commands::Config(args) => commands::config::execute(args, &cli.config, writer).await,
    }
}
```

Key design decisions:

1. **Logs to stderr, output to stdout.** This allows piping JSON output to
   `jq` without tracing noise interfering.
2. **Non-zero exit codes** for CI integration: a scan that finds
   vulnerabilities returns exit code 4, which `set -e` scripts can catch.
3. **No `unwrap()` or `anyhow`** inside subcommand handlers. Each handler
   returns `Result<(), CliError>`, and `main()` converts the typed error
   to an exit code.

---

## 5. Module Interaction -- How CLI Calls Into Other Crates

### 5.1 Dependency Direction

```
ironpost-cli
  |-- ironpost-core           (config, error types, domain types)
  |-- ironpost-sbom-scanner   (SbomScanner, ScanResult, RuleLoader, etc.)
  |-- ironpost-log-pipeline   (RuleLoader, DetectionRule, RuleEngine)
  |-- ironpost-container-guard (DockerClient, IsolationExecutor -- existing)
  +-- [Linux] ironpost-ebpf-engine
```

The CLI never depends on `ironpost-daemon` as a library. Communication with
a running daemon (for `status`, `start --daemonize`) uses one of these
mechanisms:

| Mechanism | Subcommand | Description |
|-----------|-----------|-------------|
| Direct library call | `scan`, `rules`, `config` | Import crate, instantiate, call pub API |
| PID file check | `status` | Read `/var/run/ironpost/ironpost.pid`, check if process alive |
| Process spawn | `start -d` | `std::process::Command::new("ironpost-daemon")` |
| Foreground exec | `start` | Load config, build `Orchestrator`, call `run()` |

### 5.2 Per-Subcommand Interaction Diagram

#### `ironpost start` (foreground, no `-d`)

```
CLI main
  |-> load IronpostConfig (ironpost_core::config)
  |-> apply CLI overrides (log_level)
  |-> init tracing
  |-> Orchestrator::build_from_config(config)  // reuses daemon logic
  |-> orchestrator.run().await                 // blocks until SIGTERM/SIGINT
```

For foreground mode, the CLI acts as the daemon itself. This reuses the
`Orchestrator` from `ironpost-daemon` as a library dependency. The approach
requires adding `ironpost-daemon` as a dependency **only for the `start`
subcommand**. Alternatively (and preferably for separation), the CLI
can re-implement orchestrator construction inline, or spawn the daemon
binary:

```
CLI main
  |-> std::process::Command::new("ironpost-daemon")
  |       .args(["--config", config_path])
  |       .exec()                              // replaces the CLI process
```

This keeps `ironpost-cli` independent of `ironpost-daemon` internals.

#### `ironpost start -d` (daemon mode)

```
CLI main
  |-> validate config exists
  |-> std::process::Command::new("ironpost-daemon")
  |       .args(["--config", config_path])
  |       .stdin(Stdio::null())
  |       .stdout(Stdio::null())
  |       .stderr(Stdio::null())
  |       .spawn()                             // detached child process
  |-> wait briefly, check PID file
  |-> report success/failure
```

#### `ironpost status`

```
CLI main
  |-> load IronpostConfig
  |-> read PID file (config.general.pid_file)
  |-> check if PID is alive (kill(pid, 0) on Unix)
  |-> report daemon_running, uptime estimate
  |-> for each module section in config:
  |       report enabled/disabled from config
  |       (live health requires a future HTTP/Unix socket API)
```

Note: Full health check requires the daemon to expose a health endpoint
(HTTP or Unix domain socket). For the initial implementation, `status`
reports what can be determined from config + PID file alone.

#### `ironpost scan [path]`

```
CLI main
  |-> load IronpostConfig
  |-> build SbomScannerConfig from core config + CLI overrides
  |-> SbomScannerBuilder::new()
  |       .config(scanner_config)
  |       .build()                             // creates SbomScanner + alert_rx
  |-> scanner.start().await                    // loads VulnDb
  |-> scanner.scan_once().await                // returns Vec<ScanResult>
  |-> scanner.stop().await
  |-> convert ScanResult -> ScanReport
  |-> writer.render(&report)
  |-> if findings > 0: return Err(CliError::Scan(...))  // exit code 4
```

This is a direct library call. The CLI constructs the scanner, triggers
a single scan, collects results, and renders them. No daemon required.

#### `ironpost rules list`

```
CLI main
  |-> load IronpostConfig
  |-> determine rules directory (from config or default)
  |-> RuleLoader::load_directory(rules_dir).await
  |-> filter by --status if provided
  |-> convert Vec<DetectionRule> -> RuleListReport
  |-> writer.render(&report)
```

#### `ironpost rules validate`

```
CLI main
  |-> RuleLoader::load_directory(path).await
  |-> collect successes + failures
  |-> convert to RuleValidationReport
  |-> writer.render(&report)
  |-> if invalid > 0: return Err(CliError::Rule(...))
```

#### `ironpost config validate`

```
CLI main
  |-> IronpostConfig::load(config_path).await
  |       on success: report valid
  |       on error: report invalid + error details
```

#### `ironpost config show`

```
CLI main
  |-> IronpostConfig::load(config_path).await
  |       (includes env var overrides)
  |-> if --section: extract only that section
  |-> convert to ConfigReport
  |-> writer.render(&report)
  |       Text mode: pretty-print as TOML
  |       JSON mode: serialize full config
```

### 5.3 Dependency Graph (Cargo.toml)

```toml
[package]
name = "ironpost-cli"
version = "0.1.0"
edition = "2024"

[dependencies]
ironpost-core          = { path = "../crates/core" }
ironpost-log-pipeline  = { path = "../crates/log-pipeline" }
ironpost-container-guard = { path = "../crates/container-guard" }
ironpost-sbom-scanner  = { path = "../crates/sbom-scanner" }
tokio    = { workspace = true }
tracing  = { workspace = true }
tracing-subscriber = { workspace = true }
clap     = { workspace = true }
serde    = { workspace = true }
serde_json = { workspace = true }
toml     = { workspace = true }

[target.'cfg(target_os = "linux")'.dependencies]
ironpost-ebpf-engine = { path = "../crates/ebpf-engine" }
```

---

## 6. Design Principles

### 6.1 Separation of Concerns

- **Parsing** (cli.rs): No side effects, no IO. Pure data structure definitions.
- **Execution** (commands/*.rs): Business logic. Receives parsed args, calls
  library crates, returns typed results or errors.
- **Rendering** (output.rs): Formatting only. Receives typed payloads, writes
  to stdout. No business logic.
- **Error mapping** (error.rs): Maps domain errors to exit codes. No business logic.

### 6.2 Testability

Each layer is independently testable:

- **cli.rs**: Test by constructing `Cli::try_parse_from(["ironpost", "scan", "."])`.
  No filesystem or network required.
- **commands/*.rs**: Accept config/args as parameters, return `Result`. Can be
  tested with in-memory configs and temp directories.
- **output.rs**: `Render` trait implementations can be tested by writing to a
  `Vec<u8>` buffer and asserting the text content.
- **error.rs**: `exit_code()` mapping is a pure function -- unit test each variant.

### 6.3 Extension Points

Adding a new subcommand requires:

1. Add a variant to `Commands` enum in `cli.rs`.
2. Create a new file in `commands/` with an `execute` function.
3. Define a payload struct implementing `Serialize + Render`.
4. Add the dispatch arm in `main.rs::run()`.

No existing code needs modification beyond the dispatch table.

### 6.4 Conventions Compliance

- **No `println!`/`eprintln!`**: Output goes through `OutputWriter` (to stdout),
  logging goes through `tracing` (to stderr).
- **No `unwrap()`**: All fallible operations use `?` with `CliError`.
- **No `unsafe`**: Not needed in the CLI crate.
- **`anyhow` not used in subcommand handlers**: Subcommand handlers use `CliError`.
  The `main()` function converts `CliError` to exit codes explicitly.
- **Modules depend only on `core`**: The CLI depends on each leaf crate directly
  but leaf crates never depend on each other.
- **`tracing` for all logging**: `tracing::info!`, `tracing::error!`, etc.

---

## 7. Future Considerations

### 7.1 Daemon Health API

The `status` command currently relies on PID file checking. A future
iteration should introduce a Unix domain socket or HTTP endpoint in
`ironpost-daemon` that exposes `DaemonHealth` (from `ironpost-daemon::health`).
The CLI would connect to that socket and deserialize the health report.

### 7.2 Configuration Hot Reload

`ironpost config reload` could send `SIGHUP` to the daemon PID, triggering
a config reload via the `tokio::watch` channel already wired in the
orchestrator.

### 7.3 Container Subcommand (Existing)

The existing `container list/isolate/release` subcommands in the current
`main.rs` should be preserved as an additional `Commands::Container(ContainerArgs)`
variant, using the same `OutputWriter` pattern for text/JSON output.

### 7.4 eBPF Subcommand (Linux only)

```rust
#[cfg(target_os = "linux")]
Commands::Ebpf(EbpfArgs),
```

Gated behind `cfg(target_os = "linux")`, preserving the existing pattern.

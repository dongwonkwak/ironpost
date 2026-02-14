# Getting Started with Ironpost

**Unified Security Monitoring Platform — Installation, Configuration, and First Run Guide**

This guide walks you through installing Ironpost from source, configuring it for your environment, writing detection rules, and running your first security scans.

**Estimated time:** 30 minutes (source build) to 3 minutes (Docker demo)

## Table of Contents

1. [Prerequisites](#prerequisites)
2. [Building from Source](#building-from-source)
3. [Configuration](#configuration)
4. [First Run](#first-run)
5. [Writing Detection Rules](#writing-detection-rules)
6. [Container Security Policies](#container-security-policies)
7. [SBOM Vulnerability Scanning](#sbom-vulnerability-scanning)
8. [Docker Demo (Quick Experience)](#docker-demo-quick-experience)
9. [Next Steps](#next-steps)

---

## Prerequisites

### System Requirements

Ironpost is a Rust-based platform that runs on **Linux, macOS, and Windows**. Full feature support varies by platform.

| Requirement | Minimum | Recommended | Notes |
|-----------|---------|-------------|-------|
| **Rust** | 1.93.0 | Latest stable | Install from [rustup.rs](https://rustup.rs) |
| **Linux Kernel** | 5.7+ | 6.0+ | For eBPF module (optional) |
| **Docker** | 20.10+ | Latest | For container isolation and demo (optional) |
| **RAM** | 2 GB | 4+ GB | For running all modules simultaneously |
| **Disk** | 500 MB | 2+ GB | For binaries, logs, and SBOM data |

### Platform-Specific Notes

**Linux (Full Support)**
- All modules work natively
- eBPF module requires kernel 5.7+ with `CONFIG_BPF=y`
- Requires `CAP_NET_ADMIN` (or root) to attach XDP programs; `CAP_BPF` is used for BPF map/program operations
- eBPF toolchain setup needed (see [Building with eBPF](#building-with-ebpf))

**macOS (Partial Support)**
- Workspace modules compile (log-pipeline, container-guard, sbom-scanner)
- eBPF module not supported (automatically excluded)
- Docker integration works via Docker Desktop
- Use `cargo build` without eBPF toolchain setup

**Windows (Partial Support)**
- Most modules work via WSL2
- Requires WSL2 with Linux kernel 5.7+ for eBPF
- Docker integration works via Docker Desktop

---

## Building from Source

### 1. Clone the Repository

```bash
# Clone with git (requires git 2.20+)
git clone https://github.com/dongwonkwak/ironpost.git
cd ironpost

# Verify you're on the main branch
git status
# Expected output: On branch main
```

### 2. Install Rust Toolchain

If you don't have Rust installed, install it first:

```bash
# Download and install Rust (Linux/macOS/Windows WSL)
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh

# Activate Rust in current shell
source $HOME/.cargo/env

# Verify installation
rustc --version
# Expected: rustc 1.93.x
cargo --version
# Expected: cargo 1.93.x
```

### 3. Build the Workspace (Without eBPF)

The quickest way to get started without eBPF (suitable for all platforms):

```bash
# Build all workspace crates in release mode (optimized)
cargo build --release

# This creates binaries at:
# ./target/release/ironpost-daemon    (main daemon)
# ./target/release/ironpost-cli       (CLI tool)
```

**Expected output:**
```
   Compiling ironpost-core v0.1.0
   Compiling ironpost-ebpf-engine v0.1.0
   Compiling ironpost-log-pipeline v0.1.0
   ... (continues for ~2-3 minutes on first build)
   Finished release [optimized] target(s) in 150s
```

### 4. Building with eBPF (Linux Only)

To include the eBPF network monitoring module (Linux only), follow these additional steps:

#### Install eBPF Dependencies

```bash
# Install bpf-linker (required for eBPF bytecode linking)
cargo install bpf-linker

# Install nightly Rust toolchain with rust-src component
rustup toolchain install nightly --component rust-src

# Verify installation
bpf-linker --version
# Expected: bpf-linker 0.5.x
```

#### Build with eBPF

```bash
# Use the xtask build system to include eBPF
cargo run -p xtask -- build --all --release

# Verify eBPF bytecode was compiled
llvm-objdump -S target/bpfel-unknown-none/release/ironpost-ebpf | head -30
# Expected: eBPF bytecode instructions
```

### 5. Minimal Build (CLI + Daemon Only)

If you only need the CLI and daemon without logging modules:

```bash
# Build just the essential binaries
cargo build --release -p ironpost-cli -p ironpost-daemon

# Resulting binaries:
# ./target/release/ironpost-daemon
# ./target/release/ironpost-cli
```

---

## Configuration

Ironpost uses a single TOML configuration file to manage all modules.

### 1. Create Configuration File

Copy the example configuration to use as a starting point:

```bash
# Copy example to ironpost.toml
cp ironpost.toml.example ironpost.toml

# (Optional) Edit with your preferred editor
nano ironpost.toml   # or vim, emacs, etc.
```

### 2. Minimal Configuration (Log Pipeline Only)

For a quick test, use the default configuration that enables only the log pipeline:

```toml
# ironpost.toml (minimal setup)

[general]
log_level = "debug"           # Show detailed logs
log_format = "json"           # Structured logging
data_dir = "/tmp/ironpost"    # Use temporary directory for testing
pid_file = "/tmp/ironpost.pid"

[log_pipeline]
enabled = true
sources = ["syslog", "file"]
syslog_bind = "127.0.0.1:1514"  # Bind to localhost only (no root required; unprivileged port)
watch_paths = ["/var/log/syslog", "/var/log/auth.log"]
batch_size = 100
flush_interval_secs = 5

# Optional storage (set to PostgreSQL/Redis if available)
[log_pipeline.storage]
postgres_url = "postgresql://localhost:5432/ironpost"
redis_url = "redis://localhost:6379"
```

### 3. Full Configuration (All Modules)

To enable all modules, update the configuration:

```toml
# ironpost.toml (full setup - Linux with Docker)

[general]
log_level = "info"
log_format = "json"
data_dir = "/var/lib/ironpost"
pid_file = "/var/run/ironpost/ironpost.pid"

[ebpf]
enabled = true                # Requires Linux 5.7+, CAP_BPF or root
interface = "eth0"           # Change to your network interface
xdp_mode = "skb"             # "skb" for compatibility, "native" for performance
ring_buffer_size = 262144
blocklist_max_entries = 10000

[log_pipeline]
enabled = true
sources = ["syslog", "file"]
syslog_bind = "0.0.0.0:514"  # Listen on all interfaces
watch_paths = ["/var/log/syslog", "/var/log/auth.log"]
batch_size = 1000            # Higher throughput
flush_interval_secs = 5

[log_pipeline.storage]
postgres_url = "postgresql://user:password@localhost:5432/ironpost"
redis_url = "redis://localhost:6379"
retention_days = 30

[container]
enabled = true               # Requires Docker socket access
docker_socket = "/var/run/docker.sock"
poll_interval_secs = 10
policy_path = "/etc/ironpost/policies"
auto_isolate = false         # Set to true after testing policies

[sbom]
enabled = true
scan_dirs = ["."]            # Scan current directory
vuln_db_path = "/var/lib/ironpost/vuln-db"
min_severity = "medium"
output_format = "cyclonedx"
```

### 4. Environment Variable Overrides

Configuration values can be overridden via environment variables, useful for containerized deployments:

```bash
# Override log level without editing config file
export IRONPOST_GENERAL_LOG_LEVEL=debug
export IRONPOST_LOG_PIPELINE_BATCH_SIZE=500

# Override storage URLs (recommended for secrets)
export IRONPOST_STORAGE_POSTGRES_URL="postgresql://user:pass@prod-db:5432/ironpost"
export IRONPOST_STORAGE_REDIS_URL="redis://:password@prod-redis:6379"

# Vector type fields use CSV format
export IRONPOST_LOG_PIPELINE_WATCH_PATHS="/var/log/auth.log,/var/log/kern.log"

# Start daemon with overrides applied
./target/release/ironpost-daemon
```

### 5. Validate Configuration

Before starting the daemon, validate your configuration:

```bash
# Validate configuration syntax and rules
./target/release/ironpost-cli --config ironpost.toml config validate

# Expected output:
# Configuration validation: PASSED
# All required fields are present and valid

# If validation fails, you'll see errors like:
# Configuration validation: FAILED
# Error: [log_pipeline] syslog_bind: invalid socket address
```

---

## First Run

### 1. Prepare Data Directories

Create necessary directories (required if using custom data_dir):

```bash
# Create data directory
mkdir -p /var/lib/ironpost
mkdir -p /var/lib/ironpost/vuln-db

# Create policy directory for container-guard
mkdir -p /etc/ironpost/policies
mkdir -p /etc/ironpost/rules

# Set appropriate permissions (if running as non-root)
chmod 755 /var/lib/ironpost
chmod 755 /etc/ironpost/policies
chmod 755 /etc/ironpost/rules
```

### 2. Run Daemon in Foreground (Development/Testing)

Start the daemon in foreground mode to see all logs in your terminal:

```bash
# Run daemon with your configuration
./target/release/ironpost-daemon --config ironpost.toml

# You should see logs like:
# 2026-02-14T10:30:00Z INFO  ironpost-daemon: Daemon starting with config: ironpost.toml
# 2026-02-14T10:30:01Z INFO  log-pipeline: Log collection started on 0.0.0.0:514
# 2026-02-14T10:30:01Z INFO  ebpf-engine: XDP program loaded on eth0 (mode: skb)
# 2026-02-14T10:30:01Z INFO  container-guard: Docker monitoring enabled
# 2026-02-14T10:30:01Z INFO  sbom-scanner: CVE database initialized
# 2026-02-14T10:30:01Z INFO  ironpost-daemon: All modules started successfully

# Press Ctrl+C to stop the daemon
```

### 3. Check Daemon Status in Another Terminal

While the daemon is running, open a new terminal and check its status:

```bash
# List all modules and their status
./target/release/ironpost-cli status

# Expected output:
# Daemon: running (uptime: 45s)
#
# Module               Enabled    Health
# ============================================
# ebpf-engine          yes        running
# log-pipeline         yes        running
# container-guard      yes        running
# sbom-scanner         yes        running

# Verbose output with configuration details
./target/release/ironpost-cli status --verbose
```

### 4. Send Test Log Messages

Send sample syslog messages to verify the log pipeline is working:

```bash
# Send a test syslog message (RFC 5424 format)
echo '<34>1 2026-02-14T10:30:00Z test-host sshd - - - Failed password for root from 192.168.1.100' | \
  nc -u -w1 127.0.0.1 514

# Expected output in daemon terminal:
# 2026-02-14T10:30:05Z DEBUG log-pipeline: Parsed log entry from syslog source
# 2026-02-14T10:30:05Z DEBUG log-pipeline: Batch processed: 1 logs, 0 alerts
```

---

## Writing Detection Rules

Ironpost uses YAML-based detection rules for the log-pipeline module to identify security threats.

### 1. Create Rules Directory

```bash
# Create rules directory
mkdir -p /etc/ironpost/rules
cd /etc/ironpost/rules
```

### 2. Write a Simple Detection Rule

Create a basic SSH brute force detection rule:

```yaml
# ssh-brute-force.yaml
id: ssh_brute_force
title: SSH Brute Force Attack
description: Detects multiple failed SSH login attempts from same IP within timeframe
severity: high

detection:
  # Conditions: All must match
  conditions:
    - field: process
      operator: equals
      value: sshd
      modifier: case_insensitive

    - field: message
      operator: contains
      value: "Failed password"

  # Threshold: Trigger alert when conditions met N times in timeframe
  threshold:
    count: 5              # 5 failed attempts
    timeframe_secs: 60    # within 60 seconds
    group_by: src_ip      # from same IP address

# Metadata for tracking
tags:
  - attack.credential_access
  - T1110  # MITRE ATT&CK ID: Brute Force
  - ssh
  - authentication
```

### 3. More Rule Examples

**SQL Injection Detection:**

```yaml
# sql-injection.yaml
id: sql_injection_attempt
title: SQL Injection Attack Attempt
severity: critical

detection:
  conditions:
    - field: message
      operator: regex
      value: "(?i)(union.*select|select.*from|drop.*table|insert.*into|update.*set)"

    - field: protocol
      operator: equals
      value: "http"

  threshold:
    count: 1
    timeframe_secs: 300
    group_by: src_ip

tags:
  - attack.defense_evasion
  - T1190
```

**Privilege Escalation via Sudo:**

```yaml
# unauthorized-sudo.yaml
id: unauthorized_sudo_attempt
title: Unauthorized Sudo Execution
severity: high

detection:
  conditions:
    - field: process
      operator: equals
      value: sudo

    - field: message
      operator: contains
      value: "NOT in sudoers"

  threshold:
    count: 3
    timeframe_secs: 300
    group_by: user

tags:
  - attack.privilege_escalation
  - T1548.003
```

### 4. Validate Rules

Before deploying, validate your YAML rule syntax:

```bash
# Validate all rules in directory
./target/release/ironpost-cli rules validate /etc/ironpost/rules

# Expected output:
# Rule Validation: /etc/ironpost/rules
#   Files: 3, 3 valid, 0 invalid
#   ✓ ssh-brute-force.yaml
#   ✓ sql-injection.yaml
#   ✓ unauthorized-sudo.yaml

# If validation fails:
# Rules Validation: /etc/ironpost/rules
#   Files: 3, 2 valid, 1 invalid
#   Error in malformed-rule.yaml: Missing required field 'title'
```

### 5. Test Rules with Sample Logs

Create a test log file and verify rules match correctly:

```bash
# Create test log (RFC 5424 format, one per line)
cat > test-logs.txt << 'EOF'
<34>1 2026-02-14T10:30:00Z webserver sshd - - - Failed password for root from 192.168.1.100
<34>1 2026-02-14T10:30:05Z webserver sshd - - - Failed password for admin from 192.168.1.100
<34>1 2026-02-14T10:30:10Z webserver sshd - - - Failed password for user from 192.168.1.100
<34>1 2026-02-14T10:30:15Z webserver sshd - - - Failed password for root from 192.168.1.100
<34>1 2026-02-14T10:30:20Z webserver sshd - - - Failed password for admin from 192.168.1.100
EOF

# Validate rule syntax before deployment
./target/release/ironpost-cli rules validate /etc/ironpost/rules

# Expected output:
# Rule Validation: /etc/ironpost/rules
#   Files: 1, 1 valid, 0 invalid
#   ✓ ssh-brute-force.yaml
```

---

## Container Security Policies

If using container-guard for Docker isolation, define security policies in TOML format.

### 1. Create Policies Directory

```bash
# Create policies directory
mkdir -p /etc/ironpost/policies
cd /etc/ironpost/policies
```

### 2. Write a Simple Isolation Policy

Create a policy that pauses web server containers on high-severity alerts:

```toml
# pause-web-servers.toml
id = "pause_web_on_high"
name = "Pause Web Servers on High Alert"
description = "Automatically pause web server containers when HIGH or CRITICAL alerts trigger"
enabled = true
priority = 10

# Trigger condition
[target_filter]
severity_threshold = "high"      # Alert severity: info, low, medium, high, critical
action_when_matched = "pause"    # Action: pause, stop, network_disconnect

# Container selection filters
[container_filter]
# Match by container name (glob patterns supported)
names = ["web-*", "api-*", "nginx*"]

# Match by image name (glob patterns supported)
images = ["nginx:*", "node:*", "httpd:*"]
```

### 3. Database-Specific Isolation Policy

Create a stricter policy for database containers:

```toml
# stop-db-on-critical.toml
id = "stop_db_on_critical"
name = "Stop Database Containers on Critical Alert"
description = "Stop (don't just pause) database containers on CRITICAL security alerts"
enabled = true
priority = 20

[target_filter]
severity_threshold = "critical"
action_when_matched = "stop"

[container_filter]
names = ["postgres*", "mysql*", "mongodb*"]
```

---

## SBOM Vulnerability Scanning

Ironpost can scan your project's dependencies for known vulnerabilities.

### 1. Run a Quick SBOM Scan

Scan the current project directory:

```bash
# Scan current directory for lockfiles
./target/release/ironpost-cli scan

# Expected output:
# Scan: /home/user/ironpost
# Lockfiles scanned: 1 (Cargo.lock)
# Total packages: 127
#
# Vulnerabilities: 0 found

# Or with JSON output for CI/CD integration
./target/release/ironpost-cli --output json scan . > sbom-scan.json
```

### 2. Run Scan with Custom Settings

```bash
# Scan with minimum severity filter
./target/release/ironpost-cli scan . --min-severity critical

# Scan and generate SPDX format SBOM
./target/release/ironpost-cli scan . --sbom-format spdx

# Scan specific directory
./target/release/ironpost-cli scan /path/to/project

# All options combined
./target/release/ironpost-cli scan /app \
  --min-severity high \
  --sbom-format cyclonedx \
  --output json > scan-report.json
```

### 3. Interpret Scan Results

```bash
# View detailed JSON results
cat sbom-scan.json | jq '.vulnerabilities'

# Expected output on vulnerable project:
# {
#   "critical": 0,
#   "high": 2,
#   "medium": 1,
#   "low": 0,
#   "info": 0,
#   "total": 3
# }

# View specific CVE findings
cat sbom-scan.json | jq '.findings[] | {cve_id, package, severity}'

# Extract packages with known vulnerabilities
cat sbom-scan.json | jq '.findings[].package' | sort -u
```

---

## Docker Demo (Quick Experience)

For the fastest way to experience Ironpost without building from source, use Docker Compose.

### 1. Prerequisites

Ensure Docker and Docker Compose are installed:

```bash
# Check Docker
docker --version
# Expected: Docker version 20.10.x or higher

docker compose version
# Expected: Docker Compose version v2.x.x or higher
```

### 2. Run Docker Demo Stack

```bash
# Clone repository (if not already done)
git clone https://github.com/dongwonkwak/ironpost.git
cd ironpost

# Start all demo services (includes daemon, log simulator, attack simulator)
docker compose -f docker/docker-compose.yml -f docker/docker-compose.demo.yml up -d

# Wait for startup
sleep 30

# View logs from daemon
docker compose logs -f ironpost

# Expected output (after ~10 seconds):
# 2026-02-14T10:30:00Z INFO  log-pipeline: Log received from webserver01
# 2026-02-14T10:30:10Z WARN  log-pipeline: Alert: SSH Brute Force Attack (HIGH)
# 2026-02-14T10:30:11Z INFO  container-guard: Container nginx isolated: action=pause
```

### 3. Interact with Demo

While demo is running:

```bash
# Check daemon status
docker compose exec ironpost ironpost-cli status

# View recent logs in demo
docker compose logs ironpost | tail -50

# Manually trigger SBOM scan
docker compose exec ironpost ironpost-cli scan /app

# Check if nginx container was paused
docker ps | grep nginx
# Expected: STATUS = "Up X seconds (Paused)"
```

### 4. Cleanup Demo

```bash
# Stop all services
docker compose down

# Remove data volumes
docker compose down -v

# Verify cleanup
docker ps -a | grep ironpost
# Expected: No output (all removed)
```

---

## Next Steps

### 1. Read Architecture Documentation

Understand how Ironpost works internally:

- [`docs/architecture.md`](./architecture.md) — System design, module interactions, event flows
- [`docs/configuration.md`](./configuration.md) — Detailed configuration reference
- [`README.md`](../README.md) — Project overview and features

### 2. Explore Module Documentation

Deep-dive into individual modules:

- `crates/log-pipeline/README.md` — Log parsing, rule engine, parser details
- `crates/container-guard/README.md` — Docker integration, policy engine
- `crates/sbom-scanner/README.md` — SBOM generation, CVE database structure
- `crates/ebpf-engine/README.md` — eBPF networking, XDP programs

### 3. Set Up Production Deployment

When ready to deploy to production:

```bash
# Use optimized build
cargo build --release

# Create production config (with real database URLs, restrictive log levels)
cp ironpost.toml.example ironpost.toml.prod
# Edit ironpost.toml.prod with production settings
```

### 4. Troubleshooting

**Syslog not being received:**
```bash
sudo netstat -lun | grep 514
echo 'test' | nc -u -w1 127.0.0.1 514
```

**Rules not matching logs:**
```bash
IRONPOST_GENERAL_LOG_LEVEL=debug ./target/release/ironpost-daemon --config ironpost.toml
./target/release/ironpost-cli rules validate /etc/ironpost/rules
```

**Docker module not connecting:**
```bash
docker ps  # Verify Docker access
ls -la /var/run/docker.sock
sudo usermod -aG docker $USER  # Add user to docker group if needed
```

---

## Summary

You now have a working Ironpost installation with:

✅ **Log Pipeline** — Collecting and parsing syslog messages from multiple sources
✅ **Detection Rules** — YAML-based threat patterns for identifying security incidents
✅ **Container Isolation** — Docker policies to automatically respond to threats
✅ **SBOM Scanning** — Vulnerability detection in project dependencies
✅ **CLI Interface** — Complete command-line toolkit for operations and automation

**Next Commands:**

```bash
# Start daemon
./target/release/ironpost-daemon --config ironpost.toml

# Check status (in another terminal)
./target/release/ironpost-cli status

# Test detection rules
./target/release/ironpost-cli rules validate /etc/ironpost/rules

# Scan dependencies
./target/release/ironpost-cli scan .

# View help
./target/release/ironpost-cli --help
```

Happy securing! 🛡️

# Ironpost Demo Guide

**Experience Ironpost's core security monitoring features in 3 minutes.**

This demo showcases Ironpost's integrated security platform with real log collection, threat detection, container isolation, and SBOM vulnerability scanning—all running in a containerized environment.

---

## Table of Contents

1. [Introduction](#introduction)
2. [Prerequisites](#prerequisites)
3. [Quick Start (3-Minute Experience)](#quick-start-3-minute-experience)
4. [Step-by-Step Experience](#step-by-step-experience)
5. [Architecture Overview](#architecture-overview)
6. [Cleanup](#cleanup)
7. [Troubleshooting](#troubleshooting)
8. [Next Steps](#next-steps)

---

## Introduction

This demo environment demonstrates the following Ironpost features:

| Feature | What You'll See |
|---------|-----------------|
| **Log Pipeline** | Real-time syslog collection and parsing (RFC 5424 format) |
| **Detection Rules** | YAML-based threat detection matching suspicious patterns |
| **Alerting** | AlertEvent generation when rules trigger |
| **Container Isolation** | Automatic pause/stop of containers based on security policies |
| **SBOM Scanning** | Vulnerability discovery in lockfiles (Cargo.lock, package-lock.json) |

**Demo Architecture:**
- **Normal logs** generated every 5 seconds (SSH, nginx, systemd events)
- **Attack simulation** triggers after 10 seconds (brute force, SQL injection, port scan)
- **Monitoring target** nginx container ready for isolation demo
- **Redis** service for event caching
- **PostgreSQL** for log storage (optional)

---

## Prerequisites

Before starting, ensure you have:

### Required Software

- **Docker** 20.10+ ([Installation Guide](https://docs.docker.com/get-docker/))
- **Docker Compose** v2.0+ (bundled with Docker Desktop, or install separately)
- **4GB+ RAM** recommended for all services
- **Available Ports**: 514 (syslog), 80 (nginx demo), 6379 (redis)

### Verify Installation

```bash
# Check Docker version
docker --version
# Expected: Docker version 20.10.x or higher

# Check Docker Compose version
docker compose version
# Expected: Docker Compose version v2.x.x or higher

# Verify Docker is running
docker ps
# Expected: Shows running containers (or empty table if none running)
```

### Port Availability

Check if required ports are free:

```bash
# Check syslog port (514)
lsof -i :514 || echo "Port 514 is available"

# Check redis port (6379)
lsof -i :6379 || echo "Port 6379 is available"

# Check nginx demo port (8888)
lsof -i :8888 || echo "Port 8888 is available"
```

**If ports are in use**, see [Troubleshooting](#troubleshooting) section.

---

## Quick Start (3-Minute Experience)

Copy and paste these commands to start the full demo stack:

```bash
# 1. Clone the repository
git clone https://github.com/<your-username>/ironpost.git
cd ironpost

# 2. Copy environment configuration
cp docker/.env.example docker/.env

# 3. Start the demo stack (all services)
docker compose -f docker/docker-compose.yml -f docker/docker-compose.demo.yml up -d

# 4. Move into docker/ directory (subsequent commands assume this)
cd docker

# 5. Wait for services to be ready (~30 seconds)
echo "Waiting for Ironpost to start..."
sleep 30

# 6. Follow Ironpost logs (press Ctrl+C to exit)
docker compose logs -f ironpost
```

**Expected Output (after 30 seconds):**

```json
{"timestamp":"2026-02-12T00:45:30Z","level":"INFO","module":"ironpost-daemon","message":"All modules started successfully"}
{"timestamp":"2026-02-12T00:45:32Z","level":"INFO","module":"log-pipeline","message":"Received log from webserver01: Accepted publickey for admin"}
{"timestamp":"2026-02-12T00:45:40Z","level":"WARN","module":"log-pipeline","message":"Alert triggered: SSH Brute Force Attack (severity: high)"}
{"timestamp":"2026-02-12T00:45:41Z","level":"INFO","module":"container-guard","message":"Container nginx isolated: action=pause reason=high_severity_alert"}
```

**Success Indicators:**
- ✅ Log messages appear every 5 seconds (normal logs)
- ✅ Alert messages appear after ~10 seconds (attack simulation)
- ✅ Container isolation action logged
- ✅ No `ERROR` level messages in logs

---

## Step-by-Step Experience

> **Note:** All `docker compose` commands below assume you are in the `docker/` directory
> (as instructed in Quick Start step 4). If you are in the repository root instead,
> prefix each command with `-f docker/docker-compose.yml -f docker/docker-compose.demo.yml`.

### 1. Log Monitoring

**What it demonstrates:** Real-time log collection and parsing from syslog sources.

```bash
# View live logs from Ironpost daemon
docker compose logs -f ironpost
```

**Expected Output:**

```json
{"timestamp":"2026-02-12T00:46:00Z","level":"DEBUG","module":"log-pipeline","fields":{"source":"syslog","parser":"rfc5424","host":"webserver01"},"message":"Parsed log entry successfully"}
{"timestamp":"2026-02-12T00:46:05Z","level":"INFO","module":"log-pipeline","message":"Batch processed: 8 logs, 0 alerts"}
{"timestamp":"2026-02-12T00:46:10Z","level":"DEBUG","module":"log-pipeline","fields":{"rule_id":"ssh_brute_force","matched":true},"message":"Rule matched for incoming log"}
```

**What to observe:**
- Logs are processed in batches (configured for 50 logs or 2-second intervals in demo)
- Each log shows structured fields (timestamp, level, module, message)
- JSON format enables easy integration with log aggregation tools

---

### 2. Alert Verification

**What it demonstrates:** YAML rule matching triggers AlertEvent generation.

The attack simulator runs automatically after 10 seconds. Watch for alert events:

```bash
# Filter for alert-related logs
docker compose logs ironpost | grep -i "alert"
```

**Expected Output:**

```json
{"timestamp":"2026-02-12T00:46:15Z","level":"WARN","module":"log-pipeline","fields":{"rule_id":"ssh_brute_force","severity":"high","src_ip":"203.0.113.42"},"message":"Alert triggered: SSH Brute Force Attack"}
{"timestamp":"2026-02-12T00:46:20Z","level":"WARN","module":"log-pipeline","fields":{"rule_id":"sql_injection","severity":"critical"},"message":"Alert triggered: SQL Injection Attempt"}
{"timestamp":"2026-02-12T00:46:25Z","level":"WARN","module":"log-pipeline","fields":{"rule_id":"port_scan_detected","severity":"medium"},"message":"Alert triggered: Port Scan Activity"}
```

**Demo Rules Triggered:**
1. **ssh_brute_force**: 3 failed SSH attempts in 60 seconds → HIGH severity
2. **sql_injection**: SQL keywords in HTTP request → CRITICAL severity
3. **privilege_escalation**: Unauthorized sudo attempt → HIGH severity
4. **suspicious_download**: wget/curl to malicious domains → MEDIUM severity
5. **port_scan_detected**: Multiple SYN packets to different ports → MEDIUM severity

**Rule Configuration:**

```yaml
# Example: docker/demo/rules/ssh-brute-force.yml
id: ssh_brute_force
title: SSH Brute Force Attack
severity: high
detection:
  conditions:
    - field: process
      modifier: equals
      value: sshd
    - field: message
      modifier: contains
      value: "Failed password"
  threshold:
    count: 3
    timeframe_secs: 60
    field: src_ip
```

---

### 3. Container Isolation

**What it demonstrates:** Alert-driven container enforcement via Docker API.

After alerts are triggered, Container Guard automatically isolates matching containers:

```bash
# Check Container Guard actions
docker compose logs ironpost | grep -i "container"
```

**Expected Output:**

```json
{"timestamp":"2026-02-12T00:46:16Z","level":"INFO","module":"container-guard","fields":{"action":"pause","container_id":"nginx_abc123","policy":"web-server"},"message":"Isolation action executed successfully"}
{"timestamp":"2026-02-12T00:46:16Z","level":"INFO","module":"container-guard","fields":{"event_type":"action","action":"container_pause"},"message":"ActionEvent emitted"}
```

**Verify Container Status:**

```bash
# List all containers (including paused)
docker ps -a

# Expected output:
# CONTAINER ID   IMAGE          STATUS                  PORTS     NAMES
# abc123def456   nginx:alpine   Up 2 minutes (Paused)   80/tcp    ironpost-demo-nginx
```

**Manual Isolation Test:**

```bash
# Resume the paused container
docker unpause ironpost-demo-nginx

# Verify it's running
docker ps | grep nginx
# Expected: STATUS = Up X minutes

# Trigger another alert to see auto-isolation again
docker compose restart attack-simulator
```

**Container Policies:**

The demo uses policies defined in `docker/demo/policies/demo-policy.yml`:

```yaml
- id: pause-web-on-high
  name: Pause Web Servers on High Severity
  severity_threshold: High
  target_filter:
    container_names:
      - "ironpost-demo-nginx"
    image_patterns:
      - "nginx:*"
  action: Pause
  priority: 10
```

Containers matching the `target_filter` (by name or image pattern) are automatically paused when high-severity alerts occur. Label-based filtering is not yet supported in this version.

---

### 4. SBOM Scanning

**What it demonstrates:** Lockfile parsing, dependency graph generation, and CVE vulnerability matching.

Trigger a manual SBOM scan:

```bash
# Run SBOM scan on the Ironpost workspace
docker compose exec ironpost ironpost-cli scan /var/lib/ironpost --sbom-format cyclonedx
```

**Expected Output:**

```
Scanning directory: /app
Discovered lockfiles:
  - /app/Cargo.lock (Rust/Cargo)

Parsing lockfiles...
  Cargo.lock: 127 packages found

Generating SBOM (CycloneDX 1.5)...
SBOM saved to: /var/lib/ironpost/sbom-20260212-004630.json

Checking for vulnerabilities...
Vulnerability Database: 15,432 CVE entries loaded

Scan Results:
  Packages scanned: 127
  Vulnerabilities found: 2
    CRITICAL: 0
    HIGH: 1
    MEDIUM: 1
    LOW: 0

Findings:
  [HIGH] tokio 1.35.0 - CVE-2024-XXXXX: Memory leak in shutdown path
    Affected: tokio 1.35.0
    Fixed in: tokio 1.35.1
  [MEDIUM] serde_json 1.0.108 - CVE-2024-YYYYY: DoS via deeply nested JSON
    Affected: serde_json 1.0.108
    Fixed in: serde_json 1.0.109

Alert events generated: 2
```

**View Generated SBOM:**

```bash
# List SBOM files
docker compose exec ironpost ls -lh /var/lib/ironpost/sbom-*.json

# View SBOM content (first 50 lines)
docker compose exec ironpost head -n 50 /var/lib/ironpost/sbom-*.json
```

**SBOM Format (CycloneDX 1.5 JSON):**

```json
{
  "bomFormat": "CycloneDX",
  "specVersion": "1.5",
  "version": 1,
  "metadata": {
    "timestamp": "2026-02-12T00:46:30Z",
    "tools": [{
      "vendor": "Ironpost",
      "name": "sbom-scanner",
      "version": "0.1.0"
    }]
  },
  "components": [
    {
      "type": "library",
      "name": "tokio",
      "version": "1.35.0",
      "purl": "pkg:cargo/tokio@1.35.0"
    }
  ]
}
```

**Automatic Scanning:**

The demo configures periodic scanning every hour:

```toml
[sbom]
enabled = true
scan_dirs = ["/app"]
vuln_db_update_hours = 1
min_severity = "low"  # Alert on all severity levels (demo only)
```

---

### 5. Health Check

**What it demonstrates:** Module health status aggregation and daemon health endpoint.

Check overall daemon health:

```bash
# Query health status via CLI
docker compose exec ironpost ironpost-cli status
```

**Expected Output:**

```
Ironpost Daemon Status
======================

Overall Health: Healthy

Modules:
  [✓] ebpf-engine:      Stopped  (disabled in Docker demo)
  [✓] log-pipeline:     Healthy  (uptime: 2m 15s, processed: 120 logs, alerts: 5)
  [✓] container-guard:  Healthy  (uptime: 2m 15s, monitored: 2 containers, actions: 1)
  [✓] sbom-scanner:     Healthy  (uptime: 2m 15s, scans: 0, vulns: 0)

Configuration:
  Config file: /etc/ironpost/ironpost.toml
  Log level:   debug
  Data dir:    /var/lib/ironpost
  PID file:    /var/run/ironpost.pid

Uptime: 2 minutes 15 seconds
```

**Module States:**

| State | Description |
|-------|-------------|
| **Healthy** | Module running normally, all checks passing |
| **Degraded** | Module running with reduced capacity (e.g., high memory) |
| **Unhealthy** | Module error state, not processing events |
| **Stopped** | Module intentionally stopped (ebpf in Docker demo) |

**Docker Healthcheck:**

Ironpost includes a built-in Docker healthcheck (defined in `docker/Dockerfile`):

```bash
# Check container health via Docker
docker inspect ironpost-daemon --format='{{.State.Health.Status}}'
# Expected: healthy
```

---

## Architecture Overview

The demo environment consists of these components:

```
┌─────────────────────────────────────────────────────────────────────┐
│                        Ironpost Demo Stack                          │
├─────────────────────────────────────────────────────────────────────┤
│                                                                     │
│  ┌──────────────┐     ┌──────────────┐     ┌──────────────┐       │
│  │  PostgreSQL  │────▶│    Redis     │────▶│  Ironpost    │       │
│  │  (storage)   │     │  (cache)     │     │   Daemon     │       │
│  └──────────────┘     └──────────────┘     └──────┬───────┘       │
│                                                    │               │
│                                                    │               │
│  ┌──────────────────────────────────────────────────┼──────┐       │
│  │              Ironpost Daemon Services           │      │       │
│  │  ┌────────────┬──────────────┬─────────────────┴──┐   │       │
│  │  │ log-pipeline│ container-guard│ sbom-scanner    │   │       │
│  │  │ (syslog:514)│ (/var/run/    │ (/app)          │   │       │
│  │  │             │  docker.sock) │                 │   │       │
│  │  └─────┬──────┴──────┬────────┴─────────────────┘   │       │
│  └────────┼─────────────┼──────────────────────────────┘       │
│           │             │                                       │
│           │             │                                       │
│  ┌────────▼─────┐  ┌────▼──────────┐  ┌────────────────┐      │
│  │ log-generator│  │ attack-simulator│  │ nginx (demo)  │      │
│  │ (normal logs)│  │ (malicious logs)│  │ (isolation    │      │
│  │ every 5s     │  │ one-time run    │  │  target)      │      │
│  └──────────────┘  └─────────────────┘  └────────────────┘      │
│                                                                  │
└──────────────────────────────────────────────────────────────────┘

         External Access
         ▼
    [Host Port 8888] ──▶ nginx:80 (demo web server)
    [Host Port 514]  ──▶ ironpost:1514 (syslog ingestion)
```

### Component Roles

**Infrastructure Services:**
- **PostgreSQL**: Stores log entries and alert history (retention: 7 days in demo)
- **Redis**: Caches alert deduplication state and threshold counters

**Ironpost Daemon Modules:**
- **log-pipeline**: Collects syslog messages, parses them, matches detection rules
- **container-guard**: Monitors Docker containers, evaluates policies, executes isolation actions
- **sbom-scanner**: Discovers lockfiles, generates SBOMs, scans for CVEs
- **ebpf-engine**: (Disabled in Docker) Would capture network packets via XDP

**Demo Workload Services:**
- **log-generator**: Sends realistic normal logs every 5 seconds (SSH success, nginx requests, systemd events)
- **attack-simulator**: Sends malicious log patterns after 10-second delay (brute force, SQL injection, port scan)
- **nginx**: Runs as demo workload, target for container isolation

### Event Flow

```
┌──────────────┐
│ log-generator│
│ attack-sim   │
└──────┬───────┘
       │ UDP syslog (port 514)
       ▼
┌──────────────────────────────────────┐
│   Ironpost Daemon                    │
│                                      │
│   ┌────────────────┐                 │
│   │ log-pipeline   │                 │
│   │ 1. Collect     │                 │
│   │ 2. Parse       │                 │
│   │ 3. Match rules │                 │
│   └───────┬────────┘                 │
│           │ AlertEvent (if matched)  │
│           ▼                          │
│   ┌────────────────┐                 │
│   │ container-guard│                 │
│   │ 1. Evaluate    │                 │
│   │    policy      │                 │
│   │ 2. Isolate     │                 │
│   │    container   │                 │
│   └───────┬────────┘                 │
│           │ ActionEvent              │
│           ▼                          │
│   ┌────────────────┐                 │
│   │ Docker API     │                 │
│   │ pause/stop     │                 │
│   └───────┬────────┘                 │
└───────────┼──────────────────────────┘
            │
            ▼
      ┌────────────┐
      │   nginx    │
      │  (paused)  │
      └────────────┘
```

### Network Topology

All services run on an isolated Docker network (`ironpost-net`):
- Internal DNS resolution (ironpost, redis, postgresql hostnames)
- No external exposure except mapped ports (514, 8888)
- Docker socket mounted read-only for container monitoring

---

## Cleanup

When you're done exploring the demo, stop and remove all containers and volumes:

```bash
# Make sure you're in the docker/ directory
cd docker

# Stop all demo services
docker compose down

# Remove volumes (destroys all data: logs, SBOM scans, alert history)
docker compose down -v

# Verify cleanup
docker ps -a | grep ironpost
# Expected: No output (all containers removed)
```

**What gets removed:**
- ✅ All Docker containers (ironpost, nginx, log-generator, attack-simulator, redis, postgresql)
- ✅ Named volumes (ironpost-data, postgres-data, redis-data)
- ✅ Docker network (ironpost-net)

**What persists:**
- ✅ Docker images (reused for faster next startup)
- ✅ Configuration files (docker/.env, docker/demo/*)

**To remove images as well:**

```bash
# Remove Ironpost image
docker rmi ironpost/daemon:latest

# Remove all demo images
docker images | grep 'ironpost\|nginx\|alpine\|postgres\|redis' | awk '{print $3}' | xargs docker rmi
```

---

## Troubleshooting

### Port Conflicts

**Problem:** Port 514, 6379, or 8888 already in use.

**Solution:**

```bash
# 1. Identify the process using the port
lsof -i :514

# 2. Stop the conflicting service
# For syslog on port 514:
sudo systemctl stop rsyslog  # or syslog-ng

# 3. Restart the demo (from docker/ directory)
docker compose up -d
```

**Alternative:** Change ports in `docker/.env`:

```bash
# Edit docker/.env
IRONPOST_SYSLOG_PORT=1514  # Use non-privileged port

# Update docker-compose.demo.yml port mapping
# Change "514:1514" to "1514:1514"
```

---

### Permission Issues

**Problem:** `Got permission denied while trying to connect to the Docker daemon socket`

**Solution:**

```bash
# Add your user to the docker group (Linux)
sudo usermod -aG docker $USER
newgrp docker

# On macOS/Windows Docker Desktop, ensure Docker is running
docker ps  # Should not require sudo
```

---

### Memory Shortage

**Problem:** Containers crashing with OOM (Out of Memory) errors.

**Symptoms:**

```bash
docker compose logs ironpost | grep -i "killed\|oom"
# Output: "Killed" or "OOMKilled: true"
```

**Solution:**

```bash
# 1. Check available memory
docker stats --no-stream

# 2. Increase Docker memory limit (Docker Desktop):
#    Preferences → Resources → Memory → Increase to 4GB+

# 3. Reduce batch sizes in docker/demo/ironpost-demo.toml
[log_pipeline]
batch_size = 25  # Reduce from 50
```

---

### Logs Not Appearing

**Problem:** No log messages in `docker compose logs ironpost`.

**Diagnosis:**

```bash
# 1. Check if log-generator is running
docker ps | grep log-generator
# Expected: STATUS = Up X minutes

# 2. Check if ironpost is healthy
docker compose exec ironpost ironpost-cli status

# 3. Check network connectivity
docker compose exec log-generator nc -zv ironpost 1514
# Expected: "Connection succeeded"

# 4. Check syslog collector status
docker compose logs ironpost | grep -i "syslog"
```

**Solutions:**

```bash
# Restart log-generator
docker compose restart log-generator

# Wait 30 seconds for initialization
sleep 30

# Manually send a test log
echo '<14>1 2026-02-12T00:00:00Z test-host test-app - - - Test message' | \
  docker compose exec -T ironpost nc -u localhost 1514
```

---

### Container Isolation Not Working

**Problem:** Nginx container not paused after alerts.

**Requirements:**
- Linux host (container isolation requires Linux kernel namespaces)
- Docker socket mounted (`/var/run/docker.sock`)
- `auto_isolate = true` in config

**Check:**

```bash
# 1. Verify Docker socket is mounted
docker compose exec ironpost ls -l /var/run/docker.sock
# Expected: srw-rw---- (socket file)

# 2. Verify container-guard is enabled
docker compose exec ironpost ironpost-cli status | grep container-guard
# Expected: "Healthy"

# 3. Check if alerts are actually triggering
docker compose logs ironpost | grep -i "alert triggered"
# Should see HIGH or CRITICAL severity alerts

# 4. Verify policy configuration
docker compose exec ironpost cat /etc/ironpost/ironpost.toml | grep -A 5 "\[container\]"
```

**On macOS/Windows:**
Container isolation works but uses Docker Desktop's Linux VM. If issues persist:

```bash
# Restart Docker Desktop
# macOS: Docker menu → Restart
# Windows: Right-click Docker icon → Restart
```

---

### Attack Simulator Not Running

**Problem:** No attack alerts appearing after 10 seconds.

**Check:**

```bash
# 1. Check if attack-simulator ran
docker compose ps attack-simulator
# Expected: STATUS = Exited (0)

# 2. View attack-simulator logs
docker compose logs attack-simulator
# Expected: "Attack simulation complete"

# 3. Manually re-run attack simulation
docker compose restart attack-simulator
docker compose logs -f attack-simulator
```

---

## Next Steps

### 1. Local Development Build

Build Ironpost from source for local development:

```bash
# Clone repository (if not already done)
git clone https://github.com/yourusername/ironpost.git
cd ironpost

# Install Rust toolchain (if not installed)
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh

# Build workspace (excludes eBPF, suitable for macOS/Linux/Windows)
cargo build --release

# Run daemon locally (requires sudo for port 514)
sudo ./target/release/ironpost-daemon --config ironpost.toml

# Run CLI
./target/release/ironpost-cli status
```

**Full build with eBPF (Linux only):**

```bash
# Install eBPF prerequisites
cargo install bpf-linker
rustup toolchain install nightly --component rust-src

# Build everything including eBPF
cargo run -p xtask -- build --all --release

# Verify eBPF bytecode
llvm-objdump -S target/bpfel-unknown-none/release/ironpost-ebpf
```

---

### 2. Writing Custom Detection Rules

Create your own YAML rules in `docker/demo/rules/`:

```yaml
# Example: docker/demo/rules/custom-rule.yml
id: unauthorized_access
title: Unauthorized File Access
description: Detects attempts to access sensitive files
severity: high

detection:
  conditions:
    - field: process
      modifier: equals
      value: cat
    - field: message
      modifier: regex
      value: "/etc/(passwd|shadow)"

  threshold:
    count: 1
    timeframe_secs: 300

tags:
  - attack.credential_access
  - T1552.001  # MITRE ATT&CK: Credentials in Files
```

**Test your rule:**

```bash
# Validate rule syntax (validates all rules in directory)
docker compose exec ironpost ironpost-cli rules validate /etc/ironpost/rules

# To apply changes, restart the daemon to reload rules
docker compose restart ironpost
```

---

### 3. Deploying to Production

**Production Deployment Checklist:**

- [ ] **Security Hardening**:
  - Change default passwords in `docker/.env` (`POSTGRES_PASSWORD`)
  - Use Docker secrets instead of `.env` file
  - Restrict Docker socket access (read-only mount or TCP with TLS)
  - Enable TLS for PostgreSQL/Redis connections

- [ ] **Resource Limits**:
  - Increase memory limits in `docker-compose.yml` (deploy.resources.limits)
  - Configure log retention (`retention_days = 30` or higher)
  - Set up log rotation for JSON logs

- [ ] **Monitoring**:
  - Enable Prometheus exporter (add `--profile monitoring`)
  - Set up Grafana dashboards (import from `docs/grafana/`)
  - Configure alerting (Prometheus Alertmanager or webhook to PagerDuty/Slack)

- [ ] **High Availability**:
  - Run multiple Ironpost instances behind a load balancer
  - Use managed PostgreSQL/Redis (AWS RDS, Azure Database)
  - Deploy on Kubernetes with Helm chart (see `deploy/kubernetes/`)

- [ ] **Testing**:
  - Run load tests (`cargo run -p xtask -- benchmark`)
  - Simulate failures (kill containers, network partitions)
  - Verify graceful shutdown (`docker compose stop`)

**Production Configuration:**

```toml
# ironpost.prod.toml (example)
[general]
log_level = "info"  # Reduce verbosity
log_format = "json"
data_dir = "/var/lib/ironpost"

[log_pipeline]
batch_size = 5000  # Higher throughput
flush_interval_secs = 10

[log_pipeline.storage]
postgres_url = "postgresql://ironpost:SECURE_PASSWORD@prod-db:5432/ironpost?sslmode=require"
redis_url = "rediss://prod-redis:6379"  # TLS enabled
retention_days = 90

[container]
auto_isolate = false  # Require manual approval in production
```

---

### 4. Reading Architecture Docs

Dive deeper into Ironpost's design:

| Document | Purpose | Audience |
|----------|---------|----------|
| [`.knowledge/architecture.md`](../.knowledge/architecture.md) | System architecture, module interactions, event flows | System architects |
| [`README.md`](../README.md) | Project overview, quick start, tech stack | All users |
| [`crates/log-pipeline/README.md`](../crates/log-pipeline/README.md) | Log pipeline internals, parser details, rule engine | Log pipeline developers |
| [`crates/container-guard/README.md`](../crates/container-guard/README.md) | Container isolation policies, Docker API usage | Container security developers |
| [`crates/sbom-scanner/README.md`](../crates/sbom-scanner/README.md) | SBOM generation, vulnerability DB structure | Supply chain security |
| [`CLAUDE.md`](../CLAUDE.md) | Development rules, code conventions, commit format | Contributors |

**Generated API Documentation:**

```bash
# Generate and open documentation for all crates
cargo doc --workspace --no-deps --open

# All public APIs have doc comments with examples
```

---

## Summary

You've now experienced Ironpost's core features:

- ✅ **Log Pipeline**: Collected and parsed syslog messages in real-time
- ✅ **Detection Rules**: Matched YAML-based threat patterns
- ✅ **Alerting**: Generated AlertEvent on suspicious activity
- ✅ **Container Isolation**: Automatically paused containers based on policies
- ✅ **SBOM Scanning**: Discovered vulnerabilities in lockfiles

**Demo Stack Components:**
- `ironpost-daemon`: Main security monitoring engine (1 container)
- `postgresql`: Log and alert storage (1 container)
- `redis`: Event caching and deduplication (1 container)
- `nginx`: Demo workload for isolation (1 container)
- `log-generator`: Normal log traffic (1 container)
- `attack-simulator`: Malicious log patterns (1 container, one-time run)

**Total Demo Time:** ~3 minutes from start to first alert

**Next Actions:**
- Explore custom detection rules in `docker/demo/rules/`
- Modify container policies in `docker/demo/ironpost-demo.toml`
- Review architecture in [`.knowledge/architecture.md`](../.knowledge/architecture.md)
- Build from source for local development
- Deploy to production with hardened configuration

**Questions or Issues?**
- Check [Troubleshooting](#troubleshooting) section above
- Read project documentation in `docs/`
- Submit issues via the issue tracker
- See contribution guidelines in `CLAUDE.md`

---

**Ironpost Demo - Experience unified security monitoring in 3 minutes.**

```
 ___ ____   ___  _   _ ____   ___  ____ _____
|_ _|  _ \ / _ \| \ | |  _ \ / _ \/ ___|_   _|
 | || |_) | | | |  \| | |_) | | | \___ \ | |
 | ||  _ <| |_| | |\  |  __/| |_| |___) || |
|___|_| \_\\___/|_| \_|_|    \___/|____/ |_|
Unified Security Monitoring Platform
```

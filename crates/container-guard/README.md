# ironpost-container-guard

[![Crates.io](https://img.shields.io/crates/v/ironpost-container-guard.svg)](https://crates.io/crates/ironpost-container-guard)
[![Docs.rs](https://docs.rs/ironpost-container-guard/badge.svg)](https://docs.rs/ironpost-container-guard)

Alert-driven Docker container isolation based on security policies.

## Overview

`ironpost-container-guard` is a Rust library that automatically isolates Docker containers in response to security alerts. It receives `AlertEvent` messages from other Ironpost modules (e.g., `ironpost-log-pipeline`, `ironpost-ebpf-engine`) via `tokio::mpsc` channels and evaluates TOML-defined security policies to determine which containers to isolate and how.

## Features

- **Alert-driven isolation**: Responds to security alerts from log analysis and network detection modules
- **Policy-based enforcement**: TOML-defined policies with glob pattern matching for container names and images
- **Multiple isolation actions**: Pause, stop, or network disconnect
- **Retry logic with linear backoff**: Configurable retry attempts and timeout for isolation actions
- **Zero-downtime policy updates**: Runtime policy changes via `Arc<Mutex<PolicyEngine>>`
- **Docker API abstraction**: Testable via `DockerClient` trait with mock implementation
- **Container inventory caching**: TTL-based caching to reduce Docker API calls
- **Trace ID propagation**: Links isolation actions back to originating alerts for observability

## Architecture

```text
┌──────────────────────────────────────────────────┐
│         AlertEvent (from log-pipeline)           │
└─────────────────────┬────────────────────────────┘
                      │
                      ▼
          ┌───────────────────────┐
          │   ContainerGuard      │ ← Pipeline trait
          │   (Orchestrator)      │
          └───────────┬───────────┘
                 ┌────┴────┐
                 ▼         ▼
       ┌──────────────┐ ┌────────────────┐
       │DockerMonitor │ │ PolicyEngine   │
       │(inventory)   │ │(rule matching) │
       └──────┬───────┘ └───────┬────────┘
              │                 │
              └────────┬────────┘
                       ▼
            ┌───────────────────┐
            │ IsolationExecutor │
            │ (retry + timeout) │
            └─────────┬─────────┘
                      │
                      ▼
              ┌───────────────┐
              │ Docker API    │
              │ (bollard)     │
              └───────┬───────┘
                      │
                      ▼
            ActionEvent → downstream
```

### Data Flow

1. **Alert Ingestion**: `AlertEvent` arrives via `tokio::mpsc::Receiver` from `ironpost-log-pipeline`
2. **Container Inventory**: `DockerMonitor` refreshes the cached container list if TTL expired
3. **Policy Evaluation**: `PolicyEngine` evaluates the alert against each cached container
   - Checks alert severity against policy threshold
   - Checks container name/image against glob patterns
4. **Isolation Execution**: `IsolationExecutor` calls Docker API with retry logic
5. **Action Reporting**: `ActionEvent` emitted with success/failure status and trace ID

## Quick Start

### Installation

Add to your `Cargo.toml`:

```toml
[dependencies]
ironpost-container-guard = "0.1"
ironpost-core = "0.1"
tokio = { version = "1", features = ["full"] }
```

### Basic Usage

```rust
use std::sync::Arc;
use tokio::sync::mpsc;
use ironpost_container_guard::{
    ContainerGuardBuilder, BollardDockerClient, ContainerGuardConfig,
};
use ironpost_core::event::AlertEvent;
use ironpost_core::pipeline::Pipeline;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // 1. Connect to Docker
    let docker = Arc::new(BollardDockerClient::connect_local()?);

    // 2. Load configuration
    let config = ContainerGuardConfig {
        enabled: true,
        docker_socket: "/var/run/docker.sock".to_owned(),
        poll_interval_secs: 10,
        policy_path: "/etc/ironpost/policies".to_owned(),
        auto_isolate: true,
        action_timeout_secs: 30,
        retry_max_attempts: 3,
        ..Default::default()
    };

    // 3. Create alert channel (from log-pipeline in production)
    let (alert_tx, alert_rx) = mpsc::channel(256);

    // 4. Build the guard
    let (mut guard, action_rx) = ContainerGuardBuilder::new()
        .config(config)
        .docker_client(docker)
        .alert_receiver(alert_rx)
        .build()?;

    // 5. Start the pipeline
    guard.start().await?;

    // 6. Process action events in downstream (optional)
    tokio::spawn(async move {
        let mut action_rx = action_rx.unwrap();
        while let Some(action) = action_rx.recv().await {
            println!("Isolation action: {} (success: {})", action.action_type, action.success);
        }
    });

    // Simulate receiving alerts (in production, this comes from log-pipeline)
    // alert_tx.send(alert_event).await?;

    // ... run until shutdown signal
    Ok(())
}
```

## Docker Integration

### Connection Setup

The guard connects to the Docker daemon via a Unix socket (or TCP for remote daemons):

```rust,no_run
use std::sync::Arc;
use ironpost_container_guard::BollardDockerClient;

# fn main() -> Result<(), Box<dyn std::error::Error>> {
// Default socket (auto-detected)
let client = Arc::new(BollardDockerClient::connect_local()?);

// Custom socket path
let client = Arc::new(BollardDockerClient::connect_with_socket("/run/docker.sock")?);
# Ok(())
# }
```

### Supported Docker Operations

- **`list_containers()`**: Lists all running containers (stopped/exited containers excluded)
- **`inspect_container(id)`**: Fetches detailed info for a specific container
- **`pause_container(id)`**: Freezes all processes (useful for forensics)
- **`stop_container(id)`**: Sends SIGTERM, then SIGKILL after 10s
- **`disconnect_network(id, network)`**: Removes container from a network (force mode)
- **`ping()`**: Checks Docker daemon connectivity

### Container ID Validation

All operations validate container IDs to prevent injection attacks:
- Must be 1-64 characters
- Must contain only ASCII hex digits `[0-9a-fA-F]`
- Empty IDs and IDs with special characters are rejected with `ContainerGuardError::DockerApi`

## Writing Security Policies

### Policy File Format (TOML)

Policies are defined in TOML files placed in the `policy_path` directory. Each file should contain a single policy:

```toml
# /etc/ironpost/policies/high-web-pause.toml

id = "high-web-pause"
name = "High Severity - Pause Web Containers"
description = "Pause web containers on High+ alerts for investigation"
enabled = true
severity_threshold = "High"
priority = 10

[target_filter]
# Glob patterns for container names (empty = match all)
container_names = ["web-*", "nginx-*"]
# Glob patterns for image names (empty = match all)
image_patterns = ["nginx:*", "httpd:*"]

[action]
# Pause the container (freezes processes)
Pause = []
```

### Policy Fields

| Field | Type | Description |
|-------|------|-------------|
| `id` | String | Unique policy identifier (required, non-empty) |
| `name` | String | Human-readable policy name (required, non-empty) |
| `description` | String | Policy description |
| `enabled` | Boolean | Whether the policy is active |
| `severity_threshold` | String | Minimum alert severity: `Info`, `Low`, `Medium`, `High`, `Critical` |
| `priority` | u32 | Evaluation priority (lower = higher priority, first match wins) |
| `target_filter` | Object | Container selection criteria |
| `action` | Object | Isolation action to execute |

### Target Filters

Filters use glob patterns with `*` (0+ chars) and `?` (exactly 1 char):

```toml
[target_filter]
# Match containers named "web-1", "web-prod", "web-staging", etc.
container_names = ["web-*"]

# Match images from nginx or httpd
image_patterns = ["nginx:*", "httpd:*"]

# Note: Labels are not yet supported (will be rejected by validation)
# labels = ["env=prod"]  # DON'T USE - not implemented
```

#### Filter Matching Logic

- **Within a list**: Patterns are OR'd (any pattern matches → filter passes)
- **Between lists**: Filters are AND'd (all filters must pass)
- **Empty lists**: Match ALL containers (⚠️ **dangerous in production**)

**Example:**

```toml
[target_filter]
container_names = ["web-*", "api-*"]  # Matches "web-1" OR "api-1"
image_patterns = ["nginx:*"]          # AND image must match "nginx:*"
```

This matches:
- `web-server` running `nginx:1.21` ✅
- `api-gateway` running `nginx:latest` ✅
- `web-server` running `httpd:latest` ❌ (image doesn't match)
- `db-server` running `nginx:1.21` ❌ (name doesn't match)

⚠️ **Security Warning**: Empty filters match ALL containers. Always specify explicit patterns in production:

```toml
# BAD: Will isolate ALL containers on any High alert
[target_filter]
container_names = []
image_patterns = []

# GOOD: Explicit target selection
[target_filter]
container_names = ["web-*"]
image_patterns = ["nginx:*"]
```

### Isolation Actions

Three isolation actions are supported:

#### 1. Pause

Freezes all container processes without killing them. Useful for forensic analysis.

```toml
[action]
Pause = []
```

**Effect**: Container state becomes "paused". Processes are frozen but not terminated. Resume with `docker unpause <id>`.

#### 2. Stop

Gracefully stops the container with a 10-second timeout.

```toml
[action]
Stop = []
```

**Effect**: Sends SIGTERM to the container's main process, waits 10s, then sends SIGKILL if still running.

#### 3. NetworkDisconnect

Removes the container from specified networks.

```toml
[action]
NetworkDisconnect = { networks = ["bridge", "host"] }
```

**Effect**: Disconnects the container from all listed networks. If disconnection fails for some networks, errors are collected and the action is retried on the next attempt (Docker disconnect is idempotent).

### Policy Priority and Evaluation

Policies are evaluated in **priority order** (lower number = higher priority). The **first matching policy** is executed (short-circuit evaluation).

```toml
# Policy 1: High priority (evaluated first)
id = "critical-stop"
priority = 1
severity_threshold = "Critical"
[action]
Stop = []

# Policy 2: Lower priority (evaluated second)
id = "high-pause"
priority = 10
severity_threshold = "High"
[action]
Pause = []
```

If an alert has severity `Critical`:
1. Policy 1 matches → container is **stopped**
2. Policy 2 is **not evaluated** (first match wins)

### Loading Policies

Policies are loaded from a directory at startup:

```rust,no_run
use ironpost_container_guard::policy::{load_policies_from_dir, PolicyEngine};
use std::path::Path;

# fn main() -> Result<(), Box<dyn std::error::Error>> {
let policies = load_policies_from_dir(Path::new("/etc/ironpost/policies"))?;

let mut engine = PolicyEngine::new();
for policy in policies {
    engine.add_policy(policy)?;
}
# Ok(())
# }
```

#### Policy Validation

Policies are validated on load:
- `id` and `name` must be non-empty
- Severity threshold must be valid (`Info`, `Low`, `Medium`, `High`, `Critical`)
- Label-based filtering is rejected (not yet implemented)
- File size must be ≤ 10 MB
- Total policy count ≤ 1000

#### Policy Hot Reload

Policies can be updated at runtime via the shared `PolicyEngine`:

```rust,ignore
// Note: This example requires a fully constructed ContainerGuard instance
use ironpost_container_guard::{ContainerGuard, DockerClient};

async fn example<D: DockerClient>(guard: &ContainerGuard<D>) -> Result<(), Box<dyn std::error::Error>> {
    let policy_engine = guard.policy_engine_arc();

    // Add a new policy
    let new_policy = /* ... */;
    policy_engine.lock().await.add_policy(new_policy)?;

    // Remove a policy by ID
    policy_engine.lock().await.remove_policy("old-policy-id");

    Ok(())
}
```

Changes take effect immediately for subsequent alert evaluations.

## Isolation Actions Behavior

### Retry Logic

All isolation actions use **linear backoff** retry logic:

- **Max attempts**: Configurable (`retry_max_attempts`, default: 3)
- **Backoff**: `retry_backoff_base_ms * attempt` (e.g., 500ms, 1000ms, 1500ms)
- **Timeout**: Per-attempt timeout (`action_timeout_secs`, default: 30s)

### Partial Failure Handling

For `NetworkDisconnect` with multiple networks:
- All networks are attempted even if some fail
- Errors are collected and reported as a single `IsolationFailed` error
- On retry, already-disconnected networks succeed (Docker disconnect is idempotent)

### Action Events

After each isolation action (success or failure), an `ActionEvent` is emitted:

```rust
use ironpost_core::event::ActionEvent;

// ActionEvent fields:
// - action_type: "container_pause", "container_stop", "container_network_disconnect"
// - target: container ID
// - success: true/false
// - metadata.trace_id: links back to the originating AlertEvent
```

## Testing

### Using MockDockerClient

The `DockerClient` trait allows testing without a Docker daemon:

```rust,ignore
// Note: MockDockerClient is available in tests but not exposed in the public API
// This example shows the testing pattern used internally

use ironpost_container_guard::docker::MockDockerClient;
use ironpost_container_guard::ContainerGuardBuilder;
use ironpost_core::types::ContainerInfo;
use std::sync::Arc;
use std::time::SystemTime;

#[tokio::test]
async fn test_pause_action() {
    // Setup mock with test containers
    let client = Arc::new(MockDockerClient::new().with_containers(vec![
        ContainerInfo {
            id: "abc123".to_owned(),
            name: "web-server".to_owned(),
            image: "nginx:latest".to_owned(),
            status: "running".to_owned(),
            created_at: SystemTime::now(),
        },
    ]));

    // Build guard with mock client
    let (mut guard, _) = ContainerGuardBuilder::new()
        .docker_client(client)
        .build()?;

    // Test isolation logic...
}
```

### Simulating Failures

```rust,ignore
// Note: MockDockerClient is available in tests but not exposed in the public API
use ironpost_container_guard::docker::MockDockerClient;

let client = MockDockerClient::new()
    .with_containers(vec![/* ... */])
    .with_failing_actions(); // All actions will fail

// Test retry logic, error handling, etc.
```

## Configuration

### ContainerGuardConfig

All configuration fields with their defaults and validation bounds:

| Field | Default | Min | Max | Description |
|-------|---------|-----|-----|-------------|
| `enabled` | `false` | - | - | Whether the guard is active |
| `docker_socket` | `/var/run/docker.sock` | - | - | Docker daemon socket path |
| `poll_interval_secs` | `10` | 1 | 3600 | Container inventory refresh interval |
| `policy_path` | `/etc/ironpost/policies` | - | - | TOML policy directory |
| `auto_isolate` | `false` | - | - | Automatically execute isolation actions |
| `max_concurrent_actions` | `10` | 1 | 100 | Max simultaneous isolations |
| `action_timeout_secs` | `30` | 1 | 300 | Timeout per isolation action |
| `retry_max_attempts` | `3` | 0 | 10 | Max retry attempts for failed actions |
| `retry_backoff_base_ms` | `500` | 0 | 30000 | Base backoff interval |
| `container_cache_ttl_secs` | `60` | 1 | 3600 | Container inventory cache TTL |

### Environment Variable Overrides

Override configuration via environment variables:

```bash
export IRONPOST_CONTAINER_GUARD_ENABLED=true
export IRONPOST_CONTAINER_GUARD_DOCKER_SOCKET=/run/docker.sock
export IRONPOST_CONTAINER_GUARD_POLL_INTERVAL_SECS=5
export IRONPOST_CONTAINER_GUARD_AUTO_ISOLATE=true
export IRONPOST_CONTAINER_GUARD_RETRY_MAX_ATTEMPTS=5
```

## Limitations and Known Issues

### ⚠️ Restart Not Supported After `stop()`

The guard **cannot be restarted** after calling `stop()`. The alert receiver channel is consumed on `start()` and not recreated. To restart the guard, rebuild it via `ContainerGuardBuilder`.

### ⚠️ Label-Based Filtering Not Implemented

The `labels` field in `TargetFilter` is parsed but **not evaluated**. Policies with non-empty `labels` are rejected during validation to prevent a false sense of security.

### ⚠️ Empty Filters Match All Containers

Policies with empty `container_names` and `image_patterns` match **all containers**. This is dangerous in production. Always specify explicit patterns.

### ⚠️ First Match Wins (Non-Deterministic Container Selection)

The guard iterates all cached containers (from a `HashMap`) and applies the first matching policy to the first matching container. `HashMap` iteration order is non-deterministic. If a wildcard policy matches multiple containers, the isolated container is arbitrary.

**Mitigation**: Use specific container name/image patterns to target exactly the containers you intend to isolate.

### ⚠️ Partial Network Disconnect Retry Re-Executes Succeeded Operations

When `NetworkDisconnect` fails for some networks, the retry re-attempts all networks (including already-disconnected ones). Docker's disconnect operation is idempotent, so this is safe but inefficient.

## Examples

See the `examples/policies/` directory for example TOML policies:

- [`critical-network-isolate.toml`](../../examples/policies/critical-network-isolate.toml): Network isolation for Critical alerts
- [`high-web-pause.toml`](../../examples/policies/high-web-pause.toml): Pause web containers on High alerts
- [`medium-database-stop.toml`](../../examples/policies/medium-database-stop.toml): Stop database containers on Medium alerts

## See Also

- [`ironpost-core`](https://docs.rs/ironpost-core): Core types and traits
- [`ironpost-log-pipeline`](https://docs.rs/ironpost-log-pipeline): Log analysis and alert generation
- [`ironpost-ebpf-engine`](https://docs.rs/ironpost-ebpf-engine): eBPF-based network detection
- [Ironpost Architecture](../../docs/architecture.md): System-wide architecture documentation

## License

This project is part of the Ironpost security monitoring platform.

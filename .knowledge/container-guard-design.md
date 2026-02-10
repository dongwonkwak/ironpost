# Container Guard Design Document

## 1. Module Overview

`ironpost-container-guard` is responsible for Docker container security monitoring and
automatic isolation. It receives security alerts from other modules (ebpf-engine, log-pipeline)
via `tokio::mpsc` channels and executes appropriate isolation actions on containers
through the Docker API (bollard crate).

### Core Responsibilities
- Watch Docker container runtime events (create, start, stop, delete)
- Evaluate security policies against incoming alerts
- Execute isolation actions (network disconnect, pause, stop) on target containers
- Emit `ActionEvent` after executing isolation actions
- Implement core `Pipeline` trait for lifecycle management
- Maintain container inventory (list of running containers with metadata)

## 2. Architecture Diagram

```text
                   AlertEvent (from log-pipeline / ebpf-engine)
                              |
                              v
                    +-------------------+
                    |  ContainerGuard   |  <-- Pipeline trait
                    |  (Orchestrator)   |
                    +-------------------+
                     /        |        \
                    v         v         v
           +---------+  +---------+  +-----------+
           | Docker  |  | Policy  |  | Isolation |
           | Monitor |  | Engine  |  | Executor  |
           +---------+  +---------+  +-----------+
                |             |             |
                v             |             v
           +---------+       |       +----------+
           | Docker  |<------+------>| Docker   |
           | API     |              | API      |
           | (trait) |              | (trait)  |
           +---------+              +----------+
                |
                v
           Docker Daemon (/var/run/docker.sock)
```

### Data Flow

```text
AlertEvent ──mpsc──> ContainerGuard
                         |
                    1. Extract container_id from alert
                    2. PolicyEngine.evaluate(alert, container_info)
                         |
                    +---------+
                    | match?  |
                    +---------+
                   /           \
                 Yes            No
                  |              |
           3. IsolationExecutor  (log + skip)
              .execute(action)
                  |
           4. ActionEvent
              ──mpsc──> downstream
```

## 3. Core Types and Traits

### ContainerGuard (Orchestrator)
Main struct implementing `Pipeline` trait. Owns all sub-components.

```rust
pub struct ContainerGuard {
    config: ContainerGuardConfig,
    state: GuardState,
    docker: Arc<dyn DockerClient>,
    policy_engine: PolicyEngine,
    monitor: DockerMonitor,
    executor: IsolationExecutor,
    alert_rx: Option<mpsc::Receiver<AlertEvent>>,
    action_tx: mpsc::Sender<ActionEvent>,
    tasks: Vec<JoinHandle<()>>,
}
```

### DockerClient (Trait for Testability)
Abstraction over bollard Docker API for mocking in tests.

```rust
pub trait DockerClient: Send + Sync + 'static {
    fn list_containers(&self) -> BoxFuture<'_, Result<Vec<ContainerInfo>, ContainerGuardError>>;
    fn inspect_container(&self, id: &str) -> BoxFuture<'_, Result<ContainerInfo, ContainerGuardError>>;
    fn stop_container(&self, id: &str) -> BoxFuture<'_, Result<(), ContainerGuardError>>;
    fn pause_container(&self, id: &str) -> BoxFuture<'_, Result<(), ContainerGuardError>>;
    fn unpause_container(&self, id: &str) -> BoxFuture<'_, Result<(), ContainerGuardError>>;
    fn disconnect_network(&self, id: &str, network: &str) -> BoxFuture<'_, Result<(), ContainerGuardError>>;
}
```

### IsolationAction
Enum representing possible isolation actions.

```rust
pub enum IsolationAction {
    NetworkDisconnect { networks: Vec<String> },
    Pause,
    Stop,
}
```

### SecurityPolicy
Defines when and how to isolate a container.

```rust
pub struct SecurityPolicy {
    pub id: String,
    pub name: String,
    pub description: String,
    pub enabled: bool,
    pub severity_threshold: Severity,
    pub target_filter: TargetFilter,
    pub action: IsolationAction,
}
```

### ContainerEvent
Internal event type for Docker container lifecycle events.

```rust
pub struct ContainerEvent {
    pub id: String,
    pub metadata: EventMetadata,
    pub container_id: String,
    pub container_name: String,
    pub event_kind: ContainerEventKind,
}

pub enum ContainerEventKind {
    Created,
    Started,
    Stopped,
    Deleted,
    Paused,
    Unpaused,
    NetworkDisconnected { network: String },
}
```

## 4. Docker API Integration Strategy

### bollard Crate Usage
- `bollard::Docker::connect_with_local_defaults()` for socket connection
- `docker.list_containers()` for inventory
- `docker.events()` as a `Stream` for real-time event watching
- `docker.stop_container()`, `docker.pause_container()`, `docker.disconnect_network()`
  for isolation actions
- Wrapped behind `DockerClient` trait so tests can use `MockDockerClient`

### Connection Management
- Single `bollard::Docker` instance, shared via `Arc`
- Connection health checked in `Pipeline::health_check()`
- Reconnection on socket error with exponential backoff

## 5. Event Flow

1. **Alert Ingestion**: `AlertEvent` arrives via `tokio::mpsc::Receiver`
2. **Container Resolution**: Extract container ID from alert fields
   (alert.description, custom fields, or container metadata)
3. **Policy Evaluation**: `PolicyEngine` checks all enabled policies
   - Does severity meet threshold?
   - Does target filter match?
4. **Isolation Execution**: `IsolationExecutor` calls Docker API
   - Network disconnect, pause, or stop
   - Retry with backoff on transient failures
5. **Action Reporting**: `ActionEvent` sent via `tokio::mpsc::Sender`
   with success/failure status and trace_id from the originating alert

## 6. Policy Engine Design

### Policy Loading
- Policies loaded from TOML files in the configured policy directory
- Hot-reload via `tokio::watch` channel (config change propagation)
- Default built-in policies (e.g., "isolate on Critical severity")

### Policy Evaluation
- Policies evaluated in priority order
- First matching policy wins (short-circuit)
- `TargetFilter` supports:
  - Container name patterns (glob)
  - Image name patterns
  - Label selectors

### Policy Structure (TOML)
```toml
[[policy]]
id = "critical-network-isolate"
name = "Isolate on Critical Alert"
enabled = true
severity_threshold = "Critical"

[policy.target_filter]
container_names = ["*"]
image_patterns = ["*"]

[policy.action]
type = "network_disconnect"
networks = ["bridge"]
```

## 7. Error Handling Strategy

### ContainerGuardError
Domain-specific error enum with `thiserror`, converted to
`IronpostError::Container(ContainerError)` for upstream propagation.

```rust
pub enum ContainerGuardError {
    DockerApi(String),
    DockerConnection(String),
    IsolationFailed { container_id: String, reason: String },
    PolicyLoad { path: String, reason: String },
    PolicyValidation { policy_id: String, reason: String },
    ContainerNotFound(String),
    Config { field: String, reason: String },
    Channel(String),
}
```

### Recovery Strategy
- Docker API transient errors: retry with exponential backoff (max 3 attempts)
- Policy load errors: log warning, continue with existing policies
- Channel errors: log error, attempt reconnection
- Fatal errors (Docker socket unavailable): report Unhealthy via health_check

## 8. Configuration Schema

Uses core's `ContainerConfig` as base, extends with guard-specific settings:

```rust
pub struct ContainerGuardConfig {
    pub enabled: bool,
    pub docker_socket: String,
    pub poll_interval_secs: u64,
    pub policy_path: String,
    pub auto_isolate: bool,
    // Extended fields
    pub max_concurrent_actions: usize,
    pub action_timeout_secs: u64,
    pub retry_max_attempts: u32,
    pub retry_backoff_base_ms: u64,
    pub container_cache_ttl_secs: u64,
}
```

## 9. Testing Strategy

### Unit Tests
- `MockDockerClient` implementing `DockerClient` trait
- Policy evaluation logic (various severity/filter combinations)
- Config validation
- Error conversion

### Integration Tests
- Full pipeline lifecycle (start/stop/health_check)
- Alert -> Policy -> Action flow with mock Docker
- Multiple policies, priority ordering
- Container event monitoring with mock events

### No Live Docker Tests in CI
- All Docker API calls go through `DockerClient` trait
- `MockDockerClient` returns configurable responses
- Live Docker tests marked with `#[ignore]` for manual execution

## 10. Module Directory Structure

```
crates/container-guard/
  Cargo.toml
  README.md
  src/
    lib.rs          -- module root, re-exports
    error.rs        -- ContainerGuardError enum
    config.rs       -- ContainerGuardConfig + builder
    event.rs        -- ContainerEvent, ContainerEventKind, Event trait impl
    policy.rs       -- SecurityPolicy, TargetFilter, PolicyEngine
    isolation.rs    -- IsolationAction, IsolationExecutor
    monitor.rs      -- DockerMonitor (watches container events)
    guard.rs        -- ContainerGuard (main orchestrator, Pipeline impl)
    docker.rs       -- DockerClient trait + BollardDockerClient impl + MockDockerClient
```

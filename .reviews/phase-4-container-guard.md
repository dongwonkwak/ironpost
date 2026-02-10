# Code Review: ironpost-container-guard -- Phase 4 Container Guard (Re-review)

## Summary
- Reviewer: reviewer (security-focused, comprehensive re-review)
- Date: 2026-02-10 (re-review after initial fixes applied)
- Target: `crates/container-guard/` (10 source files, 1 integration test file, 3 policy examples)
- Result: **Conditional Approval** -- remaining High and new findings should be addressed before merge

### Files Reviewed
| File | Lines | Status |
|------|-------|--------|
| `crates/container-guard/Cargo.toml` | 20 | Reviewed |
| `crates/container-guard/README.md` | 32 | Reviewed |
| `crates/container-guard/src/lib.rs` | 63 | Reviewed |
| `crates/container-guard/src/error.rs` | 211 | Reviewed |
| `crates/container-guard/src/config.rs` | 509 | Reviewed |
| `crates/container-guard/src/event.rs` | 197 | Reviewed |
| `crates/container-guard/src/docker.rs` | 664 | Reviewed |
| `crates/container-guard/src/policy.rs` | 1223 | Reviewed |
| `crates/container-guard/src/isolation.rs` | 798 | Reviewed |
| `crates/container-guard/src/monitor.rs` | 757 | Reviewed |
| `crates/container-guard/src/guard.rs` | 783 | Reviewed |
| `crates/container-guard/src/enforcer.rs` | 4 | Reviewed |
| `crates/container-guard/tests/integration_tests.rs` | 985 | Reviewed |
| `examples/policies/critical-network-isolate.toml` | 21 | Reviewed |
| `examples/policies/high-web-pause.toml` | 22 | Reviewed |
| `examples/policies/medium-database-stop.toml` | 22 | Reviewed |
| `examples/policies/README.md` | 166 | Reviewed |

### Build Status
- `cargo fmt --check`: PASS
- `cargo clippy -- -D warnings`: PASS (0 warnings)
- `cargo test -p ironpost-container-guard`: PASS (202 tests: 185 unit + 17 integration)
- No `unsafe` blocks in entire crate
- No `as` numeric casting in production code
- No `unwrap()` in production code (all 180+ occurrences are in `#[cfg(test)]` blocks)
- No `println!`/`eprintln!` in production code
- No `panic!`/`todo!`/`unimplemented!` in production code
- No `std::sync::Mutex` in production or test code (all use `tokio::sync::Mutex`)

### Previous Review Resolution Status

The initial review (2026-02-10) found 29 issues. The following Critical/High items have been resolved:

| ID | Issue | Status |
|----|-------|--------|
| C1 | Unbounded container cache | RESOLVED -- `MAX_CACHED_CONTAINERS` (10,000) added |
| C2 | Policy file size unlimited | RESOLVED -- `MAX_POLICY_FILE_SIZE` (10 MB) added |
| C3 | Policy count unlimited | RESOLVED -- `MAX_POLICIES` (1,000) added |
| C4 | Broken restart channel | PARTIALLY RESOLVED -- see NEW-C1 below |
| C5 | `std::sync::Mutex` in async tests | RESOLVED -- all converted to `tokio::sync::Mutex` |
| H1 | No container ID validation | RESOLVED -- `validate_container_id()` added |
| H2 | Path traversal in policy loading | RESOLVED -- `canonicalize()` + directory boundary check added |
| H5 | TOCTOU in policy directory loading | RESOLVED -- `exists()`/`is_dir()` checks removed |

---

## Findings (Current State)

### Critical

#### NEW-C1: `stop()` still creates an orphaned channel -- restart remains broken

**File**: `crates/container-guard/src/guard.rs`, lines 279-283

**Code**:
```rust
// Recreate alert channel for restart support
let (tx, rx) = mpsc::channel(256);
// Store the receiver for potential restart
self.alert_rx = Some(rx);
// Note: The sender needs to be reconnected by the daemon
drop(tx); // Close immediately as we can't reconnect it ourselves
```

**Problem**: The previous review (C4) noted this issue and the BOARD.md states it was "fixed" by adding documentation. However, the actual fix is inadequate: the code still creates a new channel and immediately drops the sender. This means:

1. After `stop()`, `self.alert_rx` holds a receiver whose only sender has been dropped.
2. If someone calls `start()` again, the spawned processing task will call `alert_rx.recv()` which will immediately return `None` (channel closed), causing the task to exit immediately with "alert channel closed, stopping guard processing loop".
3. The comment says "The sender needs to be reconnected by the daemon" but there is no public API to provide a new sender. The `alert_rx` field is private and `ContainerGuardBuilder::alert_receiver()` is only usable during construction.
4. The `test_rapid_start_stop_cycles` test (integration_tests.rs:767) only verifies the second `stop()` fails, NOT that a second `start()` works. No test verifies restart functionality.

This is a logic error that silently breaks a core lifecycle operation. The `Pipeline` trait's `start()`/`stop()` contract implies restartability.

**Severity rationale**: Critical because this violates the `Pipeline` trait contract and could cause silent operational failures if the daemon attempts to restart the container guard module.

**Suggested Fix**: Either:
- (a) Set `self.alert_rx = None` in `stop()` and have `start()` return an error if `alert_rx` is `None`, making the non-restartable behavior explicit and testable.
- (b) Change the guard's state machine to `Stopped` and have `start()` reject calls from `Stopped` state.
- (c) Document the limitation AND have `start()` from `Stopped` state return an explicit error (not silently spawn a task that immediately exits).

---

#### NEW-C2: `load_policies_from_dir` calls `canonicalize()` on the same directory path on every loop iteration

**File**: `crates/container-guard/src/policy.rs`, lines 343-352

**Code**:
```rust
for entry in entries {
    // ...
    let canonical_path = match path.canonicalize() { ... };

    // Verify canonical path is still within the policy directory
    let canonical_dir = match dir_path.canonicalize() {  // <-- called EVERY iteration
        Ok(d) => d,
        Err(e) => { ... }
    };
    if !canonical_path.starts_with(&canonical_dir) { ... }
}
```

**Problem**: `dir_path.canonicalize()` is called inside the loop for every directory entry, but it does not change between iterations. This creates two problems:

1. **TOCTOU between iterations**: The canonical directory could change between loop iterations if the directory is replaced by a symlink mid-traversal. An attacker could:
   - Wait for the first `canonicalize()` to succeed with the real directory
   - Replace the directory with a symlink to a different location
   - The next iteration's `canonicalize()` returns the new target
   - Now `canonical_path.starts_with(&canonical_dir)` passes because the file is "within" the new target directory

2. **Performance**: Unnecessary syscalls for each entry. Should be computed once before the loop.

**Severity rationale**: The TOCTOU window is narrow but exploitable in high-security environments. Combined with the path traversal defense being the only protection, this undermines the H2 fix.

**Suggested Fix**: Compute `canonical_dir` once before the loop:
```rust
let canonical_dir = dir_path.canonicalize().map_err(|e| ...)?;
for entry in entries {
    let canonical_path = path.canonicalize()?;
    if !canonical_path.starts_with(&canonical_dir) { ... }
}
```

---

### High

#### H3: Alert-to-container matching applies isolation to first arbitrary container (STILL OPEN)

**File**: `crates/container-guard/src/guard.rs`, lines 213-249

**Problem**: Unchanged from initial review. When an alert arrives, the guard iterates ALL cached containers and applies isolation to the first one whose policy matches. Because `all_containers()` returns values from a `HashMap`, the iteration order is non-deterministic. A wildcard `TargetFilter` (empty lists, which is the default) means a single alert isolates a random container.

The `critical-network-isolate.toml` example policy uses `container_names = []` and `image_patterns = []`, meaning it matches ALL containers. Deploying this example policy would cause every Critical alert to isolate one arbitrary container.

**Risk**: In production with 100+ containers, a single false positive Critical alert isolates a random production service.

**Status**: Known limitation, but the example policies make it easy to deploy unsafely.

**Suggested Fix (minimum)**: The example `critical-network-isolate.toml` should NOT use empty filters. Change to a specific pattern like `container_names = ["*"]` is not better, but at minimum add a prominent comment warning about the wildcard behavior, or change the examples to target specific containers.

---

#### H4: Network disconnect partial failure with retry re-executes already-succeeded disconnects (STILL OPEN)

**File**: `crates/container-guard/src/isolation.rs`, lines 190-207

**Problem**: Unchanged from initial review. When disconnecting multiple networks, if the second network fails, the retry logic replays the entire list from scratch, re-attempting the first (already disconnected) network. Docker may return an error or silently succeed for already-disconnected networks, creating unpredictable behavior during retries.

---

#### H6: `TargetFilter.labels` field is parsed but never evaluated (STILL OPEN)

**File**: `crates/container-guard/src/policy.rs`, lines 36-37, 45-58

**Problem**: Unchanged from initial review. The `labels` field is deserialized but `matches()` ignores it entirely. Users who set `labels = ["env=prod"]` get a false sense of security -- their policy silently matches ALL containers regardless of labels.

The test `target_filter_with_labels` (line 1125) even documents this behavior: "Labels are currently not implemented in matching logic." But this is a test comment, not visible to policy authors.

---

#### H7: Blocking file I/O in sync functions called from async context (STILL OPEN)

**File**: `crates/container-guard/src/policy.rs`, lines 271-303, 312-387

**Problem**: `load_policy_from_file()` and `load_policies_from_dir()` perform synchronous file I/O (`std::fs::metadata`, `std::fs::read_to_string`, `std::fs::read_dir`, `Path::canonicalize`). These are public functions that are likely called from async contexts. Per CLAUDE.md, blocking I/O should use `tokio::task::spawn_blocking`.

---

#### NEW-H1: `validate_container_id` uses wrong error variant for invalid input

**File**: `crates/container-guard/src/docker.rs`, lines 19-27

**Code**:
```rust
fn validate_container_id(id: &str) -> Result<(), ContainerGuardError> {
    if id.is_empty() || id.len() > 64 {
        return Err(ContainerGuardError::ContainerNotFound(id.to_owned()));
    }
    if !id.chars().all(|c| c.is_ascii_hexdigit()) {
        return Err(ContainerGuardError::ContainerNotFound(id.to_owned()));
    }
    Ok(())
}
```

**Problem**: Invalid container IDs (e.g., containing special characters like `"../../../etc"`) return `ContainerGuardError::ContainerNotFound`. This is semantically wrong -- the container was not "not found"; the ID was malformed input. This mixes input validation failures with legitimate "container doesn't exist" responses from Docker, making it impossible for callers to distinguish between:
- "The container ID was garbage/injection attempt" (should be logged as a security event)
- "The container was deleted between check and use" (normal operational condition)

The `From<ContainerGuardError> for IronpostError` conversion maps `ContainerNotFound` to `ContainerError::NotFound`, which could trigger different retry/recovery logic than a validation error should.

**Suggested Fix**: Return `ContainerGuardError::DockerApi("invalid container ID: ...")` or add a dedicated `InvalidInput` variant.

---

#### NEW-H2: Processing task creates a separate `DockerMonitor` instance, losing cache state

**File**: `crates/container-guard/src/guard.rs`, lines 189

**Code**:
```rust
let mut monitor = DockerMonitor::new(Arc::clone(&docker), poll_interval, cache_ttl);
```

**Problem**: The `start()` method creates a NEW `DockerMonitor` inside the spawned task instead of using `self.monitor`. This means:
1. The initial `self.monitor.refresh()` (line 151) populates the guard's monitor cache, but the spawned task has a completely empty monitor.
2. `self.container_count()` (line 119) reports the guard's monitor count, which is stale/different from what the processing task sees.
3. The first alert processed by the spawned task will trigger a full Docker API refresh (because the new monitor has never been polled), adding latency to the first isolation action.

This is not just a performance issue -- it means the guard's public API (`container_count()`) reports incorrect state, and the initial refresh work (lines 151-158) is wasted.

---

#### NEW-H3: `list_containers` with `all: true` returns stopped/exited containers

**File**: `crates/container-guard/src/docker.rs`, lines 118-119

**Code**:
```rust
let options = ListContainersOptions::<String> {
    all: true,
    ..Default::default()
};
```

**Problem**: Setting `all: true` returns ALL containers including stopped, exited, and dead ones. The isolation executor then tries to pause/stop/disconnect these non-running containers, which will fail and increment `isolation_failures`. The container list should be filtered to running containers only, or the policy evaluation should check container status before attempting isolation.

---

### Medium

#### M1: Docker socket path not validated for path traversal (STILL OPEN)

**File**: `crates/container-guard/src/config.rs`, lines 135-140

**Problem**: Unchanged. `docker_socket` is only checked for emptiness, not for absolute path or `..` components.

---

#### M2: Glob pattern matching has potential quadratic backtracking (STILL OPEN)

**File**: `crates/container-guard/src/policy.rs`, lines 67-108

**Problem**: Unchanged. The backtracking glob matcher could exhibit poor performance with pathological patterns from user-supplied TOML files. The algorithm is O(n*m) worst case with the star-backtracking optimization, but patterns like `*a*a*a*a*b` against long strings of `a` characters can still cause significant backtracking.

---

#### M3: `inspect_container` uses fragile string matching for 404 detection (STILL OPEN)

**File**: `crates/container-guard/src/docker.rs`, line 159

**Code**: `if e.to_string().contains("404")`

**Problem**: Unchanged. String matching for HTTP status code detection is fragile. Should use bollard's typed error variants.

---

#### M4: No duplicate policy ID detection (STILL OPEN)

**File**: `crates/container-guard/src/policy.rs`, lines 191-202

**Problem**: `add_policy()` does not check for duplicate IDs. Multiple policies with the same ID can coexist.

---

#### M5: `enforcer.rs` is a dead file not referenced anywhere (STILL OPEN)

**File**: `crates/container-guard/src/enforcer.rs`

**Content**: 3 lines of migration comment. Not referenced in `lib.rs`. Should be deleted.

---

#### M6: Guard processing loop iterates all containers non-deterministically (STILL OPEN)

**File**: `crates/container-guard/src/guard.rs`, lines 213-249

**Problem**: Compounds with H3. HashMap iteration order is non-deterministic.

---

#### M7: Docker connection timeout hardcoded to 120 seconds (STILL OPEN)

**File**: `crates/container-guard/src/docker.rs`, line 102

**Code**: `bollard::Docker::connect_with_socket(socket_path, 120, bollard::API_DEFAULT_VERSION)`

---

#### M8: Policy string fields have no length limits (STILL OPEN)

**File**: `crates/container-guard/src/policy.rs`, lines 133-151

**Problem**: `SecurityPolicy::validate()` only checks for empty `id` and `name`. Fields like `description`, `id`, and `name` have no maximum length, despite `MAX_POLICY_FILE_SIZE` (10MB) limiting total file size. A single policy file under 10MB could have a 9MB `description`.

---

#### NEW-M1: `ContainerGuardConfig::validate()` does not validate `policy_path`

**File**: `crates/container-guard/src/config.rs`, lines 90-143

**Problem**: The `validate()` method validates all numeric fields with upper/lower bounds but performs zero validation on `policy_path`. An empty policy path is explicitly allowed (test at line 487: "Empty policy path is allowed"). However:
- No absolute path check (relative paths create ambiguity based on working directory)
- No length limit (could be an extremely long path)
- No null byte check (null bytes in paths cause undefined behavior on some platforms)

---

#### NEW-M2: `BollardDockerClient::list_containers` uses `unwrap_or_default` on critical fields

**File**: `crates/container-guard/src/docker.rs`, lines 131-141

**Code**:
```rust
let id = container.id.unwrap_or_default();
let names = container.names.unwrap_or_default();
let name = names.first().map(|n| n.trim_start_matches('/').to_owned()).unwrap_or_default();
let image = container.image.unwrap_or_default();
```

**Problem**: If Docker returns a container with `id: None`, we create a `ContainerInfo` with `id: ""`. This empty-ID container gets inserted into the `DockerMonitor`'s HashMap with key `""`, which could collide with other empty-ID containers and cause state corruption. The container ID is a primary key and should never be empty.

**Suggested Fix**: Skip containers that have `None` for `id`:
```rust
let id = match container.id {
    Some(id) if !id.is_empty() => id,
    _ => { tracing::warn!("skipping container with empty id"); continue; }
};
```

---

#### NEW-M3: `DockerMonitor::get_container` partial ID matching can be exploited

**File**: `crates/container-guard/src/monitor.rs`, lines 96-101

**Code**:
```rust
let found = self.containers.iter()
    .find(|(id, _)| id.starts_with(container_id))
    .map(|(_, c)| c.clone());
```

**Problem**: Partial ID matching with `starts_with` is ambiguous. If the cache contains containers `abc123` and `abc456`, a lookup for `abc` will match one of them non-deterministically (HashMap iteration order). The test `get_container_ambiguous_partial_id` (line 411) acknowledges this: "Should return first match" -- but "first" is random.

More importantly, this partial matching is only applied to cached containers and NOT to Docker API lookups (which go directly to `self.docker.inspect_container(container_id)`). This creates inconsistent behavior: the same partial ID might resolve to different containers depending on whether the cache was populated.

---

### Low

#### L1: Error conversion for Config/Channel maps to DockerApi (STILL OPEN)

**File**: `crates/container-guard/src/error.rs`, lines 91-93

---

#### L2: `bollard` not using workspace dependency management (STILL OPEN)

**File**: `crates/container-guard/Cargo.toml`, line 16

---

#### L3: MockDockerClient is cfg(test)-gated, integration tests must duplicate it (STILL OPEN)

**File**: `crates/container-guard/src/docker.rs` vs `tests/integration_tests.rs`

---

#### L5: `ContainerEvent::Display` uses byte-based string slicing (STILL OPEN)

**File**: `crates/container-guard/src/event.rs`, lines 120-122

---

#### L8: No tracing instrumentation on BollardDockerClient methods (STILL OPEN)

**File**: `crates/container-guard/src/docker.rs`, lines 114-256

---

#### NEW-L1: `IsolationExecutor::execute_with_retry` backoff is linear, not exponential

**File**: `crates/container-guard/src/isolation.rs`, lines 146-154

**Code**:
```rust
for attempt in 0..=self.max_retries {
    if attempt > 0 {
        let backoff = self.retry_backoff_base * attempt;
        // ...
        tokio::time::sleep(backoff).await;
    }
```

**Problem**: The comment and documentation describe "exponential backoff", but the actual implementation is linear: `base * attempt` produces `base, 2*base, 3*base, ...` instead of `base, 2*base, 4*base, ...`. True exponential backoff would be `base * 2^(attempt-1)`.

With `retry_backoff_base_ms = 500` and `max_retries = 3`:
- Current (linear): 500ms, 1000ms, 1500ms (total 3s)
- Expected (exponential): 500ms, 1000ms, 2000ms (total 3.5s)

While the difference is small with low retry counts, it violates the principle of least surprise. The test `executor_exponential_backoff_timing` (line 634) passes because it only checks minimum elapsed time (`>= 140ms`), not the exponential property.

---

#### NEW-L2: `guard.rs` `stop()` logs "alert source must be reconnected for restart" but restart is impossible

**File**: `crates/container-guard/src/guard.rs`, line 286

**Code**:
```rust
info!("container guard stopped (note: alert source must be reconnected for restart)");
```

**Problem**: The log message suggests restart is possible with reconnection, but there is no public API to reconnect the alert source. This creates misleading operational guidance in production logs.

---

#### NEW-L3: `ContainerGuardBuilder::build()` does not validate `alert_rx` presence

**File**: `crates/container-guard/src/guard.rs`, lines 376-418

**Problem**: The builder does not require `alert_rx` to be set. If `build()` is called without `alert_receiver()`, `self.alert_rx` is `None`. When `start()` is called, line 161:
```rust
let mut alert_rx = self.alert_rx.take().ok_or(IronpostError::Pipeline(
    ironpost_core::error::PipelineError::AlreadyRunning,
))?;
```
This returns `PipelineError::AlreadyRunning`, which is semantically wrong. The guard is not "already running" -- it was never given an alert receiver. The error message misleads the caller.

---

#### NEW-L4: `load_policies_from_dir` does not enforce `MAX_POLICIES` limit

**File**: `crates/container-guard/src/policy.rs`, lines 312-387

**Problem**: The function collects all valid policies from the directory into a `Vec<SecurityPolicy>` without checking `MAX_POLICIES`. The limit is only enforced when policies are later added to `PolicyEngine` via `add_policy()`. If a directory has 5000 valid TOML files, all 5000 will be loaded into memory before the caller discovers they cannot all be added.

**Suggested Fix**: Add early termination when `policies.len() >= MAX_POLICIES`.

---

#### NEW-L5: Example policies README contains Rust code blocks that might confuse `doc = include_str!`

**File**: `examples/policies/README.md`, lines 77-94

**Problem**: The README contains Rust code blocks (```rust ... ```) but the crate's `lib.rs` includes `#![doc = include_str!("../README.md")]` for the **crate** README, not the examples README. This is not a bug, but worth noting that if examples/policies/README.md were ever included in doc generation, the code blocks would need `ignore` or `text` annotations.

---

#### NEW-L6: Relaxed ordering on atomic counters may miss updates in health checks

**File**: `crates/container-guard/src/guard.rs`, lines 100-111

**Code**:
```rust
pub fn alerts_processed(&self) -> u64 {
    self.alerts_processed.load(Ordering::Relaxed)
}
```

**Problem**: The counters use `Ordering::Relaxed` for both stores (in the spawned task, line 194) and loads (in the public API). While `Relaxed` is sufficient for counter semantics (no need for synchronization with other operations), it means the counter values observed via the public API may be arbitrarily stale on weakly-ordered architectures. This is acceptable for metrics but should be documented.

---

## Positive Patterns Observed

1. **Clean error hierarchy**: `ContainerGuardError` with `thiserror` and proper `From` conversion to `IronpostError` follows the project convention.

2. **Docker API abstraction via trait**: The `DockerClient` trait pattern enables excellent testability with zero Docker dependency in tests.

3. **Configuration validation**: `ContainerGuardConfig::validate()` enforces bounds on ALL numeric fields with named constants for upper limits. The builder pattern with validation-on-build is idiomatic.

4. **Retry with backoff**: `IsolationExecutor::execute_with_retry()` correctly implements timeout wrapping per attempt and configurable retry parameters.

5. **No unsafe code**: Zero `unsafe` blocks in the entire crate. No `as` numeric casting. All conversions use `try_from()` with fallback.

6. **Proper use of `tracing`**: All logging uses `tracing` macros (`info!`, `warn!`, `error!`, `debug!`). No `println!` or `eprintln!` anywhere.

7. **Bounded channels**: Every `mpsc::channel()` call uses bounded capacity (16 or 256). No `unbounded_channel` usage.

8. **Comprehensive test coverage**: 202 tests covering unit, edge cases, and integration scenarios with custom mock Docker clients for partial failure, concurrent access, and connection failure testing.

9. **No `unwrap()` in production code**: All production paths use `?`, `map_err`, `unwrap_or_default`, or `unwrap_or_else`.

10. **Atomic counters for metrics**: `AtomicU64` for `alerts_processed`, `isolations_executed`, `isolation_failures` avoids lock contention.

11. **Event trait implementation**: Correct implementation of core `Event` trait with proper `EventMetadata` propagation and trace ID threading.

12. **Input validation on container IDs**: The `validate_container_id()` function enforces hex-only characters and maximum 64-character length as defense-in-depth against injection.

13. **Policy file size limit**: `MAX_POLICY_FILE_SIZE` (10MB) prevents OOM from malicious TOML files.

14. **Container cache limit**: `MAX_CACHED_CONTAINERS` (10,000) prevents unbounded memory growth.

15. **Path traversal protection**: `canonicalize()` + directory boundary check in `load_policies_from_dir()`.

16. **Shared policy engine**: The guard uses `Arc<Mutex<PolicyEngine>>` and shares it with the spawned task via `Arc::clone`, allowing runtime policy updates to be reflected in the processing loop.

---

## Finding Summary

| Severity | Count | IDs |
|----------|-------|-----|
| Critical | 2 | NEW-C1, NEW-C2 |
| High | 5 | H3, H4, H6, NEW-H1, NEW-H2, NEW-H3 |
| Medium | 10 | M1, M2, M3, M4, M5, M6, M7, M8, NEW-M1, NEW-M2, NEW-M3 |
| Low | 10 | L1, L2, L3, L5, L8, NEW-L1, NEW-L2, NEW-L3, NEW-L4, NEW-L6 |
| **Total** | **27** | |

### Resolved from Initial Review
| ID | Resolution |
|----|------------|
| C1 | Fixed: `MAX_CACHED_CONTAINERS` added |
| C2 | Fixed: `MAX_POLICY_FILE_SIZE` added |
| C3 | Fixed: `MAX_POLICIES` added |
| C5 | Fixed: All `std::sync::Mutex` replaced with `tokio::sync::Mutex` |
| H1 | Fixed: `validate_container_id()` added (but see NEW-H1 for error variant issue) |
| H2 | Fixed: `canonicalize()` + boundary check added (but see NEW-C2 for TOCTOU in loop) |
| H5 | Fixed: `exists()`/`is_dir()` removed |
| L4 | Accepted: UUIDv4 overhead acceptable |
| L6 | Accepted: Serialize derive overhead minimal |
| L7 | Fixed: All mutexes now tokio::sync::Mutex (no more unwrap on std Mutex) |
| L9 | Fixed: Policy engine shared via `Arc<Mutex<PolicyEngine>>` |

### Priority for Resolution

**Must fix (Critical)**:
- NEW-C1: stop()/start() restart is silently broken
- NEW-C2: `canonicalize()` called inside loop creates TOCTOU

**Should fix (High)**:
- H3: Wildcard filter isolates random container
- NEW-H1: Wrong error variant for invalid container IDs
- NEW-H2: Processing task creates separate DockerMonitor
- NEW-H3: `all: true` lists stopped containers for isolation

**Recommended (Medium)**:
- M3: String-based 404 detection
- NEW-M2: Empty container ID from Docker API
- NEW-M3: Ambiguous partial ID matching
- M4: Duplicate policy IDs
- M5: Dead enforcer.rs file
- M1, M2, M7, M8, NEW-M1

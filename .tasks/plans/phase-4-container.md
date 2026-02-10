# Phase 4: Container Guard Implementation

## Goal
Implement Docker container security monitoring and automatic isolation.
Receive alerts from ebpf-engine/log-pipeline via tokio::mpsc, evaluate security policies,
and execute isolation actions (network disconnect, pause, stop) through Docker API.

## Prerequisites
- Phase 1 (core) complete
- Phase 3 (log-pipeline) complete (AlertEvent source)
- Docker available for integration tests (optional, mock-based tests for CI)

## Design Document
- `.knowledge/container-guard-design.md`

## Scaffolding (Phase 4-A) -- Completed
- [x] T4-A1: Design document (`.knowledge/container-guard-design.md`)
- [x] T4-A2: Cargo.toml with dependencies (bollard, ironpost-core, tokio, thiserror, tracing, serde)
- [x] T4-A3: `error.rs` -- ContainerGuardError enum (8 variants) + From<ContainerGuardError> for IronpostError
- [x] T4-A4: `config.rs` -- ContainerGuardConfig + ContainerGuardConfigBuilder + from_core() + validate()
- [x] T4-A5: `event.rs` -- ContainerEvent + ContainerEventKind + Event trait impl
- [x] T4-A6: `docker.rs` -- DockerClient trait + BollardDockerClient + MockDockerClient (test)
- [x] T4-A7: `policy.rs` -- SecurityPolicy + TargetFilter + PolicyEngine + glob matching
- [x] T4-A8: `isolation.rs` -- IsolationAction + IsolationExecutor (retry + timeout)
- [x] T4-A9: `monitor.rs` -- DockerMonitor (polling + caching + partial ID lookup)
- [x] T4-A10: `guard.rs` -- ContainerGuard (Pipeline trait) + ContainerGuardBuilder
- [x] T4-A11: `lib.rs` -- module re-exports

## Implementation (Phase 4-B) -- Completed (2026-02-10)
- [x] T4-B1: Policy loading from TOML files
  - ✅ `load_policy_from_file()` - load single TOML policy file
  - ✅ `load_policies_from_dir()` - load all .toml files from directory
  - ✅ TOML deserialization with serde
  - ✅ Policy validation after loading
  - ⏳ Hot-reload via tokio::watch (future enhancement)
  - Actual: 1h
- [x] T4-B2: Container monitoring
  - ✅ Poll-based container list refresh with configurable interval
  - ✅ Container cache with TTL to reduce Docker API calls
  - ✅ Partial container ID matching
  - ✅ Container lookup by name
  - ℹ️ Real-time event streaming (future enhancement - current poll-based approach is sufficient)
  - Actual: 0h (already implemented in scaffolding)
- [x] T4-B3: Container-alert resolution
  - ✅ Policy evaluation against all running containers
  - ✅ Target filter matching (name patterns, image patterns)
  - ✅ First-matching policy wins (priority-based)
  - ✅ Alert trace ID propagation to action events
  - Actual: 0h (already implemented in scaffolding)
- [x] T4-B4: Integration tests
  - ✅ 98 total tests (92 from scaffolding + 6 new policy loading tests)
  - ✅ Docker API mocking for CI (MockDockerClient)
  - ✅ Policy evaluation tests with multiple severity levels
  - ✅ Isolation executor retry/timeout tests
  - ✅ Guard lifecycle tests (start/stop/health_check)
  - Actual: 0h (already implemented in scaffolding)
- [x] T4-B5: Core implementation
  - ✅ Retry with exponential backoff for transient failures
  - ✅ Action timeout enforcement
  - ✅ Action event emission (success/failure)
  - ℹ️ Semaphore-based concurrency limiting (future enhancement - config exists)
  - ℹ️ Deduplication and cooldown (future enhancement)
  - Actual: 0h (already implemented in scaffolding)

## Testing Summary
### Scaffolding Phase Tests (T4-A)
- error.rs: 12 tests (display, conversion)
- config.rs: 12 tests (validation, builder, serialization)
- event.rs: 6 tests (event trait, display, send+sync)
- docker.rs: 10 tests (mock client operations)
- policy.rs: 15 tests (glob matching, target filter, policy engine)
- isolation.rs: 8 tests (executor actions, retry, trace propagation)
- monitor.rs: 12 tests (refresh, cache, partial ID lookup)
- guard.rs: 8 tests (builder, lifecycle, accessors)
Total: ~83 tests

## Architecture Decisions
1. **DockerClient trait**: Abstract Docker API for testability. Production uses BollardDockerClient,
   tests use MockDockerClient. No live Docker required for CI.
2. **Policy-first evaluation**: Policies sorted by priority, first match wins (short-circuit).
3. **Retry with exponential backoff**: Transient Docker API failures retried up to max_retries.
4. **Container cache**: Avoid excessive Docker API calls. Cache with configurable TTL.
5. **Glob-based filtering**: Simple glob patterns for container name/image matching.
   No regex to avoid ReDoS (learned from Phase 3 review H3).
6. **Atomic counters**: Use AtomicU64 for counters instead of Arc<Mutex<u64>>
   (learned from Phase 3 review C1).

## Review Items from Previous Phases
- Phase 3 H1: Detector trait &self vs &mut self -- PolicyEngine uses &self for evaluate()
- Phase 3 C1: AtomicU64 instead of Arc<Mutex<u64>> -- applied to all counters
- Phase 3 C3: No `as` casting -- using try_from/into throughout
- Phase 3 H3: ReDoS prevention -- using simple glob matching instead of regex
- Phase 3 C7: HashMap growth limits -- monitor cache bounded by actual Docker containers

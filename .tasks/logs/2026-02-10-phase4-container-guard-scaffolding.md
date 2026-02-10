# Phase 4-A: Container Guard Scaffolding

## Date: 2026-02-10
## Agent: architect
## Branch: phase/4-container-guard

## Summary
Designed and scaffolded the `ironpost-container-guard` crate with full type/trait
skeletons, tests, and documentation.

## Deliverables
1. `.knowledge/container-guard-design.md` -- comprehensive design document
2. `crates/container-guard/` -- full crate skeleton (9 source files)
3. `.tasks/plans/phase-4-container.md` -- phase 4 task plan

## Files Created/Modified
- `.knowledge/container-guard-design.md` (new)
- `crates/container-guard/Cargo.toml` (updated)
- `crates/container-guard/README.md` (updated)
- `crates/container-guard/src/lib.rs` (rewritten)
- `crates/container-guard/src/error.rs` (new)
- `crates/container-guard/src/config.rs` (new)
- `crates/container-guard/src/event.rs` (new)
- `crates/container-guard/src/docker.rs` (new)
- `crates/container-guard/src/policy.rs` (rewritten)
- `crates/container-guard/src/isolation.rs` (new)
- `crates/container-guard/src/monitor.rs` (rewritten)
- `crates/container-guard/src/guard.rs` (new)
- `.tasks/plans/phase-4-container.md` (updated)
- `.tasks/BOARD.md` (updated)

## Tests
- error.rs: 12 tests
- config.rs: 12 tests
- event.rs: 6 tests
- docker.rs: 10 tests
- policy.rs: 15 tests
- isolation.rs: 8 tests
- monitor.rs: 12 tests
- guard.rs: 8 tests
- Total: ~83 unit tests

## Architecture Decisions
1. DockerClient trait for testability (MockDockerClient in tests)
2. PolicyEngine with priority-sorted evaluation (first match wins)
3. IsolationExecutor with retry + exponential backoff + timeout
4. DockerMonitor with cache TTL + partial container ID lookup
5. ContainerGuard as Pipeline trait orchestrator
6. Glob matching instead of regex (ReDoS prevention from P3 review)
7. AtomicU64 counters (from P3 review C1)

## Previous Phase Review Items Applied
- P3-C1: AtomicU64 instead of Arc<Mutex<u64>>
- P3-C3: No `as` casting (try_from/into)
- P3-H3: Simple glob matching, no regex
- P3-C7: Container cache bounded by Docker inventory
- P3-H1: PolicyEngine::evaluate() takes &self (not &mut self)

## Removed Files
- `crates/container-guard/src/enforcer.rs` (replaced by isolation.rs + guard.rs)

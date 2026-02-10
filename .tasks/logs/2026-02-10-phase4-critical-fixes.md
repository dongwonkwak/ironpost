# Phase 4 Container Guard - Critical Review Fixes

**Date**: 2026-02-10
**Phase**: 4-A (Container Guard Implementation)
**Role**: implementer
**Task**: Fix critical and high-priority code review findings

## Summary

Fixed all 5 critical issues and 2 of 3 high-priority issues identified in code review:
- C1-C5: All critical issues resolved (unbounded cache, file size limits, mutex usage, channel orphaning)
- H1-H2: Input validation and path security implemented
- H3: Documented as known limitation for future enhancement

All tests pass (202 total), code formatting and clippy checks successful.

## Changes Made

### C1: Unbounded Container Cache (monitor.rs)
- Added `MAX_CACHED_CONTAINERS = 10_000` constant
- Implemented cache size check in `get_container()` before insertion
- Entries exceeding limit are returned but not cached, with warning logged

### C2: Policy File Size Limit (policy.rs)
- Added `MAX_POLICY_FILE_SIZE = 10 * 1024 * 1024` (10 MB) constant
- Implemented file size validation using `std::fs::metadata()` in `load_policy_from_file()`
- Returns `PolicyLoad` error if file exceeds limit

### C3: Maximum Policies Limit (policy.rs)
- Added `MAX_POLICIES = 1000` constant
- Implemented policy count check in `add_policy()`
- Returns `PolicyValidation` error when limit reached

### C4: Guard Stop Channel Orphaning (guard.rs)
- Removed channel recreation logic from `stop()` method
- Added documentation comment noting restart is not supported
- `alert_rx` is consumed in `start()` and cannot be recreated

### C5: Test Mock Mutex Replacement
- Replaced all `std::sync::Mutex` with `tokio::sync::Mutex` in test mocks:
  - `tests/integration_tests.rs`: TestDockerClient
  - `src/monitor.rs`: FailingDockerClient (unit test)
  - `src/guard.rs`: FailingPingDockerClient (unit test)
  - `src/isolation.rs`: PartialFailNetworkClient (unit test)
- Changed all `.lock().unwrap()` to `.lock().await`
- Updated calling code to handle async lock acquisition

### H1: Container ID Validation (docker.rs)
- Added `validate_container_id()` function checking:
  - Non-empty ID with length ≤ 64 characters
  - All characters are ASCII hexadecimal
- Applied validation in all `BollardDockerClient` methods:
  - `inspect_container()`
  - `stop_container()`
  - `pause_container()`
  - `unpause_container()`
  - `disconnect_network()`

### H2: Policy Path Traversal Protection (policy.rs)
- Removed TOCTOU-vulnerable `exists()` and `is_dir()` checks
- Added `canonicalize()` for symlink resolution on all directory entries
- Implemented canonical path verification to ensure paths stay within policy directory
- Files outside policy directory are skipped with warning log

### H3: Alert-to-Container Mapping (Known Limitation)
- Documented as known design limitation in review file
- Current implementation applies action to first matching container (not all)
- Recommended for Phase 4-B enhancement: container hint extraction from alerts

## Testing

All tests passing:
- 185 unit tests
- 17 integration tests
- 0 failures
- `cargo fmt --check`: PASS
- `cargo clippy -- -D warnings`: PASS (0 warnings)

## Files Modified

1. `crates/container-guard/src/monitor.rs`
   - Added MAX_CACHED_CONTAINERS constant
   - Cache size check in get_container()
   - Test mock mutex replacement

2. `crates/container-guard/src/policy.rs`
   - Added MAX_POLICY_FILE_SIZE and MAX_POLICIES constants
   - File size validation in load_policy_from_file()
   - Policy count limit in add_policy()
   - TOCTOU fix and path traversal protection in load_policies_from_dir()

3. `crates/container-guard/src/docker.rs`
   - Added validate_container_id() function
   - Applied validation in all Docker API methods

4. `crates/container-guard/src/guard.rs`
   - Removed channel recreation in stop()
   - Added documentation for restart limitation
   - Test mock mutex replacement

5. `crates/container-guard/src/isolation.rs`
   - Test mock mutex replacement

6. `crates/container-guard/tests/integration_tests.rs`
   - Converted TestDockerClient to use tokio::sync::Mutex
   - Updated all test methods to be async

7. `.reviews/phase-4-container-guard.md`
   - Marked C1-C5 as "수정 완료"
   - Marked H1-H2 as "수정 완료"
   - Documented H3 as known limitation

## Security Improvements

- **DoS Prevention**: Maximum limits prevent unbounded memory growth
- **Input Validation**: Container IDs validated before Docker API calls
- **Path Security**: Symlink resolution and path traversal protection
- **Async Safety**: Proper mutex usage in async contexts prevents deadlocks
- **TOCTOU Prevention**: Direct operations without vulnerable existence checks

## Performance Impact

- Negligible: Cache size checks are O(1), policy count checks are O(1)
- Path canonicalization adds minimal overhead during policy loading
- Container ID validation is simple string validation

## Next Steps

- Phase 4-B: Consider implementing H3 enhancement (container hint extraction)
- Review medium and low priority findings for future improvements
- Integration testing with full ironpost-daemon pipeline

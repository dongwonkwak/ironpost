# T7.3: SBOM Scan E2E Tests Implementation

**Date**: 2026-02-11
**Time**: 22:15 - 23:00 (45분)
**Assignee**: tester
**Status**: ✅ Completed

## Objective
Implement E2E tests for the SBOM scanner module to validate the complete flow: lockfile discovery → vulnerability scanning → AlertEvent generation.

## Tasks Completed

### 1. Test Implementation (5 tests)
Implemented all 5 E2E test scenarios in `ironpost-daemon/tests/e2e/scenarios/sbom_flow.rs`:

1. **test_e2e_sbom_scan_vuln_found_alert**
   - Creates temp Cargo.lock with vulnerable package
   - Validates AlertEvent received with correct CVE ID and severity
   - Verifies source_module == "sbom-scanner"

2. **test_e2e_sbom_scan_clean_no_alert**
   - Creates Cargo.lock with safe packages only
   - Validates no AlertEvent is generated
   - Uses SHORT_TIMEOUT for negative assertion

3. **test_e2e_sbom_scan_multiple_vulns**
   - Creates lockfile with 3 vulnerable packages
   - Validates 3 separate AlertEvents are generated
   - Verifies each CVE ID is present

4. **test_e2e_sbom_alert_severity_mapping**
   - Tests CRITICAL, HIGH, MEDIUM severities
   - Validates each AlertEvent has correct severity mapping
   - Ensures severity filtering works

5. **test_e2e_sbom_alert_source_module**
   - Validates metadata.source_module == MODULE_SBOM_SCANNER
   - Ensures proper event attribution

### 2. Helper Functions
Created two helper functions for test data generation:

- `create_temp_cargo_lock(packages)` - Creates temp directory with Cargo.lock file
  - Returns `(TempDir, String)` to maintain directory lifetime
  - Generates valid TOML lockfile format

- `create_temp_vuln_db(entries)` - Creates temp vulnerability DB JSON file
  - Generates valid VulnDbEntry format
  - Supports multiple CVE entries

- `setup_vuln_db_dir(file)` - Copies vuln DB to cargo.json in temp directory
  - Required by scanner's DB loading logic

### 3. Production Bug Fix
Discovered and fixed bug in `crates/sbom-scanner/src/scanner.rs`:

**Issue**: SBOM scanner was using `AlertEvent::new()` which defaults to `MODULE_LOG_PIPELINE` as source_module.

**Fix**:
```rust
// Before
let alert_event = AlertEvent::new(alert, finding.vulnerability.severity);

// After
let alert_event =
    AlertEvent::with_source(alert, finding.vulnerability.severity, MODULE_SBOM_SCANNER);
```

Added import: `use ironpost_core::event::{AlertEvent, MODULE_SBOM_SCANNER};`

### 4. Test Robustness Improvements
- Added debug output for CVE ID extraction
- Handle title format variations (e.g., "CVE-2024-0001:")
- Use `trim_end_matches(':')` for consistent parsing
- Detailed assertion messages with actual values

## Test Results

```bash
cargo test -p ironpost-daemon --test e2e sbom_flow
```

**Result**: ✅ 5 passed; 0 failed; 0 ignored

### Test Coverage
- Vulnerability detection: ✅
- Clean scan (no alerts): ✅
- Multiple vulnerabilities: ✅
- Severity mapping: ✅
- Source module attribution: ✅

### SBOM Scanner Unit Tests
Verified production fix doesn't break existing tests:

```bash
cargo test -p ironpost-sbom-scanner
```

**Result**: ✅ 183 tests passed (165 unit + 10 CVE integration + 6 integration + 2 doc tests)

### Clippy Validation
```bash
cargo clippy -p ironpost-daemon --test e2e -- -D warnings
```

**Result**: ✅ No warnings

## Key Learnings

1. **Lockfile Detection**: Scanner uses exact filename matching ("Cargo.lock", "package-lock.json"). Tests must create properly named files in temp directories, not random temp files.

2. **Event Attribution**: Each module should use appropriate AlertEvent constructor:
   - `AlertEvent::new()` → defaults to MODULE_LOG_PIPELINE
   - `AlertEvent::with_source()` → specify custom source module

3. **Temp File Management**: Use `TempDir` instead of `NamedTempFile` for lockfiles, keep guard alive to prevent premature cleanup.

4. **Title Parsing**: Alert titles may include punctuation (e.g., "CVE-2024-0001:"), use `trim_end_matches()` for robust parsing.

## Files Modified

### Test Files
- `ironpost-daemon/tests/e2e/scenarios/sbom_flow.rs` (286 lines, 5 tests)

### Production Files
- `crates/sbom-scanner/src/scanner.rs` (bug fix: 2 lines changed)

## Acceptance Criteria
- ✅ Minimum 4 tests implemented (5 delivered)
- ✅ `cargo test -p ironpost-daemon --test e2e_sbom_flow` passes (via --test e2e)
- ✅ Clippy clean (no warnings)
- ✅ tempfile-based test lockfile generation
- ✅ Mock VulnDb for vulnerability simulation

## Next Steps
- T7.2 (S1: Event pipeline E2E) - in progress
- T7.7 (S6: Fault isolation) - in progress
- Phase 7 review after all E2E tests complete

## Time Tracking
- **Estimated**: 1.5h
- **Actual**: 45 minutes
- **Efficiency**: 50% (beat estimate)

**Breakdown**:
- Test skeleton analysis: 5 min
- Helper implementation: 10 min
- Test implementation: 15 min
- Debugging filename issue: 10 min
- Bug fix & validation: 5 min

# Code Review: ironpost-sbom-scanner (Phase 5) -- Re-review

## Summary
- Reviewer: reviewer (security-focused)
- Date: 2026-02-10
- Target: `crates/sbom-scanner/` -- 16 source files, 2 test files, 3 fixture files
- Tests: 183 total (165 unit + 10 CVE integration + 6 pipeline integration + 2 doc tests), all passing
- Clippy: Clean (no warnings with `-D warnings`)
- Fmt: Clean (no formatting issues)
- Result: **Conditional Approval** -- 1 Critical, 3 High, 9 Medium, 8 Low findings (21 total)
- Previous review: 23 findings (C3, H5 resolved; this review is on post-fix code with fresh analysis)

## Files Reviewed

| File | Lines | Purpose |
|------|-------|---------|
| `src/lib.rs` | 67 | Module root, re-exports |
| `src/error.rs` | 279 | SbomScannerError (9 variants) + IronpostError conversion |
| `src/config.rs` | 476 | SbomScannerConfig + builder + validation |
| `src/event.rs` | 143 | ScanEvent + Event trait impl |
| `src/types.rs` | 278 | Ecosystem, Package, PackageGraph, SbomFormat, SbomDocument |
| `src/scanner.rs` | 767 | SbomScanner orchestrator + Pipeline impl + scan_directory |
| `src/parser/mod.rs` | 141 | LockfileParser trait + LockfileDetector |
| `src/parser/cargo.rs` | 361 | CargoLockParser (TOML) |
| `src/parser/npm.rs` | 439 | NpmLockParser (JSON v2/v3) |
| `src/sbom/mod.rs` | 110 | SbomGenerator dispatch |
| `src/sbom/cyclonedx.rs` | 257 | CycloneDX 1.5 JSON generation |
| `src/sbom/spdx.rs` | 280 | SPDX 2.3 JSON generation |
| `src/vuln/mod.rs` | 627 | VulnMatcher, ScanFinding, ScanResult, SeverityCounts |
| `src/vuln/db.rs` | 671 | VulnDb + HashMap index + field validation |
| `src/vuln/version.rs` | 370 | SemVer version range matching + string fallback |
| `tests/integration_tests.rs` | 333 | E2E pipeline integration tests |
| `tests/cve_matching_tests.rs` | 507 | CVE matching edge case integration tests |
| `Cargo.toml` | 23 | Crate manifest |

---

## Previous Review Status

The initial review (2026-02-10) identified 23 findings. The following were addressed in commit `14ac3f7`:

| ID | Status | Description |
|----|--------|-------------|
| C1 | Fixed | VulnDb file size limit (50MB) + entry limit (1M) |
| C2 | Fixed | VulnDb HashMap indexing for O(1) lookup |
| C3 | Fixed | TOCTOU exists() checks removed |
| H1 | Fixed | scan_directory() shared function extracted |
| H2 | Deferred | Graceful shutdown (Phase 6) |
| H3 | Fixed | Stopped state start() rejection |
| H4 | Fixed | scan_dirs path traversal validation |
| H5 | Fixed | VulnDb entry count cap |

This re-review validates those fixes and performs a fresh, thorough analysis of the current codebase.

---

## Findings

### Critical (must fix before production)

#### NEW-C1: VulnDb `lookup()` allocates a String on every call for HashMap key

**✅ 수정 완료 (2026-02-11)**

**File:** `crates/sbom-scanner/src/vuln/db.rs`, lines 107-110, 356-369

**수정 내용:**
- 인덱스 구조를 2단계 HashMap으로 변경: `HashMap<String, HashMap<Ecosystem, Vec<usize>>>`
- `&str` 키로 직접 조회 가능 (Borrow trait 활용)
- `lookup()` 메서드에서 String 할당 제거
- 성능 주석 추가로 설계 의도 명확화

**수정 코드:**
```rust
index: HashMap<String, HashMap<Ecosystem, Vec<usize>>>,

pub fn lookup(&self, package: &str, ecosystem: &Ecosystem) -> Vec<&VulnDbEntry> {
    if let Some(eco_map) = self.index.get(package) {  // &str로 직접 조회
        if let Some(indices) = eco_map.get(ecosystem) {
            indices.iter().filter_map(|&idx| self.entries.get(idx)).collect()
        } else {
            Vec::new()
        }
    } else {
        Vec::new()
    }
}
```

**영향:**
- 50,000 패키지 스캔 시 50,000번의 String 할당 제거
- GC 압력 감소
- 성능 크리티컬 경로 최적화

---

### High (strongly recommended fix)

#### NEW-H1: Periodic scan task loop has no cancellation check -- runs indefinitely after scanner drop

**File:** `crates/sbom-scanner/src/scanner.rs`, lines 237-283

**Problem:** The periodic scan task is spawned as a `tokio::spawn` with an infinite `loop` containing `interval.tick().await`. While `stop()` calls `task.abort()`, if `stop()` is never called (e.g., the `SbomScanner` is dropped without explicit stop), the spawned task continues running indefinitely because there is no `CancellationToken`, no `watch` channel, and no `WeakSender` pattern to detect that the parent is gone.

The `alert_tx.try_send()` will eventually return `Err` when the receiver is dropped, but the task continues looping, performing filesystem scans, and consuming CPU/IO resources.

```rust
let task = tokio::spawn(async move {
    loop {                          // <-- infinite loop
        interval.tick().await;
        // ... scan logic ...
    }
});
```

**Suggested fix:** Use `tokio_util::sync::CancellationToken` or a `tokio::sync::watch` channel to signal shutdown. Alternatively, check if `alert_tx.is_closed()` at the start of each iteration and break if so.

---

#### NEW-H2: `discover_lockfiles` metadata-to-content TOCTOU gap

**✅ 수정 완료 (2026-02-11)**

**File:** `crates/sbom-scanner/src/scanner.rs`, lines 668-694

**수정 내용:**
- `File::open()` → `file.metadata()` → `read_from_file()` 패턴으로 변경
- 동일한 파일 핸들에서 metadata와 content를 순차적으로 읽음
- TOCTOU 갭 제거

**수정 코드:**
```rust
// 파일을 한 번만 열고 metadata와 content를 같은 핸들에서 읽어 TOCTOU 방지
let mut file = match std::fs::File::open(&path) { ... };

// 파일 핸들에서 metadata 가져오기 (크기 체크용)
let metadata = match file.metadata() { ... };

// 파일 크기 확인
let file_size = usize::try_from(metadata.len()).unwrap_or(usize::MAX);
if file_size > max_file_size { ... }

// 동일 핸들에서 content 읽기
let mut content = String::new();
if let Err(e) = file.read_to_string(&mut content) { ... }
```

**영향:**
- 파일 교체 공격 방어
- 커널이 동일한 inode에 대한 file descriptor 유지
- 멀티테넌트 환경에서 안전성 향상

---

#### NEW-H3: `unix_to_rfc3339` duplicated code -- 55 identical lines in cyclonedx.rs and spdx.rs

**File:** `crates/sbom-scanner/src/sbom/cyclonedx.rs`, lines 122-177 and `spdx.rs`, lines 142-197

**Problem:** The `current_timestamp()`, `unix_to_rfc3339()`, and `is_leap_year()` functions are identically duplicated across both SBOM generation modules. This is 55 lines of non-trivial date calculation code duplicated, making it a maintenance hazard. Any bug fix or improvement would need to be applied to both copies simultaneously.

This was noted as L1 in the previous review, but the code has since been significantly expanded (from 7 lines of epoch formatting to 55 lines of full calendar calculation), which elevates this to High severity. A bug in one copy but not the other would produce different timestamps in CycloneDX vs SPDX outputs from the same scan.

**Suggested fix:** Move `current_timestamp()`, `unix_to_rfc3339()`, and `is_leap_year()` to a shared module (e.g., `sbom/mod.rs` or a new `sbom/util.rs`). Both `cyclonedx.rs` and `spdx.rs` should call the shared implementation.

---

### Medium (recommended fix)

#### M1: Version string fallback comparison is semantically incorrect and can cause false negatives

**File:** `crates/sbom-scanner/src/vuln/version.rs`, lines 89-103

**Problem:** When SemVer parsing fails for the package version, the code falls back to lexicographic string comparison. This produces incorrect results for many real-world version strings:

- `"v1.0.3"` vs range `["1.0.0", "1.0.5")`: Not matched because `'v' > '1'` lexicographically. This is a **false negative** -- a vulnerable package would not be flagged.
- `"10.0.0"` vs `"2.0.0"`: `"10.0.0" < "2.0.0"` in string comparison because `'1' < '2'`.

The test at line 343-344 explicitly documents and asserts this incorrect behavior, which means it was a conscious design decision. However, in a security-critical vulnerability scanner, false negatives are dangerous because they silently miss known vulnerabilities.

```rust
fn is_in_range_string(version: &str, range: &VersionRange) -> bool {
    if let Some(ref introduced) = range.introduced
        && version < introduced.as_str() {   // lexicographic comparison
        return false;
    }
```

**Suggested fix:** Before falling back to string comparison, try stripping a leading `v`/`V` prefix and re-parsing as SemVer. For truly non-SemVer strings, log a warning and return `false` (conservative: do not match) instead of using unreliable string comparison. Add a separate function `try_normalize_version()` that handles common non-standard prefixes.

---

#### M2: SPDX SPDXID uses numeric index -- non-deterministic across runs

**File:** `crates/sbom-scanner/src/sbom/spdx.rs`, line 71

**Problem:** The SPDX package identifier is `SPDXRef-Package-{idx}` using the iteration index. Since `PackageGraph.packages` is a `Vec<Package>` and the NPM parser iterates over a `HashMap` (whose iteration order is non-deterministic), the same set of packages can produce different SPDX IDs across runs. This breaks reproducible builds and makes SBOM diffing unreliable.

```rust
let spdx_id = format!("SPDXRef-Package-{}", idx);
```

**Suggested fix:** Use `format!("SPDXRef-Package-{}", sanitize_spdx_id(&pkg.name, &pkg.version))` where `sanitize_spdx_id` replaces non-alphanumeric characters with hyphens (SPDX IDs only allow `[a-zA-Z0-9.-]`). This produces stable, meaningful identifiers.

---

#### M3: CycloneDX checksum hardcodes SHA-256 regardless of actual algorithm

**File:** `crates/sbom-scanner/src/sbom/cyclonedx.rs`, lines 63-67

**Problem:** NPM's `integrity` field uses SRI hashes (e.g., `sha512-PlhdFcill...`), but the CycloneDX output always labels them as `SHA-256`. This produces factually incorrect SBOM metadata. Similarly, the SPDX output labels checksums as `SHA256` regardless.

```rust
vec![CycloneDxHash {
    alg: "SHA-256".to_owned(),    // hardcoded, wrong for NPM
    content: c.clone(),
}]
```

**Suggested fix:** Add a field to `Package` indicating the checksum algorithm, or parse the checksum value to detect the algorithm prefix. For Cargo.lock, SHA-256 is correct. For NPM integrity values, parse the `shaXXX-` prefix.

---

#### M4: NPM parser does not limit HashMap size from untrusted JSON input

**File:** `crates/sbom-scanner/src/parser/npm.rs`, lines 41, 56

**Problem:** The `NpmLockFile.packages` HashMap and `NpmPackageEntry.dependencies` HashMap are deserialized from untrusted JSON without size limits. A crafted `package-lock.json` within the 10MB `max_file_size` limit could contain millions of tiny entries (e.g., `"a":{"version":"1"},...`), causing excessive memory allocation during HashMap construction. The `max_packages` check in `scanner.rs:456` happens after parsing is already complete.

**Suggested fix:** After deserialization, immediately check `lock_file.packages.len()` against a limit (e.g., `max_packages`) before iterating. If it exceeds the limit, return a `LockfileParse` error instead of proceeding.

---

#### M5: `semver` crate not managed through workspace.dependencies

**File:** `crates/sbom-scanner/Cargo.toml`, line 18

**Problem:** All other dependencies use `workspace = true`, but `semver` is directly specified as `semver = "1"`. This violates the project convention of version centralization via `workspace.dependencies`.

```toml
semver = "1"
```

**Suggested fix:** Add `semver = "1"` to `[workspace.dependencies]` in the root `Cargo.toml` and change this to `semver = { workspace = true }`.

---

#### M6: `discover_lockfiles` does not limit the number of lockfiles processed

**File:** `crates/sbom-scanner/src/scanner.rs`, lines 560-663

**Problem:** The `discover_lockfiles` function reads all matching lockfiles in a directory without any count limit. If a scan directory contains thousands of lockfiles (e.g., a CI artifact directory), all of them will be read into memory simultaneously via the `results` Vec. There is no upper bound on the number of `(String, String)` tuples accumulated.

**Suggested fix:** Add a `max_lockfiles_per_dir` constant (e.g., 100) and stop discovery after reaching it, logging a warning.

---

#### M7: `discover_lockfiles` only scans 1 level deep -- undocumented limitation

**File:** `crates/sbom-scanner/src/scanner.rs`, line 568-569 and `config.rs` line 39-40

**Problem:** The function only scans the immediate directory (1 level), but the `scan_dirs` config field documentation does not mention this limitation. Users configuring `scan_dirs: ["/opt/projects"]` would expect recursive scanning. The comment in the source says "1 level only (deep scanning for future extension)" but this is not reflected in the public API documentation.

**Suggested fix:** Add `/// Note: Only the immediate directory is scanned (not recursive).` to the `scan_dirs` field documentation in `SbomScannerConfig`.

---

#### M8: SPDX document name includes raw file path -- potential information disclosure

**File:** `crates/sbom-scanner/src/sbom/spdx.rs`, line 108

**Problem:** The SPDX document name is `format!("ironpost-scan-{}", graph.source_file)`. The `source_file` contains the full filesystem path (e.g., `/home/user/project/Cargo.lock`), which leaks internal directory structure in the generated SBOM document. If the SBOM is shared externally, this reveals server paths.

```rust
name: format!("ironpost-scan-{}", graph.source_file),
```

**Suggested fix:** Extract only the filename component using `Path::file_name()` or use a hash of the path.

---

#### M9: Path traversal check uses simple string contains("..") -- bypassable

**✅ 수정 완료 (2026-02-11)**

**File:** `crates/sbom-scanner/src/config.rs`, lines 170-174

**수정 내용:**
- `Path::components().any(|c| c == Component::ParentDir)` 사용
- 정확한 경로 컴포넌트 검증
- 정규화 없이도 모든 path traversal 패턴 탐지

**수정 코드:**
```rust
// Path traversal 체크: Path::components()로 정확하게 ParentDir 컴포넌트 검출
if std::path::Path::new(scan_dir)
    .components()
    .any(|c| c == std::path::Component::ParentDir)
{
    return Err(SbomScannerError::Config {
        field: "scan_dirs".to_owned(),
        reason: format!(
            "scan directory '{}' contains path traversal pattern '..'",
            scan_dir
        ),
    });
}
```

**영향:**
- `/opt/my..project/` 같은 정상 경로의 false positive 제거
- `/opt/./../../etc` 같은 복잡한 traversal 패턴 탐지
- 더 정확한 보안 검증

---

### Low (optional improvements)

#### L1: Error conversion uses `match &err` causing unnecessary String clones -- FIXED

**File:** `crates/sbom-scanner/src/error.rs`, lines 99-130

**Problem:** The `From<SbomScannerError> for IronpostError` implementation matches on `&err` (borrowed), then calls `msg.clone()` on tuple variant inner strings and `err.to_string()` on struct variants. Since the method takes `err` by value, matching by value would allow moving the inner strings instead of cloning them.

**Suggested fix:** Change `match &err` to `match err` and destructure the variants to move inner strings directly.

**Resolution:** Changed `match &err` to `match err`, destructuring all variants to move inner strings directly. Tuple variants (`SbomGeneration`, `VulnDbParse`, `Channel`) now move the string instead of cloning. Struct variants format the message inline to match `thiserror` Display output.

---

#### L2: `PackageGraph::find_package` is O(n) linear search -- FIXED

**File:** `crates/sbom-scanner/src/types.rs`, lines 114-116

**Problem:** `find_package` iterates through all packages. With large package graphs (50K packages), this is slow. Currently only used in tests, so this is low priority.

**Suggested fix:** Consider a HashMap index if `find_package` is ever used in production hot paths.

**Resolution:** Added doc comment documenting O(n) complexity and recommendation to add HashMap index if ever used in production hot paths.

---

#### L3: NpmLockFile unused deserialized fields waste memory -- FIXED

**File:** `crates/sbom-scanner/src/parser/npm.rs`, lines 37-39, 52-53

**Problem:** `_name`, `_lockfile_version`, and `_resolved` are deserialized from JSON but never used. The underscore prefix suppresses warnings, but the data is still parsed and allocated.

**Suggested fix:** Remove these fields or use `#[serde(skip)]`.

**Resolution:** Removed `_name`, `_lockfile_version` from `NpmLockFile` and `_resolved` from `NpmPackageEntry`. Added doc comments explaining the intent (serde_json ignores unknown fields by default).

---

#### L4: Package name/version lengths not validated in parsers -- FIXED

**File:** `crates/sbom-scanner/src/parser/cargo.rs`, lines 73-95 and `npm.rs`, lines 80-115

**Problem:** Package names and versions from lockfiles are accepted at any length. Tests demonstrate handling of 1000-2000 character names, but there is no enforced upper bound. While `max_file_size` limits total input, crafted lockfiles could have very long individual field values that are cloned multiple times during PURL generation and SBOM serialization.

**Suggested fix:** Add length limits (e.g., 512 for names, 256 for versions) and skip packages exceeding them.

**Resolution:** Added `MAX_PACKAGE_NAME_LEN = 512` and `MAX_PACKAGE_VERSION_LEN = 256` constants to both parsers. Packages exceeding limits are skipped with `tracing::warn!`. Updated tests to verify skipping behavior and boundary cases (at-limit values accepted).

---

#### L5: VulnDb does not implement Clone -- FIXED

**File:** `crates/sbom-scanner/src/vuln/db.rs`, line 96

**Problem:** `VulnDb` does not derive `Clone`. It is always used behind `Arc<VulnDb>`, but lacking `Clone` limits flexibility for testing and alternative patterns.

**Suggested fix:** Add `#[derive(Clone)]` or document the intent of always using `Arc`.

**Resolution:** Added `#[derive(Clone)]` to `VulnDb` and documented the `Arc<VulnDb>` sharing pattern recommendation in the struct doc comment.

---

#### L6: Redundant `_clone` suffix in periodic task variable names -- FIXED

**File:** `crates/sbom-scanner/src/scanner.rs`, lines 244-253

**Problem:** Variables like `scan_dir_clone`, `parsers_clone`, `generator_clone`, `matcher_clone` use the `_clone` suffix which is noise. The `let` binding in the inner scope already makes it clear these are copies for the closure.

```rust
let scan_dir_clone = scan_dir.clone();
let parsers_clone: Vec<Box<dyn LockfileParser>> = vec![...];
let generator_clone = generator;
let matcher_clone = matcher_opt.clone();
```

**Suggested fix:** Use clearer names like `dir`, `parsers`, `gen`, `matcher` in the inner scope.

**Resolution:** Renamed to `dir`, `parsers`, `sbom_gen` (not `gen` -- reserved keyword in Rust 2024), `matcher`, `tx`, `completed`, `found`.

---

#### L7: `ScanEvent::with_trace` accepts `impl Into<String>` but `EventMetadata::new` may expect specific types -- FIXED

**File:** `crates/sbom-scanner/src/event.rs`, line 60

**Problem:** Minor API inconsistency. `with_trace` uses `impl Into<String>` for `trace_id`, which is ergonomic, but the corresponding `new` method in `ScanEvent` (line 51) does not take a trace_id parameter. This asymmetry is minor but could confuse callers about which constructor to use.

**Suggested fix:** Add doc comments explaining when to use `new()` (starts new trace) vs `with_trace()` (continues existing trace).

**Resolution:** Added doc comments to both `new()` and `with_trace()` explaining their use cases: `new()` for starting new work flows (scan_once, periodic scans), `with_trace()` for continuing existing traces from other modules (API requests, external triggers).

---

#### L8: `tempfile` dev-dependency not managed through workspace -- FIXED (with M5)

**File:** `crates/sbom-scanner/Cargo.toml`, line 22

**Problem:** Similar to M5, `tempfile = "3"` is directly specified instead of using workspace dependencies. This is a dev-dependency so it is lower priority, but it still violates the workspace convention.

**Suggested fix:** Add `tempfile = "3"` to `[workspace.dependencies]` if not already present.

**Resolution:** Previously fixed together with M5.

---

## Verification of Previous Fix Quality

### C1 Fix (VulnDb file size limit): VERIFIED
- `MAX_VULN_DB_FILE_SIZE = 50 * 1024 * 1024` (50MB) at `db.rs:38`
- `MAX_VULN_DB_ENTRIES = 1_000_000` at `db.rs:41`
- File size check via `metadata.len()` at `db.rs:274`
- Entry count check at `db.rs:303`
- Truncation with warning at `db.rs:309-311`
- Field-level validation (CVE ID, package name, description, version lengths) at `db.rs:152-227`

### C2 Fix (HashMap indexing): VERIFIED
- `index: HashMap<(String, Ecosystem), Vec<usize>>` at `db.rs:100`
- `build_index()` at `db.rs:113-122`
- `lookup()` uses `self.index.get(&key)` at `db.rs:341`
- All constructors (`empty`, `from_entries`, `from_json`, `load_from_dir`) build index

### C3 Fix (TOCTOU removal): VERIFIED
- `scanner.rs:start()` directly calls `VulnDb::load_from_dir()` with error handling (lines 188-214)
- `discover_lockfiles()` directly calls `read_dir()` with `NotFound` handling (lines 569-581)
- `db.rs:load_from_dir()` directly calls `metadata()` with `NotFound` handling (lines 259-271)
- Symlink checking via `symlink_metadata()` at `scanner.rs:609`
- Canonical path containment check at `scanner.rs:627-637`

### H1 Fix (scan_directory shared function): VERIFIED
- `ScanContext` struct at `scanner.rs:412-421`
- `scan_directory()` function at `scanner.rs:426-555`
- Used by both `scan_once()` (line 146) and periodic task (line 267)

### H3 Fix (stop/restart rejection): VERIFIED
- Explicit `Stopped` state check at `scanner.rs:175-181`
- Clear error message returned

### H4 Fix (path traversal validation): VERIFIED
- `contains("..")` check at `config.rs:168` (scan_dirs) and `config.rs:192` (vuln_db_path)
- Empty path check at `config.rs:162`
- Path length limit (4096) at `config.rs:179-180`
- Symlink skip in `discover_lockfiles` at `scanner.rs:618-624`
- Canonical path containment check at `scanner.rs:627-637`

---

## Positive Observations

1. **No `as` casting in production code.** Correctly uses `TryFrom`/`try_from` (e.g., `u64::try_from(finding_count).unwrap_or(u64::MAX)` at `scanner.rs:541`, `usize::try_from(metadata.len()).unwrap_or(usize::MAX)` at `scanner.rs:640`).

2. **No `unsafe` code anywhere.** Zero unsafe blocks across all 16 source files.

3. **No `println!`/`eprintln!` usage.** All logging uses `tracing` macros (`info!`, `warn!`, `debug!`).

4. **No `std::sync::Mutex` usage.** Shared counters use `AtomicU64` with appropriate `Ordering::Relaxed`.

5. **No `panic!()`/`todo!()`/`unimplemented!()` in production code.** These only appear in `#[cfg(test)]` blocks.

6. **Proper `thiserror` error definitions.** `SbomScannerError` has 9 well-structured variants with context fields.

7. **File size limits enforced.** Both lockfile size (`max_file_size` config) and VulnDb file size (`MAX_VULN_DB_FILE_SIZE`) are checked before reading content.

8. **Graceful per-file error recovery.** Individual lockfile parse failures are logged and skipped, never aborting the full scan.

9. **Bounded alert channel.** Uses `mpsc::channel(capacity)` with `try_send` for backpressure.

10. **Blocking I/O properly wrapped.** All filesystem operations run inside `tokio::task::spawn_blocking`.

11. **Clean architecture.** No peer-to-peer module dependencies; only depends on `ironpost-core`.

12. **Good trait design.** `LockfileParser` trait enables extensibility. `SbomGenerator` cleanly delegates to format modules.

13. **Comprehensive test coverage.** 183 tests including malformed input, unicode, long strings, empty inputs, severity filtering, lifecycle management, and full E2E pipeline tests.

14. **TOCTOU mitigations applied.** Direct open-and-handle-error pattern used consistently throughout. Symlink detection and canonical path containment checks add defense in depth.

15. **VulnDb entry validation.** Individual entry fields (CVE ID, package name, description, version strings) are length-checked after parsing, preventing memory abuse from crafted DB files.

16. **Deterministic SBOM timestamps.** The custom `unix_to_rfc3339()` implementation produces proper ISO 8601 format without external datetime dependencies. The leap year calculation appears correct.

17. **Config validation is thorough.** Bounds checking, contextual validation, and path security checks are all present.

---

## Summary Statistics

| Severity | Count | Must Fix |
|----------|-------|----------|
| Critical | 1 | Yes (performance in hot path) |
| High | 3 | Strongly recommended |
| Medium | 9 | Recommended |
| Low | 8 | Optional |
| **Total** | **21** | |

### Critical:
- **NEW-C1**: VulnDb lookup allocates String on every call in hot path

### High priority:
- **NEW-H1**: Periodic task runs indefinitely after scanner drop (no cancellation)
- **NEW-H2**: Metadata-to-read TOCTOU gap in discover_lockfiles
- **NEW-H3**: 55 lines of date calculation code duplicated across CycloneDX and SPDX

### Medium priority:
- **M1**: String comparison fallback causes false negatives in version matching
- **M2**: SPDX IDs are non-deterministic (index-based)
- **M3**: Checksum algorithm hardcoded as SHA-256 (wrong for NPM)
- **M4**: NPM parser HashMap size unbounded from untrusted input
- **M5**: `semver` crate not in workspace.dependencies
- **M6**: No limit on lockfiles discovered per directory
- **M7**: 1-level scan depth undocumented in config API
- **M8**: SPDX document name leaks filesystem paths
- **M9**: Path traversal check uses naive string contains("..") -- bypassable

### Previously resolved (verified):
- C1, C2, C3, H1, H3, H4, H5 from initial review -- all correctly implemented

---

## Production Readiness Assessment

**Overall:** The crate is well-structured, follows project conventions, and has good test coverage. The previous Critical fixes (file size limits, HashMap indexing, TOCTOU removal) have been properly implemented. The remaining findings are primarily:

1. **Performance** (NEW-C1): Hot-path allocation in VulnDb lookup
2. **Robustness** (NEW-H1, NEW-H2): Resource cleanup and TOCTOU mitigation
3. **Compliance** (M1-M3, M8): SBOM spec conformance and version matching accuracy
4. **Defense in depth** (M4, M6, M9): Input validation improvements

**Recommendation:** Fix NEW-C1 and NEW-H1 before production deployment. The remaining items can be addressed in Phase 6 polishing.

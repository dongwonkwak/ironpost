# Phase 5: SBOM Scanner Implementation

## Goal
Implement SBOM (Software Bill of Materials) generation and CVE vulnerability scanning.
Parse dependency lockfiles (Cargo.lock, package-lock.json), generate SBOM documents
(CycloneDX 1.5 JSON, SPDX 2.3 JSON), and scan for known vulnerabilities against a
local JSON CVE database.

## Prerequisites
- Phase 1 (core) complete
- Phase 3 (log-pipeline) complete (AlertEvent pipeline integration)
- Phase 4 (container-guard) complete (Pattern reference)

## Design Document
- `.knowledge/sbom-scanner-design.md`

## Scaffolding (Phase 5-A) -- Completed (2026-02-10)
- [x] T5-A1: Design document (`.knowledge/sbom-scanner-design.md`)
  - 14 sections: module overview, architecture, core types, error handling, event integration,
    lockfile parsing, SBOM formats, vuln DB, config, Pipeline lifecycle, testing, directory structure,
    dependencies, Phase 4 review lessons
- [x] T5-A2: `Cargo.toml` with dependencies
  - ironpost-core (path), tokio, serde, serde_json, toml, tracing, thiserror, uuid (workspace), semver = "1"
  - Removed reqwest (offline mode only), removed clap (CLI in ironpost-cli binary)
- [x] T5-A3: `error.rs` -- SbomScannerError enum (9 variants) + From<SbomScannerError> for IronpostError
  - Variants: LockfileParse, SbomGeneration, VulnDbLoad, VulnDbParse, VersionParse, Config, Channel, Io, FileTooBig
  - Tests: 13 unit tests (display, conversion)
- [x] T5-A4: `config.rs` -- SbomScannerConfig + SbomScannerConfigBuilder + from_core() + validate()
  - Fields: enabled, scan_dirs, vuln_db_path, min_severity, output_format, scan_interval_secs, max_file_size, max_packages
  - Validation: scan_interval 0|60-604800, max_file_size 1-100MB, max_packages 1-500000
  - Tests: 16 unit tests
- [x] T5-A5: `event.rs` -- ScanEvent + Event trait impl
  - new() with new trace, with_trace() for existing traces
  - event_type = "scan", source_module = "sbom-scanner"
  - Tests: 4 unit tests
- [x] T5-A6: `types.rs` -- Ecosystem, Package, PackageGraph, SbomFormat, SbomDocument
  - Ecosystem: Cargo, Npm, Go, Pip with purl_type(), from_str_loose()
  - Package: name, version, ecosystem, purl, checksum, dependencies + make_purl()
  - PackageGraph: source_file, ecosystem, packages, root_packages + package_count(), find_package()
  - SbomFormat: CycloneDx, Spdx with from_str_loose()
  - Tests: 12 unit tests (display, parsing, lookup)
- [x] T5-A7: `parser/mod.rs` -- LockfileParser trait + LockfileDetector
  - LockfileParser: ecosystem(), can_parse(path), parse(content, source_path)
  - LockfileDetector: is_lockfile(), detect_ecosystem()
  - Tests: 5 unit tests
- [x] T5-A8: `parser/cargo.rs` -- CargoLockParser (LockfileParser impl)
  - TOML parsing, dependency name extraction, root package detection (no source field)
  - Tests: 6 unit tests with sample Cargo.lock
- [x] T5-A9: `parser/npm.rs` -- NpmLockParser (LockfileParser impl)
  - JSON v2/v3 parsing, scoped package support (@scope/name), nested node_modules
  - Tests: 8 unit tests with sample package-lock.json
- [x] T5-A10: `sbom/mod.rs` -- SbomGenerator
  - format-based dispatch to cyclonedx or spdx generators
  - Tests: 3 unit tests
- [x] T5-A11: `sbom/cyclonedx.rs` -- CycloneDX 1.5 JSON generation
  - bomFormat, specVersion, metadata (tools, timestamp), components (type, name, version, purl, hashes)
  - Tests: 5 unit tests
- [x] T5-A12: `sbom/spdx.rs` -- SPDX 2.3 JSON generation
  - spdxVersion, SPDXID, documentNamespace (UUID-unique), creationInfo, packages (SPDXRef IDs, externalRefs, checksums)
  - Tests: 6 unit tests (including unique namespace test)
- [x] T5-A13: `vuln/mod.rs` -- VulnMatcher, ScanFinding, ScanResult, SeverityCounts
  - VulnMatcher: scan() with version range matching + severity filtering
  - ScanResult: severity_counts(), finding_count()
  - Tests: 5 unit tests
- [x] T5-A14: `vuln/db.rs` -- VulnDb, VulnDbEntry, VersionRange
  - empty(), from_entries(), from_json(), load_from_dir(), entry_count(), lookup()
  - Tests: 8 unit tests
- [x] T5-A15: `vuln/version.rs` -- SemVer version comparison
  - is_affected() with range matching (introduced <= version < fixed)
  - SemVer comparison via semver crate, string comparison fallback
  - Tests: 10 unit tests
- [x] T5-A16: `scanner.rs` -- SbomScanner (Pipeline impl) + SbomScannerBuilder
  - State management (Initialized/Running/Stopped)
  - Pipeline trait: start() (VulnDb load), stop() (task abort), health_check() (Healthy/Degraded/Unhealthy)
  - scan_once() for manual trigger, discover_lockfiles() with file size limits
  - AtomicU64 metrics (scans_completed, vulns_found)
  - Builder: config, alert_sender, alert_channel_capacity
  - Tests: 8 unit tests (lifecycle, metrics, empty dir scan)
- [x] T5-A17: `lib.rs` -- Module declarations + public API re-exports
- [x] T5-A18: `README.md` -- Crate documentation
- [x] T5-A19: Core crate updates
  - Added MODULE_SBOM_SCANNER constant ("sbom-scanner")
  - Added EVENT_TYPE_SCAN constant ("scan")
  - Updated lib.rs re-exports

## Implementation (Phase 5-B) -- Completed (2026-02-10)
- [x] T5-B1: Compile verification (`cargo check -p ironpost-sbom-scanner`) -- PASSED
- [x] T5-B2: Clippy pass (`cargo clippy -p ironpost-sbom-scanner -- -D warnings`) -- PASSED (0 warnings)
- [x] T5-B3: Test execution (`cargo test -p ironpost-sbom-scanner`) -- PASSED (110 unit tests)
- [x] T5-B4: Periodic scan task implementation
  - Spawns background tokio task for interval-based scanning
  - Shares VulnMatcher/parsers/generator via Arc + Clone
  - Graceful shutdown via task.abort()
- [x] T5-B5: Integration tests -- PASSED (6 integration tests)
  - End-to-end: lockfile -> SBOM + vulnerability scan -> AlertEvent
  - Pipeline lifecycle with temp directories
  - Multiple sequential scans
  - Test fixtures in `tests/fixtures/` (Cargo.lock, package-lock.json, test-vuln-db.json)

## Testing (Phase 5-C) -- Pending
- [ ] T5-C1: Edge case tests
  - Malformed lockfiles (truncated, empty, binary data)
  - Extremely large package counts (at limit boundary)
  - Unicode in package names
  - Concurrent scan_once() calls
- [ ] T5-C2: Performance tests
  - Scan time with 10k+ packages
  - Memory usage verification
  - VulnDb with 100k+ entries lookup performance

## Review (Phase 5-D) -- Pending
- [ ] T5-D1: Code review
- [ ] T5-D2: Review fix implementation

## Documentation (Phase 5-E) -- Pending
- [ ] T5-E1: Doc comments for all public APIs
- [ ] T5-E2: Architecture documentation update (`docs/architecture.md`)

## Total Test Count Actual
- Unit tests: 110 (all passing)
- Integration tests: 6 (all passing)
- Doc tests: 2 (all passing)
- **Total: 118 tests** (exceeds target)

## Key Design Decisions
1. **Offline mode only**: No network dependencies. Local JSON vuln DB.
2. **LockfileParser trait**: Extensible for future formats (go.sum, Pipfile.lock).
3. **Non-restartable**: stop() -> need new builder. Documented limitation.
4. **File size limits**: max_file_size config prevents OOM from large lockfiles.
5. **Blocking I/O isolation**: All file reads via spawn_blocking.
6. **Best-effort alerts**: try_send() for AlertEvent channel (no backpressure stall).
7. **Degraded mode**: VulnDb load failure -> SBOM-only mode (no crash).

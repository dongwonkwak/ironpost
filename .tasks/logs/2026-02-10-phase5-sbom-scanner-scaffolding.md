# Phase 5: SBOM Scanner Design + Scaffolding

**Date**: 2026-02-10
**Task**: T5-A1 through T5-A19
**Agent**: architect

## Summary

Designed and scaffolded the `ironpost-sbom-scanner` crate with full implementations
(not todo!() stubs). The crate provides SBOM generation (CycloneDX 1.5, SPDX 2.3)
and CVE vulnerability scanning via local JSON databases.

## Deliverables

### Design
- `.knowledge/sbom-scanner-design.md` -- 14-section comprehensive design document

### Core Crate Updates
- `crates/core/src/event.rs` -- Added `MODULE_SBOM_SCANNER`, `EVENT_TYPE_SCAN` constants
- `crates/core/src/lib.rs` -- Added re-exports for new constants

### New Source Files (16 files)
| File | Purpose | Tests |
|------|---------|-------|
| `src/lib.rs` | Module declarations + re-exports | - |
| `src/error.rs` | SbomScannerError (9 variants) | 13 |
| `src/config.rs` | SbomScannerConfig + builder | 16 |
| `src/event.rs` | ScanEvent (Event trait) | 4 |
| `src/types.rs` | Ecosystem, Package, PackageGraph, SbomFormat, SbomDocument | 12 |
| `src/parser/mod.rs` | LockfileParser trait, LockfileDetector | 5 |
| `src/parser/cargo.rs` | CargoLockParser | 6 |
| `src/parser/npm.rs` | NpmLockParser (v2/v3) | 8 |
| `src/sbom/mod.rs` | SbomGenerator | 3 |
| `src/sbom/cyclonedx.rs` | CycloneDX 1.5 JSON | 5 |
| `src/sbom/spdx.rs` | SPDX 2.3 JSON | 6 |
| `src/vuln/mod.rs` | VulnMatcher, ScanFinding, ScanResult | 5 |
| `src/vuln/db.rs` | VulnDb, VulnDbEntry, VersionRange | 8 |
| `src/vuln/version.rs` | SemVer version comparison | 10 |
| `src/scanner.rs` | SbomScanner (Pipeline impl) + builder | 8 |
| `README.md` | Crate documentation | - |

### Task Management
- `.tasks/plans/phase-5-sbom.md` -- Detailed task breakdown (5 phases, 19+ tasks)
- `.tasks/BOARD.md` -- Updated Phase 5 status

## Test Count
- Total unit tests in scaffolding: ~109

## Design Decisions Applied
1. Followed container-guard patterns (state machine, builder, AtomicU64 metrics)
2. Applied Phase 4 review lessons (file size limits, spawn_blocking, non-restartable docs)
3. Removed unnecessary dependencies (reqwest, clap)
4. Added `semver` crate for proper version range matching
5. Offline-only mode (no network dependencies)
6. Best-effort AlertEvent sending (try_send, no backpressure)

## Pending
- Compile verification (`cargo check`)
- Clippy pass
- Test execution
- Periodic scan task implementation
- Integration tests

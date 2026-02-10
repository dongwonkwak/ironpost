# ironpost-sbom-scanner

Software Bill of Materials (SBOM) generation and CVE vulnerability scanning for Ironpost.

## Overview

`ironpost-sbom-scanner` is a Rust library crate that provides automated SBOM generation and vulnerability detection capabilities. It parses dependency lockfiles (Cargo.lock, package-lock.json), generates industry-standard SBOM documents (CycloneDX 1.5, SPDX 2.3), and scans packages against a local CVE database to detect known security vulnerabilities.

### Key Features

- **Lockfile Parsing**: Cargo.lock (TOML), package-lock.json (JSON v2/v3)
- **SBOM Generation**: CycloneDX 1.5 JSON, SPDX 2.3 JSON with Package URLs (PURL)
- **CVE Scanning**: Local JSON vulnerability database with SemVer range matching
- **Severity Filtering**: Configurable minimum severity threshold (Critical, High, Medium, Low, Info)
- **Event Integration**: Scan findings emitted as `AlertEvent` via `tokio::mpsc` for pipeline integration
- **Pipeline Lifecycle**: Implements `ironpost_core::pipeline::Pipeline` trait for unified lifecycle management
- **Extensible Design**: `LockfileParser` trait enables easy addition of new lockfile formats

## Architecture

### Component Overview

```text
                        scan_dirs (from config)
                              |
                              v
                  +-----------------------+
                  |   SbomScanner         |  <-- Pipeline trait impl
                  |   (Orchestrator)      |      (start/stop/health_check)
                  +-----------------------+
                   /         |          \
                  v          v           v
        +----------+  +----------+  +-----------+
        | Lockfile |  |   SBOM   |  |  Vuln     |
        | Parser   |  | Generator|  |  Matcher  |
        +----------+  +----------+  +-----------+
              |              |             |
              v              v             v
        +---------+   +----------+  +----------+
        | Package |   | CycloneDX|  | VulnDb   |
        | Graph   |   | / SPDX   |  | (JSON)   |
        +---------+   +----------+  +----------+
                                          |
                                          v
                                   +------------+
                                   | ScanResult |
                                   +------------+
                                          |
                                   AlertEvent (mpsc)
                                          |
                                     downstream modules
                                   (log-pipeline, storage)
```

### Data Flow

1. **Discovery**: `SbomScanner` scans configured directories for lockfiles (Cargo.lock, package-lock.json)
2. **Parsing**: Appropriate `LockfileParser` (Cargo/NPM) parses file into `PackageGraph`
3. **SBOM Generation**: `SbomGenerator` transforms graph into CycloneDX or SPDX JSON
4. **Vulnerability Matching**: `VulnMatcher` queries `VulnDb` for each package
5. **Alert Emission**: Findings above `min_severity` converted to `AlertEvent` and sent via `mpsc::Sender`

## Supported Formats

### Lockfiles

| Format | Ecosystem | File Name | Parser |
|--------|-----------|-----------|--------|
| Cargo.lock | Rust (Cargo) | `Cargo.lock` | `CargoLockParser` |
| package-lock.json | JavaScript/TypeScript (NPM) | `package-lock.json` | `NpmLockParser` (v2/v3) |

### SBOM Outputs

- **CycloneDX 1.5 JSON**: [CycloneDX specification](https://cyclonedx.org/specification/overview/)
  - Full component metadata (name, version, PURL, checksums)
  - Tool metadata (Ironpost scanner version)
  - RFC 3339 timestamps
- **SPDX 2.3 JSON**: [SPDX specification](https://spdx.dev/specifications/)
  - Package identifiers (SPDXRef-Package-*)
  - External references (PURL)
  - SHA-256 checksums

### CVE Database

Local JSON files stored in `vuln_db_path` directory:

```text
/var/lib/ironpost/vuln-db/
  cargo.json     # Cargo ecosystem vulnerabilities
  npm.json       # NPM ecosystem vulnerabilities
  go.json        # Go ecosystem (future)
  pip.json       # Python ecosystem (future)
```

Each JSON file contains an array of `VulnDbEntry`:

```json
[
  {
    "cve_id": "CVE-2024-1234",
    "package": "openssl",
    "ecosystem": "Cargo",
    "affected_ranges": [
      { "introduced": "1.0.0", "fixed": "1.1.1t" }
    ],
    "fixed_version": "1.1.1t",
    "severity": "Critical",
    "description": "Buffer overflow in...",
    "published": "2024-01-15"
  }
]
```

## Configuration

### TOML Configuration

Add to `ironpost.toml`:

```toml
[sbom]
enabled = true
scan_dirs = ["/app", "/opt/projects"]
vuln_db_path = "/var/lib/ironpost/vuln-db"
min_severity = "medium"
output_format = "cyclonedx"
```

### Environment Variable Overrides

- `IRONPOST_SBOM_ENABLED=true`
- `IRONPOST_SBOM_SCAN_DIRS=/app:/opt` (colon-separated)
- `IRONPOST_SBOM_VULN_DB_PATH=/var/lib/ironpost/vuln-db`
- `IRONPOST_SBOM_MIN_SEVERITY=high`
- `IRONPOST_SBOM_OUTPUT_FORMAT=spdx`

### Configuration Fields

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `enabled` | bool | `false` | Enable/disable scanner |
| `scan_dirs` | `Vec<String>` | `["."]` | Directories to scan (1 level, non-recursive) |
| `vuln_db_path` | String | `/var/lib/ironpost/vuln-db` | Local CVE database directory |
| `min_severity` | String | `"medium"` | Minimum severity for alerts (info/low/medium/high/critical) |
| `output_format` | String | `"cyclonedx"` | SBOM format (cyclonedx/spdx) |
| `scan_interval_secs` | u64 | `86400` | Periodic scan interval (0 = manual only) |
| `max_file_size` | usize | `10485760` | Max lockfile size (10 MB) |
| `max_packages` | usize | `50000` | Max packages per graph |

## Usage

### Basic Scanner Setup

```text
use ironpost_sbom_scanner::{SbomScannerBuilder, SbomScannerConfig};
use ironpost_core::event::AlertEvent;
use tokio::sync::mpsc;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Create alert channel
    let (alert_tx, mut alert_rx) = mpsc::channel::<AlertEvent>(100);

    // Build scanner
    let config = SbomScannerConfig::default();
    let scanner = SbomScannerBuilder::new(config)
        .alert_sender(alert_tx)
        .build()?;

    // Start scanning (periodic mode if scan_interval_secs > 0)
    scanner.start().await?;

    // Receive alerts
    while let Some(alert) = alert_rx.recv().await {
        println!("Vulnerability found: {}", alert.alert.title);
    }

    Ok(())
}
```

### Manual Scan

```text
use ironpost_sbom_scanner::{SbomScanner, SbomScannerBuilder};
use ironpost_core::pipeline::Pipeline;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let (alert_tx, _) = tokio::sync::mpsc::channel(100);
    let config = SbomScannerConfig {
        enabled: true,
        scan_interval_secs: 0,  // Disable periodic scanning
        ..Default::default()
    };

    let mut scanner = SbomScannerBuilder::new(config)
        .alert_sender(alert_tx)
        .build()?;

    scanner.start().await?;

    // Trigger manual scan
    scanner.scan_once().await?;

    // Check metrics
    println!("Scans completed: {}", scanner.scans_completed());
    println!("Vulnerabilities found: {}", scanner.vulns_found());

    scanner.stop().await?;
    Ok(())
}
```

### Parsing Lockfiles Directly

```text
use ironpost_sbom_scanner::parser::{CargoLockParser, LockfileParser};

let parser = CargoLockParser;
let content = std::fs::read_to_string("Cargo.lock")?;
let graph = parser.parse(&content, "Cargo.lock")?;

println!("Found {} packages", graph.package_count());
for pkg in &graph.packages {
    println!("  {} @ {} ({})", pkg.name, pkg.version, pkg.purl);
}
```

### Generating SBOM

```text
use ironpost_sbom_scanner::{SbomGenerator, SbomFormat};
use ironpost_sbom_scanner::parser::CargoLockParser;

let parser = CargoLockParser;
let content = std::fs::read_to_string("Cargo.lock")?;
let graph = parser.parse(&content, "Cargo.lock")?;

let generator = SbomGenerator::new(SbomFormat::CycloneDx);
let doc = generator.generate(&graph)?;

std::fs::write("sbom.json", &doc.content)?;
println!("Generated {} with {} components", doc.format, doc.component_count);
```

### Scanning for Vulnerabilities

```text
use ironpost_sbom_scanner::{VulnDb, VulnMatcher};
use ironpost_core::types::Severity;
use std::sync::Arc;

// Load vulnerability database
let db = VulnDb::load_from_dir("/var/lib/ironpost/vuln-db").await?;
let db = Arc::new(db);

// Create matcher
let matcher = VulnMatcher::new(db.clone(), Severity::Medium);

// Scan a package graph
let graph = /* ... parse lockfile ... */;
let findings = matcher.scan(&graph)?;

println!("Found {} vulnerabilities", findings.len());
for finding in findings {
    println!(
        "  {} in {} ({})",
        finding.vulnerability.cve_id,
        finding.matched_package.name,
        finding.vulnerability.severity
    );
}
```

### Custom Lockfile Parser

Extend support to new lockfile formats:

```text
use ironpost_sbom_scanner::parser::LockfileParser;
use ironpost_sbom_scanner::types::{Ecosystem, PackageGraph};
use ironpost_sbom_scanner::error::SbomScannerError;
use std::path::Path;

pub struct GoModParser;

impl LockfileParser for GoModParser {
    fn ecosystem(&self) -> Ecosystem {
        Ecosystem::Go
    }

    fn can_parse(&self, path: &Path) -> bool {
        path.file_name()
            .and_then(|n| n.to_str())
            .is_some_and(|name| name == "go.sum")
    }

    fn parse(&self, content: &str, source_path: &str) -> Result<PackageGraph, SbomScannerError> {
        // Parse go.sum format
        // Return PackageGraph
        todo!()
    }
}
```

## CVE Matching Algorithm

### Version Range Matching

1. **SemVer Parsing**: Attempts to parse package version using `semver` crate
2. **Range Evaluation**: For each `VersionRange` in DB entry:
   - If `introduced` is set: check `version >= introduced`
   - If `fixed` is set: check `version < fixed`
   - Package is vulnerable if inside any range
3. **String Fallback**: If SemVer parsing fails, uses lexicographic string comparison (with caveats, see limitations)

### Severity Filtering

Only vulnerabilities with `severity >= min_severity` generate alerts:

```text
min_severity = Severity::Medium
// Alerts: Critical, High, Medium
// Ignored: Low, Info
```

### Package URL (PURL) Format

Generated PURLs follow the [Package URL specification](https://github.com/package-url/purl-spec):

- Cargo: `pkg:cargo/serde@1.0.204`
- NPM: `pkg:npm/lodash@4.17.21`
- Go: `pkg:golang/github.com/gin-gonic/gin@1.9.0`
- Python: `pkg:pypi/django@4.2.0`

## Performance Characteristics

### Resource Limits

| Resource | Limit | Configuration |
|----------|-------|---------------|
| Lockfile size | 10 MB (default) | `max_file_size` |
| Package count | 50,000 (default) | `max_packages` |
| VulnDb file size | 50 MB (per file) | Hard-coded constant |
| VulnDb entries | 1,000,000 | Hard-coded constant |
| Package name length | 512 chars | Hard-coded constant |
| Package version length | 256 chars | Hard-coded constant |

### Complexity

- **Lockfile parsing**: O(n) where n = package count
- **SBOM generation**: O(n) serialization
- **Vulnerability lookup**: O(1) via HashMap index on `(package_name, ecosystem)`
- **Version matching**: O(m) where m = affected_ranges per CVE (typically 1-3)

### Concurrency

- **Filesystem I/O**: All file operations wrapped in `tokio::task::spawn_blocking`
- **Periodic scanning**: Single background task per scanner instance
- **Database sharing**: `Arc<VulnDb>` enables zero-copy sharing across scan operations

## Security Considerations

### Input Validation

1. **File Size Limits**: Lockfiles exceeding `max_file_size` are skipped
2. **Package Count Limits**: Graphs exceeding `max_packages` are truncated with warning
3. **Field Length Limits**: Package names/versions exceeding limits are skipped
4. **Path Traversal**: Scan directories checked for `..` patterns (rejected)
5. **Symlink Protection**: Symlinks in scan directories are skipped
6. **TOCTOU Mitigation**: File operations use open-then-read pattern (single handle)

### DoS Protection

- VulnDb entries limited to 1M total
- Individual CVE descriptions capped at 8KB
- Affected ranges per entry capped at 100
- JSON parsing memory bounded by file size limits

### False Negatives

Version comparison using string fallback (when SemVer parsing fails) may miss vulnerabilities:
- Versions with `v` prefix: `v1.0.3` sorts lexicographically before `1.0.5`
- Multi-digit versions: `10.0.0` < `2.0.0` lexicographically

**Mitigation**: Ensure CVE database uses normalized SemVer-compliant version strings.

## Testing

### Run All Tests

```bash
cargo test -p ironpost-sbom-scanner
```

### Test Coverage

- **183 total tests**:
  - 165 unit tests (parser, generator, matcher, config, error)
  - 10 CVE matching integration tests
  - 6 pipeline lifecycle integration tests
  - 2 doc tests

### Key Test Scenarios

- Malformed TOML/JSON lockfiles
- Very long package names/versions (512+ chars)
- Unicode and special characters in package metadata
- Duplicate package entries
- NPM lockfile v2 vs v3 format differences
- CVE exact version match, range match, no-fixed-version scenarios
- Severity filtering across all levels
- Empty graphs, empty databases
- Large graphs (10K+ packages)
- Scanner lifecycle (start/stop/restart/health_check)

### Run with Coverage

```bash
cargo tarpaulin --out Html --output-dir coverage --packages ironpost-sbom-scanner
```

## Limitations

### Current Scope

1. **Offline Mode Only**: No network CVE API calls (Phase 5 scope)
2. **Single-Level Scan**: `scan_dirs` only scans immediate directory (not recursive)
3. **No Container Image Support**: Does not extract or scan container layers
4. **No License Scanning**: SBOM includes package metadata only (no license compliance checks)
5. **No Source Code Analysis**: Detects declared dependencies only (no static analysis)

### Known Issues

- **String Version Comparison**: Non-SemVer versions may produce incorrect matches (see Security Considerations)
- **Restart Limitation**: `stop()` prevents `start()` on same instance (rebuild with `SbomScannerBuilder`)
- **No Graceful Shutdown**: Periodic scan task aborts immediately (Phase 6 improvement)

## Roadmap

### Phase 6 Enhancements

- [ ] Graceful shutdown with in-flight scan completion
- [ ] Recursive directory scanning
- [ ] Container image layer extraction and scanning
- [ ] Online CVE database updates (NVD, GitHub Advisory Database)
- [ ] License compliance scanning
- [ ] SBOM diff and change tracking
- [ ] WebAssembly (WASM) package scanning
- [ ] Custom CVE database sources

## Integration with Ironpost

### Daemon Integration

`ironpost-daemon` orchestrates scanner with other modules:

```text
use ironpost_sbom_scanner::SbomScannerBuilder;
use ironpost_core::event::AlertEvent;
use tokio::sync::mpsc;

// Create shared alert channel
let (alert_tx, alert_rx) = mpsc::channel::<AlertEvent>(1000);

// Build SBOM scanner
let sbom_scanner = SbomScannerBuilder::new(sbom_config)
    .alert_sender(alert_tx.clone())
    .build()?;

// Build log pipeline (shares alert channel)
let log_pipeline = LogPipelineBuilder::new(log_config)
    .alert_sender(alert_tx.clone())
    .build()?;

// Start both
sbom_scanner.start().await?;
log_pipeline.start().await?;

// Unified alert handler receives from both modules
tokio::spawn(async move {
    while let Some(alert) = alert_rx.recv().await {
        match alert.alert.rule_name.as_str() {
            "sbom_vuln_scan" => handle_sbom_alert(alert),
            _ => handle_log_alert(alert),
        }
    }
});
```

### Event Flow

```text
SbomScanner --[AlertEvent]--> log-pipeline --[storage]--> PostgreSQL
                         |
                         +----> container-guard --[isolate]--> Docker API
```

## Module Structure

```text
crates/sbom-scanner/
  Cargo.toml                  -- Dependencies
  README.md                   -- This file
  src/
    lib.rs                    -- Module root, re-exports
    error.rs                  -- SbomScannerError enum
    config.rs                 -- SbomScannerConfig + builder
    event.rs                  -- ScanEvent + Event trait impl
    types.rs                  -- Ecosystem, Package, PackageGraph, SbomFormat, SbomDocument
    scanner.rs                -- SbomScanner + SbomScannerBuilder + Pipeline impl
    parser/
      mod.rs                  -- LockfileParser trait + LockfileDetector
      cargo.rs                -- CargoLockParser (TOML)
      npm.rs                  -- NpmLockParser (JSON v2/v3)
    sbom/
      mod.rs                  -- SbomGenerator dispatch
      cyclonedx.rs            -- CycloneDX 1.5 JSON generation
      spdx.rs                 -- SPDX 2.3 JSON generation
      util.rs                 -- Shared timestamp utilities
    vuln/
      mod.rs                  -- VulnMatcher, ScanFinding, ScanResult
      db.rs                   -- VulnDb + VulnDbEntry + load/query
      version.rs              -- SemVer version range matching
  tests/
    integration_tests.rs      -- End-to-end pipeline tests
    cve_matching_tests.rs     -- CVE matching edge case tests
    fixtures/
      test-cargo.lock         -- Sample Cargo.lock
      test-package-lock.json  -- Sample package-lock.json
      vuln-db/
        cargo.json            -- Test CVE database
```

## Dependencies

| Crate | Version | Purpose |
|-------|---------|---------|
| `ironpost-core` | path | Core types, traits, error handling |
| `tokio` | workspace | Async runtime, channels |
| `serde` | workspace | Serialization |
| `serde_json` | workspace | JSON parsing/generation |
| `toml` | workspace | Cargo.lock TOML parsing |
| `tracing` | workspace | Structured logging |
| `thiserror` | workspace | Error type derivation |
| `uuid` | workspace | Event ID generation |
| `semver` | 1 | Semantic version parsing and comparison |

## Contributing

### Code Conventions

- **Rust 2024 edition**: Use latest language features
- **Error Handling**: `thiserror` for domain errors, never `unwrap()` in production
- **Logging**: `tracing` macros (never `println!`)
- **Async**: `tokio::sync` primitives (never `std::sync::Mutex`)
- **Safety**: No `unsafe` without `// SAFETY:` justification
- **Testing**: Every public API has unit tests + doc tests

### Adding New Parser

1. Create `src/parser/{ecosystem}.rs`
2. Implement `LockfileParser` trait
3. Add to `LockfileDetector::known_filenames`
4. Add tests in `tests/integration_tests.rs`
5. Update this README

### Submitting Patches

1. Run `cargo fmt`
2. Run `cargo clippy -- -D warnings`
3. Add/update tests
4. Update doc comments
5. Test with `cargo test -p ironpost-sbom-scanner`

## License

See root LICENSE file.

## See Also

- [`ironpost-core`](../core/README.md) - Core types and traits
- [`ironpost-log-pipeline`](../log-pipeline/README.md) - Log analysis and alerts
- [`ironpost-container-guard`](../container-guard/README.md) - Container isolation
- [CycloneDX Specification](https://cyclonedx.org/)
- [SPDX Specification](https://spdx.dev/)
- [Package URL (PURL) Specification](https://github.com/package-url/purl-spec)

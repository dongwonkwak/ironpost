# ironpost-sbom-scanner

Ironpost SBOM (Software Bill of Materials) generation and CVE vulnerability scanning.

## Overview

`ironpost-sbom-scanner` parses dependency lockfiles (Cargo.lock, package-lock.json),
generates SBOM documents in CycloneDX 1.5 or SPDX 2.3 JSON format, and scans for
known vulnerabilities against a local CVE database.

## Features

- **Lockfile parsing**: Cargo.lock (TOML), package-lock.json (JSON v2/v3)
- **SBOM generation**: CycloneDX 1.5 JSON, SPDX 2.3 JSON
- **CVE scanning**: Local JSON vulnerability database, SemVer range matching
- **Severity filtering**: Configurable minimum severity threshold
- **Event integration**: Scan findings emitted as `AlertEvent` via `tokio::mpsc`
- **Pipeline lifecycle**: Implements core `Pipeline` trait (start/stop/health_check)
- **Extensible**: `LockfileParser` trait for adding new lockfile formats

## Architecture

```text
scan_dirs --> LockfileDetector --> LockfileParser --> PackageGraph
                                                         |
                                   +---------------------+---------------------+
                                   |                                           |
                             SbomGenerator                                VulnMatcher
                                   |                                           |
                             SbomDocument                               Vec<ScanFinding>
                                                                              |
                                                                        AlertEvent
                                                                              |
                                                                     mpsc --> downstream
```

## Quick Start

```text
# Add to Cargo.toml
[dependencies]
ironpost-sbom-scanner = { path = "../sbom-scanner" }
ironpost-core = { path = "../core" }
tokio = { version = "1", features = ["full"] }
```

## Configuration

Configured via the `[sbom]` section in `ironpost.toml`:

```toml
[sbom]
enabled = true
scan_dirs = ["/app", "/opt"]
vuln_db_path = "/var/lib/ironpost/vuln-db"
min_severity = "medium"
output_format = "cyclonedx"
```

## Vulnerability Database

The scanner uses a local JSON database stored in the configured `vuln_db_path` directory:

```text
/var/lib/ironpost/vuln-db/
  cargo.json     # Cargo ecosystem vulnerabilities
  npm.json       # NPM ecosystem vulnerabilities
```

## See Also

- `ironpost-core` - Core types and traits
- `ironpost-log-pipeline` - Log analysis and alert generation
- `ironpost-container-guard` - Container isolation

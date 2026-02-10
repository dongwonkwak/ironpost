//! CVE matching and edge case integration tests for SBOM scanner

use std::path::PathBuf;
use std::time::Duration;

use ironpost_core::pipeline::Pipeline;
use ironpost_core::types::Severity;
use ironpost_sbom_scanner::{SbomFormat, SbomScannerBuilder, SbomScannerConfig};

fn fixture_path(name: &str) -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("tests")
        .join("fixtures")
        .join(name)
}

/// Test CVE matching with exact version match
#[tokio::test]
async fn test_cve_exact_version_match() {
    let temp_dir = tempfile::tempdir().unwrap();
    let vuln_db_path = temp_dir.path().to_string_lossy().to_string();

    // Create CVE DB with exact version range
    let cve_db = r#"[
        {
            "cve_id": "CVE-2024-EXACT",
            "package": "exact-match-pkg",
            "ecosystem": "Cargo",
            "affected_ranges": [
                {
                    "introduced": "1.0.0",
                    "fixed": "1.0.1"
                }
            ],
            "fixed_version": "1.0.1",
            "severity": "High",
            "description": "Exact version match test",
            "published": "2024-01-01"
        }
    ]"#;
    let cargo_db_path = temp_dir.path().join("cargo.json");
    std::fs::write(&cargo_db_path, cve_db).unwrap();

    // Create lockfile with vulnerable version
    let lockfile_dir = tempfile::tempdir().unwrap();
    let lockfile_path = lockfile_dir.path().join("Cargo.lock");
    let lockfile_content = r#"
[[package]]
name = "exact-match-pkg"
version = "1.0.0"
source = "registry+https://github.com/rust-lang/crates.io-index"
"#;
    std::fs::write(&lockfile_path, lockfile_content).unwrap();

    let config = SbomScannerConfig {
        enabled: true,
        scan_dirs: vec![lockfile_dir.path().to_string_lossy().to_string()],
        vuln_db_path,
        min_severity: Severity::Info,
        output_format: SbomFormat::CycloneDx,
        scan_interval_secs: 0,
        max_file_size: 10 * 1024 * 1024,
        max_packages: 10000,
    };

    let (mut scanner, _) = SbomScannerBuilder::new().config(config).build().unwrap();

    scanner.start().await.unwrap();
    let results = scanner.scan_once().await.unwrap();

    assert!(!results.is_empty());
    let result = &results[0];
    assert_eq!(result.findings.len(), 1);
    assert_eq!(result.findings[0].vulnerability.cve_id, "CVE-2024-EXACT");

    scanner.stop().await.unwrap();
}

/// Test CVE matching with version range (introduce..fixed)
#[tokio::test]
async fn test_cve_version_range_match() {
    let temp_dir = tempfile::tempdir().unwrap();
    let vuln_db_path = temp_dir.path().to_string_lossy().to_string();

    let cve_db = r#"[
        {
            "cve_id": "CVE-2024-RANGE",
            "package": "range-pkg",
            "ecosystem": "Cargo",
            "affected_ranges": [
                {
                    "introduced": "1.0.0",
                    "fixed": "2.0.0"
                }
            ],
            "fixed_version": "2.0.0",
            "severity": "Medium",
            "description": "Version range test",
            "published": "2024-01-01"
        }
    ]"#;
    let cargo_db_path = temp_dir.path().join("cargo.json");
    std::fs::write(&cargo_db_path, cve_db).unwrap();

    let lockfile_dir = tempfile::tempdir().unwrap();
    let lockfile_path = lockfile_dir.path().join("Cargo.lock");
    let lockfile_content = r#"
[[package]]
name = "range-pkg"
version = "1.5.0"
source = "registry+https://github.com/rust-lang/crates.io-index"
"#;
    std::fs::write(&lockfile_path, lockfile_content).unwrap();

    let config = SbomScannerConfig {
        enabled: true,
        scan_dirs: vec![lockfile_dir.path().to_string_lossy().to_string()],
        vuln_db_path,
        min_severity: Severity::Info,
        output_format: SbomFormat::CycloneDx,
        scan_interval_secs: 0,
        max_file_size: 10 * 1024 * 1024,
        max_packages: 10000,
    };

    let (mut scanner, _) = SbomScannerBuilder::new().config(config).build().unwrap();

    scanner.start().await.unwrap();
    let results = scanner.scan_once().await.unwrap();

    assert!(!results.is_empty());
    assert_eq!(results[0].findings.len(), 1);
    assert_eq!(
        results[0].findings[0].vulnerability.cve_id,
        "CVE-2024-RANGE"
    );

    scanner.stop().await.unwrap();
}

/// Test CVE matching with no fixed version (all future versions affected)
#[tokio::test]
async fn test_cve_no_fixed_version() {
    let temp_dir = tempfile::tempdir().unwrap();
    let vuln_db_path = temp_dir.path().to_string_lossy().to_string();

    let cve_db = r#"[
        {
            "cve_id": "CVE-2024-UNFIXED",
            "package": "unfixed-pkg",
            "ecosystem": "Cargo",
            "affected_ranges": [
                {
                    "introduced": "1.0.0",
                    "fixed": null
                }
            ],
            "fixed_version": null,
            "severity": "Critical",
            "description": "Unfixed vulnerability",
            "published": "2024-01-01"
        }
    ]"#;
    let cargo_db_path = temp_dir.path().join("cargo.json");
    std::fs::write(&cargo_db_path, cve_db).unwrap();

    let lockfile_dir = tempfile::tempdir().unwrap();
    let lockfile_path = lockfile_dir.path().join("Cargo.lock");
    let lockfile_content = r#"
[[package]]
name = "unfixed-pkg"
version = "99.99.99"
source = "registry+https://github.com/rust-lang/crates.io-index"
"#;
    std::fs::write(&lockfile_path, lockfile_content).unwrap();

    let config = SbomScannerConfig {
        enabled: true,
        scan_dirs: vec![lockfile_dir.path().to_string_lossy().to_string()],
        vuln_db_path,
        min_severity: Severity::Info,
        output_format: SbomFormat::CycloneDx,
        scan_interval_secs: 0,
        max_file_size: 10 * 1024 * 1024,
        max_packages: 10000,
    };

    let (mut scanner, _) = SbomScannerBuilder::new().config(config).build().unwrap();

    scanner.start().await.unwrap();
    let results = scanner.scan_once().await.unwrap();

    assert!(!results.is_empty());
    assert_eq!(results[0].findings.len(), 1);
    assert!(results[0].findings[0].vulnerability.fixed_version.is_none());

    scanner.stop().await.unwrap();
}

/// Test severity filtering (min_severity threshold)
#[tokio::test]
async fn test_severity_filtering() {
    let temp_dir = tempfile::tempdir().unwrap();
    let vuln_db_path = temp_dir.path().to_string_lossy().to_string();

    let cve_db = r#"[
        {
            "cve_id": "CVE-2024-LOW",
            "package": "test-pkg",
            "ecosystem": "Cargo",
            "affected_ranges": [{"introduced": "1.0.0", "fixed": null}],
            "fixed_version": null,
            "severity": "Low",
            "description": "Low severity",
            "published": "2024-01-01"
        },
        {
            "cve_id": "CVE-2024-HIGH",
            "package": "test-pkg",
            "ecosystem": "Cargo",
            "affected_ranges": [{"introduced": "1.0.0", "fixed": null}],
            "fixed_version": null,
            "severity": "High",
            "description": "High severity",
            "published": "2024-01-01"
        }
    ]"#;
    let cargo_db_path = temp_dir.path().join("cargo.json");
    std::fs::write(&cargo_db_path, cve_db).unwrap();

    let lockfile_dir = tempfile::tempdir().unwrap();
    let lockfile_path = lockfile_dir.path().join("Cargo.lock");
    let lockfile_content = r#"
[[package]]
name = "test-pkg"
version = "1.0.0"
source = "registry+https://github.com/rust-lang/crates.io-index"
"#;
    std::fs::write(&lockfile_path, lockfile_content).unwrap();

    // Test with High threshold - should only get High
    let config = SbomScannerConfig {
        enabled: true,
        scan_dirs: vec![lockfile_dir.path().to_string_lossy().to_string()],
        vuln_db_path,
        min_severity: Severity::High,
        output_format: SbomFormat::CycloneDx,
        scan_interval_secs: 0,
        max_file_size: 10 * 1024 * 1024,
        max_packages: 10000,
    };

    let (mut scanner, _) = SbomScannerBuilder::new().config(config).build().unwrap();

    scanner.start().await.unwrap();
    let results = scanner.scan_once().await.unwrap();

    assert!(!results.is_empty());
    // Only HIGH severity should be reported
    assert_eq!(results[0].findings.len(), 1);
    assert_eq!(results[0].findings[0].vulnerability.cve_id, "CVE-2024-HIGH");

    scanner.stop().await.unwrap();
}

/// Test clean scan results (no vulnerabilities found)
#[tokio::test]
async fn test_clean_scan_no_vulnerabilities() {
    let temp_dir = tempfile::tempdir().unwrap();
    let vuln_db_path = temp_dir.path().to_string_lossy().to_string();

    // Create empty CVE DB
    let cve_db = "[]";
    let cargo_db_path = temp_dir.path().join("cargo.json");
    std::fs::write(&cargo_db_path, cve_db).unwrap();

    let test_lockfile = fixture_path("Cargo.lock");
    let test_dir = test_lockfile
        .parent()
        .unwrap()
        .to_string_lossy()
        .to_string();

    let config = SbomScannerConfig {
        enabled: true,
        scan_dirs: vec![test_dir],
        vuln_db_path,
        min_severity: Severity::Info,
        output_format: SbomFormat::CycloneDx,
        scan_interval_secs: 0,
        max_file_size: 10 * 1024 * 1024,
        max_packages: 10000,
    };

    let (mut scanner, alert_rx_opt) = SbomScannerBuilder::new().config(config).build().unwrap();

    let mut alert_rx = alert_rx_opt.unwrap();

    scanner.start().await.unwrap();
    let results = scanner.scan_once().await.unwrap();

    assert!(!results.is_empty());
    // No findings expected
    for result in &results {
        assert_eq!(result.findings.len(), 0);
    }

    // No alerts should be sent
    tokio::time::timeout(Duration::from_millis(100), alert_rx.recv())
        .await
        .expect_err("should timeout - no alerts");

    scanner.stop().await.unwrap();
}

/// Test SBOM generation format (CycloneDX vs SPDX)
#[tokio::test]
async fn test_sbom_format_cyclonedx() {
    let test_lockfile = fixture_path("Cargo.lock");
    let test_dir = test_lockfile
        .parent()
        .unwrap()
        .to_string_lossy()
        .to_string();

    let config = SbomScannerConfig {
        enabled: true,
        scan_dirs: vec![test_dir],
        vuln_db_path: "/nonexistent/vuln-db".to_owned(),
        min_severity: Severity::Info,
        output_format: SbomFormat::CycloneDx,
        scan_interval_secs: 0,
        max_file_size: 10 * 1024 * 1024,
        max_packages: 10000,
    };

    let (mut scanner, _) = SbomScannerBuilder::new().config(config).build().unwrap();

    scanner.start().await.unwrap();
    let results = scanner.scan_once().await.unwrap();

    assert!(!results.is_empty());
    let sbom = results[0].sbom_document.as_ref().unwrap();
    assert!(sbom.content.contains("bomFormat"));
    assert!(sbom.content.contains("CycloneDX"));

    scanner.stop().await.unwrap();
}

/// Test multiple lockfiles in same directory
#[tokio::test]
async fn test_multiple_lockfiles_in_directory() {
    let test_lockfile = fixture_path("Cargo.lock");
    let test_dir = test_lockfile
        .parent()
        .unwrap()
        .to_string_lossy()
        .to_string();

    let config = SbomScannerConfig {
        enabled: true,
        scan_dirs: vec![test_dir],
        vuln_db_path: "/nonexistent/vuln-db".to_owned(),
        min_severity: Severity::Info,
        output_format: SbomFormat::CycloneDx,
        scan_interval_secs: 0,
        max_file_size: 10 * 1024 * 1024,
        max_packages: 10000,
    };

    let (mut scanner, _) = SbomScannerBuilder::new().config(config).build().unwrap();

    scanner.start().await.unwrap();
    let results = scanner.scan_once().await.unwrap();

    // Should find both Cargo.lock and package-lock.json
    assert!(results.len() >= 2, "should find multiple lockfiles");

    let has_cargo = results.iter().any(|r| r.source_file.contains("Cargo.lock"));
    let has_npm = results
        .iter()
        .any(|r| r.source_file.contains("package-lock.json"));

    assert!(has_cargo, "should find Cargo.lock");
    assert!(has_npm, "should find package-lock.json");

    scanner.stop().await.unwrap();
}

/// Test scanner lifecycle (start -> stop -> health check)
#[tokio::test]
async fn test_scanner_lifecycle() {
    let test_lockfile = fixture_path("Cargo.lock");
    let test_dir = test_lockfile
        .parent()
        .unwrap()
        .to_string_lossy()
        .to_string();

    let config = SbomScannerConfig {
        enabled: true,
        scan_dirs: vec![test_dir],
        vuln_db_path: "/nonexistent/vuln-db".to_owned(),
        min_severity: Severity::Info,
        output_format: SbomFormat::CycloneDx,
        scan_interval_secs: 0,
        max_file_size: 10 * 1024 * 1024,
        max_packages: 10000,
    };

    let (mut scanner, _) = SbomScannerBuilder::new().config(config).build().unwrap();

    // Before start: Unhealthy
    let health = scanner.health_check().await;
    assert!(health.is_unhealthy());

    // Start
    scanner.start().await.unwrap();
    let results1 = scanner.scan_once().await.unwrap();
    assert!(!results1.is_empty());

    // Stop
    scanner.stop().await.unwrap();
    let health = scanner.health_check().await;
    assert!(health.is_unhealthy());
}

/// Test max file size enforcement
#[tokio::test]
async fn test_max_file_size_enforcement() {
    let lockfile_dir = tempfile::tempdir().unwrap();
    let lockfile_path = lockfile_dir.path().join("Cargo.lock");

    // Create a large lockfile (> max_file_size)
    let mut large_content = String::new();
    for i in 0..100 {
        large_content.push_str(&format!(
            r#"
[[package]]
name = "pkg-{}"
version = "1.0.0"
source = "registry+https://github.com/rust-lang/crates.io-index"
"#,
            i
        ));
    }
    std::fs::write(&lockfile_path, &large_content).unwrap();

    let config = SbomScannerConfig {
        enabled: true,
        scan_dirs: vec![lockfile_dir.path().to_string_lossy().to_string()],
        vuln_db_path: "/nonexistent/vuln-db".to_owned(),
        min_severity: Severity::Info,
        output_format: SbomFormat::CycloneDx,
        scan_interval_secs: 0,
        max_file_size: 100, // Very small limit
        max_packages: 10000,
    };

    let (mut scanner, _) = SbomScannerBuilder::new().config(config).build().unwrap();

    scanner.start().await.unwrap();

    // Large file should be skipped
    let results = scanner.scan_once().await.unwrap();
    assert!(
        results.is_empty(),
        "large file should be skipped due to size limit"
    );

    scanner.stop().await.unwrap();
}

/// Test malformed lockfile handling
#[tokio::test]
async fn test_malformed_lockfile_skipped() {
    let lockfile_dir = tempfile::tempdir().unwrap();
    let lockfile_path = lockfile_dir.path().join("Cargo.lock");

    // Create malformed lockfile
    std::fs::write(&lockfile_path, "invalid toml [[[ content").unwrap();

    let config = SbomScannerConfig {
        enabled: true,
        scan_dirs: vec![lockfile_dir.path().to_string_lossy().to_string()],
        vuln_db_path: "/nonexistent/vuln-db".to_owned(),
        min_severity: Severity::Info,
        output_format: SbomFormat::CycloneDx,
        scan_interval_secs: 0,
        max_file_size: 10 * 1024 * 1024,
        max_packages: 10000,
    };

    let (mut scanner, _) = SbomScannerBuilder::new().config(config).build().unwrap();

    scanner.start().await.unwrap();

    // Malformed file should be skipped gracefully
    let results = scanner.scan_once().await.unwrap();
    assert!(
        results.is_empty(),
        "malformed file should be skipped gracefully"
    );

    scanner.stop().await.unwrap();
}

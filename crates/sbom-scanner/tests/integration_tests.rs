//! Integration tests for SBOM scanner
//!
//! Tests the full pipeline: lockfile parsing -> SBOM generation -> vulnerability scanning -> AlertEvent

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

/// Test end-to-end pipeline: Cargo.lock -> SBOM + vulnerability scan -> AlertEvent
#[tokio::test]
async fn test_e2e_cargo_lock_scan() {
    let test_lockfile = fixture_path("Cargo.lock");
    let test_dir = test_lockfile
        .parent()
        .unwrap()
        .to_string_lossy()
        .to_string();

    let config = SbomScannerConfig {
        enabled: true,
        scan_dirs: vec![test_dir],
        vuln_db_path: "/nonexistent/vuln-db".to_owned(), // Non-existent path is OK
        min_severity: Severity::Info,
        output_format: SbomFormat::CycloneDx,
        scan_interval_secs: 0, // Manual scan only
        max_file_size: 10 * 1024 * 1024,
        max_packages: 10000,
    };

    let (mut scanner, alert_rx_opt) = SbomScannerBuilder::new().config(config).build().unwrap();

    let mut alert_rx = alert_rx_opt.unwrap();

    scanner.start().await.unwrap();

    // Perform manual scan
    let results = scanner.scan_once().await.unwrap();

    // Should find at least one lockfile
    assert!(!results.is_empty(), "should find test lockfiles");

    let cargo_result = results
        .iter()
        .find(|r| r.source_file.contains("Cargo.lock"));

    assert!(cargo_result.is_some(), "should scan Cargo.lock");

    let result = cargo_result.unwrap();
    assert_eq!(result.total_packages, 3); // test-app, vulnerable-test-pkg, safe-pkg
    assert!(result.sbom_document.is_some(), "should generate SBOM");

    let sbom = result.sbom_document.as_ref().unwrap();
    assert_eq!(sbom.component_count, 3);
    assert!(sbom.content.contains("vulnerable-test-pkg"));
    assert!(sbom.content.contains("safe-pkg"));

    scanner.stop().await.unwrap();

    // Alert channel should be empty (no vuln DB loaded)
    tokio::time::timeout(Duration::from_millis(100), alert_rx.recv())
        .await
        .expect_err("should timeout - no alerts without vuln DB");
}

/// Test end-to-end pipeline with vulnerability database
#[tokio::test]
async fn test_e2e_with_vuln_db() {
    let test_lockfile = fixture_path("Cargo.lock");
    let test_dir = test_lockfile
        .parent()
        .unwrap()
        .to_string_lossy()
        .to_string();

    // Create temp dir for vuln DB
    let temp_dir = tempfile::tempdir().unwrap();
    let vuln_db_path = temp_dir.path().to_string_lossy().to_string();

    // Copy test vuln DB
    let test_vuln_db = fixture_path("test-vuln-db.json");
    let cargo_db_path = temp_dir.path().join("cargo.json");
    std::fs::copy(&test_vuln_db, &cargo_db_path).unwrap();

    let config = SbomScannerConfig {
        enabled: true,
        scan_dirs: vec![test_dir],
        vuln_db_path,
        min_severity: Severity::Info,
        output_format: SbomFormat::Spdx,
        scan_interval_secs: 0,
        max_file_size: 10 * 1024 * 1024,
        max_packages: 10000,
    };

    let (mut scanner, alert_rx_opt) = SbomScannerBuilder::new().config(config).build().unwrap();

    let mut alert_rx = alert_rx_opt.unwrap();

    scanner.start().await.unwrap();
    assert!(scanner.is_vuln_db_loaded(), "should load vuln DB");

    // Perform manual scan
    let results = scanner.scan_once().await.unwrap();
    assert!(!results.is_empty());

    let cargo_result = results
        .iter()
        .find(|r| r.source_file.contains("Cargo.lock"))
        .unwrap();

    // Should find vulnerability (vulnerable-test-pkg 0.1.5 is in range 0.1.0-0.2.0)
    assert_eq!(
        cargo_result.findings.len(),
        1,
        "should find 1 vulnerability"
    );

    let finding = &cargo_result.findings[0];
    assert_eq!(finding.vulnerability.cve_id, "CVE-2024-TEST-0001");
    assert_eq!(finding.vulnerability.package, "vulnerable-test-pkg");
    assert_eq!(finding.vulnerability.severity, Severity::Critical);

    // Should receive alert event
    // Note: Directory contains both Cargo.lock and package-lock.json, so we may receive
    // alerts in any order. Collect alerts until we find the Cargo CVE.
    let mut cargo_alert = None;
    let deadline = tokio::time::Instant::now() + Duration::from_millis(500);

    while tokio::time::Instant::now() < deadline {
        match tokio::time::timeout_at(deadline, alert_rx.recv()).await {
            Ok(Some(event)) if event.alert.title.contains("CVE-2024-TEST-0001") => {
                cargo_alert = Some(event);
                break;
            }
            Ok(Some(_)) => continue, // Different alert, keep looking
            Ok(None) => panic!("alert channel closed unexpectedly"),
            Err(_) => break, // Timeout
        }
    }

    let alert_event = cargo_alert.expect("should receive CVE-2024-TEST-0001 alert");
    assert_eq!(alert_event.severity, Severity::Critical);

    // Verify metrics
    // Scanner finds both lockfiles in the fixtures directory
    assert!(
        scanner.scans_completed() >= 1,
        "should complete at least one scan"
    );
    assert!(
        scanner.vulns_found() >= 1,
        "should find at least one vulnerability"
    );

    scanner.stop().await.unwrap();
}

/// Test NPM package-lock.json scanning
#[tokio::test]
async fn test_npm_package_lock_scan() {
    let test_lockfile = fixture_path("package-lock.json");
    let test_dir = test_lockfile
        .parent()
        .unwrap()
        .to_string_lossy()
        .to_string();

    let temp_dir = tempfile::tempdir().unwrap();
    let vuln_db_path = temp_dir.path().to_string_lossy().to_string();

    // Create NPM vuln DB
    let test_vuln_db = fixture_path("test-vuln-db.json");
    let npm_db_path = temp_dir.path().join("npm.json");
    std::fs::copy(&test_vuln_db, &npm_db_path).unwrap();

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

    let npm_result = results
        .iter()
        .find(|r| r.source_file.contains("package-lock.json"));

    assert!(npm_result.is_some(), "should scan package-lock.json");

    let result = npm_result.unwrap();
    assert_eq!(result.total_packages, 1); // lodash only

    // lodash 4.17.20 is in vulnerable range [4.0.0, 4.17.21)
    assert_eq!(result.findings.len(), 1);
    assert_eq!(
        result.findings[0].vulnerability.cve_id,
        "CVE-2024-TEST-0002"
    );
    assert_eq!(result.findings[0].vulnerability.severity, Severity::High);

    // Should receive at least one alert
    let alert_event = tokio::time::timeout(Duration::from_millis(500), alert_rx.recv())
        .await
        .unwrap()
        .unwrap();

    // Alert could be for lodash (NPM) or vulnerable-test-pkg (Cargo) depending on scan order
    let title = &alert_event.alert.title;
    assert!(
        title.contains("CVE-2024-TEST-0002") || title.contains("CVE-2024-TEST-0001"),
        "alert should contain a CVE ID, got: {}",
        title
    );

    scanner.stop().await.unwrap();
}

/// Test scanner health check states
#[tokio::test]
async fn test_scanner_health_states() {
    let config = SbomScannerConfig {
        enabled: true,
        scan_dirs: vec!["/nonexistent/scan/dir".to_owned()],
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

    // After start with no DB: Degraded
    scanner.start().await.unwrap();
    let health = scanner.health_check().await;
    assert!(!health.is_healthy()); // Should be degraded or unhealthy

    // After stop: Unhealthy
    scanner.stop().await.unwrap();
    let health = scanner.health_check().await;
    assert!(health.is_unhealthy());
}

/// Test max packages limit enforcement
#[tokio::test]
async fn test_max_packages_limit() {
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
        max_packages: 2, // Lower than actual package count (3)
    };

    let (mut scanner, _) = SbomScannerBuilder::new().config(config).build().unwrap();

    scanner.start().await.unwrap();

    // Should skip lockfile due to max_packages limit
    let results = scanner.scan_once().await.unwrap();

    // Results should be empty or without the test lockfile
    let cargo_result = results
        .iter()
        .find(|r| r.source_file.contains("Cargo.lock"));

    // Lockfile should be skipped due to package limit
    assert!(
        cargo_result.is_none(),
        "should skip lockfile with too many packages"
    );

    scanner.stop().await.unwrap();
}

/// Test repeated sequential scans do not panic
#[tokio::test]
async fn test_repeated_sequential_scans() {
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

    // Run multiple scans sequentially (scan_once needs &self, not concurrent)
    for _ in 0..3 {
        let result = scanner.scan_once().await;
        assert!(result.is_ok(), "multiple scans should succeed");
    }

    scanner.stop().await.unwrap();
}

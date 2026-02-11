//! S2: SBOM scan -> AlertEvent E2E tests.
//!
//! Validates that the SBOM scanner correctly discovers vulnerabilities
//! and converts them to AlertEvents routed through the alert channel.

// Helpers will be used when tests are implemented in T7.3
#[allow(unused_imports)]
use crate::helpers::assertions::*;
#[allow(unused_imports)]
use crate::helpers::events::*;

#[allow(unused_imports)]
use ironpost_core::event::{AlertEvent, MODULE_SBOM_SCANNER};
#[allow(unused_imports)]
use ironpost_core::types::Severity;
#[allow(unused_imports)]
use tokio::sync::mpsc;

// ---------------------------------------------------------------------------
// T7.3 will implement the following test functions.
// ---------------------------------------------------------------------------

/// SBOM scanner finds a known vulnerable package -> AlertEvent generated
/// with correct CVE ID and severity.
#[tokio::test]
#[ignore] // T7.3: implementation pending
async fn test_e2e_sbom_scan_vuln_found_alert() {
    // 1. Create temp Cargo.lock with a vulnerable package
    // 2. Configure SBOM scanner to scan temp directory
    // 3. Assert AlertEvent received with CVE info
}

/// Clean project with no vulnerabilities -> no AlertEvent generated.
#[tokio::test]
#[ignore] // T7.3: implementation pending
async fn test_e2e_sbom_scan_clean_no_alert() {
    // 1. Create temp Cargo.lock with only safe packages
    // 2. Run scan
    // 3. Assert no AlertEvent within SHORT_TIMEOUT
}

/// Multiple vulnerabilities -> one AlertEvent per vulnerability.
#[tokio::test]
#[ignore] // T7.3: implementation pending
async fn test_e2e_sbom_scan_multiple_vulns() {
    // 1. Create lockfile with 3 vulnerable packages
    // 2. Assert 3 AlertEvents received
}

/// Vulnerability severity is correctly mapped to AlertEvent severity.
#[tokio::test]
#[ignore] // T7.3: implementation pending
async fn test_e2e_sbom_alert_severity_mapping() {
    // 1. Create vulns with CRITICAL, HIGH, MEDIUM severities
    // 2. Assert each AlertEvent has corresponding severity
}

/// SBOM AlertEvent has source_module == "sbom-scanner".
#[tokio::test]
#[ignore] // T7.3: implementation pending
async fn test_e2e_sbom_alert_source_module() {
    // 1. Generate SBOM alert
    // 2. Assert metadata.source_module == MODULE_SBOM_SCANNER
}

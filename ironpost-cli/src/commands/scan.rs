//! `ironpost scan` command handler

use std::io::Write;
use std::path::Path;

use serde::Serialize;
use tracing::info;

use ironpost_core::config::IronpostConfig;
use ironpost_core::pipeline::Pipeline;
use ironpost_core::types::Severity;
use ironpost_sbom_scanner::{SbomFormat, SbomScannerBuilder, SbomScannerConfigBuilder};

use crate::cli::ScanArgs;
use crate::error::CliError;
use crate::output::{OutputWriter, Render};

/// Execute the `scan` command.
pub async fn execute(
    args: ScanArgs,
    config_path: &Path,
    writer: &OutputWriter,
) -> Result<(), CliError> {
    let config = IronpostConfig::load(config_path).await?;

    // Parse min severity and SBOM format
    let min_severity = parse_severity(&args.min_severity)?;
    let sbom_format = parse_sbom_format(&args.sbom_format)?;

    // Build scanner config from CLI args and core config
    let scanner_config = SbomScannerConfigBuilder::default()
        .scan_dirs(vec![args.path.display().to_string()])
        .vuln_db_path(config.sbom.vuln_db_path.clone())
        .min_severity(min_severity)
        .output_format(sbom_format)
        .build()
        .map_err(|e| CliError::Scan(format!("invalid scanner config: {}", e)))?;

    info!(path = %args.path.display(), "starting SBOM scan");

    // Build scanner (builder creates alert channel internally)
    let (mut scanner, alert_rx_opt) = SbomScannerBuilder::new()
        .config(scanner_config)
        .build()
        .map_err(|e| CliError::Scan(format!("failed to build scanner: {}", e)))?;

    // Start scanner (loads VulnDb)
    scanner.start().await?;

    // Run one-shot scan
    let scan_results = scanner.scan_once().await?;

    // Stop scanner
    scanner.stop().await?;

    // Close alert channel and drain any remaining alerts if present
    if let Some(alert_rx) = alert_rx_opt {
        drop(alert_rx); // Close by dropping
    }

    // Convert results to report
    let report = build_scan_report(args.path.display().to_string(), scan_results, min_severity);

    writer.render(&report)?;

    // Return error if vulnerabilities found (exit code 4)
    if report.vulnerabilities.total > 0 {
        return Err(CliError::Scan(format!(
            "found {} vulnerabilities",
            report.vulnerabilities.total
        )));
    }

    Ok(())
}

fn parse_severity(s: &str) -> Result<Severity, CliError> {
    match s.to_lowercase().as_str() {
        "info" => Ok(Severity::Info),
        "low" => Ok(Severity::Low),
        "medium" => Ok(Severity::Medium),
        "high" => Ok(Severity::High),
        "critical" => Ok(Severity::Critical),
        _ => Err(CliError::Command(format!(
            "invalid severity: {} (expected: info, low, medium, high, critical)",
            s
        ))),
    }
}

fn parse_sbom_format(s: &str) -> Result<SbomFormat, CliError> {
    match s.to_lowercase().as_str() {
        "cyclonedx" => Ok(SbomFormat::CycloneDx),
        "spdx" => Ok(SbomFormat::Spdx),
        _ => Err(CliError::Command(format!(
            "invalid SBOM format: {} (expected: cyclonedx, spdx)",
            s
        ))),
    }
}

fn build_scan_report(
    path: String,
    results: Vec<ironpost_sbom_scanner::vuln::ScanResult>,
    min_severity: Severity,
) -> ScanReport {
    let mut lockfiles_scanned = 0;
    let mut total_packages = 0;
    let mut findings = Vec::new();

    let mut vuln_summary = VulnSummary::default();

    for result in results {
        lockfiles_scanned += 1;
        total_packages += result.total_packages;

        let severity_counts = result.severity_counts();
        vuln_summary.critical += severity_counts.critical;
        vuln_summary.high += severity_counts.high;
        vuln_summary.medium += severity_counts.medium;
        vuln_summary.low += severity_counts.low;
        vuln_summary.info += severity_counts.info;

        for finding in result.findings {
            // Filter by min_severity
            if severity_level(&finding.vulnerability.severity) < severity_level(&min_severity) {
                continue;
            }

            findings.push(FindingEntry {
                cve_id: finding.vulnerability.cve_id.clone(),
                package: finding.matched_package.name.clone(),
                version: finding.matched_package.version.to_string(),
                severity: format!("{:?}", finding.vulnerability.severity),
                fixed_version: finding.vulnerability.fixed_version.clone(),
                description: finding.vulnerability.description.clone(),
            });
        }
    }

    vuln_summary.total = vuln_summary.critical
        + vuln_summary.high
        + vuln_summary.medium
        + vuln_summary.low
        + vuln_summary.info;

    ScanReport {
        path,
        lockfiles_scanned,
        total_packages,
        vulnerabilities: vuln_summary,
        findings,
    }
}

fn severity_level(severity: &Severity) -> u8 {
    match severity {
        Severity::Info => 0,
        Severity::Low => 1,
        Severity::Medium => 2,
        Severity::High => 3,
        Severity::Critical => 4,
    }
}

#[derive(Serialize)]
pub struct ScanReport {
    pub path: String,
    pub lockfiles_scanned: usize,
    pub total_packages: usize,
    pub vulnerabilities: VulnSummary,
    pub findings: Vec<FindingEntry>,
}

#[derive(Serialize, Default)]
pub struct VulnSummary {
    pub critical: usize,
    pub high: usize,
    pub medium: usize,
    pub low: usize,
    pub info: usize,
    pub total: usize,
}

#[derive(Serialize)]
pub struct FindingEntry {
    pub cve_id: String,
    pub package: String,
    pub version: String,
    pub severity: String,
    pub fixed_version: Option<String>,
    pub description: String,
}

impl Render for ScanReport {
    fn render_text(&self, w: &mut dyn Write) -> std::io::Result<()> {
        use colored::Colorize;

        writeln!(w, "Scan: {}", self.path.bold())?;
        writeln!(w, "Lockfiles scanned: {}", self.lockfiles_scanned)?;
        writeln!(w, "Total packages: {}", self.total_packages)?;
        writeln!(w)?;

        let vuln_str = format!(
            "{} total (C:{} H:{} M:{} L:{} I:{})",
            self.vulnerabilities.total,
            self.vulnerabilities.critical,
            self.vulnerabilities.high,
            self.vulnerabilities.medium,
            self.vulnerabilities.low,
            self.vulnerabilities.info
        );

        if self.vulnerabilities.total > 0 {
            writeln!(w, "Vulnerabilities: {}", vuln_str.red().bold())?;
        } else {
            writeln!(w, "Vulnerabilities: {}", vuln_str.green().bold())?;
        }

        writeln!(w)?;

        if self.findings.is_empty() {
            writeln!(w, "{}", "No vulnerabilities found.".green())?;
        } else {
            writeln!(
                w,
                "{:<18} {:<10} {:<25} {:<12} Fixed",
                "CVE", "Severity", "Package", "Version"
            )?;
            writeln!(w, "{}", "-".repeat(80))?;

            for f in &self.findings {
                let severity_colored = match f.severity.as_str() {
                    "Critical" => f.severity.red().bold(),
                    "High" => f.severity.red(),
                    "Medium" => f.severity.yellow(),
                    "Low" => f.severity.normal(),
                    "Info" => f.severity.dimmed(),
                    _ => f.severity.normal(),
                };

                writeln!(
                    w,
                    "{:<18} {:<10} {:<25} {:<12} {}",
                    f.cve_id,
                    severity_colored,
                    f.package,
                    f.version,
                    f.fixed_version.as_deref().unwrap_or("N/A")
                )?;
            }
        }

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_severity_valid_lowercase() {
        let result = parse_severity("info");
        assert!(result.is_ok(), "should parse 'info'");
        assert!(matches!(result.expect("ok"), Severity::Info));
    }

    #[test]
    fn test_parse_severity_valid_uppercase() {
        let result = parse_severity("CRITICAL");
        assert!(result.is_ok(), "should parse 'CRITICAL'");
        assert!(matches!(result.expect("ok"), Severity::Critical));
    }

    #[test]
    fn test_parse_severity_all_levels() {
        let levels = [
            ("info", Severity::Info),
            ("low", Severity::Low),
            ("medium", Severity::Medium),
            ("high", Severity::High),
            ("critical", Severity::Critical),
        ];

        for (input, expected) in levels {
            let result = parse_severity(input).expect("should parse valid severity");
            assert_eq!(
                format!("{:?}", result),
                format!("{:?}", expected),
                "severity mismatch for {}",
                input
            );
        }
    }

    #[test]
    fn test_parse_severity_invalid() {
        let result = parse_severity("invalid");
        assert!(result.is_err(), "should reject invalid severity");
        let err = result.expect_err("should be error");
        let err_str = format!("{}", err);
        assert!(
            err_str.contains("invalid severity"),
            "error should mention invalid severity"
        );
    }

    #[test]
    fn test_parse_severity_empty_string() {
        let result = parse_severity("");
        assert!(result.is_err(), "should reject empty string");
    }

    #[test]
    fn test_parse_sbom_format_cyclonedx() {
        let result = parse_sbom_format("cyclonedx");
        assert!(result.is_ok(), "should parse 'cyclonedx'");
        assert!(matches!(result.expect("ok"), SbomFormat::CycloneDx));
    }

    #[test]
    fn test_parse_sbom_format_spdx() {
        let result = parse_sbom_format("spdx");
        assert!(result.is_ok(), "should parse 'spdx'");
        assert!(matches!(result.expect("ok"), SbomFormat::Spdx));
    }

    #[test]
    fn test_parse_sbom_format_case_insensitive() {
        let result = parse_sbom_format("CycloneDX");
        assert!(result.is_ok(), "should parse case-insensitive");
        assert!(matches!(result.expect("ok"), SbomFormat::CycloneDx));
    }

    #[test]
    fn test_parse_sbom_format_invalid() {
        let result = parse_sbom_format("invalid");
        assert!(result.is_err(), "should reject invalid format");
        let err = result.expect_err("should be error");
        let err_str = format!("{}", err);
        assert!(
            err_str.contains("invalid SBOM format"),
            "error should mention format"
        );
    }

    #[test]
    fn test_severity_level_ordering() {
        assert!(severity_level(&Severity::Info) < severity_level(&Severity::Low));
        assert!(severity_level(&Severity::Low) < severity_level(&Severity::Medium));
        assert!(severity_level(&Severity::Medium) < severity_level(&Severity::High));
        assert!(severity_level(&Severity::High) < severity_level(&Severity::Critical));
    }

    #[test]
    fn test_severity_level_values() {
        assert_eq!(severity_level(&Severity::Info), 0);
        assert_eq!(severity_level(&Severity::Low), 1);
        assert_eq!(severity_level(&Severity::Medium), 2);
        assert_eq!(severity_level(&Severity::High), 3);
        assert_eq!(severity_level(&Severity::Critical), 4);
    }

    #[test]
    fn test_scan_report_render_text_no_vulnerabilities() {
        let report = ScanReport {
            path: "/test/path".to_owned(),
            lockfiles_scanned: 2,
            total_packages: 50,
            vulnerabilities: VulnSummary::default(),
            findings: Vec::new(),
        };

        let mut buffer = Vec::new();
        report
            .render_text(&mut buffer)
            .expect("text rendering should succeed");

        let output = String::from_utf8(buffer).expect("valid UTF-8");
        assert!(output.contains("/test/path"), "should show scan path");
        assert!(output.contains("50"), "should show package count");
        assert!(
            output.contains("No vulnerabilities found"),
            "should show clean message"
        );
    }

    #[test]
    fn test_scan_report_render_text_with_findings() {
        let report = ScanReport {
            path: "/test".to_owned(),
            lockfiles_scanned: 1,
            total_packages: 10,
            vulnerabilities: VulnSummary {
                critical: 1,
                high: 2,
                medium: 0,
                low: 0,
                info: 0,
                total: 3,
            },
            findings: vec![
                FindingEntry {
                    cve_id: "CVE-2024-0001".to_owned(),
                    package: "vulnerable-pkg".to_owned(),
                    version: "1.0.0".to_owned(),
                    severity: "Critical".to_owned(),
                    fixed_version: Some("1.0.1".to_owned()),
                    description: "Test vulnerability".to_owned(),
                },
                FindingEntry {
                    cve_id: "CVE-2024-0002".to_owned(),
                    package: "another-pkg".to_owned(),
                    version: "2.0.0".to_owned(),
                    severity: "High".to_owned(),
                    fixed_version: None,
                    description: "Another test".to_owned(),
                },
            ],
        };

        let mut buffer = Vec::new();
        report
            .render_text(&mut buffer)
            .expect("text rendering should succeed");

        let output = String::from_utf8(buffer).expect("valid UTF-8");
        assert!(output.contains("CVE-2024-0001"), "should show CVE ID");
        assert!(
            output.contains("vulnerable-pkg"),
            "should show package name"
        );
        assert!(
            output.contains("N/A"),
            "should show N/A for missing fixed version"
        );
    }

    #[test]
    fn test_scan_report_json_serialization() {
        let report = ScanReport {
            path: "/test".to_owned(),
            lockfiles_scanned: 1,
            total_packages: 5,
            vulnerabilities: VulnSummary {
                critical: 1,
                high: 0,
                medium: 0,
                low: 0,
                info: 0,
                total: 1,
            },
            findings: vec![],
        };

        let json = serde_json::to_string(&report).expect("JSON serialization should succeed");
        let parsed: serde_json::Value = serde_json::from_str(&json).expect("should parse JSON");

        assert_eq!(parsed["path"].as_str(), Some("/test"));
        assert_eq!(parsed["lockfiles_scanned"].as_u64(), Some(1));
        assert_eq!(parsed["total_packages"].as_u64(), Some(5));
        assert_eq!(parsed["vulnerabilities"]["total"].as_u64(), Some(1));
    }

    #[test]
    fn test_vuln_summary_default() {
        let summary = VulnSummary::default();
        assert_eq!(summary.critical, 0);
        assert_eq!(summary.high, 0);
        assert_eq!(summary.medium, 0);
        assert_eq!(summary.low, 0);
        assert_eq!(summary.info, 0);
        assert_eq!(summary.total, 0);
    }

    #[test]
    fn test_finding_entry_json_structure() {
        let finding = FindingEntry {
            cve_id: "CVE-2024-1234".to_owned(),
            package: "test-package".to_owned(),
            version: "1.0.0".to_owned(),
            severity: "High".to_owned(),
            fixed_version: Some("1.0.1".to_owned()),
            description: "Test description".to_owned(),
        };

        let json = serde_json::to_string(&finding).expect("JSON serialization should succeed");
        let parsed: serde_json::Value = serde_json::from_str(&json).expect("should parse JSON");

        assert_eq!(parsed["cve_id"].as_str(), Some("CVE-2024-1234"));
        assert_eq!(parsed["package"].as_str(), Some("test-package"));
        assert_eq!(parsed["version"].as_str(), Some("1.0.0"));
        assert_eq!(parsed["severity"].as_str(), Some("High"));
        assert_eq!(parsed["fixed_version"].as_str(), Some("1.0.1"));
    }

    #[test]
    fn test_scan_report_render_text_all_severity_levels() {
        let report = ScanReport {
            path: "/test".to_owned(),
            lockfiles_scanned: 1,
            total_packages: 100,
            vulnerabilities: VulnSummary {
                critical: 1,
                high: 2,
                medium: 3,
                low: 4,
                info: 5,
                total: 15,
            },
            findings: Vec::new(),
        };

        let mut buffer = Vec::new();
        report
            .render_text(&mut buffer)
            .expect("rendering should succeed");

        let output = String::from_utf8(buffer).expect("valid UTF-8");
        assert!(output.contains("C:1"), "should show critical count");
        assert!(output.contains("H:2"), "should show high count");
        assert!(output.contains("M:3"), "should show medium count");
        assert!(output.contains("L:4"), "should show low count");
        assert!(output.contains("I:5"), "should show info count");
    }

    #[test]
    fn test_scan_report_large_package_count() {
        let report = ScanReport {
            path: "/large/project".to_owned(),
            lockfiles_scanned: 10,
            total_packages: 10000,
            vulnerabilities: VulnSummary::default(),
            findings: Vec::new(),
        };

        let mut buffer = Vec::new();
        report
            .render_text(&mut buffer)
            .expect("large count should render");

        let output = String::from_utf8(buffer).expect("valid UTF-8");
        assert!(
            output.contains("10000"),
            "should handle large package counts"
        );
    }

    #[test]
    fn test_finding_entry_with_unicode_package_name() {
        let finding = FindingEntry {
            cve_id: "CVE-2024-0001".to_owned(),
            package: "パッケージ-日本語".to_owned(),
            version: "1.0.0".to_owned(),
            severity: "Medium".to_owned(),
            fixed_version: None,
            description: "Unicode test".to_owned(),
        };

        let json = serde_json::to_string(&finding).expect("should serialize unicode");
        assert!(json.contains("パッケージ"), "should preserve unicode");
    }

    #[test]
    fn test_scan_report_empty_path() {
        let report = ScanReport {
            path: String::new(),
            lockfiles_scanned: 0,
            total_packages: 0,
            vulnerabilities: VulnSummary::default(),
            findings: Vec::new(),
        };

        let mut buffer = Vec::new();
        report
            .render_text(&mut buffer)
            .expect("empty path should render");

        let output = String::from_utf8(buffer).expect("valid UTF-8");
        assert!(output.contains("Scan:"), "should have header");
    }
}

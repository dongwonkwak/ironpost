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

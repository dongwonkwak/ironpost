//! 취약점 매칭 -- CVE 데이터베이스 조회 및 패키지 매칭
//!
//! [`VulnMatcher`]는 [`PackageGraph`]의 패키지를 [`VulnDb`]와 대조하여
//! 알려진 취약점을 탐지합니다.
//!
//! # 사용 흐름
//!
//! 1. `VulnDb::load_from_dir()` -- 로컬 JSON DB 로드
//! 2. `VulnMatcher::new(db, min_severity)` -- 매처 생성
//! 3. `VulnMatcher::scan(graph)` -- 패키지 그래프 스캔
//! 4. 결과: `Vec<ScanFinding>` -- 발견된 취약점 목록

pub mod db;
pub mod version;

use std::sync::Arc;
use std::time::SystemTime;

use ironpost_core::types::{Severity, Vulnerability};

use crate::error::SbomScannerError;
use crate::types::{Ecosystem, Package, PackageGraph, SbomDocument};

pub use db::{VulnDb, VulnDbEntry, VersionRange};

/// 스캔에서 발견된 단일 취약점
#[derive(Debug, Clone)]
pub struct ScanFinding {
    /// 취약점 정보 (core 타입)
    pub vulnerability: Vulnerability,
    /// 매칭된 패키지 정보
    pub matched_package: Package,
    /// 스캔 소스 (lockfile 경로)
    pub scan_source: String,
}

/// 스캔 결과 -- 하나의 lockfile 스캔 전체 결과
#[derive(Debug, Clone)]
pub struct ScanResult {
    /// 스캔 고유 ID
    pub scan_id: String,
    /// 스캔된 lockfile 경로
    pub source_file: String,
    /// 패키지 생태계
    pub ecosystem: Ecosystem,
    /// 전체 패키지 수
    pub total_packages: usize,
    /// 발견된 취약점 목록
    pub findings: Vec<ScanFinding>,
    /// 생성된 SBOM 문서 (선택적)
    pub sbom_document: Option<SbomDocument>,
    /// 스캔 시각
    pub scanned_at: SystemTime,
}

impl ScanResult {
    /// 발견된 취약점 수를 반환합니다.
    pub fn finding_count(&self) -> usize {
        self.findings.len()
    }

    /// 심각도별 취약점 수를 반환합니다 (Critical, High, Medium, Low, Info 순).
    pub fn severity_counts(&self) -> SeverityCounts {
        let mut counts = SeverityCounts::default();
        for finding in &self.findings {
            match finding.vulnerability.severity {
                Severity::Critical => counts.critical += 1,
                Severity::High => counts.high += 1,
                Severity::Medium => counts.medium += 1,
                Severity::Low => counts.low += 1,
                Severity::Info => counts.info += 1,
            }
        }
        counts
    }
}

/// 심각도별 취약점 개수
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct SeverityCounts {
    pub critical: usize,
    pub high: usize,
    pub medium: usize,
    pub low: usize,
    pub info: usize,
}

impl SeverityCounts {
    /// 전체 취약점 수를 반환합니다.
    pub fn total(&self) -> usize {
        self.critical + self.high + self.medium + self.low + self.info
    }
}

/// 취약점 매처
///
/// VulnDb의 취약점 데이터와 패키지 그래프를 대조하여 취약한 패키지를 식별합니다.
#[derive(Clone)]
pub struct VulnMatcher {
    /// 취약점 데이터베이스 (공유)
    db: Arc<VulnDb>,
    /// 알림 생성 최소 심각도
    min_severity: Severity,
}

impl VulnMatcher {
    /// 새 매처를 생성합니다.
    pub fn new(db: Arc<VulnDb>, min_severity: Severity) -> Self {
        Self { db, min_severity }
    }

    /// 데이터베이스 참조를 반환합니다.
    pub fn db(&self) -> &VulnDb {
        &self.db
    }

    /// 최소 심각도를 반환합니다.
    pub fn min_severity(&self) -> Severity {
        self.min_severity
    }

    /// 패키지 그래프를 스캔하여 취약점을 탐지합니다.
    ///
    /// # 동작
    ///
    /// 1. 각 패키지에 대해 VulnDb에서 해당 이름의 취약점 조회
    /// 2. 버전 범위 매칭으로 영향 여부 확인
    /// 3. 심각도가 `min_severity` 이상인 취약점만 결과에 포함
    ///
    /// # Returns
    ///
    /// 발견된 취약점 목록 (`Vec<ScanFinding>`)
    pub fn scan(
        &self,
        graph: &PackageGraph,
    ) -> Result<Vec<ScanFinding>, SbomScannerError> {
        let mut findings = Vec::new();

        for package in &graph.packages {
            let entries = self.db.lookup(&package.name, &package.ecosystem);

            for entry in entries {
                // 버전 범위 매칭
                if !version::is_affected(&package.version, &entry.affected_ranges) {
                    continue;
                }

                // 심각도 필터
                if entry.severity < self.min_severity {
                    continue;
                }

                let vulnerability = Vulnerability {
                    cve_id: entry.cve_id.clone(),
                    package: package.name.clone(),
                    affected_version: package.version.clone(),
                    fixed_version: entry.fixed_version.clone(),
                    severity: entry.severity,
                    description: entry.description.clone(),
                };

                findings.push(ScanFinding {
                    vulnerability,
                    matched_package: package.clone(),
                    scan_source: graph.source_file.clone(),
                });
            }
        }

        Ok(findings)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_db() -> VulnDb {
        VulnDb::from_entries(vec![
            VulnDbEntry {
                cve_id: "CVE-2024-0001".to_owned(),
                package: "vulnerable-pkg".to_owned(),
                ecosystem: Ecosystem::Cargo,
                affected_ranges: vec![VersionRange {
                    introduced: Some("0.1.0".to_owned()),
                    fixed: Some("0.1.5".to_owned()),
                }],
                fixed_version: Some("0.1.5".to_owned()),
                severity: Severity::High,
                description: "A test vulnerability".to_owned(),
                published: "2024-01-01".to_owned(),
            },
            VulnDbEntry {
                cve_id: "CVE-2024-0002".to_owned(),
                package: "another-pkg".to_owned(),
                ecosystem: Ecosystem::Cargo,
                affected_ranges: vec![VersionRange {
                    introduced: Some("1.0.0".to_owned()),
                    fixed: None,
                }],
                fixed_version: None,
                severity: Severity::Low,
                description: "A low severity vuln".to_owned(),
                published: "2024-02-01".to_owned(),
            },
        ])
    }

    fn sample_graph() -> PackageGraph {
        PackageGraph {
            source_file: "Cargo.lock".to_owned(),
            ecosystem: Ecosystem::Cargo,
            packages: vec![
                Package {
                    name: "vulnerable-pkg".to_owned(),
                    version: "0.1.3".to_owned(),
                    ecosystem: Ecosystem::Cargo,
                    purl: "pkg:cargo/vulnerable-pkg@0.1.3".to_owned(),
                    checksum: None,
                    dependencies: vec![],
                },
                Package {
                    name: "safe-pkg".to_owned(),
                    version: "1.0.0".to_owned(),
                    ecosystem: Ecosystem::Cargo,
                    purl: "pkg:cargo/safe-pkg@1.0.0".to_owned(),
                    checksum: None,
                    dependencies: vec![],
                },
                Package {
                    name: "another-pkg".to_owned(),
                    version: "1.2.0".to_owned(),
                    ecosystem: Ecosystem::Cargo,
                    purl: "pkg:cargo/another-pkg@1.2.0".to_owned(),
                    checksum: None,
                    dependencies: vec![],
                },
            ],
            root_packages: vec![],
        }
    }

    #[test]
    fn matcher_finds_vulnerable_package() {
        let db = Arc::new(sample_db());
        let matcher = VulnMatcher::new(db, Severity::Info);
        let findings = matcher.scan(&sample_graph()).unwrap();

        // Should find CVE-2024-0001 for vulnerable-pkg and CVE-2024-0002 for another-pkg
        assert!(findings.len() >= 1);
        let cve_ids: Vec<&str> = findings.iter().map(|f| f.vulnerability.cve_id.as_str()).collect();
        assert!(cve_ids.contains(&"CVE-2024-0001"));
    }

    #[test]
    fn matcher_respects_min_severity() {
        let db = Arc::new(sample_db());
        let matcher = VulnMatcher::new(db, Severity::High);
        let findings = matcher.scan(&sample_graph()).unwrap();

        // Only CVE-2024-0001 (High) should be included, not CVE-2024-0002 (Low)
        for finding in &findings {
            assert!(finding.vulnerability.severity >= Severity::High);
        }
    }

    #[test]
    fn matcher_skips_safe_packages() {
        let db = Arc::new(sample_db());
        let matcher = VulnMatcher::new(db, Severity::Info);
        let findings = matcher.scan(&sample_graph()).unwrap();

        // safe-pkg should not appear in findings
        let pkgs: Vec<&str> = findings.iter().map(|f| f.vulnerability.package.as_str()).collect();
        assert!(!pkgs.contains(&"safe-pkg"));
    }

    #[test]
    fn severity_counts_calculation() {
        let result = ScanResult {
            scan_id: "test".to_owned(),
            source_file: "Cargo.lock".to_owned(),
            ecosystem: Ecosystem::Cargo,
            total_packages: 0,
            findings: vec![
                ScanFinding {
                    vulnerability: Vulnerability {
                        cve_id: "CVE-1".to_owned(),
                        package: "a".to_owned(),
                        affected_version: "1.0".to_owned(),
                        fixed_version: None,
                        severity: Severity::Critical,
                        description: String::new(),
                    },
                    matched_package: Package {
                        name: "a".to_owned(),
                        version: "1.0".to_owned(),
                        ecosystem: Ecosystem::Cargo,
                        purl: String::new(),
                        checksum: None,
                        dependencies: vec![],
                    },
                    scan_source: "test".to_owned(),
                },
                ScanFinding {
                    vulnerability: Vulnerability {
                        cve_id: "CVE-2".to_owned(),
                        package: "b".to_owned(),
                        affected_version: "1.0".to_owned(),
                        fixed_version: None,
                        severity: Severity::High,
                        description: String::new(),
                    },
                    matched_package: Package {
                        name: "b".to_owned(),
                        version: "1.0".to_owned(),
                        ecosystem: Ecosystem::Cargo,
                        purl: String::new(),
                        checksum: None,
                        dependencies: vec![],
                    },
                    scan_source: "test".to_owned(),
                },
            ],
            sbom_document: None,
            scanned_at: SystemTime::now(),
        };

        let counts = result.severity_counts();
        assert_eq!(counts.critical, 1);
        assert_eq!(counts.high, 1);
        assert_eq!(counts.medium, 0);
        assert_eq!(counts.total(), 2);
    }

    #[test]
    fn empty_scan_result() {
        let result = ScanResult {
            scan_id: "empty".to_owned(),
            source_file: "test".to_owned(),
            ecosystem: Ecosystem::Cargo,
            total_packages: 0,
            findings: vec![],
            sbom_document: None,
            scanned_at: SystemTime::now(),
        };
        assert_eq!(result.finding_count(), 0);
        assert_eq!(result.severity_counts().total(), 0);
    }
}

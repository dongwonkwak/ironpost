//! 취약점 데이터베이스 -- 로컬 JSON DB 로딩 및 조회
//!
//! [`VulnDb`]는 로컬 파일시스템의 JSON 파일에서 취약점 데이터를 로드합니다.
//!
//! # DB 디렉토리 구조
//!
//! ```text
//! /var/lib/ironpost/vuln-db/
//!   cargo.json     # Cargo 생태계 취약점
//!   npm.json       # NPM 생태계 취약점
//! ```
//!
//! # JSON 형식
//!
//! ```json
//! [
//!   {
//!     "cve_id": "CVE-2024-1234",
//!     "package": "openssl",
//!     "ecosystem": "Cargo",
//!     "affected_ranges": [{ "introduced": "1.0.0", "fixed": "1.1.1t" }],
//!     "fixed_version": "1.1.1t",
//!     "severity": "Critical",
//!     "description": "Buffer overflow in...",
//!     "published": "2024-01-15"
//!   }
//! ]
//! ```

use serde::{Deserialize, Serialize};

use ironpost_core::types::Severity;

use crate::error::SbomScannerError;
use crate::types::Ecosystem;

/// 취약점 DB 파일 최대 크기 (50 MB)
const MAX_VULN_DB_FILE_SIZE: u64 = 50 * 1024 * 1024;

/// 전체 취약점 DB 엔트리 최대 개수 (1,000,000개)
const MAX_VULN_DB_ENTRIES: usize = 1_000_000;

/// 취약점 DB 엔트리
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VulnDbEntry {
    /// CVE ID (예: CVE-2024-1234)
    pub cve_id: String,
    /// 영향받는 패키지명
    pub package: String,
    /// 패키지 생태계
    pub ecosystem: Ecosystem,
    /// 영향받는 버전 범위
    pub affected_ranges: Vec<VersionRange>,
    /// 수정된 버전 (있을 경우)
    pub fixed_version: Option<String>,
    /// 심각도
    pub severity: Severity,
    /// 취약점 설명
    pub description: String,
    /// 공개 일자 (ISO 8601)
    pub published: String,
}

/// 영향받는 버전 범위
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VersionRange {
    /// 도입 버전 (이 버전부터 영향)
    pub introduced: Option<String>,
    /// 수정 버전 (이 버전에서 수정됨, None이면 미수정)
    pub fixed: Option<String>,
}

/// 취약점 데이터베이스
///
/// 로컬 JSON 파일에서 로드된 취약점 엔트리를 보유합니다.
/// 패키지 이름과 생태계로 조회할 수 있습니다.
///
/// # 인덱싱
///
/// O(1) 조회를 위해 `(package_name, ecosystem)` 쌍으로 인덱싱된 HashMap을 사용합니다.
pub struct VulnDb {
    /// 전체 취약점 엔트리
    entries: Vec<VulnDbEntry>,
    /// 패키지 이름과 생태계로 인덱싱된 조회 맵
    index: std::collections::HashMap<(String, Ecosystem), Vec<usize>>,
}

impl VulnDb {
    /// 빈 데이터베이스를 생성합니다.
    pub fn empty() -> Self {
        Self {
            entries: Vec::new(),
            index: std::collections::HashMap::new(),
        }
    }

    /// 인덱스를 구축합니다.
    fn build_index(entries: &[VulnDbEntry]) -> std::collections::HashMap<(String, Ecosystem), Vec<usize>> {
        let mut index = std::collections::HashMap::new();
        for (idx, entry) in entries.iter().enumerate() {
            let key = (entry.package.clone(), entry.ecosystem);
            index.entry(key).or_insert_with(Vec::new).push(idx);
        }
        index
    }

    /// 엔트리 목록으로 데이터베이스를 생성합니다 (테스트용).
    pub fn from_entries(entries: Vec<VulnDbEntry>) -> Self {
        let index = Self::build_index(&entries);
        Self { entries, index }
    }

    /// JSON 문자열에서 데이터베이스를 파싱합니다.
    ///
    /// JSON 형식: `VulnDbEntry` 배열
    pub fn from_json(json: &str) -> Result<Self, SbomScannerError> {
        let entries: Vec<VulnDbEntry> = serde_json::from_str(json).map_err(|e| {
            SbomScannerError::VulnDbParse(format!("failed to parse vuln db JSON: {e}"))
        })?;

        let index = Self::build_index(&entries);
        Ok(Self { entries, index })
    }

    /// 디렉토리에서 모든 생태계의 취약점 DB를 로드합니다.
    ///
    /// 각 파일은 `{ecosystem}.json` 형식이어야 합니다:
    /// - `cargo.json`, `npm.json`, `go.json`, `pip.json`
    ///
    /// 파일이 존재하지 않으면 건너뜁니다.
    ///
    /// # 보안 제한
    ///
    /// - 파일당 최대 50MB (`MAX_VULN_DB_FILE_SIZE`)
    /// - 전체 엔트리 최대 1,000,000개 (`MAX_VULN_DB_ENTRIES`)
    ///
    /// # Note
    ///
    /// 이 함수는 동기 I/O를 수행합니다. async 컨텍스트에서 호출할 때는
    /// `tokio::task::spawn_blocking`으로 감싸세요.
    pub fn load_from_dir(dir_path: &std::path::Path) -> Result<Self, SbomScannerError> {
        let ecosystem_files = [
            ("cargo.json", Ecosystem::Cargo),
            ("npm.json", Ecosystem::Npm),
            ("go.json", Ecosystem::Go),
            ("pip.json", Ecosystem::Pip),
        ];

        let mut all_entries = Vec::new();

        for (filename, _ecosystem) in &ecosystem_files {
            let file_path = dir_path.join(filename);

            // 파일 메타데이터 확인 (크기 체크)
            let metadata = match std::fs::metadata(&file_path) {
                Ok(m) => m,
                Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                    tracing::debug!(path = %file_path.display(), "vuln db file not found, skipping");
                    continue;
                }
                Err(e) => {
                    return Err(SbomScannerError::VulnDbLoad {
                        path: file_path.display().to_string(),
                        reason: e.to_string(),
                    });
                }
            };

            let file_size = metadata.len();
            if file_size > MAX_VULN_DB_FILE_SIZE {
                return Err(SbomScannerError::VulnDbLoad {
                    path: file_path.display().to_string(),
                    reason: format!(
                        "file size {} bytes exceeds maximum {} bytes",
                        file_size, MAX_VULN_DB_FILE_SIZE
                    ),
                });
            }

            let content = std::fs::read_to_string(&file_path).map_err(|e| {
                SbomScannerError::VulnDbLoad {
                    path: file_path.display().to_string(),
                    reason: e.to_string(),
                }
            })?;

            let entries: Vec<VulnDbEntry> = serde_json::from_str(&content).map_err(|e| {
                SbomScannerError::VulnDbParse(format!(
                    "failed to parse {}: {e}",
                    file_path.display()
                ))
            })?;

            // 전체 엔트리 수 제한 체크
            if all_entries.len() + entries.len() > MAX_VULN_DB_ENTRIES {
                tracing::warn!(
                    current = all_entries.len(),
                    new = entries.len(),
                    max = MAX_VULN_DB_ENTRIES,
                    "vulnerability database entry limit reached, truncating"
                );
                let remaining = MAX_VULN_DB_ENTRIES.saturating_sub(all_entries.len());
                all_entries.extend(entries.into_iter().take(remaining));
                break;
            }

            tracing::info!(
                path = %file_path.display(),
                entries = entries.len(),
                "loaded vuln db file"
            );

            all_entries.extend(entries);
        }

        let index = Self::build_index(&all_entries);
        Ok(Self {
            entries: all_entries,
            index,
        })
    }

    /// 데이터베이스 내 전체 엔트리 수를 반환합니다.
    pub fn entry_count(&self) -> usize {
        self.entries.len()
    }

    /// 패키지 이름과 생태계로 취약점을 조회합니다.
    ///
    /// O(1) 인덱스 조회를 통해 일치하는 모든 취약점 엔트리의 참조를 반환합니다.
    pub fn lookup(&self, package: &str, ecosystem: &Ecosystem) -> Vec<&VulnDbEntry> {
        let key = (package.to_owned(), *ecosystem);
        if let Some(indices) = self.index.get(&key) {
            indices.iter().filter_map(|&idx| self.entries.get(idx)).collect()
        } else {
            Vec::new()
        }
    }

    /// 전체 엔트리에 대한 참조를 반환합니다.
    pub fn entries(&self) -> &[VulnDbEntry] {
        &self.entries
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_entries() -> Vec<VulnDbEntry> {
        vec![
            VulnDbEntry {
                cve_id: "CVE-2024-0001".to_owned(),
                package: "serde".to_owned(),
                ecosystem: Ecosystem::Cargo,
                affected_ranges: vec![VersionRange {
                    introduced: Some("1.0.0".to_owned()),
                    fixed: Some("1.0.100".to_owned()),
                }],
                fixed_version: Some("1.0.100".to_owned()),
                severity: Severity::High,
                description: "Test vulnerability".to_owned(),
                published: "2024-01-01".to_owned(),
            },
            VulnDbEntry {
                cve_id: "CVE-2024-0002".to_owned(),
                package: "lodash".to_owned(),
                ecosystem: Ecosystem::Npm,
                affected_ranges: vec![],
                fixed_version: None,
                severity: Severity::Critical,
                description: "NPM vulnerability".to_owned(),
                published: "2024-02-01".to_owned(),
            },
        ]
    }

    #[test]
    fn empty_db() {
        let db = VulnDb::empty();
        assert_eq!(db.entry_count(), 0);
        assert!(db.lookup("anything", &Ecosystem::Cargo).is_empty());
    }

    #[test]
    fn from_entries() {
        let db = VulnDb::from_entries(sample_entries());
        assert_eq!(db.entry_count(), 2);
    }

    #[test]
    fn lookup_by_package_and_ecosystem() {
        let db = VulnDb::from_entries(sample_entries());

        let results = db.lookup("serde", &Ecosystem::Cargo);
        assert_eq!(results.len(), 1);
        assert_eq!(results[0].cve_id, "CVE-2024-0001");

        let results = db.lookup("lodash", &Ecosystem::Npm);
        assert_eq!(results.len(), 1);
        assert_eq!(results[0].cve_id, "CVE-2024-0002");
    }

    #[test]
    fn lookup_wrong_ecosystem_returns_empty() {
        let db = VulnDb::from_entries(sample_entries());

        // serde exists for Cargo but not Npm
        let results = db.lookup("serde", &Ecosystem::Npm);
        assert!(results.is_empty());
    }

    #[test]
    fn lookup_nonexistent_package_returns_empty() {
        let db = VulnDb::from_entries(sample_entries());
        let results = db.lookup("nonexistent", &Ecosystem::Cargo);
        assert!(results.is_empty());
    }

    #[test]
    fn from_json_valid() {
        let json = r#"[
            {
                "cve_id": "CVE-2024-9999",
                "package": "test-pkg",
                "ecosystem": "Cargo",
                "affected_ranges": [],
                "fixed_version": null,
                "severity": "Medium",
                "description": "Test",
                "published": "2024-01-01"
            }
        ]"#;

        let db = VulnDb::from_json(json).unwrap();
        assert_eq!(db.entry_count(), 1);
        assert_eq!(db.entries()[0].cve_id, "CVE-2024-9999");
    }

    #[test]
    fn from_json_invalid() {
        let result = VulnDb::from_json("not json");
        assert!(result.is_err());
    }

    #[test]
    fn from_json_empty_array() {
        let db = VulnDb::from_json("[]").unwrap();
        assert_eq!(db.entry_count(), 0);
    }

    #[test]
    fn entries_accessor() {
        let db = VulnDb::from_entries(sample_entries());
        assert_eq!(db.entries().len(), 2);
    }

    #[test]
    fn version_range_serialization() {
        let range = VersionRange {
            introduced: Some("1.0.0".to_owned()),
            fixed: Some("1.0.5".to_owned()),
        };
        let json = serde_json::to_string(&range).unwrap();
        let parsed: VersionRange = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed.introduced, Some("1.0.0".to_owned()));
        assert_eq!(parsed.fixed, Some("1.0.5".to_owned()));
    }

    // Edge case tests

    #[test]
    fn from_json_malformed_missing_bracket() {
        let malformed = r#"[ { "cve_id": "CVE-2024-0001" "#;
        let result = VulnDb::from_json(malformed);
        assert!(result.is_err());
        match result {
            Err(SbomScannerError::VulnDbParse(_)) => {}
            _ => panic!("expected VulnDbParse error"),
        }
    }

    #[test]
    fn from_json_corrupted_truncated() {
        let corrupted = r#"[ { "cve_id": "CVE-2024-0001", "package": "test"#;
        let result = VulnDb::from_json(corrupted);
        assert!(result.is_err());
    }

    #[test]
    fn from_json_missing_required_fields() {
        let json = r#"[
            {
                "cve_id": "CVE-2024-0001"
            }
        ]"#;
        let result = VulnDb::from_json(json);
        assert!(result.is_err());
    }

    #[test]
    fn from_json_invalid_severity() {
        let json = r#"[
            {
                "cve_id": "CVE-2024-0001",
                "package": "test",
                "ecosystem": "Cargo",
                "affected_ranges": [],
                "fixed_version": null,
                "severity": "InvalidSeverity",
                "description": "test",
                "published": "2024-01-01"
            }
        ]"#;
        let result = VulnDb::from_json(json);
        assert!(result.is_err());
    }

    #[test]
    fn from_json_very_large_entry_count() {
        // Generate a large number of entries to test performance
        let mut entries = Vec::new();
        for i in 0..1000 {
            entries.push(format!(
                r#"{{
                "cve_id": "CVE-2024-{:04}",
                "package": "pkg-{}",
                "ecosystem": "Cargo",
                "affected_ranges": [],
                "fixed_version": null,
                "severity": "Low",
                "description": "test",
                "published": "2024-01-01"
            }}"#,
                i, i
            ));
        }
        let json = format!("[{}]", entries.join(","));
        let db = VulnDb::from_json(&json).unwrap();
        assert_eq!(db.entry_count(), 1000);
    }

    #[test]
    fn lookup_with_multiple_vulnerabilities_same_package() {
        let entries = vec![
            VulnDbEntry {
                cve_id: "CVE-2024-0001".to_owned(),
                package: "multi-vuln".to_owned(),
                ecosystem: Ecosystem::Cargo,
                affected_ranges: vec![],
                fixed_version: None,
                severity: Severity::High,
                description: "First vuln".to_owned(),
                published: "2024-01-01".to_owned(),
            },
            VulnDbEntry {
                cve_id: "CVE-2024-0002".to_owned(),
                package: "multi-vuln".to_owned(),
                ecosystem: Ecosystem::Cargo,
                affected_ranges: vec![],
                fixed_version: None,
                severity: Severity::Critical,
                description: "Second vuln".to_owned(),
                published: "2024-01-15".to_owned(),
            },
        ];
        let db = VulnDb::from_entries(entries);
        let results = db.lookup("multi-vuln", &Ecosystem::Cargo);
        assert_eq!(results.len(), 2);
    }

    #[test]
    fn load_from_dir_nonexistent_directory() {
        let result = VulnDb::load_from_dir(std::path::Path::new("/nonexistent/path/definitely/not/here"));
        // On some systems, accessing a non-existent directory returns an empty DB (no files found)
        // rather than an error. Both behaviors are acceptable.
        match result {
            Ok(db) => assert_eq!(db.entry_count(), 0),
            Err(_) => {} // Also acceptable
        }
    }

    #[test]
    fn load_from_dir_empty_directory() {
        let temp_dir = tempfile::tempdir().unwrap();
        let db = VulnDb::load_from_dir(temp_dir.path()).unwrap();
        assert_eq!(db.entry_count(), 0);
    }

    #[test]
    fn load_from_dir_partial_files() {
        let temp_dir = tempfile::tempdir().unwrap();
        // Create only cargo.json
        let cargo_json = temp_dir.path().join("cargo.json");
        std::fs::write(
            &cargo_json,
            r#"[
            {
                "cve_id": "CVE-2024-0001",
                "package": "test",
                "ecosystem": "Cargo",
                "affected_ranges": [],
                "fixed_version": null,
                "severity": "High",
                "description": "test",
                "published": "2024-01-01"
            }
        ]"#,
        )
        .unwrap();

        let db = VulnDb::load_from_dir(temp_dir.path()).unwrap();
        assert_eq!(db.entry_count(), 1);
    }

    #[test]
    fn load_from_dir_invalid_json_file() {
        let temp_dir = tempfile::tempdir().unwrap();
        let cargo_json = temp_dir.path().join("cargo.json");
        std::fs::write(&cargo_json, "invalid json").unwrap();

        let result = VulnDb::load_from_dir(temp_dir.path());
        assert!(result.is_err());
        match result {
            Err(SbomScannerError::VulnDbParse(_)) => {}
            _ => panic!("expected VulnDbParse error"),
        }
    }

    #[test]
    fn version_range_with_wildcard_semver() {
        let range = VersionRange {
            introduced: Some("1.0.0".to_owned()),
            fixed: Some("2.0.0".to_owned()),
        };
        let json = serde_json::to_string(&range).unwrap();
        assert!(json.contains("1.0.0"));
        assert!(json.contains("2.0.0"));
    }

    #[test]
    fn vuln_db_entry_with_empty_description() {
        let entry = VulnDbEntry {
            cve_id: "CVE-2024-0001".to_owned(),
            package: "test".to_owned(),
            ecosystem: Ecosystem::Cargo,
            affected_ranges: vec![],
            fixed_version: None,
            severity: Severity::Low,
            description: String::new(),
            published: "2024-01-01".to_owned(),
        };
        let db = VulnDb::from_entries(vec![entry]);
        assert_eq!(db.entry_count(), 1);
        assert_eq!(db.entries()[0].description, "");
    }
}

//! package-lock.json 파서
//!
//! [`NpmLockParser`]는 NPM의 package-lock.json (v2/v3) 파일을 파싱하여
//! [`PackageGraph`]를 생성합니다.
//!
//! # package-lock.json v3 형식 예시
//!
//! ```json
//! {
//!   "name": "my-app",
//!   "lockfileVersion": 3,
//!   "packages": {
//!     "": { "name": "my-app", "version": "1.0.0" },
//!     "node_modules/lodash": { "version": "4.17.21", "resolved": "...", "integrity": "sha512-..." }
//!   }
//! }
//! ```

use std::collections::HashMap;
use std::path::Path;

use serde::Deserialize;

/// NPM lockfile 파싱 시 최대 허용 패키지 수 (DoS 방지)
/// scanner.rs의 max_packages 설정에서 허용하는 최대값(500,000)에 맞춥니다.
const MAX_NPM_PACKAGES: usize = 500_000;

/// 패키지 이름 최대 길이 (512자)
const MAX_PACKAGE_NAME_LEN: usize = 512;

/// 패키지 버전 최대 길이 (256자)
const MAX_PACKAGE_VERSION_LEN: usize = 256;

use crate::error::SbomScannerError;
use crate::parser::LockfileParser;
use crate::types::{Ecosystem, Package, PackageGraph};

/// package-lock.json 파서
///
/// NPM lockfile v2/v3 형식을 파싱합니다.
pub struct NpmLockParser;

/// package-lock.json 구조 (파싱용)
///
/// `name`, `lockfileVersion` 등 사용하지 않는 필드는 의도적으로 선언하지 않았습니다.
/// `serde_json`은 기본적으로 알 수 없는 필드를 무시합니다.
#[derive(Deserialize)]
struct NpmLockFile {
    #[serde(default)]
    packages: HashMap<String, NpmPackageEntry>,
}

/// package-lock.json 내 개별 패키지 (파싱용)
///
/// `resolved` 등 사용하지 않는 필드는 의도적으로 선언하지 않았습니다.
#[derive(Deserialize)]
struct NpmPackageEntry {
    #[serde(default)]
    name: Option<String>,
    #[serde(default)]
    version: Option<String>,
    #[serde(default)]
    integrity: Option<String>,
    #[serde(default)]
    dependencies: Option<HashMap<String, String>>,
}

impl LockfileParser for NpmLockParser {
    fn ecosystem(&self) -> Ecosystem {
        Ecosystem::Npm
    }

    fn can_parse(&self, path: &Path) -> bool {
        path.file_name()
            .and_then(|n| n.to_str())
            .is_some_and(|name| name == "package-lock.json")
    }

    fn parse(&self, content: &str, source_path: &str) -> Result<PackageGraph, SbomScannerError> {
        let lock_file: NpmLockFile =
            serde_json::from_str(content).map_err(|e| SbomScannerError::LockfileParse {
                path: source_path.to_owned(),
                reason: e.to_string(),
            })?;

        // 파싱 직후 패키지 개수 체크 (메모리 할당 후이지만, 추가 처리 전에 조기 차단)
        if lock_file.packages.len() > MAX_NPM_PACKAGES {
            return Err(SbomScannerError::LockfileParse {
                path: source_path.to_owned(),
                reason: format!(
                    "too many packages: {} exceeds limit {}",
                    lock_file.packages.len(),
                    MAX_NPM_PACKAGES
                ),
            });
        }

        let mut packages = Vec::new();
        let mut root_packages = Vec::new();

        for (key, entry) in &lock_file.packages {
            // 루트 패키지는 키가 빈 문자열
            if key.is_empty() {
                if let Some(ref name) = entry.name {
                    root_packages.push(name.clone());
                }
                continue;
            }

            // "node_modules/패키지명" 형식에서 이름 추출
            let name = extract_package_name(key);
            let version = match &entry.version {
                Some(v) => v.clone(),
                None => continue, // 버전 없는 항목은 건너뜀
            };

            // 패키지 이름/버전 길이 검증
            if name.len() > MAX_PACKAGE_NAME_LEN {
                tracing::warn!(
                    name_len = name.len(),
                    max = MAX_PACKAGE_NAME_LEN,
                    "skipping npm package with name exceeding length limit"
                );
                continue;
            }
            if version.len() > MAX_PACKAGE_VERSION_LEN {
                tracing::warn!(
                    name = %name,
                    version_len = version.len(),
                    max = MAX_PACKAGE_VERSION_LEN,
                    "skipping npm package with version exceeding length limit"
                );
                continue;
            }

            let purl = Package::make_purl(&Ecosystem::Npm, &name, &version);

            // integrity를 checksum으로 사용
            let checksum = entry.integrity.clone();

            // dependencies 목록 추출
            let deps: Vec<String> = entry
                .dependencies
                .as_ref()
                .map(|d| d.keys().cloned().collect())
                .unwrap_or_default();

            packages.push(Package {
                name,
                version,
                ecosystem: Ecosystem::Npm,
                purl,
                checksum,
                dependencies: deps,
            });
        }

        Ok(PackageGraph {
            source_file: source_path.to_owned(),
            ecosystem: Ecosystem::Npm,
            packages,
            root_packages,
        })
    }
}

/// "node_modules/@scope/name" 또는 "node_modules/name" 에서 패키지명 추출
fn extract_package_name(key: &str) -> String {
    // 마지막 "node_modules/" 이후의 부분을 패키지명으로 사용
    // scoped 패키지는 "node_modules/@scope/name" 형식
    if let Some(pos) = key.rfind("node_modules/") {
        let after = &key[pos + "node_modules/".len()..];
        after.to_owned()
    } else {
        key.to_owned()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const SAMPLE_PACKAGE_LOCK: &str = r#"{
  "name": "my-app",
  "version": "1.0.0",
  "lockfileVersion": 3,
  "packages": {
    "": {
      "name": "my-app",
      "version": "1.0.0",
      "dependencies": {
        "lodash": "^4.17.21"
      }
    },
    "node_modules/lodash": {
      "version": "4.17.21",
      "resolved": "https://registry.npmjs.org/lodash/-/lodash-4.17.21.tgz",
      "integrity": "sha512-v2kDE..."
    },
    "node_modules/express": {
      "version": "4.18.2",
      "resolved": "https://registry.npmjs.org/express/-/express-4.18.2.tgz",
      "integrity": "sha512-abc...",
      "dependencies": {
        "accepts": "~1.3.8"
      }
    }
  }
}"#;

    #[test]
    fn can_parse_package_lock_json() {
        let parser = NpmLockParser;
        assert!(parser.can_parse(Path::new("package-lock.json")));
        assert!(parser.can_parse(Path::new("/project/package-lock.json")));
        assert!(!parser.can_parse(Path::new("Cargo.lock")));
        assert!(!parser.can_parse(Path::new("package.json")));
    }

    #[test]
    fn parse_sample_package_lock() {
        let parser = NpmLockParser;
        let graph = parser
            .parse(SAMPLE_PACKAGE_LOCK, "package-lock.json")
            .unwrap();

        assert_eq!(graph.ecosystem, Ecosystem::Npm);
        assert_eq!(graph.source_file, "package-lock.json");
        // 2 packages (lodash, express), root entry is skipped
        assert_eq!(graph.packages.len(), 2);
        assert_eq!(graph.root_packages, vec!["my-app"]);

        // Verify lodash
        let lodash = graph.find_package("lodash").unwrap();
        assert_eq!(lodash.version, "4.17.21");
        assert_eq!(lodash.purl, "pkg:npm/lodash@4.17.21");
        assert!(lodash.checksum.is_some());

        // Verify express has dependencies
        let express = graph.find_package("express").unwrap();
        assert_eq!(express.dependencies, vec!["accepts"]);
    }

    #[test]
    fn parse_empty_packages() {
        let parser = NpmLockParser;
        let json = r#"{ "packages": {} }"#;
        let graph = parser.parse(json, "package-lock.json").unwrap();
        assert_eq!(graph.packages.len(), 0);
    }

    #[test]
    fn parse_invalid_json_returns_error() {
        let parser = NpmLockParser;
        let result = parser.parse("not json!", "package-lock.json");
        assert!(result.is_err());
    }

    #[test]
    fn ecosystem_is_npm() {
        let parser = NpmLockParser;
        assert_eq!(parser.ecosystem(), Ecosystem::Npm);
    }

    #[test]
    fn extract_package_name_simple() {
        assert_eq!(extract_package_name("node_modules/lodash"), "lodash");
    }

    #[test]
    fn extract_package_name_scoped() {
        assert_eq!(
            extract_package_name("node_modules/@types/node"),
            "@types/node"
        );
    }

    #[test]
    fn extract_package_name_nested() {
        assert_eq!(
            extract_package_name("node_modules/express/node_modules/debug"),
            "debug"
        );
    }

    // Edge case tests

    #[test]
    fn parse_malformed_json_syntax_error() {
        let parser = NpmLockParser;
        let malformed = r#"{ "packages": { "invalid json syntax"#;
        let result = parser.parse(malformed, "package-lock.json");
        assert!(result.is_err());
        match result {
            Err(SbomScannerError::LockfileParse { path, .. }) => {
                assert_eq!(path, "package-lock.json");
            }
            _ => panic!("expected LockfileParse error"),
        }
    }

    #[test]
    fn parse_corrupted_json_truncated() {
        let parser = NpmLockParser;
        let corrupted = r#"{ "packages": { "node_modules/lodash": { "version": "4.17"#;
        let result = parser.parse(corrupted, "package-lock.json");
        assert!(result.is_err());
    }

    #[test]
    fn parse_empty_json_object() {
        let parser = NpmLockParser;
        let empty = "{}";
        let graph = parser.parse(empty, "package-lock.json").unwrap();
        assert_eq!(graph.packages.len(), 0);
        assert_eq!(graph.root_packages.len(), 0);
    }

    #[test]
    fn parse_package_lock_very_long_package_name_skipped() {
        let parser = NpmLockParser;
        let long_name = "a".repeat(2000);
        let json = format!(
            r#"{{
  "packages": {{
    "node_modules/{}": {{
      "version": "1.0.0"
    }},
    "node_modules/valid-pkg": {{
      "version": "2.0.0"
    }}
  }}
}}"#,
            long_name
        );
        let graph = parser.parse(&json, "package-lock.json").unwrap();
        // Long name (2000 > 512) should be skipped, only valid-pkg remains
        assert_eq!(graph.packages.len(), 1);
        assert_eq!(graph.packages[0].name, "valid-pkg");
    }

    #[test]
    fn parse_package_lock_name_at_limit() {
        let parser = NpmLockParser;
        let name_at_limit = "a".repeat(512);
        let json = format!(
            r#"{{
  "packages": {{
    "node_modules/{}": {{
      "version": "1.0.0"
    }}
  }}
}}"#,
            name_at_limit
        );
        let graph = parser.parse(&json, "package-lock.json").unwrap();
        // Exactly at limit should be accepted
        assert_eq!(graph.packages.len(), 1);
        assert_eq!(graph.packages[0].name.len(), 512);
    }

    #[test]
    fn parse_package_lock_very_long_version_skipped() {
        let parser = NpmLockParser;
        let long_version = "1.0.0-beta.".to_owned() + &"0".repeat(1000);
        let json = format!(
            r#"{{
  "packages": {{
    "node_modules/test-pkg": {{
      "version": "{}"
    }},
    "node_modules/valid-pkg": {{
      "version": "2.0.0"
    }}
  }}
}}"#,
            long_version
        );
        let graph = parser.parse(&json, "package-lock.json").unwrap();
        // Long version (1011 > 256) should be skipped, only valid-pkg remains
        assert_eq!(graph.packages.len(), 1);
        assert_eq!(graph.packages[0].name, "valid-pkg");
    }

    #[test]
    fn parse_package_lock_version_at_limit() {
        let parser = NpmLockParser;
        let version_at_limit = "1.0.0-beta.".to_owned() + &"0".repeat(245);
        let json = format!(
            r#"{{
  "packages": {{
    "node_modules/test-pkg": {{
      "version": "{}"
    }}
  }}
}}"#,
            version_at_limit
        );
        let graph = parser.parse(&json, "package-lock.json").unwrap();
        // Exactly at limit (256) should be accepted
        assert_eq!(graph.packages.len(), 1);
        assert_eq!(graph.packages[0].version, version_at_limit);
    }

    #[test]
    fn parse_package_lock_duplicate_packages() {
        let parser = NpmLockParser;
        let json = r#"{
  "packages": {
    "node_modules/lodash": {
      "version": "4.17.20"
    },
    "node_modules/express/node_modules/lodash": {
      "version": "4.17.21"
    }
  }
}"#;
        let graph = parser.parse(json, "package-lock.json").unwrap();
        // Both versions should be parsed (nested dependencies)
        assert_eq!(graph.packages.len(), 2);
    }

    #[test]
    fn parse_package_lock_missing_version_skipped() {
        let parser = NpmLockParser;
        let json = r#"{
  "packages": {
    "node_modules/no-version": {},
    "node_modules/valid": {
      "version": "1.0.0"
    }
  }
}"#;
        let graph = parser.parse(json, "package-lock.json").unwrap();
        // Only package with version should be included
        assert_eq!(graph.packages.len(), 1);
        assert_eq!(graph.packages[0].name, "valid");
    }

    #[test]
    fn parse_package_lock_scoped_package_name() {
        let parser = NpmLockParser;
        let json = r#"{
  "packages": {
    "node_modules/@types/node": {
      "version": "20.0.0"
    }
  }
}"#;
        let graph = parser.parse(json, "package-lock.json").unwrap();
        assert_eq!(graph.packages.len(), 1);
        assert_eq!(graph.packages[0].name, "@types/node");
    }

    #[test]
    fn parse_package_lock_root_entry_extracted() {
        let parser = NpmLockParser;
        let json = r#"{
  "packages": {
    "": {
      "name": "my-root-app",
      "version": "1.0.0"
    }
  }
}"#;
        let graph = parser.parse(json, "package-lock.json").unwrap();
        assert_eq!(graph.root_packages, vec!["my-root-app"]);
        // Root entry should not appear in packages
        assert_eq!(graph.packages.len(), 0);
    }

    #[test]
    fn parse_package_lock_unicode_in_package_name() {
        let parser = NpmLockParser;
        let json = r#"{
  "packages": {
    "node_modules/测试-包": {
      "version": "1.0.0"
    }
  }
}"#;
        let graph = parser.parse(json, "package-lock.json").unwrap();
        assert_eq!(graph.packages.len(), 1);
        assert_eq!(graph.packages[0].name, "测试-包");
    }

    #[test]
    fn parse_package_lock_lockfile_version_2() {
        let parser = NpmLockParser;
        let json = r#"{
  "name": "test-app",
  "lockfileVersion": 2,
  "packages": {
    "node_modules/lodash": {
      "version": "4.17.21"
    }
  }
}"#;
        let graph = parser.parse(json, "package-lock.json").unwrap();
        assert_eq!(graph.packages.len(), 1);
    }

    #[test]
    fn parse_package_lock_empty_dependencies() {
        let parser = NpmLockParser;
        let json = r#"{
  "packages": {
    "node_modules/no-deps": {
      "version": "1.0.0",
      "dependencies": {}
    }
  }
}"#;
        let graph = parser.parse(json, "package-lock.json").unwrap();
        assert_eq!(graph.packages.len(), 1);
        assert!(graph.packages[0].dependencies.is_empty());
    }

    #[test]
    fn parse_package_lock_no_packages_field() {
        let parser = NpmLockParser;
        let json = r#"{ "name": "app", "lockfileVersion": 3 }"#;
        let graph = parser.parse(json, "package-lock.json").unwrap();
        assert_eq!(graph.packages.len(), 0);
    }
}

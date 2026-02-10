//! 도메인 타입 -- SBOM 스캐너 전용 데이터 구조
//!
//! 패키지, 의존성 그래프, 생태계 등 SBOM 관련 핵심 타입을 정의합니다.

use std::fmt;

use serde::{Deserialize, Serialize};

/// 패키지 생태계 (언어/패키지 관리자)
///
/// 각 lockfile 형식에 대응하는 패키지 생태계를 나타냅니다.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum Ecosystem {
    /// Rust (Cargo.lock)
    Cargo,
    /// JavaScript/TypeScript (package-lock.json)
    Npm,
    /// Go (go.sum)
    Go,
    /// Python (Pipfile.lock, requirements.txt)
    Pip,
}

impl fmt::Display for Ecosystem {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Cargo => write!(f, "cargo"),
            Self::Npm => write!(f, "npm"),
            Self::Go => write!(f, "go"),
            Self::Pip => write!(f, "pip"),
        }
    }
}

impl Ecosystem {
    /// 생태계에 대응하는 Package URL 타입 접두사를 반환합니다.
    ///
    /// 예: Cargo -> "pkg:cargo/", Npm -> "pkg:npm/"
    pub fn purl_type(&self) -> &str {
        match self {
            Self::Cargo => "cargo",
            Self::Npm => "npm",
            Self::Go => "golang",
            Self::Pip => "pypi",
        }
    }

    /// 문자열에서 생태계를 파싱합니다 (대소문자 구분 없음).
    pub fn from_str_loose(s: &str) -> Option<Self> {
        match s.to_lowercase().as_str() {
            "cargo" | "rust" | "crate" | "crates" => Some(Self::Cargo),
            "npm" | "node" | "javascript" | "js" => Some(Self::Npm),
            "go" | "golang" => Some(Self::Go),
            "pip" | "python" | "pypi" => Some(Self::Pip),
            _ => None,
        }
    }
}

/// 소프트웨어 패키지 정보
///
/// lockfile에서 파싱된 단일 패키지의 메타데이터를 나타냅니다.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Package {
    /// 패키지 이름
    pub name: String,
    /// 패키지 버전
    pub version: String,
    /// 패키지 생태계
    pub ecosystem: Ecosystem,
    /// Package URL (예: `pkg:cargo/serde@1.0.204`)
    pub purl: String,
    /// 체크섬 (SHA-256, 있을 경우)
    pub checksum: Option<String>,
    /// 직접 의존하는 패키지 이름 목록
    pub dependencies: Vec<String>,
}

impl Package {
    /// 패키지 이름과 버전으로 PURL을 생성합니다.
    pub fn make_purl(ecosystem: &Ecosystem, name: &str, version: &str) -> String {
        format!("pkg:{}/{}@{}", ecosystem.purl_type(), name, version)
    }
}

impl fmt::Display for Package {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}@{} ({})", self.name, self.version, self.ecosystem)
    }
}

/// 패키지 의존성 그래프
///
/// 하나의 lockfile에서 파싱된 전체 의존성 트리를 나타냅니다.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PackageGraph {
    /// 원본 lockfile 경로
    pub source_file: String,
    /// 생태계
    pub ecosystem: Ecosystem,
    /// 전체 패키지 목록
    pub packages: Vec<Package>,
    /// 루트 패키지 이름 목록 (직접 의존성)
    pub root_packages: Vec<String>,
}

impl PackageGraph {
    /// 그래프 내 패키지 수를 반환합니다.
    pub fn package_count(&self) -> usize {
        self.packages.len()
    }

    /// 이름으로 패키지를 검색합니다.
    pub fn find_package(&self, name: &str) -> Option<&Package> {
        self.packages.iter().find(|p| p.name == name)
    }
}

impl fmt::Display for PackageGraph {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "PackageGraph({}, {} packages, ecosystem={})",
            self.source_file,
            self.packages.len(),
            self.ecosystem,
        )
    }
}

/// SBOM 출력 형식
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum SbomFormat {
    /// CycloneDX 1.5 JSON
    CycloneDx,
    /// SPDX 2.3 JSON
    Spdx,
}

impl fmt::Display for SbomFormat {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::CycloneDx => write!(f, "cyclonedx"),
            Self::Spdx => write!(f, "spdx"),
        }
    }
}

impl SbomFormat {
    /// 문자열에서 SBOM 형식을 파싱합니다.
    pub fn from_str_loose(s: &str) -> Option<Self> {
        match s.to_lowercase().as_str() {
            "cyclonedx" | "cdx" => Some(Self::CycloneDx),
            "spdx" => Some(Self::Spdx),
            _ => None,
        }
    }
}

/// SBOM 문서
///
/// 생성된 SBOM의 형식과 내용을 담습니다.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SbomDocument {
    /// SBOM 형식
    pub format: SbomFormat,
    /// JSON 문자열 내용
    pub content: String,
    /// 포함된 컴포넌트 수
    pub component_count: usize,
}

impl fmt::Display for SbomDocument {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "SbomDocument(format={}, components={})",
            self.format, self.component_count,
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ecosystem_display() {
        assert_eq!(Ecosystem::Cargo.to_string(), "cargo");
        assert_eq!(Ecosystem::Npm.to_string(), "npm");
        assert_eq!(Ecosystem::Go.to_string(), "go");
        assert_eq!(Ecosystem::Pip.to_string(), "pip");
    }

    #[test]
    fn ecosystem_purl_type() {
        assert_eq!(Ecosystem::Cargo.purl_type(), "cargo");
        assert_eq!(Ecosystem::Npm.purl_type(), "npm");
        assert_eq!(Ecosystem::Go.purl_type(), "golang");
        assert_eq!(Ecosystem::Pip.purl_type(), "pypi");
    }

    #[test]
    fn ecosystem_from_str_loose() {
        assert_eq!(Ecosystem::from_str_loose("cargo"), Some(Ecosystem::Cargo));
        assert_eq!(Ecosystem::from_str_loose("RUST"), Some(Ecosystem::Cargo));
        assert_eq!(Ecosystem::from_str_loose("npm"), Some(Ecosystem::Npm));
        assert_eq!(Ecosystem::from_str_loose("Node"), Some(Ecosystem::Npm));
        assert_eq!(Ecosystem::from_str_loose("go"), Some(Ecosystem::Go));
        assert_eq!(Ecosystem::from_str_loose("pip"), Some(Ecosystem::Pip));
        assert_eq!(Ecosystem::from_str_loose("unknown"), None);
    }

    #[test]
    fn package_make_purl() {
        let purl = Package::make_purl(&Ecosystem::Cargo, "serde", "1.0.204");
        assert_eq!(purl, "pkg:cargo/serde@1.0.204");

        let purl = Package::make_purl(&Ecosystem::Npm, "lodash", "4.17.21");
        assert_eq!(purl, "pkg:npm/lodash@4.17.21");
    }

    #[test]
    fn package_display() {
        let pkg = Package {
            name: "serde".to_owned(),
            version: "1.0.204".to_owned(),
            ecosystem: Ecosystem::Cargo,
            purl: "pkg:cargo/serde@1.0.204".to_owned(),
            checksum: None,
            dependencies: vec![],
        };
        assert_eq!(pkg.to_string(), "serde@1.0.204 (cargo)");
    }

    #[test]
    fn package_graph_find_package() {
        let graph = PackageGraph {
            source_file: "Cargo.lock".to_owned(),
            ecosystem: Ecosystem::Cargo,
            packages: vec![
                Package {
                    name: "serde".to_owned(),
                    version: "1.0.204".to_owned(),
                    ecosystem: Ecosystem::Cargo,
                    purl: "pkg:cargo/serde@1.0.204".to_owned(),
                    checksum: None,
                    dependencies: vec![],
                },
            ],
            root_packages: vec!["serde".to_owned()],
        };

        assert!(graph.find_package("serde").is_some());
        assert!(graph.find_package("nonexistent").is_none());
        assert_eq!(graph.package_count(), 1);
    }

    #[test]
    fn sbom_format_display() {
        assert_eq!(SbomFormat::CycloneDx.to_string(), "cyclonedx");
        assert_eq!(SbomFormat::Spdx.to_string(), "spdx");
    }

    #[test]
    fn sbom_format_from_str_loose() {
        assert_eq!(SbomFormat::from_str_loose("cyclonedx"), Some(SbomFormat::CycloneDx));
        assert_eq!(SbomFormat::from_str_loose("cdx"), Some(SbomFormat::CycloneDx));
        assert_eq!(SbomFormat::from_str_loose("spdx"), Some(SbomFormat::Spdx));
        assert_eq!(SbomFormat::from_str_loose("SPDX"), Some(SbomFormat::Spdx));
        assert_eq!(SbomFormat::from_str_loose("xml"), None);
    }
}

//! SBOM 문서 생성 -- CycloneDX, SPDX 형식 출력
//!
//! [`SbomGenerator`]는 [`PackageGraph`]를 입력받아
//! 지정된 형식의 SBOM 문서(JSON)를 생성합니다.
//!
//! # 지원 형식
//!
//! - CycloneDX 1.5 JSON -- [`cyclonedx`] 모듈
//! - SPDX 2.3 JSON -- [`spdx`] 모듈

pub mod cyclonedx;
pub mod spdx;

use crate::error::SbomScannerError;
use crate::types::{PackageGraph, SbomDocument, SbomFormat};

/// SBOM 문서 생성기
///
/// 설정된 형식(CycloneDX 또는 SPDX)에 따라 JSON SBOM 문서를 생성합니다.
#[derive(Clone, Copy)]
pub struct SbomGenerator {
    /// 출력 형식
    format: SbomFormat,
}

impl SbomGenerator {
    /// 지정된 형식으로 SBOM 생성기를 만듭니다.
    pub fn new(format: SbomFormat) -> Self {
        Self { format }
    }

    /// 현재 설정된 출력 형식을 반환합니다.
    pub fn format(&self) -> SbomFormat {
        self.format
    }

    /// 패키지 그래프에서 SBOM 문서를 생성합니다.
    ///
    /// # Arguments
    ///
    /// - `graph`: 의존성 파일에서 파싱된 패키지 그래프
    ///
    /// # Returns
    ///
    /// JSON 형식의 [`SbomDocument`]
    pub fn generate(&self, graph: &PackageGraph) -> Result<SbomDocument, SbomScannerError> {
        match self.format {
            SbomFormat::CycloneDx => cyclonedx::generate(graph),
            SbomFormat::Spdx => spdx::generate(graph),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::{Ecosystem, Package};

    fn sample_graph() -> PackageGraph {
        PackageGraph {
            source_file: "Cargo.lock".to_owned(),
            ecosystem: Ecosystem::Cargo,
            packages: vec![
                Package {
                    name: "serde".to_owned(),
                    version: "1.0.204".to_owned(),
                    ecosystem: Ecosystem::Cargo,
                    purl: "pkg:cargo/serde@1.0.204".to_owned(),
                    checksum: Some("abc123".to_owned()),
                    dependencies: vec![],
                },
            ],
            root_packages: vec![],
        }
    }

    #[test]
    fn generator_cyclonedx() {
        let generator = SbomGenerator::new(SbomFormat::CycloneDx);
        assert_eq!(generator.format(), SbomFormat::CycloneDx);

        let doc = generator.generate(&sample_graph()).unwrap();
        assert_eq!(doc.format, SbomFormat::CycloneDx);
        assert_eq!(doc.component_count, 1);
        assert!(doc.content.contains("CycloneDX"));
    }

    #[test]
    fn generator_spdx() {
        let generator = SbomGenerator::new(SbomFormat::Spdx);
        assert_eq!(generator.format(), SbomFormat::Spdx);

        let doc = generator.generate(&sample_graph()).unwrap();
        assert_eq!(doc.format, SbomFormat::Spdx);
        assert_eq!(doc.component_count, 1);
        assert!(doc.content.contains("SPDX"));
    }

    #[test]
    fn generator_empty_graph() {
        let generator = SbomGenerator::new(SbomFormat::CycloneDx);
        let graph = PackageGraph {
            source_file: "Cargo.lock".to_owned(),
            ecosystem: Ecosystem::Cargo,
            packages: vec![],
            root_packages: vec![],
        };
        let doc = generator.generate(&graph).unwrap();
        assert_eq!(doc.component_count, 0);
    }
}

//! CycloneDX 1.5 JSON SBOM 생성
//!
//! [CycloneDX](https://cyclonedx.org/) 1.5 사양에 따른 JSON SBOM 문서를 생성합니다.

use serde::Serialize;

use super::util;
use crate::error::SbomScannerError;
use crate::types::{PackageGraph, SbomDocument, SbomFormat};

/// CycloneDX 1.5 BOM 루트 구조
#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct CycloneDxBom {
    bom_format: String,
    spec_version: String,
    version: u32,
    metadata: CycloneDxMetadata,
    components: Vec<CycloneDxComponent>,
}

/// CycloneDX 메타데이터
#[derive(Serialize)]
struct CycloneDxMetadata {
    timestamp: String,
    tools: Vec<CycloneDxTool>,
}

/// CycloneDX 도구 정보
#[derive(Serialize)]
struct CycloneDxTool {
    name: String,
    version: String,
}

/// CycloneDX 컴포넌트
#[derive(Serialize)]
struct CycloneDxComponent {
    #[serde(rename = "type")]
    component_type: String,
    name: String,
    version: String,
    purl: String,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    hashes: Vec<CycloneDxHash>,
}

/// CycloneDX 해시 정보
#[derive(Serialize)]
struct CycloneDxHash {
    alg: String,
    content: String,
}

/// 패키지 그래프에서 CycloneDX 1.5 JSON SBOM을 생성합니다.
pub fn generate(graph: &PackageGraph) -> Result<SbomDocument, SbomScannerError> {
    let components: Vec<CycloneDxComponent> = graph
        .packages
        .iter()
        .map(|pkg| {
            let hashes = pkg
                .checksum
                .as_ref()
                .map(|c| {
                    let (algorithm, hash_value) = util::parse_checksum_algorithm(c, &pkg.ecosystem);
                    vec![CycloneDxHash {
                        alg: algorithm.to_owned(),
                        content: hash_value.to_owned(),
                    }]
                })
                .unwrap_or_default();

            CycloneDxComponent {
                component_type: "library".to_owned(),
                name: pkg.name.clone(),
                version: pkg.version.clone(),
                purl: pkg.purl.clone(),
                hashes,
            }
        })
        .collect();

    let component_count = components.len();

    let bom = CycloneDxBom {
        bom_format: "CycloneDX".to_owned(),
        spec_version: "1.5".to_owned(),
        version: 1,
        metadata: CycloneDxMetadata {
            timestamp: util::current_timestamp(),
            tools: vec![CycloneDxTool {
                name: "ironpost-sbom-scanner".to_owned(),
                version: env!("CARGO_PKG_VERSION").to_owned(),
            }],
        },
        components,
    };

    let content = serde_json::to_string_pretty(&bom).map_err(|e| {
        SbomScannerError::SbomGeneration(format!("CycloneDX serialization failed: {e}"))
    })?;

    Ok(SbomDocument {
        format: SbomFormat::CycloneDx,
        content,
        component_count,
    })
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
                Package {
                    name: "tokio".to_owned(),
                    version: "1.38.0".to_owned(),
                    ecosystem: Ecosystem::Cargo,
                    purl: "pkg:cargo/tokio@1.38.0".to_owned(),
                    checksum: None,
                    dependencies: vec![],
                },
            ],
            root_packages: vec![],
        }
    }

    #[test]
    fn generate_cyclonedx_contains_required_fields() {
        let doc = generate(&sample_graph()).unwrap();
        assert!(doc.content.contains("CycloneDX"));
        assert!(doc.content.contains("1.5"));
        assert!(doc.content.contains("ironpost-sbom-scanner"));
        assert_eq!(doc.component_count, 2);
    }

    #[test]
    fn generate_cyclonedx_contains_packages() {
        let doc = generate(&sample_graph()).unwrap();
        assert!(doc.content.contains("serde"));
        assert!(doc.content.contains("1.0.204"));
        assert!(doc.content.contains("pkg:cargo/serde@1.0.204"));
        assert!(doc.content.contains("tokio"));
    }

    #[test]
    fn generate_cyclonedx_includes_checksum() {
        let doc = generate(&sample_graph()).unwrap();
        assert!(doc.content.contains("SHA-256"));
        assert!(doc.content.contains("abc123"));
    }

    #[test]
    fn generate_cyclonedx_empty_graph() {
        let graph = PackageGraph {
            source_file: "Cargo.lock".to_owned(),
            ecosystem: Ecosystem::Cargo,
            packages: vec![],
            root_packages: vec![],
        };
        let doc = generate(&graph).unwrap();
        assert_eq!(doc.component_count, 0);
        assert!(doc.content.contains("CycloneDX"));
    }

    #[test]
    fn generate_cyclonedx_is_valid_json() {
        let doc = generate(&sample_graph()).unwrap();
        let parsed: serde_json::Value = serde_json::from_str(&doc.content).unwrap();
        assert_eq!(parsed["bomFormat"], "CycloneDX");
        assert_eq!(parsed["specVersion"], "1.5");
        assert!(parsed["components"].is_array());
    }
}

//! SPDX 2.3 JSON SBOM 생성
//!
//! [SPDX](https://spdx.dev/) 2.3 사양에 따른 JSON SBOM 문서를 생성합니다.

use serde::Serialize;

use super::util;
use crate::error::SbomScannerError;
use crate::types::{PackageGraph, SbomDocument, SbomFormat};

/// SPDX 2.3 문서 루트 구조
#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct SpdxDocument {
    spdx_version: String,
    #[serde(rename = "SPDXID")]
    spdx_id: String,
    name: String,
    data_license: String,
    document_namespace: String,
    creation_info: SpdxCreationInfo,
    packages: Vec<SpdxPackage>,
}

/// SPDX 생성 정보
#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct SpdxCreationInfo {
    created: String,
    creators: Vec<String>,
}

/// SPDX 패키지
#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct SpdxPackage {
    #[serde(rename = "SPDXID")]
    spdx_id: String,
    name: String,
    version_info: String,
    download_location: String,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    external_refs: Vec<SpdxExternalRef>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    checksums: Vec<SpdxChecksum>,
}

/// SPDX 외부 참조
#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct SpdxExternalRef {
    reference_category: String,
    reference_type: String,
    reference_locator: String,
}

/// SPDX 체크섬
#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct SpdxChecksum {
    algorithm: String,
    checksum_value: String,
}

/// 패키지 그래프에서 SPDX 2.3 JSON SBOM을 생성합니다.
pub fn generate(graph: &PackageGraph) -> Result<SbomDocument, SbomScannerError> {
    let spdx_packages: Vec<SpdxPackage> = graph
        .packages
        .iter()
        .map(|pkg| {
            // 결정론적 SPDX ID 생성: 패키지 이름과 버전 기반 (인덱스 대신)
            let sanitized_name = pkg
                .name
                .chars()
                .map(|c| {
                    if c.is_alphanumeric() || c == '.' || c == '-' {
                        c
                    } else {
                        '-'
                    }
                })
                .collect::<String>();
            let sanitized_version = pkg
                .version
                .chars()
                .map(|c| {
                    if c.is_alphanumeric() || c == '.' {
                        c
                    } else {
                        '-'
                    }
                })
                .collect::<String>();
            let spdx_id = format!("SPDXRef-Package-{}-{}", sanitized_name, sanitized_version);

            let external_refs = vec![SpdxExternalRef {
                reference_category: "PACKAGE-MANAGER".to_owned(),
                reference_type: "purl".to_owned(),
                reference_locator: pkg.purl.clone(),
            }];

            let checksums = pkg
                .checksum
                .as_ref()
                .map(|c| {
                    let (algorithm, hash_value) = util::parse_checksum_algorithm(c, &pkg.ecosystem);
                    vec![SpdxChecksum {
                        algorithm: algorithm.replace('-', ""), // SPDX는 "SHA256" 형식 (하이픈 제거)
                        checksum_value: hash_value.to_owned(),
                    }]
                })
                .unwrap_or_default();

            SpdxPackage {
                spdx_id,
                name: pkg.name.clone(),
                version_info: pkg.version.clone(),
                download_location: "NOASSERTION".to_owned(),
                external_refs,
                checksums,
            }
        })
        .collect();

    let component_count = spdx_packages.len();

    let namespace = format!("https://ironpost.dev/spdx/{}", uuid::Uuid::new_v4());

    let doc = SpdxDocument {
        spdx_version: "SPDX-2.3".to_owned(),
        spdx_id: "SPDXRef-DOCUMENT".to_owned(),
        name: format!(
            "ironpost-scan-{}",
            std::path::Path::new(&graph.source_file)
                .file_name()
                .and_then(|n| n.to_str())
                .unwrap_or("unknown")
        ),
        data_license: "CC0-1.0".to_owned(),
        document_namespace: namespace,
        creation_info: SpdxCreationInfo {
            created: util::current_timestamp(),
            creators: vec!["Tool: ironpost-sbom-scanner".to_owned()],
        },
        packages: spdx_packages,
    };

    let content = serde_json::to_string_pretty(&doc)
        .map_err(|e| SbomScannerError::SbomGeneration(format!("SPDX serialization failed: {e}")))?;

    Ok(SbomDocument {
        format: SbomFormat::Spdx,
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
            packages: vec![Package {
                name: "serde".to_owned(),
                version: "1.0.204".to_owned(),
                ecosystem: Ecosystem::Cargo,
                purl: "pkg:cargo/serde@1.0.204".to_owned(),
                checksum: Some("abc123".to_owned()),
                dependencies: vec![],
            }],
            root_packages: vec![],
        }
    }

    #[test]
    fn generate_spdx_contains_required_fields() {
        let doc = generate(&sample_graph()).unwrap();
        assert!(doc.content.contains("SPDX-2.3"));
        assert!(doc.content.contains("SPDXRef-DOCUMENT"));
        assert!(doc.content.contains("CC0-1.0"));
        assert!(doc.content.contains("ironpost-sbom-scanner"));
        assert_eq!(doc.component_count, 1);
    }

    #[test]
    fn generate_spdx_contains_packages() {
        let doc = generate(&sample_graph()).unwrap();
        assert!(doc.content.contains("serde"));
        assert!(doc.content.contains("1.0.204"));
        assert!(doc.content.contains("pkg:cargo/serde@1.0.204"));
    }

    #[test]
    fn generate_spdx_includes_checksum() {
        let doc = generate(&sample_graph()).unwrap();
        assert!(doc.content.contains("SHA256"));
        assert!(doc.content.contains("abc123"));
    }

    #[test]
    fn generate_spdx_empty_graph() {
        let graph = PackageGraph {
            source_file: "Cargo.lock".to_owned(),
            ecosystem: Ecosystem::Cargo,
            packages: vec![],
            root_packages: vec![],
        };
        let doc = generate(&graph).unwrap();
        assert_eq!(doc.component_count, 0);
        assert!(doc.content.contains("SPDX"));
    }

    #[test]
    fn generate_spdx_is_valid_json() {
        let doc = generate(&sample_graph()).unwrap();
        let parsed: serde_json::Value = serde_json::from_str(&doc.content).unwrap();
        assert_eq!(parsed["spdxVersion"], "SPDX-2.3");
        assert_eq!(parsed["SPDXID"], "SPDXRef-DOCUMENT");
        assert!(parsed["packages"].is_array());
    }

    #[test]
    fn generate_spdx_unique_namespace() {
        let graph = sample_graph();
        let doc1 = generate(&graph).unwrap();
        let doc2 = generate(&graph).unwrap();

        let v1: serde_json::Value = serde_json::from_str(&doc1.content).unwrap();
        let v2: serde_json::Value = serde_json::from_str(&doc2.content).unwrap();

        // Each generation should have a unique namespace
        assert_ne!(v1["documentNamespace"], v2["documentNamespace"]);
    }
}

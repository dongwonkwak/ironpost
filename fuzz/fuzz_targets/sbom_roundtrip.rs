#![no_main]

use arbitrary::Arbitrary;
use libfuzzer_sys::fuzz_target;

use ironpost_sbom_scanner::sbom::cyclonedx;
use ironpost_sbom_scanner::sbom::spdx;
use ironpost_sbom_scanner::types::{Ecosystem, Package, PackageGraph};

/// 퍼저용 구조적 PackageGraph 입력
#[derive(Arbitrary, Debug)]
struct FuzzPackageGraph {
    ecosystem: FuzzEcosystem,
    packages: Vec<FuzzPackage>,
}

#[derive(Arbitrary, Debug)]
enum FuzzEcosystem {
    Cargo,
    Npm,
}

#[derive(Arbitrary, Debug)]
struct FuzzPackage {
    name: String,
    version: String,
    checksum: Option<String>,
}

impl FuzzEcosystem {
    fn to_ecosystem(&self) -> Ecosystem {
        match self {
            FuzzEcosystem::Cargo => Ecosystem::Cargo,
            FuzzEcosystem::Npm => Ecosystem::Npm,
        }
    }
}

fuzz_target!(|input: FuzzPackageGraph| {
    // 패키지 수 제한 (퍼징 성능)
    let packages: Vec<Package> = input
        .packages
        .iter()
        .take(100)
        .enumerate()
        .map(|(i, p)| {
            let name = if p.name.is_empty() {
                format!("pkg-{i}")
            } else if p.name.len() > 128 {
                p.name[..128].to_owned()
            } else {
                p.name.clone()
            };
            let version = if p.version.is_empty() {
                "0.0.0".to_owned()
            } else if p.version.len() > 64 {
                p.version[..64].to_owned()
            } else {
                p.version.clone()
            };
            let eco = input.ecosystem.to_ecosystem();
            Package {
                name: name.clone(),
                version: version.clone(),
                ecosystem: eco,
                purl: format!("pkg:{}/{}@{}", eco.purl_type(), name, version),
                checksum: p.checksum.clone(),
                dependencies: Vec::new(),
            }
        })
        .collect();

    let graph = PackageGraph {
        source_file: "fuzz-input".to_owned(),
        ecosystem: input.ecosystem.to_ecosystem(),
        packages: packages.clone(),
        root_packages: if packages.is_empty() {
            Vec::new()
        } else {
            vec![packages[0].name.clone()]
        },
    };

    // CycloneDX 생성 + JSON 유효성 검증
    if let Ok(doc) = cyclonedx::generate(&graph) {
        // 생성된 JSON이 파싱 가능해야 한다
        let _: serde_json::Value =
            serde_json::from_str(&doc.content).expect("CycloneDX output must be valid JSON");
    }

    // SPDX 생성 + JSON 유효성 검증
    if let Ok(doc) = spdx::generate(&graph) {
        let _: serde_json::Value =
            serde_json::from_str(&doc.content).expect("SPDX output must be valid JSON");
    }
});

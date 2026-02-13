//! SBOM 스캐너 벤치마크
//!
//! Cargo.lock 파싱, SBOM 생성, CVE 매칭 성능을 측정합니다.

use criterion::{BenchmarkId, Criterion, Throughput, black_box, criterion_group, criterion_main};
use ironpost_core::types::Severity;
use ironpost_sbom_scanner::sbom::cyclonedx;
use ironpost_sbom_scanner::types::Ecosystem;
use ironpost_sbom_scanner::vuln::db::{VersionRange, VulnDb, VulnDbEntry};
use ironpost_sbom_scanner::{CargoLockParser, LockfileParser};

/// 소규모 Cargo.lock (10개 패키지)
const SMALL_CARGO_LOCK: &str = r#"
[[package]]
name = "app"
version = "0.1.0"
dependencies = ["serde", "tokio"]

[[package]]
name = "serde"
version = "1.0.204"
source = "registry+https://github.com/rust-lang/crates.io-index"
checksum = "abc123"

[[package]]
name = "serde_derive"
version = "1.0.204"
source = "registry+https://github.com/rust-lang/crates.io-index"
checksum = "def456"

[[package]]
name = "tokio"
version = "1.38.0"
source = "registry+https://github.com/rust-lang/crates.io-index"
checksum = "ghi789"

[[package]]
name = "bytes"
version = "1.6.0"
source = "registry+https://github.com/rust-lang/crates.io-index"
checksum = "jkl012"

[[package]]
name = "tracing"
version = "0.1.40"
source = "registry+https://github.com/rust-lang/crates.io-index"
checksum = "mno345"

[[package]]
name = "anyhow"
version = "1.0.86"
source = "registry+https://github.com/rust-lang/crates.io-index"
checksum = "pqr678"

[[package]]
name = "clap"
version = "4.5.7"
source = "registry+https://github.com/rust-lang/crates.io-index"
checksum = "stu901"

[[package]]
name = "regex"
version = "1.10.5"
source = "registry+https://github.com/rust-lang/crates.io-index"
checksum = "vwx234"

[[package]]
name = "serde_json"
version = "1.0.120"
source = "registry+https://github.com/rust-lang/crates.io-index"
checksum = "yz567"
"#;

/// 대규모 Cargo.lock 생성 (count개 패키지)
fn generate_large_cargo_lock(count: usize) -> String {
    let mut lockfile = String::from(
        r#"
[[package]]
name = "app"
version = "0.1.0"
dependencies = []
"#,
    );

    for i in 0..count {
        lockfile.push_str(&format!(
            r#"
[[package]]
name = "package-{}"
version = "1.{}.0"
source = "registry+https://github.com/rust-lang/crates.io-index"
checksum = "abc{:04x}"
"#,
            i,
            i % 100,
            i
        ));
    }

    lockfile
}

fn bench_cargo_lock_parsing(c: &mut Criterion) {
    let parser = CargoLockParser;

    let mut group = c.benchmark_group("cargo_lock_parsing");

    // 소규모 (10개)
    group.throughput(Throughput::Elements(10));
    group.bench_function("small_10_packages", |b| {
        b.iter(|| {
            parser
                .parse(black_box(SMALL_CARGO_LOCK), "Cargo.lock")
                .unwrap()
        })
    });

    // 대규모 (100개)
    let large_100 = generate_large_cargo_lock(100);
    group.throughput(Throughput::Elements(100));
    group.bench_function("large_100_packages", |b| {
        b.iter(|| parser.parse(black_box(&large_100), "Cargo.lock").unwrap())
    });

    group.finish();
}

fn bench_sbom_generation(c: &mut Criterion) {
    let parser = CargoLockParser;
    let small_graph = parser.parse(SMALL_CARGO_LOCK, "Cargo.lock").unwrap();
    let large_100_graph = parser
        .parse(&generate_large_cargo_lock(100), "Cargo.lock")
        .unwrap();

    let mut group = c.benchmark_group("sbom_generation");

    // CycloneDX 생성 - 소규모
    group.throughput(Throughput::Elements(10));
    group.bench_function("cyclonedx_small_10", |b| {
        b.iter(|| cyclonedx::generate(black_box(&small_graph)).unwrap())
    });

    // CycloneDX 생성 - 대규모
    group.throughput(Throughput::Elements(100));
    group.bench_function("cyclonedx_large_100", |b| {
        b.iter(|| cyclonedx::generate(black_box(&large_100_graph)).unwrap())
    });

    group.finish();
}

fn bench_vuln_db_lookup(c: &mut Criterion) {
    // 테스트용 취약점 DB 생성
    let mut entries = Vec::new();
    for i in 0..1000 {
        entries.push(VulnDbEntry {
            cve_id: format!("CVE-2024-{:04}", i),
            package: format!("package-{}", i % 100), // 100개 패키지에 각 10개 CVE
            ecosystem: Ecosystem::Cargo,
            affected_ranges: vec![VersionRange {
                introduced: Some("1.0.0".to_owned()),
                fixed: Some("1.10.0".to_owned()),
            }],
            fixed_version: Some("1.10.0".to_owned()),
            severity: Severity::High,
            description: format!("Vulnerability in package-{}", i % 100),
            published: "2024-01-01".to_owned(),
        });
    }

    let db = VulnDb::from_entries(entries);

    let mut group = c.benchmark_group("vuln_db_lookup");

    // 단일 패키지 조회 (10개 CVE 반환)
    group.throughput(Throughput::Elements(1));
    group.bench_function("single_package_lookup", |b| {
        b.iter(|| db.lookup(black_box("package-0"), black_box(&Ecosystem::Cargo)))
    });

    // 100개 패키지 일괄 조회
    group.throughput(Throughput::Elements(100));
    group.bench_function("batch_100_lookups", |b| {
        b.iter(|| {
            for i in 0..100 {
                db.lookup(
                    black_box(&format!("package-{}", i)),
                    black_box(&Ecosystem::Cargo),
                );
            }
        })
    });

    // 존재하지 않는 패키지 조회 (miss)
    group.throughput(Throughput::Elements(1));
    group.bench_function("miss_lookup", |b| {
        b.iter(|| db.lookup(black_box("nonexistent-pkg"), black_box(&Ecosystem::Cargo)))
    });

    group.finish();
}

fn bench_vuln_db_creation(c: &mut Criterion) {
    // JSON 문자열 생성
    let mut entries_json = Vec::new();
    for i in 0..1000 {
        entries_json.push(format!(
            r#"{{
                "cve_id": "CVE-2024-{:04}",
                "package": "package-{}",
                "ecosystem": "Cargo",
                "affected_ranges": [
                    {{"introduced": "1.0.0", "fixed": "1.10.0"}}
                ],
                "fixed_version": "1.10.0",
                "severity": "High",
                "description": "Test vulnerability {}",
                "published": "2024-01-01"
            }}"#,
            i,
            i % 100,
            i
        ));
    }
    let json = format!("[{}]", entries_json.join(","));

    let mut group = c.benchmark_group("vuln_db_creation");
    group.throughput(Throughput::Elements(1000));

    group.bench_function("from_json_1000_entries", |b| {
        b.iter(|| VulnDb::from_json(black_box(&json)).unwrap())
    });

    group.finish();
}

fn bench_end_to_end_scan(c: &mut Criterion) {
    let parser = CargoLockParser;

    // 취약점 DB 생성
    let mut vuln_entries = Vec::new();
    for i in 0..100 {
        vuln_entries.push(VulnDbEntry {
            cve_id: format!("CVE-2024-{:04}", i),
            package: format!("package-{}", i),
            ecosystem: Ecosystem::Cargo,
            affected_ranges: vec![VersionRange {
                introduced: Some("1.0.0".to_owned()),
                fixed: Some("1.99.0".to_owned()),
            }],
            fixed_version: Some("1.99.0".to_owned()),
            severity: Severity::High,
            description: format!("Test vuln {}", i),
            published: "2024-01-01".to_owned(),
        });
    }
    let vuln_db = VulnDb::from_entries(vuln_entries);

    let lockfile_100 = generate_large_cargo_lock(100);

    let mut group = c.benchmark_group("end_to_end_scan");
    group.throughput(Throughput::Elements(100));

    group.bench_function("parse_sbom_scan_100", |b| {
        b.iter(|| {
            // Cargo.lock 파싱
            let graph = parser
                .parse(black_box(&lockfile_100), "Cargo.lock")
                .unwrap();

            // SBOM 생성
            let _sbom = cyclonedx::generate(black_box(&graph)).unwrap();

            // 모든 패키지에 대해 CVE 조회
            let mut _vulnerabilities = Vec::new();
            for pkg in &graph.packages {
                let vulns = vuln_db.lookup(&pkg.name, &pkg.ecosystem);
                _vulnerabilities.extend(vulns);
            }
        })
    });

    group.finish();
}

fn bench_package_graph_scaling(c: &mut Criterion) {
    let parser = CargoLockParser;

    let mut group = c.benchmark_group("package_graph_scaling");

    for size in [10, 50, 100].iter() {
        let lockfile = generate_large_cargo_lock(*size);
        group.throughput(Throughput::Elements(*size as u64));
        group.bench_with_input(BenchmarkId::from_parameter(size), size, |b, _| {
            b.iter(|| parser.parse(black_box(&lockfile), "Cargo.lock").unwrap())
        });
    }

    group.finish();
}

criterion_group!(
    benches,
    bench_cargo_lock_parsing,
    bench_sbom_generation,
    bench_vuln_db_lookup,
    bench_vuln_db_creation,
    bench_end_to_end_scan,
    bench_package_graph_scaling
);
criterion_main!(benches);

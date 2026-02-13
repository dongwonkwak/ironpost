//! 컨테이너 정책 평가 벤치마크
//!
//! 정책 평가, glob 매칭, 컨테이너 캐시 성능을 측정합니다.

use criterion::{black_box, criterion_group, criterion_main, BenchmarkId, Criterion, Throughput};
use ironpost_container_guard::policy::{PolicyEngine, SecurityPolicy, TargetFilter};
use ironpost_container_guard::isolation::IsolationAction;
use ironpost_core::event::AlertEvent;
use ironpost_core::types::{Alert, ContainerInfo, Severity};
use std::time::SystemTime;

fn create_alert(severity: Severity) -> AlertEvent {
    AlertEvent::new(
        Alert {
            id: "alert-001".to_owned(),
            title: "Test Alert".to_owned(),
            description: "test".to_owned(),
            severity,
            rule_name: "test_rule".to_owned(),
            source_ip: None,
            target_ip: None,
            created_at: SystemTime::now(),
        },
        severity,
    )
}

fn create_container(name: &str, image: &str) -> ContainerInfo {
    ContainerInfo {
        id: "abc123def456".to_owned(),
        name: name.to_owned(),
        image: image.to_owned(),
        status: "running".to_owned(),
        created_at: SystemTime::now(),
    }
}

fn create_policy(
    id: &str,
    severity: Severity,
    priority: u32,
    name_pattern: &str,
    image_pattern: &str,
) -> SecurityPolicy {
    SecurityPolicy {
        id: id.to_owned(),
        name: format!("Policy {}", id),
        description: "Test policy".to_owned(),
        enabled: true,
        severity_threshold: severity,
        target_filter: TargetFilter {
            container_names: if name_pattern.is_empty() {
                vec![]
            } else {
                vec![name_pattern.to_owned()]
            },
            image_patterns: if image_pattern.is_empty() {
                vec![]
            } else {
                vec![image_pattern.to_owned()]
            },
            labels: vec![],
        },
        action: IsolationAction::Pause,
        priority,
    }
}

fn bench_single_policy_evaluation(c: &mut Criterion) {
    let mut engine = PolicyEngine::new();
    let policy = create_policy("policy-1", Severity::High, 1, "", "");
    engine.add_policy(policy).unwrap();

    let alert = create_alert(Severity::Critical);
    let container = create_container("web-server", "nginx:latest");

    let mut group = c.benchmark_group("single_policy");
    group.throughput(Throughput::Elements(1));

    group.bench_function("evaluate", |b| {
        b.iter(|| {
            engine.evaluate(black_box(&alert), black_box(&container))
        })
    });

    group.finish();
}

fn bench_policy_scaling(c: &mut Criterion) {
    let alert = create_alert(Severity::High);
    let container = create_container("web-server-01", "nginx:latest");

    let mut group = c.benchmark_group("policy_scaling");

    for policy_count in [1, 10, 100].iter() {
        let mut engine = PolicyEngine::new();

        for i in 0..*policy_count {
            let policy = if i % 3 == 0 {
                create_policy(&format!("p-{}", i), Severity::Medium, i, "", "")
            } else if i % 3 == 1 {
                create_policy(&format!("p-{}", i), Severity::High, i, "web-*", "")
            } else {
                create_policy(&format!("p-{}", i), Severity::Low, i, "", "nginx:*")
            };
            engine.add_policy(policy).unwrap();
        }

        group.throughput(Throughput::Elements(*policy_count as u64));
        group.bench_with_input(
            BenchmarkId::from_parameter(policy_count),
            policy_count,
            |b, _| {
                b.iter(|| {
                    engine.evaluate(black_box(&alert), black_box(&container))
                })
            },
        );
    }

    group.finish();
}

fn bench_glob_matching(c: &mut Criterion) {
    let mut group = c.benchmark_group("glob_matching");
    group.throughput(Throughput::Elements(1));

    // 간단한 와일드카드
    let filter_simple = TargetFilter {
        container_names: vec!["web-*".to_owned()],
        image_patterns: vec![],
        labels: vec![],
    };
    let container = create_container("web-server-01", "nginx:latest");

    group.bench_function("simple_wildcard", |b| {
        b.iter(|| {
            filter_simple.matches(black_box(&container))
        })
    });

    // 복잡한 패턴
    let filter_complex = TargetFilter {
        container_names: vec!["web-*-prod-*".to_owned()],
        image_patterns: vec!["nginx:*".to_owned()],
        labels: vec![],
    };
    let container_complex = create_container("web-app-prod-01", "nginx:1.25-alpine");

    group.bench_function("complex_pattern", |b| {
        b.iter(|| {
            filter_complex.matches(black_box(&container_complex))
        })
    });

    // 여러 패턴 OR
    let filter_multi = TargetFilter {
        container_names: vec![
            "web-*".to_owned(),
            "api-*".to_owned(),
            "db-*".to_owned(),
            "cache-*".to_owned(),
        ],
        image_patterns: vec![
            "nginx:*".to_owned(),
            "redis:*".to_owned(),
            "postgres:*".to_owned(),
        ],
        labels: vec![],
    };

    group.bench_function("multiple_patterns", |b| {
        b.iter(|| {
            filter_multi.matches(black_box(&container))
        })
    });

    group.finish();
}

fn bench_policy_priority_ordering(c: &mut Criterion) {
    // 우선순위 역순으로 추가하여 정렬 성능 측정
    let mut group = c.benchmark_group("policy_priority");

    for count in [10, 50, 100].iter() {
        group.throughput(Throughput::Elements(*count as u64));
        group.bench_with_input(BenchmarkId::from_parameter(count), count, |b, &c| {
            b.iter(|| {
                let mut engine = PolicyEngine::new();
                // 역순으로 추가 (우선순위 높은 것을 나중에)
                for i in (0..c).rev() {
                    let policy = create_policy(&format!("p-{}", i), Severity::High, i, "", "");
                    engine.add_policy(policy).unwrap();
                }
            })
        });
    }

    group.finish();
}

fn bench_severity_filtering(c: &mut Criterion) {
    let mut engine = PolicyEngine::new();

    // 다양한 심각도의 정책 추가
    engine
        .add_policy(create_policy("p-critical", Severity::Critical, 1, "", ""))
        .unwrap();
    engine
        .add_policy(create_policy("p-high", Severity::High, 2, "", ""))
        .unwrap();
    engine
        .add_policy(create_policy("p-medium", Severity::Medium, 3, "", ""))
        .unwrap();
    engine
        .add_policy(create_policy("p-low", Severity::Low, 4, "", ""))
        .unwrap();

    let container = create_container("test-container", "test:latest");

    let mut group = c.benchmark_group("severity_filtering");
    group.throughput(Throughput::Elements(1));

    for severity in [
        Severity::Info,
        Severity::Low,
        Severity::Medium,
        Severity::High,
        Severity::Critical,
    ]
    .iter()
    {
        let alert = create_alert(*severity);
        group.bench_with_input(
            BenchmarkId::from_parameter(format!("{:?}", severity)),
            severity,
            |b, _| {
                b.iter(|| {
                    engine.evaluate(black_box(&alert), black_box(&container))
                })
            },
        );
    }

    group.finish();
}

fn bench_container_name_variations(c: &mut Criterion) {
    let mut engine = PolicyEngine::new();
    engine
        .add_policy(create_policy("p1", Severity::High, 1, "web-*", ""))
        .unwrap();

    let alert = create_alert(Severity::Critical);

    let mut group = c.benchmark_group("container_name_matching");
    group.throughput(Throughput::Elements(1));

    // 짧은 이름
    let short = create_container("web-1", "nginx:latest");
    group.bench_function("short_name", |b| {
        b.iter(|| {
            engine.evaluate(black_box(&alert), black_box(&short))
        })
    });

    // 긴 이름
    let long = create_container(
        "web-production-eu-west-1a-server-instance-12345",
        "nginx:latest",
    );
    group.bench_function("long_name", |b| {
        b.iter(|| {
            engine.evaluate(black_box(&alert), black_box(&long))
        })
    });

    // 매칭 실패 (앞부분 불일치)
    let mismatch = create_container("api-server", "nginx:latest");
    group.bench_function("mismatch", |b| {
        b.iter(|| {
            engine.evaluate(black_box(&alert), black_box(&mismatch))
        })
    });

    group.finish();
}

fn bench_policy_add_remove(c: &mut Criterion) {
    let mut group = c.benchmark_group("policy_mutation");

    // 정책 추가
    group.bench_function("add_policy", |b| {
        b.iter(|| {
            let mut engine = PolicyEngine::new();
            let policy = create_policy("test", Severity::High, 1, "", "");
            engine.add_policy(black_box(policy)).unwrap();
        })
    });

    // 정책 제거
    group.bench_function("remove_policy", |b| {
        b.iter(|| {
            let mut engine = PolicyEngine::new();
            for i in 0..10 {
                let policy = create_policy(&format!("p-{}", i), Severity::High, i, "", "");
                engine.add_policy(policy).unwrap();
            }
            engine.remove_policy(black_box("p-5"));
        })
    });

    group.finish();
}

criterion_group!(
    benches,
    bench_single_policy_evaluation,
    bench_policy_scaling,
    bench_glob_matching,
    bench_policy_priority_ordering,
    bench_severity_filtering,
    bench_container_name_variations,
    bench_policy_add_remove
);
criterion_main!(benches);

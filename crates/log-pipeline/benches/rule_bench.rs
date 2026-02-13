//! 룰 매칭 벤치마크
//!
//! 단일/다중 룰 매칭 성능과 스케일링을 측정합니다.

use criterion::{BenchmarkId, Criterion, Throughput, black_box, criterion_group, criterion_main};
use ironpost_core::types::{LogEntry, Severity};
use ironpost_log_pipeline::rule::matcher::RuleMatcher;
use ironpost_log_pipeline::rule::types::{
    ConditionModifier, DetectionCondition, DetectionRule, FieldCondition, RuleStatus,
    ThresholdConfig,
};
use std::time::SystemTime;

fn create_log_entry(message: &str) -> LogEntry {
    LogEntry {
        source: "syslog".to_owned(),
        timestamp: SystemTime::now(),
        hostname: "web-server-01".to_owned(),
        process: "sshd".to_owned(),
        message: message.to_owned(),
        severity: Severity::High,
        fields: vec![
            ("pid".to_owned(), "1234".to_owned()),
            ("source_ip".to_owned(), "192.168.1.100".to_owned()),
        ],
    }
}

fn create_simple_rule(id: &str) -> DetectionRule {
    DetectionRule {
        id: id.to_owned(),
        title: format!("Test Rule {}", id),
        description: "Test rule".to_owned(),
        severity: Severity::High,
        status: RuleStatus::Enabled,
        detection: DetectionCondition {
            conditions: vec![FieldCondition {
                field: "process".to_owned(),
                modifier: ConditionModifier::Exact,
                value: "sshd".to_owned(),
            }],
            threshold: None,
        },
        tags: vec!["test".to_owned()],
    }
}

fn create_regex_rule(id: &str, pattern: &str) -> DetectionRule {
    DetectionRule {
        id: id.to_owned(),
        title: format!("Regex Rule {}", id),
        description: "Regex rule".to_owned(),
        severity: Severity::High,
        status: RuleStatus::Enabled,
        detection: DetectionCondition {
            conditions: vec![FieldCondition {
                field: "message".to_owned(),
                modifier: ConditionModifier::Regex,
                value: pattern.to_owned(),
            }],
            threshold: None,
        },
        tags: vec!["test".to_owned()],
    }
}

fn create_complex_rule(id: &str) -> DetectionRule {
    DetectionRule {
        id: id.to_owned(),
        title: format!("Complex Rule {}", id),
        description: "Multi-condition rule".to_owned(),
        severity: Severity::High,
        status: RuleStatus::Enabled,
        detection: DetectionCondition {
            conditions: vec![
                FieldCondition {
                    field: "process".to_owned(),
                    modifier: ConditionModifier::Exact,
                    value: "sshd".to_owned(),
                },
                FieldCondition {
                    field: "message".to_owned(),
                    modifier: ConditionModifier::Contains,
                    value: "Failed password".to_owned(),
                },
                FieldCondition {
                    field: "source_ip".to_owned(),
                    modifier: ConditionModifier::Regex,
                    value: r"192\.168\.\d+\.\d+".to_owned(),
                },
            ],
            threshold: None,
        },
        tags: vec!["authentication".to_owned(), "brute_force".to_owned()],
    }
}

fn create_threshold_rule(id: &str) -> DetectionRule {
    DetectionRule {
        id: id.to_owned(),
        title: format!("Threshold Rule {}", id),
        description: "Rule with threshold".to_owned(),
        severity: Severity::High,
        status: RuleStatus::Enabled,
        detection: DetectionCondition {
            conditions: vec![FieldCondition {
                field: "process".to_owned(),
                modifier: ConditionModifier::Exact,
                value: "sshd".to_owned(),
            }],
            threshold: Some(ThresholdConfig {
                field: "source_ip".to_owned(),
                count: 5,
                timeframe_secs: 300,
            }),
        },
        tags: vec!["test".to_owned()],
    }
}

fn bench_single_rule_match(c: &mut Criterion) {
    let mut matcher = RuleMatcher::new();
    let rule = create_simple_rule("rule-1");
    matcher.compile_rule(&rule).unwrap();

    let entry = create_log_entry("Failed password for root from 192.168.1.100");

    let mut group = c.benchmark_group("single_rule");
    group.throughput(Throughput::Elements(1));

    group.bench_function("exact_match", |b| {
        b.iter(|| {
            matcher
                .matches(black_box(&rule), black_box(&entry))
                .unwrap()
        })
    });

    group.finish();
}

fn bench_regex_rule_match(c: &mut Criterion) {
    let mut matcher = RuleMatcher::new();
    let rule = create_regex_rule("regex-1", r"Failed.*password.*from.*\d+\.\d+\.\d+\.\d+");
    matcher.compile_rule(&rule).unwrap();

    let entry = create_log_entry("Failed password for root from 192.168.1.100");

    let mut group = c.benchmark_group("regex_rule");
    group.throughput(Throughput::Elements(1));

    group.bench_function("regex_match", |b| {
        b.iter(|| {
            matcher
                .matches(black_box(&rule), black_box(&entry))
                .unwrap()
        })
    });

    group.finish();
}

fn bench_complex_rule_match(c: &mut Criterion) {
    let mut matcher = RuleMatcher::new();
    let rule = create_complex_rule("complex-1");
    matcher.compile_rule(&rule).unwrap();

    let entry = create_log_entry("Failed password for root from 192.168.1.100");

    let mut group = c.benchmark_group("complex_rule");
    group.throughput(Throughput::Elements(1));

    group.bench_function("multi_condition", |b| {
        b.iter(|| {
            matcher
                .matches(black_box(&rule), black_box(&entry))
                .unwrap()
        })
    });

    group.finish();
}

fn bench_multiple_rules_scaling(c: &mut Criterion) {
    let entry = create_log_entry("Failed password for root from 192.168.1.100");

    let mut group = c.benchmark_group("rules_scaling");

    for rule_count in [1, 10, 100].iter() {
        let mut matcher = RuleMatcher::new();
        let mut rules = Vec::new();

        for i in 0..*rule_count {
            let rule = if i % 3 == 0 {
                create_simple_rule(&format!("rule-{}", i))
            } else if i % 3 == 1 {
                create_regex_rule(&format!("rule-{}", i), r"Failed.*password")
            } else {
                create_complex_rule(&format!("rule-{}", i))
            };
            matcher.compile_rule(&rule).unwrap();
            rules.push(rule);
        }

        group.throughput(Throughput::Elements(*rule_count as u64));
        group.bench_with_input(
            BenchmarkId::from_parameter(rule_count),
            rule_count,
            |b, _| {
                b.iter(|| {
                    for rule in &rules {
                        matcher.matches(black_box(rule), black_box(&entry)).unwrap();
                    }
                })
            },
        );
    }

    group.finish();
}

fn bench_threshold_rule(c: &mut Criterion) {
    let mut matcher = RuleMatcher::new();
    let rule = create_threshold_rule("threshold-1");
    matcher.compile_rule(&rule).unwrap();

    let entry = create_log_entry("Failed password for root");

    let mut group = c.benchmark_group("threshold_rule");
    group.throughput(Throughput::Elements(1));

    group.bench_function("threshold_evaluation", |b| {
        b.iter(|| {
            matcher
                .matches(black_box(&rule), black_box(&entry))
                .unwrap()
        })
    });

    group.finish();
}

fn bench_rule_compilation(c: &mut Criterion) {
    let mut group = c.benchmark_group("rule_compilation");

    group.bench_function("compile_simple", |b| {
        b.iter(|| {
            let mut matcher = RuleMatcher::new();
            let rule = create_simple_rule("compile-test");
            matcher.compile_rule(black_box(&rule)).unwrap();
        })
    });

    group.bench_function("compile_regex", |b| {
        b.iter(|| {
            let mut matcher = RuleMatcher::new();
            let rule = create_regex_rule(
                "compile-test",
                r"Failed.*password.*from.*\d+\.\d+\.\d+\.\d+",
            );
            matcher.compile_rule(black_box(&rule)).unwrap();
        })
    });

    group.bench_function("compile_complex", |b| {
        b.iter(|| {
            let mut matcher = RuleMatcher::new();
            let rule = create_complex_rule("compile-test");
            matcher.compile_rule(black_box(&rule)).unwrap();
        })
    });

    group.finish();
}

criterion_group!(
    benches,
    bench_single_rule_match,
    bench_regex_rule_match,
    bench_complex_rule_match,
    bench_multiple_rules_scaling,
    bench_threshold_rule,
    bench_rule_compilation
);
criterion_main!(benches);

#![no_main]

use arbitrary::Arbitrary;
use libfuzzer_sys::fuzz_target;
use std::time::SystemTime;

use ironpost_core::types::{LogEntry, Severity};
use ironpost_log_pipeline::rule::matcher::RuleMatcher;
use ironpost_log_pipeline::rule::types::{
    ConditionModifier, DetectionCondition, DetectionRule, FieldCondition,
    RuleStatus,
};

/// 퍼저용 구조적 입력
#[derive(Arbitrary, Debug)]
struct FuzzInput {
    /// 규칙 조건 목록 (최대 8개로 제한)
    conditions: Vec<FuzzCondition>,
    /// 매칭 대상 LogEntry 필드값
    entry_message: String,
    entry_process: String,
    entry_hostname: String,
}

#[derive(Arbitrary, Debug)]
struct FuzzCondition {
    field: FuzzField,
    modifier: FuzzModifier,
    value: String,
}

#[derive(Arbitrary, Debug)]
enum FuzzField {
    Message,
    Process,
    Hostname,
    Source,
}

#[derive(Arbitrary, Debug)]
enum FuzzModifier {
    Exact,
    Contains,
    StartsWith,
    EndsWith,
    Regex,
}

impl FuzzField {
    fn as_str(&self) -> &str {
        match self {
            FuzzField::Message => "message",
            FuzzField::Process => "process",
            FuzzField::Hostname => "hostname",
            FuzzField::Source => "source",
        }
    }
}

impl FuzzModifier {
    fn to_condition_modifier(&self) -> ConditionModifier {
        match self {
            FuzzModifier::Exact => ConditionModifier::Exact,
            FuzzModifier::Contains => ConditionModifier::Contains,
            FuzzModifier::StartsWith => ConditionModifier::StartsWith,
            FuzzModifier::EndsWith => ConditionModifier::EndsWith,
            FuzzModifier::Regex => ConditionModifier::Regex,
        }
    }
}

fuzz_target!(|input: FuzzInput| {
    // 조건 수 제한 (성능)
    let conditions: Vec<FieldCondition> = input
        .conditions
        .iter()
        .take(8)
        .map(|c| FieldCondition {
            field: c.field.as_str().to_owned(),
            modifier: c.modifier.to_condition_modifier(),
            value: c.value.clone(),
        })
        .collect();

    if conditions.is_empty() {
        return;
    }

    let rule = DetectionRule {
        id: "fuzz_rule".to_owned(),
        title: "Fuzz Rule".to_owned(),
        description: String::new(),
        severity: Severity::Info,
        status: RuleStatus::Enabled,
        detection: DetectionCondition {
            conditions,
            threshold: None,
        },
        tags: Vec::new(),
    };

    let mut matcher = RuleMatcher::new();

    // compile_rule이 실패해도 크래시는 안 됨
    if matcher.compile_rule(&rule).is_err() {
        return;
    }

    let entry = LogEntry {
        source: "fuzz".to_owned(),
        timestamp: SystemTime::now(),
        hostname: input.entry_hostname,
        process: input.entry_process,
        message: input.entry_message,
        severity: Severity::Info,
        fields: Vec::new(),
    };

    // matches도 크래시 없이 Ok/Err 반환해야 함
    let _ = matcher.matches(&rule, &entry);
});

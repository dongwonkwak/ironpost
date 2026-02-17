# Phase 11: Parser Fuzzing 설계 문서

> 작성일: 2026-02-17
> 작성자: architect
> 브랜치: `feat/parser-fuzzing`

---

## 1. 개요

### 1.1 목표

Ironpost 플랫폼의 모든 파서 및 입력 처리 경로에 대해 구조적 퍼징(structured fuzzing)을 도입하여, 기존 단위 테스트와 property-based 테스트로는 발견하기 어려운 크래시, 패닉, 무한 루프, 메모리 과다 사용 등의 결함을 사전에 탐지한다.

### 1.2 범위

| 항목 | 포함 여부 |
|------|-----------|
| `fuzz/` 독립 크레이트 (workspace 외부) | O |
| Syslog 파서 퍼징 (`SyslogParser`) | O |
| JSON 로그 파서 퍼징 (`JsonLogParser`) | O |
| 파서 라우터 퍼징 (`ParserRouter`) | O |
| 규칙 YAML 파서 퍼징 (`RuleLoader::parse_yaml`) | O |
| 규칙 매처 퍼징 (`RuleMatcher`) | O |
| Cargo.lock 파서 퍼징 (`CargoLockParser`) | O |
| NPM package-lock.json 파서 퍼징 (`NpmLockParser`) | O |
| SBOM 라운드트립 퍼징 (generate -> re-parse) | O |
| Corpus 시드 파일 생성 | O |
| CI nightly 퍼징 워크플로우 | O |
| `Arbitrary` trait 구현 (구조화 입력) | O |
| Coverage-guided 퍼징 전용 빌드 | X (libFuzzer 기본 커버리지 활용) |
| OSS-Fuzz 통합 | X (향후 Phase) |

### 1.3 설계 원칙

1. **Workspace 격리**: `fuzz/` 디렉토리는 workspace member가 아닌 독립 크레이트로 구성한다. `cargo-fuzz`(libFuzzer)는 `panic = "abort"` 프로파일을 자체적으로 관리하므로, workspace의 기존 프로파일 설정과 충돌하지 않는다.
2. **비침습적**: 기존 라이브러리 크레이트의 코드를 수정하지 않는다. 모든 퍼징 하네스는 public API만 사용한다.
3. **재현성**: 크래시 재현을 위한 시드 관리와 artifact 보존 전략을 수립한다.
4. **CI 친화적**: GitHub Actions nightly 워크플로우에서 시간 제한(time-boxed) 퍼징을 수행한다.

---

## 2. 아키텍처

### 2.1 디렉토리 구조

```text
ironpost/
+-- Cargo.toml                    # workspace, exclude = ["...", "fuzz"]
+-- fuzz/
|   +-- Cargo.toml                # 독립 크레이트 (workspace 외부)
|   +-- fuzz_targets/
|   |   +-- syslog_parser.rs      # Syslog RFC 5424/3164 퍼징
|   |   +-- json_parser.rs        # JSON 로그 파서 퍼징
|   |   +-- parser_router.rs      # ParserRouter 자동 감지 퍼징
|   |   +-- rule_yaml.rs          # DetectionRule YAML 파싱 퍼징
|   |   +-- rule_matcher.rs       # RuleMatcher 조건 평가 퍼징
|   |   +-- cargo_lock.rs         # Cargo.lock TOML 파싱 퍼징
|   |   +-- npm_lock.rs           # package-lock.json 파싱 퍼징
|   |   +-- sbom_roundtrip.rs     # SBOM generate -> JSON parse 라운드트립
|   +-- corpus/
|   |   +-- syslog/               # Syslog 시드 파일
|   |   +-- json/                 # JSON 로그 시드 파일
|   |   +-- rule_yaml/            # YAML 규칙 시드 파일
|   |   +-- cargo_lock/           # Cargo.lock 시드 파일
|   |   +-- npm_lock/             # package-lock.json 시드 파일
|   +-- artifacts/                # 크래시 파일 저장 (gitignore)
|   +-- .gitignore                # artifacts/ 제외
+-- .github/workflows/fuzz.yml    # Nightly 퍼징 워크플로우
```

### 2.2 Workspace 설정 변경

`Cargo.toml`의 `exclude` 목록에 `fuzz`를 추가한다.

```toml
exclude = [
    "crates/ebpf-engine/ebpf",
    "fuzz",
]
```

### 2.3 fuzz/Cargo.toml

```toml
[package]
name = "ironpost-fuzz"
version = "0.0.0"
publish = false
edition = "2024"

[package.metadata]
cargo-fuzz = true

[dependencies]
libfuzzer-sys = "0.4"
arbitrary = { version = "1", features = ["derive"] }
ironpost-log-pipeline = { path = "../crates/log-pipeline" }
ironpost-sbom-scanner = { path = "../crates/sbom-scanner" }
ironpost-core = { path = "../crates/core" }

# rule_matcher 퍼징에서 LogEntry 구성에 필요
chrono = "0.4"

# SBOM 라운드트립에서 JSON 검증에 필요
serde_json = "1"

[[bin]]
name = "fuzz_syslog_parser"
path = "fuzz_targets/syslog_parser.rs"
doc = false

[[bin]]
name = "fuzz_json_parser"
path = "fuzz_targets/json_parser.rs"
doc = false

[[bin]]
name = "fuzz_parser_router"
path = "fuzz_targets/parser_router.rs"
doc = false

[[bin]]
name = "fuzz_rule_yaml"
path = "fuzz_targets/rule_yaml.rs"
doc = false

[[bin]]
name = "fuzz_rule_matcher"
path = "fuzz_targets/rule_matcher.rs"
doc = false

[[bin]]
name = "fuzz_cargo_lock"
path = "fuzz_targets/cargo_lock.rs"
doc = false

[[bin]]
name = "fuzz_npm_lock"
path = "fuzz_targets/npm_lock.rs"
doc = false

[[bin]]
name = "fuzz_sbom_roundtrip"
path = "fuzz_targets/sbom_roundtrip.rs"
doc = false
```

### 2.4 의존성 방향

```text
fuzz/Cargo.toml (독립, workspace 외부)
    +-- ironpost-core (path = "../crates/core")
    +-- ironpost-log-pipeline (path = "../crates/log-pipeline")
    +-- ironpost-sbom-scanner (path = "../crates/sbom-scanner")
    +-- libfuzzer-sys
    +-- arbitrary
```

퍼징 크레이트는 라이브러리 크레이트의 public API만 사용한다. 라이브러리 크레이트 자체는 수정하지 않는다.

### 2.5 cargo-fuzz와 panic = "abort" 호환성

Workspace `Cargo.toml`에 `[profile.dev] panic = "abort"`가 설정되어 있다. `cargo-fuzz`는 자체적으로 `[profile.release]`에 `panic = "abort"`를 설정하며, 퍼징 빌드에서는 libFuzzer가 요구하는 instrumentation을 삽입한다. `fuzz/` 크레이트가 workspace member가 아니므로 workspace 프로파일 설정과 충돌하지 않는다.

---

## 3. Fuzz Target 정의

### 3.1 개요 테이블

| # | Target 이름 | 대상 모듈 | 입력 형식 | 주요 탐색 영역 |
|---|-------------|-----------|-----------|----------------|
| 1 | `fuzz_syslog_parser` | log-pipeline | `&[u8]` (비구조적) | PRI 디코딩, RFC 3339/BSD 타임스탬프, SD 파싱, 경계값 |
| 2 | `fuzz_json_parser` | log-pipeline | `&[u8]` (비구조적) | 중첩 JSON 깊이, 대용량 문자열, 타임스탬프 파싱 |
| 3 | `fuzz_parser_router` | log-pipeline | `&[u8]` (비구조적) | 형식 자동 감지, 파서 간 전환, 엣지 케이스 |
| 4 | `fuzz_rule_yaml` | log-pipeline | `&str` (비구조적) | YAML 파싱, 규칙 검증, 악의적 YAML 구조 |
| 5 | `fuzz_rule_matcher` | log-pipeline | `Arbitrary` (구조적) | 정규식 처리, ReDoS, 조건 매칭 로직 |
| 6 | `fuzz_cargo_lock` | sbom-scanner | `&str` (비구조적) | TOML 파싱, 의존성 그래프 구성, 필드 길이 제한 |
| 7 | `fuzz_npm_lock` | sbom-scanner | `&str` (비구조적) | JSON 파싱, 패키지 수 제한, scoped 패키지 |
| 8 | `fuzz_sbom_roundtrip` | sbom-scanner | `Arbitrary` (구조적) | CycloneDX/SPDX 생성, JSON 유효성, 라운드트립 일관성 |

### 3.2 Target 1: Syslog Parser (`fuzz_syslog_parser`)

**대상 함수**: `SyslogParser::parse(&self, raw: &[u8]) -> Result<LogEntry, IronpostError>`

**입력 형식**: 비구조적 바이트 슬라이스 (`&[u8]`)

**탐색 엣지 케이스**:
- PRI 값 경계: `<0>`, `<191>`, `<192>`, `<999>`, `<>`
- RFC 3339 타임스탬프 파싱 오류: 잘린 날짜, 잘못된 시간대, 윤초
- BSD 타임스탬프 fallback: `Jan  1`, 윤년 `Feb 29`, 잘못된 월명
- Structured Data: 중첩 대괄호, 이스케이프 문자 (`\"`, `\\`, `\]`), 빈 SD
- NILVALUE (`-`) 처리: 각 필드 위치에서의 NILVALUE
- 최대 입력 크기(64KB) 초과 입력
- 비 UTF-8 바이트 시퀀스
- 멀티바이트 UTF-8 문자 (CJK, 이모지) 경계에서의 잘림

**하네스 코드**:

```rust
#![no_main]

use libfuzzer_sys::fuzz_target;
use ironpost_core::pipeline::LogParser;
use ironpost_log_pipeline::parser::SyslogParser;

fuzz_target!(|data: &[u8]| {
    let parser = SyslogParser::new();

    // 크래시나 패닉 없이 Ok 또는 Err을 반환해야 한다
    let _ = parser.parse(data);
});
```

### 3.3 Target 2: JSON Log Parser (`fuzz_json_parser`)

**대상 함수**: `JsonLogParser::parse(&self, raw: &[u8]) -> Result<LogEntry, IronpostError>`

**입력 형식**: 비구조적 바이트 슬라이스 (`&[u8]`)

**탐색 엣지 케이스**:
- 깊이 제한(32) 초과 중첩 JSON 객체
- 최대 입력 크기(1MB) 근처 및 초과 입력
- 극단적으로 큰 문자열 값 (키 또는 값)
- 빈 JSON 객체 `{}`
- 배열 값 처리 (`"tags": [1,2,3]`)
- 타임스탬프 파싱: RFC 3339, Unix epoch (초/밀리초/마이크로초/나노초), 잘못된 형식
- 필드 매핑 키 부재
- 중복 키
- NaN, Infinity, 매우 큰 숫자
- null 값 필드

**하네스 코드**:

```rust
#![no_main]

use libfuzzer_sys::fuzz_target;
use ironpost_core::pipeline::LogParser;
use ironpost_log_pipeline::parser::JsonLogParser;

fuzz_target!(|data: &[u8]| {
    let parser = JsonLogParser::default();
    let _ = parser.parse(data);
});
```

### 3.4 Target 3: Parser Router (`fuzz_parser_router`)

**대상 함수**: `ParserRouter::parse(&self, raw: &[u8]) -> Result<LogEntry, IronpostError>`

**입력 형식**: 비구조적 바이트 슬라이스 (`&[u8]`)

**탐색 엣지 케이스**:
- Syslog와 JSON 형식이 모호한 입력 (예: `<34>{"message":"test"}`)
- 모든 파서가 실패하는 입력
- 한 파서에서 예외가 발생해도 다음 파서로 fallback하는지 확인
- 빈 입력 `b""`
- 단일 바이트 입력
- ASCII 제어 문자로만 구성된 입력

**하네스 코드**:

```rust
#![no_main]

use libfuzzer_sys::fuzz_target;
use ironpost_log_pipeline::parser::ParserRouter;

fuzz_target!(|data: &[u8]| {
    let router = ParserRouter::with_defaults();
    let _ = router.parse(data);
});
```

### 3.5 Target 4: Rule YAML Parser (`fuzz_rule_yaml`)

**대상 함수**: `RuleLoader::parse_yaml(yaml_str: &str, source: &str) -> Result<DetectionRule, LogPipelineError>`

**입력 형식**: 비구조적 문자열 (`&str`)

**탐색 엣지 케이스**:
- YAML bomb (앵커/별칭을 이용한 지수적 확장): `serde_yaml`의 기본 보호 검증
- 극단적으로 긴 필드 값 (id, title, description > 256자)
- severity 필드에 잘못된 값
- detection.conditions가 빈 배열인 경우
- threshold.count = 0, threshold.timeframe_secs = 0
- 중첩 YAML 구조 (맵 내부 맵)
- 유니코드 제로 폭 문자, BOM 마커
- 탭/스페이스 혼용 들여쓰기
- YAML 태그 (`!!python/object`, `!!str` 등)
- 매우 큰 tags 배열 (10,000개 이상)

**하네스 코드**:

```rust
#![no_main]

use libfuzzer_sys::fuzz_target;
use ironpost_log_pipeline::rule::RuleLoader;

fuzz_target!(|data: &[u8]| {
    // YAML 파서는 &str을 받으므로 UTF-8 변환 필요
    if let Ok(yaml_str) = std::str::from_utf8(data) {
        let _ = RuleLoader::parse_yaml(yaml_str, "fuzz-input.yml");
    }
});
```

### 3.6 Target 5: Rule Matcher (`fuzz_rule_matcher`)

**대상 함수**:
- `RuleMatcher::compile_rule(&mut self, rule: &DetectionRule) -> Result<(), LogPipelineError>`
- `RuleMatcher::matches(&self, rule: &DetectionRule, entry: &LogEntry) -> Result<bool, LogPipelineError>`

**입력 형식**: `Arbitrary` 구조적 입력 (섹션 5에서 상세 정의)

**탐색 엣지 케이스**:
- ReDoS 패턴: `(.+)+`, `(a+)+`, `(a|aa)+`
- 정규식 길이 > 1,000 (MAX_REGEX_LENGTH 초과)
- FORBIDDEN_PATTERNS와 일치하는 패턴
- ConditionModifier 모든 변형: Exact, Contains, StartsWith, EndsWith, Regex
- 빈 문자열 조건 값
- LogEntry 필드 중 존재하지 않는 필드명 참조
- 매우 많은 조건 (수천 개)
- 동일한 rule_id로 여러 번 compile_rule 호출

**하네스 코드**:

```rust
#![no_main]

use arbitrary::Arbitrary;
use libfuzzer_sys::fuzz_target;
use std::time::SystemTime;

use ironpost_core::types::{LogEntry, Severity};
use ironpost_log_pipeline::rule::matcher::RuleMatcher;
use ironpost_log_pipeline::rule::types::{
    ConditionModifier, DetectionCondition, DetectionRule, FieldCondition,
    RuleStatus, ThresholdConfig,
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
```

### 3.7 Target 6: Cargo.lock Parser (`fuzz_cargo_lock`)

**대상 함수**: `CargoLockParser::parse(&self, content: &str, source_path: &str) -> Result<PackageGraph, SbomScannerError>`

**입력 형식**: 비구조적 문자열 (`&str`)

**탐색 엣지 케이스**:
- 잘못된 TOML 구문
- `[[package]]` 섹션 없는 TOML
- 극단적으로 긴 패키지 이름 (> 512자) 또는 버전 (> 256자)
- 빈 name/version 필드
- 순환 의존성 그래프
- 중복 패키지 이름+버전
- dependencies 목록에 존재하지 않는 패키지 참조
- 매우 많은 패키지 (수만 개)
- source 필드에 악의적 URL
- checksum 필드에 비정상 값
- 유니코드 패키지 이름

**하네스 코드**:

```rust
#![no_main]

use libfuzzer_sys::fuzz_target;
use ironpost_sbom_scanner::parser::LockfileParser;
use ironpost_sbom_scanner::parser::cargo::CargoLockParser;

fuzz_target!(|data: &[u8]| {
    if let Ok(content) = std::str::from_utf8(data) {
        let parser = CargoLockParser;
        let _ = parser.parse(content, "fuzz/Cargo.lock");
    }
});
```

### 3.8 Target 7: NPM package-lock.json Parser (`fuzz_npm_lock`)

**대상 함수**: `NpmLockParser::parse(&self, content: &str, source_path: &str) -> Result<PackageGraph, SbomScannerError>`

**입력 형식**: 비구조적 문자열 (`&str`)

**탐색 엣지 케이스**:
- 잘못된 JSON 구문
- packages 맵이 없는 JSON 객체
- 패키지 수 > 500,000 (MAX_NPM_PACKAGES)
- scoped 패키지 이름 (`@scope/name`)
- lockfileVersion 필드 부재/비정상 값
- node_modules 경로 깊이가 극단적으로 깊은 경우
- 빈 패키지 이름/버전
- 극단적으로 긴 패키지 이름 (> 512자)
- dependencies 필드에 비정상 타입 (문자열 대신 숫자 등)
- 루트 패키지 (`""` 키) 부재

**하네스 코드**:

```rust
#![no_main]

use libfuzzer_sys::fuzz_target;
use ironpost_sbom_scanner::parser::LockfileParser;
use ironpost_sbom_scanner::parser::npm::NpmLockParser;

fuzz_target!(|data: &[u8]| {
    if let Ok(content) = std::str::from_utf8(data) {
        let parser = NpmLockParser;
        let _ = parser.parse(content, "fuzz/package-lock.json");
    }
});
```

### 3.9 Target 8: SBOM Roundtrip (`fuzz_sbom_roundtrip`)

**대상 함수**:
- `ironpost_sbom_scanner::sbom::cyclonedx::generate(&PackageGraph) -> Result<SbomDocument, SbomScannerError>`
- `ironpost_sbom_scanner::sbom::spdx::generate(&PackageGraph) -> Result<SbomDocument, SbomScannerError>`

**입력 형식**: `Arbitrary` 구조적 입력 (`PackageGraph`)

**탐색 엣지 케이스**:
- 빈 패키지 그래프 (packages = [])
- 패키지 이름/버전에 JSON 특수 문자 (`"`, `\`, `\n`)
- purl 필드에 비정상 형식
- 매우 많은 패키지 (수천 개)
- 의존성에 존재하지 않는 패키지 참조
- 생성된 JSON이 유효한 JSON인지 검증 (라운드트립)
- Ecosystem 변형 전체 (Cargo, Npm, Go, Pip)

**하네스 코드**:

```rust
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
                ecosystem: eco.clone(),
                purl: format!(
                    "pkg:{}/{}@{}",
                    eco.as_str(),
                    name,
                    version
                ),
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
        let _: serde_json::Value = serde_json::from_str(&doc.content)
            .expect("CycloneDX output must be valid JSON");
    }

    // SPDX 생성 + JSON 유효성 검증
    if let Ok(doc) = spdx::generate(&graph) {
        let _: serde_json::Value = serde_json::from_str(&doc.content)
            .expect("SPDX output must be valid JSON");
    }
});
```

**참고**: `sbom_roundtrip`에서 `expect()`를 사용하는 것은 의도적이다. SBOM 생성기가 유효하지 않은 JSON을 출력하면 이는 버그이며, libFuzzer가 이를 크래시로 포착해야 한다.

---

## 4. Corpus 시드 전략

### 4.1 시드 출처

각 퍼징 타겟에 대해 기존 테스트 케이스, 실제 파일, 그리고 수동 생성한 엣지 케이스 파일을 시드 corpus로 제공한다.

| 타겟 | 시드 출처 | 예상 시드 수 |
|------|-----------|-------------|
| syslog | 기존 단위 테스트의 입력 문자열 추출 | 15-20 |
| json | 기존 단위 테스트의 JSON 입력 추출 | 10-15 |
| rule_yaml | `docker/demo/rules/*.yml` 파일 복사 + 엣지 케이스 | 20-25 |
| cargo_lock | 프로젝트 자체 `Cargo.lock` + 소규모/빈 lockfile | 5-8 |
| npm_lock | v2/v3 형식 최소 예제 + scoped 패키지 예제 | 5-8 |

### 4.2 시드 생성 방법

**4.2.1 기존 테스트에서 추출**

기존 단위 테스트에서 사용된 입력 문자열을 파일로 저장한다.

```bash
# Syslog 시드 예시
echo -n '<34>1 2024-01-15T12:00:00Z host sshd 1234 - - Failed password' \
    > fuzz/corpus/syslog/rfc5424_basic

echo -n '<13>Jan  5 14:30:00 myhost sshd[1234]: Failed password' \
    > fuzz/corpus/syslog/bsd_basic

echo -n '<165>1 2024-01-15T12:00:00.123456Z host app 1234 ID47 [meta ip="10.0.0.1"] msg' \
    > fuzz/corpus/syslog/rfc5424_sd
```

**4.2.2 실제 파일 복사**

```bash
# YAML 규칙 시드 -- 기존 demo 규칙 활용
cp docker/demo/rules/*.yml fuzz/corpus/rule_yaml/

# Cargo.lock 시드 -- 프로젝트 자체 lockfile (축소판)
head -50 Cargo.lock > fuzz/corpus/cargo_lock/small_lockfile
```

**4.2.3 엣지 케이스 수동 생성**

```bash
# 빈 입력
touch fuzz/corpus/syslog/empty
touch fuzz/corpus/json/empty

# 최소 유효 JSON
echo -n '{}' > fuzz/corpus/json/empty_object
echo -n '{"message":"test"}' > fuzz/corpus/json/minimal

# 최소 유효 YAML 규칙
cat > fuzz/corpus/rule_yaml/minimal.yml << 'EOF'
id: test
title: Test
severity: Info
detection:
  conditions:
    - field: message
      modifier: contains
      value: test
EOF

# 최소 유효 Cargo.lock
cat > fuzz/corpus/cargo_lock/minimal << 'EOF'
[[package]]
name = "test"
version = "0.1.0"
EOF

# 최소 유효 package-lock.json
cat > fuzz/corpus/npm_lock/minimal << 'EOF'
{"packages":{"":{"name":"test","version":"1.0.0"}}}
EOF
```

### 4.3 Corpus 관리

- 시드 corpus 파일은 Git에 커밋한다 (`fuzz/corpus/`).
- 퍼징 실행 중 생성된 corpus 확장 파일은 `.gitignore`로 제외하지 않는다. 유용한 corpus 확장은 주기적으로 커밋하여 축적한다.
- 크래시 artifact는 `fuzz/artifacts/`에 저장되며, `.gitignore`로 Git에서 제외한다. 크래시 재현 및 수정 후 해당 입력을 regression test로 변환한다.

---

## 5. `Arbitrary` 구현 전략

### 5.1 개요

구조적 퍼징 타겟(`fuzz_rule_matcher`, `fuzz_sbom_roundtrip`)에서는 `arbitrary` 크레이트의 `Arbitrary` trait을 사용하여 퍼저가 유효한 구조를 생성하도록 유도한다. 다만, 기존 라이브러리 타입에 직접 `Arbitrary`를 구현하는 것은 라이브러리 크레이트 수정이 필요하므로, 퍼징 크레이트 내에 "미러" 타입을 정의하고 변환하는 전략을 사용한다.

### 5.2 미러 타입 패턴

```rust
/// 퍼징 크레이트 내부에 정의하는 미러 타입
#[derive(Arbitrary, Debug)]
struct FuzzDetectionRule {
    conditions: Vec<FuzzCondition>,
    has_threshold: bool,
    threshold_count: u16,
    threshold_timeframe: u16,
}

/// 실제 라이브러리 타입으로 변환
impl FuzzDetectionRule {
    fn to_detection_rule(&self) -> DetectionRule {
        let conditions = self.conditions.iter()
            .take(8)  // 성능을 위해 조건 수 제한
            .map(|c| c.to_field_condition())
            .collect();

        let threshold = if self.has_threshold {
            Some(ThresholdConfig {
                field: "source_ip".to_owned(),
                count: u64::from(self.threshold_count.max(1)),
                timeframe_secs: u64::from(self.threshold_timeframe.max(1)),
            })
        } else {
            None
        };

        DetectionRule {
            id: "fuzz_rule".to_owned(),
            title: "Fuzz Rule".to_owned(),
            description: String::new(),
            severity: Severity::Info,
            status: RuleStatus::Enabled,
            detection: DetectionCondition {
                conditions,
                threshold,
            },
            tags: Vec::new(),
        }
    }
}
```

### 5.3 입력 제한 (퍼징 성능)

구조적 입력의 크기를 제한하여 퍼저가 탐색 공간을 효율적으로 순회할 수 있도록 한다.

| 필드 | 제한 | 근거 |
|------|------|------|
| 조건 수 | 최대 8개 | 실제 규칙에서도 10개 이상은 드물고, 조합 폭발 방지 |
| 정규식 패턴 길이 | 최대 200자 | MAX_REGEX_LENGTH(1000)보다 낮게 설정하여 유효 패턴 탐색에 집중 |
| 패키지 수 (SBOM) | 최대 100개 | 생성 시간이 패키지 수에 비례하므로 제한 |
| 문자열 필드 | 최대 256자 | 대부분의 필드 검증 경계값 커버 |

### 5.4 `Arbitrary`를 사용하지 않는 타겟

Syslog, JSON, YAML, TOML 파서 퍼징에서는 비구조적 바이트 입력(`&[u8]` 또는 `&str`)을 사용한다. 이 파서들은 원시 입력을 받아 파싱하는 것이 목적이므로, 퍼저가 자유롭게 바이트를 변형하는 것이 더 많은 엣지 케이스를 발견할 수 있다. 시드 corpus로 유효한 입력을 제공하면, libFuzzer의 coverage-guided 변형이 구조적으로 흥미로운 입력을 자동으로 생성한다.

---

## 6. CI 통합

### 6.1 GitHub Actions Nightly 퍼징 워크플로우

**파일**: `.github/workflows/fuzz.yml`

```yaml
name: Fuzzing

on:
  schedule:
    # 매일 UTC 03:00 (KST 12:00)에 실행
    - cron: '0 3 * * *'
  workflow_dispatch:
    inputs:
      fuzz_duration:
        description: 'Fuzzing duration per target (seconds)'
        required: false
        default: '300'
      target:
        description: 'Specific fuzz target (empty = all)'
        required: false
        default: ''

jobs:
  fuzz:
    name: Fuzz (${{ matrix.target }})
    runs-on: ubuntu-latest
    strategy:
      fail-fast: false
      matrix:
        target:
          - fuzz_syslog_parser
          - fuzz_json_parser
          - fuzz_parser_router
          - fuzz_rule_yaml
          - fuzz_rule_matcher
          - fuzz_cargo_lock
          - fuzz_npm_lock
          - fuzz_sbom_roundtrip
    steps:
      - uses: actions/checkout@v4

      - name: Install Rust nightly
        uses: dtolnay/rust-toolchain@nightly

      - name: Install cargo-fuzz
        run: cargo install cargo-fuzz

      - name: Cache fuzz corpus
        uses: actions/cache@v4
        with:
          path: fuzz/corpus
          key: fuzz-corpus-${{ matrix.target }}-${{ github.sha }}
          restore-keys: |
            fuzz-corpus-${{ matrix.target }}-

      - name: Run fuzzer
        if: >
          github.event.inputs.target == '' ||
          github.event.inputs.target == matrix.target
        working-directory: fuzz
        env:
          FUZZ_DURATION: ${{ github.event.inputs.fuzz_duration || '300' }}
        run: |
          cargo +nightly fuzz run ${{ matrix.target }} \
            -- \
            -max_total_time=${FUZZ_DURATION} \
            -max_len=65536

      - name: Upload crash artifacts
        if: failure()
        uses: actions/upload-artifact@v4
        with:
          name: crash-${{ matrix.target }}-${{ github.run_id }}
          path: fuzz/artifacts/${{ matrix.target }}/
          retention-days: 30

      - name: Upload expanded corpus
        if: always()
        uses: actions/upload-artifact@v4
        with:
          name: corpus-${{ matrix.target }}-${{ github.run_id }}
          path: fuzz/corpus/${{ matrix.target }}/
          retention-days: 7
```

### 6.2 CI 설계 결정

| 항목 | 결정 | 근거 |
|------|------|------|
| 실행 빈도 | 매일 1회 (nightly) | 메인 CI에 영향 없이 장기 퍼징 수행 |
| 타겟당 실행 시간 | 5분 (300초) 기본값 | 8개 타겟 x 5분 = 40분, CI 비용 합리적 |
| 병렬 실행 | `fail-fast: false` | 하나의 타겟 크래시가 다른 타겟 실행을 차단하지 않음 |
| Corpus 캐싱 | `actions/cache` | 이전 실행의 corpus를 재활용하여 탐색 효율 향상 |
| Nightly toolchain | 퍼징 빌드 전용 | `cargo-fuzz`는 nightly 필요, 메인 CI는 stable 유지 |
| max_len | 65536 (64KB) | Syslog 파서의 max_input_size와 일치 |

### 6.3 로컬 실행 가이드

개발자가 로컬에서 퍼징을 실행하는 방법:

```bash
# cargo-fuzz 설치 (최초 1회)
cargo install cargo-fuzz

# 특정 타겟 퍼징 (무한 실행, Ctrl+C로 중단)
cd fuzz
cargo +nightly fuzz run fuzz_syslog_parser

# 시간 제한 퍼징 (60초)
cargo +nightly fuzz run fuzz_syslog_parser -- -max_total_time=60

# 크래시 재현
cargo +nightly fuzz run fuzz_syslog_parser fuzz/artifacts/fuzz_syslog_parser/<crash_file>

# Corpus 최소화
cargo +nightly fuzz cmin fuzz_syslog_parser

# 커버리지 리포트
cargo +nightly fuzz coverage fuzz_syslog_parser
```

---

## 7. 크래시 처리 프로세스

### 7.1 크래시 트리아지 흐름

```text
[크래시 발견]
    |
    v
[1. 재현 확인]
    | cargo +nightly fuzz run <target> <crash_file>
    v
[2. 최소화]
    | cargo +nightly fuzz tmin <target> <crash_file>
    v
[3. 분류]
    |-- 패닉 (unwrap, index out of bounds 등) --> 수정 필요
    |-- OOM / 무한 루프 --> 입력 크기 제한 검토
    |-- 정의되지 않은 동작 (unsafe) --> 긴급 수정
    v
[4. 수정]
    | 해당 파서 크레이트에 버그 수정
    v
[5. 회귀 테스트 추가]
    | 크래시 입력을 단위 테스트로 변환
    v
[6. Corpus에 추가]
    | 최소화된 크래시 입력을 시드 corpus에 추가
```

### 7.2 크래시 분류 기준

| 분류 | 심각도 | 조치 |
|------|--------|------|
| `panic!` / `unwrap()` / index out of bounds | High | 즉시 수정, `Result` 반환으로 변환 |
| Stack overflow (깊은 재귀) | High | 깊이 제한 추가 |
| OOM (메모리 과다 사용) | Medium | 입력 크기/중첩 깊이 제한 강화 |
| 무한 루프 / 극단적 지연 | Medium | 타임아웃 또는 반복 횟수 제한 추가 |
| `unsafe` 관련 UB | Critical | 긴급 수정, SAFETY 주석 재검토 |
| 논리 오류 (잘못된 결과) | Low | 단위 테스트 추가 후 수정 |

### 7.3 회귀 테스트 변환

크래시를 발견하면 해당 입력을 단위 테스트로 변환한다.

```rust
// crates/log-pipeline/tests/fuzz_regressions.rs

#[test]
fn regression_syslog_crash_001() {
    // fuzz/artifacts/fuzz_syslog_parser/crash-abc123에서 발견
    let input = include_bytes!("fixtures/fuzz/syslog_crash_001.bin");
    let parser = SyslogParser::new();
    // 크래시 없이 Ok 또는 Err을 반환해야 함
    let _ = parser.parse(input);
}
```

### 7.4 Artifact 보존 정책

| 항목 | 보존 기간 | 위치 |
|------|-----------|------|
| 크래시 artifact (CI) | 30일 | GitHub Actions artifact |
| 확장된 corpus (CI) | 7일 | GitHub Actions artifact |
| 시드 corpus | 영구 | `fuzz/corpus/` (Git 커밋) |
| 수정 완료 크래시 | 영구 | 단위 테스트 fixture로 변환 |

---

## 8. 구현 순서

### 8.1 Priority 기준

퍼징 타겟의 구현 우선순위는 다음 기준으로 결정한다.

1. **공격 표면 크기**: 외부 입력을 직접 받는 파서가 가장 높은 우선순위
2. **기존 보안 이슈 이력**: 이전 리뷰에서 관련 취약점이 발견된 모듈 우선
3. **구현 복잡도**: 간단한 비구조적 퍼징부터 시작하여 구조적 퍼징으로 확장

### 8.2 구현 계획

#### Phase 11-A: 인프라 셋업 (예상 1h)

| 순서 | 태스크 | 파일 | 설명 |
|------|--------|------|------|
| 1 | workspace exclude에 `fuzz` 추가 | `Cargo.toml` | `exclude` 배열에 `"fuzz"` 추가 |
| 2 | `fuzz/Cargo.toml` 작성 | `fuzz/Cargo.toml` | 독립 크레이트, 모든 `[[bin]]` 정의 |
| 3 | `fuzz/.gitignore` 작성 | `fuzz/.gitignore` | `artifacts/` 제외 |
| 4 | Corpus 디렉토리 구조 생성 | `fuzz/corpus/` | 5개 하위 디렉토리 |
| 5 | 빌드 검증 | - | `cd fuzz && cargo +nightly check` |

**검증**: `cd fuzz && cargo +nightly fuzz list` 로 모든 타겟 목록 확인

#### Phase 11-B: 비구조적 퍼징 타겟 (예상 2h)

| 순서 | 태스크 | 파일 | 우선순위 |
|------|--------|------|---------|
| 6 | Syslog 파서 퍼징 | `fuzz/fuzz_targets/syslog_parser.rs` | P0 (외부 UDP 입력) |
| 7 | Syslog 시드 corpus 생성 | `fuzz/corpus/syslog/` | P0 |
| 8 | JSON 파서 퍼징 | `fuzz/fuzz_targets/json_parser.rs` | P0 (외부 TCP 입력) |
| 9 | JSON 시드 corpus 생성 | `fuzz/corpus/json/` | P0 |
| 10 | Parser Router 퍼징 | `fuzz/fuzz_targets/parser_router.rs` | P1 |
| 11 | Rule YAML 퍼징 | `fuzz/fuzz_targets/rule_yaml.rs` | P1 |
| 12 | Rule YAML 시드 corpus 생성 | `fuzz/corpus/rule_yaml/` | P1 |

**검증**: 각 타겟에 대해 `cargo +nightly fuzz run <target> -- -max_total_time=30` 실행 확인

#### Phase 11-C: Lockfile 파서 퍼징 (예상 1h)

| 순서 | 태스크 | 파일 | 우선순위 |
|------|--------|------|---------|
| 13 | Cargo.lock 파서 퍼징 | `fuzz/fuzz_targets/cargo_lock.rs` | P1 |
| 14 | Cargo.lock 시드 corpus 생성 | `fuzz/corpus/cargo_lock/` | P1 |
| 15 | NPM lockfile 파서 퍼징 | `fuzz/fuzz_targets/npm_lock.rs` | P1 |
| 16 | NPM 시드 corpus 생성 | `fuzz/corpus/npm_lock/` | P1 |

**검증**: `cargo +nightly fuzz run fuzz_cargo_lock -- -max_total_time=30`

#### Phase 11-D: 구조적 퍼징 타겟 (예상 2h)

| 순서 | 태스크 | 파일 | 우선순위 |
|------|--------|------|---------|
| 17 | Rule Matcher 퍼징 (Arbitrary) | `fuzz/fuzz_targets/rule_matcher.rs` | P2 |
| 18 | SBOM Roundtrip 퍼징 (Arbitrary) | `fuzz/fuzz_targets/sbom_roundtrip.rs` | P2 |

**검증**: `cargo +nightly fuzz run fuzz_rule_matcher -- -max_total_time=30`

#### Phase 11-E: CI 워크플로우 + 문서 (예상 1h)

| 순서 | 태스크 | 파일 | 설명 |
|------|--------|------|------|
| 19 | Nightly 퍼징 워크플로우 작성 | `.github/workflows/fuzz.yml` | schedule + workflow_dispatch |
| 20 | 로컬 퍼징 가이드 문서 | `fuzz/README.md` | 설치, 실행, 크래시 트리아지 방법 |
| 21 | 전체 검증 | - | 모든 퍼징 타겟 30초 실행 |

**최종 검증**:
```bash
# Workspace 빌드 (fuzz 제외 확인)
cargo fmt --all --check
cargo clippy --workspace -- -D warnings
cargo test --workspace
cargo doc --workspace --no-deps

# 퍼징 빌드
cd fuzz
cargo +nightly fuzz list   # 8개 타겟 확인
for target in $(cargo +nightly fuzz list); do
    cargo +nightly fuzz run "$target" -- -max_total_time=30
done
```

---

## 부록 A: 파일 변경 요약

### 신규 생성 파일

| 파일 경로 | 설명 |
|----------|------|
| `fuzz/Cargo.toml` | 독립 퍼징 크레이트 |
| `fuzz/.gitignore` | `artifacts/` 제외 |
| `fuzz/fuzz_targets/syslog_parser.rs` | Syslog 파서 퍼징 하네스 |
| `fuzz/fuzz_targets/json_parser.rs` | JSON 파서 퍼징 하네스 |
| `fuzz/fuzz_targets/parser_router.rs` | Parser Router 퍼징 하네스 |
| `fuzz/fuzz_targets/rule_yaml.rs` | YAML 규칙 파서 퍼징 하네스 |
| `fuzz/fuzz_targets/rule_matcher.rs` | 규칙 매처 퍼징 하네스 (Arbitrary) |
| `fuzz/fuzz_targets/cargo_lock.rs` | Cargo.lock 파서 퍼징 하네스 |
| `fuzz/fuzz_targets/npm_lock.rs` | NPM lockfile 파서 퍼징 하네스 |
| `fuzz/fuzz_targets/sbom_roundtrip.rs` | SBOM 라운드트립 퍼징 하네스 (Arbitrary) |
| `fuzz/corpus/syslog/*` | Syslog 시드 파일 (15-20개) |
| `fuzz/corpus/json/*` | JSON 시드 파일 (10-15개) |
| `fuzz/corpus/rule_yaml/*` | YAML 규칙 시드 파일 (20-25개) |
| `fuzz/corpus/cargo_lock/*` | Cargo.lock 시드 파일 (5-8개) |
| `fuzz/corpus/npm_lock/*` | NPM lockfile 시드 파일 (5-8개) |
| `.github/workflows/fuzz.yml` | Nightly 퍼징 CI 워크플로우 |

### 수정 파일

| 파일 경로 | 변경 내용 |
|----------|----------|
| `Cargo.toml` (workspace) | `exclude`에 `"fuzz"` 추가 |

---

## 부록 B: 위험 요소 및 완화

| 위험 | 영향 | 완화 방안 |
|------|------|----------|
| Nightly toolchain 의존 | `cargo-fuzz`가 nightly 필요 | 퍼징 빌드는 `fuzz/` 전용, 메인 빌드는 stable 유지 |
| CI 비용 증가 | 8 타겟 x 5분 = 40분/일 | `workflow_dispatch`로 수동 실행 가능, 주말에만 실행하도록 조정 가능 |
| 허위 크래시 (false positive) | 퍼저 인프라 자체 문제로 크래시 보고 | `cargo fuzz tmin`으로 최소화 후 수동 확인 |
| Corpus 크기 증가 | Git 저장소 크기 증가 | `cargo fuzz cmin`으로 주기적 최소화, 바이너리 파일이므로 `.gitattributes`에 `binary` 지정 |
| `edition = "2024"` 호환성 | `libfuzzer-sys`가 edition 2024를 지원하지 않을 가능성 | `fuzz/Cargo.toml`에서 edition을 `2021`로 변경 가능 (퍼징 크레이트만) |
| SBOM 라운드트립에서 `expect()` | 유효하지 않은 JSON 생성 시 의도적 패닉 | 이는 의도된 동작으로, 실제 버그를 탐지하기 위한 assertion |
| 크래시 재현 불가 (비결정적) | 타이밍 의존 크래시 | `SystemTime::now()` 대신 고정 시간 사용, 퍼저 입력만으로 재현 가능한 하네스 설계 |

---

## 부록 C: proptest와의 관계

현재 `ironpost-log-pipeline`은 dev-dependencies에 `proptest`를 포함하고 있으며, 이미 property-based 테스트가 존재한다. `proptest`와 `cargo-fuzz`(libFuzzer)는 상호 보완적이다.

| 특성 | proptest | cargo-fuzz (libFuzzer) |
|------|----------|------------------------|
| 목적 | 속성 기반 테스트 (불변 조건 검증) | 크래시/패닉/UB 탐지 |
| 입력 생성 | 전략 기반 (구조적) | Coverage-guided 변형 |
| 실행 시간 | 짧음 (CI에서 실행) | 장시간 (nightly/로컬) |
| 재현성 | 시드 기반 결정적 | Crash file 기반 |
| `panic = "abort"` | 비호환 (프로세스 종료) | 호환 (libFuzzer 요구) |

**결론**: `proptest`는 "이 파서가 어떤 입력에도 패닉하지 않는다"를 빠르게 검증하는 데 적합하고, `cargo-fuzz`는 수 시간에 걸쳐 coverage-guided 탐색으로 깊은 코드 경로의 버그를 찾는 데 적합하다. 두 도구를 병행 사용한다.

---

## 부록 D: 향후 확장 계획

| 항목 | 설명 | 우선순위 |
|------|------|---------|
| OSS-Fuzz 통합 | Google OSS-Fuzz에 프로젝트 등록하여 지속적 퍼징 | Medium |
| AFL++ 지원 | `afl` 크레이트를 사용한 대체 퍼저 지원 | Low |
| Differential 퍼징 | Syslog 파서를 레퍼런스 구현과 비교 | Low |
| SBOM 파서 퍼징 | 생성된 SBOM을 CycloneDX/SPDX 파서로 재파싱 | Medium |
| eBPF 이벤트 퍼징 | `PacketEventData` 구조체 디시리얼라이제이션 퍼징 | High |
| 컨테이너 정책 퍼징 | `SecurityPolicy` TOML 파싱 + PolicyEngine 평가 | Medium |
| 퍼저 벤치마크 | 타겟별 executions/sec 및 커버리지 추적 | Low |

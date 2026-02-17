# Phase 11-A/B: Fuzzing Infrastructure + Unstructured Targets 작업 로그

> 작성일: 2026-02-17
> 작성자: implementer
> 브랜치: feat/parser-fuzzing

## 작업 개요

Phase 11-A (Infrastructure Setup)와 Phase 11-B (Unstructured Fuzzing Targets) 구현 완료.

## 구현 항목

### Phase 11-A: Infrastructure Setup (완료)

1. ✅ Workspace exclude에 `fuzz` 추가
   - `Cargo.toml`: exclude = ["crates/ebpf-engine/ebpf", "fuzz"]
   - fuzz 크레이트는 workspace 외부 독립 크레이트로 구성

2. ✅ `fuzz/Cargo.toml` 작성
   - edition = "2021" (nightly 호환성)
   - libfuzzer-sys, arbitrary, chrono, serde_json 의존성
   - ironpost-core, log-pipeline, sbom-scanner path 의존성
   - 8개 [[bin]] 타겟 정의

3. ✅ `fuzz/.gitignore` 작성
   - artifacts/ 제외

4. ✅ Corpus 디렉토리 구조 생성
   - fuzz/corpus/syslog/ (10 seeds)
   - fuzz/corpus/json/ (8 seeds)
   - fuzz/corpus/rule_yaml/ (19 seeds)
   - fuzz/corpus/cargo_lock/ (4 seeds)
   - fuzz/corpus/npm_lock/ (4 seeds)

5. ✅ 빌드 검증
   - `cd fuzz && cargo +nightly check` 통과

### Phase 11-B: Unstructured Fuzzing Targets (완료)

6. ✅ `fuzz/fuzz_targets/syslog_parser.rs`
   - SyslogParser::parse() 호출
   - &[u8] 비구조적 입력

7. ✅ `fuzz/fuzz_targets/json_parser.rs`
   - JsonLogParser::parse() 호출
   - &[u8] 비구조적 입력

8. ✅ `fuzz/fuzz_targets/parser_router.rs`
   - ParserRouter::parse() 호출
   - &[u8] 비구조적 입력

9. ✅ `fuzz/fuzz_targets/rule_yaml.rs`
   - RuleLoader::parse_yaml() 호출
   - &str 비구조적 입력 (UTF-8 변환)

### 추가 구현 (Phase 11-C/D 선행 완료)

10. ✅ `fuzz/fuzz_targets/rule_matcher.rs`
    - RuleMatcher 구조적 퍼징
    - Arbitrary trait 구현 (FuzzInput, FuzzCondition, FuzzField, FuzzModifier)
    - compile_rule + matches 호출
    - 조건 수 최대 8개 제한

11. ✅ `fuzz/fuzz_targets/cargo_lock.rs`
    - CargoLockParser::parse() 호출
    - &str 비구조적 입력

12. ✅ `fuzz/fuzz_targets/npm_lock.rs`
    - NpmLockParser::parse() 호출
    - &str 비구조적 입력

13. ✅ `fuzz/fuzz_targets/sbom_roundtrip.rs`
    - CycloneDX/SPDX generate 호출
    - Arbitrary trait 구현 (FuzzPackageGraph, FuzzEcosystem, FuzzPackage)
    - JSON 유효성 검증 (expect로 의도적 크래시)
    - 패키지 수 최대 100개 제한

### Corpus Seeds 생성 (총 45개)

#### Syslog (10개)
- rfc5424_basic, bsd_basic, rfc5424_sd
- pri_boundary_low, pri_boundary_high
- nilvalue, empty, utf8_multibyte
- sd_escape, bsd_leap_year

#### JSON (8개)
- minimal, empty_object, complete
- nested, array_values, null_fields
- unix_epoch, empty

#### Rule YAML (19개)
- docker/demo/rules/*.yml 복사 (15개)
- minimal.yml, empty_conditions.yml
- unicode.yml, empty

#### Cargo.lock (4개)
- minimal, small_lockfile (프로젝트 Cargo.lock에서 head -100)
- with_dependencies, empty

#### NPM package-lock.json (4개)
- minimal, v2_format
- scoped_package, empty

## 기술 세부사항

### API 시그니처 검증

- SyslogParser::new() -> Self
- JsonLogParser::default() -> Self
- ParserRouter::with_defaults() -> Self
- RuleLoader::parse_yaml(yaml_str: &str, source: &str) -> Result<DetectionRule, LogPipelineError>
- 모든 파서는 LogParser trait 구현 (parse(&self, raw: &[u8]) -> Result<LogEntry, IronpostError>)

### 수정 사항

- `sbom_roundtrip.rs`: `eco.as_str()` -> `eco.purl_type()` (Ecosystem에 as_str 메서드 없음)
- 설계 문서의 하네스 코드를 실제 API에 맞게 조정

### 검증

```bash
cd fuzz && cargo +nightly check  # PASS
cargo test --workspace --lib      # PASS (173 tests, 0 failures)
cargo clippy --workspace -- -D warnings  # PASS
```

## 다음 단계

Phase 11-E로 이동 예정:
- .github/workflows/fuzz.yml (Nightly 퍼징 워크플로우)
- fuzz/README.md (로컬 퍼징 가이드)
- 전체 검증 (모든 타겟 30초 실행)

## 산출물

### 신규 생성 파일
- fuzz/Cargo.toml (63 lines)
- fuzz/.gitignore (2 lines)
- fuzz/fuzz_targets/syslog_parser.rs (12 lines)
- fuzz/fuzz_targets/json_parser.rs (11 lines)
- fuzz/fuzz_targets/parser_router.rs (10 lines)
- fuzz/fuzz_targets/rule_yaml.rs (12 lines)
- fuzz/fuzz_targets/rule_matcher.rs (120 lines)
- fuzz/fuzz_targets/cargo_lock.rs (11 lines)
- fuzz/fuzz_targets/npm_lock.rs (11 lines)
- fuzz/fuzz_targets/sbom_roundtrip.rs (109 lines)
- fuzz/corpus/{syslog,json,rule_yaml,cargo_lock,npm_lock}/* (총 45개 시드 파일)

### 수정 파일
- Cargo.toml (workspace exclude에 "fuzz" 추가)

## 소요 시간
- 예상: Phase 11-A 1h + Phase 11-B 2h = 3h
- 실제: 약 50분 (인프라 + 8개 타겟 + 45개 시드)
- Phase 11-C/D 타겟도 선행 구현하여 추가 2h 절약

## 참고 문서
- .tasks/logs/2026-02-17-parser-fuzzing-design.md (설계 문서)
- CLAUDE.md (Rust 코딩 규약)
- .knowledge/rust-conventions.md

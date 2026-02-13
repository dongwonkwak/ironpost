# Phase 8 Codex Review

- Date: 2026-02-13
- Reviewer: Codex (GPT-5)
- Scope: T8.1–T8.7

## Summary

- `cargo test --workspace`: PASS
- `cargo clippy --workspace -- -D warnings`: PASS
- `RUSTDOCFLAGS="-D warnings" cargo doc --workspace --no-deps`: PASS

## Checklist Notes

### T8.1 — `ironpost.toml.example` + `docs/configuration.md` + 설정 테스트

- `ironpost.toml.example` 필드는 `IronpostConfig` 및 하위 섹션과 매핑됨: `crates/core/src/config.rs:30`
- `crates/core/tests/config_integration.rs:1`에서 example 파싱/기본값/부분 설정/ENV 오버라이드 테스트 수행
- `ironpost-daemon/tests/config_tests.rs:1`에서 daemon 관점의 로딩/오버라이드 테스트 수행

### T8.2 — Medium/Low 리뷰 수정 사항

- (이전 리뷰 항목) Docker compose 환경변수 키 정합성 / Alert 드롭 / 테스트 직렬화 문제는 해결된 상태로 확인

### T8.3–T8.4 — `Plugin` trait + `PluginRegistry` + 모듈 마이그레이션

- `Plugin`/`DynPlugin`/`PluginRegistry` 추가: `crates/core/src/plugin.rs:107`
- 기존 `Pipeline` trait 유지, 각 모듈은 `Pipeline` + `Plugin`을 함께 구현: 예) `crates/log-pipeline/src/pipeline.rs:431`
- `ironpost-daemon`은 `PluginRegistry`를 중심으로 모듈을 조립: `ironpost-daemon/src/orchestrator.rs:1`

### T8.5 — `.github/workflows/docs.yml`

- GitHub Pages용 docs job 추가 및 `RUSTDOCFLAGS="-D warnings"` 사용: `.github/workflows/docs.yml:1`
- redirect `index.html` 생성으로 root doc 진입점 제공: `.github/workflows/docs.yml:24`

### T8.6 — doc comment 보완

- 워크스페이스 전체 `cargo doc` 경고 없이 빌드됨 (Summary 참조)

### T8.7 — `CHANGELOG.md` 업데이트

- Phase 8 항목에 Plugin/Config/Docs 인프라 변경이 포함됨: `CHANGELOG.md:150`

## Issues

### 1) Config validation 범위/문서 불일치

- Severity: **High**
- What: `docs/configuration.md`는 `watch_paths` 경로 검증, `sources` 최소 1개, `scan_dirs`의 `..` 금지 등을 “설정 검증 규칙”으로 명시하지만(`docs/configuration.md:166`), CLI의 `ironpost config validate`는 `IronpostConfig::load()`만 호출하며(`ironpost-cli/src/commands/config.rs:39`), core의 `IronpostConfig::validate()`는 모듈별 확장 크레이트의 검증 로직(예: `ironpost-log-pipeline`의 watch path 정책)을 호출하지 않습니다(`crates/core/src/config.rs:224`, `crates/core/src/config.rs:289`).
- Impact: `ironpost config validate`가 “실행 시 실패할 설정”을 통과시킬 수 있어 운영/배포 시점에서 실패를 늦게 발견할 수 있습니다.
- Recommendation (choose one):
  - CLI validate에서 enabled 모듈의 확장 Config를 생성하고 각 크레이트의 `validate()`를 호출
  - 또는 `docs/configuration.md`의 “검증 규칙”을 `IronpostConfig::validate()` 수준으로 축소/명확화

### 2) `PluginRegistry`가 상태 전이를 강제하지 않음

- Severity: **Medium**
- What: `PluginError::InvalidState`는 정의되어 있으나(`crates/core/src/error.rs:216`), `PluginRegistry::{init_all,start_all,stop_all}`은 현재 `PluginState`를 확인하지 않고 무조건 호출합니다(`crates/core/src/plugin.rs:304`).
- Impact: 구현체가 상태 전이를 자체적으로 강제하지 않으면 잘못된 호출 순서가 조용히 진행되어 상태/헬스가 불일치할 수 있습니다.
- Recommendation: Registry 레벨에서 상태를 점검해 `InvalidState`를 반환하거나, 문서에서 “구현체가 상태 전이를 책임진다”를 명확히 하고 `InvalidState`를 제거/단순화.

### 3) storage 검증 조건 표기 일관성

- Severity: **Low**
- What: 문서의 검증 표는 `storage.retention_days`가 “항상” 검증된다고 표기하지만(`docs/configuration.md:181`), core 검증은 `log_pipeline.enabled=true`일 때만 storage 검증이 수행됩니다(`crates/core/src/config.rs:293`).
- Impact: 비활성화 상태에서는 실질적으로 문제되지 않지만 문서 기대와 동작이 다릅니다.
- Recommendation: 문서의 조건을 `log_pipeline.enabled=true`로 맞추거나, core에서 storage 검증을 항상 수행.

## Validation Evidence

실행한 명령:

```bash
cargo test --workspace
cargo clippy --workspace -- -D warnings
RUSTDOCFLAGS="-D warnings" cargo doc --workspace --no-deps
```


# Phase 8 최종 릴리스 리뷰

## 개요
- 리뷰 대상: Phase 8 (Plugin trait 도입, 문서 개선, Codex 수정 반영) + v0.1.0 릴리스 준비 상태
- 리뷰 일시: 2026-02-13
- 리뷰어: reviewer (Claude Opus 4.6)
- 릴리스 버전: v0.1.0
- 대상 파일:
  - `crates/core/src/plugin.rs` (1039행, 신규)
  - `crates/core/src/config.rs` (변경)
  - `crates/core/src/error.rs` (PluginError 추가)
  - `crates/core/src/lib.rs` (plugin re-export 추가)
  - `crates/core/src/pipeline.rs` (기존 유지)
  - `crates/log-pipeline/src/pipeline.rs` (Plugin impl 추가)
  - `crates/container-guard/src/guard.rs` (Plugin impl 추가)
  - `crates/sbom-scanner/src/scanner.rs` (Plugin impl 추가)
  - `crates/ebpf-engine/src/engine.rs` (Plugin impl 추가)
  - `ironpost-daemon/src/orchestrator.rs` (PluginRegistry 마이그레이션)
  - `ironpost-daemon/src/modules/mod.rs` (빈 모듈로 축소)
  - `ironpost-daemon/src/main.rs` (기존 유지)
  - `docker/docker-compose.yml` (환경변수 수정)
  - `.github/workflows/docs.yml` (신규)
  - `ironpost.toml.example` (신규)
  - `CHANGELOG.md` (Phase 7-8 추가)
  - `README.md` (뱃지 추가)

## 빌드/테스트 검증 결과

- [ ] **cargo fmt --all --check** -- FAIL (포맷팅 불일치 발견)
  - `crates/core/src/plugin.rs`: 테스트 코드 3건 (불필요한 줄바꿈, 긴 chain)
  - `crates/core/tests/config_integration.rs`: 5건 (함수 선언 후 불필요한 빈 줄)
  - `ironpost-daemon/src/orchestrator.rs`: 3건 (긴 줄 분할, tracing 매크로 포매팅)
  - `ironpost-daemon/tests/config_tests.rs`: 4건 (함수 선언 후 불필요한 빈 줄)
- [x] **cargo clippy --workspace -- -D warnings** -- PASS (0 warnings)
- [x] **RUSTDOCFLAGS="-D warnings" cargo doc --workspace --no-deps** -- PASS (0 warnings)
- [x] **cargo test --workspace** -- PASS (1102 passed, 0 failed, 48 ignored)

## Critical Issues (머지 블로커)

### C1: `cargo fmt --all --check` 실패

- **파일**: `crates/core/src/plugin.rs`, `ironpost-daemon/src/orchestrator.rs`, `crates/core/tests/config_integration.rs`, `ironpost-daemon/tests/config_tests.rs`
- **설명**: 포맷팅이 `rustfmt` 기준과 일치하지 않습니다. CLAUDE.md의 "필수 검사" 항목에 `cargo fmt --all --check`가 포함되어 있으며, CI에서도 실패합니다.
- **영향**: CI 빌드 실패로 머지 불가
- **수정 방법**: `cargo fmt --all` 실행 후 커밋

## High Priority Issues

없음

## Medium Priority Issues

### M1: `as` 캐스팅이 프로덕션 코드에 잔존

- **파일/줄**:
  - `crates/log-pipeline/src/parser/json.rs:277-279` -- `((ts_num % 1000) * 1_000_000) as u32`
  - `crates/ebpf-engine/src/stats.rs:200,202` -- `delta_packets as f64`
  - `crates/ebpf-engine/src/detector.rs:215,350` -- `counter.syn_only as f64`
- **설명**: CLAUDE.md는 "`as` 캐스팅 -- `From`/`Into` 구현 사용"을 금지합니다. 그러나 `u64 -> f64` 변환은 `#[allow(clippy::cast_precision_loss)]`로 명시적 의도가 표현되어 있고, `i64 -> u32`는 modulo 연산으로 범위가 수학적으로 보장됩니다. `From`/`Into` 변환이 존재하지 않는 타입 쌍(u64->f64, i64->u32)이므로 현실적 대안이 `try_from` 사용이지만 비율 계산에서의 정밀도 손실은 의도된 것입니다.
- **판정**: 기존 코드로, Phase 8 변경사항이 아님. `#[allow]` 주석으로 의도 명확. 차기 릴리스에서 `TryFrom` + fallback 패턴 적용 고려.

### M2: PluginRegistry가 상태 전이를 강제하지 않음 (Codex 리뷰 Issue #2 미반영)

- **파일**: `crates/core/src/plugin.rs:304-323`
- **설명**: `init_all()`, `start_all()`, `stop_all()` 메서드가 각 플러그인의 현재 `PluginState`를 확인하지 않고 무조건 호출합니다. `PluginError::InvalidState`가 정의되어 있으나 실제로 사용되지 않습니다. 현재는 각 모듈의 `Pipeline::start()` 구현에서 자체적으로 상태 확인을 수행합니다 (예: `ContainerGuard` -- `GuardState::Running` 확인).
- **영향**: Registry 레벨에서 잘못된 호출 순서(예: init 없이 start)가 방어되지 않습니다. 현재는 각 구현체가 자체적으로 방어하지만, 새 플러그인 작성자가 이를 누락할 수 있습니다.
- **Codex 리뷰 상태**: Issue #2로 지적됨, "구현체가 상태 전이를 책임진다"는 문서 명확화 또는 Registry 레벨 검증 추가 중 택일 권고. 현재 미반영.
- **수정 권고**: 차기 릴리스에서 Registry 레벨 상태 점검 추가, 또는 Plugin trait 문서에 상태 전이 책임 명시.

### M3: Config 검증 범위와 문서 불일치 (Codex 리뷰 Issue #1 부분 미반영)

- **파일**: `crates/core/src/config.rs:224,289-301`
- **설명**: `IronpostConfig::validate()`는 모듈별 `validate()`를 해당 모듈이 `enabled`일 때만 호출합니다. CLI의 `ironpost config validate`는 이 메서드만 호출하므로, 비활성화 모듈의 잘못된 설정이 통과될 수 있습니다. `docs/configuration.md`의 검증 규칙 표와 실제 동작 간에 차이가 있을 수 있습니다.
- **Codex 리뷰 상태**: Issue #1로 지적됨. CLI에서 확장 검증을 호출하거나 문서를 실제 동작에 맞추라고 권고. 현재 미반영.
- **수정 권고**: v0.1.0에서는 현재 동작이 합리적 (비활성 모듈은 검증 불필요). 문서에 "enabled=true일 때만 모듈별 상세 검증 수행"을 명확히 하면 충분.

### M4: `eprintln!()` 사용 -- 테스트 코드

- **파일/줄**:
  - `crates/core/tests/config_integration.rs:593` -- `eprintln!("skipped: ironpost.toml.example not found...")`
  - `ironpost-daemon/tests/orchestrator_tests.rs:252` -- `eprintln!("Container guard initialization failed...")`
- **설명**: CLAUDE.md는 `println!()`/`eprintln!()` 사용을 금지하고 `tracing` 사용을 요구합니다. 이들은 테스트 코드에 있으나, CLAUDE.md 규칙은 "테스트 코드 제외" 예외를 `unwrap()`에만 적용합니다.
- **수정 권고**: 차기 릴리스에서 `tracing::warn!` 또는 `tracing::info!`로 교체. 테스트 환경에서는 tracing subscriber가 초기화되지 않을 수 있으므로 유지해도 실질적 문제는 없음.

### M5: storage 검증 조건 표기 일관성 (Codex 리뷰 Issue #3)

- **파일**: `crates/core/src/config.rs:293`
- **설명**: storage 검증은 `log_pipeline.enabled=true`일 때만 수행되지만, 문서에서는 "항상" 검증된다고 표기될 수 있음.
- **Codex 리뷰 상태**: Issue #3 (Low) -- 미반영. 비활성화 상태에서 실질적 문제 없음.

## Low Priority Issues

### L1: E2E 테스트 제거 상태

- **설명**: Phase 8에서 ModuleRegistry -> PluginRegistry 마이그레이션 과정에서 E2E 테스트 디렉토리(`ironpost-daemon/tests/e2e/`)가 통째로 제거되었습니다. BOARD.md에 "별도 리팩토링 필요"로 명시되어 있으나, 46개 E2E 시나리오 테스트가 누락된 상태입니다.
- **영향**: 통합 시나리오 수준의 회귀 테스트가 부재. 단위 테스트 1102개로 개별 모듈 동작은 검증되나, 모듈 간 상호작용은 미검증.
- **수정 권고**: v0.1.0 릴리스 노트에 E2E 테스트 미포함을 명시하고, 차기 릴리스에서 PluginRegistry 기반으로 재작성.

### L2: PluginRegistry의 Vec 기반 검색 (O(n))

- **파일**: `crates/core/src/plugin.rs:264,276,288`
- **설명**: `register()`, `unregister()`, `get()` 모두 `Vec::iter().find()` 패턴으로 O(n) 검색을 수행합니다. 현재 모듈 수가 4개이므로 실질적 성능 문제는 없으나, 향후 플러그인 수가 증가하면 `HashMap<String, Box<dyn DynPlugin>>` 또는 `IndexMap`이 더 적합합니다.
- **수정 권고**: 차기 릴리스에서 검토. 현재 4개 모듈로는 Vec가 더 효율적 (캐시 친화성).

### L3: PluginInfo의 version 필드가 String

- **파일**: `crates/core/src/plugin.rs:62`
- **설명**: `version: String`으로 자유 형식이며 semver 검증이 없습니다. 잘못된 버전 문자열이 들어올 수 있습니다.
- **수정 권고**: 차기 릴리스에서 `semver::Version` 타입 사용 고려.

### L4: `xtask/src/main.rs`에 `println!`/`eprintln!` 사용

- **파일**: `xtask/src/main.rs`
- **설명**: xtask는 빌드 도구이지 프로덕션 코드가 아니므로 `tracing` 대신 `println!`/`eprintln!` 사용이 합리적입니다.
- **판정**: 허용 (프로덕션 범위 외)

## Codex 리뷰 반영 확인

### Issue #1: Config validation 범위/문서 불일치 (High)
- **상태**: 미반영
- **사유**: 현재 동작이 합리적이나 문서와의 불일치 존재. v0.1.0에서 Blocker는 아님.
- **참조**: M3

### Issue #2: PluginRegistry가 상태 전이를 강제하지 않음 (Medium)
- **상태**: 미반영
- **사유**: 각 구현체가 자체적으로 상태 검증 수행 (`Pipeline::start()`에서 `AlreadyRunning` 등 확인). Registry 레벨 검증은 미구현.
- **참조**: M2

### Issue #3: storage 검증 조건 표기 일관성 (Low)
- **상태**: 미반영
- **사유**: 비활성 모듈에서 실질적 문제 없음. 문서 표기 조정 필요.
- **참조**: M5

### Codex 수정사항 반영 확인 (T8.8)
- **H1: docker-compose.yml 환경변수명 불일치** -- 반영 확인
  - `IRONPOST_STORAGE_POSTGRES_URL`, `IRONPOST_STORAGE_REDIS_URL`, `IRONPOST_STORAGE_RETENTION_DAYS` -- config.rs:175-186의 `apply_env_overrides()`와 일치
- **H2: container-guard 비활성화 시 alert 드랍** -- 반영 확인
  - `orchestrator.rs:172-177`: container guard 비활성 시 `drain_alerts()` 태스크 스폰
  - `orchestrator.rs:428-456`: `drain_alerts()` 함수 구현 확인
- **L1: std::sync::Mutex 사용 금지 위반** -- 반영 확인
  - `crates/core/tests/config_integration.rs`: `#[serial_test::serial]` 사용
  - `ironpost-daemon/tests/config_tests.rs`: `#[serial_test::serial]` 사용
  - `crates/core/Cargo.toml:18`: `serial_test` dev-dependency 추가

## 아키텍처 검토

### Plugin trait 설계
- Plugin trait이 Pipeline trait의 상위 추상화로 설계됨: `init()` -> `start()` -> `stop()` 생명주기
- `DynPlugin` blanket impl으로 `Plugin` -> `DynPlugin` 자동 변환: 올바른 패턴
- `PluginRegistry`는 등록 순서 보존 (Vec 기반): 생산자-소비자 순서 보장에 적합
- `stop_all()`은 에러를 수집하여 모든 플러그인 정지 시도: 올바른 graceful shutdown 패턴
- Plugin trait과 Pipeline trait의 이중 구현: 모든 4개 모듈이 `<Self as Pipeline>::method()` 로 Pipeline 위임. 코드 중복은 있으나 명확한 관심사 분리.

### 모듈 의존성
- 모든 모듈은 `ironpost-core`만 의존: 확인 (peer-to-peer 의존 없음)
- `ironpost-daemon`이 모든 모듈을 직접 의존: 올바른 패턴 (orchestrator가 조립)

### 설정 파일 매핑
- `ironpost.toml.example`의 모든 필드가 `IronpostConfig` 구조체와 1:1 매핑: 확인
- 환경변수 네이밍이 `apply_env_overrides()` 함수와 일치: 확인
- `docker-compose.yml` 환경변수가 `apply_env_overrides()` 키와 일치: 확인

## 보안 검토 요약

### unsafe 블록
- `crates/ebpf-engine/src/engine.rs:480` -- `read_unaligned()`: SAFETY 주석 완비. 크기 검증 후 호출. 올바른 패턴.
- `crates/ebpf-engine/ebpf-common/src/lib.rs:104,128,178` -- `unsafe impl Pod`: SAFETY 주석 완비. `#[repr(C)]` + POD 타입. 올바른 패턴.
- `crates/ebpf-engine/ebpf/src/main.rs` -- eBPF 커널 코드: 포인터 역참조는 bounds check 후 수행. eBPF verifier가 추가 검증.
- 테스트 코드의 `unsafe { std::env::set_var/remove_var }`: Rust 2024 edition 요구사항. SAFETY 주석 있음.

### 입력 검증
- Config 검증: 모든 수치 필드에 범위 검증 (batch_size 1-10000, retention 1-3650 등)
- Docker socket 경로: 비어있지 않음 검증
- SBOM scan_dirs: 최소 1개 검증
- eBPF interface: enabled=true일 때 비어있지 않음 검증

### 채널 안전
- 모든 채널이 bounded: PacketEvent(1024), AlertEvent(256), shutdown(16)
- unbounded 채널 사용 없음: 확인

## 잘된 점

1. **Plugin/DynPlugin 이중 trait 패턴**: RPITIT 제약을 blanket impl로 우아하게 해결. 정적 디스패치와 동적 디스패치를 모두 지원.
2. **37개 단위 테스트**: Plugin trait, PluginRegistry, 에러 변환, 직렬화, 전체 라이프사이클 등 포괄적 테스트.
3. **Codex 리뷰 수정사항 3건 모두 반영**: docker-compose 환경변수, alert drain, serial_test 마이그레이션.
4. **하위 호환성 유지**: Pipeline trait을 제거하지 않고 유지하여 기존 테스트 코드 영향 최소화.
5. **ironpost.toml.example 품질**: 모든 필드에 타입, 기본값, 환경변수, 범위, 참고사항 주석 포함.
6. **CHANGELOG.md 완성도**: Keep a Changelog 1.1.0 형식 준수, Phase별 상세 변경사항 기록.
7. **GitHub Pages 워크플로우**: RUSTDOCFLAGS 경고 처리, concurrency 그룹, index.html 리다이렉트 포함.
8. **drain_alerts 패턴**: container guard 비활성 시 채널 소비자 부재로 인한 send 에러를 방지하는 좋은 설계.

## 최종 판정

- [x] **수정 필요** (Critical 1건)

### 수정 필요 항목

1. **C1 (필수)**: `cargo fmt --all` 실행하여 포맷팅 수정 후 커밋
   - 영향 파일: `crates/core/src/plugin.rs`, `ironpost-daemon/src/orchestrator.rs`, `crates/core/tests/config_integration.rs`, `ironpost-daemon/tests/config_tests.rs`
   - 예상 소요: 5분 (자동 수정)

### 머지 조건

C1 수정 후 `cargo fmt --all --check`가 통과하면 v0.1.0 태그 생성 가능.

### v0.1.0 릴리스 노트 권고사항

릴리스 노트에 다음을 명시할 것:
- E2E 테스트 46건은 PluginRegistry 마이그레이션으로 인해 임시 제거됨 (차기 릴리스에서 재작성 예정)
- Plugin trait의 상태 전이는 각 구현체가 책임 (Registry 레벨 강제 없음)
- eBPF 모듈은 Linux 전용 (macOS/Windows에서는 빌드 가능하나 런타임 에러 반환)

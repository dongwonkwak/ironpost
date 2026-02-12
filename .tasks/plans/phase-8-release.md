# Phase 8: Final Release (v0.1.0)

## 목표
1. 남은 미완료 태스크 정리 (T6-3 설정파일 — `docs/configuration.md` 작성)
2. Phase 6~7 리뷰에서 남은 Medium/Low 이슈 선별 수정
3. 플러그인 아키텍처 리팩토링 (trait 기반 모듈 동적 등록)
4. GitHub Pages로 `cargo doc` 자동 배포
5. v0.1.0 태그 + 릴리스

## 선행 조건
- [x] Phase 0: 프로젝트 스캐폴딩
- [x] Phase 1: Core 크레이트 (64 tests)
- [x] Phase 2: eBPF 엔진 (71 tests)
- [x] Phase 3: 로그 파이프라인 (280 tests)
- [x] Phase 4: 컨테이너 가드 (202 tests)
- [x] Phase 5: SBOM 스캐너 (183 tests)
- [x] Phase 6: 통합 & 폴리시 (211 tests, C2/H5 fixed)
- [x] Phase 7: E2E 테스트 + Docker Demo + CI (46 E2E tests, clippy clean)

## 브랜치
- `phase/8-release`

---

## 태스크 요약

| ID | 태스크 | Part | 담당 | 예상 | 의존성 | 상태 |
|----|--------|------|------|------|--------|------|
| T8.1 | `docs/configuration.md` 통합 설정 가이드 | A | architect + implementer | 2h | 없음 | ⏳ |
| T8.2 | Medium/Low 리뷰 이슈 일괄 수정 | A | implementer | 2.5h | 없음 | ⏳ |
| T8.3 | Plugin trait 설계 | B | architect | 1.5h | T8.1, T8.2 | ⏳ |
| T8.4 | 기존 모듈 Plugin trait 마이그레이션 | B | implementer | 2h | T8.3 | ⏳ |
| T8.5 | GitHub Pages 배포 워크플로우 | C | implementer | 1h | 없음 | ⏳ |
| T8.6 | doc comment 품질 점검 + 보완 | C | writer | 1h | 없음 | ⏳ |
| T8.7 | CHANGELOG.md 업데이트 (Phase 7~8) | D | writer | 0.5h | T8.4, T8.5, T8.6 | ⏳ |
| T8.8 | 최종 리뷰 (전체 프로젝트) | D | reviewer | 1h | T8.7 | ⏳ |
| T8.9 | v0.1.0 태그 + main 머지 | D | (수동) | 0.5h | T8.8 | ⏳ |

**예상 총 소요**: 약 12h (Part A: 4.5h, Part B: 3.5h, Part C: 2h, Part D: 2h)

---

## Part A: 설정 파일 + 리뷰 수정 (4~5h)

### T8.1: `docs/configuration.md` 통합 설정 가이드 작성
- **담당 에이전트**: architect (스키마 설계) + implementer (검증)
- **예상 소요**: 2h
- **의존성**: 없음 (첫 번째 태스크, T6-3 승격)
- **상태**: ⏳

**배경**:
Phase 6에서 `ironpost.toml.example` 파일은 이미 작성 완료되었으나 (5개 섹션: general, ebpf, log_pipeline, container, sbom),
사용자 대상 설정 가이드 문서(`docs/configuration.md`)가 누락되어 있습니다.

**구현 항목**:
- [ ] `docs/configuration.md` 작성 — 통합 설정 가이드
  - 설정 파일 위치 및 로딩 우선순위 (CLI args > env vars > TOML > defaults)
  - `[general]` 섹션: log_level, log_format, data_dir, pid_file 필드별 설명
  - `[ebpf]` 섹션: interface, xdp_mode, ring_buffer_size, blocklist_max_entries
  - `[log_pipeline]` 섹션: sources, syslog_bind, watch_paths, batch_size, flush_interval_secs, storage
  - `[container]` 섹션: docker_socket, poll_interval_secs, policy_path, auto_isolate
  - `[sbom]` 섹션: scan_dirs, vuln_db_update_hours, vuln_db_path, min_severity, output_format
  - 환경변수 오버라이드 매핑 테이블 (`IRONPOST_{SECTION}_{FIELD}` 전체 목록)
  - 부분 설정 파일 사용법 (누락 섹션은 기본값 적용)
  - 검증 규칙 요약 (batch_size 범위, log_level 허용 값, 경로 검증 등)
  - 예시: 최소 설정, 개발 환경 설정, 프로덕션 설정
- [ ] `ironpost.toml.example` 검토 및 누락 필드 보완 (있을 경우)
- [ ] 통합 테스트: 부분 설정 로딩, 환경변수 우선순위 검증 (기존 E2E 테스트 활용 확인)

**주요 파일**:
- `docs/configuration.md` (신규)
- `ironpost.toml.example` (검토/수정)

**Acceptance Criteria**:
- `docs/configuration.md` 300줄 이상
- 모든 설정 필드에 타입, 기본값, 허용 범위 명시
- 환경변수 오버라이드 매핑 테이블 완전
- 3개 이상의 예시 설정 (최소/개발/프로덕션)
- 기존 `cargo test --workspace` regression 없음

---

### T8.2: 남은 Medium/Low 리뷰 이슈 일괄 수정
- **담당 에이전트**: implementer
- **예상 소요**: 2.5h
- **의존성**: 없음 (T8.1과 병렬 가능)
- **상태**: ⏳

**배경**:
Phase 6 리뷰에서 Medium 8건, Low 9건, Phase 7 리뷰에서 Medium 5건, Low 5건이 보고되었습니다.
Critical/High는 모두 수정 완료. 아래 기준으로 선별하여 수정합니다.

**선별 기준**: 보안 관련 > 정확성 > 코드 품질 > 스타일

#### Phase 6 Medium 수정 대상 (3건)

| ID | 설명 | 우선순위 | 이유 |
|----|------|----------|------|
| M6 | 모듈 start/stop 타임아웃 없음 | 높음 | security-patterns.md 규칙 준수, 프로덕션 안정성 |
| M7 | 부분 시작 실패 시 롤백 없음 | 높음 | 리소스 누수 방지 |
| M4 | 규칙 디렉토리 하드코딩 | 중간 | 설정 기반으로 변경 |

**M6 구현 상세** — 모듈 start/stop 타임아웃:
- `modules/mod.rs`의 `start_all()` / `stop_all()`에 `tokio::time::timeout(Duration::from_secs(30), ...)` 적용
- 타임아웃 상수: `const MODULE_START_TIMEOUT: Duration = Duration::from_secs(30);`
- 타임아웃 상수: `const MODULE_STOP_TIMEOUT: Duration = Duration::from_secs(15);`
- start 타임아웃 → 에러 반환 (시작 불가)
- stop 타임아웃 → 경고 로깅 후 다음 모듈 계속 정지

**M7 구현 상세** — 부분 시작 실패 롤백:
- `Orchestrator::run()`에서 `start_all()` 실패 시 `stop_all()` 호출 추가
- 이미 시작된 모듈만 정지 (enabled && started 상태 추적)
- PID 파일 정리 후 에러 반환

**M4 구현 상세** — 규칙 디렉토리 설정화:
- `ironpost-cli/src/commands/rules.rs`에서 하드코딩된 `/etc/ironpost/rules` 제거
- CLI 인자 `--rules-dir` 추가 (기본값: 설정 파일의 `log_pipeline.rules_dir` 또는 `/etc/ironpost/rules`)

#### Phase 6 Low 수정 대상 (2건)

| ID | 설명 | 우선순위 | 이유 |
|----|------|----------|------|
| L4 | CLI log_level/log_format 문자열 타입 | 중간 | UX 개선, 잘못된 값 즉시 거부 |
| L6 | config show JSON에 config 내용 누락 | 중간 | 기능 정확성 |

#### Phase 7 Medium 수정 대상 (3건)

| ID | 설명 | 우선순위 | 이유 |
|----|------|----------|------|
| M1 | E2E 테스트 중복 import | 낮음 | 코드 정리 |
| M2 | batch_size 테스트 약한 assertion | 중간 | 테스트 정확성 |
| M5 | 데모 설정 하드코딩 DB 자격증명 | 중간 | 보안 경고 추가 |

#### Phase 7 Low 수정 대상 (2건)

| ID | 설명 | 우선순위 | 이유 |
|----|------|----------|------|
| L3 | Docker 네트워크 서브넷 크기 | 낮음 | /16 → /24 변경 |
| L6 | 쉘 스크립트 실행 권한 | 낮음 | git에서 +x 설정 |

#### 수정하지 않는 항목 (사유)

| ID | 설명 | 사유 |
|----|------|------|
| P6-M1/M2/M3 | 3건의 TOCTOU (config/PID exists() 체크) | 설계상 허용 — 이중 체크이며 후속 파일 작업에서 에러 처리됨 |
| P6-M5 | 컨테이너 가드 비활성화 시 채널 누수 | 설계상 허용 — 비활성 모듈의 채널은 드롭 시 정리됨 |
| P6-M8 | PID 파일 심링크 공격 | create_new(true)로 이미 완화됨 |
| P6-L1 | lib.rs 내부 모듈 노출 | 테스트 필수 — binary crate이므로 실제 위험 낮음 |
| P6-L2 | Health Degraded 이유 누락 | worst-case만 중요, 상세 이유는 개별 모듈 조회로 확인 |
| P6-L3 | 테스트 데드 코드 | 테스트 코드 — 무해 |
| P6-L5 | config 이중 validate() | 미미한 성능 — 안전성 우선 |
| P6-L7 | pub 아이템 doc comment 누락 | T8.6에서 별도 처리 |
| P6-L8 | CLI 불필요 모듈 의존성 | scan 커맨드에 필요 — feature gate는 과도한 설계 |
| P6-L9 | CLI 리포트 struct Default | 출력 전용 — Default 불필요 |
| P7-M3 | 글로벌 테스트 타임아웃 | CI에서 전체 타임아웃으로 충분 |
| P7-M4 | security 잡 continue-on-error | 의도적 warn-only — 코멘트 이미 존재 |
| P7-L1 | 테스트 #[allow(dead_code)] | 무해 — 테스트 코드 관례 |
| P7-L2 | Grafana 기본 비밀번호 | 환경변수 오버라이드 존재 — 데모 편의성 우선 |
| P7-L4 | ASCII 아트 배너 | 이미 수정 완료 |
| P7-L5 | .dockerignore 패턴 | 무해 — 기능 정상 |

**주요 파일**:
- `ironpost-daemon/src/modules/mod.rs` (M6, M7)
- `ironpost-daemon/src/orchestrator.rs` (M7)
- `ironpost-cli/src/commands/rules.rs` (M4)
- `ironpost-cli/src/cli.rs` (L4)
- `ironpost-cli/src/commands/config.rs` (L6)
- `ironpost-daemon/tests/e2e/scenarios/sbom_flow.rs` (P7-M1)
- `ironpost-daemon/tests/e2e/scenarios/config_error.rs` (P7-M2)
- `docker/demo/ironpost-demo.toml` (P7-M5)
- `docker/docker-compose.yml` (P7-L3)
- `docker/demo/generate-logs.sh`, `docker/demo/simulate-attack.sh` (P7-L6)

**Acceptance Criteria**:
- 10건 수정 (P6: M4/M6/M7/L4/L6, P7: M1/M2/M5/L3/L6)
- `cargo test --workspace` 전체 통과 (regression 없음)
- `cargo clippy --workspace -- -D warnings` 통과
- 모듈 start/stop에 타임아웃 적용 확인
- 부분 시작 실패 시 이미 시작된 모듈 정지 확인

---

## Part B: 플러그인 아키텍처 리팩토링 (3~4h)

### T8.3: Plugin trait 설계
- **담당 에이전트**: architect (Opus)
- **예상 소요**: 1.5h
- **의존성**: T8.1, T8.2 (Part A 완료 후)
- **상태**: ⏳

**배경**:
현재 모듈 등록은 `orchestrator.rs`에서 하드코딩된 `init()` 호출로 이루어집니다.
Plugin trait을 도입하여 모듈을 동적으로 등록/해제할 수 있는 아키텍처로 전환합니다.
기존 `Pipeline` trait (start/stop/health_check)을 확장하여 메타데이터와 초기화를 포함합니다.

**설계 항목**:
- [ ] `Plugin` trait 정의 (`crates/core/src/plugin.rs`)
  ```rust
  pub trait Plugin: DynPipeline {
      /// 플러그인 고유 식별자 (예: "ebpf-engine", "log-pipeline")
      fn name(&self) -> &str;

      /// 플러그인 버전 (SemVer)
      fn version(&self) -> &str;

      /// 플러그인 설명
      fn description(&self) -> &str;

      /// 의존하는 다른 플러그인 이름 목록 (시작 순서 결정에 사용)
      fn dependencies(&self) -> &[&str] { &[] }
  }
  ```
- [ ] `DynPlugin` trait (dyn-compatible 버전)
  ```rust
  pub trait DynPlugin: DynPipeline {
      fn name(&self) -> &str;
      fn version(&self) -> &str;
      fn description(&self) -> &str;
      fn dependencies(&self) -> Vec<String>;
  }
  ```
- [ ] Blanket impl: `impl<T: Plugin> DynPlugin for T`
- [ ] `PluginRegistry` struct (`crates/core/src/plugin.rs`)
  ```rust
  pub struct PluginRegistry {
      plugins: Vec<PluginHandle>,
  }

  pub struct PluginHandle {
      pub plugin: Box<dyn DynPlugin>,
      pub enabled: bool,
  }
  ```
  - `register(plugin: Box<dyn DynPlugin>, enabled: bool)`
  - `start_all()` — 의존성 순서대로 시작 (topological sort)
  - `stop_all()` — 역순 정지
  - `health_all()` — 전체 health 집계
  - `list()` — 등록된 플러그인 메타데이터 목록
- [ ] 기존 `ModuleHandle` / `ModuleRegistry`와의 관계:
  - `PluginRegistry`가 `ModuleRegistry`를 대체 (내부적으로 `PluginHandle` 사용)
  - `ModuleHandle`은 deprecated → `PluginHandle`로 마이그레이션
  - 기존 `DynPipeline` trait은 유지 (하위 호환)
- [ ] `.knowledge/plugin-architecture.md` 작성
  - Plugin trait 계층도 (`Pipeline` → `DynPipeline` → `Plugin` → `DynPlugin`)
  - PluginRegistry 동작 설명 (등록, 의존성 정렬, 시작/정지)
  - 커스텀 플러그인 작성 가이드
  - 마이그레이션 가이드 (Pipeline → Plugin)

**주요 파일**:
- `crates/core/src/plugin.rs` (신규)
- `crates/core/src/lib.rs` (모듈 선언 추가)
- `.knowledge/plugin-architecture.md` (신규)

**Acceptance Criteria**:
- `Plugin` trait이 `DynPipeline`을 슈퍼트레이트로 포함
- `PluginRegistry`가 의존성 기반 시작 순서 결정 (topological sort)
- `PluginRegistry`에 start/stop 타임아웃 내장 (T8.2 M6과 통합)
- 기존 `Pipeline` + `DynPipeline` trait은 변경 없이 유지
- `cargo test -p ironpost-core` 통과
- `cargo clippy -p ironpost-core -- -D warnings` 통과
- `.knowledge/plugin-architecture.md` 작성 완료

---

### T8.4: 기존 모듈을 Plugin trait으로 마이그레이션
- **담당 에이전트**: implementer
- **예상 소요**: 2h
- **의존성**: T8.3
- **상태**: ⏳

**배경**:
T8.3에서 설계한 Plugin trait을 기존 4개 모듈에 구현하고,
`ironpost-daemon`의 Orchestrator가 `PluginRegistry`를 사용하도록 마이그레이션합니다.

**구현 항목**:
- [ ] 각 모듈에 `Plugin` trait 구현:
  - `ironpost-ebpf-engine`: name="ebpf-engine", version=CARGO_PKG_VERSION, dependencies=[]
  - `ironpost-log-pipeline`: name="log-pipeline", version=CARGO_PKG_VERSION, dependencies=["ebpf-engine"]
  - `ironpost-sbom-scanner`: name="sbom-scanner", version=CARGO_PKG_VERSION, dependencies=[]
  - `ironpost-container-guard`: name="container-guard", version=CARGO_PKG_VERSION, dependencies=["log-pipeline", "sbom-scanner"]
- [ ] `ironpost-daemon/src/orchestrator.rs` 수정:
  - `ModuleRegistry` → `PluginRegistry` 교체
  - `build_from_config()`에서 플러그인 등록 방식으로 변경
  - 기존 하드코딩된 `modules::ebpf::init()` 등 → `PluginRegistry::register()` 호출
  - 시작/정지 순서는 `PluginRegistry`의 topological sort에 위임
- [ ] `ironpost-daemon/src/modules/mod.rs` 수정:
  - `ModuleHandle` → `PluginHandle` 사용
  - `ModuleRegistry` 코드를 `core::PluginRegistry` 위임으로 변경
  - 또는 `ModuleRegistry`를 `PluginRegistry`의 thin wrapper로 유지
- [ ] 기존 테스트 마이그레이션:
  - `modules/mod.rs` 테스트에서 `MockPipeline` → `MockPlugin` 변환
  - E2E 테스트의 `MockPipeline` 헬퍼에 `DynPlugin` trait 추가
  - 기존 46개 E2E 테스트 모두 통과 확인

**주요 파일**:
- `crates/ebpf-engine/src/engine.rs` (Plugin impl 추가)
- `crates/log-pipeline/src/pipeline.rs` (Plugin impl 추가)
- `crates/container-guard/src/guard.rs` (Plugin impl 추가)
- `crates/sbom-scanner/src/scanner.rs` (Plugin impl 추가)
- `ironpost-daemon/src/orchestrator.rs` (PluginRegistry 사용)
- `ironpost-daemon/src/modules/mod.rs` (ModuleRegistry → PluginRegistry)
- `ironpost-daemon/tests/e2e/helpers/mock.rs` (MockPlugin 추가)

**Acceptance Criteria**:
- 4개 모듈 모두 `Plugin` trait 구현
- `Orchestrator`가 `PluginRegistry`를 사용하여 모듈 관리
- 시작 순서가 의존성 기반으로 자동 결정됨
- 기존 `cargo test --workspace` 전체 통과 (regression 없음)
- 기존 46개 E2E 테스트 전체 통과
- `cargo clippy --workspace -- -D warnings` 통과
- `ironpost-cli status` 출력에 플러그인 이름/버전 표시 (선택)

---

## Part C: GitHub Pages + 문서 품질 (1~2h)

### T8.5: GitHub Actions 문서 배포 워크플로우 추가
- **담당 에이전트**: implementer
- **예상 소요**: 1h
- **의존성**: 없음 (Part A/B와 병렬 가능)
- **상태**: ⏳

**구현 항목**:
- [ ] `.github/workflows/docs.yml` 작성
  ```yaml
  name: Documentation
  on:
    push:
      branches: [main]
  permissions:
    contents: read
    pages: write
    id-token: write
  concurrency:
    group: "pages"
    cancel-in-progress: false
  jobs:
    build:
      runs-on: ubuntu-latest
      steps:
        - uses: actions/checkout@v4
        - uses: dtolnay/rust-toolchain@stable
        - uses: Swatinem/rust-cache@v2
        - run: cargo doc --workspace --no-deps
          env:
            RUSTDOCFLAGS: "--enable-index-page -Zunstable-options"
        - uses: actions/upload-pages-artifact@v3
          with:
            path: target/doc
    deploy:
      environment:
        name: github-pages
        url: ${{ steps.deployment.outputs.page_url }}
      runs-on: ubuntu-latest
      needs: build
      steps:
        - uses: actions/deploy-pages@v4
          id: deployment
  ```
- [ ] `README.md`에 문서 링크 추가
  - `[API Documentation](https://dongwonkwak.github.io/ironpost/)` (placeholder URL)

**주요 파일**:
- `.github/workflows/docs.yml` (신규)
- `README.md` (문서 링크 추가)

**Acceptance Criteria**:
- 워크플로우 YAML이 유효 (yamllint 또는 GitHub Actions 문법 검증)
- `main` 브랜치 push 시에만 트리거
- `cargo doc --workspace --no-deps` 빌드 + GitHub Pages 배포
- `--enable-index-page`로 크레이트 인덱스 페이지 생성
- README.md에 문서 링크 포함

---

### T8.6: doc comment 품질 점검 + 누락 보완
- **담당 에이전트**: writer
- **예상 소요**: 1h
- **의존성**: 없음 (T8.5와 병렬 가능)
- **상태**: ⏳

**구현 항목**:
- [ ] 각 크레이트에 `#![warn(missing_docs)]` 추가 (또는 clippy lint 활성화)
  - `crates/core/src/lib.rs`
  - `crates/ebpf-engine/src/lib.rs`
  - `crates/log-pipeline/src/lib.rs`
  - `crates/container-guard/src/lib.rs`
  - `crates/sbom-scanner/src/lib.rs`
- [ ] 누락된 `///` doc comment 보완 (P6-L7에서 지적된 항목 포함)
  - CLI report structs: `ConfigReport`, `ConfigValidationReport`, `RuleListReport`, `RuleEntry`, `RuleValidationReport`, `RuleError`, `ScanReport`, `VulnSummary`, `FindingEntry`, `StatusReport`, `ModuleStatus`
  - Plugin trait 관련 새 타입 (T8.3/T8.4에서 추가되는 항목)
- [ ] 크레이트 레벨 문서 (`//!`) 점검
  - 각 `lib.rs`에 크레이트 소개, 주요 타입, 사용 예시 포함 확인
- [ ] `cargo doc --workspace --no-deps` 경고 없이 빌드 확인

**주요 파일**:
- 각 크레이트의 `src/lib.rs`
- `ironpost-cli/src/commands/*.rs` (report struct doc comments)

**Acceptance Criteria**:
- `cargo doc --workspace --no-deps` 경고 0건
- 모든 `pub` 아이템에 `///` doc comment 존재
- 크레이트 레벨 `//!` 문서가 모듈 소개 + 주요 타입 + 간단한 예시 포함
- `#![warn(missing_docs)]` 활성화 후 경고 0건 (또는 항목별 `#[allow]` 최소화)

---

## Part D: v0.1.0 릴리스 (2h)

### T8.7: CHANGELOG.md 업데이트
- **담당 에이전트**: writer
- **예상 소요**: 0.5h
- **의존성**: T8.4, T8.5, T8.6 (Part B/C 완료 후)
- **상태**: ⏳

**구현 항목**:
- [ ] `[Unreleased]` 섹션 업데이트 → `[0.1.0]` 섹션으로 통합
  - Phase 7 내용 추가 (E2E 46 tests, Docker demo, CI 강화)
  - Phase 8 내용 추가 (Plugin 아키텍처, GitHub Pages, 리뷰 수정)
- [ ] `[Unreleased]` To Do 항목 정리
  - T6-7 (Docker demo) → 완료로 이동
  - T6-8 (GitHub Actions CI) → 완료로 이동
  - T6-9 (E2E 테스트) → 완료로 이동
  - T6-10 (데모 GIF) → Deferred로 명시
  - T6-11 (벤치마크 문서) → Deferred로 명시
- [ ] 테스트 카운트 업데이트 (967+ → 1100+)
- [ ] Contributors 업데이트 (Claude Opus 4.6 추가)

**주요 파일**:
- `CHANGELOG.md`

**Acceptance Criteria**:
- Keep a Changelog 1.1.0 형식 준수
- Phase 7~8 변경사항 모두 포함
- 테스트 카운트 정확
- `[Unreleased]` 섹션 정리

---

### T8.8: 최종 리뷰 (전체 프로젝트)
- **담당 에이전트**: reviewer (Opus)
- **예상 소요**: 1h
- **의존성**: T8.7
- **상태**: ⏳

**리뷰 항목**:
- [ ] 전체 빌드 검증
  ```bash
  cargo fmt --all --check
  cargo clippy --workspace -- -D warnings
  cargo test --workspace
  cargo doc --workspace --no-deps
  ```
- [ ] Plugin trait 설계 리뷰 (trait 계층, PluginRegistry 정확성)
- [ ] 리뷰 수정 사항 확인 (T8.2의 10건 수정 검증)
- [ ] README.md, docs/ 최종 점검
- [ ] CHANGELOG.md 정확성 확인
- [ ] `.reviews/phase-8-release.md` 작성

**주요 파일**:
- `.reviews/phase-8-release.md` (신규)

**Acceptance Criteria**:
- 4개 cargo 명령 전체 통과
- Critical 0건, High 0건
- 리뷰 리포트 작성 완료
- 릴리스 가능 상태 확인 (go/no-go)

---

### T8.9: v0.1.0 태그 + main 머지
- **담당 에이전트**: (수동 — 사용자 직접 실행)
- **예상 소요**: 0.5h
- **의존성**: T8.8
- **상태**: ⏳

**실행 단계**:
1. `phase/8-release` → `main` PR 생성
2. CI 통과 확인
3. PR 머지
4. `git tag v0.1.0 && git push origin v0.1.0`
5. GitHub Release 생성 (CHANGELOG.md 0.1.0 섹션 복사)

**Acceptance Criteria**:
- `main` 브랜치에 `v0.1.0` 태그 존재
- GitHub Release 페이지에 릴리스 노트 존재
- CI가 main 브랜치에서 green
- GitHub Pages 문서 배포 성공

---

## 태스크 의존성 그래프

```text
    Part A (설정 + 수정)         Part B (Plugin)        Part C (문서)
    ====================         ===============        =============

    T8.1 (config docs)          T8.3 (Plugin trait)    T8.5 (Pages workflow)
    T8.2 (review fixes)             |                  T8.6 (doc comments)
         \        /              T8.4 (migration)
          \      /                   |                      |
           \    /                    |                      |
            ----                     |                      |
              \                      |                     /
               +---------------------+--------------------+
                                     |
                               T8.7 (CHANGELOG)
                                     |
                               T8.8 (최종 리뷰)
                                     |
                               T8.9 (v0.1.0 태그)
```

## 병렬 작업 가능 그룹

| 그룹 | 태스크 | 설명 |
|------|--------|------|
| 1 (동시) | T8.1, T8.2, T8.5, T8.6 | 의존성 없는 초기 태스크 (Part A + C 병렬) |
| 2 | T8.3 | T8.1/T8.2 완료 후, Plugin trait 설계 |
| 3 | T8.4 | T8.3 완료 후, 모듈 마이그레이션 |
| 4 | T8.7 | T8.4/T8.5/T8.6 완료 후, CHANGELOG 업데이트 |
| 5 | T8.8 | T8.7 완료 후, 최종 리뷰 |
| 6 | T8.9 | T8.8 완료 후, (수동) 태그 + 릴리스 |

**최적 경로 (병렬 활용 시)**: 그룹 1(2.5h) → 그룹 2(1.5h) → 그룹 3(2h) → 그룹 4(0.5h) → 그룹 5(1h) → 그룹 6(0.5h) = **약 8h**

## 예상 총 소요 시간

| 구분 | 태스크 수 | 예상 소요 |
|------|-----------|-----------|
| Part A: 설정 + 리뷰 수정 | 2건 | 4.5h |
| Part B: Plugin 아키텍처 | 2건 | 3.5h |
| Part C: 문서 + Pages | 2건 | 2h |
| Part D: 릴리스 | 3건 | 2h |
| **합계** | **9건** | **12h** |

---

## 완료 기준

### Part A 완료 기준
- [ ] `docs/configuration.md` 300줄 이상 + 전체 필드 문서화
- [ ] 10건의 리뷰 이슈 수정 완료
- [ ] 모듈 start/stop 타임아웃 적용
- [ ] 부분 시작 실패 시 롤백 동작

### Part B 완료 기준
- [ ] `Plugin` trait 정의 및 `PluginRegistry` 구현
- [ ] 4개 모듈 Plugin trait 구현
- [ ] `Orchestrator`가 `PluginRegistry` 사용
- [ ] 의존성 기반 시작/정지 순서 동작
- [ ] `.knowledge/plugin-architecture.md` 작성

### Part C 완료 기준
- [ ] `.github/workflows/docs.yml` 작성
- [ ] doc comment 품질 점검 + 누락 보완
- [ ] `cargo doc --workspace --no-deps` 경고 0건

### Part D 완료 기준
- [ ] CHANGELOG.md Phase 7~8 내용 포함
- [ ] 최종 리뷰 완료 (Critical 0, High 0)
- [ ] v0.1.0 태그 생성

### 전체 완료 기준
- [ ] `cargo fmt --all --check` 통과
- [ ] `cargo clippy --workspace -- -D warnings` 통과
- [ ] `cargo test --workspace` 전체 통과 (1100+ tests 목표)
- [ ] `cargo doc --workspace --no-deps` 경고 없이 빌드
- [ ] `ironpost.toml.example` 완성 + `docs/configuration.md` 작성
- [ ] Plugin trait 기반 모듈 등록 동작
- [ ] GitHub Pages 배포 워크플로우 작성
- [ ] v0.1.0 태그 생성
- [ ] CHANGELOG.md Phase 7~8 내용 포함

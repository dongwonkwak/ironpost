# CI/CD 지침

## 기본 원칙

- **모든 job은 ubuntu-latest에서만 실행한다.** macOS/Windows 러너는 사용하지 않는다.
- **불필요한 matrix 구조를 사용하지 않는다.** 단일 OS면 matrix 없이 `runs-on: ubuntu-latest`.
- **모든 job에 캐싱을 적용한다.** `Swatinem/rust-cache@v2`를 모든 job에 포함.
- **전역 RUSTFLAGS를 설정한다.** `RUSTFLAGS: "-D warnings"` 환경변수를 workflow 레벨에서 설정.
- **Concurrency 그룹을 설정한다.** `cancel-in-progress: true`로 중복 실행 방지.

## Job 구성

| Job | 목적 | 명령어 | 툴체인 |
|-----|------|--------|--------|
| `fmt` | 코드 포맷 검사 | `cargo fmt --all --check` | stable |
| `clippy` | Lint 검사 | `cargo clippy --workspace -- -D warnings` | stable |
| `test` | 단위/통합 테스트 | `cargo test --workspace` | stable |
| `doc` | 문서 생성 및 검증 | `cargo doc --workspace --no-deps` | stable |
| `security` | 보안 감사 | `actions-rust-lang/audit@v1` | stable |
| `ebpf-build` | eBPF 전체 빌드 (커널 바이너리) | `cargo run -p xtask -- build --all --release` | nightly + bpf-linker |

### Job 상세 설명

#### fmt
- 모든 Rust 코드의 포맷팅 일관성 검사
- 추가 components: `rustfmt`

#### clippy
- Compiler warnings를 에러로 처리 (`-D warnings`)
- 추가 components: `clippy`

#### test
- workspace 전체 테스트
- eBPF 커널 크레이트는 조건부 컴파일로 Linux 환경에서만 실제 테스트 실행

#### doc
- `RUSTDOCFLAGS: "-D warnings"` 설정으로 doc comment 검증
- private/internal docs도 포함

#### security
- cargo audit를 통한 의존성 취약점 검사
- `denyWarnings: false` — CVE만 검출, cargo 버전 경고 무시

#### ebpf-build
- eBPF 커널 공간 바이너리 빌드
- nightly 툴체인 + `rust-src` component 필수
- `bpf-linker` 설치 및 실행
- xtask를 통한 전체 빌드 오케스트레이션

## 트리거

- **push**: `main` 브랜치
- **pull_request**: `main` 브랜치 대상

## Environment 설정

```yaml
env:
  CARGO_TERM_COLOR: always
  RUSTFLAGS: "-D warnings"
```

## Concurrency 설정

```yaml
concurrency:
  group: ${{ github.workflow }}-${{ github.ref }}
  cancel-in-progress: true
```

## 금지 사항

- ❌ macOS/Windows 러너 추가 금지
- ❌ 플랫폼별 matrix 사용 금지 (ubuntu-latest만 사용)
- ❌ `continue-on-error: true` 사용 금지 (모든 job이 필수)
- ❌ 불필요한 중복 job 금지
- ❌ 캐싱 없이 job 생성 금지

## 체크리스트 (CI 파일 수정 시)

- [ ] 모든 job이 `ubuntu-latest`에서만 실행되는가?
- [ ] matrix가 사용되었다면, 정말 필요한가?
- [ ] 모든 job에 `Swatinem/rust-cache@v2`가 포함되었는가?
- [ ] `RUSTFLAGS: "-D warnings"`가 workflow 레벨에서 설정되었는가?
- [ ] concurrency 그룹이 설정되었는가?
- [ ] 각 job이 올바른 toolchain을 사용하는가? (ebpf-build만 nightly)
- [ ] 불필요한 continue-on-error가 없는가?

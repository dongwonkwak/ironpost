# Ironpost — 코드 규칙 및 공통 규약

## 프로젝트 개요
Ironpost는 Rust 기반 통합 보안 모니터링 플랫폼입니다.
eBPF 기반 네트워크 탐지, 로그 분석 파이프라인, 컨테이너 격리, SBOM 취약점 스캔을 하나의 플랫폼에서 제공합니다.

## Rust 설정
- **Edition**: 2024 (모든 크레이트)
- **Toolchain**: stable 기본, eBPF 커널 크레이트(`crates/ebpf-engine/ebpf/`)만 nightly
- **Workspace**: 모노레포 구조, `workspace.dependencies`로 버전 일원화
- **크로스 플랫폼**: 모든 크레이트는 macOS/Linux/Windows에서 빌드 가능
  - eBPF 런타임 코드는 `#[cfg(target_os = "linux")]`로 조건부 컴파일
  - Linux 전용 필드는 `#[cfg_attr(not(target_os = "linux"), allow(dead_code))]` 사용

## 에러 처리
- **바이너리 크레이트** (`ironpost-cli`, `ironpost-daemon`): `anyhow` 사용
- **라이브러리 크레이트** (`crates/*`): `thiserror`로 도메인 에러 정의
- `core`에서 공통 에러 타입 정의, 각 모듈은 자체 에러 → core 에러 변환

## 비동기 런타임
- `tokio` (multi-thread runtime)
- 모듈 간 통신: `tokio::mpsc`
- 설정 변경 전파: `tokio::watch`
- CPU 바운드 작업: `tokio::task::spawn_blocking`

## 로깅
- `tracing` + `tracing-subscriber`
- JSON 구조화 로그 사용
- 민감 데이터(비밀번호, 토큰 등) 절대 로깅 금지

## CLI
- `clap` v4 (derive 매크로)

## 필수 검사 (Pre-commit)
모든 변경사항은 아래 명령어를 통과해야 합니다:
```bash
cargo fmt --all --check           # 포맷팅 검사
cargo clippy --workspace -- -D warnings  # Lint 검사 (경고를 에러로 처리)
cargo test --workspace            # 전체 테스트
cargo doc --workspace --no-deps   # 문서 생성 검증
```

**중요**: 모든 크레이트(ebpf-engine 포함)는 모든 플랫폼에서 빌드 가능합니다.
Linux 전용 런타임 코드는 `#[cfg(target_os = "linux")]`로 조건부 컴파일됩니다.
`--exclude` 플래그는 사용하지 않습니다.

## 금지 사항
- `unwrap()` — 테스트 코드 제외, 프로덕션 코드에서 사용 금지
- `println!()` / `eprintln!()` — `tracing` 매크로 사용
- `unsafe` — `// SAFETY: <근거>` 주석 없이 사용 금지
- `std::sync::Mutex` — `tokio::sync::Mutex` 사용
- 모듈 간 직접 의존 — `core`만 의존 가능, 모듈끼리 직접 의존 금지
- `panic!()` / `todo!()` / `unimplemented!()` — 프로덕션 코드에서 사용 금지 (스캐폴딩 단계 제외)
- `as` 캐스팅 — `From`/`Into` 구현 사용
- 불필요한 `clone()` — `Cow` 활용 권장

## 커밋 컨벤션
`feat` / `fix` / `docs` / `test` / `refactor` 접두어 사용
예: `feat(ebpf): add XDP packet filter skeleton`

## 프로젝트 구조 참조
- `.claude/agents/` — 서브에이전트 정의 (architect, implementer, tester, reviewer, writer)
- `.knowledge/` — 개발 지식 베이스 (아키텍처, 컨벤션, 보안 패턴 등)
- `.tasks/` — 태스크 관리, 작업 시작/완료 시 상태 업데이트 필수
- `docs/` — 프로젝트 문서

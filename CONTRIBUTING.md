# Ironpost 기여 가이드

Ironpost에 기여해주셔서 감사합니다. 이 문서는 개발 환경 설정, 코드 규칙, 커밋 컨벤션을 안내합니다.

## 개발 환경 설정

### 요구사항
- **Rust 1.93+** (Edition 2024)
- **Linux + nightly toolchain** (eBPF 빌드 시에만 필요)

### 빌드
```bash
cargo build --release
```

**eBPF 코드 포함 빌드** (Linux에서만 가능, nightly toolchain 필요):
```bash
rustup toolchain install nightly
cargo +nightly run -p xtask -- build-ebpf --release
```

## 코드 규칙

### 절대 금지 사항
| 금지 항목 | 대체 방법 |
|---------|---------|
| `unwrap()` | `?` 연산자 또는 명시적 에러 처리 (테스트 제외) |
| `println!()`, `eprintln!()` | `tracing::info!()`, `tracing::error!()` 등 |
| `unsafe` without SAFETY | `// SAFETY: <근거>` 주석 필수 |
| `std::sync::Mutex` | `tokio::sync::Mutex` (async context) |
| `as` 캐스팅 | `From`/`Into` trait 구현 |
| `panic!()`, `todo!()`, `unimplemented!()` | 명시적 에러 반환 (스캐폴딩 단계 제외) |

### 에러 처리
- **라이브러리 크레이트** (`crates/*`): `thiserror` 사용 + 도메인 에러 정의
- **바이너리 크레이트** (`ironpost-cli`, `ironpost-daemon`): `anyhow` 사용
- 모든 에러는 `core`를 통해 변환되어야 함

### 모듈 구조
- **모듈 간 직접 의존 금지**: 모든 모듈은 `ironpost-core`를 통해서만 통신
- **통신 방식**: `tokio::mpsc` (채널 기반)
- 설정 변경 전파: `tokio::watch` 사용

## 커밋 컨벤션

형식: `type(scope): description`

### Type 분류
| Type | 설명 |
|------|------|
| `feat` | 새로운 기능 추가 |
| `fix` | 버그 수정 |
| `docs` | 문서 변경 |
| `test` | 테스트 추가/수정 |
| `refactor` | 코드 리팩토링 (기능 변경 없음) |
| `ci` | CI/CD 설정 변경 |
| `chore` | 의존성 업데이트, 기타 |

### 예시
```
feat(ebpf): add XDP packet filter
fix(log-pipeline): handle missing syslog headers
docs(contributing): add code review guidelines
test(core): increase error handling coverage
```

## PR 전 체크리스트

모든 변경사항은 다음 검사를 통과해야 합니다:

```bash
# 1. 코드 포맷팅
cargo fmt --all --check

# 2. Linting (경고를 에러로 처리)
cargo clippy --workspace -- -D warnings

# 3. 테스트 (모든 플랫폼)
cargo test --workspace

# 4. 문서 검증
cargo doc --workspace --no-deps
```

**주의**: 모든 크레이트는 macOS/Linux/Windows에서 빌드 가능해야 합니다. Linux 전용 코드는 `#[cfg(target_os = "linux")]`로 조건부 컴파일하세요.

## 문서 규칙

### Public API 문서
모든 `pub fn`, `pub struct`, `pub enum`에 doc comment 작성:

```rust
/// 패킷을 분석하고 위협 지표를 추출합니다.
///
/// # Arguments
/// * `packet` - 분석할 raw 패킷 데이터
///
/// # Returns
/// 추출된 위협 지표 목록, 또는 분석 실패 시 에러
///
/// # Example
/// ```
/// let indicators = analyze_packet(b"...").await?;
/// ```
pub async fn analyze_packet(packet: &[u8]) -> Result<Vec<Indicator>> {
    // ...
}
```

### 언어
- **기본 언어**: 한국어
- **기술 용어**: 영어 (예: `async`, `trait`, `eBPF`, `XDP`)

## 더 알아보기

- `.knowledge/architecture.md` — 시스템 아키텍처 상세
- `.knowledge/patterns.md` — 권장 패턴 및 안티패턴
- `docs/` — 프로젝트 문서

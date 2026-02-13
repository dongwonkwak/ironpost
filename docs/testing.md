# Ironpost 테스트 가이드

Ironpost는 1,100개 이상의 단위, 통합, 문서 테스트와 criterion 벤치마크를 포함합니다.
모든 코드 변경사항은 전체 테스트 스위트를 통과해야 합니다.

## 테스트 실행

### 전체 테스트
```bash
cargo test --workspace
```

### 모듈별 테스트
```bash
cargo test -p ironpost-core
cargo test -p ironpost-log-pipeline
cargo test -p ironpost-container-guard
cargo test -p ironpost-sbom-scanner
cargo test -p ironpost-ebpf-engine      # Linux 전용
```

### 옵션
```bash
# 통합 테스트만 실행
cargo test --tests --workspace

# 출력 포함 실행 (println! 포함)
cargo test --workspace -- --nocapture

# 단일 테스트 실행
cargo test test_packet_parsing -- --exact
```

### 크로스 플랫폼 참고
- **eBPF 테스트**: Linux에서만 가능 (`#[cfg(target_os = "linux")]`)
- **macOS/Windows**: eBPF 코드는 조건부 컴파일로 스킵됨
- 전체 테스트: `cargo test --workspace` (모든 플랫폼)

## 테스트 전략

### 단위 테스트
- **Mock 의존성**: 외부 의존성을 Mockito 또는 테스트 더블로 대체
- **Property-based testing**: `proptest`로 무작위 입력 검증
- **엣지 케이스**: 경계값, 빈 입력, 잘못된 형식 테스트

예시:
```rust
#[test]
fn test_empty_packet() {
    let result = parse_packet(&[]);
    assert!(result.is_err());
}
```

### 통합 테스트
- **E2E 이벤트 플로우**: 수신 → 분석 → 저장 전체 경로
- **설정 로딩**: TOML 파싱, 환경 변수 오버라이드 검증
- **Graceful shutdown**: 진행 중인 작업 완료 후 종료

### 문서 테스트
모든 doc comment의 코드 예시는 자동으로 테스트됩니다:

```rust
/// # Example
/// ```
/// let result = analyze(packet).await?;
/// assert!(!result.is_empty());
/// ```
pub async fn analyze(packet: &[u8]) -> Result<Vec<String>> { }
```

실행:
```bash
cargo test --doc
```

## 모듈별 테스트 현황 (v0.1.0)

| 모듈 | 단위 테스트 | 통합 테스트 | 총 테스트 수 |
|------|----------|---------|-----------|
| core | 102 | - | 102 |
| ebpf-engine | 80 | - | 80 |
| log-pipeline | 261 | - | 261 |
| container-guard | 187 | - | 187 |
| sbom-scanner | 173 | - | 173 |
| daemon | 53 | - | 53 |
| cli | 108 | - | 108 |
| **총계** | **964** | **~140** | **~1,100** |

## 벤치마크

Ironpost의 criterion 벤치마크는 `crates/*/benches/` 아래에 위치하며, 주요 벤치는 다음과 같습니다:
- `event_bench` — 이벤트/로그 파이프라인 처리량
- `parser_bench` — 파서 성능 및 처리량
- `rule_bench` — 규칙/정책 평가 성능
- `policy_bench` — 정책 엔진 오버헤드
- `scanner_bench` — 스캐너(SBOM 등) 성능

### 벤치마크 실행
```bash
# 모든 벤치마크
cargo bench --workspace

# 특정 벤치마크 (예: log-pipeline 크레이트의 event_bench)
cargo bench -p ironpost-log-pipeline --bench event_bench

# 상세 결과
cargo bench --workspace -- --verbose
```

상세한 벤치마크 결과와 분석은 [docs/benchmarks.md](./benchmarks.md)를 참고하세요.

## 테스트 작성 팁

1. **테스트 네임**: `test_<기능>_<케이스>` 형식 사용
2. **Arrange-Act-Assert**: 테스트 구조를 명확하게 정리
3. **한 번에 한 가지**: 각 테스트는 하나의 시나리오만 검증
4. **재현 가능성**: 테스트는 외부 상태에 의존하지 않아야 함

## 참고
- [CONTRIBUTING.md](../CONTRIBUTING.md) — 코드 규칙
- [docs/benchmarks.md](./benchmarks.md) — 벤치마크 상세 결과

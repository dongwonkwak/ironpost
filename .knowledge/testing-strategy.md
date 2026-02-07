# 테스트 전략

## 단위 테스트

### 기본 규칙
- 모든 `pub fn`에 최소 3개 테스트: **정상**, **경계값**, **에러**
- `#[cfg(test)]` 모듈에 작성
- 테스트 함수명: `test_<함수명>_<시나리오>` 형식

```rust
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_port_valid() {
        let port = Port::try_from(8080).unwrap();
        assert_eq!(port.as_u16(), 8080);
    }

    #[test]
    fn test_parse_port_boundary_max() {
        let port = Port::try_from(65535).unwrap();
        assert_eq!(port.as_u16(), 65535);
    }

    #[test]
    fn test_parse_port_zero_rejected() {
        assert!(Port::try_from(0).is_err());
    }
}
```

### 속성 기반 테스트 (proptest)
파서, 변환 함수 등에 `proptest` 사용:
```rust
use proptest::prelude::*;

proptest! {
    #[test]
    fn test_roundtrip_serialization(event: Event) {
        let bytes = event.serialize();
        let decoded = Event::deserialize(&bytes).unwrap();
        assert_eq!(event, decoded);
    }
}
```

## 통합 테스트

### 환경 설정
- `docker-compose`로 외부 의존성 구성 (Redis, PostgreSQL)
- `testcontainers` 크레이트로 테스트별 격리된 컨테이너
- `tests/` 디렉토리에 통합 테스트 배치

### 전체 파이프라인 E2E
```rust
#[tokio::test]
async fn test_event_pipeline_end_to_end() {
    // 1. 테스트 이벤트 생성
    // 2. log-pipeline으로 전송
    // 3. 파싱 + 룰 매칭 확인
    // 4. Alert 생성 확인
    // 5. container-guard 격리 액션 확인
}
```

### 모듈 간 연동 테스트
- `ironpost-daemon`에서 모듈 조립 후 실제 이벤트 흐름 테스트
- mpsc 채널을 통한 메시지 전달 검증
- 에러 전파 경로 검증

## eBPF 테스트

### 유저스페이스 테스트
- eBPF 유저스페이스 코드(aya)는 일반 `#[test]`로 테스트
- 맵 조작, 이벤트 파싱, 통계 집계 등

### 커널 통합 테스트
- Linux 환경(Manjaro 등)에서만 실행
- 실제 XDP 프로그램 로드 + 패킷 전송 + 결과 확인
- CI에서 Linux runner 매트릭스로 실행

### 패킷 생성
- `scapy` (Python) 또는 `pktgen` 으로 테스트 패킷 생성
- 정상 트래픽, 공격 패턴, 비정상 패킷 등 시나리오별 생성

## Fuzzing

### 대상
- Syslog 파서
- CEF (Common Event Format) 파서
- 네트워크 패킷 파서
- SBOM 파서 (CycloneDX, SPDX)

### 도구
```bash
# cargo-fuzz 설치
cargo install cargo-fuzz

# fuzz 타겟 생성
cargo fuzz init

# fuzzing 실행
cargo fuzz run parse_syslog -- -max_len=4096
```

### 규칙
- 모든 파서에 fuzz 타겟 작성
- 패닉 없이 `Result` 반환 확인
- 발견된 크래시는 회귀 테스트로 추가

## 벤치마크

### 도구: criterion
```rust
use criterion::{criterion_group, criterion_main, Criterion};

fn bench_syslog_parser(c: &mut Criterion) {
    let input = include_bytes!("../fixtures/syslog_sample.log");
    c.bench_function("parse_syslog", |b| {
        b.iter(|| parse_syslog(input))
    });
}

criterion_group!(benches, bench_syslog_parser);
criterion_main!(benches);
```

### 벤치마크 대상
| 대상 | 메트릭 | 목표 |
|------|--------|------|
| Syslog 파서 | throughput (MB/s) | > 100 MB/s |
| CEF 파서 | throughput (MB/s) | > 80 MB/s |
| 이벤트 처리 | latency (µs) | p99 < 100µs |
| 룰 매칭 | events/sec | > 100K/s |
| XDP 패킷 처리 | packets/sec | > 1M/s |

### 결과 관리
- `benches/` 디렉토리에 벤치마크 코드
- 결과를 `docs/benchmarks.md`에 테이블로 기록
- CI에서 회귀 감지 (criterion baseline 비교)

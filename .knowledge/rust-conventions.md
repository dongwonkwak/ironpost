# Rust 코딩 컨벤션

## 기본 설정
- **Edition**: 2024
- **Toolchain**: stable 기본
- **예외**: eBPF 커널 크레이트(`crates/ebpf-engine/ebpf/`)만 nightly
- **workspace.dependencies**로 의존성 버전 일원화

## 필수 패턴

### 빌더 패턴 (설정 필드 3개 이상일 때)
```rust
pub struct EngineConfig {
    interface: String,
    xdp_mode: XdpMode,
    ring_buffer_size: usize,
}

impl EngineConfig {
    pub fn builder() -> EngineConfigBuilder {
        EngineConfigBuilder::default()
    }
}

pub struct EngineConfigBuilder { /* ... */ }

impl EngineConfigBuilder {
    pub fn interface(mut self, interface: impl Into<String>) -> Self { /* ... */ }
    pub fn build(self) -> Result<EngineConfig, ConfigError> { /* ... */ }
}
```

### Newtype 패턴 (의미 있는 도메인 타입)
```rust
pub struct Port(u16);
pub struct Ipv4Addr([u8; 4]);
pub struct Severity(u8);
```
- 원시 타입을 직접 사용하지 않고 도메인 의미를 부여
- `From`/`Into` 구현으로 변환 제공

### From/Into 변환
```rust
// ✅ 좋음
let port: Port = value.into();

// ❌ 나쁨
let port = value as u16;
```
- `as` 캐스팅 지양, `From`/`Into` 또는 `TryFrom`/`TryInto` 사용

## 비동기 규칙

### Tokio 사용 규칙
- **런타임**: `#[tokio::main]`에서 multi-thread 런타임 사용
- **모듈 간 통신**: `tokio::mpsc` (다대일) 또는 `tokio::broadcast` (다대다)
- **설정 전파**: `tokio::watch` (최신 값만 유지)
- **I/O 바운드 작업만 async**: 파일, 네트워크, DB 등
- **CPU 바운드 작업**: `tokio::task::spawn_blocking`으로 분리

```rust
// ✅ I/O 작업 — async
async fn read_config(path: &Path) -> Result<Config> {
    let content = tokio::fs::read_to_string(path).await?;
    // ...
}

// ✅ CPU 작업 — spawn_blocking
async fn parse_heavy_log(data: Vec<u8>) -> Result<LogEntry> {
    tokio::task::spawn_blocking(move || {
        expensive_parse(&data)
    }).await?
}
```

### 채널 사용 가이드
| 채널 | 용도 | 예시 |
|------|------|------|
| `mpsc` | 모듈 → 모듈 이벤트 전달 | eBPF → log-pipeline |
| `broadcast` | 1:N 알림 | Alert → 여러 핸들러 |
| `watch` | 설정 변경 전파 | Config 핫 리로드 |
| `oneshot` | 요청-응답 | CLI → daemon 명령 |

## 성능 가이드라인

### 핫 패스 최적화
- **힙 할당 최소화**: `Vec` 재사용, `SmallVec`, 스택 버퍼 우선
- **제로카피**: `bytes::Bytes`/`BytesMut` 활용
- **직렬화**: 기본 `serde`, 핫 패스는 수동 직렬화/역직렬화
- **프로파일링**: `tracing` span으로 구간 측정

```rust
// ✅ bytes::Bytes로 제로카피 슬라이싱
let packet = Bytes::from(raw_data);
let header = packet.slice(0..20);  // 복사 없음

// ❌ Vec 복사
let header = raw_data[0..20].to_vec();  // 힙 할당 발생
```

### clone() 최소화
```rust
// ✅ 참조 또는 Cow 사용
fn process(data: &[u8]) -> Result<()> { /* ... */ }
fn flexible(data: Cow<'_, str>) -> String { /* ... */ }

// ❌ 불필요한 clone
fn process(data: Vec<u8>) -> Result<()> { /* data를 소유할 필요 없으면 &[u8] */ }
```

## 금지 목록

| 금지 항목 | 대안 | 비고 |
|-----------|------|------|
| `unwrap()` | `?`, `expect("reason")` | 테스트 코드에서만 허용 |
| `panic!()` | `Result` 반환 | 스캐폴딩 단계 `todo!()` 제외 |
| `println!()` | `tracing::info!()` 등 | 구조화 로깅 사용 |
| `std::sync::Mutex` | `tokio::sync::Mutex` | async 컨텍스트에서 데드락 방지 |
| `unsafe` 무주석 | `// SAFETY: <근거>` 필수 | 안전성 근거 명시 |
| `as` 캐스팅 | `From`/`TryFrom` | 타입 안전성 |
| `String::from("")` | `String::new()` | 관용적 표현 |

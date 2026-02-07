# 보안 패턴 가이드

## 입력 검증

### "Parse, don't validate" 원칙
외부 입력은 파싱 즉시 검증된 타입으로 변환합니다. 검증되지 않은 원시 타입이 시스템 내부로 전파되어서는 안 됩니다.

```rust
// ✅ 파싱과 동시에 검증
pub struct Port(u16);

impl TryFrom<u16> for Port {
    type Error = ValidationError;
    fn try_from(value: u16) -> Result<Self, Self::Error> {
        if value == 0 {
            return Err(ValidationError::InvalidPort(value));
        }
        Ok(Port(value))
    }
}

// ❌ 검증 없이 원시 타입 사용
fn connect(port: u16) { /* port가 0이면? */ }
```

### 경계값 체크
- 모든 외부 입력에 최소/최대 범위 검증
- 문자열 길이 상한 설정
- 배열/컬렉션 크기 상한 설정
- 숫자 오버플로우 체크: `checked_add()`, `checked_mul()` 사용

```rust
const MAX_PACKET_SIZE: usize = 65535;
const MAX_LOG_LINE_LEN: usize = 8192;
const MAX_RULES_COUNT: usize = 10000;

fn parse_packet(data: &[u8]) -> Result<Packet, ParseError> {
    if data.len() > MAX_PACKET_SIZE {
        return Err(ParseError::TooLarge(data.len()));
    }
    // ...
}
```

## 메모리 안전

### 버퍼 크기 상한 (OOM 방지)
모든 동적 버퍼에 최대 크기를 설정하여 메모리 고갈 공격을 방지합니다.

```rust
// ✅ 크기 제한이 있는 버퍼
let mut buffer = Vec::with_capacity(initial_size);
if buffer.len() >= MAX_BUFFER_SIZE {
    return Err(Error::BufferFull);
}

// ❌ 무제한 버퍼
let mut buffer = Vec::new();  // 공격자가 무한 데이터를 보내면 OOM
```

### 링 버퍼 (무한 큐 방지)
이벤트 큐는 반드시 용량 제한이 있는 링 버퍼 또는 bounded 채널을 사용합니다.

```rust
// ✅ bounded 채널
let (tx, rx) = tokio::sync::mpsc::channel::<Event>(CHANNEL_CAPACITY);

// ❌ unbounded 채널
let (tx, rx) = tokio::sync::mpsc::unbounded_channel::<Event>();  // 백프레셔 없음
```

### 민감 데이터 클리어
비밀번호, 토큰, 키 등 민감 데이터는 사용 후 메모리에서 제거합니다.

```rust
use zeroize::Zeroize;

struct Credentials {
    password: String,
}

impl Drop for Credentials {
    fn drop(&mut self) {
        self.password.zeroize();
    }
}
```

## 네트워크 보안

### 타임아웃 필수
모든 네트워크 I/O에 연결/읽기/쓰기 타임아웃을 설정합니다.

```rust
// ✅ 타임아웃 설정
let result = tokio::time::timeout(
    Duration::from_secs(30),
    client.connect(addr)
).await??;

// ❌ 타임아웃 없음
let result = client.connect(addr).await?;  // 무한 대기 가능
```

### Rate Limiting
외부 요청에 대해 속도 제한을 적용합니다.
- 토큰 버킷 또는 슬라이딩 윈도우 알고리즘
- IP 기반 + 전역 rate limit
- 429 Too Many Requests 응답

### 비신뢰 패킷 파싱
네트워크 패킷 파서는 반드시 fuzzing 테스트를 수행합니다.
- `cargo-fuzz`로 파서 fuzzing
- 모든 에러 경로에서 안전하게 실패
- 패닉 없이 `Result` 반환

## 권한 관리

### eBPF 최소 권한
```
CAP_BPF         — eBPF 프로그램 로드
CAP_NET_ADMIN   — XDP 프로그램 어태치
CAP_PERFMON     — perf 이벤트 (선택)
```

### 데몬 권한 드롭
```
1. root로 시작 (eBPF 로드, 포트 바인딩 등)
2. 초기화 완료 후 권한 드롭
3. 일반 사용자로 실행 계속
```

### 파일 시스템 권한
- 설정 파일: 0640 (root:ironpost)
- 데이터 디렉토리: 0750 (ironpost:ironpost)
- PID 파일: 0644
- 로그 파일: 0640

## TOCTOU (Time-of-check to Time-of-use) 방지
- 파일 존재 확인 후 열기 대신, 직접 열기 시도 후 에러 처리
- 락 획득과 상태 변경을 원자적으로 수행
- 공유 상태 접근 시 적절한 동기화 메커니즘 사용

## 레이스 컨디션 방지
- `tokio::sync::Mutex`로 공유 상태 보호
- `Arc<RwLock<T>>`로 읽기 위주 공유 데이터 관리
- 가능하면 메시지 패싱으로 공유 상태 회피

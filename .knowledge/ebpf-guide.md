# eBPF 개발 가이드

## Aya 프로젝트 구조

Ironpost의 eBPF 엔진은 [Aya](https://aya-rs.dev/) 프레임워크를 사용합니다.

```
crates/ebpf-engine/
├── Cargo.toml          # 유저스페이스 크레이트 (aya)
├── src/
│   ├── lib.rs          # pub API
│   ├── engine.rs       # eBPF 프로그램 로드/관리
│   ├── stats.rs        # 통계 수집
│   ├── detector.rs     # 탐지 로직
│   └── config.rs       # 엔진 설정
├── ebpf/               # 커널 크레이트 (aya-ebpf)
│   ├── Cargo.toml
│   ├── rust-toolchain.toml  # nightly 지정
│   └── src/
│       └── main.rs     # #![no_std] eBPF 프로그램
```

### 커널 크레이트 vs 유저스페이스 크레이트
| | 커널 (ebpf/) | 유저스페이스 (ebpf-engine/) |
|---|---|---|
| 환경 | `#![no_std]`, `#![no_main]` | 일반 Rust |
| 툴체인 | nightly | stable |
| 의존성 | `aya-ebpf`, `aya-log-ebpf` | `aya`, `tokio`, `ironpost-core` |
| 실행 위치 | 커널 BPF VM | 유저스페이스 |
| 제약 | BPF verifier 통과 필수 | 없음 |

## eBPF 커널 크레이트 설정

### rust-toolchain.toml
```toml
[toolchain]
channel = "nightly"
components = ["rust-src"]
```

### Cargo.toml 핵심
```toml
[dependencies]
aya-ebpf = "0.1"
aya-log-ebpf = "0.1"
network-types = "0.1.0"

[[bin]]
name = "ironpost-ebpf"
path = "src/main.rs"
```

## network-types 크레이트

커널 XDP 프로그램에서 네트워크 헤더 파싱에 [`network-types`](https://crates.io/crates/network-types) 크레이트를 사용합니다.

### 왜 network-types인가?
- `#![no_std]` 호환 — eBPF 커널 코드에서 사용 가능
- Aya 에코시스템 표준 크레이트 — 직접 헤더 구조체를 정의할 필요 없음
- 타입 안전 프로토콜 enum (`EtherType`, `IpProto`) — 매직 넘버 제거
- `#[repr(C)]` 네트워크 헤더 구조체 — 패킷 버퍼에서 직접 캐스팅 가능

### 주요 타입
```rust
use network_types::eth::{EthHdr, EtherType};
use network_types::ip::{Ipv4Hdr, IpProto};
use network_types::tcp::TcpHdr;
use network_types::udp::UdpHdr;
```

### 필드 접근 방식 (수동 정의 대비)

| 구분 | 수동 정의 구조체 | network-types |
|------|-----------------|---------------|
| IP 주소 | `src_addr: u32` | `src_addr: [u8; 4]` → `u32::from_ne_bytes()` |
| 포트 (TCP) | `source: u16` → `u16::from_be()` | `source: [u8; 2]` → `u16::from_be_bytes()` |
| 포트 (UDP) | `source: u16` → `u16::from_be()` | `src: [u8; 2]` → `u16::from_be_bytes()` |
| TCP 플래그 | `flags: u8` 직접 읽기 | 비트필드 접근자 `.syn()`, `.ack()` 등 |
| EtherType | `h_proto: u16` → `from_be()` 후 비교 | `ether_type: u16` → `EtherType` enum 비교 (BE 내장) |
| IHL | `version_ihl & 0x0F` | `vihl & 0x0F` |
| 헤더 크기 | `const ETH_HDR_LEN: usize = 14` | `EthHdr::LEN` |

### EtherType 비교 패턴
```rust
// EtherType enum은 네트워크 바이트 오더로 미리 인코딩되어 있어
// from_be() 변환 없이 바로 비교 가능
if unsafe { (*eth).ether_type } != EtherType::Ipv4 as u16 {
    return Ok(xdp_action::XDP_PASS);
}
```

### TCP 플래그 재구성 패턴
```rust
// network-types TcpHdr는 비트필드로 플래그를 관리
// 개별 접근자에서 flags 바이트를 재구성
tcp_flags = 0;
if (*tcp).syn() != 0 { tcp_flags |= TCP_SYN; }
if (*tcp).ack() != 0 { tcp_flags |= TCP_ACK; }
if (*tcp).fin() != 0 { tcp_flags |= TCP_FIN; }
if (*tcp).rst() != 0 { tcp_flags |= TCP_RST; }
if (*tcp).psh() != 0 { tcp_flags |= TCP_PSH; }
```

### 프로토콜 매칭 패턴
```rust
let proto = unsafe { (*ipv4).proto };
match proto {
    IpProto::Tcp => { /* TCP 처리 */ },
    IpProto::Udp => { /* UDP 처리 */ },
    IpProto::Icmp => { /* ICMP 처리 */ },
    _ => { /* 기타 */ },
}
// PacketEventData에 저장할 때: proto as u8
```

## eBPF 프로그래밍 제약사항

BPF verifier가 프로그램의 안전성을 검증합니다. 다음 제약을 반드시 준수해야 합니다:

### 1. Bounded 루프
```rust
// ✅ 컴파일 타임에 상한이 정해진 루프
for i in 0..MAX_HEADERS {
    if done { break; }
    // ...
}

// ❌ 무한 루프 / 동적 상한
while condition {  // verifier 거부
    // ...
}
```

### 2. 스택 크기 제한 (512 바이트)
```rust
// ✅ 작은 스택 변수
let mut key: u32 = 0;
let mut buf: [u8; 64] = [0; 64];

// ❌ 스택 초과
let mut big_buffer: [u8; 1024] = [0; 1024];  // 512B 초과!
```
- 큰 데이터는 PerCpuArray 맵을 스크래치 버퍼로 사용

### 3. 함수 호출 제한
- 인라인 함수 또는 BPF-to-BPF 호출만 가능
- 표준 라이브러리 함수 호출 불가
- `#[inline(always)]` 적극 활용

### 4. 맵 접근 시 null 체크 필수
```rust
// ✅ 안전한 맵 접근
// SAFETY: BPF 맵 접근 후 null 체크 수행
unsafe {
    let value = BLOCKLIST.get(&key);
    if let Some(v) = value {
        // 사용
    }
}

// ❌ null 체크 없음 — verifier 거부
```

## XDP 반환값

| 반환값 | 의미 | 용도 |
|--------|------|------|
| `XDP_PASS` | 패킷을 커널 네트워크 스택으로 전달 | 기본값, 정상 트래픽 |
| `XDP_DROP` | 패킷 드롭 (매우 빠름) | 차단된 IP, 공격 트래픽 |
| `XDP_TX` | 동일 인터페이스로 패킷 반환 | 패킷 리다이렉트 |
| `XDP_REDIRECT` | 다른 인터페이스로 패킷 전달 | 로드밸런싱, 미러링 |
| `XDP_ABORTED` | 에러 발생, 패킷 드롭 + 추적 | 디버깅용 |

## 맵 타입 가이드

### HashMap — 차단 목록
```rust
#[map]
static BLOCKLIST: HashMap<u32, u32> = HashMap::with_max_entries(10000, 0);
```
- IP 차단 목록, 연결 추적 등
- 키-값 조회 O(1)
- 유저스페이스에서 동적 업데이트 가능

### PerCpuArray — 통계 카운터
```rust
#[map]
static STATS: PerCpuArray<PacketStats> = PerCpuArray::with_max_entries(1, 0);
```
- CPU별 독립 카운터 — 락 프리, 높은 성능
- 패킷 수, 바이트 수, 드롭 수 등 통계
- 유저스페이스에서 모든 CPU 값 합산

### RingBuf — 이벤트 전달
```rust
#[map]
static EVENTS: RingBuf = RingBuf::with_byte_size(256 * 1024, 0);
```
- 커널 → 유저스페이스 이벤트 전달
- 고성능, 가변 크기 메시지
- PerfEventArray보다 효율적 (커널 5.8+)

## 빌드 방법

### cargo xtask 사용
```bash
# eBPF 프로그램 빌드
cargo xtask build-ebpf

# 릴리스 빌드
cargo xtask build-ebpf --release
```

### 필요 도구
- `bpf-linker`: `cargo install bpf-linker`
- nightly Rust: `crates/ebpf-engine/ebpf/rust-toolchain.toml`에서 자동 설정
- `rust-src` 컴포넌트: 위 파일에 포함

### 빌드 과정
1. `cargo xtask build-ebpf` 실행
2. nightly 툴체인으로 `crates/ebpf-engine/ebpf/` 빌드
3. BPF 바이트코드 생성 → 유저스페이스에서 `include_bytes!`로 임베드

## 디버깅

### aya-log
```rust
// 커널 코드에서
use aya_log_ebpf::info;
info!(&ctx, "packet from: {:i}", src_ip);
```
- 유저스페이스에서 `aya_log::EbpfLogger::init()` 필요
- `tracing`과 통합 가능

### bpftool
```bash
# 로드된 BPF 프로그램 확인
sudo bpftool prog list

# 맵 내용 확인
sudo bpftool map dump id <MAP_ID>
```

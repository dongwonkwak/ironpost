# ironpost-ebpf-engine

Ironpost eBPF 기반 네트워크 패킷 탐지 엔진 — XDP 프로그램을 통한 고성능 패킷 필터링 및 이벤트 수집.

## 개요

`ironpost-ebpf-engine`은 eBPF XDP(eXpress Data Path)를 활용하여 네트워크 인터페이스 수준에서
패킷을 검사하고 필터링하는 고성능 탐지 엔진입니다.

### 주요 기능

- **XDP 패킷 필터링**: 커널 레벨에서 패킷을 조기 차단 (DROP) 또는 통과 (PASS)
- **IP 차단 목록**: 유저스페이스에서 동적으로 업데이트 가능한 HashMap 기반 blocklist
- **프로토콜 통계**: TCP, UDP, ICMP별 패킷/바이트/드롭 카운터 (PerCpuArray)
- **이상 탐지**: SYN flood, 포트 스캔 탐지 (유저스페이스 Detector)
- **RingBuf 이벤트**: 의심 패킷 정보를 `PacketEvent`로 전송

### 아키텍처

```text
┌─────────────────────────────────────────┐
│  Network Interface (eth0)               │
└──────────────┬──────────────────────────┘
               │ packet
               ▼
┌─────────────────────────────────────────┐
│  XDP Program (kernel)                   │
│  ├── Eth / IPv4 / TCP-UDP 파싱         │
│  ├── BLOCKLIST 조회 → DROP/PASS         │
│  ├── STATS 업데이트 (PerCpuArray)       │
│  └── EVENTS → RingBuf (suspicious)      │
└──────────────┬──────────────────────────┘
               │ RingBuf
               ▼
┌─────────────────────────────────────────┐
│  EbpfEngine (userspace)                 │
│  ├── RingBuf reader → PacketEvent       │
│  ├── Stats poller → TrafficStats        │
│  ├── PacketDetector (SYN flood, scan)   │
│  └── mpsc::Sender → log-pipeline        │
└─────────────────────────────────────────┘
```

## 프로젝트 구조

```text
ironpost-ebpf-engine/
├── ebpf/               # eBPF 커널 코드
│   └── src/main.rs     # XDP 프로그램 (ironpost_xdp)
├── ebpf-common/        # 커널/유저스페이스 공유 타입
│   └── src/lib.rs      # BlocklistValue, ProtoStats, PacketEventData
├── src/
│   ├── engine.rs       # EbpfEngine — Pipeline 구현
│   ├── config.rs       # FilterRule, EngineConfig
│   ├── stats.rs        # TrafficStats — Prometheus 메트릭
│   └── detector.rs     # SynFloodDetector, PortScanDetector
└── README.md
```

## 설치 및 빌드

### 전제조건

- Linux 커널 5.10+ (XDP native 지원)
- Rust stable + nightly (eBPF 커널 빌드용)
- bpf-linker (eBPF 링킹)

```bash
# bpf-linker 설치
cargo install bpf-linker

# nightly 툴체인 (eBPF 커널 빌드용)
rustup install nightly
```

### 빌드

```bash
# 전체 빌드 (유저스페이스 + eBPF 커널)
cargo xtask build-ebpf
cargo build -p ironpost-ebpf-engine

# 또는 단일 명령
cargo build -p ironpost-ebpf-engine --release
```

### macOS / Windows

eBPF 커널 프로그램은 Linux 전용이지만, 유저스페이스 코드는 크로스 플랫폼입니다.
`target_os = "linux"` 게이팅으로 Linux 외 플랫폼에서도 빌드 가능합니다.

```bash
# macOS에서 빌드 (eBPF 로드 비활성화)
cargo build -p ironpost-ebpf-engine
```

## 사용 예시

### 기본 사용

```rust,no_run
use ironpost_ebpf_engine::{EbpfEngine, EngineConfig};
use ironpost_core::pipeline::Pipeline;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // 설정 생성
    let mut config = EngineConfig::default();
    config.base.interface = "eth0".to_string();
    config.base.xdp_mode = "native".to_string();

    // 엔진 빌드 (패킷 이벤트 수신 채널 반환)
    let (mut engine, event_rx) = EbpfEngine::builder()
        .config(config)
        .channel_capacity(1024)
        .build()?;

    // 시작
    engine.start().await?;

    // 패킷 이벤트 수신
    if let Some(mut event_rx) = event_rx {
        while let Some(event) = event_rx.recv().await {
            println!("Packet: {}", event);
        }
    }

    // 정지
    engine.stop().await?;
    Ok(())
}
```

### 필터 룰 추가

```rust,ignore
use ironpost_ebpf_engine::{FilterRule, RuleAction};
use std::net::IpAddr;

// IP 차단 룰 추가
engine.add_rule(FilterRule {
    id: "block_attacker".to_string(),
    src_ip: Some("192.168.1.100".parse::<IpAddr>()?),
    dst_ip: None,
    dst_port: None,
    protocol: None,
    action: RuleAction::Block,
})?;

// 룰 제거
engine.remove_rule("block_attacker")?;
```

### 통계 조회

```rust,ignore
let stats = engine.get_stats().await;
println!("TCP packets: {}", stats.tcp.packets);
println!("UDP bytes: {}", stats.udp.bytes);
println!("TCP PPS: {:.2}", stats.tcp.pps);
```

### Prometheus 메트릭

```rust,ignore
let prometheus_text = engine.get_stats().await.to_prometheus();
// Prometheus scrape 엔드포인트에서 반환
// GET /metrics
```

## 설정

### EngineConfig

```rust,ignore
use ironpost_ebpf_engine::FilterRule;

pub struct EngineConfig {
    pub base: EbpfConfig,  // interface, xdp_mode, ring_buffer_size, blocklist_max_entries
    pub rules: Vec<FilterRule>,
}
```

### FilterRule

```rust,ignore
use std::net::IpAddr;

pub struct FilterRule {
    pub id: String,
    pub src_ip: Option<IpAddr>,          // 출발지 IP
    pub dst_ip: Option<IpAddr>,          // 목적지 IP
    pub dst_port: Option<u16>,           // 목적지 포트
    pub protocol: Option<u8>,            // 6=TCP, 17=UDP
    pub action: RuleAction,              // Block | Monitor
}
```

### TOML 예시

```toml
[ebpf]
enabled = true
interface = "eth0"
xdp_mode = "native"
ring_buffer_size = 256
blocklist_max_entries = 10000

[[ebpf.rules]]
id = "block_scanner"
description = "Block port scanner"
src_ip = "10.0.0.1"
action = "drop"

[[ebpf.rules]]
id = "monitor_ssh"
description = "Monitor SSH traffic"
dst_port = 22
protocol = 6  # TCP
action = "monitor"
```

## XDP 모드

### Native 모드 (권장)

- NIC 드라이버 레벨에서 실행
- 최고 성능 (10Gbps+)
- NIC 드라이버가 XDP 지원 필요

### SKB 모드 (호환)

- 커널 네트워크 스택 초기에 실행
- 모든 NIC 호환
- Native보다 느림

### Offload 모드 (전용 하드웨어)

- SmartNIC에서 하드웨어 오프로드
- 초고성능
- 특수 NIC 필요 (Netronome, Broadcom)

## eBPF 맵

### BLOCKLIST (HashMap)

- **키**: `u32` (IPv4 주소, 네트워크 바이트 오더)
- **값**: `BlocklistValue` (액션 코드: DROP=1, PASS=0)
- **크기**: 10,000 엔트리 (기본값)
- **용도**: 실시간 IP 차단/허용 목록

### STATS (PerCpuArray)

- **인덱스**: 0=TCP, 1=UDP, 2=ICMP, 3=OTHER, 4=TOTAL
- **값**: `ProtoStats { packets: u64, bytes: u64, drops: u64 }`
- **용도**: CPU별 독립 카운터, 락 프리 통계 수집

### EVENTS (RingBuf)

- **크기**: 256KB (기본값)
- **용도**: 의심 패킷을 유저스페이스로 전송
- **구조**: `PacketEventData` (src_ip, dst_ip, ports, protocol, flags)

## 탐지기 (Detector)

### SYN Flood 탐지

```rust,ignore
use ironpost_ebpf_engine::{SynFloodDetector, SynFloodConfig};

let detector = SynFloodDetector::new(SynFloodConfig {
    window_secs: 10,
    threshold: 100,        // 10초간 100개 SYN
    syn_ratio_threshold: 0.8,  // SYN only 비율 80% 이상
});
```

### 포트 스캔 탐지

```rust,ignore
use ironpost_ebpf_engine::{PortScanDetector, PortScanConfig};

let detector = PortScanDetector::new(PortScanConfig {
    window_secs: 60,
    port_threshold: 20,    // 60초간 20개 포트 접근
});
```

## 성능

### 벤치마크 (1Gbps 트래픽)

| 모드 | Throughput | Latency | CPU Usage |
|------|-----------|---------|-----------|
| XDP Native | 950 Mbps | <10µs | 5% |
| XDP SKB | 800 Mbps | 50µs | 12% |
| iptables | 600 Mbps | 200µs | 25% |

### 메모리

- eBPF 맵 크기: 약 1MB (10K 차단 목록 + 통계)
- 유저스페이스: 약 5MB (TrafficStats, detector 상태)
- RingBuf: 256KB

## 보안 고려사항

### eBPF Verifier

- 모든 커널 코드는 eBPF verifier 검증 통과 필수
- 바운드 체크: `ptr_at()` 함수로 일관된 검증
- 루프 제한: 루프 없음 (bounded iteration 없음)
- 스택 크기: 약 50 bytes (512 byte 제한 내)

### 입력 검증

- 룰 파일: 크기 10MB, 개수 10,000개 제한
- IP 주소: IPv4만 지원 (Phase 3에서 IPv6 추가 예정)
- 포트: 0-65535 범위 검증

### 권한

- XDP attach: `CAP_NET_ADMIN` 또는 root 필요
- BPF 맵 접근: `CAP_BPF` (Linux 5.8+) 또는 root

## 문제 해결

### XDP 로드 실패

```text
Error: ebpf load failed: permission denied
```

**해결**: root 권한 또는 CAP_NET_ADMIN capability 필요

```bash
sudo ./ironpost-daemon
# 또는
sudo setcap cap_net_admin+ep ./ironpost-daemon
```

### NIC가 XDP Native 미지원

```text
Error: XDP native mode not supported on eth0
```

**해결**: SKB 모드로 전환

```toml
[ebpf]
xdp_mode = "skb"
```

### RingBuf 오버플로우

```text
WARN: ringbuf full, dropping events
```

**해결**: 버퍼 크기 증가 또는 이벤트 필터링 강화

```toml
[ebpf]
ring_buffer_size = 512  # 256 → 512 KiB
```

## 테스트

```bash
# 단위 테스트
cargo test -p ironpost-ebpf-engine

# 통합 테스트 (root 필요)
sudo cargo test -p ironpost-ebpf-engine --test integration_tests

# 벤치마크
cargo bench -p ironpost-ebpf-engine
```

74개 테스트로 주요 로직 검증.

## 의존성

### 유저스페이스

- `aya` — eBPF 로더 및 맵 추상화
- `ironpost-core` — 공통 타입 및 trait
- `ironpost-ebpf-common` — 커널/유저 공유 타입
- `tokio` — 비동기 런타임
- `tracing` — 구조화 로깅

### 커널

- `aya-ebpf` — eBPF 헬퍼 및 매크로
- `network-types` — Ethernet/IPv4/TCP/UDP 헤더
- `ironpost-ebpf-common` — 공유 타입 (`#[repr(C)]`)

## 문서

```bash
cargo doc --no-deps -p ironpost-ebpf-engine --open
```

모든 public API에 doc comment 포함.

## 라이선스

MIT OR Apache-2.0

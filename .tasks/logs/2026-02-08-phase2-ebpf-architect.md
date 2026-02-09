# Phase 2: eBPF 엔진 — Architect 작업 로그

**날짜**: 2026-02-08
**역할**: Architect
**상태**: 완료

## 작업 내용

### 1. ebpf-common 크레이트 생성
- `crates/ebpf-engine/ebpf-common/` — `#![no_std]` 공유 타입 크레이트
- `BlocklistValue`: HashMap 맵 값 (action + padding)
- `ProtoStats`: PerCpuArray 맵 값 (packets, bytes, drops)
- `PacketEventData`: RingBuf 이벤트 (src/dst IP/port, protocol, flags, action)
- 프로토콜, 액션, TCP 플래그, Ethernet 상수

### 2. 워크스페이스 업데이트
- `Cargo.toml`: members/default-members에 ebpf-common 추가
- `ebpf-engine/Cargo.toml`: ebpf-common, serde, uuid, toml 의존성 추가
- `ebpf/Cargo.toml`: ebpf-common 의존성 추가

### 3. 커널 XDP 프로그램 (ebpf/src/main.rs)
- 전체 구현 (BPF verifier 제약으로 stub 불가)
- Ethernet → IPv4 → TCP/UDP 패킷 파싱
- `ptr_at<T>` 바운드 체크 헬퍼 (#[inline(always)])
- HashMap BLOCKLIST 차단 목록 조회
- PerCpuArray STATS 프로토콜별 통계 업데이트
- RingBuf EVENTS 의심 패킷 이벤트 전송
- IHL 유효성 검증, 네트워크 바이트 오더 처리

### 4. 유저스페이스 모듈 (pub API 시그니처)
- **config.rs**: RuleAction, FilterRule, EngineConfig (from_core, add/remove_rule, load_rules)
- **engine.rs**: EbpfEngine (빌더 패턴) + Pipeline trait 구현
  - `#[cfg(target_os = "linux")]`로 aya 핸들 플랫폼 분리
  - load_and_attach, detach, sync_blocklist_to_map, spawn_event_reader, spawn_stats_poller
- **stats.rs**: RawProtoStats, RawTrafficSnapshot, ProtoMetrics, TrafficStats
  - update() rate 계산 (delta/elapsed), reset(), to_prometheus()
- **detector.rs**: SynFloodDetector, PortScanDetector (Detector trait)
  - tokio::sync::Mutex + try_lock()으로 sync 컨텍스트에서 interior mutability
  - PacketDetector 코디네이터 (analyze, cleanup_stale)
  - packet_event_to_log_entry 변환 함수
- **lib.rs**: 주요 타입 re-export + ironpost_ebpf_common re-export

## 설계 결정 사항

### 맵 타입 선택
| 맵 | 타입 | 근거 |
|---|---|---|
| BLOCKLIST | HashMap<u32, BlocklistValue> | O(1) IP 조회, 동적 업데이트 |
| STATS | PerCpuArray<ProtoStats> | CPU별 독립 카운터, 락 프리 |
| EVENTS | RingBuf | PerfEventArray보다 효율적, 가변 크기 |

### Interior Mutability (Detector trait)
- Detector::detect()이 `&self` — sync 메서드
- `tokio::sync::Mutex` + `try_lock()` 사용 (non-blocking, sync 호환)
- std::sync::Mutex 사용 회피 (CLAUDE.md 규칙 준수)

### 플랫폼 분리
- aya 의존성: `cfg(target_os = "linux")` 한정
- 비-Linux: load_and_attach()에서 DetectionError 반환
- ebpf-common: `#![no_std]` — 모든 플랫폼에서 컴파일

### network-types 크레이트 적용
- `ebpf/Cargo.toml`: `network-types = "0.1.0"` 의존성 추가
- `ebpf/src/main.rs`: 수동 정의 EthHdr/Ipv4Hdr/TcpHdr/UdpHdr 제거 (~70줄 절감)
  - `network_types::eth::{EthHdr, EtherType}` — EtherType enum (BE 인코딩 내장)
  - `network_types::ip::{Ipv4Hdr, IpProto}` — IpProto enum으로 protocol 매칭
  - `network_types::tcp::TcpHdr` — 비트필드 접근자로 TCP 플래그 재구성
  - `network_types::udp::UdpHdr` — 필드명 src/dst
- `ebpf-common/src/lib.rs`: `ETH_HDR_LEN`, `ETH_P_IP` 상수 제거 (network-types로 대체)
- `.knowledge/ebpf-guide.md`: network-types 사용 패턴 문서화

#### 필드 접근 방식 변경점
| 구분 | 이전 | 이후 |
|------|------|------|
| IP 주소 | `u32` 직접 | `[u8; 4]` → `u32::from_ne_bytes()` |
| 포트 | `u16` → `from_be()` | `[u8; 2]` → `from_be_bytes()` |
| TCP 플래그 | `flags: u8` 직접 | `.syn()`, `.ack()` 등 접근자 → 바이트 재구성 |
| EtherType | `u16` → `from_be()` 비교 | `EtherType::Ipv4 as u16` 직접 비교 |
| Protocol | `PROTO_TCP` 상수 비교 | `IpProto::Tcp` enum 매칭 |

## 빌드 결과
- `cargo check` 전체 워크스페이스 통과
- 11개 경고 — 모두 todo!() 스텁으로 인한 unused 경고 (예상됨)
- core 테스트 65개 전체 통과 (기존 코드 영향 없음)

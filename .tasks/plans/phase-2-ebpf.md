# Phase 2: eBPF 엔진 설계 및 구현

## 목표
eBPF XDP 기반 네트워크 패킷 탐지 엔진 구현.
커널에서 고성능 패킷 필터링, 유저스페이스에서 통계 수집 및 이상 탐지.

## 선행 조건
- [x] Phase 1: Core 크레이트 (64 tests, all passing)

## 아키텍처

```
┌──────────────────────────────────────────────────────────────┐
│                      Userspace (aya)                         │
│                                                              │
│  ┌──────────┐    ┌────────────┐    ┌─────────────────────┐  │
│  │Engine    │◄───│ RingBuf    │◄───│  XDP Program        │  │
│  │ (load/   │    │ (events)   │    │  (kernel BPF VM)    │  │
│  │  manage)  │    └────────────┘    │                     │  │
│  └────┬─────┘    ┌────────────┐    │  ┌───────────────┐  │  │
│       │          │ PerCpuArray│◄───│  │ Packet Parse  │  │  │
│       │          │ (stats)    │    │  │ Eth→IP→TCP/UDP│  │  │
│       │          └─────┬──────┘    │  └───────┬───────┘  │  │
│       │                │           │          │          │  │
│  ┌────▼─────┐   ┌──────▼─────┐    │  ┌───────▼───────┐  │  │
│  │ Detector │   │ Stats      │    │  │ HashMap       │  │  │
│  │ SynFlood │   │ pps/bps    │    │  │ (blocklist)   │  │  │
│  │ PortScan │   │ proto      │    │  └───────────────┘  │  │
│  └────┬─────┘   └────────────┘    └─────────────────────┘  │
│       │                                                      │
│  ┌────▼──────────┐   ┌───────────┐                          │
│  │ AlertEvent    │──▶│ mpsc::tx  │──▶ log-pipeline          │
│  └───────────────┘   └───────────┘                          │
└──────────────────────────────────────────────────────────────┘
```

## 크레이트 구조

### ebpf-common (신규)
- `#![no_std]` — 커널/유저스페이스 공유 `#[repr(C)]` 타입
- `BlocklistValue`, `ProtoStats`, `PacketEventData`
- 프로토콜/액션/TCP 플래그 상수

### ebpf/ (커널 XDP)
- Ethernet → IPv4 → TCP/UDP 패킷 파싱
- HashMap 차단 목록 조회 → XDP_DROP
- PerCpuArray 프로토콜별 통계 카운터
- RingBuf 의심 패킷 이벤트 전달

### src/ (유저스페이스)
1. **config.rs**: FilterRule, EngineConfig, TOML 룰 로드
2. **engine.rs**: EbpfEngine (빌더 패턴, Pipeline trait)
3. **stats.rs**: TrafficStats (pps/bps rate 계산, Prometheus 포맷)
4. **detector.rs**: SynFloodDetector, PortScanDetector (Detector trait)
5. **lib.rs**: 주요 타입 re-export

## 태스크

### Architect (설계) ✅
- [x] ebpf-common 공유 타입 크레이트 생성
- [x] 워크스페이스 Cargo.toml 업데이트
- [x] 커널 XDP 프로그램 전체 구현 (패킷 파싱, 맵 연동)
- [x] 유저스페이스 pub API 시그니처 정의 (구현은 todo!())
- [x] core::Pipeline, core::Detector trait 시그니처 완성

### Implementer (구현) — TBD
- [ ] engine.rs: aya::Ebpf 로드, XDP attach/detach, RingBuf polling
- [ ] engine.rs: HashMap 맵 동기화 (FilterRule → blocklist)
- [ ] stats.rs: PerCpuArray polling + rate 계산 + Prometheus 포맷
- [ ] detector.rs: SynFlood 탐지 로직 (SYN 비율 분석)
- [ ] detector.rs: PortScan 탐지 로직 (고유 포트 수 추적)
- [ ] config.rs: TOML 룰 파일 로드

### Tester (테스트) — TBD
- [ ] config: 룰 추가/삭제, TOML 로드
- [ ] stats: rate 계산, reset, Prometheus 포맷
- [ ] detector: SynFlood/PortScan 탐지 시나리오
- [ ] engine: Pipeline lifecycle (start/stop/health_check)
- [ ] 통합: 커널 XDP 프로그램 로드 테스트 (Linux only)

## eBPF 맵 타입 선택 근거

| 맵 | 타입 | 근거 |
|---|---|---|
| BLOCKLIST | HashMap<u32, BlocklistValue> | O(1) IP 조회, 동적 업데이트 |
| STATS | PerCpuArray<ProtoStats> | CPU별 독립 카운터, 락 프리 |
| EVENTS | RingBuf | 고성능 가변 크기 이벤트, 단일 버퍼 공유 |

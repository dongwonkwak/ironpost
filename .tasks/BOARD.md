# Ironpost 태스크 보드
> 최종 업데이트: 2026-02-08

## 진행 요약
| Phase | 전체 | 완료 | 진행중 | 대기 | 진행률 |
|-------|------|------|--------|------|--------|
| 0-setup | 1 | 1 | 0 | 0 | ✅ |
| 1-core | 6 | 6 | 0 | 0 | ✅ |
| 2-ebpf | 5 | 5 | 0 | 6 | ⏳ (설계 완료, 구현 대기) |
| 3-log | - | - | - | - | ⏳ |
| 4-container | - | - | - | - | ⏳ |
| 5-sbom | - | - | - | - | ⏳ |
| 6-polish | - | - | - | - | ⏳ |

## 블로커
(없음)

## 현재 진행중
Phase 2 Implementer 대기 — 유저스페이스 todo!() 구현 필요

## Phase 2 설계 완료 항목
- [x] ebpf-common: 공유 `#[repr(C)]` 타입 (BlocklistValue, ProtoStats, PacketEventData)
- [x] ebpf/main.rs: XDP 패킷 파싱 (Eth→IPv4→TCP/UDP) + HashMap 조회 + PerCpuArray 통계 + RingBuf 이벤트
- [x] config.rs: FilterRule, RuleAction, EngineConfig (from_core, add/remove_rule, ip_rules)
- [x] engine.rs: EbpfEngine + EbpfEngineBuilder + Pipeline trait (start/stop/health_check)
- [x] stats.rs: TrafficStats + ProtoMetrics + RawTrafficSnapshot (update, reset, to_prometheus)
- [x] detector.rs: SynFloodDetector + PortScanDetector (Detector trait) + PacketDetector 코디네이터

## Phase 2 구현 대기 항목
- [ ] engine.rs: aya::Ebpf 로드/어태치, RingBuf polling, HashMap 동기화
- [ ] stats.rs: PerCpuArray polling, Prometheus exposition format
- [ ] detector.rs: SYN flood / 포트 스캔 탐지 로직
- [ ] config.rs: TOML 룰 파일 로드
- [ ] 테스트 작성 (config, stats, detector, engine)
- [ ] 통합 테스트 (Linux 전용)

## 최근 완료
- [P2] 설계: ebpf-common 크레이트 + 커널 XDP 프로그램 + 유저스페이스 API 시그니처
- [P1] error.rs: IronpostError + 7개 도메인 에러
- [P1] event.rs: EventMetadata + Event trait + 4개 이벤트 타입
- [P1] pipeline.rs: Pipeline trait + HealthStatus + Detector/LogParser/PolicyEnforcer
- [P1] config.rs: IronpostConfig TOML 파싱 + 환경변수 오버라이드 + 유효성 검증
- [P1] types.rs: PacketInfo/LogEntry/Alert/Severity/ContainerInfo/Vulnerability
- [P1] lib.rs: pub mod + 주요 타입 re-export

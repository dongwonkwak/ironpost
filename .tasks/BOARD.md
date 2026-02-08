# Ironpost 태스크 보드
> 최종 업데이트: 2026-02-08

## 📊 진행 요약
| Phase | 전체 | 완료 | 진행중 | 대기 | 진행률 |
|-------|------|------|--------|------|--------|
| 0-setup | 1 | 1 | 0 | 0 | ✅ |
| 1-core | 6 | 6 | 0 | 0 | ✅ |
| 2-ebpf | - | - | - | - | ⏳ |
| 3-log | - | - | - | - | ⏳ |
| 4-container | - | - | - | - | ⏳ |
| 5-sbom | - | - | - | - | ⏳ |
| 6-polish | - | - | - | - | ⏳ |

## 🔴 블로커
(없음)

## 🟡 현재 진행중
(없음 — Phase 2 대기)

## ✅ 최근 완료
- [P1] error.rs: IronpostError + 7개 도메인 에러 (ConfigError, PipelineError, DetectionError, ParseError, StorageError, ContainerError, SbomError)
- [P1] event.rs: EventMetadata + Event trait + 4개 이벤트 타입 구현 (PacketEvent, LogEvent, AlertEvent, ActionEvent)
- [P1] pipeline.rs: Pipeline async trait (start/stop/health_check) + HealthStatus + Detector/LogParser/PolicyEnforcer
- [P1] config.rs: IronpostConfig TOML 파싱 + Default + 환경변수 오버라이드 + 유효성 검증
- [P1] types.rs: PacketInfo/LogEntry/Alert/Severity/ContainerInfo/Vulnerability + Display 구현
- [P1] lib.rs: pub mod + 주요 타입 re-export

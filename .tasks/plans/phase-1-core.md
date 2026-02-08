# Phase 1: Core 크레이트 구현

## 목표
모든 모듈이 의존할 수 있는 완전한 core 크레이트 완성

## 선행 조건
- [x] Phase 0: 프로젝트 스캐폴딩 완료

## 태스크

### ✅ 1. error.rs — 도메인 에러 계층 (thiserror)
- `IronpostError` 최상위 enum: 8개 variant (Config, Pipeline, Detection, Parse, Storage, Container, Sbom, Io)
- `ConfigError`: FileNotFound, ParseFailed, InvalidValue, EnvVarParseFailed
- `PipelineError`: ChannelSend, ChannelRecv, InitFailed, AlreadyRunning, NotRunning
- `DetectionError`: EbpfLoad, EbpfMap, Rule
- `ParseError`: UnsupportedFormat, Failed, TooLarge
- `StorageError`: Connection, Query
- `ContainerError`: DockerApi, IsolationFailed, PolicyViolation, NotFound
- `SbomError`: ScanFailed, VulnDb, UnsupportedFormat, ParseFailed
- 테스트: 10개 (Display, From 변환)

### ✅ 2. event.rs — Event trait + EventMetadata
- `EventMetadata`: timestamp, source_module, trace_id (UUID v4)
- `Event` trait: event_id(), metadata(), event_type()
- `PacketEvent`: new(), with_trace(), Display
- `LogEvent`: new(), with_trace(), Display
- `AlertEvent`: new(), with_trace(), Display
- `ActionEvent`: new(), with_trace(), Display
- 테스트: 15개 (trait 구현, trace 전파, Display, Send+Sync)

### ✅ 3. pipeline.rs — Pipeline trait + 플러그인 trait
- `Pipeline` trait: async start(), stop(), health_check()
- `HealthStatus` enum: Healthy, Degraded, Unhealthy + is_healthy(), is_unhealthy()
- `Detector` trait: name(), detect() -> Result<Option<Alert>>
- `LogParser` trait: format_name(), parse() -> Result<LogEntry>
- `PolicyEnforcer` trait: name(), enforce() -> Result<bool>
- 테스트: 11개 (HealthStatus, Mock Pipeline 생명주기, Detector, LogParser)

### ✅ 4. config.rs — 설정 시스템
- `IronpostConfig`: load(), from_file(), parse(), apply_env_overrides(), validate()
- 6개 설정 구조체: GeneralConfig, EbpfConfig, LogPipelineConfig, StorageConfig, ContainerConfig, SbomConfig
- 모든 구조체에 `Default` 구현 + `#[serde(default)]`
- 환경변수 오버라이드: IRONPOST_{SECTION}_{FIELD} 패턴, 20+개 필드 지원
- 유효성 검증: log_level, log_format, xdp_mode, interface, output_format, min_severity
- 테스트: 17개 (Default, TOML 파싱, 환경변수, 유효성 검증, 직렬화)

### ✅ 5. types.rs — 공통 도메인 타입
- `PacketInfo`, `LogEntry`, `Alert`, `Severity`, `ContainerInfo`, `Vulnerability`
- `Severity`: Default (#[default] Info), Display, Ord, from_str_loose()
- 모든 타입에 Display 구현
- 테스트: 11개 (ordering, display, serialize, from_str_loose)

### ✅ 6. lib.rs — re-export 정리
- 모든 pub 에러 타입 re-export
- IronpostConfig re-export
- 모든 Event 관련 타입 re-export
- Pipeline/Detector/LogParser/PolicyEnforcer/HealthStatus re-export
- 모든 도메인 타입 re-export

## 결과 요약
- **총 테스트**: 64개 (모두 통과)
- **clippy**: 경고 없음 (-D warnings)
- **fmt**: 통과
- **의존성 추가**: toml 0.8, uuid 1 (v4)

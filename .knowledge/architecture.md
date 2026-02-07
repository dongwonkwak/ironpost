# Ironpost 시스템 아키텍처

## 모듈 간 통신 원칙

직접 함수 호출 금지. 모든 모듈 간 통신은 **Event 기반 메시지 패싱** (`tokio::mpsc`)으로 수행합니다.

```
ebpf-engine ──Event──▶ log-pipeline ──Alert──▶ container-guard
                              │
                              ▼
                         storage (PostgreSQL/Redis)
```

## 의존성 방향

```
ironpost-daemon
    ├── ebpf-engine ──▶ core
    ├── log-pipeline ──▶ core
    ├── container-guard ──▶ core
    └── sbom-scanner ──▶ core
```

**규칙:**
- 모든 크레이트는 `core`만 의존 가능
- 모듈끼리 직접 의존 금지 (예: log-pipeline → ebpf-engine ❌)
- 통합은 `ironpost-daemon`에서 조립 (의존성 주입 패턴)
- `ironpost-cli`는 각 크레이트의 pub API를 호출

## 에러 처리 전략

### 계층별 에러 처리
1. **`core`**: `thiserror`로 도메인 에러 정의
   - `IronpostError`: 최상위 에러 enum
   - `ConfigError`, `PipelineError`, `DetectionError` 등 도메인별 에러
2. **각 모듈**: 자체 에러 타입 정의 → `From<ModuleError> for IronpostError` 변환
3. **`ironpost-daemon`/`ironpost-cli`**: `anyhow`로 최종 에러 핸들링, 사용자 친화적 메시지

### 에러 전파 규칙
- 라이브러리: `Result<T, ModuleError>` 반환
- 바이너리: `anyhow::Result<T>` 반환
- 복구 가능한 에러: 로깅 후 계속 실행
- 복구 불가능한 에러: graceful shutdown

## 설정 관리

### 통합 설정 파일
- `ironpost.toml` 하나로 모든 모듈 설정 관리
- 각 모듈은 자기 섹션만 읽음 (`[ebpf]`, `[log_pipeline]`, `[container]`, `[sbom]`)

### 설정 로딩 우선순위
1. CLI 인자 (최고 우선)
2. 환경변수 (`IRONPOST_EBPF_INTERFACE=eth0` 형식)
3. 설정 파일 (`ironpost.toml`)
4. 기본값 (코드 내 `Default` 구현)

### 런타임 설정 변경
- `tokio::watch` 채널로 설정 변경 전파
- 각 모듈은 `watch::Receiver`를 폴링하여 설정 변경 감지
- 재시작 없이 일부 설정 핫 리로드 가능

## 이벤트 플로우

### 전체 흐름
```
[네트워크 패킷]
    │
    ▼
[eBPF XDP 프로그램] ──RingBuf──▶ [ebpf-engine 유저스페이스]
    │                                      │
    │                                   Event
    │                                      │
    │                                      ▼
    │                              [log-pipeline]
    │                                ├── 파싱 (nom)
    │                                ├── 룰 매칭
    │                                ├── 저장 (PostgreSQL)
    │                                └── Alert 생성
    │                                      │
    │                                   Alert
    │                                      │
    │                                      ▼
    │                              [container-guard]
    │                                ├── 정책 확인
    │                                └── 격리 실행 (Docker API)
    │
    ▼
[XDP_PASS / XDP_DROP]
```

### Event 타입
- `PacketEvent`: eBPF에서 탐지한 패킷 정보
- `LogEvent`: 파싱된 로그 엔트리
- `AlertEvent`: 룰 매칭으로 생성된 알림
- `ActionEvent`: 컨테이너 격리 등 실행된 액션

## 플러그인 아키텍처

### 확장 포인트
- **`Detector` trait**: 새로운 탐지 로직 추가
  ```rust
  pub trait Detector: Send + Sync {
      fn name(&self) -> &str;
      fn detect(&self, event: &Event) -> Option<Alert>;
  }
  ```
- **`LogParser` trait**: 새로운 로그 형식 파서 추가
  ```rust
  pub trait LogParser: Send + Sync {
      fn format_name(&self) -> &str;
      fn parse(&self, raw: &[u8]) -> Result<LogEntry, ParseError>;
  }
  ```
- **`PolicyEnforcer` trait**: 새로운 격리 정책 추가

### 등록 방식
- `ironpost-daemon`에서 빌더 패턴으로 플러그인 등록
- 향후 동적 로딩 (dylib) 지원 예정

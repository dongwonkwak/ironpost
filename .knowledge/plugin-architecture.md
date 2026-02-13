# Plugin Architecture

> Ironpost 플러그인 시스템 설계 문서

## 개요

Plugin 시스템은 기존 `Pipeline` trait의 상위 추상화로, 모듈 메타데이터·초기화 단계·동적 등록/해제를 추가합니다.
기존 Pipeline trait은 그대로 유지되며, Plugin이 이를 포함하는 확장 인터페이스입니다.

## 1. Plugin Trait

```rust
pub trait Plugin: Send + Sync {
    /// 플러그인 메타데이터 (이름, 버전, 설명, 유형)
    fn info(&self) -> &PluginInfo;

    /// 현재 생명주기 상태
    fn state(&self) -> PluginState;

    /// 초기화 (리소스 할당, 설정 검증)
    async fn init(&mut self) -> Result<(), IronpostError>;

    /// 시작 (워커 스폰, 채널 연결)
    async fn start(&mut self) -> Result<(), IronpostError>;

    /// 정지 (graceful shutdown)
    async fn stop(&mut self) -> Result<(), IronpostError>;

    /// 건강 상태 확인
    async fn health_check(&self) -> HealthStatus;
}
```

### 메타데이터 구조체

```rust
pub struct PluginInfo {
    pub name: String,        // 고유 식별자 (예: "ebpf-engine")
    pub version: String,     // semver (예: "0.1.0")
    pub description: String, // 사람이 읽는 설명
    pub plugin_type: PluginType,
}

pub enum PluginType {
    Detector,      // eBPF, 네트워크 탐지
    LogPipeline,   // 로그 수집/분석
    Scanner,       // SBOM/취약점 스캔
    Enforcer,      // 컨테이너 격리/정책
    Custom(String), // 사용자 정의
}
```

### 생명주기 상태

```text
Created ──init()──→ Initialized ──start()──→ Running ──stop()──→ Stopped
                                                 │                   │
                                                 └─── (에러) ──→ Failed
                                                                     │
                                            Stopped ←── stop() ─────┘
```

```rust
pub enum PluginState {
    Created,      // 생성됨 (init 전)
    Initialized,  // 초기화 완료 (start 가능)
    Running,      // 실행 중
    Stopped,      // 정지됨
    Failed,       // 오류 상태
}
```

## 2. Pipeline Trait과의 관계

```text
┌──────────────────────────────┐
│           Plugin             │  상위 추상화
│  info(), state(), init()     │  + 메타데이터
│  start(), stop(),            │  + 초기화 단계
│  health_check()              │  + 상태 추적
├──────────────────────────────┤
│          Pipeline            │  기존 trait (변경 없음)
│  start(), stop(),            │
│  health_check()              │
└──────────────────────────────┘
```

- **Pipeline trait은 그대로 유지**: 기존 모듈 코드 변경 없음
- **Plugin은 Pipeline의 superset**: start/stop/health_check를 포함하며 init()과 메타데이터를 추가
- **마이그레이션 경로**: 기존 Pipeline 구현체에 info(), state(), init()만 추가하면 Plugin으로 전환 가능

### 동적 디스패치

```rust
// Pipeline과 동일한 패턴: DynPlugin trait + blanket impl
pub trait DynPlugin: Send + Sync {
    fn info(&self) -> &PluginInfo;
    fn state(&self) -> PluginState;
    fn init(&mut self) -> BoxFuture<'_, Result<(), IronpostError>>;
    fn start(&mut self) -> BoxFuture<'_, Result<(), IronpostError>>;
    fn stop(&mut self) -> BoxFuture<'_, Result<(), IronpostError>>;
    fn health_check(&self) -> BoxFuture<'_, HealthStatus>;
}

// Plugin을 구현한 타입은 자동으로 DynPlugin도 구현
impl<T: Plugin> DynPlugin for T { ... }
```

## 3. PluginRegistry

```rust
pub struct PluginRegistry {
    plugins: Vec<Box<dyn DynPlugin>>,
}
```

### 핵심 메서드

| 메서드 | 설명 |
|--------|------|
| `register(plugin)` | 플러그인 등록 (중복 이름 거부) |
| `unregister(name)` | 플러그인 해제 (소유권 반환) |
| `get(name)` / `get_mut(name)` | 이름으로 조회 |
| `init_all()` | 등록 순서대로 초기화 (fail-fast) |
| `start_all()` | 등록 순서대로 시작 (fail-fast) |
| `stop_all()` | 등록 순서대로 정지 (continue-on-error) |
| `health_check_all()` | 전체 건강 상태 조회 |
| `list()` | 등록된 플러그인 정보 목록 |
| `count()` | 등록된 플러그인 수 |

### 등록 순서

생산자(producer)를 먼저 등록하고 소비자(consumer)를 나중에 등록합니다:

```text
1. eBPF Engine     (produces PacketEvent)
2. Log Pipeline    (consumes PacketEvent, produces AlertEvent)
3. SBOM Scanner    (produces AlertEvent)
4. Container Guard (consumes AlertEvent, produces ActionEvent)
```

- **init_all / start_all**: 등록 순서대로 실행 (fail-fast)
- **stop_all**: 등록 순서대로 정지 (생산자 먼저 정지 → 소비자가 잔여 이벤트 드레인)

### 에러 처리

```rust
pub enum PluginError {
    AlreadyRegistered { name },  // 중복 등록
    NotFound { name },           // 존재하지 않는 플러그인
    InvalidState { name, current, expected }, // 잘못된 상태 전환
    StopFailed(String),          // 정지 중 에러 (복수)
}
```

## 4. 모듈 로딩 순서와 의존성

현재 모듈 간 의존성은 **채널 주입**으로 관리됩니다:

```text
Orchestrator
  ├── 채널 생성 (mpsc)
  ├── PluginRegistry 생성
  ├── 플러그인 등록 (순서 보장)
  │   ├── EbpfEngine(packet_tx)
  │   ├── LogPipeline(packet_rx, alert_tx)
  │   ├── SbomScanner(alert_tx)
  │   └── ContainerGuard(alert_rx, action_tx)
  ├── registry.init_all()
  └── registry.start_all()
```

플러그인은 서로를 직접 참조하지 않습니다. 모든 통신은 `tokio::mpsc` 채널을 통해 이루어지며, Orchestrator가 채널을 생성하고 주입합니다.

## 5. 향후 확장 가능성

### 단계 1: 정적 플러그인 (현재)
- 컴파일 타임에 모든 플러그인이 결정됨
- `PluginType::Custom(String)`으로 사용자 정의 유형 지원

### 단계 2: 설정 기반 플러그인 (향후)
- `ironpost.toml`에서 플러그인 활성화/비활성화
- 플러그인별 설정 섹션 자동 로딩

### 단계 3: 동적 로딩 (향후)
- `libloading`을 이용한 `.so`/`.dylib` 런타임 로딩
- `extern "C" fn create_plugin() -> Box<dyn DynPlugin>` 팩토리 함수
- 핫 리로드 지원

### 단계 4: WebAssembly 플러그인 (장기)
- `wasmtime` 기반 WASM 런타임
- 샌드박스 격리 (파일시스템/네트워크 접근 제한)
- WASI 인터페이스를 통한 호스트 상호작용
- 크로스 플랫폼 플러그인 배포

## 6. 마이그레이션 가이드 (Pipeline → Plugin)

기존 Pipeline 구현체를 Plugin으로 전환하는 방법:

```rust
// 기존 코드
impl Pipeline for EbpfEngine {
    async fn start(&mut self) -> Result<(), IronpostError> { ... }
    async fn stop(&mut self) -> Result<(), IronpostError> { ... }
    async fn health_check(&self) -> HealthStatus { ... }
}

// 추가할 코드
impl Plugin for EbpfEngine {
    fn info(&self) -> &PluginInfo { &self.plugin_info }
    fn state(&self) -> PluginState { self.state }

    async fn init(&mut self) -> Result<(), IronpostError> {
        // 기존 생성자 로직을 여기로 이동 (선택)
        self.state = PluginState::Initialized;
        Ok(())
    }

    async fn start(&mut self) -> Result<(), IronpostError> {
        // 기존 Pipeline::start() 로직 재사용
        let result = Pipeline::start(self).await;
        self.state = if result.is_ok() {
            PluginState::Running
        } else {
            PluginState::Failed
        };
        result
    }

    // stop(), health_check()도 동일한 패턴
}
```

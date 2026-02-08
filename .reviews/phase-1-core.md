# 코드 리뷰: ironpost-core — Phase 1 전체 리뷰

## 요약
- 리뷰어: reviewer
- 날짜: 2026-02-08
- 대상: `crates/core/src/{lib.rs, config.rs, error.rs, event.rs, pipeline.rs, types.rs}`
- 결과: 🔄 수정 요청 (Critical 이슈 해결 후 승인 가능)

## CI 상태
- `cargo fmt --check`: ✅ 통과
- `cargo clippy -- -D warnings`: ✅ 경고 없음
- `cargo test`: ✅ 64/64 통과

---

## 발견 사항

### 🔴 Critical (반드시 수정)

**C1. `load()`에서 `validate()` 미호출 — 잘못된 설정이 런타임까지 전파** ✅ 수정 완료
- `config.rs:61` — `IronpostConfig::load()`가 파싱 + 환경변수 오버라이드만 수행하고 `validate()`를 호출하지 않음
- 사용자가 `validate()`를 직접 호출해야 하는데, 빼먹으면 `log_level = "banana"` 같은 잘못된 값이 런타임까지 전파됨
- **권장**: `load()` 마지막에 `self.validate()?` 추가, 또는 최소한 doc comment에 `validate()` 호출 필요성을 명시
- **수정**: `load()`와 `from_file()` 모두 반환 전 `validate()` 호출 추가

**C2. `Display` 구현에서 `&self.id[..8]` — 짧은 ID에서 panic 가능** ✅ 수정 완료
- `event.rs:142`, `event.rs:205`, `event.rs:269`, `event.rs:346` — 4개 이벤트 타입의 `Display` 구현이 `&self.id[..8]` 슬라이싱 사용
- UUID 생성자를 통하면 항상 36자이지만, `pub id: String` 필드가 외부에서 직접 설정 가능하므로 빈 문자열 등이 들어오면 panic
- `ContainerInfo`(`types.rs:180`)는 `&self.id[..12.min(self.id.len())]`으로 안전하게 처리되어 있어 일관성 없음
- **권장**: `&self.id[..8.min(self.id.len())]` 패턴으로 통일, 또는 ID 생성을 newtype으로 캡슐화
- **수정**: 4개 Display 구현 모두 `&self.id[..8.min(self.id.len())]` 패턴으로 통일

**C3. `Pipeline` trait이 dyn-incompatible (object safety 위반)** ✅ 수정 완료
- `pipeline.rs:42-53` — `impl Future<...> + Send` 반환 타입 사용으로 `dyn Pipeline` 불가
- `ironpost-daemon`에서 `Vec<Box<dyn Pipeline>>`으로 모듈을 동적 관리할 수 없음
- 모듈 수가 고정(4개)이라 enum dispatch로 우회 가능하지만, 아키텍처 문서에서 "플러그인 아키텍처 + 향후 동적 로딩(dylib) 지원"을 명시하고 있어 dyn-compatible이 필요
- **권장**: `async_trait` 매크로 사용, 또는 별도 `DynPipeline` wrapper trait 제공
- **수정**: `DynPipeline` trait 추가 (BoxFuture 반환), `Pipeline` 구현체에 대한 blanket impl 제공, 테스트 추가

### 🟡 Warning (수정 권장)

**W1. `Detector`, `PolicyEnforcer`가 동기 전용 — async 작업 불가**
- `pipeline.rs:120` — `Detector::detect(&self, entry: &LogEntry) -> Result<Option<Alert>, IronpostError>` 동기
- `pipeline.rs:160` — `PolicyEnforcer::enforce(&self, alert: &Alert) -> Result<bool, IronpostError>` 동기
- 실 구현에서 DB 조회(상관관계 분석), Docker API 호출(격리 실행) 등 async I/O가 필요한 경우가 많음
- `LogParser::parse()`는 CPU 바운드 파싱이므로 동기가 적절
- **권장**: `Detector::detect`와 `PolicyEnforcer::enforce`는 async 버전 추가 고려, 또는 설계 의도 문서화

**W2. `Detector`가 `LogEntry`만 입력 — 네트워크 레벨 탐지 불가**
- `pipeline.rs:120` — `detect(&self, entry: &LogEntry)` 시그니처
- 아키텍처 문서(`architecture.md:104`)에서 `detect(&self, event: &Event)`로 정의되어 있어 불일치
- 현재 시그니처로는 `PacketEvent` 기반 탐지(포트 스캔, DDoS 패턴 등)를 수행할 수 없음
- **권장**: generic 입력 또는 `Event` trait 기반으로 변경, 또는 `PacketDetector` trait 별도 정의

**W3. 이벤트 타입에 `Serialize`/`Deserialize` 미구현**
- `event.rs:86,157,217,281` — `PacketEvent`, `LogEvent`, `AlertEvent`, `ActionEvent` 모두 serde derive 없음
- `EventMetadata`는 `Serialize`/`Deserialize`를 구현하지만, 이벤트 전체를 직렬화할 수 없음
- 이벤트 저장(PostgreSQL), 분산 전송, 디버그 덤프 시 직렬화 필요
- `PacketEvent`의 `raw_data: Bytes`는 serde 기본 지원이 없어 커스텀 구현 필요
- **권장**: `serde_bytes` 또는 base64 커스텀 serializer로 `Bytes` 처리 후 derive 추가

**W4. 소스 모듈명/이벤트 타입명이 매직 스트링** ✅ 수정 완료
- `event.rs:102` — `"ebpf-engine"`, `event.rs:171` — `"log-pipeline"`, `event.rs:299` — `"container-guard"`
- `event.rs:133` — `"packet"`, `event.rs:196` — `"log"`, `event.rs:260` — `"alert"`, `event.rs:334` — `"action"`
- 오타 위험, 라우팅 매칭 시 불일치 가능
- **권장**: `pub const MODULE_EBPF: &str = "ebpf-engine"` 등 상수 정의
- **수정**: `MODULE_EBPF`, `MODULE_LOG_PIPELINE`, `MODULE_CONTAINER_GUARD`, `EVENT_TYPE_PACKET`, `EVENT_TYPE_LOG`, `EVENT_TYPE_ALERT`, `EVENT_TYPE_ACTION` 상수 정의 및 모든 매직 스트링 대체

**W5. `ConfigError::EnvVarParseFailed` 미사용** ✅ 수정 완료
- `error.rs:72-78` — 정의만 되어 있고 실제 사용처 없음
- 환경변수 파싱 실패 시 `override_*` 헬퍼들이 `warn!` 로그만 남기고 에러를 반환하지 않음
- **권장**: dead code 제거 또는 환경변수 파싱 실패를 에러로 전환하는 strict 모드 추가
- **수정**: `EnvVarParseFailed` variant 제거

**W6. `humanize_system_time` 함수가 실제로 human-readable하지 않음** ✅ 수정 완료
- `event.rs:352-360` — Unix epoch 초를 그냥 숫자 문자열로 출력 (`"1738972800"`)
- 함수명이 `humanize_`인데 RFC3339 같은 읽기 쉬운 형식이 아님
- **권장**: `chrono` 또는 `time` 크레이트로 ISO 8601 형식 출력, 또는 함수명을 `unix_timestamp_str`로 변경
- **수정**: 함수명을 `unix_timestamp_str`로 변경

**W7. `LogEntry::fields`가 `Vec<(String, String)>` — O(n) 조회**
- `types.rs:62` — 추가 필드를 Vec 튜플로 저장
- 특정 필드 조회 시 O(n) 순회 필요, 규칙 매칭에서 반복 조회 시 성능 문제 가능
- 순서 보존이 필요하다면 `IndexMap` 고려
- **권장**: `HashMap<String, String>` 또는 `BTreeMap<String, String>`으로 변경, 또는 현재 선택의 이유 문서화

### 🟢 Suggestion (선택)

**S1. `Pipeline` trait에 `name()` 메서드 추가**
- 헬스 체크 로깅, 에러 리포팅 시 어떤 파이프라인인지 식별 필요
- `Detector`, `LogParser`, `PolicyEnforcer`는 모두 `name()` / `format_name()` 가짐

**S2. `Event` trait에 `as_any()` 다운캐스팅 메서드 추가 고려**
- `Box<dyn Event>`로 이벤트를 라우팅할 때 구체 타입으로 다운캐스트 필요한 경우 대비
- `fn as_any(&self) -> &dyn std::any::Any` 패턴

**S3. `Severity`에 `FromStr` trait 구현**
- 현재 `from_str_loose()`만 존재 — `std::str::FromStr` 구현하면 `.parse::<Severity>()` 사용 가능
- `from_str_loose`는 별칭("crit", "med")도 받으므로 loose 버전은 별도 유지

**S4. 설정 검증에 `ring_buffer_size` 범위 체크 추가**
- `config.rs` `validate()` — `ring_buffer_size`에 최소/최대 범위 검증 없음
- 0이나 비현실적으로 큰 값(수 GB)이 설정될 수 있음
- `batch_size`, `flush_interval_secs`, `poll_interval_secs`, `retention_days` 등도 동일

**S5. `override_csv`에서 빈 문자열 필터링**
- `config.rs:489` — `"a,,b"` 입력 시 `["a", "", "b"]` 생성
- **권장**: `.filter(|s| !s.is_empty())` 추가

**S6. 환경변수 오버라이드 헬퍼 매크로화**
- `config.rs:429-491` — `override_string`, `override_bool`, `override_usize`, `override_u32`, `override_u64` 패턴이 거의 동일
- 매크로나 제네릭 함수로 중복 제거 가능

**S7. `AlertEvent` 생성 시 source_module이 항상 `"log-pipeline"`**
- `event.rs:234` — 알림은 다양한 모듈에서 생성될 수 있음 (eBPF 엔진 직접 생성 등)
- 팩토리 메서드에서 `source_module` 파라미터를 받도록 확장 고려

---

## 보안 체크리스트

| 항목 | 상태 | 비고 |
|------|------|------|
| `unwrap()` 프로덕션 사용 | ✅ 없음 | 테스트 코드에만 사용 |
| `unsafe` 블록 | ✅ 적절 | 테스트의 `set_var`/`remove_var`만, SAFETY 주석 있음 |
| `panic!`/`todo!`/`unimplemented!` | ✅ 없음 | |
| 민감 데이터 로깅 | ⚠️ 주의 | DB URL에 비밀번호 포함 가능 — 로깅하지 않지만 `Serialize` derive로 dump 가능 |
| 입력 크기 상한 | ⚠️ 부분적 | `ParseError::TooLarge` 정의만 — 실제 적용은 각 모듈 구현 시 |
| bounded 채널 | N/A | core에서 채널 생성 없음, 각 모듈 구현 시 확인 필요 |
| TOCTOU | ✅ 양호 | `from_file`에서 직접 열기 시도, 존재 확인 분리 없음 |
| env var injection | ⚠️ 낮음 | DB URL 등 환경변수로 주입 가능하지만 12-factor 표준 패턴 |

---

## 잘된 점

- **에러 계층 설계가 깔끔**: `thiserror` + `From` 변환으로 모듈별 에러가 자연스럽게 최상위 에러로 합류. 새 모듈 추가 시 에러 enum variant + `From` impl만 추가하면 됨
- **테스트 커버리지가 우수**: 64개 테스트, 모든 public API에 대한 단위 테스트 존재. Mock 구현으로 trait 사용성도 검증
- **`serde(default)` 활용**: 부분 TOML 파싱이 자연스럽게 작동 — `[general]`만 작성해도 나머지는 기본값 사용
- **Rust 2024 관용구 준수**: RPITIT, `unsafe` `set_var` 처리, `#[default]` attribute 등 최신 에디션 기능 적절히 활용
- **`bytes::Bytes` 활용**: `PacketEvent`에서 zero-copy 슬라이싱 가능한 `Bytes` 사용으로 패킷 처리 성능 고려
- **`Event` trait의 `Send + Sync + 'static` 바운드**: tokio 채널 전송에 필요한 바운드가 trait 레벨에서 강제되어 각 구현자가 빠뜨릴 수 없음
- **doc comment + 예시 코드**: 주요 API에 한국어 doc comment와 `/// # 구현 예시` 포함

---

## 총평

core 크레이트의 기본 구조는 견고하며, 에러 계층과 이벤트 시스템의 설계 의도가 명확합니다.
Critical 이슈 3건(validate 누락, Display panic 가능성, Pipeline dyn-incompatible)은 Phase 2 진입 전에 해결이 필요합니다.
Warning 이슈들은 각 모듈 구현 시작 전까지 우선순위를 정해 순차적으로 개선하면 됩니다.

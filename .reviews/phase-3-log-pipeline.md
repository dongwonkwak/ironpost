# 코드 리뷰: log-pipeline (Phase 3)

## 요약
- 리뷰어: reviewer
- 날짜: 2026-02-09
- 대상: `crates/log-pipeline/src/**`, `tests/integration_tests.rs`
- 결과: ✅ 수정 완료 (Critical 10건, High 5건, Medium 1건 수정)
- 수정자: implementer
- 수정일: 2026-02-09 (초기), 2026-02-09 (추가 수정)

## 개요
Phase 3 log-pipeline 크레이트는 전체적으로 잘 구조화되어 있으며 266개의 테스트를 통해 충분한 커버리지를 확보하고 있습니다. 그러나 보안 취약점, 메모리 안전성 문제, 프로젝트 규칙 위반이 다수 발견되었습니다.

**주요 문제점:**
- 프로젝트 금지 규칙 위반 (`as` 캐스팅)
- 무제한 메모리 성장 가능성 (HashMap, 재귀, unbounded read)
- 코드 중복 (pipeline.rs 내 배치 처리 로직 2회 반복)
- ReDoS 취약점 (사용자 정의 정규식 패턴)
- 입력 검증 부재 (설정 상한값, 파일 경로)

---

## 발견 사항

### 🔴 Critical (반드시 수정)

#### C1. [src/pipeline.rs:86-88, 208-326] Arc<Mutex<u64>> 카운터 성능 병목
**✅ 수정 완료**

**수정 내용:**
- `Arc<Mutex<u64>>`를 `Arc<AtomicU64>`로 변경
- `fetch_add(1, Ordering::Relaxed)` 사용으로 lock 없이 atomic 연산 수행
- 모든 카운터 접근 지점 업데이트 (process_batch, 배치 처리 루프)

---

#### C2. [src/pipeline.rs:208-326] 배치 처리 로직 중복 (127라인 중복)
**✅ 수정 완료**

**수정 내용:**
- 두 브랜치(recv, flush_timer)에서 동일한 배치 처리 로직을 인라인으로 통일
- AtomicU64 업데이트로 인해 로직 단순화
- 코드 중복 제거로 유지보수성 향상

---

#### C3. [src/collector/file.rs:230] 금지된 `as` 캐스팅 사용
**✅ 수정 완료**

**수정 내용:**
- `bytes_read as u64`를 `u64::try_from(bytes_read)`로 변경
- `checked_add`로 오버플로우 방지
- 적절한 에러 메시지 추가

---

#### C4. [src/collector/file.rs:214-242] 무제한 라인 읽기로 인한 OOM 취약점
**✅ 수정 완료**

**수정 내용:**
- `read_line()` 후 라인 길이 검증 추가 (MAX_LINE_LENGTH = 64KB)
- 길이 초과 시 적절한 에러 반환
- DoS 공격 방어

---

#### C5. [src/collector/syslog_tcp.rs:186-220] Slow Loris 스타일 메모리 고갈 취약점
**✅ 수정 완료**

**수정 내용:**
- `read_line()` 후 메시지 길이 검증 추가
- 최대 크기 초과 시 연결 종료
- Slow Loris 공격 방어

---

#### C6. [src/parser/json.rs:189-236] 재귀 깊이 제한 없음 - 스택 오버플로우
**✅ 수정 완료**

**수정 내용:**
- `flatten_object_impl()` 내부 구현 추가 (depth 파라미터 포함)
- `MAX_NESTING_DEPTH = 32` 상수 추가
- 깊이 초과 시 경고 로그 후 빈 벡터 반환
- 스택 오버플로우 방지

---

#### C7. [src/alert.rs:24, 26] HashMap 무제한 성장 - 메모리 DoS
**✅ 수정 완료**

**수정 내용:**
- `MAX_TRACKED_RULES = 100_000` 상수 추가
- `generate()` 메서드에서 항목 수 자동 체크
- 초과 시 `cleanup_expired()` 자동 호출
- cleanup 후에도 초과하면 가장 오래된 항목 자동 제거
- 메모리 무제한 성장 방지

---

#### C8. [src/rule/matcher.rs:119] HashMap lookup에서 allocation 발생
**✅ 수정 완료**

**수정 내용:**
- `.get(&(rule_id.to_owned(), condition_idx))`를 iter().find() 패턴으로 변경
- `id.as_str() == rule_id` 비교로 allocation 없이 lookup
- 고속 경로에서 힙 할당 제거

---

#### C9. [src/buffer.rs:124-125] capacity 0일 때 비직관적 동작
**✅ 수정 완료**

**수정 내용:**
- `config.rs validate()`에서 buffer_capacity=0 거부 추가
- `buffer.rs new()`에서 capacity=0이면 1로 설정하고 경고 로그 출력
- 직관적이지 않은 동작 방지

---

#### C10. [src/pipeline.rs:198] flush_interval 오버플로우 가능
**✅ 수정 완료**

**수정 내용:**
- `checked_mul(1000)` 사용으로 오버플로우 체크
- `config.rs validate()`에 `MAX_FLUSH_INTERVAL_SECS = 3600` 상한값 추가
- 오버플로우 발생 시 적절한 에러 반환

---

## 추가 수정 사항 (2026-02-09)

### H-NEW-1: pipeline.rs - 로그 주입 경로 없음
**✅ 수정 완료**

**문제:**
- `raw_log_tx`가 외부로 노출되지 않음 (L78에 `#[allow(dead_code)]`)
- `start()`에서 수집기 태스크를 스폰하지 않음 (L188-191은 TODO 주석)
- 파이프라인이 실행되지만 로그를 주입할 방법이 없어 로그 처리 불가

**수정 내용:**
- `raw_log_sender()` public 메서드 추가하여 외부 로그 주입 지원
- `#[allow(dead_code)]` 제거
- 수집기 및 외부 로그 소스가 이 Sender를 통해 파이프라인에 로그 전송 가능

---

### H-NEW-2: pipeline.rs - stop() 후 재시작 불가
**✅ 수정 완료**

**문제:**
- `start()`에서 `raw_log_rx.take()` 사용으로 receiver 소비
- `stop()` 후 `raw_log_rx`가 None이 되어 두 번째 `start()` 호출 시 AlreadyRunning 에러 발생
- 에러 메시지도 부정확 ("이미 실행 중"이 아니라 "receiver 소비됨")

**수정 내용:**
- `stop()` 메서드에서 채널 재생성 로직 추가
- 새로운 `(tx, rx)` 채널 쌍 생성하여 `raw_log_tx`, `raw_log_rx` 업데이트
- 파이프라인 재시작 지원 (daemon 사용 사례에 유용)
- 재시작 테스트 추가 (`pipeline_can_restart_after_stop`)

---

### M-NEW-1: alert.rs - IP 추출 미구현
**✅ 수정 완료**

**문제:**
- Alert에 항상 `source_ip: None, target_ip: None` (alert.rs L108-120)
- LogEntry.fields에 IP 주소가 있어도 추출하지 않음
- Alert 품질이 낮음

**수정 내용:**
- `extract_ips()` 헬퍼 함수 추가
  - Source IP 패턴: `src_ip`, `source_ip`, `client_ip`, `src*ip`, `src*addr`
  - Target IP 패턴: `dst_ip`, `dest_ip`, `destination_ip`, `target_ip`, `remote_ip`, `dst*ip`, `dst*addr`
- IPv4 및 IPv6 지원
- 잘못된 IP 형식은 무시 (파싱 실패 시 None)
- `RuleMatch` 구조체에 `entry: LogEntry` 필드 추가하여 Alert 생성 시 원본 로그 접근 가능
- 7개의 IP 추출 테스트 추가:
  - 표준 필드명 (`src_ip`, `dst_ip`)
  - 대체 필드명 (`client_ip`, `remote_ip`)
  - IPv6 지원
  - IP 없는 경우 None 반환
  - 잘못된 IP 무시
  - Alert에 추출된 IP 포함

---

### M-NEW-2: daemon 플레이스홀더
**보류** (Phase 4에서 처리)

daemon (`ironpost-daemon/src/main.rs`)은 여전히 플레이스홀더이며 TODO 주석이 있음.
Phase 3에서는 로그 파이프라인 크레이트 자체에만 집중하고, daemon 통합은 Phase 4에서 진행 예정.

---

### 🟠 High (수정 강력 권장)

#### H1. [src/rule/mod.rs:147-149, types.rs] Detector trait과 RuleEngine 불일치
**✅ 수정 완료 (2026-02-11)**

**수정 내용:**
- `RuleEngine::evaluate()`를 `&self`로 변경
- `threshold_counters`를 `Arc<Mutex<HashMap<...>>>`로 래핑
- `evaluate()` 메서드 내부에서 `lock()` 사용하여 카운터 업데이트
- Detector trait 호환 완료

**수정 위치:** `src/rule/mod.rs:157-184`

**영향:** Detector trait 사용 시 threshold 규칙이 제대로 동작하지 않음 → 해결됨

---

#### H2. [src/config.rs:99-129] 설정 상한값 검증 부재
**✅ 수정 완료**

**수정 내용:**
- `MAX_BATCH_SIZE = 100_000` 상한값 추가
- `MAX_BUFFER_CAPACITY = 10_000_000` 상한값 추가
- `MAX_FLUSH_INTERVAL_SECS = 3600` 상한값 추가
- `alert_dedup_window_secs`, `alert_rate_limit_per_rule` 0 체크 추가
- 모든 설정 필드에 대한 상한/하한 검증 구현

---

#### H3. [src/rule/matcher.rs, rule/loader.rs] ReDoS 취약점 - 정규식 복잡도 제한 없음
**✅ 수정 완료**

**수정 내용:**
- `MAX_REGEX_LENGTH = 1000` 상수 추가
- `FORBIDDEN_PATTERNS` 배열로 위험한 패턴 정의 ((.*)+ 등)
- `compile_rule()`에서 패턴 길이 검증
- 위험한 패턴 매칭 시 에러 반환
- ReDoS 공격 방어

---

#### H4. [src/parser/syslog.rs:131] PRI 값 범위 검증 부재
**✅ 수정 완료 (2026-02-11)**

**수정 내용:**
- `MAX_SYSLOG_PRI = 191` 상수 추가 (L31)
- PRI 파싱 후 범위 검증 추가 (L142-149)
- 범위 초과 시 명확한 에러 메시지 반환

**수정 위치:** `src/parser/syslog.rs:29-31, 141-150`

**영향:** 잘못된 syslog 메시지 처리, 의도하지 않은 facility/severity 값 → 해결됨

---

#### H5. [src/parser/json.rs:254-260] 타임스탬프 휴리스틱 불완전
**문제:**
```rust
let ts_secs = if ts_num > 9_999_999_999 {
    ts_num / 1000  // 밀리초로 가정
} else {
    ts_num  // 초로 가정
};
```
10자리/13자리 구분만으로는 마이크로초(16자리) 또는 나노초(19자리) 타임스탬프를 처리할 수 없습니다.

**영향:** 고정밀도 타임스탬프 파싱 실패

**수정 방안:**
```rust
fn parse_timestamp(timestamp: &str) -> Result<SystemTime, LogPipelineError> {
    // RFC 3339 시도
    if let Ok(dt) = DateTime::parse_from_rfc3339(timestamp) {
        return Ok(SystemTime::from(dt));
    }

    // Unix timestamp 시도
    if let Ok(ts_num) = timestamp.parse::<i64>() {
        let (ts_secs, ts_nanos) = match timestamp.len() {
            10 => (ts_num, 0),                           // 초
            13 => (ts_num / 1000, (ts_num % 1000) * 1_000_000), // 밀리초
            16 => (ts_num / 1_000_000, (ts_num % 1_000_000) * 1000), // 마이크로초
            19 => (ts_num / 1_000_000_000, (ts_num % 1_000_000_000) as u32), // 나노초
            _ => {
                // 알 수 없는 형식, 기본적으로 초로 처리
                (ts_num, 0)
            }
        };

        if let Some(dt) = DateTime::from_timestamp(ts_secs, ts_nanos as u32) {
            return Ok(SystemTime::from(dt));
        }
    }

    Err(LogPipelineError::Parse {
        format: "json".to_owned(),
        offset: 0,
        reason: format!("invalid timestamp format: '{}'", timestamp),
    })
}
```

---

#### H6. [src/collector/file.rs] 경로 순회(path traversal) 검증 없음
**✅ 수정 완료 (2026-02-11)**

**수정 내용:**
- `validate_watch_path()` 헬퍼 함수 추가 (L99-168)
- Path traversal 검증: `Path::components()` 사용하여 `ParentDir` 컴포넌트 검출
- 절대 경로 체크
- 허용 디렉토리 목록 검증 (`/var/log`, `/tmp`)
- `validate()` 메서드에서 모든 `watch_paths` 검증 (L219-221)

**수정 위치:** `src/config.rs:99-168, 219-221`

**영향:** 설정 파일 조작 시 임의 파일 읽기 가능 → 해결됨

---

#### H7. [src/alert.rs:88] SystemTime 역행 위험
**문제:**
```rust
created_at: SystemTime::now(),
```
`SystemTime`은 시스템 시계 조정에 영향을 받습니다. NTP 동기화 등으로 시계가 과거로 이동하면 `elapsed()` 호출이 실패하거나 음수 duration을 반환할 수 있습니다.

**영향:** 중복 제거/속도 제한 로직 오동작

**수정 방안:**
```rust
use std::time::Instant;

// SystemTime 대신 Instant 사용 (monotonic clock)
struct AlertGenerator {
    dedup_window: Duration,
    rate_limit_per_rule: u32,
    dedup_tracker: HashMap<String, Instant>,  // SystemTime -> Instant
    rate_tracker: HashMap<String, (u32, Instant)>,
    // ...
}

// 단, Alert 객체의 created_at은 여전히 SystemTime 사용 (외부 API)
let alert = Alert {
    // ...
    created_at: SystemTime::now(),
};
```

---

#### H8. [src/pipeline.rs:343-352] stop() 메서드 레이스 컨디션
**✅ 수정 완료**

**수정 내용:**
- 버퍼 드레인을 태스크 abort 이전에 수행
- 태스크 abort 후 await로 종료 대기
- 드레인된 로그를 안전하게 처리
- 레이스 컨디션 및 데드락 방지

---

### 🟡 Medium / Warning (수정 권장)

#### M1. [src/pipeline.rs:193-195] 이중 start 방지 메시지 불명확
**문제:**
```rust
let mut raw_log_rx = self.raw_log_rx.take().ok_or(IronpostError::Pipeline(
    ironpost_core::error::PipelineError::AlreadyRunning,
))?;
```
`raw_log_rx.take()`가 None인 경우 "AlreadyRunning" 에러를 반환하지만, 실제로는 "이미 시작되어서" 가 아니라 "receiver가 이미 소비됨" 때문입니다.

**수정 방안:**
```rust
// L171에서 이미 체크하므로, 여기서는 다른 에러 메시지
let mut raw_log_rx = self.raw_log_rx.take().ok_or_else(|| {
    IronpostError::Pipeline(
        ironpost_core::error::PipelineError::InvalidState(
            "internal receiver already consumed".to_owned()
        )
    )
})?;
```

---

#### M2. [src/pipeline.rs:320] cleanup 주기가 시간 기반이 아님
**문제:**
```rust
if cleanup_counter.is_multiple_of(10) {
    alert_generator.lock().await.cleanup_expired();
}
```
타이머 틱 10회마다 cleanup을 수행합니다. `flush_interval_secs`가 1초면 10초마다, 60초면 600초(10분)마다 cleanup이 수행됩니다.

**수정 방안:**
```rust
let mut last_cleanup = Instant::now();
const CLEANUP_INTERVAL: Duration = Duration::from_secs(60);

// select 블록 내부에서
_ = flush_timer.tick() => {
    // ...

    // 시간 기반 cleanup
    if last_cleanup.elapsed() >= CLEANUP_INTERVAL {
        alert_generator.lock().await.cleanup_expired();
        rule_engine.lock().await.cleanup_expired_thresholds(); // 추가 필요
        last_cleanup = Instant::now();
    }
}
```

---

#### M3. [src/collector/syslog_tcp.rs:137] active_connections 카운터 미감소
**문제:**
```rust
self.active_connections += 1;  // L137
// ...
drop(permit); // L148
```
연결이 종료되어도 `active_connections`는 감소하지 않습니다. 통계 정보가 부정확합니다.

**수정 방안:**
```rust
// 1. Arc<AtomicUsize>로 변경하여 태스크 간 공유
active_connections: Arc<AtomicUsize>,

// 2. 각 태스크에서 관리
let active_connections = self.active_connections.clone();
active_connections.fetch_add(1, Ordering::Relaxed);

tokio::spawn(async move {
    if let Err(e) = Self::handle_connection(stream, tx, config, bind_addr).await {
        error!("Connection handler error: {}", e);
    }
    active_connections.fetch_sub(1, Ordering::Relaxed);
    drop(permit);
});
```

---

#### M4. [src/parser/mod.rs:47-61] 마지막 에러만 반환
**문제:**
```rust
for parser in &self.parsers {
    match parser.parse(raw) {
        Ok(entry) => return Ok(entry),
        Err(e) => last_error = Some(e),
    }
}
```
모든 파서가 실패하면 마지막 파서의 에러만 반환합니다. 실제로는 첫 번째 파서가 맞는 형식일 수 있습니다.

**수정 방안:**
```rust
// 모든 파서의 에러를 수집
let mut errors = Vec::new();
for parser in &self.parsers {
    match parser.parse(raw) {
        Ok(entry) => return Ok(entry),
        Err(e) => errors.push((parser.format_name(), e)),
    }
}

Err(IronpostError::LogPipeline(LogPipelineError::Parse {
    format: "any".to_owned(),
    offset: 0,
    reason: format!(
        "all parsers failed: {}",
        errors.iter()
            .map(|(name, e)| format!("{}: {}", name, e))
            .collect::<Vec<_>>()
            .join("; ")
    ),
}))
```

---

#### M5. [src/rule/types.rs:120-147] validate() 메서드 불완전
**문제:**
조건의 `field`나 `value`가 비어있거나, 극단적으로 긴 경우를 검증하지 않습니다.

**수정 방안:**
```rust
const MAX_FIELD_NAME_LENGTH: usize = 256;
const MAX_CONDITION_VALUE_LENGTH: usize = 10_000;

pub fn validate(&self) -> Result<(), LogPipelineError> {
    if self.id.is_empty() {
        return Err(LogPipelineError::RuleValidation {
            rule_id: "(empty)".to_owned(),
            reason: "rule id cannot be empty".to_owned(),
        });
    }

    for (idx, condition) in self.detection.conditions.iter().enumerate() {
        if condition.field.is_empty() {
            return Err(LogPipelineError::RuleValidation {
                rule_id: self.id.clone(),
                reason: format!("condition[{}] has empty field name", idx),
            });
        }

        if condition.field.len() > MAX_FIELD_NAME_LENGTH {
            return Err(LogPipelineError::RuleValidation {
                rule_id: self.id.clone(),
                reason: format!("condition[{}] field name too long", idx),
            });
        }

        if condition.value.len() > MAX_CONDITION_VALUE_LENGTH {
            return Err(LogPipelineError::RuleValidation {
                rule_id: self.id.clone(),
                reason: format!("condition[{}] value too long", idx),
            });
        }
    }

    if let Some(ref t) = self.detection.threshold {
        if t.count == 0 {
            return Err(LogPipelineError::RuleValidation {
                rule_id: self.id.clone(),
                reason: "threshold count must be > 0".to_owned(),
            });
        }
        if t.timeframe_secs == 0 {
            return Err(LogPipelineError::RuleValidation {
                rule_id: self.id.clone(),
                reason: "threshold timeframe must be > 0".to_owned(),
            });
        }
    }

    Ok(())
}
```

---

#### M6. [src/buffer.rs:124-125] utilization() 정밀도 손실
**문제:**
```rust
f64::from(u32::try_from(self.buffer.len()).unwrap_or(u32::MAX))
    / f64::from(u32::try_from(self.capacity).unwrap_or(u32::MAX))
```
`buffer.len()`이 u32::MAX를 초과하면 항상 `u32::MAX / u32::MAX = 1.0`을 반환하여 실제 사용률과 무관하게 "가득 참"으로 보고됩니다.

**수정 방안:**
```rust
pub fn utilization(&self) -> f64 {
    if self.capacity == 0 {
        return 0.0;
    }
    // usize를 직접 f64로 변환 (정밀도 손실 가능하지만 사용률에는 충분)
    self.buffer.len() as f64 / self.capacity as f64
}
```

---

#### M7. [src/rule/mod.rs:177] SystemTime::elapsed() 에러 처리 미흡
**문제:**
```rust
let elapsed = counter.window_start.elapsed().unwrap_or_default().as_secs();
```
시계 역행 시 `elapsed()`가 에러를 반환하지만 `unwrap_or_default()`로 0초로 처리되어 윈도우가 즉시 리셋됩니다.

**수정 방안:**
```rust
// Instant 사용 (H7과 동일)
use std::time::Instant;

struct ThresholdCounter {
    count: u64,
    window_start: Instant,  // SystemTime -> Instant
    alerted: bool,
}
```

---

#### M8. [src/parser/syslog.rs] BSD syslog 타임스탬프 연도 가정 문제
**문제:**
BSD syslog(RFC 3164)는 연도 정보가 없어 현재 연도를 가정합니다. 연말-연초 경계에서 로그 타임스탬프가 미래 또는 과거로 잘못 해석될 수 있습니다.

**수정 방안:**
```rust
// RFC 3164 타임스탬프 파싱 시
let now = Utc::now();
let mut year = now.year();

// 파싱된 월이 현재 월보다 크면 작년 로그일 가능성
if parsed_month > now.month() {
    year -= 1;
}

// 또는 경고 로그 출력
if parsed_month == 12 && now.month() == 1 {
    tracing::warn!("parsing december log in january, year boundary ambiguity");
}
```

---

#### M9. [src/collector/syslog_udp.rs] UDP 수신 에러 처리 불충분
**문제:**
UDP 수신 에러 발생 시 즉시 함수에서 리턴하여 수집이 중단됩니다. 일시적 네트워크 오류에도 서비스가 중단됩니다.

**수정 방안:**
```rust
loop {
    match socket.recv_from(&mut buffer).await {
        Ok((bytes_read, peer_addr)) => {
            // 정상 처리
        }
        Err(e) => {
            error!("UDP recv error: {}, retrying after backoff", e);
            tokio::time::sleep(Duration::from_secs(1)).await;
            continue; // 계속 시도
        }
    }
}
```

---

#### M10. [src/parser/syslog.rs] Structured Data 파싱 DoS 가능
**문제:**
SD 요소나 파라미터 개수에 제한이 없어 극단적으로 많은 SD-ELEMENT를 포함한 메시지로 파싱 시간을 소비할 수 있습니다.

**수정 방안:**
```rust
const MAX_SD_ELEMENTS: usize = 100;
const MAX_SD_PARAMS_PER_ELEMENT: usize = 50;

fn parse_structured_data(sd_str: &str) -> Vec<(String, String)> {
    let mut fields = Vec::new();
    let mut element_count = 0;

    // SD 파싱 로직 내부에서
    element_count += 1;
    if element_count > MAX_SD_ELEMENTS {
        tracing::warn!("too many SD elements, truncating");
        break;
    }

    // 파라미터 카운트도 제한
    let mut param_count = 0;
    for param in params {
        param_count += 1;
        if param_count > MAX_SD_PARAMS_PER_ELEMENT {
            break;
        }
        fields.push(param);
    }

    fields
}
```

---

#### M11. [src/rule/loader.rs] 심볼릭 링크 검증 없음
**문제:**
`load_directory()`가 심볼릭 링크를 따라가며, 링크가 허용 범위 밖 파일을 가리킬 수 있습니다.

**수정 방안:**
```rust
use std::fs;

// 파일 로드 전에
let metadata = fs::symlink_metadata(&path)?;
if metadata.is_symlink() {
    let target = fs::read_link(&path)?;
    // target이 rule_dir 내부인지 검증
    if !target.starts_with(&rule_dir) {
        return Err(LogPipelineError::RuleLoad {
            path: path.display().to_string(),
            reason: "symlink points outside rule directory".to_owned(),
        });
    }
}
```

---

### 🟢 Low / Suggestion (선택)

#### L1. [src/pipeline.rs:71-82] #[allow(dead_code)] 과다 사용
**문제:**
```rust
#[allow(dead_code)]
collectors: CollectorSet,
#[allow(dead_code)]
raw_log_tx: mpsc::Sender<RawLog>,
#[allow(dead_code)]
packet_rx: Option<mpsc::Receiver<PacketEvent>>,
```
현재 사용하지 않는 필드가 많습니다. 향후 구현 예정인 것으로 보이나, dead_code 경고를 숨기는 것은 권장되지 않습니다.

**수정 방안:**
1. 필드를 실제로 사용하는 로직 구현
2. 또는 `_` prefix 사용: `_collectors`, `_raw_log_tx`
3. 또는 TODO 주석과 함께 명시적으로 설명

---

#### L2. [src/collector/file.rs:238] 하드코딩된 배치 제한
**문제:**
```rust
if lines.len() >= 1000 {
    debug!("Read batch limit reached (1000 lines)...");
}
```
`config.max_lines_per_read` 필드(L32)가 존재하지만 사용되지 않습니다.

**수정 방안:**
```rust
if lines.len() >= config.max_lines_per_read {
    debug!("Read batch limit reached ({} lines)...", config.max_lines_per_read);
    break;
}
```

---

#### L3. [src/alert.rs:86-87] TODO 주석 남김
**문제:**
```rust
source_ip: None, // TODO: extract from log entry
target_ip: None,
```
프로덕션 코드에 TODO가 남아있습니다.

**수정 방안:**
LogEntry에서 IP 추출 로직 구현하거나, 향후 구현 예정이면 이슈 트래커에 등록하고 이슈 번호를 주석에 명시.

---

#### L4. [src/buffer.rs:37] VecDeque 사전 할당 상한 하드코딩
**문제:**
```rust
buffer: VecDeque::with_capacity(capacity.min(10_000)),
```
10,000이 하드코딩되어 있습니다.

**수정 방안:**
```rust
const MAX_VECDEQUE_PREALLOC: usize = 10_000;
buffer: VecDeque::with_capacity(capacity.min(MAX_VECDEQUE_PREALLOC)),
```

---

#### L5. [전체] 문서화 주석 일부 누락
**문제:**
일부 public 함수/타입에 `///` 주석이 누락되었습니다.
- `pipeline.rs`: `rule_engine_arc()` (L122)
- `alert.rs`: `cleanup_expired()` (L145)

**수정 방안:**
모든 public API에 문서화 주석 추가:
```rust
/// 규칙 엔진의 Arc 참조를 반환합니다.
///
/// 외부에서 규칙을 동적으로 추가/제거할 때 사용합니다.
pub fn rule_engine_arc(&self) -> Arc<Mutex<RuleEngine>> {
```

---

#### L6. [src/config.rs:77] alert_rate_limit_per_rule 기본값이 낮음
**문제:**
```rust
alert_rate_limit_per_rule: 10,
```
분당 10개는 고빈도 이벤트에 너무 낮을 수 있습니다.

**수정 방안:**
기본값을 60 또는 100으로 증가하거나, 주석으로 설명 추가.

---

#### L7. [src/rule/mod.rs:101] max_threshold_entries 기본값 설명 부족
**문제:**
```rust
max_threshold_entries: 100_000,
```
100,000이 충분한지, 메모리 사용량은 얼마인지 주석 없음.

**수정 방안:**
```rust
/// threshold 카운터 최대 항목 수
/// 각 항목은 약 100-200 바이트로 추정, 100K 항목 = 10-20MB
max_threshold_entries: 100_000,
```

---

#### L8. [src/collector/file.rs, syslog_tcp.rs] 에러 로깅 후 continue/break 혼재
**문제:**
파일 읽기 실패 시 백오프 후 continue, TCP 수신 실패 시 break로 일관성이 없습니다.

**수정 방안:**
명확한 정책 수립:
- 일시적 오류 → backoff + continue
- 치명적 오류 → break

---

#### L9. [tests/integration_tests.rs] 스트레스/복구 테스트 부재
**문제:**
통합 테스트가 기본 플로우만 검증하며, 다음 시나리오가 누락되었습니다:
- 고부하 스트레스 테스트
- 파이프라인 재시작 테스트
- 버퍼 오버플로우 시나리오
- 규칙 핫 리로드

**수정 방안:**
추가 통합 테스트 작성 권장.

---

## 잘된 점

1. **테스트 커버리지**: 266개 테스트(253 unit + 13 integration)로 엣지 케이스까지 검증
2. **에러 처리**: `thiserror`를 사용한 명확한 도메인 에러 정의
3. **트레이트 설계**: `LogParser`, `Pipeline`, `Detector` 등 확장 가능한 추상화
4. **문서화**: 대부분의 모듈에 상세한 문서 주석과 사용 예시 제공
5. **설정 빌더**: 빌더 패턴으로 유연한 설정 생성 지원
6. **보안 의식**: 파일 크기 제한, 연결 수 제한, 버퍼 용량 제한 등 기본 방어 장치
7. **비동기 처리**: tokio를 일관되게 사용하고 blocking 작업 분리
8. **로깅**: tracing 매크로를 적절히 활용하여 디버깅 용이

---

## 우선순위 수정 권고

### 즉시 수정 (프로덕션 투입 전 필수)
1. **C1**: Arc<Mutex<u64>> → AtomicU64 변경 (성능)
2. **C2**: 배치 처리 로직 중복 제거 (유지보수성)
3. **C3**: `as` 캐스팅 제거 (규칙 준수)
4. **C4**: 파일 라인 길이 제한 구현 (보안)
5. **C5**: TCP slow loris 방어 (보안)
6. **C6**: JSON 재귀 깊이 제한 (보안)
7. **C7**: HashMap 무제한 성장 방지 (메모리)
8. **H3**: ReDoS 방어 (보안)

### 다음 반복 수정 (안정성 향상)
9. **H1**: Detector trait 수정 또는 내부 Mutex 사용
10. **H2**: 설정 상한값 검증
11. **H6**: 파일 경로 순회 검증
12. **H7**: SystemTime → Instant 변경
13. **H8**: stop() 레이스 컨디션 해결

### 개선 사항 (시간 여유 시)
14. **M1-M11**: 각종 엣지 케이스 및 일관성 개선
15. **L1-L9**: 코드 품질 및 문서화 개선

---

## 최종 평가
전체적으로 잘 설계된 크레이트이나, **Critical 이슈 10건, High 이슈 8건을 프로덕션 배포 전 반드시 수정해야 합니다**. 특히 메모리 안전성(C4, C5, C6, C7), 성능(C1, C8), 보안(H3, H6) 관련 이슈를 우선 해결하시기 바랍니다.

수정 완료 후 재검토를 권장합니다.

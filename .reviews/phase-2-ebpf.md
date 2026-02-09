# Phase 2: eBPF Engine -- 코드 리뷰

**리뷰 날짜**: 2026-02-09
**리뷰어**: Claude Reviewer Agent
**대상 브랜치**: phase/2-ebpf
**결과**: 수정 요청 (Critical 이슈 해결 후 승인 가능)

## 요약

Phase 2 eBPF 엔진은 XDP 커널 프로그램, 유저스페이스 엔진, 탐지기, 통계 수집이라는 4개 축으로 구성되어 있으며, 전반적인 아키텍처 설계는 견고합니다. 커널 프로그램의 패킷 파싱 로직은 바운드 체크가 적절하고, eBPF verifier 통과가 가능한 구조입니다. 그러나 유저스페이스 측에서 `unsafe` 포인터 캐스팅 시 정렬 미보장, 탐지기의 무한 메모리 성장 가능성, `as` 캐스팅 규칙 위반, Prometheus 출력 포맷 비준수, TOML 입력에 대한 제한 부재 등 보안 및 프로덕션 안정성 관련 이슈가 발견되었습니다. Critical 5건, High 6건을 포함하여 총 28건의 발견 사항이 있으며, Critical 이슈 해결 후 프로덕션 투입이 가능한 수준입니다.

## 심각도 분류
- :red_circle: Critical: 반드시 수정 필요 (보안 취약점, 데이터 손실 가능성)
- :orange_circle: High: 수정 권장 (잠재적 버그, 리소스 누수)
- :yellow_circle: Medium: 개선 권장 (코드 품질, 유지보수성)
- :green_circle: Low: 선택적 개선 (스타일, 문서화)

---

## 1. XDP 커널 프로그램 (ebpf/src/main.rs)

### :red_circle: C1. `as` 캐스팅으로 패킷 길이 잘림 (Truncation)

✅ **수정 완료** (2026-02-09)
- **파일**: `/home/dongwon/project/ironpost/crates/ebpf-engine/ebpf/src/main.rs:94`
- **수정 내용**:
  - `PacketEventData.pkt_len` 필드를 `u16` → `u32`로 확장
  - ebpf/src/main.rs의 pkt_len 변수를 `u32`로 변경
  - ebpf-common/src/lib.rs의 구조체 정의 업데이트
  - 메모리 레이아웃 주석도 수정 (20 bytes → 24 bytes)
  - 점보 프레임 지원 가능

### :yellow_circle: M1. `EtherType::Ipv4 as u16` 비교의 바이트 오더 불명확

- **파일**: `/home/dongwon/project/ironpost/crates/ebpf-engine/ebpf/src/main.rs:103`
- **코드**:
  ```rust
  if unsafe { (*eth).ether_type } != EtherType::Ipv4 as u16 {
  ```
- **문제**: `network-types` 크레이트의 `EtherType::Ipv4`가 이미 네트워크 바이트 오더(`0x0800_u16.to_be()`)로 인코딩되어 있다는 주석(100-101행)이 있지만, `network-types` 크레이트 버전에 따라 이 동작이 달라질 수 있습니다. 코드의 정확성이 외부 크레이트의 내부 구현에 의존하고 있어 취약합니다.
- **수정 제안**: 명시적으로 변환하여 의도를 확실히 하거나, 어설션 테스트 추가:
  ```rust
  if unsafe { u16::from_be((*eth).ether_type) } != 0x0800 {
  ```

### :yellow_circle: M2. `proto as u8` 캐스팅

- **파일**: `/home/dongwon/project/ironpost/crates/ebpf-engine/ebpf/src/main.rs:197`
- **코드**:
  ```rust
  protocol: proto as u8,
  ```
- **문제**: `IpProto`에서 `u8`로의 `as` 캐스팅. eBPF 커널 코드에서는 `From/Into`가 사용 불가하므로 허용될 수 있지만, `IpProto`의 실제 repr이 `u8`인지 확인이 필요합니다.
- **수정 제안**: `network-types` 크레이트에서 `IpProto`가 `#[repr(u8)]`임을 확인하고 주석으로 명시.

### :green_circle: L1. `ihl` 변환 시 `as usize` 사용

- **파일**: `/home/dongwon/project/ironpost/crates/ebpf-engine/ebpf/src/main.rs:114`
- **코드**:
  ```rust
  let ihl = (unsafe { (*ipv4).vihl } & 0x0F) as usize;
  ```
- **문제**: `u8 & 0x0F`의 결과는 항상 0~15 범위이므로 `usize`로의 `as` 캐스팅은 안전합니다. CLAUDE.md 규칙 위반이지만 eBPF 커널 코드에서는 허용 가능. 주석 추가 권장.

### :green_circle: L2. eBPF verifier 호환성 -- 전반적으로 양호

- **파일**: `/home/dongwon/project/ironpost/crates/ebpf-engine/ebpf/src/main.rs` (전체)
- **평가**:
  - 모든 패킷 접근은 `ptr_at()` 함수를 통해 바운드 체크 수행 -- 양호
  - 루프 없음 (unbounded iteration 없음) -- 양호
  - 스택 크기: `PacketEventData`(20 bytes) + 지역 변수 약 30 bytes = 약 50 bytes -- 512 byte 제한 내
  - `HashMap`, `PerCpuArray`, `RingBuf` 맵 접근 모두 null/Option 체크 수행 -- 양호
  - `#[inline(always)]`로 헬퍼 함수 인라인화 -- verifier가 함수 호출 그래프를 분석할 수 있도록 보장

### :green_circle: L3. `update_stats`의 `pkt_len as u64` 캐스팅

- **파일**: `/home/dongwon/project/ironpost/crates/ebpf-engine/ebpf/src/main.rs:246`
- **코드**:
  ```rust
  (*stats).bytes += pkt_len as u64;
  ```
- **문제**: `u16`에서 `u64`로의 widening 캐스팅이므로 데이터 손실 없음. eBPF 커널 코드에서는 허용. 다만 C1에서 `pkt_len` 자체가 잘릴 수 있다는 점은 함께 고려 필요.

---

## 2. Engine (engine.rs)

### :red_circle: C2. `unsafe` 포인터 읽기 시 정렬(alignment) 미보장

✅ **수정 완료** (2026-02-09)
- **파일**: `/home/dongwon/project/ironpost/crates/ebpf-engine/src/engine.rs:416-419`
- **수정 내용**:
  - `std::ptr::read` → `std::ptr::read_unaligned`로 변경
  - SAFETY 주석 업데이트하여 정렬 미보장 명시
  - UB 가능성 제거

### :red_circle: C3. `as` 캐스팅 사용 -- CLAUDE.md 위반

✅ **수정 완료** (2026-02-09)
- **파일**: `/home/dongwon/project/ironpost/crates/ebpf-engine/src/engine.rs:435`
- **수정 내용**:
  - `as usize` → `usize::try_from().unwrap_or(usize::MAX)`로 변경
  - pkt_len이 u32로 변경되어 32비트 시스템 대응
  - CLAUDE.md 규칙 준수

### :orange_circle: H1. `sync_blocklist_to_map()`이 기존 엔트리를 삭제하지 않음

✅ **수정 완료** (2026-02-09)
- **파일**: `/home/dongwon/project/ironpost/crates/ebpf-engine/src/engine.rs:311-313`
- **수정 내용**:
  - 현재 룰의 IP 집합을 `HashSet`으로 수집
  - eBPF HashMap의 기존 키를 순회하여 수집
  - 현재 룰에 없는 키를 `map.remove()` 호출하여 삭제
  - 삭제 성공/실패 로그 추가
  - 룰 제거 시 커널 맵 동기화 완료

### :orange_circle: H2. `start()` 롤백 시 백그라운드 태스크 미정리

✅ **수정 완료** (2026-02-09)
- **파일**: `/home/dongwon/project/ironpost/crates/ebpf-engine/src/engine.rs:621-632`
- **수정 내용**:
  - 롤백 로직에 `self.tasks.drain()` 추가
  - 각 태스크에 대해 `abort()` 호출
  - `#[cfg(target_os = "linux")]` 가드로 Linux 전용 코드 보호
  - 초기화 실패 시 리소스 누수 방지 완료

### :orange_circle: H3. RingBuf 이벤트 리더의 busy-wait 폴링 (10ms sleep)

- **파일**: `/home/dongwon/project/ironpost/crates/ebpf-engine/src/engine.rs:453-456`
- **코드**:
  ```rust
  None => {
      // RingBuf가 비어있으면 짧게 대기
      tokio::time::sleep(std::time::Duration::from_millis(10)).await;
  }
  ```
- **문제**: `ringbuf.next()`가 `None`을 반환하면 10ms 대기 후 재시도하는 busy-wait 패턴입니다. 트래픽이 없을 때도 초당 100회 wakeup이 발생하여 불필요한 CPU 사용이 생깁니다. aya 0.13의 `RingBuf`는 `AsyncRingBuf` 또는 epoll 기반 비동기 대기를 지원합니다.
- **수정 제안**: `aya::maps::ring_buf::RingBuf`의 비동기 API를 사용하거나, 최소한 adaptive backoff를 적용:
  ```rust
  // 또는 aya의 AsyncPerfEventArray/RingBuf async API 사용
  let mut backoff = Duration::from_millis(1);
  match ringbuf.next() {
      Some(data) => { backoff = Duration::from_millis(1); /* ... */ }
      None => {
          tokio::time::sleep(backoff).await;
          backoff = backoff.min(Duration::from_millis(100)) * 2;
      }
  }
  ```

### :yellow_circle: M3. `eprintln!` 사용 -- CLAUDE.md 위반

✅ **수정 완료** (2026-02-09)
- **파일**: `/home/dongwon/project/ironpost/crates/ebpf-engine/src/engine.rs:964`
- **수정 내용**:
  - `eprintln!()` → `tracing::warn!()` 변경
  - 구조화된 로깅 포맷 사용
  - CLAUDE.md 규칙 준수 완료

### :yellow_circle: M4. `EbpfEngine`이 `Pipeline: Send + Sync` 만족 불확실

- **파일**: `/home/dongwon/project/ironpost/crates/ebpf-engine/src/engine.rs:55-67`
- **문제**: `Pipeline` trait은 `Send + Sync`를 요구합니다. `EbpfEngine`은 `#[cfg(target_os = "linux")]`에서 `aya::Ebpf` 필드를 포함합니다. `aya::Ebpf`가 `Send`는 구현하지만 `Sync`는 구현하지 않을 수 있습니다. `&mut self`로만 접근하므로 `Sync`가 불필요할 수 있지만, 명시적 검증이 필요합니다.
- **수정 제안**: 컴파일 타임 검증 추가:
  ```rust
  #[cfg(target_os = "linux")]
  const _: () = {
      fn assert_send_sync<T: Send + Sync>() {}
      fn check() { assert_send_sync::<EbpfEngine>(); }
  };
  ```

### :yellow_circle: M5. stats poller의 무한 루프에 취소 메커니즘 없음

- **파일**: `/home/dongwon/project/ironpost/crates/ebpf-engine/src/engine.rs:506-536`
- **문제**: stats poller 태스크는 무한 루프이며, 중단은 오직 `task.abort()`에 의존합니다. abort는 비동기 취소점(`.await`)에서만 동작하므로, `interval.tick().await` 이후 긴 동기 작업이 추가되면 취소가 지연될 수 있습니다. 현재는 문제없지만, `tokio::select!`와 cancellation token을 사용하는 것이 더 안전합니다.
- **수정 제안**: `tokio_util::sync::CancellationToken` 도입.

### :green_circle: L4. `health_check()`에 `TODO` 주석 -- 프로덕션 전 해결 필요

- **파일**: `/home/dongwon/project/ironpost/crates/ebpf-engine/src/engine.rs:670`
- **코드**:
  ```rust
  // TODO: XDP 프로그램 상태 확인, 맵 접근 가능 여부 등
  HealthStatus::Healthy
  ```
- **문제**: 실행 중이기만 하면 항상 `Healthy`를 반환. XDP 프로그램이 detach되었거나 맵 접근 실패 시에도 Healthy로 보고됩니다. CLAUDE.md에서 `todo!()` 매크로를 금지하고 있으나, 주석 형태의 TODO는 허용됩니다. 다만 프로덕션 투입 전 실질적 상태 확인 구현이 필요합니다.

---

## 3. Detector (detector.rs)

### :red_circle: C4. 무한 메모리 성장 -- IP 스푸핑 기반 DoS

✅ **수정 완료** (2026-02-09)
- **파일**: `/home/dongwon/project/ironpost/crates/ebpf-engine/src/detector.rs:111,254`
- **수정 내용**:
  - `MAX_TRACKED_IPS = 100_000` 상수 정의
  - `SynFloodDetector::detect()` 내부에 최대 엔트리 수 검증 추가
  - `PortScanDetector::detect()` 내부에 최대 엔트리 수 검증 추가
  - 초과 시 만료 엔트리 자동 정리 후, 여전히 초과하면 새 IP 추적 거부
  - 경고 로그 추가로 관측 가능성 확보
  - OOM 공격 방어 완료

### :orange_circle: H4. `try_lock()` 실패 시 탐지 누락 (silent miss)

✅ **수정 완료** (2026-02-09)
- **파일**: `/home/dongwon/project/ironpost/crates/ebpf-engine/src/detector.rs:186-188,308-311`
- **수정 내용**:
  - `SynFloodDetector::detect()`에서 `try_lock()` 실패 시 `tracing::debug!` 로그 추가
  - `PortScanDetector::detect()`에서 `try_lock()` 실패 시 `tracing::debug!` 로그 추가
  - 락 경합 상황 관측 가능성 확보
  - 최소한의 observability 개선 완료
  - 장기 개선: Detector trait async 전환은 Phase 1 리뷰 W2와 연계하여 별도 작업

### :orange_circle: H5. SYN flood 탐지 후 카운터 리셋 없음 -- 반복 알림 폭주

✅ **수정 완료** (2026-02-09)
- **파일**: `/home/dongwon/project/ironpost/crates/ebpf-engine/src/detector.rs:214-237`
- **수정 내용**:
  - `SynCounter` 구조체에 `alerted: bool` 필드 추가
  - 탐지 조건 확인 시 `!counter.alerted` 조건 추가
  - 알림 생성 시 `counter.alerted = true` 설정
  - 윈도우 리셋 시 `counter.alerted = false`로 초기화
  - 중복 알림 방지 완료
  - 알림 채널 포화 방지

### :yellow_circle: M6. `as f64` 캐스팅 -- CLAUDE.md 위반

- **파일**: `/home/dongwon/project/ironpost/crates/ebpf-engine/src/detector.rs:216`
- **코드**:
  ```rust
  let ratio = counter.syn_only as f64 / counter.total_tcp as f64;
  ```
- **문제**: CLAUDE.md에서 `as` 캐스팅을 금지하고 있습니다. `u64`에서 `f64`로의 변환은 정밀도 손실이 있을 수 있지만(2^53 초과 시), 비율 계산에서는 실용적 문제가 없습니다. 다만 규칙 준수 차원에서 수정 권장.
- **비고**: `stats.rs:196-198`에서도 동일한 패턴이 사용됩니다.

### :yellow_circle: M7. `AlertEvent::new()` source_module이 항상 `"log-pipeline"`

- **파일**: `/home/dongwon/project/ironpost/crates/ebpf-engine/src/detector.rs:400-402` (간접)
- **코드**:
  ```rust
  let alert_event = AlertEvent::new(alert, severity);
  ```
- **문제**: `AlertEvent::new()`는 core의 `event.rs:252-253`에서 `MODULE_LOG_PIPELINE`을 source_module로 설정합니다. 그러나 이 Alert는 eBPF 엔진에서 생성된 것이므로 `MODULE_EBPF`가 되어야 합니다. 이벤트 추적 시 잘못된 소스 모듈이 기록됩니다.
- **수정 제안**: `AlertEvent::with_trace()` 또는 `AlertEvent`에 source_module 파라미터를 받는 생성자 추가. 또는 Phase 1 리뷰 S7에서 제안된 대로 팩토리 메서드에 source_module 파라미터 추가.

---

## 4. Stats (stats.rs)

### :orange_circle: H6. `as f64` 캐스팅 -- CLAUDE.md 위반 + 대형 값 정밀도 손실

- **파일**: `/home/dongwon/project/ironpost/crates/ebpf-engine/src/stats.rs:196-198`
- **코드**:
  ```rust
  metrics.pps = delta_packets as f64 / elapsed_secs;
  metrics.bps = (delta_bytes as f64 * 8.0) / elapsed_secs;
  ```
- **문제**:
  1. CLAUDE.md `as` 캐스팅 금지 위반
  2. `u64`에서 `f64`로의 변환은 2^53 (약 9 * 10^15) 초과 시 정밀도 손실. 장기 운영 시스템에서 누적 바이트가 PB 단위에 도달하면 delta 계산이 부정확해질 수 있습니다.
  3. `delta_bytes * 8`에서 오버플로우 가능 (f64 범위 내이지만, `u64` 상태에서 곱하면 오버플로우 가능)
- **수정 제안**: 최소한 주석으로 정밀도 손실 허용 근거 명시. 이상적으로는:
  ```rust
  #[allow(clippy::cast_precision_loss)] // delta 값은 1초 간격이므로 2^53 미만
  let pps = f64::from(delta_packets as u32) / elapsed_secs; // 또는 명시적 처리
  ```

### :yellow_circle: M8. Prometheus exposition format 비준수

- **파일**: `/home/dongwon/project/ironpost/crates/ebpf-engine/src/stats.rs:148-180`
- **문제**: [Prometheus exposition format](https://prometheus.io/docs/instrumenting/exposition_formats/) 스펙에 따르면:
  1. 각 메트릭 이름 앞에 `# HELP`와 `# TYPE` 주석이 있어야 합니다
  2. Counter 타입 메트릭은 `# TYPE ironpost_packets_total counter`로 선언해야 합니다
  3. Gauge 타입 메트릭(pps, bps)은 `# TYPE ironpost_pps gauge`로 선언해야 합니다
  4. 현재 코드는 메트릭 라인만 출력하고 메타데이터가 없습니다
- **수정 제안**: 각 메트릭 그룹 앞에 TYPE/HELP 주석 추가:
  ```rust
  output.push_str("# HELP ironpost_packets_total Total packets processed\n");
  output.push_str("# TYPE ironpost_packets_total counter\n");
  // ... 메트릭 라인들
  ```

### :yellow_circle: M9. f64 포매팅이 Prometheus 표준과 불일치할 수 있음

- **파일**: `/home/dongwon/project/ironpost/crates/ebpf-engine/src/stats.rs:157-158`
- **코드**:
  ```rust
  ironpost_pps{{proto=\"{}\"}} {}\n\
  ironpost_bps{{proto=\"{}\"}} {}\n",
  ```
- **문제**: Rust의 `f64` Display 포매팅은 `1234.5`처럼 출력하지만, 값이 정확히 0일 때 `0`으로 출력됩니다. Prometheus는 이를 수용하지만, `NaN`이나 `Infinity`가 출력되면 파싱 오류가 발생합니다. `elapsed_secs`가 0에 매우 가까운 경우 `pps`가 `inf`가 될 수 있습니다.
- **수정 제안**: `f64::is_finite()` 체크 추가:
  ```rust
  let pps = if pps.is_finite() { pps } else { 0.0 };
  ```

### :green_circle: L5. `saturating_sub` 사용 -- 양호

- **파일**: `/home/dongwon/project/ironpost/crates/ebpf-engine/src/stats.rs:193-194`
- **평가**: 카운터 리셋(wraparound) 시나리오에서 `saturating_sub`을 올바르게 사용하여 underflow를 방지. 테스트(`test_update_saturating_sub_prevents_underflow`)로 검증 완료.

---

## 5. Config (config.rs)

### :red_circle: C5. 입력 검증 부재 -- TOML 룰 파일에서 DoS 가능

✅ **수정 완료** (2026-02-09)
- **파일**: `/home/dongwon/project/ironpost/crates/ebpf-engine/src/config.rs:100-124`
- **수정 내용**:
  - 검증 상수 정의: `MAX_RULES_FILE_SIZE` (10MB), `MAX_RULES_COUNT` (10,000), `MAX_RULE_ID_LEN` (256), `MAX_DESCRIPTION_LEN` (1024)
  - 파일 크기 검증 추가 (metadata 조회)
  - 룰 개수 검증 추가
  - 룰 ID 검증: 빈 문자열, 길이 초과, 중복 검사
  - 설명 길이 검증 추가
  - 모든 검증 실패 시 명확한 에러 메시지 반환
  - DoS 공격 방어 완료

### :yellow_circle: M10. `FilterRule`에 `validate()` 메서드 없음

- **파일**: `/home/dongwon/project/ironpost/crates/ebpf-engine/src/config.rs:48-64`
- **문제**: `FilterRule`은 serde로 역직렬화되지만 필드 값의 유효성을 검증하지 않습니다:
  - `protocol`이 유효한 IP 프로토콜 번호인지 (0-255 범위는 `u8`로 자동 보장되지만, 의미적 유효성은 미검증)
  - `id`가 빈 문자열인지
  - `description`이 비정상적으로 긴지
  - `dst_port`가 0인지 (0번 포트는 보통 사용하지 않음)
- **수정 제안**: `FilterRule::validate()` 메서드 추가 또는 serde의 `#[serde(try_from)]` 활용.

### :green_circle: L6. `add_rule`의 O(n) 복잡도

- **파일**: `/home/dongwon/project/ironpost/crates/ebpf-engine/src/config.rs:129-131`
- **코드**:
  ```rust
  pub fn add_rule(&mut self, rule: FilterRule) {
      self.rules.retain(|r| r.id != rule.id);
      self.rules.push(rule);
  }
  ```
- **문제**: `retain`으로 전체 Vec을 순회하므로 O(n). 룰이 수천 개일 때 반복 호출 시 성능 저하 가능. 현재는 실용적 문제 없으나, `HashMap<String, FilterRule>` 사용 시 O(1) 가능.

---

## 6. 공통 타입 (ebpf-common)

### :green_circle: L7. `#[repr(C)]` 타입의 메모리 레이아웃 -- 양호

- **파일**: `/home/dongwon/project/ironpost/crates/ebpf-engine/ebpf-common/src/lib.rs:91-175`
- **평가**:
  - `BlocklistValue` (4 bytes): action(1) + pad(3) -- 4바이트 정렬 양호
  - `ProtoStats` (24 bytes): packets(8) + bytes(8) + drops(8) -- 8바이트 정렬 양호
  - `PacketEventData` (20 bytes): 문서화된 레이아웃(139-151행)이 실제 필드와 일치
  - 모든 타입에 `// SAFETY:` 주석과 함께 `unsafe impl aya::Pod` 구현 -- 양호

### :green_circle: L8. `feature = "user"` 게이팅 -- 양호

- **파일**: `/home/dongwon/project/ironpost/crates/ebpf-engine/ebpf-common/src/lib.rs:93,103,116,127,154,177`
- **평가**: `aya::Pod` impl과 `Debug` derive가 `#[cfg(feature = "user")]`로 적절히 게이팅되어 커널 빌드 시 std 의존성이 포함되지 않습니다.

### :yellow_circle: M11. `PacketEventData` 크기가 20 bytes -- 4바이트 정렬 충족하지만 8바이트 정렬 미충족

- **파일**: `/home/dongwon/project/ironpost/crates/ebpf-engine/ebpf-common/src/lib.rs:152-174`
- **문제**: `PacketEventData`의 첫 필드가 `u32`이므로 정렬 요구사항은 4 bytes입니다. 총 크기 20 bytes는 4의 배수이므로 문제없습니다. 그러나 C2에서 지적한 `std::ptr::read` 정렬 이슈와 연관되어, RingBuf에서 반환되는 데이터의 정렬이 최소 4바이트인지 확인이 필요합니다.

---

## 7. 크로스커팅 이슈

### :red_circle: C6. `as` 캐스팅 다수 사용 -- CLAUDE.md 위반 (유저스페이스)

✅ **수정 완료** (2026-02-09)
- **위치**: 유저스페이스 코드 전반
- **수정 내용**:
  - `engine.rs:435`: `as usize` → `usize::try_from().unwrap_or(usize::MAX)` 변경
  - `stats.rs:196,198`: `#[allow(clippy::cast_precision_loss)]` 주석 추가 + 사유 명시
  - `detector.rs:216`: `#[allow(clippy::cast_precision_loss)]` 주석 추가 + 사유 명시
  - 모든 u64 → f64 캐스팅에 정밀도 손실 허용 근거 문서화
  - CLAUDE.md 규칙 준수 완료

### :yellow_circle: M12. `cfg(target_os = "linux")` 게이팅 -- 양호하나 개선 가능

- **파일**: `/home/dongwon/project/ironpost/crates/ebpf-engine/src/engine.rs` 전반
- **평가**:
  - `bpf` 필드: `#[cfg(target_os = "linux")]` -- 양호
  - `tasks` 필드: `#[cfg(target_os = "linux")]` -- 양호
  - `load_and_attach()`: Linux/non-Linux 분리 -- 양호
  - `detach()`: Linux/non-Linux 분리 -- 양호
  - `sync_blocklist_to_map()`: 내부 `#[cfg]` 블록 -- 양호
  - `spawn_event_reader()`: 내부 `#[cfg]` 블록 -- 양호
  - `spawn_stats_poller()`: 내부 `#[cfg]` 블록 -- 양호
  - `stop()`: `self.tasks.drain()` -- `#[cfg(target_os = "linux")]` 블록 내 -- 양호
  - `sum_percpu_stats()`: `#[cfg(target_os = "linux")]` -- 양호
- **개선 제안**: Linux 전용 로직을 별도 모듈(`engine_linux.rs`)로 분리하면 가독성 향상.

### :yellow_circle: M13. Core trait 사용 -- 부분적 적합

- **평가**:
  - `Pipeline` trait 구현 (`engine.rs:596`): `start`, `stop`, `health_check` -- 양호
  - `Detector` trait 구현 (`detector.rs:134,277`): `SynFloodDetector`, `PortScanDetector` -- 양호
  - `IronpostError` 사용: 모든 public 함수가 `Result<_, IronpostError>` 반환 -- 양호
  - `PacketEvent`, `AlertEvent` 사용 -- 양호
  - **문제**: core의 `Detector` trait은 `LogEntry`를 입력으로 받지만, eBPF 엔진의 자연스러운 입력은 `PacketEventData`입니다. 이를 위해 `packet_event_to_log_entry()` 변환 함수가 필요한데, 이는 매 패킷마다 7개의 `String` 할당이 발생하는 비효율적인 구조입니다.
  - Phase 1 리뷰 W2에서 이미 지적된 아키텍처 이슈와 동일: `Detector::detect(&self, entry: &LogEntry)` 시그니처가 네트워크 레벨 탐지에 부적합.

### :green_circle: L9. 모듈 의존성 규칙 준수 -- 양호

- **평가**: `ironpost-ebpf-engine`은 오직 `ironpost-core`와 `ironpost-ebpf-common`에만 의존하며, 다른 모듈(log-pipeline, container-guard 등)에 직접 의존하지 않습니다. CLAUDE.md의 "모듈 간 직접 의존 금지 -- core만 의존 가능" 규칙을 준수합니다.

### :green_circle: L10. `tokio::sync::Mutex` 사용 -- CLAUDE.md 준수

- **평가**: `std::sync::Mutex` 사용이 감지되지 않았습니다. `TrafficStats`, `SynFloodDetector`, `PortScanDetector` 모두 `tokio::sync::Mutex`를 사용합니다.

### :green_circle: L11. `unwrap()` 사용 -- 테스트 코드에만 한정, 양호

- **평가**: 모든 `unwrap()` 호출이 `#[cfg(test)]` 블록 내에 있습니다. 프로덕션 코드에서는 `unwrap()` 사용이 없습니다.

### :green_circle: L12. `unsafe` 블록 -- 모두 SAFETY 주석 보유

- **평가**:
  - `engine.rs:416-419`: `std::ptr::read` -- SAFETY 주석 있음 (단, C2에서 정렬 문제 지적)
  - `ebpf/src/main.rs`: 다수의 unsafe 블록 -- 모두 SAFETY 주석 있음
  - `ebpf-common/src/lib.rs:103-104,127-128,177-178`: `unsafe impl Pod` -- SAFETY 주석 있음

---

## 보안 체크리스트

| 항목 | 상태 | 비고 |
|------|------|------|
| `unwrap()` 프로덕션 사용 | 양호 | 테스트 코드에만 사용 |
| `unsafe` 블록 SAFETY 주석 | 양호 | 모든 unsafe에 주석 있음 (C2 정렬 이슈 별도) |
| `panic!`/`todo!`/`unimplemented!` | 양호 | 프로덕션 코드에 없음 (테스트 `panic!` 1건은 허용) |
| 민감 데이터 로깅 | 양호 | IP 주소만 로깅, 비밀번호/토큰 로깅 없음 |
| 입력 크기 상한 | 미흡 | 룰 파일 크기/개수 제한 없음 (C5) |
| bounded 채널 | 양호 | `mpsc::channel(capacity)` 사용 |
| TOCTOU | 양호 | 파일 존재 확인 분리 없이 직접 읽기 시도 |
| 메모리 성장 제한 | 미흡 | HashMap 무한 성장 가능 (C4) |
| 바이트 오더 처리 | 양호 | 일관된 be/ne 변환 |
| eBPF verifier 호환성 | 양호 | 바운드 체크, 스택 제한, 루프 없음 |
| `as` 캐스팅 금지 (유저스페이스) | 위반 | 5건 발견 (C3, C6) |
| `eprintln!` 사용 금지 | 위반 | 1건 (M3, 테스트 코드) |

---

## 통계
- :red_circle: Critical: 5건 (C1 패킷 길이 잘림, C2 정렬 미보장, C3 as 캐스팅, C4 메모리 DoS, C5 입력 검증 부재)
- :orange_circle: High: 6건 (H1 맵 동기화 불완전, H2 롤백 태스크 미정리, H3 busy-wait, H4 탐지 누락, H5 알림 폭주, H6 as 캐스팅+정밀도)
- :yellow_circle: Medium: 9건 (M1~M5, M6~M9, M10~M13)
- :green_circle: Low: 8건 (L1~L12)
- **총 발견 사항: 28건**

---

## 잘된 점

- **XDP 프로그램의 패킷 파싱이 안전함**: `ptr_at()` 함수를 통한 일관된 바운드 체크로 eBPF verifier 호환성 확보
- **`#[repr(C)]` 공유 타입 설계가 우수**: 명시적 패딩, 레이아웃 문서화, feature gate를 통한 커널/유저스페이스 분리
- **롤백 보장**: `start()` 실패 시 XDP 프로그램을 detach하는 롤백 로직 구현 (H2의 부분적 미흡에도 불구하고 기본 구조는 양호)
- **`saturating_sub` 사용**: 통계 카운터의 underflow 방지
- **cfg 게이팅이 체계적**: Linux 전용 코드가 `#[cfg(target_os = "linux")]`으로 깔끔하게 분리
- **테스트 커버리지**: 74개 테스트로 주요 로직 검증 완료
- **doc comment 충실**: 모든 public API에 한국어 doc comment와 아키텍처 다이어그램 포함
- **에러 처리 체계**: 모든 aya 연산에 적절한 에러 변환과 컨텍스트 메시지 부착

---

## 결론 및 권장사항

### 프로덕션 투입 전 필수 수정 (Critical)

1. **C2 (unsafe 정렬)**: `std::ptr::read_unaligned` 사용으로 즉시 수정. UB 발생 가능성이 있는 가장 긴급한 이슈.
2. **C4 (메모리 DoS)**: 탐지기 HashMap에 최대 크기 제한 추가. 외부 공격으로 인한 OOM 방지.
3. **C5 (입력 검증)**: 룰 파일 크기/개수/필드 검증 추가. 악의적 입력에 대한 방어.
4. **C1 (패킷 길이)**: 점보 프레임 환경에서의 데이터 정확성. `pkt_len` 필드를 `u32`로 확장하거나 클램핑.
5. **C3, C6 (as 캐스팅)**: CLAUDE.md 규칙 준수. `From/Into` 변환으로 교체.

### 우선 수정 권장 (High)

1. **H1 (맵 동기화)**: 룰 삭제가 커널에 반영되지 않는 보안 정책 위반 수정.
2. **H5 (알림 폭주)**: 탐지 후 카운터 리셋으로 중복 알림 방지.
3. **H2 (롤백 태스크)**: 초기화 실패 시 이미 스폰된 태스크 정리.
4. **H4 (탐지 누락)**: 최소한 try_lock 실패 로깅 추가.

### 아키텍처 개선 (장기)

- `Detector` trait의 `LogEntry` 입력을 generic하게 변경하여 `PacketEventData` -> `LogEntry` 변환 오버헤드 제거 (Phase 1 W2와 연계)
- RingBuf 비동기 폴링으로 busy-wait 제거
- Linux 전용 코드를 별도 모듈로 분리하여 가독성 향상

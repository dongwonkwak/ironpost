# T7.7: S6 모듈 장애 격리 E2E 테스트 구현

**일시**: 2026-02-11 22:30 - 23:00
**소요 시간**: 30분
**담당**: tester
**상태**: ✅ 완료

## 목표
모듈 장애 격리 시나리오를 검증하는 E2E 테스트 구현. 한 모듈의 실패가 다른 모듈에 영향을 미치지 않고, health 상태가 올바르게 집계되는지 검증.

## 구현 내용

### 1. 모듈 시작/정지 실패 격리 테스트 (2개)

#### `test_e2e_one_module_start_failure_others_stop`
- 시나리오: 3개 모듈 중 2번째 모듈이 시작 실패
- 검증:
  - start_all()이 에러 반환
  - 에러 메시지에 실패한 모듈명("module2") 포함
  - 첫 번째 모듈은 시작됨 (early return으로 3번째는 시작 안됨)
  - 호출자는 stop_all()로 정리 필요

#### `test_e2e_stop_failure_continues_others`
- 시나리오: 3개 모듈 중 2번째 모듈이 정지 실패
- 검증:
  - stop_all()이 에러 반환하지만 3번째 모듈은 정지됨
  - 에러 메시지에 실패한 모듈명 포함
  - AtomicBool 플래그로 3번째 모듈의 정지 확인

### 2. 런타임 Health 격리 테스트 (1개)

#### `test_e2e_runtime_module_degraded_others_healthy`
- 시나리오: 3개 모듈 (Healthy, Degraded, Healthy)
- 검증:
  - health_statuses() 호출 시 각 모듈의 독립적인 상태 확인
  - Degraded 모듈이 나머지 Healthy 모듈에 영향 없음
  - aggregate_status() = Degraded (worst-case 규칙)

### 3. 채널 장애 처리 테스트 (1개)

#### `test_e2e_channel_sender_dropped_receiver_handles`
- 시나리오: 생산자 채널(alert_tx)이 drop됨
- 검증:
  - 수신자(alert_rx.recv())가 None 반환 (panic 없음)
  - Graceful하게 채널 닫힘 처리

### 4. Health 집계 테스트 (5개)

#### `test_e2e_health_aggregation_worst_case`
- 시나리오: Healthy, Degraded, Unhealthy 혼합
- 검증: Unhealthy 반환 (worst-case), 에러 이유에 "unhealthy-module" 포함

#### `test_e2e_health_aggregation_all_healthy`
- 시나리오: 3개 모듈 모두 Healthy
- 검증: 집계 결과 = Healthy

#### `test_e2e_disabled_modules_excluded_from_health`
- 시나리오: 비활성화된 모듈이 Unhealthy 상태
- 검증: 집계 결과 = Healthy (비활성화 모듈은 무시됨)

#### `test_e2e_health_aggregation_degraded_wins_over_healthy`
- 시나리오: Healthy + Degraded (Unhealthy 없음)
- 검증: Degraded 반환, 에러 이유에 "module2" 포함

#### `test_e2e_health_aggregation_multiple_degraded`
- 시나리오: 2개 모듈 모두 Degraded (각기 다른 이유)
- 검증: Degraded 반환, 두 모듈의 이유 모두 포함 ("module1: issue1", "module2: issue2")

#### `test_e2e_health_aggregation_empty_list`
- 시나리오: 빈 모듈 리스트
- 검증: Healthy 반환 (unhealthy 모듈 없음)

## 추가 수정

### 다른 파일의 컴파일 에러 수정

#### pipeline_flow.rs
- `FieldCondition` import 경로 수정: `rule::types::FieldCondition`
- `alert_tx` 변수명 복원 (실제 사용됨)

#### sbom_flow.rs
- 사용하지 않는 import 제거: `AlertEvent`, `tokio::sync::mpsc`

#### shutdown.rs
- 사용하지 않는 import 제거: `std::sync::Arc`
- `.alert()` 메서드 호출 → `.alert` 필드 접근으로 수정

#### config_error.rs (clippy 경고 수정)
- `result.is_err()` + `result.unwrap_err()` → `if let Err(err) = result` 패턴으로 변경
- `clippy::unnecessary-unwrap` 경고 해결

## 테스트 결과

```bash
cargo test --package ironpost-daemon --test e2e fault_isolation
```

**결과**: 10 passed, 0 failed

### 테스트 목록
1. test_e2e_disabled_modules_excluded_from_health
2. test_e2e_health_aggregation_empty_list
3. test_e2e_health_aggregation_all_healthy
4. test_e2e_health_aggregation_degraded_wins_over_healthy
5. test_e2e_runtime_module_degraded_others_healthy
6. test_e2e_one_module_start_failure_others_stop
7. test_e2e_stop_failure_continues_others
8. test_e2e_health_aggregation_worst_case
9. test_e2e_health_aggregation_multiple_degraded
10. test_e2e_channel_sender_dropped_receiver_handles

### Clippy 검증
```bash
cargo clippy --package ironpost-daemon --tests -- -D warnings
```

**결과**: 경고 없음 (clean)

## 커버리지

### 테스트 시나리오
- ✅ T7.7-1: 모듈 시작 실패 → 나머지 정리
- ✅ T7.7-2: 런타임 Degraded → 나머지 Healthy
- ✅ T7.7-3: 채널 송신자 drop → 수신자 graceful 처리
- ✅ T7.7-4: 정지 실패 → 나머지 모듈 정지 계속
- ✅ T7.7-5: Health 집계 worst-case 규칙
- 추가: Degraded 우선순위, 여러 Degraded 이유 집계, 빈 리스트 처리

### 엣지 케이스
- 비활성화 모듈은 health 집계에서 제외
- 여러 Degraded 모듈의 이유 모두 포함
- 빈 모듈 리스트 → Healthy
- early return으로 3번째 모듈 시작 안됨
- stop 실패 시 에러 로깅 후 계속 진행

## 변경 파일
- `ironpost-daemon/tests/e2e/scenarios/fault_isolation.rs` (구현, 358 lines)
- `ironpost-daemon/tests/e2e/scenarios/pipeline_flow.rs` (import 수정)
- `ironpost-daemon/tests/e2e/scenarios/sbom_flow.rs` (import 정리)
- `ironpost-daemon/tests/e2e/scenarios/shutdown.rs` (import + 필드 접근 수정)
- `ironpost-daemon/tests/e2e/scenarios/config_error.rs` (clippy 수정)

## 의존성
- MockPipeline (helpers/mock_pipeline.rs) 활용
- ModuleRegistry, ModuleHandle (ironpost-daemon/src/modules/mod.rs)
- aggregate_status, ModuleHealth (ironpost-daemon/src/health.rs)
- HealthStatus (ironpost-core/pipeline.rs)

## 산출물
- **테스트**: 10개 (fault isolation 시나리오)
- **총 E2E 테스트**: 46개 (1개 실패는 기존 이슈)
- **라인 수**: fault_isolation.rs 358 lines

## 다음 단계
- T7.2, T7.3 완료 후 전체 E2E 테스트 통과 확인
- Phase 7 리뷰 준비 (T7.14)

## 참고
- `.tasks/plans/phase-7-e2e.md` T7.7 섹션
- `.knowledge/testing-strategy.md` E2E 테스트 전략

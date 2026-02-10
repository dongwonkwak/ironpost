# T3-9: 통합 테스트 추가

**작업자**: tester
**날짜**: 2026-02-09
**시작**: 13:45
**완료**: 14:10
**소요 시간**: 25분

## 목표
reviewer가 지적한 누락된 통합 테스트 시나리오 추가:
1. Collector → Pipeline Flow 테스트 (실제 로그 주입부터 알림 생성까지)
2. Restart Scenario 테스트 (start → stop → start 재시작 기능 검증)

## 작업 내용

### 1. 추가된 통합 테스트 (6개)

#### `test_collector_to_pipeline_flow`
- **목적**: raw_log_sender()를 통한 전체 파이프라인 흐름 검증
- **시나리오**:
  1. 임시 규칙 디렉토리 생성 및 YAML 규칙 파일 작성
  2. 파이프라인 빌드 및 시작
  3. `raw_log_sender()`로 로그 주입
  4. 규칙 매칭 및 알림 생성 확인
  5. 통계 카운터 검증
- **검증 항목**: 규칙 로드, 로그 파싱, 규칙 매칭, 알림 생성, 처리 카운터

#### `test_collector_to_pipeline_no_match`
- **목적**: 규칙에 매칭되지 않는 로그 처리 검증
- **시나리오**: 매칭되지 않는 로그 주입 후 알림이 생성되지 않음을 확인
- **검증 항목**: 타임아웃 확인, 로그는 처리되지만 알림은 없음

#### `test_pipeline_restart_scenario`
- **목적**: 파이프라인 재시작 기능 검증
- **시나리오**:
  1. 첫 번째 사이클: start → 로그 처리 → stop
  2. 두 번째 사이클: start → 로그 처리 → stop
  3. 세 번째 사이클: start → 로그 처리 → stop
- **검증 항목**: 각 사이클에서 로그 처리, 카운터 누적, 상태 전환

#### `test_multiple_log_injection`
- **목적**: 다수의 로그 연속 주입 시 배치 처리 검증
- **시나리오**: 20개 로그를 연속으로 주입하여 배치 플러시 동작 확인
- **검증 항목**: 모든 로그 처리, 파싱 에러 없음, 버퍼 사용률

#### `test_json_log_pipeline_flow`
- **목적**: JSON 형식 로그 파싱 및 규칙 매칭 검증
- **시나리오**: JSON 로그 주입 → 파싱 → 규칙 매칭 → 알림 생성
- **검증 항목**: JSON 파서 동작, 규칙 매칭, 알림 생성

#### `test_pipeline_health_check_states`
- **목적**: 헬스 체크가 상태에 따라 올바른 응답 반환
- **시나리오**: 초기/실행/정지 상태에서 헬스 체크 호출
- **검증 항목**: Unhealthy(초기) → Healthy(실행) → Unhealthy(정지)

### 2. 주요 수정 사항

#### 컴파일 에러 수정
- `HealthStatus` import 추가
- Alert 구조체의 `rule_id` 필드가 없음 → `rule_name`, `title`로 검증 변경
- HealthStatus 변형: `Stopped` → `Unhealthy` (실제 구현에 맞춤)

#### YAML 규칙 형식 수정
- 심각도 필드: `severity: high` → `severity: High` (대소문자 구분)
- `status: enabled` 필드 제거 (기본값 사용)

#### 타이밍 조정
- 비동기 처리 대기 시간: 200ms → 1500ms (flush_interval_secs=1 보다 길게)
- 배치 크기: batch_size=10 → batch_size=1 (즉시 처리로 테스트 속도 향상)

#### JSON 테스트 수정
- 규칙 조건: `field: level, value: ERROR` → `field: message, modifier: contains, value: Database`
- 이유: JSON 파서가 level 필드를 severity로 변환하므로, 원본 필드로 직접 매칭 불가

### 3. 테스트 결과

```
cargo test -p ironpost-log-pipeline
```

**결과**: ✅ 280 tests passed
- 261 unit tests (기존)
- 19 integration tests (13 기존 + 6 신규)

**커버리지**:
- 전체 파이프라인 흐름 (수집 → 파싱 → 규칙 → 알림)
- 재시작 시나리오 (3회 반복)
- JSON 파싱 경로
- 헬스 체크 상태 전환
- 엣지 케이스 (매칭 없음, 다중 로그, 빈 규칙)

## 기술적 도전

### 1. 비동기 타이밍 문제
- **문제**: 로그 처리가 비동기로 이루어져 테스트에서 처리 완료를 보장하기 어려움
- **해결**: flush_interval_secs보다 긴 대기 시간 사용, batch_size=1로 즉시 플러시 유도

### 2. JSON 파싱 규칙 매칭
- **문제**: JSON 파서가 `level` 필드를 자동으로 `severity`로 변환하여 원본 필드 접근 불가
- **해결**: 규칙을 `message` 필드 매칭으로 변경

### 3. 규칙 파일 형식
- **문제**: 처음에 `severity: high` 형식으로 작성하여 규칙 로드 실패
- **해결**: Rust enum 직렬화 형식에 맞춰 `severity: High`로 수정

## 산출물
- `crates/log-pipeline/tests/integration_tests.rs`: 6개 신규 테스트 추가 (+322 lines)
- 총 테스트 수: 280개 (261 unit + 19 integration)

## 검증
```bash
cargo test -p ironpost-log-pipeline
cargo clippy -p ironpost-log-pipeline
cargo fmt --check
```

모두 통과 ✅

## 다음 단계
- Phase 3 완료
- Phase 4: container-guard 모듈 시작

# 2026-02-11 -- Phase 2~5 리뷰 미반영 수정 (T6-4)

## 작업 시간
- 시작: 2026-02-11 (KST)
- 종료: 2026-02-11 (KST)
- 소요: 약 2.5시간
- 커밋: 7ed699b

## 목표
Phase 2~5 리뷰 미반영 수정 사항 22건 중 12건 처리 (High 9건, Medium 3건)

## 수행 내역

### High Priority (9건)

#### ✅ 1. [P3-H5] log-pipeline: 타임스탬프 휴리스틱 확장
- **파일**: `crates/log-pipeline/src/parser/json.rs:265-285`
- **문제**: 10자리/13자리만 지원, 마이크로초/나노초 미지원
- **수정**: 10/13/16/19 자리 Unix timestamp 모두 지원
  - 10자리: 초
  - 13자리: 밀리초
  - 16자리: 마이크로초
  - 19자리: 나노초
- **타입 수정**: `(ts_secs, ts_nanos): (i64, u32)` 명시적 타입 지정

#### ✅ 2. [P3-H7] log-pipeline: SystemTime → Instant
- **파일**: `crates/log-pipeline/src/alert.rs`
- **문제**: SystemTime은 시계 역행에 취약
- **수정**:
  - `dedup_tracker: HashMap<String, Instant>`
  - `rate_tracker: HashMap<String, (u32, Instant)>`
  - `is_duplicate()`, `is_rate_limited()`, `update_rate_counter()` 로직 단순화
  - `cleanup_expired()` 불필요한 Result unwrap 제거
- **유지**: Alert.created_at은 외부 API 호환성 위해 SystemTime 유지

#### ✅ 3. [P4-NEW-H1] container-guard: 에러 variant 수정
- **파일**: `crates/container-guard/src/docker.rs:64-77`
- **문제**: 유효하지 않은 컨테이너 ID가 `ContainerNotFound` 반환
- **수정**: `ContainerGuardError::Config` variant 사용
- **이유**: 입력 검증 실패는 설정 오류이지 "not found"가 아님

#### ✅ 4. [P4-NEW-H2] container-guard: Processing task DockerMonitor 공유
- **상태**: 이미 해결됨
- **확인**: guard.rs:179에서 `Arc::clone(&self.monitor)` 사용
- **결론**: 별도 인스턴스 생성하지 않음

#### ✅ 5. [P4-H6] container-guard: labels 필드 검증
- **상태**: 이미 해결됨
- **확인**: policy.rs:150-159에서 비어있지 않은 labels 거부
- **메시지**: "label-based filtering is not yet supported"

#### ✅ 6-7. [P5-H2, P5-NEW-H1] sbom-scanner: Graceful shutdown
- **파일**: `crates/sbom-scanner/{Cargo.toml,src/scanner.rs}`
- **의존성 추가**: tokio-util = "0.7" (workspace에도 추가)
- **수정**:
  - `cancellation_token: CancellationToken` 필드 추가
  - 주기적 스캔 루프에 `tokio::select!` + `token.cancelled()` 적용
  - `stop()` 메서드에서 `token.cancel()` 호출
  - abort() 대신 graceful shutdown 구현

#### ✅ 8. [P5-NEW-H3] sbom-scanner: unix_to_rfc3339 중복
- **상태**: 이미 해결됨
- **확인**: `crates/sbom-scanner/src/sbom/util.rs`에 공유 구현
- **사용**: cyclonedx.rs:90, spdx.rs:142 모두 `super::util::current_timestamp()` 사용

#### ✅ 9. [P2-H3] ebpf-engine: RingBuf adaptive backoff
- **상태**: 이미 해결됨
- **확인**: engine.rs:433-495 exponential backoff 구현
  - 초기 1ms → 최대 100ms
  - 이벤트 수신 시 backoff 리셋
  - idle 시 지수적 증가

### Medium Priority (3건)

#### ✅ 10. [P3-M2] log-pipeline: cleanup 시간 기반 변경
- **파일**: `crates/log-pipeline/src/pipeline.rs:230-351`
- **문제**: `cleanup_counter` (tick 기반) → flush_interval 의존
- **수정**:
  - `last_cleanup: Instant` 추가
  - `CLEANUP_INTERVAL: Duration = 60초` 상수
  - `last_cleanup.elapsed() >= CLEANUP_INTERVAL` 조건으로 변경

#### ✅ 11. [P4-M5] container-guard: enforcer.rs 삭제
- **파일**: `crates/container-guard/src/enforcer.rs`
- **내용**: 3줄 마이그레이션 주석만 존재
- **수정**: 파일 삭제

#### ✅ 12. [P2-M7] ebpf-engine: AlertEvent source_module 수정
- **파일**: `crates/core/src/event.rs`, `crates/ebpf-engine/src/detector.rs`
- **문제**: `AlertEvent::new()` 항상 MODULE_LOG_PIPELINE 사용
- **수정**:
  - core: `AlertEvent::with_source(alert, severity, source_module)` 메서드 추가
  - detector.rs: `AlertEvent::with_source(alert, severity, MODULE_EBPF)` 사용

## 테스트 결과
```bash
cargo test -p ironpost-core -p ironpost-log-pipeline \
  -p ironpost-container-guard -p ironpost-sbom-scanner --lib
```
- **결과**: 173 tests passed
- **clippy**: No warnings (-D warnings)

## 커밋 상세
```
7ed699b fix(review): resolve 12 Phase 2-5 review issues (High 9, Medium 3)
```

## 산출물
- 수정 파일: 15개
  - .tasks/BOARD.md
  - Cargo.toml (workspace에 tokio-util 추가)
  - crates/container-guard/src/docker.rs
  - crates/container-guard/src/guard.rs (기존 수정)
  - crates/container-guard/src/policy.rs (기존 수정)
  - crates/core/src/event.rs
  - crates/ebpf-engine/src/detector.rs
  - crates/log-pipeline/src/alert.rs
  - crates/log-pipeline/src/config.rs (기존 수정)
  - crates/log-pipeline/src/parser/json.rs
  - crates/log-pipeline/src/parser/syslog.rs (기존 수정)
  - crates/log-pipeline/src/pipeline.rs
  - crates/log-pipeline/src/rule/mod.rs (기존 수정)
  - crates/sbom-scanner/Cargo.toml
  - crates/sbom-scanner/src/scanner.rs
- 삭제 파일: 1개
  - crates/container-guard/src/enforcer.rs

## 미처리 이슈 (추후 작업)
### Critical (4건) - 별도 태스크로 분리 예정
- P4-NEW-C1: stop()/start() 재시작 불가
- P4-NEW-C2: canonicalize() TOCTOU
- P5-NEW-C1: VulnDb lookup String 할당
- P3-H1: Detector trait &self vs &mut self

### High (5건)
- P3-H4: Syslog PRI 값 범위 검증 (0-191)
- P3-H6: 파일 경로 순회 검증
- P4-H3: 와일드카드 필터
- P4-NEW-H3: `all: true` 필터
- P5-NEW-H2: discover_lockfiles TOCTOU

### Medium (1건)
- P5-M9: Path traversal 검증

## 주요 패턴
1. **시간 추적**: SystemTime → Instant (시계 역행 방어)
2. **Graceful shutdown**: CancellationToken 사용
3. **에러 시맨틱**: 입력 검증 = Config variant
4. **API 확장**: with_source() 메서드 추가 (기존 호환)
5. **중복 제거**: 공유 유틸리티 모듈 사용

## 다음 단계
- T6-5: 루트 README.md 재작성
- T6-6: CHANGELOG.md 작성
- 나머지 Critical/High 이슈 별도 태스크로 처리

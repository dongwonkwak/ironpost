# T7.15 - Phase 7 Codex Review Fixes

**담당**: implementer
**일자**: 2026-02-11
**예상 시간**: 1h
**실제 시간**: 45분
**상태**: ✅ 완료

## 태스크 개요
Phase 7 Codex 리뷰에서 발견된 4건의 이슈 수정:
- C1: Dockerfile ironpost.toml Missing (Critical)
- H1: Non-root User Cannot Bind Port 514/udp (High)
- M1: Environment Variable Test Race Condition (Medium)
- L1: eprintln! Usage (Low)

## 작업 시작
**시작 시간**: 2026-02-11 10:00

## 수행 내용

### C1: Dockerfile ironpost.toml Missing (Critical)
**문제**: 빌더 스테이지에 없는 파일을 런타임 스테이지에서 복사
**수정**:
- `docker/Dockerfile` (line 70): `COPY --from=builder /app/ironpost.toml` 제거
- 설정 파일은 docker-compose.yml의 볼륨 마운트를 통해 제공됨

### H1: Non-root User Cannot Bind Port 514/udp (High)
**문제**: 비특권 사용자는 514번 포트(< 1024) 바인딩 불가
**수정**:
1. 내부 포트를 514 → 1514로 변경
2. `docker/Dockerfile` (line 81-82): EXPOSE 1514/udp로 변경, 설명 추가
3. `docker/docker-compose.yml` (line 67): 포트 매핑 `514:1514/udp`로 수정
4. `docker/docker-compose.yml` (line 83): `IRONPOST_LOG_PIPELINE_SYSLOG_BIND=0.0.0.0:1514`로 변경

### M1: Environment Variable Test Race Condition (Medium)
**문제**: 전역 환경변수를 수정하는 테스트가 병렬 실행 시 충돌 가능
**수정**:
1. `Cargo.toml` (line 47): `serial_test = "3"` workspace 의존성 추가
2. `ironpost-daemon/Cargo.toml` (line 30): dev-dependencies에 serial_test 추가
3. `ironpost-daemon/tests/e2e/scenarios/lifecycle.rs` (line 119): `#[serial_test::serial]` 매크로 적용

### L1: eprintln! Usage (Low)
**문제**: 프로젝트 규칙 위반 (eprintln! 금지, tracing 사용 필수)
**수정**:
- `ironpost-daemon/tests/e2e/scenarios/sbom_flow.rs` (lines 250, 259):
  - `eprintln!()` → `tracing::debug!()` 변경
  - 테스트 디버깅 기능 유지하면서 프로젝트 컨벤션 준수

## 검증

### Clippy 검증
```bash
$ cargo clippy --workspace -- -D warnings
    Finished `dev` profile [unoptimized + debuginfo] target(s) in 1.78s
```
✅ 경고 없음

### 테스트 검증
```bash
$ cargo test --workspace
```
✅ 108개 테스트 전체 통과
- ironpost-cli: 54 tests
- ironpost-core: 64 tests
- ironpost-daemon: 28 tests (E2E 포함)
- ironpost-container-guard: 8 tests
- ironpost-log-pipeline: 13 tests
- ironpost-sbom-scanner: 8 tests
- 모든 doctest 통과

## 산출물

### 파일 수정
1. `docker/Dockerfile` (2건 수정)
   - line 70: COPY 명령 제거
   - line 81-82: EXPOSE 포트 변경 및 주석 추가

2. `docker/docker-compose.yml` (2건 수정)
   - line 67: 포트 매핑 변경
   - line 83: SYSLOG_BIND 환경변수 변경

3. `Cargo.toml` (1건 추가)
   - line 47: serial_test 의존성 추가

4. `ironpost-daemon/Cargo.toml` (1건 추가)
   - line 30: serial_test dev-dependency 추가

5. `ironpost-daemon/tests/e2e/scenarios/lifecycle.rs` (1건 수정)
   - line 119: #[serial_test::serial] 매크로 추가

6. `ironpost-daemon/tests/e2e/scenarios/sbom_flow.rs` (2건 수정)
   - lines 250, 259: eprintln! → tracing::debug! 변경

### 문서 생성
- `.reviews/phase-7-codex-review.md`: 1350 라인 리뷰 보고서
  - 4개 이슈 상세 분석
  - 수정 전후 비교
  - 검증 결과
  - 영향 분석
  - 권장사항

## 기술적 의사결정

### 포트 매핑 전략 (H1)
**결정**: 컨테이너 내부에서 비특권 포트(1514) 사용, Docker에서 외부 514로 매핑
**근거**:
- 보안: 비루트 사용자로 실행 유지 (defense in depth)
- 호환성: 외부 클라이언트는 여전히 표준 514 포트 사용 가능
- 이식성: Docker 포트 매핑은 표준 관행

### 테스트 격리 전략 (M1)
**결정**: serial_test 크레이트 사용하여 환경변수 테스트 직렬화
**근거**:
- 단순성: #[serial] 매크로만 추가하면 됨
- 안전성: 테스트 간 환경변수 충돌 완전 방지
- 성능: 1개 테스트만 직렬화, 나머지는 병렬 실행

### 로깅 표준화 (L1)
**결정**: 모든 디버그 출력은 tracing 사용
**근거**:
- 일관성: 프로젝트 전체 로깅 표준 준수
- 제어 가능성: RUST_LOG 환경변수로 출력 제어
- 구조화: JSON 로그 지원

## 학습 내용

1. **Docker 보안 모범 사례**
   - 비루트 사용자 실행 시 특권 포트 접근 불가
   - 포트 매핑으로 우회 (컨테이너 내부 > 1024, 호스트 < 1024)

2. **Rust 테스트 격리**
   - 환경변수는 프로세스 전역 상태
   - serial_test 크레이트로 테스트 직렬화 가능
   - Rust 2024: set_var/remove_var은 unsafe

3. **12-Factor App 원칙**
   - 설정을 코드와 분리 (볼륨 마운트)
   - 빌드 아티팩트에 설정 포함하지 않음

## 완료 시간
**종료 시간**: 2026-02-11 10:45
**실제 소요**: 45분 (예상 1h 대비 15분 단축)

## 다음 단계
- [ ] T7.10: docker-compose.demo.yml 작성
- [ ] T7.11: docs/demo.md 데모 실행 가이드
- [ ] T7.14: Phase 7 코드 리뷰 완료

## 메모
- 모든 수정사항은 프로젝트 컨벤션(CLAUDE.md) 준수
- Docker 보안 모범 사례 적용 (비루트 실행)
- 테스트 안정성 개선 (race condition 제거)
- 코드 품질 향상 (clippy 통과, eprintln! 제거)

# Phase 3 리뷰 지적사항 수정

**담당:** implementer
**날짜:** 2026-02-09
**태스크:** T3-7 리뷰 지적사항 반영

## 작업 내용

### Critical 이슈 수정 (10건)

#### C1. Arc<Mutex<u64>> 카운터 성능 병목
- **수정:** `Arc<Mutex<u64>>` → `Arc<AtomicU64>` 변경
- **영향:** 고속 로그 처리 시 Mutex 경합 제거, lock-free atomic 연산
- **파일:** `pipeline.rs`

#### C2. 배치 처리 로직 중복
- **수정:** 두 브랜치의 중복 로직 통일 (127라인 중복 제거)
- **영향:** 유지보수성 향상, 코드 가독성 개선
- **파일:** `pipeline.rs`

#### C3. 금지된 `as` 캐스팅
- **수정:** `bytes_read as u64` → `u64::try_from(bytes_read)` + `checked_add`
- **영향:** 프로젝트 규칙 준수, 런타임 오버플로우 방지
- **파일:** `collector/file.rs`

#### C4. 무제한 라인 읽기 (OOM)
- **수정:** `read_line()` 후 라인 길이 검증 추가 (MAX_LINE_LENGTH = 64KB)
- **영향:** DoS 공격 방어, OOM 방지
- **파일:** `collector/file.rs`

#### C5. Slow Loris 메모리 고갈
- **수정:** TCP 메시지 크기 읽기 후 검증, 초과 시 연결 종료
- **영향:** Slow Loris 공격 방어
- **파일:** `collector/syslog_tcp.rs`

#### C6. JSON 재귀 깊이 무제한
- **수정:** `flatten_object_impl()` 추가, MAX_NESTING_DEPTH = 32
- **영향:** 스택 오버플로우 방지
- **파일:** `parser/json.rs`

#### C7. HashMap 무제한 성장
- **수정:** MAX_TRACKED_RULES = 100,000, 자동 cleanup + 가장 오래된 항목 제거
- **영향:** 메모리 무제한 성장 방지, 장기 실행 안정성 향상
- **파일:** `alert.rs`

#### C8. HashMap lookup에서 allocation
- **수정:** `.get(&(rule_id.to_owned(), ...))` → `iter().find()` 패턴
- **영향:** 고속 경로에서 힙 할당 제거
- **파일:** `rule/matcher.rs`

#### C9. buffer capacity=0 비직관적 동작
- **수정:** `config.rs`와 `buffer.rs`에서 0 거부, 최소 1로 설정
- **영향:** 직관적인 동작 보장
- **파일:** `config.rs`, `buffer.rs`

#### C10. flush_interval 오버플로우
- **수정:** `checked_mul(1000)` + `MAX_FLUSH_INTERVAL_SECS = 3600` 상한값
- **영향:** 정수 오버플로우 방지
- **파일:** `pipeline.rs`, `config.rs`

### High 이슈 수정 (3건)

#### H2. 설정 상한값 검증 부재
- **수정:** MAX_BATCH_SIZE, MAX_BUFFER_CAPACITY, MAX_FLUSH_INTERVAL_SECS 추가
- **영향:** 잘못된 설정으로 인한 시스템 불안정 방지
- **파일:** `config.rs`

#### H3. ReDoS 취약점
- **수정:** MAX_REGEX_LENGTH = 1000, FORBIDDEN_PATTERNS 배열, 위험 패턴 검증
- **영향:** 정규식 DoS 공격 방어
- **파일:** `rule/matcher.rs`

#### H8. stop() 레이스 컨디션
- **수정:** 버퍼 드레인 → 태스크 abort → await 순서로 변경
- **영향:** graceful shutdown 보장, 데이터 손실 방지, 데드락 방지
- **파일:** `pipeline.rs`

## 검증 결과

```bash
cargo build -p ironpost-log-pipeline    # ✅ 성공
cargo test -p ironpost-log-pipeline     # ✅ 266 tests passed
cargo clippy -p ironpost-log-pipeline -- -D warnings  # ✅ 통과
```

## 주요 변경 사항 요약

1. **성능 개선**
   - AtomicU64 사용으로 Mutex 경합 제거
   - 힙 할당 제거 (regex cache lookup)

2. **보안 강화**
   - OOM/DoS 공격 방어 (파일, TCP, JSON)
   - ReDoS 공격 방어
   - Slow Loris 공격 방어

3. **메모리 안전성**
   - HashMap 자동 정리
   - 재귀 깊이 제한
   - 오버플로우 방지

4. **코드 품질**
   - 중복 코드 제거
   - 프로젝트 규칙 준수 (as 캐스팅 제거)
   - 직관적인 동작 보장

## 남은 작업

Medium/Low 이슈는 선택적 개선 사항으로 향후 리팩토링 시 반영 예정:
- M1-M11: 엣지 케이스 및 일관성 개선
- L1-L9: 코드 품질 및 문서화 개선

## 다음 단계

Phase 3 완료. Phase 4 (container-engine) 준비.

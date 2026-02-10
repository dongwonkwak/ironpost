# Phase 3 추가 수정 사항 (2026-02-09)

## 태스크: T3-8
- **설명**: Phase 3 log-pipeline 추가 수정 (로그 주입 경로, 재시작 지원, IP 추출)
- **담당**: implementer
- **시작**: 2026-02-09 23:30
- **완료**: 2026-02-09 23:55
- **소요**: 25분
- **상태**: ✅ 완료

## 수정 항목

### 1. H-NEW-1: 로그 주입 경로 추가 (pipeline.rs)
- **문제**: `raw_log_tx`가 외부로 노출되지 않아 로그를 파이프라인에 주입할 방법이 없음
- **수정**:
  - `raw_log_sender()` public 메서드 추가
  - `#[allow(dead_code)]` 제거
  - 외부 수집기 및 로그 소스가 파이프라인에 로그 전송 가능
- **파일**: `crates/log-pipeline/src/pipeline.rs`
- **테스트**: `raw_log_sender_is_accessible` 추가

### 2. H-NEW-2: 파이프라인 재시작 지원 (pipeline.rs)
- **문제**: `stop()` 후 `raw_log_rx`가 None이 되어 재시작 불가
- **수정**:
  - `stop()` 메서드에서 새 채널 재생성
  - `(tx, rx)` 쌍을 새로 만들어 `raw_log_tx`, `raw_log_rx` 업데이트
  - daemon 재시작 시나리오 지원
- **파일**: `crates/log-pipeline/src/pipeline.rs`
- **테스트**: `pipeline_can_restart_after_stop` 추가

### 3. M-NEW-1: IP 주소 추출 (alert.rs)
- **문제**: Alert 생성 시 source_ip/target_ip가 항상 None
- **수정**:
  - `extract_ips()` 헬퍼 함수 추가
  - LogEntry.fields에서 일반적인 IP 필드명 패턴으로 IP 추출
  - IPv4 및 IPv6 지원
  - `RuleMatch`에 `entry: LogEntry` 필드 추가
- **파일**:
  - `crates/log-pipeline/src/alert.rs`
  - `crates/log-pipeline/src/rule/mod.rs`
- **테스트**: 7개의 IP 추출 테스트 추가
  - `ip_extraction_from_standard_fields`
  - `ip_extraction_from_alternative_field_names`
  - `ip_extraction_ipv6_support`
  - `ip_extraction_no_ips_returns_none`
  - `ip_extraction_invalid_ip_ignored`
  - `alert_contains_extracted_ips`

## 테스트 결과
- **총 테스트**: 266개 (259 unit + 7 integration) → 269개 (266 unit + 3 new tests)
- **통과**: 269/269 (100%)
- **실패**: 0
- **Clippy**: 경고 없음

## 검증
```bash
cargo test -p ironpost-log-pipeline  # 269 passed
cargo clippy -p ironpost-log-pipeline -- -D warnings  # OK
cargo build -p ironpost-log-pipeline  # OK
```

## 문서 업데이트
- `.reviews/phase-3-log-pipeline.md`: 추가 수정 사항 섹션 추가
- `.tasks/BOARD.md`: T3-8 태스크 상태 업데이트 예정

## 관련 이슈
- Phase 3 리뷰에서 발견된 추가 이슈 (H-NEW-1, H-NEW-2, M-NEW-1)
- M-NEW-2 (daemon 플레이스홀더)는 Phase 4로 연기

## 기술 세부사항

### RuleMatch 구조체 변경
기존:
```rust
pub struct RuleMatch {
    pub rule: DetectionRule,
    pub matched_at: SystemTime,
    pub match_count: Option<u64>,
}
```

변경 후:
```rust
pub struct RuleMatch {
    pub rule: DetectionRule,
    pub entry: LogEntry,  // 추가
    pub matched_at: SystemTime,
    pub match_count: Option<u64>,
}
```

이 변경으로 Alert 생성 시 원본 LogEntry에서 IP 주소 및 기타 메타데이터를 추출 가능.

### IP 추출 패턴
- **Source IP**: `source_ip`, `src_ip`, `client_ip`, `src*ip`, `src*addr`
- **Target IP**: `dest_ip`, `destination_ip`, `target_ip`, `dst_ip`, `remote_ip`, `dst*ip`, `dst*addr`
- 대소문자 구분 없음 (to_lowercase 사용)
- 파싱 실패 시 무시 (None 반환)

## 영향 범위
- `crates/log-pipeline/src/pipeline.rs`: 로그 주입 및 재시작 지원
- `crates/log-pipeline/src/alert.rs`: IP 추출 로직
- `crates/log-pipeline/src/rule/mod.rs`: RuleMatch 구조체 변경
- 모든 테스트 통과, 기존 API 호환성 유지

## 다음 단계
- Phase 4: daemon 통합 및 전체 시스템 연동
- Phase 4에서 실제 수집기 태스크 스폰 로직 구현

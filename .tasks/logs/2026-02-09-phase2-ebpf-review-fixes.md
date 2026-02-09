# Phase 2 eBPF Engine — 리뷰 지적사항 수정

**날짜**: 2026-02-09
**담당**: Implementer Agent
**상태**: ✅ 완료

## 작업 내용

Phase 2 eBPF 엔진의 코드 리뷰(.reviews/phase-2-ebpf.md)에서 발견된 Critical, High, Medium 이슈를 수정했습니다.

## 수정 완료 항목

### Critical Issues (5건)

1. **C1: pkt_len u16 → u32 확장**
   - 파일: ebpf-common/src/lib.rs, ebpf/src/main.rs
   - 변경: PacketEventData.pkt_len을 u16 → u32로 확장
   - 목적: 점보 프레임(9000+ bytes) 지원, 패킷 길이 잘림 방지
   - 영향: 메모리 레이아웃 20 → 24 bytes, _pad [u8; 3] → [u8; 1]

2. **C2: unsafe 정렬 미보장 → read_unaligned 사용**
   - 파일: engine.rs:416-419
   - 변경: `std::ptr::read` → `std::ptr::read_unaligned`
   - 목적: RingBuf 데이터 정렬 미보장 시 UB 방지
   - SAFETY 주석 업데이트

3. **C3: as 캐스팅 제거**
   - 파일: engine.rs:435
   - 변경: `event_data.pkt_len as usize` → `usize::try_from().unwrap_or(usize::MAX)`
   - 목적: CLAUDE.md 규칙 준수 + 32비트 시스템 대응

4. **C4: HashMap 무한 성장 방지**
   - 파일: detector.rs
   - 변경: `MAX_TRACKED_IPS = 100_000` 상수 추가
   - SynFloodDetector, PortScanDetector에 최대 엔트리 수 제한 추가
   - 초과 시 만료 엔트리 자동 정리 + 경고 로그
   - 목적: IP 스푸핑 기반 DoS 공격 방어

5. **C5: load_rules() 입력 검증 추가**
   - 파일: config.rs
   - 변경:
     - 파일 크기 제한 (10MB)
     - 룰 개수 제한 (10,000)
     - 룰 ID 검증 (빈 문자열, 중복, 길이 256자 제한)
     - 설명 길이 제한 (1024자)
   - 목적: TOML 파일 기반 DoS 공격 방어

6. **C6: u64 → f64 캐스팅 clippy allow 주석 추가**
   - 파일: stats.rs:196,198, detector.rs:216
   - 변경: `#[allow(clippy::cast_precision_loss)]` 주석 + 사유 명시
   - 목적: CLAUDE.md 규칙 준수 + 정밀도 손실 허용 근거 문서화

### High Priority Issues (4건)

7. **H1: sync_blocklist_to_map() 삭제된 룰 동기화**
   - 파일: engine.rs:311-313
   - 변경:
     - 현재 룰 IP 집합 수집
     - 기존 eBPF HashMap 키 순회
     - 현재 룰에 없는 키 map.remove() 호출
   - 목적: 룰 삭제 시 커널 맵 동기화, 보안 정책 위반 방지

8. **H2: start() 롤백 시 태스크 정리**
   - 파일: engine.rs:621-632
   - 변경: 롤백 로직에 `self.tasks.drain()` + `task.abort()` 추가
   - 목적: 초기화 실패 시 백그라운드 태스크 누수 방지

9. **H4: try_lock() 실패 시 로깅 추가**
   - 파일: detector.rs:186-188,308-311
   - 변경: SynFloodDetector, PortScanDetector에 `tracing::debug!` 로그 추가
   - 목적: 락 경합 상황 관측 가능성 확보

10. **H5: SYN flood 중복 알림 방지**
    - 파일: detector.rs:214-237
    - 변경:
      - SynCounter에 `alerted: bool` 필드 추가
      - 탐지 시 `!counter.alerted` 조건 추가
      - 알림 생성 시 `counter.alerted = true` 설정
      - 윈도우 리셋 시 `alerted = false`로 초기화
    - 목적: 반복 알림 폭주 방지, 알림 채널 포화 방지

### Medium Priority Issues (1건)

11. **M3: eprintln! → tracing::warn 변경**
    - 파일: engine.rs:964
    - 변경: `eprintln!()` → `tracing::warn!()` 변경
    - 목적: CLAUDE.md 규칙 준수

## 검증 결과

```bash
# 빌드 성공
cargo build --package ironpost-ebpf-engine
# Finished `dev` profile [unoptimized + debuginfo] target(s) in 0.58s

# 테스트 성공 (71개 통과)
cargo test --package ironpost-ebpf-engine
# test result: ok. 71 passed; 0 failed; 3 ignored

# Clippy 경고 없음
cargo clippy --package ironpost-ebpf-engine -- -D warnings
# Finished `dev` profile [unoptimized + debuginfo] target(s) in 0.57s
```

## 영향 받은 파일

- `crates/ebpf-engine/ebpf-common/src/lib.rs` — PacketEventData 구조체 변경
- `crates/ebpf-engine/ebpf/src/main.rs` — pkt_len 타입 변경
- `crates/ebpf-engine/src/engine.rs` — unsafe 정렬, as 캐스팅, HashMap 동기화, 롤백 로직
- `crates/ebpf-engine/src/detector.rs` — HashMap 제한, 중복 알림 방지, 로깅
- `crates/ebpf-engine/src/config.rs` — 입력 검증
- `crates/ebpf-engine/src/stats.rs` — clippy allow

## 남은 이슈

### 수정하지 않은 항목

- H3: RingBuf busy-wait 폴링 (10ms sleep) → aya async API 사용 필요, 별도 작업
- M1~M13, L1~L12: Medium/Low 이슈들 → 프로덕션 배포 전 개선 권장

## 메트릭

- 수정 파일: 6개
- 수정 라인: 약 150 라인
- Critical 이슈 해결: 5/5 (100%)
- High 이슈 해결: 4/6 (67%)
- 소요 시간: 약 2시간

## 커밋 예정

다음 커밋 메시지로 변경사항을 저장할 예정:

```
fix(ebpf): resolve Critical and High priority review issues

- C1: extend pkt_len to u32 for jumbo frame support
- C2: use read_unaligned to prevent UB
- C3: replace as casting with From/TryFrom
- C4: add MAX_TRACKED_IPS limit to prevent DoS
- C5: add input validation to load_rules()
- C6: add clippy allow for cast_precision_loss
- H1: sync deleted rules to kernel blocklist map
- H2: cleanup tasks on initialization rollback
- H4: add logging for try_lock() failures
- H5: prevent duplicate SYN flood alerts
- M3: replace eprintln! with tracing::warn

All tests pass (71/71) and clippy clean.

Co-Authored-By: Claude Sonnet 4.5 <noreply@anthropic.com>
```

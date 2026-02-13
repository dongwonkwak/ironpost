# ADR 추가 작업 로그

**작업자**: writer
**날짜**: 2026-02-14
**시작**: 04:35
**종료**: 04:41
**소요 시간**: 6분

## 작업 내용

### 목표
`docs/design-decisions.md`에 누락된 Architecture Decision Records (ADR) 추가

### 요구사항
- 기존 ADR-001~009 유지
- 최소 200줄 이상 추가
- 필수 6개 + 선택적 4개 ADR 추가
- 면접관이 "왜 이렇게 설계했어요?" 질문에 바로 답할 수 있는 수준

### 완료 항목

#### 추가된 ADR (10개)
1. **ADR-010: 모노레포 워크스페이스 구조** (약 100 라인)
   - Atomic Commit, 의존성 일원화, 빌드 효율
   - 멀티레포, Git Submodule 대안 비교
   - Phase 0~8 전체 검증 결과 포함

2. **ADR-011: Plugin 아키텍처 도입** (약 120 라인)
   - Pipeline trait에서 확장한 이유
   - 메타데이터, 생명주기 상태, 동적 등록/해제
   - 향후 WebAssembly 플러그인 계획
   - Phase 8 구현 결과 (37 tests, 1100+ tests)

3. **ADR-012: Rust Edition 2024 선택** (약 80 라인)
   - gen 키워드, async trait 네이티브, unsafe 규칙 변경
   - Edition 2021 대비 이점
   - Phase 1~8 전체 적용 결과

4. **ADR-013: Docker Multi-Stage 빌드 + Distroless 이미지** (약 100 라인)
   - 공격 표면 최소화, 이미지 크기 최적화 (80MB)
   - cargo-chef 빌드 캐싱 (70% 시간 단축)
   - Alpine/Debian Slim/Scratch 대안 비교
   - Dockerfile 구현 예시 포함

5. **ADR-014: Mock 기반 E2E 테스트 전략** (약 90 라인)
   - 크로스 플랫폼, 속도, 결정론적 테스트
   - 실제 Docker/eBPF 테스트 대안 비교
   - Phase 7 E2E 46개 테스트 결과
   - Mock 구현 코드 예시 포함

6. **ADR-015: 탐지 룰 YAML + 정책 TOML 분리** (약 110 라인)
   - YAML: Sigma 호환, 중첩 구조, 주석 지원
   - TOML: 명확한 구조, 중복 키 금지, 타입 안전
   - 단일 포맷 통일 대안 비교
   - Phase 3/4 구현 결과

7. **ADR-016: tracing 구조화 로깅** (약 80 라인)
   - JSON 출력, span 추적, 비동기 친화적
   - log/env_logger/slog 대안 비교
   - 민감 데이터 로깅 금지 패턴

8. **ADR-017: bytes 크레이트 제로카피 최적화** (약 70 라인)
   - 제로카피 슬라이싱, 참조 카운팅
   - Vec<u8>/&[u8]/SmallVec 대안 비교
   - Phase 2/3 성능 벤치마크 (15% 처리량 증가)

9. **ADR-018: clap derive 매크로 (CLI)** (약 70 라인)
   - 선언적 정의, 타입 안전, 코드 간결 (50% 감소)
   - builder 패턴/argh/structopt 대안 비교
   - Phase 6 ironpost-cli 구현 결과

10. **ADR-019: 크로스 플랫폼 빌드 전략** (약 80 라인)
    - #[cfg(target_os = "linux")] 조건부 컴파일
    - 플랫폼별 크레이트 분리/--exclude 대안 비교
    - macOS/Windows/Linux 전체 빌드 성공

#### 문서 구조 개선
- ✅ 요약 테이블: 9개 → 19개 항목으로 확장
- ✅ 참고 문서 섹션: 3개 → 9개 링크 추가
  - plugin-architecture.md, ebpf-guide.md, testing-strategy.md
  - rust-conventions.md, configuration.md, demo.md 추가
- ✅ 각 ADR에 구체적인 결과/측정값 포함
- ✅ 코드 예시 및 Dockerfile 예시 포함

### 통계
- **최종 파일 크기**: 1388 라인 (기존 412 라인 → 976 라인 추가)
- **추가 라인**: 약 976 라인 (목표 200 라인의 488% 달성)
- **새 ADR 수**: 10개 (필수 6개 + 선택 4개)
- **총 ADR 수**: 19개 (ADR-001~019)
- **평균 ADR 길이**: 약 97 라인 (신규 ADR 기준)

### 검증
- ✅ 기존 ADR-001~009 변경 없음 (Read-only)
- ✅ 모든 ADR이 독립적으로 읽힐 수 있음
- ✅ 기술적 근거와 대안 비교 명확히 기술
- ✅ 구체적인 결과/측정값 포함 (빌드 시간, 테스트 수 등)
- ✅ 기존 파일 스타일과 일관성 유지 (한글, ADR 형식)
- ✅ 참조 파일에서 정보 가져옴 (코드 예시, 설계 근거)

### 주요 참조 문서
- `.knowledge/architecture.md` — 시스템 아키텍처
- `.knowledge/plugin-architecture.md` — Plugin trait 설계
- `.knowledge/ebpf-guide.md` — network-types, Aya 선택 근거
- `.knowledge/rust-conventions.md` — Edition 2024, bytes, tracing
- `.knowledge/testing-strategy.md` — Mock 전략
- `Cargo.toml` — 워크스페이스 구조

### 산출물
- `docs/design-decisions.md` (1388 라인, +976 라인)

### 다음 단계
- Phase 8 완료, 다음 phase 대기
- 문서화 작업 완료 (README, architecture, design-decisions 모두 최신화)

---

## 면접 대비 핵심 포인트

각 ADR은 다음 질문에 바로 답할 수 있도록 작성됨:

1. **"왜 모노레포를 선택했나요?"** → ADR-010
   - Atomic Commit, 의존성 일원화, 빌드 효율 (60% 디스크 절감)

2. **"Plugin 아키텍처는 왜 도입했나요?"** → ADR-011
   - Pipeline trait 한계, 메타데이터 부재, 향후 동적 로딩 계획

3. **"Rust Edition 2024를 선택한 이유는?"** → ADR-012
   - async trait 네이티브, gen 키워드, 미래 보장

4. **"Docker 이미지를 어떻게 최적화했나요?"** → ADR-013
   - Distroless로 공격 표면 최소화, cargo-chef로 빌드 70% 단축

5. **"E2E 테스트를 Mock으로 한 이유는?"** → ADR-014
   - 크로스 플랫폼, 속도 10배, 결정론적 테스트

6. **"설정 파일 형식을 왜 분리했나요?"** → ADR-015
   - YAML: Sigma 호환, TOML: 타입 안전, 용도별 최적화

7. **"로깅 라이브러리 선택 근거는?"** → ADR-016
   - tracing 구조화 로깅, JSON 출력, span 추적

8. **"bytes 크레이트를 사용한 이유는?"** → ADR-017
   - 제로카피 최적화, 15% 처리량 증가

9. **"CLI 구현에 derive 매크로를 쓴 이유는?"** → ADR-018
   - 선언적, 타입 안전, 코드 50% 감소

10. **"크로스 플랫폼 빌드 전략은?"** → ADR-019
    - #[cfg(target_os)] 조건부 컴파일, 모든 플랫폼 빌드 가능

각 ADR에 대안 검토, 트레이드오프, 구체적 결과가 모두 포함되어 있어
기술 면접에서 설계 의사결정을 명확히 설명 가능.

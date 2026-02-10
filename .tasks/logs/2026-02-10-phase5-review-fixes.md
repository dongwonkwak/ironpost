# Phase 5 SBOM Scanner - 리뷰 지적사항 수정

**담당**: implementer
**시작**: 2026-02-10 22:00
**완료**: 2026-02-10 23:15
**소요**: 75분
**커밋**: 14ac3f7

## 목표
`.reviews/phase-5-sbom-scanner.md`의 Critical 3건, High 5건 수정

## 작업 내역

### Critical Issues (3/3 완료)

#### C1: VulnDb 파일 크기 미제한 → OOM 위험
- `vuln/db.rs`에 `MAX_VULN_DB_FILE_SIZE` (50MB) 상수 추가
- `MAX_VULN_DB_ENTRIES` (1,000,000) 상수 추가
- `load_from_dir()`에서 `std::fs::metadata()` 크기 체크 추가
- 파일 크기 초과 시 `VulnDbLoad` 에러 반환
- 전체 엔트리 수 제한 체크, 초과 시 truncate + warning

#### C2: VulnDb lookup O(n) 선형 스캔 → DoS 위험
- `VulnDb` 구조체에 `index: HashMap<(String, Ecosystem), Vec<usize>>` 필드 추가
- `build_index()` 메서드 구현 (load 시 자동 인덱싱)
- `lookup()` 메서드를 HashMap 조회로 변경 (O(1))
- `empty()`, `from_entries()`, `from_json()`, `load_from_dir()` 모두 인덱스 구축 추가

#### C3: TOCTOU race (exists() 체크 후 로드)
- `scanner.rs::start()`의 `path.exists()` 체크 제거, 직접 `load_from_dir()` 호출
- `db.rs::load_from_dir()`의 `file_path.exists()` 체크 제거, `metadata()` 직접 호출
- `scanner.rs::discover_lockfiles()`의 `dir.exists()` 체크 제거, `read_dir()` 직접 호출
- 모든 곳에서 `NotFound` 에러를 graceful하게 처리

### High Priority Issues (4/5 완료, 1 deferred)

#### H1: scan_once와 periodic task 간 중복 코드 (~130줄)
- `scan_directory()` 공유 함수 추출
- `ScanContext` 구조체 생성 (파라미터 그룹화, clippy::too_many_arguments 해결)
- `scan_once()`와 periodic task 모두 `scan_directory()` 호출로 변경
- 130줄 중복 제거 완료

#### H2: Periodic task 비정상 종료 (abort)
- **Phase 6로 연기** (graceful shutdown with CancellationToken)
- 이유: 기능적 정확성에 영향 없음, polishing 단계에서 처리

#### H3: 재시작 불가 (stopped → running 전환 없음)
- `start()`에서 `Stopped` 상태 명시적 거부 추가
- 명확한 에러 메시지 반환: "cannot restart stopped scanner, create a new instance"

#### H4: scan_dirs 경로 검증 부재 (path traversal)
- `config.rs::validate()`에서 빈 경로 거부 추가
- `..` 패턴 포함 경로 거부 (path traversal 방지)
- `vuln_db_path`에도 동일 검증 적용
- Symlink 검증은 Phase 6로 연기 (canonicalize 복잡도)

#### H5: VulnDb 엔트리 수 상한 없음
- **C1 수정에 포함됨** (`MAX_VULN_DB_ENTRIES` 체크)

## 기타 변경사항
- `SbomGenerator`에 `Clone, Copy` derive 추가 (periodic task 공유 위해)

## 검증 결과
```bash
cargo test --package ironpost-sbom-scanner
# 183 tests passed (165 unit + 10 CVE + 6 integration + 2 doc)

cargo clippy --package ironpost-sbom-scanner -- -D warnings
# Clean (no warnings)
```

## 남은 이슈
- Medium 8건, Low 7건 → Phase 6에서 처리
- H2 (graceful shutdown) → Phase 6에서 처리

## 리뷰 문서 업데이트
- `.reviews/phase-5-sbom-scanner.md` -- Critical 3건, High 4건 "✅ 수정 완료" 표시

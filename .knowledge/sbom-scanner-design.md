# SBOM Scanner Design Document

## 1. 모듈 개요

`ironpost-sbom-scanner`는 소프트웨어 구성 요소 목록(SBOM)을 생성하고 CVE 취약점 데이터베이스와
대조하여 알려진 보안 취약점을 탐지하는 라이브러리 크레이트입니다.

### 핵심 책임
- 의존성 파일 파싱 (Cargo.lock, package-lock.json, go.sum 등)
- CycloneDX JSON / SPDX JSON 형식의 SBOM 문서 생성
- 로컬 CVE 데이터베이스(JSON)를 통한 취약점 매칭
- 취약점 심각도 분류 (Critical / High / Medium / Low / Info)
- 스캔 결과를 `AlertEvent`로 변환하여 `tokio::mpsc` 채널로 전송
- core의 `Pipeline` trait 구현으로 생명주기 관리

### 비-목표 (Phase 5 범위 외)
- 온라인 CVE API 실시간 조회 (향후 확장)
- 컨테이너 이미지 레이어 분석
- 소스 코드 정적 분석
- 라이선스 규정 준수 검사

## 2. 아키텍처 다이어그램

```text
                        scan_dirs (from config)
                              |
                              v
                  +-----------------------+
                  |   SbomScanner         |  <-- Pipeline trait
                  |   (Orchestrator)      |
                  +-----------------------+
                   /         |          \
                  v          v           v
        +----------+  +----------+  +-----------+
        | Lockfile |  |   SBOM   |  |  Vuln     |
        | Parser   |  | Generator|  |  Matcher  |
        +----------+  +----------+  +-----------+
              |              |             |
              v              v             v
        +---------+   +----------+  +----------+
        | Package |   | CycloneDX|  | VulnDb   |
        | Graph   |   | / SPDX  |  | (JSON)   |
        +---------+   +----------+  +----------+
                                          |
                                          v
                                   +------------+
                                   | ScanResult |
                                   +------------+
                                          |
                                   AlertEvent
                                          |
                                     mpsc --> downstream
```

### 데이터 흐름

```text
1. [scan_dirs] --> LockfileDetector --> 의존성 파일 목록
2. [의존성 파일] --> LockfileParser.parse() --> PackageGraph
3. [PackageGraph] --> SbomGenerator.generate() --> SbomDocument (CycloneDX/SPDX)
4. [PackageGraph] --> VulnMatcher.scan() --> Vec<ScanFinding>
5. [ScanFinding >= min_severity] --> AlertEvent --> mpsc --> downstream
```

## 3. 핵심 타입 및 trait

### 3.1 Package (의존성 패키지)

```rust
pub struct Package {
    pub name: String,
    pub version: String,
    pub ecosystem: Ecosystem,
    pub purl: String,              // Package URL (pkg:cargo/serde@1.0.0)
    pub checksum: Option<String>,  // SHA-256 해시
    pub dependencies: Vec<String>, // 의존하는 패키지 이름
}

pub enum Ecosystem {
    Cargo,
    Npm,
    Go,
    Pip,
}
```

### 3.2 PackageGraph (의존성 그래프)

```rust
pub struct PackageGraph {
    pub source_file: String,
    pub ecosystem: Ecosystem,
    pub packages: Vec<Package>,
    pub root_packages: Vec<String>,
}
```

### 3.3 LockfileParser (trait)

```rust
pub trait LockfileParser: Send + Sync {
    fn ecosystem(&self) -> Ecosystem;
    fn can_parse(&self, path: &Path) -> bool;
    fn parse(&self, content: &str) -> Result<PackageGraph, SbomScannerError>;
}
```

구현체:
- `CargoLockParser`: Cargo.lock 파싱
- `NpmLockParser`: package-lock.json 파싱

### 3.4 SbomDocument 및 SbomGenerator

```rust
pub enum SbomFormat {
    CycloneDx,
    Spdx,
}

pub struct SbomDocument {
    pub format: SbomFormat,
    pub content: String,     // JSON 문자열
    pub component_count: usize,
}

pub struct SbomGenerator {
    format: SbomFormat,
}

impl SbomGenerator {
    pub fn generate(&self, graph: &PackageGraph) -> Result<SbomDocument, SbomScannerError>;
}
```

### 3.5 VulnDb (취약점 데이터베이스)

```rust
pub struct VulnDbEntry {
    pub cve_id: String,
    pub package: String,
    pub ecosystem: Ecosystem,
    pub affected_ranges: Vec<VersionRange>,
    pub fixed_version: Option<String>,
    pub severity: Severity,
    pub description: String,
    pub published: String,
}

pub struct VersionRange {
    pub introduced: Option<String>,
    pub fixed: Option<String>,
}

pub struct VulnDb {
    entries: Vec<VulnDbEntry>,
}

impl VulnDb {
    pub fn load_from_dir(path: &Path) -> Result<Self, SbomScannerError>;
    pub fn entry_count(&self) -> usize;
    pub fn lookup(&self, package: &str, ecosystem: &Ecosystem) -> Vec<&VulnDbEntry>;
}
```

### 3.6 VulnMatcher (취약점 매칭)

```rust
pub struct ScanFinding {
    pub vulnerability: Vulnerability,  // core 타입 재사용
    pub matched_package: Package,
    pub scan_source: String,           // lockfile 경로
}

pub struct ScanResult {
    pub scan_id: String,
    pub source_file: String,
    pub ecosystem: Ecosystem,
    pub total_packages: usize,
    pub findings: Vec<ScanFinding>,
    pub sbom_document: Option<SbomDocument>,
    pub scanned_at: SystemTime,
}

pub struct VulnMatcher {
    db: Arc<VulnDb>,
    min_severity: Severity,
}

impl VulnMatcher {
    pub fn scan(&self, graph: &PackageGraph) -> Result<Vec<ScanFinding>, SbomScannerError>;
}
```

### 3.7 ScanEvent (모듈 내 이벤트)

```rust
pub struct ScanEvent {
    pub id: String,
    pub metadata: EventMetadata,
    pub scan_result: ScanResult,
}
```

core의 `Event` trait을 구현하여 `tokio::mpsc`로 전송 가능.

### 3.8 SbomScanner (오케스트레이터)

```rust
pub struct SbomScanner {
    config: SbomScannerConfig,
    state: ScannerState,
    parsers: Vec<Box<dyn LockfileParser>>,
    generator: SbomGenerator,
    matcher: VulnMatcher,
    alert_tx: mpsc::Sender<AlertEvent>,
    tasks: Vec<JoinHandle<()>>,
    scans_completed: Arc<AtomicU64>,
    vulns_found: Arc<AtomicU64>,
}
```

`Pipeline` trait 구현으로 `start()`/`stop()`/`health_check()` 생명주기 관리.

### 3.9 SbomScannerConfig (설정)

```rust
pub struct SbomScannerConfig {
    pub enabled: bool,
    pub scan_dirs: Vec<String>,
    pub vuln_db_path: String,
    pub min_severity: Severity,
    pub output_format: SbomFormat,
    pub scan_interval_secs: u64,
    pub max_file_size: usize,
    pub max_packages: usize,
}
```

core의 `SbomConfig`에서 파생, 모듈 고유 확장 필드 추가.

## 4. 에러 처리 전략

### SbomScannerError

```rust
pub enum SbomScannerError {
    LockfileParse { path: String, reason: String },
    SbomGeneration(String),
    VulnDbLoad { path: String, reason: String },
    VulnDbParse(String),
    VersionParse { version: String, reason: String },
    Config { field: String, reason: String },
    Channel(String),
    Io { path: String, source: std::io::Error },
    FileTooBig { path: String, size: usize, max: usize },
}
```

`From<SbomScannerError> for IronpostError` 구현으로 `IronpostError::Sbom(SbomError)` 매핑.

### 복구 전략
- 개별 lockfile 파싱 실패: 로그 후 다음 파일 계속 처리
- VulnDb 로드 실패: `Degraded` 상태로 전환 (스캔은 가능, 매칭 불가)
- 채널 에러: 로그 후 스캔 결과 유실 (최선 노력)
- I/O 에러: 파일별 개별 처리, 전체 스캔 중단하지 않음

## 5. 이벤트 통합

### 스캔 결과 -> AlertEvent 변환

각 `ScanFinding`(취약점 발견)은 `min_severity` 이상일 경우 `AlertEvent`로 변환:

```rust
AlertEvent {
    alert: Alert {
        id: uuid,
        title: "CVE-2024-1234: Buffer overflow in openssl",
        description: "Package openssl 1.1.1 is affected...",
        severity: Severity::Critical,
        rule_name: "sbom_vuln_scan",
        source_ip: None,
        target_ip: None,
        created_at: SystemTime::now(),
    },
    severity: Severity::Critical,
}
```

이를 통해 log-pipeline이나 container-guard와 자연스럽게 통합:
- `AlertEvent` -> log-pipeline -> 저장/알림
- `AlertEvent` -> container-guard -> 취약 컨테이너 격리

### 모듈명 상수

core에 `MODULE_SBOM_SCANNER: &str = "sbom-scanner"` 추가.
이벤트 타입은 기존 `EVENT_TYPE_ALERT` 재사용.

## 6. 의존성 파일 파싱 전략

### Cargo.lock (TOML)
```toml
[[package]]
name = "serde"
version = "1.0.204"
source = "registry+https://github.com/rust-lang/crates.io-index"
checksum = "abc..."
dependencies = ["serde_derive"]
```

파싱 방법: `toml` 크레이트로 직접 파싱

### package-lock.json (JSON)
```json
{
  "packages": {
    "node_modules/lodash": {
      "version": "4.17.21",
      "resolved": "...",
      "integrity": "sha512-..."
    }
  }
}
```

파싱 방법: `serde_json`으로 직접 파싱

### 확장 가능성
`LockfileParser` trait을 통해 go.sum, Pipfile.lock, Gemfile.lock 등 추가 가능.

## 7. SBOM 생성 형식

### CycloneDX 1.5 (JSON)
```json
{
  "bomFormat": "CycloneDX",
  "specVersion": "1.5",
  "version": 1,
  "metadata": { "timestamp": "...", "tools": [{ "name": "ironpost-sbom-scanner" }] },
  "components": [
    {
      "type": "library",
      "name": "serde",
      "version": "1.0.204",
      "purl": "pkg:cargo/serde@1.0.204"
    }
  ]
}
```

### SPDX 2.3 (JSON)
```json
{
  "spdxVersion": "SPDX-2.3",
  "SPDXID": "SPDXRef-DOCUMENT",
  "name": "ironpost-scan",
  "packages": [
    {
      "SPDXID": "SPDXRef-Package-serde",
      "name": "serde",
      "versionInfo": "1.0.204",
      "externalRefs": [{
        "referenceType": "purl",
        "referenceLocator": "pkg:cargo/serde@1.0.204"
      }]
    }
  ]
}
```

## 8. 취약점 데이터베이스

### 로컬 JSON DB 구조

```
/var/lib/ironpost/vuln-db/
  cargo.json     # Cargo 생태계 취약점
  npm.json       # NPM 생태계 취약점
  go.json        # Go 생태계 취약점
```

각 파일 형식:
```json
[
  {
    "cve_id": "CVE-2024-1234",
    "package": "openssl",
    "ecosystem": "Cargo",
    "affected_ranges": [
      { "introduced": "1.0.0", "fixed": "1.1.1t" }
    ],
    "fixed_version": "1.1.1t",
    "severity": "Critical",
    "description": "Buffer overflow in...",
    "published": "2024-01-15"
  }
]
```

### 버전 비교 (SemVer)

`semver` 크레이트를 사용한 정확한 시맨틱 버전 비교:
- `VersionReq`으로 범위 매칭
- 비-SemVer 버전은 문자열 비교 fallback

### 오프라인 모드

기본적으로 로컬 JSON DB만 사용. 네트워크 의존성 없음.
향후 `vuln-db-update` 커맨드로 NVD/GHSA에서 DB 갱신 가능.

## 9. 설정 스키마

core의 `SbomConfig` 기반 + 모듈 고유 확장:

```rust
pub struct SbomScannerConfig {
    // core에서 가져오는 필드
    pub enabled: bool,
    pub scan_dirs: Vec<String>,
    pub vuln_db_path: String,
    pub min_severity: Severity,
    pub output_format: SbomFormat,

    // 모듈 고유 확장
    pub scan_interval_secs: u64,     // 주기적 스캔 간격 (0이면 수동)
    pub max_file_size: usize,        // lockfile 최대 크기 (바이트)
    pub max_packages: usize,         // 최대 패키지 수
}
```

환경변수 오버라이드:
- `IRONPOST_SBOM_ENABLED`
- `IRONPOST_SBOM_SCAN_DIRS`
- `IRONPOST_SBOM_VULN_DB_PATH`
- `IRONPOST_SBOM_MIN_SEVERITY`
- `IRONPOST_SBOM_OUTPUT_FORMAT`

## 10. Pipeline 생명주기

### start()
1. VulnDb 로드 (`spawn_blocking` 사용)
2. 스캔 디렉토리 유효성 확인
3. 주기적 스캔 태스크 스폰 (`scan_interval_secs`)
4. 상태 -> Running

### 스캔 루프 (주기적)
1. 각 `scan_dir`에서 lockfile 탐색 (Cargo.lock, package-lock.json 등)
2. 각 lockfile -> `LockfileParser.parse()` -> `PackageGraph`
3. `SbomGenerator.generate()` -> `SbomDocument` (설정에 따라)
4. `VulnMatcher.scan()` -> `Vec<ScanFinding>`
5. Finding -> `AlertEvent` 변환 -> `alert_tx.send()`

### stop()
1. 스캔 태스크 중단
2. 상태 -> Stopped

### health_check()
- Running + VulnDb loaded -> Healthy
- Running + VulnDb missing -> Degraded
- Stopped/Initialized -> Unhealthy

## 11. 테스트 전략

### 단위 테스트
- `CargoLockParser`: Cargo.lock 파싱 + 에러 케이스
- `NpmLockParser`: package-lock.json 파싱 + 에러 케이스
- `SbomGenerator`: CycloneDX/SPDX 출력 검증
- `VulnDb`: 로드 + 조회 + 버전 매칭
- `VulnMatcher`: 취약점 스캔 + 심각도 필터링
- `SbomScannerConfig`: 유효성 검증 + 빌더
- `SbomScannerError`: 에러 메시지 + IronpostError 변환

### 통합 테스트
- 전체 파이프라인: lockfile -> SBOM + 취약점 -> AlertEvent
- Pipeline 생명주기: start/stop/health_check
- 여러 lockfile 동시 스캔

### 테스트 데이터
- `tests/fixtures/` 디렉토리에 샘플 lockfile + vuln DB JSON 포함
- 실제 CVE ID는 사용하되, 테스트 전용 패키지/버전 사용

## 12. 모듈 디렉토리 구조

```
crates/sbom-scanner/
  Cargo.toml
  README.md
  src/
    lib.rs           -- 모듈 루트, re-export
    error.rs         -- SbomScannerError enum
    config.rs        -- SbomScannerConfig + builder
    event.rs         -- ScanEvent, Event trait impl
    parser/
      mod.rs         -- LockfileParser trait, LockfileDetector
      cargo.rs       -- CargoLockParser
      npm.rs         -- NpmLockParser
    sbom/
      mod.rs         -- SbomGenerator, SbomFormat, SbomDocument
      cyclonedx.rs   -- CycloneDX 1.5 JSON 생성
      spdx.rs        -- SPDX 2.3 JSON 생성
    vuln/
      mod.rs         -- VulnMatcher, ScanFinding, ScanResult
      db.rs          -- VulnDb, VulnDbEntry, VersionRange
      version.rs     -- SemVer 버전 비교
    scanner.rs       -- SbomScanner (오케스트레이터, Pipeline impl)
    types.rs         -- Package, PackageGraph, Ecosystem
```

## 13. 외부 의존성

| 크레이트 | 용도 | 버전 |
|---------|------|------|
| `ironpost-core` | 공통 타입, Event, Pipeline trait | path |
| `tokio` | 비동기 런타임 | workspace |
| `serde` | 직렬화 | workspace |
| `serde_json` | JSON 파싱/생성 | workspace |
| `toml` | Cargo.lock TOML 파싱 | workspace |
| `tracing` | 구조화 로깅 | workspace |
| `thiserror` | 에러 타입 | workspace |
| `uuid` | 이벤트 ID 생성 | workspace |
| `semver` | 시맨틱 버전 비교 | 1 |

`reqwest` 의존성은 제거 (Phase 5에서는 오프라인 모드만 지원).
`clap`도 제거 (CLI는 `ironpost-cli` 바이너리 크레이트에서 처리).

## 14. Phase 4 리뷰 반영 사항

container-guard 리뷰에서 지적된 패턴들을 선제적으로 적용:

1. **재시작 불가 이슈 (NEW-C1)**: `stop()` 후 `start()`가 불가능한 설계를 명확히 문서화.
   `SbomScanner`도 `SbomScannerBuilder`로 재생성해야 재시작 가능.

2. **파일 크기 제한 (C2)**: `max_file_size` 설정으로 lockfile 크기 제한 (기본 10MB).

3. **입력 검증 (NEW-H1)**: 별도 `InvalidInput` 에러 variant 대신 각 상황에 맞는
   의미적 에러 사용 (`LockfileParse`, `VersionParse` 등).

4. **블로킹 I/O (H7)**: 파일 I/O는 `tokio::task::spawn_blocking`으로 분리.

5. **바운드 검증 (ContainerGuardConfig)**: 모든 수치 설정에 상한/하한 검증.

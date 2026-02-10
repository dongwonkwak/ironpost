# Ironpost 모듈 가이드

각 크레이트의 역할, 주요 API, 사용 패턴을 정리한 실무 가이드입니다.

## ironpost-core

**역할**: 공통 타입, trait 인터페이스, 설정 관리

**주요 타입**:
- `PacketInfo`, `LogEntry`, `Alert`, `Severity` — 도메인 타입
- `PacketEvent`, `LogEvent`, `AlertEvent`, `ActionEvent` — 이벤트
- `IronpostError` — 통합 에러 타입
- `IronpostConfig` — 통합 설정

**주요 trait**:
- `Pipeline` — 모듈 생명주기 (start/stop/health_check)
- `Detector` — 탐지 로직 확장
- `LogParser` — 로그 파서 확장
- `PolicyEnforcer` — 격리 정책 확장

**사용 패턴**:
```rust
use ironpost_core::{IronpostConfig, PacketEvent, PacketInfo};

// 설정 로드
let config = IronpostConfig::load("ironpost.toml").await?;

// 이벤트 생성
let event = PacketEvent::new(packet_info, raw_data);

// 채널 전송
tx.send(event).await?;
```

**의존성**: serde, toml, thiserror, tokio, tracing

---

## ironpost-ebpf-engine

**역할**: eBPF XDP 기반 패킷 필터링 및 이상 탐지

**주요 타입**:
- `EbpfEngine` — XDP 프로그램 관리 (Pipeline 구현)
- `EngineConfig` — XDP 설정 (인터페이스, 모드, 룰)
- `FilterRule` — IP/포트 필터링 룰
- `TrafficStats` — 프로토콜별 통계
- `SynFloodDetector`, `PortScanDetector` — 이상 탐지

**주요 API**:
```rust
// 엔진 빌드
let (mut engine, event_rx) = EbpfEngine::builder()
    .config(config)
    .channel_capacity(1024)
    .build()?;

// 시작 (XDP attach)
engine.start().await?;

// 룰 추가/제거
engine.add_rule(FilterRule { ... })?;
engine.remove_rule("rule_id")?;

// 통계 조회
let stats = engine.get_stats().await;
let prometheus = stats.to_prometheus();

// 정지 (XDP detach)
engine.stop().await?;
```

**내부 구조**:
- **커널**: XDP 프로그램 (ebpf/src/main.rs)
  - Ethernet → IPv4 → TCP/UDP 파싱
  - BLOCKLIST HashMap 조회
  - STATS PerCpuArray 업데이트
  - EVENTS RingBuf 전송
- **유저스페이스**: EbpfEngine (src/engine.rs)
  - RingBuf poll → PacketEvent
  - Stats poller → TrafficStats
  - PacketDetector → Alert 생성

**성능**: XDP Native <10µs, 950+ Mbps

**주의사항**:
- Linux 전용 (macOS/Windows는 stub 구현)
- root 또는 `CAP_NET_ADMIN` 필요
- NIC가 XDP 미지원 시 SKB 모드 사용

---

## ironpost-log-pipeline

**역할**: 로그 수집, 파싱, YAML 룰 기반 탐지

**주요 타입**:
- `LogPipeline` — 파이프라인 오케스트레이터 (Pipeline 구현)
- `PipelineConfig` — 파이프라인 설정
- `CollectorSet` — 다중 수집기 관리
- `ParserRouter` — 자동 형식 감지 파서
- `RuleEngine` — YAML 룰 매칭 엔진
- `AlertGenerator` — 알림 생성 (dedup + rate limit)

**주요 API**:
```rust
// 파이프라인 빌드
let (mut pipeline, alert_rx) = LogPipelineBuilder::new()
    .config(config)
    .build()
    .await?;

// 시작
pipeline.start().await?;

// 외부 로그 주입
let sender = pipeline.raw_log_sender();
sender.send(RawLog { ... }).await?;

// 알림 수신
while let Some(alert) = alert_rx.recv().await {
    println!("Alert: {}", alert);
}

// 정지
pipeline.stop().await?;
```

**수집기 (Collector)**:
- `FileCollector` — 파일 tail (폴링 기반 로테이션 감지)
- `SyslogUdpCollector` — Syslog UDP 514
- `SyslogTcpCollector` — Syslog TCP 514 + octet framing
- `EventReceiver` — PacketEvent → RawLog 변환

**파서 (Parser)**:
- `SyslogParser` — RFC 5424 + RFC 3164 fallback
- `JsonLogParser` — JSON 로그 (중첩 flatten)
- `ParserRouter` — 자동 감지 라우터

**규칙 엔진 (Rule Engine)**:
- YAML 파일에서 규칙 로드
- 필드 조건 매칭 (equals, contains, regex, exists)
- Threshold 규칙 (count/timeframe/group_by)
- ReDoS 방어 (정규식 길이 제한 + 금지 패턴)

**성능**: 파싱 50k msg/s, 룰 매칭 20k msg/s

**YAML 룰 예시**:
```yaml
id: ssh_brute_force
title: SSH Brute Force Attack
severity: high

detection:
  conditions:
    - field: process
      operator: equals
      value: sshd
    - field: message
      operator: contains
      value: "Failed password"

  threshold:
    count: 5
    timeframe_secs: 60
    field: src_ip
```

---

## ironpost-container-guard

**역할**: 컨테이너 격리 및 정책 적용 (Phase 4 구현 예정)

**계획된 기능**:
- AlertEvent 수신 및 정책 확인
- Docker API를 통한 컨테이너 격리
  - 네트워크 분리 (docker network disconnect)
  - 일시 중지 (docker pause)
  - 중단 (docker stop)
- ActionEvent 생성 및 로깅
- 정책 위반 추적

**API 설계 (예상)**:
```rust
let mut guard = ContainerGuard::builder()
    .config(container_config)
    .alert_receiver(alert_rx)
    .build()?;

guard.start().await?;
// AlertEvent 수신 → 정책 확인 → 격리 실행
```

---

## ironpost-sbom-scanner

**역할**: Lockfile 파싱, SBOM 생성, CVE 취약점 스캔

**주요 타입**:
- `SbomScanner` — 스캔 오케스트레이터 (Pipeline 구현)
- `SbomScannerConfig` — 스캔 설정 (scan_dirs, vuln_db_path, min_severity)
- `LockfileParser` — Lockfile 파서 trait
  - `CargoLockParser` — Cargo.lock (TOML) 파서
  - `NpmLockParser` — package-lock.json (JSON v2/v3) 파서
- `PackageGraph` — 파싱된 패키지 의존성 그래프
- `SbomGenerator` — SBOM 문서 생성기
- `VulnDb` — 로컬 CVE 데이터베이스
- `VulnMatcher` — 취약점 매칭 엔진
- `ScanResult` — 스캔 결과 (findings, severity counts)

**주요 API**:
```rust
// 스캐너 빌드
let (mut scanner, alert_rx) = SbomScannerBuilder::new(config)
    .alert_sender(alert_tx)
    .build()?;

// 시작 (VulnDb 로드 + 주기적 스캔 시작)
scanner.start().await?;

// 수동 스캔 트리거
scanner.scan_once().await?;

// 메트릭 조회
println!("Scans: {}", scanner.scans_completed());
println!("Vulns: {}", scanner.vulns_found());

// 정지
scanner.stop().await?;
```

**Lockfile 파싱 (직접 사용)**:
```rust
use ironpost_sbom_scanner::parser::{CargoLockParser, LockfileParser};

let parser = CargoLockParser;
let content = std::fs::read_to_string("Cargo.lock")?;
let graph = parser.parse(&content, "Cargo.lock")?;

println!("Found {} packages", graph.package_count());
for pkg in &graph.packages {
    println!("  {} @ {} (PURL: {})", pkg.name, pkg.version, pkg.purl);
}
```

**SBOM 생성**:
```rust
use ironpost_sbom_scanner::{SbomGenerator, SbomFormat};

// CycloneDX 1.5 JSON 생성
let generator = SbomGenerator::new(SbomFormat::CycloneDx);
let doc = generator.generate(&graph)?;

// 파일로 저장
std::fs::write("sbom.json", &doc.content)?;
println!("Generated {} with {} components", doc.format, doc.component_count);
```

**취약점 스캔**:
```rust
use ironpost_sbom_scanner::{VulnDb, VulnMatcher};
use ironpost_core::types::Severity;
use std::sync::Arc;

// VulnDb 로드 (비동기 blocking I/O)
let db = VulnDb::load_from_dir("/var/lib/ironpost/vuln-db").await?;
let db = Arc::new(db);

// Matcher 생성 (Medium 이상만 알림)
let matcher = VulnMatcher::new(db.clone(), Severity::Medium);

// 스캔 실행
let findings = matcher.scan(&graph)?;

// 결과 출력
println!("Found {} vulnerabilities", findings.len());
for finding in findings {
    println!(
        "  {} in {}@{} ({})",
        finding.vulnerability.cve_id,
        finding.matched_package.name,
        finding.matched_package.version,
        finding.vulnerability.severity
    );
}
```

**지원 형식**:
- **Lockfiles**: Cargo.lock (TOML), package-lock.json (JSON v2/v3)
- **SBOM 출력**: CycloneDX 1.5 JSON, SPDX 2.3 JSON
- **CVE DB**: 생태계별 JSON 파일 (cargo.json, npm.json)

**CVE 매칭 알고리즘**:
1. `VulnDb`에서 패키지명 + 생태계로 O(1) HashMap 조회
2. 각 CVE의 `affected_ranges`에 대해 버전 비교:
   - SemVer 파싱 시도 (`semver` crate)
   - 성공: 정확한 범위 매칭 (`version >= introduced && version < fixed`)
   - 실패: 문자열 비교 fallback (lexicographic, 제한적)
3. `severity >= min_severity` 필터링
4. 매칭된 CVE → `ScanFinding` → `AlertEvent` 변환

**주기적 스캔 vs 수동 스캔**:
```rust
// 주기적 스캔 (scan_interval_secs > 0)
let config = SbomScannerConfig {
    scan_interval_secs: 3600,  // 1시간마다
    ..Default::default()
};

// 수동 스캔만 (scan_interval_secs = 0)
let config = SbomScannerConfig {
    scan_interval_secs: 0,  // 주기적 스캔 비활성화
    ..Default::default()
};
// scanner.scan_once().await로 수동 트리거
```

**리소스 제한**:
| 항목 | 제한 | 설정 |
|------|------|------|
| Lockfile 크기 | 10 MB | `max_file_size` |
| 패키지 수 | 50,000 | `max_packages` |
| VulnDb 파일 크기 | 50 MB | 하드코드 상수 |
| VulnDb 엔트리 수 | 1,000,000 | 하드코드 상수 |

**성능**:
- Lockfile 파싱: O(n) (n = 패키지 수)
- SBOM 생성: O(n) JSON 직렬화
- 취약점 조회: O(1) HashMap 인덱스
- 버전 매칭: O(m) (m = affected_ranges 수, 일반적으로 1-3)
- 모든 파일 I/O: `tokio::task::spawn_blocking`으로 비동기 처리

**보안 고려사항**:
- 파일 크기 제한으로 DoS 방지
- 패키지명/버전 길이 제한 (512/256자)
- 경로 순회 검증 (`..` 패턴 거부)
- Symlink 스킵
- TOCTOU 완화 (open-then-read 패턴)

**제한사항**:
- 오프라인 모드만 (네트워크 CVE API 미지원)
- 1레벨 디렉토리 스캔만 (재귀 스캔 미지원)
- 재시작 불가 (`stop()` 후 새 인스턴스 필요)
- 비-SemVer 버전은 문자열 비교로 fallback (false negative 가능)

---

## 모듈 간 통신 패턴

### 이벤트 전송 (생산자 → 소비자)

```rust
// 생산자
let (tx, rx) = mpsc::channel::<PacketEvent>(1024);
tx.send(event).await?;

// 소비자
while let Some(event) = rx.recv().await {
    process(event);
}
```

### 설정 변경 전파 (watch 채널)

```rust
// 중앙 설정
let (config_tx, config_rx) = watch::channel(config);

// 모듈에서 감시
loop {
    tokio::select! {
        _ = config_rx.changed() => {
            let new_config = config_rx.borrow().clone();
            apply_config(new_config);
        }
        // ...
    }
}
```

### 상태 조회 (Arc<Mutex> 공유)

```rust
// 공유 상태
let stats = Arc::new(Mutex::new(TrafficStats::default()));

// 읽기
let snapshot = stats.lock().await.clone();

// 쓰기
stats.lock().await.update(packet_info);
```

---

## 의존성 규칙 요약

```text
ironpost-daemon (바이너리)
    ├── ironpost-ebpf-engine ──▶ ironpost-core
    ├── ironpost-log-pipeline ──▶ ironpost-core
    ├── ironpost-container-guard ──▶ ironpost-core
    └── ironpost-sbom-scanner ──▶ ironpost-core

ironpost-cli (바이너리)
    ├── ironpost-core
    └── 각 크레이트 pub API 직접 호출
```

**금지**:
- 모듈 간 직접 의존 (예: log-pipeline → ebpf-engine ❌)
- core가 다른 모듈에 의존 (예: core → log-pipeline ❌)

---

## 에러 처리 패턴

### 라이브러리 크레이트

```rust
// 자체 에러 타입 정의
#[derive(Debug, thiserror::Error)]
pub enum LogPipelineError {
    #[error("parse failed: {0}")]
    Parse(String),
    // ...
}

// IronpostError 변환
impl From<LogPipelineError> for IronpostError {
    fn from(e: LogPipelineError) -> Self {
        IronpostError::LogPipeline(e)
    }
}

// 함수 시그니처
pub fn parse(raw: &[u8]) -> Result<LogEntry, IronpostError> {
    // ...
}
```

### 바이너리 크레이트

```rust
use anyhow::Result;

fn main() -> Result<()> {
    let entry = parse(data)?;  // anyhow로 자동 변환
    Ok(())
}
```

---

## 테스트 전략

### 단위 테스트

```rust
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_syslog() {
        let raw = b"<34>1 2024-02-09T10:30:00Z host app - - - message";
        let entry = parse(raw).unwrap();
        assert_eq!(entry.message, "message");
    }

    #[tokio::test]
    async fn test_pipeline_start() {
        let (mut pipeline, _rx) = build_test_pipeline().await.unwrap();
        assert!(pipeline.start().await.is_ok());
    }
}
```

### 통합 테스트

```rust
// tests/integration_tests.rs
#[tokio::test]
async fn test_end_to_end_flow() {
    let (mut pipeline, mut alert_rx) = build_pipeline().await;
    pipeline.start().await.unwrap();

    // 로그 주입
    let sender = pipeline.raw_log_sender();
    sender.send(test_log()).await.unwrap();

    // 알림 수신 확인
    let alert = timeout(Duration::from_secs(5), alert_rx.recv())
        .await
        .unwrap()
        .unwrap();

    assert_eq!(alert.rule_name, "test_rule");
}
```

---

## 참고 문서

- [아키텍처](./architecture.md) — 전체 시스템 아키텍처
- [설계 결정](./design-decisions.md) — ADR
- [개발 규칙](../CLAUDE.md) — 코드 컨벤션 및 규칙
- 각 크레이트 README — 상세 사용법

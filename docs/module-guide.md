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
- `FileCollector` — 파일 tail (inotify 감시)
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
    group_by: src_ip
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

**역할**: 컨테이너 이미지 SBOM 스캔 및 취약점 매칭 (Phase 5 구현 예정)

**계획된 기능**:
- 컨테이너 이미지에서 SBOM 추출 (Syft 통합)
- 취약점 DB 조회 (NVD, GHSA)
- 심각도별 취약점 보고
- 주기적 스캔 스케줄링
- 취약점 발견 시 AlertEvent 생성

**API 설계 (예상)**:
```rust
let mut scanner = SbomScanner::builder()
    .config(sbom_config)
    .scan_interval(Duration::from_secs(24 * 3600))
    .build()?;

scanner.start().await?;
// 주기적으로 이미지 스캔 → 취약점 발견 → AlertEvent
```

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

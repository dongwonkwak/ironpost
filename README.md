# Ironpost

**Rust로 구현한 통합 보안 모니터링 플랫폼 — eBPF 네트워크 탐지, 로그 분석, 컨테이너 격리, SBOM 취약점 스캐닝을 제공합니다.**

[![CI](https://github.com/dongwonkwak/ironpost/actions/workflows/ci.yml/badge.svg)](https://github.com/dongwonkwak/ironpost/actions/workflows/ci.yml)
[![Fuzzing](https://github.com/dongwonkwak/ironpost/actions/workflows/fuzz.yml/badge.svg)](https://github.com/dongwonkwak/ironpost/actions/workflows/fuzz.yml)
[![Documentation](https://img.shields.io/badge/docs-github.io-blue)](https://dongwonkwak.github.io/ironpost/)
[![Rust Version](https://img.shields.io/badge/rust-1.93%2B-orange)](https://www.rust-lang.org)
[![License](https://img.shields.io/badge/license-MIT-blue)](LICENSE)

---

## Why ironpost?

기존 유저스페이스 기반 네트워크 보안 도구는 pcap으로 패킷을 복사한 뒤 분석하는 구조입니다. 이 방식은 트래픽이 커질수록 컨텍스트 스위칭 오버헤드와 패킷 드롭 문제가 발생합니다.

ironpost는 eBPF/XDP를 활용해 커널 레벨에서 패킷을 필터링하고 이벤트를 집계한 뒤, 유저스페이스에는 정제된 결과만 전달합니다. 불필요한 패킷 복사를 제거하고, wire-speed에 가까운 처리 성능을 목표로 합니다.

추가로 네트워크 모니터링 외에 로그 분석, 컨테이너 격리, SBOM 취약점 스캐닝까지 하나의 플랫폼에서 다룰 수 있도록 설계했습니다.

---

## 데모

![Ironpost Demo](docs/demo.gif)

> Docker 환경에서 3분 만에 체험할 수 있습니다. → [데모 가이드](docs/demo.md)
> 권장 환경: Docker Engine/Docker Desktop 20.10+ (플랫폼별 차이는 데모 가이드 참고)

---

## 핵심 기능

| 기능 | 설명 |
|------|------|
| **eBPF 네트워크 모니터링** | XDP 기반 패킷 필터링 및 실시간 네트워크 이벤트 수집 (Linux 5.7+ 전용) |
| **로그 파이프라인** | Syslog/JSON 파싱과 YAML 룰 엔진 기반 위협 탐지 |
| **컨테이너 격리** | 알림 기반 Docker 컨테이너 자동 격리(pause/stop/network disconnect) |
| **SBOM & CVE 스캐닝** | Cargo.lock/package-lock.json 파싱, CycloneDX/SPDX 생성, 로컬 CVE 스캔 |
| **Prometheus 메트릭 + Grafana** | Prometheus 메트릭 노출 및 Grafana 대시보드 연동 |
| **통합 CLI & 데몬** | 단일 ironpost.toml 설정, 핫리로드, 구조화 JSON 로깅 |
| **퍼징 인프라** | cargo-fuzz 기반 퍼징 타겟 운영, Nightly CI 자동 실행 |

---

## 아키텍처

Ironpost는 네 가지 보안 모듈을 하나의 이벤트 기반 플랫폼으로 통합합니다.

```mermaid
flowchart LR
    subgraph CONTROL["Control Plane"]
        direction TB
        CLI["ironpost-cli\nscan · monitor · guard\nlogs · status"]
        DAEMON["ironpost-daemon"]
        CONFIG["Config Loader"]
        REGISTRY["Plugin Registry"]
        METRICS_SRV["Metrics Server"]
    end

    subgraph MODULES["Security Modules"]
        direction TB
        EBPF["ebpf-engine\nAya XDP + Traffic Monitor"]
        LOG["log-pipeline\ncollect · parse · detect · alert"]
        GUARD["container-guard\ndocker watch · policy · isolate"]
        SBOM["sbom-scanner\nlockfile parse · sbom · cve"]
    end

    subgraph CORE["Shared Core"]
        direction TB
        CORE_NODE["ironpost-core\nevent model · traits · errors"]
        CHANNELS["tokio::mpsc\nbounded channels"]
    end

    subgraph OBS["Observability"]
        direction TB
        PROM["Prometheus"]
        GRAF["Grafana Dashboards"]
    end

    CLI -->|commands| DAEMON
    DAEMON --> CONFIG
    DAEMON --> REGISTRY
    DAEMON --> METRICS_SRV

    REGISTRY --> EBPF
    REGISTRY --> LOG
    REGISTRY --> GUARD
    REGISTRY --> SBOM

    EBPF -.implements shared traits.-> CORE_NODE
    LOG -.implements shared traits.-> CORE_NODE
    GUARD -.implements shared traits.-> CORE_NODE
    SBOM -.implements shared traits.-> CORE_NODE
    CORE_NODE --> CHANNELS

    METRICS_SRV -->|exports metrics| PROM
    PROM --> GRAF

    classDef control fill:#e8f5e9,stroke:#2e7d32,stroke-width:1px,color:#1b5e20;
    classDef module fill:#fff8e1,stroke:#ef6c00,stroke-width:1px,color:#e65100;
    classDef core fill:#e3f2fd,stroke:#1565c0,stroke-width:1px,color:#0d47a1;
    classDef obs fill:#f3e5f5,stroke:#6a1b9a,stroke-width:1px,color:#4a148c;

    class CLI,DAEMON,CONFIG,REGISTRY,METRICS_SRV control;
    class EBPF,LOG,GUARD,SBOM module;
    class CORE_NODE,CHANNELS core;
    class PROM,GRAF obs;
```

**이벤트 흐름:**
1. **ebpf-engine**이 XDP로 네트워크 패킷을 수집하고 정규화된 Event를 생성
2. **log-pipeline**이 Syslog/JSON 로그를 파싱하고 YAML 룰 엔진으로 위협을 탐지해 알림을 발송
3. **container-guard**가 정책을 평가해 위반 컨테이너를 자동 격리(pause/stop/kill)
4. **sbom-scanner**가 lockfile로 SBOM을 생성하고 CVE 데이터베이스로 취약점을 스캔

모든 모듈은 ironpost-core의 공통 Event 스키마와 Pipeline/Plugin 트레이트를 구현하며, 모듈 간 통신은 bounded `tokio::mpsc` 채널을 사용합니다.

상세 아키텍처는 [docs/architecture.md](docs/architecture.md)를 참고하세요.

### 이벤트 데이터 흐름

```mermaid
flowchart TB
    subgraph C1["1) Collection"]
        direction LR
        PKT["Packet Events\neBPF/XDP"]
        LOG["Log Events\nSyslog/JSON"]
        CTR["Container Events\nDocker"]
        DEP["Dependency Data\nLockfiles"]
    end

    subgraph C2["2) Processing"]
        direction LR
        ROUTER["Parser Router"]
        NORMALIZE["Event Normalizer"]
        ENRICH["Enrichment"]
    end

    subgraph C3["3) Detection"]
        direction LR
        RULE["Rule Engine\nYAML"]
        POLICY["Policy Engine"]
        CVE["CVE Matcher"]
    end

    subgraph C4["4) Response"]
        direction LR
        ALERT["Alert Dispatcher"]
        ISOLATE["Isolation\npause · stop · kill"]
        REPORT["SBOM Report\nCycloneDX/SPDX"]
        METRICS["Metrics"]
    end

    subgraph OUT["Output"]
        direction LR
        WEBHOOK["Webhook"]
        FILE["Log File"]
        CONSOLE["Console / CLI"]
        GRAFANA["Grafana"]
    end

    PKT --> ROUTER
    LOG --> ROUTER
    CTR --> ROUTER
    DEP --> CVE

    ROUTER --> NORMALIZE --> ENRICH
    ENRICH --> RULE
    ENRICH --> POLICY

    RULE --> ALERT
    POLICY --> ISOLATE
    CVE --> REPORT

    ALERT --> WEBHOOK
    ALERT --> FILE
    ALERT --> CONSOLE
    ISOLATE --> CONSOLE
    REPORT --> FILE

    ENRICH -.metrics.-> METRICS
    RULE -.metrics.-> METRICS
    POLICY -.metrics.-> METRICS
    METRICS --> GRAFANA

    classDef collect fill:#fff8e1,stroke:#ef6c00,stroke-width:1px,color:#e65100;
    classDef process fill:#e3f2fd,stroke:#1565c0,stroke-width:1px,color:#0d47a1;
    classDef detect fill:#e8f5e9,stroke:#2e7d32,stroke-width:1px,color:#1b5e20;
    classDef respond fill:#f3e5f5,stroke:#6a1b9a,stroke-width:1px,color:#4a148c;
    classDef output fill:#eceff1,stroke:#455a64,stroke-width:1px,color:#263238;

    class PKT,LOG,CTR,DEP collect;
    class ROUTER,NORMALIZE,ENRICH process;
    class RULE,POLICY,CVE detect;
    class ALERT,ISOLATE,REPORT,METRICS respond;
    class WEBHOOK,FILE,CONSOLE,GRAFANA output;
```

---

## 빠른 시작

### 설치

**GitHub Release에서 다운로드:**

```bash
# 최신 릴리스 다운로드
curl -L https://github.com/dongwonkwak/ironpost/releases/latest/download/ironpost-v0.1.0-x86_64-linux.tar.gz | tar xz
sudo mv ironpost-cli ironpost-daemon /usr/local/bin/
```

**소스에서 빌드:**

```bash
git clone https://github.com/dongwonkwak/ironpost.git
cd ironpost
cargo build --release -p ironpost-cli -p ironpost-daemon
```

### 실행

```bash
# 저장소 클론
git clone https://github.com/dongwonkwak/ironpost.git
cd ironpost

# 빌드 (eBPF 제외)
cargo build --release

# 설정 복사
cp ironpost.toml.example ironpost.toml

# 데몬 실행
sudo ./target/release/ironpost-daemon --config ironpost.toml

# 상태 확인
./target/release/ironpost-cli status
```

eBPF 모듈까지 포함해 빌드하려면 Linux 환경에서 `cargo run -p xtask -- build --all --release`를 사용하세요.
상세 설정, 플랫폼별 제약, Docker 데모는 [시작 가이드](docs/getting-started.md)를 참고하세요.

---

## 크레이트 구조

| 크레이트 | 경로 | 설명 |
|---------|------|------|
| ironpost-core | crates/core | 공통 타입, trait, 설정, 에러 |
| ironpost-ebpf-engine | crates/ebpf-engine | eBPF XDP 커널 프로그램 + 유저스페이스 엔진 |
| ironpost-log-pipeline | crates/log-pipeline | 다중 소스 로그 수집, 파서, YAML 룰 엔진 |
| ironpost-container-guard | crates/container-guard | Docker 컨테이너 모니터링, 정책 엔진, 격리 |
| ironpost-sbom-scanner | crates/sbom-scanner | Lockfile 파서, SBOM 생성, CVE 스캐너 |
| ironpost-daemon | ironpost-daemon | 오케스트레이터 데몬 (PluginRegistry + MetricsServer) |
| ironpost-cli | ironpost-cli | 통합 CLI |

---

## 기술 스택

| 계층 | 기술 |
|------|------|
| 언어 | Rust 2024 Edition |
| 비동기 런타임 | Tokio |
| eBPF | Aya (순수 Rust) |
| 로그 파싱 | nom (파서 콤비네이터) |
| 컨테이너 API | bollard (비동기 Docker 클라이언트) |
| CLI | clap v4 (derive 매크로) |
| 에러 처리 | thiserror (라이브러리) / anyhow (바이너리) |
| 로깅 | tracing (구조화 JSON 로깅) |
| 직렬화 | serde (TOML, JSON, YAML) |
| 메트릭 | prometheus-client + Grafana |
| 퍼징 | cargo-fuzz (libFuzzer 기반) |

---

## 성능 하이라이트

| 컴포넌트 | 요약 |
|----------|------|
| Log Parser | 고성능 파싱 (RFC5424/RFC3164/JSON) |
| Rule Engine | exact match 기준 초고속 매칭 경로 제공 |
| SBOM Scanner | lockfile 파싱부터 CVE 조회까지 선형 확장 |
| Container Guard | 정책 평가 및 격리 액션을 낮은 오버헤드로 수행 |
| Event System | `tokio::mpsc` 기반 이벤트 처리 파이프라인 제공 |

벤치마크 상세 결과는 [docs/benchmarks.md](docs/benchmarks.md)를 참고하세요.
측정 환경과 산식 기준은 [벤치마크 환경](docs/benchmarks.md#벤치마크-환경) 섹션을 기준으로 해석하세요.

---

## 테스트 & 품질

- 유닛/통합/E2E 테스트를 CI에서 지속적으로 검증
- fuzz 타겟(파서, 룰 엔진, lockfile, SBOM 라운드트립)을 Nightly CI에서 자동 실행
- 퍼징으로 발견·수정된 버그: Syslog parser 멀티바이트 UTF-8 char boundary panic

---

## 문서

| 문서 | 내용 |
|------|------|
| [시작 가이드](docs/getting-started.md) | 설치, 빌드, 첫 실행 |
| [아키텍처](docs/architecture.md) | 시스템 설계, 모듈 연동 |
| [설정 가이드](docs/configuration.md) | ironpost.toml 상세 설정 |
| [설계 결정](docs/design-decisions.md) | ADR 기반 기술 선택 근거 |
| [테스트](docs/testing.md) | 테스트 전략, 실행 방법, 품질 기준 |
| [벤치마크](docs/benchmarks.md) | criterion 실측 성능 |
| [데모](docs/demo.md) | Docker 3분 체험 가이드 |
| [API 문서](https://dongwonkwak.github.io/ironpost/) | cargo doc (GitHub Pages) |
| [퍼징 가이드](fuzz/README.md) | 로컬 퍼징 실행, 크래시 처리 절차 |

---

## Roadmap

향후 계획:
- 플러그인 아키텍처 확장 (외부 플러그인, WASM 런타임)
- 부하 테스트 및 벤치마크 고도화
- Kubernetes 배포 (Helm chart)

---

## 기여 및 라이선스

**기여:** 기여 방법은 [CONTRIBUTING.md](CONTRIBUTING.md)를 참고하세요.

**라이선스:** MIT License — [LICENSE](LICENSE) 파일을 참고하세요.

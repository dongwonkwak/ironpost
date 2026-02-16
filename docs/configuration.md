# Configuration Guide

Ironpost는 단일 TOML 파일(`ironpost.toml`)로 모든 모듈을 설정합니다.

## 빠른 시작

```bash
# 예시 설정 복사
cp ironpost.toml.example ironpost.toml

# 설정 검증
ironpost config validate --config ironpost.toml

# 현재 설정 확인
ironpost config show
```

## 설정 로딩 우선순위

설정값은 다음 순서로 결정됩니다 (높은 순):

| 순위 | 소스 | 예시 |
|------|------|------|
| 1 | CLI 인자 | `--log-level debug` |
| 2 | 환경변수 | `IRONPOST_GENERAL_LOG_LEVEL=debug` |
| 3 | 설정 파일 | `ironpost.toml` |
| 4 | 기본값 | 코드 내 `Default` 구현 |

CLI 인자가 최우선이며, 환경변수는 설정 파일을 덮어씁니다.

```bash
# 설정 파일에서 log_level = "info"라도 환경변수가 우선
IRONPOST_GENERAL_LOG_LEVEL=debug ironpost daemon start

# CLI 인자가 환경변수보다도 우선
IRONPOST_GENERAL_LOG_LEVEL=debug ironpost daemon start --log-level trace
```

## 환경변수 매핑

모든 설정 필드는 `IRONPOST_{SECTION}_{FIELD}` 형식의 환경변수로 오버라이드 가능합니다.

### [general]

| 필드 | 환경변수 | 타입 | 기본값 | 허용값 |
|------|---------|------|--------|--------|
| `log_level` | `IRONPOST_GENERAL_LOG_LEVEL` | String | `"info"` | trace, debug, info, warn, error |
| `log_format` | `IRONPOST_GENERAL_LOG_FORMAT` | String | `"json"` | json, pretty |
| `data_dir` | `IRONPOST_GENERAL_DATA_DIR` | String | `"/var/lib/ironpost"` | 임의 경로 |
| `pid_file` | `IRONPOST_GENERAL_PID_FILE` | String | `"/var/run/ironpost/ironpost.pid"` | 임의 경로 |

### [ebpf]

| 필드 | 환경변수 | 타입 | 기본값 | 허용값/범위 |
|------|---------|------|--------|------------|
| `enabled` | `IRONPOST_EBPF_ENABLED` | bool | `false` | true, false |
| `interface` | `IRONPOST_EBPF_INTERFACE` | String | `"eth0"` | 네트워크 인터페이스명 |
| `xdp_mode` | `IRONPOST_EBPF_XDP_MODE` | String | `"skb"` | native, skb, hw |
| `ring_buffer_size` | `IRONPOST_EBPF_RING_BUFFER_SIZE` | usize | `262144` | > 0 |
| `blocklist_max_entries` | `IRONPOST_EBPF_BLOCKLIST_MAX_ENTRIES` | usize | `10000` | > 0 |

### [log_pipeline]

| 필드 | 환경변수 | 타입 | 기본값 | 허용값/범위 |
|------|---------|------|--------|------------|
| `enabled` | `IRONPOST_LOG_PIPELINE_ENABLED` | bool | `true` | true, false |
| `sources` | `IRONPOST_LOG_PIPELINE_SOURCES` | Vec | `["syslog","file"]` | CSV 형식 |
| `syslog_bind` | `IRONPOST_LOG_PIPELINE_SYSLOG_BIND` | String | `"0.0.0.0:1514"` | addr:port (unprivileged) |
| `watch_paths` | `IRONPOST_LOG_PIPELINE_WATCH_PATHS` | Vec | `["/var/log/syslog"]` | CSV 형식, 절대 경로 |
| `batch_size` | `IRONPOST_LOG_PIPELINE_BATCH_SIZE` | usize | `100` | 1 ~ 10,000 |
| `flush_interval_secs` | `IRONPOST_LOG_PIPELINE_FLUSH_INTERVAL_SECS` | u64 | `5` | > 0 |

### [log_pipeline.storage]

| 필드 | 환경변수 | 타입 | 기본값 | 허용값/범위 |
|------|---------|------|--------|------------|
| `postgres_url` | `IRONPOST_STORAGE_POSTGRES_URL` | String | `"postgresql://localhost:5432/ironpost"` | PostgreSQL URL |
| `redis_url` | `IRONPOST_STORAGE_REDIS_URL` | String | `"redis://localhost:6379"` | Redis URL |
| `retention_days` | `IRONPOST_STORAGE_RETENTION_DAYS` | u32 | `30` | 1 ~ 3,650 |

### [container]

| 필드 | 환경변수 | 타입 | 기본값 | 허용값/범위 |
|------|---------|------|--------|------------|
| `enabled` | `IRONPOST_CONTAINER_ENABLED` | bool | `false` | true, false |
| `docker_socket` | `IRONPOST_CONTAINER_DOCKER_SOCKET` | String | `"/var/run/docker.sock"` | 소켓 경로 |
| `poll_interval_secs` | `IRONPOST_CONTAINER_POLL_INTERVAL_SECS` | u64 | `10` | 1 ~ 3,600 |
| `policy_path` | `IRONPOST_CONTAINER_POLICY_PATH` | String | `"/etc/ironpost/policies"` | 디렉토리 경로 |
| `auto_isolate` | `IRONPOST_CONTAINER_AUTO_ISOLATE` | bool | `false` | true, false |

### [sbom]

| 필드 | 환경변수 | 타입 | 기본값 | 허용값/범위 |
|------|---------|------|--------|------------|
| `enabled` | `IRONPOST_SBOM_ENABLED` | bool | `false` | true, false |
| `scan_dirs` | `IRONPOST_SBOM_SCAN_DIRS` | Vec | `["."]` | CSV 형식 |
| `vuln_db_update_hours` | `IRONPOST_SBOM_VULN_DB_UPDATE_HOURS` | u32 | `24` | 1 ~ 8,760 |
| `vuln_db_path` | `IRONPOST_SBOM_VULN_DB_PATH` | String | `"/var/lib/ironpost/vuln-db"` | 디렉토리 경로 |
| `min_severity` | `IRONPOST_SBOM_MIN_SEVERITY` | String | `"medium"` | info, low, medium, high, critical |
| `output_format` | `IRONPOST_SBOM_OUTPUT_FORMAT` | String | `"cyclonedx"` | spdx, cyclonedx |

## 부분 설정

Ironpost는 부분 설정을 지원합니다. 필요한 섹션과 필드만 작성하면 나머지는 기본값이 적용됩니다.

### 최소 설정 (기본값 사용)

빈 파일이나 빈 문자열도 유효합니다:

```toml
# 빈 파일 — 모든 필드가 기본값으로 동작
# log_pipeline만 기본 활성화 (enabled = true)
```

### 특정 섹션만 설정

```toml
# 로그 레벨만 변경하고 나머지는 기본값
[general]
log_level = "debug"
```

### 특정 모듈만 활성화

```toml
# SBOM 스캐너만 활성화
[sbom]
enabled = true
scan_dirs = ["/app"]
min_severity = "high"
```

### 여러 섹션 조합

```toml
[general]
log_level = "debug"

[log_pipeline]
batch_size = 500

[sbom]
enabled = true
scan_dirs = ["/app", "/opt"]
```

## 설정 검증

### CLI 검증 명령어

```bash
# 기본 경로 (ironpost.toml) 검증
ironpost config validate

# 특정 파일 검증
ironpost config validate --config /path/to/ironpost.toml

# 현재 설정 확인 (환경변수 오버라이드 포함)
ironpost config show

# 특정 섹션만 확인
ironpost config show --section general
ironpost config show --section ebpf
```

### 검증 규칙

모듈이 비활성화(`enabled = false`)되어 있으면 해당 모듈의 필드 검증이 건너뛰어집니다.

| 섹션 | 필드 | 조건 | 규칙 |
|------|------|------|------|
| general | `log_level` | 항상 | trace, debug, info, warn, error 중 하나 |
| general | `log_format` | 항상 | json, pretty 중 하나 |
| ebpf | `xdp_mode` | enabled=true | native, skb, hw 중 하나 |
| ebpf | `interface` | enabled=true | 비어있으면 안 됨 |
| ebpf | `ring_buffer_size` | enabled=true | > 0 |
| ebpf | `blocklist_max_entries` | enabled=true | > 0 |
| log_pipeline | `batch_size` | enabled=true | 1 ~ 10,000 |
| log_pipeline | `flush_interval_secs` | enabled=true | > 0 |
| log_pipeline | `sources` | enabled=true | 최소 1개 |
| storage | `retention_days` | 항상 | 1 ~ 3,650 |
| container | `docker_socket` | enabled=true | 비어있으면 안 됨 |
| container | `poll_interval_secs` | enabled=true | 1 ~ 3,600 |
| sbom | `output_format` | enabled=true | spdx, cyclonedx 중 하나 |
| sbom | `min_severity` | enabled=true | info, low, medium, high, critical 중 하나 |
| sbom | `vuln_db_update_hours` | enabled=true | 1 ~ 8,760 |
| sbom | `scan_dirs` | enabled=true | 최소 1개, ".." 패턴 불가 |

### 프로그래밍 API

```rust
use ironpost_core::config::IronpostConfig;

// 파일 로드 + 환경변수 오버라이드 + 검증
let config = IronpostConfig::load("ironpost.toml").await?;

// 파일만 로드 (환경변수 오버라이드 없음)
let config = IronpostConfig::from_file("ironpost.toml").await?;

// TOML 문자열에서 파싱
let config = IronpostConfig::parse("[general]\nlog_level = \"debug\"")?;

// 수동 검증
config.validate()?;

// 환경변수 오버라이드 수동 적용
let mut config = IronpostConfig::parse("")?;
config.apply_env_overrides();
config.validate()?;
```

## Vec 타입 환경변수

`Vec<String>` 타입 필드는 CSV 형식으로 환경변수에서 설정합니다:

```bash
# 쉼표로 구분, 양쪽 공백 자동 제거
export IRONPOST_LOG_PIPELINE_SOURCES="syslog, file, journald"
export IRONPOST_LOG_PIPELINE_WATCH_PATHS="/var/log/auth.log,/var/log/kern.log"
export IRONPOST_SBOM_SCAN_DIRS="/app,/opt,/usr/local"
```

## 보안 주의사항

### 민감 정보

데이터베이스 연결 문자열 등 비밀번호가 포함된 값은 설정 파일 대신 환경변수를 사용하세요:

```bash
# 권장: 환경변수로 민감 정보 전달
export IRONPOST_STORAGE_POSTGRES_URL="postgresql://user:password@host:5432/db"
export IRONPOST_STORAGE_REDIS_URL="redis://:password@host:6379"
```

`ironpost config show` 명령어는 연결 문자열의 자격증명을 자동으로 마스킹합니다:
```
postgresql://***REDACTED***@host:5432/db
```

### 경로 검증

- `watch_paths`, `scan_dirs`에서 path traversal(`..`) 패턴을 거부합니다
- `watch_paths`는 `/var/log` 또는 `/tmp` 하위 절대 경로만 허용합니다
- `auto_isolate = true`는 프로덕션 환경에서 정책 검증 후 활성화하세요

## 모듈별 확장 설정

각 모듈 크레이트는 core 설정을 확장하여 모듈 고유 필드를 추가합니다.
이 필드들은 `ironpost.toml`에 직접 기록하지 않고, 모듈 내부에서 기본값이 적용됩니다.

### log-pipeline 확장

| 필드 | 기본값 | 설명 |
|------|--------|------|
| `rule_dir` | `/etc/ironpost/rules` | YAML 탐지 규칙 디렉토리 |
| `rule_reload_secs` | `30` | 규칙 리로드 주기 (초) |
| `buffer_capacity` | `10,000` | 인메모리 버퍼 최대 용량 |
| `drop_policy` | `Oldest` | 버퍼 오버플로우 드롭 정책 (Oldest/Newest) |
| `alert_dedup_window_secs` | `60` | 알림 중복 제거 윈도우 (초) |
| `alert_rate_limit_per_rule` | `10` | 규칙당 분당 최대 알림 수 |

### container-guard 확장

| 필드 | 기본값 | 설명 |
|------|--------|------|
| `max_concurrent_actions` | `10` | 동시 격리 액션 최대 수 (1~100) |
| `action_timeout_secs` | `30` | 격리 액션 타임아웃 (1~300초) |
| `retry_max_attempts` | `3` | 격리 실패 재시도 횟수 (0~10) |
| `retry_backoff_base_ms` | `500` | 재시도 백오프 기본 간격 (0~30,000ms) |
| `container_cache_ttl_secs` | `60` | 컨테이너 정보 캐시 TTL (1~3,600초) |

### sbom-scanner 확장

| 필드 | 기본값 | 설명 |
|------|--------|------|
| `scan_interval_secs` | `86400` | 주기적 스캔 간격 (0=수동, 60~604,800) |
| `max_file_size` | `10,485,760` | lockfile 최대 크기 (10MB) |
| `max_packages` | `50,000` | 최대 허용 패키지 수 |

## Metrics 설정 (선택사항)

Ironpost는 29개의 Prometheus 메트릭을 노출하여 Grafana 대시보드에서 모니터링할 수 있습니다.

### 메트릭 활성화

```toml
[metrics]
enabled = true
listen_addr = "127.0.0.1"  # Docker에서는 "0.0.0.0" 사용
port = 9100
endpoint = "/metrics"
```

### 메트릭 환경변수

| 필드 | 환경변수 | 타입 | 기본값 | 허용값/범위 |
|------|---------|------|--------|------------|
| `enabled` | `IRONPOST_METRICS_ENABLED` | bool | `false` | true, false |
| `listen_addr` | `IRONPOST_METRICS_LISTEN_ADDR` | String | `"127.0.0.1"` | 임의 IP 주소 |
| `port` | `IRONPOST_METRICS_PORT` | u16 | `9100` | 1024 ~ 65535 |
| `endpoint` | `IRONPOST_METRICS_ENDPOINT` | String | `"/metrics"` | URL 경로 |

### 메트릭 카테고리 (29개)

**eBPF 엔진 (7개)**:
- `ebpf_packets_received_total`: 수신한 패킷 수
- `ebpf_packets_processed_total`: 처리된 패킷 수
- `ebpf_packets_dropped_total`: 드롭된 패킷 수
- `ebpf_syn_floods_detected_total`: 감지된 SYN flood 공격 수
- `ebpf_port_scans_detected_total`: 감지된 포트 스캔 수
- `ebpf_bytes_processed_total`: 처리된 바이트 수
- `ebpf_processing_latency_us`: 패킷 처리 지연시간 (µs)

**로그 파이프라인 (8개)**:
- `log_pipeline_messages_received_total`: 수신한 로그 메시지 수
- `log_pipeline_messages_parsed_total`: 파싱된 메시지 수
- `log_pipeline_parse_errors_total`: 파싱 오류 수
- `log_pipeline_rules_matched_total`: 매칭된 규칙 수
- `log_pipeline_alerts_generated_total`: 생성된 알림 수
- `log_pipeline_batches_processed_total`: 처리된 배치 수
- `log_pipeline_buffer_size`: 현재 버퍼 크기
- `log_pipeline_processing_time_ms`: 메시지 처리 시간 (ms)

**컨테이너 격리 (6개)**:
- `container_guard_alerts_received_total`: 수신한 알림 수
- `container_guard_actions_executed_total`: 실행된 격리 액션 수
- `container_guard_actions_failed_total`: 실패한 액션 수
- `container_guard_containers_isolated`: 현재 격리된 컨테이너 수
- `container_guard_action_duration_ms`: 액션 실행 시간 (ms)
- `container_guard_docker_api_calls_total`: Docker API 호출 수

**SBOM 스캐너 (5개)**:
- `sbom_scans_started_total`: 시작된 스캔 수
- `sbom_scans_completed_total`: 완료된 스캔 수
- `sbom_vulnerabilities_found_total`: 발견된 취약점 수
- `sbom_packages_scanned_total`: 스캔된 패키지 수
- `sbom_scan_duration_seconds`: 스캔 실행 시간 (초)

**데몬 상태 (3개)**:
- `ironpost_uptime_seconds`: 데몬 가동시간 (초)
- `ironpost_modules_health`: 모듈 건강 상태 (1=healthy, 0=degraded/unhealthy)
- `ironpost_version`: 데몬 버전 (label)

### Grafana 대시보드

Docker Compose로 실행 시 Grafana 대시보드를 사용할 수 있습니다:

```bash
# 모니터링 스택 시작 (Prometheus + Grafana)
docker compose --profile monitoring up -d

# Grafana 접속
# URL: http://localhost:3000
# ID: admin / Password: changeme
```

**포함된 대시보드:**
1. **Overview**: 전체 시스템 상태, 각 모듈 메트릭 요약
2. **Log Pipeline**: 로그 수신율, 파싱 성공률, 알림 발생 추이
3. **Security**: 컨테이너 격리 현황, 취약점 발견 현황, 공격 감지 추이

### localhost vs Docker 환경

**로컬 개발 (localhost):**
```toml
[metrics]
enabled = true
listen_addr = "127.0.0.1"
port = 9100
endpoint = "/metrics"
```

```bash
# 메트릭 확인
curl http://127.0.0.1:9100/metrics
```

**Docker 환경:**
```toml
[metrics]
enabled = true
listen_addr = "0.0.0.0"  # 컨테이너 외부에서 접근 가능
port = 9100
endpoint = "/metrics"
```

```bash
# 호스트에서 메트릭 확인
curl http://localhost:9100/metrics

# 또는 Docker 컨테이너 내부에서
docker compose exec ironpost curl http://localhost:9100/metrics
```

**보안 주의사항:**
- 프로덕션 환경에서 `listen_addr = "0.0.0.0"`은 위험할 수 있습니다
- 방화벽으로 메트릭 포트(9100)를 제한하거나, 리버스 프록시(nginx 등)를 사용하세요
- 메트릭 엔드포인트는 인증을 지원하지 않으므로, 신뢰할 수 있는 네트워크에서만 노출하세요

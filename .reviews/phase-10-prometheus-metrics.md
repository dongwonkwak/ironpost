# Phase 10 Codex 리뷰: Prometheus Metrics + Grafana Dashboard (업데이트)

브랜치: `feat/prometheus-metrics`

## Summary

- `1번`(High 우선) + `2번`(Medium 후속) 반영 후 재검증 기준으로 갱신했습니다.
- 기존 High 2건, Medium 4건은 코드 반영으로 해결 또는 위험도 완화 확인.
- 기존 Low 2건까지 반영 완료하여, 현재 **잔여 이슈는 없습니다**.

## Resolved Findings (with Severity)

1. **[High][Resolved] Grafana datasource UID 불일치**
   - `docker/grafana/provisioning/datasources/prometheus.yml:5`에 `uid: prometheus` 추가됨.
   - 대시보드 UID 하드코딩(`docker/grafana/dashboards/ironpost-overview.json:27` 등)과 정합성 확보.

2. **[High][Resolved] Grafana 조회 메트릭 미기록**
   - dropped 로그 카운터 기록 추가: `crates/log-pipeline/src/pipeline.rs:459`
   - VulnDB last-update gauge 초기화/업데이트 추가: `crates/sbom-scanner/src/scanner.rs:203`, `crates/sbom-scanner/src/scanner.rs:223`

3. **[Medium][Resolved] `MetricsConfig.endpoint` dead config**
   - validate에서 `/metrics` 이외 경로 거부: `crates/core/src/config.rs:404`
   - 런타임에서도 동일 제약 검사: `ironpost-daemon/src/metrics_server.rs:35`
   - 관련 테스트 추가: `crates/core/src/config.rs:1088`, `ironpost-daemon/tests/metrics_server_tests.rs:52`

4. **[Medium][Resolved] SBOM 메트릭 집계 왜곡**
   - 사이클 단위 severity gauge 집계 함수 추가: `crates/sbom-scanner/src/scanner.rs:532`
   - 전체 결과 기준으로 gauge 갱신: `crates/sbom-scanner/src/scanner.rs:180`, `crates/sbom-scanner/src/scanner.rs:326`
   - 스캔 duration은 디렉토리 스캔당 1회 기록: `crates/sbom-scanner/src/scanner.rs:707`

5. **[Medium][Resolved] Core env 테스트 flaky**
   - env override 테스트에 `#[serial]` 적용: `crates/core/src/config.rs:933`, `crates/core/src/config.rs:1110`
   - 재검증에서 `cargo test -p ironpost-core` 통과.

6. **[Medium][Mitigated] 메트릭 엔드포인트 외부 노출 기본값**
   - 기본 listen 주소를 localhost로 변경: `crates/core/src/config.rs:373`
   - compose 포트 publish 기본도 localhost bind로 변경: `docker/docker-compose.yml:71`
   - 외부 노출 시 경고 로그 추가: `ironpost-daemon/src/metrics_server.rs:46`
   - 참고: 인증 자체는 여전히 없으므로 외부 노출 시 네트워크 제어는 필요.

7. **[Low][Resolved] Histogram quantile PromQL 단일 타깃 전제**
   - 다중 인스턴스 안전한 집계식으로 수정:
   - `docker/grafana/dashboards/ironpost-log-pipeline.json:814`
   - `docker/grafana/dashboards/ironpost-log-pipeline.json:905`
   - `docker/grafana/dashboards/ironpost-log-pipeline.json:996`
   - `docker/grafana/dashboards/ironpost-security.json:372`

8. **[Low][Resolved] `clippy --all-targets` deprecated 테스트 호출 실패**
   - deprecated API 호출을 테스트 헬퍼로 감싸 lint 허용 범위를 테스트 전용으로 제한:
   - `crates/ebpf-engine/src/stats.rs:267`
   - `crates/ebpf-engine/src/stats.rs:551`
   - `crates/ebpf-engine/src/stats.rs:575`
   - `crates/ebpf-engine/src/stats.rs:592`

## Remaining Findings (Severity Ordered)

- 없음

## Checklist Coverage (Updated)

1. **CLAUDE.md 규칙 위반 여부**
   - 프로덕션 코드 기준 `unwrap/println/panic/todo` 신규 위반은 미발견.
   - `unsafe`는 테스트 환경변수 조작 구간에서 `SAFETY` 주석과 함께 사용됨 (`crates/core/src/config.rs:936` 등).

2. **메트릭 이름 일관성**
   - `ironpost_` 접두어, `_total/_seconds` 접미어 규칙은 전반적으로 일관.

3. **이중 기록 전략**
   - `Arc<AtomicU64>` + `metrics::counter!()` 전략 유지.
   - dropped 로그 카운터 누락은 해결됨 (`crates/log-pipeline/src/pipeline.rs:459`).

4. **MetricsConfig validate()**
   - endpoint 제약(`/metrics` only)과 테스트가 추가되어 누락 케이스 보완됨.

5. **에러 처리**
   - `Result` 전파 및 `tracing` 로깅 패턴 유지, 신규 경로도 동일.

6. **Docker 설정 호환성**
   - demo compose 병합 렌더링 정상.
   - metrics bind host 기본값이 보수적으로 변경되어 기존 demo를 깨지 않음.

7. **Grafana PromQL 정확성**
   - 미기록 메트릭/quantile 집계식 이슈 모두 해결.

8. **테스트 커버리지**
   - endpoint unsupported 경로 테스트 추가.
   - env flaky 재현 항목은 serial 처리 후 안정화.

9. **clippy / 불필요 clone/allocation**
   - workspace clippy 및 all-targets clippy 모두 통과.

10. **보안**
   - 기본 노출면이 localhost로 축소됨.
   - 외부 노출 시 인증 부재 리스크는 운영 정책(네트워크 제어)으로 보완 필요.

## Validation Commands Run (Latest)

- `cargo clippy --workspace -- -D warnings` ✅
- `cargo clippy --workspace --all-targets -- -D warnings` ✅
- `cargo test -p ironpost-core` ✅
- `cargo test -p ironpost-daemon --test metrics_server_tests` ✅
- `cargo test -p ironpost-sbom-scanner` ✅
- `cargo test -p ironpost-log-pipeline` ✅
- `cargo test -p ironpost-ebpf-engine` ✅
- `docker compose -f docker/docker-compose.yml -f docker/docker-compose.demo.yml config` ✅

---

# Reviewer 상위 레벨 리뷰

**리뷰어**: Claude Opus 4.6 (Reviewer)
**리뷰 일자**: 2026-02-16
**브랜치**: `feat/prometheus-metrics`

## 최종 판정: APPROVE

Codex 리뷰에서 발견된 모든 이슈가 적절히 수정되었으며, 상위 레벨 아키텍처 관점에서도
머지에 문제가 될 블로커는 없습니다. 아래 Advisory 이슈들은 향후 개선 사항으로 기록합니다.

## 검증 결과

| 검사 항목 | 결과 |
|-----------|------|
| `cargo fmt --all --check` | ✅ PASS |
| `cargo clippy --workspace -- -D warnings` | ✅ PASS |
| `cargo test --workspace` | ✅ PASS (550+ tests, 0 failures) |
| `cargo doc --workspace --no-deps` | ✅ PASS |
| `docker compose config` | ✅ PASS |

---

## 1. 아키텍처 적합성

**평가: 양호**

전역 레코더 패턴(`metrics-exporter-prometheus`의 `PrometheusBuilder::install()`)은
Ironpost의 플러그인 아키텍처와 잘 맞습니다.

**장점:**
- `ironpost-core::metrics` 모듈이 모든 메트릭 이름을 중앙에서 상수로 관리하여
  모듈 간 의존 금지 규칙을 위반하지 않으면서 일관된 네이밍을 보장
- 각 모듈은 `metrics::counter!()` 등 매크로만 호출하므로 Prometheus 구현에 직접 의존하지 않음
- 전역 레코더는 `ironpost-daemon`(바이너리 크레이트)에서만 설치, 라이브러리 크레이트는 인터페이스만 사용
- `describe_all()` 함수로 모든 HELP 텍스트를 한 곳에서 등록 — 유지보수 용이

**제약:**
- 전역 레코더는 프로세스당 1회만 설치 가능하므로 멀티 인스턴스 테스트에서 약간의 불편함이 있음
  (이미 `#[serial]`로 대응)

---

## 2. 확장성 (OpenTelemetry 전환, 다중 인스턴스)

**평가: 양호 (Advisory 1건)**

- `metrics` 크레이트의 facade 패턴 덕분에, 향후 OpenTelemetry로 전환 시
  레코더만 교체(`metrics-exporter-prometheus` → `metrics-tracing-context` + OTel exporter)하면
  모듈 코드는 변경 불필요
- Grafana PromQL에서 `sum by (le)` 패턴 사용으로 다중 인스턴스 환경에서도
  histogram quantile이 정확하게 집계됨

**[Advisory][A-1] 다중 인스턴스 배포 시 `instance` 레이블 전략**
- 현재 Prometheus scrape config에서 `instance: ironpost-daemon`으로 하드코딩
- 다중 인스턴스 배포 시 각 인스턴스별 구분을 위해 Prometheus의 `relabel_configs`
  또는 환경변수 기반 레이블 주입이 필요
- 심각도: Low — 현재는 단일 인스턴스 전제이므로 문제 없음

---

## 3. 운영 관점: 메트릭 카디널리티 폭발 위험

**평가: 양호**

현재 레이블 설계는 보수적이며 카디널리티 폭발 위험이 낮습니다:

| 메트릭 | 레이블 | 최대 카디널리티 |
|--------|--------|----------------|
| `ebpf_protocol_packets_total` | `protocol` | 4 (tcp/udp/icmp/other) |
| `ebpf_packets_per_second` | `protocol` | 5 (위 4 + total) |
| `sbom_scanner_cves_found` | `severity` | 5 (critical/high/medium/low/info) |
| `container_guard_isolations_total` | `action`, `result` | ~6 (3 actions x 2 results) |
| `sbom_scanner_packages_scanned_total` | `ecosystem` | 2 (cargo/npm, 확장 시 증가) |

총 고유 시계열 수: ~50 미만으로 운영 부담이 거의 없습니다.

**위험 요소 없음**: 사용자 입력이 레이블에 직접 들어가는 경로가 없으며,
`container_id`나 `source_ip` 같은 고카디널리티 값은 의도적으로 레이블에서 제외됨.

---

## 4. 이중 기록 전략: `Arc<AtomicU64>` + `metrics::counter!()`

**평가: 수용 가능 (Advisory 1건)**

현재 `log-pipeline`과 `sbom-scanner`에서 `Arc<AtomicU64>`(내부 카운터)와
`metrics::counter!()`(Prometheus 카운터)를 동시에 사용합니다.

**이중 기록이 필요한 이유:**
- `Arc<AtomicU64>`는 `health_check()`, `processed_count()` 등 동기적 조회에 사용
- `metrics::counter!()`는 Prometheus scrape용
- `metrics` 크레이트의 `counter.get()` API가 없으므로 내부 조회용 별도 카운터 필요

**[Advisory][A-2] 장기적 통합 가능성**
- `metrics` 크레이트가 향후 카운터 값 조회 API를 제공하면 통합 가능
- 또는 `metrics-util`의 `DebuggingRecorder`와 유사한 패턴으로 커스텀 레코더를 만들어
  내부 조회와 Prometheus 출력을 하나로 통합 가능
- 현재 상태에서는 값이 항상 동기화되며 실질적인 불일치 위험 없음
- 심각도: Low — 기술 부채이지만 기능적 문제 없음

---

## 5. Docker 구성: 기존 demo와의 호환성, 모니터링 스택 분리

**평가: 우수**

- `prometheus`와 `grafana` 서비스를 `profiles: [monitoring]`으로 분리하여
  기본 `docker compose up`에서는 모니터링 스택이 시작되지 않음
- 기존 demo compose와의 병합(`-f docker-compose.yml -f docker-compose.demo.yml`)이 정상 동작
- Prometheus/Grafana는 `depends_on: prometheus`로 올바른 의존 관계 설정
- 볼륨이 모두 named volume으로 정의되어 데이터 영속성 보장
- Grafana datasource provisioning에 `uid: prometheus`가 설정되어 대시보드와의 정합성 확보

---

## 6. 보안

**평가: 양호 (Advisory 1건)**

**이미 적용된 보호:**
- 기본 listen_addr: `127.0.0.1` (localhost only)
- Docker compose에서 metrics 포트: `${IRONPOST_METRICS_BIND_HOST:-127.0.0.1}:9100:9100`
- `0.0.0.0` 바인딩 시 경고 로그 출력
- 메트릭 엔드포인트 경로 제한 (`/metrics` only)

**[Advisory][A-3] 인증 없는 메트릭 엔드포인트**
- 메트릭 엔드포인트에 인증이 없음. 현재 localhost 바인딩으로 완화되었으나,
  사용자가 `listen_addr: "0.0.0.0"`으로 변경하면 내부 운영 정보가 노출됨
- 노출되는 정보: 가동 시간, 플러그인 수, 패킷 처리량, CVE 수, 컨테이너 수 등
  — 직접적인 credential 유출은 없으나 정찰에 활용 가능
- 향후 mTLS 또는 Bearer token 인증 추가를 권장
- 심각도: Low — 기본값이 localhost이므로 현재 위험은 낮음

---

## 7. 코드 품질

**평가: 우수**

### 7.1 네이밍
- 모든 메트릭이 `ironpost_` 접두어 + 모듈명 + 의미 있는 이름으로 구성
- Prometheus 네이밍 컨벤션 준수: `_total` (counter), `_seconds` (histogram), 접미어 없음 (gauge)
- 상수 이름이 메트릭 이름과 1:1 대응하여 grep으로 추적 가능

### 7.2 문서화
- `metrics.rs` 모듈 doc: 네이밍 컨벤션, 사용 예시 포함
- `metrics_server.rs`: doc comment, 에러 조건 명시
- `describe_all()`: 모든 메트릭에 HELP 텍스트 등록

### 7.3 에러 처리
- `metrics_server::install_metrics_recorder()`에서 `anyhow::Result` 전파
- 소켓 바인드 실패, 레코더 이중 설치 등 모든 실패 경로가 `Result`로 처리
- CLAUDE.md 규칙 위반 (unwrap/panic/println) 없음 확인

### 7.4 테스트
- `metrics.rs`: 7개 테스트 (접두어, 개수, describe_all panic-free, 레이블 lowercase, 버킷 정렬)
- `metrics_server_tests.rs`: 4개 통합 테스트 (정상 설치, 잘못된 주소, 미지원 endpoint, 비활성화)
- 환경변수 테스트: `#[serial]`로 flaky 방지
- 전체 workspace: 550+ 테스트 통과

### 7.5 코드 중복
- `pipeline.rs`에서 배치 처리 루프가 size-trigger(L:474-529)와 timer-trigger(L:551-597) 사이에
  거의 동일한 로직이 반복됨. 이는 기존 코드 구조의 한계이며, 이번 PR에서 메트릭 호출만 추가한 것이므로
  이번 리뷰 범위 밖이지만 향후 리팩토링 대상으로 기록

---

## 8. Grafana 대시보드

**평가: 양호**

- 3개 대시보드 (Overview 10패널, Log Pipeline 11패널, Security 12패널) — 33개 패널 총
- 모든 패널이 `datasource.uid: "prometheus"`를 참조 → provisioning과 정합
- histogram quantile이 `sum by (le)` 패턴으로 다중 인스턴스 안전
- 대시보드 UID가 의미 있는 문자열 (`ironpost-overview` 등)로 설정
- CVE 분포에 piechart, 성공률에 gauge 등 적절한 시각화 선택

---

## Advisory 이슈 요약

| ID | 심각도 | 제목 | 조치 |
|----|--------|------|------|
| A-1 | Low | 다중 인스턴스 시 instance 레이블 전략 | 향후 HA 배포 시 대응 |
| A-2 | Low | Arc<AtomicU64> + metrics 이중 기록 장기 부채 | metrics crate 진화 시 통합 검토 |
| A-3 | Low | 인증 없는 메트릭 엔드포인트 | 향후 mTLS/Bearer token 추가 권장 |

**블로커 없음. 모든 Advisory는 Low 심각도이며 향후 개선 사항입니다.**

---

## Reviewer 검증 명령어

```bash
cargo fmt --all --check                    # ✅ PASS
cargo clippy --workspace -- -D warnings    # ✅ PASS
cargo test --workspace                     # ✅ PASS (550+ tests)
cargo doc --workspace --no-deps            # ✅ PASS
docker compose -f docker/docker-compose.yml config  # ✅ PASS
```

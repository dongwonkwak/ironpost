# ironpost-log-pipeline

Ironpost 로그 파이프라인 -- 로그 수집, 파싱, 룰 매칭, 알림 생성을 담당하는 크레이트입니다.

## 기능

- **수집**: 파일 감시(tail), Syslog UDP/TCP (RFC 5424), eBPF PacketEvent 수신
- **파싱**: Syslog RFC 5424, 구조화 JSON (자동 감지 라우터)
- **룰 엔진**: YAML 기반 탐지 규칙 (간소화된 Sigma 스타일)
- **알림**: 중복 제거, 속도 제한, AlertEvent 생성
- **버퍼**: 인메모리 배치 버퍼 (오버플로우 정책 선택 가능)

## 아키텍처

```text
Collectors -> Buffer -> ParserRouter -> RuleEngine -> AlertGenerator -> downstream
```

모든 모듈 간 통신은 `tokio::mpsc` 채널을 통한 이벤트 기반 메시지 패싱으로 수행됩니다.
`ironpost-core`에만 의존하며, 다른 모듈(ebpf-engine 등)에 직접 의존하지 않습니다.

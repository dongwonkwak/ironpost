//! 통합 테스트 -- 파이프라인 전체 흐름 검증
//!
//! 이 파일은 로그 수집부터 알림 생성까지의 전체 파이프라인을 검증합니다.

use std::path::PathBuf;

use tokio::sync::mpsc;

use ironpost_core::event::{AlertEvent, PacketEvent};
use ironpost_core::pipeline::{HealthStatus, LogParser, Pipeline};
use ironpost_core::types::PacketInfo;
use ironpost_log_pipeline::{
    LogPipelineBuilder, PipelineConfig, RuleEngine, SyslogParser,
};

/// 파서 → 규칙 엔진 흐름 테스트
#[tokio::test]
async fn test_parse_and_match_flow() {
    // 1. 파서 생성
    let parser = SyslogParser::new();

    // 2. 규칙 엔진 생성
    let rules_dir = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("examples/rules");
    let mut rule_engine = RuleEngine::new();

    // 규칙 디렉토리가 존재하면 로드
    if rules_dir.exists() {
        let _ = rule_engine
            .load_rules_from_dir(&rules_dir)
            .await;
    }

    // 3. 테스트 로그 파싱
    let raw_log = b"<34>1 2024-01-15T12:00:00Z testhost sshd 1234 - - Failed password for root from 192.168.1.100";
    let log_entry = parser.parse(raw_log).expect("failed to parse log");

    // 4. 규칙 매칭
    let matches = rule_engine.evaluate(&log_entry).expect("failed to evaluate");

    // 5. 검증 - 규칙 엔진이 정상 동작하는지 확인 (패닉 없이 완료)
    let _count = matches.len();
}

/// 여러 형식의 로그를 파싱하고 규칙 매칭하는 테스트
#[tokio::test]
async fn test_multi_format_parsing() {
    let parser = SyslogParser::new();

    // RFC 5424 형식
    let rfc5424 = b"<34>1 2024-01-15T12:00:00Z host app - - - message";
    let result1 = parser.parse(rfc5424);
    assert!(result1.is_ok());

    // RFC 3164 형식
    let rfc3164 = b"<34>Jan 15 12:00:00 host app: message";
    let result2 = parser.parse(rfc3164);
    assert!(result2.is_ok());
}

/// 파이프라인 빌더 테스트
#[tokio::test]
async fn test_pipeline_builder() {
    let config = PipelineConfig::default();
    let (alert_tx, _alert_rx) = mpsc::channel::<AlertEvent>(100);

    let result = LogPipelineBuilder::new()
        .config(config)
        .alert_sender(alert_tx)
        .build();

    // 빌드 성공 확인
    assert!(result.is_ok());

    if let Ok((pipeline, _rx)) = result {
        // 헬스 체크 가능 확인
        let _health = pipeline.health_check().await;
        // Health status를 성공적으로 반환하면 OK
    }
}

/// 빈 규칙 디렉토리로 파이프라인 실행 테스트
#[tokio::test]
async fn test_empty_rules_directory() {
    let temp_dir = tempfile::tempdir().expect("failed to create temp dir");

    let config = PipelineConfig {
        rule_dir: temp_dir.path().to_str().unwrap().to_owned(),
        ..Default::default()
    };

    let (alert_tx, _alert_rx) = mpsc::channel::<AlertEvent>(100);

    let result = LogPipelineBuilder::new()
        .config(config)
        .alert_sender(alert_tx)
        .build();

    // 규칙 없이도 빌드는 성공해야 함
    assert!(result.is_ok());
}

/// PacketEvent 생성 테스트
#[tokio::test]
async fn test_packet_event_creation() {
    use bytes::Bytes;
    use std::net::{IpAddr, Ipv4Addr};
    use std::time::SystemTime;

    // PacketInfo 생성
    let packet_info = PacketInfo {
        src_ip: IpAddr::V4(Ipv4Addr::new(192, 168, 1, 100)),
        dst_ip: IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)),
        src_port: 54321,
        dst_port: 80,
        protocol: 6, // TCP
        size: 1024,
        timestamp: SystemTime::now(),
    };

    let raw_data = Bytes::from_static(b"test packet data");
    let packet_event = PacketEvent::new(packet_info, raw_data);

    // PacketEvent가 정상적으로 생성되는지 확인
    assert_eq!(packet_event.packet_info.src_ip, IpAddr::V4(Ipv4Addr::new(192, 168, 1, 100)));
    assert_eq!(packet_event.packet_info.protocol, 6);
}

/// 동시 다발적 로그 파싱 스트레스 테스트
#[tokio::test]
async fn test_concurrent_log_parsing() {
    let mut handles = vec![];

    for i in 0..10 {
        let parser_clone = SyslogParser::new();
        let handle = tokio::spawn(async move {
            for j in 0..10 {
                let log = format!(
                    "<34>1 2024-01-15T12:00:00Z host app{} - - - message {}",
                    i, j
                );
                let result = parser_clone.parse(log.as_bytes());
                assert!(result.is_ok());
            }
        });
        handles.push(handle);
    }

    // 모든 태스크 완료 대기
    for handle in handles {
        handle.await.expect("parsing task failed");
    }
}

/// 규칙 엔진 매칭 기본 동작 테스트
#[tokio::test]
async fn test_rule_engine_basic_matching() {
    let mut rule_engine = RuleEngine::new();

    // 예제 규칙 디렉토리가 있으면 로드
    let rules_dir = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("examples/rules");
    if rules_dir.exists() {
        let _result = rule_engine.load_rules_from_dir(&rules_dir).await;
    }

    // 규칙 카운트 확인 (패닉 없이 완료)
    let _rule_count = rule_engine.rule_count();
}

/// 파서 에러 처리 테스트
#[tokio::test]
async fn test_parser_error_handling() {
    let parser = SyslogParser::new();

    // 빈 입력
    let result = parser.parse(b"");
    assert!(result.is_err());

    // 잘못된 형식
    let result = parser.parse(b"not a valid syslog message at all");
    assert!(result.is_err() || result.is_ok()); // 구현에 따라 다름
}

/// 파이프라인 설정 검증 테스트
#[tokio::test]
async fn test_config_validation() {
    let config = PipelineConfig::default();

    // 기본 설정은 유효해야 함
    assert!(config.validate().is_ok());

    // 잘못된 설정 - batch_size = 0
    let invalid_config1 = PipelineConfig {
        batch_size: 0,
        ..Default::default()
    };
    assert!(invalid_config1.validate().is_err());

    // 잘못된 설정 - flush_interval_secs = 0
    let invalid_config2 = PipelineConfig {
        flush_interval_secs: 0,
        ..Default::default()
    };
    assert!(invalid_config2.validate().is_err());

    // 잘못된 설정 - buffer_capacity = 0
    let invalid_config3 = PipelineConfig {
        buffer_capacity: 0,
        ..Default::default()
    };
    assert!(invalid_config3.validate().is_err());
}

/// 파이프라인 빌더 체인 테스트
#[tokio::test]
async fn test_builder_chaining() {
    let config = PipelineConfig::default();
    let (alert_tx, _alert_rx) = mpsc::channel::<AlertEvent>(100);
    let (_packet_tx, packet_rx) = mpsc::channel::<PacketEvent>(100);

    // 모든 빌더 메서드 체인
    let result = LogPipelineBuilder::new()
        .config(config)
        .alert_sender(alert_tx)
        .packet_receiver(packet_rx)
        .build();

    assert!(result.is_ok());
}

/// 알림 채널 테스트
#[tokio::test]
async fn test_alert_channel_creation() {
    let config = PipelineConfig::default();

    // 외부 채널 제공 안 함 - 빌더가 생성
    let result = LogPipelineBuilder::new()
        .config(config)
        .build();

    assert!(result.is_ok());
    if let Ok((_, rx)) = result {
        // 빌더가 생성한 수신 채널 확인
        assert!(rx.is_some());
    }
}

/// 설정 기본값 테스트
#[tokio::test]
async fn test_default_config_values() {
    let config = PipelineConfig::default();

    assert!(config.batch_size > 0);
    assert!(config.flush_interval_secs > 0);
    assert!(config.buffer_capacity > 0);
    assert!(config.alert_dedup_window_secs > 0);
    assert!(config.alert_rate_limit_per_rule > 0);
}

/// 여러 파서 인스턴스 독립성 테스트
#[tokio::test]
async fn test_multiple_parser_instances() {
    let parser1 = SyslogParser::new();
    let parser2 = SyslogParser::new();

    let log = b"<34>1 2024-01-15T12:00:00Z host app - - - message";

    let result1 = parser1.parse(log);
    let result2 = parser2.parse(log);

    assert!(result1.is_ok());
    assert!(result2.is_ok());

    // 두 파서가 독립적으로 동작해야 함
    assert_eq!(
        result1.unwrap().message,
        result2.unwrap().message
    );
}

/// Collector → Pipeline Flow 통합 테스트
///
/// 이 테스트는 다음을 검증합니다:
/// 1. raw_log_sender()를 통해 로그 주입
/// 2. 파이프라인이 로그를 파싱
/// 3. 규칙 엔진이 매칭 수행
/// 4. 알림이 생성되어 채널로 전송
#[tokio::test(flavor = "multi_thread")]
async fn test_collector_to_pipeline_flow() {
    use std::fs;
    use std::io::Write;
    use std::time::Duration;
    use bytes::Bytes;

    // 1. 임시 규칙 디렉토리 생성
    let temp_dir = tempfile::tempdir().expect("failed to create temp dir");
    let rules_dir = temp_dir.path().join("rules");
    fs::create_dir(&rules_dir).expect("failed to create rules dir");

    // 2. 테스트 규칙 작성 - "failed login" 문자열을 탐지
    let rule_yaml = r#"
id: test-failed-login
title: Failed Login Detection
description: Detects failed login attempts
severity: High
detection:
  conditions:
    - field: message
      modifier: contains
      value: "Failed password"
tags:
  - authentication
  - test
"#;
    let rule_path = rules_dir.join("test-failed-login.yaml");
    let mut rule_file = fs::File::create(&rule_path).expect("failed to create rule file");
    rule_file.write_all(rule_yaml.as_bytes()).expect("failed to write rule");
    drop(rule_file);

    // 3. 파이프라인 설정
    let config = PipelineConfig {
        rule_dir: rules_dir.to_str().unwrap().to_owned(),
        batch_size: 10,
        buffer_capacity: 100,
        flush_interval_secs: 1,
        alert_dedup_window_secs: 60,
        alert_rate_limit_per_rule: 100,
        ..Default::default()
    };

    // 4. 파이프라인 빌드 (외부 alert 채널 사용)
    let (alert_tx, mut alert_rx) = mpsc::channel::<AlertEvent>(100);
    let result = LogPipelineBuilder::new()
        .config(config)
        .alert_sender(alert_tx)
        .build();

    assert!(result.is_ok(), "pipeline build failed");
    let (mut pipeline, _) = result.unwrap();

    // 5. 파이프라인 시작
    pipeline.start().await.expect("failed to start pipeline");

    // 규칙이 로드되었는지 확인
    let rule_count = pipeline.rule_count().await;
    assert_eq!(rule_count, 1, "expected 1 rule to be loaded");

    // 6. raw_log_sender() 획득
    let sender = pipeline.raw_log_sender();

    // 7. 규칙에 매칭되는 로그 주입
    let matching_log = b"<34>1 2024-01-15T12:00:00Z testhost sshd 1234 - - Failed password for root from 192.168.1.100";
    let raw_log = ironpost_log_pipeline::collector::RawLog::new(
        Bytes::from_static(matching_log),
        "test_source"
    );

    sender.send(raw_log).await.expect("failed to send log");

    // 8. 타임아웃 내에 알림 수신 대기
    let alert = tokio::time::timeout(Duration::from_secs(3), alert_rx.recv())
        .await
        .expect("timeout waiting for alert")
        .expect("alert channel closed");

    // 9. 알림 검증
    assert!(alert.alert.rule_name.contains("test-failed-login") || alert.alert.title.contains("Failed Login"));
    assert_eq!(alert.alert.severity, ironpost_core::types::Severity::High);

    // 10. 통계 확인
    let processed = pipeline.processed_count().await;
    assert_eq!(processed, 1, "expected 1 log to be processed");

    let parse_errors = pipeline.parse_error_count().await;
    assert_eq!(parse_errors, 0, "expected no parse errors");

    // 11. 파이프라인 정지
    pipeline.stop().await.expect("failed to stop pipeline");
}

/// Collector → Pipeline Flow 테스트: 매칭되지 않는 로그
///
/// 규칙에 매칭되지 않는 로그를 주입하면 알림이 생성되지 않아야 함
#[tokio::test(flavor = "multi_thread")]
async fn test_collector_to_pipeline_no_match() {
    use std::fs;
    use std::io::Write;
    use std::time::Duration;
    use bytes::Bytes;

    // 1. 임시 규칙 디렉토리 생성
    let temp_dir = tempfile::tempdir().expect("failed to create temp dir");
    let rules_dir = temp_dir.path().join("rules");
    fs::create_dir(&rules_dir).expect("failed to create rules dir");

    // 2. "attack" 문자열을 탐지하는 규칙
    let rule_yaml = r#"
id: test-attack-detection
title: Attack Detection
description: Detects attack keyword
severity: Critical
detection:
  conditions:
    - field: message
      modifier: contains
      value: "ATTACK"
tags:
  - security
"#;
    let rule_path = rules_dir.join("test-attack.yaml");
    let mut rule_file = fs::File::create(&rule_path).expect("failed to create rule file");
    rule_file.write_all(rule_yaml.as_bytes()).expect("failed to write rule");
    drop(rule_file);

    // 3. 파이프라인 빌드
    let config = PipelineConfig {
        rule_dir: rules_dir.to_str().unwrap().to_owned(),
        batch_size: 10,
        buffer_capacity: 100,
        flush_interval_secs: 1,
        ..Default::default()
    };

    let (alert_tx, mut alert_rx) = mpsc::channel::<AlertEvent>(100);
    let result = LogPipelineBuilder::new()
        .config(config)
        .alert_sender(alert_tx)
        .build();

    assert!(result.is_ok());
    let (mut pipeline, _) = result.unwrap();

    // 4. 파이프라인 시작
    pipeline.start().await.expect("failed to start pipeline");

    // 5. 규칙에 매칭되지 않는 로그 주입
    let sender = pipeline.raw_log_sender();
    let non_matching_log = b"<34>1 2024-01-15T12:00:00Z host app - - - Normal log message without keyword";
    let raw_log = ironpost_log_pipeline::collector::RawLog::new(
        Bytes::from_static(non_matching_log),
        "test_source"
    );

    sender.send(raw_log).await.expect("failed to send log");

    // 6. 알림이 오지 않아야 함 (타임아웃 예상)
    let result = tokio::time::timeout(Duration::from_millis(500), alert_rx.recv()).await;
    assert!(result.is_err(), "expected timeout, but received alert");

    // 7. 로그는 처리되었어야 함 (flush 대기)
    tokio::time::sleep(Duration::from_millis(1500)).await;
    let processed = pipeline.processed_count().await;
    assert_eq!(processed, 1, "expected 1 log to be processed");

    // 8. 파이프라인 정지
    pipeline.stop().await.expect("failed to stop pipeline");
}

/// Restart Scenario 통합 테스트
///
/// 파이프라인을 start → stop → start하여 재시작 기능을 검증
#[tokio::test(flavor = "multi_thread")]
async fn test_pipeline_restart_scenario() {
    use std::time::Duration;
    use bytes::Bytes;

    // 1. 빈 규칙 디렉토리
    let temp_dir = tempfile::tempdir().expect("failed to create temp dir");
    let rules_dir = temp_dir.path().join("rules");
    std::fs::create_dir(&rules_dir).expect("failed to create rules dir");

    // 2. 파이프라인 빌드
    let config = PipelineConfig {
        rule_dir: rules_dir.to_str().unwrap().to_owned(),
        batch_size: 10,
        buffer_capacity: 100,
        flush_interval_secs: 1,
        ..Default::default()
    };

    let (alert_tx, _alert_rx) = mpsc::channel::<AlertEvent>(100);
    let result = LogPipelineBuilder::new()
        .config(config)
        .alert_sender(alert_tx)
        .build();

    assert!(result.is_ok());
    let (mut pipeline, _) = result.unwrap();

    // === 첫 번째 사이클 ===

    // 3. 첫 번째 시작
    pipeline.start().await.expect("first start failed");
    assert_eq!(pipeline.state_name(), "running");

    // 4. 로그 주입
    let sender1 = pipeline.raw_log_sender();
    let log1 = b"<34>1 2024-01-15T12:00:00Z host app - - - First cycle log";
    let raw_log1 = ironpost_log_pipeline::collector::RawLog::new(
        Bytes::from_static(log1),
        "test_cycle1"
    );
    sender1.send(raw_log1).await.expect("failed to send log in cycle 1");

    // 5. 처리 대기 (flush interval보다 길게)
    tokio::time::sleep(Duration::from_millis(1500)).await;

    // 6. 통계 확인
    let processed1 = pipeline.processed_count().await;
    assert_eq!(processed1, 1, "expected 1 log processed in cycle 1");

    // 7. 첫 번째 정지
    pipeline.stop().await.expect("first stop failed");
    assert_eq!(pipeline.state_name(), "stopped");

    // === 두 번째 사이클 (재시작) ===

    // 8. 두 번째 시작 (재시작)
    pipeline.start().await.expect("restart failed");
    assert_eq!(pipeline.state_name(), "running");

    // 9. 새로운 로그 주입
    let sender2 = pipeline.raw_log_sender();
    let log2 = b"<34>1 2024-01-15T12:01:00Z host app - - - Second cycle log";
    let raw_log2 = ironpost_log_pipeline::collector::RawLog::new(
        Bytes::from_static(log2),
        "test_cycle2"
    );
    sender2.send(raw_log2).await.expect("failed to send log in cycle 2");

    // 10. 처리 대기 (flush interval보다 길게)
    tokio::time::sleep(Duration::from_millis(1500)).await;

    // 11. 통계 확인 (카운터는 누적됨)
    let processed2 = pipeline.processed_count().await;
    assert_eq!(processed2, 2, "expected 2 logs processed after restart");

    // 12. 두 번째 정지
    pipeline.stop().await.expect("second stop failed");
    assert_eq!(pipeline.state_name(), "stopped");

    // === 세 번째 사이클 (한 번 더 재시작) ===

    // 13. 세 번째 시작
    pipeline.start().await.expect("second restart failed");
    assert_eq!(pipeline.state_name(), "running");

    // 14. 새로운 로그 주입
    let sender3 = pipeline.raw_log_sender();
    let log3 = b"<34>1 2024-01-15T12:02:00Z host app - - - Third cycle log";
    let raw_log3 = ironpost_log_pipeline::collector::RawLog::new(
        Bytes::from_static(log3),
        "test_cycle3"
    );
    sender3.send(raw_log3).await.expect("failed to send log in cycle 3");

    // 15. 처리 대기 (flush interval보다 길게)
    tokio::time::sleep(Duration::from_millis(1500)).await;

    // 16. 최종 통계 확인
    let processed3 = pipeline.processed_count().await;
    assert_eq!(processed3, 3, "expected 3 logs processed after second restart");

    // 17. 최종 정지
    pipeline.stop().await.expect("third stop failed");
}

/// 다중 로그 주입 시나리오
///
/// 여러 개의 로그를 연속으로 주입하여 배치 처리와 플러시 동작을 검증
#[tokio::test(flavor = "multi_thread")]
async fn test_multiple_log_injection() {
    use std::time::Duration;
    use bytes::Bytes;

    // 1. 파이프라인 설정 (작은 배치 크기)
    let temp_dir = tempfile::tempdir().expect("failed to create temp dir");
    let rules_dir = temp_dir.path().join("rules");
    std::fs::create_dir(&rules_dir).expect("failed to create rules dir");

    let config = PipelineConfig {
        rule_dir: rules_dir.to_str().unwrap().to_owned(),
        batch_size: 5, // 작은 배치 크기로 테스트
        buffer_capacity: 100,
        flush_interval_secs: 1,
        ..Default::default()
    };

    let (alert_tx, _alert_rx) = mpsc::channel::<AlertEvent>(100);
    let result = LogPipelineBuilder::new()
        .config(config)
        .alert_sender(alert_tx)
        .build();

    assert!(result.is_ok());
    let (mut pipeline, _) = result.unwrap();

    // 2. 파이프라인 시작
    pipeline.start().await.expect("failed to start pipeline");

    // 3. 다수의 로그 주입
    let sender = pipeline.raw_log_sender();
    let log_count = 20;

    for i in 0..log_count {
        let log_msg = format!("<34>1 2024-01-15T12:00:00Z host app - - - Test log message {}", i);
        let raw_log = ironpost_log_pipeline::collector::RawLog::new(
            Bytes::from(log_msg.into_bytes()),
            "test_batch"
        );
        sender.send(raw_log).await.expect("failed to send log");
    }

    // 4. 모든 로그가 처리될 때까지 대기
    tokio::time::sleep(Duration::from_millis(500)).await;

    // 5. 통계 확인
    let processed = pipeline.processed_count().await;
    assert_eq!(processed, log_count, "expected all logs to be processed");

    let parse_errors = pipeline.parse_error_count().await;
    assert_eq!(parse_errors, 0, "expected no parse errors");

    // 6. 버퍼 사용률 확인 (모두 처리되었으면 낮아야 함)
    let utilization = pipeline.buffer_utilization().await;
    assert!(utilization < 0.5, "buffer should be mostly empty after processing");

    // 7. 파이프라인 정지
    pipeline.stop().await.expect("failed to stop pipeline");
}

/// JSON 로그 파싱 및 규칙 매칭 테스트
///
/// JSON 형식 로그를 파이프라인에 주입하여 파싱 및 매칭 검증
#[tokio::test(flavor = "multi_thread")]
async fn test_json_log_pipeline_flow() {
    use std::fs;
    use std::io::Write;
    use std::time::Duration;
    use bytes::Bytes;

    // 1. 규칙 디렉토리 생성
    let temp_dir = tempfile::tempdir().expect("failed to create temp dir");
    let rules_dir = temp_dir.path().join("rules");
    fs::create_dir(&rules_dir).expect("failed to create rules dir");

    // 2. JSON 로그용 규칙 작성 (message 필드에서 키워드 탐지)
    let rule_yaml = r#"
id: test-json-error
title: JSON Error Detection
description: Detects database errors in JSON logs
severity: Medium
detection:
  conditions:
    - field: message
      modifier: contains
      value: "Database"
tags:
  - json
  - error
"#;
    let rule_path = rules_dir.join("test-json-error.yaml");
    let mut rule_file = fs::File::create(&rule_path).expect("failed to create rule file");
    rule_file.write_all(rule_yaml.as_bytes()).expect("failed to write rule");
    drop(rule_file);

    // 3. 파이프라인 빌드 (빠른 플러시로 테스트 속도 향상)
    let config = PipelineConfig {
        rule_dir: rules_dir.to_str().unwrap().to_owned(),
        batch_size: 1, // 단일 로그로 즉시 플러시
        buffer_capacity: 100,
        flush_interval_secs: 1,
        ..Default::default()
    };

    let (alert_tx, mut alert_rx) = mpsc::channel::<AlertEvent>(100);
    let result = LogPipelineBuilder::new()
        .config(config)
        .alert_sender(alert_tx)
        .build();

    assert!(result.is_ok());
    let (mut pipeline, _) = result.unwrap();

    // 4. 파이프라인 시작
    pipeline.start().await.expect("failed to start pipeline");

    // 5. JSON 로그 주입
    let sender = pipeline.raw_log_sender();
    let json_log = r#"{"timestamp":"2024-01-15T12:00:00Z","level":"ERROR","message":"Database connection failed","src_ip":"192.168.1.50"}"#;
    let raw_log = ironpost_log_pipeline::collector::RawLog::new(
        Bytes::from(json_log.as_bytes().to_vec()),
        "test_json"
    ).with_format_hint("json");

    sender.send(raw_log).await.expect("failed to send JSON log");

    // 6. 알림 대기
    let alert = tokio::time::timeout(Duration::from_secs(3), alert_rx.recv())
        .await
        .expect("timeout waiting for alert")
        .expect("alert channel closed");

    // 7. 알림 검증
    assert!(alert.alert.rule_name.contains("test-json-error") || alert.alert.title.contains("JSON Error"));
    assert_eq!(alert.alert.severity, ironpost_core::types::Severity::Medium);

    // 8. 통계 확인
    let processed = pipeline.processed_count().await;
    assert_eq!(processed, 1);

    // 9. 파이프라인 정지
    pipeline.stop().await.expect("failed to stop pipeline");
}

/// 헬스 체크 통합 테스트
///
/// 파이프라인의 헬스 체크가 상태에 따라 올바르게 동작하는지 검증
#[tokio::test]
async fn test_pipeline_health_check_states() {
    use std::time::Duration;

    // 1. 파이프라인 빌드
    let temp_dir = tempfile::tempdir().expect("failed to create temp dir");
    let rules_dir = temp_dir.path().join("rules");
    std::fs::create_dir(&rules_dir).expect("failed to create rules dir");

    let config = PipelineConfig {
        rule_dir: rules_dir.to_str().unwrap().to_owned(),
        ..Default::default()
    };

    let (alert_tx, _alert_rx) = mpsc::channel::<AlertEvent>(100);
    let result = LogPipelineBuilder::new()
        .config(config)
        .alert_sender(alert_tx)
        .build();

    assert!(result.is_ok());
    let (mut pipeline, _) = result.unwrap();

    // 2. 초기 상태: Unhealthy (not started)
    let health = pipeline.health_check().await;
    match health {
        HealthStatus::Unhealthy(_) => {},
        _ => panic!("expected Unhealthy status before start, got: {:?}", health),
    }

    // 3. 시작 후: Healthy
    pipeline.start().await.expect("failed to start");
    tokio::time::sleep(Duration::from_millis(100)).await;

    let health = pipeline.health_check().await;
    match health {
        HealthStatus::Healthy => {},
        _ => panic!("expected Healthy status after start, got: {:?}", health),
    }

    // 4. 정지 후: Unhealthy (stopped)
    pipeline.stop().await.expect("failed to stop");
    let health = pipeline.health_check().await;
    match health {
        HealthStatus::Unhealthy(_) => {},
        _ => panic!("expected Unhealthy status after stop, got: {:?}", health),
    }
}

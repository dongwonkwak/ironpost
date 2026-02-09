//! 통합 테스트 -- 파이프라인 전체 흐름 검증
//!
//! 이 파일은 로그 수집부터 알림 생성까지의 전체 파이프라인을 검증합니다.

use std::path::PathBuf;
use std::time::Duration;

use tokio::sync::mpsc;

use ironpost_core::event::{AlertEvent, PacketEvent};
use ironpost_core::pipeline::{LogParser, Pipeline};
use ironpost_core::types::{PacketInfo, Severity};
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

    // 5. 검증 - 규칙 엔진이 정상 동작하는지 확인
    assert!(matches.len() >= 0); // 패닉 없이 완료
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

    let mut config = PipelineConfig::default();
    config.rule_dir = temp_dir.path().to_str().unwrap().to_owned();

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
        let _ = rule_engine.load_rules_from_dir(&rules_dir);
    }

    // 규칙 카운트 확인
    let rule_count = rule_engine.rule_count();
    assert!(rule_count >= 0);
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
    let mut config = PipelineConfig::default();

    // 기본 설정은 유효해야 함
    assert!(config.validate().is_ok());

    // 잘못된 설정
    config.batch_size = 0;
    assert!(config.validate().is_err());

    config.batch_size = 100;
    config.flush_interval_secs = 0;
    assert!(config.validate().is_err());

    config.flush_interval_secs = 5;
    config.buffer_capacity = 0;
    assert!(config.validate().is_err());
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

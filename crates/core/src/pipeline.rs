//! 파이프라인 trait — 모듈 생명주기 및 확장 포인트 정의
//!
//! [`Pipeline`] trait은 모든 모듈이 구현하는 생명주기 인터페이스입니다.
//! [`Detector`], [`LogParser`], [`PolicyEnforcer`] trait은 플러그인 확장 포인트입니다.

use std::fmt;
use std::future::Future;
use std::pin::Pin;

use serde::{Deserialize, Serialize};

use crate::error::IronpostError;

/// dyn-compatible Future 타입 별칭
pub type BoxFuture<'a, T> = Pin<Box<dyn Future<Output = T> + Send + 'a>>;
use crate::types::{Alert, LogEntry};

/// 모든 파이프라인 모듈이 구현하는 생명주기 trait
///
/// `ironpost-daemon`에서 각 모듈을 시작/정지하고 상태를 확인하는 데 사용됩니다.
///
/// # 구현 예시
/// ```ignore
/// struct EbpfPipeline { /* ... */ }
///
/// impl Pipeline for EbpfPipeline {
///     async fn start(&mut self) -> Result<(), IronpostError> {
///         // XDP 프로그램 로드, 링 버퍼 설정 등
///         Ok(())
///     }
///
///     async fn stop(&mut self) -> Result<(), IronpostError> {
///         // 리소스 정리, 프로그램 언로드
///         Ok(())
///     }
///
///     async fn health_check(&self) -> HealthStatus {
///         HealthStatus::Healthy
///     }
/// }
/// ```
pub trait Pipeline: Send + Sync {
    /// 모듈을 시작합니다.
    ///
    /// 리소스 초기화, 워커 스폰, 채널 연결 등을 수행합니다.
    /// 이미 실행 중인 경우 `PipelineError::AlreadyRunning`을 반환합니다.
    fn start(&mut self) -> impl std::future::Future<Output = Result<(), IronpostError>> + Send;

    /// 모듈을 정지합니다.
    ///
    /// Graceful shutdown을 수행합니다.
    /// 진행 중인 작업을 완료하고 리소스를 정리합니다.
    fn stop(&mut self) -> impl std::future::Future<Output = Result<(), IronpostError>> + Send;

    /// 모듈의 현재 상태를 확인합니다.
    ///
    /// 주기적으로 호출되어 모듈의 건강 상태를 모니터링합니다.
    fn health_check(&self) -> impl std::future::Future<Output = HealthStatus> + Send;
}

/// dyn-compatible 파이프라인 trait
///
/// `Pipeline` trait은 RPITIT를 사용하므로 `dyn Pipeline`이 불가합니다.
/// `DynPipeline`은 `BoxFuture`를 반환하여 `Vec<Box<dyn DynPipeline>>`으로
/// 모듈을 동적 관리할 수 있게 합니다.
///
/// # 구현 예시
/// ```ignore
/// // Pipeline을 구현한 타입은 blanket impl으로 자동으로 DynPipeline도 구현됩니다.
/// let modules: Vec<Box<dyn DynPipeline>> = vec![
///     Box::new(ebpf_pipeline),
///     Box::new(log_pipeline),
/// ];
/// ```
pub trait DynPipeline: Send + Sync {
    /// 모듈을 시작합니다.
    fn start(&mut self) -> BoxFuture<'_, Result<(), IronpostError>>;

    /// 모듈을 정지합니다.
    fn stop(&mut self) -> BoxFuture<'_, Result<(), IronpostError>>;

    /// 모듈의 현재 상태를 확인합니다.
    fn health_check(&self) -> BoxFuture<'_, HealthStatus>;
}

impl<T: Pipeline> DynPipeline for T {
    fn start(&mut self) -> BoxFuture<'_, Result<(), IronpostError>> {
        Box::pin(Pipeline::start(self))
    }

    fn stop(&mut self) -> BoxFuture<'_, Result<(), IronpostError>> {
        Box::pin(Pipeline::stop(self))
    }

    fn health_check(&self) -> BoxFuture<'_, HealthStatus> {
        Box::pin(Pipeline::health_check(self))
    }
}

/// 모듈 헬스 상태
///
/// 각 모듈의 현재 운영 상태를 나타냅니다.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum HealthStatus {
    /// 정상 동작 중
    Healthy,
    /// 성능 저하 또는 부분적 장애 (서비스는 계속 동작)
    Degraded(String),
    /// 비정상 — 서비스 불가 상태
    Unhealthy(String),
}

impl HealthStatus {
    /// 정상 상태인지 확인합니다.
    pub fn is_healthy(&self) -> bool {
        matches!(self, Self::Healthy)
    }

    /// 비정상 상태인지 확인합니다.
    pub fn is_unhealthy(&self) -> bool {
        matches!(self, Self::Unhealthy(_))
    }
}

impl fmt::Display for HealthStatus {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Healthy => write!(f, "healthy"),
            Self::Degraded(reason) => write!(f, "degraded: {reason}"),
            Self::Unhealthy(reason) => write!(f, "unhealthy: {reason}"),
        }
    }
}

/// 탐지 로직을 구현하는 trait
///
/// 새로운 탐지 규칙을 추가하려면 이 trait을 구현합니다.
/// `ironpost-daemon`에서 빌더 패턴으로 등록하여 사용합니다.
///
/// # 구현 예시
/// ```ignore
/// struct BruteForceDetector;
///
/// impl Detector for BruteForceDetector {
///     fn name(&self) -> &str { "brute_force" }
///
///     fn detect(&self, entry: &LogEntry) -> Result<Option<Alert>, IronpostError> {
///         if entry.message.contains("Failed password") {
///             Ok(Some(Alert { /* ... */ }))
///         } else {
///             Ok(None)
///         }
///     }
/// }
/// ```
pub trait Detector: Send + Sync {
    /// 탐지기 이름
    fn name(&self) -> &str;

    /// 로그 엔트리를 분석하여 알림 생성 여부를 결정합니다.
    ///
    /// 탐지 규칙에 매칭되면 `Ok(Some(Alert))`을,
    /// 매칭되지 않으면 `Ok(None)`을 반환합니다.
    fn detect(&self, entry: &LogEntry) -> Result<Option<Alert>, IronpostError>;
}

/// 로그 파서 trait
///
/// 새로운 로그 형식을 지원하려면 이 trait을 구현합니다.
/// Syslog, CEF, JSON 등 다양한 형식의 파서를 추가할 수 있습니다.
///
/// # 구현 예시
/// ```ignore
/// struct SyslogParser;
///
/// impl LogParser for SyslogParser {
///     fn format_name(&self) -> &str { "syslog" }
///
///     fn parse(&self, raw: &[u8]) -> Result<LogEntry, IronpostError> {
///         // syslog 형식 파싱 로직
///         todo!()
///     }
/// }
/// ```
pub trait LogParser: Send + Sync {
    /// 지원하는 로그 형식 이름
    fn format_name(&self) -> &str;

    /// 원시 바이트를 로그 엔트리로 파싱합니다.
    fn parse(&self, raw: &[u8]) -> Result<LogEntry, IronpostError>;
}

/// 격리 정책을 구현하는 trait
///
/// 보안 알림에 대한 자동 대응 정책을 정의합니다.
/// 알림의 심각도와 유형에 따라 격리 여부를 결정합니다.
pub trait PolicyEnforcer: Send + Sync {
    /// 정책 이름
    fn name(&self) -> &str;

    /// 알림에 대해 격리 실행 여부를 결정하고, 필요 시 격리를 수행합니다.
    ///
    /// 격리를 수행했으면 `Ok(true)`, 수행하지 않았으면 `Ok(false)`를 반환합니다.
    fn enforce(&self, alert: &Alert) -> Result<bool, IronpostError>;
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn health_status_healthy() {
        let status = HealthStatus::Healthy;
        assert!(status.is_healthy());
        assert!(!status.is_unhealthy());
        assert_eq!(status.to_string(), "healthy");
    }

    #[test]
    fn health_status_degraded() {
        let status = HealthStatus::Degraded("high latency".to_owned());
        assert!(!status.is_healthy());
        assert!(!status.is_unhealthy());
        assert!(status.to_string().contains("high latency"));
    }

    #[test]
    fn health_status_unhealthy() {
        let status = HealthStatus::Unhealthy("connection lost".to_owned());
        assert!(!status.is_healthy());
        assert!(status.is_unhealthy());
        assert!(status.to_string().contains("connection lost"));
    }

    #[test]
    fn health_status_equality() {
        assert_eq!(HealthStatus::Healthy, HealthStatus::Healthy);
        assert_ne!(
            HealthStatus::Healthy,
            HealthStatus::Degraded("reason".to_owned())
        );
    }

    #[test]
    fn health_status_serialize_deserialize() {
        let status = HealthStatus::Degraded("slow".to_owned());
        let json = serde_json::to_string(&status).unwrap();
        let deserialized: HealthStatus = serde_json::from_str(&json).unwrap();
        assert_eq!(status, deserialized);
    }

    // Pipeline trait의 구현 테스트를 위한 mock
    struct MockPipeline {
        running: bool,
    }

    impl MockPipeline {
        fn new() -> Self {
            Self { running: false }
        }
    }

    impl Pipeline for MockPipeline {
        async fn start(&mut self) -> Result<(), IronpostError> {
            if self.running {
                return Err(crate::error::PipelineError::AlreadyRunning.into());
            }
            self.running = true;
            Ok(())
        }

        async fn stop(&mut self) -> Result<(), IronpostError> {
            if !self.running {
                return Err(crate::error::PipelineError::NotRunning.into());
            }
            self.running = false;
            Ok(())
        }

        async fn health_check(&self) -> HealthStatus {
            if self.running {
                HealthStatus::Healthy
            } else {
                HealthStatus::Unhealthy("not running".to_owned())
            }
        }
    }

    #[tokio::test]
    async fn mock_pipeline_lifecycle() {
        let mut pipeline = MockPipeline::new();

        // 시작 전 상태 확인
        assert!(Pipeline::health_check(&pipeline).await.is_unhealthy());

        // 시작
        Pipeline::start(&mut pipeline).await.unwrap();
        assert!(Pipeline::health_check(&pipeline).await.is_healthy());

        // 중복 시작 시 에러
        let err = Pipeline::start(&mut pipeline).await;
        assert!(err.is_err());

        // 정지
        Pipeline::stop(&mut pipeline).await.unwrap();
        assert!(Pipeline::health_check(&pipeline).await.is_unhealthy());

        // 중복 정지 시 에러
        let err = Pipeline::stop(&mut pipeline).await;
        assert!(err.is_err());
    }

    #[tokio::test]
    async fn dyn_pipeline_can_be_boxed() {
        let mut pipeline: Box<dyn DynPipeline> = Box::new(MockPipeline::new());

        assert!(pipeline.health_check().await.is_unhealthy());
        pipeline.start().await.unwrap();
        assert!(pipeline.health_check().await.is_healthy());
        pipeline.stop().await.unwrap();
        assert!(pipeline.health_check().await.is_unhealthy());
    }

    // Detector trait mock 테스트
    struct AlwaysAlertDetector;

    impl Detector for AlwaysAlertDetector {
        fn name(&self) -> &str {
            "always-alert"
        }

        fn detect(&self, entry: &LogEntry) -> Result<Option<Alert>, IronpostError> {
            Ok(Some(Alert {
                id: "test-alert".to_owned(),
                title: format!("Alert for: {}", entry.message),
                description: String::new(),
                severity: crate::types::Severity::Medium,
                rule_name: self.name().to_owned(),
                source_ip: None,
                target_ip: None,
                created_at: std::time::SystemTime::now(),
            }))
        }
    }

    #[test]
    fn detector_produces_alert() {
        let detector = AlwaysAlertDetector;
        assert_eq!(detector.name(), "always-alert");

        let entry = LogEntry {
            source: "test".to_owned(),
            timestamp: std::time::SystemTime::now(),
            hostname: "localhost".to_owned(),
            process: "test".to_owned(),
            message: "suspicious activity".to_owned(),
            severity: crate::types::Severity::Info,
            fields: vec![],
        };

        let result = detector.detect(&entry).unwrap();
        assert!(result.is_some());
        let alert = result.unwrap();
        assert!(alert.title.contains("suspicious activity"));
    }

    // LogParser trait mock 테스트
    struct SimpleParser;

    impl LogParser for SimpleParser {
        fn format_name(&self) -> &str {
            "simple"
        }

        fn parse(&self, raw: &[u8]) -> Result<LogEntry, IronpostError> {
            let message = String::from_utf8_lossy(raw).into_owned();
            Ok(LogEntry {
                source: "simple-parser".to_owned(),
                timestamp: std::time::SystemTime::now(),
                hostname: "unknown".to_owned(),
                process: "unknown".to_owned(),
                message,
                severity: crate::types::Severity::Info,
                fields: vec![],
            })
        }
    }

    #[test]
    fn log_parser_parses_raw_bytes() {
        let parser = SimpleParser;
        assert_eq!(parser.format_name(), "simple");

        let entry = parser.parse(b"hello world").unwrap();
        assert_eq!(entry.message, "hello world");
    }
}

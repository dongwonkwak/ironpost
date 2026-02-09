//! 파이프라인 오케스트레이션 -- 수집/파싱/매칭/알림의 전체 흐름을 관리합니다.
//!
//! [`LogPipeline`]은 core의 [`Pipeline`](ironpost_core::pipeline::Pipeline) trait을 구현하여
//! `ironpost-daemon`에서 다른 모듈과 동일한 생명주기로 관리됩니다.
//!
//! # 내부 아키텍처
//! ```text
//! Collectors -> mpsc -> Buffer -> Parser -> RuleEngine -> AlertGenerator -> mpsc -> downstream
//! ```

use tokio::sync::mpsc;

use ironpost_core::error::IronpostError;
use ironpost_core::event::{AlertEvent, PacketEvent};
use ironpost_core::pipeline::{HealthStatus, Pipeline};

use crate::alert::AlertGenerator;
use crate::buffer::LogBuffer;
use crate::collector::{CollectorSet, RawLog};
use crate::config::PipelineConfig;
use crate::error::LogPipelineError;
use crate::parser::ParserRouter;
use crate::rule::RuleEngine;

/// 파이프라인 실행 상태
#[derive(Debug, Clone, PartialEq, Eq)]
enum PipelineState {
    /// 초기화됨, 아직 시작하지 않음
    Initialized,
    /// 실행 중
    Running,
    /// 정지됨
    Stopped,
}

/// 로그 파이프라인 -- 수집/파싱/룰 매칭/알림의 전체 흐름을 관리합니다.
///
/// core의 `Pipeline` trait을 구현하여 `ironpost-daemon`에서
/// 다른 모듈과 동일한 생명주기(start/stop/health_check)로 관리됩니다.
///
/// # 사용 예시
/// ```ignore
/// use ironpost_log_pipeline::{LogPipeline, LogPipelineBuilder};
///
/// let (pipeline, alert_rx) = LogPipelineBuilder::new()
///     .config(config)
///     .packet_receiver(packet_rx)  // from ebpf-engine
///     .build()?;
///
/// // Pipeline trait으로 시작
/// pipeline.start().await?;
/// ```
pub struct LogPipeline {
    /// 파이프라인 설정
    config: PipelineConfig,
    /// 현재 상태
    state: PipelineState,
    /// 파서 라우터
    #[allow(dead_code)]
    parser: ParserRouter,
    /// 규칙 엔진
    rule_engine: RuleEngine,
    /// 알림 생성기
    #[allow(dead_code)]
    alert_generator: AlertGenerator,
    /// 로그 버퍼
    buffer: LogBuffer,
    /// 수집기 세트
    #[allow(dead_code)]
    collectors: CollectorSet,
    /// 내부 RawLog 채널 (수집기 -> 파이프라인)
    #[allow(dead_code)]
    raw_log_rx: Option<mpsc::Receiver<RawLog>>,
    /// 내부 RawLog 채널 송신측 (수집기에 전달)
    #[allow(dead_code)]
    raw_log_tx: mpsc::Sender<RawLog>,
    /// 알림 전송 채널 (파이프라인 -> downstream)
    #[allow(dead_code)]
    alert_tx: mpsc::Sender<AlertEvent>,
    /// PacketEvent 수신 채널 (ebpf-engine -> 파이프라인, daemon에서 연결)
    #[allow(dead_code)]
    packet_rx: Option<mpsc::Receiver<PacketEvent>>,
    /// 백그라운드 태스크 핸들
    tasks: Vec<tokio::task::JoinHandle<()>>,
    /// 파싱 에러 카운터
    parse_error_count: u64,
    /// 처리된 로그 카운터
    processed_count: u64,
}

impl LogPipeline {
    /// 현재 상태를 반환합니다.
    pub fn state_name(&self) -> &str {
        match self.state {
            PipelineState::Initialized => "initialized",
            PipelineState::Running => "running",
            PipelineState::Stopped => "stopped",
        }
    }

    /// 처리된 로그 수를 반환합니다.
    pub fn processed_count(&self) -> u64 {
        self.processed_count
    }

    /// 파싱 에러 수를 반환합니다.
    pub fn parse_error_count(&self) -> u64 {
        self.parse_error_count
    }

    /// 로드된 규칙 수를 반환합니다.
    pub fn rule_count(&self) -> usize {
        self.rule_engine.rule_count()
    }

    /// 버퍼 사용률을 반환합니다.
    pub fn buffer_utilization(&self) -> f64 {
        self.buffer.utilization()
    }

    /// 규칙 엔진에 대한 불변 참조를 반환합니다.
    pub fn rule_engine(&self) -> &RuleEngine {
        &self.rule_engine
    }

    /// 규칙 엔진에 대한 가변 참조를 반환합니다.
    pub fn rule_engine_mut(&mut self) -> &mut RuleEngine {
        &mut self.rule_engine
    }
}

impl Pipeline for LogPipeline {
    async fn start(&mut self) -> Result<(), IronpostError> {
        if self.state == PipelineState::Running {
            return Err(ironpost_core::error::PipelineError::AlreadyRunning.into());
        }

        tracing::info!("starting log pipeline");

        // 1. 규칙 로드
        let rule_count = self
            .rule_engine
            .load_rules_from_dir(&self.config.rule_dir)
            .await
            .map_err(IronpostError::from)?;
        tracing::info!(rules = rule_count, "loaded detection rules");

        // 2. 수집기 태스크 스폰
        // TODO: spawn collector tasks based on config.sources
        // Each collector gets a clone of raw_log_tx

        // 3. 메인 처리 루프 스폰
        // TODO: spawn main processing loop:
        //   - recv from raw_log_rx
        //   - buffer.push()
        //   - when should_flush: drain_batch -> parse -> rule_engine.evaluate -> alert_generator.generate
        //   - send AlertEvent to alert_tx

        self.state = PipelineState::Running;
        tracing::info!("log pipeline started");
        Ok(())
    }

    async fn stop(&mut self) -> Result<(), IronpostError> {
        if self.state != PipelineState::Running {
            return Err(ironpost_core::error::PipelineError::NotRunning.into());
        }

        tracing::info!("stopping log pipeline");

        // 1. 백그라운드 태스크 중단
        for task in self.tasks.drain(..) {
            task.abort();
        }

        // 2. 버퍼에 남은 로그 처리 (graceful drain)
        let remaining = self.buffer.drain_all();
        if !remaining.is_empty() {
            tracing::info!(count = remaining.len(), "draining remaining buffered logs");
            // TODO: process remaining logs
        }

        self.state = PipelineState::Stopped;
        tracing::info!("log pipeline stopped");
        Ok(())
    }

    async fn health_check(&self) -> HealthStatus {
        match self.state {
            PipelineState::Running => {
                let utilization = self.buffer.utilization();
                if utilization > 0.9 {
                    HealthStatus::Degraded(format!(
                        "buffer utilization high: {:.1}%",
                        utilization * 100.0
                    ))
                } else {
                    HealthStatus::Healthy
                }
            }
            PipelineState::Initialized => HealthStatus::Unhealthy("not started".to_owned()),
            PipelineState::Stopped => HealthStatus::Unhealthy("stopped".to_owned()),
        }
    }
}

/// 로그 파이프라인 빌더
///
/// 파이프라인을 구성하고 필요한 채널을 생성합니다.
pub struct LogPipelineBuilder {
    config: PipelineConfig,
    packet_rx: Option<mpsc::Receiver<PacketEvent>>,
    alert_tx: Option<mpsc::Sender<AlertEvent>>,
    alert_channel_capacity: usize,
}

impl LogPipelineBuilder {
    /// 새 빌더를 생성합니다.
    pub fn new() -> Self {
        Self {
            config: PipelineConfig::default(),
            packet_rx: None,
            alert_tx: None,
            alert_channel_capacity: 1024,
        }
    }

    /// 파이프라인 설정을 지정합니다.
    pub fn config(mut self, config: PipelineConfig) -> Self {
        self.config = config;
        self
    }

    /// eBPF 엔진의 PacketEvent 수신 채널을 설정합니다.
    ///
    /// `ironpost-daemon`에서 ebpf-engine의 출력 채널을 여기에 연결합니다.
    pub fn packet_receiver(mut self, rx: mpsc::Receiver<PacketEvent>) -> Self {
        self.packet_rx = Some(rx);
        self
    }

    /// 외부 알림 전송 채널을 설정합니다.
    ///
    /// 설정하지 않으면 빌더가 새 채널을 생성합니다.
    pub fn alert_sender(mut self, tx: mpsc::Sender<AlertEvent>) -> Self {
        self.alert_tx = Some(tx);
        self
    }

    /// 알림 채널 용량을 설정합니다 (외부 채널 미사용 시).
    pub fn alert_channel_capacity(mut self, capacity: usize) -> Self {
        self.alert_channel_capacity = capacity;
        self
    }

    /// 파이프라인을 빌드합니다.
    ///
    /// # Returns
    /// - `LogPipeline`: 파이프라인 인스턴스
    /// - `Option<mpsc::Receiver<AlertEvent>>`: 알림 수신 채널
    ///   (외부 alert_sender를 설정한 경우 None)
    pub fn build(
        self,
    ) -> Result<(LogPipeline, Option<mpsc::Receiver<AlertEvent>>), LogPipelineError> {
        self.config.validate()?;

        let (raw_log_tx, raw_log_rx) = mpsc::channel(self.config.buffer_capacity);

        let (alert_tx, alert_rx) = if let Some(tx) = self.alert_tx {
            (tx, None)
        } else {
            let (tx, rx) = mpsc::channel(self.alert_channel_capacity);
            (tx, Some(rx))
        };

        let buffer = LogBuffer::new(self.config.buffer_capacity, self.config.drop_policy.clone());

        let alert_generator = AlertGenerator::new(
            self.config.alert_dedup_window_secs,
            self.config.alert_rate_limit_per_rule,
        );

        let pipeline = LogPipeline {
            config: self.config,
            state: PipelineState::Initialized,
            parser: ParserRouter::with_defaults(),
            rule_engine: RuleEngine::new(),
            alert_generator,
            buffer,
            collectors: CollectorSet::default(),
            raw_log_rx: Some(raw_log_rx),
            raw_log_tx,
            alert_tx,
            packet_rx: self.packet_rx,
            tasks: Vec::new(),
            parse_error_count: 0,
            processed_count: 0,
        };

        Ok((pipeline, alert_rx))
    }
}

impl Default for LogPipelineBuilder {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn builder_creates_pipeline() {
        let (pipeline, alert_rx) = LogPipelineBuilder::new().build().unwrap();
        assert_eq!(pipeline.state_name(), "initialized");
        assert!(alert_rx.is_some());
    }

    #[test]
    fn builder_with_external_alert_sender() {
        let (alert_tx, _alert_rx) = mpsc::channel(10);
        let (_pipeline, rx) = LogPipelineBuilder::new()
            .alert_sender(alert_tx)
            .build()
            .unwrap();
        assert!(rx.is_none()); // no internal receiver when external sender is provided
    }

    #[test]
    fn builder_with_invalid_config_fails() {
        let mut config = PipelineConfig::default();
        config.batch_size = 0;
        let result: Result<(LogPipeline, _), _> = LogPipelineBuilder::new().config(config).build();
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn pipeline_lifecycle() {
        let (mut pipeline, _alert_rx) = LogPipelineBuilder::new().build().unwrap();

        // Before start
        assert!(pipeline.health_check().await.is_unhealthy());

        // Double stop before start fails
        let err = pipeline.stop().await;
        assert!(err.is_err());
    }

    #[test]
    fn pipeline_accessors() {
        let (pipeline, _) = LogPipelineBuilder::new().build().unwrap();
        assert_eq!(pipeline.processed_count(), 0);
        assert_eq!(pipeline.parse_error_count(), 0);
        assert_eq!(pipeline.rule_count(), 0);
        assert_eq!(pipeline.buffer_utilization(), 0.0);
    }
}

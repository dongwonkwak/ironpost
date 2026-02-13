//! 파이프라인 오케스트레이션 -- 수집/파싱/매칭/알림의 전체 흐름을 관리합니다.
//!
//! [`LogPipeline`]은 core의 [`Pipeline`] trait을 구현하여
//! `ironpost-daemon`에서 다른 모듈과 동일한 생명주기로 관리됩니다.
//!
//! # 내부 아키텍처
//! ```text
//! Collectors -> mpsc -> Buffer -> Parser -> RuleEngine -> AlertGenerator -> mpsc -> downstream
//! ```

use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;

use tokio::sync::{Mutex, mpsc};
use tokio::time::{Instant, interval};

use ironpost_core::error::IronpostError;
use ironpost_core::event::{AlertEvent, MODULE_LOG_PIPELINE, PacketEvent};
use ironpost_core::pipeline::{HealthStatus, Pipeline};
use ironpost_core::plugin::{Plugin, PluginInfo, PluginState, PluginType};

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
    /// 플러그인 메타데이터
    plugin_info: PluginInfo,
    /// 플러그인 상태
    plugin_state: PluginState,
    /// 파이프라인 설정
    config: PipelineConfig,
    /// 현재 상태
    state: PipelineState,
    /// 파서 라우터 (공유)
    parser: Arc<ParserRouter>,
    /// 규칙 엔진 (공유)
    rule_engine: Arc<Mutex<RuleEngine>>,
    /// 알림 생성기 (공유)
    alert_generator: Arc<Mutex<AlertGenerator>>,
    /// 로그 버퍼
    buffer: Arc<Mutex<LogBuffer>>,
    /// 수집기 세트
    #[allow(dead_code)]
    collectors: CollectorSet,
    /// 내부 RawLog 채널 (수집기 -> 파이프라인)
    raw_log_rx: Option<mpsc::Receiver<RawLog>>,
    /// 내부 RawLog 채널 송신측 (수집기에 전달)
    raw_log_tx: mpsc::Sender<RawLog>,
    /// 알림 전송 채널 (파이프라인 -> downstream)
    alert_tx: mpsc::Sender<AlertEvent>,
    /// PacketEvent 수신 채널 (ebpf-engine -> 파이프라인, daemon에서 연결)
    #[allow(dead_code)]
    packet_rx: Option<mpsc::Receiver<PacketEvent>>,
    /// 백그라운드 태스크 핸들
    tasks: Vec<tokio::task::JoinHandle<()>>,
    /// 파싱 에러 카운터 (공유)
    parse_error_count: Arc<AtomicU64>,
    /// 처리된 로그 카운터 (공유)
    processed_count: Arc<AtomicU64>,
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
    pub async fn processed_count(&self) -> u64 {
        self.processed_count.load(Ordering::Relaxed)
    }

    /// 파싱 에러 수를 반환합니다.
    pub async fn parse_error_count(&self) -> u64 {
        self.parse_error_count.load(Ordering::Relaxed)
    }

    /// 로드된 규칙 수를 반환합니다.
    pub async fn rule_count(&self) -> usize {
        self.rule_engine.lock().await.rule_count()
    }

    /// 버퍼 사용률을 반환합니다.
    pub async fn buffer_utilization(&self) -> f64 {
        self.buffer.lock().await.utilization()
    }

    /// 규칙 엔진에 대한 Arc 참조를 반환합니다.
    pub fn rule_engine_arc(&self) -> Arc<Mutex<RuleEngine>> {
        Arc::clone(&self.rule_engine)
    }

    /// 원시 로그 주입을 위한 Sender를 반환합니다.
    ///
    /// 수집기나 외부 로그 소스가 이 Sender를 사용하여 파이프라인에 로그를 전송할 수 있습니다.
    ///
    /// # 사용 예시
    /// ```ignore
    /// let sender = pipeline.raw_log_sender();
    /// sender.send(RawLog::new(data, "custom_source")).await?;
    /// ```
    pub fn raw_log_sender(&self) -> mpsc::Sender<RawLog> {
        self.raw_log_tx.clone()
    }

    /// 배치를 처리합니다: 파싱 -> 규칙 매칭 -> 알림 생성
    async fn process_batch(&self, batch: Vec<RawLog>) {
        for raw_log in batch {
            // 1. 파싱
            let log_entry = match self.parser.parse(&raw_log.data) {
                Ok(entry) => {
                    self.processed_count.fetch_add(1, Ordering::Relaxed);
                    entry
                }
                Err(e) => {
                    self.parse_error_count.fetch_add(1, Ordering::Relaxed);
                    tracing::debug!(
                        source = %raw_log.source,
                        error = %e,
                        "failed to parse log entry"
                    );
                    continue;
                }
            };

            // 2. 규칙 매칭
            match self.rule_engine.lock().await.evaluate(&log_entry) {
                Ok(matches) => {
                    // 3. 알림 생성
                    for rule_match in matches {
                        let mut alert_gen = self.alert_generator.lock().await;
                        if let Some(alert_event) = alert_gen.generate(&rule_match, None) {
                            drop(alert_gen); // unlock before send
                            // 4. 알림 전송
                            if let Err(e) = self.alert_tx.send(alert_event).await {
                                tracing::error!(error = %e, "failed to send alert event");
                            }
                        }
                    }
                }
                Err(e) => {
                    tracing::warn!(error = %e, "rule evaluation failed");
                }
            }
        }
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
            .lock()
            .await
            .load_rules_from_dir(&self.config.rule_dir)
            .await
            .map_err(IronpostError::from)?;
        tracing::info!(rules = rule_count, "loaded detection rules");

        // 2. 수집기 태스크 스폰
        // TODO: spawn collector tasks based on config.sources
        // Each collector gets a clone of raw_log_tx
        // This will be implemented when integrating with actual data sources

        // 3. 메인 처리 루프 스폰
        let mut raw_log_rx = self.raw_log_rx.take().ok_or(IronpostError::Pipeline(
            ironpost_core::error::PipelineError::AlreadyRunning,
        ))?;

        let batch_size = self.config.batch_size;
        let flush_interval_ms = self
            .config
            .flush_interval_secs
            .checked_mul(1000)
            .ok_or_else(|| {
                IronpostError::Pipeline(ironpost_core::error::PipelineError::InitFailed(
                    "flush_interval_secs too large (overflow)".to_owned(),
                ))
            })?;

        let parser = Arc::clone(&self.parser);
        let rule_engine = Arc::clone(&self.rule_engine);
        let alert_generator = Arc::clone(&self.alert_generator);
        let buffer = Arc::clone(&self.buffer);
        let alert_tx = self.alert_tx.clone();
        let parse_error_count = Arc::clone(&self.parse_error_count);
        let processed_count = Arc::clone(&self.processed_count);

        let processing_task = tokio::spawn(async move {
            let mut flush_timer = interval(Duration::from_millis(flush_interval_ms));
            flush_timer.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);

            let mut last_flush = Instant::now();
            let mut last_cleanup = Instant::now();
            const CLEANUP_INTERVAL: Duration = Duration::from_secs(60);

            loop {
                tokio::select! {
                    // RawLog 수신
                    result = raw_log_rx.recv() => {
                        match result {
                            Some(raw_log) => {
                                let mut buf = buffer.lock().await;
                                buf.push(raw_log);

                                // 배치 크기 도달 시 즉시 플러시
                                if buf.should_flush(batch_size) {
                                    let batch = buf.drain_batch(batch_size);
                                    drop(buf); // unlock buffer before processing

                                    tracing::debug!(batch_size = batch.len(), "flushing batch (size trigger)");

                                    // 공유 process_batch 로직 호출
                                    for raw_log in batch {
                                        match parser.parse(&raw_log.data) {
                                            Ok(log_entry) => {
                                                processed_count.fetch_add(1, Ordering::Relaxed);

                                                match rule_engine.lock().await.evaluate(&log_entry) {
                                                    Ok(matches) => {
                                                        for rule_match in matches {
                                                            let mut alert_gen = alert_generator.lock().await;
                                                            if let Some(alert_event) = alert_gen.generate(
                                                                &rule_match,
                                                                None,
                                                            ) {
                                                                drop(alert_gen);
                                                                if let Err(e) = alert_tx.send(alert_event).await {
                                                                    tracing::error!(error = %e, "failed to send alert event");
                                                                }
                                                            }
                                                        }
                                                    }
                                                    Err(e) => {
                                                        tracing::warn!(error = %e, "rule evaluation failed");
                                                    }
                                                }
                                            }
                                            Err(e) => {
                                                parse_error_count.fetch_add(1, Ordering::Relaxed);
                                                tracing::debug!(
                                                    source = %raw_log.source,
                                                    error = %e,
                                                    "failed to parse log entry"
                                                );
                                            }
                                        }
                                    }

                                    last_flush = Instant::now();
                                }
                            }
                            None => {
                                tracing::info!("raw_log channel closed, stopping processing loop");
                                break;
                            }
                        }
                    }

                    // 타이머 기반 플러시
                    _ = flush_timer.tick() => {
                        let mut buf = buffer.lock().await;
                        if !buf.is_empty() && last_flush.elapsed() >= Duration::from_millis(flush_interval_ms) {
                            let batch = buf.drain_all();
                            drop(buf);

                            tracing::debug!(batch_size = batch.len(), "flushing batch (timer trigger)");

                            // 공유 process_batch 로직 호출
                            for raw_log in batch {
                                match parser.parse(&raw_log.data) {
                                    Ok(log_entry) => {
                                        processed_count.fetch_add(1, Ordering::Relaxed);

                                        match rule_engine.lock().await.evaluate(&log_entry) {
                                            Ok(matches) => {
                                                for rule_match in matches {
                                                    let mut alert_gen = alert_generator.lock().await;
                                                    if let Some(alert_event) = alert_gen.generate(
                                                        &rule_match,
                                                        None,
                                                    ) {
                                                        drop(alert_gen);
                                                        if let Err(e) = alert_tx.send(alert_event).await {
                                                            tracing::error!(error = %e, "failed to send alert event");
                                                        }
                                                    }
                                                }
                                            }
                                            Err(e) => {
                                                tracing::warn!(error = %e, "rule evaluation failed");
                                            }
                                        }
                                    }
                                    Err(e) => {
                                        parse_error_count.fetch_add(1, Ordering::Relaxed);
                                        tracing::debug!(
                                            source = %raw_log.source,
                                            error = %e,
                                            "failed to parse log entry"
                                        );
                                    }
                                }
                            }

                            last_flush = Instant::now();
                        }

                        // 시간 기반 cleanup (매 60초)
                        if last_cleanup.elapsed() >= CLEANUP_INTERVAL {
                            alert_generator.lock().await.cleanup_expired();
                            // rule_engine도 cleanup 추가 가능 (향후 확장)
                            last_cleanup = Instant::now();
                        }
                    }
                }
            }
        });

        self.tasks.push(processing_task);

        self.state = PipelineState::Running;
        tracing::info!("log pipeline started");
        Ok(())
    }

    async fn stop(&mut self) -> Result<(), IronpostError> {
        if self.state != PipelineState::Running {
            return Err(ironpost_core::error::PipelineError::NotRunning.into());
        }

        tracing::info!("stopping log pipeline");

        // 1. 먼저 버퍼 드레인 (태스크가 아직 실행 중일 때)
        let remaining = self.buffer.lock().await.drain_all();

        // 2. 그 다음 태스크 중단 및 대기
        for task in self.tasks.drain(..) {
            task.abort();
            // JoinHandle이 abort된 후에도 안전하게 await 가능
            let _ = task.await;
        }

        // 3. 드레인된 로그 처리
        if !remaining.is_empty() {
            tracing::info!(
                count = remaining.len(),
                "processing remaining buffered logs"
            );
            self.process_batch(remaining).await;
        }

        // 4. 채널 재생성 (재시작 지원)
        let (tx, rx) = mpsc::channel(self.config.buffer_capacity);
        self.raw_log_tx = tx;
        self.raw_log_rx = Some(rx);

        self.state = PipelineState::Stopped;
        tracing::info!("log pipeline stopped");
        Ok(())
    }

    async fn health_check(&self) -> HealthStatus {
        match self.state {
            PipelineState::Running => {
                let utilization = self.buffer.lock().await.utilization();
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

/// Plugin trait 구현
///
/// LogPipeline을 플러그인 시스템에 통합하여
/// PluginRegistry를 통한 생명주기 관리를 지원합니다.
impl Plugin for LogPipeline {
    fn info(&self) -> &PluginInfo {
        &self.plugin_info
    }

    fn state(&self) -> PluginState {
        self.plugin_state
    }

    async fn init(&mut self) -> Result<(), IronpostError> {
        // 현재는 별도 초기화 로직 없음
        // 필요 시 규칙 검증, 설정 검증 등을 여기에 추가
        self.plugin_state = PluginState::Initialized;
        tracing::debug!(plugin = %self.plugin_info.name, "plugin initialized");
        Ok(())
    }

    async fn start(&mut self) -> Result<(), IronpostError> {
        let result = <Self as Pipeline>::start(self).await;
        if result.is_ok() {
            self.plugin_state = PluginState::Running;
        } else {
            self.plugin_state = PluginState::Failed;
        }
        result
    }

    async fn stop(&mut self) -> Result<(), IronpostError> {
        let result = <Self as Pipeline>::stop(self).await;
        if result.is_ok() {
            self.plugin_state = PluginState::Stopped;
        } else {
            self.plugin_state = PluginState::Failed;
        }
        result
    }

    async fn health_check(&self) -> HealthStatus {
        <Self as Pipeline>::health_check(self).await
    }
}

/// 로그 파이프라인 빌더
///
/// 파이프라인을 구성하고 필요한 채널을 생성합니다.
///
/// # Examples
///
/// ```no_run
/// # async fn example() -> Result<(), ironpost_log_pipeline::error::LogPipelineError> {
/// use ironpost_log_pipeline::{LogPipelineBuilder, PipelineConfig};
///
/// let config = PipelineConfig::default();
/// let (pipeline, alert_rx) = LogPipelineBuilder::new()
///     .config(config)
///     .build()?;
/// # Ok(())
/// # }
/// ```
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
    ///
    /// # Errors
    ///
    /// 설정 검증에 실패하면 에러를 반환합니다.
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

        let buffer = Arc::new(Mutex::new(LogBuffer::new(
            self.config.buffer_capacity,
            self.config.drop_policy.clone(),
        )));

        let alert_generator = Arc::new(Mutex::new(AlertGenerator::new(
            self.config.alert_dedup_window_secs,
            self.config.alert_rate_limit_per_rule,
        )));

        let plugin_info = PluginInfo {
            name: MODULE_LOG_PIPELINE.to_owned(),
            version: env!("CARGO_PKG_VERSION").to_owned(),
            description: "Log collection, parsing, and rule-based detection pipeline".to_owned(),
            plugin_type: PluginType::LogPipeline,
        };

        let pipeline = LogPipeline {
            plugin_info,
            plugin_state: PluginState::Created,
            config: self.config,
            state: PipelineState::Initialized,
            parser: Arc::new(ParserRouter::with_defaults()),
            rule_engine: Arc::new(Mutex::new(RuleEngine::new())),
            alert_generator,
            buffer,
            collectors: CollectorSet::default(),
            raw_log_rx: Some(raw_log_rx),
            raw_log_tx,
            alert_tx,
            packet_rx: self.packet_rx,
            tasks: Vec::new(),
            parse_error_count: Arc::new(AtomicU64::new(0)),
            processed_count: Arc::new(AtomicU64::new(0)),
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
        let config = PipelineConfig {
            batch_size: 0, // invalid
            ..Default::default()
        };
        let result: Result<(LogPipeline, _), _> = LogPipelineBuilder::new().config(config).build();
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn pipeline_lifecycle() {
        let (mut pipeline, _alert_rx) = LogPipelineBuilder::new().build().unwrap();

        // Before start
        assert!(Pipeline::health_check(&pipeline).await.is_unhealthy());

        // Double stop before start fails
        let err = Pipeline::stop(&mut pipeline).await;
        assert!(err.is_err());
    }

    #[tokio::test]
    async fn pipeline_accessors() {
        let (pipeline, _) = LogPipelineBuilder::new().build().unwrap();
        assert_eq!(pipeline.processed_count().await, 0);
        assert_eq!(pipeline.parse_error_count().await, 0);
        assert_eq!(pipeline.rule_count().await, 0);
        assert_eq!(pipeline.buffer_utilization().await, 0.0);
    }

    #[tokio::test]
    async fn raw_log_sender_is_accessible() {
        use crate::collector::RawLog;
        use bytes::Bytes;

        let (pipeline, _alert_rx) = LogPipelineBuilder::new().build().unwrap();
        let sender = pipeline.raw_log_sender();

        // Verify we can send logs through the sender
        let raw_log = RawLog::new(Bytes::from_static(b"test log"), "test_source");
        let result = sender.send(raw_log).await;
        assert!(result.is_ok());
    }

    #[tokio::test]
    async fn pipeline_can_restart_after_stop() {
        // Create a temporary directory for rules
        let temp_dir = std::env::temp_dir().join("ironpost_test_restart");
        std::fs::create_dir_all(&temp_dir).ok();

        let config = PipelineConfig {
            rule_dir: temp_dir.to_string_lossy().to_string(),
            ..Default::default()
        };

        let (mut pipeline, _alert_rx) = LogPipelineBuilder::new().config(config).build().unwrap();

        // Start the pipeline
        Pipeline::start(&mut pipeline).await.unwrap();
        assert_eq!(pipeline.state_name(), "running");

        // Stop the pipeline
        Pipeline::stop(&mut pipeline).await.unwrap();
        assert_eq!(pipeline.state_name(), "stopped");

        // Restart the pipeline
        let result = Pipeline::start(&mut pipeline).await;
        assert!(result.is_ok(), "pipeline should be restartable after stop");
        assert_eq!(pipeline.state_name(), "running");

        // Clean up
        Pipeline::stop(&mut pipeline).await.unwrap();
    }
}

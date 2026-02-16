//! 파이프라인 오케스트레이션 -- 수집/파싱/매칭/알림의 전체 흐름을 관리합니다.
//!
//! [`LogPipeline`]은 core의 [`Pipeline`] trait을 구현하여
//! `ironpost-daemon`에서 다른 모듈과 동일한 생명주기로 관리됩니다.
//!
//! # 내부 아키텍처
//! ```text
//! Collectors -> mpsc -> Buffer -> Parser -> RuleEngine -> AlertGenerator -> mpsc -> downstream
//! ```

use std::collections::{HashMap, HashSet};
use std::path::PathBuf;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;

use tokio::sync::{Mutex, RwLock, mpsc};
use tokio::time::{Instant, interval};
use tokio_util::sync::CancellationToken;

use ironpost_core::error::IronpostError;
use ironpost_core::event::{AlertEvent, MODULE_LOG_PIPELINE, PacketEvent};
use ironpost_core::metrics as m;
use ironpost_core::pipeline::{HealthStatus, Pipeline};
use ironpost_core::plugin::{Plugin, PluginInfo, PluginState, PluginType};

use crate::alert::AlertGenerator;
use crate::buffer::LogBuffer;
use crate::collector::file::FileCollectorConfig;
use crate::collector::syslog_tcp::SyslogTcpConfig;
use crate::collector::syslog_udp::SyslogUdpConfig;
use crate::collector::{
    CollectorSet, CollectorStatus, EventReceiver, FileCollector, RawLog, SyslogTcpCollector,
    SyslogUdpCollector,
};
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
    collectors: CollectorSet,
    /// 수집기 런타임 상태 (health/observability 용도)
    collector_statuses: Arc<RwLock<HashMap<String, CollectorStatus>>>,
    /// 내부 RawLog 채널 (수집기 -> 파이프라인)
    raw_log_rx: Option<mpsc::Receiver<RawLog>>,
    /// 내부 RawLog 채널 송신측 (수집기에 전달)
    raw_log_tx: mpsc::Sender<RawLog>,
    /// 알림 전송 채널 (파이프라인 -> downstream)
    alert_tx: mpsc::Sender<AlertEvent>,
    /// PacketEvent 수신 채널 (ebpf-engine -> 파이프라인, daemon에서 연결)
    packet_rx: Option<mpsc::Receiver<PacketEvent>>,
    /// 백그라운드 태스크 핸들
    tasks: Vec<tokio::task::JoinHandle<()>>,
    /// EventReceiver task handle (returns packet_rx on shutdown)
    event_receiver_task: Option<tokio::task::JoinHandle<Option<mpsc::Receiver<PacketEvent>>>>,
    /// Cancellation token for graceful shutdown
    cancel_token: CancellationToken,
    /// 파싱 에러 카운터 (공유)
    parse_error_count: Arc<AtomicU64>,
    /// 처리된 로그 카운터 (공유)
    processed_count: Arc<AtomicU64>,
}

impl LogPipeline {
    async fn set_collector_status(
        statuses: &Arc<RwLock<HashMap<String, CollectorStatus>>>,
        name: &str,
        status: CollectorStatus,
    ) {
        statuses.write().await.insert(name.to_owned(), status);
    }

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

    /// UDP syslog 수집기를 spawn합니다.
    fn spawn_syslog_udp(&mut self) {
        let tx = self.raw_log_tx.clone();
        let cancel = self.cancel_token.clone();
        let statuses = Arc::clone(&self.collector_statuses);
        let config = SyslogUdpConfig {
            bind_addr: self.config.syslog_bind.clone(),
            ..SyslogUdpConfig::default()
        };

        let handle = tokio::spawn(async move {
            Self::set_collector_status(&statuses, "syslog_udp", CollectorStatus::Running).await;
            let mut collector = SyslogUdpCollector::new_with_cancel(config, tx, cancel);
            if let Err(e) = collector.run().await {
                tracing::error!(
                    collector = "syslog_udp",
                    error = %e,
                    "syslog UDP collector terminated with error"
                );
                Self::set_collector_status(
                    &statuses,
                    "syslog_udp",
                    CollectorStatus::Error(e.to_string()),
                )
                .await;
            } else {
                Self::set_collector_status(&statuses, "syslog_udp", CollectorStatus::Stopped).await;
            }
        });
        self.collectors.register("syslog_udp");
        self.tasks.push(handle);
    }

    /// TCP syslog 수집기를 spawn합니다.
    fn spawn_syslog_tcp(&mut self) {
        let tx = self.raw_log_tx.clone();
        let statuses = Arc::clone(&self.collector_statuses);
        let config = SyslogTcpConfig {
            bind_addr: self.config.syslog_tcp_bind.clone(),
            ..SyslogTcpConfig::default()
        };
        let cancel = self.cancel_token.clone();

        let handle = tokio::spawn(async move {
            Self::set_collector_status(&statuses, "syslog_tcp", CollectorStatus::Running).await;
            let mut collector = SyslogTcpCollector::new(config, tx, cancel);
            if let Err(e) = collector.run().await {
                tracing::error!(
                    collector = "syslog_tcp",
                    error = %e,
                    "syslog TCP collector terminated with error"
                );
                Self::set_collector_status(
                    &statuses,
                    "syslog_tcp",
                    CollectorStatus::Error(e.to_string()),
                )
                .await;
            } else {
                Self::set_collector_status(&statuses, "syslog_tcp", CollectorStatus::Stopped).await;
            }
        });
        self.collectors.register("syslog_tcp");
        self.tasks.push(handle);
    }

    /// 파일 수집기를 spawn합니다.
    fn spawn_file_collector(&mut self) {
        let tx = self.raw_log_tx.clone();
        let cancel = self.cancel_token.clone();
        let statuses = Arc::clone(&self.collector_statuses);
        let config = FileCollectorConfig {
            watch_paths: self.config.watch_paths.iter().map(PathBuf::from).collect(),
            ..FileCollectorConfig::default()
        };

        let handle = tokio::spawn(async move {
            Self::set_collector_status(&statuses, "file", CollectorStatus::Running).await;
            let mut collector = FileCollector::new_with_cancel(config, tx, cancel);
            if let Err(e) = collector.run().await {
                tracing::error!(
                    collector = "file",
                    error = %e,
                    "file collector terminated with error"
                );
                Self::set_collector_status(
                    &statuses,
                    "file",
                    CollectorStatus::Error(e.to_string()),
                )
                .await;
            } else {
                Self::set_collector_status(&statuses, "file", CollectorStatus::Stopped).await;
            }
        });
        self.collectors.register("file");
        self.tasks.push(handle);
    }

    /// eBPF EventReceiver를 spawn합니다.
    ///
    /// EventReceiver는 graceful shutdown 시 packet_rx를 반환하여
    /// 재시작을 지원합니다.
    fn spawn_event_receiver(&mut self, packet_rx: mpsc::Receiver<PacketEvent>) {
        let tx = self.raw_log_tx.clone();
        let cancel = self.cancel_token.clone();
        let statuses = Arc::clone(&self.collector_statuses);

        let handle = tokio::spawn(async move {
            Self::set_collector_status(&statuses, "event_receiver", CollectorStatus::Running).await;
            let receiver = EventReceiver::new(packet_rx, tx);
            match receiver.run(cancel).await {
                Ok(returned_rx) => {
                    tracing::info!("event receiver stopped gracefully");
                    Self::set_collector_status(
                        &statuses,
                        "event_receiver",
                        CollectorStatus::Stopped,
                    )
                    .await;
                    Some(returned_rx)
                }
                Err(e) => {
                    tracing::error!(
                        collector = "event_receiver",
                        error = %e,
                        "event receiver terminated with error"
                    );
                    Self::set_collector_status(
                        &statuses,
                        "event_receiver",
                        CollectorStatus::Error(e.to_string()),
                    )
                    .await;
                    None
                }
            }
        });
        self.collectors.register("event_receiver");
        self.event_receiver_task = Some(handle);
    }
}

impl Pipeline for LogPipeline {
    async fn start(&mut self) -> Result<(), IronpostError> {
        if self.state == PipelineState::Running {
            return Err(ironpost_core::error::PipelineError::AlreadyRunning.into());
        }

        tracing::info!("starting log pipeline");

        self.collector_statuses.write().await.clear();

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
        let mut spawned_collectors = HashSet::new();
        let sources = self.config.sources.clone();

        for source in &sources {
            match source.as_str() {
                "syslog" => {
                    // syslog = syslog_udp + syslog_tcp 동시 활성화
                    if spawned_collectors.insert("syslog_udp") {
                        self.spawn_syslog_udp();
                    }
                    if spawned_collectors.insert("syslog_tcp") {
                        self.spawn_syslog_tcp();
                    }
                }
                "syslog_udp" => {
                    if spawned_collectors.insert("syslog_udp") {
                        self.spawn_syslog_udp();
                    }
                }
                "syslog_tcp" => {
                    if spawned_collectors.insert("syslog_tcp") {
                        self.spawn_syslog_tcp();
                    }
                }
                "file" => {
                    if spawned_collectors.insert("file") {
                        self.spawn_file_collector();
                    }
                }
                unknown => {
                    tracing::warn!(source = unknown, "unknown collector source, skipping");
                }
            }
        }

        // EventReceiver spawn (packet_rx가 있을 때만)
        if let Some(packet_rx) = self.packet_rx.take() {
            self.spawn_event_receiver(packet_rx);
            spawned_collectors.insert("event_receiver");
        }

        tracing::info!(
            collectors = ?spawned_collectors,
            count = spawned_collectors.len(),
            "spawned collector tasks"
        );

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
        let cancel = self.cancel_token.clone();

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
                                if buf.push(raw_log) {
                                    metrics::counter!(m::LOG_PIPELINE_LOGS_DROPPED_TOTAL).increment(1);
                                }

                                // 배치 크기 도달 시 즉시 플러시
                                if buf.should_flush(batch_size) {
                                    let batch = buf.drain_batch(batch_size);
                                    let buffer_size_snapshot = buf.len();
                                    drop(buf); // unlock buffer before processing

                                    tracing::debug!(batch_size = batch.len(), "flushing batch (size trigger)");

                                    let start_time = Instant::now();

                                    // 공유 process_batch 로직 호출
                                    for raw_log in batch {
                                        metrics::counter!(m::LOG_PIPELINE_LOGS_COLLECTED_TOTAL).increment(1);

                                        match parser.parse(&raw_log.data) {
                                            Ok(log_entry) => {
                                                processed_count.fetch_add(1, Ordering::Relaxed);
                                                metrics::counter!(m::LOG_PIPELINE_LOGS_PROCESSED_TOTAL).increment(1);

                                                match rule_engine.lock().await.evaluate(&log_entry) {
                                                    Ok(matches) => {
                                                        if !matches.is_empty() {
                                                            metrics::counter!(m::LOG_PIPELINE_RULE_MATCHES_TOTAL).increment(matches.len() as u64);
                                                        }
                                                        for rule_match in matches {
                                                            let mut alert_gen = alert_generator.lock().await;
                                                            if let Some(alert_event) = alert_gen.generate(
                                                                &rule_match,
                                                                None,
                                                            ) {
                                                                drop(alert_gen);
                                                                match alert_tx.send(alert_event).await {
                                                                    Ok(()) => {
                                                                        metrics::counter!(m::LOG_PIPELINE_ALERTS_SENT_TOTAL).increment(1);
                                                                    }
                                                                    Err(e) => {
                                                                        tracing::error!(error = %e, "failed to send alert event");
                                                                    }
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
                                                metrics::counter!(m::LOG_PIPELINE_PARSE_ERRORS_TOTAL).increment(1);
                                                tracing::debug!(
                                                    source = %raw_log.source,
                                                    error = %e,
                                                    "failed to parse log entry"
                                                );
                                            }
                                        }
                                    }

                                    let elapsed = start_time.elapsed().as_secs_f64();
                                    metrics::histogram!(m::LOG_PIPELINE_PROCESSING_DURATION_SECONDS).record(elapsed);

                                    #[allow(clippy::cast_precision_loss)]
                                    metrics::gauge!(m::LOG_PIPELINE_BUFFER_SIZE).set(buffer_size_snapshot as f64);

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
                            let buffer_size_snapshot = buf.len();
                            drop(buf);

                            tracing::debug!(batch_size = batch.len(), "flushing batch (timer trigger)");

                            let start_time = Instant::now();

                            // 공유 process_batch 로직 호출
                            for raw_log in batch {
                                metrics::counter!(m::LOG_PIPELINE_LOGS_COLLECTED_TOTAL).increment(1);

                                match parser.parse(&raw_log.data) {
                                    Ok(log_entry) => {
                                        processed_count.fetch_add(1, Ordering::Relaxed);
                                        metrics::counter!(m::LOG_PIPELINE_LOGS_PROCESSED_TOTAL).increment(1);

                                        match rule_engine.lock().await.evaluate(&log_entry) {
                                            Ok(matches) => {
                                                if !matches.is_empty() {
                                                    metrics::counter!(m::LOG_PIPELINE_RULE_MATCHES_TOTAL).increment(matches.len() as u64);
                                                }
                                                for rule_match in matches {
                                                    let mut alert_gen = alert_generator.lock().await;
                                                    if let Some(alert_event) = alert_gen.generate(
                                                        &rule_match,
                                                        None,
                                                    ) {
                                                        drop(alert_gen);
                                                        match alert_tx.send(alert_event).await {
                                                            Ok(()) => {
                                                                metrics::counter!(m::LOG_PIPELINE_ALERTS_SENT_TOTAL).increment(1);
                                                            }
                                                            Err(e) => {
                                                                tracing::error!(error = %e, "failed to send alert event");
                                                            }
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
                                        metrics::counter!(m::LOG_PIPELINE_PARSE_ERRORS_TOTAL).increment(1);
                                        tracing::debug!(
                                            source = %raw_log.source,
                                            error = %e,
                                            "failed to parse log entry"
                                        );
                                    }
                                }
                            }

                            let elapsed = start_time.elapsed().as_secs_f64();
                            metrics::histogram!(m::LOG_PIPELINE_PROCESSING_DURATION_SECONDS).record(elapsed);

                            #[allow(clippy::cast_precision_loss)]
                            metrics::gauge!(m::LOG_PIPELINE_BUFFER_SIZE).set(buffer_size_snapshot as f64);

                            last_flush = Instant::now();
                        }

                        // 시간 기반 cleanup (매 60초)
                        if last_cleanup.elapsed() >= CLEANUP_INTERVAL {
                            alert_generator.lock().await.cleanup_expired();
                            // rule_engine도 cleanup 추가 가능 (향후 확장)
                            last_cleanup = Instant::now();
                        }
                    }

                    // Cancellation signal
                    _ = cancel.cancelled() => {
                        tracing::info!("processing task received shutdown signal");
                        break;
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

        // 2. Graceful shutdown signal 전송
        self.cancel_token.cancel();
        tracing::debug!("sent cancellation signal to all collectors");

        // 3. Give collectors a moment to shutdown gracefully
        tokio::time::sleep(Duration::from_millis(100)).await;

        // 4. EventReceiver task 처리 (packet_rx 복원)
        if let Some(task) = self.event_receiver_task.take() {
            // Use timeout to avoid hanging if task doesn't respond to cancellation
            match tokio::time::timeout(Duration::from_secs(2), task).await {
                Ok(Ok(Some(packet_rx))) => {
                    tracing::info!("restoring packet_rx for restart support");
                    self.packet_rx = Some(packet_rx);
                }
                Ok(Ok(None)) => {
                    tracing::warn!("event_receiver task returned None, packet_rx not restored");
                }
                Ok(Err(e)) => {
                    tracing::warn!(error = %e, "event_receiver task join failed");
                }
                Err(_) => {
                    tracing::warn!(
                        "event_receiver task did not respond to cancellation within timeout"
                    );
                }
            }
        }

        // 5. 나머지 collector tasks 정리
        for task in self.tasks.drain(..) {
            let _ = task.await;
        }

        // 6. 수집기 상태 정리
        self.collectors.stop_all();
        self.collectors.clear();
        self.collector_statuses.write().await.clear();

        // 7. 드레인된 로그 처리
        if !remaining.is_empty() {
            tracing::info!(
                count = remaining.len(),
                "processing remaining buffered logs"
            );
            self.process_batch(remaining).await;
        }

        // 8. 채널 재생성 (재시작 지원)
        let (tx, rx) = mpsc::channel(self.config.buffer_capacity);
        self.raw_log_tx = tx;
        self.raw_log_rx = Some(rx);

        // 9. Reset cancellation token for next start
        self.cancel_token = CancellationToken::new();

        self.state = PipelineState::Stopped;
        tracing::info!("log pipeline stopped");
        Ok(())
    }

    async fn health_check(&self) -> HealthStatus {
        match self.state {
            PipelineState::Running => {
                let collector_statuses = self.collector_statuses.read().await;
                let collector_errors: Vec<String> = collector_statuses
                    .iter()
                    .filter_map(|(name, status)| match status {
                        CollectorStatus::Error(reason) => Some(format!("{name}: {reason}")),
                        _ => None,
                    })
                    .collect();

                if !collector_errors.is_empty() {
                    return HealthStatus::Unhealthy(format!(
                        "collector errors: {}",
                        collector_errors.join(", ")
                    ));
                }

                let stopped_collectors: Vec<String> = collector_statuses
                    .iter()
                    .filter_map(|(name, status)| match status {
                        CollectorStatus::Stopped => Some(name.clone()),
                        _ => None,
                    })
                    .collect();

                if !stopped_collectors.is_empty() {
                    return HealthStatus::Degraded(format!(
                        "collectors stopped unexpectedly: {}",
                        stopped_collectors.join(", ")
                    ));
                }

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
            collector_statuses: Arc::new(RwLock::new(HashMap::new())),
            raw_log_rx: Some(raw_log_rx),
            raw_log_tx,
            alert_tx,
            packet_rx: self.packet_rx,
            tasks: Vec::new(),
            event_receiver_task: None,
            cancel_token: CancellationToken::new(),
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

    #[tokio::test]
    async fn collector_spawns_syslog_udp_from_syslog_source() {
        let temp_dir = std::env::temp_dir().join("ironpost_test_syslog_udp");
        std::fs::create_dir_all(&temp_dir).ok();

        let config = PipelineConfig {
            rule_dir: temp_dir.to_string_lossy().to_string(),
            sources: vec!["syslog".to_owned()],
            syslog_bind: "127.0.0.1:0".to_owned(), // auto port
            syslog_tcp_bind: "127.0.0.1:0".to_owned(),
            ..Default::default()
        };

        let (mut pipeline, _) = LogPipelineBuilder::new().config(config).build().unwrap();
        Pipeline::start(&mut pipeline).await.unwrap();

        // "syslog" should spawn both UDP and TCP collectors
        assert_eq!(pipeline.collectors.len(), 2);
        let statuses = pipeline.collectors.statuses();
        assert!(statuses.iter().any(|(name, _)| name == "syslog_udp"));
        assert!(statuses.iter().any(|(name, _)| name == "syslog_tcp"));

        Pipeline::stop(&mut pipeline).await.unwrap();
    }

    #[tokio::test]
    async fn collector_spawns_syslog_udp_only() {
        let temp_dir = std::env::temp_dir().join("ironpost_test_syslog_udp_only");
        std::fs::create_dir_all(&temp_dir).ok();

        let config = PipelineConfig {
            rule_dir: temp_dir.to_string_lossy().to_string(),
            sources: vec!["syslog_udp".to_owned()],
            syslog_bind: "127.0.0.1:0".to_owned(),
            ..Default::default()
        };

        let (mut pipeline, _) = LogPipelineBuilder::new().config(config).build().unwrap();
        Pipeline::start(&mut pipeline).await.unwrap();

        assert_eq!(pipeline.collectors.len(), 1);
        let statuses = pipeline.collectors.statuses();
        assert_eq!(statuses[0].0, "syslog_udp");

        Pipeline::stop(&mut pipeline).await.unwrap();
    }

    #[tokio::test]
    async fn collector_spawns_file_collector() {
        let temp_dir = std::env::temp_dir().join("ironpost_test_file");
        std::fs::create_dir_all(&temp_dir).ok();

        let config = PipelineConfig {
            rule_dir: temp_dir.to_string_lossy().to_string(),
            sources: vec!["file".to_owned()],
            watch_paths: vec![temp_dir.join("test.log").to_string_lossy().to_string()],
            ..Default::default()
        };

        let (mut pipeline, _) = LogPipelineBuilder::new().config(config).build().unwrap();
        Pipeline::start(&mut pipeline).await.unwrap();

        assert_eq!(pipeline.collectors.len(), 1);
        let statuses = pipeline.collectors.statuses();
        assert_eq!(statuses[0].0, "file");

        Pipeline::stop(&mut pipeline).await.unwrap();
    }

    #[tokio::test]
    async fn empty_sources_spawns_no_collectors() {
        let temp_dir = std::env::temp_dir().join("ironpost_test_empty");
        std::fs::create_dir_all(&temp_dir).ok();

        let config = PipelineConfig {
            rule_dir: temp_dir.to_string_lossy().to_string(),
            sources: vec![],
            enabled: false, // sources empty requires enabled: false
            ..Default::default()
        };

        let (mut pipeline, _) = LogPipelineBuilder::new().config(config).build().unwrap();
        Pipeline::start(&mut pipeline).await.unwrap();

        assert_eq!(pipeline.collectors.len(), 0);

        Pipeline::stop(&mut pipeline).await.unwrap();
    }

    #[tokio::test]
    async fn unknown_source_skipped_with_warning() {
        let temp_dir = std::env::temp_dir().join("ironpost_test_unknown");
        std::fs::create_dir_all(&temp_dir).ok();

        let config = PipelineConfig {
            rule_dir: temp_dir.to_string_lossy().to_string(),
            sources: vec!["unknown_source".to_owned(), "syslog_udp".to_owned()],
            syslog_bind: "127.0.0.1:0".to_owned(),
            ..Default::default()
        };

        let (mut pipeline, _) = LogPipelineBuilder::new().config(config).build().unwrap();
        // Should not fail even with unknown source
        Pipeline::start(&mut pipeline).await.unwrap();

        // Only syslog_udp should be registered
        assert_eq!(pipeline.collectors.len(), 1);
        let statuses = pipeline.collectors.statuses();
        assert_eq!(statuses[0].0, "syslog_udp");

        Pipeline::stop(&mut pipeline).await.unwrap();
    }

    #[tokio::test]
    async fn duplicate_collectors_prevented() {
        let temp_dir = std::env::temp_dir().join("ironpost_test_dedup");
        std::fs::create_dir_all(&temp_dir).ok();

        let config = PipelineConfig {
            rule_dir: temp_dir.to_string_lossy().to_string(),
            sources: vec![
                "syslog".to_owned(),     // expands to syslog_udp + syslog_tcp
                "syslog_udp".to_owned(), // duplicate UDP
                "syslog_tcp".to_owned(), // duplicate TCP
            ],
            syslog_bind: "127.0.0.1:0".to_owned(),
            syslog_tcp_bind: "127.0.0.1:0".to_owned(),
            ..Default::default()
        };

        let (mut pipeline, _) = LogPipelineBuilder::new().config(config).build().unwrap();
        Pipeline::start(&mut pipeline).await.unwrap();

        // Should only have 2 collectors (UDP and TCP), not 4
        assert_eq!(pipeline.collectors.len(), 2);
        let statuses = pipeline.collectors.statuses();
        assert!(statuses.iter().any(|(name, _)| name == "syslog_udp"));
        assert!(statuses.iter().any(|(name, _)| name == "syslog_tcp"));

        Pipeline::stop(&mut pipeline).await.unwrap();
    }

    #[tokio::test]
    async fn collector_spawn_failure_does_not_prevent_pipeline_start() {
        let temp_dir = std::env::temp_dir().join("ironpost_test_spawn_fail");
        std::fs::create_dir_all(&temp_dir).ok();

        // 파싱 불가능한 주소로 의도적으로 bind 실패를 유도
        let config = PipelineConfig {
            rule_dir: temp_dir.to_string_lossy().to_string(),
            sources: vec!["syslog_udp".to_owned()],
            syslog_bind: "invalid-bind-address".to_owned(),
            ..Default::default()
        };

        let (mut pipeline, _) = LogPipelineBuilder::new().config(config).build().unwrap();

        // Pipeline start should succeed even if individual collectors fail
        let result = Pipeline::start(&mut pipeline).await;
        assert!(
            result.is_ok(),
            "pipeline should start even if collectors fail to bind"
        );
        assert_eq!(pipeline.state_name(), "running");

        // collector runtime 에러가 health에 반영되는지 확인
        tokio::time::sleep(Duration::from_millis(50)).await;
        let health = Pipeline::health_check(&pipeline).await;
        assert!(
            matches!(health, HealthStatus::Unhealthy(_)),
            "collector bind failure should be visible in health status"
        );

        Pipeline::stop(&mut pipeline).await.unwrap();
    }

    #[tokio::test]
    async fn event_receiver_spawned_when_packet_rx_present() {
        let temp_dir = std::env::temp_dir().join("ironpost_test_event_rx");
        std::fs::create_dir_all(&temp_dir).ok();

        let (packet_tx, packet_rx) = mpsc::channel(10);

        let config = PipelineConfig {
            rule_dir: temp_dir.to_string_lossy().to_string(),
            sources: vec![],
            enabled: false, // sources empty
            ..Default::default()
        };

        let (mut pipeline, _) = LogPipelineBuilder::new()
            .config(config)
            .packet_receiver(packet_rx)
            .build()
            .unwrap();

        Pipeline::start(&mut pipeline).await.unwrap();

        // event_receiver should be registered
        let has_event_receiver = pipeline
            .collectors
            .statuses()
            .iter()
            .any(|(name, _)| name == "event_receiver");
        assert!(has_event_receiver);

        drop(packet_tx);
        Pipeline::stop(&mut pipeline).await.unwrap();
    }

    #[tokio::test]
    async fn multiple_collectors_spawn_simultaneously() {
        let temp_dir = std::env::temp_dir().join("ironpost_test_multi");
        std::fs::create_dir_all(&temp_dir).ok();

        let config = PipelineConfig {
            rule_dir: temp_dir.to_string_lossy().to_string(),
            sources: vec![
                "syslog_udp".to_owned(),
                "syslog_tcp".to_owned(),
                "file".to_owned(),
            ],
            syslog_bind: "127.0.0.1:0".to_owned(),
            syslog_tcp_bind: "127.0.0.1:0".to_owned(),
            watch_paths: vec![temp_dir.join("test.log").to_string_lossy().to_string()],
            ..Default::default()
        };

        let (mut pipeline, _) = LogPipelineBuilder::new().config(config).build().unwrap();
        Pipeline::start(&mut pipeline).await.unwrap();

        assert_eq!(pipeline.collectors.len(), 3);
        let statuses = pipeline.collectors.statuses();
        assert!(statuses.iter().any(|(name, _)| name == "syslog_udp"));
        assert!(statuses.iter().any(|(name, _)| name == "syslog_tcp"));
        assert!(statuses.iter().any(|(name, _)| name == "file"));

        Pipeline::stop(&mut pipeline).await.unwrap();
    }

    /// H1 회귀 테스트: packet_rx가 재시작 후에도 정상 동작하는지 확인
    #[tokio::test]
    async fn packet_rx_survives_restart() {
        let temp_dir = std::env::temp_dir().join("ironpost_test_packet_rx_restart");
        std::fs::create_dir_all(&temp_dir).ok();

        // packet_rx를 포함한 파이프라인 생성
        let (packet_tx, packet_rx) = mpsc::channel(10);
        let config = PipelineConfig {
            rule_dir: temp_dir.to_string_lossy().to_string(),
            sources: vec![], // no other collectors
            enabled: false,
            ..Default::default()
        };

        let (mut pipeline, _alert_rx) = LogPipelineBuilder::new()
            .config(config)
            .packet_receiver(packet_rx)
            .build()
            .unwrap();

        // 첫 번째 start
        Pipeline::start(&mut pipeline).await.unwrap();
        assert!(
            pipeline
                .collectors
                .statuses()
                .iter()
                .any(|(name, _)| name == "event_receiver"),
            "event_receiver should be spawned on first start"
        );

        // Stop
        Pipeline::stop(&mut pipeline).await.unwrap();

        // 두 번째 start (재시작) - 이전에는 packet_rx가 None이어서 실패했음
        let result = Pipeline::start(&mut pipeline).await;
        assert!(
            result.is_ok(),
            "pipeline should restart successfully (H1 fix)"
        );
        assert!(
            pipeline
                .collectors
                .statuses()
                .iter()
                .any(|(name, _)| name == "event_receiver"),
            "event_receiver should be re-spawned on restart (H1 fix)"
        );

        // Clean up
        drop(packet_tx);
        Pipeline::stop(&mut pipeline).await.unwrap();
    }

    /// H2 회귀 테스트: TCP collector의 connection handler가 stop() 시 정리되는지 확인
    #[tokio::test]
    async fn tcp_connection_handlers_cleanup_on_stop() {
        let temp_dir = std::env::temp_dir().join("ironpost_test_tcp_cleanup");
        std::fs::create_dir_all(&temp_dir).ok();

        let config = PipelineConfig {
            rule_dir: temp_dir.to_string_lossy().to_string(),
            sources: vec!["syslog_tcp".to_owned()],
            syslog_tcp_bind: "127.0.0.1:0".to_owned(),
            ..Default::default()
        };

        let (mut pipeline, _alert_rx) = LogPipelineBuilder::new().config(config).build().unwrap();

        // Start pipeline
        Pipeline::start(&mut pipeline).await.unwrap();

        // 실제 바인드된 주소를 얻기 위해 잠시 대기
        tokio::time::sleep(Duration::from_millis(100)).await;

        // Stop pipeline (H2 fix: connection handlers should be cleaned up)
        let stop_result =
            tokio::time::timeout(Duration::from_secs(2), Pipeline::stop(&mut pipeline)).await;
        assert!(
            stop_result.is_ok() && stop_result.unwrap().is_ok(),
            "stop should succeed even with active connections"
        );

        // restart 가능 여부도 함께 확인 (socket/task 누수 방지)
        Pipeline::start(&mut pipeline).await.unwrap();
        Pipeline::stop(&mut pipeline).await.unwrap();
        assert_eq!(pipeline.state_name(), "stopped");
    }
}

//! eBPF 엔진 — XDP 프로그램 로드/관리 및 이벤트 처리
//!
//! [`EbpfEngine`]은 eBPF XDP 프로그램의 전체 라이프사이클을 관리합니다.
//! 빌더 패턴([`EbpfEngineBuilder`])으로 생성하며, [`Pipeline`] trait을 구현합니다.
//!
//! # 아키텍처
//! ```text
//! ┌──────────────┐     ┌─────────────┐     ┌──────────────┐
//! │  XDP Program │────▶│ RingBuf     │────▶│ EbpfEngine   │
//! │  (kernel)    │     │ (events)    │     │ (userspace)  │
//! └──────────────┘     └─────────────┘     └──────┬───────┘
//!                                                  │
//!                              ┌───────────────────┼──────────────┐
//!                              ▼                   ▼              ▼
//!                       PacketDetector      TrafficStats    mpsc::Sender
//!                       (anomaly detect)    (poll stats)    (→ log-pipeline)
//! ```
//!
//! # 사용 예시
//! ```ignore
//! let (mut engine, event_rx) = EbpfEngine::builder()
//!     .config(engine_config)
//!     .channel_capacity(1024)
//!     .build()?;
//!
//! engine.start().await?;
//! // event_rx에서 PacketEvent를 수신하여 다른 모듈로 전달
//! ```

use tokio::sync::mpsc;
use tracing::info;

use ironpost_core::error::{DetectionError, IronpostError, PipelineError};
use ironpost_core::event::PacketEvent;
use ironpost_core::pipeline::{HealthStatus, Pipeline};

use crate::config::{EngineConfig, FilterRule};
use crate::detector::PacketDetector;
use crate::stats::TrafficStats;

/// eBPF 엔진 — XDP 프로그램 로드/관리 및 이벤트 처리
///
/// # 필드
/// - `config`: 엔진 설정 + 필터링 룰
/// - `event_tx`: PacketEvent를 다른 모듈로 전송하는 채널
/// - `running`: 현재 실행 상태
/// - `stats`: 프로토콜별 트래픽 통계
/// - `detector`: 패킷 기반 위협 탐지기
///
/// # Linux 전용
/// `aya::Ebpf` 핸들은 Linux에서만 사용 가능합니다.
/// macOS/Windows에서는 start() 시 에러를 반환합니다.
pub struct EbpfEngine {
    config: EngineConfig,
    event_tx: mpsc::Sender<PacketEvent>,
    running: bool,
    stats: TrafficStats,
    detector: PacketDetector,
    /// 로드된 eBPF 프로그램 핸들 (Linux 전용)
    #[cfg(target_os = "linux")]
    bpf: Option<aya::Ebpf>,
}

/// eBPF 엔진 빌더
///
/// 3개 이상의 설정 필드를 가지므로 빌더 패턴을 사용합니다.
/// `build()`는 `(EbpfEngine, mpsc::Receiver<PacketEvent>)` 튜플을 반환하여
/// 이벤트 수신자를 호출자에게 전달합니다.
pub struct EbpfEngineBuilder {
    config: Option<EngineConfig>,
    event_tx: Option<mpsc::Sender<PacketEvent>>,
    channel_capacity: usize,
    detector: Option<PacketDetector>,
}

impl EbpfEngineBuilder {
    /// 새 빌더를 생성합니다.
    fn new() -> Self {
        Self {
            config: None,
            event_tx: None,
            channel_capacity: 1024,
            detector: None,
        }
    }

    /// 엔진 설정을 지정합니다.
    pub fn config(mut self, config: EngineConfig) -> Self {
        self.config = Some(config);
        self
    }

    /// 외부 이벤트 채널의 송신자를 지정합니다.
    ///
    /// 지정하지 않으면 `build()` 시 내부적으로 생성합니다.
    pub fn event_sender(mut self, tx: mpsc::Sender<PacketEvent>) -> Self {
        self.event_tx = Some(tx);
        self
    }

    /// 내부 이벤트 채널 용량을 지정합니다 (기본: 1024).
    pub fn channel_capacity(mut self, cap: usize) -> Self {
        self.channel_capacity = cap;
        self
    }

    /// 패킷 탐지기를 지정합니다.
    pub fn detector(mut self, detector: PacketDetector) -> Self {
        self.detector = Some(detector);
        self
    }

    /// 엔진과 이벤트 수신 채널을 생성합니다.
    ///
    /// # 에러
    /// - `PipelineError::InitFailed`: 필수 설정이 누락된 경우
    pub fn build(self) -> Result<(EbpfEngine, mpsc::Receiver<PacketEvent>), IronpostError> {
        let config = self.config.ok_or_else(|| {
            PipelineError::InitFailed("config is required".to_owned())
        })?;

        let (event_tx, event_rx) = if let Some(tx) = self.event_tx {
            // 외부 채널 사용 시 더미 수신자 생성
            let (_dummy_tx, rx) = mpsc::channel(1);
            let _ = _dummy_tx; // 더미 송신자 드롭
            (tx, rx)
        } else {
            mpsc::channel(self.channel_capacity)
        };

        let detector = self.detector.unwrap_or_else(PacketDetector::default);

        let engine = EbpfEngine {
            config,
            event_tx,
            running: false,
            stats: TrafficStats::new(),
            detector,
            #[cfg(target_os = "linux")]
            bpf: None,
        };

        Ok((engine, event_rx))
    }
}

impl EbpfEngine {
    /// 빌더를 반환합니다.
    pub fn builder() -> EbpfEngineBuilder {
        EbpfEngineBuilder::new()
    }

    /// 현재 트래픽 통계를 반환합니다.
    pub fn stats(&self) -> &TrafficStats {
        &self.stats
    }

    /// 현재 설정을 반환합니다.
    pub fn config(&self) -> &EngineConfig {
        &self.config
    }

    /// 필터링 룰을 추가합니다.
    ///
    /// 엔진이 실행 중이면 eBPF HashMap 맵도 동시에 업데이트합니다.
    pub fn add_rule(&mut self, rule: FilterRule) -> Result<(), IronpostError> {
        self.config.add_rule(rule);
        if self.running {
            self.sync_blocklist_to_map()?;
        }
        Ok(())
    }

    /// 필터링 룰을 제거합니다.
    ///
    /// 엔진이 실행 중이면 eBPF HashMap 맵도 동시에 업데이트합니다.
    pub fn remove_rule(&mut self, rule_id: &str) -> Result<bool, IronpostError> {
        let removed = self.config.remove_rule(rule_id);
        if removed && self.running {
            self.sync_blocklist_to_map()?;
        }
        Ok(removed)
    }

    /// XDP 프로그램을 로드하고 네트워크 인터페이스에 어태치합니다.
    ///
    /// # Linux 전용
    /// macOS/Windows에서는 `DetectionError::EbpfLoad` 에러를 반환합니다.
    #[cfg(target_os = "linux")]
    fn load_and_attach(&mut self) -> Result<(), IronpostError> {
        todo!("aya::Ebpf::load() + XDP attach to interface")
    }

    /// XDP 프로그램을 로드합니다 (비-Linux 스텁).
    #[cfg(not(target_os = "linux"))]
    fn load_and_attach(&mut self) -> Result<(), IronpostError> {
        Err(DetectionError::EbpfLoad(
            "eBPF is only supported on Linux".to_owned(),
        )
        .into())
    }

    /// XDP 프로그램을 언로드합니다.
    #[cfg(target_os = "linux")]
    fn detach(&mut self) -> Result<(), IronpostError> {
        todo!("XDP detach + aya::Ebpf drop")
    }

    /// XDP 프로그램을 언로드합니다 (비-Linux 스텁).
    #[cfg(not(target_os = "linux"))]
    fn detach(&mut self) -> Result<(), IronpostError> {
        Ok(())
    }

    /// 현재 룰을 eBPF HashMap 맵에 동기화합니다.
    fn sync_blocklist_to_map(&mut self) -> Result<(), IronpostError> {
        todo!("FilterRule → eBPF HashMap 맵 동기화")
    }

    /// RingBuf에서 이벤트를 수신하는 백그라운드 태스크를 스폰합니다.
    ///
    /// 수신된 PacketEventData를 PacketEvent로 변환하여 event_tx로 전송합니다.
    /// 동시에 PacketDetector에 전달하여 이상 탐지를 수행합니다.
    fn spawn_event_reader(&self) -> Result<(), IronpostError> {
        todo!("RingBuf polling task spawn")
    }

    /// PerCpuArray에서 통계를 주기적으로 폴링하는 백그라운드 태스크를 스폰합니다.
    fn spawn_stats_poller(&self) -> Result<(), IronpostError> {
        todo!("PerCpuArray polling task spawn")
    }
}

impl Pipeline for EbpfEngine {
    /// eBPF XDP 프로그램을 로드하고 엔진을 시작합니다.
    ///
    /// 1. XDP 프로그램 로드 및 인터페이스 어태치
    /// 2. 필터링 룰을 eBPF HashMap에 동기화
    /// 3. RingBuf 이벤트 수신 태스크 스폰
    /// 4. 통계 폴링 태스크 스폰
    async fn start(&mut self) -> Result<(), IronpostError> {
        if self.running {
            return Err(PipelineError::AlreadyRunning.into());
        }

        info!(
            interface = self.config.base.interface.as_str(),
            xdp_mode = self.config.base.xdp_mode.as_str(),
            "starting eBPF engine"
        );

        self.load_and_attach()?;
        self.sync_blocklist_to_map()?;
        self.spawn_event_reader()?;
        self.spawn_stats_poller()?;

        self.running = true;
        Ok(())
    }

    /// eBPF 엔진을 정지하고 리소스를 정리합니다.
    ///
    /// 1. 백그라운드 태스크 취소
    /// 2. XDP 프로그램 언로드
    /// 3. 통계 리셋
    async fn stop(&mut self) -> Result<(), IronpostError> {
        if !self.running {
            return Err(PipelineError::NotRunning.into());
        }

        info!("stopping eBPF engine");

        self.detach()?;
        self.running = false;
        Ok(())
    }

    /// 엔진의 현재 상태를 확인합니다.
    async fn health_check(&self) -> HealthStatus {
        if !self.running {
            return HealthStatus::Unhealthy("not running".to_owned());
        }

        // TODO: XDP 프로그램 상태 확인, 맵 접근 가능 여부 등
        HealthStatus::Healthy
    }
}

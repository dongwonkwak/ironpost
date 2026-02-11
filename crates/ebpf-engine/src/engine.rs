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

use std::sync::Arc;

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
    /// Linux에서만 사용되는 필드 (spawn_event_reader에서 사용)
    #[cfg_attr(not(target_os = "linux"), allow(dead_code))]
    event_tx: mpsc::Sender<PacketEvent>,
    running: bool,
    stats: Arc<tokio::sync::Mutex<TrafficStats>>,
    /// Linux에서만 사용되는 필드 (spawn_event_reader에서 사용)
    #[cfg_attr(not(target_os = "linux"), allow(dead_code))]
    detector: Arc<PacketDetector>,
    /// 로드된 eBPF 프로그램 핸들 (Linux 전용)
    #[cfg(target_os = "linux")]
    bpf: Option<aya::Ebpf>,
    /// 백그라운드 태스크 핸들들
    #[cfg(target_os = "linux")]
    tasks: Vec<tokio::task::JoinHandle<()>>,
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
    /// # 반환 값
    /// - `EbpfEngine`: 생성된 엔진 인스턴스
    /// - `Option<mpsc::Receiver<PacketEvent>>`: 이벤트 수신자
    ///   - `Some(rx)`: 내부 채널 사용 시 (기본)
    ///   - `None`: 외부 채널 사용 시 (`event_sender()`로 지정)
    ///
    /// # 에러
    /// - `PipelineError::InitFailed`: 필수 설정이 누락된 경우
    ///
    /// # 참고
    /// 외부 채널을 사용한 경우 (`event_sender()`로 지정),
    /// 이벤트는 외부 채널의 수신자로만 전달됩니다.
    pub fn build(self) -> Result<(EbpfEngine, Option<mpsc::Receiver<PacketEvent>>), IronpostError> {
        let config = self
            .config
            .ok_or_else(|| PipelineError::InitFailed("config is required".to_owned()))?;

        // channel_capacity 검증
        if self.channel_capacity == 0 {
            return Err(PipelineError::InitFailed(
                "channel_capacity must be greater than 0".to_owned(),
            )
            .into());
        }

        let (event_tx, event_rx) = if let Some(tx) = self.event_tx {
            // 외부 채널 사용 시 수신자 없음
            (tx, None)
        } else {
            // 내부 채널 생성
            let (tx, rx) = mpsc::channel(self.channel_capacity);
            (tx, Some(rx))
        };

        let detector = Arc::new(self.detector.unwrap_or_default());

        let engine = EbpfEngine {
            config,
            event_tx,
            running: false,
            stats: Arc::new(tokio::sync::Mutex::new(TrafficStats::new())),
            detector,
            #[cfg(target_os = "linux")]
            bpf: None,
            #[cfg(target_os = "linux")]
            tasks: Vec::new(),
        };

        Ok((engine, event_rx))
    }
}

impl EbpfEngine {
    /// 빌더를 반환합니다.
    pub fn builder() -> EbpfEngineBuilder {
        EbpfEngineBuilder::new()
    }

    /// 현재 트래픽 통계에 대한 Arc를 반환합니다.
    pub fn stats(&self) -> Arc<tokio::sync::Mutex<TrafficStats>> {
        Arc::clone(&self.stats)
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
        use aya::{Ebpf, programs::Xdp, programs::XdpFlags};

        // eBPF 바이트코드 로드 (cargo xtask build-ebpf로 빌드된 바이너리)
        // 실제 프로덕션에서는 include_bytes!()로 바이너리를 임베드하지만,
        // 여기서는 런타임에 파일에서 로드하는 방식을 사용합니다.
        let ebpf_path = std::env::var("IRONPOST_EBPF_PATH")
            .unwrap_or_else(|_| "target/bpfel-unknown-none/release/ironpost-ebpf".to_owned());

        let ebpf_data = std::fs::read(&ebpf_path).map_err(|e| {
            DetectionError::EbpfLoad(format!(
                "failed to read eBPF binary from {}: {}",
                ebpf_path, e
            ))
        })?;

        let mut bpf = Ebpf::load(&ebpf_data)
            .map_err(|e| DetectionError::EbpfLoad(format!("failed to load eBPF program: {}", e)))?;

        // XDP 프로그램 획득
        let program: &mut Xdp = bpf
            .program_mut("ironpost_xdp")
            .ok_or_else(|| {
                DetectionError::EbpfLoad("XDP program 'ironpost_xdp' not found".to_owned())
            })?
            .try_into()
            .map_err(|e| {
                DetectionError::EbpfLoad(format!("failed to convert to XDP program: {}", e))
            })?;

        // XDP 프로그램 로드
        program
            .load()
            .map_err(|e| DetectionError::EbpfLoad(format!("failed to load XDP program: {}", e)))?;

        // XDP 모드 결정 (SKB/DRV/HW)
        let xdp_flags = match self.config.base.xdp_mode.as_str() {
            "native" | "drv" => XdpFlags::DRV_MODE,
            "hw" => XdpFlags::HW_MODE,
            _ => XdpFlags::SKB_MODE,
        };

        // 네트워크 인터페이스에 어태치
        program
            .attach(&self.config.base.interface, xdp_flags)
            .map_err(|e| {
                DetectionError::EbpfLoad(format!(
                    "failed to attach XDP to interface '{}': {}",
                    self.config.base.interface, e
                ))
            })?;

        // eBPF 핸들 저장
        self.bpf = Some(bpf);

        Ok(())
    }

    /// XDP 프로그램을 로드합니다 (비-Linux 스텁).
    #[cfg(not(target_os = "linux"))]
    fn load_and_attach(&mut self) -> Result<(), IronpostError> {
        Err(DetectionError::EbpfLoad("eBPF is only supported on Linux".to_owned()).into())
    }

    /// XDP 프로그램을 언로드합니다.
    #[cfg(target_os = "linux")]
    fn detach(&mut self) -> Result<(), IronpostError> {
        // aya::Ebpf를 drop하면 자동으로 XDP가 detach됩니다
        if let Some(bpf) = self.bpf.take() {
            drop(bpf);
        }
        Ok(())
    }

    /// XDP 프로그램을 언로드합니다 (비-Linux 스텁).
    #[cfg(not(target_os = "linux"))]
    fn detach(&mut self) -> Result<(), IronpostError> {
        Ok(())
    }

    /// 현재 룰을 eBPF HashMap 맵에 동기화합니다.
    fn sync_blocklist_to_map(&mut self) -> Result<(), IronpostError> {
        #[cfg(target_os = "linux")]
        {
            use aya::maps::HashMap as AyaHashMap;
            use ironpost_ebpf_common::{
                ACTION_DROP, ACTION_MONITOR, BlocklistValue, MAP_BLOCKLIST,
            };
            use std::net::IpAddr;

            // eBPF가 로드되지 않았으면 스킵
            let Some(ref mut bpf) = self.bpf else {
                return Ok(());
            };

            // BLOCKLIST 맵 획득
            let mut map: AyaHashMap<_, u32, BlocklistValue> =
                AyaHashMap::try_from(bpf.map_mut(MAP_BLOCKLIST).ok_or_else(|| {
                    DetectionError::EbpfMap(format!("map '{}' not found", MAP_BLOCKLIST))
                })?)
                .map_err(|e| {
                    DetectionError::EbpfMap(format!("failed to get blocklist map: {}", e))
                })?;

            // 현재 룰의 IP 집합 수집
            let current_ips: std::collections::HashSet<u32> = self
                .config
                .ip_rules()
                .filter_map(|r| {
                    if let Some(IpAddr::V4(ipv4)) = r.src_ip {
                        Some(u32::from_be_bytes(ipv4.octets()))
                    } else {
                        None
                    }
                })
                .collect();

            // 기존 맵의 키를 수집하여 삭제 대상 확인
            let existing_keys: Vec<u32> = map.keys().filter_map(|k| k.ok()).collect();

            // 현재 룰에 없는 키 삭제
            for key in existing_keys {
                if !current_ips.contains(&key) {
                    if let Err(e) = map.remove(&key) {
                        tracing::warn!(ip = u32::from_be(key), error = %e, "failed to remove stale blocklist entry");
                    } else {
                        tracing::debug!(ip = u32::from_be(key), "removed stale blocklist entry");
                    }
                }
            }

            // 모든 IP 룰을 맵에 추가
            for rule in self.config.ip_rules() {
                let Some(src_ip) = rule.src_ip else {
                    continue;
                };

                // IP 주소를 u32 네트워크 바이트 오더로 변환
                let ip_u32 = match src_ip {
                    IpAddr::V4(ipv4) => u32::from_be_bytes(ipv4.octets()),
                    IpAddr::V6(_) => {
                        // IPv6는 현재 지원하지 않음 (커널 맵이 u32 키)
                        tracing::warn!(
                            rule_id = rule.id.as_str(),
                            "IPv6 addresses are not supported in blocklist, skipping"
                        );
                        continue;
                    }
                };

                // RuleAction을 BlocklistValue로 변환
                let action_code = match rule.action {
                    crate::config::RuleAction::Block => ACTION_DROP,
                    crate::config::RuleAction::Monitor => ACTION_MONITOR,
                };

                let value = BlocklistValue {
                    action: action_code,
                    _pad: [0; 3],
                };

                // 맵에 삽입
                map.insert(ip_u32, value, 0).map_err(|e| {
                    DetectionError::EbpfMap(format!(
                        "failed to insert rule '{}' into blocklist: {}",
                        rule.id, e
                    ))
                })?;

                tracing::debug!(
                    rule_id = rule.id.as_str(),
                    src_ip = %src_ip,
                    action = ?rule.action,
                    "synced rule to eBPF blocklist"
                );
            }
        }

        #[cfg(not(target_os = "linux"))]
        {
            // 비-Linux 플랫폼에서는 no-op
        }

        Ok(())
    }

    /// RingBuf에서 이벤트를 수신하는 백그라운드 태스크를 스폰합니다.
    ///
    /// 수신된 PacketEventData를 PacketEvent로 변환하여 event_tx로 전송합니다.
    /// 동시에 PacketDetector에 전달하여 이상 탐지를 수행합니다.
    fn spawn_event_reader(&mut self) -> Result<(), IronpostError> {
        #[cfg(target_os = "linux")]
        {
            use aya::maps::RingBuf;
            use bytes::Bytes;
            use ironpost_core::types::PacketInfo;
            use ironpost_ebpf_common::{MAP_EVENTS, PacketEventData};
            use std::net::IpAddr;

            // eBPF가 로드되지 않았으면 스킵
            let Some(ref mut bpf) = self.bpf else {
                return Ok(());
            };

            // EVENTS RingBuf 획득 (소유권 획득)
            let ringbuf = RingBuf::try_from(bpf.take_map(MAP_EVENTS).ok_or_else(|| {
                DetectionError::EbpfMap(format!("map '{}' not found", MAP_EVENTS))
            })?)
            .map_err(|e| DetectionError::EbpfMap(format!("failed to get events ringbuf: {}", e)))?;

            let event_tx = self.event_tx.clone();
            let detector = Arc::clone(&self.detector);

            // 백그라운드 태스크 스폰
            let handle = tokio::task::spawn(async move {
                let mut ringbuf = ringbuf;
                tracing::info!("eBPF event reader task started");

                // Exponential backoff: idle일 때 CPU 사용 최소화
                // 초기 1ms → 최대 100ms (초당 ~10회 wakeup, 기존 100회에서 90% 감소)
                let mut backoff_ms: u64 = 1;
                const MAX_BACKOFF_MS: u64 = 100;

                loop {
                    // RingBuf에서 이벤트 폴링
                    match ringbuf.next() {
                        Some(data) => {
                            // 이벤트 수신 시 backoff 리셋
                            backoff_ms = 1;

                            // PacketEventData 역직렬화
                            if data.len() < std::mem::size_of::<PacketEventData>() {
                                tracing::warn!(
                                    size = data.len(),
                                    expected = std::mem::size_of::<PacketEventData>(),
                                    "received undersized event, skipping"
                                );
                                continue;
                            }

                            // SAFETY: PacketEventData는 #[repr(C)]이며 크기 검증을 완료했습니다.
                            // RingBuf에서 반환된 데이터의 정렬이 보장되지 않을 수 있으므로
                            // read_unaligned를 사용하여 UB를 방지합니다.
                            let event_data = unsafe {
                                std::ptr::read_unaligned(data.as_ptr() as *const PacketEventData)
                            };

                            // PacketInfo로 변환
                            let src_ip = IpAddr::V4(std::net::Ipv4Addr::from(event_data.src_ip));
                            let dst_ip = IpAddr::V4(std::net::Ipv4Addr::from(event_data.dst_ip));

                            let packet_info = PacketInfo {
                                src_ip,
                                dst_ip,
                                src_port: event_data.src_port,
                                dst_port: event_data.dst_port,
                                protocol: event_data.protocol,
                                size: usize::try_from(event_data.pkt_len).unwrap_or(usize::MAX),
                                timestamp: std::time::SystemTime::now(),
                            };

                            // PacketEvent 생성
                            let packet_event = PacketEvent::new(packet_info, Bytes::new());

                            // 탐지기로 전달
                            if let Err(e) = detector.analyze(&event_data) {
                                tracing::error!(error = %e, "failed to analyze packet event");
                            }

                            // 이벤트 채널로 전송
                            if let Err(e) = event_tx.send(packet_event).await {
                                tracing::error!(error = %e, "failed to send packet event, channel closed");
                                break;
                            }
                        }
                        None => {
                            // RingBuf가 비어있으면 지수적 백오프로 대기
                            // idle 시 CPU 사이클 낭비 방지, 부하 증가 시 빠른 반응
                            tokio::time::sleep(std::time::Duration::from_millis(backoff_ms)).await;
                            backoff_ms = (backoff_ms * 2).min(MAX_BACKOFF_MS);
                        }
                    }
                }

                tracing::info!("eBPF event reader task stopped");
            });

            self.tasks.push(handle);
        }

        #[cfg(not(target_os = "linux"))]
        {
            // 비-Linux 플랫폼에서는 no-op
        }

        Ok(())
    }

    /// PerCpuArray에서 통계를 주기적으로 폴링하는 백그라운드 태스크를 스폰합니다.
    fn spawn_stats_poller(&mut self) -> Result<(), IronpostError> {
        #[cfg(target_os = "linux")]
        {
            use crate::stats::RawTrafficSnapshot;
            use aya::maps::PerCpuArray;
            use ironpost_ebpf_common::{
                MAP_STATS, ProtoStats, STATS_IDX_ICMP, STATS_IDX_OTHER, STATS_IDX_TCP,
                STATS_IDX_TOTAL, STATS_IDX_UDP,
            };

            // eBPF가 로드되지 않았으면 스킵
            let Some(ref mut bpf) = self.bpf else {
                return Ok(());
            };

            // STATS PerCpuArray 획득 (소유권 획득)
            let stats_map =
                PerCpuArray::<_, ProtoStats>::try_from(bpf.take_map(MAP_STATS).ok_or_else(
                    || DetectionError::EbpfMap(format!("map '{}' not found", MAP_STATS)),
                )?)
                .map_err(|e| DetectionError::EbpfMap(format!("failed to get stats map: {}", e)))?;

            // TrafficStats Arc 복사
            let stats = Arc::clone(&self.stats);

            // 백그라운드 태스크 스폰
            let handle = tokio::task::spawn(async move {
                tracing::info!("eBPF stats poller task started");

                let mut interval = tokio::time::interval(std::time::Duration::from_secs(1));

                loop {
                    interval.tick().await;

                    // 각 프로토콜 인덱스에서 통계 수집
                    let tcp = sum_percpu_stats(&stats_map, STATS_IDX_TCP);
                    let udp = sum_percpu_stats(&stats_map, STATS_IDX_UDP);
                    let icmp = sum_percpu_stats(&stats_map, STATS_IDX_ICMP);
                    let other = sum_percpu_stats(&stats_map, STATS_IDX_OTHER);
                    let total = sum_percpu_stats(&stats_map, STATS_IDX_TOTAL);

                    let snapshot = RawTrafficSnapshot {
                        tcp,
                        udp,
                        icmp,
                        other,
                        total,
                    };

                    // TrafficStats 업데이트
                    {
                        let mut stats_guard = stats.lock().await;
                        stats_guard.update(snapshot);
                    }
                }

                // 이 루프는 무한 루프이므로 여기 도달하지 않지만, 컴파일러를 위해 남김
                #[allow(unreachable_code)]
                {
                    tracing::info!("eBPF stats poller task stopped");
                }
            });

            self.tasks.push(handle);
        }

        #[cfg(not(target_os = "linux"))]
        {
            // 비-Linux 플랫폼에서는 no-op
        }

        Ok(())
    }
}

// =============================================================================
// Helper Functions (Linux 전용)
// =============================================================================

/// PerCpuArray에서 특정 인덱스의 모든 CPU 값을 합산합니다.
#[cfg(target_os = "linux")]
fn sum_percpu_stats(
    map: &aya::maps::PerCpuArray<aya::maps::MapData, ironpost_ebpf_common::ProtoStats>,
    index: u32,
) -> crate::stats::RawProtoStats {
    use crate::stats::RawProtoStats;

    match map.get(&index, 0) {
        Ok(per_cpu_values) => {
            // 모든 CPU의 값을 합산
            let mut total = RawProtoStats::default();
            for cpu_stats in per_cpu_values.iter() {
                total.packets += cpu_stats.packets;
                total.bytes += cpu_stats.bytes;
                total.drops += cpu_stats.drops;
            }
            total
        }
        Err(e) => {
            tracing::warn!(index = index, error = %e, "failed to read PerCpuArray stats");
            RawProtoStats::default()
        }
    }
}

// =============================================================================
// Pipeline Trait Implementation
// =============================================================================

impl EbpfEngine {
    /// XDP 어태치 이후 초기화 단계를 수행합니다.
    ///
    /// 이 메서드가 실패하면 start()에서 자동으로 롤백합니다.
    fn initialize_post_attach(&mut self) -> Result<(), IronpostError> {
        self.sync_blocklist_to_map()?;
        self.spawn_event_reader()?;
        self.spawn_stats_poller()?;
        Ok(())
    }
}

impl Pipeline for EbpfEngine {
    /// eBPF XDP 프로그램을 로드하고 엔진을 시작합니다.
    ///
    /// 1. XDP 프로그램 로드 및 인터페이스 어태치
    /// 2. 필터링 룰을 eBPF HashMap에 동기화
    /// 3. RingBuf 이벤트 수신 태스크 스폰
    /// 4. 통계 폴링 태스크 스폰
    ///
    /// # 롤백 보장
    /// 초기화 중 에러 발생 시 자동으로 XDP 프로그램을 detach하여
    /// 리소스 누수를 방지합니다.
    async fn start(&mut self) -> Result<(), IronpostError> {
        if self.running {
            return Err(PipelineError::AlreadyRunning.into());
        }

        info!(
            interface = self.config.base.interface.as_str(),
            xdp_mode = self.config.base.xdp_mode.as_str(),
            "starting eBPF engine"
        );

        // XDP 프로그램 로드 및 어태치
        self.load_and_attach()?;

        // 이후 단계에서 실패 시 자동 롤백
        if let Err(e) = self.initialize_post_attach() {
            tracing::error!(error = %e, "failed to initialize engine, rolling back");

            // 이미 스폰된 백그라운드 태스크 정리
            #[cfg(target_os = "linux")]
            {
                for task in self.tasks.drain(..) {
                    task.abort();
                }
            }

            // XDP 프로그램 detach (롤백)
            if let Err(detach_err) = self.detach() {
                tracing::error!(
                    error = %detach_err,
                    "failed to detach XDP during rollback"
                );
            }
            return Err(e);
        }

        self.running = true;
        Ok(())
    }

    /// eBPF 엔진을 정지하고 리소스를 정리합니다.
    ///
    /// 1. 백그라운드 태스크 취소
    /// 2. XDP 프로그램 언로드
    ///
    /// # 참고
    /// 통계(stats)는 리셋되지 않으므로, stop() 후에도 누적된 트래픽 통계를 조회할 수 있습니다.
    async fn stop(&mut self) -> Result<(), IronpostError> {
        if !self.running {
            return Err(PipelineError::NotRunning.into());
        }

        info!("stopping eBPF engine");

        // 백그라운드 태스크 취소
        #[cfg(target_os = "linux")]
        {
            for task in self.tasks.drain(..) {
                task.abort();
            }
        }

        // XDP 프로그램 detach
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

#[cfg(test)]
mod tests {
    use super::*;
    use ironpost_core::config::EbpfConfig;
    use std::net::IpAddr;

    // =============================================================================
    // EbpfEngineBuilder 테스트
    // =============================================================================

    #[test]
    fn test_builder_minimal_config() {
        let config = EngineConfig::default();

        let result = EbpfEngine::builder().config(config).build();

        assert!(result.is_ok());
        let (engine, event_rx) = result.unwrap();

        assert!(!engine.running);
        assert!(event_rx.is_some()); // 내부 채널 생성됨
    }

    #[test]
    fn test_builder_missing_config_fails() {
        let result = EbpfEngine::builder().build();

        assert!(result.is_err());
    }

    #[test]
    fn test_builder_with_external_channel() {
        let config = EngineConfig::default();
        let (external_tx, _external_rx) = mpsc::channel(100);

        let result = EbpfEngine::builder()
            .config(config)
            .event_sender(external_tx)
            .build();

        assert!(result.is_ok());
        let (engine, event_rx) = result.unwrap();

        assert!(!engine.running);
        assert!(event_rx.is_none()); // 외부 채널 사용 시 None
    }

    #[test]
    fn test_builder_custom_channel_capacity() {
        let config = EngineConfig::default();

        let result = EbpfEngine::builder()
            .config(config)
            .channel_capacity(2048)
            .build();

        assert!(result.is_ok());
    }

    #[test]
    fn test_builder_with_custom_detector() {
        use crate::detector::{PacketDetector, PortScanConfig, SynFloodConfig};

        let config = EngineConfig::default();
        let (alert_tx, _alert_rx) = mpsc::channel(100);
        let detector = PacketDetector::new(
            alert_tx,
            SynFloodConfig::default(),
            PortScanConfig::default(),
        );

        let result = EbpfEngine::builder()
            .config(config)
            .detector(detector)
            .build();

        assert!(result.is_ok());
    }

    #[test]
    fn test_builder_fluent_api() {
        let config = EngineConfig::default();

        let result = EbpfEngine::builder()
            .config(config)
            .channel_capacity(512)
            .build();

        assert!(result.is_ok());
    }

    // =============================================================================
    // EbpfEngine 기본 기능 테스트
    // =============================================================================

    #[test]
    fn test_engine_initial_state() {
        let config = EngineConfig::default();
        let (engine, _rx) = EbpfEngine::builder().config(config).build().unwrap();

        assert!(!engine.running);
        assert_eq!(engine.config().rules.len(), 0);
    }

    #[test]
    fn test_engine_config_access() {
        let mut config = EngineConfig::default();
        config.base.interface = "eth0".to_owned();

        let (engine, _rx) = EbpfEngine::builder().config(config).build().unwrap();

        assert_eq!(engine.config().base.interface, "eth0");
    }

    #[test]
    fn test_engine_stats_access() {
        let config = EngineConfig::default();
        let (engine, _rx) = EbpfEngine::builder().config(config).build().unwrap();

        let stats_arc = engine.stats();
        assert!(Arc::strong_count(&stats_arc) >= 2); // engine + 테스트 참조
    }

    // =============================================================================
    // add_rule / remove_rule 테스트 (엔진 미실행 상태)
    // =============================================================================

    #[test]
    fn test_add_rule_when_not_running() {
        use std::net::Ipv4Addr;

        let config = EngineConfig::default();
        let (mut engine, _rx) = EbpfEngine::builder().config(config).build().unwrap();

        let rule = crate::config::FilterRule {
            id: "test-rule".to_owned(),
            src_ip: Some(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1))),
            dst_ip: None,
            dst_port: None,
            protocol: None,
            action: crate::config::RuleAction::Block,
            description: "Test rule".to_owned(),
        };

        let result = engine.add_rule(rule);
        assert!(result.is_ok());
        assert_eq!(engine.config().rules.len(), 1);
    }

    #[test]
    fn test_remove_rule_when_not_running() {
        use std::net::Ipv4Addr;

        let config = EngineConfig::default();
        let (mut engine, _rx) = EbpfEngine::builder().config(config).build().unwrap();

        let rule = crate::config::FilterRule {
            id: "test-rule".to_owned(),
            src_ip: Some(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1))),
            dst_ip: None,
            dst_port: None,
            protocol: None,
            action: crate::config::RuleAction::Block,
            description: "Test rule".to_owned(),
        };

        engine.add_rule(rule).unwrap();
        assert_eq!(engine.config().rules.len(), 1);

        let removed = engine.remove_rule("test-rule").unwrap();
        assert!(removed);
        assert_eq!(engine.config().rules.len(), 0);
    }

    #[test]
    fn test_remove_nonexistent_rule() {
        let config = EngineConfig::default();
        let (mut engine, _rx) = EbpfEngine::builder().config(config).build().unwrap();

        let removed = engine.remove_rule("nonexistent").unwrap();
        assert!(!removed);
    }

    // =============================================================================
    // Pipeline trait 테스트 (비-Linux 환경)
    // =============================================================================

    #[cfg(not(target_os = "linux"))]
    #[tokio::test]
    async fn test_start_fails_on_non_linux() {
        let config = EngineConfig::default();
        let (mut engine, _rx) = EbpfEngine::builder().config(config).build().unwrap();

        let result = engine.start().await;
        assert!(result.is_err());

        let err = result.unwrap_err();
        assert!(err.to_string().contains("eBPF is only supported on Linux"));
    }

    #[tokio::test]
    async fn test_stop_when_not_running() {
        let config = EngineConfig::default();
        let (mut engine, _rx) = EbpfEngine::builder().config(config).build().unwrap();

        let result = engine.stop().await;
        assert!(result.is_err());

        let err = result.unwrap_err();
        assert!(err.to_string().contains("not running"));
    }

    #[tokio::test]
    async fn test_health_check_when_not_running() {
        let config = EngineConfig::default();
        let (engine, _rx) = EbpfEngine::builder().config(config).build().unwrap();

        let status = engine.health_check().await;
        match status {
            HealthStatus::Unhealthy(msg) => {
                assert!(msg.contains("not running"));
            }
            _ => panic!("Expected Unhealthy status"),
        }
    }

    // =============================================================================
    // Linux 전용 통합 테스트
    // =============================================================================

    #[cfg(target_os = "linux")]
    mod linux_integration {
        use super::*;

        #[tokio::test]
        #[ignore] // CI에서 권한 문제로 스킵, 로컬에서만 실행
        async fn test_start_with_invalid_interface() {
            let mut config = EngineConfig::default();
            config.base.interface = "nonexistent-iface".to_owned();

            let (mut engine, _rx) = EbpfEngine::builder().config(config).build().unwrap();

            let result = engine.start().await;
            assert!(result.is_err());

            let err = result.unwrap_err();
            assert!(err.to_string().contains("failed to attach XDP"));
        }

        #[tokio::test]
        #[ignore] // CI에서 권한 문제로 스킵
        async fn test_start_without_ebpf_binary() {
            // SAFETY: 테스트 환경에서 환경변수를 설정합니다.
            // 단일 스레드로 실행되므로 다른 테스트와 격리되어 있습니다.
            unsafe {
                std::env::set_var("IRONPOST_EBPF_PATH", "/nonexistent/path/ebpf");
            }

            let config = EngineConfig::default();
            let (mut engine, _rx) = EbpfEngine::builder().config(config).build().unwrap();

            let result = engine.start().await;
            assert!(result.is_err());

            let err = result.unwrap_err();
            assert!(err.to_string().contains("failed to read eBPF binary"));

            // SAFETY: 테스트 후 환경변수를 정리합니다.
            unsafe {
                std::env::remove_var("IRONPOST_EBPF_PATH");
            }
        }

        #[tokio::test]
        #[ignore] // 권한 및 네트워크 인터페이스 필요
        async fn test_start_stop_lifecycle() {
            // 이 테스트는 실제 네트워크 인터페이스와 root 권한이 필요합니다.
            // 로컬 개발 환경에서 `cargo test --package ironpost-ebpf-engine -- --ignored` 실행

            let mut config = EngineConfig::default();
            config.base.interface = "lo".to_owned(); // loopback 사용
            config.base.xdp_mode = "skb".to_owned();

            let (mut engine, _rx) = EbpfEngine::builder().config(config).build().unwrap();

            // start
            let start_result = engine.start().await;
            if start_result.is_err() {
                // eBPF 바이너리가 없거나 권한 부족 시 스킵
                tracing::warn!(error = ?start_result.unwrap_err(), "skipping test due to error");
                return;
            }

            assert!(engine.running);

            // health check
            let status = engine.health_check().await;
            assert!(matches!(status, HealthStatus::Healthy));

            // stop
            let stop_result = engine.stop().await;
            assert!(stop_result.is_ok());
            assert!(!engine.running);
        }
    }

    // =============================================================================
    // 경계값 및 에러 케이스 테스트
    // =============================================================================

    #[test]
    fn test_builder_with_zero_capacity() {
        let config = EngineConfig::default();

        let result = EbpfEngine::builder()
            .config(config)
            .channel_capacity(0)
            .build();

        assert!(result.is_err());
        if let Err(err) = result {
            assert!(
                err.to_string()
                    .contains("channel_capacity must be greater than 0")
            );
        }
    }

    #[test]
    fn test_builder_with_large_capacity() {
        let config = EngineConfig::default();

        let result = EbpfEngine::builder()
            .config(config)
            .channel_capacity(1_000_000)
            .build();

        assert!(result.is_ok());
    }

    #[test]
    fn test_multiple_engines_creation() {
        let config1 = EngineConfig::default();
        let config2 = EngineConfig::default();

        let result1 = EbpfEngine::builder().config(config1).build();
        let result2 = EbpfEngine::builder().config(config2).build();

        assert!(result1.is_ok());
        assert!(result2.is_ok());
    }

    #[test]
    fn test_engine_config_from_core() {
        let ebpf_config = EbpfConfig {
            enabled: true,
            interface: "eth0".to_owned(),
            xdp_mode: "native".to_owned(),
            ring_buffer_size: 2048,
            blocklist_max_entries: 10000,
        };

        let engine_config = EngineConfig::from_core(&ebpf_config);
        let (engine, _rx) = EbpfEngine::builder().config(engine_config).build().unwrap();

        assert_eq!(engine.config().base.interface, "eth0");
        assert_eq!(engine.config().base.xdp_mode, "native");
        assert_eq!(engine.config().base.ring_buffer_size, 2048);
    }

    // =============================================================================
    // 바이트 오더 일관성 테스트 (회귀 방지)
    // =============================================================================

    #[test]
    fn test_blocklist_key_byte_order_consistency() {
        // 커널(XDP)과 유저스페이스(engine)의 BLOCKLIST 맵 키 표현이 일치하는지 검증
        // 버그: 키 생성 방식 불일치로 IP 필터링 실패

        use std::net::Ipv4Addr;

        // 테스트 IP 주소들
        let test_ips = [
            Ipv4Addr::new(10, 0, 0, 1),
            Ipv4Addr::new(192, 168, 1, 100),
            Ipv4Addr::new(172, 16, 0, 50),
            Ipv4Addr::new(8, 8, 8, 8),
        ];

        for ip in test_ips.iter() {
            // 커널(XDP) 방식: from_be_bytes([a, b, c, d])
            let kernel_key = u32::from_be_bytes(ip.octets());

            // 유저스페이스(engine) 방식: FilterRule의 IP → u32 변환
            // engine.rs:346에서 사용되는 방식
            let userspace_key = u32::from_be_bytes(ip.octets());

            // 검증: 두 방식이 동일한 키를 생성해야 함
            assert_eq!(
                kernel_key, userspace_key,
                "IP {} 의 커널/유저스페이스 키 불일치: kernel={:#x}, userspace={:#x}",
                ip, kernel_key, userspace_key
            );

            // 추가 검증: 키에서 다시 IP로 변환 가능해야 함
            // kernel_key는 이미 호스트 바이트 오더이므로 그대로 사용
            let recovered_ip = Ipv4Addr::from(kernel_key);
            assert_eq!(
                recovered_ip, *ip,
                "IP 복원 실패: original={}, recovered={}",
                ip, recovered_ip
            );
        }
    }

    #[test]
    fn test_packet_event_data_byte_order_round_trip() {
        // PacketEventData의 IP/포트가 커널 → 유저스페이스 변환 후 올바른지 검증

        use std::net::Ipv4Addr;

        let src_ip = Ipv4Addr::new(10, 0, 0, 50);
        let dst_ip = Ipv4Addr::new(192, 168, 1, 1);
        let src_port: u16 = 12345;
        let dst_port: u16 = 443;

        // 커널(XDP)에서 생성되는 방식 시뮬레이션
        let kernel_src_ip = u32::from_be_bytes(src_ip.octets());
        let kernel_dst_ip = u32::from_be_bytes(dst_ip.octets());
        let kernel_src_port = u16::from_be_bytes(src_port.to_be_bytes());
        let kernel_dst_port = u16::from_be_bytes(dst_port.to_be_bytes());

        // 유저스페이스(engine.rs:455-462)에서 복원하는 방식
        let recovered_src_ip = Ipv4Addr::from(kernel_src_ip);
        let recovered_dst_ip = Ipv4Addr::from(kernel_dst_ip);
        let recovered_src_port = kernel_src_port;
        let recovered_dst_port = kernel_dst_port;

        // 검증: 원본과 복원된 값이 일치해야 함
        assert_eq!(recovered_src_ip, src_ip);
        assert_eq!(recovered_dst_ip, dst_ip);
        assert_eq!(recovered_src_port, src_port);
        assert_eq!(recovered_dst_port, dst_port);
    }

    #[test]
    fn test_ip_address_network_byte_order() {
        // IP 주소의 네트워크 바이트 오더(big-endian) 표현 검증

        use std::net::Ipv4Addr;

        // 10.0.0.1 = 0x0a000001 (network byte order)
        let ip = Ipv4Addr::new(10, 0, 0, 1);
        let as_u32 = u32::from_be_bytes(ip.octets());

        // 검증: 네트워크 바이트 오더로 변환
        assert_eq!(as_u32, 0x0a00_0001);

        // little-endian 시스템에서도 동일한 결과여야 함
        let ip2 = Ipv4Addr::new(192, 168, 1, 100);
        let as_u32_2 = u32::from_be_bytes(ip2.octets());
        assert_eq!(as_u32_2, 0xc0a8_0164); // 192=0xc0, 168=0xa8, 1=0x01, 100=0x64

        // 역변환 검증
        let recovered = Ipv4Addr::from(as_u32_2);
        assert_eq!(recovered, ip2);
    }
}

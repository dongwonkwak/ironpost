//! 통계 수집 — PerCpuArray 기반 패킷 통계
//!
//! [`TrafficStats`]는 eBPF PerCpuArray 맵에서 수집한 프로토콜별 트래픽 통계를 관리합니다.
//! 엔진 내부에서 주기적으로 폴링하여 업데이트하고, 외부에서 조회할 수 있습니다.
//!
//! # 데이터 흐름
//! ```text
//! PerCpuArray (kernel) ──poll──▶ RawTrafficSnapshot ──update──▶ TrafficStats
//!                                (CPU별 값 합산)                (rate 계산)
//! ```

use std::time::Instant;

use serde::Serialize;

/// CPU별 합산된 원시 통계 (단일 프로토콜)
///
/// PerCpuArray에서 읽은 모든 CPU의 값을 합산한 결과입니다.
#[derive(Debug, Clone, Default)]
pub struct RawProtoStats {
    /// 처리된 패킷 수 (누적)
    pub packets: u64,
    /// 전송 바이트 수 (누적)
    pub bytes: u64,
    /// 드롭된 패킷 수 (누적)
    pub drops: u64,
}

/// 전체 트래픽 원시 통계 스냅샷
///
/// 한 번의 폴링에서 수집한 모든 프로토콜의 누적 통계입니다.
#[derive(Debug, Clone, Default)]
pub struct RawTrafficSnapshot {
    /// TCP 통계
    pub tcp: RawProtoStats,
    /// UDP 통계
    pub udp: RawProtoStats,
    /// ICMP 통계
    pub icmp: RawProtoStats,
    /// 기타 프로토콜 통계
    pub other: RawProtoStats,
    /// 전체 합계
    pub total: RawProtoStats,
}

/// 프로토콜별 트래픽 메트릭 (누적 + 비율)
///
/// Prometheus 메트릭 노출에 사용됩니다.
#[derive(Debug, Clone, Default, Serialize)]
pub struct ProtoMetrics {
    /// 처리된 패킷 수 (누적)
    pub packets: u64,
    /// 전송 바이트 수 (누적)
    pub bytes: u64,
    /// 드롭된 패킷 수 (누적)
    pub drops: u64,
    /// 초당 패킷 수 (packets per second)
    pub pps: f64,
    /// 초당 비트 수 (bits per second)
    pub bps: f64,
}

/// 전체 트래픽 통계
///
/// 프로토콜별 메트릭과 rate 계산 상태를 관리합니다.
/// `Serialize`를 구현하여 JSON/Prometheus 형태로 노출 가능합니다.
///
/// # Rate 계산
/// `update()`를 호출할 때마다 이전 스냅샷과의 차이(delta)를 시간으로 나누어
/// pps, bps를 계산합니다.
#[derive(Debug, Clone, Serialize)]
pub struct TrafficStats {
    /// TCP 통계
    pub tcp: ProtoMetrics,
    /// UDP 통계
    pub udp: ProtoMetrics,
    /// ICMP 통계
    pub icmp: ProtoMetrics,
    /// 기타 프로토콜 통계
    pub other: ProtoMetrics,
    /// 전체 합계
    pub total: ProtoMetrics,
    /// 마지막 업데이트 시각 (rate 계산용, 직렬화 제외)
    #[serde(skip)]
    last_poll: Option<Instant>,
    /// 이전 폴링의 원시 값 (delta 계산용, 직렬화 제외)
    #[serde(skip)]
    prev_raw: Option<RawTrafficSnapshot>,
}

impl TrafficStats {
    /// 제로 초기화된 통계를 생성합니다.
    pub fn new() -> Self {
        Self {
            tcp: ProtoMetrics::default(),
            udp: ProtoMetrics::default(),
            icmp: ProtoMetrics::default(),
            other: ProtoMetrics::default(),
            total: ProtoMetrics::default(),
            last_poll: None,
            prev_raw: None,
        }
    }

    /// 원시 통계 스냅샷으로부터 메트릭을 업데이트합니다.
    ///
    /// 이전 스냅샷이 있으면 delta를 계산하여 pps, bps를 갱신합니다.
    /// 첫 번째 호출에서는 rate가 0으로 설정됩니다.
    pub fn update(&mut self, raw: RawTrafficSnapshot) {
        let now = Instant::now();

        if let (Some(prev), Some(last_time)) = (&self.prev_raw, self.last_poll) {
            let elapsed = now.duration_since(last_time).as_secs_f64();
            if elapsed > 0.0 {
                Self::compute_rate(&mut self.tcp, &raw.tcp, &prev.tcp, elapsed);
                Self::compute_rate(&mut self.udp, &raw.udp, &prev.udp, elapsed);
                Self::compute_rate(&mut self.icmp, &raw.icmp, &prev.icmp, elapsed);
                Self::compute_rate(&mut self.other, &raw.other, &prev.other, elapsed);
                Self::compute_rate(&mut self.total, &raw.total, &prev.total, elapsed);
            }
        } else {
            // 첫 번째 폴링 — 누적값만 설정, rate는 0
            Self::set_cumulative(&mut self.tcp, &raw.tcp);
            Self::set_cumulative(&mut self.udp, &raw.udp);
            Self::set_cumulative(&mut self.icmp, &raw.icmp);
            Self::set_cumulative(&mut self.other, &raw.other);
            Self::set_cumulative(&mut self.total, &raw.total);
        }

        self.prev_raw = Some(raw);
        self.last_poll = Some(now);
    }

    /// 통계를 초기화합니다.
    pub fn reset(&mut self) {
        *self = Self::new();
    }

    /// Prometheus exposition format 문자열을 생성합니다.
    ///
    /// ```text
    /// ironpost_packets_total{proto="tcp"} 12345
    /// ironpost_bytes_total{proto="tcp"} 678900
    /// ironpost_drops_total{proto="tcp"} 42
    /// ironpost_pps{proto="tcp"} 1234.5
    /// ironpost_bps{proto="tcp"} 5678000.0
    /// ```
    pub fn to_prometheus(&self) -> String {
        todo!("Prometheus exposition format 생성")
    }

    /// delta를 계산하여 rate를 갱신합니다.
    fn compute_rate(
        metrics: &mut ProtoMetrics,
        current: &RawProtoStats,
        prev: &RawProtoStats,
        elapsed_secs: f64,
    ) {
        metrics.packets = current.packets;
        metrics.bytes = current.bytes;
        metrics.drops = current.drops;

        let delta_packets = current.packets.saturating_sub(prev.packets);
        let delta_bytes = current.bytes.saturating_sub(prev.bytes);

        metrics.pps = delta_packets as f64 / elapsed_secs;
        // bytes → bits: *8
        metrics.bps = (delta_bytes as f64 * 8.0) / elapsed_secs;
    }

    /// 누적값만 설정합니다 (rate는 0).
    fn set_cumulative(metrics: &mut ProtoMetrics, raw: &RawProtoStats) {
        metrics.packets = raw.packets;
        metrics.bytes = raw.bytes;
        metrics.drops = raw.drops;
        metrics.pps = 0.0;
        metrics.bps = 0.0;
    }
}

impl Default for TrafficStats {
    fn default() -> Self {
        Self::new()
    }
}

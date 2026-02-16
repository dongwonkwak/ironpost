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

use ironpost_core::metrics as m;
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

        // Update Prometheus metrics
        metrics::counter!(m::EBPF_PACKETS_TOTAL).absolute(self.total.packets);
        metrics::counter!(m::EBPF_BYTES_TOTAL).absolute(self.total.bytes);
        metrics::counter!(m::EBPF_PACKETS_BLOCKED_TOTAL).absolute(self.total.drops);

        // Protocol-specific counters
        for (proto, stats) in [
            ("tcp", &self.tcp),
            ("udp", &self.udp),
            ("icmp", &self.icmp),
            ("other", &self.other),
        ] {
            metrics::counter!(
                m::EBPF_PROTOCOL_PACKETS_TOTAL,
                m::LABEL_PROTOCOL => proto
            )
            .absolute(stats.packets);
        }

        // Rate metrics (gauges)
        for (proto, stats) in [
            ("tcp", &self.tcp),
            ("udp", &self.udp),
            ("icmp", &self.icmp),
            ("other", &self.other),
            ("total", &self.total),
        ] {
            metrics::gauge!(m::EBPF_PACKETS_PER_SECOND, m::LABEL_PROTOCOL => proto).set(stats.pps);
            metrics::gauge!(m::EBPF_BITS_PER_SECOND, m::LABEL_PROTOCOL => proto).set(stats.bps);
        }
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
    ///
    /// # Deprecated
    ///
    /// This method is deprecated in favor of the global `metrics` crate integration.
    /// Metrics are now automatically exported via the Prometheus exporter in `ironpost-daemon`.
    #[deprecated(
        since = "0.1.0",
        note = "Use the global metrics exporter in ironpost-daemon instead"
    )]
    pub fn to_prometheus(&self) -> String {
        let mut output = String::new();

        // 프로토콜별 메트릭 생성 헬퍼 함수
        let emit_metrics = |proto: &str, metrics: &ProtoMetrics| -> String {
            format!(
                "ironpost_packets_total{{proto=\"{}\"}} {}\n\
                 ironpost_bytes_total{{proto=\"{}\"}} {}\n\
                 ironpost_drops_total{{proto=\"{}\"}} {}\n\
                 ironpost_pps{{proto=\"{}\"}} {}\n\
                 ironpost_bps{{proto=\"{}\"}} {}\n",
                proto,
                metrics.packets,
                proto,
                metrics.bytes,
                proto,
                metrics.drops,
                proto,
                metrics.pps,
                proto,
                metrics.bps,
            )
        };

        // 각 프로토콜 메트릭 추가
        output.push_str(&emit_metrics("tcp", &self.tcp));
        output.push_str(&emit_metrics("udp", &self.udp));
        output.push_str(&emit_metrics("icmp", &self.icmp));
        output.push_str(&emit_metrics("other", &self.other));
        output.push_str(&emit_metrics("total", &self.total));

        output
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

        // u64 → f64 변환: 1초 간격 폴링이므로 delta 값은 실용적으로 2^53 미만
        // 정밀도 손실이 발생할 수 있지만 비율 계산에서는 문제없음
        #[allow(clippy::cast_precision_loss)]
        {
            metrics.pps = delta_packets as f64 / elapsed_secs;
            // bytes → bits: *8
            metrics.bps = (delta_bytes as f64 * 8.0) / elapsed_secs;
        }
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

#[cfg(test)]
mod tests {
    use super::*;

    fn render_prometheus(stats: &TrafficStats) -> String {
        #[allow(deprecated)]
        {
            stats.to_prometheus()
        }
    }

    // =============================================================================
    // RawProtoStats 테스트
    // =============================================================================

    #[test]
    fn test_raw_proto_stats_default() {
        let stats = RawProtoStats::default();
        assert_eq!(stats.packets, 0);
        assert_eq!(stats.bytes, 0);
        assert_eq!(stats.drops, 0);
    }

    #[test]
    fn test_raw_traffic_snapshot_default() {
        let snapshot = RawTrafficSnapshot::default();
        assert_eq!(snapshot.tcp.packets, 0);
        assert_eq!(snapshot.udp.packets, 0);
        assert_eq!(snapshot.icmp.packets, 0);
        assert_eq!(snapshot.other.packets, 0);
        assert_eq!(snapshot.total.packets, 0);
    }

    // =============================================================================
    // TrafficStats 초기화 테스트
    // =============================================================================

    #[test]
    fn test_traffic_stats_new_all_zeros() {
        let stats = TrafficStats::new();

        assert_eq!(stats.tcp.packets, 0);
        assert_eq!(stats.tcp.bytes, 0);
        assert_eq!(stats.tcp.drops, 0);
        assert_eq!(stats.tcp.pps, 0.0);
        assert_eq!(stats.tcp.bps, 0.0);

        assert_eq!(stats.udp.packets, 0);
        assert_eq!(stats.icmp.packets, 0);
        assert_eq!(stats.other.packets, 0);
        assert_eq!(stats.total.packets, 0);

        assert!(stats.last_poll.is_none());
        assert!(stats.prev_raw.is_none());
    }

    #[test]
    fn test_traffic_stats_default() {
        let stats = TrafficStats::default();
        assert_eq!(stats.tcp.packets, 0);
        assert_eq!(stats.total.pps, 0.0);
    }

    // =============================================================================
    // update 테스트 (첫 번째 폴링)
    // =============================================================================

    #[test]
    fn test_update_first_poll_sets_cumulative_only() {
        let mut stats = TrafficStats::new();

        let snapshot = RawTrafficSnapshot {
            tcp: RawProtoStats {
                packets: 1000,
                bytes: 64000,
                drops: 10,
            },
            udp: RawProtoStats {
                packets: 500,
                bytes: 32000,
                drops: 5,
            },
            icmp: RawProtoStats {
                packets: 100,
                bytes: 8000,
                drops: 1,
            },
            other: RawProtoStats {
                packets: 50,
                bytes: 4000,
                drops: 0,
            },
            total: RawProtoStats {
                packets: 1650,
                bytes: 108000,
                drops: 16,
            },
        };

        stats.update(snapshot);

        // 누적값은 설정되어야 함
        assert_eq!(stats.tcp.packets, 1000);
        assert_eq!(stats.tcp.bytes, 64000);
        assert_eq!(stats.tcp.drops, 10);

        // rate는 0이어야 함 (첫 번째 폴링)
        assert_eq!(stats.tcp.pps, 0.0);
        assert_eq!(stats.tcp.bps, 0.0);

        assert_eq!(stats.udp.packets, 500);
        assert_eq!(stats.udp.pps, 0.0);

        assert_eq!(stats.total.packets, 1650);
        assert_eq!(stats.total.pps, 0.0);

        // 상태 저장 확인
        assert!(stats.last_poll.is_some());
        assert!(stats.prev_raw.is_some());
    }

    // =============================================================================
    // update 테스트 (두 번째 폴링, rate 계산)
    // =============================================================================

    #[test]
    fn test_update_second_poll_calculates_rate() {
        let mut stats = TrafficStats::new();

        let snapshot1 = RawTrafficSnapshot {
            tcp: RawProtoStats {
                packets: 1000,
                bytes: 64000,
                drops: 10,
            },
            udp: RawProtoStats::default(),
            icmp: RawProtoStats::default(),
            other: RawProtoStats::default(),
            total: RawProtoStats {
                packets: 1000,
                bytes: 64000,
                drops: 10,
            },
        };

        stats.update(snapshot1);

        // 시간 경과 시뮬레이션 (내부 Instant는 직접 조작 불가하므로 짧은 sleep 사용)
        std::thread::sleep(std::time::Duration::from_millis(100));

        let snapshot2 = RawTrafficSnapshot {
            tcp: RawProtoStats {
                packets: 2000, // +1000 packets
                bytes: 128000, // +64000 bytes
                drops: 20,     // +10 drops
            },
            udp: RawProtoStats::default(),
            icmp: RawProtoStats::default(),
            other: RawProtoStats::default(),
            total: RawProtoStats {
                packets: 2000,
                bytes: 128000,
                drops: 20,
            },
        };

        stats.update(snapshot2);

        // 누적값 확인
        assert_eq!(stats.tcp.packets, 2000);
        assert_eq!(stats.tcp.bytes, 128000);
        assert_eq!(stats.tcp.drops, 20);

        // rate 확인 (대략 0.1초 동안 1000 패킷, 64000 바이트 증가)
        // pps ≈ 1000 / 0.1 = 10000 pps
        // bps ≈ 64000 * 8 / 0.1 = 5120000 bps
        // 실제 sleep 시간이 정확하지 않으므로 범위로 검증
        assert!(stats.tcp.pps > 0.0);
        assert!(stats.tcp.bps > 0.0);
        assert!(stats.tcp.pps < 100000.0); // 상한선
    }

    #[test]
    fn test_update_zero_elapsed_time_skips_rate_calculation() {
        // 이 테스트는 이론적으로 elapsed = 0인 경우를 시뮬레이션할 수 없으므로
        // update()가 내부적으로 elapsed > 0.0 체크를 하는지 확인하는 역할
        // 실제로는 항상 elapsed > 0이므로 로직 검증 목적
        let mut stats = TrafficStats::new();

        let snapshot = RawTrafficSnapshot {
            tcp: RawProtoStats {
                packets: 1000,
                bytes: 64000,
                drops: 10,
            },
            udp: RawProtoStats::default(),
            icmp: RawProtoStats::default(),
            other: RawProtoStats::default(),
            total: RawProtoStats::default(),
        };

        stats.update(snapshot.clone());

        // 즉시 다시 업데이트 (elapsed가 매우 작지만 0은 아님)
        stats.update(snapshot);

        // rate가 계산되지 않거나 매우 큰 값이 될 수 있음
        // 코드는 elapsed > 0.0 체크를 하므로 panic이 발생하지 않아야 함
        assert!(stats.tcp.packets == 1000);
    }

    // =============================================================================
    // update 테스트 (빈 데이터)
    // =============================================================================

    #[test]
    fn test_update_with_empty_snapshot() {
        let mut stats = TrafficStats::new();

        let empty_snapshot = RawTrafficSnapshot::default();

        stats.update(empty_snapshot);

        assert_eq!(stats.tcp.packets, 0);
        assert_eq!(stats.tcp.pps, 0.0);
        assert_eq!(stats.udp.packets, 0);
        assert_eq!(stats.total.packets, 0);
    }

    // =============================================================================
    // reset 테스트
    // =============================================================================

    #[test]
    fn test_reset_clears_all_state() {
        let mut stats = TrafficStats::new();

        let snapshot = RawTrafficSnapshot {
            tcp: RawProtoStats {
                packets: 1000,
                bytes: 64000,
                drops: 10,
            },
            udp: RawProtoStats::default(),
            icmp: RawProtoStats::default(),
            other: RawProtoStats::default(),
            total: RawProtoStats {
                packets: 1000,
                bytes: 64000,
                drops: 10,
            },
        };

        stats.update(snapshot);

        assert_eq!(stats.tcp.packets, 1000);
        assert!(stats.last_poll.is_some());

        stats.reset();

        assert_eq!(stats.tcp.packets, 0);
        assert_eq!(stats.tcp.bytes, 0);
        assert_eq!(stats.tcp.pps, 0.0);
        assert_eq!(stats.tcp.bps, 0.0);
        assert!(stats.last_poll.is_none());
        assert!(stats.prev_raw.is_none());
    }

    // =============================================================================
    // to_prometheus 테스트
    // =============================================================================

    #[test]
    fn test_to_prometheus_format() {
        let mut stats = TrafficStats::new();

        stats.tcp.packets = 12345;
        stats.tcp.bytes = 678900;
        stats.tcp.drops = 42;
        stats.tcp.pps = 1234.5;
        stats.tcp.bps = 5678000.0;

        stats.udp.packets = 5000;
        stats.udp.bytes = 250000;
        stats.udp.drops = 10;
        stats.udp.pps = 500.0;
        stats.udp.bps = 2000000.0;

        let output = render_prometheus(&stats);

        // TCP 메트릭 확인
        assert!(output.contains(r#"ironpost_packets_total{proto="tcp"} 12345"#));
        assert!(output.contains(r#"ironpost_bytes_total{proto="tcp"} 678900"#));
        assert!(output.contains(r#"ironpost_drops_total{proto="tcp"} 42"#));
        assert!(output.contains(r#"ironpost_pps{proto="tcp"} 1234.5"#));
        assert!(output.contains(r#"ironpost_bps{proto="tcp"} 5678000"#));

        // UDP 메트릭 확인
        assert!(output.contains(r#"ironpost_packets_total{proto="udp"} 5000"#));
        assert!(output.contains(r#"ironpost_bytes_total{proto="udp"} 250000"#));

        // 모든 프로토콜 라벨 확인
        assert!(output.contains(r#"proto="tcp""#));
        assert!(output.contains(r#"proto="udp""#));
        assert!(output.contains(r#"proto="icmp""#));
        assert!(output.contains(r#"proto="other""#));
        assert!(output.contains(r#"proto="total""#));
    }

    #[test]
    fn test_to_prometheus_zero_values() {
        let stats = TrafficStats::new();
        let output = render_prometheus(&stats);

        // 제로 값도 출력되어야 함
        assert!(output.contains(r#"ironpost_packets_total{proto="tcp"} 0"#));
        assert!(output.contains(r#"ironpost_pps{proto="tcp"} 0"#));
    }

    #[test]
    fn test_to_prometheus_all_protocols() {
        let mut stats = TrafficStats::new();

        stats.tcp.packets = 100;
        stats.udp.packets = 200;
        stats.icmp.packets = 300;
        stats.other.packets = 400;
        stats.total.packets = 1000;

        let output = render_prometheus(&stats);

        // 각 프로토콜별 메트릭 존재 확인
        assert!(output.contains(r#"proto="tcp""#));
        assert!(output.contains(r#"proto="udp""#));
        assert!(output.contains(r#"proto="icmp""#));
        assert!(output.contains(r#"proto="other""#));
        assert!(output.contains(r#"proto="total""#));

        // 패킷 수 확인
        assert!(output.contains(r#"ironpost_packets_total{proto="tcp"} 100"#));
        assert!(output.contains(r#"ironpost_packets_total{proto="udp"} 200"#));
        assert!(output.contains(r#"ironpost_packets_total{proto="icmp"} 300"#));
        assert!(output.contains(r#"ironpost_packets_total{proto="other"} 400"#));
        assert!(output.contains(r#"ironpost_packets_total{proto="total"} 1000"#));
    }

    // =============================================================================
    // 경계값 테스트
    // =============================================================================

    #[test]
    fn test_update_with_max_values() {
        let mut stats = TrafficStats::new();

        let snapshot = RawTrafficSnapshot {
            tcp: RawProtoStats {
                packets: u64::MAX,
                bytes: u64::MAX,
                drops: u64::MAX,
            },
            udp: RawProtoStats::default(),
            icmp: RawProtoStats::default(),
            other: RawProtoStats::default(),
            total: RawProtoStats {
                packets: u64::MAX,
                bytes: u64::MAX,
                drops: u64::MAX,
            },
        };

        stats.update(snapshot);

        assert_eq!(stats.tcp.packets, u64::MAX);
        assert_eq!(stats.tcp.bytes, u64::MAX);
        assert_eq!(stats.tcp.drops, u64::MAX);
    }

    #[test]
    fn test_update_saturating_sub_prevents_underflow() {
        let mut stats = TrafficStats::new();

        let snapshot1 = RawTrafficSnapshot {
            tcp: RawProtoStats {
                packets: 1000,
                bytes: 64000,
                drops: 10,
            },
            udp: RawProtoStats::default(),
            icmp: RawProtoStats::default(),
            other: RawProtoStats::default(),
            total: RawProtoStats::default(),
        };

        stats.update(snapshot1);

        std::thread::sleep(std::time::Duration::from_millis(50));

        // 두 번째 스냅샷이 첫 번째보다 작은 경우 (카운터 리셋 시나리오)
        let snapshot2 = RawTrafficSnapshot {
            tcp: RawProtoStats {
                packets: 500, // 감소
                bytes: 32000, // 감소
                drops: 5,     // 감소
            },
            udp: RawProtoStats::default(),
            icmp: RawProtoStats::default(),
            other: RawProtoStats::default(),
            total: RawProtoStats::default(),
        };

        stats.update(snapshot2);

        // saturating_sub로 인해 delta는 0이 되고 rate도 0이 됨
        assert_eq!(stats.tcp.pps, 0.0);
        assert_eq!(stats.tcp.bps, 0.0);

        // 누적값은 현재 값으로 업데이트됨
        assert_eq!(stats.tcp.packets, 500);
    }

    // =============================================================================
    // 여러 업데이트 연속 테스트
    // =============================================================================

    #[test]
    fn test_multiple_updates_accumulate_correctly() {
        let mut stats = TrafficStats::new();

        for i in 1..=5 {
            let snapshot = RawTrafficSnapshot {
                tcp: RawProtoStats {
                    packets: i * 1000,
                    bytes: i * 64000,
                    drops: i * 10,
                },
                udp: RawProtoStats::default(),
                icmp: RawProtoStats::default(),
                other: RawProtoStats::default(),
                total: RawProtoStats {
                    packets: i * 1000,
                    bytes: i * 64000,
                    drops: i * 10,
                },
            };

            stats.update(snapshot);
            std::thread::sleep(std::time::Duration::from_millis(50));
        }

        assert_eq!(stats.tcp.packets, 5000);
        assert_eq!(stats.tcp.bytes, 320000);
        assert!(stats.tcp.pps > 0.0); // rate가 계산되었어야 함
    }
}

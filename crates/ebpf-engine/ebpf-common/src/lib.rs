//! eBPF 커널/유저스페이스 공유 타입
//!
//! 이 크레이트는 `#![no_std]` 환경에서 사용 가능한 공통 타입을 정의합니다.
//! eBPF 커널 프로그램과 유저스페이스가 동일한 메모리 레이아웃(`#[repr(C)]`)을
//! 사용하도록 보장합니다.
//!
//! # 맵 타입 선택 근거
//! - **HashMap** (`BLOCKLIST`): IP 차단 목록 — O(1) 조회, 유저스페이스에서 동적 업데이트
//! - **PerCpuArray** (`STATS`): 프로토콜별 통계 — CPU별 독립 카운터, 락 프리 고성능
//! - **RingBuf** (`EVENTS`): 이벤트 전달 — 고성능 가변 크기 메시지, PerfEventArray보다 효율적

#![no_std]

// =============================================================================
// 맵 이름 상수
// =============================================================================

/// 차단 목록 HashMap 맵 이름
pub const MAP_BLOCKLIST: &str = "BLOCKLIST";
/// 통계 PerCpuArray 맵 이름
pub const MAP_STATS: &str = "STATS";
/// 이벤트 RingBuf 맵 이름
pub const MAP_EVENTS: &str = "EVENTS";

// =============================================================================
// 프로토콜 상수
// =============================================================================

/// ICMP 프로토콜 번호
pub const PROTO_ICMP: u8 = 1;
/// TCP 프로토콜 번호
pub const PROTO_TCP: u8 = 6;
/// UDP 프로토콜 번호
pub const PROTO_UDP: u8 = 17;

// =============================================================================
// Stats 맵 인덱스 (PerCpuArray)
// =============================================================================

/// TCP 통계 인덱스
pub const STATS_IDX_TCP: u32 = 0;
/// UDP 통계 인덱스
pub const STATS_IDX_UDP: u32 = 1;
/// ICMP 통계 인덱스
pub const STATS_IDX_ICMP: u32 = 2;
/// 기타 프로토콜 통계 인덱스
pub const STATS_IDX_OTHER: u32 = 3;
/// 전체 합계 통계 인덱스
pub const STATS_IDX_TOTAL: u32 = 4;
/// PerCpuArray 최대 엔트리 수
pub const STATS_MAX_ENTRIES: u32 = 5;

// =============================================================================
// 액션 코드 (RingBuf 이벤트 + 차단 목록)
// =============================================================================

/// 패킷 통과
pub const ACTION_PASS: u8 = 0;
/// 패킷 차단 (XDP_DROP)
pub const ACTION_DROP: u8 = 1;
/// 패킷 통과 + 모니터링 (이벤트 전송)
pub const ACTION_MONITOR: u8 = 2;

// =============================================================================
// TCP 플래그
// =============================================================================

/// FIN 플래그
pub const TCP_FIN: u8 = 0x01;
/// SYN 플래그
pub const TCP_SYN: u8 = 0x02;
/// RST 플래그
pub const TCP_RST: u8 = 0x04;
/// PSH 플래그
pub const TCP_PSH: u8 = 0x08;
/// ACK 플래그
pub const TCP_ACK: u8 = 0x10;

// =============================================================================
// 공유 데이터 구조
// =============================================================================

/// 차단 목록 값
///
/// `HashMap<u32, BlocklistValue>` 맵에서 사용됩니다.
/// 키는 IPv4 주소 (네트워크 바이트 오더, `u32`)입니다.
///
/// # 맵 선택 근거
/// HashMap은 O(1) 키-값 조회를 제공하여 패킷당 차단 여부를 빠르게 판단합니다.
/// 유저스페이스에서 동적으로 엔트리를 추가/삭제할 수 있어 런타임 룰 업데이트가 가능합니다.
#[repr(C)]
#[derive(Clone, Copy)]
#[cfg_attr(feature = "user", derive(Debug))]
pub struct BlocklistValue {
    /// 적용할 액션 (ACTION_DROP 또는 ACTION_MONITOR)
    pub action: u8,
    /// 4바이트 정렬을 위한 패딩
    pub _pad: [u8; 3],
}

// SAFETY: BlocklistValue는 #[repr(C)]이며 모든 필드가 Plain Old Data입니다.
// 메모리 정렬이 보장되고 패딩도 명시적으로 정의되어 있습니다.
#[cfg(feature = "user")]
unsafe impl aya::Pod for BlocklistValue {}

/// 프로토콜별 통계 카운터
///
/// `PerCpuArray<ProtoStats>` 맵에서 사용됩니다.
///
/// # 맵 선택 근거
/// PerCpuArray는 CPU별 독립 카운터를 제공하여 락 없이 고성능 통계 수집이 가능합니다.
/// 각 CPU가 자신의 인스턴스만 업데이트하므로 캐시 라인 경합이 없습니다.
/// 유저스페이스에서 모든 CPU의 값을 합산하여 전체 통계를 계산합니다.
#[repr(C)]
#[derive(Clone, Copy)]
#[cfg_attr(feature = "user", derive(Debug))]
pub struct ProtoStats {
    /// 처리된 패킷 수
    pub packets: u64,
    /// 전송 바이트 수
    pub bytes: u64,
    /// 드롭된 패킷 수
    pub drops: u64,
}

// SAFETY: ProtoStats는 #[repr(C)]이며 모든 필드가 Plain Old Data입니다.
#[cfg(feature = "user")]
unsafe impl aya::Pod for ProtoStats {}

/// 의심 패킷 이벤트 데이터
///
/// `RingBuf`를 통해 커널 → 유저스페이스로 전달됩니다.
///
/// # 맵 선택 근거
/// RingBuf는 PerfEventArray보다 효율적인 가변 크기 이벤트 전달을 지원합니다.
/// 단일 링 버퍼를 모든 CPU가 공유하여 메모리 효율이 높고,
/// 커널 5.8+에서 지원되는 최신 메커니즘입니다.
///
/// # 메모리 레이아웃 (20 바이트, 4바이트 정렬)
/// ```text
/// offset  field       size
/// 0       src_ip      4
/// 4       dst_ip      4
/// 8       src_port    2
/// 10      dst_port    2
/// 12      pkt_len     2
/// 14      protocol    1
/// 15      action      1
/// 16      tcp_flags   1
/// 17      _pad        3
/// ```
#[repr(C)]
#[derive(Clone, Copy)]
#[cfg_attr(feature = "user", derive(Debug))]
pub struct PacketEventData {
    /// 출발지 IPv4 주소 (네트워크 바이트 오더)
    pub src_ip: u32,
    /// 목적지 IPv4 주소 (네트워크 바이트 오더)
    pub dst_ip: u32,
    /// 출발지 포트 (네트워크 바이트 오더)
    pub src_port: u16,
    /// 목적지 포트 (네트워크 바이트 오더)
    pub dst_port: u16,
    /// 패킷 길이 (바이트)
    pub pkt_len: u16,
    /// IP 프로토콜 번호 (PROTO_TCP, PROTO_UDP, PROTO_ICMP)
    pub protocol: u8,
    /// 적용된 액션 (ACTION_PASS, ACTION_DROP, ACTION_MONITOR)
    pub action: u8,
    /// TCP 플래그 (TCP 패킷인 경우, 0이면 비-TCP)
    pub tcp_flags: u8,
    /// 4바이트 정렬을 위한 패딩
    pub _pad: [u8; 3],
}

// SAFETY: PacketEventData는 #[repr(C)]이며 모든 필드가 Plain Old Data입니다.
#[cfg(feature = "user")]
unsafe impl aya::Pod for PacketEventData {}

/// ProtoStats의 제로 초기화를 반환합니다.
impl ProtoStats {
    /// 제로 초기화된 통계를 생성합니다.
    pub const fn zeroed() -> Self {
        Self {
            packets: 0,
            bytes: 0,
            drops: 0,
        }
    }
}

/// PacketEventData의 제로 초기화를 반환합니다.
impl PacketEventData {
    /// 제로 초기화된 이벤트 데이터를 생성합니다.
    pub const fn zeroed() -> Self {
        Self {
            src_ip: 0,
            dst_ip: 0,
            src_port: 0,
            dst_port: 0,
            pkt_len: 0,
            protocol: 0,
            action: 0,
            tcp_flags: 0,
            _pad: [0; 3],
        }
    }
}

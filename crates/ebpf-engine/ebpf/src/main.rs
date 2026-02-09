//! Ironpost XDP 패킷 필터 프로그램
//!
//! 네트워크 인터페이스에 어태치되어 모든 수신 패킷을 검사합니다.
//!
//! # 처리 흐름
//! 1. Ethernet 헤더 파싱 → IPv4만 처리
//! 2. IPv4 헤더 파싱 → src_ip, dst_ip, protocol 추출
//! 3. TCP/UDP 헤더 파싱 → 포트, TCP 플래그 추출
//! 4. 차단 목록(HashMap) 조회 → 매칭 시 XDP_DROP
//! 5. 프로토콜별 통계(PerCpuArray) 업데이트
//! 6. 의심 패킷 이벤트(RingBuf)로 유저스페이스 전달
//!
//! # BPF 맵
//! - `BLOCKLIST`: HashMap<u32, BlocklistValue> — IP 차단 목록
//! - `STATS`: PerCpuArray<ProtoStats> — 프로토콜별 패킷/바이트/드롭 카운터
//! - `EVENTS`: RingBuf — 의심 패킷 이벤트를 유저스페이스로 전달
//!
//! # 네트워크 헤더
//! 헤더 구조체는 [`network_types`] 크레이트를 사용합니다.
//! `EthHdr`, `Ipv4Hdr`, `TcpHdr`, `UdpHdr` — `#![no_std]` 호환, Aya 에코시스템 표준.

#![no_std]
#![no_main]

use aya_ebpf::{
    bindings::xdp_action,
    macros::{map, xdp},
    maps::{HashMap, PerCpuArray, RingBuf},
    programs::XdpContext,
};
use aya_log_ebpf::info;
use core::mem;

use network_types::eth::{EthHdr, EtherType};
use network_types::ip::{IpProto, Ipv4Hdr};
use network_types::tcp::TcpHdr;
use network_types::udp::UdpHdr;

use ironpost_ebpf_common::{
    ACTION_DROP, ACTION_MONITOR, ACTION_PASS, BlocklistValue, PacketEventData, ProtoStats,
    STATS_IDX_ICMP, STATS_IDX_OTHER, STATS_IDX_TCP, STATS_IDX_TOTAL, STATS_IDX_UDP,
    STATS_MAX_ENTRIES, TCP_ACK, TCP_FIN, TCP_PSH, TCP_RST, TCP_SYN,
};

// =============================================================================
// eBPF 맵 정의
// =============================================================================

/// IP 차단 목록
///
/// - 키: IPv4 주소 (u32, 네트워크 바이트 오더)
/// - 값: BlocklistValue (액션 코드)
/// - 맵 선택 근거: O(1) 조회, 유저스페이스에서 동적 업데이트 가능
#[map]
static BLOCKLIST: HashMap<u32, BlocklistValue> = HashMap::with_max_entries(10_000, 0);

/// 프로토콜별 통계 카운터
///
/// - 인덱스: STATS_IDX_TCP(0), STATS_IDX_UDP(1), STATS_IDX_ICMP(2),
///           STATS_IDX_OTHER(3), STATS_IDX_TOTAL(4)
/// - 맵 선택 근거: CPU별 독립 카운터, 락 프리, 캐시 라인 경합 없음
#[map]
static STATS: PerCpuArray<ProtoStats> = PerCpuArray::with_max_entries(STATS_MAX_ENTRIES, 0);

/// 의심 패킷 이벤트 링 버퍼
///
/// - 크기: 256KB (설정으로 변경 가능)
/// - 맵 선택 근거: PerfEventArray보다 효율적, 가변 크기 메시지, 단일 버퍼 공유
#[map]
static EVENTS: RingBuf = RingBuf::with_byte_size(256 * 1024, 0);

// =============================================================================
// XDP 엔트리 포인트
// =============================================================================

/// XDP 패킷 필터 엔트리 포인트
///
/// 네트워크 인터페이스에 어태치되어 모든 수신 패킷을 검사합니다.
/// 에러 발생 시 XDP_ABORTED를 반환하여 패킷을 드롭하고 추적합니다.
#[xdp]
pub fn ironpost_xdp(ctx: XdpContext) -> u32 {
    match try_ironpost_xdp(ctx) {
        Ok(ret) => ret,
        Err(_) => xdp_action::XDP_ABORTED,
    }
}

/// 메인 패킷 처리 로직
///
/// 패킷을 파싱하고 차단 여부를 결정합니다.
fn try_ironpost_xdp(ctx: XdpContext) -> Result<u32, u32> {
    let data = ctx.data();
    let data_end = ctx.data_end();
    // 점보 프레임 지원을 위해 u32로 저장
    let pkt_len: u32 = (data_end - data) as u32;

    // 1) Ethernet 헤더 파싱
    let eth = ptr_at::<EthHdr>(&ctx, 0).ok_or(0u32)?;

    // IPv4만 처리 (IPv6은 Phase 2 확장 범위)
    // EtherType enum은 네트워크 바이트 오더로 미리 인코딩되어 있어
    // from_be() 변환 없이 바로 비교 가능
    // SAFETY: 바운드 체크를 ptr_at에서 수행했으므로 포인터 접근이 안전합니다
    if unsafe { (*eth).ether_type } != EtherType::Ipv4 as u16 {
        return Ok(xdp_action::XDP_PASS);
    }

    // 2) IPv4 헤더 파싱
    let ipv4 = ptr_at::<Ipv4Hdr>(&ctx, EthHdr::LEN).ok_or(0u32)?;
    // SAFETY: ptr_at 바운드 체크 통과
    // network-types는 IP 주소를 [u8; 4]로 저장 → u32로 변환 (네트워크 바이트 오더 유지)
    let src_ip = unsafe { u32::from_ne_bytes((*ipv4).src_addr) };
    let dst_ip = unsafe { u32::from_ne_bytes((*ipv4).dst_addr) };
    let proto = unsafe { (*ipv4).proto };
    let ihl = (unsafe { (*ipv4).vihl } & 0x0F) as usize;
    let ip_hdr_len = ihl * 4;

    // IHL 유효성 검증 (최소 5, 최대 15)
    if ihl < 5 || ihl > 15 {
        return Ok(xdp_action::XDP_PASS);
    }

    let transport_offset = EthHdr::LEN + ip_hdr_len;

    // 3) TCP/UDP 헤더 파싱 → 포트 + TCP 플래그 추출
    let mut src_port: u16 = 0;
    let mut dst_port: u16 = 0;
    let mut tcp_flags: u8 = 0;

    match proto {
        IpProto::Tcp => {
            if let Some(tcp) = ptr_at::<TcpHdr>(&ctx, transport_offset) {
                // SAFETY: ptr_at 바운드 체크 통과
                // network-types: 포트는 [u8; 2], TCP 플래그는 비트필드 접근자
                unsafe {
                    src_port = u16::from_be_bytes((*tcp).source);
                    dst_port = u16::from_be_bytes((*tcp).dest);

                    // 비트필드 접근자로 TCP 플래그 바이트 재구성
                    tcp_flags = 0;
                    if (*tcp).fin() != 0 {
                        tcp_flags |= TCP_FIN;
                    }
                    if (*tcp).syn() != 0 {
                        tcp_flags |= TCP_SYN;
                    }
                    if (*tcp).rst() != 0 {
                        tcp_flags |= TCP_RST;
                    }
                    if (*tcp).psh() != 0 {
                        tcp_flags |= TCP_PSH;
                    }
                    if (*tcp).ack() != 0 {
                        tcp_flags |= TCP_ACK;
                    }
                }
            }
        }
        IpProto::Udp => {
            if let Some(udp) = ptr_at::<UdpHdr>(&ctx, transport_offset) {
                // SAFETY: ptr_at 바운드 체크 통과
                // network-types: UdpHdr 포트 필드명은 src/dst ([u8; 2])
                unsafe {
                    src_port = u16::from_be_bytes((*udp).src);
                    dst_port = u16::from_be_bytes((*udp).dst);
                }
            }
        }
        _ => {} // ICMP 등: 포트 없음, tcp_flags=0 유지
    }

    // 4) 차단 목록 조회
    let mut action = ACTION_PASS;
    // SAFETY: HashMap 맵 접근 후 Option으로 null 체크 수행
    let blocked = unsafe { BLOCKLIST.get(&src_ip) };
    if let Some(entry) = blocked {
        action = entry.action;
    }

    // 5) 프로토콜별 통계 업데이트
    let stats_idx = match proto {
        IpProto::Tcp => STATS_IDX_TCP,
        IpProto::Udp => STATS_IDX_UDP,
        IpProto::Icmp => STATS_IDX_ICMP,
        _ => STATS_IDX_OTHER,
    };
    update_stats(stats_idx, pkt_len, action);
    update_stats(STATS_IDX_TOTAL, pkt_len, action);

    // 6) 의심 패킷 또는 모니터링 대상 → RingBuf로 이벤트 전송
    if action == ACTION_DROP || action == ACTION_MONITOR {
        let event = PacketEventData {
            src_ip,
            dst_ip,
            src_port,
            dst_port,
            pkt_len,
            protocol: proto as u8,
            action,
            tcp_flags,
            _pad: [0; 1],
        };
        emit_event(&event);
    }

    // 7) 최종 결정
    if action == ACTION_DROP {
        info!(&ctx, "DROP src={:i}", u32::from_be(src_ip));
        Ok(xdp_action::XDP_DROP)
    } else {
        Ok(xdp_action::XDP_PASS)
    }
}

// =============================================================================
// 헬퍼 함수
// =============================================================================

/// 패킷 버퍼에서 타입 T의 포인터를 안전하게 획득합니다.
///
/// BPF verifier가 요구하는 바운드 체크를 수행합니다.
/// `data + offset + sizeof(T) <= data_end`를 만족해야 합니다.
#[inline(always)]
fn ptr_at<T>(ctx: &XdpContext, offset: usize) -> Option<*const T> {
    let start = ctx.data();
    let end = ctx.data_end();
    let len = mem::size_of::<T>();

    if start + offset + len > end {
        return None;
    }

    Some((start + offset) as *const T)
}

/// PerCpuArray 통계 카운터를 업데이트합니다.
///
/// CPU별 독립 카운터이므로 락 없이 안전하게 업데이트됩니다.
#[inline(always)]
fn update_stats(idx: u32, pkt_len: u32, action: u8) {
    // SAFETY: PerCpuArray 맵 접근 후 null 체크 수행.
    // get_ptr_mut는 현재 CPU의 엔트리에 대한 가변 포인터를 반환합니다.
    unsafe {
        let stats_ptr = STATS.get_ptr_mut(idx);
        if let Some(stats) = stats_ptr {
            (*stats).packets += 1;
            (*stats).bytes += pkt_len as u64;
            if action == ACTION_DROP {
                (*stats).drops += 1;
            }
        }
    }
}

/// RingBuf를 통해 패킷 이벤트를 유저스페이스로 전송합니다.
///
/// 버퍼가 가득 찬 경우 이벤트는 드롭됩니다 (성능 우선).
#[inline(always)]
fn emit_event(event: &PacketEventData) {
    // SAFETY: RingBuf에 PacketEventData 크기만큼 예약 후 데이터를 기록합니다.
    // reserve 실패(버퍼 부족) 시 조용히 무시합니다.
    if let Some(mut entry) = EVENTS.reserve::<PacketEventData>(0) {
        entry.write(*event);
        entry.submit(0);
    }
}

#[cfg(not(test))]
#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    loop {}
}

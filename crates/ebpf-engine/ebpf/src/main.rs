#![no_std]
#![no_main]

use aya_ebpf::{bindings::xdp_action, macros::xdp, programs::XdpContext};
use aya_log_ebpf::info;

/// XDP 패킷 필터 프로그램
///
/// 네트워크 인터페이스에 어태치되어 모든 수신 패킷을 검사합니다.
#[xdp]
pub fn ironpost_xdp(ctx: XdpContext) -> u32 {
    match try_ironpost_xdp(ctx) {
        Ok(ret) => ret,
        Err(_) => xdp_action::XDP_ABORTED,
    }
}

fn try_ironpost_xdp(ctx: XdpContext) -> Result<u32, u32> {
    info!(&ctx, "received a packet");
    Ok(xdp_action::XDP_PASS)
}

#[cfg(not(test))]
#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    loop {}
}

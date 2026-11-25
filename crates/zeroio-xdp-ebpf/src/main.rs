#![no_std]
#![no_main]

use aya_ebpf::{
    bindings::xdp_action,
    macros::{map, xdp},
    maps::{PerCpuArray, XskMap},
    programs::XdpContext,
};
use zeroio_xdp_common::XdpCounters;

#[map(name = "ZEROIO_COUNTERS")]
static ZEROIO_COUNTERS: PerCpuArray<XdpCounters> =
    PerCpuArray::<XdpCounters>::with_max_entries(1, 0);

#[map(name = "ZEROIO_XSKS")]
static ZEROIO_XSKS: XskMap = XskMap::with_max_entries(4096, 0);

#[xdp]
pub fn zeroio_xdp(ctx: XdpContext) -> u32 {
    let _ = &ZEROIO_XSKS;
    if let Some(counters) = ZEROIO_COUNTERS.get_ptr_mut(0) {
        // SAFETY: PerCpuArray slot 0 is exclusively owned by the executing CPU.
        unsafe {
            (*counters).packets = (*counters).packets.saturating_add(1);
            (*counters).passed = (*counters).passed.saturating_add(1);
        }
    }
    let _ = ctx;
    xdp_action::XDP_PASS
}

#[cfg(not(test))]
#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    loop {}
}

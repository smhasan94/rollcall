//! Hand-written fixture firmware (SHA-127): uses every runtime dependency so each is linked.
#![no_std]
#![no_main]

use cortex_m_rt::entry;
use panic_halt as _;

#[entry]
fn main() -> ! {
    let mut tick: u32 = board_support::LED_PIN;
    loop {
        tick = core::hint::black_box(tick.wrapping_add(1));
    }
}

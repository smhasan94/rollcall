//! Hand-written fixture firmware (SHA-127): links the deliberately old heapless 0.5.6.
#![no_std]
#![no_main]

use cortex_m_rt::entry;
use heapless::consts::U8;
use heapless::Vec;
use panic_halt as _;

#[entry]
fn main() -> ! {
    let mut samples: Vec<u32, U8> = Vec::new();
    let mut tick: u32 = 0;
    loop {
        tick = core::hint::black_box(tick.wrapping_add(1));
        if samples.push(tick).is_err() {
            samples.clear();
        }
    }
}

use aya_ebpf::macros::map;
use aya_ebpf::maps::RingBuf;

// Increase ringbuf size to better handle short bursts without dropping events.
#[map(name = "EVENTS")]
pub static mut EVENTS: RingBuf = RingBuf::with_byte_size(8 * 1024 * 1024, 0);

#[map(name = "EXEC_EVENTS")]
pub static mut EXEC_EVENTS: RingBuf = RingBuf::with_byte_size(4 * 1024 * 1024, 0);

#[map(name = "EXIT_EVENTS")]
pub static mut EXIT_EVENTS: RingBuf = RingBuf::with_byte_size(4 * 1024 * 1024, 0);


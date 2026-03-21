use aya_ebpf::macros::map;
use aya_ebpf::maps::{HashMap, RingBuf};

// Increase ringbuf size to better handle short bursts without dropping events.
#[map(name = "EVENTS")]
pub static mut EVENTS: RingBuf = RingBuf::with_byte_size(8 * 1024 * 1024, 0);

#[map(name = "EXEC_EVENTS")]
pub static mut EXEC_EVENTS: RingBuf = RingBuf::with_byte_size(4 * 1024 * 1024, 0);

#[map(name = "EXIT_EVENTS")]
pub static mut EXIT_EVENTS: RingBuf = RingBuf::with_byte_size(4 * 1024 * 1024, 0);

/// XDP 五元组事件输出。
#[map(name = "FLOW_EVENTS")]
pub static mut FLOW_EVENTS: RingBuf = RingBuf::with_byte_size(16 * 1024 * 1024, 0);

/// 需要跳过的 IPv4 地址（源/目的都可能检查）。
///
/// value 只是占位，用 1 表示命中。
#[map(name = "SKIP_IPS")]
pub static mut SKIP_IPS: HashMap<u32, u8> = HashMap::with_max_entries(1024, 0);

/// 本机 IPv4 地址集合（用于判断 inbound/outbound）。
///
/// value 只是占位，用 1 表示命中。
#[map(name = "LOCAL_IPS")]
pub static mut LOCAL_IPS: HashMap<u32, u8> = HashMap::with_max_entries(64, 0);


use aya_ebpf::macros::map;
use aya_ebpf::maps::{HashMap, RingBuf};
use hids_common::TlsFdKey;

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

/// TLS 明文事件输出（OpenSSL SSL_write/SSL_read）。
#[map(name = "TLS_EVENTS")]
pub static mut TLS_EVENTS: RingBuf = RingBuf::with_byte_size(16 * 1024 * 1024, 0);

/// `SSL_read` 入参与返回配对：key=`pid_tgid`, value=buf_ptr(u64)。
#[map(name = "TLS_READ_ARGS")]
pub static mut TLS_READ_ARGS: HashMap<u64, u64> = HashMap::with_max_entries(32768, 0);

/// `SSL_read` 入参与返回配对：key=`pid_tgid`, value=ssl_ptr(u64)。
#[map(name = "TLS_READ_SSLPTR")]
pub static mut TLS_READ_SSLPTR: HashMap<u64, u64> = HashMap::with_max_entries(32768, 0);

/// OpenSSL `SSL*` -> fd 关联（key 包含 tgid + ssl_ptr）。
#[map(name = "TLS_SSL_FD")]
pub static mut TLS_SSL_FD: HashMap<TlsFdKey, i32> = HashMap::with_max_entries(65536, 0);

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

/// XDP 需要重点关注的目标端口集合（value=1 占位）。
#[map(name = "SENSITIVE_PORTS")]
pub static mut SENSITIVE_PORTS: HashMap<u16, u8> = HashMap::with_max_entries(1024, 0);

/// 是否全端口采集（key 固定为 0，value=1 表示开启）。
#[map(name = "CAPTURE_ALL_PORTS")]
pub static mut CAPTURE_ALL_PORTS: HashMap<u8, u8> = HashMap::with_max_entries(1, 0);

#![no_std]

pub const COMM_LEN: usize = 16;
pub const MAX_LINE: usize = 256;
/// `execve` 路径缓冲（与 eBPF / 用户态 ABI 一致）。
pub const MAX_EXEC_PATH: usize = 256;
/// TLS 明文截断长度（HTTPS 解密后只取前 N 字节用于检测/解析）。
///
/// 说明：这里是每次 `SSL_read`/`SSL_write` 事件能携带的最大明文字节数，
/// 并不代表会“全量留存”。用户态仍会做截断/脱敏/过滤后再上报。
pub const TLS_DATA_MAX: usize = 2048;

/// Bash 命令行捕获事件（用于从 eBPF 上报到用户态）。
///
/// 这是一个“最小可验证”的 HIDS 事件：能够证明我们已经成功挂载 uretprobe，
/// 并把用户输入的命令行从内核侧传回用户态。
#[repr(C)]
#[derive(Clone, Copy, Debug)]
pub struct CommandEvent {
    /// 线程 pid（下 32 位）。
    pub pid: u32,
    /// 进程 tgid（上 32 位），即通常意义上的进程号。
    pub tgid: u32,
    /// 用户 ID。
    pub uid: u32,
    /// 进程名（comm），最多 16 字节。
    pub comm: [u8; COMM_LEN],
    /// readline 返回的命令行内容（以 NUL 结尾；不足部分为 0）。
    pub line: [u8; MAX_LINE],
    /// `line` 的有效长度（包含 NUL 时也会算在内；具体取决于 helper 返回值）。
    pub len: u32,
}

/// execve（进程启动）事件：含可执行文件路径（从 `sys_enter_execve` 的 `filename` 指针读取）。
#[repr(C)]
#[derive(Clone, Copy, Debug)]
pub struct ExecEvent {
    /// 线程 pid（下 32 位）
    pub pid: u32,
    /// 进程 tgid（上 32 位）
    pub tgid: u32,
    /// 用户 ID
    pub uid: u32,
    /// 当前进程名（comm），16 字节
    pub comm: [u8; COMM_LEN],
    /// `execve` 的 `filename` 字符串（NUL 结尾；不足部分为 0）
    pub filename: [u8; MAX_EXEC_PATH],
    /// `filename` 有效长度（含 NUL 时取决于 helper 返回值）
    pub filename_len: u32,
}

/// 进程退出事件（exit/exit_group），携带 exit code。
#[repr(C)]
#[derive(Clone, Copy, Debug)]
pub struct ExitEvent {
    /// 线程 pid（下 32 位）
    pub pid: u32,
    /// 进程 tgid（上 32 位）
    pub tgid: u32,
    /// 用户 ID
    pub uid: u32,
    /// 当前进程名（comm），16 字节
    pub comm: [u8; COMM_LEN],
    /// 退出码（尽量按 i32 记录；通常 0 表示成功）
    pub exit_code: i32,
}

/// XDP 五元组流量事件（IPv4 + TCP/UDP）。
///
/// 说明：这里发的是“每个符合条件的数据包”的五元组，而不是聚合统计。
/// 后续如果你想降低发送量，可以把内核改成聚合后再发送。
#[repr(C)]
#[derive(Clone, Copy, Debug)]
pub struct FlowEvent {
    pub ts: u64,
    pub src_ip: u32,
    pub dst_ip: u32,
    pub src_port: u16,
    pub dst_port: u16,
    /// IP 协议号：6=TCP，17=UDP
    pub proto: u8,
    /// TCP flags（仅当 proto=TCP 时有效）：SYN/ACK/RST/FIN/PSH/URG 等位图
    pub tcp_flags: u8,
    /// 方向：0=unknown 1=inbound 2=outbound
    pub direction: u8,
    /// dst_port 是否属于敏感端口（监控端口列表）
    pub is_sensitive_port: u8,
    /// IP 头部之后的传输层长度（粗略）
    pub payload_len: u32,
}

/// TLS 连接 fd 关联键：`tgid + ssl_ptr`。
#[repr(C)]
#[derive(Clone, Copy, Debug)]
pub struct TlsFdKey {
    pub tgid: u32,
    pub ssl_ptr: u64,
}

/// OpenSSL 明文事件（`SSL_write` / `SSL_read`）。
#[repr(C)]
#[derive(Clone, Copy, Debug)]
pub struct TlsEvent {
    pub pid: u32,
    pub tgid: u32,
    pub uid: u32,
    pub comm: [u8; COMM_LEN],
    /// OpenSSL `SSL*` 指针（作为连接/会话级别的关联键；不同连接通常不同）。
    ///
    /// 注意：这是实现细节字段，仅用于在用户态做“同连接重组/去重”，不要当作稳定标识跨机器/跨重启持久化。
    pub ssl_ptr: u64,
    /// OpenSSL 连接对应的 FD（通过 `SSL_set_fd` 等函数记录），未知时为 -1。
    pub fd: i32,
    /// 0=SSL_write(发送明文) 1=SSL_read(接收解密后明文)
    pub direction: u8,
    /// `data` 有效长度（<= TLS_DATA_MAX）
    pub len: u32,
    pub data: [u8; TLS_DATA_MAX],
}


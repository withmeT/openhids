#![no_std]

pub const COMM_LEN: usize = 16;
pub const MAX_LINE: usize = 256;

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

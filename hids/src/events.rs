use serde::{Deserialize, Serialize};

/// 单条从 eBPF ringbuf 拉取到用户态的“命令事件”，随后会被 batch/压缩后发送到接收端。
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AgentEvent {
    pub ts_ms: u64,
    pub uid: u32,
    pub tgid: u32,
    pub pid: u32,
    pub comm: String,
    pub line: String,
}


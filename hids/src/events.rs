use serde::{Deserialize, Serialize};

/// 单条从 eBPF ringbuf 拉取到用户态的“命令事件”，随后会被 batch/压缩后发送到接收端。
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AgentEvent {
    /// 事件类型：0=bash 命令行，1=预留，2=flow，3=HTTP L7，4=execve，5=进程退出，6=文件变更，7=TLS 明文
    pub event_kind: u8,
    pub ts_ms: u64,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub local_ip: Option<String>,
    pub uid: u32,
    pub tgid: u32,
    pub pid: u32,
    pub comm: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub line: Option<String>,
    /// event_kind=0：SSH 会话内交互 shell 时，尽力解析远程客户端 IPv4（沿父进程找到 `sshd` 并对照 `/proc/net/tcp`）。
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ssh_client_ip: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub exit_code: Option<i32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub success: Option<bool>,

    /// 与 `event_kind=2` 五元组对齐的关联键（`tcp:client_ip:cport->server_ip:server_port`），便于与 HTTP L7 在平台侧按时间窗 JOIN。
    #[serde(skip_serializing_if = "Option::is_none")]
    pub flow_correlation_key: Option<String>,

    /// event_kind=2：网络五元组（IPv4 + TCP/UDP）
    #[serde(skip_serializing_if = "Option::is_none")]
    pub flow_src_ip: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub flow_dst_ip: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub flow_src_port: Option<u16>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub flow_dst_port: Option<u16>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub flow_proto: Option<u8>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub flow_tcp_flags: Option<u8>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub flow_direction: Option<u8>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub flow_is_sensitive_port: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub flow_payload_len: Option<u32>,

    /// event_kind=3：HTTP 请求截断片段（明文 80/8080/8000）；若存在 `http_status` 则表示为响应行解析结果。
    #[serde(skip_serializing_if = "Option::is_none")]
    pub http_payload_trunc: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub http_trunc_len: Option<u16>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub http_method: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub http_url: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub http_body_trunc: Option<String>,
    /// 请求头中的 Host（若有）。
    #[serde(skip_serializing_if = "Option::is_none")]
    pub http_host: Option<String>,
    /// 请求头 Cookie 截断（线索字段，可能较长已截断）。
    #[serde(skip_serializing_if = "Option::is_none")]
    pub http_cookie_trunc: Option<String>,
    /// 响应状态码（仅当嗅探到 `HTTP/1.x` 响应行时填充；请求事件为 None）。
    #[serde(skip_serializing_if = "Option::is_none")]
    pub http_status: Option<u16>,

    /// event_kind=4：`execve` 的可执行路径（自 `sys_enter_execve.filename`）。
    #[serde(skip_serializing_if = "Option::is_none")]
    pub exec_path: Option<String>,

    /// event_kind=6：被监控路径下的文件路径。
    #[serde(skip_serializing_if = "Option::is_none")]
    pub file_path: Option<String>,

    /// event_kind=6：变更类型（如 create / modify / remove / rename / other）。
    #[serde(skip_serializing_if = "Option::is_none")]
    pub file_op: Option<String>,

    /// event_kind=7：TLS 明文方向（ssl_read / ssl_write）。
    #[serde(skip_serializing_if = "Option::is_none")]
    pub tls_direction: Option<String>,
    /// event_kind=7：TLS 明文截断（用于测试/检测，不建议生产全量留存）。
    #[serde(skip_serializing_if = "Option::is_none")]
    pub tls_payload_trunc: Option<String>,
    /// event_kind=7：命中的威胁类型（如 `sqli_keyword`）。
    #[serde(skip_serializing_if = "Option::is_none")]
    pub tls_threat: Option<String>,
}

/// Agent 上报时的内存队列压力（便于服务端/运维观察背压）。
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct AgentStats {
    pub pending_batches: usize,
    pub pending_bytes: usize,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub spool_pending_files: Option<usize>,
}

/// 一次 HTTP 发送的“批次包裹层”，用于携带版本信息并保持事件数组不变。
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IngestEnvelope {
    pub agent_version: String,
    pub schema_version: u32,
    #[serde(default)]
    pub host_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub agent_stats: Option<AgentStats>,
    pub events: Vec<AgentEvent>,
}


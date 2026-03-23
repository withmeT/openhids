use serde::{Deserialize, Serialize};

/// 单条从 eBPF ringbuf 拉取到用户态的“命令事件”，随后会被 batch/压缩后发送到接收端。
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AgentEvent {
    /// 事件类型：0=命令输入，1=命令执行结果，2=flow，3=HTTP L7（请求或响应线索）
    pub event_kind: u8,
    pub ts_ms: u64,
    pub uid: u32,
    pub tgid: u32,
    pub pid: u32,
    pub comm: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub line: Option<String>,
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
}

/// 一次 HTTP 发送的“批次包裹层”，用于携带版本信息并保持事件数组不变。
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IngestEnvelope {
    pub agent_version: String,
    pub schema_version: u32,
    #[serde(default)]
    pub host_id: Option<String>,
    pub events: Vec<AgentEvent>,
}


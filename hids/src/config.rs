use std::{
    fs,
    path::{Path, PathBuf},
};

use anyhow::Context as _;
use serde::Deserialize;

/// 运行时配置（启动加载）。
///
/// 目标：把散落在 agent 主循环里的 `HIDS_*` 环境变量读取逻辑集中起来，
/// 便于你后续把“动态调整（重载配置）”做成独立能力。
#[derive(Debug, Clone)]
pub struct Config {
    /// 机器标识，用于服务端多主机隔离/索引。
    pub host_id: String,

    pub ingest_url: String,

    pub flush_bytes: usize,
    pub flush_interval_ms: u64,
    pub flush_max_events: usize,

    pub spool_dir: PathBuf,
    pub spool_max_bytes: u64,

    pub mem_queue_max_bytes: usize,
    pub max_send_batches_per_iter: usize,

    pub spool_drain_interval_secs: u64,

    /// 配置文件热重载轮询间隔（秒）。
    pub config_reload_interval_secs: u64,

    /// 是否启用 XDP 五元组采集。
    pub xdp_enabled: bool,
    /// XDP 挂载接口（网卡名）。
    ///
    /// 特殊值：`auto` 表示自动识别外联网卡（默认）。
    pub xdp_iface: String,
    /// 需要跳过监听的 IPv4 地址列表（字符串形式，如 `1.2.3.4`）。
    pub xdp_skip_ips: Vec<String>,

    /// 用户态 HTTP L7 采集端口（明文 HTTP）。
    pub http_l7_ports: Vec<u16>,
}

#[derive(Debug, Default, Clone, Deserialize)]
struct PartialConfig {
    host_id: Option<String>,

    ingest_url: Option<String>,

    flush_bytes: Option<usize>,
    flush_interval_ms: Option<u64>,
    flush_max_events: Option<usize>,

    spool_dir: Option<String>,
    spool_max_bytes: Option<u64>,

    mem_queue_max_bytes: Option<usize>,
    max_send_batches_per_iter: Option<usize>,

    spool_drain_interval_secs: Option<u64>,

    config_reload_interval_secs: Option<u64>,

    xdp_enabled: Option<bool>,
    xdp_iface: Option<String>,
    xdp_skip_ips: Option<Vec<String>>,
    http_l7_ports: Option<Vec<u16>>,
}

impl Config {
    pub fn load() -> anyhow::Result<Self> {
        // Defaults
        let mut cfg = Self {
            host_id: detect_host_id(),
            ingest_url: "http://127.0.0.1:8000/ingest".to_string(),

            flush_bytes: 1 * 1024 * 1024,
            flush_interval_ms: 2_000,
            flush_max_events: 2000,

            spool_dir: PathBuf::from("./spool"),
            spool_max_bytes: 100 * 1024 * 1024,

            mem_queue_max_bytes: 10 * 1024 * 1024,
            max_send_batches_per_iter: 2,

            spool_drain_interval_secs: 2,

            config_reload_interval_secs: 5,

            xdp_enabled: true,
            xdp_iface: "auto".to_string(),
            xdp_skip_ips: Vec::new(),
            http_l7_ports: vec![80, 8080, 8000],
        };

        // Optional config file (JSON)
        // Default: ./hids-agent.json (config path can be overridden by env)
        let config_path = std::env::var("HIDS_CONFIG_PATH")
            .unwrap_or_else(|_| "./hids-agent.json".to_string());
        if Path::new(&config_path).exists() {
            let raw = fs::read_to_string(&config_path)
                .with_context(|| format!("read config file {config_path}"))?;
            let partial: PartialConfig = serde_json::from_str(&raw)
                .with_context(|| format!("parse json config file {config_path}"))?;
            cfg.apply_partial(partial);
        }

        // Env override (host_id has higher priority than config file)
        if let Ok(v) = std::env::var("HIDS_HOST_ID") {
            cfg.host_id = v;
        }

        // Env overrides
        cfg.ingest_url = std::env::var("HIDS_INGEST_URL").unwrap_or(cfg.ingest_url);

        cfg.flush_bytes = parse_env_usize("HIDS_FLUSH_BYTES").unwrap_or(cfg.flush_bytes);
        cfg.flush_interval_ms =
            parse_env_u64("HIDS_FLUSH_INTERVAL_MS").unwrap_or(cfg.flush_interval_ms);
        cfg.flush_max_events =
            parse_env_usize("HIDS_FLUSH_MAX_EVENTS").unwrap_or(cfg.flush_max_events);

        if let Ok(v) = std::env::var("HIDS_SPOOL_DIR") {
            cfg.spool_dir = PathBuf::from(v);
        }
        cfg.spool_max_bytes = parse_env_u64("HIDS_SPOOL_MAX_BYTES").unwrap_or(cfg.spool_max_bytes);

        cfg.mem_queue_max_bytes =
            parse_env_usize("HIDS_MEM_QUEUE_MAX_BYTES").unwrap_or(cfg.mem_queue_max_bytes);
        cfg.max_send_batches_per_iter = parse_env_usize("HIDS_MAX_SEND_BATCHES_PER_ITER")
            .unwrap_or(cfg.max_send_batches_per_iter);
        cfg.spool_drain_interval_secs = parse_env_u64("HIDS_SPOOL_DRAIN_INTERVAL_SECS")
            .unwrap_or(cfg.spool_drain_interval_secs);

        cfg.config_reload_interval_secs =
            parse_env_u64("HIDS_CONFIG_RELOAD_INTERVAL_SECS")
                .unwrap_or(cfg.config_reload_interval_secs);

        cfg.xdp_enabled = std::env::var("HIDS_XDP_ENABLED")
            .ok()
            .and_then(|v| v.parse::<bool>().ok())
            .unwrap_or(cfg.xdp_enabled);

        cfg.xdp_iface = std::env::var("HIDS_XDP_IFACE").unwrap_or(cfg.xdp_iface);

        // env: HIDS_XDP_SKIP_IPS=1.1.1.1,2.2.2.2
        let env_skip = std::env::var("HIDS_XDP_SKIP_IPS").ok();
        if let Some(v) = env_skip {
            cfg.xdp_skip_ips = v
                .split(',')
                .map(|s| s.trim().to_string())
                .filter(|s| !s.is_empty())
                .collect();
        }

        // env: HIDS_HTTP_L7_PORTS=80,8080,8000
        if let Ok(v) = std::env::var("HIDS_HTTP_L7_PORTS") {
            let mut ports = Vec::new();
            for p in v.split(',') {
                if let Ok(pp) = p.trim().parse::<u16>() {
                    ports.push(pp);
                }
            }
            if !ports.is_empty() {
                cfg.http_l7_ports = ports;
            }
        }

        Ok(cfg)
    }

    fn apply_partial(&mut self, partial: PartialConfig) {
        if let Some(v) = partial.host_id {
            self.host_id = v;
        }
        if let Some(v) = partial.ingest_url {
            self.ingest_url = v;
        }
        if let Some(v) = partial.flush_bytes {
            self.flush_bytes = v;
        }
        if let Some(v) = partial.flush_interval_ms {
            self.flush_interval_ms = v;
        }
        if let Some(v) = partial.flush_max_events {
            self.flush_max_events = v;
        }
        if let Some(v) = partial.spool_dir {
            self.spool_dir = PathBuf::from(v);
        }
        if let Some(v) = partial.spool_max_bytes {
            self.spool_max_bytes = v;
        }
        if let Some(v) = partial.mem_queue_max_bytes {
            self.mem_queue_max_bytes = v;
        }
        if let Some(v) = partial.max_send_batches_per_iter {
            self.max_send_batches_per_iter = v;
        }
        if let Some(v) = partial.spool_drain_interval_secs {
            self.spool_drain_interval_secs = v;
        }
        if let Some(v) = partial.config_reload_interval_secs {
            self.config_reload_interval_secs = v;
        }

        if let Some(v) = partial.xdp_enabled {
            self.xdp_enabled = v;
        }
        if let Some(v) = partial.xdp_iface {
            self.xdp_iface = v;
        }
        if let Some(v) = partial.xdp_skip_ips {
            self.xdp_skip_ips = v;
        }
        if let Some(v) = partial.http_l7_ports {
            self.http_l7_ports = v;
        }
    }
}

fn parse_env_usize(key: &str) -> Option<usize> {
    std::env::var(key).ok().and_then(|v| v.parse::<usize>().ok())
}

fn parse_env_u64(key: &str) -> Option<u64> {
    std::env::var(key).ok().and_then(|v| v.parse::<u64>().ok())
}

fn detect_host_id() -> String {
    // best-effort; avoid extra deps.
    if let Ok(v) = std::fs::read_to_string("/etc/machine-id") {
        let v = v.trim().to_string();
        if !v.is_empty() {
            return v;
        }
    }
    if let Ok(v) = std::fs::read_to_string("/var/lib/dbus/machine-id") {
        let v = v.trim().to_string();
        if !v.is_empty() {
            return v;
        }
    }
    // Fallback: env HOSTNAME (often set in container) or "unknown".
    std::env::var("HOSTNAME").unwrap_or_else(|_| "unknown".to_string())
}


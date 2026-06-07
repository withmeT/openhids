//! Environment-driven configuration (loaded after `dotenvy::dotenv()` in `run()`).

use std::path::{Path, PathBuf};

const DEFAULT_BIND_ADDR: &str = "127.0.0.1:8000";
const DEFAULT_ES_URL: &str = "http://127.0.0.1:9200";
const DEFAULT_ES_INDEX: &str = "hids-events";
const DEFAULT_ES_ALERTS_INDEX: &str = "hids-alerts";
const DEFAULT_QUEUE_CAPACITY: usize = 50_000;
const DEFAULT_BATCH_SIZE: usize = 1_000;
const DEFAULT_FLUSH_MS: u64 = 200;
const DEFAULT_THREAT_SYN_WINDOW_SEC: u64 = 1;
const DEFAULT_THREAT_SYN_THRESHOLD: u32 = 15;
const DEFAULT_ES_MAX_RETRIES: u32 = 5;
const DEFAULT_ES_RETRY_BASE_MS: u64 = 200;
const DEFAULT_MAX_BODY_MB: usize = 32;
const DEFAULT_SPOOL_DIR: &str = "./spool-server";
const DEFAULT_THREAT_RULES: &str = "rules/threat-rules.yaml";
const DEFAULT_ALERTS_MIN_LEVEL: &str = "low";

fn read_usize(key: &str, default: usize) -> usize {
    std::env::var(key)
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(default)
}

fn read_u64(key: &str, default: u64) -> u64 {
    std::env::var(key)
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(default)
}

fn read_u32(key: &str, default: u32) -> u32 {
    std::env::var(key)
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(default)
}

fn read_bool(key: &str, default: bool) -> bool {
    match std::env::var(key).ok().map(|v| v.to_ascii_lowercase()) {
        Some(ref s) if s == "1" || s == "true" || s == "yes" => true,
        Some(ref s) if s == "0" || s == "false" || s == "no" => false,
        Some(_) => default,
        None => default,
    }
}

fn ingest_token_from_env() -> Option<String> {
    std::env::var("INGEST_TOKEN")
        .ok()
        .filter(|s| !s.trim().is_empty())
        .or_else(|| {
            std::env::var("HIDS_API_KEY")
                .ok()
                .filter(|s| !s.trim().is_empty())
        })
}

fn threat_rules_path_from_env() -> Option<PathBuf> {
    if let Ok(p) = std::env::var("THREAT_RULES_PATH") {
        if !p.trim().is_empty() {
            return Some(PathBuf::from(p));
        }
    }
    let disable = read_bool("THREAT_RULES_DISABLE", false);
    if disable {
        return None;
    }
    let default = PathBuf::from(DEFAULT_THREAT_RULES);
    if default.is_file() {
        Some(default)
    } else {
        None
    }
}

#[derive(Debug, Clone)]
pub struct Config {
    pub bind_addr: String,
    pub es_url: String,
    pub es_index: String,
    pub es_alerts_index: String,
    pub es_alerts_enabled: bool,
    pub es_alerts_min_level: String,
    pub es_username: Option<String>,
    pub es_password: Option<String>,
    pub queue_capacity: usize,
    pub batch_size: usize,
    pub flush_ms: u64,
    pub threat_syn_window_sec: u64,
    pub threat_syn_threshold: u32,
    pub threat_rules_path: Option<PathBuf>,
    pub flow_drop_plain_syn: bool,
    pub es_max_retries: u32,
    pub es_retry_base_ms: u64,
    pub es_daily_index: bool,
    pub es_document_id: bool,
    pub spool_dir: PathBuf,
    pub spool_enabled: bool,
    pub ingest_token: Option<String>,
    pub max_body_bytes: usize,
}

impl Config {
    pub fn from_env() -> Self {
        let max_body_mb = read_usize("INGEST_MAX_BODY_MB", DEFAULT_MAX_BODY_MB).max(1);
        Self {
            bind_addr: std::env::var("BIND_ADDR").unwrap_or_else(|_| DEFAULT_BIND_ADDR.to_string()),
            es_url: std::env::var("ES_URL")
                .ok()
                .filter(|s| !s.is_empty())
                .or_else(|| std::env::var("HIDS_ES_URL").ok())
                .unwrap_or_else(|| DEFAULT_ES_URL.to_string()),
            es_index: std::env::var("ES_INDEX")
                .ok()
                .filter(|s| !s.is_empty())
                .or_else(|| std::env::var("HIDS_ES_INDEX").ok())
                .unwrap_or_else(|| DEFAULT_ES_INDEX.to_string()),
            es_alerts_index: std::env::var("ES_ALERTS_INDEX")
                .ok()
                .filter(|s| !s.is_empty())
                .unwrap_or_else(|| DEFAULT_ES_ALERTS_INDEX.to_string()),
            es_alerts_enabled: read_bool("ES_ALERTS_ENABLED", true),
            es_alerts_min_level: std::env::var("ES_ALERTS_MIN_LEVEL")
                .ok()
                .filter(|s| !s.trim().is_empty())
                .unwrap_or_else(|| DEFAULT_ALERTS_MIN_LEVEL.to_string()),
            es_username: std::env::var("ES_USERNAME")
                .ok()
                .filter(|s| !s.is_empty())
                .or_else(|| std::env::var("HIDS_ES_USER").ok()),
            es_password: std::env::var("ES_PASSWORD")
                .ok()
                .filter(|s| !s.is_empty())
                .or_else(|| std::env::var("HIDS_ES_PASSWORD").ok()),
            queue_capacity: read_usize("QUEUE_CAPACITY", DEFAULT_QUEUE_CAPACITY),
            batch_size: read_usize("BATCH_SIZE", DEFAULT_BATCH_SIZE),
            flush_ms: read_u64("FLUSH_MS", DEFAULT_FLUSH_MS),
            threat_syn_window_sec: read_u64("THREAT_SYN_WINDOW_SEC", DEFAULT_THREAT_SYN_WINDOW_SEC).max(1),
            threat_syn_threshold: read_u32("THREAT_SYN_THRESHOLD", DEFAULT_THREAT_SYN_THRESHOLD).max(2),
            threat_rules_path: threat_rules_path_from_env(),
            flow_drop_plain_syn: read_bool("FLOW_DROP_PLAIN_SYN", false),
            es_max_retries: read_u32("ES_MAX_RETRIES", DEFAULT_ES_MAX_RETRIES).max(1),
            es_retry_base_ms: read_u64("ES_RETRY_BASE_MS", DEFAULT_ES_RETRY_BASE_MS).max(50),
            es_daily_index: read_bool("ES_DAILY_INDEX", false),
            es_document_id: read_bool("ES_DOCUMENT_ID", true),
            spool_dir: PathBuf::from(
                std::env::var("SPOOL_DIR").unwrap_or_else(|_| DEFAULT_SPOOL_DIR.to_string()),
            ),
            spool_enabled: read_bool("SPOOL_ON_ES_FAILURE", true),
            ingest_token: ingest_token_from_env(),
            max_body_bytes: max_body_mb.saturating_mul(1024 * 1024),
        }
    }

    pub fn threat_rules_path_display(&self) -> Option<&Path> {
        self.threat_rules_path.as_deref()
    }
}

//! Environment-driven configuration (loaded after `dotenvy::dotenv()` in `run()`).

const DEFAULT_BIND_ADDR: &str = "127.0.0.1:8000";
const DEFAULT_ES_URL: &str = "http://127.0.0.1:9200";
const DEFAULT_ES_INDEX: &str = "hids-events";
const DEFAULT_QUEUE_CAPACITY: usize = 50_000;
const DEFAULT_BATCH_SIZE: usize = 1_000;
const DEFAULT_FLUSH_MS: u64 = 200;
const DEFAULT_THREAT_SYN_WINDOW_SEC: u64 = 1;
const DEFAULT_THREAT_SYN_THRESHOLD: u32 = 15;

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

#[derive(Debug, Clone)]
pub struct Config {
    pub bind_addr: String,
    pub es_url: String,
    pub es_index: String,
    pub es_username: Option<String>,
    pub es_password: Option<String>,
    pub queue_capacity: usize,
    pub batch_size: usize,
    pub flush_ms: u64,
    /// Sliding bucket size in seconds for SYN burst detection (`event_kind` 2).
    pub threat_syn_window_sec: u64,
    /// How many SYN events in one bucket triggers `syn_burst` rule.
    pub threat_syn_threshold: u32,
}

impl Config {
    pub fn from_env() -> Self {
        Self {
            bind_addr: std::env::var("BIND_ADDR").unwrap_or_else(|_| DEFAULT_BIND_ADDR.to_string()),
            es_url: std::env::var("ES_URL").unwrap_or_else(|_| DEFAULT_ES_URL.to_string()),
            es_index: std::env::var("ES_INDEX").unwrap_or_else(|_| DEFAULT_ES_INDEX.to_string()),
            es_username: std::env::var("ES_USERNAME").ok(),
            es_password: std::env::var("ES_PASSWORD").ok(),
            queue_capacity: read_usize("QUEUE_CAPACITY", DEFAULT_QUEUE_CAPACITY),
            batch_size: read_usize("BATCH_SIZE", DEFAULT_BATCH_SIZE),
            flush_ms: read_u64("FLUSH_MS", DEFAULT_FLUSH_MS),
            threat_syn_window_sec: read_u64(
                "THREAT_SYN_WINDOW_SEC",
                DEFAULT_THREAT_SYN_WINDOW_SEC,
            )
            .max(1),
            threat_syn_threshold: std::env::var("THREAT_SYN_THRESHOLD")
                .ok()
                .and_then(|v| v.parse().ok())
                .unwrap_or(DEFAULT_THREAT_SYN_THRESHOLD)
                .max(2),
        }
    }
}

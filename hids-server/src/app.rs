//! Shared application state (queue + threat aggregation handles + event broadcast).

use std::sync::Arc;

use tokio::sync::{broadcast, mpsc};

use crate::config::Config;
use crate::metrics::IngestMetrics;
use crate::models::AgentEvent;
use crate::threat::aggregate::SynBurstTracker;
use crate::threat::rules_yaml::Ruleset;

/// 实时事件广播通道容量
const EVENT_BROADCAST_CAPACITY: usize = 4096;

#[derive(Clone)]
pub struct AppState {
    pub tx: mpsc::Sender<AgentEvent>,
    pub syn_tracker: Arc<SynBurstTracker>,
    pub ruleset: Option<Arc<Ruleset>>,
    pub flow_drop_plain_syn: bool,
    pub metrics: Arc<IngestMetrics>,
    pub ingest_token: Option<String>,
    pub queue_capacity: usize,
    /// 实时事件广播（WebSocket 订阅用）
    pub event_broadcast: broadcast::Sender<Arc<serde_json::Value>>,
    /// ES 查询客户端配置
    pub es_query_url: String,
    pub es_query_index: String,
    pub es_query_auth: Option<(String, String)>,
    pub es_daily_index: bool,
}

impl AppState {
    pub fn new(
        cfg: &Config,
        tx: mpsc::Sender<AgentEvent>,
        syn_tracker: Arc<SynBurstTracker>,
        ruleset: Option<Arc<Ruleset>>,
        metrics: Arc<IngestMetrics>,
    ) -> Self {
        let (event_broadcast, _) = broadcast::channel(EVENT_BROADCAST_CAPACITY);
        let es_query_auth = match (&cfg.es_username, &cfg.es_password) {
            (Some(u), Some(p)) => Some((u.clone(), p.clone())),
            _ => None,
        };

        Self {
            tx,
            syn_tracker,
            ruleset,
            flow_drop_plain_syn: cfg.flow_drop_plain_syn,
            metrics,
            ingest_token: cfg.ingest_token.clone(),
            queue_capacity: cfg.queue_capacity,
            event_broadcast,
            es_query_url: cfg.es_url.trim_end_matches('/').to_string(),
            es_query_index: cfg.es_index.clone(),
            es_query_auth,
            es_daily_index: cfg.es_daily_index,
        }
    }
}

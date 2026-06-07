//! Shared application state (queue + threat aggregation handles).

use std::sync::Arc;

use tokio::sync::mpsc;

use crate::config::Config;
use crate::metrics::IngestMetrics;
use crate::models::AgentEvent;
use crate::threat::aggregate::SynBurstTracker;
use crate::threat::rules_yaml::Ruleset;

#[derive(Clone)]
pub struct AppState {
    pub tx: mpsc::Sender<AgentEvent>,
    pub syn_tracker: Arc<SynBurstTracker>,
    pub ruleset: Option<Arc<Ruleset>>,
    pub flow_drop_plain_syn: bool,
    pub metrics: Arc<IngestMetrics>,
    pub ingest_token: Option<String>,
    pub queue_capacity: usize,
}

impl AppState {
    pub fn new(
        cfg: &Config,
        tx: mpsc::Sender<AgentEvent>,
        syn_tracker: Arc<SynBurstTracker>,
        ruleset: Option<Arc<Ruleset>>,
        metrics: Arc<IngestMetrics>,
    ) -> Self {
        Self {
            tx,
            syn_tracker,
            ruleset,
            flow_drop_plain_syn: cfg.flow_drop_plain_syn,
            metrics,
            ingest_token: cfg.ingest_token.clone(),
            queue_capacity: cfg.queue_capacity,
        }
    }
}

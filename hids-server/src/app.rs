//! Shared application state (queue + threat aggregation handles).

use std::sync::Arc;

use tokio::sync::mpsc;

use crate::models::AgentEvent;
use crate::threat::aggregate::SynBurstTracker;

#[derive(Clone)]
pub struct AppState {
    pub tx: mpsc::Sender<AgentEvent>,
    pub syn_tracker: Arc<SynBurstTracker>,
}

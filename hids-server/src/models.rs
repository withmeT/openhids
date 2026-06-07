//! Ingest envelope and per-event document wrapper.

use serde::{Deserialize, Serialize};
use serde::de;
use serde_json::Value;

/// Built-in threat ruleset version (when YAML rules are disabled).
pub const THREAT_MODEL_VERSION: &str = "hids-threat-0.1.0";

/// One HIDS event document in Elasticsearch (one bulk `index` action per value).
#[derive(Debug, Clone, Serialize)]
#[serde(transparent)]
pub struct AgentEvent(pub Value);

impl<'de> Deserialize<'de> for AgentEvent {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let v = Value::deserialize(deserializer)?;
        if v.is_object() {
            Ok(AgentEvent(v))
        } else {
            Err(de::Error::custom(
                "each events[] item must be a JSON object (AgentEvent)",
            ))
        }
    }
}

/// Agent batch envelope (`hids` agent `IngestEnvelope` compatible).
#[derive(Debug, Clone, Deserialize)]
pub struct IngestEnvelope {
    #[serde(default)]
    pub agent_version: Option<String>,
    #[serde(default)]
    pub schema_version: Option<u32>,
    #[serde(default)]
    pub host_id: Option<String>,
    /// Agent-side queue pressure snapshot (optional).
    #[serde(default)]
    pub agent_stats: Option<Value>,
    pub events: Vec<AgentEvent>,
}

impl IngestEnvelope {
    pub fn event_count(&self) -> usize {
        self.events.len()
    }
}

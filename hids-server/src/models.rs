//! Ingest envelope and per-event document wrapper.

use serde::{Deserialize, Serialize};
use serde::de;
use serde_json::Value;

/// Threat ruleset version embedded in each document for replay and tuning.
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

#[derive(Debug, Deserialize)]
pub struct IngestEnvelope {
    pub events: Vec<AgentEvent>,
}

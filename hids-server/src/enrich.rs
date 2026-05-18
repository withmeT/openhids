//! Server-side fields merged before threat analysis and queueing.

use std::time::{SystemTime, UNIX_EPOCH};

use serde_json::Value;

use crate::models::AgentEvent;

/// Unix millis when the server accepted this event. Only added if missing.
pub const INGEST_TS_MS_FIELD: &str = "ingest_ts_ms";

fn unix_millis_now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0)
}

pub fn apply_ingest_timestamp(mut ev: AgentEvent) -> AgentEvent {
    if let Value::Object(ref mut map) = ev.0 {
        if !map.contains_key(INGEST_TS_MS_FIELD) {
            map.insert(
                INGEST_TS_MS_FIELD.to_string(),
                Value::Number(unix_millis_now().into()),
            );
        }
    }
    ev
}

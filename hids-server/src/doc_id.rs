//! Stable Elasticsearch document ids for idempotent ingest.

use std::collections::hash_map::DefaultHasher;
use std::hash::{Hash, Hasher};

use serde_json::Value;

pub fn stable_document_id(doc: &Value) -> Option<String> {
    let map = doc.as_object()?;
    let host = map.get("host_id")?.as_str().unwrap_or("unknown");
    let ts = map
        .get("ts_ms")
        .and_then(|v| v.as_u64().or_else(|| v.as_i64().map(|n| n as u64)))?;
    let kind = map
        .get("event_kind")
        .and_then(|v| v.as_u64().or_else(|| v.as_i64().map(|n| n as u64)))?;
    let pid = map
        .get("pid")
        .and_then(|v| v.as_u64().or_else(|| v.as_i64().map(|n| n as u64)))
        .unwrap_or(0);

    let mut hasher = DefaultHasher::new();
    host.hash(&mut hasher);
    ts.hash(&mut hasher);
    kind.hash(&mut hasher);
    pid.hash(&mut hasher);

    if let Some(line) = map.get("line").and_then(|v| v.as_str()) {
        line.chars().take(96).collect::<String>().hash(&mut hasher);
    } else if let Some(key) = map.get("flow_correlation_key").and_then(|v| v.as_str()) {
        key.hash(&mut hasher);
    } else if let Some(url) = map.get("http_url").and_then(|v| v.as_str()) {
        url.chars().take(96).collect::<String>().hash(&mut hasher);
    }

    Some(format!("{:016x}", hasher.finish()))
}

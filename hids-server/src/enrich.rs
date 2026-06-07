//! Server-side fields merged before threat analysis and queueing.

use std::collections::hash_map::DefaultHasher;
use std::hash::{Hash, Hasher};
use std::time::{SystemTime, UNIX_EPOCH};

use serde_json::{json, Map, Value};

use crate::filter;
use crate::models::AgentEvent;
use crate::time_fmt::{self, json_value_as_millis};

pub const INGEST_TS_MS_FIELD: &str = "ingest_ts_ms";
pub const INGEST_TIME_FIELD: &str = "ingest_time";
pub const INGEST_TIME_ISO_FIELD: &str = "ingest_time_iso";
pub const EVENT_TIME_FIELD: &str = "event_time";
pub const EVENT_TIME_ISO_FIELD: &str = "event_time_iso";

/// 归一化客户端 IP（便于 ES 聚合 / 威胁关联）。
pub const CLIENT_IP_FIELD: &str = "client_ip";
/// 归一化服务端 IP（本机或目标）。
pub const SERVER_IP_FIELD: &str = "server_ip";
/// 跨 event_kind 关联键（优先 agent 的 `flow_correlation_key`）。
pub const CORRELATION_KEY_FIELD: &str = "correlation_key";
/// ES 默认时间字段（Kibana Discover）。
pub const ES_TIMESTAMP_FIELD: &str = "@timestamp";

/// Batch-level metadata copied from `IngestEnvelope`.
#[derive(Debug, Clone)]
pub struct EnvelopeMeta {
    pub agent_version: Option<String>,
    pub schema_version: Option<u32>,
    pub host_id: Option<String>,
    pub batch_event_count: usize,
    pub agent_stats: Option<Value>,
}

fn unix_millis_now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0)
}

fn str_field<'a>(map: &'a Map<String, Value>, key: &str) -> Option<&'a str> {
    map.get(key).and_then(|v| v.as_str())
}

fn num_i64(map: &Map<String, Value>, key: &str) -> Option<i64> {
    map.get(key).and_then(|v| v.as_i64())
}

/// `tcp:client:cport->server:server_port` → client IP
fn client_ip_from_flow_key(key: &str) -> Option<&str> {
    let rest = key.strip_prefix("tcp:")?;
    let client = rest.split("->").next()?;
    client.split(':').next().filter(|s| !s.is_empty())
}

/// `tcp:client:cport->server:server_port` → server IP
fn server_ip_from_flow_key(key: &str) -> Option<&str> {
    let rest = key.strip_prefix("tcp:")?;
    let server_part = rest.split("->").nth(1)?;
    server_part.split(':').next().filter(|s| !s.is_empty())
}

fn line_fingerprint(line: &str) -> u64 {
    let mut h = DefaultHasher::new();
    line.chars().take(128).collect::<String>().hash(&mut h);
    h.finish()
}

fn build_correlation_key(map: &Map<String, Value>, kind: Option<i64>) -> Option<String> {
    if let Some(k) = str_field(map, "flow_correlation_key") {
        return Some(k.to_string());
    }

    let host = str_field(map, "host_id").unwrap_or("unknown_host");

    match kind {
        Some(0) => {
            let ssh = str_field(map, "ssh_client_ip").unwrap_or("-");
            let line = str_field(map, "line").unwrap_or("");
            let fp = line_fingerprint(line);
            Some(format!("bash:{host}:{ssh}:{fp:x}"))
        }
        Some(2) => {
            let src = str_field(map, "flow_src_ip").unwrap_or("-");
            let dst = str_field(map, "flow_dst_ip").unwrap_or("-");
            let sp = map
                .get("flow_src_port")
                .and_then(|v| v.as_u64().or_else(|| v.as_i64().map(|n| n as u64)))
                .unwrap_or(0);
            let dp = map
                .get("flow_dst_port")
                .and_then(|v| v.as_u64().or_else(|| v.as_i64().map(|n| n as u64)))
                .unwrap_or(0);
            Some(format!("flow:{host}:{src}:{sp}->{dst}:{dp}"))
        }
        Some(3) | Some(7) => {
            let method = str_field(map, "http_method").unwrap_or("-");
            let url = str_field(map, "http_url")
                .or_else(|| str_field(map, "http_payload_trunc"))
                .unwrap_or("-");
            let url_key: String = url.chars().take(160).collect();
            Some(format!("http:{host}:{method}:{url_key}"))
        }
        Some(k) => {
            let ts = map
                .get("ts_ms")
                .and_then(json_value_as_millis)
                .unwrap_or(0);
            Some(format!("kind{k}:{host}:{ts}"))
        }
        None => None,
    }
}

fn normalize_ips_and_correlation(map: &mut Map<String, Value>) {
    let kind = num_i64(map, "event_kind");
    let flow_key = str_field(map, "flow_correlation_key").map(|s| s.to_string());

    if !map.contains_key(CLIENT_IP_FIELD) {
        let client = match kind {
            Some(0) => str_field(map, "ssh_client_ip").map(|s| s.to_string()),
            Some(2) => str_field(map, "flow_src_ip").map(|s| s.to_string()),
            Some(3) | Some(7) => flow_key
                .as_deref()
                .and_then(client_ip_from_flow_key)
                .map(|s| s.to_string()),
            _ => None,
        };
        if let Some(ip) = client.filter(|s| !s.is_empty()) {
            map.insert(CLIENT_IP_FIELD.to_string(), Value::String(ip));
        }
    }

    if !map.contains_key(SERVER_IP_FIELD) {
        let server = match kind {
            Some(0) | Some(3) | Some(7) => str_field(map, "local_ip").map(|s| s.to_string()),
            Some(2) => str_field(map, "flow_dst_ip").map(|s| s.to_string()),
            _ => None,
        };
        let server = server.or_else(|| {
            flow_key
                .as_deref()
                .and_then(server_ip_from_flow_key)
                .map(|s| s.to_string())
        });
        if let Some(ip) = server.filter(|s| !s.is_empty()) {
            map.insert(SERVER_IP_FIELD.to_string(), Value::String(ip));
        }
    }

    if !map.contains_key(CORRELATION_KEY_FIELD) {
        if let Some(key) = build_correlation_key(map, kind) {
            map.insert(CORRELATION_KEY_FIELD.to_string(), Value::String(key));
        }
    }

    if !map.contains_key(ES_TIMESTAMP_FIELD) {
        let root = Value::Object(map.clone());
        if let Some(iso) = filter::pick_timestamp_iso(&root) {
            map.insert(ES_TIMESTAMP_FIELD.to_string(), Value::String(iso));
        }
    }
}

/// Apply envelope defaults, ingest timestamp, normalized fields, and `hids.*` metadata.
pub fn enrich_event(mut ev: AgentEvent, envelope: &EnvelopeMeta) -> AgentEvent {
    if !ev.0.is_object() {
        ev.0 = Value::Object(Map::new());
    }
    let map = ev.0.as_object_mut().expect("object");

    if let Some(ref host) = envelope.host_id {
        if !map.contains_key("host_id") {
            map.insert("host_id".to_string(), Value::String(host.clone()));
        }
    }
    if let Some(ver) = envelope.schema_version {
        if !map.contains_key("schema_version") {
            map.insert("schema_version".to_string(), Value::Number(ver.into()));
        }
    }
    if let Some(ref av) = envelope.agent_version {
        if !map.contains_key("agent_version") {
            map.insert("agent_version".to_string(), Value::String(av.clone()));
        }
    }

    if !map.contains_key(INGEST_TS_MS_FIELD) {
        map.insert(
            INGEST_TS_MS_FIELD.to_string(),
            Value::Number(unix_millis_now().into()),
        );
    }

    if let Some(ms) = map.get(INGEST_TS_MS_FIELD).and_then(json_value_as_millis) {
        if let Some(display) = time_fmt::millis_to_china_display(ms) {
            map.insert(INGEST_TIME_FIELD.to_string(), Value::String(display));
        }
        if let Some(iso) = time_fmt::millis_to_china_iso(ms) {
            map.insert(INGEST_TIME_ISO_FIELD.to_string(), Value::String(iso));
        }
    }

    if let Some(ms) = map.get("ts_ms").and_then(json_value_as_millis) {
        if let Some(display) = time_fmt::millis_to_china_display(ms) {
            map.insert(EVENT_TIME_FIELD.to_string(), Value::String(display));
        }
        if let Some(iso) = time_fmt::millis_to_china_iso(ms) {
            map.insert(EVENT_TIME_ISO_FIELD.to_string(), Value::String(iso));
        }
    }

    normalize_ips_and_correlation(map);

    let event_kind = map.get("event_kind").and_then(|v| v.as_u64());
    let mut hids_meta = json!({
        "pipeline": "ingest_v2",
        "batch_event_count": envelope.batch_event_count,
    });
    if let Some(ek) = event_kind {
        hids_meta["event_kind"] = json!(ek);
    }
    if let Some(ref av) = envelope.agent_version {
        hids_meta["envelope_agent_version"] = json!(av);
    }
    if let Some(ref stats) = envelope.agent_stats {
        hids_meta["agent_stats"] = stats.clone();
    }

    map.insert("hids".to_string(), hids_meta);

    ev
}

//! Ingest-time filters (drop before queue) to control ES volume.

use serde_json::Value;

use crate::time_fmt::json_value_as_millis;

fn num_i64(v: &Value, key: &str) -> Option<i64> {
    v.as_object()?.get(key).and_then(|x| x.as_i64())
}

fn bool_field(v: &Value, key: &str) -> Option<bool> {
    v.as_object()?.get(key).and_then(|x| x.as_bool())
}

/// 丢弃「纯 SYN + 非敏感端口」的 XDP flow，降低扫描噪声（默认关闭）。
pub fn should_drop_plain_syn_flow(root: &Value, enabled: bool) -> bool {
    if !enabled {
        return false;
    }
    if num_i64(root, "event_kind") != Some(2) {
        return false;
    }
    if num_i64(root, "flow_tcp_flags") != Some(2) {
        return false;
    }
    if bool_field(root, "flow_is_sensitive_port") == Some(true) {
        return false;
    }
    true
}

/// 使用 `event_time_iso` 优先作为 ES `@timestamp` 的源。
pub fn pick_timestamp_iso(root: &Value) -> Option<String> {
    if let Some(s) = root
        .as_object()?
        .get("event_time_iso")
        .and_then(|v| v.as_str())
    {
        return Some(s.to_string());
    }
    root.as_object()?
        .get("ts_ms")
        .and_then(json_value_as_millis)
        .and_then(crate::time_fmt::millis_to_china_iso)
}

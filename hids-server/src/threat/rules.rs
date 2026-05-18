//! Coarse stateless rules + SYN burst hook. Tune here for early-phase detection.

use std::sync::LazyLock;

use regex::Regex;
use serde_json::{json, Value};

use crate::threat::aggregate::SynBurstTracker;

#[derive(Debug, Clone)]
pub struct RuleHit {
    pub id: &'static str,
    pub severity: &'static str,
    pub category: &'static str,
    pub evidence: Value,
}

static RE_SHELL_DANGEROUS: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(
        r"(?i)(\|\s*bash|/dev/tcp/|chmod\s+[-+]x|chmod\s+777|\bcurl\b.*\|\s*sh|\bwget\b.*\|\s*sh|rm\s+-rf\s+/|base64\s+-d)",
    )
    .expect("regex compile")
});

static RE_SENSITIVE_BODY: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"(?i)(password|passwd|token|secret|authorization)\s*[=:]")
        .expect("regex compile")
});

fn as_object(v: &Value) -> Option<&serde_json::Map<String, Value>> {
    v.as_object()
}

fn num_i64(v: &Value, key: &str) -> Option<i64> {
    as_object(v)?.get(key).and_then(|x| x.as_i64())
}

fn num_u64(v: &Value, key: &str) -> Option<u64> {
    as_object(v)?.get(key).and_then(|x| x.as_u64())
}

fn str_field<'a>(v: &'a Value, key: &str) -> Option<&'a str> {
    as_object(v)?.get(key).and_then(|x| x.as_str())
}

fn host_key(v: &Value) -> String {
    str_field(v, "host_id")
        .unwrap_or("unknown_host")
        .to_string()
}

/// Collect rule hits for one event. Order is stable for debugging.
pub fn collect_hits(root: &Value, syn_tracker: &SynBurstTracker) -> Vec<RuleHit> {
    let mut out = Vec::new();

    if !root.is_object() {
        return out;
    }

    let kind = num_i64(root, "event_kind");

    // --- event_kind 0: shell ---
    if kind == Some(0) {
        if let Some(line) = str_field(root, "line") {
            if RE_SHELL_DANGEROUS.is_match(line) {
                out.push(RuleHit {
                    id: "shell_suspicious_pattern",
                    severity: "medium",
                    category: "shell",
                    evidence: json!({ "field": "line", "match": "coarse_regex" }),
                });
            }
        }
        if str_field(root, "ssh_client_ip").is_some() {
            out.push(RuleHit {
                id: "shell_ssh_session",
                severity: "info",
                category: "shell",
                evidence: json!({ "field": "ssh_client_ip", "present": true }),
            });
        }
    }

    // --- event_kind 2: XDP flow ---
    if kind == Some(2) {
        if let Some(port) = num_i64(root, "flow_dst_port") {
            if matches!(port, 22 | 3389 | 23 | 445 | 3306 | 6379 | 5432) {
                out.push(RuleHit {
                    id: "network_sensitive_port_touch",
                    severity: "low",
                    category: "network",
                    evidence: json!({ "flow_dst_port": port }),
                });
            }
        }

        let flags = num_i64(root, "flow_tcp_flags");
        if flags == Some(2) {
            let comm = str_field(root, "comm");
            if comm.is_none() || comm == Some("xdp") {
                let host = host_key(root);
                let src = str_field(root, "flow_src_ip").unwrap_or("");
                let dst_port = num_i64(root, "flow_dst_port").unwrap_or(0);
                let ts = num_u64(root, "ts_ms").unwrap_or(0);

                if syn_tracker.observe_syn(&host, src, dst_port, ts) {
                    out.push(RuleHit {
                        id: "network_syn_burst",
                        severity: "medium",
                        category: "network_scan",
                        evidence: json!({
                            "flow_src_ip": src,
                            "flow_dst_port": dst_port,
                            "signal": "syn_count_reached_threshold_in_window",
                        }),
                    });
                }
            }
        }
    }

    // --- event_kind 3: http_l7 ---
    if kind == Some(3) {
        if num_i64(root, "http_status") == Some(400) {
            out.push(RuleHit {
                id: "http_bad_request",
                severity: "low",
                category: "web",
                evidence: json!({ "http_status": 400 }),
            });
        }
    }

    // --- event_kind 7: nginx L7 ---
    if kind == Some(7) {
        let body = str_field(root, "http_body_trunc").unwrap_or("");
        let tls = str_field(root, "tls_payload_trunc").unwrap_or("");
        if RE_SENSITIVE_BODY.is_match(body) || RE_SENSITIVE_BODY.is_match(tls) {
            out.push(RuleHit {
                id: "web_sensitive_token_in_telemetry",
                severity: "low",
                category: "sensitive_data",
                evidence: json!({ "field": "http_body_trunc_or_tls_payload_trunc" }),
            });
        }
        if str_field(root, "http_method").is_some_and(|m| m.eq_ignore_ascii_case("POST"))
            && str_field(root, "http_url")
                .is_some_and(|u| u.to_ascii_lowercase().contains("login"))
        {
            out.push(RuleHit {
                id: "web_login_post",
                severity: "info",
                category: "auth_activity",
                evidence: json!({ "http_method": "POST" }),
            });
        }
    }

    out
}

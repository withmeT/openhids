//! Built-in coarse rules + SYN burst hook.

use std::sync::LazyLock;

use regex::Regex;
use serde_json::{json, Value};

use crate::threat::aggregate::SynBurstTracker;

#[derive(Debug, Clone)]
pub struct RuleHit {
    pub id: String,
    pub severity: String,
    pub category: String,
    pub evidence: Value,
}

#[derive(Debug, Default)]
pub struct ThreatContext {
    pub ssh_client_ip: Option<String>,
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

fn str_field<'a>(v: &'a Value, key: &str) -> Option<&'a str> {
    as_object(v)?.get(key).and_then(|x| x.as_str())
}

fn host_key(v: &Value) -> String {
    str_field(v, "host_id")
        .unwrap_or("unknown_host")
        .to_string()
}

/// Built-in detectors (always enabled).
pub fn collect_builtin_hits(
    root: &Value,
    syn_tracker: &SynBurstTracker,
) -> (Vec<RuleHit>, ThreatContext) {
    let mut out = Vec::new();
    let mut ctx = ThreatContext::default();

    if !root.is_object() {
        return (out, ctx);
    }

    let kind = num_i64(root, "event_kind");

    if kind == Some(0) {
        if let Some(line) = str_field(root, "line") {
            if RE_SHELL_DANGEROUS.is_match(line) {
                out.push(RuleHit {
                    id: "shell_suspicious_pattern".to_string(),
                    severity: "medium".to_string(),
                    category: "shell".to_string(),
                    evidence: json!({ "field": "line", "match": "coarse_regex" }),
                });
            }
        }
        if let Some(ip) = str_field(root, "ssh_client_ip") {
            ctx.ssh_client_ip = Some(ip.to_string());
        }
    }

    if kind == Some(2) {
        if let Some(port) = num_i64(root, "flow_dst_port") {
            if matches!(port, 22 | 3389 | 23 | 445 | 3306 | 6379 | 5432) {
                out.push(RuleHit {
                    id: "network_sensitive_port_touch".to_string(),
                    severity: "low".to_string(),
                    category: "network".to_string(),
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
                let ts = as_object(root)
                    .and_then(|m| m.get("ts_ms"))
                    .and_then(|v| v.as_u64())
                    .unwrap_or(0);

                if syn_tracker.observe_syn(&host, src, dst_port, ts) {
                    out.push(RuleHit {
                        id: "network_syn_burst".to_string(),
                        severity: "medium".to_string(),
                        category: "network_scan".to_string(),
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

    if kind == Some(3) {
        if num_i64(root, "http_status") == Some(400) {
            out.push(RuleHit {
                id: "http_bad_request".to_string(),
                severity: "low".to_string(),
                category: "web".to_string(),
                evidence: json!({ "http_status": 400 }),
            });
        }
    }

    if kind == Some(7) {
        if let Some(agent_threat) = str_field(root, "tls_threat") {
            out.push(RuleHit {
                id: "agent_tls_threat".to_string(),
                severity: "medium".to_string(),
                category: "web".to_string(),
                evidence: json!({ "tls_threat": agent_threat }),
            });
        }

        let body = str_field(root, "http_body_trunc").unwrap_or("");
        let tls = str_field(root, "tls_payload_trunc").unwrap_or("");
        if RE_SENSITIVE_BODY.is_match(body) || RE_SENSITIVE_BODY.is_match(tls) {
            out.push(RuleHit {
                id: "web_sensitive_token_in_telemetry".to_string(),
                severity: "low".to_string(),
                category: "sensitive_data".to_string(),
                evidence: json!({ "field": "http_body_trunc_or_tls_payload_trunc" }),
            });
        }
        if str_field(root, "http_method").is_some_and(|m| m.eq_ignore_ascii_case("POST"))
            && str_field(root, "http_url")
                .is_some_and(|u| u.to_ascii_lowercase().contains("login"))
        {
            out.push(RuleHit {
                id: "web_login_post".to_string(),
                severity: "info".to_string(),
                category: "auth_activity".to_string(),
                evidence: json!({ "http_method": "POST" }),
            });
        }
    }

    (out, ctx)
}

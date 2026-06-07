//! Threat preprocessing: built-in rules + optional YAML rules + SYN aggregation.

pub mod aggregate;
pub mod rules;
pub mod rules_yaml;

use std::sync::Arc;

use serde_json::{json, Value};

use crate::models::AgentEvent;
use crate::threat::aggregate::SynBurstTracker;
use crate::threat::rules::RuleHit;
use crate::threat::rules_yaml::Ruleset;

/// Run detectors and merge a `threat` object into the document root.
pub fn analyze_event(
    ev: &mut AgentEvent,
    syn_tracker: &SynBurstTracker,
    ruleset: Option<&Arc<Ruleset>>,
) {
    let (hits, ctx) = if let Some(rs) = ruleset {
        rs.analyze(&ev.0, syn_tracker)
    } else {
        rules::collect_builtin_hits(&ev.0, syn_tracker)
    };

    let model_version = ruleset
        .map(|r| r.version.as_str())
        .unwrap_or(crate::models::THREAT_MODEL_VERSION);

    merge_threat(&mut ev.0, hits, ctx, model_version);
}

fn severity_weight(s: &str) -> u32 {
    match s {
        "high" => 45,
        "medium" => 22,
        "low" => 10,
        "info" => 4,
        _ => 8,
    }
}

fn level_from_score(score: u32) -> &'static str {
    if score >= 40 {
        "high"
    } else if score >= 22 {
        "medium"
    } else if score >= 6 {
        "low"
    } else {
        "none"
    }
}

fn merge_threat(
    root: &mut Value,
    hits: Vec<RuleHit>,
    ctx: rules::ThreatContext,
    model_version: &str,
) {
    let Some(map) = root.as_object_mut() else {
        return;
    };

    let score: u32 = hits
        .iter()
        .map(|h| severity_weight(&h.severity))
        .sum::<u32>()
        .min(100);

    let mut categories: Vec<String> = hits.iter().map(|h| h.category.clone()).collect();
    categories.sort();
    categories.dedup();

    let rules_json: Vec<Value> = hits
        .into_iter()
        .map(|h| {
            json!({
                "id": h.id,
                "severity": h.severity,
                "category": h.category,
                "evidence": h.evidence,
            })
        })
        .collect();

    let level = if rules_json.is_empty() {
        "none"
    } else {
        let l = level_from_score(score);
        if l == "none" {
            "low"
        } else {
            l
        }
    };

    let mut threat = json!({
        "level": level,
        "score": score,
        "categories": categories,
        "rules": rules_json,
        "model_version": model_version,
    });

    if let Some(ip) = ctx.ssh_client_ip {
        threat["context"] = json!({ "ssh_client_ip": ip });
    }

    map.insert("threat".to_string(), threat);
}

/// Whether this document should be mirrored to the alerts index.
pub fn should_index_alert(root: &Value, min_level: &str) -> bool {
    let level = root
        .as_object()
        .and_then(|m| m.get("threat"))
        .and_then(|t| t.get("level"))
        .and_then(|v| v.as_str())
        .unwrap_or("none");

    if level == "none" {
        return false;
    }

    threat_level_rank(level) >= threat_level_rank(min_level)
}

fn threat_level_rank(level: &str) -> u8 {
    match level {
        "high" => 4,
        "medium" => 3,
        "low" => 2,
        "info" => 1,
        _ => 0,
    }
}

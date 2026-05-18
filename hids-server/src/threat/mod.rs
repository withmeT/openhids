//! Threat preprocessing: coarse rules + optional aggregation state.

pub mod aggregate;
pub mod rules;

use serde_json::{json, Value};

use crate::models::{AgentEvent, THREAT_MODEL_VERSION};
use crate::threat::aggregate::SynBurstTracker;
use crate::threat::rules::RuleHit;

/// Run detectors and merge a `threat` object into the document root.
pub fn analyze_event(ev: &mut AgentEvent, syn_tracker: &SynBurstTracker) {
    let hits = rules::collect_hits(&ev.0, syn_tracker);
    merge_threat(&mut ev.0, hits);
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

fn merge_threat(root: &mut Value, hits: Vec<RuleHit>) {
    let Some(map) = root.as_object_mut() else {
        return;
    };

    let score: u32 = hits.iter().map(|h| severity_weight(h.severity)).sum::<u32>().min(100);

    let mut categories: Vec<String> = hits
        .iter()
        .map(|h| h.category.to_string())
        .collect();
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

    map.insert(
        "threat".to_string(),
        json!({
            "level": level,
            "score": score,
            "categories": categories,
            "rules": rules_json,
            "model_version": THREAT_MODEL_VERSION,
        }),
    );
}

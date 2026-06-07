//! External YAML rules loaded at startup.

use std::path::Path;

use anyhow::Context;
use regex::Regex;
use serde::Deserialize;
use serde_json::{json, Value};

use super::rules::{RuleHit, ThreatContext};
use crate::threat::aggregate::SynBurstTracker;
use crate::threat::rules::collect_builtin_hits;

#[derive(Debug, Deserialize)]
struct RulesFile {
    version: String,
    rules: Vec<YamlRule>,
}

#[derive(Debug, Deserialize)]
struct YamlRule {
    id: String,
    #[serde(default)]
    event_kinds: Vec<i64>,
    field: String,
    #[serde(default = "default_match_kind", alias = "match")]
    match_kind: String,
    pattern: String,
    severity: String,
    category: String,
}

fn default_match_kind() -> String {
    "regex".to_string()
}

#[derive(Debug)]
enum Matcher {
    Regex(Regex),
    Contains(String),
}

#[derive(Debug)]
struct CompiledRule {
    id: String,
    event_kinds: Vec<i64>,
    field: String,
    matcher: Matcher,
    severity: String,
    category: String,
}

#[derive(Debug)]
pub struct Ruleset {
    pub version: String,
    rules: Vec<CompiledRule>,
}

impl Ruleset {
    pub fn rule_count(&self) -> usize {
        self.rules.len()
    }

    pub fn load(path: &Path) -> anyhow::Result<Self> {
        let raw = std::fs::read_to_string(path)
            .with_context(|| format!("read rules file {}", path.display()))?;
        let file: RulesFile =
            serde_yaml::from_str(&raw).with_context(|| format!("parse yaml {}", path.display()))?;

        let mut rules = Vec::with_capacity(file.rules.len());
        for r in file.rules {
            let matcher = match r.match_kind.to_ascii_lowercase().as_str() {
                "regex" => Matcher::Regex(
                    Regex::new(&r.pattern)
                        .with_context(|| format!("compile regex for rule {}", r.id))?,
                ),
                "contains" => Matcher::Contains(r.pattern),
                other => anyhow::bail!("unsupported match kind '{other}' in rule {}", r.id),
            };
            rules.push(CompiledRule {
                id: r.id,
                event_kinds: r.event_kinds,
                field: r.field,
                matcher,
                severity: r.severity,
                category: r.category,
            });
        }

        Ok(Self {
            version: file.version,
            rules,
        })
    }

    pub fn analyze(
        &self,
        root: &Value,
        syn_tracker: &SynBurstTracker,
    ) -> (Vec<RuleHit>, ThreatContext) {
        let (mut hits, ctx) = collect_builtin_hits(root, syn_tracker);

        if !root.is_object() {
            return (hits, ctx);
        }

        let kind = root
            .as_object()
            .and_then(|m| m.get("event_kind"))
            .and_then(|v| v.as_i64());

        for rule in &self.rules {
            if !rule.event_kinds.is_empty() {
                let Some(k) = kind else {
                    continue;
                };
                if !rule.event_kinds.contains(&k) {
                    continue;
                }
            }

            let Some(text) = root
                .as_object()
                .and_then(|m| m.get(&rule.field))
                .and_then(|v| v.as_str())
            else {
                continue;
            };

            let matched = match &rule.matcher {
                Matcher::Regex(re) => re.is_match(text),
                Matcher::Contains(needle) => text.contains(needle.as_str()),
            };

            if matched {
                hits.push(RuleHit {
                    id: rule.id.clone(),
                    severity: rule.severity.clone(),
                    category: rule.category.clone(),
                    evidence: json!({
                        "field": rule.field,
                        "source": "yaml",
                    }),
                });
            }
        }

        (hits, ctx)
    }
}

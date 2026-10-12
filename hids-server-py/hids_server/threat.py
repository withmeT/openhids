"""对应 Rust ``threat/``：内置规则 + YAML 规则 + SYN 突发聚合 + threat 对象合并。"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Optional

import yaml

THREAT_MODEL_VERSION = "hids-threat-0.2.0"

_PRUNE_EVERY_SYN = 4096
_MAX_TRACKER_KEYS = 200_000

RE_SHELL_DANGEROUS = re.compile(
    r"(?i)(\|\s*bash|/dev/tcp/|chmod\s+[-+]x|chmod\s+777|\bcurl\b.*\|\s*sh|\bwget\b.*\|\s*sh|rm\s+-rf\s+/|base64\s+-d)"
)
RE_SENSITIVE_BODY = re.compile(r"(?i)(password|passwd|token|secret|authorization)\s*[=:]")

_SENSITIVE_PORTS = frozenset({22, 3389, 23, 445, 3306, 6379, 5432})


@dataclass
class RuleHit:
    id: str
    severity: str
    category: str
    evidence: Any


@dataclass
class ThreatContext:
    ssh_client_ip: Optional[str] = None


class SynBurstTracker:
    """按 (host, src_ip, dst_port) 做固定时间桶 SYN 计数，首达阈值时发一次信号。"""

    def __init__(self, window_sec: int, threshold: int) -> None:
        self._window_ms = max(window_sec * 1000, 1)
        self._threshold = threshold
        self._inner: dict[str, tuple[int, int]] = {}
        self._syn_observations = 0

    def observe_syn(self, host_key: str, src_ip: str, dst_port: int, ts_ms: int) -> bool:
        n = self._syn_observations
        self._syn_observations += 1
        if n % _PRUNE_EVERY_SYN == 0:
            self._prune_stale(ts_ms)

        bucket = ts_ms // self._window_ms
        key = f"{host_key}|{src_ip}|{dst_port}"

        entry = self._inner.get(key)
        if entry is None:
            self._inner[key] = (bucket, 1)
            return self._threshold == 1
        old_bucket, count = entry
        if old_bucket != bucket:
            self._inner[key] = (bucket, 1)
            return self._threshold == 1
        count = min(count + 1, 0xFFFF_FFFF)
        self._inner[key] = (bucket, count)
        return count == self._threshold

    def _prune_stale(self, ts_ms: int) -> None:
        current = ts_ms // self._window_ms
        keep_from = max(current - 120, 0)
        self._inner = {k: v for k, v in self._inner.items() if v[0] >= keep_from}
        if len(self._inner) > _MAX_TRACKER_KEYS:
            self._inner.clear()


def _str_field(event: dict, key: str) -> Optional[str]:
    value = event.get(key)
    return value if isinstance(value, str) else None


def _num_i64(event: dict, key: str) -> Optional[int]:
    value = event.get(key)
    if isinstance(value, bool) or not isinstance(value, int):
        return None
    return value


def collect_builtin_hits(
    root: Any, syn_tracker: SynBurstTracker
) -> tuple[list[RuleHit], ThreatContext]:
    """内置探测规则（始终启用），与 Rust ``collect_builtin_hits`` 一致。"""
    hits: list[RuleHit] = []
    ctx = ThreatContext()
    if not isinstance(root, dict):
        return hits, ctx

    kind = _num_i64(root, "event_kind")

    if kind == 0:
        line = _str_field(root, "line")
        if line is not None and RE_SHELL_DANGEROUS.search(line):
            hits.append(
                RuleHit(
                    id="shell_suspicious_pattern",
                    severity="medium",
                    category="shell",
                    evidence={"field": "line", "match": "coarse_regex"},
                )
            )
        ssh_ip = _str_field(root, "ssh_client_ip")
        if ssh_ip is not None:
            ctx.ssh_client_ip = ssh_ip

    if kind == 2:
        port = _num_i64(root, "flow_dst_port")
        if port in _SENSITIVE_PORTS:
            hits.append(
                RuleHit(
                    id="network_sensitive_port_touch",
                    severity="low",
                    category="network",
                    evidence={"flow_dst_port": port},
                )
            )

        if _num_i64(root, "flow_tcp_flags") == 2:
            comm = _str_field(root, "comm")
            if comm is None or comm == "xdp":
                host = _str_field(root, "host_id") or "unknown_host"
                src = _str_field(root, "flow_src_ip") or ""
                dst_port = _num_i64(root, "flow_dst_port") or 0
                ts = root.get("ts_ms")
                ts = ts if isinstance(ts, int) and not isinstance(ts, bool) and ts >= 0 else 0
                if syn_tracker.observe_syn(host, src, dst_port, ts):
                    hits.append(
                        RuleHit(
                            id="network_syn_burst",
                            severity="medium",
                            category="network_scan",
                            evidence={
                                "flow_src_ip": src,
                                "flow_dst_port": dst_port,
                                "signal": "syn_count_reached_threshold_in_window",
                            },
                        )
                    )

    if kind == 3 and _num_i64(root, "http_status") == 400:
        hits.append(
            RuleHit(
                id="http_bad_request",
                severity="low",
                category="web",
                evidence={"http_status": 400},
            )
        )

    if kind == 7:
        agent_threat = _str_field(root, "tls_threat")
        if agent_threat is not None:
            hits.append(
                RuleHit(
                    id="agent_tls_threat",
                    severity="medium",
                    category="web",
                    evidence={"tls_threat": agent_threat},
                )
            )

        body = _str_field(root, "http_body_trunc") or ""
        tls = _str_field(root, "tls_payload_trunc") or ""
        if RE_SENSITIVE_BODY.search(body) or RE_SENSITIVE_BODY.search(tls):
            hits.append(
                RuleHit(
                    id="web_sensitive_token_in_telemetry",
                    severity="low",
                    category="sensitive_data",
                    evidence={"field": "http_body_trunc_or_tls_payload_trunc"},
                )
            )

        method = _str_field(root, "http_method")
        url = _str_field(root, "http_url")
        if method is not None and method.upper() == "POST" and url is not None and "login" in url.lower():
            hits.append(
                RuleHit(
                    id="web_login_post",
                    severity="info",
                    category="auth_activity",
                    evidence={"http_method": "POST"},
                )
            )

    return hits, ctx


@dataclass
class _CompiledRule:
    id: str
    event_kinds: list[int]
    field: str
    matcher: Any  # re.Pattern 或 ("contains", str)
    severity: str
    category: str


@dataclass
class Ruleset:
    """启动时加载的外部 YAML 规则。"""

    version: str
    rules: list[_CompiledRule] = field(default_factory=list)

    @property
    def rule_count(self) -> int:
        return len(self.rules)

    @classmethod
    def load(cls, path: Path) -> "Ruleset":
        raw = yaml.safe_load(path.read_text(encoding="utf-8"))
        if not isinstance(raw, dict) or "version" not in raw:
            raise ValueError(f"invalid rules file {path}")
        rules: list[_CompiledRule] = []
        for r in raw.get("rules") or []:
            match_kind = str(r.get("match", "regex")).lower()
            pattern = r["pattern"]
            if match_kind == "regex":
                matcher: Any = re.compile(pattern)
            elif match_kind == "contains":
                matcher = ("contains", pattern)
            else:
                raise ValueError(f"unsupported match kind '{match_kind}' in rule {r['id']}")
            rules.append(
                _CompiledRule(
                    id=r["id"],
                    event_kinds=[int(k) for k in r.get("event_kinds") or []],
                    field=r["field"],
                    matcher=matcher,
                    severity=r["severity"],
                    category=r["category"],
                )
            )
        return cls(version=str(raw["version"]), rules=rules)

    def analyze(
        self, root: Any, syn_tracker: SynBurstTracker
    ) -> tuple[list[RuleHit], ThreatContext]:
        hits, ctx = collect_builtin_hits(root, syn_tracker)
        if not isinstance(root, dict):
            return hits, ctx

        kind = _num_i64(root, "event_kind")
        for rule in self.rules:
            if rule.event_kinds:
                if kind is None or kind not in rule.event_kinds:
                    continue
            text = root.get(rule.field)
            if not isinstance(text, str):
                continue
            if isinstance(rule.matcher, tuple):
                matched = rule.matcher[1] in text
            else:
                matched = rule.matcher.search(text) is not None
            if matched:
                hits.append(
                    RuleHit(
                        id=rule.id,
                        severity=rule.severity,
                        category=rule.category,
                        evidence={"field": rule.field, "source": "yaml"},
                    )
                )
        return hits, ctx


def _severity_weight(severity: str) -> int:
    return {"high": 45, "medium": 22, "low": 10, "info": 4}.get(severity, 8)


def _level_from_score(score: int) -> str:
    if score >= 40:
        return "high"
    if score >= 22:
        return "medium"
    if score >= 6:
        return "low"
    return "none"


def analyze_event(
    event: dict,
    syn_tracker: SynBurstTracker,
    ruleset: Optional[Ruleset],
) -> None:
    """跑探测器并把 ``threat`` 对象合并进文档根，与 Rust ``analyze_event`` 一致。"""
    if ruleset is not None:
        hits, ctx = ruleset.analyze(event, syn_tracker)
        model_version = ruleset.version
    else:
        hits, ctx = collect_builtin_hits(event, syn_tracker)
        model_version = THREAT_MODEL_VERSION

    score = min(sum(_severity_weight(h.severity) for h in hits), 100)
    categories = sorted({h.category for h in hits})
    rules_json = [
        {"id": h.id, "severity": h.severity, "category": h.category, "evidence": h.evidence}
        for h in hits
    ]

    if not rules_json:
        level = "none"
    else:
        level = _level_from_score(score)
        if level == "none":
            level = "low"

    threat: dict[str, Any] = {
        "level": level,
        "score": score,
        "categories": categories,
        "rules": rules_json,
        "model_version": model_version,
    }
    if ctx.ssh_client_ip is not None:
        threat["context"] = {"ssh_client_ip": ctx.ssh_client_ip}

    event["threat"] = threat


def _threat_level_rank(level: str) -> int:
    return {"high": 4, "medium": 3, "low": 2, "info": 1}.get(level, 0)


def should_index_alert(root: Any, min_level: str) -> bool:
    """该文档是否镜像写入告警索引。"""
    level = "none"
    if isinstance(root, dict):
        threat = root.get("threat")
        if isinstance(threat, dict):
            value = threat.get("level")
            if isinstance(value, str):
                level = value
    if level == "none":
        return False
    return _threat_level_rank(level) >= _threat_level_rank(min_level)

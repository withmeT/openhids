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


# ---------------------------------------------------------------------------
# 多事件关联（时间窗口 + 同主机行为链）
# ---------------------------------------------------------------------------

RE_DOWNLOAD_TOOL = re.compile(r"(?i)\b(curl|wget|tftp|scp)\b")
_TMP_EXEC_PREFIXES = ("/tmp/", "/dev/shm/", "/var/tmp/")

_CORR_MAX_HOSTS = 4096
_CORR_MAX_SIGNALS_PER_HOST = 128
_CORR_MULTI_STAGE_MIN_RULES = 3


@dataclass
class _Signal:
    ts_ms: int
    kind: str  # download / tmp_exec / shell_suspicious / hit
    rule_id: str
    summary: str


class CorrelationTracker:
    """时间窗口内同主机的多事件关联（可解释的确定性行为链）。

    单个事件各自看可能只是低危信号；在窗口内构成行为链时升级告警：

    - ``corr_download_then_tmp_exec``（high）：下载工具出现后，同主机从
      /tmp、/dev/shm、/var/tmp 执行程序 —— 典型"下载落地执行"链。
    - ``corr_shell_then_sensitive_port``（medium）：可疑 shell 命令后，
      同主机出现敏感端口网络活动。
    - ``corr_multi_stage_activity``（medium）：窗口内同主机累计命中
      ≥3 条不同规则 —— 多阶段可疑活动兜底。

    每条关联告警的 evidence 附带触发链（时间 + 信号 + 摘要），可直接解释
    "为什么产生该告警"。同一主机同一关联规则在窗口内只触发一次。
    """

    def __init__(self, window_sec: int = 60, max_hosts: int = _CORR_MAX_HOSTS) -> None:
        self._window_ms = max(window_sec, 1) * 1000
        self._max_hosts = max_hosts
        self._signals: dict[str, list[_Signal]] = {}
        self._last_fired: dict[tuple[str, str], int] = {}

    # -- 信号提取 -----------------------------------------------------------

    @staticmethod
    def _event_summary(event: dict) -> str:
        for key in ("line", "exec_path", "http_url", "flow_dst_ip"):
            value = event.get(key)
            if isinstance(value, str) and value:
                return value[:80]
        return ""

    def _extract_signals(self, event: dict, hits: list[RuleHit], ts_ms: int) -> list[_Signal]:
        signals: list[_Signal] = []
        kind = _num_i64(event, "event_kind")
        summary = self._event_summary(event)

        if kind == 0:
            line = _str_field(event, "line") or ""
            if RE_DOWNLOAD_TOOL.search(line):
                signals.append(_Signal(ts_ms, "download", "", summary))
        if kind == 4:
            path = _str_field(event, "exec_path") or ""
            args = event.get("exec_args")
            arg_text = " ".join(a for a in args if isinstance(a, str)) if isinstance(args, list) else ""
            if RE_DOWNLOAD_TOOL.search(path) or RE_DOWNLOAD_TOOL.search(arg_text):
                signals.append(_Signal(ts_ms, "download", "", summary))
            if path.startswith(_TMP_EXEC_PREFIXES):
                signals.append(_Signal(ts_ms, "tmp_exec", "", summary))
        for hit in hits:
            if hit.id == "shell_suspicious_pattern":
                signals.append(_Signal(ts_ms, "shell_suspicious", hit.id, summary))
            signals.append(_Signal(ts_ms, "hit", hit.id, summary))
        return signals

    # -- 主入口 -------------------------------------------------------------

    def observe(self, event: dict, hits: list[RuleHit]) -> list[RuleHit]:
        """记录本事件信号，返回新形成的关联告警（可能为空）。"""
        if not isinstance(event, dict):
            return []
        host = _str_field(event, "host_id") or "unknown_host"
        ts_ms = _num_i64(event, "ts_ms")
        if ts_ms is None or ts_ms <= 0:
            return []

        window = self._signals.setdefault(host, [])
        # 窗口内裁剪 + 容量上限
        cutoff = ts_ms - self._window_ms
        window[:] = [s for s in window if s.ts_ms >= cutoff][-_CORR_MAX_SIGNALS_PER_HOST:]
        if len(self._signals) > self._max_hosts:
            oldest = min(self._signals, key=lambda h: self._signals[h][-1].ts_ms if self._signals[h] else 0)
            if oldest != host:
                del self._signals[oldest]

        new_signals = self._extract_signals(event, hits, ts_ms)
        corr_hits: list[RuleHit] = []

        kind = _num_i64(event, "event_kind")

        # 链 1：下载 → tmp 目录执行
        if any(s.kind == "tmp_exec" for s in new_signals):
            prior = [s for s in window if s.kind == "download"]
            if prior and self._arm(host, "corr_download_then_tmp_exec", ts_ms):
                corr_hits.append(self._make_hit(
                    "corr_download_then_tmp_exec", "high", "correlation",
                    prior[-1], ts_ms, self._event_summary(event),
                ))

        # 链 2：可疑 shell → 敏感端口网络活动
        if kind == 2 and _num_i64(event, "flow_dst_port") in _SENSITIVE_PORTS:
            prior = [s for s in window if s.kind == "shell_suspicious"]
            if prior and self._arm(host, "corr_shell_then_sensitive_port", ts_ms):
                corr_hits.append(self._make_hit(
                    "corr_shell_then_sensitive_port", "medium", "correlation",
                    prior[-1], ts_ms, self._event_summary(event),
                ))

        # 链 3：窗口内 ≥N 条不同规则命中（多阶段活动兜底）
        distinct = {s.rule_id for s in window if s.kind == "hit"}
        distinct |= {h.id for h in hits}
        if len(distinct) >= _CORR_MULTI_STAGE_MIN_RULES and self._arm(
            host, "corr_multi_stage_activity", ts_ms
        ):
            corr_hits.append(RuleHit(
                id="corr_multi_stage_activity",
                severity="medium",
                category="correlation",
                evidence={
                    "window_ms": self._window_ms,
                    "distinct_rules": sorted(distinct),
                },
            ))

        window.extend(new_signals)
        return corr_hits

    # -- 内部 ---------------------------------------------------------------

    def _arm(self, host: str, rule_id: str, ts_ms: int) -> bool:
        """同主机同关联规则在窗口内只触发一次。"""
        key = (host, rule_id)
        last = self._last_fired.get(key)
        if last is not None and ts_ms - last < self._window_ms:
            return False
        if len(self._last_fired) > self._max_hosts * 4:
            self._last_fired.clear()
        self._last_fired[key] = ts_ms
        return True

    @staticmethod
    def _make_hit(
        rule_id: str, severity: str, category: str,
        trigger: _Signal, ts_ms: int, current_summary: str,
    ) -> RuleHit:
        return RuleHit(
            id=rule_id,
            severity=severity,
            category=category,
            evidence={
                "chain": [
                    {"ts_ms": trigger.ts_ms, "signal": trigger.kind, "summary": trigger.summary},
                    {"ts_ms": ts_ms, "signal": "current_event", "summary": current_summary},
                ],
                "gap_ms": ts_ms - trigger.ts_ms,
            },
        )


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
    correlator: Optional[CorrelationTracker] = None,
) -> None:
    """跑探测器并把 ``threat`` 对象合并进文档根，与 Rust ``analyze_event`` 一致。

    传入 ``correlator`` 时追加时间窗口多事件关联（关联命中与普通规则
    一样进入 ``threat.rules``，evidence 带行为链）。
    """
    if ruleset is not None:
        hits, ctx = ruleset.analyze(event, syn_tracker)
        model_version = ruleset.version
    else:
        hits, ctx = collect_builtin_hits(event, syn_tracker)
        model_version = THREAT_MODEL_VERSION

    if correlator is not None:
        hits.extend(correlator.observe(event, hits))

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

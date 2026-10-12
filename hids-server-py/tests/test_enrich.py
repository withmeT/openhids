"""enrich / filter / time_fmt 行为对齐测试。"""

from hids_server.enrich import EnvelopeMeta, build_correlation_key, enrich_event
from hids_server.filter import pick_timestamp_iso, should_drop_plain_syn_flow
from hids_server.time_fmt import millis_to_china_display, millis_to_china_iso


def test_china_time_formats():
    # 2026-05-14 10:55:48.222 UTC -> 18:55:48.222 +08:00
    ms = 1_778_756_148_222
    assert millis_to_china_display(ms) == "2026-05-14 18:55:48.222"
    assert millis_to_china_iso(ms) == "2026-05-14T18:55:48.222+08:00"
    # 毫秒补零
    assert millis_to_china_display(1_778_756_148_005).endswith(".005")


def test_correlation_key_shapes():
    bash = {"host_id": "h1", "ssh_client_ip": "1.2.3.4", "line": "ls -la"}
    key = build_correlation_key(bash, 0)
    assert key.startswith("bash:h1:1.2.3.4:")

    flow = {
        "host_id": "h1",
        "flow_src_ip": "10.0.0.1",
        "flow_dst_ip": "10.0.0.2",
        "flow_src_port": 1234,
        "flow_dst_port": 443,
    }
    assert build_correlation_key(flow, 2) == "flow:h1:10.0.0.1:1234->10.0.0.2:443"

    http = {"host_id": "h1", "http_method": "POST", "http_url": "/login"}
    assert build_correlation_key(http, 3) == "http:h1:POST:/login"

    other = {"host_id": "h1", "ts_ms": 42}
    assert build_correlation_key(other, 6) == "kind6:h1:42"

    # 事件自带 flow_correlation_key 时直接复用
    existing = {"flow_correlation_key": "tcp:a:1->b:2"}
    assert build_correlation_key(existing, 2) == "tcp:a:1->b:2"


def test_enrich_event_fields():
    meta = EnvelopeMeta(
        agent_version="1.0", schema_version=3, host_id="h-env", batch_event_count=2
    )
    event = enrich_event({"event_kind": 0, "ts_ms": 1_778_756_148_222, "line": "id"}, meta)

    assert event["host_id"] == "h-env"
    assert event["schema_version"] == 3
    assert event["agent_version"] == "1.0"
    assert event["event_time"] == "2026-05-14 18:55:48.222"
    assert event["event_time_iso"] == "2026-05-14T18:55:48.222+08:00"
    assert event["@timestamp"] == event["event_time_iso"]
    assert event["correlation_key"].startswith("bash:h-env:-:")
    assert event["hids"]["pipeline"] == "ingest_v2"
    assert event["hids"]["batch_event_count"] == 2
    assert "ingest_ts_ms" in event and "ingest_time_iso" in event

    # 已有字段不被覆盖
    event2 = enrich_event({"host_id": "mine", "event_kind": 0, "ts_ms": 1}, meta)
    assert event2["host_id"] == "mine"


def test_client_server_ip_from_flow_key():
    meta = EnvelopeMeta(batch_event_count=1)
    event = enrich_event(
        {
            "event_kind": 7,
            "ts_ms": 1,
            "flow_correlation_key": "tcp:9.9.9.9:1234->8.8.8.8:443",
        },
        meta,
    )
    assert event["client_ip"] == "9.9.9.9"
    assert event["server_ip"] == "8.8.8.8"


def test_syn_flow_filter():
    syn = {"event_kind": 2, "flow_tcp_flags": 2, "flow_is_sensitive_port": False}
    assert should_drop_plain_syn_flow(syn, True)
    assert not should_drop_plain_syn_flow(syn, False)
    assert not should_drop_plain_syn_flow(dict(syn, flow_is_sensitive_port=True), True)
    assert not should_drop_plain_syn_flow(dict(syn, flow_tcp_flags=18), True)


def test_pick_timestamp_prefers_event_time_iso():
    assert pick_timestamp_iso({"event_time_iso": "X", "ts_ms": 1}) == "X"
    assert pick_timestamp_iso({"ts_ms": 1_778_756_148_222}) == "2026-05-14T18:55:48.222+08:00"
    assert pick_timestamp_iso({}) is None

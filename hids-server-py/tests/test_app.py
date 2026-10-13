"""/ingest 异常场景测试（建议书 9.2：鉴权、坏请求、压缩异常、队列满）。

不进入 lifespan（不启动 EsBulkWriter 后台任务），事件只进内存队列，
不会真的连 Elasticsearch。
"""

from __future__ import annotations

import gzip
import json
from pathlib import Path

from fastapi.testclient import TestClient

from hids_server.app import create_app
from hids_server.config import Config

TOKEN = "test-token"


def make_client(**overrides) -> TestClient:
    defaults = dict(
        ingest_token=TOKEN,
        threat_rules_disable=True,
        static_dir=Path("nonexistent-static"),
    )
    defaults.update(overrides)
    return TestClient(create_app(Config(**defaults)))


def post_ingest(client: TestClient, body: bytes, token: str | None = TOKEN, **headers):
    h = dict(headers)
    if token is not None:
        h["authorization"] = f"Bearer {token}"
    return client.post("/ingest", content=body, headers=h)


def envelope(events: list[dict]) -> bytes:
    return json.dumps({"events": events, "host_id": "h1", "schema_version": 4}).encode()


EV = {"event_kind": 0, "ts_ms": 1_000, "host_id": "h1", "line": "echo hi"}


def test_missing_token_401():
    client = make_client()
    assert post_ingest(client, envelope([EV]), token=None).status_code == 401


def test_wrong_token_401():
    client = make_client()
    assert post_ingest(client, envelope([EV]), token="wrong").status_code == 401


def test_no_server_token_configured_rejects_all():
    client = make_client(ingest_token=None)
    # 未配置 INGEST_TOKEN 时拒绝一切上报（安全默认）
    assert post_ingest(client, envelope([EV]), token=None).status_code == 401


def test_invalid_json_400():
    client = make_client()
    assert post_ingest(client, b"not-json").status_code == 400


def test_empty_events_400():
    client = make_client()
    assert post_ingest(client, envelope([])).status_code == 400


def test_non_object_event_400():
    client = make_client()
    body = json.dumps({"events": ["str-item"]}).encode()
    assert post_ingest(client, body).status_code == 400


def test_body_too_large_400():
    client = make_client(max_body_bytes=16)
    assert post_ingest(client, envelope([EV])).status_code == 400


def test_corrupt_gzip_400():
    client = make_client()
    resp = post_ingest(client, b"\x1f\x8bcorrupt", **{"content-encoding": "gzip"})
    assert resp.status_code == 400


def test_gzip_roundtrip_202():
    client = make_client()
    body = gzip.compress(envelope([EV]))
    resp = post_ingest(client, body, **{"content-encoding": "gzip"})
    assert resp.status_code == 202
    assert resp.json()["accepted"] == 1


def test_queue_full_503():
    client = make_client(queue_capacity=1)
    resp = post_ingest(client, envelope([EV, dict(EV, ts_ms=2_000)]))
    assert resp.status_code == 503


def test_accepted_event_gets_threat_object():
    client = make_client()
    resp = post_ingest(client, envelope([EV]))
    assert resp.status_code == 202
    state = client.app.state.hids
    stored = state.queue.get_nowait()
    assert "threat" in stored and "@timestamp" in stored


def test_stats_exposes_queue_and_spool(tmp_path):
    client = make_client(spool_dir=tmp_path)
    (tmp_path / "bulk-failed-1.ndjson").write_text("{}\n")
    post_ingest(client, envelope([EV]))
    snap = client.get("/stats").json()
    assert snap["ingest_queue_depth"] == 1
    assert snap["spool_backlog_files"] == 1
    assert snap["accepted"] == 1

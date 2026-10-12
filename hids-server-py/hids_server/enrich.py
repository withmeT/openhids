"""对应 Rust ``enrich.rs``：入队前合并服务端字段。

所有字段都遵循原实现的“不存在才写入”语义，输出字段名与格式逐一对齐，
保证 Python / Rust 两个服务端并行期间写出的文档可比对。
"""

from __future__ import annotations

import time
from dataclasses import dataclass
from typing import Any, Optional

from . import time_fmt
from .filter import pick_timestamp_iso
from .siphash import SipHasher13
from .time_fmt import json_value_as_millis

INGEST_TS_MS_FIELD = "ingest_ts_ms"
INGEST_TIME_FIELD = "ingest_time"
INGEST_TIME_ISO_FIELD = "ingest_time_iso"
EVENT_TIME_FIELD = "event_time"
EVENT_TIME_ISO_FIELD = "event_time_iso"
CLIENT_IP_FIELD = "client_ip"
SERVER_IP_FIELD = "server_ip"
CORRELATION_KEY_FIELD = "correlation_key"
ES_TIMESTAMP_FIELD = "@timestamp"


@dataclass
class EnvelopeMeta:
    """对应 Rust ``EnvelopeMeta``：batch 级元数据。"""

    agent_version: Optional[str] = None
    schema_version: Optional[int] = None
    host_id: Optional[str] = None
    batch_event_count: int = 0
    agent_stats: Optional[Any] = None


def _unix_millis_now() -> int:
    return int(time.time() * 1000)


def _str_field(event: dict, key: str) -> Optional[str]:
    value = event.get(key)
    return value if isinstance(value, str) else None


def _client_ip_from_flow_key(key: str) -> Optional[str]:
    """``tcp:client:cport->server:sport`` → client IP"""
    if not key.startswith("tcp:"):
        return None
    client = key[4:].split("->", 1)[0]
    ip = client.split(":", 1)[0]
    return ip or None


def _server_ip_from_flow_key(key: str) -> Optional[str]:
    """``tcp:client:cport->server:sport`` → server IP"""
    if not key.startswith("tcp:"):
        return None
    parts = key[4:].split("->", 1)
    if len(parts) < 2:
        return None
    ip = parts[1].split(":", 1)[0]
    return ip or None


def line_fingerprint(line: str) -> int:
    """与 Rust ``line_fingerprint`` 逐位一致（SipHash-1-3，前 128 字符）。"""
    h = SipHasher13()
    h.write_str(line[:128])
    return h.finish()


def _port_u64(event: dict, key: str) -> int:
    value = event.get(key)
    if isinstance(value, bool) or not isinstance(value, int) or value < 0:
        return 0
    return value


def build_correlation_key(event: dict, kind: Optional[int]) -> Optional[str]:
    flow_key = _str_field(event, "flow_correlation_key")
    if flow_key is not None:
        return flow_key

    host = _str_field(event, "host_id") or "unknown_host"

    if kind == 0:
        ssh = _str_field(event, "ssh_client_ip") or "-"
        line = _str_field(event, "line") or ""
        return f"bash:{host}:{ssh}:{line_fingerprint(line):x}"
    if kind == 2:
        src = _str_field(event, "flow_src_ip") or "-"
        dst = _str_field(event, "flow_dst_ip") or "-"
        sp = _port_u64(event, "flow_src_port")
        dp = _port_u64(event, "flow_dst_port")
        return f"flow:{host}:{src}:{sp}->{dst}:{dp}"
    if kind in (3, 7):
        method = _str_field(event, "http_method") or "-"
        url = _str_field(event, "http_url") or _str_field(event, "http_payload_trunc") or "-"
        return f"http:{host}:{method}:{url[:160]}"
    if kind is not None:
        ts = json_value_as_millis(event.get("ts_ms")) or 0
        return f"kind{kind}:{host}:{ts}"
    return None


def _event_kind_i64(event: dict) -> Optional[int]:
    value = event.get("event_kind")
    if isinstance(value, bool) or not isinstance(value, int):
        return None
    return value


def _normalize_ips_and_correlation(event: dict) -> None:
    kind = _event_kind_i64(event)
    flow_key = _str_field(event, "flow_correlation_key")

    if CLIENT_IP_FIELD not in event:
        client: Optional[str] = None
        if kind == 0:
            client = _str_field(event, "ssh_client_ip")
        elif kind == 2:
            client = _str_field(event, "flow_src_ip")
        elif kind in (3, 7) and flow_key is not None:
            client = _client_ip_from_flow_key(flow_key)
        if client:
            event[CLIENT_IP_FIELD] = client

    if SERVER_IP_FIELD not in event:
        server: Optional[str] = None
        if kind in (0, 3, 7):
            server = _str_field(event, "local_ip")
        elif kind == 2:
            server = _str_field(event, "flow_dst_ip")
        if server is None and flow_key is not None:
            server = _server_ip_from_flow_key(flow_key)
        if server:
            event[SERVER_IP_FIELD] = server

    if CORRELATION_KEY_FIELD not in event:
        key = build_correlation_key(event, kind)
        if key is not None:
            event[CORRELATION_KEY_FIELD] = key

    if ES_TIMESTAMP_FIELD not in event:
        iso = pick_timestamp_iso(event)
        if iso is not None:
            event[ES_TIMESTAMP_FIELD] = iso


def enrich_event(event: Any, envelope: EnvelopeMeta) -> dict:
    """应用 envelope 默认值、入库时间戳、归一化字段和 ``hids.*`` 元数据。"""
    if not isinstance(event, dict):
        event = {}

    if envelope.host_id is not None and "host_id" not in event:
        event["host_id"] = envelope.host_id
    if envelope.schema_version is not None and "schema_version" not in event:
        event["schema_version"] = envelope.schema_version
    if envelope.agent_version is not None and "agent_version" not in event:
        event["agent_version"] = envelope.agent_version

    if INGEST_TS_MS_FIELD not in event:
        event[INGEST_TS_MS_FIELD] = _unix_millis_now()

    ingest_ms = json_value_as_millis(event.get(INGEST_TS_MS_FIELD))
    if ingest_ms is not None:
        display = time_fmt.millis_to_china_display(ingest_ms)
        if display is not None:
            event[INGEST_TIME_FIELD] = display
        iso = time_fmt.millis_to_china_iso(ingest_ms)
        if iso is not None:
            event[INGEST_TIME_ISO_FIELD] = iso

    event_ms = json_value_as_millis(event.get("ts_ms"))
    if event_ms is not None:
        display = time_fmt.millis_to_china_display(event_ms)
        if display is not None:
            event[EVENT_TIME_FIELD] = display
        iso = time_fmt.millis_to_china_iso(event_ms)
        if iso is not None:
            event[EVENT_TIME_ISO_FIELD] = iso

    _normalize_ips_and_correlation(event)

    event_kind = event.get("event_kind")
    hids_meta: dict[str, Any] = {
        "pipeline": "ingest_v2",
        "batch_event_count": envelope.batch_event_count,
    }
    if isinstance(event_kind, int) and not isinstance(event_kind, bool) and event_kind >= 0:
        hids_meta["event_kind"] = event_kind
    if envelope.agent_version is not None:
        hids_meta["envelope_agent_version"] = envelope.agent_version
    if envelope.agent_stats is not None:
        hids_meta["agent_stats"] = envelope.agent_stats

    event["hids"] = hids_meta
    return event

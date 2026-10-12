"""对应 Rust ``doc_id.rs``：幂等写入用的稳定 Elasticsearch ``_id``。"""

from __future__ import annotations

from typing import Any, Optional

from .siphash import SipHasher13


def _as_u64(value: Any) -> Optional[int]:
    """对应 Rust 的 ``as_u64().or_else(as_i64 as u64)``。"""
    if isinstance(value, bool) or not isinstance(value, int):
        return None
    return value & 0xFFFF_FFFF_FFFF_FFFF if value >= -(2**63) else None


def stable_document_id(doc: Any) -> Optional[str]:
    if not isinstance(doc, dict):
        return None
    host_raw = doc.get("host_id")
    if host_raw is None:
        return None
    host = host_raw if isinstance(host_raw, str) else "unknown"
    ts = _as_u64(doc.get("ts_ms"))
    kind = _as_u64(doc.get("event_kind"))
    if ts is None or kind is None:
        return None
    pid = _as_u64(doc.get("pid")) or 0

    h = SipHasher13()
    h.write_str(host)
    h.write_u64(ts)
    h.write_u64(kind)
    h.write_u64(pid)

    line = doc.get("line")
    flow_key = doc.get("flow_correlation_key")
    url = doc.get("http_url")
    if isinstance(line, str):
        h.write_str(line[:96])
    elif isinstance(flow_key, str):
        h.write_str(flow_key)
    elif isinstance(url, str):
        h.write_str(url[:96])

    return format(h.finish(), "016x")

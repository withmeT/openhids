"""对应 Rust ``filter.rs``：入库前过滤与 ``@timestamp`` 选择。"""

from __future__ import annotations

from typing import Any, Optional

from .time_fmt import json_value_as_millis, millis_to_china_iso


def should_drop_plain_syn_flow(event: dict, enabled: bool) -> bool:
    """丢弃非敏感端口的纯 SYN flow（event_kind=2, tcp_flags=2）扫描噪声。"""
    if not enabled:
        return False
    if event.get("event_kind") != 2:
        return False
    if event.get("flow_tcp_flags") != 2:
        return False
    return event.get("flow_is_sensitive_port") is False


def pick_timestamp_iso(event: Any) -> Optional[str]:
    """优先 ``event_time_iso``，否则由 ``ts_ms`` 转中国 ISO 时间。"""
    if not isinstance(event, dict):
        return None
    iso = event.get("event_time_iso")
    if isinstance(iso, str) and iso:
        return iso
    ms = json_value_as_millis(event.get("ts_ms"))
    if ms is not None:
        return millis_to_china_iso(ms)
    return None

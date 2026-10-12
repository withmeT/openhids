"""对应 Rust ``ws.rs``：WebSocket 实时事件广播。

Rust 用 ``tokio::broadcast(4096)``，滞后时收到 ``Lagged(n)``。asyncio 版给每个
客户端一个有界 ``asyncio.Queue``；投递时队满就丢弃并累计 skipped，客户端下次
读取前先收到 ``{"_system": "lagged", "skipped": n}``，语义一致。
"""

from __future__ import annotations

import asyncio
import json
from dataclasses import dataclass, field
from typing import Any, Optional

BROADCAST_CAPACITY = 4096


@dataclass
class _Subscriber:
    queue: asyncio.Queue = field(default_factory=lambda: asyncio.Queue(maxsize=BROADCAST_CAPACITY))
    skipped: int = 0


class EventBroadcast:
    def __init__(self) -> None:
        self._subscribers: set[_Subscriber] = set()

    def subscribe(self) -> _Subscriber:
        sub = _Subscriber()
        self._subscribers.add(sub)
        return sub

    def unsubscribe(self, sub: _Subscriber) -> None:
        self._subscribers.discard(sub)

    def publish(self, event: dict) -> None:
        for sub in self._subscribers:
            try:
                sub.queue.put_nowait(event)
            except asyncio.QueueFull:
                sub.skipped += 1


def parse_kind_filter(raw: Optional[str]) -> Optional[set[int]]:
    if not raw:
        return None
    kinds: set[int] = set()
    for part in raw.split(","):
        part = part.strip()
        if part:
            try:
                kinds.add(int(part))
            except ValueError:
                continue
    return kinds or None


def matches_filter(
    event: Any,
    kinds: Optional[set[int]],
    host_id: Optional[str],
    alerts_only: bool,
) -> bool:
    if not isinstance(event, dict):
        return False
    if kinds is not None:
        kind = event.get("event_kind")
        if isinstance(kind, bool) or not isinstance(kind, int) or kind not in kinds:
            return False
    if host_id:
        if event.get("host_id") != host_id:
            return False
    if alerts_only:
        threat = event.get("threat")
        level = threat.get("level") if isinstance(threat, dict) else None
        if not isinstance(level, str) or level == "none":
            return False
    return True


def lagged_message(skipped: int) -> str:
    return json.dumps({"_system": "lagged", "skipped": skipped})

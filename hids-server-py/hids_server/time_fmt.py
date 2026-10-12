"""对应 Rust ``time_fmt.rs``：Unix 毫秒 → 中国时间（固定 UTC+8）字符串。"""

from __future__ import annotations

from datetime import datetime, timedelta, timezone
from typing import Any, Optional

CHINA_TZ = timezone(timedelta(hours=8))


def millis_to_china_display(millis: int) -> Optional[str]:
    """``2026-05-14 18:55:48.222``"""
    try:
        dt = datetime.fromtimestamp(millis / 1000, tz=CHINA_TZ)
    except (OverflowError, OSError, ValueError):
        return None
    return f"{dt.strftime('%Y-%m-%d %H:%M:%S')}.{millis % 1000:03d}"


def millis_to_china_iso(millis: int) -> Optional[str]:
    """``2026-05-14T18:55:48.222+08:00``"""
    try:
        dt = datetime.fromtimestamp(millis / 1000, tz=CHINA_TZ)
    except (OverflowError, OSError, ValueError):
        return None
    return f"{dt.strftime('%Y-%m-%dT%H:%M:%S')}.{millis % 1000:03d}+08:00"


def json_value_as_millis(value: Any) -> Optional[int]:
    """非负整数毫秒；bool 不算数字，负数与 Rust 的 ``u64::try_from`` 一样拒绝。"""
    if isinstance(value, bool) or not isinstance(value, int):
        return None
    return value if value >= 0 else None

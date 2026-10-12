"""对应 Rust ``spool.rs``：ES 批量写入永久失败时落盘，等待离线回放。"""

from __future__ import annotations

import time
from pathlib import Path


def write_failed_bulk(spool_dir: Path, body: str) -> Path:
    spool_dir.mkdir(parents=True, exist_ok=True)
    path = spool_dir / f"bulk-failed-{int(time.time() * 1000)}.ndjson"
    path.write_text(body, encoding="utf-8")
    return path

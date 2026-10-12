"""对应 Rust ``metrics.rs``：ingest 计数器快照。

CPython 下 asyncio 单线程 + GIL，普通 int 自增即可，无需原子操作。
"""

from __future__ import annotations

from dataclasses import asdict, dataclass


@dataclass
class IngestMetrics:
    accepted: int = 0
    dropped_plain_syn_flow: int = 0
    rejected_queue_full: int = 0
    rejected_unauthorized: int = 0
    rejected_bad_request: int = 0
    es_flushed_docs: int = 0
    es_alerts_flushed_docs: int = 0
    es_bulk_requests: int = 0
    es_bulk_item_errors: int = 0
    es_bulk_failures: int = 0
    es_spooled_batches: int = 0

    def snapshot(self) -> dict:
        return asdict(self)

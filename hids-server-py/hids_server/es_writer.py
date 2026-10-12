"""对应 Rust ``es_writer.rs``：异步批量写 Elasticsearch。

asyncio 版的 mpsc + tokio::select：``asyncio.Queue`` 作有界队列，
独立 task 聚批，批满（batch_size）或到时（flush_ms）即冲刷。
"""

from __future__ import annotations

import asyncio
import json
import logging
from datetime import datetime, timezone
from typing import Optional

import httpx

from .config import Config
from .doc_id import stable_document_id
from .metrics import IngestMetrics
from .spool import write_failed_bulk
from .threat import should_index_alert

logger = logging.getLogger(__name__)


def resolve_write_index(base: str, daily: bool) -> str:
    if not daily:
        return base
    return f"{base}-{datetime.now(timezone.utc).strftime('%Y.%m.%d')}"


class EsBulkWriter:
    def __init__(self, cfg: Config, queue: asyncio.Queue, metrics: IngestMetrics) -> None:
        self._cfg = cfg
        self._queue = queue
        self._metrics = metrics
        auth = (
            (cfg.es_username, cfg.es_password)
            if cfg.es_username is not None and cfg.es_password is not None
            else None
        )
        self._client = httpx.AsyncClient(base_url=cfg.es_url, auth=auth, timeout=30.0)

    async def aclose(self) -> None:
        await self._client.aclose()

    async def run(self) -> None:
        """主循环：批满（batch_size）或距首个缓冲事件超过 flush_ms 才冲刷。

        与 Rust ``es_writer.rs`` 的 ``tokio::select!`` 语义对齐：低流量下
        事件在 buffer 里累积到截止时间统一冲刷，而不是来一个发一个。
        取消时冲刷残留后退出。
        """
        buffer: list[dict] = []
        flush_interval = self._cfg.flush_ms / 1000
        deadline: Optional[float] = None
        loop = asyncio.get_running_loop()
        try:
            while True:
                timeout = None if deadline is None else max(deadline - loop.time(), 0.0)
                try:
                    event = await asyncio.wait_for(self._queue.get(), timeout=timeout)
                except asyncio.TimeoutError:
                    # 到达冲刷截止时间
                    if buffer:
                        await self._flush(buffer)
                        buffer = []
                    deadline = None
                    continue
                buffer.append(event)
                if deadline is None:
                    deadline = loop.time() + flush_interval
                while len(buffer) < self._cfg.batch_size:
                    try:
                        buffer.append(self._queue.get_nowait())
                    except asyncio.QueueEmpty:
                        break
                if len(buffer) >= self._cfg.batch_size:
                    await self._flush(buffer)
                    buffer = []
                    deadline = None
        except asyncio.CancelledError:
            if buffer:
                await self._flush(buffer)
            raise

    async def _flush(self, events: list[dict]) -> None:
        index = resolve_write_index(self._cfg.es_index, self._cfg.es_daily_index)
        body = self._build_bulk_body(events, index)
        ok = await self._post_bulk_with_retry(body, label="events")
        if ok:
            self._metrics.es_flushed_docs += len(events)

        if self._cfg.es_alerts_enabled:
            alerts = [
                ev for ev in events if should_index_alert(ev, self._cfg.es_alerts_min_level)
            ]
            if alerts:
                alerts_index = resolve_write_index(
                    self._cfg.es_alerts_index, self._cfg.es_daily_index
                )
                alerts_body = self._build_bulk_body(alerts, alerts_index)
                if await self._post_bulk_with_retry(alerts_body, label="alerts"):
                    self._metrics.es_alerts_flushed_docs += len(alerts)

    def _build_bulk_body(self, events: list[dict], index: str) -> str:
        lines: list[str] = []
        for ev in events:
            action: dict = {"index": {"_index": index}}
            if self._cfg.es_document_id:
                doc_id = stable_document_id(ev)
                if doc_id is not None:
                    action["index"]["_id"] = doc_id
            lines.append(json.dumps(action, ensure_ascii=False, separators=(",", ":")))
            lines.append(json.dumps(ev, ensure_ascii=False, separators=(",", ":")))
        return "\n".join(lines) + "\n"

    async def _post_bulk_with_retry(self, body: str, label: str) -> bool:
        delay_base = self._cfg.es_retry_base_ms / 1000
        for attempt in range(1, self._cfg.es_max_retries + 1):
            retryable, ok = await self._post_bulk_once(body)
            if ok:
                return True
            if not retryable or attempt == self._cfg.es_max_retries:
                break
            await asyncio.sleep(delay_base * (1 << min(attempt - 1, 6)))

        self._metrics.es_bulk_failures += 1
        if self._cfg.spool_on_es_failure and label == "events":
            try:
                path = write_failed_bulk(self._cfg.spool_dir, body)
                self._metrics.es_spooled_batches += 1
                logger.warning("bulk failed permanently, spooled to %s", path)
            except OSError:
                logger.exception("failed to spool bulk body")
        return False

    async def _post_bulk_once(self, body: str) -> tuple[bool, bool]:
        """返回 (retryable, ok)。429/5xx/网络错误可重试，其余 4xx 不可。"""
        self._metrics.es_bulk_requests += 1
        try:
            resp = await self._client.post(
                "/_bulk", content=body, headers={"content-type": "application/x-ndjson"}
            )
        except httpx.HTTPError as exc:
            logger.warning("bulk request error: %s", exc)
            return True, False

        if resp.status_code == 429 or resp.status_code >= 500:
            return True, False
        if resp.status_code >= 400:
            logger.error("bulk rejected (%s): %s", resp.status_code, resp.text[:500])
            return False, False

        try:
            payload = resp.json()
        except ValueError:
            return False, True
        if payload.get("errors"):
            item_errors = sum(
                1
                for item in payload.get("items", [])
                if (item.get("index") or {}).get("error") is not None
            )
            self._metrics.es_bulk_item_errors += item_errors
            logger.warning("bulk completed with %d item errors", item_errors)
        return False, True

"""EsBulkWriter 聚批语义测试：批满立即冲刷、到期统一冲刷、取消冲刷残留。

对应建议书"核心功能要有可重复测试"：锁定与 Rust ``es_writer.rs`` 对齐的
tokio::select 语义，防止回退成"来一个事件发一次 _bulk"。
"""

from __future__ import annotations

import asyncio

import pytest

from hids_server.config import Config
from hids_server.es_writer import EsBulkWriter
from hids_server.metrics import IngestMetrics


def make_writer(batch_size: int, flush_ms: int):
    cfg = Config(batch_size=batch_size, flush_ms=flush_ms)
    queue: asyncio.Queue = asyncio.Queue()
    writer = EsBulkWriter(cfg, queue, IngestMetrics())
    flushes: list[list[dict]] = []

    async def record_flush(events: list[dict]) -> None:
        flushes.append(list(events))

    writer._flush = record_flush  # type: ignore[method-assign]
    return writer, queue, flushes


async def wait_until(cond, timeout: float = 2.0) -> None:
    async with asyncio.timeout(timeout):
        while not cond():
            await asyncio.sleep(0.01)


async def test_flush_when_batch_full():
    """批满（batch_size）立即冲刷，不等 flush_ms。"""
    writer, queue, flushes = make_writer(batch_size=3, flush_ms=60_000)
    task = asyncio.create_task(writer.run())
    try:
        for i in range(3):
            queue.put_nowait({"n": i})
        await wait_until(lambda: len(flushes) == 1)
        assert [ev["n"] for ev in flushes[0]] == [0, 1, 2]
    finally:
        task.cancel()
        with pytest.raises(asyncio.CancelledError):
            await task
    await writer.aclose()


async def test_accumulates_until_deadline():
    """低流量下事件累积到 flush_ms 截止时间一次性冲刷，而不是来一个发一个。"""
    writer, queue, flushes = make_writer(batch_size=100, flush_ms=150)
    task = asyncio.create_task(writer.run())
    try:
        queue.put_nowait({"n": 0})
        await asyncio.sleep(0.05)  # 仍在冲刷窗口内
        queue.put_nowait({"n": 1})
        assert flushes == []  # 截止时间未到，不应提前冲刷
        await wait_until(lambda: len(flushes) == 1)
        assert [ev["n"] for ev in flushes[0]] == [0, 1]
    finally:
        task.cancel()
        with pytest.raises(asyncio.CancelledError):
            await task
    await writer.aclose()


async def test_cancel_flushes_remainder():
    """停机取消时冲刷残留 buffer，不丢事件。"""
    writer, queue, flushes = make_writer(batch_size=100, flush_ms=60_000)
    task = asyncio.create_task(writer.run())
    queue.put_nowait({"n": 0})
    await wait_until(lambda: queue.empty())
    await asyncio.sleep(0.02)  # 让事件进入 buffer
    task.cancel()
    with pytest.raises(asyncio.CancelledError):
        await task
    assert len(flushes) == 1 and flushes[0] == [{"n": 0}]
    await writer.aclose()

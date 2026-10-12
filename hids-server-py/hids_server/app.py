"""对应 Rust ``routes.rs`` + ``app.rs`` + ``lib.rs``：FastAPI 应用与全部路由。"""

from __future__ import annotations

import asyncio
import gzip
import io
import json
import logging
import time
from collections import deque
from contextlib import asynccontextmanager
from itertools import count
from pathlib import Path
from typing import Optional

from fastapi import FastAPI, Query, Request, WebSocket, WebSocketDisconnect
from fastapi.responses import FileResponse, JSONResponse, Response
from fastapi.staticfiles import StaticFiles

from . import enrich, filter as flt, threat
from .config import Config
from .es_writer import EsBulkWriter
from .metrics import IngestMetrics
from .protocol import ProtocolError, open_json, seal_json
from .query import EsQuery
from .ws import EventBroadcast, lagged_message, matches_filter, parse_kind_filter

logger = logging.getLogger(__name__)

MAX_DECOMPRESSED_INGEST_BYTES = 64 * 1024 * 1024
MAX_COMMAND_CHECKS = 32
MAX_COMMAND_PATHS = 64
MAX_COMMAND_QUEUE_PER_HOST = 64
MAX_COMMAND_TEXT_BYTES = 512
MAX_COMMAND_DETAIL_BYTES = 512
MAX_COMMAND_RESULT_ITEMS = 64

UNAUTHORIZED_MSG = "missing or invalid ingest credentials"
QUEUE_FULL_MSG = "ingest queue is full, please retry"
COMMAND_QUEUE_FULL_MSG = "command queue is full, please retry"


def _bad_request(msg: str) -> JSONResponse:
    return JSONResponse(status_code=400, content={"error": msg})


def _unauthorized() -> JSONResponse:
    return JSONResponse(status_code=401, content={"error": UNAUTHORIZED_MSG})


def _unix_millis_now() -> int:
    return int(time.time() * 1000)


class AppState:
    """对应 Rust ``AppState``。"""

    def __init__(self, cfg: Config) -> None:
        self.cfg = cfg
        self.metrics = IngestMetrics()
        self.queue: asyncio.Queue = asyncio.Queue(maxsize=cfg.queue_capacity)
        self.broadcast = EventBroadcast()
        self.syn_tracker = threat.SynBurstTracker(
            cfg.threat_syn_window_sec, cfg.threat_syn_threshold
        )
        self.ruleset: Optional[threat.Ruleset] = None
        if not cfg.threat_rules_disable and cfg.threat_rules_path is not None:
            try:
                self.ruleset = threat.Ruleset.load(cfg.threat_rules_path)
                logger.info(
                    "loaded %d yaml threat rules (version %s)",
                    self.ruleset.rule_count,
                    self.ruleset.version,
                )
            except (OSError, ValueError) as exc:
                logger.warning("yaml rules unavailable, using builtin only: %s", exc)
        self.command_queue: dict[str, deque] = {}
        self.command_seq = count(1)
        self.es_writer = EsBulkWriter(cfg, self.queue, self.metrics)
        self.es_query = EsQuery(cfg)
        self.writer_task: Optional[asyncio.Task] = None


def _authorize_ingest(request_headers, expected: str) -> bool:
    auth = request_headers.get("authorization")
    if auth is not None:
        scheme, _, token = auth.partition(" ")
        if scheme.lower() == "bearer" and token.strip() == expected:
            return True
    api_key = request_headers.get("x-api-key")
    return api_key is not None and api_key == expected


def _require_auth(state: AppState, request_headers) -> Optional[JSONResponse]:
    expected = state.cfg.ingest_token
    if expected is None:
        return _unauthorized()
    if not _authorize_ingest(request_headers, expected):
        return _unauthorized()
    return None


def _decode_ingest_body(body: bytes, content_encoding: Optional[str]) -> dict:
    if content_encoding and "gzip" in content_encoding.lower():
        try:
            decompressor = gzip.GzipFile(fileobj=io.BytesIO(body))
            body = decompressor.read(MAX_DECOMPRESSED_INGEST_BYTES + 1)
        except OSError as exc:
            raise ValueError(f"decompress ingest body failed: {exc}") from exc
        if len(body) > MAX_DECOMPRESSED_INGEST_BYTES:
            raise ValueError("decompressed ingest body exceeds limit")
    try:
        payload = json.loads(body)
    except ValueError as exc:
        raise ValueError(f"parse ingest body failed: {exc}") from exc
    if not isinstance(payload, dict):
        raise ValueError("parse ingest body failed: not a JSON object")
    return payload


def create_app(cfg: Optional[Config] = None) -> FastAPI:
    cfg = cfg or Config.from_env()
    state = AppState(cfg)

    @asynccontextmanager
    async def lifespan(_: FastAPI):
        state.writer_task = asyncio.create_task(state.es_writer.run())
        yield
        state.writer_task.cancel()
        try:
            await state.writer_task
        except asyncio.CancelledError:
            pass
        await state.es_writer.aclose()
        await state.es_query.aclose()

    app = FastAPI(title="hids-server", lifespan=lifespan)
    app.state.hids = state

    # --- 运维 ---

    @app.get("/healthz")
    async def healthz():
        return {
            "status": "ok",
            "queue_capacity": cfg.queue_capacity,
            "ingest_auth_required": cfg.ingest_token is not None,
            "yaml_rules": state.ruleset is not None,
            "flow_drop_plain_syn": cfg.flow_drop_plain_syn,
            "baseline_control_enabled": cfg.command_key is not None,
        }

    @app.get("/stats")
    async def stats():
        return state.metrics.snapshot()

    # --- 摄取 ---

    def _ingest_one(event: dict, meta: enrich.EnvelopeMeta) -> Optional[JSONResponse]:
        """enrich + threat + 入队 + 广播。队满返回 503。"""
        event = enrich.enrich_event(event, meta)
        threat.analyze_event(event, state.syn_tracker, state.ruleset)
        try:
            state.queue.put_nowait(event)
        except asyncio.QueueFull:
            state.metrics.rejected_queue_full += 1
            return JSONResponse(status_code=503, content={"error": QUEUE_FULL_MSG})
        state.broadcast.publish(event)
        return None

    @app.post("/ingest")
    async def ingest(request: Request):
        if (resp := _require_auth(state, request.headers)) is not None:
            state.metrics.rejected_unauthorized += 1
            return resp

        body = await request.body()
        if len(body) > cfg.max_body_bytes:
            state.metrics.rejected_bad_request += 1
            return _bad_request("request body too large")
        try:
            payload = _decode_ingest_body(body, request.headers.get("content-encoding"))
        except ValueError as exc:
            state.metrics.rejected_bad_request += 1
            return _bad_request(str(exc))

        events = payload.get("events")
        if not isinstance(events, list) or not events:
            state.metrics.rejected_bad_request += 1
            return _bad_request("events array must not be empty")
        if not all(isinstance(ev, dict) for ev in events):
            state.metrics.rejected_bad_request += 1
            return _bad_request("each events[] item must be a JSON object")

        meta = enrich.EnvelopeMeta(
            agent_version=payload.get("agent_version"),
            schema_version=payload.get("schema_version"),
            host_id=payload.get("host_id"),
            batch_event_count=len(events),
            agent_stats=payload.get("agent_stats"),
        )

        accepted = 0
        for event in events:
            if flt.should_drop_plain_syn_flow(event, cfg.flow_drop_plain_syn):
                state.metrics.dropped_plain_syn_flow += 1
                continue
            if (resp := _ingest_one(event, meta)) is not None:
                return resp
            accepted += 1

        if accepted == 0:
            state.metrics.rejected_bad_request += 1
            return _bad_request("no events accepted after filtering")

        state.metrics.accepted += accepted
        return JSONResponse(
            status_code=202, content={"accepted": accepted, "batch_size": len(events)}
        )

    # --- 查询 ---

    @app.get("/events/search")
    async def events_search(
        request: Request,
        size: int = Query(default=50, ge=1),
        from_offset: int = Query(default=0, ge=0),
        event_kind: Optional[int] = None,
        host_id: Optional[str] = None,
        keyword: Optional[str] = None,
        threat_level: Optional[str] = None,
        client_ip: Optional[str] = None,
        sort: str = "@timestamp",
        order: str = "desc",
    ):
        try:
            return await state.es_query.events_search(
                time_from=request.query_params.get("from"),
                time_to=request.query_params.get("to"),
                host_id=host_id,
                event_kind=event_kind,
                keyword=keyword,
                threat_level=threat_level,
                client_ip=client_ip,
                size=size,
                from_offset=from_offset,
                sort=sort,
                order=order,
            )
        except Exception as exc:  # ES 不可达/查询错误 → 400，与 Rust 一致
            return _bad_request(f"es search failed: {exc}")

    @app.get("/events/recent")
    async def events_recent(
        size: int = Query(default=20, ge=1), event_kind: Optional[int] = None
    ):
        try:
            return await state.es_query.events_recent(size=size, event_kind=event_kind)
        except Exception as exc:
            return _bad_request(f"es search failed: {exc}")

    @app.get("/alerts")
    async def alerts(
        request: Request,
        size: int = Query(default=50, ge=1),
        from_offset: int = Query(default=0, ge=0),
        level: Optional[str] = None,
        host_id: Optional[str] = None,
    ):
        try:
            return await state.es_query.alerts_search(
                size=size,
                from_offset=from_offset,
                level=level,
                host_id=host_id,
                time_from=request.query_params.get("from"),
                time_to=request.query_params.get("to"),
            )
        except Exception as exc:
            return _bad_request(f"es search failed: {exc}")

    @app.get("/hosts")
    async def hosts():
        try:
            return await state.es_query.hosts_list()
        except Exception as exc:
            return _bad_request(f"es search failed: {exc}")

    # --- 加密控制面 ---

    @app.post("/commands")
    async def enqueue_command(request: Request):
        if (resp := _require_auth(state, request.headers)) is not None:
            return resp
        if cfg.command_key is None:
            return _bad_request("HIDS_COMMAND_KEY is not configured")

        try:
            payload = json.loads(await request.body())
        except ValueError as exc:
            return _bad_request(f"parse command request failed: {exc}")
        host_id = payload.get("host_id")
        checks = payload.get("checks")
        if not isinstance(host_id, str) or not host_id.strip() or not checks:
            return _bad_request("host_id and checks are required")
        if len(host_id) > MAX_COMMAND_TEXT_BYTES:
            return _bad_request("host_id is too long")
        if not isinstance(checks, list) or len(checks) > MAX_COMMAND_CHECKS:
            return _bad_request(f"at most {MAX_COMMAND_CHECKS} checks are allowed")
        for check in checks:
            if not isinstance(check, dict):
                return _bad_request("each check must be an object")
            check_id = check.get("id")
            if (
                not isinstance(check_id, str)
                or not check_id.strip()
                or len(check_id) > MAX_COMMAND_TEXT_BYTES
            ):
                return _bad_request("each check id must be 1-512 bytes")
            paths = check.get("paths") or []
            if len(paths) > MAX_COMMAND_PATHS or any(
                not isinstance(p, str) or len(p) > MAX_COMMAND_TEXT_BYTES for p in paths
            ):
                return _bad_request(
                    f"each file hash check supports at most {MAX_COMMAND_PATHS} paths"
                    f" of {MAX_COMMAND_TEXT_BYTES} bytes"
                )

        now = _unix_millis_now()
        request_id = f"baseline-{now}-{next(state.command_seq)}"
        ttl = payload.get("ttl_secs")
        ttl = ttl if isinstance(ttl, int) and not isinstance(ttl, bool) else 300
        command = {
            "request_id": request_id,
            "host_id": host_id,
            "issued_at_ms": now,
            "expires_at_ms": now + min(max(ttl, 10), 3600) * 1000,
            "checks": checks,
        }
        queue = state.command_queue.setdefault(host_id, deque())
        if len(queue) >= MAX_COMMAND_QUEUE_PER_HOST:
            return JSONResponse(status_code=429, content={"error": COMMAND_QUEUE_FULL_MSG})
        queue.append(command)
        return JSONResponse(status_code=202, content={"request_id": request_id})

    @app.get("/commands/next")
    async def next_command(request: Request, host_id: str):
        if (resp := _require_auth(state, request.headers)) is not None:
            return resp
        if cfg.command_key is None:
            return _bad_request("HIDS_COMMAND_KEY is not configured")

        queue = state.command_queue.get(host_id)
        command = queue.popleft() if queue else None
        if command is None:
            return Response(status_code=204)
        try:
            envelope = seal_json(command, cfg.command_key)
        except Exception as exc:
            return _bad_request(f"encrypt command failed: {exc}")
        return JSONResponse(status_code=200, content=envelope)

    @app.post("/commands/result")
    async def command_result(request: Request):
        if (resp := _require_auth(state, request.headers)) is not None:
            return resp
        if cfg.command_key is None:
            return _bad_request("HIDS_COMMAND_KEY is not configured")

        try:
            envelope = json.loads(await request.body())
            result = open_json(envelope, cfg.command_key)
        except (ValueError, ProtocolError) as exc:
            return _bad_request(f"decrypt baseline result failed: {exc}")

        request_id = result.get("request_id")
        host_id = result.get("host_id")
        items = result.get("results")
        if (
            not isinstance(request_id, str)
            or not request_id.strip()
            or not isinstance(host_id, str)
            or not host_id.strip()
        ):
            return _bad_request("baseline result request_id and host_id are required")
        if not isinstance(items, list) or not items or len(items) > MAX_COMMAND_RESULT_ITEMS:
            return _bad_request(
                f"baseline result must contain 1-{MAX_COMMAND_RESULT_ITEMS} items"
            )
        oversized = (
            len(request_id) > MAX_COMMAND_TEXT_BYTES
            or len(host_id) > MAX_COMMAND_TEXT_BYTES
            or any(
                not isinstance(item, dict)
                or len(item.get("id") or "") > MAX_COMMAND_TEXT_BYTES
                or len(item.get("summary") or "") > MAX_COMMAND_TEXT_BYTES
                or len(item.get("details") or []) > MAX_COMMAND_RESULT_ITEMS
                or any(len(d) > MAX_COMMAND_DETAIL_BYTES for d in item.get("details") or [])
                for item in items
            )
        )
        if oversized:
            return _bad_request("baseline result contains oversized fields")

        completed_at = result.get("completed_at_ms") or 0
        meta = enrich.EnvelopeMeta(
            agent_version="control-plane", schema_version=5, batch_event_count=1
        )
        accepted = 0
        for item in items:
            event = {
                "event_kind": 8,
                "ts_ms": completed_at,
                "uid": 0,
                "tgid": 0,
                "pid": 0,
                "comm": "baseline",
                "host_id": host_id,
                "baseline_request_id": request_id,
                "baseline_check": item.get("kind") or "unknown",
                "baseline_status": item.get("status") or "unknown",
                "baseline_result": json.dumps(
                    {"summary": item.get("summary") or "", "details": item.get("details") or []},
                    ensure_ascii=False,
                    separators=(",", ":"),
                ),
            }
            if (resp := _ingest_one(event, meta)) is not None:
                return resp
            accepted += 1
        state.metrics.accepted += accepted
        return JSONResponse(status_code=202, content={"accepted": accepted})

    # --- WebSocket ---

    @app.websocket("/ws/events")
    async def ws_events(websocket: WebSocket):
        kinds = parse_kind_filter(websocket.query_params.get("event_kinds"))
        host_id = websocket.query_params.get("host_id")
        alerts_only = (websocket.query_params.get("alerts_only") or "").lower() == "true"

        await websocket.accept()
        sub = state.broadcast.subscribe()
        try:
            while True:
                event = await sub.queue.get()
                if sub.skipped:
                    skipped, sub.skipped = sub.skipped, 0
                    await websocket.send_text(lagged_message(skipped))
                if matches_filter(event, kinds, host_id, alerts_only):
                    await websocket.send_text(
                        json.dumps(event, ensure_ascii=False, separators=(",", ":"))
                    )
        except (WebSocketDisconnect, RuntimeError):
            pass
        finally:
            state.broadcast.unsubscribe(sub)

    # --- 静态文件 + SPA fallback ---

    static_dir: Path = cfg.static_dir
    if static_dir.is_dir():
        app.mount("/static", StaticFiles(directory=str(static_dir)), name="static")

        @app.get("/{path:path}", include_in_schema=False)
        async def spa(path: str):
            candidate = (static_dir / path).resolve()
            if (
                path
                and candidate.is_file()
                and candidate.is_relative_to(static_dir.resolve())
            ):
                return FileResponse(candidate)
            index = static_dir / "index.html"
            if index.is_file():
                return FileResponse(index)
            return JSONResponse(status_code=404, content={"error": "not found"})

    return app

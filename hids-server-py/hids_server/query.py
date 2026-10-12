"""对应 Rust ``query.rs``：Elasticsearch 查询接口的 DSL 构造与响应整形。"""

from __future__ import annotations

from typing import Any, Optional

import httpx

from .config import Config

MAX_PAGE_SIZE = 500
MAX_RECENT_SIZE = 200


def resolve_query_index(cfg: Config) -> str:
    return f"{cfg.es_index}*" if cfg.es_daily_index else cfg.es_index


def resolve_alerts_query_index(cfg: Config) -> str:
    return f"{cfg.es_alerts_index}*" if cfg.es_daily_index else cfg.es_alerts_index


def _hits(payload: dict) -> tuple[int, list[dict]]:
    hits = payload.get("hits") or {}
    total = ((hits.get("total") or {}).get("value")) or 0
    events = [h.get("_source") for h in hits.get("hits") or [] if h.get("_source") is not None]
    return total, events


class EsQuery:
    def __init__(self, cfg: Config) -> None:
        self._cfg = cfg
        auth = (
            (cfg.es_username, cfg.es_password)
            if cfg.es_username is not None and cfg.es_password is not None
            else None
        )
        self._client = httpx.AsyncClient(base_url=cfg.es_url, auth=auth, timeout=30.0)

    async def aclose(self) -> None:
        await self._client.aclose()

    async def _search(self, index: str, body: dict) -> dict:
        resp = await self._client.post(f"/{index}/_search", json=body)
        resp.raise_for_status()
        return resp.json()

    async def events_search(
        self,
        *,
        time_from: Optional[str] = None,
        time_to: Optional[str] = None,
        host_id: Optional[str] = None,
        event_kind: Optional[int] = None,
        keyword: Optional[str] = None,
        threat_level: Optional[str] = None,
        client_ip: Optional[str] = None,
        size: int = 50,
        from_offset: int = 0,
        sort: str = "@timestamp",
        order: str = "desc",
    ) -> dict:
        must: list[dict] = []
        if time_from or time_to:
            rng: dict[str, Any] = {}
            if time_from:
                rng["gte"] = time_from
            if time_to:
                rng["lte"] = time_to
            must.append({"range": {"@timestamp": rng}})
        if host_id:
            must.append({"term": {"host_id": host_id}})
        if event_kind is not None:
            must.append({"term": {"event_kind": event_kind}})
        if threat_level:
            must.append({"term": {"threat.level": threat_level}})
        if client_ip:
            must.append({"term": {"client_ip": client_ip}})
        if keyword:
            must.append(
                {
                    "multi_match": {
                        "query": keyword,
                        "fields": [
                            "line",
                            "http_url",
                            "http_body_trunc",
                            "tls_payload_trunc",
                            "exec_path",
                            "file_path",
                            "comm",
                            "correlation_key",
                        ],
                        "type": "phrase_prefix",
                    }
                }
            )

        body = {
            "query": {"bool": {"must": must}} if must else {"match_all": {}},
            "size": min(size, MAX_PAGE_SIZE),
            "from": from_offset,
            "sort": [{sort: {"order": order if order in ("asc", "desc") else "desc"}}],
        }
        payload = await self._search(resolve_query_index(self._cfg), body)
        total, events = _hits(payload)
        return {"total": total, "events": events}

    async def events_recent(self, *, size: int = 20, event_kind: Optional[int] = None) -> dict:
        must: list[dict] = []
        if event_kind is not None:
            must.append({"term": {"event_kind": event_kind}})
        body = {
            "query": {"bool": {"must": must}} if must else {"match_all": {}},
            "size": min(size, MAX_RECENT_SIZE),
            "sort": [{"@timestamp": {"order": "desc"}}],
        }
        payload = await self._search(resolve_query_index(self._cfg), body)
        total, events = _hits(payload)
        return {"total": total, "events": events}

    async def alerts_search(
        self,
        *,
        size: int = 50,
        from_offset: int = 0,
        level: Optional[str] = None,
        host_id: Optional[str] = None,
        time_from: Optional[str] = None,
        time_to: Optional[str] = None,
    ) -> dict:
        must: list[dict] = []
        if level:
            must.append({"term": {"threat.level": level}})
        if host_id:
            must.append({"term": {"host_id": host_id}})
        if time_from or time_to:
            rng: dict[str, Any] = {}
            if time_from:
                rng["gte"] = time_from
            if time_to:
                rng["lte"] = time_to
            must.append({"range": {"@timestamp": rng}})

        body = {
            "query": {
                "bool": {
                    "must": must,
                    "must_not": [{"term": {"threat.level": "none"}}],
                }
            },
            "size": min(size, MAX_PAGE_SIZE),
            "from": from_offset,
            "sort": [{"@timestamp": {"order": "desc"}}],
        }
        payload = await self._search(resolve_query_index(self._cfg), body)
        total, events = _hits(payload)
        return {"total": total, "events": events}

    async def hosts_list(self) -> dict:
        body = {
            "size": 0,
            "aggs": {
                "hosts": {
                    "terms": {"field": "host_id", "size": 1000},
                    "aggs": {
                        "last_seen": {"max": {"field": "@timestamp"}},
                        "event_count": {"value_count": {"field": "event_kind"}},
                    },
                }
            },
        }
        payload = await self._search(resolve_query_index(self._cfg), body)
        buckets = (((payload.get("aggregations") or {}).get("hosts") or {}).get("buckets")) or []
        hosts = [
            {
                "host_id": b.get("key"),
                "event_count": int((b.get("event_count") or {}).get("value") or 0),
                "last_seen": (b.get("last_seen") or {}).get("value_as_string"),
            }
            for b in buckets
        ]
        return {"hosts": hosts, "total": len(hosts)}

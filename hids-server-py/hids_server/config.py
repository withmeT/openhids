"""对应 Rust ``config.rs``：全部来自环境变量，别名与默认值保持一致。"""

from __future__ import annotations

import os
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional


def _env(name: str, *aliases: str) -> Optional[str]:
    for key in (name, *aliases):
        value = os.environ.get(key)
        if value is not None and value != "":
            return value
    return None


def _env_bool(name: str, default: bool) -> bool:
    raw = _env(name)
    if raw is None:
        return default
    return raw.strip().lower() in ("1", "true", "yes", "on")


def _env_int(name: str, default: int, minimum: Optional[int] = None) -> int:
    raw = _env(name)
    try:
        value = int(raw) if raw is not None else default
    except ValueError:
        value = default
    if minimum is not None:
        value = max(value, minimum)
    return value


@dataclass
class Config:
    bind_addr: str = "127.0.0.1:8000"
    es_url: str = "http://127.0.0.1:9200"
    es_index: str = "hids-events"
    es_alerts_index: str = "hids-alerts"
    es_alerts_enabled: bool = True
    es_alerts_min_level: str = "low"
    es_username: Optional[str] = None
    es_password: Optional[str] = None
    queue_capacity: int = 50_000
    batch_size: int = 1_000
    flush_ms: int = 200
    threat_syn_window_sec: int = 1
    threat_syn_threshold: int = 15
    threat_corr_window_sec: int = 60
    threat_corr_disable: bool = False
    threat_rules_path: Optional[Path] = field(default_factory=lambda: Path("rules/threat-rules.yaml"))
    threat_rules_disable: bool = False
    flow_drop_plain_syn: bool = False
    es_max_retries: int = 5
    es_retry_base_ms: int = 200
    es_daily_index: bool = False
    es_document_id: bool = True
    spool_dir: Path = field(default_factory=lambda: Path("./spool-server"))
    spool_on_es_failure: bool = True
    ingest_token: Optional[str] = None
    max_body_bytes: int = 32 * 1024 * 1024
    static_dir: Path = field(default_factory=lambda: Path("static"))
    command_key: Optional[bytes] = None

    @classmethod
    def from_env(cls) -> "Config":
        from .protocol import parse_key

        command_key: Optional[bytes] = None
        raw_key = _env("HIDS_COMMAND_KEY")
        if raw_key is not None:
            command_key = parse_key(raw_key)

        rules_path_raw = _env("THREAT_RULES_PATH")
        rules_path: Optional[Path] = (
            Path(rules_path_raw) if rules_path_raw else Path("rules/threat-rules.yaml")
        )

        return cls(
            bind_addr=_env("BIND_ADDR") or "127.0.0.1:8000",
            es_url=_env("ES_URL", "HIDS_ES_URL") or "http://127.0.0.1:9200",
            es_index=_env("ES_INDEX", "HIDS_ES_INDEX") or "hids-events",
            es_alerts_index=_env("ES_ALERTS_INDEX") or "hids-alerts",
            es_alerts_enabled=_env_bool("ES_ALERTS_ENABLED", True),
            es_alerts_min_level=_env("ES_ALERTS_MIN_LEVEL") or "low",
            es_username=_env("ES_USERNAME", "HIDS_ES_USER"),
            es_password=_env("ES_PASSWORD", "HIDS_ES_PASSWORD"),
            queue_capacity=_env_int("QUEUE_CAPACITY", 50_000, minimum=1),
            batch_size=_env_int("BATCH_SIZE", 1_000, minimum=1),
            flush_ms=_env_int("FLUSH_MS", 200, minimum=1),
            threat_syn_window_sec=_env_int("THREAT_SYN_WINDOW_SEC", 1, minimum=1),
            threat_syn_threshold=_env_int("THREAT_SYN_THRESHOLD", 15, minimum=2),
            threat_corr_window_sec=_env_int("THREAT_CORR_WINDOW_SEC", 60, minimum=1),
            threat_corr_disable=_env_bool("THREAT_CORR_DISABLE", False),
            threat_rules_path=rules_path,
            threat_rules_disable=_env_bool("THREAT_RULES_DISABLE", False),
            flow_drop_plain_syn=_env_bool("FLOW_DROP_PLAIN_SYN", False),
            es_max_retries=_env_int("ES_MAX_RETRIES", 5, minimum=1),
            es_retry_base_ms=_env_int("ES_RETRY_BASE_MS", 200, minimum=50),
            es_daily_index=_env_bool("ES_DAILY_INDEX", False),
            es_document_id=_env_bool("ES_DOCUMENT_ID", True),
            spool_dir=Path(_env("SPOOL_DIR") or "./spool-server"),
            spool_on_es_failure=_env_bool("SPOOL_ON_ES_FAILURE", True),
            ingest_token=_env("INGEST_TOKEN", "HIDS_API_KEY"),
            max_body_bytes=_env_int("INGEST_MAX_BODY_MB", 32, minimum=1) * 1024 * 1024,
            static_dir=Path(_env("STATIC_DIR") or "static"),
            command_key=command_key,
        )

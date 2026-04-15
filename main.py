#!/usr/bin/env python3
from __future__ import annotations

"""
服务端（demo.md 版）

- POST /ingest: 接收 agent 批次事件（重点是 event_kind=2 的 flow 五元组）
- 写入 received.jsonl: 保留原始事件（用于回放/验证不丢）
- 写入 alerts.jsonl: 输出威胁检测告警（规则见 demo.md）

目标：
- XDP 客户端极致轻量（不依赖 payload）
- 服务端做滑动窗口建模 + 规则检测
"""

import json
import math
import statistics
import time
from collections import Counter, defaultdict, deque
from dataclasses import dataclass
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Deque, Dict, Iterable, List, Optional, Tuple


def now_ms() -> int:
    return int(time.time() * 1000)


def _safe_int(x, default=0) -> int:
    try:
        return int(x)
    except Exception:
        return default


def _stddev(xs: List[float]) -> float:
    if len(xs) < 2:
        return float("inf")
    try:
        return statistics.pstdev(xs)
    except Exception:
        return float("inf")


@dataclass
class SlidingUniqueCounter:
    window_ms: int
    # store (ts_ms, value)
    q: Deque[Tuple[int, str]]
    cnt: Counter

    @classmethod
    def new(cls, window_ms: int) -> "SlidingUniqueCounter":
        return cls(window_ms=window_ms, q=deque(), cnt=Counter())

    def add(self, ts_ms: int, value: str) -> None:
        self._evict(ts_ms)
        self.q.append((ts_ms, value))
        self.cnt[value] += 1

    def unique(self, ts_ms: int) -> int:
        self._evict(ts_ms)
        return len(self.cnt)

    def total(self, ts_ms: int) -> int:
        self._evict(ts_ms)
        return len(self.q)

    def _evict(self, ts_ms: int) -> None:
        cutoff = ts_ms - self.window_ms
        while self.q and self.q[0][0] < cutoff:
            _, v = self.q.popleft()
            self.cnt[v] -= 1
            if self.cnt[v] <= 0:
                del self.cnt[v]


@dataclass
class SlidingAvg:
    window_ms: int
    q: Deque[Tuple[int, int]]
    s: int

    @classmethod
    def new(cls, window_ms: int) -> "SlidingAvg":
        return cls(window_ms=window_ms, q=deque(), s=0)

    def add(self, ts_ms: int, value: int) -> None:
        self._evict(ts_ms)
        self.q.append((ts_ms, value))
        self.s += value

    def avg(self, ts_ms: int) -> float:
        self._evict(ts_ms)
        if not self.q:
            return 0.0
        return self.s / len(self.q)

    def count(self, ts_ms: int) -> int:
        self._evict(ts_ms)
        return len(self.q)

    def _evict(self, ts_ms: int) -> None:
        cutoff = ts_ms - self.window_ms
        while self.q and self.q[0][0] < cutoff:
            _, v = self.q.popleft()
            self.s -= v


@dataclass
class BeaconTracker:
    window_ms: int
    max_intervals: int
    last_ts_ms: Optional[int]
    intervals_ms: Deque[int]

    @classmethod
    def new(cls, window_ms: int, max_intervals: int = 24) -> "BeaconTracker":
        return cls(
            window_ms=window_ms,
            max_intervals=max_intervals,
            last_ts_ms=None,
            intervals_ms=deque(),
        )

    def add(self, ts_ms: int) -> None:
        if self.last_ts_ms is not None:
            dt = ts_ms - self.last_ts_ms
            if dt >= 0:
                self.intervals_ms.append(dt)
                while len(self.intervals_ms) > self.max_intervals:
                    self.intervals_ms.popleft()
        self.last_ts_ms = ts_ms

        # We can't precisely evict old intervals without storing timestamps per interval.
        # Use max_intervals as a cap to keep memory bounded.

    def score(self) -> Tuple[int, float]:
        xs = list(self.intervals_ms)
        if len(xs) < 6:
            return (len(xs), float("inf"))
        return (len(xs), _stddev([float(x) for x in xs]))


class ThreatModel:
    """
    demo.md rules:
    - port scan: src_ip, 30s unique_dst_port>20 and total_conn>30
    - lateral movement: src_ip, 60s dst_port fixed and unique_dst_ip>20
    - brute force: src_ip, 30s dst_port in {22,3306} conn_count > threshold (ssh>20 mysql>10)
    - beaconing: src_ip->dst_ip stable interval (stddev below threshold)
    - ddos/flood: dst_ip, 1s conn_rate > N
    """

    def __init__(self):
        self.src_conn_30 = defaultdict(lambda: SlidingUniqueCounter.new(30_000))
        self.src_ports_30 = defaultdict(lambda: SlidingUniqueCounter.new(30_000))
        self.src_dstips_60 = defaultdict(lambda: SlidingUniqueCounter.new(60_000))
        self.src_avg_payload_60 = defaultdict(lambda: SlidingAvg.new(60_000))

        # lateral: (src_ip, dst_port) -> unique dst_ip in 60s
        self.src_port_dstips_60: Dict[Tuple[str, int], SlidingUniqueCounter] = defaultdict(
            lambda: SlidingUniqueCounter.new(60_000)
        )

        # brute: (src_ip, dst_port) -> conn count in 30s
        self.src_port_conn_30: Dict[Tuple[str, int], SlidingUniqueCounter] = defaultdict(
            lambda: SlidingUniqueCounter.new(30_000)
        )

        # beacon: (src_ip, dst_ip) -> intervals
        self.beacon_5m: Dict[Tuple[str, str], BeaconTracker] = defaultdict(
            lambda: BeaconTracker.new(5 * 60_000)
        )

        # ddos per dst: count events per second
        self.dst_conn_1s: Dict[str, int] = defaultdict(int)
        self.dst_conn_1s_bucket: int = int(time.time())

        # suppress repeated alerts
        self.last_alert_ms: Dict[Tuple[str, str], int] = {}

    def ingest_flow(self, ev: dict) -> List[dict]:
        ts_ms = _safe_int(ev.get("ts_ms"), now_ms())
        src_ip = str(ev.get("flow_src_ip") or ev.get("src_ip") or "")
        dst_ip = str(ev.get("flow_dst_ip") or ev.get("dst_ip") or "")
        dst_port = _safe_int(ev.get("flow_dst_port") or ev.get("dst_port"), 0)
        payload_len = _safe_int(ev.get("flow_payload_len") or ev.get("payload_len"), 0)

        if not src_ip or not dst_ip or dst_port <= 0:
            return []

        # 1) base aggregation
        self.src_conn_30[src_ip].add(ts_ms, "1")  # value doesn't matter; q length is conn count
        self.src_ports_30[src_ip].add(ts_ms, str(dst_port))
        self.src_dstips_60[src_ip].add(ts_ms, dst_ip)
        self.src_avg_payload_60[src_ip].add(ts_ms, payload_len)

        self.src_port_dstips_60[(src_ip, dst_port)].add(ts_ms, dst_ip)
        self.src_port_conn_30[(src_ip, dst_port)].add(ts_ms, "1")

        self.beacon_5m[(src_ip, dst_ip)].add(ts_ms)

        # 2) ddos bucket
        sec = int(ts_ms / 1000)
        if sec != self.dst_conn_1s_bucket:
            self.dst_conn_1s_bucket = sec
            self.dst_conn_1s.clear()
        self.dst_conn_1s[dst_ip] += 1

        # 3) rules
        alerts: List[dict] = []
        alerts.extend(self._rule_port_scan(src_ip, ts_ms))
        alerts.extend(self._rule_lateral(src_ip, dst_port, ts_ms))
        alerts.extend(self._rule_bruteforce(src_ip, dst_port, ts_ms))
        alerts.extend(self._rule_beacon(src_ip, dst_ip, ts_ms))
        alerts.extend(self._rule_ddos(dst_ip, ts_ms))
        return alerts

    def _emit(self, kind: str, key: str, ts_ms: int, detail: dict) -> List[dict]:
        suppress_key = (kind, key)
        last = self.last_alert_ms.get(suppress_key, 0)
        # suppress duplicates for 10s
        if ts_ms - last < 10_000:
            return []
        self.last_alert_ms[suppress_key] = ts_ms
        return [
            {
                "alert_kind": kind,
                "ts_ms": ts_ms,
                "key": key,
                **detail,
            }
        ]

    def _rule_port_scan(self, src_ip: str, ts_ms: int) -> List[dict]:
        uniq_ports = self.src_ports_30[src_ip].unique(ts_ms)
        total_conn = self.src_conn_30[src_ip].total(ts_ms)
        if uniq_ports > 20 and total_conn > 30:
            return self._emit(
                "port_scan_suspected",
                src_ip,
                ts_ms,
                {
                    "src_ip": src_ip,
                    "window_s": 30,
                    "unique_dst_port": uniq_ports,
                    "total_conn": total_conn,
                },
            )
        return []

    def _rule_lateral(self, src_ip: str, dst_port: int, ts_ms: int) -> List[dict]:
        uniq_dst_ip = self.src_port_dstips_60[(src_ip, dst_port)].unique(ts_ms)
        if uniq_dst_ip > 20:
            return self._emit(
                "lateral_movement_suspected",
                f"{src_ip}:{dst_port}",
                ts_ms,
                {
                    "src_ip": src_ip,
                    "dst_port": dst_port,
                    "window_s": 60,
                    "unique_dst_ip": uniq_dst_ip,
                },
            )
        return []

    def _rule_bruteforce(self, src_ip: str, dst_port: int, ts_ms: int) -> List[dict]:
        if dst_port not in (22, 3306):
            return []
        count = self.src_port_conn_30[(src_ip, dst_port)].total(ts_ms)
        thresh = 20 if dst_port == 22 else 10
        if count > thresh:
            return self._emit(
                "bruteforce_suspected",
                f"{src_ip}:{dst_port}",
                ts_ms,
                {
                    "src_ip": src_ip,
                    "dst_port": dst_port,
                    "window_s": 30,
                    "connection_count": count,
                    "threshold": thresh,
                    "service": "ssh" if dst_port == 22 else "mysql",
                },
            )
        return []

    def _rule_beacon(self, src_ip: str, dst_ip: str, ts_ms: int) -> List[dict]:
        n, sd = self.beacon_5m[(src_ip, dst_ip)].score()
        # Heuristic: stddev < 300ms for stable beaconing (tunable)
        if n >= 6 and sd < 300.0:
            return self._emit(
                "c2_beaconing_suspected",
                f"{src_ip}->{dst_ip}",
                ts_ms,
                {
                    "src_ip": src_ip,
                    "dst_ip": dst_ip,
                    "window_s": 300,
                    "interval_samples": n,
                    "interval_stddev_ms": sd,
                },
            )
        return []

    def _rule_ddos(self, dst_ip: str, ts_ms: int) -> List[dict]:
        # demo.md: 1s conn_rate > N
        n = self.dst_conn_1s.get(dst_ip, 0)
        if n > 500:
            return self._emit(
                "ddos_flood_suspected",
                dst_ip,
                ts_ms,
                {
                    "dst_ip": dst_ip,
                    "window_s": 1,
                    "conn_rate": n,
                    "threshold": 500,
                },
            )
        return []


MODEL = ThreatModel()


class Handler(BaseHTTPRequestHandler):
    server_version = "hids-main/0.2"
    spool_file = "received.jsonl"
    alerts_file = "alerts.jsonl"

    def _send(self, code: int, body: dict):
        data = json.dumps(body, ensure_ascii=False).encode("utf-8")
        self.send_response(code)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    def do_POST(self):
        if self.path != "/ingest":
            self._send(404, {"ok": False, "error": "not found"})
            return

        n = int(self.headers.get("Content-Length", "0") or "0")
        raw = self.rfile.read(n)
        try:
            payload = json.loads(raw.decode("utf-8") if raw else "null")
        except Exception as e:
            self._send(400, {"ok": False, "error": f"invalid json: {e}"})
            return

        # envelope support
        if isinstance(payload, dict) and "events" in payload:
            meta = {
                "agent_version": payload.get("agent_version"),
                "schema_version": payload.get("schema_version"),
                "host_id": payload.get("host_id"),
            }
            items = payload.get("events") or []
            items = [
                {**it, **{k: v for k, v in meta.items() if v is not None}}
                for it in items
                if isinstance(it, dict)
            ]
        else:
            items = payload if isinstance(payload, list) else [payload]

        # persist raw events
        try:
            if items:
                with open(self.spool_file, "a", encoding="utf-8") as f:
                    for it in items:
                        f.write(json.dumps(it, ensure_ascii=False) + "\n")
        except Exception as e:
            self._send(500, {"ok": False, "error": f"failed to write {self.spool_file}: {e}"})
            return

        # run detection on flow events
        alerts: List[dict] = []
        for it in items:
            if not isinstance(it, dict):
                continue
            if _safe_int(it.get("event_kind"), -1) != 2:
                continue
            alerts.extend(MODEL.ingest_flow(it))

        if alerts:
            try:
                with open(self.alerts_file, "a", encoding="utf-8") as f:
                    for a in alerts:
                        f.write(json.dumps(a, ensure_ascii=False) + "\n")
            except Exception as e:
                self._send(
                    500, {"ok": False, "error": f"failed to write {self.alerts_file}: {e}"}
                )
                return

        # 只打印 HTTPS/TLS 明文相关日志（event_kind=7），其他事件不在控制台输出。
        https_items = [
            it for it in items
            if isinstance(it, dict) and _safe_int(it.get("event_kind"), -1) == 7
        ]
        if https_items:
            print(
                f"[{time.strftime('%F %T')}] https_items={len(https_items)} bytes={len(raw)}",
                flush=True,
            )
            first = https_items[0]
            print(
                f"  https_first={{'comm': {first.get('comm')!r}, 'tls_direction': {first.get('tls_direction')!r}, "
                f"'tls_threat': {first.get('tls_threat')!r}, 'tls_payload_trunc': {first.get('tls_payload_trunc')!r}}}",
                flush=True,
            )
        if alerts and https_items:
            print(f"  alert_first={alerts[0]}", flush=True)

        self._send(200, {"ok": True, "received": len(items), "alerts": len(alerts), "ts": time.time()})

    def log_message(self, fmt: str, *args):
        return


def main():
    host = "127.0.0.1"
    port = 8899
    httpd = ThreadingHTTPServer((host, port), Handler)
    print(f"listening on http://{host}:{port}/ingest", flush=True)
    httpd.serve_forever()


if __name__ == "__main__":
    main()


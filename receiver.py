#!/usr/bin/env python3
from __future__ import annotations

import json
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer


class Handler(BaseHTTPRequestHandler):
    server_version = "hids-receiver/0.1"

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

        now = time.time()
        items = payload if isinstance(payload, list) else [payload]
        print(
            f"[{time.strftime('%F %T')}] received batches=1 items={len(items)} bytes={len(raw)}",
            flush=True,
        )
        if items:
            # 打印第一条方便你确认字段
            print(f"  first={items[0]}", flush=True)

        self._send(200, {"ok": True, "received": len(items), "ts": now})

    def log_message(self, fmt: str, *args):
        # silence default access log
        return


def main():
    host = "127.0.0.1"
    port = 8000
    httpd = ThreadingHTTPServer((host, port), Handler)
    print(f"listening on http://{host}:{port}/ingest", flush=True)
    httpd.serve_forever()


if __name__ == "__main__":
    main()


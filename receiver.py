#!/usr/bin/env python3
from __future__ import annotations

import json
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer


class Handler(BaseHTTPRequestHandler):
    server_version = "hids-receiver/0.1"
    spool_file = "received.jsonl"

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
        if isinstance(payload, dict) and "events" in payload:
            meta = {
                "agent_version": payload.get("agent_version"),
                "schema_version": payload.get("schema_version"),
                "host_id": payload.get("host_id"),
            }
            items = payload.get("events") or []
            # attach metadata to each written event
            items = [
                {**it, **{k: v for k, v in meta.items() if v is not None}}
                for it in items
                if isinstance(it, dict)
            ]
        else:
            items = payload if isinstance(payload, list) else [payload]
        print(
            f"[{time.strftime('%F %T')}] received batches=1 items={len(items)} bytes={len(raw)}",
            flush=True,
        )

        # Persist every item so we don't "lose logs" at the receiver.
        # If we can't write, we should fail the request so the agent retries via spool.
        try:
            if items:
                with open(self.spool_file, "a", encoding="utf-8") as f:
                    for it in items:
                        f.write(json.dumps(it, ensure_ascii=False) + "\n")
                    f.flush()
            else:
                # still treat empty batch as success
                pass
        except Exception as e:
            self._send(500, {"ok": False, "error": f"failed to write {self.spool_file}: {e}"})
            return

        if items:
            # Print first + last to reduce console spam while still confirming data isn't empty.
            if len(items) == 1:
                print(f"  first={items[0]}", flush=True)
            else:
                print(f"  first={items[0]}", flush=True)
                print(f"  last={items[-1]}", flush=True)

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


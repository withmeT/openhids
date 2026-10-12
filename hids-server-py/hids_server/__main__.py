"""``python -m hids_server`` 入口。"""

from __future__ import annotations

import logging

import uvicorn
from dotenv import load_dotenv

from .app import create_app
from .config import Config


def main() -> None:
    logging.basicConfig(
        level=logging.INFO, format="%(asctime)s %(levelname)s %(name)s %(message)s"
    )
    load_dotenv()  # 与 Rust 版 dotenvy 行为一致：自动加载当前目录 .env
    cfg = Config.from_env()
    host, _, port = cfg.bind_addr.rpartition(":")
    app = create_app(cfg)
    uvicorn.run(app, host=host or "127.0.0.1", port=int(port), log_level="info")


if __name__ == "__main__":
    main()

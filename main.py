#!/usr/bin/env python3
"""
兼容你之前提到的 `main.py` 接口文件名。

当前实现直接复用 `receiver.py` 的 HTTP ingestion server：
- POST `/ingest`：接收 agent 的批次事件（命令输入/流量五元组等）。
"""

from receiver import main


if __name__ == "__main__":
    main()


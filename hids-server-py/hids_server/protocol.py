"""对应 Rust ``hids-protocol``：加密控制面协议，必须与 agent 二进制互通。

线格式（与 Rust 完全一致）：
JSON → zstd(level 3) → ChaCha20-Poly1305(key 32B, nonce 12B, 无 AAD) → base64
解压读取上限 8 MiB，超限拒绝。
"""

from __future__ import annotations

import base64
import io
import json
import os
from typing import Any

import zstandard
from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305

NONCE_LEN = 12
KEY_LEN = 32
COMPRESSION_LEVEL = 3
MAX_DECOMPRESSED_BYTES = 8 * 1024 * 1024

BASELINE_CHECK_KINDS = ("system_info", "listening_ports", "process_summary", "file_hashes")
BASELINE_STATUSES = ("ok", "failed", "rejected")


class ProtocolError(ValueError):
    """控制面协议错误，消息文案与 Rust 实现对齐。"""


def parse_key(value: str) -> bytes:
    value = value.strip()
    if not value:
        raise ProtocolError("control-plane key is empty")
    if len(value) == KEY_LEN * 2:
        try:
            return bytes.fromhex(value)
        except ValueError as exc:
            raise ProtocolError("control-plane key is not valid hex") from exc
    try:
        decoded = base64.b64decode(value, validate=True)
    except Exception as exc:
        raise ProtocolError("control-plane key must be 64 hex chars or base64") from exc
    if len(decoded) != KEY_LEN:
        raise ProtocolError("control-plane key must decode to 32 bytes")
    return decoded


def seal_json(value: Any, key: bytes) -> dict:
    raw = json.dumps(value, ensure_ascii=False, separators=(",", ":")).encode("utf-8")
    compressed = zstandard.ZstdCompressor(level=COMPRESSION_LEVEL).compress(raw)
    nonce = os.urandom(NONCE_LEN)
    ciphertext = ChaCha20Poly1305(key).encrypt(nonce, compressed, None)
    return {
        "version": 1,
        "algorithm": "chacha20poly1305",
        "compression": "zstd",
        "nonce": base64.b64encode(nonce).decode("ascii"),
        "ciphertext": base64.b64encode(ciphertext).decode("ascii"),
    }


def open_json(envelope: dict, key: bytes) -> Any:
    if (
        envelope.get("version") != 1
        or envelope.get("algorithm") != "chacha20poly1305"
        or envelope.get("compression") != "zstd"
    ):
        raise ProtocolError("unsupported control-plane envelope")

    try:
        nonce = base64.b64decode(envelope.get("nonce") or "", validate=True)
    except Exception as exc:
        raise ProtocolError("invalid control-plane nonce") from exc
    if len(nonce) != NONCE_LEN:
        raise ProtocolError("invalid control-plane nonce length")
    try:
        ciphertext = base64.b64decode(envelope.get("ciphertext") or "", validate=True)
    except Exception as exc:
        raise ProtocolError("invalid control-plane ciphertext") from exc

    try:
        compressed = ChaCha20Poly1305(key).decrypt(nonce, ciphertext, None)
    except InvalidTag as exc:
        raise ProtocolError("control-plane authentication failed") from exc

    # 流式解压 + 上限检查：多读 1 字节以区分“恰好达到上限”与“超限”
    reader = zstandard.ZstdDecompressor().stream_reader(io.BytesIO(compressed))
    raw = reader.read(MAX_DECOMPRESSED_BYTES + 1)
    if len(raw) > MAX_DECOMPRESSED_BYTES:
        raise ProtocolError("control-plane payload exceeds decompressed size limit")
    return json.loads(raw)

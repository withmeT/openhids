"""加密控制面协议测试（线格式回环 + 拒绝路径）。"""

import pytest

from hids_server.protocol import (
    MAX_DECOMPRESSED_BYTES,
    ProtocolError,
    open_json,
    parse_key,
    seal_json,
)

KEY = parse_key("8f4a1c0e2b6d9f31a5c7e8d0b2f4a6c81e3d5f70921436587a9cbdef01234567")


def test_parse_key_hex_and_base64():
    hex_key = "ab" * 32
    assert parse_key(hex_key) == bytes.fromhex(hex_key)
    import base64

    b64 = base64.b64encode(bytes(range(32))).decode()
    assert parse_key(b64) == bytes(range(32))

    with pytest.raises(ProtocolError):
        parse_key("")
    with pytest.raises(ProtocolError):
        parse_key("zz" * 32)  # 非法 hex
    with pytest.raises(ProtocolError):
        parse_key("dG9vc2hvcnQ=")  # 解码后不是 32 字节


def test_round_trip():
    command = {
        "request_id": "t-1",
        "host_id": "h-1",
        "issued_at_ms": 1,
        "expires_at_ms": 2,
        "checks": [{"id": "os", "kind": "system_info", "paths": []}],
    }
    envelope = seal_json(command, KEY)
    assert envelope["version"] == 1
    assert envelope["algorithm"] == "chacha20poly1305"
    assert envelope["compression"] == "zstd"
    assert open_json(envelope, KEY) == command


def test_tampered_payload_rejected():
    envelope = seal_json("secret", KEY)
    envelope["ciphertext"] = envelope["ciphertext"][:-4] + "AAAA"
    with pytest.raises(ProtocolError, match="authentication failed"):
        open_json(envelope, KEY)


def test_wrong_envelope_header_rejected():
    envelope = seal_json("x", KEY)
    bad = dict(envelope, algorithm="aes-gcm")
    with pytest.raises(ProtocolError, match="unsupported"):
        open_json(bad, KEY)


def test_oversized_payload_rejected():
    big = "a" * MAX_DECOMPRESSED_BYTES  # JSON 字符串加引号后刚好超限
    envelope = seal_json(big, KEY)
    with pytest.raises(ProtocolError, match="decompressed size limit"):
        open_json(envelope, KEY)


def test_payload_at_limit_accepted():
    # "…" JSON 带 2 字节引号，留出余量
    payload = "a" * (MAX_DECOMPRESSED_BYTES - 2)
    envelope = seal_json(payload, KEY)
    assert open_json(envelope, KEY) == payload

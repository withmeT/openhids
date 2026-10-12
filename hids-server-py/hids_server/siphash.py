"""Rust ``DefaultHasher`` (SipHash-1-3, zero keys) 的纯 Python 复刻。

Rust 服务端用 ``std::collections::hash_map::DefaultHasher`` 生成两类对外可见、
需要跨实现保持稳定的值：

- ``stable_document_id``：Elasticsearch ``_id``（幂等写入）
- ``line_fingerprint``：kind=0 事件 ``correlation_key`` 的一部分

迁移到 Python 后这两个值必须逐位一致，否则并行期间同一事件会在 ES 里出现
两份文档、历史 correlation_key 断链。因此这里按 Rust 的 ``Hasher`` 写入协议
精确复刻：

- ``&str``：先写 UTF-8 字节，再写一个 ``0xff`` 结尾字节
- ``u64``：小端 8 字节

黄金向量由 ``tools/golden_vectors.rs`` 在当前 Rust 工具链上生成，
测试见 ``tests/test_siphash.py``。
"""

from __future__ import annotations

MASK64 = 0xFFFF_FFFF_FFFF_FFFF


def _rotl(x: int, b: int) -> int:
    return ((x << b) | (x >> (64 - b))) & MASK64


class SipHasher13:
    """SipHash-1-3，k0 = k1 = 0，与 Rust ``DefaultHasher::new()`` 一致。"""

    def __init__(self) -> None:
        # k0 = k1 = 0 时的初始状态
        self.v0 = 0x736F_6D65_7073_6575
        self.v1 = 0x646F_7261_6E64_6F6D
        self.v2 = 0x6C79_6765_6E65_7261
        self.v3 = 0x7465_6462_7974_6573
        self._tail = b""
        self._length = 0

    def _sipround(self) -> None:
        v0, v1, v2, v3 = self.v0, self.v1, self.v2, self.v3
        v0 = (v0 + v1) & MASK64
        v1 = _rotl(v1, 13) ^ v0
        v0 = _rotl(v0, 32)
        v2 = (v2 + v3) & MASK64
        v3 = _rotl(v3, 16) ^ v2
        v0 = (v0 + v3) & MASK64
        v3 = _rotl(v3, 21) ^ v0
        v2 = (v2 + v1) & MASK64
        v1 = _rotl(v1, 17) ^ v2
        v2 = _rotl(v2, 32)
        self.v0, self.v1, self.v2, self.v3 = v0, v1, v2, v3

    def _process_block(self, m: int) -> None:
        self.v3 ^= m
        self._sipround()  # c = 1 轮压缩
        self.v0 ^= m

    def write(self, data: bytes) -> None:
        self._length += len(data)
        buf = self._tail + data
        n_blocks = len(buf) // 8
        for i in range(n_blocks):
            m = int.from_bytes(buf[i * 8 : i * 8 + 8], "little")
            self._process_block(m)
        self._tail = buf[n_blocks * 8 :]

    # --- Rust Hasher 写入协议 ---

    def write_u8(self, value: int) -> None:
        self.write(value.to_bytes(1, "little"))

    def write_u64(self, value: int) -> None:
        self.write(value.to_bytes(8, "little"))

    def write_str(self, value: str) -> None:
        """等价于 Rust 的 ``str::hash``：UTF-8 字节 + 0xff 终结符。"""
        self.write(value.encode("utf-8"))
        self.write_u8(0xFF)

    def finish(self) -> int:
        # 末块：高位字节放 length & 0xff，其余为 tail 补零
        m = (self._length & 0xFF) << 56
        m |= int.from_bytes(self._tail.ljust(8, b"\x00")[:7] + b"\x00", "little")
        self._process_block(m)
        self.v2 ^= 0xFF
        self._sipround()  # d = 3 轮终结
        self._sipround()
        self._sipround()
        return (self.v0 ^ self.v1 ^ self.v2 ^ self.v3) & MASK64

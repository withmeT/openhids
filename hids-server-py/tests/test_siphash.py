"""SipHash-1-3 黄金向量测试。

向量由 ``tools/golden_vectors.rs``（Rust ``DefaultHasher``）生成，
保证 doc_id / correlation_key 与 Rust 服务端逐位一致。
"""

from hids_server.doc_id import stable_document_id
from hids_server.enrich import line_fingerprint
from hids_server.siphash import SipHasher13


def _doc_id_style(host, ts, kind, pid, suffix=None):
    h = SipHasher13()
    h.write_str(host)
    h.write_u64(ts)
    h.write_u64(kind)
    h.write_u64(pid)
    if suffix is not None:
        h.write_str(suffix)
    return format(h.finish(), "016x")


def test_golden_vectors_match_rust_default_hasher():
    assert (
        _doc_id_style("host-a", 1778756148222, 0, 4242, "curl http://example.com/login -d a=1"[:96])
        == "ea216e1c65c53cb0"
    )
    assert (
        _doc_id_style("host-b", 1700000000000, 2, 0, "tcp:10.0.0.5:51234->10.0.0.9:443")
        == "918915b2b3447a5e"
    )
    assert _doc_id_style("host-c", 1, 5, 0) == "b2679b486a5b09fd"

    h = SipHasher13()
    h.write_str("")
    assert format(h.finish(), "016x") == "30406ea523c53def"

    h = SipHasher13()
    h.write_u64(0xDEADBEEF)
    assert format(h.finish(), "016x") == "1e1d875fb6b69775"


def test_line_fingerprint_matches_rust():
    assert format(line_fingerprint("cat /etc/passwd"), "x") == "c676dcdc8600b102"
    # Unicode 截断按字符数而非字节数
    assert format(line_fingerprint("数据库连接失败请检查配置"), "x") == "51a1b2adbde64bd1"


def test_stable_document_id_field_selection():
    base = {"host_id": "host-a", "ts_ms": 1778756148222, "event_kind": 0, "pid": 4242}
    with_line = dict(base, line="curl http://example.com/login -d a=1")
    assert stable_document_id(with_line) == "ea216e1c65c53cb0"

    flow = {
        "host_id": "host-b",
        "ts_ms": 1700000000000,
        "event_kind": 2,
        "flow_correlation_key": "tcp:10.0.0.5:51234->10.0.0.9:443",
    }
    assert stable_document_id(flow) == "918915b2b3447a5e"

    bare = {"host_id": "host-c", "ts_ms": 1, "event_kind": 5}
    assert stable_document_id(bare) == "b2679b486a5b09fd"

    # line 优先于 flow_correlation_key
    both = dict(with_line, flow_correlation_key="tcp:1.2.3.4:1->5.6.7.8:2")
    assert stable_document_id(both) == "ea216e1c65c53cb0"

    assert stable_document_id({"ts_ms": 1, "event_kind": 0}) is None  # 缺 host_id
    assert stable_document_id({"host_id": "h", "event_kind": 0}) is None  # 缺 ts_ms

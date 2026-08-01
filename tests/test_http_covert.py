"""
test_http_covert.py — HTTP C2 depth, ICMP tunnelling, port mismatch, beacon v2.
"""
import sys, os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "pipeline"))

from pipeline.model import HttpTransaction, TlsTransaction
from pipeline.http_analysis import detect_http_exfil
from pipeline.covert_channels import detect_icmp_tunnel, detect_port_mismatch
from pipeline.traffic_analysis import detect_beaconing
from conftest import _make_conn


def _http(uri, ua=None, dst="203.0.113.9", port=80, method="POST"):
    return HttpTransaction(ts=1.0, src_ip="10.0.0.5", dst_ip=dst, dst_port=port,
                           method=method, host="c2.bad", uri=uri, user_agent=ua)


class TestHttpC2:
    def test_gate_pattern_strong(self):
        f = detect_http_exfil([_http("/gate.php")])
        assert len(f) == 1 and f[0].severity == "strong"

    def test_set_agent_pattern(self):
        f = detect_http_exfil([_http("/api/set_agent?id=1&token=x&act=log")])
        assert len(f) == 1 and f[0].severity == "strong"

    def test_suspicious_ua_weak(self):
        f = detect_http_exfil([_http("/normal", ua="python-requests")])
        assert len(f) == 1 and f[0].severity == "weak"

    def test_benign_http_not_flagged(self):
        f = detect_http_exfil([_http("/index.html", ua="Mozilla/5.0 (Windows NT 10.0) Chrome/120", method="GET")])
        assert f == []


class TestIcmpTunnel:
    def test_tunnel_detected(self):
        icmp = [("10.0.0.5", "203.0.113.9", 200) for _ in range(20)]
        f = detect_icmp_tunnel(icmp)
        assert len(f) == 1 and f[0].severity == "strong"

    def test_normal_ping_not_flagged(self):
        icmp = [("10.0.0.5", "8.8.8.8", 32) for _ in range(20)]   # normal 32B pings
        assert detect_icmp_tunnel(icmp) == []

    def test_few_packets_not_flagged(self):
        icmp = [("10.0.0.5", "203.0.113.9", 200) for _ in range(3)]
        assert detect_icmp_tunnel(icmp) == []


class TestPortMismatch:
    def test_http_nonstandard_port(self):
        f = detect_port_mismatch([_http("/", dst="203.0.113.9", port=55123)], [])
        assert len(f) == 1 and f[0].detail.endswith("55123")

    def test_http_standard_port_ok(self):
        assert detect_port_mismatch([_http("/", port=80)], []) == []

    def test_ftps_on_21_not_flagged(self):
        """Explicit FTPS (AUTH TLS on tcp/21) is standard, not a covert channel."""
        tls = [TlsTransaction(ts=1, src_ip="10.0.0.5", dst_ip="203.0.113.9", dst_port=21)]
        assert detect_port_mismatch([], tls) == []

    def test_tls_nonstandard_port(self):
        tls = [TlsTransaction(ts=1, src_ip="10.0.0.5", dst_ip="203.0.113.9", dst_port=4444)]
        f = detect_port_mismatch([], tls)
        assert len(f) == 1 and "4444" in f[0].detail


class TestBeaconV2:
    def test_size_regularity_recorded(self):
        """A beacon with identical request sizes has size_cv ~ 0."""
        conns = [_make_conn(ts=1000.0 + i * 30.0, dst_ip="203.0.113.51",
                            dst_port=443, orig_bytes=256) for i in range(8)]
        v = [b for b in detect_beaconing(conns) if b.is_beacon][0]
        assert v.size_cv == 0.0

    def test_variable_sizes_higher_cv(self):
        conns = [_make_conn(ts=1000.0 + i * 30.0, dst_ip="203.0.113.52",
                            dst_port=443, orig_bytes=100 + i * 300) for i in range(8)]
        v = [b for b in detect_beaconing(conns) if b.is_beacon][0]
        assert v.size_cv > 0.1

"""
test_dns_analysis.py — DNS tunnelling, DGA, and DoH detection.

Calibrated against real traffic (dnscat2 / dnsexfiltrator vs the DNS-Tunneling
top-1M benign set): tunnels trip entropy + subdomain-length + tunnelling-record-
type + volume together; ordinary resolution trips none.
"""
import sys, os, base64, hashlib
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "pipeline"))

from pipeline.model import DnsTransaction, TlsTransaction, HttpTransaction
from pipeline.dns_analysis import detect_dns_tunneling, detect_dga, detect_doh


def _tunnel_txns(n=80, domain="evil-tunnel.com"):
    """High-entropy, long, unique subdomains over TXT — a data tunnel."""
    out = []
    for i in range(n):
        blob = base64.b32encode(hashlib.sha256(str(i).encode()).digest()).decode().rstrip("=").lower()
        sub = f"{blob[:32]}.{blob[32:48]}"
        out.append(DnsTransaction(ts=float(i), src_ip="10.0.0.5", dst_ip="10.0.0.1",
                                  query=f"{sub}.{domain}", qtype="TXT", rcode="NOERROR"))
    return out


def _benign_txns(n=80):
    """Short, low-entropy, A-record lookups to many normal domains."""
    hosts = ["www", "mail", "api", "cdn", "shop"]
    out = []
    for i in range(n):
        out.append(DnsTransaction(ts=float(i), src_ip="10.0.0.5", dst_ip="10.0.0.1",
                                  query=f"{hosts[i % len(hosts)]}.example{i}.com",
                                  qtype="A", rcode="NOERROR"))
    return out


class TestDnsTunnel:
    def test_tunnel_detected(self):
        f = detect_dns_tunneling(_tunnel_txns())
        assert len(f) == 1
        assert f[0].domain == "evil-tunnel.com"
        assert f[0].tunnel_rt_fraction >= 0.5
        assert f[0].avg_entropy >= 3.2

    def test_benign_not_flagged(self):
        assert detect_dns_tunneling(_benign_txns()) == []

    def test_low_volume_tunnel_still_caught_on_content(self):
        """Even a handful of tunnel queries trip on entropy+length+record-type."""
        f = detect_dns_tunneling(_tunnel_txns(n=6))
        assert len(f) == 1

    def test_high_volume_benign_not_flagged(self):
        """Volume/uniqueness alone (top-1M-style) must NOT flag."""
        assert detect_dns_tunneling(_benign_txns(n=500)) == []


class TestDga:
    def test_dga_detected(self):
        txns = [DnsTransaction(ts=float(i), src_ip="10.0.0.5", dst_ip="10.0.0.1",
                               query=base64.b32encode(hashlib.md5(str(i).encode()).digest())
                                       .decode().rstrip("=").lower() + ".com",
                               qtype="A", rcode="NXDOMAIN") for i in range(30)]
        f = detect_dga(txns)
        assert len(f) == 1 and f[0].kind == "dga"

    def test_normal_resolution_not_dga(self):
        txns = [DnsTransaction(ts=float(i), src_ip="10.0.0.5", dst_ip="10.0.0.1",
                               query="www.google.com", qtype="A", rcode="NOERROR")
                for i in range(30)]
        assert detect_dga(txns) == []


class TestDoH:
    def test_known_doh_endpoint(self):
        tls = [TlsTransaction(ts=1.0, src_ip="10.0.0.5", dst_ip="8.8.8.8",
                              server_name="dns.google")]
        assert "dns.google" in detect_doh(tls, [])

    def test_normal_tls_not_doh(self):
        tls = [TlsTransaction(ts=1.0, src_ip="10.0.0.5", dst_ip="1.2.3.4",
                              server_name="example.com")]
        assert detect_doh(tls, []) == []

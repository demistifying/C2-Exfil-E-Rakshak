"""
test_pcap_loader.py — PCAP and Zeek conn.log loading tests.

Covers:
  * Scapy path: load the synthetic PCAP, verify connection count and IPs
  * Scapy path: HTTP method/URI/host extraction from cleartext packets
  * Zeek path: parse a well-formed conn.log into Connection records
"""
import sys, os, tempfile
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "pipeline"))

import pytest
from pipeline.pcap_loader import load_pcap, load_zeek_conn
from pipeline.traffic_analysis import Connection


# ===== Scapy path ===========================================================

class TestLoadPcapScapy:
    @pytest.fixture(autouse=True)
    def _paths(self):
        self.base = os.path.join(os.path.dirname(__file__), "..")
        self.synthetic = os.path.join(self.base, "data", "sample_infostealer.pcap")
        self.real = os.path.join(
            self.base, "data",
            "2024-10-23-Redline-Stealer-infection-traffic.pcap",
            "2024-10-23-Redline-Stealer-infection-traffic.pcap")

    def test_load_synthetic_returns_connections(self):
        """Synthetic PCAP loads and returns a non-empty list of Connections."""
        if not os.path.exists(self.synthetic):
            pytest.skip("Synthetic PCAP not found")
        conns = load_pcap(self.synthetic)
        assert len(conns) > 0
        # Duck-type check: pcap_loader's Connection may be a different import
        # path than pipeline.traffic_analysis.Connection, so isinstance can fail.
        assert all(hasattr(c, 'dst_ip') and hasattr(c, 'ts') for c in conns)

    def test_synthetic_contains_known_c2(self):
        """Synthetic PCAP should contain traffic to the reference C2 IP."""
        if not os.path.exists(self.synthetic):
            pytest.skip("Synthetic PCAP not found")
        conns = load_pcap(self.synthetic)
        dst_ips = {c.dst_ip for c in conns}
        assert "188.190.10.10" in dst_ips

    def test_http_method_extraction(self):
        """Cleartext HTTP POST in the synthetic PCAP should have method/URI set."""
        if not os.path.exists(self.synthetic):
            pytest.skip("Synthetic PCAP not found")
        conns = load_pcap(self.synthetic)
        posts = [c for c in conns if c.http_method == "POST"]
        assert len(posts) > 0
        assert posts[0].http_uri is not None

    def test_load_real_pcap(self):
        """Real Redline PCAP loads and contains the known C2 IP."""
        if not os.path.exists(self.real):
            pytest.skip("Real PCAP not found")
        conns = load_pcap(self.real)
        assert len(conns) > 0
        dst_ips = {c.dst_ip for c in conns}
        assert "188.190.10.10" in dst_ips


# ===== IPv6 handling ========================================================

class TestLoadPcapIPv6:
    def test_native_ipv6_flow_loaded(self, tmp_path):
        """A native IPv6/TCP flow must be loaded with its IPv6 destination —
        not silently skipped as it was when the loader was IPv4-only."""
        from scapy.all import Ether, IPv6, TCP, Raw, wrpcap
        c2 = "2001:db8:dead:beef::1"
        pkts = [
            Ether() / IPv6(src="2001:db8::5", dst=c2) /
            TCP(sport=50000, dport=443, flags="S"),
            Ether() / IPv6(src="2001:db8::5", dst=c2) /
            TCP(sport=50000, dport=443, flags="PA") / Raw(load=b"X" * 500),
        ]
        pcap = str(tmp_path / "v6.pcap")
        wrpcap(pcap, pkts)
        conns = load_pcap(pcap)
        dst_ips = {c.dst_ip for c in conns}
        assert c2 in dst_ips

    def test_6to4_tunnel_resolves_inner_ipv6(self, tmp_path):
        """6to4-tunnelled IPv6 (IPv4 proto-41 wrapping IPv6) must resolve to the
        inner IPv6 endpoint, not the IPv4 tunnel relay — else tunnelled exfil
        hides behind the relay address."""
        from scapy.all import Ether, IP, IPv6, TCP, Raw, wrpcap
        inner = "2001:638:902:1::7596"
        pkts = [
            Ether() / IP(src="81.131.67.131", dst="192.88.99.1") /
            IPv6(src="2002:5183:4383::1", dst=inner) /
            TCP(sport=1032, dport=21, flags="PA") / Raw(load=b"USER anonymous\r\n"),
        ]
        pcap = str(tmp_path / "6to4.pcap")
        wrpcap(pcap, pkts)
        conns = load_pcap(pcap)
        dst_ips = {c.dst_ip for c in conns}
        assert inner in dst_ips
        assert "192.88.99.1" not in dst_ips   # tunnel relay must not be the endpoint


# ===== Zeek conn.log path ===================================================

SAMPLE_CONNLOG = """\
#separator \\x09
#set_separator\t,
#empty_field\t(empty)
#unset_field\t-
#path\tconn
#open\t2024-10-23-19-20-00
#fields\tts\tuid\tid.orig_h\tid.orig_p\tid.resp_h\tid.resp_p\tproto\tservice\tduration\torig_bytes\tresp_bytes\tconn_state\tlocal_orig\tlocal_resp\tmissed_bytes\thistory\torig_pkts\torig_ip_bytes\tresp_pkts\tresp_ip_bytes\ttunnel_parents
#types\ttime\tstring\taddr\tport\taddr\tport\tenum\tstring\tinterval\tcount\tcount\tstring\tbool\tbool\tcount\tstring\tcount\tcount\tcount\tcount\tset[string]
1729710932.123\tCxyz\t10.10.23.101\t49697\t188.190.10.10\t55123\ttcp\thttp\t1.2\t5120\t200\tSF\t-\t-\t0\tShADadFf\t10\t5600\t8\t520\t(empty)
1729710938.456\tCabc\t10.10.23.101\t49699\t104.26.13.31\t443\ttcp\tssl\t0.5\t300\t4000\tSF\t-\t-\t0\tShADadFf\t5\t500\t10\t4200\t(empty)
#close\t2024-10-23-19-25-00
"""


class TestLoadZeekConn:
    def test_parse_connlog(self, tmp_path):
        """Parse a well-formed Zeek conn.log into Connection records."""
        logfile = tmp_path / "conn.log"
        logfile.write_text(SAMPLE_CONNLOG)
        conns = load_zeek_conn(str(logfile))
        assert len(conns) == 2
        assert all(hasattr(c, 'dst_ip') and hasattr(c, 'ts') for c in conns)

    def test_connlog_ips(self, tmp_path):
        """Verify parsed IPs match what's in the conn.log."""
        logfile = tmp_path / "conn.log"
        logfile.write_text(SAMPLE_CONNLOG)
        conns = load_zeek_conn(str(logfile))
        assert conns[0].dst_ip == "188.190.10.10"
        assert conns[0].dst_port == 55123
        assert conns[1].dst_ip == "104.26.13.31"

    def test_connlog_bytes(self, tmp_path):
        """Verify parsed byte counts."""
        logfile = tmp_path / "conn.log"
        logfile.write_text(SAMPLE_CONNLOG)
        conns = load_zeek_conn(str(logfile))
        assert conns[0].orig_bytes == 5120
        assert conns[0].resp_bytes == 200

    def test_connlog_empty_file(self, tmp_path):
        """Empty conn.log → empty list, no crash."""
        logfile = tmp_path / "conn.log"
        logfile.write_text("#fields\tts\n#close\n")
        conns = load_zeek_conn(str(logfile))
        assert len(conns) == 0

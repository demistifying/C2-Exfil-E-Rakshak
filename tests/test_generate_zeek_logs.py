"""
test_generate_zeek_logs.py — the fast pcap->Zeek-log fallback is CORRECT.

Regression guard for the original bug where JA3 was hardcoded (every TLS flow
got the same fingerprint) and dns.log was never emitted.
"""
import sys, os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "pipeline"))
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "tools"))

import pytest
from scapy.all import Ether, IP, UDP, DNS, DNSQR, wrpcap, rdpcap, TCP
from generate_zeek_logs import parse
from tls_analysis import fingerprint_client_hello

FTPS = os.path.join(os.path.dirname(__file__), "..", "data", "FTP Testing",
                    "ftp-auth-tls.pcap")
_OLD_HARDCODED = "2800f914a7a44f4340d210515152a4f4"


def _ssl_ja3s(out_dir):
    p = os.path.join(out_dir, "ssl.log")
    if not os.path.exists(p):
        return []
    return [ln.split("\t")[10] for ln in open(p)
            if ln and not ln.startswith("#")]


class TestRealJA3:
    def test_ja3_is_computed_not_hardcoded(self, tmp_path):
        if not os.path.exists(FTPS):
            pytest.skip("ftp-auth-tls.pcap not present")
        out = str(tmp_path / "z"); parse(FTPS, out)
        ja3s = _ssl_ja3s(out)
        assert ja3s, "no ssl.log JA3 emitted"
        # must equal the value our own parser computes (real), not a constant
        pk = rdpcap(FTPS)
        expected = None
        for x in pk:
            if TCP in x:
                pl = bytes(x[TCP].payload)
                if len(pl) > 5 and pl[0] == 0x16 and pl[5] == 0x01:
                    expected = fingerprint_client_hello(pl[5:])[0]; break
        assert expected and expected in ja3s
        assert _OLD_HARDCODED not in ja3s        # the old bug is gone


class TestDnsLog:
    def test_dns_log_emitted_with_query(self, tmp_path):
        pcap = str(tmp_path / "dns.pcap")
        pk = (Ether() / IP(src="10.0.0.5", dst="10.0.0.1") /
              UDP(sport=5000, dport=53) /
              DNS(rd=1, qd=DNSQR(qname="tunnel.evil.example", qtype="TXT")))
        wrpcap(pcap, [pk])
        out = str(tmp_path / "z"); parse(pcap, out)
        dns_log = os.path.join(out, "dns.log")
        assert os.path.exists(dns_log)
        rows = [ln for ln in open(dns_log) if ln and not ln.startswith("#")]
        assert any("tunnel.evil.example" in r and "TXT" in r for r in rows)


class TestConnLog:
    def test_conn_orientation_upload(self, tmp_path):
        """Internal->public flow records the upload as orig_bytes."""
        pcap = str(tmp_path / "c.pcap")
        pk = (Ether() / IP(src="192.168.1.10", dst="203.0.113.9") /
              TCP(sport=5000, dport=21, flags="PA") / b"STOR secret.txt\r\n")
        wrpcap(pcap, [pk])
        out = str(tmp_path / "z"); parse(pcap, out)
        conn = [ln for ln in open(os.path.join(out, "conn.log"))
                if ln and not ln.startswith("#")][0].split("\t")
        assert conn[2] == "192.168.1.10"          # id.orig_h = the internal client
        assert int(conn[9]) > 0                    # orig_bytes (upload) counted

"""
test_tls_analysis.py — JA4 fingerprinting, robustness, and TLS cert analysis.
"""
import sys, os, sqlite3
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "pipeline"))

import pytest
from scapy.all import rdpcap, IP, wrpcap, TCP
from pipeline.tls_analysis import (parse_client_hello, ja4, fingerprint_client_hello,
                                   analyze_certificate)
from pipeline.model import TlsTransaction

FTPS = os.path.join(os.path.dirname(__file__), "..", "data", "FTP Testing",
                    "ftp-auth-tls.pcap")


def _first_client_hello(pcap):
    for pk in rdpcap(pcap):
        if TCP in pk:
            pl = bytes(pk[TCP].payload)
            if len(pl) > 5 and pl[0] == 0x16 and pl[5] == 0x01:
                return pl[5:]
    return None


class TestJA4:
    def test_format_and_determinism(self):
        if not os.path.exists(FTPS):
            pytest.skip("ftp-auth-tls.pcap not present")
        hs = _first_client_hello(FTPS)
        j1 = fingerprint_client_hello(hs)[1]
        j2 = fingerprint_client_hello(hs)[1]
        assert j1 == j2                       # deterministic
        parts = j1.split("_")
        assert len(parts) == 3                # ja4_a _ ja4_b _ ja4_c
        assert parts[0][0] in ("t", "q")      # transport
        assert len(parts[1]) == 12 and len(parts[2]) == 12

    def test_truncated_hello_returns_none(self):
        assert parse_client_hello(b"\x01\x00\x00") is None

    def test_non_client_hello_returns_none(self):
        assert parse_client_hello(b"\x02\x00\x00\x10") is None


class TestCertAnalysis:
    def test_self_signed_strong(self):
        t = TlsTransaction(ts=1, src_ip="10.0.0.5", dst_ip="1.2.3.4",
                           subject="CN=evil", issuer="CN=evil")
        f = analyze_certificate(t)
        assert f and f.severity == "strong" and "self-signed" in f.reason

    def test_validation_failed_weak(self):
        t = TlsTransaction(ts=1, src_ip="10.0.0.5", dst_ip="1.2.3.4",
                           subject="CN=a", issuer="CN=DigiCert",
                           validation_status="self signed certificate in chain")
        f = analyze_certificate(t)
        assert f and f.severity == "weak"

    def test_valid_cert_none(self):
        t = TlsTransaction(ts=1, src_ip="10.0.0.5", dst_ip="1.2.3.4",
                           subject="CN=example.com", issuer="CN=DigiCert",
                           validation_status="ok")
        assert analyze_certificate(t) is None


class TestKnownBadJA4:
    def _public_ftps(self, tmp_path):
        if not os.path.exists(FTPS):
            pytest.skip("ftp-auth-tls.pcap not present")
        pk = rdpcap(FTPS)
        for p in pk:
            if IP in p:
                if p[IP].dst == "127.0.0.1": p[IP].dst = "198.51.100.200"
                if p[IP].src == "127.0.0.1": p[IP].src = "192.168.1.50"
                del p[IP].chksum
                if p.haslayer("TCP"): del p["TCP"].chksum
        out = str(tmp_path / "ftps.pcap"); wrpcap(out, pk)
        return out

    def test_attribute_known_bad_ja4(self, tmp_path, monkeypatch):
        from attribution import attribute, init_threatintel_db
        db = str(tmp_path / "ti.sqlite"); init_threatintel_db(path=db, seed=True)
        c = sqlite3.connect(db)
        try: c.execute("ALTER TABLE bad_indicators ADD COLUMN indicator_type TEXT DEFAULT 'ip'")
        except sqlite3.OperationalError: pass
        c.execute("INSERT OR REPLACE INTO bad_indicators(value,source,note,indicator_type) "
                  "VALUES(?,?,?,?)", ("t13d1516h2_aaaaaaaaaaaa_bbbbbbbbbbbb", "kb", "x", "ja4"))
        c.commit(); c.close()
        monkeypatch.setenv("THREATINTEL_DB", db)
        a = attribute("203.0.113.50", ja4="t13d1516h2_aaaaaaaaaaaa_bbbbbbbbbbbb")
        assert a.reputation_hit is True

    def test_clean_ip_flagged_by_ja4(self, tmp_path, monkeypatch):
        from zeek_ingest import bundle_from_pcap
        from attribution import init_threatintel_db
        pcap = self._public_ftps(tmp_path)
        ja4_val = [t.ja4 for t in bundle_from_pcap(pcap).tls if t.ja4][0]
        db = str(tmp_path / "ti.sqlite"); init_threatintel_db(path=db, seed=True)
        c = sqlite3.connect(db)
        try: c.execute("ALTER TABLE bad_indicators ADD COLUMN indicator_type TEXT DEFAULT 'ip'")
        except sqlite3.OperationalError: pass
        c.execute("INSERT OR REPLACE INTO bad_indicators(value,source,note,indicator_type) "
                  "VALUES(?,?,?,?)", (ja4_val, "kb", "FTPS C2", "ja4")); c.commit(); c.close()
        monkeypatch.setenv("THREATINTEL_DB", db)
        from orchestrator import build_network_events
        net = build_network_events(pcap)
        c2 = [e for e in net if e["dst_ip"] == "198.51.100.200"]
        assert c2 and c2[0]["confidence_tier"] == "confirmed"
        assert c2[0]["ja4"] == ja4_val

"""
test_ftps_ja3_mitigation.py — encrypted-FTP (FTPS) is caught by TLS fingerprint.

When an FTP session negotiates AUTH TLS, the STOR command is encrypted and the
FTP-STOR detector goes blind. The mitigation: fingerprint the ClientHello (JA3)
straight from the pcap — no Zeek — so the destination still gets attribution,
and a known-bad fingerprint still flags it at the confirmed tier.

These tests drive the real FTPS handshake from the Zeek corpus, rewritten from
loopback to a public C2 so it isn't filtered as private.
"""
import sys, os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "pipeline"))

import sqlite3
import pytest
from scapy.all import rdpcap, IP, wrpcap

FTPS = os.path.join(os.path.dirname(__file__), "..", "data", "FTP Testing",
                    "ftp-auth-tls.pcap")
C2 = "198.51.100.200"


def _public_ftps_pcap(dst_path: str) -> str:
    """Rewrite the loopback FTPS capture to a public client->C2 session."""
    if not os.path.exists(FTPS):
        pytest.skip("ftp-auth-tls.pcap not present")
    pk = rdpcap(FTPS)
    for p in pk:
        if IP in p:
            if p[IP].dst == "127.0.0.1":
                p[IP].dst = C2
            if p[IP].src == "127.0.0.1":
                p[IP].src = "192.168.1.50"
            del p[IP].chksum
            if p.haslayer("TCP"):
                del p["TCP"].chksum
    wrpcap(dst_path, pk)
    return dst_path


def _seed_ja3(db_path: str, ja3: str):
    from attribution import init_threatintel_db
    init_threatintel_db(path=db_path, seed=True)
    c = sqlite3.connect(db_path)
    try:
        c.execute("ALTER TABLE bad_indicators ADD COLUMN indicator_type TEXT DEFAULT 'ip'")
    except sqlite3.OperationalError:
        pass
    c.execute("INSERT OR REPLACE INTO bad_indicators(value,source,note,indicator_type) "
              "VALUES(?,?,?,?)", (ja3, "known_bad_ja3", "FTPS C2", "ja3"))
    c.commit(); c.close()


def test_ftps_handshake_is_fingerprinted(tmp_path):
    """The AUTH TLS ClientHello yields a JA3 straight from the pcap (no Zeek)."""
    from ja3_from_pcap import extract_flows
    pcap = _public_ftps_pcap(str(tmp_path / "ftps.pcap"))
    ja3s = [f.ja3 for f in extract_flows(pcap).values() if f.ja3]
    assert ja3s, "no JA3 extracted from the FTPS handshake"


def test_known_bad_ftps_ja3_flags_confirmed(tmp_path, monkeypatch):
    """A known-bad FTPS fingerprint flags the C2 at the confirmed tier even
    though its STOR is encrypted and invisible."""
    from ja3_from_pcap import extract_flows
    pcap = _public_ftps_pcap(str(tmp_path / "ftps.pcap"))
    ja3 = [f.ja3 for f in extract_flows(pcap).values() if f.ja3][0]

    db = str(tmp_path / "ti.sqlite")
    _seed_ja3(db, ja3)
    monkeypatch.setenv("THREATINTEL_DB", db)

    from orchestrator import build_network_events
    events = build_network_events(pcap)
    c2_events = [e for e in events if e["dst_ip"] == C2]
    assert len(c2_events) == 1
    e = c2_events[0]
    assert e["kind"] == "ja3"
    assert e["reputation_hit"] is True
    assert e["confidence_tier"] == "confirmed"


def test_benign_ftps_ja3_does_not_flag(tmp_path, monkeypatch):
    """The same FTPS handshake, fingerprint NOT known-bad → no flag."""
    pcap = _public_ftps_pcap(str(tmp_path / "ftps.pcap"))
    db = str(tmp_path / "ti.sqlite")
    from attribution import init_threatintel_db
    init_threatintel_db(path=db, seed=True)      # seed IPs only, not this JA3
    monkeypatch.setenv("THREATINTEL_DB", db)

    from orchestrator import build_network_events
    events = build_network_events(pcap)
    # The fingerprint path must NOT fire (JA4 not known-bad) and nothing is
    # confirmed. (The content-agnostic catch-all may still surface the upload as
    # a weak candidate — that is expected and not a fingerprint match.)
    c2 = [e for e in events if e["dst_ip"] == C2]
    assert all(e["kind"] != "ja3" for e in c2)
    assert all(e["confidence_tier"] != "confirmed" for e in c2)

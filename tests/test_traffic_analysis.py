"""
test_traffic_analysis.py — beaconing and exfiltration detection tests.

Covers the core detection logic that everything downstream depends on:
  * Beaconing: regular-interval callbacks → is_beacon=True, irregular → False
  * Exfiltration: large POST / high upload-ratio → is_exfil=True
  * Private IP filtering: RFC1918 destinations never flagged
"""
import sys, os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "pipeline"))

from pipeline.traffic_analysis import (
    Connection, detect_beaconing, detect_exfil, detect_ftp_exfil, _is_private_ip,
    network_confidence_tier, detect_unclassified_egress,
)
from conftest import _make_conn


class TestUnclassifiedEgress:
    """Content-agnostic catch-all for UNKNOWN exfil channels."""

    def test_novel_channel_flagged(self):
        """Raw high-upload flow on an odd port, unexplained → flagged."""
        c = _make_conn(dst_ip="203.0.113.9", dst_port=4444,
                       orig_bytes=50000, resp_bytes=500)
        v = detect_unclassified_egress([c], covered_dsts=set())
        assert len(v) == 1 and v[0].dst_ip == "203.0.113.9"

    def test_already_explained_not_reflagged(self):
        c = _make_conn(dst_ip="203.0.113.9", dst_port=4444,
                       orig_bytes=50000, resp_bytes=500)
        assert detect_unclassified_egress([c], covered_dsts={"203.0.113.9"}) == []

    def test_download_not_flagged(self):
        c = _make_conn(dst_ip="203.0.113.9", dst_port=443,
                       orig_bytes=200, resp_bytes=90000)
        assert detect_unclassified_egress([c], covered_dsts=set()) == []

    def test_private_dst_not_flagged(self):
        c = _make_conn(dst_ip="192.168.1.5", dst_port=4444,
                       orig_bytes=50000, resp_bytes=0)
        assert detect_unclassified_egress([c], covered_dsts=set()) == []

    def test_tiny_upload_not_flagged(self):
        c = _make_conn(dst_ip="203.0.113.9", dst_port=4444,
                       orig_bytes=100, resp_bytes=0)
        assert detect_unclassified_egress([c], covered_dsts=set()) == []


def _ftp_conn(dst_ip="203.0.113.80", dst_port=21, orig_bytes=200,
              resp_bytes=800, cmd="STOR secrets.txt", src_ip="10.0.0.5"):
    """An FTP control-channel connection carrying an upload command."""
    return Connection(
        ts=1000.0, src_ip=src_ip, dst_ip=dst_ip, dst_port=dst_port, proto="tcp",
        orig_bytes=orig_bytes, resp_bytes=resp_bytes, history="",
        ftp_upload_cmd=cmd,
    )


# ===== Beaconing detection =================================================

class TestBeaconingPositive:
    def test_regular_interval_detected(self, beacon_conns):
        """10 connections at 30s intervals → beacon detected."""
        verdicts = detect_beaconing(beacon_conns)
        assert len(verdicts) == 1
        v = verdicts[0]
        assert v.is_beacon is True
        assert v.dst_ip == "198.51.100.22"
        assert v.connection_count == 10
        assert v.confidence > 0.5

    def test_jitter_ratio_low(self, beacon_conns):
        """Perfect 30s intervals → jitter ratio should be 0.0."""
        v = detect_beaconing(beacon_conns)[0]
        assert v.jitter_ratio == 0.0

    def test_mean_interval(self, beacon_conns):
        """Mean interval should be 30.0s for 30s-spaced connections."""
        v = detect_beaconing(beacon_conns)[0]
        assert v.mean_interval_s == 30.0


class TestBeaconingNegative:
    def test_irregular_not_flagged(self, irregular_conns):
        """Randomly spaced connections → no beacon verdict (or is_beacon=False)."""
        verdicts = detect_beaconing(irregular_conns)
        beacons = [v for v in verdicts if v.is_beacon]
        assert len(beacons) == 0

    def test_too_few_connections(self):
        """Only 2 connections → below min_count, never flagged."""
        conns = [
            _make_conn(ts=1000.0, dst_ip="198.51.100.70", dst_port=443),
            _make_conn(ts=1030.0, dst_ip="198.51.100.70", dst_port=443),
        ]
        verdicts = detect_beaconing(conns, min_count=4)
        assert len(verdicts) == 0


class TestBeaconingPrivateIP:
    def test_private_dst_excluded(self):
        """Beaconing to a private IP (e.g. victim's own LAN) → not flagged."""
        conns = [
            _make_conn(ts=1000.0 + i * 30.0, dst_ip="10.10.23.101", dst_port=443)
            for i in range(10)
        ]
        verdicts = detect_beaconing(conns)
        assert len(verdicts) == 0


class TestBeaconingNearZeroInterval:
    def test_parallel_connections_not_a_beacon(self):
        """4 near-simultaneous connections (mean interval ~0) are a parallel
        burst (browser opening sockets to a CDN), NOT a periodic beacon —
        this was a real false-positive source on live enterprise traffic."""
        conns = [
            _make_conn(ts=1000.0 + i * 0.01, dst_ip="203.0.113.50", dst_port=443)
            for i in range(6)
        ]
        beacons = [v for v in detect_beaconing(conns) if v.is_beacon]
        assert len(beacons) == 0

    def test_real_interval_still_beacons(self):
        """Sanity: genuine 30s-spaced callbacks still flag."""
        conns = [
            _make_conn(ts=1000.0 + i * 30.0, dst_ip="203.0.113.51", dst_port=443)
            for i in range(6)
        ]
        beacons = [v for v in detect_beaconing(conns) if v.is_beacon]
        assert len(beacons) == 1


# ===== Confidence tiering ==================================================

class TestConfidenceTier:
    def test_reputation_is_confirmed(self):
        """Threat-intel / JA3 backing → confirmed, even on a single signal."""
        assert network_confidence_tier(True, 1) == "confirmed"

    def test_two_signals_is_strong(self):
        """Beacon AND exfil on the same dst, no intel → strong."""
        assert network_confidence_tier(False, 2) == "strong"

    def test_single_signal_is_weak(self):
        """A lone behavioural signal (STOR/exfil/beacon), no intel → weak."""
        assert network_confidence_tier(False, 1) == "weak"

    def test_reputation_beats_signal_count(self):
        assert network_confidence_tier(True, 2) == "confirmed"


# ===== Exfiltration detection ==============================================

class TestExfilPositive:
    def test_large_post(self, exfil_post_conn):
        """HTTP POST with 5KB payload → exfil detected."""
        verdicts = detect_exfil([exfil_post_conn])
        assert len(verdicts) == 1
        v = verdicts[0]
        assert v.is_exfil is True
        assert v.http_method == "POST"
        assert v.confidence >= 0.8   # POST + high ratio → high conf

    def test_high_upload_ratio_no_post(self):
        """High upload ratio without POST → still flagged (non-HTTP exfil)."""
        c = _make_conn(
            dst_ip="198.51.100.77", dst_port=8080,
            orig_bytes=4000, resp_bytes=200,
        )
        verdicts = detect_exfil([c])
        assert len(verdicts) == 1
        assert verdicts[0].is_exfil is True


class TestExfilNegative:
    def test_download_heavy_not_flagged(self, benign_download_conn):
        """Download-heavy flow (low upload ratio) → not exfil."""
        verdicts = detect_exfil([benign_download_conn])
        assert len(verdicts) == 0

    def test_small_post_not_flagged(self, small_post_conn):
        """Tiny POST (500 bytes) → below min_upload_bytes threshold."""
        verdicts = detect_exfil([small_post_conn])
        assert len(verdicts) == 0


class TestExfilPrivateIP:
    def test_private_dst_excluded(self):
        """Large POST to a private IP → not flagged as exfil."""
        c = _make_conn(
            dst_ip="192.168.1.1", dst_port=80,
            orig_bytes=5000, resp_bytes=200,
            http_method="POST", http_uri="/upload",
        )
        verdicts = detect_exfil([c])
        assert len(verdicts) == 0


# ===== FTP-STOR exfiltration detection =====================================

class TestFTPExfilPositive:
    def test_stor_flags_low_volume(self):
        """A STOR command with only ~200 bytes → flagged despite tiny volume.

        This is the AgentTesla-style case the byte-threshold path misses."""
        v = detect_ftp_exfil([_ftp_conn(orig_bytes=218)])
        assert len(v) == 1
        assert v[0].is_exfil is True
        assert v[0].dst_ip == "203.0.113.80"
        assert v[0].http_method == "FTP"
        assert "STOR" in v[0].http_uri
        assert v[0].confidence == 0.8

    def test_appe_detected(self):
        """APPE (append) is also an upload command → flagged."""
        v = detect_ftp_exfil([_ftp_conn(cmd="APPE stolen.dat")])
        assert len(v) == 1

    def test_one_verdict_per_server(self):
        """Multiple STOR flows to the same server → a single verdict."""
        conns = [
            _ftp_conn(cmd="STOR passwords.txt"),
            _ftp_conn(cmd="STOR cookies.txt"),
        ]
        v = detect_ftp_exfil(conns)
        assert len(v) == 1


class TestFTPExfilNegative:
    def test_no_stor_not_flagged(self):
        """FTP control traffic without an upload command → not flagged."""
        c = Connection(ts=1000.0, src_ip="10.0.0.5", dst_ip="203.0.113.80",
                       dst_port=21, proto="tcp", orig_bytes=500, resp_bytes=800)
        assert detect_ftp_exfil([c]) == []

    def test_private_server_excluded(self):
        """STOR to an internal/private FTP server → not flagged."""
        v = detect_ftp_exfil([_ftp_conn(dst_ip="10.9.0.5")])
        assert v == []


# ===== Private IP helper ===================================================

class TestIsPrivateIP:
    def test_rfc1918_class_a(self):
        assert _is_private_ip("10.0.0.1") is True

    def test_rfc1918_class_b(self):
        assert _is_private_ip("172.16.0.1") is True

    def test_rfc1918_class_c(self):
        assert _is_private_ip("192.168.1.1") is True

    def test_loopback(self):
        assert _is_private_ip("127.0.0.1") is True

    def test_public_ip(self):
        assert _is_private_ip("188.190.10.10") is False

    def test_ipv6_loopback(self):
        assert _is_private_ip("::1") is True

    def test_ipv6_link_local(self):
        assert _is_private_ip("fe80::1") is True

    def test_ipv6_unique_local(self):
        assert _is_private_ip("fc00::1") is True

    def test_ipv6_global_unicast_is_public(self):
        """A routable IPv6 (e.g. an FTP/C2 server) must NOT be filtered."""
        assert _is_private_ip("2001:638:902:1:201:2ff:fee2:7596") is False

    def test_invalid_ip(self):
        assert _is_private_ip("not-an-ip") is False

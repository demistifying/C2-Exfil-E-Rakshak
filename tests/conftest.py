"""
Shared pytest fixtures for the Windows C2/Exfiltration module test suite.

All fixtures produce self-contained data — no external files, no network calls.
"""
from __future__ import annotations
import sys
import os
import json
import tempfile
import pytest

# Ensure the pipeline package is importable regardless of working directory.
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "pipeline"))

from pipeline.traffic_analysis import Connection


# ---------------------------------------------------------------------------
# Connection factories
# ---------------------------------------------------------------------------

def _make_conn(dst_ip="203.0.113.50", dst_port=443, ts=1000.0,
               orig_bytes=100, resp_bytes=5000, proto="tcp",
               http_method=None, http_host=None, http_uri=None,
               src_ip="10.0.0.5") -> Connection:
    """Utility — create a Connection with sensible defaults."""
    return Connection(
        ts=ts, src_ip=src_ip, dst_ip=dst_ip, dst_port=dst_port, proto=proto,
        orig_bytes=orig_bytes, resp_bytes=resp_bytes, history="",
        http_method=http_method, http_host=http_host, http_uri=http_uri,
    )


@pytest.fixture
def beacon_conns() -> list[Connection]:
    """10 connections to a single destination at perfectly regular 30-second
    intervals — classic C2 beaconing pattern."""
    return [
        _make_conn(ts=1000.0 + i * 30.0, dst_ip="198.51.100.22", dst_port=443)
        for i in range(10)
    ]


@pytest.fixture
def irregular_conns() -> list[Connection]:
    """Randomly-spaced connections — should NOT trigger beaconing."""
    import random
    random.seed(42)
    times = sorted([1000.0 + random.uniform(0, 600) for _ in range(10)])
    return [
        _make_conn(ts=t, dst_ip="198.51.100.33", dst_port=443)
        for t in times
    ]


@pytest.fixture
def exfil_post_conn() -> Connection:
    """A large HTTP POST — classic credential exfiltration."""
    return _make_conn(
        dst_ip="198.51.100.44", dst_port=80, ts=1000.0,
        orig_bytes=5000, resp_bytes=200,
        http_method="POST", http_uri="/gate.php",
    )


@pytest.fixture
def benign_download_conn() -> Connection:
    """Normal web traffic: mostly downloading, small upload ratio."""
    return _make_conn(
        dst_ip="198.51.100.55", dst_port=443, ts=1000.0,
        orig_bytes=200, resp_bytes=50000,
    )


@pytest.fixture
def small_post_conn() -> Connection:
    """Tiny POST (form submission) — below exfil byte threshold."""
    return _make_conn(
        dst_ip="198.51.100.66", dst_port=443, ts=1000.0,
        orig_bytes=500, resp_bytes=200,
        http_method="POST", http_uri="/login",
    )


# ---------------------------------------------------------------------------
# Threat-intel DB fixtures
# ---------------------------------------------------------------------------

@pytest.fixture
def tmp_threatintel_db(tmp_path):
    """A temporary threat-intel SQLite DB seeded with known-bad IPs."""
    db_path = str(tmp_path / "test_threatintel.sqlite")
    from pipeline.attribution import init_threatintel_db
    init_threatintel_db(path=db_path, seed=True)
    return db_path


# ---------------------------------------------------------------------------
# Access event fixtures (for correlation tests)
# ---------------------------------------------------------------------------

@pytest.fixture
def sample_access_events() -> list[dict]:
    """Host access events with known timestamps for correlation testing."""
    return [
        {
            "timestamp": "2024-10-23T19:15:30+00:00",
            "data_type": "browser_credentials",
            "api_call": "CryptUnprotectData",
            "process": "stealer.exe",
        },
        {
            "timestamp": "2024-10-23T19:15:31+00:00",
            "data_type": "keystrokes",
            "api_call": "SetWindowsHookEx(WH_KEYBOARD_LL)",
            "process": "stealer.exe",
        },
    ]


@pytest.fixture
def sample_network_events() -> list[dict]:
    """Network events timed to correlate with sample_access_events."""
    return [
        {
            "timestamp": "2024-10-23T19:15:35+00:00",   # 5s after access[0]
            "dst_ip": "198.51.100.44",
            "dst_port": 80,
            "confidence": 0.9,
            "reputation_hit": True,
        },
        {
            "timestamp": "2024-10-23T19:16:45+00:00",   # 75s after access[0] — outside window
            "dst_ip": "198.51.100.55",
            "dst_port": 443,
            "confidence": 0.5,
            "reputation_hit": False,
        },
    ]

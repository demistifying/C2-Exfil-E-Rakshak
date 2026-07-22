"""
test_evidence_chain.py — hash-chained evidence integrity tests.

Evidence-grade integrity for a police context: each output row embeds
SHA-256(prev_hash + this_row). Tampering with any row breaks verification
from that row onward. These tests prove that property.
"""
import sys, os, json, hashlib, uuid, copy
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "pipeline"))

from pipeline.orchestrator import emit_schema_rows


def _make_correlated():
    """Minimal correlated event objects for testing the emitter."""
    from pipeline.correlation import CorrelatedEvent
    return [
        CorrelatedEvent(
            data_type_accessed="browser_credentials",
            access_api_call="CryptUnprotectData",
            access_ts="2024-10-23T19:15:30+00:00",
            destination_ip="198.51.100.44",
            destination_port=80,
            network_ts="2024-10-23T19:15:35+00:00",
            time_delta_s=5.0,
            network_confidence=0.9,
            reputation_hit=True,
            correlation_confidence=0.93,
            confidence_tier="confirmed",
        ),
        CorrelatedEvent(
            data_type_accessed="keystrokes",
            access_api_call="SetWindowsHookEx(WH_KEYBOARD_LL)",
            access_ts="2024-10-23T19:15:31+00:00",
            destination_ip="198.51.100.44",
            destination_port=80,
            network_ts="2024-10-23T19:15:35+00:00",
            time_delta_s=4.0,
            network_confidence=0.9,
            reputation_hit=True,
            correlation_confidence=0.95,
            confidence_tier="confirmed",
        ),
    ]


def _make_network_events():
    """Minimal network events for testing the emitter."""
    return [
        {
            "kind": "exfil",
            "dst_ip": "198.51.100.44",
            "dst_port": 80,
            "timestamp": "2024-10-23T19:15:35+00:00",
            "confidence": 0.9,
            "reputation_hit": True,
        },
    ]


def _verify_chain(rows: list[dict]) -> tuple[bool, int]:
    """Re-compute the hash chain from scratch and verify.
    Returns (all_valid, first_broken_index). If all valid, first_broken_index = -1."""
    prev = "0" * 64
    for i, row in enumerate(rows):
        row_copy = {k: v for k, v in row.items() if k != "evidence_hash"}
        expected = hashlib.sha256(
            (prev + json.dumps(row_copy, sort_keys=True)).encode()
        ).hexdigest()
        if row["evidence_hash"] != expected:
            return False, i
        prev = row["evidence_hash"]
    return True, -1


class TestChainContinuity:
    def test_chain_valid(self):
        """Every hash = SHA256(prev_hash + row_content). No breaks."""
        rows = emit_schema_rows(
            _make_network_events(), _make_correlated(), sample_id="test123")
        valid, idx = _verify_chain(rows)
        assert valid, f"Chain broke at row {idx}"

    def test_chain_has_correct_length(self):
        """Should have 2 correlated + 1 network-only = 3 rows."""
        rows = emit_schema_rows(
            _make_network_events(), _make_correlated(), sample_id="test123")
        assert len(rows) == 3

    def test_genesis_hash(self):
        """First row's hash should chain from the zero hash (0*64)."""
        rows = emit_schema_rows(
            _make_network_events(), _make_correlated(), sample_id="test123")
        row = rows[0]
        row_copy = {k: v for k, v in row.items() if k != "evidence_hash"}
        expected = hashlib.sha256(
            ("0" * 64 + json.dumps(row_copy, sort_keys=True)).encode()
        ).hexdigest()
        assert row["evidence_hash"] == expected


class TestChainTamperDetection:
    def test_tamper_breaks_chain(self):
        """Modifying a row's content → chain verification fails from that row."""
        rows = emit_schema_rows(
            _make_network_events(), _make_correlated(), sample_id="test123")
        # Tamper with the second row
        rows[1]["confidence_score"] = 0.01
        valid, idx = _verify_chain(rows)
        assert not valid
        assert idx == 1  # breaks at the tampered row

    def test_tamper_first_row(self):
        """Tampering the first row breaks the entire chain."""
        rows = emit_schema_rows(
            _make_network_events(), _make_correlated(), sample_id="test123")
        rows[0]["destination_ip"] = "1.2.3.4"
        valid, idx = _verify_chain(rows)
        assert not valid
        assert idx == 0


class TestChainSingleRow:
    def test_single_row_chains_from_genesis(self):
        """A single row should still chain from the zero hash."""
        rows = emit_schema_rows(
            _make_network_events(), [], sample_id="test123")
        assert len(rows) == 1
        valid, _ = _verify_chain(rows)
        assert valid

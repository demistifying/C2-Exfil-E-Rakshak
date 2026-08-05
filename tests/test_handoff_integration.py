"""
test_handoff_integration.py — WinST/DT handoff consumption + honesty gates,
beaconing handshake guard, bundle filter, and the schema join/custody fields.

These cover the integration gaps identified against the ST/DT contracts:
manifest-aware gating (network_mode / clock / telemetry), the handshake guard
that stops inetsim SYN-retry storms masquerading as beacons, guest_ip/window
scoping, and the per-run join keys + custody-chain link.
"""
import os
import sys
import json

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "pipeline"))

import pytest
from pipeline.model import Connection, AnalysisBundle, Session, DnsTransaction
from pipeline.traffic_analysis import detect_beaconing
from pipeline.bundle_filter import filter_bundle
from pipeline.handoff import (Handoff, load_handoff, gate_network_events,
                              gate_correlated, affected_data_types)


def _conn(ts, resp_bytes, history, dst="203.0.113.9"):
    return Connection(ts=ts, src_ip="10.0.0.5", dst_ip=dst, dst_port=443,
                      proto="tcp", orig_bytes=200, resp_bytes=resp_bytes,
                      history=history)


# ---------------- beaconing handshake guard ----------------

class TestHandshakeGuard:
    def test_retry_storm_tagged_unanswered_and_capped(self):
        storm = [_conn(i * 60.0, 0, "S") for i in range(8)]     # no reply, ever
        v = detect_beaconing(storm)[0]
        assert v.is_beacon and v.unanswered
        assert v.handshake_ratio == 0.0
        assert v.confidence <= 0.3

    def test_real_answered_beacon_not_tagged(self):
        real = [_conn(i * 57.0, 1500, "ShADadfF") for i in range(8)]
        v = detect_beaconing(real)[0]
        assert v.is_beacon and not v.unanswered
        assert v.handshake_ratio == 1.0 and v.confidence > 0.5

    def test_partial_answers_not_flagged_unanswered(self):
        mixed = [_conn(i * 60.0, (1500 if i % 2 else 0),
                       ("ShADf" if i % 2 else "S")) for i in range(8)]
        v = detect_beaconing(mixed)[0]
        assert not v.unanswered and 0 < v.handshake_ratio < 1


# ---------------- bundle filter (guest_ip + window) ----------------

class TestBundleFilter:
    def _bundle(self):
        b = AnalysisBundle(source="test")
        # guest 10.0.0.5 flows, plus a foreign VM flow, plus an out-of-window one
        b.sessions = [
            Session(ts=1000.0, src_ip="10.0.0.5", src_port=1, dst_ip="8.8.8.8",
                    dst_port=53, proto="udp", service="dns", orig_bytes=1,
                    resp_bytes=1, history="Dd", duration=0.1, conn_state="SF", uid="a"),
            Session(ts=1000.0, src_ip="10.0.0.9", src_port=1, dst_ip="8.8.4.4",
                    dst_port=53, proto="udp", service="dns", orig_bytes=1,
                    resp_bytes=1, history="Dd", duration=0.1, conn_state="SF", uid="b"),
            Session(ts=5000.0, src_ip="10.0.0.5", src_port=1, dst_ip="1.2.3.4",
                    dst_port=80, proto="tcp", service="http", orig_bytes=1,
                    resp_bytes=1, history="Sr", duration=0.1, conn_state="S0", uid="c"),
        ]
        b.dns = [DnsTransaction(ts=1000.0, src_ip="10.0.0.5", dst_ip="8.8.8.8",
                                query="x.test", qtype="A", rcode="NOERROR",
                                answers=[], uid="a")]
        return b

    def test_filter_by_guest_ip_drops_foreign_vm(self):
        b = self._bundle()
        summary = filter_bundle(b, guest_ip="10.0.0.5")
        assert summary["applied"]
        assert all(s.src_ip == "10.0.0.5" or s.dst_ip == "10.0.0.5"
                   for s in b.sessions)
        assert len(b.sessions) == 2          # foreign 10.0.0.9 dropped

    def test_filter_by_window_drops_out_of_range(self):
        b = self._bundle()
        # window covers ts=1000 but not ts=5000
        filter_bundle(b, guest_ip="10.0.0.5",
                      start_utc="1970-01-01T00:15:00+00:00",   # 900s
                      end_utc="1970-01-01T00:20:00+00:00")     # 1200s
        assert len(b.sessions) == 1 and b.sessions[0].ts == 1000.0

    def test_no_params_is_noop(self):
        b = self._bundle()
        before = len(b.sessions)
        summary = filter_bundle(b)
        assert summary["applied"] is False and len(b.sessions) == before


# ---------------- manifest honesty gates ----------------

def _h(**kw):
    base = dict(schema_version="1.0", session_id="s1", cape_task_id=1,
                network_mode="live_egress", clock_quality_acceptable=True,
                telemetry_degraded=False, providers_unavailable=[])
    base.update(kw)
    return Handoff(**base)


class TestGates:
    def test_simulated_inetsim_adds_absence_caveat(self):
        ev = [{"kind": "exfil", "dst_ip": "1.2.3.4", "confidence_tier": "confirmed"}]
        notes = gate_network_events(ev, _h(network_mode="simulated_inetsim"))
        assert any("SIMULATED" in n and "ABSENCE" in n for n in notes)
        assert ev[0]["network_mode"] == "simulated_inetsim"
        # contacting a known-bad host is still real -> tier untouched
        assert ev[0]["confidence_tier"] == "confirmed"

    def test_bad_clock_caps_beacon_but_not_reputation(self):
        ev = [{"kind": "beacon", "dst_ip": "1.2.3.4", "confidence_tier": "strong",
               "reputation_hit": False},
              {"kind": "beacon", "dst_ip": "9.9.9.9", "confidence_tier": "confirmed",
               "reputation_hit": True}]
        gate_network_events(ev, _h(clock_quality_acceptable=False))
        assert ev[0]["confidence_tier"] == "weak"       # timing claim capped
        assert ev[1]["confidence_tier"] == "confirmed"  # reputation stands

    def test_telemetry_degraded_caps_mapped_data_types(self):
        aff, glob = affected_data_types(
            _h(telemetry_degraded=True, providers_unavailable=["Microsoft-Windows-Win32k"]))
        assert {"keystrokes", "screenshot", "clipboard"} <= aff and not glob

    def test_telemetry_degraded_correlated_capping(self):
        corr = [{"data_type_accessed": "keystrokes", "confidence_tier": "strong",
                 "reputation_hit": False},
                {"data_type_accessed": "browser_credentials", "confidence_tier": "strong",
                 "reputation_hit": False}]
        gate_correlated(corr, _h(telemetry_degraded=True,
                                 providers_unavailable=["Microsoft-Windows-Win32k"]))
        assert corr[0]["confidence_tier"] == "weak"     # keystrokes -> Win32k gone
        assert corr[1]["confidence_tier"] == "strong"   # creds provider unaffected

    def test_unmapped_provider_triggers_global_fallback(self):
        aff, glob = affected_data_types(
            _h(telemetry_degraded=True, providers_unavailable=["Some-Unknown-Provider"]))
        assert glob is True

    def test_no_handoff_is_noop(self):
        ev = [{"kind": "beacon", "confidence_tier": "strong"}]
        assert gate_network_events(ev, None) == []
        assert ev[0]["confidence_tier"] == "strong"


class TestLoadHandoff:
    def test_load_and_extract(self, tmp_path):
        p = tmp_path / "m.json"
        json.dump({
            "schema_version": "1.0", "session_id": "sess-9", "cape_task_id": 9,
            "network_mode": "simulated_inetsim",
            "detonation_start_utc": "2024-01-01T00:00:00+00:00",
            "detonation_end_utc": "2024-01-01T00:05:00+00:00",
            "guest_vm_identity": {"guest_ip": "10.0.0.5"},
            "correlation": {"clock_quality_acceptable": False},
            "telemetry": {"telemetry_degraded": True,
                          "providers_unavailable": [{"provider": "P", "reason": "x", "message": "y"}]},
            "integrity": {"hash_manifest_sha256": "ab" * 32},
        }, open(p, "w"))
        h = load_handoff(str(p))
        assert h.session_id == "sess-9" and h.cape_task_id == 9
        assert h.simulated and h.clock_quality_acceptable is False
        assert h.telemetry_degraded and h.providers_unavailable == ["P"]
        assert h.guest_ip == "10.0.0.5" and h.hash_manifest_sha256 == "ab" * 32

    def test_missing_clock_field_defaults_to_not_acceptable(self, tmp_path):
        # safe default: absent clock quality -> treat as NOT acceptable
        p = tmp_path / "m.json"
        json.dump({"schema_version": "1.0", "session_id": "s", "cape_task_id": 1,
                   "network_mode": "live_egress", "correlation": {},
                   "telemetry": {}}, open(p, "w"))
        assert load_handoff(str(p)).clock_quality_acceptable is False


class TestEmitJoinAndCustody:
    def _net(self):
        return [{"kind": "exfil", "dst_ip": "1.2.3.4", "dst_port": 443,
                 "timestamp": "2024-01-01T00:00:00+00:00", "reputation_hit": True,
                 "confidence": 1.0, "destination_domain": None}]

    def test_join_fields_on_rows(self):
        from pipeline.orchestrator import emit_schema_rows
        h = _h(session_id="sess-42", cape_task_id=42,
               hash_manifest_sha256="cd" * 32)
        rows = emit_schema_rows(self._net(), [], "sample", handoff=h)
        assert rows[0]["session_id"] == "sess-42"
        assert rows[0]["cape_task_id"] == 42

    def test_custody_seed_links_chain(self):
        """First row records the manifest hash AND the chain is seeded from it —
        so tampering with the manifest hash changes our first evidence_hash."""
        from pipeline.orchestrator import emit_schema_rows
        seed = "cd" * 32
        h = _h(hash_manifest_sha256=seed)
        rows = emit_schema_rows(self._net(), [], "sample", handoff=h)
        assert rows[0]["manifest_sha256"] == seed
        # a different seed must produce a different first-row hash
        h2 = _h(hash_manifest_sha256="ef" * 32)
        rows2 = emit_schema_rows(self._net(), [], "sample", handoff=h2)
        assert rows[0]["evidence_hash"] != rows2[0]["evidence_hash"]

    def test_no_handoff_no_join_or_manifest(self):
        from pipeline.orchestrator import emit_schema_rows
        rows = emit_schema_rows(self._net(), [], "sample")
        assert rows[0]["session_id"] is None and rows[0]["cape_task_id"] is None
        assert "manifest_sha256" not in rows[0]   # only present when linked

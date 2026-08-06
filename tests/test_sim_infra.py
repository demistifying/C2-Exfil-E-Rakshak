"""
test_sim_infra.py — simulated-network detection + infrastructure handling.

Regression coverage for the gaps found on the real task-18 bundle (a
simulated_inetsim detonation where the C2 sits on a private responder and the
manifest carried guest_ip="unknown"):

  * guest_ip sentinel ("unknown") must NOT filter the whole bundle away
  * guest VM inferred when the manifest didn't populate it
  * private simulated-C2 responder is analysed (not dropped by the private filter)
  * guest + DNS resolver treated as infrastructure, never confirmed as C2
  * clock acceptability derived from maximum_uncertainty_ns
  * static prior consumed from the ST/DT "iocs" schema key
"""
import os
import sys
import json

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "pipeline"))

from pipeline.model import Session, DnsTransaction, AnalysisBundle, Connection
from pipeline.bundle_filter import (filter_bundle, infer_guest_ip,
                                    simulated_c2_scope, _norm_guest_ip)
from pipeline.traffic_analysis import detect_beaconing
from pipeline.static_prior import ingest_prior, correlate_static_prior
from pipeline.handoff import load_handoff


def _sess(ts, src, dst, dport=443, service="ssl", resp=1000, hist="ShADadfF"):
    return Session(ts=ts, src_ip=src, src_port=1234, dst_ip=dst, dst_port=dport,
                   proto="tcp", service=service, orig_bytes=200, resp_bytes=resp,
                   history=hist, duration=1.0, conn_state="SF", uid=f"u{ts}")


# ---------- guest_ip sentinel + inference ----------

class TestGuestIdentity:
    def test_unknown_sentinel_normalized_to_none(self):
        assert _norm_guest_ip("unknown") is None
        assert _norm_guest_ip("") is None
        assert _norm_guest_ip("10.0.0.5") == "10.0.0.5"

    def test_unknown_guest_ip_does_not_wipe_bundle(self):
        b = AnalysisBundle(source="t")
        b.sessions = [_sess(1.0, "10.0.0.5", "8.8.8.8")]
        summary = filter_bundle(b, guest_ip="unknown")
        assert summary["applied"] is False and len(b.sessions) == 1

    def test_infer_guest_ip_dominant_private_source(self):
        b = AnalysisBundle(source="t")
        b.sessions = ([_sess(i, "10.66.0.101", "10.66.0.254") for i in range(5)]
                      + [_sess(9, "10.66.0.9", "10.66.0.254")])
        assert infer_guest_ip(b) == "10.66.0.101"


# ---------- simulated-C2 scope + detection ----------

class TestSimulatedScope:
    def test_scope_excludes_guest_and_noise(self):
        b = AnalysisBundle(source="t")
        b.sessions = [_sess(1, "10.66.0.101", "10.66.0.254"),
                      _sess(2, "10.66.0.101", "10.66.0.255"),   # broadcast noise
                      _sess(3, "10.66.0.101", "239.255.255.250")]  # multicast
        scope = simulated_c2_scope(b, "10.66.0.101")
        assert scope == {"10.66.0.254"}

    def test_private_responder_beacon_seen_only_with_allowlist(self):
        # 8 regular answered callbacks to a PRIVATE responder
        conns = [Connection(ts=i * 60.0, src_ip="10.66.0.101", dst_ip="10.66.0.50",
                            dst_port=8080, proto="tcp", orig_bytes=300, resp_bytes=800,
                            history="ShADadfF") for i in range(8)]
        # default: private dst filtered -> nothing
        assert detect_beaconing(conns) == []
        # simulation scope allows it -> beacon detected, answered
        v = detect_beaconing(conns, allow_dsts={"10.66.0.50"})
        assert v and v[0].is_beacon and not v[0].unanswered


# ---------- infrastructure never confirmed as C2 ----------

class TestStaticPriorInfra:
    def test_iocs_schema_key_accepted(self):
        raw = {"schema_version": "1.0", "sample_sha256": "a" * 64,
               "iocs": [{"type": "ip", "value": "203.0.113.9",
                         "provenance": {"source_path": "x", "source_sha256": "b" * 64}}],
               "family_attribution": {"family": "TestFam", "evidence": [{"k": 1}]}}
        prior = ingest_prior(raw).prior
        assert [(i.type, i.value) for i in prior.indicators] == [("ip", "203.0.113.9")]
        assert prior.family == "TestFam"

    def test_raw_observed_promotes_public_contact(self):
        raw = {"iocs": [{"type": "ip", "value": "203.0.113.9"}]}
        prior = ingest_prior(raw).prior
        corr = correlate_static_prior(prior, [], observed_ips={"203.0.113.9"})
        assert corr[0].observed is True

    def test_resolver_not_matched_when_excluded_upstream(self):
        # if infra (resolver) is excluded from observed_ips, a resolver-only IOC
        # stays dormant rather than being confirmed as contacted C2
        raw = {"iocs": [{"type": "ip", "value": "10.66.0.254"}]}
        prior = ingest_prior(raw).prior
        corr = correlate_static_prior(prior, [], observed_ips=set())
        assert corr[0].observed is False


# ---------- clock uncertainty ----------

class TestClockUncertainty:
    def test_low_uncertainty_is_acceptable(self, tmp_path):
        p = tmp_path / "m.json"
        json.dump({"schema_version": "1.0", "session_id": "1", "cape_task_id": 1,
                   "network_mode": "simulated_inetsim",
                   "correlation": {"maximum_uncertainty_ns": 501908965},  # ~0.5s
                   "telemetry": {}}, open(p, "w"))
        assert load_handoff(str(p)).clock_quality_acceptable is True

    def test_high_uncertainty_not_acceptable(self, tmp_path):
        p = tmp_path / "m.json"
        json.dump({"schema_version": "1.0", "session_id": "1", "cape_task_id": 1,
                   "network_mode": "live_egress",
                   "correlation": {"maximum_uncertainty_ns": 30_000_000_000},  # 30s
                   "telemetry": {}}, open(p, "w"))
        assert load_handoff(str(p)).clock_quality_acceptable is False

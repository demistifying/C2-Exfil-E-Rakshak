"""
test_umat_event_contract.py — conformance with UMAT's C2 event schema 1.3.

UMAT (the integration control plane) validates every row we emit against
contracts/c2/c2-event-v1.3.schema.json. That schema REQUIRES four fields the
module previously never produced — case_id, finding_kind, plain_language,
evidence_refs — and sets additionalProperties=false, so an extra key is as
fatal as a missing one.

Its runtime pin is held at the pre-1.3 commit until we emit them, so these
tests are the gate on promotion.

The schema is vendored as a fixture rather than read from a sibling checkout:
the test must fail when WE drift, and must not silently pass or error when a
UMAT clone happens to be absent.
"""
import json
import os
import sys
import uuid

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "pipeline"))

import pytest

from pipeline.orchestrator import (
    emit_schema_rows, _finding_kind, _plain_language, _evidence_refs,
    _VALID_FINDING_KINDS, parse_args,
)

jsonschema = pytest.importorskip("jsonschema")

SCHEMA_PATH = os.path.join(os.path.dirname(__file__), "fixtures",
                           "umat-c2-event-v1.3.schema.json")


def _schema():
    with open(SCHEMA_PATH, encoding="utf-8") as f:
        return json.load(f)


def _net_event(**over):
    e = {
        "kind": "beacon",
        "timestamp": "2026-08-05T16:51:00.677024+00:00",
        "dst_ip": "203.0.113.9",
        "dst_port": 443,
        "destination_domain": "evil.example",
        "confidence": 0.9,
        "confidence_tier": "strong",
        "reputation_hit": False,
        "geo_country": "SG",
    }
    e.update(over)
    return e


def _rows(net=None, correlated=None, case_id=None):
    return emit_schema_rows(net if net is not None else [_net_event()],
                            correlated or [],
                            sample_id="a" * 64, case_id=case_id)


# --------------------------------------------------------------------------
# schema conformance
# --------------------------------------------------------------------------

class TestUmatConformance:
    def test_row_validates_against_umat_schema(self):
        rows = _rows(case_id=str(uuid.uuid4()))
        assert rows
        for r in rows:
            jsonschema.validate(r, _schema())

    def test_all_four_required_fields_present(self):
        r = _rows(case_id=str(uuid.uuid4()))[0]
        for f in ("case_id", "finding_kind", "plain_language", "evidence_refs"):
            assert f in r, f"{f} missing — UMAT cannot promote its runtime pin"

    def test_no_extra_keys(self):
        """additionalProperties=false: an unexpected key fails as hard as a
        missing one."""
        allowed = set(_schema()["properties"])
        for r in _rows(case_id=str(uuid.uuid4())):
            assert not (set(r) - allowed), f"keys outside the contract: {set(r) - allowed}"

    def test_every_native_kind_maps_into_their_enum(self):
        """Our detector vocabulary is finer-grained than theirs; every value
        must fold onto a legal finding_kind, including unknown detectors."""
        native = ["beacon", "exfil", "smtp_exfil", "unclassified_egress",
                  "static_ioc", "dga", "dga_ml", "dns_tunnel", "icmp_tunnel",
                  "port_mismatch", "tls_cert", "a_detector_added_next_week", None]
        for k in native:
            assert _finding_kind(k) in _VALID_FINDING_KINDS, k
            assert _finding_kind(k, True) in _VALID_FINDING_KINDS, k

    @pytest.mark.parametrize("native,expected", [
        ("beacon", "beacon"), ("exfil", "exfil"), ("smtp_exfil", "exfil"),
        ("dga", "dns"), ("dns_tunnel", "dns"), ("icmp_tunnel", "covert_channel"),
        ("port_mismatch", "covert_channel"), ("static_ioc", "static_ioc"),
        ("tls_cert", "reputation"),
    ])
    def test_kind_mapping(self, native, expected):
        assert _finding_kind(native) == expected

    def test_unknown_detector_with_reputation_hit_is_reputation(self):
        assert _finding_kind("brand_new", reputation_hit=True) == "reputation"

    def test_correlated_rows_are_kind_correlation(self):
        class C:
            data_type_accessed = "browser_credentials"
            access_api_call = "CryptUnprotectData"
            destination_ip = "203.0.113.9"
            destination_port = 443
            network_ts = "2026-08-05T16:51:04+00:00"
            time_delta_s = 4.0
            correlation_confidence = 0.9
            confidence_tier = "strong"
            reputation_hit = True
            mitre_technique_id = "T1555.003"
        rows = _rows(correlated=[C()], case_id=str(uuid.uuid4()))
        assert rows[0]["finding_kind"] == "correlation"
        jsonschema.validate(rows[0], _schema())


# --------------------------------------------------------------------------
# plain_language — officer-facing, and never stronger than the tier
# --------------------------------------------------------------------------

class TestPlainLanguage:
    def test_non_empty_for_every_kind(self):
        for k in ("beacon", "exfil", "dga", "icmp_tunnel", "static_ioc",
                  "tls_cert", "unclassified_egress", None):
            rows = _rows([_net_event(kind=k)], case_id=str(uuid.uuid4()))
            assert rows[0]["plain_language"].strip(), k

    def test_weak_tier_is_marked_unconfirmed(self):
        r = _rows([_net_event(confidence_tier="weak")])[0]
        assert "not confirmed" in r["plain_language"]

    def test_allowlisted_is_marked_benign(self):
        r = _rows([_net_event(confidence_tier="allowlisted")])[0]
        assert "not a threat" in r["plain_language"]

    def test_confirmed_carries_no_hedge(self):
        r = _rows([_net_event(confidence_tier="confirmed")])[0]
        assert "not confirmed" not in r["plain_language"]

    def test_contains_no_api_jargon(self):
        """L1 text is read by officers. No API names, no hex, no field names."""
        r = _rows([_net_event()])[0]
        low = r["plain_language"].lower()
        for jargon in ("ja3", "sha256", "confidence_tier", "ntcreatefile",
                       "cryptunprotectdata", "null", "none"):
            assert jargon not in low, jargon

    def test_threat_intel_note_surfaced(self):
        r = _rows([_net_event(reputation_hit=True, reputation_score=1.0,
                              reputation_note="RedLine Stealer C2 (URLhaus)")])[0]
        assert "threat-intelligence list" in r["plain_language"]


# --------------------------------------------------------------------------
# evidence_refs + case_id + chain integrity
# --------------------------------------------------------------------------

class TestEvidenceAndChain:
    def test_evidence_refs_is_list_of_objects(self):
        refs = _rows()[0]["evidence_refs"]
        assert isinstance(refs, list) and refs
        assert all(isinstance(x, dict) for x in refs)

    def test_ja3_and_intel_become_refs(self):
        r = _rows([_net_event(ja3_hash="2800f914", reputation_source="URLhaus",
                              reputation_note="n")])[0]
        types = {x["type"] for x in r["evidence_refs"]}
        assert {"network_event", "tls_fingerprint", "threat_intel"} <= types

    def test_case_id_defaults_none_for_standalone(self):
        assert _rows()[0]["case_id"] is None

    def test_case_id_is_threaded_through(self):
        cid = str(uuid.uuid4())
        assert _rows(case_id=cid)[0]["case_id"] == cid

    def test_case_id_flag_parses(self):
        cid = "019fe74d-9750-7923-abe1-4654ddc1b2ca"
        assert parse_args(["x.pcap", "--case-id", cid])["case_id"] == cid

    def test_integration_fields_are_inside_the_hash(self):
        """They must be covered by the evidence chain, not appended after it —
        otherwise the officer-facing text is not tamper-evident."""
        base = _rows(case_id="11111111-1111-1111-1111-111111111111")[0]
        other = _rows(case_id="22222222-2222-2222-2222-222222222222")[0]
        assert base["evidence_hash"] != other["evidence_hash"]

    def test_chain_still_links_rows(self):
        rows = _rows([_net_event(dst_ip="203.0.113.1"),
                      _net_event(dst_ip="203.0.113.2")])
        assert len({r["evidence_hash"] for r in rows}) == 2

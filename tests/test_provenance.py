"""
test_provenance.py — correlation hardening (best-match) + item-level provenance.
"""
import sys, os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "pipeline"))
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "tools"))

from pipeline.correlation import correlate
from pipeline.provenance import build_provenance, ITEM_TYPE
import etw_scenario_gen as gen


class TestBestMatch:
    def test_collapses_many_to_many(self):
        """Two accesses, three in-window exfils → best-match yields ≤2 (one per
        access), not the full spray."""
        acc, n = gen.many_to_many()
        full = correlate(acc, n)
        best = correlate(acc, n, best_match=True)
        assert len(best) < len(full)
        assert len(best) == 2                       # one per access event

    def test_best_pick_is_highest_confidence(self):
        acc, n = gen.many_to_many()
        best = correlate(acc, n, best_match=True)
        # the confirmed/reputation-hit destination should be chosen
        assert all(b.reputation_hit for b in best if b.destination_ip == "198.51.100.7")


class TestScenarios:
    def test_aligned_correlates(self):
        acc, n = gen.aligned()
        assert len(correlate(acc, n, best_match=True)) == 1

    def test_skewed_does_not_correlate(self):
        acc, n = gen.skewed()
        assert correlate(acc, n, best_match=True) == []

    def test_causal_chain_separates_destinations(self):
        acc, n = gen.causal_chain()
        prov = build_provenance(correlate(acc, n, best_match=True), n)
        dests = {r.destination_ip for r in prov}
        assert dests == {"198.51.100.7", "203.0.113.9"}


class TestProvenance:
    def test_otp_item_provenance(self):
        """The headline: clipboard OTP → HTTP exfil, item classified as OTP."""
        acc, n = gen.otp_example()
        prov = build_provenance(correlate(acc, n, best_match=True), n)
        assert len(prov) == 1
        r = prov[0]
        assert r.item_type == "otp"
        assert r.exfil_protocol == "HTTP"
        assert r.inferred is False                  # plaintext HTTP
        assert "GetClipboardData" in r.statement()

    def test_credential_classified(self):
        acc, n = gen.aligned()
        r = build_provenance(correlate(acc, n, best_match=True), n)[0]
        assert r.item_type == "credential"

    def test_encrypted_payload_is_inferred(self):
        """When the exfil payload is not plaintext, the item is an INFERENCE."""
        acc = [gen.access("browser_credentials", "CryptUnprotectData", 1.0)]
        n = [gen.net("198.51.100.7", 4.0, kind="ja3", plaintext=False, port=443)]
        r = build_provenance(correlate(acc, n, best_match=True), n)[0]
        assert r.inferred is True
        assert "inferred" in r.statement()

    def test_item_type_map_covers_contract_enum(self):
        for dt in ("browser_credentials", "keystrokes", "screenshot",
                   "clipboard", "crypto_wallet", "system_info", "file_access"):
            assert dt in ITEM_TYPE


# ---- broad coverage: every item type, every protocol, edges ----------------

import pytest


@pytest.mark.parametrize("data_type,expected_item", [
    ("browser_credentials", "credential"),
    ("keystrokes", "keystroke_log"),
    ("screenshot", "screenshot"),
    ("clipboard", "clipboard_data"),
    ("crypto_wallet", "crypto_wallet"),
    ("system_info", "system_info"),
    ("file_access", "file"),
])
def test_every_item_type_classified(data_type, expected_item):
    acc = [gen.access(data_type, "Api", 1.0)]
    n = [gen.net("198.51.100.7", 4.0)]
    r = build_provenance(correlate(acc, n, best_match=True), n)[0]
    assert r.item_type == expected_item
    assert r.data_type_accessed == data_type


@pytest.mark.parametrize("kind,port,plaintext,proto", [
    ("exfil", 21, True, "FTP/HTTP"),
    ("smtp_exfil", 25, True, "SMTP"),
    ("cloud_exfil", 443, False, "HTTPS (cloud)"),
    ("dns_tunnel", 53, True, "DNS"),
    ("http_c2", 80, True, "HTTP"),
    ("ja3", 443, False, "TLS"),
    ("icmp_tunnel", 0, False, "ICMP"),
])
def test_every_protocol_labelled(kind, port, plaintext, proto):
    acc = [gen.access("browser_credentials", "CryptUnprotectData", 1.0)]
    n = [gen.net("198.51.100.7", 4.0, kind=kind, port=port, plaintext=plaintext)]
    r = build_provenance(correlate(acc, n, best_match=True), n)[0]
    assert r.exfil_protocol == proto


@pytest.mark.parametrize("plaintext,inferred", [(True, False), (False, True)])
def test_inference_flag_tracks_plaintext(plaintext, inferred):
    acc = [gen.access("browser_credentials", "CryptUnprotectData", 1.0)]
    n = [gen.net("198.51.100.7", 4.0, plaintext=plaintext)]
    r = build_provenance(correlate(acc, n, best_match=True), n)[0]
    assert r.inferred is inferred


class TestProvenanceNegatives:
    def test_access_without_exfil_no_provenance(self):
        """Data accessed on host but nothing exfiltrated in-window → no record."""
        acc = [gen.access("browser_credentials", "CryptUnprotectData", 1.0)]
        assert build_provenance(correlate(acc, [], best_match=True), []) == []

    def test_exfil_before_access_no_provenance(self):
        acc = [gen.access("browser_credentials", "CryptUnprotectData", 10.0)]
        n = [gen.net("198.51.100.7", 3.0)]           # exfil BEFORE access
        assert build_provenance(correlate(acc, n, best_match=True), n) == []

    def test_out_of_window_no_provenance(self):
        acc = [gen.access("browser_credentials", "CryptUnprotectData", 1.0)]
        n = [gen.net("198.51.100.7", 30.0)]          # +29s, outside 15s window
        assert build_provenance(correlate(acc, n, best_match=True), n) == []


class TestWindowBoundary:
    def test_at_window_edge_correlates(self):
        acc = [gen.access("browser_credentials", "CryptUnprotectData", 1.0)]
        n = [gen.net("198.51.100.7", 16.0)]          # exactly +15s
        assert len(correlate(acc, n, best_match=True)) == 1

    def test_just_outside_window_does_not(self):
        acc = [gen.access("browser_credentials", "CryptUnprotectData", 1.0)]
        n = [gen.net("198.51.100.7", 16.5)]          # +15.5s
        assert correlate(acc, n, best_match=True) == []


class TestFullStealer:
    def test_multi_item_multi_channel(self):
        """A realistic stealer: 6 data types over FTP/SMTP/cloud/HTTP → a
        provenance record per stolen item, with the right protocol each."""
        acc, n = gen.full_stealer()
        prov = build_provenance(correlate(acc, n, best_match=True), n)
        assert len(prov) == 6                         # one per accessed item
        items = {r.item_type for r in prov}
        assert {"credential", "crypto_wallet", "keystroke_log", "screenshot",
                "system_info", "otp"} <= items
        protos = {r.exfil_protocol for r in prov}
        # each item resolved to its true channel — four distinct protocols
        assert {"FTP/HTTP", "SMTP", "HTTPS (cloud)", "HTTP"} <= protos

    def test_each_record_has_a_statement(self):
        acc, n = gen.full_stealer()
        prov = build_provenance(correlate(acc, n, best_match=True), n)
        for r in prov:
            s = r.statement()
            dest = r.destination_domain or r.destination_ip
            assert r.item_type in s and dest in s and "over" in s

    def test_wallet_over_ftp_confirmed(self):
        acc, n = gen.full_stealer()
        prov = build_provenance(correlate(acc, n, best_match=True), n)
        w = [r for r in prov if r.item_type == "crypto_wallet"][0]
        assert w.exfil_protocol == "FTP/HTTP" and w.confidence_tier == "confirmed"

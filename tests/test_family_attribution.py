"""
test_family_attribution.py — F3 family/campaign attribution.
"""
import sys, os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "pipeline"))

from pipeline.family_attribution import attribute_family, _match_families


def _ev(kind, **extra):
    e = {"kind": kind, "dst_ip": "1.2.3.4", "reputation_hit": False}
    e.update(extra)
    return e


class TestSources:
    def test_static_family_is_confirmed(self):
        v = attribute_family([], static_family="Lumma Stealer")
        assert v and v[0].family == "Lumma Stealer"
        assert v[0].confidence == "confirmed" and v[0].basis == "static_prior"

    def test_threat_intel_note_is_likely(self):
        ev = [_ev("exfil", reputation_note="Redline Stealer C2 (reference sample)")]
        v = attribute_family(ev)
        assert any(x.family == "RedLine Stealer" and x.confidence == "likely"
                   and x.basis == "threat_intel" for x in v)

    def test_static_match_note_used(self):
        ev = [_ev("exfil", static_match="matches static-extracted C2 (GuLoader)")]
        v = attribute_family(ev)
        assert any(x.family == "GuLoader" for x in v)


class TestBehavioural:
    def test_dns_tunnel_dnscat(self):
        v = attribute_family([_ev("dns_tunnel", destination_domain="x.evil")])
        assert any(x.family == "dnscat2" and x.confidence == "possible" for x in v)

    def test_http_gate_plus_beacon_cobalt_strike(self):
        v = attribute_family([_ev("http_c2"), _ev("beacon")])
        assert any(x.family == "Cobalt Strike" and x.confidence == "possible" for x in v)

    def test_smtp_agenttesla(self):
        v = attribute_family([_ev("smtp_exfil", smtp_subject="Pc Name: dave")])
        assert any(x.family == "AgentTesla" for x in v)

    def test_benign_no_family(self):
        assert attribute_family([_ev("unclassified_egress")]) == []


class TestRankingAndDedup:
    def test_confirmed_beats_behavioural_same_family(self):
        """Static-prior AgentTesla + behavioural AgentTesla → one entry, confirmed."""
        v = attribute_family([_ev("smtp_exfil")], static_family="AgentTesla")
        at = [x for x in v if x.family == "AgentTesla"]
        assert len(at) == 1 and at[0].confidence == "confirmed"

    def test_ranked_highest_first(self):
        ev = [_ev("dns_tunnel"),  # possible dnscat2
              _ev("exfil", reputation_note="Lumma Stealer C2")]  # likely Lumma
        v = attribute_family(ev)
        assert v[0].confidence == "likely"     # likely ranks above possible


class TestKeywords:
    def test_match(self):
        assert "Cobalt Strike" in _match_families("Cobalt Strike 4.x beacon")
        assert "AgentTesla" in _match_families("agent tesla keylogger")
        assert _match_families("perfectly normal traffic") == set()

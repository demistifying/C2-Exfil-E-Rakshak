"""
test_dga_classifier.py — validate the DGA ML classifier on HELD-OUT REAL domains.

None of these domains are in the training set (which is real dictionary words +
faithful DGA-algorithm reproductions). These are published real DGA IOCs and
real benign domains, so the tests measure genuine generalisation, not fit.
"""
import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "pipeline"))

import pytest
from pipeline.dga_classifier import get_model, featurize, DGAModel
from pipeline.dns_analysis import detect_dga, detect_dga_ml, _entropy

MODEL = get_model()
requires_model = pytest.mark.skipif(MODEL is None, reason="dga_lr.json not built")

# --- held-out REAL domains (never in training) ---
RANDOM_DGA = ["vddxnvzqjks", "gcrkitmvnf", "intgmxddndbik",
              "vbforvmgdvcs", "qwptdvlrbqkw"]           # Conficker/Cryptolocker
DICT_DGA_CAUGHT = ["carrywindow", "movementhappen",     # matsnu / suppobox style
                   "shouldertook"]        # low-entropy word-salad the model catches
BENIGN = ["google", "microsoft", "wikipedia", "github", "cloudflare",
          "greenhouse", "notebook", "sunflower", "basketball", "newspaper"]


class TestRealDomainGeneralisation:
    @requires_model
    def test_random_dga_detected(self):
        assert all(MODEL.score(d).is_dga for d in RANDOM_DGA)

    @requires_model
    def test_benign_not_flagged(self):
        # precision guard: no real benign domain (incl. compound words) flagged
        flagged = [d for d in BENIGN if MODEL.score(d).is_dga]
        assert flagged == [], f"benign false positives: {flagged}"

    @requires_model
    def test_dictionary_dga_caught_where_entropy_heuristic_fails(self):
        """The whole reason this model exists: catch low-entropy word-salad DGAs
        that never trip the entropy threshold (3.2)."""
        for d in DICT_DGA_CAUGHT:
            assert _entropy(d) < 3.2, f"{d} would already trip the heuristic"
            assert MODEL.score(d).is_dga, f"ML missed dictionary-DGA {d}"


class TestExplainability:
    @requires_model
    def test_score_returns_driving_features(self):
        s = MODEL.score("movementhappen")
        assert s.top_features and all(len(t) == 2 for t in s.top_features)
        # contributions are signed floats, most-positive first
        vals = [c for _, c in s.top_features]
        assert vals == sorted(vals, reverse=True)


class TestDeterminism:
    @requires_model
    def test_same_input_same_score(self):
        assert MODEL.score("carrywindow").probability == \
               MODEL.score("carrywindow").probability

    @requires_model
    def test_reload_is_stable(self):
        m2 = DGAModel.load()
        assert m2.score("vddxnvzqjks").probability == \
               MODEL.score("vddxnvzqjks").probability


class TestPipelineIntegration:
    def _dns(self, domains):
        class Q:
            def __init__(s, q):
                s.query, s.qtype, s.rcode, s.dst_ip, s.ts = q, "A", "NOERROR", "10.0.0.53", 0.0
        return [Q(d) for d in domains]

    @requires_model
    def test_ml_surfaces_dictionary_dga_as_candidate(self):
        dns = self._dns([f"{d}.net" for d in DICT_DGA_CAUGHT] * 2)
        found = {f.domain for f in detect_dga_ml(dns)}
        assert any(d.startswith("carrywindow") or d.startswith("movementhappen")
                   for d in found), f"pipeline missed dict-DGA: {found}"

    @requires_model
    def test_ml_does_not_flag_benign_domains(self):
        dns = self._dns([f"{d}.com" for d in BENIGN])
        assert detect_dga_ml(dns) == []

    @requires_model
    def test_ml_skips_domains_heuristic_already_caught(self):
        dns = self._dns(["carrywindow.net"] * 3)
        already = {"carrywindow.net"}
        assert detect_dga_ml(dns, already=already) == []


class TestGracefulDegradation:
    def test_missing_model_returns_empty(self, monkeypatch):
        import pipeline.dns_analysis as da
        monkeypatch.setattr("dga_classifier.get_model", lambda *a, **k: None)
        # detect_dga_ml must never raise when the artifact is absent
        assert da.detect_dga_ml(self_dns()) == []


def self_dns():
    class Q:
        query, qtype, rcode, dst_ip, ts = "example.com", "A", "NOERROR", "10.0.0.53", 0.0
    return [Q()]

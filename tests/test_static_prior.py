"""
test_static_prior.py — static IOC prior ingestion + static<->network correlation.
"""
import sys, os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "pipeline"))

import pytest
from pipeline.static_prior import (ingest_prior, load_static_prior,
                                   correlate_static_prior, StaticIndicator,
                                   StaticPrior)


class TestIngest:
    def test_valid_prior(self):
        raw = {"family": "RedLine", "capabilities": ["T1555.003"],
               "c2_indicators": [{"type": "ip", "value": "1.2.3.4"},
                                 {"type": "domain", "value": "evil.example"}]}
        r = ingest_prior(raw)
        assert r.ok and len(r.prior.indicators) == 2
        assert r.prior.family == "RedLine"

    def test_invalid_type_rejected(self):
        r = ingest_prior({"c2_indicators": [{"type": "banana", "value": "x"}]})
        assert not r.ok and len(r.prior.indicators) == 0

    def test_missing_fields_rejected(self):
        r = ingest_prior({"c2_indicators": [{"type": "ip"}]})
        assert not r.ok

    def test_strict_raises(self):
        with pytest.raises(ValueError):
            ingest_prior({"c2_indicators": [{"type": "bad", "value": "x"}]}, strict=True)

    def test_missing_file(self):
        assert not load_static_prior("data/nope.json").ok


class TestMatchKeys:
    def test_url_to_host(self):
        assert "evil.example" in StaticIndicator("url", "http://evil.example/gate.php").match_keys()

    def test_url_bare_ip(self):
        assert "1.2.3.4" in StaticIndicator("url", "ftp://1.2.3.4/up/").match_keys()

    def test_email_to_domain(self):
        keys = StaticIndicator("email", "drop@evil.example").match_keys()
        assert "evil.example" in keys

    def test_ip(self):
        assert StaticIndicator("ip", "1.2.3.4").match_keys() == {"1.2.3.4"}


class TestCorrelate:
    def _net(self):
        return [{"dst_ip": "93.89.225.40", "destination_domain": None, "kind": "exfil"},
                {"dst_ip": "1.1.1.1", "destination_domain": "cdn.example", "kind": "beacon"}]

    def test_observed_ip(self):
        prior = StaticPrior(indicators=[StaticIndicator("ip", "93.89.225.40")])
        c = correlate_static_prior(prior, self._net())
        assert c[0].observed and "93.89.225.40" in c[0].matched_dst

    def test_observed_via_url_host(self):
        prior = StaticPrior(indicators=[StaticIndicator("url", "http://cdn.example/x")])
        c = correlate_static_prior(prior, self._net())
        assert c[0].observed

    def test_dormant_indicator(self):
        prior = StaticPrior(indicators=[StaticIndicator("domain", "never-seen.example")])
        c = correlate_static_prior(prior, self._net())
        assert not c[0].observed and c[0].matched_dst == []

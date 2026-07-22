"""
test_correlation.py — host-access ↔ network-exfil correlation tests.

Tests the module's core novel value: linking WHAT the malware accessed on the
host to WHERE it sent data on the network, using temporal proximity.

Covers:
  * In-window match (access event → network event within 15s)
  * Out-of-window miss (network event > 15s after access)
  * Negative delta miss (network event BEFORE access — impossible for exfil)
  * Confidence tier assignment (confirmed / strong / weak / unconfirmed)
"""
import sys, os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "pipeline"))

from pipeline.correlation import correlate, CorrelatedEvent, _tier


class TestInWindowCorrelation:
    def test_match_within_window(self, sample_access_events, sample_network_events):
        """Access event 5s before network event → should correlate."""
        results = correlate(sample_access_events, sample_network_events, window_s=15)
        # At least the first access event should match the first network event
        # (5s delta, within 15s window)
        matched = [r for r in results if r.destination_ip == "198.51.100.44"]
        assert len(matched) >= 1
        m = matched[0]
        assert m.time_delta_s == 5.0
        assert m.correlation_confidence > 0

    def test_correlation_carries_data_type(self, sample_access_events, sample_network_events):
        """Correlated event carries the data_type from the access event."""
        results = correlate(sample_access_events, sample_network_events, window_s=15)
        matched = [r for r in results if r.destination_ip == "198.51.100.44"]
        data_types = {m.data_type_accessed for m in matched}
        assert "browser_credentials" in data_types


class TestOutOfWindowCorrelation:
    def test_no_match_outside_window(self, sample_access_events, sample_network_events):
        """Network event 75s after access → outside 15s window → no match."""
        results = correlate(sample_access_events, sample_network_events, window_s=15)
        outside = [r for r in results if r.destination_ip == "198.51.100.55"]
        assert len(outside) == 0

    def test_custom_window_expands_matches(self, sample_access_events, sample_network_events):
        """Expanding window to 120s → the previously-excluded event now matches."""
        results = correlate(sample_access_events, sample_network_events, window_s=120)
        outside = [r for r in results if r.destination_ip == "198.51.100.55"]
        assert len(outside) >= 1


class TestNegativeDelta:
    def test_network_before_access_not_correlated(self):
        """Network event BEFORE access event → negative delta → skip."""
        access = [{"timestamp": "2024-10-23T19:16:00+00:00",
                    "data_type": "browser_credentials",
                    "api_call": "CryptUnprotectData"}]
        network = [{"timestamp": "2024-10-23T19:15:50+00:00",  # 10s BEFORE
                     "dst_ip": "198.51.100.88", "dst_port": 80,
                     "confidence": 0.9, "reputation_hit": True}]
        results = correlate(access, network, window_s=15)
        assert len(results) == 0


class TestConfidenceTiers:
    def test_tier_confirmed(self):
        """Reputation hit + high confidence → confirmed."""
        assert _tier(0.8, reputation_hit=True, has_timing=True) == "confirmed"

    def test_tier_strong(self):
        """High confidence, no reputation → strong."""
        assert _tier(0.7, reputation_hit=False, has_timing=True) == "strong"

    def test_tier_weak(self):
        """Low confidence → weak (valid terminal state)."""
        assert _tier(0.3, reputation_hit=False, has_timing=True) == "weak"

    def test_tier_unconfirmed(self):
        """No timing, no reputation → unconfirmed."""
        assert _tier(0.3, reputation_hit=False, has_timing=False) == "unconfirmed"

    def test_confirmed_requires_both(self):
        """Reputation hit alone with low confidence → still NOT confirmed."""
        assert _tier(0.3, reputation_hit=True, has_timing=True) != "confirmed"

    def test_confirmed_minimum_threshold(self):
        """Exactly at 0.6 threshold with reputation → confirmed."""
        assert _tier(0.6, reputation_hit=True, has_timing=True) == "confirmed"

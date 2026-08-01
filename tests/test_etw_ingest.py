"""
test_etw_ingest.py — ETW ingestion, validation, clock-sync, and the
ingestion→correlation handoff.

This is the cross-module integration surface with the Windows ST/DT sandbox,
so it is tested from both sides: malformed input must be rejected clearly, and
valid input must flow through correlation carrying its ATT&CK technique.
"""
import sys, os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "pipeline"))

import pytest
from pipeline.etw_ingest import (
    parse_event, ingest, load_etw_events, assess_clock_sync,
    ETWValidationError, ETWAccessEvent, DATA_TYPE_TECHNIQUE, VALID_DATA_TYPES,
)
from pipeline.correlation import correlate


def _evt(ts="2026-02-03T16:13:59+00:00", data_type="browser_credentials",
         api_call="CryptUnprotectData", process="stealer.exe"):
    return {"timestamp": ts, "data_type": data_type,
            "api_call": api_call, "process": process}


# ===== Valid ingestion =====================================================

class TestValidIngestion:
    def test_parse_single_event(self):
        ev = parse_event(_evt())
        assert isinstance(ev, ETWAccessEvent)
        assert ev.data_type == "browser_credentials"
        assert ev.mitre_technique == "T1555.003"
        assert ev.capability == "Credentials from Web Browsers"
        assert ev.timestamp.tzinfo is not None

    def test_all_enum_types_map_to_a_technique(self):
        for dt in VALID_DATA_TYPES:
            ev = parse_event(_evt(data_type=dt))
            assert ev.mitre_technique == DATA_TYPE_TECHNIQUE[dt][0]

    def test_ingest_sorts_by_timestamp(self):
        raw = [
            _evt(ts="2026-02-03T16:13:59+00:00"),
            _evt(ts="2026-02-03T16:13:50+00:00"),
            _evt(ts="2026-02-03T16:13:55+00:00"),
        ]
        report = ingest(raw)
        assert report.ok
        ts = [e.timestamp for e in report.events]
        assert ts == sorted(ts)

    def test_fixture_file_loads(self):
        report = load_etw_events("data/access_events_fixture.json")
        assert report.ok
        assert len(report.events) == 3

    def test_optional_process_absent(self):
        raw = _evt()
        del raw["process"]
        ev = parse_event(raw)
        assert ev.process is None


# ===== Validation failures =================================================

class TestValidationFailures:
    def test_missing_required_field(self):
        raw = _evt(); del raw["api_call"]
        with pytest.raises(ETWValidationError):
            parse_event(raw)

    def test_invalid_data_type(self):
        with pytest.raises(ETWValidationError):
            parse_event(_evt(data_type="mind_reading"))

    def test_timestamp_without_timezone_rejected(self):
        """UTC offset is required — naive local time is ambiguous for sync."""
        with pytest.raises(ETWValidationError):
            parse_event(_evt(ts="2026-02-03T16:13:59"))

    def test_unparseable_timestamp(self):
        with pytest.raises(ETWValidationError):
            parse_event(_evt(ts="last tuesday"))

    def test_non_strict_skips_bad_events(self):
        raw = [_evt(), _evt(data_type="bogus"), _evt()]
        report = ingest(raw, strict=False)
        assert len(report.events) == 2
        assert len(report.errors) == 1
        assert not report.ok

    def test_strict_raises_on_first_bad(self):
        raw = [_evt(), _evt(data_type="bogus")]
        with pytest.raises(ETWValidationError):
            ingest(raw, strict=True)

    def test_top_level_must_be_array(self):
        report = ingest({"not": "a list"})
        assert not report.ok

    def test_missing_file(self):
        report = load_etw_events("data/does_not_exist.json")
        assert not report.ok


# ===== Clock-sync assessment ===============================================

class TestClockSync:
    def test_aligned_clocks_are_correlatable(self):
        events = ingest([_evt(ts="2026-02-03T16:13:59+00:00")]).events
        net = [{"timestamp": "2026-02-03T16:14:03+00:00", "dst_ip": "5.6.7.8"}]
        sync = assess_clock_sync(events, net)
        assert sync.correlatable is True
        assert sync.likely_skew is False

    def test_skewed_clocks_flagged(self):
        events = ingest([_evt(ts="2026-02-03T16:13:59+00:00")]).events
        net = [{"timestamp": "2026-02-03T17:13:59+00:00", "dst_ip": "5.6.7.8"}]  # +1h
        sync = assess_clock_sync(events, net)
        assert sync.correlatable is False
        assert sync.likely_skew is True

    def test_network_only_before_access_not_skew(self):
        events = ingest([_evt(ts="2026-02-03T16:13:59+00:00")]).events
        net = [{"timestamp": "2026-02-03T16:10:00+00:00", "dst_ip": "5.6.7.8"}]
        sync = assess_clock_sync(events, net)
        assert sync.correlatable is False
        assert sync.likely_skew is False   # no forward pair → not a skew signal


# ===== Ingestion → correlation handoff =====================================

class TestIngestionToCorrelation:
    def test_validated_events_correlate_and_carry_technique(self):
        events = ingest([_evt(ts="2026-02-03T16:13:59+00:00",
                              data_type="keystrokes",
                              api_call="SetWindowsHookEx")]).events
        net = [{"timestamp": "2026-02-03T16:14:01+00:00", "dst_ip": "162.241.123.75",
                "dst_port": 21, "confidence": 0.8, "reputation_hit": False}]
        results = correlate(events, net, window_s=15)
        assert len(results) == 1
        r = results[0]
        assert r.data_type_accessed == "keystrokes"
        assert r.mitre_technique_id == "T1056.001"
        assert r.destination_ip == "162.241.123.75"

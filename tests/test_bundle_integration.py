"""
test_bundle_integration.py — the four ST/DT bundle integration gaps.

Covers contract fields that were present in the WinST/DT handoff manifest but
not consumed on this side:

  1. correlation.access_events_path  — locate access events from the manifest
  2. behavior/clock-sync.json        — consume the RESIDUAL UNCERTAINTY only
  3. capabilities.dynamic.tls_interception — branch the encrypted-traffic path
  4. sample.meta.json                — independent static corroboration

Plus the correlation veto (host_network_correlation_enabled=false), which lets
the sandbox disown timing claims its own preconditions could not support.

On (2): ST/DT ALREADY normalises access-event timestamps onto the host clock.
Verified against the real task-18 bundle — the guest ran ~3603.7s (about an
hour) behind the host, yet its access_events already align with the PCAP to
within seconds. Applying guest_minus_host_ns ourselves would move correct
timestamps by an hour and silently zero out every correlation, so we take only
the residual uncertainty (~502ms) and VERIFY the alignment rather than
re-deriving it.
"""
import os
import sys
import json
from datetime import datetime, timezone, timedelta

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "pipeline"))

import pytest
from pipeline.handoff import (load_handoff, verify_clock_alignment,
                              correlation_window_slack_s, gate_network_events)
from pipeline.sample_meta import (SampleMeta, ingest_sample_meta,
                                  load_sample_meta, load_from_handoff,
                                  promote_with_static_corroboration)


# --------------------------------------------------------------------------
# bundle builder
# --------------------------------------------------------------------------

def _manifest(**over):
    m = {
        "schema_version": "1.0",
        "session_id": "11",
        "status": "completed",
        "errors": [],
        "sample_sha256": "a" * 64,
        "submitted_at_utc": "2026-08-05T10:13:00+00:00",
        "detonation_start_utc": "2026-08-05T10:14:00+00:00",
        "detonation_end_utc": "2026-08-05T10:19:00+00:00",
        "guest_vm_identity": {"image_version": "v1", "vm_uuid": "u", "guest_ip": "10.66.0.101"},
        "network_mode": "simulated_inetsim",
        "static_risk_score": 7.5,
        "static_hypotheses": ["packed", "suspicious_imports:CryptUnprotectData"],
        "cape_task_id": 11,
        "capemon_enabled": True,
        "correlation": {
            "access_events_path": "behavior/access_events.json",
            "event_count": 3,
            "clock_quality_acceptable": True,
            "host_network_correlation_enabled": True,
            "reason": None,
        },
        "telemetry": {"telemetry_degraded": False, "providers_unavailable": []},
        "integrity": {"hash_manifest_sha256": "b" * 64},
        "artifact_paths": {
            "pcap": "network/capture.pcapng",
            "trace_etl": "behavior/trace.etl",
            "clock_sync": "behavior/clock-sync.json",
            "access_events": "behavior/access_events.json",
        },
    }
    m.update(over)
    return m


def _bundle(tmp_path, manifest=None, clock=None, sample_meta=None):
    """Write a minimal on-disk handoff bundle; return the manifest path."""
    (tmp_path / "behavior").mkdir(exist_ok=True)
    (tmp_path / "network").mkdir(exist_ok=True)
    mpath = tmp_path / "manifest.json"
    mpath.write_text(json.dumps(manifest or _manifest()))
    (tmp_path / "behavior" / "access_events.json").write_text("[]")
    if clock is not None:
        (tmp_path / "behavior" / "clock-sync.json").write_text(json.dumps(clock))
    if sample_meta is not None:
        (tmp_path / "sample.meta.json").write_text(json.dumps(sample_meta))
    return str(mpath)


# --------------------------------------------------------------------------
# 1. access_events_path resolution
# --------------------------------------------------------------------------

class TestAccessEventsPath:
    def test_resolved_from_correlation_block(self, tmp_path):
        h = load_handoff(_bundle(tmp_path))
        assert h.access_events_path == str(tmp_path / "behavior" / "access_events.json")
        assert os.path.exists(h.access_events_path)
        assert h.access_event_count == 3

    def test_falls_back_to_contract_default_when_absent(self, tmp_path):
        m = _manifest(correlation={"event_count": 0,
                                   "clock_quality_acceptable": True,
                                   "host_network_correlation_enabled": True,
                                   "reason": None})
        del m["artifact_paths"]["access_events"]
        h = load_handoff(_bundle(tmp_path, manifest=m))
        assert h.access_events_path.endswith(os.path.join("behavior", "access_events.json"))

    def test_pcap_and_sample_meta_paths_resolved(self, tmp_path):
        h = load_handoff(_bundle(tmp_path))
        assert h.pcap_path.endswith(os.path.join("network", "capture.pcapng"))
        assert h.sample_meta_path.endswith("sample.meta.json")

    def test_correlation_veto_is_honoured(self, tmp_path):
        m = _manifest(correlation={
            "access_events_path": "behavior/access_events.json",
            "event_count": 3, "clock_quality_acceptable": False,
            "host_network_correlation_enabled": False,
            "reason": "clock offset exceeded tolerance"})
        h = load_handoff(_bundle(tmp_path, manifest=m))
        assert h.host_network_correlation_enabled is False
        assert h.correlation_reason == "clock offset exceeded tolerance"

    def test_missing_field_defaults_to_enabled(self, tmp_path):
        m = _manifest(correlation={"event_count": 1,
                                   "clock_quality_acceptable": True,
                                   "reason": None})
        h = load_handoff(_bundle(tmp_path, manifest=m))
        assert h.host_network_correlation_enabled is True


# --------------------------------------------------------------------------
# 2. clock-sync.json — consume the UNCERTAINTY, never the offset
# --------------------------------------------------------------------------

class TestClockQuality:
    """ST/DT pre-normalises access-event timestamps onto the HOST clock.

    Verified against the real task-18 bundle: the guest ran ~3603.7s (about an
    hour) behind the host, yet access_events (16:51:10-17:00:19) already align
    with the PCAP (16:51:00-17:00:17). correlation.clock_algorithm records what
    ST/DT DID; it is not an instruction to us. We therefore take the residual
    uncertainty only — applying the offset again would move correct timestamps
    by an hour and silently zero out every correlation.
    """

    REAL = {
        "schema_version": "1.0",
        "algorithm": "http_date_midpoint_linear_interpolation",
        "measurements": {
            "start": {"guest_minus_host_ns": -3603710896854,
                      "uncertainty_ns": 501224518},
            "end": {"guest_minus_host_ns": -3603876647036,
                    "uncertainty_ns": 501908965},
        },
        "quality": {"acceptable": True,
                    "maximum_observed_uncertainty_ns": 501908965},
    }

    def test_real_shape_uncertainty_parsed(self, tmp_path):
        h = load_handoff(_bundle(tmp_path, clock=self.REAL))
        assert round(h.clock_uncertainty_ms, 1) == 501.9
        assert h.clock_quality_reported is True

    def test_no_appliable_offset_is_exposed(self, tmp_path):
        """Regression guard: an hour-sized offset sits in the file. If it ever
        leaks into an appliable attribute, correlation breaks silently."""
        h = load_handoff(_bundle(tmp_path, clock=self.REAL))
        assert not [a for a in dir(h) if "offset" in a]

    def test_uncertainty_widens_correlation_window(self, tmp_path):
        h = load_handoff(_bundle(tmp_path, clock=self.REAL))
        assert round(correlation_window_slack_s(h), 3) == 0.502
        assert correlation_window_slack_s(None) == 0.0

    def test_algorithm_falls_back_to_clock_sync_file(self, tmp_path):
        h = load_handoff(_bundle(tmp_path, clock=self.REAL))
        assert h.clock_algorithm == "http_date_midpoint_linear_interpolation"

    def test_manifest_algorithm_takes_precedence(self, tmp_path):
        """The real bundle states the algorithm in correlation.clock_algorithm;
        that is the authoritative record of what ST/DT applied."""
        m = _manifest(correlation={
            "access_events_path": "behavior/access_events.json",
            "event_count": 3,
            "clock_algorithm": "linear_start_end_interpolation",
            "maximum_uncertainty_ns": 501908965,
            "host_network_correlation_enabled": True,
            "reason_code": None})
        h = load_handoff(_bundle(tmp_path, manifest=m, clock=self.REAL))
        assert h.clock_algorithm == "linear_start_end_interpolation"

    def test_falls_back_to_worst_measurement(self, tmp_path):
        doc = {"algorithm": "x", "measurements": {
            "start": {"uncertainty_ns": 200_000_000},
            "end": {"uncertainty_ns": 900_000_000}}}
        h = load_handoff(_bundle(tmp_path, clock=doc))
        assert round(h.clock_uncertainty_ms) == 900

    def test_absent_file(self, tmp_path):
        h = load_handoff(_bundle(tmp_path))
        assert h.clock_uncertainty_ms == 0.0 and h.clock_quality_reported is None

    def test_malformed_file_degrades(self, tmp_path):
        p = _bundle(tmp_path)
        (tmp_path / "behavior" / "clock-sync.json").write_text("{not json")
        assert load_handoff(p).clock_uncertainty_ms == 0.0


class TestClockAlignmentGuard:
    """Verify ST/DT actually pre-corrected — but never auto-correct, because a
    wrong guess is worse than a flagged mismatch."""

    def _ev(self, iso):
        return {"timestamp": datetime.fromisoformat(iso)}

    def test_aligned_timelines_no_warning(self, tmp_path):
        h = load_handoff(_bundle(tmp_path))
        acc = [self._ev("2026-08-05T16:51:10+00:00"), self._ev("2026-08-05T17:00:19+00:00")]
        net = [self._ev("2026-08-05T16:51:00+00:00"), self._ev("2026-08-05T17:00:17+00:00")]
        assert verify_clock_alignment(acc, net, h) is None

    def test_hour_offset_flagged_not_corrected(self, tmp_path):
        h = load_handoff(_bundle(tmp_path))
        acc = [self._ev("2026-08-05T15:51:10+00:00")]      # raw guest time
        net = [self._ev("2026-08-05T16:51:00+00:00")]
        before = acc[0]["timestamp"]
        note = verify_clock_alignment(acc, net, h)
        assert note and "CLOCK ALIGNMENT SUSPECT" in note and "NOT auto-corrected" in note
        assert acc[0]["timestamp"] == before               # untouched

    def test_string_timestamps_supported(self, tmp_path):
        h = load_handoff(_bundle(tmp_path))
        assert verify_clock_alignment(
            [{"timestamp": "2026-08-05T15:51:10+00:00"}],
            [{"timestamp": "2026-08-05T16:51:00+00:00"}], h) is not None

    def test_empty_inputs_noop(self, tmp_path):
        h = load_handoff(_bundle(tmp_path))
        assert verify_clock_alignment([], [{"timestamp": 1.0}], h) is None
        assert verify_clock_alignment([{"timestamp": 1.0}], [], h) is None


# --------------------------------------------------------------------------
# 3. tls_interception
# --------------------------------------------------------------------------

def _with_tls(status):
    return _manifest(capabilities={"dynamic": {"tls_interception": {"status": status}}})


class TestTlsInterception:
    def test_pinning_suspected_detected(self, tmp_path):
        h = load_handoff(_bundle(tmp_path, manifest=_with_tls("certificate_pinning_suspected")))
        assert h.tls_pinning_suspected and not h.tls_plaintext_available

    def test_intercepted_means_plaintext(self, tmp_path):
        h = load_handoff(_bundle(tmp_path, manifest=_with_tls("intercepted")))
        assert h.tls_plaintext_available and not h.tls_pinning_suspected

    def test_no_tls_observed_is_neither(self, tmp_path):
        h = load_handoff(_bundle(tmp_path, manifest=_with_tls("no_tls_observed")))
        assert not h.tls_pinning_suspected and not h.tls_plaintext_available

    def test_absent_capabilities_block_is_safe(self, tmp_path):
        h = load_handoff(_bundle(tmp_path))
        assert h.tls_interception_status is None
        assert not h.tls_pinning_suspected

    def test_pinning_marks_events_plaintext_unavailable_and_notes(self, tmp_path):
        h = load_handoff(_bundle(tmp_path, manifest=_with_tls("certificate_pinning_suspected")))
        events = [{"kind": "beacon", "confidence_tier": "strong"}]
        notes = gate_network_events(events, h)
        assert events[0]["plaintext_available"] is False
        assert any("TLS NOT INTERCEPTED" in n for n in notes)
        assert any("metadata-only" in n for n in notes)

    def test_interception_noted_as_plaintext_supported(self, tmp_path):
        h = load_handoff(_bundle(tmp_path, manifest=_with_tls("intercepted")))
        notes = gate_network_events([{"kind": "exfil"}], h)
        assert any("TLS INTERCEPTED" in n for n in notes)


# --------------------------------------------------------------------------
# 4. sample.meta.json
# --------------------------------------------------------------------------

_META = {
    "schema_version": "1.0",
    "sample_sha256": "a" * 64,
    "sample_md5": "b" * 32,
    "sample_sha1": "c" * 40,
    "file_type": "PE32 executable",
    "static_risk_score": 8.0,
    "static_hypotheses": ["packed", "suspicious_imports:CryptUnprotectData"],
    "yara": {"fast_hits": ["generic_packer"], "deep_hits": ["RedLine_Stealer_config"]},
    "clamav": {"status": "infected", "signature": "Win.Trojan.RedLine-9876543-0"},
    "vt_lookup": "54/72",
}


class TestSampleMeta:
    def test_fields_ingested(self):
        m = ingest_sample_meta(_META)
        assert m.ok
        assert m.sample_sha256 == "a" * 64
        assert m.static_risk_score == 8.0
        assert m.yara_deep_hits == ["RedLine_Stealer_config"]
        assert m.clamav_signature.startswith("Win.Trojan.RedLine")

    def test_family_inferred_from_yara(self):
        assert ingest_sample_meta(_META).family == "RedLine Stealer"

    def test_family_none_when_unrecognised(self):
        m = ingest_sample_meta({**_META, "yara": {"fast_hits": [], "deep_hits": []},
                                "clamav": {"status": "clean", "signature": None}})
        assert m.family is None

    def test_corroborating_signals_collected(self):
        sig = ingest_sample_meta(_META).corroborating_signals()
        assert any("yara_deep" in s for s in sig)
        assert any("clamav" in s for s in sig)
        assert any("virustotal" in s for s in sig)

    @pytest.mark.parametrize("vt,expected", [
        ("54/72", True), ("0/72", False), ("not_configured", False),
        ("unavailable", False), (None, False), ("", False),
    ])
    def test_vt_detection_parsing(self, vt, expected):
        assert ingest_sample_meta({**_META, "vt_lookup": vt}).vt_detected is expected

    def test_clean_sample_is_not_flagged(self):
        m = ingest_sample_meta({**_META,
                                "yara": {"fast_hits": [], "deep_hits": []},
                                "clamav": {"status": "clean", "signature": None},
                                "vt_lookup": "0/72"})
        assert not m.independently_flagged

    def test_risk_score_alone_is_not_corroboration(self):
        """static_risk_score/hypotheses are heuristics from the same binary
        inspection — treating them as independent would inflate tiers."""
        m = ingest_sample_meta({**_META,
                                "yara": {"fast_hits": [], "deep_hits": []},
                                "clamav": {"status": "clean", "signature": None},
                                "vt_lookup": "not_configured"})
        assert m.static_risk_score == 8.0
        assert m.static_hypotheses
        assert not m.independently_flagged

    def test_capability_techniques_mapped(self):
        t = ingest_sample_meta(_META).capability_techniques()
        assert "T1555.003" in t and "T1027.002" in t

    def test_malformed_types_recorded_not_raised(self):
        m = ingest_sample_meta({**_META, "yara": "nope", "static_hypotheses": "nope"})
        assert not m.ok and len(m.errors) == 2

    def test_missing_file_is_error_not_exception(self, tmp_path):
        m = load_sample_meta(str(tmp_path / "nope.json"))
        assert not m.ok and "file not found" in m.errors[0]

    def test_loads_from_handoff_bundle(self, tmp_path):
        h = load_handoff(_bundle(tmp_path, sample_meta=_META))
        m = load_from_handoff(h)
        assert m.ok and m.family == "RedLine Stealer"


class TestArgParsing:
    """Regression: a flag must never be bound as a positional path."""

    def test_handoff_flag_not_read_as_access_events(self):
        from pipeline.orchestrator import parse_args
        a = parse_args(["x.pcap", "--handoff", "m.json"])
        assert a["pcap"] == "x.pcap"
        assert a["acc_path_explicit"] is None      # was "--handoff" before the fix
        assert a["handoff_path"] == "m.json"

    def test_explicit_access_events_still_positional(self):
        from pipeline.orchestrator import parse_args
        a = parse_args(["x.pcap", "acc.json", "--handoff", "m.json"])
        assert a["acc_path_explicit"] == "acc.json"
        assert a["handoff_path"] == "m.json"

    def test_flag_values_not_treated_as_positionals(self):
        from pipeline.orchestrator import parse_args
        a = parse_args(["x.pcap", "--zeek-dir", "out/zeek",
                        "--static-prior", "p.json", "--handoff", "m.json"])
        assert a["pcap"] == "x.pcap"
        assert a["acc_path_explicit"] is None
        assert a["zeek_dir"] == "out/zeek"
        assert a["static_prior_path"] == "p.json"

    def test_defaults_when_no_args(self):
        from pipeline.orchestrator import parse_args
        a = parse_args([])
        assert a["pcap"].endswith("sample_infostealer.pcap")
        assert a["acc_path_explicit"] is None and a["handoff_path"] is None

    def test_flags_before_positionals(self):
        from pipeline.orchestrator import parse_args
        a = parse_args(["--handoff", "m.json", "x.pcap"])
        assert a["pcap"] == "x.pcap" and a["handoff_path"] == "m.json"


class TestStaticPromotion:
    def _ev(self, tier, **kw):
        return {"confidence_tier": tier, "destination_ip": "198.51.100.44", **kw}

    def test_strong_promoted_to_confirmed(self):
        ev = [self._ev("strong")]
        notes = promote_with_static_corroboration(ev, ingest_sample_meta(_META))
        assert ev[0]["confidence_tier"] == "confirmed"
        assert ev[0]["static_corroboration"]
        assert any("promoted strong -> confirmed" in n for n in notes)

    def test_weak_is_not_promoted(self):
        """A weak finding is weak because its own behavioural evidence is thin.
        An unrelated static hit does not repair that."""
        ev = [self._ev("weak")]
        promote_with_static_corroboration(ev, ingest_sample_meta(_META))
        assert ev[0]["confidence_tier"] == "weak"

    def test_capped_finding_is_not_promoted(self):
        ev = [self._ev("strong", capped_by_caveat="clock_unreliable")]
        promote_with_static_corroboration(ev, ingest_sample_meta(_META))
        assert ev[0]["confidence_tier"] == "strong"

    def test_confirmed_unchanged(self):
        ev = [self._ev("confirmed")]
        assert promote_with_static_corroboration(ev, ingest_sample_meta(_META)) == []
        assert ev[0]["confidence_tier"] == "confirmed"

    def test_clean_sample_promotes_nothing(self):
        clean = ingest_sample_meta({**_META,
                                    "yara": {"fast_hits": [], "deep_hits": []},
                                    "clamav": {"status": "clean", "signature": None},
                                    "vt_lookup": "0/72"})
        ev = [self._ev("strong")]
        assert promote_with_static_corroboration(ev, clean) == []
        assert ev[0]["confidence_tier"] == "strong"

    def test_none_meta_is_noop(self):
        ev = [self._ev("strong")]
        assert promote_with_static_corroboration(ev, None) == []
        assert ev[0]["confidence_tier"] == "strong"
class TestNetworkModeVocabularies:
    """Three producers spell the same axis three different ways.

    WinST/DT emits `live_egress`, UMAT's API takes `isolated_simulated` /
    `real_world_egress`, and this module used to match only `simulated_inetsim`.
    An unmatched value fell through to "not simulated", silently dropping the
    absence-is-not-proof caveat.
    """

    def test_every_known_spelling_is_classified(self):
        from handoff import _normalise_network_mode
        for value in ("simulated_inetsim", "isolated_simulated", "SIMULATED",
                      "no_egress", "offline"):
            assert _normalise_network_mode(value) == "simulated", value
        for value in ("live_egress", "real_world_egress", "controlled_egress",
                      "real-egress"):
            assert _normalise_network_mode(value) == "real", value

    def test_unknown_mode_is_neither_simulated_nor_real(self):
        """The dangerous default. An unrecognised value must not imply real
        egress, because that would present an absence of exfil as meaningful."""
        from handoff import _normalise_network_mode
        for value in ("something_new", "", None):
            assert _normalise_network_mode(value) == "unknown", value

    def test_live_egress_from_the_real_bundle_is_recognised(self):
        """The AgentTesla run carried network_mode='live_egress' — a value this
        module had never seen until it appeared in production."""
        from handoff import _normalise_network_mode
        assert _normalise_network_mode("live_egress") == "real"


class TestAccessedObjectReachesTheReport:
    """WinST/DT's rich-access-event patch supplies object_path/object_name.
    Before it, a report could say "file accessed via NtCreateFile" 171 times
    without naming a single file."""

    def test_object_path_is_ingested(self):
        from etw_ingest import parse_event
        ev = parse_event({
            "timestamp": "2026-08-11T17:30:49.346026Z",
            "data_type": "file_access", "api_call": "NtReadFile",
            "process": "sample.exe",
            "object_path": r"C:\Users\A\AppData\Local\Microsoft\Edge\User Data\Login Data",
            "object_name": "Login Data",
        })
        assert ev.object_path.endswith("Login Data")
        assert ev.object_label == ev.object_path
        assert ev.to_dict()["object_path"] == ev.object_path

    def test_bundles_without_the_patch_still_load(self):
        """Older bundles carry only the four original fields."""
        from etw_ingest import parse_event
        ev = parse_event({
            "timestamp": "2026-08-11T17:30:49.346026Z",
            "data_type": "file_access", "api_call": "NtReadFile",
            "process": "sample.exe",
        })
        assert ev.object_path is None and ev.object_label is None

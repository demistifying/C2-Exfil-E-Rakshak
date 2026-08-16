"""
test_resolved_destinations.py — C2 identification under a simulated network.

Under network_mode=simulated_inetsim every connection terminates at the INetSim
responder, so the destination IP is always the simulator and carries no
attribution. The malware's actual intended destination survives only as a DNS
query name.

The other DNS detectors look for ANOMALOUS names (algorithmic, tunnelled). Real
C2 is routinely an ordinary, legitimate-looking domain — abused webmail and
cloud services are the standard exfil channel for AgentTesla/Snake-Keylogger
style stealers — so anomaly detection alone never sees them.

Verified against the real RubyJumper capture, which resolved eight domains:
seven Microsoft/Windows telemetry endpoints and accounts.zoho.com. Before this
detector the module's only output on that sample was a false positive
(msftncsi.com flagged by the ML DGA classifier).
"""
import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "pipeline"))

import pytest

from pipeline.dns_analysis import detect_resolved_destinations, _is_os_background


class _Q:
    """Minimal DnsTransaction stand-in."""

    def __init__(self, query, ts=1000.0, dst_ip="10.66.0.1"):
        self.query = query
        self.ts = ts
        self.dst_ip = dst_ip
        self.answers = []
        self.rcode = 0


# The exact eight names RubyJumper resolved.
REAL_CAPTURE = [
    "config.edge.skype.com", "settings-win.data.microsoft.com",
    "slscr.update.microsoft.com", "msedge.api.cdp.microsoft.com",
    "v10.events.data.microsoft.com", "browser.pipe.aria.microsoft.com",
    "dns.msftncsi.com", "accounts.zoho.com",
]


def _findings(names, **kw):
    return detect_resolved_destinations([_Q(n) for n in names], **kw)


class TestRealCapture:
    def test_isolates_the_one_non_background_domain(self):
        """The whole point: separate the sample's destination from OS noise."""
        found = _findings(REAL_CAPTURE)
        candidates = [f.domain for f in found if f.confidence > 0]
        assert candidates == ["accounts.zoho.com"]

    def test_every_domain_is_still_reported(self):
        """Background traffic is down-tiered, never hidden — an analyst must be
        able to see everything the sample resolved."""
        found = _findings(REAL_CAPTURE)
        assert {f.domain for f in found} == set(REAL_CAPTURE)

    def test_microsoft_telemetry_is_background(self):
        for name in REAL_CAPTURE:
            if name != "accounts.zoho.com":
                assert _is_os_background(name), name

    def test_abused_service_is_not_background(self):
        assert not _is_os_background("accounts.zoho.com")


class TestAbusedServicesUnderBackgroundSuffixes:
    """A broad suffix allowlist is a recall hole.

    google.com, live.com and office.com are on the background list because that
    is what suppresses the OS telemetry flood. But Drive, Apps Script, OneDrive
    and Office mail are documented exfiltration channels sitting under exactly
    those suffixes, and were being scored 0.0 as expected OS traffic.

    It fails worst where the module matters most: under simulated_inetsim a DNS
    name is the only surviving evidence of intent, so staging to Google Drive
    produced no candidate at all.
    """

    ABUSED = ("drive.google.com", "docs.google.com", "script.google.com",
              "storage.googleapis.com", "onedrive.live.com",
              "outlook.office.com", "graph.microsoft.com")

    @pytest.mark.parametrize("host", ABUSED)
    def test_abused_service_survives_its_background_suffix(self, host):
        assert not _is_os_background(host), host

    @pytest.mark.parametrize("host", ABUSED)
    def test_abused_service_becomes_a_candidate(self, host):
        found = _findings([host])
        assert found and found[0].confidence > 0, host

    def test_genuine_os_noise_is_still_suppressed(self):
        """The exception must not reopen the flood it was protecting against."""
        for host in ("settings-win.data.microsoft.com", "v10.events.data.microsoft.com",
                     "ctldl.windowsupdate.com", "clients2.google.com",
                     "connectivitycheck.gstatic.com", "login.live.com"):
            assert _is_os_background(host), host

    def test_subdomains_of_an_abused_host_are_covered(self):
        assert not _is_os_background("myfolder.drive.google.com")


class TestCandidateSemantics:
    def test_resolution_is_a_candidate_not_a_verdict(self):
        """Same rule as beaconing: a lone signal never reaches strong/confirmed.
        Tiering is decided downstream by corroboration."""
        found = _findings(["evil.example"])
        assert found[0].confidence <= 0.5

    def test_evidence_states_intent_not_contact(self):
        found = _findings(["evil.example"])
        text = found[0].evidence.lower()
        assert "intended to contact" in text
        for overstated in ("sent data", "exfiltrated", "connected to"):
            assert overstated not in text

    def test_background_evidence_says_why(self):
        found = _findings(["settings-win.data.microsoft.com"])
        assert "background traffic" in found[0].evidence.lower()

    def test_query_counts_are_carried(self):
        found = _findings(["a.example", "a.example", "b.example"])
        counts = {f.domain: f.query_count for f in found}
        assert counts == {"a.example": 2, "b.example": 1}


class TestDeduplication:
    def test_domains_owned_by_a_more_specific_detector_are_skipped(self):
        """A tunnelling or DGA finding is stronger and already reported; this
        detector must not emit a duplicate weaker row for the same name."""
        found = _findings(REAL_CAPTURE, already={"accounts.zoho.com"})
        assert "accounts.zoho.com" not in {f.domain for f in found}

    def test_tunnel_subdomains_roll_up_to_the_claimed_parent(self):
        """A DNS tunnel carries its payload in the subdomain, so one tunnel
        produces thousands of unique names under a single parent. Claiming only
        the exact parent string let every encoded label through as its own
        candidate.

        Measured on the real dnscat2 capture: 6,906 rows emitted, 6,892 of them
        restating the one tunnel the tunnelling detector had already reported
        correctly at 'strong'. After rolling up: 16 rows, with the real finding
        visible instead of buried.
        """
        names = [f"{i:032x}.cisco-update.com" for i in range(50)]
        found = _findings(names, already={"cisco-update.com"})
        assert found == []

    def test_rollup_matches_any_parent_not_just_the_registered_domain(self):
        found = _findings(["a.b.tunnel.example.test"],
                          already={"tunnel.example.test"})
        assert found == []

    def test_rollup_does_not_suppress_an_unrelated_sibling(self):
        """Suppression must be scoped to the claimed parent — a different
        domain that merely shares a suffix must still be reported."""
        found = _findings(["evil.example", "x.cisco-update.com"],
                          already={"cisco-update.com"})
        assert [f.domain for f in found] == ["evil.example"]

    def test_site_allowlist_downgrades_to_background(self):
        found = _findings(["accounts.zoho.com"], allow_domains={"accounts.zoho.com"})
        assert found[0].confidence == 0.0

    def test_allowlist_matches_registered_domain(self):
        found = _findings(["mail.corp.example"], allow_domains={"corp.example"})
        assert found[0].confidence == 0.0


class TestRobustness:
    @pytest.mark.parametrize("bad", ["", None, "localhost", "   "])
    def test_unqualified_names_are_ignored(self, bad):
        assert _findings([bad]) == []

    def test_trailing_dot_and_case_are_normalised(self):
        found = _findings(["EVIL.Example.", "evil.example"])
        assert len(found) == 1 and found[0].query_count == 2

    def test_reverse_lookups_are_background(self):
        assert _is_os_background("1.0.66.10.in-addr.arpa")

    def test_empty_input(self):
        assert detect_resolved_destinations([]) == []

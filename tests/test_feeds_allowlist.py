"""
test_feeds_allowlist.py — F1 threat-intel feeds/domain reputation + F2 allowlist.
"""
import sys, os, json, sqlite3
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "pipeline"))

import pytest
from pipeline.attribution import domain_reputation, init_threatintel_db
from pipeline.feed_import import import_indicator_list, db_stats, import_ja4_known_bad
from pipeline.allowlist import is_allowlisted, apply_allowlist, load_allowlist


# ---------------- F1: feeds + domain reputation ----------------

class TestDomainReputation:
    def _db(self, tmp_path):
        db = str(tmp_path / "ti.sqlite")
        init_threatintel_db(path=db, seed=False)
        feed = str(tmp_path / "dga_domains.txt")
        open(feed, "w").write("# feed\nevil.example\nbad-c2.su\n")
        import_indicator_list(feed, "domain", "feed/dga", db)
        return db

    def test_exact_domain_hit(self, tmp_path):
        db = self._db(tmp_path)
        assert domain_reputation("evil.example", db)[0] is True

    def test_registered_domain_hit(self, tmp_path):
        """A known-bad registered domain matches an observed subdomain."""
        db = self._db(tmp_path)
        assert domain_reputation("sub.deep.evil.example", db)[0] is True

    def test_clean_domain_miss(self, tmp_path):
        db = self._db(tmp_path)
        assert domain_reputation("microsoft.com", db)[0] is False

    def test_feed_import_counts(self, tmp_path):
        db = self._db(tmp_path)
        assert db_stats(db).get("domain") == 2

    def test_ja4_import(self, tmp_path):
        db = str(tmp_path / "ti.sqlite"); init_threatintel_db(path=db, seed=False)
        import_ja4_known_bad(db)          # from KNOWN_BAD_JA4 (may be 0, must not error)
        assert isinstance(db_stats(db), dict)


# ---------------- F2: sanctioned-service allowlist ----------------

class TestAllowlistMatching:
    def test_sanctioned_domain(self):
        assert is_allowlisted("update.microsoft.com")[0] is True

    def test_sanctioned_subdomain(self):
        assert is_allowlisted("fe2.update.microsoft.com")[0] is True

    def test_exfil_channels_not_allowlisted(self):
        # the services malware abuses for exfil must NOT be suppressible
        assert is_allowlisted("api.telegram.org")[0] is False
        assert is_allowlisted("drive.google.com")[0] is False
        assert is_allowlisted("discord.com")[0] is False

    def test_unknown_not_allowlisted(self):
        assert is_allowlisted("evil.example")[0] is False

    def test_cidr_match_from_site_file(self, tmp_path):
        p = str(tmp_path / "allowlist.json")
        json.dump({"domains": [], "cidrs": ["198.51.100.0/24"]}, open(p, "w"))
        al = load_allowlist(p)
        assert is_allowlisted(ip="198.51.100.7", allowlist=al)[0] is True
        assert is_allowlisted(ip="203.0.113.7", allowlist=al)[0] is False


class TestAllowlistApplication:
    def test_weak_sanctioned_downtiered(self):
        ev = [{"kind": "unclassified_egress", "dst_ip": "20.1.2.3",
               "destination_domain": "settings-win.data.microsoft.com",
               "confidence_tier": "weak"}]
        assert apply_allowlist(ev) == 1
        assert ev[0]["confidence_tier"] == "allowlisted"
        assert ev[0]["allowlist_match"] == "settings-win.data.microsoft.com"

    def test_confirmed_never_downtiered(self):
        """Confirmed wins — even a sanctioned domain stays confirmed (anti-fronting)."""
        ev = [{"kind": "exfil", "dst_ip": "1.2.3.4",
               "destination_domain": "ctldl.windowsupdate.com",
               "confidence_tier": "confirmed"}]
        apply_allowlist(ev)
        assert ev[0]["confidence_tier"] == "confirmed"

    def test_strong_untouched(self):
        ev = [{"kind": "cloud_exfil", "dst_ip": "1.2.3.4",
               "destination_domain": "ocsp.digicert.com", "confidence_tier": "strong"}]
        apply_allowlist(ev)
        assert ev[0]["confidence_tier"] == "strong"

    def test_weak_unsanctioned_stays_weak(self):
        ev = [{"kind": "unclassified_egress", "dst_ip": "5.6.7.8",
               "destination_domain": "evil.example", "confidence_tier": "weak"}]
        apply_allowlist(ev)
        assert ev[0]["confidence_tier"] == "weak"

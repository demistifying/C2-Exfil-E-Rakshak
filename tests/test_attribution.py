"""
test_attribution.py — reputation lookup and graceful degradation tests.

Covers:
  * Known-bad IP → reputation hit with correct source
  * Clean IP → no hit
  * Missing DB file → graceful False, no crash
  * Missing GeoLite2 → returns None, no crash
"""
import sys, os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "pipeline"))

from pipeline.attribution import (
    attribute, init_threatintel_db, _reputation_lookup, Attribution,
)


class TestReputationHit:
    def test_known_bad_ip(self, tmp_threatintel_db):
        """Seeded known-bad IP → reputation_hit=True, source populated."""
        hit, source, note = _reputation_lookup("188.190.10.10", path=tmp_threatintel_db)
        assert hit is True
        assert source is not None
        assert "Redline" in note or "FeodoTracker" in source

    def test_second_seeded_ip(self, tmp_threatintel_db):
        """Second seeded IP (StealC) → also hits."""
        hit, source, note = _reputation_lookup("91.92.240.190", path=tmp_threatintel_db)
        assert hit is True


class TestReputationMiss:
    def test_clean_ip(self, tmp_threatintel_db):
        """Google's IP → no reputation hit."""
        hit, source, note = _reputation_lookup("142.250.190.78", path=tmp_threatintel_db)
        assert hit is False
        assert source is None
        assert note is None


class TestReputationGracefulDegradation:
    def test_missing_db_file(self, tmp_path):
        """If the DB file doesn't exist, return False — never crash."""
        hit, source, note = _reputation_lookup(
            "188.190.10.10", path=str(tmp_path / "nonexistent.sqlite"))
        assert hit is False

    def test_empty_db(self, tmp_path):
        """Empty DB (no seed) → no hits."""
        db = str(tmp_path / "empty.sqlite")
        init_threatintel_db(path=db, seed=False)
        hit, _, _ = _reputation_lookup("188.190.10.10", path=db)
        assert hit is False


class TestJA3Reputation:
    """The encrypted-traffic path: a known-bad JA3 fingerprint must raise a
    reputation hit even when the destination IP is not itself known-bad."""

    @staticmethod
    def _seed_ja3(db_path):
        import sqlite3
        init_threatintel_db(path=db_path, seed=True)
        conn = sqlite3.connect(db_path)
        conn.execute("ALTER TABLE bad_indicators ADD COLUMN indicator_type TEXT DEFAULT 'ip'")
        conn.execute(
            "INSERT OR REPLACE INTO bad_indicators (value, source, note, indicator_type) "
            "VALUES (?,?,?,?)",
            ("72a589da586844d7f0818ce684948eea", "known_bad_ja3",
             "Cobalt Strike default", "ja3"))
        conn.commit()
        conn.close()

    def test_bad_ja3_on_clean_ip_raises_hit(self, tmp_path, monkeypatch):
        db = str(tmp_path / "ja3.sqlite")
        self._seed_ja3(db)
        monkeypatch.setenv("THREATINTEL_DB", db)
        # 203.0.113.9 is NOT seeded as a bad IP, but the JA3 is known-bad.
        a = attribute("203.0.113.9", ja3_hash="72a589da586844d7f0818ce684948eea")
        assert a.reputation_hit is True
        assert "JA3" in (a.reputation_note or "")

    def test_unknown_ja3_does_not_raise_hit(self, tmp_path, monkeypatch):
        db = str(tmp_path / "ja3.sqlite")
        self._seed_ja3(db)
        monkeypatch.setenv("THREATINTEL_DB", db)
        a = attribute("203.0.113.9", ja3_hash="ffffffffffffffffffffffffffffffff")
        assert a.reputation_hit is False

    def test_ip_hit_takes_precedence_over_ja3(self, tmp_path, monkeypatch):
        db = str(tmp_path / "ja3.sqlite")
        self._seed_ja3(db)
        monkeypatch.setenv("THREATINTEL_DB", db)
        # Known-bad IP AND a clean JA3 → still a hit, source from the IP.
        a = attribute("188.190.10.10", ja3_hash="ffffffffffffffffffffffffffffffff")
        assert a.reputation_hit is True
        assert "JA3" not in (a.reputation_note or "")


class TestGeoGracefulDegradation:
    def test_attribute_without_geolite2(self, tmp_threatintel_db, monkeypatch):
        """Without GeoLite2 .mmdb files, geo fields should be None — not crash."""
        monkeypatch.setenv("GEOLITE2_CITY_DB", "nonexistent.mmdb")
        monkeypatch.setenv("GEOLITE2_ASN_DB", "nonexistent.mmdb")
        monkeypatch.setenv("THREATINTEL_DB", tmp_threatintel_db)
        a = attribute("188.190.10.10")
        assert isinstance(a, Attribution)
        assert a.geo_country is None
        assert a.asn is None
        assert a.reputation_hit is True   # reputation still works

"""
attribution.py — Windows C2/Exfiltration module, attribution stage.

Enriches a candidate destination (from beaconing/exfil detection) with:
  * GeoIP / ASN     — where is it, who owns the netblock  (MaxMind GeoLite2)
  * reputation      — is it a known-bad indicator          (local threat-intel DB)

DESIGN NOTE — offline operation:
Both lookups are designed to work fully offline, which is required for the
air-gapped operation objective:
  * GeoLite2 is a local .mmdb file, no network calls.
  * Reputation is a LOCAL SQLite table seeded from abuse.ch feeds (Feodo Tracker,
    URLhaus) downloaded once, out-of-band. In a connected deployment this table
    is periodically refreshed from a self-hosted MISP instance; the lookup
    interface does not change.

Graceful degradation: if the GeoLite2 db or reputation db is absent, attribution
returns 'unknown' rather than crashing — a missing enrichment source must never
take down the pipeline.
"""

from __future__ import annotations
from dataclasses import dataclass, asdict
import sqlite3
import os
import json


@dataclass
class Attribution:
    ip: str
    geo_country: str | None
    asn: str | None
    asn_org: str | None
    reputation_hit: bool
    reputation_source: str | None
    reputation_note: str | None


# ----- GeoIP / ASN ---------------------------------------------------------

_GEO_DB = os.environ.get("GEOLITE2_CITY_DB", "data/GeoLite2-City.mmdb")
_ASN_DB = os.environ.get("GEOLITE2_ASN_DB", "data/GeoLite2-ASN.mmdb")


def _geo_lookup(ip: str) -> tuple[str | None, str | None, str | None]:
    """Returns (country, asn, asn_org). Fully offline via GeoLite2 .mmdb."""
    country = asn = asn_org = None
    try:
        import geoip2.database  # type: ignore
        if os.path.exists(_GEO_DB):
            with geoip2.database.Reader(_GEO_DB) as r:
                country = r.city(ip).country.iso_code
        if os.path.exists(_ASN_DB):
            with geoip2.database.Reader(_ASN_DB) as r:
                resp = r.asn(ip)
                asn = f"AS{resp.autonomous_system_number}"
                asn_org = resp.autonomous_system_organization
    except Exception:
        pass  # graceful degradation — missing db or lib => unknown
    return country, asn, asn_org


# ----- Reputation (local threat-intel DB) ----------------------------------

_REP_DB = os.environ.get("THREATINTEL_DB", "data/threatintel.sqlite")


def init_threatintel_db(path: str = _REP_DB, seed: bool = True) -> None:
    """Create the local reputation DB. Seeded with a few known-bad IPs for
    the demo; in production this is populated from abuse.ch / MISP."""
    conn = sqlite3.connect(path)
    conn.execute("""CREATE TABLE IF NOT EXISTS bad_indicators (
        value TEXT PRIMARY KEY, source TEXT, note TEXT)""")
    if seed:
        # Known-bad IPs matching the reference infostealer captures.
        seeds = [
            ("188.190.10.10", "abuse.ch/FeodoTracker", "Redline Stealer C2 (reference sample)"),
            ("91.92.240.190", "abuse.ch/URLhaus", "StealC-V2 C2 (reference sample)"),
            ("153.92.1.49", "abuse.ch/FeodoTracker", "Lumma Stealer C2 (2026-01-31 exercise)"),
        ]
        conn.executemany(
            "INSERT OR IGNORE INTO bad_indicators (value, source, note) VALUES (?,?,?)", seeds)
    conn.commit()
    conn.close()


def _reputation_lookup(ip: str, path: str = _REP_DB) -> tuple[bool, str | None, str | None]:
    if not os.path.exists(path):
        return False, None, None
    try:
        conn = sqlite3.connect(path)
        row = conn.execute(
            "SELECT source, note FROM bad_indicators WHERE value = ?", (ip,)
        ).fetchone()
        conn.close()
        if row:
            return True, row[0], row[1]
    except Exception:
        pass
    return False, None, None


def attribute(ip: str, ja3_hash: str | None = None) -> Attribution:
    """Attribute a destination by IP and, when available, JA3 fingerprint.

    The JA3 lookup is the encrypted-traffic path: a TLS-only C2 whose IP is
    not yet known-bad can still be flagged if its ClientHello fingerprint
    matches a known-bad JA3 (Cobalt Strike, Metasploit, etc.) seeded via
    `feed_import.py ja3`. Either indicator producing a hit is sufficient —
    an IP hit takes precedence for the source/note, otherwise the JA3 hit
    supplies them.
    """
    # Resolve the DB path at call time so an overridden THREATINTEL_DB (env or
    # test monkeypatch set after import) is honoured, not the import-time value.
    db_path = os.environ.get("THREATINTEL_DB", _REP_DB)
    country, asn, asn_org = _geo_lookup(ip)
    hit, source, note = _reputation_lookup(ip, path=db_path)
    if not hit and ja3_hash:
        ja3_hit, ja3_source, ja3_note = _reputation_lookup(ja3_hash, path=db_path)
        if ja3_hit:
            hit = True
            source = ja3_source or "known_bad_ja3"
            note = f"JA3 match: {ja3_note}" if ja3_note else "known-bad JA3 fingerprint"
    return Attribution(
        ip=ip, geo_country=country, asn=asn, asn_org=asn_org,
        reputation_hit=hit, reputation_source=source, reputation_note=note)


if __name__ == "__main__":
    import sys
    init_threatintel_db()
    for ip in (sys.argv[1:] or ["188.190.10.10", "142.250.190.78"]):
        print(json.dumps(asdict(attribute(ip))))

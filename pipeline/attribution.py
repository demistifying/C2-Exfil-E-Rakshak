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

from datapaths import data_path, resolve as _resolve_data

_DEFAULT_GEO_DB = data_path("GeoLite2-City.mmdb")
_DEFAULT_ASN_DB = data_path("GeoLite2-ASN.mmdb")

# Module-level values are kept for backwards compatibility with anything that
# imports them, but the lookup resolves the environment at CALL time.
_GEO_DB = os.environ.get("GEOLITE2_CITY_DB", _DEFAULT_GEO_DB)
_ASN_DB = os.environ.get("GEOLITE2_ASN_DB", _DEFAULT_ASN_DB)


def _geo_db_paths() -> tuple[str, str]:
    """Resolve the GeoLite2 paths from the environment on every lookup.

    These were previously captured at import time, which made
    GEOLITE2_CITY_DB / GEOLITE2_ASN_DB documented overrides that silently did
    nothing — the module is imported long before any caller sets them. A
    deployment pointing at, say, /srv/winstdt/geoip/ would have been ignored and
    every finding would have shipped with no country and no ASN, with no error
    to explain why.

    It went unnoticed because the graceful-degradation test asserted geo was
    None while the default path happened not to exist, so it passed for the
    wrong reason and never exercised the override at all.
    """
    return (_resolve_data("GEOLITE2_CITY_DB", "GeoLite2-City.mmdb"),
            _resolve_data("GEOLITE2_ASN_DB", "GeoLite2-ASN.mmdb"))


def _geo_lookup(ip: str) -> tuple[str | None, str | None, str | None]:
    """Returns (country, asn, asn_org). Fully offline via GeoLite2 .mmdb."""
    country = asn = asn_org = None
    geo_db, asn_db = _geo_db_paths()
    try:
        import geoip2.database  # type: ignore
        if os.path.exists(geo_db):
            with geoip2.database.Reader(geo_db) as r:
                country = r.city(ip).country.iso_code
        if os.path.exists(asn_db):
            with geoip2.database.Reader(asn_db) as r:
                resp = r.asn(ip)
                asn = f"AS{resp.autonomous_system_number}"
                asn_org = resp.autonomous_system_organization
    except Exception:
        pass  # graceful degradation — missing db or lib => unknown
    return country, asn, asn_org


# ----- Reputation (local threat-intel DB) ----------------------------------

# Module-relative, NOT cwd-relative. Under UMAT the orchestrator runs with its
# working directory set to a per-run scratch workspace, where "data/..." does
# not exist — so the whole threat-intel database silently contributed nothing
# to every deployed run. See pipeline/datapaths.py.
_REP_DB = os.environ.get("THREATINTEL_DB") or data_path("threatintel.sqlite")


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


def attribute(ip: str, ja3_hash: str | None = None,
              ja4: str | None = None) -> Attribution:
    """Attribute a destination by IP and, when available, TLS fingerprint.

    The fingerprint lookup is the encrypted-traffic path: a TLS-only C2 whose IP
    is not yet known-bad can still be flagged if its ClientHello fingerprint
    matches a known-bad JA3 or JA4 (Cobalt Strike, Metasploit, stealer families)
    seeded via feeds. Any one indicator producing a hit is sufficient; an IP hit
    takes precedence for the source/note. JA4 is the modern, randomisation-robust
    fingerprint (JA3 is kept for back-compat).
    """
    # Resolve the DB path at call time so an overridden THREATINTEL_DB (env or
    # test monkeypatch set after import) is honoured, not the import-time value.
    db_path = os.environ.get("THREATINTEL_DB", _REP_DB)
    country, asn, asn_org = _geo_lookup(ip)
    hit, source, note = _reputation_lookup(ip, path=db_path)
    for label, fp in (("JA3", ja3_hash), ("JA4", ja4)):
        if hit or not fp:
            continue
        fp_hit, fp_source, fp_note = _reputation_lookup(fp, path=db_path)
        if fp_hit:
            hit = True
            source = fp_source or f"known_bad_{label.lower()}"
            note = f"{label} match: {fp_note}" if fp_note else f"known-bad {label} fingerprint"
    return Attribution(
        ip=ip, geo_country=country, asn=asn, asn_org=asn_org,
        reputation_hit=hit, reputation_source=source, reputation_note=note)


def _registered_domain(domain: str) -> str:
    labels = domain.lower().rstrip(".").split(".")
    return ".".join(labels[-2:]) if len(labels) >= 2 else domain.lower()


def domain_reputation(domain: str, path: str | None = None):
    """Reputation lookup for a DOMAIN indicator (from URLhaus/DGA feeds etc.).

    Checks the exact host and its registered domain, so a known-bad
    `evil.example` still matches an observed `sub.evil.example`. This is the path
    that promotes a DNS-tunnel / cloud / HTTP-gate finding — whose IOC is a
    domain, not an IP — to the confirmed tier once feeds are loaded.
    """
    if not domain:
        return False, None, None
    db = path or os.environ.get("THREATINTEL_DB", _REP_DB)
    for cand in (domain.lower().rstrip("."), _registered_domain(domain)):
        hit, source, note = _reputation_lookup(cand, path=db)
        if hit:
            return hit, source, note
    return False, None, None


if __name__ == "__main__":
    import sys
    init_threatintel_db()
    for ip in (sys.argv[1:] or ["188.190.10.10", "142.250.190.78"]):
        print(json.dumps(asdict(attribute(ip))))

"""
feed_import.py — import threat-intel from abuse.ch CSV feeds into the local DB.

Supports three feed formats:
  * ThreatFox C2 IOCs, indexed by malware family  <- the C2 feed
  * Feodo Tracker C2 IP blocklist (Emotet/Dridex/QakBot/TrickBot/BazarLoader)
  * URLhaus URL dump — payload DOWNLOAD locations, not C2

The distinction matters. Feodo covers five botnet families; URLhaus lists where
payloads are hosted. Neither indexes the C2 of a modern RAT, so a Remcos or
AsyncRAT destination matched nothing and could never be corroborated into
`confirmed`. ThreatFox is the feed that closes that gap, and because it is
indexed by family the reputation note carries real attribution — "Remcos C2"
rather than "malware_download".

Designed for OFFLINE use: download the CSVs once (or on a connected machine),
then run this importer air-gapped. The threat-intel DB schema and lookup
interface are identical regardless of how the data got in.

MISP upgrade path: replace this CSV import with a pymisp pull against a
self-hosted MISP instance. The DB schema doesn't change — MISP events would
just populate the same bad_indicators table with richer context.

Usage:
  # Import Feodo Tracker C2 IPs
  python pipeline/feed_import.py feodo data/feodotracker_ipblocklist.csv

  # Import URLhaus URLs
  python pipeline/feed_import.py urlhaus data/urlhaus_urls.csv

  # Seed JA3 hashes from the hardcoded known-bad list
  python pipeline/feed_import.py ja3
"""

from __future__ import annotations
import csv
import sqlite3
import os
import sys

sys.path.insert(0, os.path.dirname(__file__))

_REP_DB = os.environ.get("THREATINTEL_DB", "data/threatintel.sqlite")


def _ensure_schema(conn: sqlite3.Connection):
    """Ensure the extended threat-intel schema exists.

    Extends the original bad_indicators table with indicator_type and last_seen
    while remaining backward-compatible with the original schema.
    """
    conn.execute("""CREATE TABLE IF NOT EXISTS bad_indicators (
        value TEXT PRIMARY KEY,
        source TEXT,
        note TEXT,
        indicator_type TEXT DEFAULT 'ip',
        last_seen TEXT
    )""")
    # Add columns if they don't exist (upgrading from old schema)
    for col, defn in [("indicator_type", "TEXT DEFAULT 'ip'"),
                      ("last_seen", "TEXT")]:
        try:
            conn.execute(f"ALTER TABLE bad_indicators ADD COLUMN {col} {defn}")
        except sqlite3.OperationalError:
            pass  # column already exists


def import_feodo(csv_path: str, db_path: str = _REP_DB) -> int:
    """Import Feodo Tracker C2 IP blocklist.

    Format: CSV with columns like:
      # first_seen_utc,dst_ip,dst_port,c2_status,last_online,malware
    Lines starting with # are comments (except the header line).
    """
    if not os.path.exists(csv_path):
        print(f"[!] File not found: {csv_path}")
        return 0

    conn = sqlite3.connect(db_path)
    _ensure_schema(conn)
    count = 0

    with open(csv_path, encoding="utf-8", errors="replace") as f:
        for line in f:
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            parts = line.split(",")
            if len(parts) < 6:
                continue
            ip = parts[1].strip().strip('"')
            port = parts[2].strip().strip('"')
            malware = parts[5].strip().strip('"')
            first_seen = parts[0].strip().strip('"')

            # An uncommented header row would otherwise be stored as an
            # indicator literally named "dst_ip". Validating the value is an
            # address covers that and any other malformed line, without
            # depending on the header being marked with '#'.
            if not _is_ip_literal(ip):
                continue

            note = f"{malware} C2 (port {port})"
            conn.execute(
                "INSERT OR REPLACE INTO bad_indicators "
                "(value, source, note, indicator_type, last_seen) "
                "VALUES (?, ?, ?, ?, ?)",
                (ip, "abuse.ch/FeodoTracker", note, "ip", first_seen))
            count += 1

    conn.commit()
    conn.close()
    return count


# abuse.ch's own hosts appear in the URLhaus feed because every row carries a
# urlhaus_link back to the site. Importing them would flag the intelligence
# provider itself as a C2 — a false positive an officer would immediately, and
# rightly, distrust.
_FEED_SELF_REFERENCE = ("abuse.ch",)

# Shared hosting, CDNs and file-sharing services.
#
# URLhaus is a URL blocklist, not a domain blocklist. When an attacker uploads a
# payload to a legitimate service, the malicious indicator is the *URL* —
# https://raw.githubusercontent.com/<attacker>/<repo>/payload.exe — not the host.
# Reducing that to the host and storing it as a bad domain brands GitHub itself
# as malware infrastructure.
#
# This is not hypothetical. Before this filter the shipped snapshot contained
# github.com, raw.githubusercontent.com, drive.google.com, www.dropbox.com and
# seven others; a benign capture scored github.com as 'confirmed malicious' with
# the note "malware_download". In front of a review committee, one such finding
# discredits every other finding in the report.
#
# The list cannot ever be complete, which is the deeper reason URL-derived
# *domain* indicators are weak evidence. It removes the worst offenders; the
# corroboration rule is what actually keeps a lone indicator from becoming a
# verdict.
_SHARED_HOSTING = (
    "github.com", "githubusercontent.com", "github.io", "gitlab.com", "bitbucket.org",
    "sourceforge.net", "gitea.com", "codeberg.org",
    "google.com", "googleapis.com", "googleusercontent.com", "googledrive.com", "goo.gl",
    "dropbox.com", "dropboxusercontent.com", "onedrive.com", "onedrive.live.com",
    "sharepoint.com", "1drv.ms", "mediafire.com", "mega.nz", "box.com",
    "discord.com", "discordapp.com", "discordapp.net", "telegram.org", "t.me",
    "amazonaws.com", "cloudfront.net", "azureedge.net", "blob.core.windows.net",
    "r2.dev", "cloudflarestorage.com", "backblazeb2.com", "digitaloceanspaces.com",
    "herokuapp.com", "vercel.app", "vercel-storage.com", "netlify.app", "glitch.me",
    "firebaseapp.com", "firebasestorage.googleapis.com", "web.app", "pages.dev",
    "workers.dev", "repl.co", "replit.dev", "ngrok.io", "ngrok-free.app",
    "blogspot.com", "wordpress.com", "wixsite.com", "weebly.com", "webflow.io",
    "pastebin.com", "paste.ee", "ghostbin.com", "archive.org", "sites.google.com",
)


def _is_ip_literal(host: str) -> bool:
    """True when a URL host is a bare address rather than a name.

    URLhaus lists URLs, so roughly seven in eight of its hosts are raw IPs.
    Storing those as indicator_type='domain' means an IP lookup can never match
    them and the whole feed contributes nothing to reputation scoring.
    """
    import ipaddress
    try:
        ipaddress.ip_address(host)
        return True
    except ValueError:
        return False


def import_urlhaus(csv_path: str, db_path: str = _REP_DB) -> int:
    """Import URLhaus URL dump.

    Format: CSV with columns:
      # id,dateadded,url,url_status,last_online,threat,tags,urlhaus_link,...

    URLhaus is a URL feed, not an indicator feed, so three normalisations are
    applied here rather than being left to whoever prepares the snapshot. They
    used to be manual post-import cleaning steps recorded only in
    data/feeds/README.md, which meant a fresh clone running `refresh` rebuilt a
    subtly wrong database while believing it had reproduced the shipped one.
    """
    if not os.path.exists(csv_path):
        print(f"[!] File not found: {csv_path}")
        return 0

    conn = sqlite3.connect(db_path)
    _ensure_schema(conn)
    count = 0

    from urllib.parse import urlparse

    with open(csv_path, encoding="utf-8", errors="replace") as f:
        for line in f:
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            parts = line.split(",")
            if len(parts) < 7:
                continue
            url = parts[2].strip().strip('"')
            threat = parts[5].strip().strip('"')
            dateadded = parts[1].strip().strip('"')
            tags = parts[6].strip().strip('"')

            # (1) The converted feed keeps a bare header row. Left alone it is
            #     stored as an indicator literally named "url", which then
            #     matches nothing and inflates the indicator count.
            if parts[0].strip().strip('"').lower() in ("id", "#id") or url.lower() == "url":
                continue

            # Extract domain/IP from URL for lookup compatibility
            parsed = urlparse(url)
            host = (parsed.hostname or url).strip().rstrip(".").lower()
            if not host:
                continue

            # (2) Never flag the feed provider itself.
            if any(host == d or host.endswith("." + d) for d in _FEED_SELF_REFERENCE):
                continue

            # (3) Type the indicator by what it actually is, so IP lookups hit.
            indicator_type = "ip" if _is_ip_literal(host) else "domain"

            # (4) Never brand a shared host from a URL feed. A bare IP serving a
            #     payload is itself the distribution point and is kept; a name
            #     belonging to a hosting provider is not evidence about that
            #     provider. See _SHARED_HOSTING.
            if indicator_type == "domain" and any(
                    host == d or host.endswith("." + d) for d in _SHARED_HOSTING):
                continue

            note = f"{threat} ({tags})" if tags else threat
            conn.execute(
                "INSERT OR REPLACE INTO bad_indicators "
                "(value, source, note, indicator_type, last_seen) "
                "VALUES (?, ?, ?, ?, ?)",
                (host, "abuse.ch/URLhaus", note, indicator_type, dateadded))
            count += 1

    conn.commit()
    conn.close()
    return count


def import_threatfox(csv_path: str, db_path: str = _REP_DB) -> int:
    """Import abuse.ch ThreatFox — C2 infrastructure, indexed by family.

    This is the feed this module actually needs, and the one it was missing.
    Feodo Tracker covers only Emotet/Dridex/QakBot/TrickBot/BazarLoader (5 IPs in
    the shipped snapshot), and URLhaus lists payload-DOWNLOAD URLs, not C2. So a
    modern RAT — Remcos, AsyncRAT, AgentTesla, Lumma — matched nothing, and no
    finding against its C2 could be corroborated into `confirmed`.

    ThreatFox indexes live C2 by malware family, which also gives the reputation
    note real attribution value: "Remcos C2" rather than "malware_download".

    Format (CSV export):
      first_seen_utc, ioc_id, ioc_value, ioc_type, threat_type, fk_malware,
      malware_alias, malware_printable, last_seen_utc, confidence_level, ...

    `ioc_value` for an ip:port IOC is "203.0.113.9:2404"; the port is dropped and
    the address stored, because reputation is looked up per destination address.
    The port is preserved in the note, since a RAT on its configured port is a
    stronger match than the same host on 443.
    """
    if not os.path.exists(csv_path):
        print(f"[!] File not found: {csv_path}")
        return 0

    conn = sqlite3.connect(db_path)
    _ensure_schema(conn)
    count = 0

    with open(csv_path, encoding="utf-8", errors="replace") as f:
        for row in csv.reader(f):
            if not row or row[0].lstrip().startswith("#") or len(row) < 8:
                continue
            first_seen = row[0].strip().strip('" ')
            value = row[2].strip().strip('" ')
            ioc_type = row[3].strip().strip('" ').lower()
            family = (row[7].strip().strip('" ')
                      or row[5].strip().strip('" ') or "unknown")
            if not value or value.lower() == "ioc_value":
                continue

            port = None
            if ioc_type in ("ip:port", "ip_port") and ":" in value:
                value, _, port = value.rpartition(":")
                indicator_type = "ip"
            elif ioc_type in ("domain", "hostname"):
                indicator_type = "domain"
            elif _is_ip_literal(value):
                indicator_type = "ip"
            else:
                continue     # url / hash IOCs are out of scope for this table

            value = value.strip().rstrip(".").lower()
            if not value:
                continue
            # Same rule as URLhaus: never brand a shared host from a feed.
            if indicator_type == "domain" and any(
                    value == d or value.endswith("." + d)
                    for d in _SHARED_HOSTING + _FEED_SELF_REFERENCE):
                continue
            if indicator_type == "ip" and not _is_ip_literal(value):
                continue

            note = f"{family} C2" + (f" (port {port})" if port else "")
            conn.execute(
                "INSERT OR REPLACE INTO bad_indicators "
                "(value, source, note, indicator_type, last_seen) "
                "VALUES (?, ?, ?, ?, ?)",
                (value, "abuse.ch/ThreatFox", note, indicator_type, first_seen))
            count += 1

    conn.commit()
    conn.close()
    return count


def import_ja3_known_bad(db_path: str = _REP_DB) -> int:
    """Seed known-bad JA3 hashes into the threat-intel DB.

    These come from the hardcoded list in ja3_loader.py so they're available
    via the unified reputation lookup path.
    """
    from ja3_loader import KNOWN_BAD_JA3

    conn = sqlite3.connect(db_path)
    _ensure_schema(conn)
    count = 0

    for ja3_hash, description in KNOWN_BAD_JA3.items():
        conn.execute(
            "INSERT OR REPLACE INTO bad_indicators "
            "(value, source, note, indicator_type) "
            "VALUES (?, ?, ?, ?)",
            (ja3_hash, "known_bad_ja3", description, "ja3"))
        count += 1

    conn.commit()
    conn.close()
    return count


def import_ja4_known_bad(db_path: str = _REP_DB) -> int:
    """Seed known-bad JA4 fingerprints into the DB (modern JA3 successor).
    Extend `tls_analysis.KNOWN_BAD_JA4` or feed a JA4 blocklist via
    import_indicator_list(path, kind='ja4')."""
    from tls_analysis import KNOWN_BAD_JA4
    conn = sqlite3.connect(db_path)
    _ensure_schema(conn)
    n = 0
    for ja4, desc in KNOWN_BAD_JA4.items():
        conn.execute("INSERT OR REPLACE INTO bad_indicators "
                     "(value, source, note, indicator_type) VALUES (?,?,?,?)",
                     (ja4, "known_bad_ja4", desc, "ja4"))
        n += 1
    conn.commit(); conn.close()
    return n


def import_indicator_list(path: str, kind: str = "domain",
                          source: str = "custom", db_path: str = _REP_DB) -> int:
    """Import a plain one-indicator-per-line list (e.g. a DGA domain feed or a
    JA4 blocklist). '#' comment lines are ignored."""
    if not os.path.exists(path):
        print(f"[!] File not found: {path}")
        return 0
    conn = sqlite3.connect(db_path)
    _ensure_schema(conn)
    n = 0
    with open(path, encoding="utf-8", errors="replace") as f:
        for line in f:
            v = line.strip()
            if not v or v.startswith("#"):
                continue
            v = v.split(",")[0].strip().strip('"').lower()
            if not v:
                continue
            conn.execute("INSERT OR REPLACE INTO bad_indicators "
                         "(value, source, note, indicator_type) VALUES (?,?,?,?)",
                         (v, source, f"{kind} blocklist", kind))
            n += 1
    conn.commit(); conn.close()
    return n


def db_stats(db_path: str = _REP_DB) -> dict:
    """Counts per indicator type — for the report / freshness check."""
    if not os.path.exists(db_path):
        return {}
    conn = sqlite3.connect(db_path)
    _ensure_schema(conn)
    rows = conn.execute("SELECT indicator_type, COUNT(*) FROM bad_indicators "
                        "GROUP BY indicator_type").fetchall()
    conn.close()
    return {t or "ip": c for t, c in rows}


def refresh(directory: str, db_path: str = _REP_DB) -> dict:
    """Offline bulk refresh: import every recognised feed file in a directory.

    Filename conventions: feodo*.csv, urlhaus*.csv, *dga*.txt / *domains*.txt,
    *ja4*.txt. Download the feeds once on a connected machine, drop them here,
    and run this air-gapped. (MISP path: swap this for a pymisp pull into the
    same table.)
    """
    import glob
    total = {}
    for p in sorted(glob.glob(os.path.join(directory, "*"))):
        name = os.path.basename(p).lower()
        if name.startswith("threatfox"):
            total[name] = import_threatfox(p, db_path)
        elif name.startswith("feodo"):
            total[name] = import_feodo(p, db_path)
        elif name.startswith("urlhaus"):
            total[name] = import_urlhaus(p, db_path)
        elif "dga" in name or "domains" in name or "domain" in name:
            total[name] = import_indicator_list(p, "domain", "feed/dga", db_path)
        elif "ja4" in name:
            total[name] = import_indicator_list(p, "ja4", "feed/ja4", db_path)
        elif "ja3" in name:
            total[name] = import_indicator_list(p, "ja3", "feed/ja3", db_path)
    return total


if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage:")
        print("  python pipeline/feed_import.py feodo <csv>")
        print("  python pipeline/feed_import.py urlhaus <csv>")
        print("  python pipeline/feed_import.py threatfox <csv>")
        print("  python pipeline/feed_import.py domains <list.txt>")
        print("  python pipeline/feed_import.py ja3 | ja4")
        print("  python pipeline/feed_import.py refresh <feed_dir>")
        print("  python pipeline/feed_import.py stats")
        sys.exit(1)

    feed_type = sys.argv[1].lower()
    arg = sys.argv[2] if len(sys.argv) > 2 else None

    if feed_type == "feodo":
        print(f"[*] Imported {import_feodo(arg or 'data/feodotracker.csv')} Feodo C2 IPs")
    elif feed_type == "threatfox":
        print(f"[*] Imported {import_threatfox(arg or 'data/feeds/threatfox.csv')} ThreatFox C2 indicators")
    elif feed_type == "urlhaus":
        print(f"[*] Imported {import_urlhaus(arg or 'data/urlhaus.csv')} URLhaus indicators")
    elif feed_type == "domains":
        print(f"[*] Imported {import_indicator_list(arg, 'domain', 'custom')} domain indicators")
    elif feed_type == "ja3":
        print(f"[*] Imported {import_ja3_known_bad()} known-bad JA3 hashes")
    elif feed_type == "ja4":
        print(f"[*] Imported {import_ja4_known_bad()} known-bad JA4 fingerprints")
    elif feed_type == "refresh":
        res = refresh(arg or "data/feeds")
        print(f"[*] Refresh imported: {res}")
        print(f"[*] DB now holds: {db_stats()}")
    elif feed_type == "stats":
        print(f"[*] Threat-intel DB: {db_stats()}")
    else:
        print(f"[!] Unknown feed type: {feed_type}")
        sys.exit(1)

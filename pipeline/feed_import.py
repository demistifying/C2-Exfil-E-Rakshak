"""
feed_import.py — import threat-intel from abuse.ch CSV feeds into the local DB.

Supports two feed formats:
  * Feodo Tracker C2 IP blocklist (csv.gz from abuse.ch)
  * URLhaus URL dump (csv.gz from abuse.ch)

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


def import_urlhaus(csv_path: str, db_path: str = _REP_DB) -> int:
    """Import URLhaus URL dump.

    Format: CSV with columns:
      # id,dateadded,url,url_status,last_online,threat,tags,urlhaus_link,...
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
            if len(parts) < 7:
                continue
            url = parts[2].strip().strip('"')
            threat = parts[5].strip().strip('"')
            dateadded = parts[1].strip().strip('"')
            tags = parts[6].strip().strip('"')

            # Extract domain/IP from URL for lookup compatibility
            from urllib.parse import urlparse
            parsed = urlparse(url)
            host = parsed.hostname or url

            note = f"{threat} ({tags})" if tags else threat
            conn.execute(
                "INSERT OR REPLACE INTO bad_indicators "
                "(value, source, note, indicator_type, last_seen) "
                "VALUES (?, ?, ?, ?, ?)",
                (host, "abuse.ch/URLhaus", note, "domain", dateadded))
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
        if name.startswith("feodo"):
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
        print("  python pipeline/feed_import.py domains <list.txt>")
        print("  python pipeline/feed_import.py ja3 | ja4")
        print("  python pipeline/feed_import.py refresh <feed_dir>")
        print("  python pipeline/feed_import.py stats")
        sys.exit(1)

    feed_type = sys.argv[1].lower()
    arg = sys.argv[2] if len(sys.argv) > 2 else None

    if feed_type == "feodo":
        print(f"[*] Imported {import_feodo(arg or 'data/feodotracker.csv')} Feodo C2 IPs")
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

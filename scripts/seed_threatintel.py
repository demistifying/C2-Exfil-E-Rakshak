#!/usr/bin/env python3
"""
seed_threatintel.py — rebuild data/threatintel.sqlite from the shipped feeds.

Run once after cloning, before any analysis run:

    python scripts/seed_threatintel.py

Everything it needs is committed under data/feeds/, so this works air-gapped
and makes no network calls. That property is load-bearing: the module is meant
to run on an isolated forensics host, and an importer that quietly reached out
to abuse.ch mid-analysis would break the air-gap claim the design rests on.

Why this exists
---------------
data/threatintel.sqlite is gitignored (it is a build artifact, and committing a
binary that changes on every feed refresh makes every diff unreadable). Before
this script, a fresh clone therefore had only the three built-in demo seeds from
attribution.init_threatintel_db(), so every reputation and attribution finding
came back empty — on someone else's machine the module looked like it simply did
not work.

Idempotent: importers use INSERT OR REPLACE, so re-running refreshes in place.
Pass --rebuild to discard the existing database first.
"""
from __future__ import annotations

import argparse
import os
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)
sys.path.insert(0, os.path.join(ROOT, "pipeline"))

FEED_DIR = os.path.join(ROOT, "data", "feeds")
DB_PATH = os.environ.get("THREATINTEL_DB", os.path.join(ROOT, "data", "threatintel.sqlite"))

# The shipped snapshot is documented in data/feeds/README.md. This is a floor,
# not an exact figure: re-running against a newer abuse.ch download should still
# pass, while a broken parser (a feed format change, an empty download) drops
# well below it and fails loudly instead of leaving a near-empty database that
# silently produces no findings.
MIN_EXPECTED_INDICATORS = 500


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__,
                                     formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--rebuild", action="store_true",
                        help="delete the existing database before importing")
    parser.add_argument("--feed-dir", default=FEED_DIR,
                        help=f"directory of feed snapshots (default: {FEED_DIR})")
    args = parser.parse_args()

    # feed_import resolves _REP_DB at import time from this variable, and the
    # importers capture it as a default argument, so it must be set first.
    os.environ["THREATINTEL_DB"] = DB_PATH
    import feed_import  # noqa: E402  (import after THREATINTEL_DB is set)

    if args.rebuild and os.path.exists(DB_PATH):
        os.remove(DB_PATH)
        print(f"[*] Removed existing {os.path.relpath(DB_PATH, ROOT)}")

    if not os.path.isdir(args.feed_dir):
        print(f"[!] Feed directory missing: {args.feed_dir}", file=sys.stderr)
        return 1

    imported = feed_import.refresh(args.feed_dir, DB_PATH)
    for name, rows in sorted(imported.items()):
        print(f"[*] {name}: {rows} indicators")
    if not imported:
        print(f"[!] No feed files matched in {args.feed_dir}", file=sys.stderr)
        return 1

    # JA3/JA4 fingerprints are compiled into the module rather than downloaded,
    # so they are seeded separately from the file-based feeds.
    print(f"[*] known-bad JA3: {feed_import.import_ja3_known_bad(DB_PATH)}")
    print(f"[*] known-bad JA4: {feed_import.import_ja4_known_bad(DB_PATH)}")

    stats = feed_import.db_stats(DB_PATH)
    total = sum(stats.values())
    print(f"[*] Threat-intel DB: {stats}")

    if total < MIN_EXPECTED_INDICATORS:
        print(f"[!] Only {total} indicators (expected at least "
              f"{MIN_EXPECTED_INDICATORS}). The feed snapshots are probably "
              f"truncated or the feed format changed — reputation findings "
              f"would be silently empty.", file=sys.stderr)
        return 1

    print(f"[+] Seeded {total} indicators into {os.path.relpath(DB_PATH, ROOT)}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

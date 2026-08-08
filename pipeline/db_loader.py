"""
db_loader.py — load pipeline output into the shared PostgreSQL store.

Reads output/exfil_events.json and inserts into the shared schema. Uses
psycopg (v3). Connection params from env (DATABASE_URL) or sensible defaults
matching the docker-compose service.

Now populates ALL columns defined in sql/schema.sql including:
  asn, geo_country, ja3_hash, plaintext_available, destination_domain

Usage:  python pipeline/db_loader.py
"""
from __future__ import annotations
import os
import json
import sys


def get_conn():
    import psycopg
    dsn = os.environ.get(
        "DATABASE_URL",
        "postgresql://analyst:analyst@localhost:5432/malware")
    return psycopg.connect(dsn)


def load(events_path="output/exfil_events.json"):
    rows = json.load(open(events_path))
    if not rows:
        print("[!] No rows to load."); return
    sample_id = rows[0]["sample_id"]
    # Overall sample tier = highest tier present.
    # allowlisted ranks BELOW unconfirmed: a finding deliberately judged
    # benign must never become the sample-level verdict over a real one.
    order = {"confirmed": 3, "strong": 2, "weak": 1, "unconfirmed": 0,
             "allowlisted": -1}
    _DEF = -1
    tier = max((r["confidence_tier"] for r in rows), key=lambda t: order.get(t, _DEF))

    with get_conn() as conn, conn.cursor() as cur:
        cur.execute(
            "INSERT INTO samples (sample_id, platform, confidence_tier) "
            "VALUES (%s,%s,%s) ON CONFLICT (sample_id) DO UPDATE "
            "SET confidence_tier = EXCLUDED.confidence_tier",
            (sample_id, "windows", tier))
        for r in rows:
            cur.execute(
                """INSERT INTO exfil_events
                   (event_id, sample_id, session_id, cape_task_id, platform, timestamp,
                    data_type_accessed, access_api_call,
                    destination_ip, destination_port,
                    destination_domain, asn, asn_org, geo_country,
                    reputation_score, reputation_note, reputation_source,
                    ja3_hash, plaintext_available,
                    confidence_score, confidence_tier,
                    mitre_technique_id, manifest_sha256, evidence_hash,
                    case_id, finding_kind, plain_language, capped_by_caveat,
                    evidence_refs)
                   VALUES (%(event_id)s, %(sample_id)s, %(session_id)s, %(cape_task_id)s,
                    %(platform)s, %(timestamp)s,
                    %(data_type_accessed)s, %(access_api_call)s,
                    %(destination_ip)s, %(destination_port)s,
                    %(destination_domain)s, %(asn)s, %(asn_org)s, %(geo_country)s,
                    %(reputation_score)s, %(reputation_note)s, %(reputation_source)s,
                    %(ja3_hash)s, %(plaintext_available)s,
                    %(confidence_score)s, %(confidence_tier)s,
                    %(mitre_technique_id)s, %(manifest_sha256)s, %(evidence_hash)s,
                    %(case_id)s, %(finding_kind)s, %(plain_language)s,
                    %(capped_by_caveat)s, %(evidence_refs)s::jsonb)
                   ON CONFLICT (event_id) DO NOTHING""",
                {k: r.get(k) for k in (
                    "event_id", "sample_id", "session_id", "cape_task_id",
                    "platform", "timestamp",
                    "data_type_accessed", "access_api_call",
                    "destination_ip", "destination_port",
                    "destination_domain", "asn", "asn_org", "geo_country",
                    "reputation_score", "reputation_note", "reputation_source",
                    "ja3_hash", "plaintext_available",
                    "confidence_score", "confidence_tier",
                    "mitre_technique_id", "manifest_sha256", "evidence_hash",
                    "case_id", "finding_kind", "plain_language",
                    "capped_by_caveat")}
                | {"evidence_refs": json.dumps(r.get("evidence_refs") or [])})
        conn.commit()
    print(f"[*] Loaded sample {sample_id[:16]}... ({tier}) with {len(rows)} events")


if __name__ == "__main__":
    try:
        load(sys.argv[1] if len(sys.argv) > 1 else "output/exfil_events.json")
    except Exception as e:
        print(f"[!] DB load failed ({e}).")
        print("    Is the Postgres container up? docker compose up -d postgres")
        sys.exit(1)

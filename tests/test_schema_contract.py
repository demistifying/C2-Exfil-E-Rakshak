"""
test_schema_contract.py — guard the exfil_events output contract.

This is the test class that was MISSING and let attribution context (and,
earlier, destination_domain) be computed but silently dropped before the
output rows / DB. It keeps four surfaces in lockstep:

  1. emit_schema_rows() row keys
  2. sql/schema.sql  exfil_events columns
  3. db_loader.py    INSERT column list  (what actually reaches Postgres)
  4. the CSV IOC export (analyst/SIEM-facing feed)

If any producer computes a field the schema/loader/export drops, these fail.
"""
import os
import re
import sys
import json

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "pipeline"))

from pipeline.orchestrator import build_network_events, emit_schema_rows
from pipeline.attribution import init_threatintel_db
from pipeline.export_iocs import export_csv

ROOT = os.path.join(os.path.dirname(__file__), "..")
# A real reputation-hit sample so attribution fields are actually populated.
REDLINE = os.path.join(
    ROOT, "data",
    "2024-10-23-Redline-Stealer-infection-traffic.pcap",
    "2024-10-23-Redline-Stealer-infection-traffic.pcap")

# Fields intentionally not persisted to the shared schema (internal-only).
# Keep this explicit so anything NEW that falls out is caught, not assumed OK.
INTERNAL_ONLY = set()


def _schema_columns():
    sql = open(os.path.join(ROOT, "sql", "schema.sql")).read()
    body = re.search(
        r"CREATE TABLE IF NOT EXISTS exfil_events\s*\((.*?)\);", sql, re.S).group(1)
    cols = []
    for line in body.splitlines():
        line = line.strip()
        if not line or line.startswith("--"):
            continue
        tok = line.split()[0]
        if tok.upper() in ("PRIMARY", "FOREIGN", "CONSTRAINT", "UNIQUE", "CHECK"):
            continue
        cols.append(tok)
    return set(cols)


def _loader_insert_columns():
    src = open(os.path.join(ROOT, "pipeline", "db_loader.py")).read()
    body = re.search(r"INSERT INTO exfil_events\s*\((.*?)\)\s*VALUES", src, re.S).group(1)
    return {c.strip() for c in body.replace("\n", " ").split(",") if c.strip()}


def _rows():
    init_threatintel_db()
    net = build_network_events(REDLINE)
    return emit_schema_rows(net, [], sample_id="contract-test")


def test_sample_present():
    assert os.path.exists(REDLINE), "Redline sample missing — contract test needs it"


def test_rows_have_attribution_populated():
    """Regression guard for the exact bug: the note must reach the rows."""
    rows = _rows()
    assert rows, "no rows emitted"
    hit = [r for r in rows if r.get("reputation_note")]
    assert hit, "reputation_note reached no row — attribution dropped again"
    r = hit[0]
    assert "redline" in r["reputation_note"].lower()
    assert r["reputation_source"]
    assert r["confidence_tier"] == "confirmed"


def test_every_row_key_is_a_schema_column():
    schema = _schema_columns()
    rows = _rows()
    keys = set().union(*(set(r) for r in rows))
    dropped = keys - schema - INTERNAL_ONLY
    assert not dropped, f"row keys not in schema (silently dropped on DB write): {dropped}"


def test_loader_persists_every_schema_column():
    """The INSERT must cover every schema column (minus DB-defaulted ones)."""
    schema = _schema_columns()
    loader = _loader_insert_columns()
    missing = schema - loader
    assert not missing, f"schema columns the DB loader never inserts: {missing}"


def test_loader_columns_all_exist_in_schema():
    assert not (_loader_insert_columns() - _schema_columns()), \
        "db_loader inserts a column that isn't in schema.sql"


def test_attribution_reaches_csv_export(tmp_path):
    rows = _rows()
    out = str(tmp_path / "iocs.csv")
    export_csv(rows, out)
    text = open(out).read().lower()
    assert "reputation_note" in text, "CSV header missing attribution column"
    assert "redline" in text, "attribution reason absent from CSV IOC feed"


# --- domain-only IOC must survive to BOTH exports (regression: STIX dropped it,
#     CSV collapsed multiple onto an empty ("",port) key) ---

def _domain_only_rows():
    return [
        {"event_id": "e1", "sample_id": "s", "destination_ip": "",
         "destination_port": 0, "destination_domain": "validation.winstdt.test",
         "confidence_tier": "strong", "confidence_score": 0.8,
         "reputation_score": 0.0, "mitre_technique_id": "T1071",
         "timestamp": "2026-08-05T15:17:48Z", "evidence_hash": "h1"},
        {"event_id": "e2", "sample_id": "s", "destination_ip": "",
         "destination_port": 0, "destination_domain": "c2.example.test",
         "confidence_tier": "strong", "confidence_score": 0.8,
         "reputation_score": 0.0, "mitre_technique_id": "T1071",
         "timestamp": "2026-08-05T15:17:49Z", "evidence_hash": "h2"},
    ]


def test_domain_only_ioc_in_stix(tmp_path):
    from pipeline.export_iocs import export_stix
    out = str(tmp_path / "stix.json")
    n = export_stix(_domain_only_rows(), out)
    bundle = json.load(open(out))
    inds = [o for o in bundle["objects"] if o["type"] == "indicator"]
    # both domain IOCs must get their own domain-name indicator
    assert n == 2 and len(inds) == 2
    patterns = " ".join(i["pattern"] for i in inds)
    assert "domain-name:value = 'validation.winstdt.test'" in patterns
    assert "domain-name:value = 'c2.example.test'" in patterns


def test_domain_only_iocs_not_collapsed_in_csv(tmp_path):
    out = str(tmp_path / "iocs.csv")
    n = export_csv(_domain_only_rows(), out)
    text = open(out).read()
    assert n == 2, "domain-only IOCs collapsed onto one row"
    assert "validation.winstdt.test" in text and "c2.example.test" in text

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

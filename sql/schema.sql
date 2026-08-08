-- Shared cross-module schema. All modules (Windows ST/DT, Windows C2/Exfil,
-- Android) write here. This file is the single source of truth for the contract.

CREATE TABLE IF NOT EXISTS samples (
  sample_id        TEXT PRIMARY KEY,          -- sha256
  platform         TEXT NOT NULL,             -- 'windows' | 'android'
  submitted_at     TIMESTAMPTZ NOT NULL DEFAULT now(),
  confidence_tier  TEXT NOT NULL              -- confirmed|strong|weak|unconfirmed
);

CREATE TABLE IF NOT EXISTS static_iocs (
  id                SERIAL PRIMARY KEY,
  sample_id         TEXT REFERENCES samples(sample_id),
  ioc_type          TEXT,                      -- domain|ip|url|port
  value             TEXT,
  confidence_weight REAL,
  source            TEXT,                      -- family_decryptor|mobsf_manifest|yara
  case_id           UUID,                      -- per-run case (unified tool)
  first_seen_at     TIMESTAMPTZ,
  seen_in_traffic   BOOLEAN DEFAULT FALSE      -- static IOC also observed on the wire
);

CREATE TABLE IF NOT EXISTS exfil_events (
  event_id            TEXT PRIMARY KEY,        -- uuid
  sample_id           TEXT REFERENCES samples(sample_id),
  session_id          TEXT,                    -- WinST/DT handoff session (per-run join)
  cape_task_id        INTEGER,                 -- CAPE task id (per-run join)
  platform            TEXT NOT NULL,
  timestamp           TIMESTAMPTZ NOT NULL,
  data_type_accessed  TEXT,
  access_api_call     TEXT,
  destination_ip      TEXT,
  destination_port    INTEGER,
  destination_domain  TEXT,
  asn                 TEXT,
  asn_org             TEXT,                    -- ASN owner (attribution context)
  geo_country         TEXT,
  reputation_score    REAL,
  reputation_note     TEXT,                    -- e.g. 'RedLine Stealer C2 (feed: URLhaus)'
  reputation_source   TEXT,                    -- which feed/intel named it
  ja3_hash            TEXT,
  plaintext_available BOOLEAN,
  confidence_score    REAL,
  confidence_tier     TEXT,
  mitre_technique_id  TEXT,
  manifest_sha256     TEXT,                    -- ST/DT bundle hash (custody-chain link; first row)
  evidence_hash       TEXT,                    -- sha256 chained to prior row (seeded from manifest_sha256)
  -- --- unified-tool integration (schema 1.3) --------------------------------
  -- These live HERE, not in contract/schema_v2.sql, because
  -- tests/test_schema_contract.py parses this file to keep emit_schema_rows(),
  -- db_loader's INSERT and the CSV export in lockstep. A column defined
  -- elsewhere is invisible to that guard — which is exactly the silent-drop
  -- bug the guard exists to prevent.
  case_id             UUID,                    -- per-run case for the unified tool, NULL standalone
  finding_kind        TEXT,                    -- beacon|exfil|correlation|reputation|covert_channel|dns|static_ioc
  plain_language      TEXT,                    -- officer-facing one-liner
  capped_by_caveat    TEXT,                    -- caveat code that limited this tier, if any
  evidence_refs       JSONB DEFAULT '[]'::jsonb -- pointers to raw evidence (zeek uid, pkt window, access seq)
);

CREATE TABLE IF NOT EXISTS evidence_log (
  entry_id      TEXT PRIMARY KEY,
  sample_id     TEXT REFERENCES samples(sample_id),
  event_ref     TEXT,
  evidence_hash TEXT NOT NULL,
  timestamp     TIMESTAMPTZ NOT NULL DEFAULT now(),
  case_id       UUID                           -- per-run case (unified tool)
);

CREATE INDEX IF NOT EXISTS idx_exfil_sample ON exfil_events(sample_id);
CREATE INDEX IF NOT EXISTS idx_exfil_dstip  ON exfil_events(destination_ip);

-- ---------------------------------------------------------------------------
-- Idempotent upgrades for databases created before schema 1.3. CREATE TABLE
-- IF NOT EXISTS above is a no-op on an existing DB, so the same columns are
-- restated here as ALTERs. Safe to re-run.
-- ---------------------------------------------------------------------------
ALTER TABLE exfil_events ADD COLUMN IF NOT EXISTS case_id          UUID;
ALTER TABLE exfil_events ADD COLUMN IF NOT EXISTS finding_kind     TEXT;
ALTER TABLE exfil_events ADD COLUMN IF NOT EXISTS plain_language   TEXT;
ALTER TABLE exfil_events ADD COLUMN IF NOT EXISTS capped_by_caveat TEXT;
ALTER TABLE exfil_events ADD COLUMN IF NOT EXISTS evidence_refs    JSONB DEFAULT '[]'::jsonb;
ALTER TABLE static_iocs  ADD COLUMN IF NOT EXISTS case_id          UUID;
ALTER TABLE static_iocs  ADD COLUMN IF NOT EXISTS first_seen_at    TIMESTAMPTZ;
ALTER TABLE static_iocs  ADD COLUMN IF NOT EXISTS seen_in_traffic  BOOLEAN DEFAULT FALSE;
ALTER TABLE evidence_log ADD COLUMN IF NOT EXISTS case_id          UUID;

CREATE INDEX IF NOT EXISTS idx_exfil_case  ON exfil_events(case_id);
CREATE INDEX IF NOT EXISTS idx_static_case ON static_iocs(case_id);

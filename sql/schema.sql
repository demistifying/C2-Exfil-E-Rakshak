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
  source            TEXT
);

CREATE TABLE IF NOT EXISTS exfil_events (
  event_id            TEXT PRIMARY KEY,        -- uuid
  sample_id           TEXT REFERENCES samples(sample_id),
  platform            TEXT NOT NULL,
  timestamp           TIMESTAMPTZ NOT NULL,
  data_type_accessed  TEXT,
  access_api_call     TEXT,
  destination_ip      TEXT,
  destination_port    INTEGER,
  asn                 TEXT,
  geo_country         TEXT,
  reputation_score    REAL,
  ja3_hash            TEXT,
  plaintext_available BOOLEAN,
  confidence_score    REAL,
  confidence_tier     TEXT,
  mitre_technique_id  TEXT,
  evidence_hash       TEXT                     -- sha256 chained to prior row
);

CREATE TABLE IF NOT EXISTS evidence_log (
  entry_id      TEXT PRIMARY KEY,
  sample_id     TEXT REFERENCES samples(sample_id),
  event_ref     TEXT,
  evidence_hash TEXT NOT NULL,
  timestamp     TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS idx_exfil_sample ON exfil_events(sample_id);
CREATE INDEX IF NOT EXISTS idx_exfil_dstip  ON exfil_events(destination_ip);

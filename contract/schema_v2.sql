-- =============================================================================
-- E-Rakshak — Unified Integration Schema v2 (ADDITIVE migration)
-- =============================================================================
-- Extends the existing windows_c2exfil_module/sql/schema.sql. Nothing here
-- drops or renames an existing table or column, so the current db_loader.py
-- keeps working unchanged. New work targets `case_id`; legacy `sample_id`
-- joins continue to function.
--
-- Design rules:
--   1. `cases` is the per-RUN entity. `samples` stays keyed on sha256 (per
--      FILE). One sample analysed three times = 1 sample row, 3 case rows.
--      Without this split, re-analysis silently overwrites prior results.
--   2. Every UI-facing query keys off case_id. The UI never joins on sha256.
--   3. Both platforms write identical spine tables. Platform-specific data
--      goes in cases.platform_details (JSONB), rendered in a fixed UI slot.
--   4. Confidence is ALWAYS the canonical 5-tier scale (incl. allowlisted).
--      Continuous scores stay internal and feed the tier, never exposed.
-- =============================================================================

-- ---------------------------------------------------------------------------
-- Shared vocabularies. Enforced in the DB so adapter drift fails loudly at
-- write time rather than silently rendering wrong in the UI.
-- ---------------------------------------------------------------------------

DO $$ BEGIN
    CREATE TYPE platform_t AS ENUM ('windows', 'android');
EXCEPTION WHEN duplicate_object THEN NULL; END $$;

-- NOTE: five values, not four. 'allowlisted' is a real tier already emitted by
-- the C2/Exfil module (see output/exfil_events.json and handoff.py::_cap, where
-- it ranks BELOW unconfirmed). It marks a finding that was detected but
-- deliberately down-tiered as benign — e.g. the msftncsi.com DGA false positive
-- on task-18: surfaced for the analyst, never asserted. A four-value enum would
-- reject those rows outright.
DO $$ BEGIN
    CREATE TYPE confidence_t AS ENUM (
        'allowlisted',    -- detected, judged benign; shown but not asserted
        'unconfirmed',
        'weak',
        'strong',
        'confirmed'
    );
EXCEPTION WHEN duplicate_object THEN NULL; END $$;

DO $$ BEGIN
    CREATE TYPE case_status_t AS ENUM (
        'queued',        -- accepted, not yet claimed by a worker
        'running',       -- worker claimed it
        'completed',     -- analysis finished, results written
        'partial',       -- finished but degraded; see caveats
        'failed',        -- analysis could not complete
        'unsupported'    -- file type not routable to any platform
    );
EXCEPTION WHEN duplicate_object THEN NULL; END $$;

-- What was accessed. Shared verbatim across Windows and Android.
--
-- Windows values come from docs/etw_interface_contract.md (and are already
-- enforced by ST/DT's schemas/access_events.schema.json).
-- Android values come from docs/android_schema_parity.md and §4 of
-- unified_solution_overview.md — BOTH of which already agree on 'sms',
-- 'contacts', 'location', 'camera', 'call_log'. Do not rename these.
DO $$ BEGIN
    CREATE TYPE data_type_t AS ENUM (
        -- Windows (etw_interface_contract.md)
        'browser_credentials',
        'keystrokes',
        'screenshot',
        'clipboard',
        'crypto_wallet',
        'system_info',
        'file_access',
        -- Android (android_schema_parity.md) — Windows simply never emits these
        'sms',
        'contacts',
        'call_log',
        'location',
        'camera',
        'microphone',       -- not in the parity doc; add there before first use
        'other'
    );
EXCEPTION WHEN duplicate_object THEN NULL; END $$;

-- What the malware CAN DO, in officer-facing terms. This is the vocabulary
-- behind the L1 verdict screen.
DO $$ BEGIN
    CREATE TYPE capability_t AS ENUM (
        'credential_theft',
        'keylogging',
        'screen_capture',
        'clipboard_theft',
        'file_exfiltration',
        'crypto_wallet_theft',
        'sms_interception',        -- OTP theft — central to Indian fraud cases
        'contact_exfiltration',
        'call_log_access',
        'location_tracking',
        'audio_recording',
        'camera_access',
        'remote_command_execution',
        'persistence',
        'process_injection',
        'anti_analysis',
        'overlay_attack',          -- Android banking-fraud staple
        'accessibility_abuse',     -- Android
        'device_admin_abuse'       -- Android
    );
EXCEPTION WHEN duplicate_object THEN NULL; END $$;

-- ---------------------------------------------------------------------------
-- cases — the per-run entity. Primary key for everything the UI touches.
-- ---------------------------------------------------------------------------

CREATE TABLE IF NOT EXISTS cases (
    case_id             UUID PRIMARY KEY,
    sample_id           TEXT NOT NULL REFERENCES samples(sample_id),  -- sha256
    platform            platform_t NOT NULL,
    original_filename   TEXT,
    file_size_bytes     BIGINT,
    file_type           TEXT,                    -- from magic-byte routing

    status              case_status_t NOT NULL DEFAULT 'queued',
    status_reason       TEXT,                    -- required when failed/unsupported

    submitted_at        TIMESTAMPTZ NOT NULL DEFAULT now(),
    started_at          TIMESTAMPTZ,
    completed_at        TIMESTAMPTZ,

    -- Analysis profile. Windows uses the WinST/DT enum; Android may use
    -- 'standard' only. Free text so neither side is blocked by the other.
    profile             TEXT DEFAULT 'standard',

    -- Back-reference into the producing pipeline, so an analyst can find the
    -- native run. Windows: CAPE task id. Android: MobSF scan hash (md5).
    native_session_id   TEXT,
    native_task_id      INTEGER,

    -- Overall verdict, derived by the adapter from its findings.
    verdict             confidence_t,
    verdict_summary     TEXT,                    -- one plain-language sentence

    -- Platform-specific panel content. Rendered in a fixed UI slot; the UI
    -- never interprets these keys, it dispatches on `platform`.
    platform_details    JSONB NOT NULL DEFAULT '{}'::jsonb,

    -- Provenance: which tool versions produced this case.
    tool_versions       JSONB NOT NULL DEFAULT '{}'::jsonb,

    schema_version      TEXT NOT NULL DEFAULT '2.0'
);

CREATE INDEX IF NOT EXISTS idx_cases_sample   ON cases(sample_id);
CREATE INDEX IF NOT EXISTS idx_cases_status   ON cases(status);
CREATE INDEX IF NOT EXISTS idx_cases_platform ON cases(platform);
CREATE INDEX IF NOT EXISTS idx_cases_recent   ON cases(submitted_at DESC);

-- Worker queue claim pattern (no Redis needed):
--   UPDATE cases SET status='running', started_at=now()
--    WHERE case_id = (SELECT case_id FROM cases
--                      WHERE status='queued' AND platform='windows'
--                      ORDER BY submitted_at
--                      FOR UPDATE SKIP LOCKED LIMIT 1)
--   RETURNING *;

-- ---------------------------------------------------------------------------
-- capabilities — "what does this malware do", in officer language.
-- This is the L1 verdict screen's data source. Currently unowned; both
-- adapters must populate it.
-- ---------------------------------------------------------------------------

CREATE TABLE IF NOT EXISTS capabilities (
    capability_id       UUID PRIMARY KEY,
    case_id             UUID NOT NULL REFERENCES cases(case_id) ON DELETE CASCADE,
    capability          capability_t NOT NULL,

    -- REQUIRED. Written for a non-technical officer. No jargon, no API names.
    -- Good: "Records everything typed on the keyboard, including passwords."
    -- Bad:  "SetWindowsHookEx(WH_KEYBOARD_LL) observed."
    plain_language      TEXT NOT NULL,

    mitre_technique_id  TEXT,                    -- e.g. 'T1056.001'
    confidence_tier     confidence_t NOT NULL,

    -- Where this came from, so the UI can show corroboration count and an
    -- analyst can trace it: 'capa' | 'cape_signature' | 'yara' |
    -- 'correlation' | 'mobsf_permission' | 'mobsf_api_monitor' | 'frida'
    source              TEXT NOT NULL,

    -- Free-form pointers into raw evidence (event seq, Zeek uid, MobSF finding
    -- id, file path). Rendered as the L3 drill-down.
    evidence_refs       JSONB NOT NULL DEFAULT '[]'::jsonb,

    UNIQUE (case_id, capability, source)
);

CREATE INDEX IF NOT EXISTS idx_capabilities_case ON capabilities(case_id);

-- ---------------------------------------------------------------------------
-- caveats — the unified honesty layer.
--
-- This is what makes a "clean" verdict trustworthy. An investigator told what
-- the tool could NOT see trusts it more than one shown an unqualified green
-- tick. Both platforms MUST emit these; they are not optional polish.
-- ---------------------------------------------------------------------------

CREATE TABLE IF NOT EXISTS caveats (
    caveat_id           UUID PRIMARY KEY,
    case_id             UUID NOT NULL REFERENCES cases(case_id) ON DELETE CASCADE,

    -- Stable machine code. UI dispatches icon/severity on this.
    -- Windows: 'network_simulated', 'telemetry_degraded', 'clock_unreliable',
    --          'anti_evasion_residual', 'tls_pinning_suspected',
    --          'capemon_active'
    -- Android: 'emulator_not_hardened', 'tls_pinning_suspected',
    --          'permissions_not_exercised', 'online_lookup_used',
    --          'device_backend_limited'
    code                TEXT NOT NULL,

    severity            TEXT NOT NULL CHECK (severity IN ('info','warning','critical')),

    -- REQUIRED. Officer-facing. Must state the CONSEQUENCE, not the condition.
    -- Good: "Network responses were simulated. Destinations shown were really
    --        contacted, but no data actually left the sandbox — and the absence
    --        of theft here does not prove the app is safe."
    -- Bad:  "network_mode = simulated_inetsim"
    plain_language      TEXT NOT NULL,

    -- What this caveat undermines. Empty array = applies to the whole case.
    -- Used to CAP confidence on affected findings, not just to display.
    affects_data_types  data_type_t[] NOT NULL DEFAULT '{}',
    affects_finding_kinds TEXT[] NOT NULL DEFAULT '{}',  -- 'beacon','correlation','exfil'

    detail              JSONB NOT NULL DEFAULT '{}'::jsonb  -- machine detail for analysts
);

CREATE INDEX IF NOT EXISTS idx_caveats_case ON caveats(case_id);

-- ---------------------------------------------------------------------------
-- artifacts — downloadable raw files and external drill-down links (L3).
--
-- The UI resolves downloads through artifact_id ONLY. It never accepts a
-- user-supplied path. These files come from malware analysis; path traversal
-- here is a real risk, not a theoretical one.
-- ---------------------------------------------------------------------------

CREATE TABLE IF NOT EXISTS artifacts (
    artifact_id         UUID PRIMARY KEY,
    case_id             UUID NOT NULL REFERENCES cases(case_id) ON DELETE CASCADE,

    kind                TEXT NOT NULL,   -- 'pcap','etl','access_events','report_json',
                                         -- 'report_html','screenshot','memory_dump',
                                         -- 'hash_manifest','mobsf_report','logcat'
    label               TEXT NOT NULL,   -- human label for the download button
    storage_path        TEXT,            -- server-side absolute path; NEVER sent to client
    external_url        TEXT,            -- for links out (CAPE UI, MobSF UI)

    sha256              TEXT,
    size_bytes          BIGINT,
    content_type        TEXT,

    -- 'officer' artifacts are safe to expose in the primary UI.
    -- 'analyst' covers raw malware artifacts, dropped files, memory dumps,
    -- and the CAPE/MobSF UIs. NEVER expose 'analyst' to the officer tier.
    access_tier         TEXT NOT NULL DEFAULT 'analyst'
                        CHECK (access_tier IN ('officer','analyst')),

    CHECK (storage_path IS NOT NULL OR external_url IS NOT NULL)
);

CREATE INDEX IF NOT EXISTS idx_artifacts_case ON artifacts(case_id);

-- ---------------------------------------------------------------------------
-- Columns on the EXISTING tables (case_id, finding_kind, plain_language,
-- capped_by_caveat, evidence_refs, first_seen_at, seen_in_traffic) are NOT
-- defined here. They live in sql/schema.sql as of schema 1.3, because
-- tests/test_schema_contract.py parses that file to keep emit_schema_rows(),
-- db_loader's INSERT and the CSV export in lockstep. A column defined outside
-- it is invisible to that guard — the exact silent-drop class of bug the guard
-- exists to catch.
--
-- Apply order:  sql/schema.sql  THEN  this file.
-- ---------------------------------------------------------------------------

-- ---------------------------------------------------------------------------
-- provenance — item-level "which stolen item left, via what, to where, when".
--
-- This is the C2/Exfil module's headline capability (see MEETING_BRIEF.md) and
-- v1 of this contract omitted it entirely. It is what turns a destination list
-- into the sentence an officer can act on, and it carries the recovered bytes'
-- hash, which is the strongest evidentiary artefact the tool produces.
-- Windows populates it from pipeline/provenance.py; Android may leave it empty.
-- ---------------------------------------------------------------------------

CREATE TABLE IF NOT EXISTS exfil_provenance (
    provenance_id     UUID PRIMARY KEY,
    case_id           UUID NOT NULL REFERENCES cases(case_id) ON DELETE CASCADE,
    event_id          TEXT REFERENCES exfil_events(event_id),

    item_type         data_type_t,       -- what was stolen
    access_api_call   TEXT,              -- how it was taken
    channel           TEXT,              -- how it left: 'ftp'|'http'|'smtp'|'dns'|'tls'
    destination       TEXT,              -- where it went
    time_delta_s      REAL,              -- access -> egress gap
    recovered_bytes   BIGINT,            -- size of reconstructed content, if any
    recovered_sha256  TEXT,              -- hash of the recovered content
    confidence_tier   confidence_t NOT NULL,
    plain_language    TEXT               -- officer-facing one-liner
);

CREATE INDEX IF NOT EXISTS idx_provenance_case ON exfil_provenance(case_id);

-- ---------------------------------------------------------------------------
-- Convenience view: everything the case-list screen needs, one query.
-- ---------------------------------------------------------------------------

CREATE OR REPLACE VIEW case_summary AS
SELECT
    c.case_id,
    c.sample_id,
    c.platform,
    c.original_filename,
    c.status,
    c.verdict,
    c.verdict_summary,
    c.submitted_at,
    c.completed_at,
    (SELECT count(*) FROM capabilities cap WHERE cap.case_id = c.case_id) AS capability_count,
    (SELECT count(*) FROM exfil_events e  WHERE e.case_id  = c.case_id) AS finding_count,
    (SELECT count(*) FROM caveats cv
      WHERE cv.case_id = c.case_id AND cv.severity IN ('warning','critical')) AS caveat_count,
    (SELECT count(DISTINCT e.destination_ip) FROM exfil_events e
      WHERE e.case_id = c.case_id AND e.destination_ip IS NOT NULL) AS destination_count
FROM cases c;

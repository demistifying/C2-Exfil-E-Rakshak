# E-Rakshak — Integration & Ingestion Handover

**You are taking over:** the ingestion service, the workers, the adapters, the
aggregation API, and the UI — everything that turns three independent analysis
modules into one tool.

**You are not taking over:** the analysis modules themselves. Windows ST/DT,
Windows C2/Exfiltration and Android each have an owner and each keeps working
exactly as it does now. If you find yourself editing CAPE, MobSF or a detection
pipeline, stop — that's a conversation with the owner, not a change you make.

Read §4 before writing any code. It contains four decisions that were made for
specific reasons, and at least two of them were re-litigated once already and
cost real time.

---

## 1. The tool in one page

A police investigator seizes a device, extracts a suspicious file, and needs two
questions answered in language they can act on:

> **What is this stealing, and where is it sending it?**

They upload the file through a browser. The tool detects whether it's a Windows
binary or an Android APK, routes it to the right analysis backend, detonates it
in isolation, and produces a report an officer with no security training can read
— with the raw forensic artefacts one click away for an analyst or a court.

Problem statement ERH26_PS_04. Scored on: detection accuracy, **clarity of the
exfiltration/C2 mapping**, safety and isolation of the analysis environment,
coverage across both platforms, and **usability of reports for non-technical
officers**. Bonus objectives: automated MITRE ATT&CK mapping, encrypted-traffic
analysis without decryption, threat-intel enrichment, and offline/air-gapped
operation.

The last two scored criteria are yours. Nobody else in the project is building
the officer-facing layer.

---

## 2. Current state — honest inventory

### Works, proven on real data

| Component | Owner | Evidence |
|---|---|---|
| Windows ST/DT sandbox → handoff bundle | teammate | Real bundles exist (task 11, task 18). Written atomically. |
| Windows C2/Exfil detection pipeline | Raghav | 328 tests. Consumes real bundles end to end. |
| Shared schema (`sql/schema.sql`) | Raghav | Rows emitted, hash-chained, custody-linked to the ST/DT manifest. |

### Postgres — verified working (2026-08-08)

Both migrations were applied to a real PostgreSQL 16 instance and
`db_loader.load()` was run against the actual `output/exfil_events.json`:

```
sql/schema.sql          -> OK
contract/schema_v2.sql  -> OK   (5 enums, 9 tables, case_summary view)
db_loader.load()        -> OK   ("Loaded sample a86b385c... (allowlisted), 1 event")
confidence_t ranked     -> allowlisted < unconfirmed < weak < strong < confirmed
```

An earlier draft of this document said the Postgres path was unproven and made
it your first task. That was wrong — it works. Do not spend a day on it.

### What actually reaches the database — the real gap

This is the part that matters, and it is larger than it looks. After a full
pipeline run plus `db_loader`:

| Table | Rows | Writer |
|---|---:|---|
| `samples` | 1 | `db_loader.py` |
| `exfil_events` | 1 | `db_loader.py` |
| `static_iocs` | **0** | **none exists anywhere in the codebase** |
| `evidence_log` | **0** | **none exists** |
| `exfil_provenance` | 0 | new table; provenance goes to JSON only |
| `cases` / `capabilities` / `caveats` / `artifacts` | 0 | new tables |

`db_loader.py` writes two tables and knows nothing about `case_id`. Provenance,
IOCs, caveats and the evidence log are written to `output/*.json` and never
persisted. **The adapter therefore has more to do than "stamp `case_id` on
existing rows"** — an earlier draft of this document claimed the pipeline
already emitted `static_iocs` and provenance to the database. It does not.

### Android module

Currently upstream MobSF plus a rooted-AVD launcher (`test11.sh`). No detection
layer, no schema output. See §7.

### Does not exist at all — this is your build

Ingestion service · `cases` and `case_id` · workers · adapters ·
`static_iocs` / `evidence_log` / provenance persistence · `capabilities` ·
`caveats` · `artifacts` · aggregation endpoint · the entire UI.

---

## 3. Where everything lives

```
windows_c2exfil_module/            <- the C2/Exfil repo; everything below is version controlled
  contract/
    INTEGRATION_HANDOVER.md    <- this document
    INTEGRATION_CONTRACT.md    <- read first. The architecture + adapter obligations.
    schema_v2.sql              <- integration tables. Apply AFTER sql/schema.sql.
    case_object.schema.json    <- THE UI contract. The API returns exactly this.
    ANDROID_BUNDLE_SPEC.md     <- handed to the Android team; pending
    pipeline/                  ← the C2/Exfil detection pipeline (not yours to edit)
    sql/schema.sql             ← the existing shared schema
    docs/                      ← etw_interface_contract, static_prior_contract,
                                 android_schema_parity — all pre-existing contracts
    output/                    ← real example output from a live run
    output/winstdt-task-18-.../srv/winstdt/handoff/18/
                               ← A REAL COMPLETE BUNDLE. Develop against this.

../../unified_solution_overview.md   <- the four-module reference. Authoritative.
                                        (still outside the repo)
```

Repos: `MYTH-il/WinST-DT-module` (Windows sandbox) ·
`demistifying/C2-Exfil-E-Rakshak` (C2/Exfil) · `d4ruvil/erakshak` (Android/MobSF).

**Develop against `handoff/18/`.** It is a real, complete bundle: manifest,
sample.meta.json, report.json, 1968 access events, clock-sync, a PCAP, Suricata
output and a 64 MB ETL. You do not need a working sandbox to build everything in
§5.

---

## 4. Decisions already made — do not relitigate

### 4.1 Modules never talk to each other, or to the UI

Every module writes a **result bundle to a known path**. The integration side
writes **adapters** that read those bundles into Postgres. The UI reads Postgres
and nothing else.

This is why: it keeps three teams from encoding vocabularies independently, keeps
database credentials off malware-handling hosts, and means you fix a mapping bug
yourself instead of filing an issue and waiting.

The rejected alternative — each module generating its own officer report, with
"we'll just keep them consistent" — is not less work. It is this contract,
implemented three times, with no validator and three places to fix every change.
It also puts three visually different tools in front of one officer, which is a
scored criterion.

### 4.2 The confidence scale has FIVE values

`confirmed` · `strong` · `weak` · `unconfirmed` · **`allowlisted`**

`allowlisted` ranks *below* `unconfirmed`. It marks a finding that was detected
and then deliberately judged benign — surfaced for the analyst, never asserted.
It is already emitted (`output/exfil_events.json`). A four-value enum rejects
those rows at insert time. An earlier draft of the contract got this wrong.

### 4.3 Never apply the sandbox's clock offset

ST/DT already normalises access-event timestamps onto the host clock before
writing them. `correlation.clock_algorithm` describes what it **already did** —
it is provenance, not an instruction.

On task-18 the guest ran **3603 seconds (an hour) behind the host**, yet the
access events already align with the PCAP to within seconds. Applying
`guest_minus_host_ns` yourself moves correct timestamps by an hour and silently
reduces correlation to zero — no error, just an empty result that looks
plausible. This was implemented once, in error, and reverted.

Take only the **residual uncertainty** (~502 ms) to widen the correlation window.
`pipeline/handoff.py` has a test asserting no attribute containing "offset"
exists, so a reintroduction fails loudly.

### 4.4 Do not rebuild CAPE's or MobSF's UI

Both are complete analyst tools. They are your **L3** — link out to them. Weeks
of work for zero evaluation credit, and both expose raw malware artefacts that
must never reach the officer tier.

---

## 5. The build, in order

Sizes assume one developer who has read §4. "Done when" is the acceptance test —
if you can't demonstrate it, the phase isn't finished.

### Phase 0 — Stand up Postgres · ~1 hour

Bring up Postgres from `docker-compose.yml`, apply `sql/schema.sql` then
`contract/schema_v2.sql` (additive — it does not drop or rename anything, so the
existing `db_loader.py` keeps working). Run the pipeline against `handoff/18/`
and `python pipeline/db_loader.py`.

Both migrations and the loader have been verified against a real PostgreSQL 16
instance, so this should be uneventful. It is Phase 0 only because everything
else reads from here.

**Done when:** `select * from case_summary` returns a row.

### Phase 1 — Ingestion service · ~1 day

FastAPI. `POST /api/v1/cases` accepts an upload, computes SHA-256, writes the
sample to a quarantine path (no execute bit), inserts `samples` + `cases`
(`status='queued'`), returns `case_id`. Returns in under a second — it never
waits for analysis.

Routing is magic bytes, not heuristics: `MZ` at offset 0 → windows;
ZIP magic containing `AndroidManifest.xml` and `classes.dex` → android;
`dex\n035\0` → android. .NET assemblies and MSI are still Windows; ELF, JAR and
plain ZIP are neither → `status='unsupported'` with a readable reason.

**Dedupe on SHA-256** — a known sample returns the existing case instead of
re-detonating. Turns a ten-minute wait into an instant answer and demos well.

**Done when:** uploading a PE and an APK creates correctly-routed queued cases,
an unsupported file fails readably, and re-uploading returns the original case.

### Phase 2 — Windows worker · ~1 day

A loop on the CAPE host. Claim work with:

```sql
UPDATE cases SET status='running', started_at=now()
WHERE case_id = (SELECT case_id FROM cases
                 WHERE status='queued' AND platform='windows'
                 ORDER BY submitted_at
                 FOR UPDATE SKIP LOCKED LIMIT 1)
RETURNING case_id;
```

That is the whole dispatch mechanism. No Redis, no broker. Poll every 5s.

Then: submit to CAPE's REST API → record `native_task_id` → poll until complete →
ST/DT's reporting module has written the bundle → run the C2/Exfil orchestrator
against it → run the adapter (Phase 3) → set `completed`.

The worker contains **no analysis logic**. It sequences things that already exist.

Add a reaper on the API side:

```sql
UPDATE cases SET status='failed', status_reason='worker timeout'
WHERE status='running' AND started_at < now() - interval '30 minutes';
```

And make writes idempotent — delete findings by `case_id` before inserting, in
one transaction. Cheap now, painful to retrofit.

**Done when:** a queued case runs to `completed` unattended, a killed worker
leaves a case that the reaper marks `failed`, and re-running produces no
duplicate rows.

### Phase 3 — Windows adapter · ~2 days

Bigger than it first appears, because most of the pipeline's output currently
stops at `output/*.json` and never reaches Postgres (see §2).

**Persist what already exists but isn't stored.** `static_iocs` and
`evidence_log` have *no writer anywhere in the codebase*; provenance is written
to `output/provenance.json` and nowhere else. Either extend `db_loader.py` or —
cleaner — write these in the adapter so `db_loader` stays the legacy path.

**Stamp `case_id`** on `exfil_events`, `static_iocs`, `evidence_log` and
`exfil_provenance`. `db_loader.py` predates `case_id` and does not set it.

**Populate the new tables** from the bundle: `cases.platform_details.windows`,
`caveats`, `artifacts`, `tool_versions`.

Caveats are a mechanical mapping from the manifest (table in
`INTEGRATION_CONTRACT.md` §7.1): `network_simulated`, `telemetry_degraded`,
`clock_unreliable`, `anti_evasion_residual`, `tls_pinning_suspected`.

**Capabilities needs the most thought** — it is the officer screen's data source.
There is a partial producer already: `etw_ingest.py` holds a
`data_type → (ATT&CK id, human-readable capability)` map, so host access events
give you capabilities for free. Supplement with CAPE signatures from
`report.json`, YARA hits, `static_hypotheses`, and correlation results — a
correlated access→egress pair is the strongest capability evidence available.
**Not from capa** (see §6).

**Done when:** `handoff/18/` produces rows in all nine tables, and every caveat
in the manifest appears with officer-readable text.

### Phase 3b — two small fixes in `db_loader.py` · ~1 hour

Both are C2/Exfil module code, so agree them with its owner rather than editing
unilaterally:

- The sample-tier ranking is `{"confirmed":3,"strong":2,"weak":1,"unconfirmed":0}`
  with `order.get(t, 0)`. **`allowlisted` is missing**, so it silently ties with
  `unconfirmed` instead of ranking below it. Add it as `-1`.
- `case_id` is absent from the `exfil_events` INSERT.

### Phase 4 — Aggregation endpoint · ~1 day

`GET /api/v1/cases/{case_id}` returns exactly `case_object.schema.json`.
Validate the response against that schema in a test — it is the contract three
other pieces depend on.

Also: `GET /api/v1/cases` (list, filterable — use the `case_summary` view),
`GET /api/v1/cases/{id}/status` (cheap poll target),
`GET /api/v1/artifacts/{artifact_id}` (download).

**Downloads resolve by `artifact_id` only.** Never accept a client-supplied path
— these are live malware artefacts and traversal here is a real risk. Filter by
`access_tier` before rendering: `analyst` covers raw samples, dropped files,
memory dumps and the CAPE/MobSF UIs, and must never appear in the officer view.

**Done when:** the response validates against the schema, and no field in the
UI's model comes from anywhere else.

### Phase 5 — UI · ~4–5 days

React + Vite + Tailwind. Poll, don't stream.

**L1 — Verdict.** One screen, plain language, no jargon. Verdict, headline,
what was taken, where it went, capabilities, **caveats**. This is what the
officer reads and what goes in a case file.

**L2 — Findings.** Filterable `exfil_events` table with tiers and evidence, IOC
list with CSV/STIX export, the unified timeline, MITRE mapping, provenance, and
the platform-specific panel.

**L3 — Raw.** Artifact downloads and links out to CAPE/MobSF. Never rebuilt.

Two things that carry disproportionate weight:

**Provenance is the headline.** *"Saved browser passwords were read and sent to
188.190.10.10 over FTP 4 seconds later — 2118 bytes recovered, SHA-256
3fa0b087…"* That single sentence demonstrates attribution, provenance and
evidence integrity together. Give it prominence.

**Render caveats as first-class UI, not footnotes.** "Network responses were
simulated — the absence of theft here does not prove this file is safe." An
investigator told what the tool *couldn't* see trusts it more than one shown an
unqualified green tick. This is cheap to build and directly serves a scored
criterion.

**Done when:** a non-technical person can read a completed case and correctly
state what the malware stole, where it went, and what the analysis could not see.

### Phase 6 — Android · ~2 days after their bundle lands

Same worker skeleton, different calls: drive MobSF's REST API, capture the
emulator PCAP, run the **same** C2/Exfil pipeline against it, run the Android
adapter. If Phase 4 was built properly, the UI needs no changes — only the
`platform_details.android` panel.

---

## 6. Traps

Each of these cost real time to find. None is obvious from the code.

**capa is not available.** On task-18, `capa`, `die`, `trid` and `screenshots`
all report `tool_failure`; `floss` is `not_requested`. Do not design UI panels
around them. Four static tools failing together looks like one broken install
path — worth asking ST/DT to investigate, but don't block on it.

**Suricata belongs to ST/DT.** It ships `analysis/suricata.json` in the bundle
and reports `completed`. Do not run a second instance; drop it from
`docker-compose.yml`. Two instances means duplicate or contradictory alerts.

**ST/DT's published schema rejects ST/DT's own output.** Their committed
`handoff_manifest.schema.json` requires `correlation.clock_quality_acceptable`
and `correlation.reason`; the real manifest has neither and adds five fields
under `additionalProperties: false`. So `schemas/` is deliberately empty and
`Handoff.schema_validation` reports `skipped`. Ask them to republish; then the
file drops in and validation works with no code change.

**`sample.meta.json` contains no network indicators.** The family config
decryptors extract C2 from binaries, but no manifest field carries it to us. The
contract for this already exists — `docs/static_prior_contract.md`, v1.0 — and
has simply never been populated. The ask is not "please design this", it's "the
contract has been in docs/ since v1.0, what's blocking population?"

**`guest_ip` can be the literal string `"unknown"`.** Handled in the pipeline;
handle it in anything new that filters by it.

**Android and Windows must share the `data_type` vocabulary verbatim.**
`docs/android_schema_parity.md` and `unified_solution_overview.md` §4 already
agree on `sms`, `contacts`, `location`, `camera`, `call_log`. Use `sms`, not
`sms_messages`. If the two platforms diverge here, the unified view cannot group
findings and the whole exercise fails quietly.

---

## 7. Blocked on others — track, don't absorb

**Windows ST/DT.** Populate the static IOC prior. Republish the manifest schema.
Explain the four `tool_failure` results. Run one real (non-benign) sample —
everything so far is a benign validation payload, so no
`browser_credentials`/`keystrokes`/`screenshot` events have ever been produced,
and the classification path is structurally validated but never exercised.

**Android.** Implement `contract/ANDROID_BUNDLE_SPEC.md`. The critical item is
one line — adding `-tcpdump` to the emulator launch in `test11.sh` — which lets
the existing C2/Exfil pipeline run unmodified against Android traffic and gives
the platform beaconing, JA3/JA4, DNS tunnelling, DGA, attribution, threat intel
and evidence chaining with **no new detection code**. Also: pick redroid *or*
AVD, and move off MobSF's online lookups, which currently break the air-gapped
objective.

**The organising committee.** Two questions were asked and I don't know if they
were answered — both are in `Requested Clarifications.docx` and both affect you:
whether the tool is a sandbox or a **live triage sweep of a victim's machine**
(a scope question, not a detail), and whether the cyber cell has an **existing
evidence-handling format** the report should match rather than us inventing one.
The second directly shapes L1. Chase it before the UI hardens.

---

## 8. Scope control

If time runs short, cut in this order and say so openly rather than shipping
something that overstates itself:

1. Android (Phase 6) — ship Windows-only, documented as such
2. L2 richness — the timeline and MITRE view before the findings table
3. STIX export — CSV alone is defensible

**Do not cut:** the caveat layer, the hash-chain verification, or the officer-
facing plain language. Those are the difference between a dashboard and forensic
software, and two of them are directly scored.

The project's consistent posture has been that an honestly-scoped smaller build
beats a larger one that overstates what works. Keep that. Every claim in the UI
should be traceable to an artefact you can point at.

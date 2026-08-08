# E-Rakshak — Unified Integration Contract v2.0

**Status:** proposed, pending sign-off from all three module owners
**Files:** `schema_v2.sql` (DDL, additive) · `case_object.schema.json` (API response)

---

## 1. The one rule

> **Modules never talk to each other, and never talk to the UI.
> Every module writes to the shared schema. The UI reads only the shared schema.**

Each module keeps its own pipeline, its own language, its own host, and its own
native report. Nothing about how a module works internally changes. What each
module gains is a small, read-only **adapter** that maps output it already
produces into the shared tables.

Concretely, this means:

- No module rewrites. No changes to CAPE, MobSF, or the detection logic.
- Each module's existing report stays as the **analyst-facing** artifact (L3).
- The **officer-facing** view is generated once, from the shared schema, by the UI.
- **Modules produce a result bundle at a known path. The integration side writes
  the adapters that read those bundles into Postgres.** No module owner needs to
  learn this schema, the tier scale, or the capability vocabulary — and database
  credentials stay off the malware-handling hosts. ST/DT already produces such a
  bundle (`/srv/winstdt/handoff/{task_id}/`), so for it this is a no-op; Android
  needs one wrapper script (see `ANDROID_BUNDLE_SPEC.md`).

The alternative — each module producing its own final officer report — was
considered and rejected. "Just keep the reports consistent" is not a smaller job
than this contract; it is this contract, implemented three times, with no
validator and three places to fix every change. It also puts three visually
different tools in front of one officer, which is the criterion we are scored on.

---

## 2. Architecture

```
  upload
    │
    ▼
┌──────────────────────────────────────────────────────────┐
│ INGESTION SERVICE  (FastAPI)                              │
│  · magic-byte routing: PE → windows, APK/DEX → android    │
│  · sha256 dedupe: known sample returns the existing case   │
│  · writes samples + cases (status=queued)                  │
│  · quarantine storage, no execute bit, never served back    │
└───────────────┬──────────────────────────────────────────┘
                │  cases table IS the queue
                │  (SELECT … FOR UPDATE SKIP LOCKED — no Redis)
       ┌────────┴────────┐
       ▼                 ▼
┌──────────────┐  ┌──────────────────┐
│ WINDOWS      │  │ ANDROID          │
│ WORKER       │  │ WORKER           │
│ (CAPE host)  │  │ (emulator host)  │
│              │  │                  │
│ CAPE ▸ ST/DT │  │ MobSF REST API   │
│ handoff      │  │ + emulator PCAP  │
│ bundle       │  │                  │
│   ▼          │  │   ▼        ▼     │
│ C2/Exfil     │  │ static   PCAP →  │
│ pipeline     │  │ adapter  C2/Exfil│
│   ▼          │  │   ▼      pipeline│
│ ADAPTER      │  │ ADAPTER    ▼     │
└──────┬───────┘  └─────┬────────────┘
       │                │
       ▼                ▼
   ┌────────────────────────────┐
   │  SHARED SCHEMA (Postgres)  │
   │  cases · capabilities ·    │
   │  exfil_events · static_iocs│
   │  caveats · artifacts ·     │
   │  evidence_log              │
   └─────────────┬──────────────┘
                 ▼
   GET /api/v1/cases/{case_id}  →  case object
                 ▼
              REACT UI
```

**Note the Android branch.** The C2/Exfil pipeline appears on both sides. It is
the same code. See §6.

---

## 3. The three UI layers

| Layer | Audience | Source | Rule |
|---|---|---|---|
| **L1 — Verdict** | Investigating officer | `summary`, `capabilities`, `caveats` | Plain language only. No API names, no hashes, no jargon. |
| **L2 — Findings** | Trained investigator | `findings`, `iocs`, `timeline`, `platform_details` | Structured, filterable. Technical but labelled. |
| **L3 — Raw** | Analyst / court | `artifacts` | Downloads and links out to CAPE UI, MobSF UI, native reports. **Never rebuilt.** |

Every layer links downward. Nothing surfaces L3 by default.

---

## 4. Identity model

`samples` is keyed on **sha256** — one row per *file*.
`cases` is keyed on **case_id (UUID)** — one row per *analysis run*.

One sample analysed three times = one sample row, three case rows. Without this
split, re-analysis silently overwrites prior results, which is unacceptable for
evidence.

**The UI addresses everything by `case_id`.** Native identifiers (CAPE task id,
MobSF scan md5) are stored in `cases.native_session_id` / `native_task_id` for
analyst drill-down only.

---

## 5. Shared vocabularies — the part that must not drift

Three enums are shared verbatim across both platforms. They are enforced as
Postgres types so a mismatched adapter fails loudly at write time instead of
rendering wrong in the UI.

**`confidence_t`** — `confirmed` · `strong` · `weak` · `unconfirmed` · `allowlisted`

**Five values, not four.** `allowlisted` ranks *below* `unconfirmed` and is
already emitted by the C2/Exfil module (`output/exfil_events.json`,
`handoff.py::_cap`) for a finding that was detected and then deliberately
judged benign — surfaced for the analyst, never asserted. The msftncsi.com DGA
false positive on task-18 is exactly this. A four-value enum rejects those rows.

Android's HIGH/MEDIUM/LOW maps in: HIGH + independent intel hit → `confirmed`;
HIGH → `strong`; MEDIUM → `weak`; LOW → `unconfirmed`. Continuous 0.0–1.0
scores stay internal and feed the tier — they are not a separate exposed field.

**`data_type_t`** — Windows values from `docs/etw_interface_contract.md`;
Android values from `docs/android_schema_parity.md` and
`unified_solution_overview.md` §4, which already agree on `sms`, `contacts`,
`location`, `camera`, `call_log`. **Use `sms`, not `sms_messages`** — an earlier
draft of this document invented the latter and it is wrong. `microphone` is the
one value not in the parity doc; add it there before first use.

**`capability_t`** — the officer-facing "what does this malware do" vocabulary.
Includes the Android fraud staples this project actually targets:
`sms_interception` (OTP theft), `overlay_attack`, `accessibility_abuse`,
`device_admin_abuse`.

Adding a value to any of these is a coordinated change: bump `schema_version`,
note it here, and tell the other two owners.

---

## 6. Android gets the C2/Exfil pipeline for free

MobSF observes network activity — extracted domains, a blocklist check,
geolocation, and HTTP flows through its proxy. It does **not** do beaconing
analysis, JA3/JA4, DNS tunnelling, DGA detection, covert channels,
upload-asymmetry exfil detection, threat-intel correlation, ASN attribution,
confidence tiering, or evidence chaining.

The Windows C2/Exfil module does all of that, and it is **PCAP-first with a
swappable source** (`pcap_loader.py` → `Connection[]`).

So:

```bash
# test11.sh — inside launch_emulator()
"$EMULATOR_BIN" -avd "$AVD_NAME" \
    -no-snapshot -writable-system \
    -tcpdump "${CAPTURE_DIR}/capture.pcap" \      # ← add this
    -netdelay none -netspeed full \
    > "$LOGFILE" 2>&1 &
```

For redroid, capture on the container's bridge interface instead.

That one flag gives Android beaconing, JA3/JA4, TLS-certificate analysis, DNS
tunnelling, DGA, covert channels, attribution, threat intel, four-tier
confidence, and hash-chained evidence — **with zero new detection code and zero
changes inside either module.** The C2/Exfil pipeline runs as a new consumer of
a new input.

Keep MobSF's HTTP flows as well: MobSF installs its own CA, so those carry
decrypted HTTPS *content* the PCAP will not have. That maps onto the existing
`plaintext_available` column.

**Architectural framing for evaluators:** one network-detection spine, two
acquisition front-ends.

---

## 7. Adapter obligations

Adapters are written by the integration side (§1). What each module owes is a
complete bundle at a known path. Each adapter is roughly 150–300 lines.

### 7.1 Windows ST/DT — bundle already exists

`/srv/winstdt/handoff/{task_id}/` written atomically (temp, then rename), so the
presence of `manifest.json` is itself the completion signal. Adapter reads:

| Target | Source |
|---|---|
| `cases.platform_details.windows` | `sample.meta.json`, `report.json`, `manifest.telemetry`, `analysis/suricata.json` |
| `capabilities` | CAPE signatures (`report.json`), YARA hits, `static_hypotheses`, correlation results |
| `static_iocs` | config-decryptor output — see the gap note below |
| `exfil_provenance` | the C2/Exfil module's `provenance.py` output |
| `caveats` | see mapping below |
| `artifacts` | bundle files + link out to CAPE UI for this task id |
| `cases.tool_versions` | `manifest.tool_versions` |

> **capa is not available.** On the task-18 bundle `capa`, `die`, `trid` and
> `screenshots` all report `tool_failure` and `floss` is `not_requested`. Do not
> build `capabilities` around capa until that is fixed — four static tools
> failing together looks like one broken install path, and it is worth asking
> ST/DT to investigate.

> **Suricata is owned by ST/DT.** `analysis/suricata.json` ships in the bundle
> and `capabilities.dynamic.suricata` reports `completed`. The C2/Exfil module
> must not run a second instance — drop it from `docker-compose.yml`.

> **Static IOC gap.** `sample.meta.json` carries no network indicators, and the
> manifest has no field for the C2 configs the family decryptors extract. The
> contract for this already exists and is fully specified in
> `docs/static_prior_contract.md` (v1.0) — it simply has never been populated.
> The ask is not "please design this", it is "the contract has been in docs/
> since v1.0; what is blocking population?"

Caveat mapping (mechanical, from the manifest):

| Manifest condition | Caveat code | Severity |
|---|---|---|
| `network_mode = simulated_inetsim` | `network_simulated` | warning |
| `telemetry.telemetry_degraded = true` | `telemetry_degraded` | warning |
| `correlation.clock_quality_acceptable = false` | `clock_unreliable` | critical |
| `report.residual_anti_evasion_risks[]` non-empty | `anti_evasion_residual` | info |
| `capabilities.dynamic.tls_interception.status = certificate_pinning_suspected` | `tls_pinning_suspected` | info |
| `capemon_enabled = true` | `capemon_active` | info |

**Please confirm which of `capa`, `floss`, `die`, `trid`, `screenshots`,
`suricata`, `tls_interception`, `memory_dump`, `volatility` are actually
implemented versus present in the schema only.** UI panels will be built against
whatever is real; a schema entry is not an implementation.

### 7.2 Windows C2/Exfil — owner: this module

Already produces `exfil_events` with correct tiering, attribution, and hash
chaining. Remaining work:

- Write `case_id` onto every emitted row (additive column, nullable today).
- Emit `finding_kind` and a `plain_language` one-liner per finding.
- Emit `evidence_refs` (Zeek uid, packet window, access-event seq) for L3 drill-down.
- Set `capped_by_caveat` when a caveat limits a tier, so the UI can show *why*
  a finding did not reach a higher confidence.
- Populate `capabilities` from correlation results — a correlated
  access→egress pair is the strongest capability evidence available.
- Consume `sample.meta.json` / `static_hypotheses` as the IOC prior, and set
  `static_iocs.seen_in_traffic = true` on match. **This is the single strongest
  corroboration signal in the whole tool and it is currently unused.**
- Apply `behavior/clock-sync.json` offset rather than only detecting skew.

### 7.3 Android — owner: Android module

MobSF stays unmodified and is driven over its REST API (`/api/v1/upload`,
`/api/v1/scan`, `/api/v1/report_json`). Keeping MobSF as a separate service
accessed over HTTP — rather than importing its code — is also the cleaner
answer to its GPL-3.0 licensing.

| Target | Source |
|---|---|
| `cases.platform_details.android` | `report_json`: package, permissions, certificate, trackers, APKiD, security score |
| `capabilities` | permission→capability map + API monitor + Frida hooks |
| `static_iocs` | MobSF extracted domains, URLs, emails, trackers |
| `exfil_events` | **the C2/Exfil pipeline, fed by the emulator PCAP** (§6) |
| `artifacts` | MobSF report, screenshots, logcat, PCAP + link out to MobSF UI |
| `caveats` | see below |

Required Android caveats — these are the analogue of the Windows manifest gates
and are **not optional**:

| Condition | Caveat code | Severity |
|---|---|---|
| Emulator not hardened against evasion (redroid/stock AVD are trivially detectable) | `emulator_not_hardened` | critical |
| App pinned certificates; MobSF CA did not intercept | `tls_pinning_suspected` | warning |
| Permissions declared but never exercised during the run | `permissions_not_exercised` | info |
| MobSF online domain / VirusTotal lookup used | `online_lookup_used` | warning |

That last one matters: online lookups break the air-gapped operation objective.
Either repoint at the local threat-intel DB the Windows side already uses, or
declare the caveat honestly.

Also: pick **one** device backend (redroid or AVD) and drop the other.

---

## 8. API surface

```
POST   /api/v1/cases                  upload → {case_id, status}
GET    /api/v1/cases                  list → case_summary rows (filter, paginate)
GET    /api/v1/cases/{case_id}        → case object (case_object.schema.json)
GET    /api/v1/cases/{case_id}/status → lightweight poll target
GET    /api/v1/artifacts/{artifact_id} → download, resolved server-side
GET    /api/v1/export/{case_id}?fmt=csv|stix  → IOC export
```

Downloads resolve by `artifact_id` only. **Never accept a client-supplied
path** — these files come from live malware analysis and path traversal here is
a real risk, not a theoretical one. Filter by `access_tier` before rendering:
`analyst` covers raw samples, dropped files, memory dumps, and the CAPE/MobSF
UIs, and must never appear in the officer view.

---

## 9. Sign-off

This contract is frozen once all three owners agree. Additive optional fields
afterwards do not require a version bump; anything else bumps `schema_version`
and gets noted here.

- [ ] Windows ST/DT — confirms §7.1, answers the capability-implementation question
- [ ] Windows C2/Exfil — confirms §7.2
- [ ] Android — confirms §7.3, confirms `-tcpdump` and device backend choice
- [ ] All — confirm the three shared vocabularies in §5

**Until this is signed, no UI component and no adapter should be written.**
That is the whole point of writing it down first: four people build in parallel
against one agreed shape, instead of serially against each other.

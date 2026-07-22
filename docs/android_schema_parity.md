# Android Module — Schema Parity Checklist

**Purpose**: Ensure the Android module writes the identical `exfil_events` schema
so the shared PostgreSQL store and downstream reporting work across both platforms.

**Schema source of truth**: `sql/schema.sql`

---

## Required Columns

The Android module must populate these columns for every `exfil_events` row:

| Column | Type | Android responsibility | Notes |
|---|---|---|---|
| `event_id` | TEXT (UUID) | Generate a UUID per event | Must be unique |
| `sample_id` | TEXT | SHA-256 of the APK file | Must match the `samples` table entry |
| `platform` | TEXT | Always `"android"` | — |
| `timestamp` | TIMESTAMPTZ | Timestamp of the network event | UTC ISO 8601 |
| `data_type_accessed` | TEXT | Map to shared enum: `sms`, `contacts`, `location`, `camera`, `call_log`, `browser_credentials` | Use the same strings for Android-specific types |
| `access_api_call` | TEXT | Android API or permission that performed the access | e.g. `READ_SMS`, `READ_CONTACTS` |
| `destination_ip` | TEXT | IP the data was sent to | From mitmproxy |
| `destination_domain` | TEXT | Domain name (from HTTP Host header or SNI) | From mitmproxy |
| `destination_port` | INTEGER | Port number | — |
| `asn` | TEXT | ASN of the destination | Use GeoLite2 or MISP, **not VirusTotal** |
| `geo_country` | TEXT | Country code of destination | Same |
| `reputation_score` | REAL | 0.0–1.0, 1.0 = known bad | From local threat-intel DB |
| `ja3_hash` | TEXT | JA3 fingerprint if TLS | mitmproxy can extract this |
| `plaintext_available` | BOOLEAN | Whether payload was decrypted | `true` if mitmproxy intercepted |
| `confidence_score` | REAL | 0.0–1.0, internal score | Feeds `confidence_tier` |
| `confidence_tier` | TEXT | Map from your HIGH/MEDIUM/LOW | See mapping table below |
| `mitre_technique_id` | TEXT | ATT&CK technique | See mapping table below |
| `evidence_hash` | TEXT | SHA-256 hash chain | **Must be CHAINED, not per-entry** |

---

## Confidence Tier Mapping

The canonical 4-tier scale agreed across modules:

| Android level | → Windows tier | Condition |
|---|---|---|
| HIGH + reputation hit | `confirmed` | Independent threat-intel hit AND behavioral correlation |
| HIGH | `strong` | Strong correlation, no independent intel hit |
| MEDIUM | `weak` | Co-occurrence only (valid terminal state) |
| LOW | `unconfirmed` | Generic scan, no dynamic confirmation |

**The continuous 0.0–1.0 `confidence_score` stays INTERNAL.** It feeds the
tier but is not the exposed field for reporting.

---

## MITRE ATT&CK Mapping (Recommended for Android)

| Android capability | MITRE technique | ID |
|---|---|---|
| SMS/OTP theft | Input Capture: GUI Input Capture | T1056.002 |
| Contact exfiltration | Data from Local System | T1005 |
| Location tracking | Location Tracking | T1430 |
| Camera capture | Video Capture | T1125 |
| Call log access | Data from Local System | T1005 |
| Network exfiltration | Exfiltration Over C2 Channel | T1041 |
| C2 beaconing | Application Layer Protocol: Web | T1071.001 |

---

## Evidence Hash Chain

**This is critical for evidentiary claims.**

The evidence hash chain MUST be:
1. **Chained**: `evidence_hash[n] = SHA-256(evidence_hash[n-1] + row_content)`
2. **Genesis**: First row chains from `"0" * 64` (64 zero characters)
3. **Row content**: JSON-serialized row (without `evidence_hash`) with `sort_keys=True`

A per-entry hash (SHA-256 of just the row itself) is NOT sufficient — it doesn't
prove ordering or detect inserted/deleted rows.

See `pipeline/orchestrator.py:emit_schema_rows()` for the reference implementation.

---

## Verification

The Windows module includes a verification function in `tests/test_evidence_chain.py`
that re-computes the chain from scratch. Ask the Windows team for this test and
run it against your output to confirm parity.

---

## Offline Attribution

> [!WARNING]
> The Android module currently uses the **live VirusTotal API** for reputation
> checks. This **breaks the air-gapped/offline objective**. The fix is to point
> reputation checks at the same local MISP / `threatintel.sqlite` DB that the
> Windows module uses. The lookup interface is identical — only the data source
> changes.

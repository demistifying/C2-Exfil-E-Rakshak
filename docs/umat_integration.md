# UMAT Integration — where the contract lives

**The integration contract is not in this repository.** It is owned by the UMAT
control plane:

> **https://github.com/MYTH-il/E-Rakshak-UMAT** → `contracts/`

This module is one of four components UMAT orchestrates. UMAT owns the case
model, the shared vocabularies, and the schema every module's output is
validated against. This document exists so nobody re-derives them here.

An earlier `contract/` directory in this repository proposed a parallel case
object, vocabulary set and Android bundle spec. UMAT had already implemented all
three, in more depth. That directory has been removed rather than maintained
alongside — two sources of truth for a schema is the failure mode the contract
exists to prevent.

---

## What UMAT owns

| Artifact | Path in UMAT |
|---|---|
| Event schema we must satisfy | `contracts/c2/c2-event-v1.3.schema.json` |
| Result envelope wrapping our rows | `contracts/c2/c2-result.schema.json` |
| Input we are handed | `contracts/c2/c2-input.schema.json` |
| Public case object (the UI contract) | `contracts/case-object.schema.json` |
| Confidence tiers, data types, verdicts, caveats, artifacts, stages, evidence levels | `contracts/vocabularies/*.json` |
| Android bundle shape | `contracts/android/android-bundle.schema.json` |
| Windows import shape | `contracts/windows/windows-import.schema.json` |
| Our pinned revision + validation record | `dependency-locks/c2-exfil.json` |

Their vocabularies are authoritative. Two worth internalising:

- **`confidence.json`** is `["allowlisted","unconfirmed","weak","strong","confirmed"]`
  — five values, `allowlisted` ranked lowest. This matches what this module has
  always emitted.
- **`verdicts.json`** is separate from confidence:
  `["malicious","suspicious","no_malicious_activity_observed","inconclusive","failed"]`.
  Officer-facing language is deliberately *not* the technical tier. We emit
  tiers; UMAT derives the verdict.

Their `data-types.json` is a superset of ours — it also carries `documents`,
`calendar` and `device_identity`. Anything new we want to emit must be added
there first.

---

## What this module must satisfy

`contracts/c2/c2-event-v1.3.schema.json` validates every row we emit, with
`additionalProperties: false`. An unexpected key fails as hard as a missing one.

Four fields are **required** that predate schema 1.3 in name only — the SQL
columns stay nullable for standalone runs, but the integration profile demands
them:

| Field | Source in this module |
|---|---|
| `case_id` | UMAT's `analysis_run_id`, passed in via `--case-id`. `None` standalone. |
| `finding_kind` | `orchestrator._finding_kind()` folds our detector vocabulary onto their seven-value enum. |
| `plain_language` | `orchestrator._plain_language()` — one officer-readable sentence, never stronger than the tier. |
| `evidence_refs` | `orchestrator._evidence_refs()` — pointers back to raw evidence for L3 drill-down. |

All four are set **before** the row is hashed, so they are covered by the
evidence chain rather than appended outside it. The officer-facing sentence is
therefore tamper-evident along with everything else.

`tests/test_umat_event_contract.py` validates our real output against a vendored
copy of their schema (`tests/fixtures/umat-c2-event-v1.3.schema.json`). It is
vendored deliberately: the test must fail when *we* drift, and must not silently
pass because a UMAT checkout happens to be absent.

### Running under UMAT

```bash
python pipeline/orchestrator.py <pcap> \
    --handoff <bundle>/manifest.json \
    --case-id <umat analysis_run_id>
```

---

## Known divergences to raise, not to paper over

**`finding_kind` has no `unclassified` value.** Their enum is
`beacon | exfil | correlation | reputation | covert_channel | dns | static_ioc`.
Our catch-all detector emits `unclassified_egress` — residual egress that
matched no specific detector. It currently folds to `exfil`, on the grounds that
traffic did leave the host and the honesty is carried by the tier and the
plain-language text. That is the least-wrong option, not a correct one.
**Ask UMAT to add `unclassified`.**

**The runtime pin lags this repository.** `dependency-locks/c2-exfil.json` pins
`47225ec`; the schema is referenced from a later commit as
`reference_only_not_runtime_promoted`. Two things follow:

- The deployed runtime predates `1f65efe`, whose own commit message records
  *"before = 2 rows mislabelling guest+resolver as C2"*. That bug is live in the
  pinned revision under `simulated_inetsim`.
- UMAT also applies a patch series to our tree (`patch_series_sha256`). Those
  patches should be reviewed and, if they are fixes, upstreamed here rather than
  maintained as deployment patches.

**No LICENSE file in this repository.** UMAT records
`license_status: authorization_required_no_upstream_license_file` and
`redistribution_allowed: false`, and its release policy excludes any component
that is not redistributable. This blocks shipping the whole tool. Adding a
LICENSE is minutes of work.

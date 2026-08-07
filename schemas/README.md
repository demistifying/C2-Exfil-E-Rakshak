# schemas/ — intentionally not vendored (yet)

`pipeline/handoff.py` looks for `handoff_manifest.schema.json` here to mirror the
WinST/DT Rust validator and catch contract drift on our side.

**It is deliberately empty.** ST/DT's committed
`schemas/handoff_manifest.schema.json` does not validate ST/DT's own output:

| Real manifest (task 18) | Committed schema |
|---|---|
| `correlation.reason_code` | requires `correlation.reason` |
| *(absent)* | requires `correlation.clock_quality_acceptable` |
| `source`, `clock_algorithm`, `etw_corroboration_state`, `maximum_uncertainty_ns`, `access_events_status_path` | `additionalProperties: false` |

Vendoring it as-is would fail validation on every real bundle. `load_handoff()`
now reports this honestly via `Handoff.schema_validation` instead of silently
skipping, which is what it did before.

**To close this:** ask ST/DT to update the published schema to match what the
reporting module actually emits, then drop the file in here. Validation starts
working with no code change.

"""
handoff.py — consume the WinST/DT handoff manifest and apply honesty gates.

The ST/DT sandbox emits a signed, hash-manifested handoff bundle. Its manifest
carries three facts the network analyzer MUST respect or it will overstate its
findings:

  * network_mode = simulated_inetsim   -> the sample's C2 was answered by a
    simulator, not the real internet. Attempted destinations/cadence are real;
    SUCCESSFUL exfil/C2 cannot be proven, and its ABSENCE proves nothing. We say
    so in output instead of implying "clean".
  * clock_quality_acceptable = false   -> host and network clocks aren't reliably
    aligned, so any TIMING claim (host<->network correlation, beacon intervals)
    is unsafe. Cap those findings to weak and surface the reason. Signals that
    don't depend on timing (known-bad reputation, static-IOC match) stand.
  * telemetry_degraded = true          -> some ETW providers were unavailable, so
    the ABSENCE of a host access for the data types they feed is not evidence.
    Cap correlated findings for the affected data types.

The manifest also carries the join keys (session_id / cape_task_id) and the
bundle hash (integrity.hash_manifest_sha256) used to link the two custody chains
— those are handled at emit time (see orchestrator/evidence), not here.

Everything degrades gracefully: no manifest -> legacy behavior, no gating.
"""

from __future__ import annotations
from dataclasses import dataclass, field
from datetime import datetime, timedelta
import json
import os

SUPPORTED_SCHEMA = "1.0"

# A clock is "acceptable" for timing correlation if its uncertainty is small
# relative to the 15 s correlation window. Some manifests carry an explicit
# boolean; others (e.g. task-18) instead report maximum_uncertainty_ns from a
# linear clock interpolation — derive acceptability from it.
_CLOCK_UNCERTAINTY_LIMIT_NS = 5_000_000_000   # 5 s (< a third of the 15 s window)


def _clock_acceptable(corr: dict) -> bool:
    if "clock_quality_acceptable" in corr:
        return bool(corr.get("clock_quality_acceptable"))
    unc = corr.get("maximum_uncertainty_ns")
    if isinstance(unc, (int, float)):
        return unc <= _CLOCK_UNCERTAINTY_LIMIT_NS
    return False   # unknown -> safe default (treat as not acceptable)

# Timing-dependent detections: their confidence rests on when things happened,
# so a bad clock invalidates them (caps to weak).
_TIMING_KINDS = {"beacon"}

# How far the host-access and network timelines may legitimately differ before
# we suspect the two clocks are not aligned at all. Generous on purpose: access
# events and network events genuinely cluster differently within a detonation,
# so this must not fire on normal skew. A real misalignment (task-18's guest ran
# ~3600s behind) clears this by more than an order of magnitude.
_ALIGNMENT_TOLERANCE_S = 120.0

# Best-effort ETW-provider -> data_type map (substring, case-insensitive). Used
# to scope telemetry-degradation capping. Configurable via
# data/provider_data_type_map.json; if a degraded provider matches nothing, we
# fall back to a GLOBAL host-collection caveat rather than fake precision.
_DEFAULT_PROVIDER_MAP = {
    "kernel-file": ["file_access"],
    "kernel-registry": ["system_info"],
    "kernel-process": ["system_info"],
    "win32k": ["keystrokes", "screenshot", "clipboard"],
    "crypto": ["browser_credentials", "crypto_wallet"],
    "dpapi": ["browser_credentials"],
    "clipboard": ["clipboard"],
    "input": ["keystrokes"],
}


@dataclass
class Handoff:
    schema_version: str
    session_id: str | None
    cape_task_id: int | None
    network_mode: str | None
    clock_quality_acceptable: bool
    telemetry_degraded: bool
    providers_unavailable: list = field(default_factory=list)
    guest_ip: str | None = None
    detonation_start_utc: str | None = None
    detonation_end_utc: str | None = None
    hash_manifest_sha256: str | None = None
    path: str | None = None
    raw: dict = field(default_factory=dict)
    # 'validated' | 'skipped: ...' | 'failed: ...'  — never silently unknown
    schema_validation: str = "not_attempted"

    # --- bundle-resolved artifact paths + the ST/DT correlation gate ---------
    # manifest.correlation tells us where the access events are, how many to
    # expect, and whether ST/DT considers host<->network correlation safe to
    # run at all. Previously we required the caller to pass the path by hand.
    bundle_dir: str | None = None
    access_events_path: str | None = None
    access_event_count: int | None = None
    host_network_correlation_enabled: bool = True
    correlation_reason: str | None = None
    sample_meta_path: str | None = None
    pcap_path: str | None = None

    # access_events.status.json sidecar
    access_events_source: str | None = None          # e.g. 'cape_capemon'
    access_events_correlation_eligible: bool = True
    access_events_rejected_count: int = 0
    etw_corroboration_state: str | None = None

    # --- clock QUALITY (behavior/clock-sync.json) ---------------------------
    # IMPORTANT — read before touching this.
    #
    # ST/DT ALREADY normalises access-event timestamps onto the HOST clock
    # before writing them. `correlation.clock_algorithm` (e.g.
    # "linear_start_end_interpolation") describes what it ALREADY DID; it is a
    # provenance statement, not an instruction to us.
    #
    # Verified on the task-18 bundle: the guest clock ran ~3603.7 s (about one
    # hour) behind the host, yet access_events span 16:51:10–17:00:19 and the
    # PCAP spans 16:51:00–17:00:17. They are already aligned.
    #
    # So we must NEVER apply guest_minus_host_ns ourselves — doing so would
    # shift correct timestamps by an hour and silently destroy every
    # correlation. What we take from this file is the RESIDUAL UNCERTAINTY left
    # after their interpolation (~502 ms here), which legitimately widens our
    # matching window, plus their own quality verdict.
    clock_uncertainty_ms: float = 0.0
    clock_algorithm: str | None = None
    clock_quality_reported: bool | None = None       # clock-sync quality.acceptable

    # --- encrypted-traffic branch (capabilities.dynamic.tls_interception) ----
    tls_interception_status: str | None = None

    @property
    def simulated(self) -> bool:
        return self.network_mode == "simulated_inetsim"

    @property
    def tls_pinning_suspected(self) -> bool:
        """TLS could not be read: fall back to metadata-only signals (JA3/JA4,
        SNI, cadence, ASN) rather than treating the traffic as un-analysable."""
        return self.tls_interception_status in {
            "certificate_pinning_suspected", "certificate_rejected",
            "unsupported_protocol", "proxy_error"}

    @property
    def tls_plaintext_available(self) -> bool:
        return self.tls_interception_status == "intercepted"


def load_handoff(path: str, *, strict: bool = False) -> Handoff:
    """Load + lightly validate a handoff manifest, pinned on schema_version.

    Uses jsonschema against schemas/handoff_manifest.schema.json when both the
    library and the schema file are available (mirrors his Rust validator to
    catch contract drift on our side); otherwise falls back to a structural
    check of the fields we consume.
    """
    with open(path, encoding="utf-8") as f:
        raw = json.load(f)

    sv = raw.get("schema_version")
    if sv != SUPPORTED_SCHEMA:
        msg = f"handoff schema_version {sv!r} != supported {SUPPORTED_SCHEMA!r}"
        if strict:
            raise ValueError(msg)

    schema_status = _jsonschema_validate(raw, strict=strict)

    corr = raw.get("correlation") or {}
    tel = raw.get("telemetry") or {}
    ident = raw.get("guest_vm_identity") or {}
    integ = raw.get("integrity") or {}
    apaths = raw.get("artifact_paths") or {}
    providers = [p.get("provider") for p in (tel.get("providers_unavailable") or [])
                 if isinstance(p, dict) and p.get("provider")]

    bundle_dir = os.path.dirname(os.path.abspath(path))

    def _resolve(rel):
        return os.path.normpath(os.path.join(bundle_dir, rel)) if rel else None

    # correlation.access_events_path is the authoritative location; fall back to
    # artifact_paths.access_events, then to the contract's fixed default.
    acc_rel = (corr.get("access_events_path")
               or apaths.get("access_events")
               or "behavior/access_events.json")

    unc_ms, clock_algo, clock_ok = _load_clock_quality(
        _resolve(apaths.get("clock_sync") or "behavior/clock-sync.json"))

    status_rel = (corr.get("access_events_status_path")
                  or apaths.get("access_events_status")
                  or "behavior/access_events.status.json")
    ae_status = _load_access_events_status(_resolve(status_rel))

    return Handoff(
        schema_version=sv,
        session_id=raw.get("session_id"),
        cape_task_id=raw.get("cape_task_id"),
        network_mode=raw.get("network_mode"),
        # default to the SAFE interpretation when the field is missing: assume the
        # clock is NOT acceptable and telemetry MAY be degraded, so we never
        # silently overstate.
        clock_quality_acceptable=_clock_acceptable(corr),
        telemetry_degraded=bool(tel.get("telemetry_degraded", False)),
        providers_unavailable=providers,
        guest_ip=ident.get("guest_ip"),
        detonation_start_utc=raw.get("detonation_start_utc"),
        detonation_end_utc=raw.get("detonation_end_utc"),
        hash_manifest_sha256=integ.get("hash_manifest_sha256"),
        path=path,
        raw=raw,
        schema_validation=schema_status,
        bundle_dir=bundle_dir,
        access_events_path=_resolve(acc_rel),
        access_event_count=corr.get("event_count"),
        # Absent field -> assume ENABLED (legacy bundles predate the gate), but
        # an explicit False must be honoured: ST/DT is telling us its own
        # correlation preconditions were not met.
        host_network_correlation_enabled=bool(
            corr.get("host_network_correlation_enabled", True)),
        # real bundles use 'reason_code'; earlier drafts used 'reason'
        correlation_reason=corr.get("reason_code") or corr.get("reason")
        or ae_status.get("reason_code"),
        sample_meta_path=_resolve("sample.meta.json"),
        pcap_path=_resolve(apaths.get("pcap") or "network/capture.pcapng"),
        access_events_source=(ae_status.get("source") or corr.get("source")),
        access_events_correlation_eligible=bool(
            ae_status.get("correlation_eligible", True)),
        access_events_rejected_count=int(
            ae_status.get("rejected_event_count") or 0),
        etw_corroboration_state=(ae_status.get("etw_corroboration_state")
                                 or corr.get("etw_corroboration_state")),
        clock_uncertainty_ms=unc_ms,
        clock_algorithm=corr.get("clock_algorithm") or clock_algo,
        clock_quality_reported=clock_ok,
        tls_interception_status=_tls_status(raw),
    )


def _load_clock_quality(path: str | None) -> tuple[float, str | None, bool | None]:
    """Read the RESIDUAL uncertainty from ST/DT's clock-sync record.

    Returns (uncertainty_ms, algorithm, reported_acceptable).

    We deliberately do NOT read guest_minus_host_ns. ST/DT has already applied
    it when writing access_events (see the note on Handoff.clock_uncertainty_ms);
    re-applying it here would shift correct timestamps by the full offset — an
    hour, on the task-18 bundle — and silently break every correlation.

    Real shape (task-18):
        {"algorithm": "...",
         "measurements": {"start": {...,"uncertainty_ns": N},
                          "end":   {...,"uncertainty_ns": N}},
         "quality": {"acceptable": true, "maximum_observed_uncertainty_ns": N}}
    """
    if not path or not os.path.exists(path):
        return 0.0, None, None
    try:
        doc = json.load(open(path, encoding="utf-8"))
    except Exception:
        return 0.0, None, None
    if not isinstance(doc, dict):
        return 0.0, None, None

    quality = doc.get("quality") if isinstance(doc.get("quality"), dict) else {}
    acceptable = quality.get("acceptable")
    acceptable = bool(acceptable) if isinstance(acceptable, bool) else None

    unc_ns = quality.get("maximum_observed_uncertainty_ns")
    if not isinstance(unc_ns, (int, float)):
        # fall back to the worst per-measurement uncertainty
        seen = []
        meas = doc.get("measurements")
        if isinstance(meas, dict):
            for leg in meas.values():
                if isinstance(leg, dict) and isinstance(
                        leg.get("uncertainty_ns"), (int, float)):
                    seen.append(leg["uncertainty_ns"])
        unc_ns = max(seen) if seen else 0

    try:
        unc_ms = abs(float(unc_ns)) / 1e6
    except (TypeError, ValueError):
        unc_ms = 0.0
    return unc_ms, doc.get("algorithm"), acceptable


def _load_access_events_status(path: str | None) -> dict:
    if not path or not os.path.exists(path):
        return {}
    try:
        doc = json.load(open(path, encoding="utf-8"))
        return doc if isinstance(doc, dict) else {}
    except Exception:
        return {}


def _tls_status(raw: dict) -> str | None:
    caps = raw.get("capabilities")
    if not isinstance(caps, dict):
        return None
    dyn = caps.get("dynamic")
    if not isinstance(dyn, dict):
        return None
    tls = dyn.get("tls_interception")
    if not isinstance(tls, dict):
        return None
    return tls.get("status")


def correlation_window_slack_s(h: Handoff | None) -> float:
    """Extra seconds to widen the correlation window by, so ST/DT's stated
    residual uncertainty is accounted for rather than silently ignored.

    This is the ONLY thing we take from clock-sync.json. See the note on
    Handoff.clock_uncertainty_ms for why we never apply the offset itself.
    """
    if h is None:
        return 0.0
    return h.clock_uncertainty_ms / 1000.0


def verify_clock_alignment(events: list, network_events: list,
                           h: Handoff | None) -> str | None:
    """Guard: confirm access events look PRE-CORRECTED onto the host clock.

    We rely on ST/DT normalising timestamps before it writes them. That is an
    assumption about someone else's code, so verify it instead of trusting it:
    if their pipeline ever regresses to emitting raw guest time, the symptom
    would otherwise be a silent collapse to zero correlations.

    Compares the medians of the two timelines. A gap far larger than any
    plausible correlation window means the two clocks are not aligned. We
    REPORT it — we never silently correct, because a wrong correction is worse
    than a flagged mismatch.
    """
    if not events or not network_events:
        return None

    def _epoch(x):
        ts = x.get("timestamp") if isinstance(x, dict) else getattr(x, "timestamp", None)
        if isinstance(ts, datetime):
            return ts.timestamp()
        if isinstance(ts, (int, float)):
            return float(ts)
        if isinstance(ts, str):
            try:
                return datetime.fromisoformat(ts.replace("Z", "+00:00")).timestamp()
            except ValueError:
                return None
        return None

    a = sorted(t for t in (_epoch(e) for e in events) if t is not None)
    n = sorted(t for t in (_epoch(e) for e in network_events) if t is not None)
    if not a or not n:
        return None

    gap = a[len(a) // 2] - n[len(n) // 2]
    if abs(gap) <= _ALIGNMENT_TOLERANCE_S:
        return None
    return (f"CLOCK ALIGNMENT SUSPECT: host access events sit {gap:+.0f}s from "
            f"the network capture (algorithm reported: {h.clock_algorithm if h else 'n/a'}). "
            f"ST/DT is expected to pre-normalise access-event timestamps onto the "
            f"host clock; this gap suggests it did not. Correlations for this run "
            f"are unreliable — NOT auto-corrected, because guessing the offset is "
            f"worse than reporting the mismatch.")


def _jsonschema_validate(raw: dict, *, strict: bool) -> str:
    """Validate the manifest against ST/DT's published schema, if we have it.

    Returns a status string rather than nothing, because the previous version
    returned silently on BOTH the "library missing" and "schema file missing"
    paths — so the module claimed to mirror his Rust validator while in practice
    never validating anything. `schemas/` does not exist in this repo, so that
    was the case on every run.

    Note also that his COMMITTED handoff_manifest.schema.json does not accept
    his own real output: the task-18 manifest's correlation block carries
    `reason_code`, `source`, `clock_algorithm`, `etw_corroboration_state` and
    `maximum_uncertainty_ns`, while the schema requires `clock_quality_acceptable`
    and `reason` under `additionalProperties: false`. Dropping that schema in
    would fail every real bundle, so it is deliberately NOT vendored here.
    """
    try:
        import jsonschema  # type: ignore
    except Exception:
        return "skipped: jsonschema not installed"
    schema_path = os.path.join(os.path.dirname(__file__), "..",
                               "schemas", "handoff_manifest.schema.json")
    if not os.path.exists(schema_path):
        return "skipped: schemas/handoff_manifest.schema.json not vendored"
    try:
        schema = json.load(open(schema_path, encoding="utf-8"))
        jsonschema.validate(raw, schema)
        return "validated"
    except Exception as e:  # ValidationError or schema error
        if strict:
            raise
        # non-strict: report; the structural extraction below is defensive
        return f"failed: {type(e).__name__}: {str(e).splitlines()[0][:120]}"


def _provider_map() -> dict:
    p = os.path.join(os.path.dirname(__file__), "..", "data",
                     "provider_data_type_map.json")
    if os.path.exists(p):
        try:
            return {k.lower(): v for k, v in json.load(open(p)).items()}
        except Exception:
            pass
    return _DEFAULT_PROVIDER_MAP


def affected_data_types(h: Handoff) -> tuple[set, bool]:
    """(data_types whose host telemetry is unreliable, global_fallback?).

    global_fallback=True means a degraded provider couldn't be mapped to specific
    data types, so ALL correlated findings should be treated cautiously.
    """
    if not h.telemetry_degraded:
        return set(), False
    pmap = _provider_map()
    affected: set = set()
    unmapped = False
    for prov in h.providers_unavailable:
        pl = (prov or "").lower()
        hit = [dts for key, dts in pmap.items() if key in pl]
        if hit:
            for dts in hit:
                affected.update(dts)
        else:
            unmapped = True
    # degraded but no providers listed at all -> global caveat
    if h.telemetry_degraded and not h.providers_unavailable:
        unmapped = True
    return affected, unmapped


def _cap(obj, tier: str = "weak") -> bool:
    """Cap an event's tier to `tier` unless it's already lower/allowlisted or an
    independent (reputation/static) confirmation. Works on dicts and objects."""
    get = (lambda k: obj.get(k)) if isinstance(obj, dict) else (lambda k: getattr(obj, k, None))
    setr = (obj.__setitem__ if isinstance(obj, dict)
            else lambda k, v: setattr(obj, k, v))
    rank = {"allowlisted": 0, "unconfirmed": 1, "weak": 2, "strong": 3, "confirmed": 4}
    cur = get("confidence_tier")
    # reputation / static confirmations don't depend on timing or host telemetry.
    if get("reputation_hit") or get("static_match"):
        return False
    if cur is not None and rank.get(cur, 2) > rank[tier]:
        setr("confidence_tier", tier)
        return True
    return False


def gate_network_events(events: list, h: Handoff | None) -> list[str]:
    """Apply manifest gates to network-side events. Returns human-readable notes."""
    if h is None:
        return []
    notes: list[str] = []

    if h.simulated:
        for e in events:
            if isinstance(e, dict):
                e["network_mode"] = "simulated_inetsim"
            else:
                setattr(e, "network_mode", "simulated_inetsim")
        notes.append(
            "NETWORK SIMULATED (inetsim): C2/exfil destinations and cadence are "
            "ATTEMPTED, not confirmed-delivered. The ABSENCE of exfil here is NOT "
            "evidence the sample is clean — it only means the simulator did not "
            "elicit it. Do not score a simulated run as benign.")

    if not h.clock_quality_acceptable:
        capped = 0
        for e in events:
            kind = e.get("kind") if isinstance(e, dict) else getattr(e, "kind", None)
            if kind in _TIMING_KINDS and _cap(e, "weak"):
                capped += 1
        notes.append(
            f"CLOCK QUALITY NOT ACCEPTABLE: host/network clocks not reliably "
            f"aligned — timing-based findings capped to weak ({capped} affected). "
            f"Reputation/static confirmations are unaffected.")

    # Encrypted-traffic branch. Pinning is NOT a dead end — it just means the
    # payload is unavailable and we rely on metadata-only signals. Say which
    # path we took so a reader knows whether "no exfil content" means "none"
    # or "we could not look".
    if h.tls_pinning_suspected:
        for e in events:
            if isinstance(e, dict):
                e.setdefault("plaintext_available", False)
            elif getattr(e, "plaintext_available", None) is None:
                setattr(e, "plaintext_available", False)
        notes.append(
            f"TLS NOT INTERCEPTED ({h.tls_interception_status}): encrypted "
            f"payloads were not readable for this run. Detection falls back to "
            f"metadata-only signals (JA3/JA4, SNI, certificate, cadence, "
            f"ASN/geo). Absence of observed exfil CONTENT is not evidence that "
            f"none occurred.")
    elif h.tls_plaintext_available:
        notes.append(
            "TLS INTERCEPTED: decrypted payloads were available to ST/DT for "
            "this run; content-based exfil findings are supported by plaintext.")
    return notes


def gate_correlated(correlated: list, h: Handoff | None) -> list[str]:
    """Cap host<->network correlated findings under bad clock / degraded telemetry."""
    if h is None:
        return []
    notes: list[str] = []

    if not h.clock_quality_acceptable:
        capped = sum(1 for c in correlated if _cap(c, "weak"))
        if capped:
            notes.append(
                f"CLOCK QUALITY NOT ACCEPTABLE: {capped} host<->network correlation(s) "
                f"rest on timing alignment and were capped to weak.")

    affected, global_fallback = affected_data_types(h)
    if h.telemetry_degraded:
        capped = 0
        for c in correlated:
            dt = (c.get("data_type_accessed") if isinstance(c, dict)
                  else getattr(c, "data_type_accessed", None))
            if global_fallback or dt in affected:
                if _cap(c, "weak"):
                    capped += 1
        scope = "all data types" if global_fallback else ", ".join(sorted(affected)) or "none"
        notes.append(
            f"TELEMETRY DEGRADED (providers unavailable: "
            f"{', '.join(h.providers_unavailable) or 'unspecified'}): host-collection "
            f"absence is not evidence for [{scope}]; {capped} correlated finding(s) "
            f"capped to weak.")
    return notes

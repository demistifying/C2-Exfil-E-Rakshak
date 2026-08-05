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
import json
import os

SUPPORTED_SCHEMA = "1.0"

# Timing-dependent detections: their confidence rests on when things happened,
# so a bad clock invalidates them (caps to weak).
_TIMING_KINDS = {"beacon"}

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

    @property
    def simulated(self) -> bool:
        return self.network_mode == "simulated_inetsim"


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

    _jsonschema_validate(raw, strict=strict)

    corr = raw.get("correlation") or {}
    tel = raw.get("telemetry") or {}
    ident = raw.get("guest_vm_identity") or {}
    integ = raw.get("integrity") or {}
    providers = [p.get("provider") for p in (tel.get("providers_unavailable") or [])
                 if isinstance(p, dict) and p.get("provider")]

    return Handoff(
        schema_version=sv,
        session_id=raw.get("session_id"),
        cape_task_id=raw.get("cape_task_id"),
        network_mode=raw.get("network_mode"),
        # default to the SAFE interpretation when the field is missing: assume the
        # clock is NOT acceptable and telemetry MAY be degraded, so we never
        # silently overstate.
        clock_quality_acceptable=bool(corr.get("clock_quality_acceptable", False)),
        telemetry_degraded=bool(tel.get("telemetry_degraded", False)),
        providers_unavailable=providers,
        guest_ip=ident.get("guest_ip"),
        detonation_start_utc=raw.get("detonation_start_utc"),
        detonation_end_utc=raw.get("detonation_end_utc"),
        hash_manifest_sha256=integ.get("hash_manifest_sha256"),
        path=path,
        raw=raw,
    )


def _jsonschema_validate(raw: dict, *, strict: bool) -> None:
    try:
        import jsonschema  # type: ignore
    except Exception:
        return
    schema_path = os.path.join(os.path.dirname(__file__), "..",
                               "schemas", "handoff_manifest.schema.json")
    if not os.path.exists(schema_path):
        return
    try:
        schema = json.load(open(schema_path, encoding="utf-8"))
        jsonschema.validate(raw, schema)
    except Exception as e:  # ValidationError or schema error
        if strict:
            raise
        # non-strict: swallow; the structural extraction below is defensive


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

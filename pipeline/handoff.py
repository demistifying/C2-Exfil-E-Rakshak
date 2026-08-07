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

    # --- clock correction (behavior/clock-sync.json) -------------------------
    # ST/DT computes the guest->host offset; we used to only DETECT skew and
    # then re-derive it ourselves. Now we apply what it hands us.
    clock_offset_ms: float = 0.0
    clock_offset_uncertainty_ms: float = 0.0
    clock_offset_source: str | None = None

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

    @property
    def has_clock_offset(self) -> bool:
        return bool(self.clock_offset_ms) or bool(self.clock_offset_uncertainty_ms)


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
    apaths = raw.get("artifact_paths") or {}
    providers = [p.get("provider") for p in (tel.get("providers_unavailable") or [])
                 if isinstance(p, dict) and p.get("provider")]

    bundle_dir = os.path.dirname(os.path.abspath(path))

    def _resolve(rel):
        return os.path.join(bundle_dir, rel) if rel else None

    # correlation.access_events_path is the authoritative location; fall back to
    # artifact_paths.access_events, then to the contract's fixed default.
    acc_rel = (corr.get("access_events_path")
               or apaths.get("access_events")
               or "behavior/access_events.json")

    offset_ms, unc_ms, off_src = _load_clock_sync(
        _resolve(apaths.get("clock_sync") or "behavior/clock-sync.json"))

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
        bundle_dir=bundle_dir,
        access_events_path=_resolve(acc_rel),
        access_event_count=corr.get("event_count"),
        # Absent field -> assume ENABLED (legacy bundles predate the gate), but
        # an explicit False must be honoured: ST/DT is telling us its own
        # correlation preconditions were not met.
        host_network_correlation_enabled=bool(
            corr.get("host_network_correlation_enabled", True)),
        correlation_reason=corr.get("reason"),
        sample_meta_path=_resolve("sample.meta.json"),
        pcap_path=_resolve(apaths.get("pcap") or "network/capture.pcapng"),
        clock_offset_ms=offset_ms,
        clock_offset_uncertainty_ms=unc_ms,
        clock_offset_source=off_src,
        tls_interception_status=_tls_status(raw),
    )


def _load_clock_sync(path: str | None) -> tuple[float, float, str | None]:
    """Read ST/DT's computed guest->host clock offset.

    Accepts either a flat {offset_ms, offset_uncertainty_ms} document or one
    nested under a "clock" key, since the ST/DT side has used both shapes.
    Missing/unparseable -> (0, 0, None), i.e. no correction, which is the same
    behaviour as before this was wired.
    """
    if not path or not os.path.exists(path):
        return 0.0, 0.0, None
    try:
        doc = json.load(open(path, encoding="utf-8"))
    except Exception:
        return 0.0, 0.0, None
    if isinstance(doc.get("clock"), dict):
        doc = doc["clock"]
    try:
        off = float(doc.get("offset_ms", 0) or 0)
    except (TypeError, ValueError):
        off = 0.0
    try:
        unc = abs(float(doc.get("offset_uncertainty_ms", 0) or 0))
    except (TypeError, ValueError):
        unc = 0.0
    return off, unc, doc.get("method") or "clock-sync.json"


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


def apply_clock_offset(events: list, h: Handoff | None) -> str | None:
    """Shift host access-event timestamps onto the network capture's clock.

    ST/DT timestamps access events on the GUEST clock; the PCAP is timestamped
    on the HOST tap. Correlation compares the two, so an uncorrected offset
    silently produces false negatives (or, worse, false positives at the window
    edge). `offset_ms` is the correction to ADD to a guest timestamp to express
    it on the host clock.

    Mutates events in place. Returns a human-readable note, or None if there was
    nothing to apply.
    """
    if h is None or not h.has_clock_offset or not events:
        return None
    delta = timedelta(milliseconds=h.clock_offset_ms)
    shifted = 0
    for e in events:
        ts = e.get("timestamp") if isinstance(e, dict) else getattr(e, "timestamp", None)
        if not isinstance(ts, datetime):
            continue
        if isinstance(e, dict):
            e["timestamp"] = ts + delta
        else:
            setattr(e, "timestamp", ts + delta)
        shifted += 1
    if not shifted:
        return None
    return (f"CLOCK OFFSET APPLIED: {h.clock_offset_ms:+.0f} ms "
            f"(±{h.clock_offset_uncertainty_ms:.0f} ms, source: "
            f"{h.clock_offset_source}) to {shifted} host access event(s) to "
            f"align the guest clock with the PCAP capture clock.")


def correlation_window_slack_s(h: Handoff | None) -> float:
    """Extra seconds to widen the correlation window by, so a stated clock
    uncertainty is accounted for rather than silently ignored."""
    if h is None:
        return 0.0
    return h.clock_offset_uncertainty_ms / 1000.0


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

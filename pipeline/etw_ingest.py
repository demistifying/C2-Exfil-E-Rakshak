"""
etw_ingest.py — ingestion + validation front door for ETW host-access events.

============================ CROSS-MODULE INTERFACE ==========================
This module is the integration point between the Windows ST/DT (sandbox) module
and the C2/Exfiltration module. The sandbox captures host data-access events via
ETW (Event Tracing for Windows) during detonation and hands them off as a JSON
array. THIS module ingests that array, validates it against the contract, maps
each access to its ATT&CK technique, and feeds correlation.

Sandbox team: your output is correct if `validate_file()` passes with zero
errors. Run it directly:

    python pipeline/etw_ingest.py your_access_events.json output/network_events.json

`docs/etw_interface_contract.md` is the prose contract; THIS file is its
executable reference implementation. If the two ever disagree, this wins,
because this is what actually runs.

------------------------------------------------------------------------------
Event schema (one JSON object per host access):

    {
      "timestamp": "2026-02-03T16:13:59.366315+00:00",  # REQUIRED, ISO-8601 UTC
      "data_type": "browser_credentials",                # REQUIRED, see enum
      "api_call":  "CryptUnprotectData",                 # REQUIRED
      "process":   "stealer.exe"                          # optional
    }
==============================================================================
"""

from __future__ import annotations
from dataclasses import dataclass, field
from datetime import datetime, timezone
import json
import os


# ---- Detection layer: host capability -> ATT&CK technique -------------------
# Mapping a raw access event to the malicious capability it represents is the
# host-side "detection". Keep this the single source of truth for data_type
# semantics across the module.
DATA_TYPE_TECHNIQUE: dict[str, tuple[str, str]] = {
    # data_type            (ATT&CK id,  human-readable capability)
    "browser_credentials": ("T1555.003", "Credentials from Web Browsers"),
    "keystrokes":          ("T1056.001", "Keylogging"),
    "screenshot":          ("T1113",     "Screen Capture"),
    "clipboard":           ("T1115",     "Clipboard Data"),
    "crypto_wallet":       ("T1005",     "Data from Local System (crypto wallet)"),
    "system_info":         ("T1082",     "System Information Discovery"),
    "file_access":         ("T1005",     "Data from Local System (sensitive file)"),
}

VALID_DATA_TYPES = frozenset(DATA_TYPE_TECHNIQUE)

# The correlation engine matches an access event to a network event that starts
# within this many seconds AFTER it. Shared with correlation.py.
CORRELATION_WINDOW_S = 15


# ---- Event model -----------------------------------------------------------

@dataclass
class ETWAccessEvent:
    """A validated host access event, enriched with its ATT&CK technique."""
    timestamp: datetime            # parsed, timezone-aware (UTC)
    data_type: str
    api_call: str
    process: str | None = None
    raw_timestamp: str = ""        # original string, preserved for evidence
    mitre_technique: str | None = None
    capability: str | None = None
    # WHAT was touched, not merely that something was. WinST/DT's
    # 0003-rich-access-event-context patch added these; before it, an event
    # carried only {timestamp, data_type, api_call, process}, so a report could
    # say "file accessed via NtCreateFile" 171 times without ever naming a file.
    # Optional: older bundles predate the patch and must still load.
    object_path: str | None = None      # full path, e.g. C:\...\Login Data
    object_name: str | None = None      # leaf name, e.g. Login Data
    access_operation: str | None = None
    process_id: int | None = None
    process_path: str | None = None

    @property
    def object_label(self) -> str | None:
        """Shortest unambiguous name for the item touched."""
        return self.object_path or self.object_name or None

    def to_dict(self) -> dict:
        """Shape consumed by correlation.py (backward compatible)."""
        return {
            "timestamp": self.raw_timestamp or self.timestamp.isoformat(),
            "data_type": self.data_type,
            "api_call": self.api_call,
            "process": self.process,
            "mitre_technique": self.mitre_technique,
            "object_path": self.object_path,
            "object_name": self.object_name,
            "access_operation": self.access_operation,
            "process_id": self.process_id,
            "process_path": self.process_path,
        }


class ETWValidationError(ValueError):
    """Raised for a single malformed event (carries the index + reason)."""


@dataclass
class IngestReport:
    """Result of ingesting a batch of events: what loaded, what didn't, why."""
    events: list[ETWAccessEvent] = field(default_factory=list)
    errors: list[str] = field(default_factory=list)     # rejected events
    warnings: list[str] = field(default_factory=list)   # loaded-but-suspicious

    @property
    def ok(self) -> bool:
        return not self.errors

    def summary(self) -> str:
        return (f"{len(self.events)} valid event(s), "
                f"{len(self.errors)} error(s), {len(self.warnings)} warning(s)")


# ---- Validation / parsing --------------------------------------------------

def _parse_timestamp(value) -> datetime:
    if not isinstance(value, str):
        raise ETWValidationError(f"timestamp must be a string, got {type(value).__name__}")
    try:
        dt = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError as e:
        raise ETWValidationError(f"unparseable ISO-8601 timestamp {value!r}: {e}")
    if dt.tzinfo is None:
        # Local time without offset is ambiguous — the contract requires UTC.
        raise ETWValidationError(
            f"timestamp {value!r} has no timezone; UTC offset is required "
            f"(clock sync with PCAP timestamps depends on it)")
    return dt.astimezone(timezone.utc)


def parse_event(raw: dict, index: int = 0) -> ETWAccessEvent:
    """Validate and enrich a single raw event. Raises ETWValidationError."""
    if not isinstance(raw, dict):
        raise ETWValidationError(f"event[{index}] is not a JSON object")

    for req in ("timestamp", "data_type", "api_call"):
        if req not in raw or raw[req] in (None, ""):
            raise ETWValidationError(f"event[{index}] missing required field {req!r}")

    ts = _parse_timestamp(raw["timestamp"])

    data_type = raw["data_type"]
    if data_type not in VALID_DATA_TYPES:
        raise ETWValidationError(
            f"event[{index}] invalid data_type {data_type!r}; "
            f"expected one of {sorted(VALID_DATA_TYPES)}")

    technique, capability = DATA_TYPE_TECHNIQUE[data_type]
    return ETWAccessEvent(
        timestamp=ts,
        data_type=data_type,
        api_call=str(raw["api_call"]),
        process=raw.get("process") or None,
        raw_timestamp=raw["timestamp"],
        mitre_technique=technique,
        capability=capability,
        object_path=_optional_str(raw.get("object_path")),
        object_name=_optional_str(raw.get("object_name")),
        access_operation=_optional_str(raw.get("access_operation")),
        process_id=raw.get("process_id") if isinstance(raw.get("process_id"), int) else None,
        process_path=_optional_str(raw.get("process_path")),
    )


def _optional_str(value: object) -> str | None:
    """Trimmed string, or None. Never raises — these fields are optional and a
    bundle produced before the rich-context patch simply omits them."""
    if value is None:
        return None
    text = str(value).strip()
    return text or None


def ingest(raw_events, *, strict: bool = False) -> IngestReport:
    """Validate a list of raw events. In non-strict mode, bad events are
    skipped and recorded in the report so one malformed row can't take the
    whole handoff down. In strict mode the first error raises."""
    report = IngestReport()
    if not isinstance(raw_events, list):
        report.errors.append("top-level JSON must be an array of events")
        return report
    for i, raw in enumerate(raw_events):
        try:
            report.events.append(parse_event(raw, i))
        except ETWValidationError as e:
            if strict:
                raise
            report.errors.append(str(e))
    report.events.sort(key=lambda e: e.timestamp)
    return report


def load_etw_events(path: str, *, strict: bool = False) -> IngestReport:
    """Load + validate an ETW access-event JSON file."""
    if not os.path.exists(path):
        r = IngestReport()
        r.errors.append(f"file not found: {path}")
        return r
    try:
        with open(path) as fh:
            raw = json.load(fh)
    except json.JSONDecodeError as e:
        r = IngestReport()
        r.errors.append(f"invalid JSON in {path}: {e}")
        return r
    return ingest(raw, strict=strict)


# ---- Clock-sync assessment -------------------------------------------------

@dataclass
class ClockSyncReport:
    access_span: tuple[str, str] | None
    network_span: tuple[str, str] | None
    min_forward_delta_s: float | None   # smallest (network_ts - access_ts) >= 0
    correlatable: bool                   # any network event within window of an access
    likely_skew: bool
    note: str


def assess_clock_sync(events: list[ETWAccessEvent],
                      network_events: list[dict],
                      window_s: int = CORRELATION_WINDOW_S) -> ClockSyncReport:
    """Flag clock skew between host and network timelines.

    Correlation matches a network event that starts within `window_s` after an
    access event. If the two clocks are skewed, real exfil silently fails to
    correlate — a false negative that looks like "no correlation" rather than
    "broken input". This surfaces it explicitly before correlation runs.
    """
    def _pt(n):
        return datetime.fromisoformat(str(n["timestamp"]).replace("Z", "+00:00"))

    if not events or not network_events:
        return ClockSyncReport(None, None, None, False, False,
                               "insufficient data to assess clock sync")

    acc_ts = [e.timestamp for e in events]
    net_ts = []
    for n in network_events:
        try:
            net_ts.append(_pt(n))
        except (ValueError, KeyError):
            continue
    if not net_ts:
        return ClockSyncReport(None, None, None, False, False,
                               "no parseable network timestamps")

    # Smallest non-negative forward delta across all access→network pairs, and
    # whether any pair lands inside the correlation window.
    min_fwd = None
    correlatable = False
    for a in acc_ts:
        for n in net_ts:
            d = (n - a).total_seconds()
            if d >= 0 and (min_fwd is None or d < min_fwd):
                min_fwd = d
            if 0 <= d <= window_s:
                correlatable = True

    acc_span = (min(acc_ts).isoformat(), max(acc_ts).isoformat())
    net_span = (min(net_ts).isoformat(), max(net_ts).isoformat())

    # Heuristic: if nothing is correlatable but there IS a forward pair, and the
    # closest one is far beyond the window, the clocks are probably skewed.
    likely_skew = False
    note = "clocks appear aligned"
    if not correlatable:
        if min_fwd is not None and min_fwd > window_s:
            likely_skew = True
            note = (f"no access→network pair within {window_s}s; closest is "
                    f"{min_fwd:.1f}s — likely clock skew or misaligned captures")
        else:
            note = ("no network events occur after any access event; "
                    "either no exfil followed the accesses, or timelines don't overlap")
    return ClockSyncReport(acc_span, net_span,
                           round(min_fwd, 2) if min_fwd is not None else None,
                           correlatable, likely_skew, note)


# ---- CLI: the tool the sandbox team runs to check their integration --------

def validate_file(access_path: str, network_path: str | None = None) -> int:
    """Print a human-readable validation report. Returns a process exit code
    (0 = clean, 1 = errors) so it can gate CI."""
    report = load_etw_events(access_path)
    print(f"[etw_ingest] {access_path}")
    print(f"  {report.summary()}")
    for e in report.errors:
        print(f"  ERROR:   {e}")
    for w in report.warnings:
        print(f"  WARNING: {w}")

    if report.events:
        print("  parsed events:")
        for ev in report.events:
            proc = f" [{ev.process}]" if ev.process else ""
            print(f"    {ev.raw_timestamp}  {ev.data_type:20} "
                  f"{ev.mitre_technique:10} {ev.api_call}{proc}")

    if network_path and os.path.exists(network_path):
        try:
            net = json.load(open(network_path))
        except json.JSONDecodeError:
            net = []
        sync = assess_clock_sync(report.events, net)
        print("  clock sync:")
        print(f"    access window : {sync.access_span}")
        print(f"    network window: {sync.network_span}")
        print(f"    correlatable  : {sync.correlatable}"
              + (f"  (closest forward Δ = {sync.min_forward_delta_s}s)"
                 if sync.min_forward_delta_s is not None else ""))
        flag = "  <-- CHECK CLOCK SYNC" if sync.likely_skew else ""
        print(f"    verdict       : {sync.note}{flag}")

    return 0 if report.ok else 1


if __name__ == "__main__":
    import sys
    acc = sys.argv[1] if len(sys.argv) > 1 else "data/access_events_fixture.json"
    net = sys.argv[2] if len(sys.argv) > 2 else "output/network_events.json"
    raise SystemExit(validate_file(acc, net))

"""
timeline.py — unified host+network kill-chain timeline (E3).

Correlation answers "what linked to what"; the timeline answers "tell me the
story in order." It merges host access events (ETW) and network findings into a
single time-ordered sequence, each entry annotated with its ATT&CK technique and
kill-chain phase, so an analyst (or a report) can read the incident start to
finish: collection on the host, then exfiltration/C2 on the network.
"""

from __future__ import annotations
from dataclasses import dataclass, asdict
from datetime import datetime

# ATT&CK technique -> coarse kill-chain phase (for grouping/readability)
_PHASE = {
    "T1555": "collection", "T1555.003": "collection", "T1056.001": "collection",
    "T1113": "collection", "T1115": "collection", "T1005": "collection",
    "T1082": "discovery", "T1074": "collection",
    "T1041": "exfiltration", "T1048": "exfiltration", "T1048.003": "exfiltration",
    "T1567": "exfiltration", "T1567.002": "exfiltration", "T1071.004": "exfiltration",
    "T1071.001": "command-and-control", "T1571": "command-and-control",
    "T1573": "command-and-control", "T1095": "command-and-control",
    "T1568.002": "command-and-control", "T1105": "staging", "T1572": "exfiltration",
}


@dataclass
class TimelineEntry:
    timestamp: str
    actor: str                 # "host" | "network"
    phase: str                 # collection / exfiltration / command-and-control / ...
    mitre: str | None
    description: str
    tier: str | None = None


def _dt(ts):
    try:
        return datetime.fromisoformat(str(ts).replace("Z", "+00:00"))
    except Exception:
        return datetime.max.replace(tzinfo=None)


def build_timeline(access_events, network_events, mitre_map=None) -> list[TimelineEntry]:
    """Merge host access events + network findings into one ordered timeline."""
    mitre_map = mitre_map or {}
    entries: list[TimelineEntry] = []

    for a in access_events:
        ts = getattr(a, "raw_timestamp", None) or getattr(a, "timestamp", None)
        if hasattr(ts, "isoformat"):
            ts = ts.isoformat()
        tech = (getattr(a, "mitre_technique", None)
                or (a.get("mitre_technique") if isinstance(a, dict) else None))
        dt = getattr(a, "data_type", None) or (a.get("data_type") if isinstance(a, dict) else None)
        api = getattr(a, "api_call", None) or (a.get("api_call") if isinstance(a, dict) else None)
        entries.append(TimelineEntry(
            timestamp=str(ts), actor="host", phase=_PHASE.get(tech, "collection"),
            mitre=tech, description=f"host accessed {dt} via {api}"))

    for e in network_events:
        tech = mitre_map.get(e.get("kind"))
        who = e.get("destination_domain") or e.get("dst_ip")
        desc = f"{e.get('kind')} to {who}"
        det = (e.get("http_reason") or e.get("dns_evidence")
               or e.get("cloud_service") or e.get("covert_detail")
               or e.get("smtp_subject"))
        if det:
            desc += f" ({det})"
        entries.append(TimelineEntry(
            timestamp=str(e.get("timestamp")), actor="network",
            phase=_PHASE.get(tech, "exfiltration"), mitre=tech,
            description=desc, tier=e.get("confidence_tier")))

    entries.sort(key=lambda x: _dt(x.timestamp))
    return entries


def timeline_to_dicts(entries) -> list[dict]:
    return [asdict(e) for e in entries]


def render_timeline(entries) -> str:
    lines = []
    for e in entries:
        tier = f" [{e.tier}]" if e.tier else ""
        mitre = f" {e.mitre}" if e.mitre else ""
        lines.append(f"  {e.timestamp}  {e.actor:7} {e.phase:20}{mitre:11} "
                     f"{e.description}{tier}")
    return "\n".join(lines)

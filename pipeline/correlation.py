"""
correlation.py — Windows C2/Exfiltration module, host-to-network correlation.

This is the module's core novel stage: it links WHAT the malware accessed on the
host (credential stores, keystrokes, screenshots) to WHERE it sent data, by
matching the host access timeline against the network exfil timeline.

================= CROSS-MODULE INTERFACE (the one real dependency) ============
Host access events come from the Windows ST/DT module's ETW capture, handed off
via the shared store. The contract is the AccessEvent schema below. Until the
sandbox emits real ETW data, this stage runs against a documented fixture file
of the SAME schema, so the logic is built, tested, and ready — the only thing
that changes at integration time is the source of the access events, not this
code.

    AccessEvent = {
        "timestamp":   ISO8601 str,   # when the access happened
        "data_type":   str,           # browser_credentials | keystrokes | ...
        "api_call":    str,           # the ETW-observed API, e.g. CryptUnprotectData
        "process":     str,           # optional: observed process name
    }
==============================================================================
"""

from __future__ import annotations
from dataclasses import dataclass, asdict
from datetime import datetime
import json


TIME_WINDOW_SECONDS = 15  # tune against labeled reference samples


@dataclass
class CorrelatedEvent:
    data_type_accessed: str
    access_api_call: str
    access_ts: str
    destination_ip: str
    destination_port: int
    network_ts: str
    time_delta_s: float
    network_confidence: float      # from beaconing/exfil detection
    reputation_hit: bool
    correlation_confidence: float  # combined score
    confidence_tier: str           # confirmed | strong | weak | unconfirmed


def _parse(ts: str) -> datetime:
    return datetime.fromisoformat(ts.replace("Z", "+00:00"))


def _tier(corr_conf: float, reputation_hit: bool, has_timing: bool) -> str:
    """Canonical 4-tier scale, shared across Windows and Android modules."""
    if reputation_hit and corr_conf >= 0.6:
        return "confirmed"          # independent intel hit + behavioral link
    if has_timing and corr_conf >= 0.6:
        return "strong"             # strong timing/size lineage, no intel hit
    if has_timing and corr_conf > 0:
        return "weak"               # co-occurrence only (valid terminal state)
    return "unconfirmed"


def correlate(access_events: list[dict],
              network_events: list[dict],
              window_s: int = TIME_WINDOW_SECONDS) -> list[CorrelatedEvent]:
    """
    For each host access event, find network exfil events that started within
    `window_s` AFTER it. Temporal proximity is the base signal; a reputation
    hit and higher network confidence raise the combined score and tier.
    """
    results: list[CorrelatedEvent] = []
    for acc in access_events:
        acc_t = _parse(acc["timestamp"])
        for net in network_events:
            net_t = _parse(net["timestamp"])
            delta = (net_t - acc_t).total_seconds()
            if not (0 <= delta <= window_s):
                continue
            # Base: closer in time => higher. Then boost on network confidence
            # and reputation.
            proximity = 1.0 - (delta / window_s) * 0.5
            net_conf = float(net.get("confidence", 0.5))
            rep_hit = bool(net.get("reputation_hit", False))
            corr = proximity * 0.5 + net_conf * 0.3 + (0.2 if rep_hit else 0.0)
            corr = round(min(corr, 1.0), 2)
            results.append(CorrelatedEvent(
                data_type_accessed=acc["data_type"],
                access_api_call=acc["api_call"],
                access_ts=acc["timestamp"],
                destination_ip=net["dst_ip"],
                destination_port=int(net.get("dst_port", 0)),
                network_ts=net["timestamp"],
                time_delta_s=round(delta, 2),
                network_confidence=round(net_conf, 2),
                reputation_hit=rep_hit,
                correlation_confidence=corr,
                confidence_tier=_tier(corr, rep_hit, has_timing=True),
            ))
    return results


if __name__ == "__main__":
    import sys
    acc_path = sys.argv[1] if len(sys.argv) > 1 else "data/access_events_fixture.json"
    net_path = sys.argv[2] if len(sys.argv) > 2 else "output/network_events.json"
    with open(acc_path) as f:
        access_events = json.load(f)
    with open(net_path) as f:
        network_events = json.load(f)
    for c in correlate(access_events, network_events):
        print(json.dumps(asdict(c)))

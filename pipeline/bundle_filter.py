"""
bundle_filter.py — scope an AnalysisBundle to the detonated guest + time window.

A CAPE capture can contain traffic that isn't the sample's: other VMs on the
analysis network, host management chatter, and packets from before the sample
ran or after it was killed. Correlating or flagging any of that is a false
positive waiting to happen. The handoff manifest tells us exactly which VM ran
the sample (`guest_vm_identity.guest_ip`) and when (`detonation_start_utc` ..
`detonation_end_utc`), so we keep only flows where the guest is a participant
AND that fall inside the detonation window.

Guarded: only the parameters that are actually supplied filter anything — no
guest_ip means no IP filtering, no window means no time filtering — so a bare
pcap run (no manifest) is completely unaffected.
"""

from __future__ import annotations
from datetime import datetime
from collections import Counter
import ipaddress

# guest_ip values that mean "not populated" — must NOT be used to filter, or we
# would drop every flow (a real regression seen on task-18 where guest_ip was
# the literal string "unknown").
GUEST_IP_SENTINELS = {"", "unknown", "none", "n/a", "null"}


def _norm_guest_ip(guest_ip):
    if guest_ip is None:
        return None
    return None if str(guest_ip).strip().lower() in GUEST_IP_SENTINELS else guest_ip


def _is_private(ip: str) -> bool:
    try:
        a = ipaddress.ip_address(ip)
        return a.is_private or a.is_loopback or a.is_link_local
    except ValueError:
        return False


def _is_noise(ip: str) -> bool:
    """Broadcast / multicast / reserved / all-hosts — never a C2 endpoint."""
    try:
        a = ipaddress.ip_address(ip)
        return (a.is_multicast or a.is_reserved or a.is_unspecified
                or a.is_link_local or ip.endswith(".255") or ip.endswith(".0"))
    except ValueError:
        return False


def infer_guest_ip(bundle) -> str | None:
    """Best-effort guest VM IP when the manifest didn't populate it: the private
    address that originates the most sessions (the detonated VM)."""
    c: Counter = Counter()
    for s in getattr(bundle, "sessions", []) or []:
        ip = getattr(s, "src_ip", None)
        if ip and _is_private(ip):
            c[ip] += 1
    return c.most_common(1)[0][0] if c else None


def simulated_c2_scope(bundle, guest_ip: str | None) -> set:
    """Private destinations the guest actually contacted, minus the guest itself
    and broadcast/multicast noise.

    Under `simulated_inetsim` the sample's C2 is answered by a local simulator on
    a PRIVATE address, which the normal private-IP filter would discard. These
    are exactly the endpoints we must still analyse (attempted C2/exfil), so this
    set is fed to the detectors as an allow-list."""
    scope: set = set()
    for s in getattr(bundle, "sessions", []) or []:
        if guest_ip and getattr(s, "src_ip", None) != guest_ip:
            continue
        d = getattr(s, "dst_ip", None)
        if d and _is_private(d) and d != guest_ip and not _is_noise(d):
            scope.add(d)
    return scope


def _epoch(utc_str):
    if not utc_str:
        return None
    try:
        return datetime.fromisoformat(str(utc_str).replace("Z", "+00:00")).timestamp()
    except ValueError:
        return None


def filter_bundle(bundle, guest_ip=None, start_utc=None, end_utc=None) -> dict:
    """Filter every record list in `bundle` in place. Returns a removal summary."""
    guest_ip = _norm_guest_ip(guest_ip)      # "unknown"/"" -> no IP filtering
    start = _epoch(start_utc)
    end = _epoch(end_utc)
    if not guest_ip and start is None and end is None:
        return {"removed": 0, "kept": _total(bundle), "applied": False}

    def keep(rec) -> bool:
        if guest_ip:
            if guest_ip not in (getattr(rec, "src_ip", None),
                                getattr(rec, "dst_ip", None)):
                return False
        ts = getattr(rec, "ts", None)
        if ts is not None and isinstance(ts, (int, float)):
            if start is not None and ts < start:
                return False
            if end is not None and ts > end:
                return False
        return True

    removed = 0
    for attr in ("sessions", "dns", "http", "tls", "ftp", "smtp"):
        lst = getattr(bundle, attr, None)
        if lst is None:
            continue
        before = len(lst)
        setattr(bundle, attr, [r for r in lst if keep(r)])
        removed += before - len(getattr(bundle, attr))

    # icmp entries are (src_ip, dst_ip, data_len) tuples with no timestamp —
    # filter on guest participation only.
    if guest_ip and getattr(bundle, "icmp", None):
        before = len(bundle.icmp)
        bundle.icmp = [t for t in bundle.icmp
                       if len(t) >= 2 and guest_ip in (t[0], t[1])]
        removed += before - len(bundle.icmp)

    return {"removed": removed, "kept": _total(bundle), "applied": True,
            "guest_ip": guest_ip, "window": [start_utc, end_utc]}


def _total(bundle) -> int:
    return sum(len(getattr(bundle, a, []) or [])
               for a in ("sessions", "dns", "http", "tls", "ftp", "smtp", "icmp"))

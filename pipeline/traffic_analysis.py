"""
traffic_analysis.py — Windows C2/Exfiltration module, traffic analysis stage.

Extracts connection records from a PCAP and derives the two network-side
signals the module depends on:
  * beaconing detection  — regular-interval callbacks (C2 check-in behavior)
  * exfil detection      — large outbound POSTs / high upload-ratio flows

DESIGN NOTE — Zeek interface:
In production this stage consumes Zeek's conn.log (and ja3.log). Zeek is the
authoritative parser. This module can ALSO parse a raw PCAP directly via scapy,
so the pipeline is runnable before Zeek is wired up and as a cross-check against
Zeek's output. The connection-record schema below is intentionally a subset of
Zeek's conn.log fields, so swapping the source is a drop-in change.
"""

from __future__ import annotations
from dataclasses import dataclass, field, asdict
from collections import defaultdict
import ipaddress
import statistics
import json


# RFC1918 + loopback + link-local — the only ranges that should never appear
# as C2 destinations in a sandbox capture.  We do NOT use is_private because
# Python marks documentation / TEST-NET ranges as private too, and those can
# legitimately appear in ground-truth test data or unusual real captures.
_INTERNAL_NETS = [
    # IPv4
    ipaddress.ip_network("10.0.0.0/8"),
    ipaddress.ip_network("172.16.0.0/12"),
    ipaddress.ip_network("192.168.0.0/16"),
    ipaddress.ip_network("127.0.0.0/8"),
    ipaddress.ip_network("169.254.0.0/16"),
    ipaddress.ip_network("0.0.0.0/8"),
    # IPv6 — loopback, link-local, and unique-local (RFC 4193). Global unicast
    # (2000::/3) is treated as public, exactly like an IPv4 routable address.
    ipaddress.ip_network("::1/128"),
    ipaddress.ip_network("fe80::/10"),
    ipaddress.ip_network("fc00::/7"),
]


def _is_private_ip(ip: str) -> bool:
    """True for RFC1918, loopback, link-local — never valid C2 destinations."""
    try:
        addr = ipaddress.ip_address(ip)
        return any(addr in net for net in _INTERNAL_NETS)
    except ValueError:
        return False


# Zeek conn.log subset — this is the interface contract with the Zeek stage.
@dataclass
class Connection:
    ts: float
    src_ip: str
    dst_ip: str
    dst_port: int
    proto: str
    orig_bytes: int = 0          # bytes sent by originator (victim -> dst)
    resp_bytes: int = 0          # bytes returned
    history: str = ""            # connection state flags
    http_method: str | None = None
    http_host: str | None = None
    http_uri: str | None = None
    ftp_upload_cmd: str | None = None   # observed FTP upload command, e.g. "STOR creds.txt"


@dataclass
class BeaconVerdict:
    dst_ip: str
    dst_port: int
    connection_count: int
    mean_interval_s: float
    interval_stddev_s: float
    jitter_ratio: float          # stddev / mean — low = regular = beacon-like
    is_beacon: bool
    confidence: float
    size_cv: float = 0.0         # coeff. of variation of request sizes (low = regular)


@dataclass
class ExfilVerdict:
    src_ip: str
    dst_ip: str
    dst_port: int
    orig_bytes: int
    upload_ratio: float          # orig_bytes / (orig_bytes + resp_bytes)
    http_method: str | None
    http_uri: str | None
    is_exfil: bool
    confidence: float


# ----- Beaconing detection -------------------------------------------------

def detect_beaconing(conns: list[Connection],
                     min_count: int = 4,
                     max_jitter_ratio: float = 0.25,
                     min_interval_s: float = 1.0) -> list[BeaconVerdict]:
    """
    Groups connections by destination and flags those with regular timing.
    A low jitter ratio (stddev of inter-arrival times / mean) is the classic
    signature of automated C2 check-ins, independent of payload content —
    so this works on encrypted traffic too.

    `min_interval_s` rejects the degenerate case of several near-simultaneous
    connections (mean interval ~0), which are parallel-connection bursts (e.g.
    a browser opening 4 sockets to a CDN), not periodic C2 check-ins. Without
    this guard those score a tiny jitter and masquerade as perfect beacons —
    a real false-positive source on live traffic.
    """
    by_dst: dict[tuple[str, int], list[tuple[float, int]]] = defaultdict(list)
    for c in conns:
        if _is_private_ip(c.dst_ip):
            continue
        by_dst[(c.dst_ip, c.dst_port)].append((c.ts, c.orig_bytes))

    verdicts: list[BeaconVerdict] = []
    for (dst_ip, dst_port), rows in by_dst.items():
        if len(rows) < min_count:
            continue
        rows.sort()
        times = [t for t, _ in rows]
        sizes = [s for _, s in rows]
        intervals = [t2 - t1 for t1, t2 in zip(times, times[1:])]
        mean_iv = statistics.mean(intervals)
        stddev_iv = statistics.pstdev(intervals) if len(intervals) > 1 else 0.0
        jitter = (stddev_iv / mean_iv) if mean_iv > 0 else 1.0
        # Payload-size regularity: real C2 beacons send similarly-sized check-ins.
        mean_sz = statistics.mean(sizes) if sizes else 0.0
        size_cv = (statistics.pstdev(sizes) / mean_sz) if mean_sz > 0 else 0.0
        is_beacon = (jitter <= max_jitter_ratio) and (mean_iv >= min_interval_s)
        # Confidence: tighter timing + more callbacks => higher; regular sizes
        # add a small corroboration boost.
        conf = 0.0
        if is_beacon:
            conf = ((1 - jitter / max_jitter_ratio) * 0.55
                    + min(len(times) / 10, 1.0) * 0.35
                    + (0.10 if size_cv < 0.1 else 0.0))
            conf = min(1.0, conf)
        verdicts.append(BeaconVerdict(
            dst_ip=dst_ip, dst_port=dst_port, connection_count=len(times),
            mean_interval_s=round(mean_iv, 2), interval_stddev_s=round(stddev_iv, 3),
            jitter_ratio=round(jitter, 3), is_beacon=is_beacon,
            confidence=round(conf, 2), size_cv=round(size_cv, 3),
        ))
    return verdicts


# ----- Exfiltration detection ----------------------------------------------

def detect_exfil(conns: list[Connection],
                 min_upload_bytes: int = 1024,
                 min_upload_ratio: float = 0.7,
                 min_raw_upload_bytes: int | None = None) -> list[ExfilVerdict]:
    """
    Flags flows that push a lot of data OUT relative to what comes back.
    Data exfiltration shows up as an abnormally high upload ratio and/or a
    large HTTP POST — the opposite of normal browsing (mostly downloads).
    """
    verdicts: list[ExfilVerdict] = []
    for c in conns:
        if _is_private_ip(c.dst_ip):
            continue
        total = c.orig_bytes + c.resp_bytes
        ratio = (c.orig_bytes / total) if total > 0 else 0.0
        
        is_post = (c.http_method == "POST")
        raw_limit = min_raw_upload_bytes if min_raw_upload_bytes is not None else min_upload_bytes
        effective_min_bytes = min_upload_bytes if is_post else raw_limit

        big_post = (is_post and c.orig_bytes >= min_upload_bytes)
        high_ratio = (c.orig_bytes >= effective_min_bytes and ratio >= min_upload_ratio)
        is_exfil = big_post or high_ratio
        conf = 0.0
        if is_exfil:
            conf = 0.5
            if big_post:
                conf += 0.3
            if ratio >= min_upload_ratio:
                conf += 0.2
            conf = min(conf, 1.0)
        if is_exfil:
            verdicts.append(ExfilVerdict(
                src_ip=c.src_ip, dst_ip=c.dst_ip, dst_port=c.dst_port,
                orig_bytes=c.orig_bytes, upload_ratio=round(ratio, 2),
                http_method=c.http_method, http_uri=c.http_uri,
                is_exfil=True, confidence=round(conf, 2),
            ))
    return verdicts


# ----- Confidence tiering --------------------------------------------------

def network_confidence_tier(reputation_hit: bool,
                            corroborating_signals: int) -> str:
    """Grade a network destination on the 4-tier scale shared with the
    correlation stage and the Android module.

    The core principle: a behavioural signal alone (a big upload, a STOR, a
    beacon) is a CANDIDATE, not a verdict — benign uploads and CDN bursts look
    identical to exfil at the network layer. Only independent corroboration
    promotes it.

      confirmed : threat-intel / known-bad JA3 reputation hit (independent)
      strong    : >= 2 independent behavioural signals on the same destination
                  (e.g. it both beacons AND exfils)
      weak      : a single behavioural signal, no intel backing (suspected)

    Host<->network correlation, when available, produces its own (higher)
    tiers in correlation.py; this covers network-only destinations.
    """
    if reputation_hit:
        return "confirmed"
    if corroborating_signals >= 2:
        return "strong"
    return "weak"


# ----- Catch-all: unclassified egress --------------------------------------

@dataclass
class EgressVerdict:
    dst_ip: str
    dst_port: int
    orig_bytes: int
    upload_ratio: float


def detect_unclassified_egress(conns: list[Connection], covered_dsts: set,
                               min_bytes: int = 2048,
                               min_ratio: float = 0.6) -> list[EgressVerdict]:
    """Content-agnostic net for UNKNOWN exfil channels.

    A signature/heuristic can only catch techniques it has a rule for. This is
    the safety net for the ones it doesn't: a flow to an external host that
    pushes data OUT (high upload ratio) and is NOT already explained by a
    specific detector. It doesn't care what protocol or encoding is used — only
    that "data is leaving to somewhere we haven't accounted for." In a sandbox
    detonation, unexplained egress is inherently suspect, so this is surfaced as
    a low-confidence (weak) candidate for the analyst rather than dropped.
    """
    verdicts: list[EgressVerdict] = []
    seen: set = set()
    for c in conns:
        if _is_private_ip(c.dst_ip) or c.dst_ip in covered_dsts:
            continue
        total = c.orig_bytes + c.resp_bytes
        ratio = (c.orig_bytes / total) if total > 0 else 0.0
        if c.orig_bytes >= min_bytes and ratio >= min_ratio:
            key = (c.dst_ip, c.dst_port)
            if key in seen:
                continue
            seen.add(key)
            verdicts.append(EgressVerdict(c.dst_ip, c.dst_port, c.orig_bytes,
                                          round(ratio, 2)))
    return verdicts


# ----- FTP exfiltration detection ------------------------------------------

# FTP store commands (RFC 959): all cause a client->server file upload.
_FTP_UPLOAD_CMDS = ("STOR", "STOU", "APPE")


def detect_ftp_exfil(conns: list[Connection]) -> list[ExfilVerdict]:
    """Flag FTP data exfiltration by the presence of a store command.

    Volume-based detection misses low-volume exfil: AgentTesla-style stealers
    push small credential/keystroke dumps over FTP (often < 2 KB), well under
    any byte threshold. But the control channel carries an explicit STOR/STOU/
    APPE command — "upload this file" — which is a high-precision exfil signal
    independent of how many bytes move. The filename itself is evidence
    (e.g. "STOR ... Passwords ...").

    One verdict per destination IP (the FTP server), keyed off the control
    channel where the command was seen.
    """
    verdicts: list[ExfilVerdict] = []
    seen: set[str] = set()
    for c in conns:
        if not c.ftp_upload_cmd or _is_private_ip(c.dst_ip):
            continue
        if c.dst_ip in seen:
            continue
        seen.add(c.dst_ip)
        total = c.orig_bytes + c.resp_bytes
        ratio = (c.orig_bytes / total) if total > 0 else 0.0
        verdicts.append(ExfilVerdict(
            src_ip=c.src_ip, dst_ip=c.dst_ip, dst_port=c.dst_port,
            orig_bytes=c.orig_bytes, upload_ratio=round(ratio, 2),
            http_method="FTP", http_uri=c.ftp_upload_cmd,
            is_exfil=True,
            # An explicit store command is a strong, content-based signal.
            confidence=0.8,
        ))
    return verdicts


if __name__ == "__main__":
    import sys
    from pcap_loader import load_pcap
    conns = load_pcap(sys.argv[1] if len(sys.argv) > 1
                      else "data/sample_infostealer.pcap")
    print(f"[*] Loaded {len(conns)} connection records\n")
    print("=== Beaconing ===")
    for b in detect_beaconing(conns):
        print(json.dumps(asdict(b)))
    print("\n=== Exfiltration ===")
    for e in detect_exfil(conns):
        print(json.dumps(asdict(e)))

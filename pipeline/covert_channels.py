"""
covert_channels.py — ICMP tunnelling and protocol/port anomalies.

Covert channels hide C2/exfil in protocols that volume/port heuristics ignore:
  * ICMP tunnelling — echo packets stuffed with data (icmpsh, ptunnel). Normal
    pings carry ~32-48 bytes of fixed padding; a tunnel carries large, varying
    payloads, many of them.
  * Protocol/port mismatch — a recognised protocol (HTTP/TLS) on a non-standard
    port (e.g. Redline's HTTP on tcp/55123), a classic evasion of port-based
    monitoring.
"""

from __future__ import annotations
from dataclasses import dataclass
from collections import defaultdict

STD_HTTP_PORTS = {80, 8080, 8000, 8008, 8888}
STD_TLS_PORTS = {443, 8443, 993, 995, 465, 990, 636, 989, 5061,
                 21, 587, 25}   # explicit STARTTLS/AUTH-TLS control ports


@dataclass
class CovertFinding:
    kind: str                      # "icmp_tunnel" | "port_mismatch"
    dst_ip: str
    dst_port: int
    detail: str
    confidence: float
    severity: str                  # "strong" | "weak"


def detect_icmp_tunnel(icmp, min_packets: int = 8,
                       min_avg_payload: int = 64) -> list[CovertFinding]:
    """Flag destinations receiving many ICMP echoes with oversized payloads."""
    per: dict[str, list[int]] = defaultdict(list)
    for src, dst, dlen in icmp:
        per[dst].append(dlen)
    findings: list[CovertFinding] = []
    for dst, lens in per.items():
        if len(lens) < min_packets:
            continue
        avg = sum(lens) / len(lens)
        if avg < min_avg_payload:
            continue
        findings.append(CovertFinding(
            kind="icmp_tunnel", dst_ip=dst, dst_port=0,
            detail=f"{len(lens)} ICMP echoes, avg payload {avg:.0f}B "
                   f"(normal ping ~32-48B)",
            confidence=0.75, severity="strong"))
    return findings


def detect_port_mismatch(http, tls) -> list[CovertFinding]:
    """Flag a recognised protocol running on a non-standard port."""
    findings: list[CovertFinding] = []
    seen: set = set()
    for h in http:
        if h.dst_port not in STD_HTTP_PORTS and (h.dst_ip, h.dst_port) not in seen:
            seen.add((h.dst_ip, h.dst_port))
            findings.append(CovertFinding(
                kind="port_mismatch", dst_ip=h.dst_ip, dst_port=h.dst_port,
                detail=f"HTTP on non-standard port {h.dst_port}",
                confidence=0.4, severity="weak"))
    for t in tls:
        if t.dst_port not in STD_TLS_PORTS and (t.dst_ip, t.dst_port) not in seen:
            seen.add((t.dst_ip, t.dst_port))
            findings.append(CovertFinding(
                kind="port_mismatch", dst_ip=t.dst_ip, dst_port=t.dst_port,
                detail=f"TLS on non-standard port {t.dst_port}",
                confidence=0.4, severity="weak"))
    return findings

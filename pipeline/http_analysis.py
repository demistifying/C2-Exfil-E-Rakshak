"""
http_analysis.py — HTTP exfil/C2 depth: gate patterns, suspicious agents.

Beyond raw upload volume, HTTP C2 has recognisable structure: stealer "gate"
endpoints (`/gate.php`, `/api/set_agent`, panel/loader paths), credential-POST
shapes, and anomalous or hardcoded user-agents. These are signature-flavoured
and explainable — exactly what a court context wants — so they are graded
"strong" (a known pattern), not "confirmed" (which needs an independent
indicator).

Calibrated against samples: the synthetic stealer POSTs to `/gate.php`, Lumma
POSTs to `/api/set_agent?...&token=...&act=log`.
"""

from __future__ import annotations
from dataclasses import dataclass
import re

# Known C2/stealer gate URI patterns (explainable, extensible).
GATE_PATTERNS = [
    r"/gate\.php", r"/gate/?$", r"/api/set_agent", r"/panel/", r"/c2/",
    r"/loader/", r"/is-?ready", r"/submit\.php", r"/tasks\.php",
    r"/receiver/", r"/gateway\.php", r"/index\.php\?id=", r"/api/gate",
]
_GATE_RE = re.compile("|".join(GATE_PATTERNS), re.IGNORECASE)

# User-agents commonly seen on malware HTTP (hardcoded / library defaults).
SUSPICIOUS_UA = {
    "", "-", "mozilla", "mozilla/5.0", "microsoft-cryptoapi/10.0",
    "python-requests", "curl", "wininet", "go-http-client",
}


@dataclass
class HttpFinding:
    dst_ip: str
    dst_port: int
    host: str | None
    uri: str | None
    method: str | None
    reason: str
    severity: str                  # "strong" | "weak"
    confidence: float


def detect_http_exfil(http) -> list[HttpFinding]:
    findings: list[HttpFinding] = []
    seen: set = set()
    for h in http:
        reasons = []
        severity = None
        uri = h.uri or ""
        if _GATE_RE.search(uri):
            reasons.append(f"C2 gate pattern in URI ({uri[:48]})")
            severity = "strong"
        ua = (h.user_agent or "").strip().lower()
        if h.user_agent is not None and ua in SUSPICIOUS_UA:
            reasons.append(f"suspicious/hardcoded user-agent ({h.user_agent!r})")
            severity = severity or "weak"
        if not reasons:
            continue
        key = (h.dst_ip, uri)
        if key in seen:
            continue
        seen.add(key)
        conf = 0.7 if severity == "strong" else 0.45
        findings.append(HttpFinding(
            dst_ip=h.dst_ip, dst_port=h.dst_port, host=h.host, uri=h.uri,
            method=h.method, reason="; ".join(reasons), severity=severity,
            confidence=conf))
    return findings

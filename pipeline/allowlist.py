"""
allowlist.py — sanctioned-service allowlist (the inverse of threat intel).

Threat intel promotes known-BAD destinations to confirmed. This suppresses the
weak-tier noise from known-GOOD ones — OS/browser update, telemetry, OCSP/CRL,
connectivity checks — so the analyst's queue isn't buried in benign egress.

For a court-facing forensic tool the allowlist is DELIBERATELY conservative:

  * It only ever DOWN-TIERS a WEAK finding to `allowlisted` and ANNOTATES it — it
    never drops the finding or touches a strong/confirmed one. Nothing is hidden;
    an allowlisted item is still in the evidence record, just not demanding
    attention. A defence attorney can still see it.
  * **Confirmed always wins.** A destination with an independent bad indicator
    (threat-intel / JA3-JA4 / static prior / host correlation) is never
    suppressed — this defends against domain-fronting / abusing an allowlisted CDN.
  * The default list is NARROW: benign-by-nature endpoints, NOT whole providers.
    Services that malware genuinely abuses for exfil (Google Drive, Telegram,
    Discord, Dropbox) are POINTEDLY excluded — allowlisting them would blind the
    cloud/SaaS detector.

Environment-specific entries belong in `data/allowlist.json` (versioned as part
of chain of custody).
"""

from __future__ import annotations
import ipaddress
import json
import os

# Narrow, benign-by-nature endpoints (update / telemetry / OCSP / connectivity).
# NOT cloud storage or messaging — those are real exfil channels.
DEFAULT_DOMAINS = {
    "update.microsoft.com", "windowsupdate.com", "ctldl.windowsupdate.com",
    "delivery.mp.microsoft.com", "au.download.windowsupdate.com",
    "msftconnecttest.com", "msftncsi.com", "time.windows.com",
    "events.data.microsoft.com", "watson.telemetry.microsoft.com",
    "settings-win.data.microsoft.com",
    "ocsp.digicert.com", "ocsp.msocsp.com", "crl.microsoft.com",
    "ocsp.pki.goog", "ocsp.sectigo.com", "crl.identrust.com",
    "clients2.google.com", "connectivitycheck.gstatic.com",
    "detectportal.firefox.com", "connectivity-check.ubuntu.com",
    "pool.ntp.org", "ntp.org",
}


def load_allowlist(path: str = "data/allowlist.json"):
    """Return (domains:set, cidrs:list). Merges the default set with an optional
    site-specific JSON file ({"domains": [...], "cidrs": [...]})."""
    domains = set(DEFAULT_DOMAINS)
    cidrs = []
    if os.path.exists(path):
        try:
            data = json.load(open(path))
            domains |= {d.lower().strip() for d in data.get("domains", [])}
            for c in data.get("cidrs", []):
                try:
                    cidrs.append(ipaddress.ip_network(c, strict=False))
                except ValueError:
                    pass
        except Exception:
            pass
    return domains, cidrs


def is_allowlisted(domain=None, ip=None, allowlist=None):
    """Return (bool, matched) if the destination is a sanctioned service."""
    domains, cidrs = allowlist or load_allowlist()
    if domain:
        h = domain.lower().rstrip(".")
        for d in domains:
            if h == d or h.endswith("." + d):
                return True, d
    if ip and cidrs:
        try:
            a = ipaddress.ip_address(ip)
            for c in cidrs:
                if a in c:
                    return True, str(c)
        except ValueError:
            pass
    return False, None


def apply_allowlist(events: list[dict], allowlist=None) -> int:
    """Down-tier WEAK findings to sanctioned services. Confirmed/strong are left
    untouched (confirmed wins; strong to a sanctioned service is anomalous and
    kept for review). Returns the number of findings down-tiered."""
    allowlist = allowlist or load_allowlist()
    n = 0
    for e in events:
        if e.get("confidence_tier") != "weak":
            continue
        ok, matched = is_allowlisted(e.get("destination_domain"),
                                     e.get("dst_ip"), allowlist)
        if ok:
            e["confidence_tier"] = "allowlisted"
            e["allowlist_match"] = matched
            n += 1
    return n

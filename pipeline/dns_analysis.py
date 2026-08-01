"""
dns_analysis.py — DNS tunnelling, DGA, and DoH detection.

DNS is the most common covert exfil/C2 channel that volume/port heuristics miss,
because the data rides inside otherwise-normal-looking DNS queries. This module
scores DNS activity per registered domain on the features that separate a data
tunnel from ordinary resolution:

  * tunnelling record types  — TXT / NULL / CNAME / MX carry payload
  * subdomain entropy        — encoded data is high-entropy
  * subdomain length         — data is packed into long labels
  * volume + uniqueness      — a data channel emits many unique subdomains

Calibrated against real traffic: dnscat2 (`cisco-update.com`) and dnsexfiltrator
(`daumel.xyz`) hit all four; the DNS Tunneling top-1M-domain benign set hits none
(entropy ~2.7 vs ~3.6, subdomain len ~11 vs ~34, tunnelling-RT 0.0 vs 1.0).

The IOC for a tunnel is the DOMAIN, not the resolver IP (queries go to the
victim's own resolver), so findings are keyed by domain.
"""

from __future__ import annotations
from dataclasses import dataclass, field
from collections import defaultdict, Counter
import math

TUNNEL_RECORD_TYPES = {"TXT", "NULL", "CNAME", "MX"}
# Known public DoH endpoints (SNI/host). DoH hides DNS inside HTTPS.
KNOWN_DOH = {
    "cloudflare-dns.com", "mozilla.cloudflare-dns.com", "dns.google",
    "dns.google.com", "dns.quad9.net", "doh.opendns.com", "dns.nextdns.io",
    "doh.cleanbrowsing.org", "dns.adguard.com",
}


def _entropy(s: str) -> float:
    if not s:
        return 0.0
    counts = Counter(s)
    return -sum((c / len(s)) * math.log2(c / len(s)) for c in counts.values())


def _registered_domain(qname: str) -> str:
    """Best-effort registered domain (last two labels). Good enough for scoring;
    a full public-suffix list can refine this later."""
    labels = qname.split(".")
    return ".".join(labels[-2:]) if len(labels) >= 2 else qname


def _subdomain(qname: str) -> str:
    labels = qname.split(".")
    return ".".join(labels[:-2]) if len(labels) > 2 else ""


@dataclass
class DnsFinding:
    kind: str                       # "dns_tunnel" | "dga" | "doh"
    domain: str
    query_count: int
    avg_entropy: float
    avg_sub_len: float
    tunnel_rt_fraction: float
    unique_ratio: float
    nxdomain_ratio: float
    confidence: float
    resolver_ips: list[str] = field(default_factory=list)
    evidence: str = ""


def detect_dns_tunneling(dns, min_queries: int = 5) -> list[DnsFinding]:
    """Flag registered domains whose subdomains carry tunnelled data.

    Multi-signal by design: a single feature (e.g. one high-entropy name) is not
    enough — a tunnel trips several at once. Score >= 3 required.
    """
    per: dict[str, dict] = defaultdict(
        lambda: {"n": 0, "ent": [], "len": [], "rt": Counter(),
                 "uniq": set(), "nx": 0, "resolvers": Counter()})
    for q in dns:
        dom = _registered_domain(q.query)
        sub = _subdomain(q.query)
        d = per[dom]
        d["n"] += 1
        d["rt"][(q.qtype or "").upper()] += 1
        if q.dst_ip:
            d["resolvers"][q.dst_ip] += 1
        if q.rcode == "NXDOMAIN":
            d["nx"] += 1
        if sub:
            d["uniq"].add(sub)
            d["ent"].append(_entropy(sub))
            d["len"].append(len(sub))

    findings: list[DnsFinding] = []
    for dom, d in per.items():
        if d["n"] < min_queries or not d["ent"]:
            continue
        avg_ent = sum(d["ent"]) / len(d["ent"])
        avg_len = sum(d["len"]) / len(d["len"])
        tun_rt = sum(d["rt"][t] for t in TUNNEL_RECORD_TYPES) / d["n"]
        uniq_ratio = len(d["uniq"]) / d["n"]
        nx_ratio = d["nx"] / d["n"]

        score = 0
        reasons = []
        if avg_ent >= 3.2:
            score += 1; reasons.append(f"entropy={avg_ent:.2f}")
        if avg_len >= 20:
            score += 1; reasons.append(f"sublen={avg_len:.0f}")
        if tun_rt >= 0.5:
            score += 2; reasons.append(f"tunnelRT={tun_rt:.2f}")
        if d["n"] >= 50 and uniq_ratio >= 0.5:
            score += 1; reasons.append(f"vol={d['n']}/uniq={uniq_ratio:.2f}")
        if score < 3:
            continue
        conf = min(1.0, 0.5 + 0.15 * score)
        findings.append(DnsFinding(
            kind="dns_tunnel", domain=dom, query_count=d["n"],
            avg_entropy=round(avg_ent, 2), avg_sub_len=round(avg_len, 1),
            tunnel_rt_fraction=round(tun_rt, 2), unique_ratio=round(uniq_ratio, 2),
            nxdomain_ratio=round(nx_ratio, 2), confidence=round(conf, 2),
            resolver_ips=[ip for ip, _ in d["resolvers"].most_common(3)],
            evidence="; ".join(reasons)))
    return findings


def detect_dga(dns, min_queries: int = 10,
               min_nx_ratio: float = 0.5) -> list[DnsFinding]:
    """Flag likely DGA: many distinct high-entropy registered domains that mostly
    resolve to NXDOMAIN (malware cycling algorithmic domains to find a live C2)."""
    doms: dict[str, dict] = defaultdict(lambda: {"n": 0, "nx": 0})
    for q in dns:
        dom = _registered_domain(q.query)
        doms[dom]["n"] += 1
        if q.rcode == "NXDOMAIN":
            doms[dom]["nx"] += 1

    # SLD entropy over the set of distinct domains that returned NXDOMAIN.
    nx_domains = [d for d, s in doms.items() if s["nx"] > 0]
    if len(nx_domains) < min_queries:
        return []
    slds = [d.split(".")[0] for d in nx_domains]
    avg_ent = sum(_entropy(s) for s in slds) / len(slds)
    total = sum(s["n"] for s in doms.values())
    nx = sum(s["nx"] for s in doms.values())
    nx_ratio = nx / total if total else 0.0
    if avg_ent >= 3.2 and nx_ratio >= min_nx_ratio:
        return [DnsFinding(
            kind="dga", domain=f"<{len(nx_domains)} algorithmic domains>",
            query_count=total, avg_entropy=round(avg_ent, 2), avg_sub_len=0.0,
            tunnel_rt_fraction=0.0, unique_ratio=1.0,
            nxdomain_ratio=round(nx_ratio, 2), confidence=0.7,
            evidence=f"{len(nx_domains)} high-entropy NXDOMAIN domains")]
    return []


def detect_doh(tls, http) -> list[str]:
    """Return destination domains that are known DoH endpoints (DNS-over-HTTPS).
    DoH is dual-use, so this is an informational signal, not a verdict."""
    hits = set()
    for t in tls:
        if t.server_name and t.server_name.lower() in KNOWN_DOH:
            hits.add(t.server_name.lower())
    for h in http:
        if h.host and h.host.lower() in KNOWN_DOH:
            hits.add(h.host.lower())
    return sorted(hits)

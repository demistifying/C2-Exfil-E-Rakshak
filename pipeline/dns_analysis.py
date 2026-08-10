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


def detect_dga_ml(dns, min_prob: float = 0.75,
                  already: set | None = None) -> list[DnsFinding]:
    """ML net for DICTIONARY DGAs the entropy heuristic (`detect_dga`) misses.

    suppobox/matsnu/gozi glue real words together, so Shannon entropy stays in
    the benign band and the statistical detector never fires. The char-n-gram
    model in `dga_classifier` learns that word-salad morphology. This runs per
    distinct queried registered-domain and surfaces high-scoring ones as
    *candidates* — weak tier by construction (a lone learned signal), with the
    driving n-grams attached so the verdict is explainable, never asserted.

    Degrades gracefully: if the model artifact isn't present, returns []. The
    surfacing threshold (0.75) is deliberately above the model's 0.5 decision
    boundary to protect precision on bulk benign DNS; the model itself still
    classifies at 0.5 for evaluation.
    """
    try:
        from dga_classifier import get_model
    except Exception:
        return []
    model = get_model()
    if model is None:
        return []

    already = already or set()
    per: dict[str, dict] = defaultdict(lambda: {"n": 0, "resolvers": Counter()})
    for q in dns:
        dom = _registered_domain(q.query)
        per[dom]["n"] += 1
        if q.dst_ip:
            per[dom]["resolvers"][q.dst_ip] += 1

    findings: list[DnsFinding] = []
    for dom, d in per.items():
        if dom in already:
            continue
        sld = dom.split(".")[0]
        if len(sld) < 8:                 # dictionary DGAs are long; skip short brands
            continue
        s = model.score(sld)
        if s.probability < min_prob:
            continue
        top = ", ".join(f"{n.replace('ng:','').replace('f:','')}" for n, _ in s.top_features[:4])
        findings.append(DnsFinding(
            kind="dga_ml", domain=dom, query_count=d["n"],
            avg_entropy=0.0, avg_sub_len=float(len(sld)),
            tunnel_rt_fraction=0.0, unique_ratio=0.0, nxdomain_ratio=0.0,
            confidence=round(float(s.probability), 2),
            resolver_ips=[ip for ip, _ in d["resolvers"].most_common(3)],
            evidence=f"ML DGA classifier p={s.probability:.2f} "
                     f"(dictionary-DGA morphology; drivers: {top})"))
    return findings


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

# --- resolved-destination candidates (the simulated-network case) ------------
# Under network_mode=simulated_inetsim every connection terminates at the
# responder, so the destination IP is always the simulator and carries no
# attribution. The malware's ACTUAL intended destination survives only in the
# DNS query name. A sample can therefore be fully analysed, produce a correct
# "no C2 connections" result, and still have named its C2 out loud.
#
# The other DNS detectors here look for ANOMALOUS names (algorithmic, tunnelled).
# A real C2 is frequently an ordinary, legitimate-looking domain — abused webmail
# and cloud services are the common exfil channel for AgentTesla/Snake-Keylogger
# style stealers — so anomaly detection alone never sees them.
#
# Baseline of expected operating-system and vendor background traffic. Matched
# domains are still emitted, tiered 'allowlisted' — surfaced, never hidden.
_OS_BACKGROUND_SUFFIXES = (
    "microsoft.com", "windowsupdate.com", "windows.com", "msftncsi.com",
    "msftconnecttest.com", "skype.com", "live.com", "office.com", "office365.com",
    "msedge.net", "azureedge.net", "akadns.net", "digicert.com", "verisign.com",
    "sectigo.com", "identrust.com", "globalsign.com", "letsencrypt.org",
    "gstatic.com", "googleapis.com", "google.com", "mozilla.com", "mozilla.net",
    "ubuntu.com", "ntp.org", "in-addr.arpa", "ip6.arpa", "local", "localdomain",
)


def _is_os_background(domain: str) -> bool:
    d = (domain or "").lower().rstrip(".")
    return any(d == suffix or d.endswith("." + suffix) for suffix in _OS_BACKGROUND_SUFFIXES)


def detect_resolved_destinations(dns, already: set[str] | None = None,
                                 allow_domains: set[str] | None = None) -> list[DnsFinding]:
    """Every distinct name the sample resolved, as a C2/exfil CANDIDATE.

    A DNS query is a candidate, never a verdict — the same rule this module
    applies to beaconing. Resolution proves intent to contact, not contact, and
    certainly not malice. Tiering is decided downstream by corroboration
    (reputation hit, static-prior match); this detector only ensures the
    destination is visible instead of being discarded because the connection
    landed on a simulator.
    """
    already = {d.lower() for d in (already or set())}
    allow = {d.lower() for d in (allow_domains or set())}
    counts: dict[str, int] = {}
    for q in dns:
        name = (getattr(q, "query", "") or "").lower().rstrip(".")
        if not name or "." not in name:
            continue
        counts[name] = counts.get(name, 0) + 1

    findings: list[DnsFinding] = []
    for name, n in sorted(counts.items()):
        if name in already:
            continue                      # a more specific detector already owns it
        background = _is_os_background(name) or name in allow or _registered_domain(name) in allow
        findings.append(DnsFinding(
            kind="resolved_domain",
            domain=name,
            query_count=n,
            avg_entropy=_entropy(_subdomain(name) or name),
            avg_sub_len=float(len(_subdomain(name))),
            tunnel_rt_fraction=0.0,
            unique_ratio=0.0,
            nxdomain_ratio=0.0,
            # A resolution is a candidate, not a verdict. Background traffic is
            # scored to nothing; everything else stays weak until corroborated.
            confidence=0.0 if background else 0.4,
            evidence=(
                f"{name} was resolved {n} time(s). "
                + ("Matches expected operating-system or vendor background traffic."
                   if background else
                   "Not part of expected operating-system background traffic — treat as a "
                   "destination the sample intended to contact.")
            ),
        ))
    return findings

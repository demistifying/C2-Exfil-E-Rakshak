"""
family_attribution.py — attribute a case to a malware family / campaign (F3).

The detectors say "exfil to X over FTP"; attribution says "this looks like
AgentTesla." It fuses the signals the pipeline already has, in order of trust:

  1. static prior family  — from ST/DT binary analysis (CAPA/YARA)  -> CONFIRMED
  2. threat-intel notes    — feed entries name the family (Feodo/URLhaus/MISP,
     and known-bad JA3/JA4 descriptions)                            -> LIKELY
  3. behavioural signature — the channel/technique combination is
     characteristic of a family class                              -> POSSIBLE

Everything is explainable (each verdict lists its evidence) and honestly graded —
a behavioural match is "possible", never asserted as fact. Output feeds the
report and the IOC/STIX export.
"""

from __future__ import annotations
from dataclasses import dataclass, asdict
from collections import Counter

from attribution import attribute, domain_reputation

# canonical family -> substrings that identify it in a note/description
FAMILIES = {
    "RedLine Stealer": ["redline"],
    "Lumma Stealer": ["lumma"],
    "AgentTesla": ["agenttesla", "agent tesla"],
    "Snake Keylogger": ["snake keylogger", "snake"],
    "GuLoader": ["guloader"],
    "Cobalt Strike": ["cobalt strike", "cobaltstrike"],
    "Metasploit": ["metasploit", "meterpreter"],
    "Emotet": ["emotet"],
    "TrickBot": ["trickbot"],
    "IcedID": ["icedid"],
    "StealC": ["stealc"],
    "Hancitor": ["hancitor"],
    "Amadey": ["amadey"],
    "Pony": ["pony"],
    "Formbook": ["formbook", "xloader"],
    "Qakbot": ["qakbot", "qbot"],
    "dnscat2": ["dnscat"],
    "VIP Recovery": ["vip recovery"],
}

_RANK = {"confirmed": 3, "likely": 2, "possible": 1}


@dataclass
class FamilyVerdict:
    family: str
    confidence: str          # confirmed | likely | possible
    basis: str               # static_prior | threat_intel | behavioural
    evidence: list


def _match_families(text: str) -> set[str]:
    t = (text or "").lower()
    return {fam for fam, kws in FAMILIES.items() if any(k in t for k in kws)}


def _intel_texts(events) -> list[str]:
    """Reputation notes / static matches attached to (or looked up for) events."""
    texts, seen_ip, seen_dom = [], set(), set()
    for e in events:
        for k in ("static_match", "static_note", "reputation_note", "dns_evidence"):
            if e.get(k):
                texts.append(e[k])
        if not e.get("reputation_hit"):
            continue
        ip, dom, ja3 = e.get("dst_ip"), e.get("destination_domain"), e.get("ja3_hash")
        if ip and ip not in seen_ip:
            seen_ip.add(ip)
            note = attribute(ip, ja3_hash=ja3, ja4=e.get("ja4")).reputation_note
            if note:
                texts.append(note)
        if dom and dom not in seen_dom:
            seen_dom.add(dom)
            note = domain_reputation(dom)[2]
            if note:
                texts.append(note)
    return texts


def _behavioural(events) -> list[tuple]:
    """(family, evidence) candidates from the channel/technique combination."""
    kinds = Counter(e.get("kind") for e in events)
    uris = " ".join((e.get("http_uri") or "") for e in events).lower()
    subj = " ".join((e.get("smtp_subject") or "") for e in events).lower()
    out = []
    if kinds.get("dns_tunnel") or kinds.get("dga"):
        out.append(("dnscat2", "DNS tunnelling (TXT/MX/CNAME, high-entropy subdomains)"))
    if kinds.get("http_c2") and kinds.get("beacon"):
        out.append(("Cobalt Strike", "HTTP C2 gate + periodic beacon"))
    if kinds.get("smtp_exfil") or "pw_" in uris or "stor pw" in uris or "pc name" in subj:
        out.append(("AgentTesla", "credential/system-info exfil over SMTP/FTP"))
    return out


def attribute_family(network_events, static_family: str | None = None) -> list[FamilyVerdict]:
    """Rank family verdicts for the case (highest confidence first)."""
    best: dict[str, FamilyVerdict] = {}

    def _add(fam, conf, basis, ev):
        cur = best.get(fam)
        if cur is None or _RANK[conf] > _RANK[cur.confidence]:
            best[fam] = FamilyVerdict(fam, conf, basis, [ev])
        elif ev not in cur.evidence:
            cur.evidence.append(ev)

    if static_family:
        _add(static_family, "confirmed", "static_prior",
             "family extracted from the binary by ST/DT")

    for text in _intel_texts(network_events):
        for fam in _match_families(text):
            _add(fam, "likely", "threat_intel", f"threat-intel note: {text}")

    for fam, ev in _behavioural(network_events):
        _add(fam, "possible", "behavioural", ev)

    return sorted(best.values(),
                  key=lambda v: (_RANK[v.confidence], v.family), reverse=True)


def verdicts_to_dicts(verdicts) -> list[dict]:
    return [asdict(v) for v in verdicts]

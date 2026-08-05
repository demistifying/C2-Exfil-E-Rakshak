"""
static_prior.py — ingestion + correlation for the STATIC IOC PRIOR from ST/DT.

================================ SCOPE / BOUNDARY =============================
This module does NOT perform static analysis (unpacking, PE parsing, YARA, CAPA
capability detection, config decryption). That is the Windows ST/DT module's
job; duplicating it here would be redundant.

What this module owns is the piece that is uniquely valuable to attribution and
correlation: taking the C2/exfil IOCs that ST/DT extracts from the binary and
**cross-validating them against what was actually observed on the network**.

  * A static-extracted C2 that we ALSO see on the wire  → CONFIRMED
    (binary intent corroborated by observed behaviour — the strongest possible
    attribution).
  * A static-extracted C2 we did NOT observe            → recorded as a
    "dormant"/expected indicator, so the case is complete.

The ST/DT module fills the prior via the contract below (see
docs/static_prior_contract.md); this module ingests, validates, and correlates.
==============================================================================

Prior schema (JSON):
    {
      "sample_sha256": "…",                 # ties the prior to the case sample
      "family": "RedLine Stealer",          # optional
      "capabilities": ["T1555.003", …],     # optional, ATT&CK ids (from CAPA)
      "c2_indicators": [
        {"type": "ip",     "value": "188.190.10.10"},
        {"type": "domain", "value": "evil.example"},
        {"type": "url",    "value": "http://evil.example/gate.php"},
        {"type": "email",  "value": "drop@evil.example"}
      ]
    }
"""

from __future__ import annotations
from dataclasses import dataclass, field
from urllib.parse import urlparse
import ipaddress
import json
import os

# Matches the ST/DT c2_static_prior.schema.json ioc type enum. "hash" is a
# sample/file indicator (not a network destination) — accepted so strict
# ingestion of a real bundle doesn't reject it, but it's not network-correlatable.
VALID_TYPES = frozenset({"ip", "domain", "url", "email", "hash"})


@dataclass
class StaticIndicator:
    type: str
    value: str

    def match_keys(self) -> set[str]:
        """The concrete strings this indicator could match against network
        findings (IP and/or domain), normalising a URL to host."""
        v = self.value.strip()
        if self.type == "ip":
            return {v}
        if self.type == "domain":
            return {v.lower()}
        if self.type == "email":
            dom = v.split("@")[-1].lower()
            return {v.lower(), dom}
        if self.type == "url":
            host = urlparse(v if "://" in v else "http://" + v).hostname or ""
            keys = {host.lower()} if host else set()
            try:                                   # url may embed a bare IP
                ipaddress.ip_address(host)
                keys.add(host)
            except ValueError:
                pass
            return keys
        return {v}


@dataclass
class StaticPrior:
    sample_sha256: str | None = None
    family: str | None = None
    capabilities: list[str] = field(default_factory=list)
    indicators: list[StaticIndicator] = field(default_factory=list)


@dataclass
class PriorReport:
    prior: StaticPrior
    errors: list[str] = field(default_factory=list)

    @property
    def ok(self) -> bool:
        return not self.errors


def ingest_prior(raw: dict, *, strict: bool = False) -> PriorReport:
    prior = StaticPrior(
        sample_sha256=raw.get("sample_sha256"),
        family=raw.get("family"),
        capabilities=list(raw.get("capabilities") or []))
    report = PriorReport(prior=prior)
    for i, ind in enumerate(raw.get("c2_indicators") or []):
        if not isinstance(ind, dict) or "type" not in ind or "value" not in ind:
            msg = f"c2_indicators[{i}] must have 'type' and 'value'"
            if strict:
                raise ValueError(msg)
            report.errors.append(msg); continue
        if ind["type"] not in VALID_TYPES:
            msg = f"c2_indicators[{i}] invalid type {ind['type']!r} (expected {sorted(VALID_TYPES)})"
            if strict:
                raise ValueError(msg)
            report.errors.append(msg); continue
        if not str(ind["value"]).strip():
            report.errors.append(f"c2_indicators[{i}] empty value"); continue
        prior.indicators.append(StaticIndicator(ind["type"], str(ind["value"]).strip()))
    return report


def load_static_prior(path: str) -> PriorReport:
    if not os.path.exists(path):
        return PriorReport(StaticPrior(), errors=[f"file not found: {path}"])
    try:
        raw = json.load(open(path))
    except json.JSONDecodeError as e:
        return PriorReport(StaticPrior(), errors=[f"invalid JSON: {e}"])
    return ingest_prior(raw)


# --- static <-> network correlation -----------------------------------------

@dataclass
class StaticCorrelation:
    indicator: StaticIndicator
    observed: bool                       # seen on the network?
    matched_dst: list[str] = field(default_factory=list)


def correlate_static_prior(prior: StaticPrior,
                           network_events: list[dict]) -> list[StaticCorrelation]:
    """For each static indicator, decide whether it was observed on the network.

    A network event matches if its destination IP or domain is one of the
    indicator's match keys. Returns one correlation per indicator (observed or
    dormant)."""
    # index observed network destinations
    net_ips = {e.get("dst_ip") for e in network_events if e.get("dst_ip")}
    net_domains = {(e.get("destination_domain") or "").lower()
                   for e in network_events if e.get("destination_domain")}
    results: list[StaticCorrelation] = []
    for ind in prior.indicators:
        keys = ind.match_keys()
        matched = sorted((keys & net_ips) | {k for k in keys if k in net_domains})
        results.append(StaticCorrelation(
            indicator=ind, observed=bool(matched), matched_dst=matched))
    return results

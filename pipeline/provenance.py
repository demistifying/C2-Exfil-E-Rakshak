"""
provenance.py — item-level exfiltration provenance.

The forensic question is not just "did exfil happen and to where", but
"WHICH stolen item left the host, via what, to which destination, and when" —
e.g. *"the OTP captured via GetClipboardData at 14:03:01 was exfiltrated to
198.51.100.7 over HTTPS at 14:03:04."*

This joins three things the pipeline already produces:
  * host access events (ETW)      — WHAT was accessed, via which API, WHEN
  * host<->network correlation    — the temporal link access -> exfil
  * network exfil descriptors     — WHERE it went, over what protocol, plus the
                                    on-the-wire descriptor (STOR filename, SMTP
                                    subject, HTTP gate URI) as corroborating
                                    evidence of the item's identity.

It does not need the raw stolen bytes: the ETW data_type is the authoritative
"what", and the network descriptor corroborates it. When the payload is
encrypted the item is an INFERENCE from the preceding host access (clearly
labelled), never an overclaim.
"""

from __future__ import annotations
from dataclasses import dataclass, asdict

# host data_type -> stolen-item category
ITEM_TYPE = {
    "browser_credentials": "credential",
    "keystrokes": "keystroke_log",
    "screenshot": "screenshot",
    "clipboard": "clipboard_data",      # OTP/2FA codes frequently transit here
    "crypto_wallet": "crypto_wallet",
    "system_info": "system_info",
    "file_access": "file",
    "otp": "otp",
}

# network event kind -> exfil protocol label
_PROTOCOL = {
    "exfil": "FTP/HTTP", "smtp_exfil": "SMTP", "cloud_exfil": "HTTPS (cloud)",
    "cloud_staging": "HTTPS (cloud)", "dns_tunnel": "DNS", "http_c2": "HTTP",
    "ja3": "TLS", "tls_cert": "TLS", "beacon": "TLS/HTTP", "dga": "DNS",
    "icmp_tunnel": "ICMP", "port_mismatch": "non-standard-port",
    "static_ioc": "unknown",
}

# descriptor keywords that sharpen the item identity (evidence, not sole basis)
_ITEM_KEYWORDS = {
    "otp": "otp", "2fa": "otp", "token": "otp",
    "password": "credential", "passwords": "credential", "pw_": "credential",
    "cred": "credential", "login": "credential",
    "cookie": "cookie", "wallet": "crypto_wallet", "keylog": "keystroke_log",
}


@dataclass
class ProvenanceRecord:
    item_type: str
    data_type_accessed: str
    accessed_via: str | None
    accessed_at: str
    destination_ip: str
    destination_port: int
    destination_domain: str | None
    exfil_protocol: str
    exfiltrated_at: str
    time_delta_s: float
    evidence: str | None          # on-the-wire descriptor (filename/subject/uri)
    inferred: bool                # True if the item is inferred (encrypted payload)
    confidence_tier: str
    recovered_bytes: int = 0          # reconstructed exfil content size (D1)
    recovered_sha256: str | None = None
    recovered_preview: str | None = None

    def statement(self) -> str:
        who = self.destination_domain or self.destination_ip
        verb = "was (inferred to be) exfiltrated" if self.inferred else "was exfiltrated"
        via = f" via {self.accessed_via}" if self.accessed_via else ""
        recovered = ""
        if self.recovered_bytes:
            recovered = (f" — recovered {self.recovered_bytes} B "
                         f"(sha256 {self.recovered_sha256[:12]}…)")
        return (f"{self.item_type}{via} at {self.accessed_at} {verb} to "
                f"{who} over {self.exfil_protocol} at {self.exfiltrated_at} "
                f"(+{self.time_delta_s}s) [{self.confidence_tier}]{recovered}")


def _descriptor(net: dict) -> str | None:
    for k in ("http_uri", "smtp_subject", "cloud_service", "dns_evidence",
              "cert_reason", "covert_detail"):
        v = net.get(k)
        if v:
            return str(v)
    return None


def _refine_item(base: str, descriptor: str | None) -> str:
    """Use the network descriptor to sharpen the item type — but the host
    data_type remains authoritative; keywords only specialise it."""
    if not descriptor:
        return base
    low = descriptor.lower()
    for kw, item in _ITEM_KEYWORDS.items():
        if kw in low:
            # only specialise clipboard/keystroke into otp, or confirm credential
            if base in ("clipboard_data", "keystroke_log") and item == "otp":
                return "otp"
            if item == base:
                return base
    return base


def build_provenance(correlated, network_events: list[dict],
                     artifacts=None) -> list[ProvenanceRecord]:
    """Build one provenance record per correlated (item -> destination) link,
    attaching reconstructed exfil content (D1) when available for that dest."""
    net_by_dst: dict = {}
    for e in network_events:
        net_by_dst.setdefault((e.get("dst_ip"), e.get("dst_port")), e)
        net_by_dst.setdefault(e.get("dst_ip"), e)

    # index the largest recovered outbound artifact per destination IP
    art_by_dst: dict = {}
    for a in (artifacts or []):
        cur = art_by_dst.get(a.dest_ip)
        if cur is None or a.total_bytes > cur.total_bytes:
            art_by_dst[a.dest_ip] = a

    records: list[ProvenanceRecord] = []
    for c in correlated:
        net = (net_by_dst.get((c.destination_ip, c.destination_port))
               or net_by_dst.get(c.destination_ip) or {})
        kind = net.get("kind", "exfil")
        descriptor = _descriptor(net)
        base = ITEM_TYPE.get(c.data_type_accessed, c.data_type_accessed)
        item = _refine_item(base, descriptor)
        inferred = not bool(net.get("plaintext_available"))
        art = art_by_dst.get(c.destination_ip)
        records.append(ProvenanceRecord(
            item_type=item, data_type_accessed=c.data_type_accessed,
            accessed_via=c.access_api_call, accessed_at=c.access_ts,
            destination_ip=c.destination_ip, destination_port=c.destination_port,
            destination_domain=net.get("destination_domain"),
            exfil_protocol=_PROTOCOL.get(kind, "unknown"),
            exfiltrated_at=c.network_ts, time_delta_s=c.time_delta_s,
            evidence=descriptor, inferred=inferred,
            confidence_tier=c.confidence_tier,
            recovered_bytes=art.total_bytes if art else 0,
            recovered_sha256=art.sha256 if art else None,
            recovered_preview=art.preview if art else None))
    return records


def provenance_to_dicts(records) -> list[dict]:
    return [asdict(r) | {"statement": r.statement()} for r in records]

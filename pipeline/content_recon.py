"""
content_recon.py — reconstruct the actual EXFILTRATED CONTENT (D1).

Beyond "data went to X", a forensic case wants the data itself: the bytes that
left the host, hashed for evidence and previewed for the analyst. For cleartext
channels (HTTP POST, FTP data, SMTP DATA) we can reassemble the outbound stream
directly from the pcap; for Zeek captures the authoritative source is
`files.log` (Zeek already reassembles and hashes transferred files).

Only OUTBOUND-to-public content is reconstructed (data leaving the victim), so
downloads/responses are ignored. Each reconstructed object is an `Artifact` with
the true byte count, a SHA-256 of the recovered content (evidence integrity), and
a sanitised preview. These attach to the provenance record for their destination,
turning "credential exfiltrated to X" into "credential exfiltrated to X —
recovered 4.1 KB, sha256 …, preview 'user=…'".
"""

from __future__ import annotations
import hashlib

from model import Artifact
from traffic_analysis import _is_private_ip

_PREVIEW_LEN = 300


def _preview(content: bytes) -> str:
    """First printable characters of the content, control bytes shown as '.'."""
    snippet = content[:_PREVIEW_LEN]
    out = "".join(chr(b) if 32 <= b < 127 else "." for b in snippet)
    return out


def reconstruct_outbound_content(pcap_path: str, min_bytes: int = 64,
                                 max_flow_bytes: int = 1 << 20) -> list[Artifact]:
    """Reassemble outbound-to-public TCP payloads per flow into Artifacts.

    Streamed via PcapReader (bounded memory); each flow's buffer is capped at
    `max_flow_bytes` for the hash/preview while the TRUE size is still counted.
    """
    from scapy.all import PcapReader, IP, IPv6, TCP, Raw
    flows: dict = {}
    try:
        reader = PcapReader(pcap_path)
    except Exception:
        return []
    with reader:
        for pk in reader:
            if TCP not in pk or Raw not in pk:
                continue
            L = pk.getlayer(IP) or pk.getlayer(IPv6)
            if L is None or _is_private_ip(L.dst):
                continue                              # only data leaving to public
            data = bytes(pk[TCP].payload)
            if not data:
                continue
            key = (L.src, L.dst, int(pk[TCP].dport))
            f = flows.get(key)
            if f is None:
                f = {"buf": bytearray(), "size": 0, "ts": float(pk.time)}
                flows[key] = f
            f["size"] += len(data)
            if len(f["buf"]) < max_flow_bytes:
                f["buf"].extend(data[:max_flow_bytes - len(f["buf"])])

    artifacts: list[Artifact] = []
    for (src, dst, dport), f in flows.items():
        if f["size"] < min_bytes:
            continue
        content = bytes(f["buf"])
        artifacts.append(Artifact(
            ts=f["ts"], filename=None, mime_type=None, total_bytes=f["size"],
            sha256=hashlib.sha256(content).hexdigest(),
            source_ip=src, dest_ip=dst, is_outbound=True,
            preview=_preview(content)))
    return artifacts


def outbound_artifacts(bundle, pcap_path: str) -> list[Artifact]:
    """Prefer Zeek files.log (authoritative reassembly); else reconstruct from
    the pcap. Returns only outbound (exfil-candidate) artifacts."""
    zeek_out = [a for a in bundle.artifacts
                if a.is_outbound or (a.source_ip and _is_private_ip(a.source_ip)
                                     and a.dest_ip and not _is_private_ip(a.dest_ip))]
    if zeek_out:
        for a in zeek_out:
            a.is_outbound = True
        return zeek_out
    return reconstruct_outbound_content(pcap_path)

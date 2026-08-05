"""
evidence.py — case manifest, chain of custody, and chain verification.

For a law-enforcement / court context the analysis must be reproducible and
tamper-evident end to end, not just per output row:

  * every INPUT (sample, pcap, Zeek logs) is hashed and recorded;
  * tool and schema versions are recorded, so a result can be reproduced with
    the same code;
  * a deterministic case_id is derived from the inputs + parameters, so the same
    evidence analysed with the same settings yields the same case identity;
  * the per-row hash chain (built in the emitter) can be independently verified.

The manifest is the chain-of-custody header for a case; `verify_chain` is the
integrity check an independent party runs on the findings.
"""

from __future__ import annotations
from dataclasses import dataclass, field, asdict
from datetime import datetime, timezone
import hashlib
import json
import os
import sys
import platform

SCHEMA_VERSION = "1.1"          # bump when the exfil_events schema changes
                                # 1.1: +destination_domain, asn_org,
                                #      reputation_note, reputation_source


def sha256_file(path: str) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as fh:
        for chunk in iter(lambda: fh.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def _tool_versions() -> dict:
    versions = {
        "python": sys.version.split()[0],
        "platform": platform.platform(),
        "schema": SCHEMA_VERSION,
    }
    try:
        import scapy   # type: ignore
        versions["scapy"] = getattr(scapy, "__version__", "unknown")
    except Exception:
        versions["scapy"] = "absent"
    return versions


@dataclass
class InputRecord:
    role: str          # "sample" | "pcap" | "zeek_log"
    path: str
    sha256: str
    size_bytes: int


@dataclass
class CaseManifest:
    case_id: str                       # deterministic: f(inputs, parameters)
    created_utc: str                   # metadata only; not part of case_id
    inputs: list[InputRecord] = field(default_factory=list)
    parameters: dict = field(default_factory=dict)
    tool_versions: dict = field(default_factory=dict)

    def to_dict(self) -> dict:
        d = asdict(self)
        return d

    def write(self, path: str) -> str:
        os.makedirs(os.path.dirname(path) or ".", exist_ok=True)
        with open(path, "w") as fh:
            json.dump(self.to_dict(), fh, indent=2, sort_keys=True)
        return path


def _collect_inputs(sample: str | None, pcap: str | None,
                    zeek_dir: str | None) -> list[InputRecord]:
    recs: list[InputRecord] = []
    if sample and os.path.exists(sample):
        recs.append(InputRecord("sample", sample, sha256_file(sample),
                                os.path.getsize(sample)))
    if pcap and os.path.exists(pcap):
        recs.append(InputRecord("pcap", pcap, sha256_file(pcap),
                                os.path.getsize(pcap)))
    if zeek_dir and os.path.isdir(zeek_dir):
        for name in sorted(os.listdir(zeek_dir)):
            p = os.path.join(zeek_dir, name)
            if name.endswith(".log") and os.path.isfile(p):
                recs.append(InputRecord("zeek_log", p, sha256_file(p),
                                        os.path.getsize(p)))
    return recs


def build_case_manifest(sample: str | None = None, pcap: str | None = None,
                        zeek_dir: str | None = None,
                        parameters: dict | None = None) -> CaseManifest:
    """Hash all inputs and derive a deterministic case_id. Same evidence + same
    parameters → same case_id (reproducibility), independent of wall-clock time."""
    parameters = parameters or {}
    inputs = _collect_inputs(sample, pcap, zeek_dir)
    # Deterministic identity from input content hashes + parameters (NOT time).
    basis = json.dumps(
        {"inputs": sorted(r.sha256 for r in inputs), "parameters": parameters},
        sort_keys=True)
    case_id = hashlib.sha256(basis.encode()).hexdigest()
    return CaseManifest(
        case_id=case_id,
        created_utc=datetime.now(timezone.utc).isoformat(),
        inputs=inputs,
        parameters=parameters,
        tool_versions=_tool_versions(),
    )


# --- chain verification ------------------------------------------------------

def verify_chain(rows: list[dict]) -> tuple[bool, int]:
    """Recompute the SHA-256 hash chain over `rows` and verify integrity.
    Returns (all_valid, first_broken_index); index -1 means fully valid.

    Must match the chaining in orchestrator.emit_schema_rows:
        h_i = SHA256( h_{i-1} + json(row_i without evidence_hash) )
    """
    prev = "0" * 64
    for i, row in enumerate(rows):
        content = {k: v for k, v in row.items() if k != "evidence_hash"}
        expected = hashlib.sha256(
            (prev + json.dumps(content, sort_keys=True)).encode()).hexdigest()
        if row.get("evidence_hash") != expected:
            return False, i
        prev = row["evidence_hash"]
    return True, -1

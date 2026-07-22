"""
ja3_loader.py — parse JA3/JA3S fingerprints from Zeek's ssl.log.

JA3 is a method of fingerprinting TLS clients (and JA3S for servers) by
hashing the ClientHello / ServerHello parameters. Known-bad JA3 hashes
(e.g. Cobalt Strike, Metasploit) are matched against the threat-intel DB
alongside IP indicators.

This is the encrypted-traffic fallback: when TLS can't be decrypted (cert
pinning), JA3 + beaconing intervals + destination ASN/geo still produce
useful attribution without any payload content.

Production path: Zeek with the ja3 package generates ssl.log with ja3/ja3s
fields. This module parses that log.
"""

from __future__ import annotations
from dataclasses import dataclass
from collections import defaultdict
import os
import json


@dataclass
class JA3Record:
    ja3_hash: str | None
    ja3s_hash: str | None
    server_name: str | None   # SNI
    subject: str | None       # certificate subject


# Known-bad JA3 hashes — these should also be seeded into the threat-intel DB
# so _reputation_lookup catches them via the unified path.
KNOWN_BAD_JA3 = {
    "72a589da586844d7f0818ce684948eea": "Cobalt Strike default",
    "a0e9f5d64349fb13191bc781f81f42e1": "Cobalt Strike 4.x",
    "e35df3e00ca4ef31d42b34bebaa2f86e": "Metasploit default",
    "6734f37431670b3ab4292b8f60f29984": "Trickbot / IcedID common",
}


def load_zeek_ssl(path: str) -> dict[tuple[str, str, int], JA3Record]:
    """Parse Zeek ssl.log and return a dict keyed by (src_ip, dst_ip, dst_port).

    If the ssl.log includes ja3/ja3s fields (from the zeek-ja3 package), those
    are extracted. If not, ja3_hash/ja3s_hash are None — the record is still
    useful for SNI and certificate subject.
    """
    records: dict[tuple[str, str, int], JA3Record] = {}
    fields = []

    if not os.path.exists(path):
        return records

    with open(path) as fh:
        for line in fh:
            line = line.rstrip("\n")
            if line.startswith("#fields"):
                fields = line.split("\t")[1:]
                continue
            if line.startswith("#") or not line:
                continue
            vals = line.split("\t")
            row = dict(zip(fields, vals))

            def val(key, default=None):
                v = row.get(key, "-")
                return default if v == "-" or v == "(empty)" else v

            src_ip = val("id.orig_h", "")
            dst_ip = val("id.resp_h", "")
            try:
                dst_port = int(row.get("id.resp_p", "0"))
            except ValueError:
                dst_port = 0

            key = (src_ip, dst_ip, dst_port)
            records[key] = JA3Record(
                ja3_hash=val("ja3"),
                ja3s_hash=val("ja3s"),
                server_name=val("server_name"),
                subject=val("subject"),
            )

    return records


def check_known_bad_ja3(ja3_hash: str | None) -> tuple[bool, str | None]:
    """Check a JA3 hash against the hardcoded known-bad list.

    Returns (is_bad, description). For production use, ja3 hashes should also
    be in the threat-intel DB so the unified reputation path covers them.
    """
    if ja3_hash and ja3_hash in KNOWN_BAD_JA3:
        return True, KNOWN_BAD_JA3[ja3_hash]
    return False, None


if __name__ == "__main__":
    import sys
    path = sys.argv[1] if len(sys.argv) > 1 else "output/zeek/ssl.log"
    records = load_zeek_ssl(path)
    for key, rec in records.items():
        bad, desc = check_known_bad_ja3(rec.ja3_hash)
        flag = f"  <-- KNOWN BAD: {desc}" if bad else ""
        print(f"  {key[0]} -> {key[1]}:{key[2]}  "
              f"ja3={rec.ja3_hash}  sni={rec.server_name}{flag}")

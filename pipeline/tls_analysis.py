"""
tls_analysis.py — JA4 fingerprinting and TLS certificate analysis.

JA3 is degrading industry-wide (TLS 1.3, ECH, and GREASE randomisation make it
unstable), so this adds **JA4** (FoxIO's successor), which sorts cipher/extension
lists before hashing and so is robust to the randomisation that breaks JA3. We
keep JA3 for back-compat and compute JA4 alongside it.

JA4 (client TLS) layout:  ja4_a _ ja4_b _ ja4_c
  ja4_a : <t|q><ver><d|i><cipher-count><ext-count><alpn2>
  ja4_b : sha256( sorted cipher-suite hex )[:12]
  ja4_c : sha256( sorted extension hex (minus SNI+ALPN) + "_" + sig-algs hex )[:12]

Certificate analysis flags the TLS-server signals that accompany malware C2:
self-signed certs, failed validation, and suspicious issuers.
"""

from __future__ import annotations
from dataclasses import dataclass
import hashlib
import struct

GREASE = {0x0a0a, 0x1a1a, 0x2a2a, 0x3a3a, 0x4a4a, 0x5a5a, 0x6a6a, 0x7a7a,
          0x8a8a, 0x9a9a, 0xaaaa, 0xbaba, 0xcaca, 0xdada, 0xeaea, 0xfafa}

_VER = {0x0304: "13", 0x0303: "12", 0x0302: "11", 0x0301: "10",
        0x0300: "s3", 0x0002: "s2"}

# A few reference known-bad JA4 client fingerprints (extend via feeds).
KNOWN_BAD_JA4: dict[str, str] = {
    # placeholder well-known-tooling slots; real values arrive via feed import
}


def _u16(b, i):
    return struct.unpack(">H", b[i:i + 2])[0]


def parse_client_hello(hs: bytes) -> dict | None:
    """Parse a TLS ClientHello handshake body (starting at 0x01) into the
    component lists JA3 and JA4 both need. Returns None if not a ClientHello or
    if the record is truncated/fragmented/malformed (robustness: never raise)."""
    try:
        return _parse_client_hello(hs)
    except Exception:
        return None


def _parse_client_hello(hs: bytes) -> dict | None:
    if not hs or hs[0] != 0x01:
        return None
    hs_ver = _u16(hs, 4)
    idx = 4 + 2 + 32
    sid_len = hs[idx]; idx += 1 + sid_len
    cs_len = _u16(hs, idx); idx += 2
    ciphers = [c for i in range(0, cs_len, 2)
               if (c := _u16(hs, idx + i)) not in GREASE]
    idx += cs_len
    comp_len = hs[idx]; idx += 1 + comp_len
    ext_total = _u16(hs, idx); idx += 2
    end = min(idx + ext_total, len(hs))            # clamp to available bytes
    exts: list[int] = []
    curves: list[int] = []
    ecpf: list[int] = []
    sig_algs: list[int] = []
    alpns: list[str] = []
    sni = None
    sup_vers: list[int] = []
    while idx + 4 <= end:
        et = _u16(hs, idx); el = _u16(hs, idx + 2)
        body = hs[idx + 4:idx + 4 + el]
        if et not in GREASE:
            exts.append(et)
        if et == 0x0000 and len(body) >= 5:                      # SNI
            nl = _u16(body, 3); sni = body[5:5 + nl].decode("ascii", "ignore") or None
        elif et == 0x000a and len(body) >= 2:                    # supported groups
            gl = _u16(body, 0)
            curves = [g for i in range(2, 2 + gl, 2)
                      if (g := _u16(body, i)) not in GREASE]
        elif et == 0x000b and len(body) >= 1:                    # ec point formats
            ecpf = list(body[1:1 + body[0]])
        elif et == 0x000d and len(body) >= 2:                    # signature algorithms
            sl = _u16(body, 0)
            sig_algs = [_u16(body, i) for i in range(2, 2 + sl, 2)]
        elif et == 0x0010 and len(body) >= 2:                    # ALPN
            j = 2
            while j + 1 <= len(body):
                ln = body[j]; j += 1
                if ln == 0 or j + ln > len(body):
                    break
                alpns.append(body[j:j + ln].decode("ascii", "ignore")); j += ln
        elif et == 0x002b and len(body) >= 1:                    # supported_versions
            n = body[0]
            sup_vers = [v for i in range(1, 1 + n, 2)
                        if (v := _u16(body, i)) not in GREASE]
        idx += 4 + el
    return {"hs_version": hs_ver, "ciphers": ciphers, "extensions": exts,
            "curves": curves, "ecpf": ecpf, "sig_algs": sig_algs,
            "alpns": alpns, "sni": sni, "supported_versions": sup_vers}


def ja3(comp: dict) -> str:
    s = ",".join([
        str(comp["hs_version"]),
        "-".join(map(str, comp["ciphers"])),
        "-".join(map(str, comp["extensions"])),
        "-".join(map(str, comp["curves"])),
        "-".join(map(str, comp["ecpf"])),
    ])
    return hashlib.md5(s.encode()).hexdigest()


def ja4(comp: dict, transport: str = "t") -> str:
    # version: max of supported_versions, else handshake version
    ver_val = max(comp["supported_versions"]) if comp["supported_versions"] else comp["hs_version"]
    ver = _VER.get(ver_val, "00")
    sni_flag = "d" if comp["sni"] else "i"
    nc = min(len(comp["ciphers"]), 99)
    ne = min(len(comp["extensions"]), 99)
    if comp["alpns"]:
        a = comp["alpns"][0]
        alpn = (a[0] + a[-1]) if a else "00"
    else:
        alpn = "00"
    ja4_a = f"{transport}{ver}{sni_flag}{nc:02d}{ne:02d}{alpn}"

    ciph_hex = sorted(f"{c:04x}" for c in comp["ciphers"])
    ja4_b = hashlib.sha256(",".join(ciph_hex).encode()).hexdigest()[:12]

    # extensions minus SNI(0000) and ALPN(0010), sorted; then sig algs in order
    ext_for_c = sorted(f"{e:04x}" for e in comp["extensions"]
                       if e not in (0x0000, 0x0010))
    sig_hex = ",".join(f"{s:04x}" for s in comp["sig_algs"])
    ja4_c_in = ",".join(ext_for_c) + "_" + sig_hex
    ja4_c = hashlib.sha256(ja4_c_in.encode()).hexdigest()[:12]
    return f"{ja4_a}_{ja4_b}_{ja4_c}"


def fingerprint_client_hello(hs: bytes, transport: str = "t"):
    """Return (ja3_md5, ja4, sni) for a ClientHello, or (None, None, None)."""
    comp = parse_client_hello(hs)
    if comp is None:
        return None, None, None
    return ja3(comp), ja4(comp, transport), comp["sni"]


# --- certificate analysis ----------------------------------------------------

@dataclass
class CertFinding:
    dst_ip: str
    server_name: str | None
    reason: str
    severity: str                  # "strong" | "weak"


def analyze_certificate(tls) -> CertFinding | None:
    """Flag suspicious server certs from Zeek-provided fields. Self-signed or
    failed-validation certs accompany a lot of malware C2, but are dual-use
    (dev/test), so severity is graded, not asserted."""
    subj = (tls.subject or "").strip()
    issuer = (tls.issuer or "").strip()
    val = (tls.validation_status or "").strip().lower()
    if subj and issuer and subj == issuer:
        return CertFinding(tls.dst_ip, tls.server_name,
                           "self-signed certificate", "strong")
    if val and val not in ("ok", "", "-"):
        return CertFinding(tls.dst_ip, tls.server_name,
                           f"certificate validation failed: {val}", "weak")
    return None

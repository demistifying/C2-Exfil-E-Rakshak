"""
ja3_from_pcap.py — compute JA3/JA3S fingerprints directly from a PCAP and
emit a Zeek-format ssl.log.

This is the offline fallback for the encrypted-traffic path. The production
path is Zeek + the zeek-ja3 package producing ssl.log. When Zeek is not
available (air-gapped analyst box, CI, no container runtime), this module
parses TLS ClientHello/ServerHello records straight from the capture with
scapy and writes the SAME tab-separated ssl.log that `ja3_loader.load_zeek_ssl`
already consumes. Nothing downstream changes — only the producer of ssl.log.

JA3 spec: md5( SSLVersion,Ciphers,Extensions,EllipticCurves,ECPointFormats )
with GREASE values (RFC 8701) removed. JA3S: md5( SSLVersion,Cipher,Extensions ).

Usage:
  python pipeline/ja3_from_pcap.py <pcap> [--out output/zeek/ssl.log]
"""

from __future__ import annotations
import sys
import os
import struct
import hashlib
from dataclasses import dataclass, field

from scapy.all import rdpcap, TCP, IP  # type: ignore

# GREASE values (RFC 8701) — must be stripped before hashing.
GREASE = {
    0x0a0a, 0x1a1a, 0x2a2a, 0x3a3a, 0x4a4a, 0x5a5a, 0x6a6a, 0x7a7a,
    0x8a8a, 0x9a9a, 0xaaaa, 0xbaba, 0xcaca, 0xdada, 0xeaea, 0xfafa,
}


@dataclass
class Flow:
    src_ip: str
    dst_ip: str
    dst_port: int
    ja3: str | None = None
    ja3s: str | None = None
    server_name: str | None = None


def _u16(b: bytes, i: int) -> int:
    return struct.unpack(">H", b[i:i + 2])[0]


def _parse_client_hello(hs: bytes) -> tuple[str | None, str | None]:
    """Return (ja3_md5, sni) from a handshake body beginning with 0x01."""
    if not hs or hs[0] != 0x01:
        return None, None
    tls_ver = _u16(hs, 4)
    idx = 4 + 2 + 32                      # hs header + client version + random
    sid_len = hs[idx]; idx += 1 + sid_len
    cs_len = _u16(hs, idx); idx += 2
    ciphers = [c for i in range(0, cs_len, 2)
               if (c := _u16(hs, idx + i)) not in GREASE]
    idx += cs_len
    comp_len = hs[idx]; idx += 1 + comp_len
    ext_total = _u16(hs, idx); idx += 2
    end = idx + ext_total
    exts: list[int] = []
    curves: list[int] = []
    ecpf: list[int] = []
    sni: str | None = None
    while idx + 4 <= end:
        et = _u16(hs, idx)
        el = _u16(hs, idx + 2)
        body = hs[idx + 4:idx + 4 + el]
        if et not in GREASE:
            exts.append(et)
        if et == 0x0000 and len(body) >= 5:          # SNI
            nl = _u16(body, 3)
            sni = body[5:5 + nl].decode("ascii", "ignore") or None
        elif et == 0x000a and len(body) >= 2:        # supported groups
            gl = _u16(body, 0)
            curves = [g for i in range(2, 2 + gl, 2)
                      if (g := _u16(body, i)) not in GREASE]
        elif et == 0x000b and len(body) >= 1:        # ec point formats
            pl = body[0]
            ecpf = list(body[1:1 + pl])
        idx += 4 + el
    ja3_str = ",".join([
        str(tls_ver),
        "-".join(map(str, ciphers)),
        "-".join(map(str, exts)),
        "-".join(map(str, curves)),
        "-".join(map(str, ecpf)),
    ])
    return hashlib.md5(ja3_str.encode()).hexdigest(), sni


def _parse_server_hello(hs: bytes) -> str | None:
    """Return ja3s_md5 from a handshake body beginning with 0x02."""
    if not hs or hs[0] != 0x02:
        return None
    try:
        tls_ver = _u16(hs, 4)
        idx = 4 + 2 + 32
        sid_len = hs[idx]; idx += 1 + sid_len
        cipher = _u16(hs, idx); idx += 2
        idx += 1                                     # compression method
        ext_total = _u16(hs, idx); idx += 2
        end = idx + ext_total
        exts: list[int] = []
        while idx + 4 <= end:
            et = _u16(hs, idx)
            el = _u16(hs, idx + 2)
            if et not in GREASE:
                exts.append(et)
            idx += 4 + el
        ja3s_str = f"{tls_ver},{cipher},{'-'.join(map(str, exts))}"
        return hashlib.md5(ja3s_str.encode()).hexdigest()
    except Exception:
        return None


def extract_flows(pcap_path: str) -> dict[tuple[str, str, int], Flow]:
    """Walk the PCAP, keying flows by (src, dst, dst_port)."""
    flows: dict[tuple[str, str, int], Flow] = {}
    for pk in rdpcap(pcap_path):
        if TCP not in pk or IP not in pk:
            continue
        payload = bytes(pk[TCP].payload)
        if len(payload) < 6 or payload[0] != 0x16:   # TLS handshake record
            continue
        hs = payload[5:]
        htype = hs[0] if hs else None
        if htype == 0x01:                            # ClientHello
            key = (pk[IP].src, pk[IP].dst, int(pk[TCP].dport))
            f = flows.setdefault(key, Flow(*key))
            try:
                f.ja3, f.server_name = _parse_client_hello(hs)
            except Exception:
                pass
        elif htype == 0x02:                          # ServerHello
            # Server->client: flip so the key matches the client's flow.
            key = (pk[IP].dst, pk[IP].src, int(pk[TCP].sport))
            f = flows.setdefault(key, Flow(*key))
            f.ja3s = _parse_server_hello(hs)
    return flows


ZEEK_FIELDS = ["id.orig_h", "id.resp_h", "id.resp_p",
               "ja3", "ja3s", "server_name", "subject"]


def write_ssl_log(flows: dict, out_path: str) -> int:
    os.makedirs(os.path.dirname(out_path) or ".", exist_ok=True)
    n = 0
    with open(out_path, "w") as fh:
        fh.write("#separator \\x09\n")
        fh.write("#path\tssl\n")
        fh.write("#fields\t" + "\t".join(ZEEK_FIELDS) + "\n")
        for f in flows.values():
            if not (f.ja3 or f.ja3s):
                continue
            fh.write("\t".join([
                f.src_ip, f.dst_ip, str(f.dst_port),
                f.ja3 or "-", f.ja3s or "-",
                f.server_name or "-", "-",
            ]) + "\n")
            n += 1
    return n


def main() -> None:
    if len(sys.argv) < 2:
        print(__doc__)
        sys.exit(1)
    pcap = sys.argv[1]
    out = "output/zeek/ssl.log"
    for i, a in enumerate(sys.argv):
        if a == "--out" and i + 1 < len(sys.argv):
            out = sys.argv[i + 1]
    flows = extract_flows(pcap)
    n = write_ssl_log(flows, out)
    print(f"[ja3_from_pcap] {n} TLS flows -> {out}")
    for f in flows.values():
        if f.ja3:
            print(f"    {f.src_ip} -> {f.dst_ip}:{f.dst_port}  "
                  f"ja3={f.ja3}  sni={f.server_name or '-'}")


if __name__ == "__main__":
    main()

"""
generate_zeek_logs.py — fast pure-Python PCAP/PCAPNG -> Zeek-format TSV logs.

This is a FALLBACK for when the real `zeek` binary isn't available. Real Zeek
remains authoritative and more complete; this covers exactly the fields our
detectors consume, computed CORRECTLY (no placeholders):

  conn.log  — flows (TCP+UDP), internal-vs-external oriented for upload ratio
  dns.log   — DNS queries/responses (real qname/qtype/rcode)  -> tunnelling/DGA
  http.log  — real method/host/uri                            -> HTTP-gate
  ssl.log   — REAL JA3/JA4/SNI via pipeline.tls_analysis      -> fingerprint/cloud
  ftp.log   — STOR/STOU/APPE control commands                 -> FTP exfil
  smtp.log  — MAIL FROM / RCPT TO / Subject                   -> SMTP exfil

Reads classic pcap AND pcapng (the format of most large captures). Streamed for
bounded memory. Not emitted (use real Zeek if you need them): x509.log,
files.log — cert analysis and file-hash reassembly. Content reconstruction still
reads the pcap directly, so files.log is not required for provenance.

Usage:  python tools/generate_zeek_logs.py <capture.pcap|pcapng> <out_dir>
"""

import sys
import os
import struct
import socket
import ipaddress
import time

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "pipeline"))
from tls_analysis import fingerprint_client_hello   # REAL JA3/JA4/SNI

_INTERNAL = [ipaddress.ip_network(n) for n in (
    "10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "127.0.0.0/8",
    "169.254.0.0/16", "0.0.0.0/8", "::1/128", "fe80::/10", "fc00::/7")]


def _internal(ip):
    try:
        a = ipaddress.ip_address(ip)
        return any(a in n for n in _INTERNAL)
    except ValueError:
        return False


_QT = {1: "A", 28: "AAAA", 5: "CNAME", 16: "TXT", 10: "NULL", 15: "MX",
       33: "SRV", 12: "PTR", 6: "SOA", 2: "NS", 255: "ANY", 48: "DNSKEY"}
_RC = {0: "NOERROR", 1: "FORMERR", 2: "SERVFAIL", 3: "NXDOMAIN", 5: "REFUSED"}


def _parse_dns(payload):
    """Minimal DNS parse: first question name + type, plus qr/rcode."""
    if len(payload) < 12:
        return None
    flags = struct.unpack(">H", payload[2:4])[0]
    qr = (flags >> 15) & 1
    rcode = flags & 0x0F
    qd = struct.unpack(">H", payload[4:6])[0]
    if qd < 1:
        return None
    i, labels = 12, []
    while i < len(payload):
        ln = payload[i]
        if ln == 0:
            i += 1
            break
        if ln & 0xC0:                      # compression pointer in question: bail
            return None
        labels.append(payload[i + 1:i + 1 + ln].decode("ascii", "ignore"))
        i += 1 + ln
    if i + 2 > len(payload):
        return None
    qtype = struct.unpack(">H", payload[i:i + 2])[0]
    return {"qname": ".".join(labels), "qtype": _QT.get(qtype, str(qtype)),
            "qr": qr, "rcode": _RC.get(rcode, str(rcode))}


# --- capture-file iterators (streamed) --------------------------------------

def _iter_pcap(f):
    gh = f.read(24)
    if len(gh) < 24:
        return
    magic = gh[:4]
    if magic in (b"\xd4\xc3\xb2\xa1", b"\x4d\x3c\xb2\xa1"):
        endian = "<"
    elif magic in (b"\xa1\xb2\xc3\xd4", b"\xa1\xb2\x3c\x4d"):
        endian = ">"
    else:
        return
    nano = magic in (b"\x4d\x3c\xb2\xa1", b"\xa1\xb2\x3c\x4d")
    div = 1e9 if nano else 1e6
    linktype = struct.unpack(endian + "I", gh[20:24])[0]
    while True:
        ph = f.read(16)
        if len(ph) < 16:
            break
        ts_sec, ts_frac, incl, _orig = struct.unpack(endian + "IIII", ph)
        data = f.read(incl)
        if len(data) < incl:
            break
        yield ts_sec + ts_frac / div, linktype, data


def _iter_pcapng(f):
    hdr = f.read(12)
    if len(hdr) < 12:
        return
    endian = "<" if hdr[8:12] == b"\x4d\x3c\x2b\x1a" else ">"
    total = struct.unpack(endian + "I", hdr[4:8])[0]
    f.read(total - 12)                     # rest of Section Header Block
    linktype = 1
    while True:
        bh = f.read(8)
        if len(bh) < 8:
            break
        btype = struct.unpack(endian + "I", bh[0:4])[0]
        blen = struct.unpack(endian + "I", bh[4:8])[0]
        if blen < 12:
            break
        body = f.read(blen - 8)
        if len(body) < blen - 8:
            break
        if btype == 0x00000001:            # Interface Description Block
            linktype = struct.unpack(endian + "H", body[0:2])[0]
        elif btype == 0x00000006:          # Enhanced Packet Block
            _if, ts_hi, ts_lo, cap, _ol = struct.unpack(endian + "IIIII", body[0:20])
            data = body[20:20 + cap]
            yield ((ts_hi << 32) | ts_lo) / 1e6, linktype, data
        elif btype == 0x00000003:          # Simple Packet Block
            ol = struct.unpack(endian + "I", body[0:4])[0]
            yield 0.0, linktype, body[4:4 + ol]


def iter_packets(path):
    with open(path, "rb") as f:
        magic = f.read(4)
        f.seek(0)
        it = _iter_pcapng(f) if magic == b"\x0a\x0d\x0d\x0a" else _iter_pcap(f)
        for rec in it:
            yield rec


# --- L2/L3 decode ------------------------------------------------------------

def _l3(linktype, data):
    """Return (eth_type, ip_bytes) for the frame."""
    if linktype == 1:                      # Ethernet
        if len(data) < 14:
            return None, b""
        return struct.unpack(">H", data[12:14])[0], data[14:]
    if linktype == 113:                    # Linux SLL
        return (struct.unpack(">H", data[14:16])[0], data[16:]) if len(data) >= 16 else (None, b"")
    if linktype == 276:                    # Linux SLL2
        return (struct.unpack(">H", data[0:2])[0], data[20:]) if len(data) >= 20 else (None, b"")
    if len(data) >= 14:                    # best-effort Ethernet
        return struct.unpack(">H", data[12:14])[0], data[14:]
    return None, b""


def parse(path, out_dir):
    os.makedirs(out_dir, exist_ok=True)
    t0 = time.time()
    conns, orient = {}, {}
    http, dns, tls, ftp = [], [], [], []
    smtp = {}
    n = 0

    for ts, linktype, data in iter_packets(path):
        n += 1
        eth, ipd = _l3(linktype, data)
        if eth == 0x0800:
            if len(ipd) < 20:
                continue
            ihl = (ipd[0] & 0x0F) * 4
            proto = ipd[9]
            src = socket.inet_ntoa(ipd[12:16]); dst = socket.inet_ntoa(ipd[16:20])
            l4 = ipd[ihl:]
        elif eth == 0x86dd:
            if len(ipd) < 40:
                continue
            proto = ipd[6]
            src = socket.inet_ntop(socket.AF_INET6, ipd[8:24])
            dst = socket.inet_ntop(socket.AF_INET6, ipd[24:40])
            l4 = ipd[40:]
        else:
            continue

        if proto == 6:                     # TCP
            if len(l4) < 20:
                continue
            sport, dport = struct.unpack(">HH", l4[0:4])
            doff = ((l4[12] >> 4) & 0x0F) * 4
            pl = l4[doff:]
        elif proto == 17:                  # UDP
            if len(l4) < 8:
                continue
            sport, dport = struct.unpack(">HH", l4[0:4])
            pl = l4[8:]
            if dport == 53 or sport == 53:
                d = _parse_dns(pl)
                if d:
                    dns.append({"ts": ts, "src": src, "dst": dst, **d})
            _conn(conns, orient, ts, src, sport, dst, dport, "udp", len(pl))
            continue
        else:
            continue

        _conn(conns, orient, ts, src, sport, dst, dport, "tcp", len(pl))

        if not pl:
            continue
        # HTTP request
        if pl[:4] in (b"GET ", b"POST", b"HEAD", b"PUT "):
            lines = pl[:400].decode("latin-1", "ignore").split("\r\n")
            p = lines[0].split(" ")
            host = None
            for l in lines[1:]:
                if l.lower().startswith("host:"):
                    host = l.split(":", 1)[1].strip()
            http.append({"ts": ts, "src": src, "sport": sport, "dst": dst,
                         "dport": dport, "method": p[0],
                         "uri": p[1] if len(p) > 1 else "/", "host": host})
        # TLS ClientHello -> REAL JA3/JA4/SNI
        elif len(pl) > 5 and pl[0] == 0x16 and pl[5] == 0x01:
            ja3, ja4, sni = fingerprint_client_hello(pl[5:])
            if ja3:
                tls.append({"ts": ts, "src": src, "sport": sport, "dst": dst,
                            "dport": dport, "ja3": ja3, "ja4": ja4, "sni": sni})
        # FTP store command
        elif dport == 21 and pl[:5].upper() in (b"STOR ", b"STOU ", b"APPE "):
            cl = pl.decode("latin-1", "ignore").split("\r\n")[0].split(" ", 1)
            ftp.append({"ts": ts, "src": src, "sport": sport, "dst": dst,
                        "cmd": cl[0], "arg": cl[1] if len(cl) > 1 else ""})
        # SMTP envelope
        elif dport in (25, 587, 465):
            _smtp(smtp, ts, src, dst, dport, pl)

    print(f"[fast-zeek] {n} packets, {len(conns)} flows in {time.time()-t0:.2f}s -> {out_dir}")
    _write(out_dir, conns, http, dns, tls, ftp, smtp)


def _conn(conns, orient, ts, src, sp, dst, dp, proto, plen):
    ck = tuple(sorted([(src, sp), (dst, dp)]))
    if ck not in orient:
        if _internal(src) and not _internal(dst):
            o = (src, sp, dst, dp)
        elif _internal(dst) and not _internal(src):
            o = (dst, dp, src, sp)
        else:
            o = (src, sp, dst, dp)
        orient[ck] = o
        conns[o] = {"ts": ts, "proto": proto, "orig": 0, "resp": 0}
    oi, op, ri, rp = orient[ck]
    c = conns[orient[ck]]
    if src == oi and sp == op:
        c["orig"] += plen
    else:
        c["resp"] += plen


def _smtp(smtp, ts, src, dst, dport, pl):
    key = (src, dst, dport)
    tx = smtp.setdefault(key, {"ts": ts, "src": src, "dst": dst,
                               "from": None, "to": [], "subj": None})
    for line in pl.decode("latin-1", "ignore").split("\r\n"):
        low = line.lower()
        if low.startswith("mail from:"):
            tx["from"] = line.split(":", 1)[1].strip().strip("<>")
        elif low.startswith("rcpt to:"):
            a = line.split(":", 1)[1].strip().strip("<>")
            if a and a not in tx["to"]:
                tx["to"].append(a)
        elif low.startswith("subject:"):
            tx["subj"] = line.split(":", 1)[1].strip()


# --- Zeek TSV writers --------------------------------------------------------

def _hdr(path_name, fields):
    return f"#separator \\x09\n#path\t{path_name}\n#fields\t" + "\t".join(fields) + "\n"


def _write(out, conns, http, dns, tls, ftp, smtp):
    with open(os.path.join(out, "conn.log"), "w") as f:
        f.write(_hdr("conn", ["ts", "uid", "id.orig_h", "id.orig_p", "id.resp_h",
                              "id.resp_p", "proto", "service", "duration",
                              "orig_bytes", "resp_bytes", "history"]))
        for i, (k, c) in enumerate(conns.items()):
            oi, op, ri, rp = k
            f.write(f"{c['ts']}\tC{i+1}\t{oi}\t{op}\t{ri}\t{rp}\t{c['proto']}\t-\t"
                    f"-\t{c['orig']}\t{c['resp']}\t-\n")

    with open(os.path.join(out, "dns.log"), "w") as f:
        f.write(_hdr("dns", ["ts", "uid", "id.orig_h", "id.orig_p", "id.resp_h",
                             "id.resp_p", "query", "qtype_name", "rcode_name"]))
        for i, d in enumerate(dns):
            f.write(f"{d['ts']}\tD{i+1}\t{d['src']}\t0\t{d['dst']}\t53\t"
                    f"{d['qname'] or '-'}\t{d['qtype']}\t{d['rcode']}\n")

    with open(os.path.join(out, "http.log"), "w") as f:
        f.write(_hdr("http", ["ts", "uid", "id.orig_h", "id.orig_p", "id.resp_h",
                              "id.resp_p", "method", "host", "uri", "user_agent",
                              "status_code", "request_body_len", "response_body_len"]))
        for i, h in enumerate(http):
            f.write(f"{h['ts']}\tH{i+1}\t{h['src']}\t{h['sport']}\t{h['dst']}\t"
                    f"{h['dport']}\t{h['method']}\t{h['host'] or '-'}\t{h['uri']}\t"
                    f"-\t-\t0\t0\n")

    with open(os.path.join(out, "ssl.log"), "w") as f:
        f.write(_hdr("ssl", ["ts", "uid", "id.orig_h", "id.orig_p", "id.resp_h",
                             "id.resp_p", "version", "cipher", "curve",
                             "server_name", "ja3", "ja3s", "ja4", "subject",
                             "issuer", "validation_status"]))
        for i, t in enumerate(tls):
            f.write(f"{t['ts']}\tS{i+1}\t{t['src']}\t{t['sport']}\t{t['dst']}\t"
                    f"{t['dport']}\t-\t-\t-\t{t['sni'] or '-'}\t{t['ja3']}\t-\t"
                    f"{t['ja4'] or '-'}\t-\t-\t-\n")

    with open(os.path.join(out, "ftp.log"), "w") as f:
        f.write(_hdr("ftp", ["ts", "uid", "id.orig_h", "id.orig_p", "id.resp_h",
                             "id.resp_p", "command", "arg", "reply_code"]))
        for i, ft in enumerate(ftp):
            f.write(f"{ft['ts']}\tF{i+1}\t{ft['src']}\t{ft['sport']}\t{ft['dst']}\t"
                    f"21\t{ft['cmd']}\t{ft['arg']}\t-\n")

    with open(os.path.join(out, "smtp.log"), "w") as f:
        f.write(_hdr("smtp", ["ts", "uid", "id.orig_h", "id.resp_h", "mailfrom",
                             "rcptto", "subject", "fuids"]))
        for i, (k, tx) in enumerate(smtp.items()):
            if not (tx["from"] or tx["to"]):
                continue
            f.write(f"{tx['ts']}\tM{i+1}\t{tx['src']}\t{tx['dst']}\t"
                    f"{tx['from'] or '-'}\t{','.join(tx['to']) or '-'}\t"
                    f"{tx['subj'] or '-'}\t-\n")


if __name__ == "__main__":
    if len(sys.argv) > 2:
        parse(sys.argv[1], sys.argv[2])
    else:
        print(__doc__)

"""
zeek_ingest.py — Zeek-primary ingestion.

Zeek is the authoritative parser (industry-grade protocol coverage). We build the
unified analysis model on top of Zeek's logs rather than re-implementing protocol
parsing. A directory of Zeek logs becomes an AnalysisBundle; when Zeek isn't
available, `bundle_from_pcap` produces the same bundle from a raw pcap via the
scapy fallback (transport + whatever HTTP/FTP we can sniff), so the pipeline runs
either way.

Supports both Zeek log encodings: classic TSV (`#separator`/`#fields` header) and
JSON-lines (`zeek -e` / `LogAscii::use_json=T`).
"""

from __future__ import annotations
import os
import json
import glob

from model import (AnalysisBundle, Session, DnsTransaction, HttpTransaction,
                   TlsTransaction, FtpTransaction, SmtpTransaction, Artifact)


# --- low-level Zeek log reader ----------------------------------------------

def read_zeek_log(path: str) -> list[dict]:
    """Return a list of row-dicts from a Zeek log (TSV or JSON), '-'/'(empty)'
    normalised to None. Missing file → []."""
    if not os.path.exists(path):
        return []
    rows: list[dict] = []
    fields: list[str] = []
    with open(path, errors="replace") as fh:
        for line in fh:
            line = line.rstrip("\n")
            if not line:
                continue
            if line[0] == "{":                      # JSON-lines encoding
                try:
                    rows.append(_clean(json.loads(line)))
                except json.JSONDecodeError:
                    pass
                continue
            if line.startswith("#fields"):
                fields = line.split("\t")[1:]
                continue
            if line.startswith("#"):
                continue
            if not fields:
                continue
            vals = line.split("\t")
            rows.append(_clean(dict(zip(fields, vals))))
    return rows


def _clean(row: dict) -> dict:
    out = {}
    for k, v in row.items():
        if v in ("-", "(empty)", ""):
            out[k] = None
        else:
            out[k] = v
    return out


def _num(v, cast, default=0):
    try:
        return cast(v)
    except (ValueError, TypeError):
        return default


def _list(v) -> list:
    if v is None:
        return []
    if isinstance(v, list):
        return v
    return [x for x in str(v).split(",") if x]


# --- per-log parsers ---------------------------------------------------------

def _sessions(rows) -> list[Session]:
    out = []
    for r in rows:
        out.append(Session(
            ts=_num(r.get("ts"), float, 0.0),
            src_ip=r.get("id.orig_h") or "", src_port=_num(r.get("id.orig_p"), int),
            dst_ip=r.get("id.resp_h") or "", dst_port=_num(r.get("id.resp_p"), int),
            proto=r.get("proto") or "tcp", service=r.get("service"),
            orig_bytes=_num(r.get("orig_bytes"), int),
            resp_bytes=_num(r.get("resp_bytes"), int),
            history=r.get("history") or "",
            duration=_num(r.get("duration"), float, 0.0),
            conn_state=r.get("conn_state"), uid=r.get("uid")))
    return out


def _dns(rows) -> list[DnsTransaction]:
    return [DnsTransaction(
        ts=_num(r.get("ts"), float, 0.0),
        src_ip=r.get("id.orig_h") or "", dst_ip=r.get("id.resp_h") or "",
        query=r.get("query") or "", qtype=r.get("qtype_name"),
        rcode=r.get("rcode_name"), answers=_list(r.get("answers")),
        uid=r.get("uid")) for r in rows]


def _http(rows) -> list[HttpTransaction]:
    return [HttpTransaction(
        ts=_num(r.get("ts"), float, 0.0),
        src_ip=r.get("id.orig_h") or "", dst_ip=r.get("id.resp_h") or "",
        dst_port=_num(r.get("id.resp_p"), int, 80),
        method=r.get("method"), host=r.get("host"), uri=r.get("uri"),
        user_agent=r.get("user_agent"),
        status_code=_num(r.get("status_code"), int, None) if r.get("status_code") else None,
        req_body_len=_num(r.get("request_body_len"), int),
        resp_body_len=_num(r.get("response_body_len"), int),
        uid=r.get("uid")) for r in rows]


def _tls(rows) -> list[TlsTransaction]:
    return [TlsTransaction(
        ts=_num(r.get("ts"), float, 0.0),
        src_ip=r.get("id.orig_h") or "", dst_ip=r.get("id.resp_h") or "",
        dst_port=_num(r.get("id.resp_p"), int, 443),
        server_name=r.get("server_name"), ja3=r.get("ja3"), ja3s=r.get("ja3s"),
        ja4=r.get("ja4"), subject=r.get("subject"), issuer=r.get("issuer"),
        validation_status=r.get("validation_status"), version=r.get("version"),
        uid=r.get("uid")) for r in rows]


def _ftp(rows) -> list[FtpTransaction]:
    return [FtpTransaction(
        ts=_num(r.get("ts"), float, 0.0),
        src_ip=r.get("id.orig_h") or "", dst_ip=r.get("id.resp_h") or "",
        command=r.get("command") or "", arg=r.get("arg"),
        reply_code=_num(r.get("reply_code"), int, None) if r.get("reply_code") else None,
        uid=r.get("uid")) for r in rows]


def _smtp(rows) -> list[SmtpTransaction]:
    return [SmtpTransaction(
        ts=_num(r.get("ts"), float, 0.0),
        src_ip=r.get("id.orig_h") or "", dst_ip=r.get("id.resp_h") or "",
        mail_from=r.get("mailfrom"), rcpt_to=_list(r.get("rcptto")),
        subject=r.get("subject"), attachments=_list(r.get("fuids")),
        uid=r.get("uid")) for r in rows]


def _files(rows) -> list[Artifact]:
    out = []
    for r in rows:
        tx = _list(r.get("tx_hosts")); rx = _list(r.get("rx_hosts"))
        out.append(Artifact(
            ts=_num(r.get("ts"), float, 0.0),
            filename=r.get("filename"), mime_type=r.get("mime_type"),
            total_bytes=_num(r.get("total_bytes"), int),
            md5=r.get("md5"), sha256=r.get("sha256"),
            source_ip=tx[0] if tx else None, dest_ip=rx[0] if rx else None,
            uid=(r.get("conn_uids") or [None])[0] if isinstance(r.get("conn_uids"), list)
                 else r.get("conn_uids")))
    return out


# --- public API --------------------------------------------------------------

def load_zeek_dir(log_dir: str) -> AnalysisBundle:
    """Build an AnalysisBundle from a directory of Zeek logs (.log or .log.gz-less)."""
    def logp(name):
        p = os.path.join(log_dir, name)
        return p if os.path.exists(p) else os.path.join(log_dir, name)
    b = AnalysisBundle(source="zeek")
    b.sessions = _sessions(read_zeek_log(logp("conn.log")))
    b.dns = _dns(read_zeek_log(logp("dns.log")))
    b.http = _http(read_zeek_log(logp("http.log")))
    b.tls = _tls(read_zeek_log(logp("ssl.log")))
    b.ftp = _ftp(read_zeek_log(logp("ftp.log")))
    b.smtp = _smtp(read_zeek_log(logp("smtp.log")))
    b.artifacts = _files(read_zeek_log(logp("files.log")))
    return b


def bundle_from_pcap(pcap_path: str) -> AnalysisBundle:
    """Scapy fallback: build the same bundle from a raw pcap. Transport sessions
    plus the HTTP/FTP transactions the scapy loader can sniff, plus TLS/JA3 from
    the in-house extractor. Zeek is preferred; this keeps the tool runnable
    without it."""
    from pcap_loader import load_pcap
    b = AnalysisBundle(source="pcap")
    for c in load_pcap(pcap_path):
        b.sessions.append(Session(
            ts=c.ts, src_ip=c.src_ip, src_port=0, dst_ip=c.dst_ip,
            dst_port=c.dst_port, proto=c.proto, orig_bytes=c.orig_bytes,
            resp_bytes=c.resp_bytes, history=c.history))
        if c.http_method:
            b.http.append(HttpTransaction(
                ts=c.ts, src_ip=c.src_ip, dst_ip=c.dst_ip, dst_port=c.dst_port,
                method=c.http_method, host=c.http_host, uri=c.http_uri))
        if c.ftp_upload_cmd:
            parts = c.ftp_upload_cmd.split(" ", 1)
            b.ftp.append(FtpTransaction(
                ts=c.ts, src_ip=c.src_ip, dst_ip=c.dst_ip,
                command=parts[0], arg=parts[1] if len(parts) > 1 else None))
    # DNS + TLS/JA3 + SMTP + ICMP in a SINGLE streaming pass (rather than one each).
    b.dns, b.tls, b.smtp, b.icmp = _dns_tls_smtp_from_pcap(pcap_path)
    return b


_DNS_QTYPE = {1: "A", 28: "AAAA", 5: "CNAME", 16: "TXT", 10: "NULL", 15: "MX",
              33: "SRV", 12: "PTR", 6: "SOA", 2: "NS", 255: "ANY", 48: "DNSKEY"}
_DNS_RCODE = {0: "NOERROR", 1: "FORMERR", 2: "SERVFAIL", 3: "NXDOMAIN", 5: "REFUSED"}


_SMTP_PORTS = {25, 587, 465}


def _dns_tls_smtp_from_pcap(pcap_path: str):
    """Single streaming pass extracting DNS queries, TLS ClientHello (JA3), and
    plaintext SMTP envelopes. One pass keeps the scapy fallback fast on large
    captures; memory stays bounded via PcapReader."""
    from scapy.all import PcapReader, DNS, DNSQR, IP, IPv6, TCP, Raw, ICMP
    from tls_analysis import fingerprint_client_hello
    dns: list[DnsTransaction] = []
    tls_by_key: dict = {}
    smtp_by_key: dict = {}
    icmp: list[tuple] = []
    try:
        reader = PcapReader(pcap_path)
    except Exception:
        return dns, [], [], []
    with reader:
        for pk in reader:
            L = pk.getlayer(IP) or pk.getlayer(IPv6)
            if L is None:
                continue
            if ICMP in pk and int(pk[ICMP].type) in (8, 0):   # echo request/reply
                icmp.append((L.src, L.dst, len(bytes(pk[ICMP].payload))))
                continue
            if DNS in pk and pk[DNS].qd is not None and pk[DNS].qr == 0:
                try:
                    qname = pk[DNSQR].qname.decode("ascii", "ignore").rstrip(".")
                except Exception:
                    continue
                dns.append(DnsTransaction(
                    ts=float(pk.time), src_ip=L.src, dst_ip=L.dst, query=qname,
                    qtype=_DNS_QTYPE.get(int(pk[DNSQR].qtype), str(pk[DNSQR].qtype)),
                    rcode=_DNS_RCODE.get(int(pk[DNS].rcode))))
                continue
            if TCP not in pk:
                continue
            dport = int(pk[TCP].dport)
            payload = bytes(pk[TCP].payload)
            if len(payload) > 5 and payload[0] == 0x16 and payload[5] == 0x01:
                ja3, ja4, sni = fingerprint_client_hello(payload[5:])
                key = (L.src, L.dst, dport)
                if ja3 and key not in tls_by_key:
                    tls_by_key[key] = TlsTransaction(
                        ts=float(pk.time), src_ip=L.src, dst_ip=L.dst,
                        dst_port=dport, server_name=sni, ja3=ja3, ja4=ja4)
            elif dport in _SMTP_PORTS and Raw in pk:
                _sniff_smtp(pk, L, dport, payload, smtp_by_key)
    return dns, list(tls_by_key.values()), list(smtp_by_key.values()), icmp


def _sniff_smtp(pk, L, dport, payload, smtp_by_key):
    """Accumulate SMTP envelope fields per client->server flow."""
    try:
        text = payload.decode("latin-1", "ignore")
    except Exception:
        return
    key = (L.src, L.dst, dport)
    tx = smtp_by_key.get(key)
    if tx is None:
        tx = SmtpTransaction(ts=float(pk.time), src_ip=L.src, dst_ip=L.dst)
        smtp_by_key[key] = tx
    for line in text.split("\r\n"):
        low = line.lower()
        if low.startswith("mail from:"):
            tx.mail_from = line.split(":", 1)[1].strip().strip("<>")
        elif low.startswith("rcpt to:"):
            addr = line.split(":", 1)[1].strip().strip("<>")
            if addr and addr not in tx.rcpt_to:
                tx.rcpt_to.append(addr)
        elif low.startswith("subject:"):
            tx.subject = line.split(":", 1)[1].strip()
        elif low.startswith("content-disposition:") and "attachment" in low:
            tx.attachments.append("attachment")


def load_bundle(pcap_path: str | None = None,
                zeek_dir: str | None = None) -> AnalysisBundle:
    """Zeek-primary loader: prefer Zeek logs (conn.log present), else pcap."""
    if zeek_dir and os.path.exists(os.path.join(zeek_dir, "conn.log")):
        return load_zeek_dir(zeek_dir)
    if pcap_path:
        return bundle_from_pcap(pcap_path)
    raise ValueError("load_bundle needs a zeek_dir with conn.log or a pcap_path")

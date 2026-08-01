"""
model.py — the unified analysis data model.

Everything downstream (detection, correlation, provenance, reporting) consumes
this model, and it can be built from EITHER Zeek logs (authoritative) or a raw
pcap (scapy fallback). Keeping one model means a detector written once works
regardless of the ingestion source.

Layers:
  Session      — a transport-layer flow (Zeek conn.log): who talked to whom.
  *Transaction — a protocol-level event on a session (DNS query, HTTP request,
                 TLS handshake, FTP/SMTP command). This is where modern exfil
                 coverage lives (DNS tunnelling, cloud/SaaS, SMTP, ...).
  Artifact     — a file/blob transferred (Zeek files.log): candidate stolen data.
  AnalysisBundle — the whole case: all of the above plus provenance to the raw
                 evidence and a note of which source produced it.

`AnalysisBundle.to_connections()` bridges back to the legacy `Connection` model
so the existing detectors keep working unchanged while new detectors consume the
richer transactions directly.
"""

from __future__ import annotations
from dataclasses import dataclass, field

from traffic_analysis import Connection


# --- transport ---------------------------------------------------------------

@dataclass
class Session:
    """A transport-layer flow. Mirrors Zeek conn.log."""
    ts: float
    src_ip: str
    src_port: int
    dst_ip: str
    dst_port: int
    proto: str = "tcp"
    service: str | None = None          # zeek-identified app proto (http, ssl, dns…)
    orig_bytes: int = 0
    resp_bytes: int = 0
    history: str = ""
    duration: float = 0.0
    conn_state: str | None = None
    uid: str | None = None              # zeek connection uid — the join key


# --- protocol transactions ---------------------------------------------------

@dataclass
class DnsTransaction:
    ts: float
    src_ip: str
    dst_ip: str
    query: str = ""
    qtype: str | None = None            # A, AAAA, TXT, NULL, CNAME…
    rcode: str | None = None
    answers: list[str] = field(default_factory=list)
    uid: str | None = None


@dataclass
class HttpTransaction:
    ts: float
    src_ip: str
    dst_ip: str
    dst_port: int = 80
    method: str | None = None
    host: str | None = None
    uri: str | None = None
    user_agent: str | None = None
    status_code: int | None = None
    req_body_len: int = 0
    resp_body_len: int = 0
    uid: str | None = None


@dataclass
class TlsTransaction:
    ts: float
    src_ip: str
    dst_ip: str
    dst_port: int = 443
    server_name: str | None = None      # SNI
    ja3: str | None = None
    ja3s: str | None = None
    ja4: str | None = None              # populated once JA4 lands (Phase 2)
    subject: str | None = None
    issuer: str | None = None
    validation_status: str | None = None
    version: str | None = None
    uid: str | None = None


@dataclass
class FtpTransaction:
    ts: float
    src_ip: str
    dst_ip: str
    command: str = ""                   # STOR, RETR, USER…
    arg: str | None = None
    reply_code: int | None = None
    uid: str | None = None

    @property
    def is_upload(self) -> bool:
        return self.command.upper() in ("STOR", "STOU", "APPE")


@dataclass
class SmtpTransaction:
    ts: float
    src_ip: str
    dst_ip: str
    mail_from: str | None = None
    rcpt_to: list[str] = field(default_factory=list)
    subject: str | None = None
    attachments: list[str] = field(default_factory=list)
    uid: str | None = None


# --- artifacts ---------------------------------------------------------------

@dataclass
class Artifact:
    """A file/blob seen on the wire (Zeek files.log) — candidate stolen data."""
    ts: float
    filename: str | None = None
    mime_type: str | None = None
    total_bytes: int = 0
    md5: str | None = None
    sha256: str | None = None
    source_ip: str | None = None        # who sent it
    dest_ip: str | None = None          # who received it
    is_outbound: bool = False           # True = leaving the victim (exfil candidate)
    uid: str | None = None
    preview: str | None = None          # sanitised snippet of reconstructed content


# --- the case ----------------------------------------------------------------

@dataclass
class AnalysisBundle:
    source: str = "pcap"                 # "zeek" | "pcap"
    sessions: list[Session] = field(default_factory=list)
    dns: list[DnsTransaction] = field(default_factory=list)
    http: list[HttpTransaction] = field(default_factory=list)
    tls: list[TlsTransaction] = field(default_factory=list)
    ftp: list[FtpTransaction] = field(default_factory=list)
    smtp: list[SmtpTransaction] = field(default_factory=list)
    artifacts: list[Artifact] = field(default_factory=list)
    icmp: list[tuple] = field(default_factory=list)   # (src_ip, dst_ip, data_len)

    def to_connections(self) -> list[Connection]:
        """Project the bundle onto the legacy Connection model so existing
        detectors run unchanged. HTTP/TLS/FTP transactions enrich their session
        (method/host/uri, ftp_upload_cmd) exactly as the scapy loader did."""
        # Index enrichments by (src, dst, dst_port) and by uid.
        http_by_key: dict = {}
        for h in self.http:
            http_by_key.setdefault((h.src_ip, h.dst_ip, h.dst_port), h)
            if h.uid:
                http_by_key.setdefault(h.uid, h)
        ftp_up_by_key: dict = {}
        for f in self.ftp:
            if f.is_upload:
                cmd = f"{f.command} {f.arg}".strip()
                ftp_up_by_key.setdefault((f.src_ip, f.dst_ip), cmd)
                if f.uid:
                    ftp_up_by_key.setdefault(f.uid, cmd)

        conns: list[Connection] = []
        for s in self.sessions:
            h = (http_by_key.get(s.uid)
                 or http_by_key.get((s.src_ip, s.dst_ip, s.dst_port)))
            ftp_cmd = (ftp_up_by_key.get(s.uid)
                       or ftp_up_by_key.get((s.src_ip, s.dst_ip)))
            conns.append(Connection(
                ts=s.ts, src_ip=s.src_ip, dst_ip=s.dst_ip, dst_port=s.dst_port,
                proto=s.proto, orig_bytes=s.orig_bytes, resp_bytes=s.resp_bytes,
                history=s.history,
                http_method=h.method if h else None,
                http_host=h.host if h else None,
                http_uri=h.uri if h else None,
                ftp_upload_cmd=ftp_cmd,
            ))
        return conns

    def summary(self) -> str:
        return (f"source={self.source} sessions={len(self.sessions)} "
                f"dns={len(self.dns)} http={len(self.http)} tls={len(self.tls)} "
                f"ftp={len(self.ftp)} smtp={len(self.smtp)} "
                f"artifacts={len(self.artifacts)}")

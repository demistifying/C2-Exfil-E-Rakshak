"""
app_exfil.py — application-service exfiltration channels: cloud/SaaS and SMTP.

These are the channels where IP reputation fundamentally fails: the destination
is a legitimate provider (Google, Discord, Cloudflare) so the IP is clean, yet
the malware is using it to move stolen data. Detection is service-aware, and —
critically — RISK-tiered, because services differ enormously in dual-use:

  * high-risk : Telegram Bot API, Discord webhooks, paste sites, anonymous file
                hosts, tunnels — almost never used by legitimate automated data
                movement, so a hit is a strong signal.
  * dual-use  : Google Drive, Dropbox, OneDrive — heavily legitimate, so a hit is
                surfaced only as a weak candidate (the CIC-IDS lesson: don't turn
                a benign cloud endpoint into a confident verdict).

SMTP exfil (AgentTesla's classic channel): a victim sending mail during a
detonation is inherently suspicious; the recipient address and mail server are
the IOCs.
"""

from __future__ import annotations
from dataclasses import dataclass

# service domain -> (display name, risk)
CLOUD_SERVICES: dict[str, tuple[str, str]] = {
    # high-risk exfil channels
    "api.telegram.org": ("Telegram Bot API", "high"),
    "discord.com": ("Discord", "high"),
    "discordapp.com": ("Discord", "high"),
    "pastebin.com": ("Pastebin", "high"),
    "hastebin.com": ("Hastebin", "high"),
    "ghostbin.com": ("Ghostbin", "high"),
    "mega.nz": ("Mega", "high"),
    "mega.co.nz": ("Mega", "high"),
    "anonfiles.com": ("AnonFiles", "high"),
    "gofile.io": ("GoFile", "high"),
    "file.io": ("File.io", "high"),
    "transfer.sh": ("transfer.sh", "high"),
    "tmpfiles.org": ("tmpfiles", "high"),
    "0x0.st": ("0x0.st", "high"),
    "ngrok.io": ("ngrok tunnel", "high"),
    "trycloudflare.com": ("Cloudflare tunnel", "high"),
    # dual-use cloud storage
    "drive.google.com": ("Google Drive", "dual"),
    "drive.usercontent.google.com": ("Google Drive", "dual"),
    "docs.google.com": ("Google Docs", "dual"),
    "dropbox.com": ("Dropbox", "dual"),
    "dropboxapi.com": ("Dropbox API", "dual"),
    "onedrive.live.com": ("OneDrive", "dual"),
    "1drv.ms": ("OneDrive", "dual"),
}

_RISK_CONF = {"high": 0.75, "dual": 0.4}


@dataclass
class CloudFinding:
    service: str
    risk: str                    # "high" | "dual"
    domain: str
    dst_ip: str
    dst_port: int
    direction: str               # "upload" | "download" | "unknown"
    category: str                # "cloud_exfil" | "cloud_staging"
    confidence: float


@dataclass
class SmtpFinding:
    dst_ip: str
    mail_from: str | None
    rcpt_to: list[str]
    subject: str | None
    has_attachment: bool
    self_send: bool          # from == to: a mailbox emailing itself (stealer pattern)
    confidence: float


def _match_service(host: str | None) -> tuple[str, str, str] | None:
    """Return (service_name, risk, matched_domain) if host is a known service."""
    if not host:
        return None
    h = host.lower().rstrip(".")
    for domain, (name, risk) in CLOUD_SERVICES.items():
        if h == domain or h.endswith("." + domain):
            return name, risk, domain
    return None


def detect_cloud_exfil(tls, http, sessions) -> list[CloudFinding]:
    """Flag connections to known cloud/SaaS exfil services (via TLS SNI or HTTP
    host), risk-tiered, with best-effort upload/download direction from the
    session's byte ratio."""
    # index session byte direction by (src, dst, dport)
    byte_dir: dict = {}
    for s in sessions:
        byte_dir[(s.src_ip, s.dst_ip, s.dst_port)] = (s.orig_bytes, s.resp_bytes)

    findings: list[CloudFinding] = []
    seen: set = set()
    endpoints = [(t.src_ip, t.dst_ip, t.dst_port, t.server_name) for t in tls]
    endpoints += [(h.src_ip, h.dst_ip, h.dst_port, h.host) for h in http]
    for src, dst, dport, host in endpoints:
        m = _match_service(host)
        if not m or (dst, host) in seen:
            continue
        seen.add((dst, host))
        name, risk, domain = m
        orig, resp = byte_dir.get((src, dst, dport), (0, 0))
        if orig > resp * 1.2 and orig > 0:
            direction, category = "upload", "cloud_exfil"
        elif resp > orig:
            direction, category = "download", "cloud_staging"
        else:
            direction, category = "unknown", "cloud_exfil"
        findings.append(CloudFinding(
            service=name, risk=risk, domain=host or domain, dst_ip=dst,
            dst_port=dport, direction=direction, category=category,
            confidence=_RISK_CONF[risk]))
    return findings


def detect_smtp_exfil(smtp, sessions) -> list[SmtpFinding]:
    """Flag outbound SMTP sends. In a malware detonation the victim sending mail
    is inherently suspicious (AgentTesla-style credential/keystroke exfil)."""
    findings: list[SmtpFinding] = []
    for tx in smtp:
        if not (tx.mail_from or tx.rcpt_to):
            continue
        has_attach = bool(tx.attachments)
        mf = (tx.mail_from or "").lower()
        self_send = bool(mf and any(mf == r.lower() for r in tx.rcpt_to))
        conf = 0.6 + (0.15 if has_attach else 0.0) + (0.15 if self_send else 0.0)
        findings.append(SmtpFinding(
            dst_ip=tx.dst_ip, mail_from=tx.mail_from, rcpt_to=tx.rcpt_to,
            subject=tx.subject, has_attachment=has_attach, self_send=self_send,
            confidence=round(min(conf, 1.0), 2)))
    return findings

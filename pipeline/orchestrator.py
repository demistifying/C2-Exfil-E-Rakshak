"""
orchestrator.py — Windows C2/Exfiltration module, end-to-end runner.

Runs the full module pipeline on a PCAP:
  1. traffic analysis  (beaconing + exfil detection)
  2. attribution        (geo/ASN + reputation)
  2b. JA3 enrichment   (when Zeek ssl.log available)
  3. correlation        (host access <-> network exfil)   [needs sandbox input]
  4. emit               (shared exfil_events schema -> JSON, ready for Postgres)
  5. export             (CSV + STIX 2.1 IOC export)

Usage:
  python pipeline/orchestrator.py <pcap> [access_events.json] [--zeek-dir output/zeek]

If no access-events file is given, it uses the documented fixture and clearly
marks correlation output as fixture-based. The network stages (1-2) always run
on the REAL pcap.
"""

from __future__ import annotations
import sys
import os
import json
import uuid
import hashlib

sys.path.insert(0, os.path.dirname(__file__))
from pcap_loader import load_pcap
from zeek_ingest import load_bundle
from traffic_analysis import (detect_beaconing, detect_exfil, detect_ftp_exfil,
                              detect_unclassified_egress,
                              network_confidence_tier, _is_private_ip)
from attribution import attribute, init_threatintel_db
from correlation import correlate
from etw_ingest import load_etw_events, assess_clock_sync, IngestReport

MITRE = {  # capability -> ATT&CK technique
    "browser_credentials": "T1555.003",   # Credentials from Web Browsers
    "keystrokes": "T1056.001",            # Keylogging
    "screenshot": "T1113",                # Screen Capture
    "exfil": "T1041",                     # Exfiltration Over C2 Channel
    "beacon": "T1071.001",                # Application Layer Protocol: Web
    "ja3": "T1573",                       # Encrypted Channel (known-bad TLS fingerprint)
    "tls_cert": "T1573",                  # Encrypted Channel (suspicious certificate)
    "dns_tunnel": "T1071.004",            # Application Layer Protocol: DNS
    "dga": "T1568.002",                   # Domain Generation Algorithms
    "cloud_exfil": "T1567.002",           # Exfiltration to Cloud Storage
    "cloud_staging": "T1105",             # Ingress Tool Transfer (cloud staging)
    "smtp_exfil": "T1048.003",            # Exfil Over Unencrypted Non-C2 Protocol
    "http_c2": "T1071.001",               # Application Layer Protocol: Web (gate)
    "icmp_tunnel": "T1095",               # Non-Application Layer Protocol
    "port_mismatch": "T1571",             # Non-Standard Port
    "resolved_domain": "T1071.004",     # Application Layer Protocol: DNS (intended destination)
    "static_ioc": "T1071",                # C2 extracted from binary (dormant)
    "unclassified_egress": "T1041",       # Exfiltration Over C2 Channel (catch-all)
}


def build_network_events(pcap_path: str, zeek_dir: str | None = None,
                         static_prior_path: str | None = None,
                         handoff=None) -> list[dict]:
    """Stages 1-2: run detection + attribution.

    Zeek-primary: when a Zeek log directory with conn.log is supplied it is the
    authoritative source; otherwise we fall back to parsing the pcap directly.
    Both produce the same unified bundle, projected to Connection records for the
    detectors. If a static IOC prior from ST/DT is supplied, network findings
    that match a static-extracted C2 are promoted to confirmed.

    When a handoff manifest is supplied, the bundle is first scoped to the guest
    VM and detonation window (removes cross-VM / pre-post-detonation noise), and
    manifest honesty-gates are applied to the resulting events."""
    bundle = load_bundle(pcap_path=pcap_path, zeek_dir=zeek_dir)

    # Resolve the guest VM identity + simulated-C2 scope. Under simulated_inetsim
    # the C2 sits on a PRIVATE responder IP that the detectors' private-IP filter
    # would otherwise discard, blinding the whole analysis. `allow_dsts` lets the
    # detectors analyse exactly those responder IPs (guest->private-non-noise).
    from bundle_filter import (filter_bundle, infer_guest_ip, simulated_c2_scope,
                               _norm_guest_ip)
    guest_ip = None
    allow_dsts: set = set()
    # Infrastructure IPs are never C2: the guest VM itself and its DNS resolver(s).
    # A noisy static prior (e.g. Suricata-derived) can list these; contacting them
    # is expected and must not be confirmed as C2. Resolvers are the resp_h of DNS.
    infra_ips: set = {q.dst_ip for q in bundle.dns if getattr(q, "dst_ip", None)}
    if handoff is not None:
        guest_ip = _norm_guest_ip(handoff.guest_ip) or infer_guest_ip(bundle)
        infra_ips.add(guest_ip)
        filter_bundle(bundle, guest_ip=guest_ip,
                      start_utc=handoff.detonation_start_utc,
                      end_utc=handoff.detonation_end_utc)
        if handoff.simulated:
            # simulated C2 sits on a private responder — analyse it, but never the
            # guest or the resolver (those are transport, not the C2 endpoint).
            allow_dsts = simulated_c2_scope(bundle, guest_ip) - infra_ips
    infra_ips.discard(None)

    conns = bundle.to_connections()
    # raw contacted destinations (survive private-IP filtering) — used to decide
    # whether a static IOC was actually reached. Excludes infrastructure so a
    # resolver/guest in a noisy prior isn't falsely confirmed as a contacted C2.
    raw_observed_ips = {c.dst_ip for c in conns
                        if c.dst_ip and c.dst_ip not in infra_ips}
    raw_observed_domains = {(q.query or "").lower() for q in bundle.dns if q.query}

    beacons = detect_beaconing(conns, allow_dsts=allow_dsts)
    exfils = detect_exfil(conns, min_raw_upload_bytes=200 * 1024, allow_dsts=allow_dsts)

    # FTP store-command exfil — catches low-volume FTP exfil (AgentTesla-style)
    # that the byte-threshold path misses. Merge in, skipping exact (ip, port)
    # duplicates already reported by the volume path.
    seen_exfil = {(e.dst_ip, e.dst_port) for e in exfils}
    for fe in detect_ftp_exfil(conns, allow_dsts=allow_dsts):
        if (fe.dst_ip, fe.dst_port) not in seen_exfil:
            exfils.append(fe)
            seen_exfil.add((fe.dst_ip, fe.dst_port))

    # --- JA3 from the unified bundle ---
    # The bundle's TLS transactions come from Zeek's ssl.log when present, else
    # from the in-house pcap fingerprinter. Either way an FTPS / AUTH-TLS session
    # hides its STOR but its ClientHello is on the wire, so the destination still
    # gets a JA3 for attribution — and a known-bad fingerprint still flags it.
    from ja3_loader import JA3Record
    ja3_records = {}
    for t in bundle.tls:
        if t.ja3:
            ja3_records[(t.src_ip, t.dst_ip, t.dst_port)] = JA3Record(
                ja3_hash=t.ja3, ja3s_hash=t.ja3s,
                server_name=t.server_name, subject=t.subject)

    # Index connection timestamps so network events carry a real time.
    first_ts = {}
    for c in conns:
        first_ts.setdefault((c.dst_ip, c.dst_port), c.ts)

    # Index HTTP host for destination_domain population.
    #
    # The Host header is not a domain name. It legitimately carries a port when
    # the port is non-default, and it is often a bare address — RedLine's C2
    # sends `Host: 188.190.10.10:55123`. Stored unmodified that produced
    # destination_domain='188.190.10.10:55123', which is neither a domain nor a
    # valid IP: the officer sentence read "188.190.10.10:55123 (188.190.10.10)",
    # and the STIX export emitted domain-name:value = '188.190.10.10:55123'.
    # Strip the port, and keep the field for names only — the address already
    # has its own column.
    http_hosts = {}
    for c in conns:
        host = _host_header_domain(c.http_host)
        if host:
            http_hosts.setdefault(c.dst_ip, host)

    from datetime import datetime, timezone
    def iso(ts):
        return datetime.fromtimestamp(ts, tz=timezone.utc).isoformat()

    events = []
    for e in exfils:
        # Resolve JA3 for this destination first (match any source IP) so it
        # can feed attribution — a known-bad fingerprint raises reputation.
        ja3_hash = None
        server_name = None
        for key, rec in ja3_records.items():
            if key[1] == e.dst_ip and key[2] == e.dst_port:
                ja3_hash = rec.ja3_hash
                server_name = rec.server_name
                break
        attr = attribute(e.dst_ip, ja3_hash=ja3_hash)
        events.append({
            "kind": "exfil",
            "dst_ip": e.dst_ip, "dst_port": e.dst_port,
            "timestamp": iso(first_ts.get((e.dst_ip, e.dst_port), conns[0].ts)),
            "confidence": e.confidence,
            "reputation_hit": attr.reputation_hit,
            "geo_country": attr.geo_country, "asn": attr.asn,
            "asn_org": attr.asn_org,
            "http_uri": e.http_uri,
            "destination_domain": http_hosts.get(e.dst_ip) or server_name,
            "ja3_hash": ja3_hash,
            "plaintext_available": e.http_method is not None,
        })
    for b in beacons:
        # detect_beaconing returns a verdict for every destination with enough
        # connections; only the ones that actually beacon are candidates. A
        # non-beacon (is_beacon=False, confidence 0) must not be emitted as an
        # event, or every busy destination becomes a phantom weak-tier flag.
        if not b.is_beacon:
            continue
        ja3_hash = None
        server_name = None
        for key, rec in ja3_records.items():
            if key[1] == b.dst_ip and key[2] == b.dst_port:
                ja3_hash = rec.ja3_hash
                server_name = rec.server_name
                break
        attr = attribute(b.dst_ip, ja3_hash=ja3_hash)
        ev = {
            "kind": "beacon",
            "dst_ip": b.dst_ip, "dst_port": b.dst_port,
            "timestamp": iso(first_ts.get((b.dst_ip, b.dst_port), conns[0].ts)),
            "confidence": b.confidence,
            "reputation_hit": attr.reputation_hit,
            "geo_country": attr.geo_country, "asn": attr.asn,
            "asn_org": attr.asn_org,
            "mean_interval_s": b.mean_interval_s, "jitter_ratio": b.jitter_ratio,
            "handshake_ratio": b.handshake_ratio,
            "destination_domain": http_hosts.get(b.dst_ip) or server_name,
            "ja3_hash": ja3_hash,
            "plaintext_available": False,  # beacons are typically encrypted
        }
        # Retry storm to an unresponsive host (no completed handshake): perfectly
        # periodic but not an established channel. Cap to weak with the reason,
        # unless the IP is independently known-bad (reputation stands on its own).
        if b.unanswered and not attr.reputation_hit:
            ev["confidence_tier"] = "weak"
            ev["beacon_note"] = (
                f"no completed handshake ({b.handshake_ratio:.0%} of callbacks "
                f"answered) — regular SYN retries to an unresponsive host mimic "
                f"beaconing; not evidence of an established C2 channel")
        events.append(ev)

    # --- TLS detections: known-bad fingerprint (JA3/JA4) + certificate ---
    # A destination whose TLS fingerprint is known-bad is malicious even with no
    # visible exfil/beacon — this is how an encrypted FTPS/TLS C2, whose payload
    # we can't read, still gets caught. Fingerprint hits are confirmed-tier by
    # construction (they're a known-bad indicator). Suspicious certs (self-signed
    # / failed validation) are graded, not asserted.
    from tls_analysis import analyze_certificate
    covered = {e["dst_ip"] for e in events}
    for t in bundle.tls:
        if _is_private_ip(t.dst_ip):
            continue
        attr = attribute(t.dst_ip, ja3_hash=t.ja3, ja4=t.ja4)
        if attr.reputation_hit and t.dst_ip not in covered:
            events.append({
                "kind": "ja3", "dst_ip": t.dst_ip, "dst_port": t.dst_port,
                "timestamp": iso(first_ts.get((t.dst_ip, t.dst_port), conns[0].ts if conns else 0)),
                "confidence": 0.7, "reputation_hit": True,
                "geo_country": attr.geo_country, "asn": attr.asn,
                "asn_org": attr.asn_org, "destination_domain": t.server_name,
                "ja3_hash": t.ja3, "ja4": t.ja4, "plaintext_available": False,
            })
            covered.add(t.dst_ip)
        cf = analyze_certificate(t)
        if cf and t.dst_ip not in covered:
            events.append({
                "kind": "tls_cert", "dst_ip": t.dst_ip, "dst_port": t.dst_port,
                "timestamp": iso(first_ts.get((t.dst_ip, t.dst_port), conns[0].ts if conns else 0)),
                "confidence": 0.6, "reputation_hit": False,
                "geo_country": None, "asn": None, "asn_org": None,
                "destination_domain": t.server_name, "ja3_hash": t.ja3,
                "ja4": t.ja4, "plaintext_available": False,
                "confidence_tier": cf.severity, "cert_reason": cf.reason,
            })

    # --- DNS covert-channel detection (tunnelling / DGA) ---
    # The IOC is the DOMAIN, not the resolver (queries go to the victim's own,
    # often private, resolver) — so these are keyed by domain and their private
    # resolver IP is recorded but not filtered. A tunnel is multi-signal by
    # construction, so it is "strong" unless the resolver/domain is known-bad.
    from allowlist import load_allowlist
    from dns_analysis import (detect_dns_tunneling, detect_dga, detect_dga_ml,
                              detect_doh, detect_resolved_destinations)
    dns_ts = iso(min((q.ts for q in bundle.dns), default=conns[0].ts if conns else 0))
    stat_dga = detect_dga(bundle.dns)
    tunnels = detect_dns_tunneling(bundle.dns)
    # Domains already reported by the tunnelling detector. These MUST be handed
    # to detect_resolved_destinations below: a tunnel encodes its payload in the
    # subdomain, so leaving them unclaimed re-reports one tunnel thousands of
    # times, once per encoded label.
    tunnel_domains = {f.domain for f in tunnels}
    for f in tunnels + stat_dga:
        resolver = f.resolver_ips[0] if f.resolver_ips else ""
        rep = bool(resolver and attribute(resolver).reputation_hit)
        events.append({
            "kind": f.kind, "dst_ip": resolver, "dst_port": 53,
            "timestamp": dns_ts, "confidence": f.confidence,
            "reputation_hit": rep,
            "geo_country": None, "asn": None, "asn_org": None,
            "destination_domain": f.domain, "ja3_hash": None,
            "plaintext_available": True,
            "confidence_tier": "confirmed" if rep else "strong",
            "dns_evidence": f.evidence,
        })
    # ML net for dictionary-DGAs the entropy heuristic misses. A lone learned
    # signal -> weak candidate (explainable via the driving n-grams), unless the
    # resolver is independently known-bad. Skips domains the heuristic already got.
    stat_domains = {f.domain for f in stat_dga}
    for f in detect_dga_ml(bundle.dns, already=stat_domains):
        resolver = f.resolver_ips[0] if f.resolver_ips else ""
        rep = bool(resolver and attribute(resolver).reputation_hit)
        events.append({
            "kind": "dga", "dst_ip": resolver, "dst_port": 53,
            "timestamp": dns_ts, "confidence": f.confidence, "reputation_hit": rep,
            "geo_country": None, "asn": None, "asn_org": None,
            "destination_domain": f.domain, "ja3_hash": None,
            "plaintext_available": True,
            "confidence_tier": "confirmed" if rep else "weak",
            "dns_evidence": f.evidence,
        })
    # --- resolved destinations (essential under simulated_inetsim) -----------
    # With a simulated network every connection terminates at the responder, so
    # the destination IP carries no attribution and the sample's real intended
    # destination survives only as a DNS name. Emitting resolved names as
    # candidates is the only way a simulated run can produce a C2 mapping at all.
    # A resolution is intent to contact, never proof of contact or of malice, so
    # these stay WEAK unless independently corroborated — the same rule applied
    # to beaconing. Background OS/vendor traffic is emitted at 'allowlisted':
    # surfaced for completeness, never asserted.
    already_dns = (tunnel_domains | stat_domains
                   | {f.domain for f in detect_dga_ml(bundle.dns, already=stat_domains)})
    allow_domains, _ = load_allowlist()
    for f in detect_resolved_destinations(bundle.dns, already=already_dns,
                                          allow_domains=allow_domains):
        resolver = f.resolver_ips[0] if f.resolver_ips else ""
        rep = bool(resolver and attribute(resolver).reputation_hit)
        background = f.confidence == 0.0
        events.append({
            "kind": "resolved_domain", "dst_ip": None, "dst_port": None,
            "timestamp": dns_ts, "confidence": f.confidence, "reputation_hit": rep,
            "geo_country": None, "asn": None, "asn_org": None,
            "destination_domain": f.domain, "ja3_hash": None,
            "plaintext_available": False,
            "confidence_tier": "allowlisted" if background else "weak",
            "dns_evidence": f.evidence,
        })

    doh_hits = detect_doh(bundle.tls, bundle.http)   # informational

    # --- application-service exfil: cloud/SaaS + SMTP ---
    # IP reputation fails here (the host is a legitimate provider), so detection
    # is service-aware and risk-tiered: high-risk channels (Telegram/Discord/
    # paste/anon-file/tunnel) are "strong"; dual-use storage (Drive/Dropbox/
    # OneDrive) is only "weak" — surfaced, not asserted.
    from app_exfil import detect_cloud_exfil, detect_smtp_exfil
    for f in detect_cloud_exfil(bundle.tls, bundle.http, bundle.sessions):
        rep = bool(attribute(f.dst_ip).reputation_hit)
        tier = "confirmed" if rep else ("strong" if f.risk == "high" else "weak")
        events.append({
            "kind": f.category, "dst_ip": f.dst_ip, "dst_port": f.dst_port,
            "timestamp": dns_ts, "confidence": f.confidence, "reputation_hit": rep,
            "geo_country": None, "asn": None, "asn_org": None,
            "destination_domain": f.domain, "ja3_hash": None,
            "plaintext_available": False, "confidence_tier": tier,
            "cloud_service": f.service, "cloud_direction": f.direction,
        })
    for f in detect_smtp_exfil(bundle.smtp, bundle.sessions):
        rep = bool(attribute(f.dst_ip).reputation_hit)
        # A mail carrying an attachment (the stolen data) or sent from a mailbox
        # to itself (the AgentTesla/stealer self-send pattern) is a strong signal;
        # a bare envelope could be benign automated mail.
        tier = "confirmed" if rep else ("strong" if (f.has_attachment or f.self_send) else "weak")
        events.append({
            "kind": "smtp_exfil", "dst_ip": f.dst_ip, "dst_port": 25,
            "timestamp": dns_ts, "confidence": f.confidence, "reputation_hit": rep,
            "geo_country": None, "asn": None, "asn_org": None,
            "destination_domain": f.rcpt_to[0] if f.rcpt_to else None,
            "ja3_hash": None, "plaintext_available": True,
            "confidence_tier": tier,
            "smtp_rcpt": f.rcpt_to, "smtp_subject": f.subject,
        })

    # --- HTTP C2/exfil depth (gate patterns, suspicious agents) ---
    from http_analysis import detect_http_exfil
    for f in detect_http_exfil(bundle.http):
        if _is_private_ip(f.dst_ip):
            continue
        rep = bool(attribute(f.dst_ip).reputation_hit)
        events.append({
            "kind": "http_c2", "dst_ip": f.dst_ip, "dst_port": f.dst_port,
            "timestamp": dns_ts, "confidence": f.confidence, "reputation_hit": rep,
            "geo_country": None, "asn": None, "asn_org": None,
            "destination_domain": f.host, "ja3_hash": None,
            "plaintext_available": True,
            "confidence_tier": "confirmed" if rep else f.severity,
            "http_reason": f.reason, "http_uri": f.uri,
        })

    # --- covert channels: ICMP tunnelling + protocol/port mismatch ---
    from covert_channels import detect_icmp_tunnel, detect_port_mismatch
    for f in (detect_icmp_tunnel(bundle.icmp)
              + detect_port_mismatch(bundle.http, bundle.tls)):
        if _is_private_ip(f.dst_ip):
            continue
        rep = bool(attribute(f.dst_ip).reputation_hit)
        events.append({
            "kind": f.kind, "dst_ip": f.dst_ip, "dst_port": f.dst_port,
            "timestamp": dns_ts, "confidence": f.confidence, "reputation_hit": rep,
            "geo_country": None, "asn": None, "asn_org": None,
            "destination_domain": None, "ja3_hash": None,
            "plaintext_available": False,
            "confidence_tier": "confirmed" if rep else f.severity,
            "covert_detail": f.detail,
        })

    # --- catch-all: unclassified egress (net for UNKNOWN channels) ---
    # Anything that pushes data to an external host and wasn't explained by a
    # specific detector above. Content-agnostic; surfaced weak so novel exfil
    # never leaves silently, without asserting more than we know.
    covered = {e["dst_ip"] for e in events}
    sni_by_ip = {t.dst_ip: t.server_name for t in bundle.tls if t.server_name}
    for g in detect_unclassified_egress(conns, covered, allow_dsts=allow_dsts):
        rep = bool(attribute(g.dst_ip).reputation_hit)
        events.append({
            "kind": "unclassified_egress", "dst_ip": g.dst_ip,
            "dst_port": g.dst_port, "timestamp": dns_ts, "confidence": 0.4,
            "reputation_hit": rep, "geo_country": None, "asn": None,
            "asn_org": None,
            # attach SNI when known so a sanctioned-service allowlist can match it
            "destination_domain": sni_by_ip.get(g.dst_ip), "ja3_hash": None,
            "plaintext_available": False,
            "confidence_tier": "confirmed" if rep else "weak",
            "egress_detail": f"{g.orig_bytes}B out, upload-ratio {g.upload_ratio} "
                             f"(unexplained by specific detectors)",
        })

    # --- domain reputation (threat-intel feeds) ---
    # A finding whose destination DOMAIN is on a known-bad feed (URLhaus, DGA
    # lists, MISP) is independently corroborated -> confirmed. This is what
    # promotes DNS-tunnel / cloud / HTTP-gate findings (domain IOCs) once feeds
    # are loaded, and is the main lever on confirmed-tier recall.
    from attribution import domain_reputation
    for e in events:
        dom = e.get("destination_domain")
        if dom and not e.get("reputation_hit"):
            hit, source, note = domain_reputation(dom)
            if hit:
                e["reputation_hit"] = True
                e["confidence_tier"] = "confirmed"
                e["reputation_note"] = f"domain intel: {note or source}"

    # --- attribution context enrichment ---
    # Ensure every reputation-hit finding carries the human-meaningful "who"
    # (source + note, e.g. "Redline Stealer C2") and asn_org — not just a 0/1
    # score — so the attribution reaches the emitted evidence rows.
    for e in events:
        if e.get("reputation_hit") and not e.get("reputation_note"):
            a = attribute(e["dst_ip"], ja3_hash=e.get("ja3_hash"), ja4=e.get("ja4"))
            e["reputation_note"] = a.reputation_note
            e["reputation_source"] = a.reputation_source
            if not e.get("asn_org"):
                e["asn_org"] = a.asn_org

    # --- confidence tiering ---
    # Count distinct behavioural signal TYPES per destination so a dst that
    # both beacons AND exfils is corroborated ("strong"), while a lone signal
    # stays "weak" unless threat-intel/JA3 confirms it. Events that pre-set their
    # tier (DNS multi-signal, JA3 reputation) are respected.
    signal_kinds = {}
    for e in events:
        signal_kinds.setdefault(e["dst_ip"], set()).add(e["kind"])
    for e in events:
        if "confidence_tier" not in e:
            e["confidence_tier"] = network_confidence_tier(
                reputation_hit=e["reputation_hit"],
                corroborating_signals=len(signal_kinds.get(e["dst_ip"], ())),
            )

    # --- static IOC prior correlation (from ST/DT) ---
    # A network finding that matches a C2 extracted from the binary is the
    # strongest attribution there is (intent + observed behaviour) → confirmed.
    # Static IOCs NOT seen on the wire are recorded as dormant/expected C2 so the
    # case is complete. This module does NOT do static analysis; it consumes the
    # prior ST/DT produces and correlates it.
    if static_prior_path and os.path.exists(static_prior_path):
        from static_prior import load_static_prior, correlate_static_prior
        prior = load_static_prior(static_prior_path).prior
        # Drop infrastructure IPs (guest VM, DNS resolver) if they leaked into the
        # prior (e.g. a Suricata artifact) — the victim and its resolver are not C2.
        if infra_ips:
            prior.indicators = [ind for ind in prior.indicators
                                if not (ind.type == "ip" and ind.value in infra_ips)]
        fam = f" ({prior.family})" if prior.family else ""
        # Correlate against detections AND the raw capture, so a C2 that was
        # actually contacted (even on a private/simulated responder) counts as
        # observed rather than being mislabelled dormant.
        corr = correlate_static_prior(prior, events,
                                      observed_ips=raw_observed_ips,
                                      observed_domains=raw_observed_domains)
        matched = set()
        for c in corr:
            if c.observed:
                matched |= set(c.matched_dst)
        event_ips = {e.get("dst_ip") for e in events}
        event_doms = {(e.get("destination_domain") or "").lower() for e in events}
        for e in events:
            dom = (e.get("destination_domain") or "").lower()
            if e.get("dst_ip") in matched or (dom and dom in matched):
                e["confidence_tier"] = "confirmed"
                e["reputation_hit"] = True
                e["static_match"] = f"matches static-extracted C2{fam}"
        for c in corr:
            is_ip = c.indicator.type == "ip"
            val = c.indicator.value
            if c.observed:
                # Observed on the wire but no specific detector fired for it
                # (e.g. a single contact, or a simulated responder we can't fully
                # classify) -> still confirm it as a contacted C2, don't drop it.
                already = val in event_ips or val.lower() in event_doms
                if not already:
                    events.append({
                        "kind": "static_ioc",
                        "dst_ip": val if is_ip else "",
                        "dst_port": 0, "timestamp": dns_ts, "confidence": 0.9,
                        "reputation_hit": True, "geo_country": None, "asn": None,
                        "asn_org": None,
                        "destination_domain": None if is_ip else val,
                        "ja3_hash": None, "plaintext_available": False,
                        "confidence_tier": "confirmed",
                        "static_match": f"static-extracted C2{fam} contacted on network",
                    })
            else:
                events.append({
                    "kind": "static_ioc",
                    "dst_ip": val if is_ip else "",
                    "dst_port": 0, "timestamp": dns_ts, "confidence": 0.8,
                    "reputation_hit": False, "geo_country": None, "asn": None,
                    "asn_org": None,
                    "destination_domain": None if is_ip else val,
                    "ja3_hash": None, "plaintext_available": False,
                    "confidence_tier": "strong",
                    "static_note": f"C2 in binary{fam}, not observed on network (dormant)",
                })

    # --- sanctioned-service allowlist ---
    # Down-tier WEAK findings to known-good endpoints (update/telemetry/OCSP) to
    # 'allowlisted' so they don't clutter review. Never touches confirmed/strong;
    # nothing is hidden, only annotated. (F2)
    from allowlist import apply_allowlist
    apply_allowlist(events)

    # --- handoff honesty-gates (network side) ---
    # simulated_inetsim annotation + bad-clock capping of timing findings.
    if handoff is not None:
        from handoff import gate_network_events
        build_network_events.last_notes = gate_network_events(events, handoff)
    return events


# --- schema 1.3 integration fields ------------------------------------------
# UMAT's contracts/c2/c2-event-v1.3.schema.json REQUIRES case_id, finding_kind,
# plain_language and evidence_refs on every row, with additionalProperties=false.
# Our native `kind` vocabulary is finer-grained than their finding_kind enum, so
# it is folded down here. Their enum has no "unclassified" bucket; residual
# egress therefore maps to `exfil` (traffic did leave the host) and the honesty
# is carried by the tier and the plain-language text, not by overstating the
# kind. Raised with them as a suggested enum addition.
_FINDING_KIND = {
    "beacon": "beacon",
    "exfil": "exfil",
    "smtp_exfil": "exfil",
    "unclassified_egress": "exfil",
    "static_ioc": "static_ioc",
    "dga": "dns",
    "dga_ml": "dns",
    "dns_tunnel": "dns",
    "resolved_domain": "dns",
    "icmp_tunnel": "covert_channel",
    "port_mismatch": "covert_channel",
    "tls_cert": "reputation",
}
_VALID_FINDING_KINDS = {"beacon", "exfil", "correlation", "reputation",
                        "covert_channel", "dns", "static_ioc"}


def _finding_kind(native_kind: str | None, reputation_hit: bool = False) -> str:
    """Fold a native detector kind onto UMAT's finding_kind enum."""
    mapped = _FINDING_KIND.get(native_kind or "")
    if mapped:
        return mapped
    # Unknown detector: a reputation hit is the honest label, otherwise it is
    # simply observed egress. Never invent a category outside their enum.
    return "reputation" if reputation_hit else "exfil"


def _host_header_domain(raw: str | None) -> str | None:
    """A domain name from an HTTP Host header, or None if it isn't one.

    Returns None for bare IPv4/IPv6 literals so that destination_domain stays a
    name column. Downstream consumers (the officer sentence, the CSV/STIX IOC
    export, and UMAT's destination enrichment) all treat a populated
    destination_domain as a resolvable name.
    """
    if not raw:
        return None
    host = str(raw).strip().rstrip(".").lower()
    if not host:
        return None
    if host.startswith("["):                      # [2001:db8::1]:8080
        host = host[1:].split("]", 1)[0]
    elif host.count(":") == 1:                    # name:port / ipv4:port
        host = host.rsplit(":", 1)[0]
    # A bare address is not a domain. (A bare IPv6 literal has >1 colon and is
    # left intact by the branches above, so it is caught here too.)
    import ipaddress
    try:
        ipaddress.ip_address(host)
        return None
    except ValueError:
        pass
    return host if "." in host else None


_MAX_OBJECT_CHARS = 160


def _object_label(raw: str | None) -> str | None:
    """A path safe to put in an officer-facing sentence.

    Kept whole rather than reduced to a leaf name: the directory is what
    distinguishes a browser credential store from an unrelated file of the same
    name, and the report has to survive being read as evidence. Only
    pathological lengths are elided, from the middle, so both the drive root and
    the filename stay visible.
    """
    if not raw:
        return None
    text = " ".join(str(raw).split())     # collapse stray whitespace/newlines
    if not text:
        return None
    if len(text) <= _MAX_OBJECT_CHARS:
        return text
    keep = (_MAX_OBJECT_CHARS - 3) // 2
    return f"{text[:keep]}...{text[-keep:]}"


def _dest_label(row: dict) -> str:
    d = row.get("destination_domain")
    ip = row.get("destination_ip")
    port = row.get("destination_port")
    if d and ip:
        return f"{d} ({ip})"
    if d:
        return d
    return f"{ip}:{port}" if ip and port else (ip or "an unidentified destination")


def _plain_language(row: dict, native_kind: str | None, correlated_ctx=None) -> str:
    """One officer-readable sentence. Required, non-empty, no jargon.

    States what was observed and — where the tier is not `confirmed` — that it
    is not asserted, so the sentence can never read as stronger than the tier.
    """
    dest = _dest_label(row)
    tier = row.get("confidence_tier")
    geo = row.get("geo_country")
    where = f" in {geo}" if geo else ""

    if correlated_ctx is not None:
        what = (correlated_ctx.data_type_accessed or "data").replace("_", " ")
        # Name the actual item when WinST/DT supplied it. "read file data" tells
        # an officer nothing; "read C:\...\Edge\User Data\Login Data" is the
        # finding. Falls back cleanly for bundles predating the rich-context
        # patch, which carry no object at all.
        obj = _object_label(getattr(correlated_ctx, "accessed_object", None))
        if not obj:
            subject = what
        elif correlated_ctx.data_type_accessed == "file_access":
            # "read file access (C:\...)" is how the machine thinks. An officer
            # reads "read the file C:\...".
            subject = f"the file {obj}"
        else:
            subject = f"{what} from {obj}"
        delta = getattr(correlated_ctx, "time_delta_s", None)
        when = f" {delta:g} seconds later" if isinstance(delta, (int, float)) else ""
        base = (f"This sample read {subject} on the computer and contacted "
                f"{dest}{where}{when}.")
    elif native_kind == "static_ioc":
        base = (f"{dest} was found written inside the file itself as a "
                f"contact address.")
    elif native_kind == "beacon":
        base = (f"This sample contacted {dest}{where} repeatedly at regular "
                f"intervals, a pattern typical of remote-control software.")
    elif native_kind in ("dga", "dga_ml", "dns_tunnel"):
        base = (f"This sample used the domain-name system to reach {dest} in a "
                f"way normal software does not.")
    elif native_kind in ("icmp_tunnel", "port_mismatch"):
        base = (f"This sample sent data to {dest}{where} over an unusual "
                f"channel, which can be used to avoid monitoring.")
    elif native_kind in ("exfil", "smtp_exfil"):
        base = f"This sample uploaded data from the computer to {dest}{where}."
    elif native_kind == "resolved_domain":
        # CRITICAL: a resolution is not a connection. Under a simulated network
        # the sample may name its destination and never reach it. Saying "sent
        # data to" here would assert an egress that did not happen.
        base = (f"This sample looked up the address of {dest}, indicating it "
                f"intended to contact that destination. No connection to it was "
                f"observed.")
    elif native_kind == "tls_cert":
        base = (f"Encrypted traffic to {dest}{where} matched a fingerprint "
                f"associated with known malicious software.")
    else:
        base = f"This sample sent data out to {dest}{where}."

    note = row.get("reputation_note")
    if row.get("reputation_score") and note:
        base += f" That destination is on a threat-intelligence list ({note})."
    if tier == "allowlisted":
        base += " Reviewed and assessed as normal activity, not a threat."
    elif tier in ("weak", "unconfirmed"):
        base += " This is shown for review and is not confirmed."
    return base


def _evidence_refs(native_kind: str | None, row: dict, correlated_ctx=None) -> list:
    """Pointers back to the raw evidence behind this row, for L3 drill-down."""
    refs: list = [{
        "type": "network_event",
        "detector": native_kind or "unknown",
        "destination_ip": row.get("destination_ip"),
        "destination_port": row.get("destination_port"),
        "destination_domain": row.get("destination_domain"),
        "timestamp": row.get("timestamp"),
    }]
    if row.get("ja3_hash"):
        refs.append({"type": "tls_fingerprint", "ja3": row["ja3_hash"]})
    if row.get("reputation_source"):
        refs.append({"type": "threat_intel",
                     "source": row["reputation_source"],
                     "note": row.get("reputation_note")})
    if correlated_ctx is not None:
        ref = {
            "type": "host_access",
            "data_type": correlated_ctx.data_type_accessed,
            "api_call": correlated_ctx.access_api_call,
            "time_delta_s": getattr(correlated_ctx, "time_delta_s", None),
        }
        # The untruncated path, for analyst drill-down and for court. The
        # officer sentence carries an elided form; the evidence reference must
        # not. evidence_refs is a free-form array in c2-event-v1.3, so this
        # needs no schema change.
        obj = getattr(correlated_ctx, "accessed_object", None)
        if obj:
            ref["object_path"] = str(obj)
        refs.append(ref)
    return refs


def emit_schema_rows(network_events, correlated, sample_id, handoff=None,
                     case_id=None):
    """Stage 4: fold everything into exfil_events rows with a hash chain.

    Populates all shared-schema columns. When a handoff manifest is supplied,
    rows carry the per-run join keys (session_id / cape_task_id) and the evidence
    hash chain is SEEDED with the bundle's integrity.hash_manifest_sha256 so our
    custody chain links to ST/DT's — the first row also records the seed value.

    `case_id` is UMAT's analysis_run_id and is supplied by the caller; it stays
    None for standalone runs, where the SQL column is nullable. All four schema
    1.3 integration fields (case_id, finding_kind, plain_language,
    evidence_refs) are set BEFORE the row is hashed, so they are covered by the
    evidence chain rather than appended outside it.
    """
    from allowlist import is_allowlisted, load_allowlist

    session_id = getattr(handoff, "session_id", None) if handoff else None
    cape_task_id = getattr(handoff, "cape_task_id", None) if handoff else None
    seed = (getattr(handoff, "hash_manifest_sha256", None) if handoff else None) \
        or "0" * 64
    rows, prev = [], seed
    _allow = load_allowlist()   # loaded once; is_allowlisted() would re-read per row
    # Correlated (host+network) events are the highest-value rows.
    for c in correlated:
        # Find matching network event for enrichment fields
        net_match = None
        for ne in network_events:
            if ne["dst_ip"] == c.destination_ip and ne.get("dst_port") == c.destination_port:
                net_match = ne
                break
        row = {
            "event_id": str(uuid.uuid4()),
            "sample_id": sample_id,
            "session_id": session_id,
            "cape_task_id": cape_task_id,
            "platform": "windows",
            "timestamp": c.network_ts,
            "data_type_accessed": c.data_type_accessed,
            "access_api_call": c.access_api_call,
            "destination_ip": c.destination_ip,
            "destination_port": c.destination_port,
            "destination_domain": net_match.get("destination_domain") if net_match else None,
            "asn": net_match.get("asn") if net_match else None,
            "asn_org": net_match.get("asn_org") if net_match else None,
            "geo_country": net_match.get("geo_country") if net_match else None,
            "reputation_score": 1.0 if c.reputation_hit else 0.0,
            "reputation_note": net_match.get("reputation_note") if net_match else None,
            "reputation_source": net_match.get("reputation_source") if net_match else None,
            "ja3_hash": net_match.get("ja3_hash") if net_match else None,
            "plaintext_available": net_match.get("plaintext_available") if net_match else None,
            "confidence_score": c.correlation_confidence,
            "confidence_tier": c.confidence_tier,
            # Prefer the technique resolved at ingestion; fall back to local map.
            "mitre_technique_id": c.mitre_technique_id or MITRE.get(c.data_type_accessed),
        }
        # A correlation to a SANCTIONED SERVICE is not evidence of exfiltration.
        #
        # apply_allowlist() runs over network events only, inside
        # build_network_events. Correlated rows are assembled here, afterwards,
        # and took their tier straight from the correlation engine — so the same
        # destination could be 'allowlisted' as a beacon and 'weak' as a
        # correlation in one report.
        #
        # It is not merely inconsistent, it is a false accusation. OS telemetry
        # fires continuously, so ANY file read is followed by telemetry traffic
        # within the correlation window by coincidence. On the AgentTesla run
        # that produced seven correlations reading "file ... was (inferred to be)
        # exfiltrated to v10.events.data.microsoft.com" — the report accusing
        # Windows telemetry of receiving stolen data.
        #
        # Same rule as the network-side allowlist: only WEAK is down-tiered.
        # A strong or confirmed finding against a sanctioned service is genuinely
        # anomalous and must stay visible for review.
        if row["confidence_tier"] == "weak":
            _ok, _matched = is_allowlisted(
                row.get("destination_domain"), row.get("destination_ip"), _allow)
            if _ok:
                row["confidence_tier"] = "allowlisted"
                row["allowlist_match"] = _matched

        # --- schema 1.3 integration fields (inside the hash) ---------------
        row["case_id"] = case_id
        row["finding_kind"] = "correlation"
        row["capped_by_caveat"] = getattr(c, "capped_by_caveat", None)
        row["plain_language"] = _plain_language(row, "correlation", correlated_ctx=c)
        row["evidence_refs"] = _evidence_refs(
            net_match.get("kind") if net_match else None, row, correlated_ctx=c)
        if not rows and seed != "0" * 64:
            row["manifest_sha256"] = seed   # link to ST/DT custody chain
        prev = hashlib.sha256((prev + json.dumps(row, sort_keys=True)).encode()).hexdigest()
        row["evidence_hash"] = prev
        rows.append(row)
    # Network-only events (no host correlation yet) still recorded as IOCs.
    for e in network_events:
        row = {
            "event_id": str(uuid.uuid4()),
            "sample_id": sample_id,
            "session_id": session_id,
            "cape_task_id": cape_task_id,
            "platform": "windows",
            "timestamp": e["timestamp"],
            "data_type_accessed": None,
            "access_api_call": None,
            "destination_ip": e["dst_ip"],
            "destination_port": e["dst_port"],
            "destination_domain": e.get("destination_domain"),
            "asn": e.get("asn"),
            "asn_org": e.get("asn_org"),
            "geo_country": e.get("geo_country"),
            "reputation_score": 1.0 if e["reputation_hit"] else 0.0,
            "reputation_note": e.get("reputation_note"),
            "reputation_source": e.get("reputation_source"),
            "ja3_hash": e.get("ja3_hash"),
            "plaintext_available": e.get("plaintext_available"),
            "confidence_score": e["confidence"],
            "confidence_tier": e.get("confidence_tier",
                                     "confirmed" if e["reputation_hit"] else "weak"),
            "mitre_technique_id": MITRE.get(e["kind"]),
        }
        # --- schema 1.3 integration fields (inside the hash) ---------------
        row["case_id"] = case_id
        row["finding_kind"] = _finding_kind(e.get("kind"), bool(e.get("reputation_hit")))
        row["capped_by_caveat"] = e.get("capped_by_caveat")
        row["plain_language"] = _plain_language(row, e.get("kind"))
        row["evidence_refs"] = _evidence_refs(e.get("kind"), row)
        if not rows and seed != "0" * 64:
            row["manifest_sha256"] = seed   # link to ST/DT custody chain
        prev = hashlib.sha256((prev + json.dumps(row, sort_keys=True)).encode()).hexdigest()
        row["evidence_hash"] = prev
        rows.append(row)
    return rows


_VALUE_FLAGS = ("--zeek-dir", "--static-prior", "--handoff", "--case-id",
                "--etw-events")


def parse_args(argv: list[str]) -> dict:
    """Split argv into positionals and flag values.

    Positionals are [pcap] [access_events]. Anything starting with '--' is a
    flag and must never be mistaken for a path — previously
    `orchestrator.py x.pcap --handoff m.json` silently bound acc_path to the
    literal string "--handoff", which failed os.path.exists() and disabled
    correlation with no explanation.

    `--etw-events` is accepted but not acted on. UMAT's SubprocessC2Runtime
    passes it on every Windows run, and it then performs its own process-bound
    ETW corroboration downstream (requiring a destination/port/time match bound
    to the sample's PID before a correlation keeps sample attribution). Doing it
    here as well would duplicate that judgement in a second place, which is the
    two-sources-of-truth failure this module keeps having to undo elsewhere.

    It is declared as a VALUE FLAG rather than ignored, because ignoring it is
    not free: its argument does not begin with '--', so an undeclared flag
    leaves the path behind as a stray third positional. Today that is harmless
    (only positionals 0 and 1 are read), but it is the same shape as the
    --handoff bug above, and it would bite the moment a third positional gains a
    meaning.
    """
    flags: dict = {"zeek_dir": None, "static_prior_path": None,
                   "handoff_path": None, "case_id": None, "etw_events_path": None}
    key_for = {"--zeek-dir": "zeek_dir", "--static-prior": "static_prior_path",
               "--handoff": "handoff_path", "--case-id": "case_id",
               "--etw-events": "etw_events_path"}
    consumed: set[int] = set()
    for i, a in enumerate(argv):
        if a in _VALUE_FLAGS and i + 1 < len(argv):
            flags[key_for[a]] = argv[i + 1]
            consumed.add(i)
            consumed.add(i + 1)
    positional = [a for i, a in enumerate(argv)
                  if i not in consumed and not a.startswith("--")]
    return {
        "pcap": positional[0] if positional else "data/sample_infostealer.pcap",
        # None means "not given" -> the handoff manifest may supply it.
        "acc_path_explicit": positional[1] if len(positional) > 1 else None,
        **flags,
    }


def main():
    args = parse_args(sys.argv[1:])
    pcap = args["pcap"]
    acc_path_explicit = args["acc_path_explicit"]
    acc_path = acc_path_explicit or "data/access_events_fixture.json"
    zeek_dir = args["zeek_dir"]
    static_prior_path = args["static_prior_path"]
    handoff_path = args["handoff_path"]
    case_id = args["case_id"]   # UMAT analysis_run_id; None for standalone runs

    handoff = None
    sample_meta = None
    if handoff_path:
        from handoff import load_handoff
        handoff = load_handoff(handoff_path)

        # Resolve the access events from manifest.correlation.access_events_path
        # rather than making the caller pass it. An explicit positional argument
        # still wins, so existing invocations behave exactly as before.
        if acc_path_explicit is None and handoff.access_events_path:
            if os.path.exists(handoff.access_events_path):
                acc_path = handoff.access_events_path
                n = handoff.access_event_count
                print(f"[*] access events resolved from manifest: {acc_path}"
                      + (f" (expecting {n})" if n is not None else ""))

        # sample.meta.json — independent, binary-derived corroboration.
        from sample_meta import load_from_handoff
        sample_meta = load_from_handoff(handoff)
        if sample_meta.ok:
            fam = sample_meta.family
            sig = sample_meta.corroborating_signals()
            print(f"[*] sample.meta.json: "
                  f"family={fam or 'unknown'}, "
                  f"independent signals={sig or 'none'}")
        else:
            print(f"[*] sample.meta.json unavailable ({'; '.join(sample_meta.errors)})")
            sample_meta = None

    # Chain-of-custody: hash all inputs into a reproducible case manifest.
    from evidence import build_case_manifest, sha256_file

    # Hash in 1 MiB chunks rather than reading the capture into memory. A
    # forensics workstation is handed whatever the case produced: a 318 MiB
    # capture cost 338 MiB of RSS this way, so a multi-gigabyte one fails
    # outright on a machine with less RAM than the evidence. Same digest,
    # constant memory — sha256_file is the helper the manifest already uses.
    sample_id = sha256_file(pcap)
    manifest = build_case_manifest(
        pcap=pcap, zeek_dir=zeek_dir,
        parameters={"acc_events": os.path.basename(acc_path)})
    os.makedirs("output", exist_ok=True)
    manifest.write("output/case_manifest.json")

    init_threatintel_db()
    print(f"[*] Case ID (deterministic): {manifest.case_id[:24]}...")
    print(f"[*] Sample ID (sha256 of pcap): {sample_id[:24]}...")

    print("[*] Stage 1-2: traffic analysis + attribution on REAL pcap")
    if zeek_dir:
        print(f"    JA3 enrichment from: {zeek_dir}")
    net = build_network_events(pcap, zeek_dir=zeek_dir,
                               static_prior_path=static_prior_path,
                               handoff=handoff)
    analysis_notes = list(getattr(build_network_events, "last_notes", []) or [])
    build_network_events.last_notes = []
    os.makedirs("output", exist_ok=True)
    with open("output/network_events.json", "w") as f:
        json.dump(net, f, indent=2)
    for e in net:
        flag = "  <-- KNOWN BAD" if e["reputation_hit"] else ""
        geo = f" [{e.get('geo_country') or '?'}]" if e.get("geo_country") else ""
        ja3 = f" ja3={e.get('ja3_hash')[:12]}..." if e.get("ja3_hash") else ""
        # domain-only IOCs (e.g. dormant C2 from the binary) have no dst_ip —
        # show the domain instead of a blank ':port'.
        dest = e["dst_ip"] or e.get("destination_domain") or "?"
        port = "" if not e["dst_ip"] else f":{e['dst_port']}"
        print(f"    [{e['kind']:6}] {dest}{port} "
              f"conf={e['confidence']}{geo}{ja3}{flag}")

    fixture = os.path.exists(acc_path)
    print(f"\n[*] Stage 3: correlation "
          f"({'FIXTURE access events - sandbox interface' if fixture else 'no access events'})")
    # Ingest + validate ETW access events through the cross-module front door.
    report = load_etw_events(acc_path) if fixture else IngestReport()
    if report.errors:
        print(f"    [etw] {report.summary()}")
        for err in report.errors:
            print(f"    [etw] ERROR: {err}")
    access_events = report.events

    # Clock handling: ST/DT ALREADY normalises access-event timestamps onto the
    # host clock (correlation.clock_algorithm records how). We must not apply
    # its offset again — on the task-18 bundle the guest ran ~1h behind, so a
    # second correction would move correct timestamps by an hour and silently
    # zero out correlation. Instead: verify the assumption, and take only the
    # residual uncertainty to widen the matching window.
    if handoff is not None and access_events:
        from handoff import verify_clock_alignment, correlation_window_slack_s
        note = verify_clock_alignment(access_events, net, handoff)
        if note:
            print(f"    [etw] {note}")
            analysis_notes.append(note)
        slack = correlation_window_slack_s(handoff)
        if slack:
            print(f"    [etw] clock uncertainty ±{slack * 1000:.0f} ms "
                  f"({handoff.clock_algorithm or 'algorithm unstated'}) — "
                  f"correlation window widened accordingly")
        if handoff.access_events_rejected_count:
            n = handoff.access_events_rejected_count
            rej = (f"ACCESS EVENTS PARTIALLY REJECTED: ST/DT discarded {n} "
                   f"event(s) before handoff (source: "
                   f"{handoff.access_events_source or 'unstated'}); host-side "
                   f"absence is correspondingly less conclusive.")
            print(f"    [etw] {rej}")
            analysis_notes.append(rej)

    # ST/DT can veto correlation outright when its own preconditions failed.
    # Honour that rather than producing timing claims it has disowned.
    if handoff is not None and not (handoff.host_network_correlation_enabled
                                    and handoff.access_events_correlation_eligible):
        reason = handoff.correlation_reason or "not stated"
        note = (f"HOST<->NETWORK CORRELATION DISABLED BY SANDBOX: {reason}. "
                f"Access events were ingested but not correlated; network-side "
                f"findings stand on their own evidence.")
        print(f"    [etw] {note}")
        analysis_notes.append(note)
        correlated = []
    else:
        if access_events:
            sync = assess_clock_sync(access_events, net)
            if sync.likely_skew:
                print(f"    [etw] CLOCK SKEW: {sync.note}")
        correlated = correlate(access_events, net, best_match=True)

    # --- handoff honesty-gates (correlation side): cap timing/telemetry claims ---
    if handoff is not None:
        from handoff import gate_correlated
        analysis_notes += gate_correlated(correlated, handoff)

    # Independent static corroboration can promote strong -> confirmed, but only
    # for findings not already capped by a caveat. Runs AFTER gating for exactly
    # that reason.
    if sample_meta is not None:
        from sample_meta import promote_with_static_corroboration
        analysis_notes += promote_with_static_corroboration(correlated, sample_meta)
    for c in correlated:
        print(f"    {c.data_type_accessed} ({c.mitre_technique_id}) -> {c.destination_ip} "
              f"({c.time_delta_s}s, {c.confidence_tier}, conf={c.correlation_confidence})")

    if analysis_notes:
        print("\n[!] Analysis caveats (handoff-derived):")
        for n in analysis_notes:
            print(f"    - {n}")
        with open("output/analysis_notes.json", "w") as f:
            json.dump({"notes": analysis_notes,
                       "network_mode": getattr(handoff, "network_mode", None),
                       "session_id": getattr(handoff, "session_id", None),
                       "cape_task_id": getattr(handoff, "cape_task_id", None)}, f, indent=2)

    print("\n[*] Stage 4: emit shared exfil_events schema (hash-chained)")
    rows = emit_schema_rows(net, correlated, sample_id, handoff=handoff,
                            case_id=case_id)
    with open("output/exfil_events.json", "w") as f:
        json.dump(rows, f, indent=2)
    print(f"    Wrote {len(rows)} rows to output/exfil_events.json")
    if rows:
        print(f"    Evidence chain tip: {rows[-1]['evidence_hash'][:24]}...")
        if handoff is not None and handoff.hash_manifest_sha256:
            print(f"    Custody linked to ST/DT manifest: "
                  f"{handoff.hash_manifest_sha256[:24]}...")

    # Stage 5: export IOCs
    print("\n[*] Stage 5: export IOCs (CSV + STIX 2.1)")
    try:
        from export_iocs import export_csv, export_stix
        n_csv = export_csv(rows)
        n_stix = export_stix(rows)
        print(f"    CSV:  {n_csv} IOCs -> output/iocs.csv")
        print(f"    STIX: {n_stix} indicators -> output/iocs_stix.json")
    except Exception as e:
        print(f"    [warn] IOC export failed: {e}")

    # Stage 5b: family / campaign attribution
    from family_attribution import attribute_family, verdicts_to_dicts
    static_family = None
    if static_prior_path and os.path.exists(static_prior_path):
        from static_prior import load_static_prior
        static_family = load_static_prior(static_prior_path).prior.family
    fam = attribute_family(net, static_family=static_family)
    with open("output/attribution.json", "w") as f:
        json.dump(verdicts_to_dicts(fam), f, indent=2)
    if fam:
        print("\n[*] Stage 5b: family / campaign attribution")
        for v in fam:
            print(f"    {v.confidence.upper():9} {v.family} (via {v.basis}) — {v.evidence[0]}")

    # Stage 6: reconstruct exfiltrated content (D1) + item-level provenance
    from content_recon import reconstruct_outbound_content
    from provenance import build_provenance, provenance_to_dicts
    artifacts = reconstruct_outbound_content(pcap)
    prov = build_provenance(correlated, net, artifacts)
    with open("output/provenance.json", "w") as f:
        json.dump(provenance_to_dicts(prov), f, indent=2)
    if artifacts:
        print(f"\n[*] Stage 6a: reconstructed {len(artifacts)} outbound content "
              f"object(s) (hashed for evidence)")
    if prov:
        print("[*] Stage 6b: item-level exfil provenance")
        for r in prov:
            print("    " + r.statement())

    # Stage 7: unified host+network kill-chain timeline (E3)
    from timeline import build_timeline, timeline_to_dicts, render_timeline
    tl = build_timeline(access_events, net, mitre_map=MITRE)
    with open("output/timeline.json", "w") as f:
        json.dump(timeline_to_dicts(tl), f, indent=2)
    if tl:
        print("\n[*] Stage 7: unified kill-chain timeline")
        print(render_timeline(tl))


if __name__ == "__main__":
    main()

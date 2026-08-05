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
    "static_ioc": "T1071",                # C2 extracted from binary (dormant)
    "unclassified_egress": "T1041",       # Exfiltration Over C2 Channel (catch-all)
}


def build_network_events(pcap_path: str, zeek_dir: str | None = None,
                         static_prior_path: str | None = None) -> list[dict]:
    """Stages 1-2: run detection + attribution.

    Zeek-primary: when a Zeek log directory with conn.log is supplied it is the
    authoritative source; otherwise we fall back to parsing the pcap directly.
    Both produce the same unified bundle, projected to Connection records for the
    detectors. If a static IOC prior from ST/DT is supplied, network findings
    that match a static-extracted C2 are promoted to confirmed."""
    bundle = load_bundle(pcap_path=pcap_path, zeek_dir=zeek_dir)
    conns = bundle.to_connections()
    beacons = detect_beaconing(conns)
    exfils = detect_exfil(conns, min_raw_upload_bytes=200 * 1024)

    # FTP store-command exfil — catches low-volume FTP exfil (AgentTesla-style)
    # that the byte-threshold path misses. Merge in, skipping exact (ip, port)
    # duplicates already reported by the volume path.
    seen_exfil = {(e.dst_ip, e.dst_port) for e in exfils}
    for fe in detect_ftp_exfil(conns):
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

    # Index HTTP host for destination_domain population
    http_hosts = {}
    for c in conns:
        if c.http_host:
            http_hosts.setdefault(c.dst_ip, c.http_host)

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
        events.append({
            "kind": "beacon",
            "dst_ip": b.dst_ip, "dst_port": b.dst_port,
            "timestamp": iso(first_ts.get((b.dst_ip, b.dst_port), conns[0].ts)),
            "confidence": b.confidence,
            "reputation_hit": attr.reputation_hit,
            "geo_country": attr.geo_country, "asn": attr.asn,
            "asn_org": attr.asn_org,
            "mean_interval_s": b.mean_interval_s, "jitter_ratio": b.jitter_ratio,
            "destination_domain": http_hosts.get(b.dst_ip) or server_name,
            "ja3_hash": ja3_hash,
            "plaintext_available": False,  # beacons are typically encrypted
        })

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
    from dns_analysis import (detect_dns_tunneling, detect_dga, detect_dga_ml,
                              detect_doh)
    dns_ts = iso(min((q.ts for q in bundle.dns), default=conns[0].ts if conns else 0))
    stat_dga = detect_dga(bundle.dns)
    for f in detect_dns_tunneling(bundle.dns) + stat_dga:
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
    for g in detect_unclassified_egress(conns, covered):
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
        fam = f" ({prior.family})" if prior.family else ""
        corr = correlate_static_prior(prior, events)
        matched = set()
        for c in corr:
            if c.observed:
                matched |= set(c.matched_dst)
        for e in events:
            dom = (e.get("destination_domain") or "").lower()
            if e.get("dst_ip") in matched or (dom and dom in matched):
                e["confidence_tier"] = "confirmed"
                e["reputation_hit"] = True
                e["static_match"] = f"matches static-extracted C2{fam}"
        for c in corr:
            if not c.observed:
                is_ip = c.indicator.type == "ip"
                events.append({
                    "kind": "static_ioc",
                    "dst_ip": c.indicator.value if is_ip else "",
                    "dst_port": 0, "timestamp": dns_ts, "confidence": 0.8,
                    "reputation_hit": False, "geo_country": None, "asn": None,
                    "asn_org": None,
                    "destination_domain": None if is_ip else c.indicator.value,
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
    return events


def emit_schema_rows(network_events, correlated, sample_id):
    """Stage 4: fold everything into exfil_events rows with a hash chain.

    Now populates ALL columns defined in sql/schema.sql:
      asn, geo_country, ja3_hash, plaintext_available, destination_domain
    """
    rows, prev = [], "0" * 64
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
        prev = hashlib.sha256((prev + json.dumps(row, sort_keys=True)).encode()).hexdigest()
        row["evidence_hash"] = prev
        rows.append(row)
    # Network-only events (no host correlation yet) still recorded as IOCs.
    for e in network_events:
        row = {
            "event_id": str(uuid.uuid4()),
            "sample_id": sample_id,
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
        prev = hashlib.sha256((prev + json.dumps(row, sort_keys=True)).encode()).hexdigest()
        row["evidence_hash"] = prev
        rows.append(row)
    return rows


def main():
    pcap = sys.argv[1] if len(sys.argv) > 1 else "data/sample_infostealer.pcap"
    acc_path = sys.argv[2] if len(sys.argv) > 2 else "data/access_events_fixture.json"

    # Parse --zeek-dir / --static-prior flags if present
    zeek_dir = None
    static_prior_path = None
    for i, arg in enumerate(sys.argv):
        if arg == "--zeek-dir" and i + 1 < len(sys.argv):
            zeek_dir = sys.argv[i + 1]
        if arg == "--static-prior" and i + 1 < len(sys.argv):
            static_prior_path = sys.argv[i + 1]

    sample_id = hashlib.sha256(open(pcap, "rb").read()).hexdigest()

    # Chain-of-custody: hash all inputs into a reproducible case manifest.
    from evidence import build_case_manifest
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
                               static_prior_path=static_prior_path)
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
    if access_events:
        sync = assess_clock_sync(access_events, net)
        if sync.likely_skew:
            print(f"    [etw] CLOCK SKEW: {sync.note}")
    correlated = correlate(access_events, net, best_match=True)
    for c in correlated:
        print(f"    {c.data_type_accessed} ({c.mitre_technique_id}) -> {c.destination_ip} "
              f"({c.time_delta_s}s, {c.confidence_tier}, conf={c.correlation_confidence})")

    print("\n[*] Stage 4: emit shared exfil_events schema (hash-chained)")
    rows = emit_schema_rows(net, correlated, sample_id)
    with open("output/exfil_events.json", "w") as f:
        json.dump(rows, f, indent=2)
    print(f"    Wrote {len(rows)} rows to output/exfil_events.json")
    if rows:
        print(f"    Evidence chain tip: {rows[-1]['evidence_hash'][:24]}...")

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

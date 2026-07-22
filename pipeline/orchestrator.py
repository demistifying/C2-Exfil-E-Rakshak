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
from traffic_analysis import detect_beaconing, detect_exfil, detect_ftp_exfil
from attribution import attribute, init_threatintel_db
from correlation import correlate

MITRE = {  # capability -> ATT&CK technique
    "browser_credentials": "T1555.003",   # Credentials from Web Browsers
    "keystrokes": "T1056.001",            # Keylogging
    "screenshot": "T1113",                # Screen Capture
    "exfil": "T1041",                     # Exfiltration Over C2 Channel
    "beacon": "T1071.001",                # Application Layer Protocol: Web
}


def build_network_events(pcap_path: str, zeek_dir: str | None = None) -> list[dict]:
    """Stages 1-2: run detection + attribution on the real pcap."""
    conns = load_pcap(pcap_path)
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

    # --- JA3 enrichment (when Zeek ssl.log is available) ---
    ja3_records = {}
    if zeek_dir:
        ssl_log = os.path.join(zeek_dir, "ssl.log")
        if os.path.exists(ssl_log):
            try:
                from ja3_loader import load_zeek_ssl, check_known_bad_ja3
                ja3_records = load_zeek_ssl(ssl_log)
            except Exception as e:
                print(f"    [warn] JA3 loading failed: {e}")

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
            "geo_country": net_match.get("geo_country") if net_match else None,
            "reputation_score": 1.0 if c.reputation_hit else 0.0,
            "ja3_hash": net_match.get("ja3_hash") if net_match else None,
            "plaintext_available": net_match.get("plaintext_available") if net_match else None,
            "confidence_score": c.correlation_confidence,
            "confidence_tier": c.confidence_tier,
            "mitre_technique_id": MITRE.get(c.data_type_accessed),
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
            "geo_country": e.get("geo_country"),
            "reputation_score": 1.0 if e["reputation_hit"] else 0.0,
            "ja3_hash": e.get("ja3_hash"),
            "plaintext_available": e.get("plaintext_available"),
            "confidence_score": e["confidence"],
            "confidence_tier": "confirmed" if e["reputation_hit"] else "weak",
            "mitre_technique_id": MITRE.get(e["kind"]),
        }
        prev = hashlib.sha256((prev + json.dumps(row, sort_keys=True)).encode()).hexdigest()
        row["evidence_hash"] = prev
        rows.append(row)
    return rows


def main():
    pcap = sys.argv[1] if len(sys.argv) > 1 else "data/sample_infostealer.pcap"
    acc_path = sys.argv[2] if len(sys.argv) > 2 else "data/access_events_fixture.json"

    # Parse --zeek-dir flag if present
    zeek_dir = None
    for i, arg in enumerate(sys.argv):
        if arg == "--zeek-dir" and i + 1 < len(sys.argv):
            zeek_dir = sys.argv[i + 1]

    sample_id = hashlib.sha256(open(pcap, "rb").read()).hexdigest()

    init_threatintel_db()
    print(f"[*] Sample ID (sha256 of pcap): {sample_id[:24]}...")

    print("[*] Stage 1-2: traffic analysis + attribution on REAL pcap")
    if zeek_dir:
        print(f"    JA3 enrichment from: {zeek_dir}")
    net = build_network_events(pcap, zeek_dir=zeek_dir)
    os.makedirs("output", exist_ok=True)
    with open("output/network_events.json", "w") as f:
        json.dump(net, f, indent=2)
    for e in net:
        flag = "  <-- KNOWN BAD" if e["reputation_hit"] else ""
        geo = f" [{e.get('geo_country') or '?'}]" if e.get("geo_country") else ""
        ja3 = f" ja3={e.get('ja3_hash')[:12]}..." if e.get("ja3_hash") else ""
        print(f"    [{e['kind']:6}] {e['dst_ip']}:{e['dst_port']} "
              f"conf={e['confidence']}{geo}{ja3}{flag}")

    fixture = os.path.exists(acc_path)
    print(f"\n[*] Stage 3: correlation "
          f"({'FIXTURE access events - sandbox interface' if fixture else 'no access events'})")
    access_events = json.load(open(acc_path)) if fixture else []
    correlated = correlate(access_events, net)
    for c in correlated:
        print(f"    {c.data_type_accessed} -> {c.destination_ip} "
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


if __name__ == "__main__":
    main()

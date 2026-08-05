"""
export_iocs.py — export discovered IOCs in CSV and STIX 2.1 formats.

This is a deliverable requirement from the problem statement: exportable IOCs
(hashes, domains, IPs) in CSV/STIX, suitable for sharing with other tools
or agencies.

Reads from the pipeline's output/exfil_events.json and produces:
  * CSV: flat file with IP, domain, port, confidence tier, MITRE technique
  * STIX 2.1: proper indicator and observed-data objects with relationships

Usage:
  python pipeline/export_iocs.py                        # both formats
  python pipeline/export_iocs.py --format csv           # CSV only
  python pipeline/export_iocs.py --format stix          # STIX only
  python pipeline/export_iocs.py --input output/exfil_events.json
"""

from __future__ import annotations
import json
import csv
import os
import sys
import uuid
from datetime import datetime, timezone


def _load_events(path: str = "output/exfil_events.json") -> list[dict]:
    """Load pipeline output events."""
    if not os.path.exists(path):
        print(f"[!] No events file at {path}")
        return []
    with open(path) as f:
        return json.load(f)


def export_csv(events: list[dict], output_path: str = "output/iocs.csv") -> int:
    """Export IOCs as a flat CSV suitable for ingestion by SIEMs or sharing."""
    if not events:
        return 0

    os.makedirs(os.path.dirname(output_path) or ".", exist_ok=True)
    fieldnames = [
        "destination_ip", "destination_port", "destination_domain",
        "confidence_tier", "confidence_score", "reputation_score",
        "reputation_note", "reputation_source", "asn_org",
        "mitre_technique_id", "data_type_accessed", "timestamp",
        "evidence_hash",
    ]

    seen = set()
    rows = []
    for e in events:
        # Deduplicate by (ip, port) — keep highest confidence
        key = (e.get("destination_ip"), e.get("destination_port"))
        if key in seen:
            continue
        seen.add(key)
        rows.append({k: e.get(k) for k in fieldnames})

    with open(output_path, "w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=fieldnames)
        writer.writeheader()
        writer.writerows(rows)

    return len(rows)


def export_stix(events: list[dict], output_path: str = "output/iocs_stix.json",
                sample_id: str | None = None) -> int:
    """Export IOCs as a STIX 2.1 bundle.

    Produces:
      * indicator objects for each flagged destination IP
      * observed-data objects linking to the original events
      * relationship objects connecting indicators to observed-data
    """
    if not events:
        return 0

    os.makedirs(os.path.dirname(output_path) or ".", exist_ok=True)

    if sample_id is None:
        sample_id = events[0].get("sample_id", "unknown")

    now = datetime.now(timezone.utc).isoformat()
    objects = []

    # Deduplicate destinations
    seen_ips = {}
    for e in events:
        ip = e.get("destination_ip")
        if not ip or ip in seen_ips:
            continue

        # STIX Indicator
        indicator_id = f"indicator--{uuid.uuid5(uuid.NAMESPACE_URL, ip)}"
        indicator = {
            "type": "indicator",
            "spec_version": "2.1",
            "id": indicator_id,
            "created": now,
            "modified": now,
            "name": (f"Malicious IP: {ip}"
                     + (f" — {e['reputation_note']}" if e.get("reputation_note") else "")),
            "description": (
                f"Destination IP {ip}:{e.get('destination_port')} "
                f"flagged as {e.get('confidence_tier', 'unknown')} "
                f"by E-Rakshak Windows C2/Exfil module. "
                + (f"Attribution: {e['reputation_note']} "
                   f"(source: {e.get('reputation_source', 'n/a')}). "
                   if e.get("reputation_note") else "")
                + f"MITRE: {e.get('mitre_technique_id', 'N/A')}."
            ),
            "pattern": f"[ipv4-addr:value = '{ip}']",
            "pattern_type": "stix",
            "valid_from": e.get("timestamp", now),
            "confidence": _stix_confidence(e.get("confidence_tier", "unconfirmed")),
            "labels": ["malicious-activity"],
        }

        # Add MITRE external reference if available
        mitre = e.get("mitre_technique_id")
        if mitre:
            indicator["external_references"] = [{
                "source_name": "mitre-attack",
                "external_id": mitre,
                "url": f"https://attack.mitre.org/techniques/{mitre.replace('.', '/')}/",
            }]

        objects.append(indicator)
        seen_ips[ip] = indicator_id

    # STIX Observed-Data for each event
    for e in events:
        ip = e.get("destination_ip")
        if not ip:
            continue

        obs_id = f"observed-data--{e.get('event_id', uuid.uuid4())}"
        observed = {
            "type": "observed-data",
            "spec_version": "2.1",
            "id": obs_id,
            "created": now,
            "modified": now,
            "first_observed": e.get("timestamp", now),
            "last_observed": e.get("timestamp", now),
            "number_observed": 1,
            "object_refs": [],  # STIX 2.1 uses object_refs
        }
        objects.append(observed)

        # Relationship: indicator → observed-data
        if ip in seen_ips:
            rel = {
                "type": "relationship",
                "spec_version": "2.1",
                "id": f"relationship--{uuid.uuid4()}",
                "created": now,
                "modified": now,
                "relationship_type": "based-on",
                "source_ref": seen_ips[ip],
                "target_ref": obs_id,
            }
            objects.append(rel)

    # Assemble bundle
    bundle = {
        "type": "bundle",
        "id": f"bundle--{uuid.uuid4()}",
        "objects": objects,
    }

    with open(output_path, "w", encoding="utf-8") as f:
        json.dump(bundle, f, indent=2)

    return len(seen_ips)


def _stix_confidence(tier: str) -> int:
    """Map our 4-tier confidence to STIX confidence (0-100)."""
    return {
        "confirmed": 95,
        "strong": 75,
        "weak": 40,
        "unconfirmed": 15,
    }.get(tier, 15)


def main():
    import argparse
    parser = argparse.ArgumentParser(description="Export IOCs from pipeline output")
    parser.add_argument("--input", default="output/exfil_events.json",
                        help="Path to exfil_events.json")
    parser.add_argument("--format", choices=["csv", "stix", "both"], default="both",
                        help="Export format")
    parser.add_argument("--output-dir", default="output",
                        help="Output directory")
    args = parser.parse_args()

    events = _load_events(args.input)
    if not events:
        print("[!] No events to export.")
        sys.exit(1)

    if args.format in ("csv", "both"):
        n = export_csv(events, os.path.join(args.output_dir, "iocs.csv"))
        print(f"[*] Exported {n} IOCs to {args.output_dir}/iocs.csv")

    if args.format in ("stix", "both"):
        n = export_stix(events, os.path.join(args.output_dir, "iocs_stix.json"))
        print(f"[*] Exported {n} indicators to {args.output_dir}/iocs_stix.json")


if __name__ == "__main__":
    main()

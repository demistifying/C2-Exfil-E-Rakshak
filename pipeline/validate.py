"""
validate.py — measures the pipeline's detection accuracy against ground truth.

A weekly update should report NUMBERS, not "it runs". This harness runs the
network stages on a pcap, compares flagged malicious destinations against a
labeled ground-truth file, and reports precision / recall / F1.

Ground truth format (data/ground_truth.json):
  { "<pcap_filename>": { "malicious_ips": ["188.190.10.10"] } }

Usage:  python pipeline/validate.py
"""
from __future__ import annotations
import os, sys, json
sys.path.insert(0, os.path.dirname(__file__))
from orchestrator import build_network_events
from attribution import init_threatintel_db


def evaluate(pcap_path: str, malicious_truth: set[str]) -> dict:
    net = build_network_events(pcap_path)
    # Pipeline verdict: a destination is malicious if EITHER
    #   (a) it has a threat-intel reputation hit, OR
    #   (b) it shows exfil behavior (large outbound POST), OR
    #   (c) it beacons AND has a corroborating signal.
    # A beacon ALONE is only a candidate, not a verdict — this is what
    # separates real C2 from benign regular heartbeat traffic and is the
    # core reason attribution/correlation exist downstream of detection.
    flagged = set()
    exfil_dsts = {e["dst_ip"] for e in net if e["kind"] == "exfil"}
    for e in net:
        rep = e["reputation_hit"]
        is_exfil = e["kind"] == "exfil"
        beacon_corroborated = (e["kind"] == "beacon"
                               and (rep or e["dst_ip"] in exfil_dsts))
        if rep or is_exfil or beacon_corroborated:
            flagged.add(e["dst_ip"])

    tp = len(flagged & malicious_truth)
    fp = len(flagged - malicious_truth)
    # A false negative is ANY ground-truth malicious IP we failed to flag —
    # including ones the pipeline never even surfaced as a candidate (e.g.
    # low-volume FTP exfil below the byte threshold). Counting FN only among
    # generated candidates would hide total misses and inflate recall.
    fn = len(malicious_truth - flagged)

    precision = tp / (tp + fp) if (tp + fp) else 0.0
    recall = tp / (tp + fn) if (tp + fn) else 0.0
    f1 = (2 * precision * recall / (precision + recall)
          if (precision + recall) else 0.0)
    return {"tp": tp, "fp": fp, "fn": fn,
            "precision": round(precision, 3), "recall": round(recall, 3),
            "f1": round(f1, 3), "flagged": sorted(flagged)}


def main():
    init_threatintel_db()
    gt_path = "data/ground_truth.json"
    if not os.path.exists(gt_path):
        print(f"[!] No ground truth at {gt_path}"); sys.exit(1)
    ground_truth = json.load(open(gt_path))

    print(f"{'PCAP':<32} {'Prec':>6} {'Rec':>6} {'F1':>6}  Flagged")
    print("-" * 72)
    agg = {"tp": 0, "fp": 0, "fn": 0}
    for pcap_name, truth in ground_truth.items():
        pcap_path = os.path.join("data", pcap_name)
        if not os.path.exists(pcap_path):
            print(f"{pcap_name:<32} (missing)"); continue
        r = evaluate(pcap_path, set(truth["malicious_ips"]))
        for k in agg: agg[k] += r[k]
        print(f"{pcap_name:<32} {r['precision']:>6} {r['recall']:>6} "
              f"{r['f1']:>6}  {r['flagged']}")

    p = agg["tp"] / (agg["tp"] + agg["fp"]) if (agg["tp"] + agg["fp"]) else 0
    rec = agg["tp"] / (agg["tp"] + agg["fn"]) if (agg["tp"] + agg["fn"]) else 0
    f1 = 2*p*rec/(p+rec) if (p+rec) else 0
    print("-" * 72)
    print(f"{'AGGREGATE':<32} {round(p,3):>6} {round(rec,3):>6} {round(f1,3):>6}")


if __name__ == "__main__":
    main()

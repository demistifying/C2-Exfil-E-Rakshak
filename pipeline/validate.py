"""
validate.py — measures detection accuracy against ground truth, BY CONFIDENCE TIER.

A behavioural signal alone (a big upload, a STOR, a beacon) is a candidate, not
a verdict: on real enterprise traffic it fires on benign cloud uploads just as
readily as on exfil. So a single precision/recall number is misleading. This
harness reports metrics at three operating points:

  confirmed  : threat-intel / known-bad JA3 backing (highest precision)
  strong+    : confirmed OR >=2 corroborating behavioural signals
  any        : confirmed OR strong OR weak (every candidate surfaced)

The story to read off the aggregate: false positives concentrate at the "any"
(weak) tier, while malware stays *surfaced* at "any" — so filtering to
"confirmed" buys precision, and "any" preserves recall. Host<->network
correlation (when ETW is present) promotes weak candidates to confirmed.

Ground truth (data/ground_truth.json):
  { "<pcap>": { "malicious_ips": [...] } }         # malware sample
  { "<pcap>": { "malicious_ips": [], "benign": true } }  # negative control

Usage:  python pipeline/validate.py
"""
from __future__ import annotations
import os, sys, json
sys.path.insert(0, os.path.dirname(__file__))
from orchestrator import build_network_events
from attribution import init_threatintel_db

THRESHOLDS = ["confirmed", "strong+", "any"]


# findings whose IOC is a DOMAIN/service, not the (often legitimate) IP
DOMAIN_KINDS = {"dns_tunnel", "dga", "cloud_exfil", "cloud_staging"}


def flagged_by_threshold(pcap_path: str) -> dict[str, set]:
    """Return the set of flagged indicators (IPs, or DOMAINS for DNS/cloud
    findings) at each confidence threshold. A DNS tunnel or cloud-service abuse
    is identified by its domain, since the traffic goes to the victim's own
    resolver or a legitimate provider IP."""
    net = build_network_events(pcap_path)
    by_tier = {"confirmed": set(), "strong": set(), "weak": set()}
    for e in net:
        if e.get("kind") in DOMAIN_KINDS:
            indicator = e.get("destination_domain") or e["dst_ip"]
        else:
            indicator = e["dst_ip"]
        by_tier.setdefault(e.get("confidence_tier", "weak"), set()).add(indicator)
    return {
        "confirmed": set(by_tier["confirmed"]),
        "strong+": by_tier["confirmed"] | by_tier["strong"],
        "any": by_tier["confirmed"] | by_tier["strong"] | by_tier["weak"],
    }


def _prf(flagged: set, truth: set):
    tp = len(flagged & truth); fp = len(flagged - truth); fn = len(truth - flagged)
    return tp, fp, fn


def main():
    init_threatintel_db()
    gt_path = "data/ground_truth.json"
    if not os.path.exists(gt_path):
        print(f"[!] No ground truth at {gt_path}"); sys.exit(1)
    ground_truth = json.load(open(gt_path))

    malware = {k: v for k, v in ground_truth.items()
               if v.get("malicious_ips") and not v.get("benign")}
    benign = {k: v for k, v in ground_truth.items()
              if v.get("benign") or not v.get("malicious_ips")}

    agg = {t: {"tp": 0, "fp": 0, "fn": 0} for t in THRESHOLDS}

    # --- malware: is the C2 surfaced at each tier? ---
    print("MALWARE SAMPLES — is the C2 flagged at each confidence tier?")
    print(f"{'sample':<40}{'confirmed':>11}{'strong+':>9}{'any':>6}")
    print("-" * 72)
    for name, meta in malware.items():
        path = os.path.join("data", name)
        if not os.path.exists(path):
            print(f"{short(name):<40} (missing)"); continue
        truth = set(meta.get("malicious_ips", [])) | set(meta.get("malicious_domains", []))
        flg = flagged_by_threshold(path)
        cells = []
        for t in THRESHOLDS:
            tp, fp, fn = _prf(flg[t], truth)
            for k, v in (("tp", tp), ("fp", fp), ("fn", fn)): agg[t][k] += v
            cells.append("HIT" if tp else "miss")
        print(f"{short(name):<40}{cells[0]:>11}{cells[1]:>9}{cells[2]:>6}")

    # --- benign: false positives at each tier (lower = better) ---
    if benign:
        print("\nBENIGN CONTROLS — false positives at each tier (0 = clean)")
        print(f"{'capture':<40}{'confirmed':>11}{'strong+':>9}{'any':>6}")
        print("-" * 72)
        for name, meta in benign.items():
            path = os.path.join("data", name)
            if not os.path.exists(path):
                print(f"{short(name):<40} (missing)"); continue
            flg = flagged_by_threshold(path)
            cells = []
            for t in THRESHOLDS:
                fp = len(flg[t])                 # no malicious IPs => all are FP
                agg[t]["fp"] += fp
                cells.append(str(fp))
            print(f"{short(name):<40}{cells[0]:>11}{cells[1]:>9}{cells[2]:>6}")

    # --- aggregate precision/recall per tier ---
    print("\nAGGREGATE precision / recall by tier")
    print(f"{'':<12}{'confirmed':>12}{'strong+':>12}{'any':>12}")
    for metric in ("precision", "recall"):
        row = [metric]
        for t in THRESHOLDS:
            tp, fp, fn = agg[t]["tp"], agg[t]["fp"], agg[t]["fn"]
            if metric == "precision":
                val = tp / (tp + fp) if (tp + fp) else 1.0
            else:
                val = tp / (tp + fn) if (tp + fn) else 0.0
            row.append(f"{val:.2f}")
        print(f"{row[0]:<12}{row[1]:>12}{row[2]:>12}{row[3]:>12}")
    print(f"\n{'counts':<12}"
          + "".join(f"{'tp%d/fp%d' % (agg[t]['tp'], agg[t]['fp']):>12}" for t in THRESHOLDS))
    print("\nRead: 'confirmed' maximises precision; 'any' preserves recall "
          "(every C2 surfaced). FPs live at the weak/any tier.")


def short(name: str) -> str:
    """Trim the long nested pcap-dir names for display."""
    base = name.split("/")[-1]
    return (base[:37] + "...") if len(base) > 40 else base


if __name__ == "__main__":
    main()

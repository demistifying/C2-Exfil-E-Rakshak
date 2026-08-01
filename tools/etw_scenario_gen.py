"""
etw_scenario_gen.py — synthetic ETW + network scenarios for hardening correlation.

Real ETW host events come from the Windows ST/DT sandbox, which isn't wired yet.
To harden and test the correlation/provenance logic anyway, this generates paired
host-access + network timelines for the scenarios that matter — the same
philosophy as the FTP traffic generator, applied to host<->network correlation:

  aligned      — access then exfil a few seconds later (should correlate)
  skewed       — host/PCAP clocks off by minutes (should NOT correlate; the
                 clock-sync guard should catch it)
  many_to_many — several accesses and several exfils in-window (best-match should
                 collapse the spray to one destination per item)
  causal_chain — credential access -> exfil, keystroke access -> different exfil
  otp          — the item-level provenance example: clipboard OTP -> HTTP exfil

Each scenario returns (access_events, network_events) ready for
correlation.correlate(...) and provenance.build_provenance(...).

Usage:  python tools/etw_scenario_gen.py   # prints provenance statements
"""

from __future__ import annotations
from datetime import datetime, timezone, timedelta

_T0 = datetime(2026, 2, 3, 16, 13, 0, tzinfo=timezone.utc)


def _iso(offset_s: float) -> str:
    return (_T0 + timedelta(seconds=offset_s)).isoformat()


def access(data_type, api_call, at_s, process="stealer.exe"):
    return {"timestamp": _iso(at_s), "data_type": data_type,
            "api_call": api_call, "process": process,
            "mitre_technique": None}


def net(dst, at_s, kind="exfil", plaintext=True, **extra):
    e = {"kind": kind, "dst_ip": dst, "dst_port": extra.pop("port", 80),
         "timestamp": _iso(at_s), "confidence": extra.pop("confidence", 0.8),
         "reputation_hit": extra.pop("reputation_hit", False),
         "destination_domain": extra.pop("domain", None),
         "plaintext_available": plaintext}
    e.update(extra)
    return e


def aligned():
    acc = [access("browser_credentials", "CryptUnprotectData", 1.0)]
    n = [net("198.51.100.7", 4.0, http_uri="STOR passwords.txt")]
    return acc, n


def skewed():
    acc = [access("browser_credentials", "CryptUnprotectData", 1.0)]
    n = [net("198.51.100.7", 600.0)]           # +10 min: clocks misaligned
    return acc, n


def many_to_many():
    acc = [access("browser_credentials", "CryptUnprotectData", 1.0),
           access("keystrokes", "SetWindowsHookEx", 2.0)]
    n = [net("198.51.100.7", 4.0, confidence=0.9, reputation_hit=True),
         net("198.51.100.7", 5.0, confidence=0.5),
         net("203.0.113.9", 6.0, confidence=0.6)]
    return acc, n


def causal_chain():
    acc = [access("browser_credentials", "CryptUnprotectData", 1.0),
           access("keystrokes", "SetWindowsHookEx", 10.0)]
    n = [net("198.51.100.7", 3.0, reputation_hit=True, http_uri="STOR creds.txt"),
         net("203.0.113.9", 12.0, kind="smtp_exfil", smtp_subject="keylog dump")]
    return acc, n


def otp_example():
    """The provenance headline: an OTP captured from the clipboard is exfiltrated
    over plaintext HTTP moments later."""
    acc = [access("clipboard", "GetClipboardData", 1.0)]
    n = [net("198.51.100.7", 4.0, kind="http_c2", port=80,
             http_uri="/gate.php?otp=1", confidence=0.7)]
    return acc, n


def full_stealer():
    """A realistic infostealer: it collects several data types on the host and
    exfils each over the channel it was sent on. Timing is interleaved so each
    access resolves to its true destination (staging the whole provenance matrix
    across FTP, SMTP, cloud, and HTTP)."""
    acc = [
        access("browser_credentials", "CryptUnprotectData", 1.0),
        access("crypto_wallet", "ReadFile(wallet.dat)", 4.0),
        access("keystrokes", "SetWindowsHookEx", 7.0),
        access("screenshot", "BitBlt", 10.0),
        access("system_info", "GetComputerNameExW", 13.0),
        access("clipboard", "GetClipboardData", 16.0),
    ]
    n = [
        net("198.51.100.7", 3.0, kind="exfil", port=21,
            http_uri="STOR passwords.txt", reputation_hit=True),   # credential -> FTP
        net("198.51.100.7", 6.0, kind="exfil", port=21,
            http_uri="STOR wallet.dat", reputation_hit=True),      # wallet -> FTP
        net("203.0.113.9", 9.0, kind="smtp_exfil", port=25,
            smtp_subject="keylog dump", plaintext=True),           # keystroke -> SMTP
        net("203.0.113.9", 12.0, kind="smtp_exfil", port=25,
            plaintext=True),                                       # screenshot -> SMTP
        net("45.77.9.9", 15.0, kind="cloud_exfil", port=443, plaintext=False,
            domain="api.telegram.org", cloud_service="Telegram Bot API"),  # sysinfo -> cloud
        net("192.0.2.50", 18.0, kind="http_c2", port=80,
            http_uri="/gate.php?otp=1"),                           # clipboard/OTP -> HTTP
    ]
    return acc, n


SCENARIOS = {"aligned": aligned, "skewed": skewed, "many_to_many": many_to_many,
             "causal_chain": causal_chain, "otp": otp_example,
             "full_stealer": full_stealer}


def _demo():
    import os, sys
    sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "pipeline"))
    from correlation import correlate
    from provenance import build_provenance
    for name, fn in SCENARIOS.items():
        acc, n = fn()
        corr = correlate(acc, n, best_match=True)
        prov = build_provenance(corr, n)
        print(f"\n=== {name}: {len(corr)} correlated, {len(prov)} provenance ===")
        for r in prov:
            print("   " + r.statement())
        if not corr:
            print("   (no correlation — expected for 'skewed')")


if __name__ == "__main__":
    _demo()

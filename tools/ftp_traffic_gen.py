"""
ftp_traffic_gen.py — synthetic FTP traffic generator for PRECISION testing.

Real captures of *benign uploads to a public FTP server* are essentially
unpublished, so the STOR-to-public false-positive path can't be tested with
downloaded data. This generator produces real .pcap files for parametric FTP
sessions that flow through `pcap_loader.load_pcap` exactly like a captured
session, so we can characterise detector behaviour on controlled inputs.

IMPORTANT — scope: this is for PRECISION / logic testing, not detection claims.
A synthetic benign STOR proves how our detector *reacts* to a known-benign
upload; it does not prove real-world precision (that needs the real captures we
already use — CIC-IDS, Zeek corpus, malware samples). Use both.

Design note: benign and malicious STOR-to-public sessions are byte-for-byte
identical at the network layer except for the destination's reputation — which
is precisely why STOR-alone cannot be a verdict. This harness makes that
concrete.

Usage:
  python tools/ftp_traffic_gen.py            # write a demo pcap + print matrix
  from ftp_traffic_gen import ftp_session, write_session
"""

from __future__ import annotations
import logging
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)  # silence route warnings
from scapy.all import Ether, IP, IPv6, TCP, Raw, wrpcap, conf
conf.verb = 0


def _l3(src: str, dst: str, v6: bool):
    return IPv6(src=src, dst=dst) if v6 else IP(src=src, dst=dst)


def ftp_session(client: str, server: str, *, upload: bool = True,
                data_bytes: int = 1024, v6: bool = False,
                filename: str = "data.bin", t0: float = 1_000_000.0,
                ctrl_port: int = 40000, data_cport: int = 40001,
                data_sport: int = 50000, cmd_gap: float = 0.02):
    """Build a realistic FTP session as a list of scapy packets.

    upload=True emits a STOR (client -> server data flow); upload=False emits a
    RETR (server -> client). The control channel carries the real FTP command
    line so `pcap_loader` sets `ftp_upload_cmd`; the data channel carries
    `data_bytes` so the volume path sees a real upload/download ratio.
    """
    pkts = []
    clock = [t0]

    def emit(src, dst, sport, dport, payload: bytes = b"", dt: float = cmd_gap):
        clock[0] += dt
        p = Ether() / _l3(src, dst, v6) / TCP(sport=sport, dport=dport, flags="PA")
        if payload:
            p = p / Raw(load=payload)
        p.time = clock[0]
        pkts.append(p)

    # --- control channel (port 21) ---
    emit(client, server, ctrl_port, 21, b"USER anonymous\r\n")
    emit(server, client, 21, ctrl_port, b"331 Password required\r\n")
    emit(client, server, ctrl_port, 21, b"PASS test@example.com\r\n")
    emit(server, client, 21, ctrl_port, b"230 Login successful\r\n")
    emit(client, server, ctrl_port, 21, b"TYPE I\r\n")
    emit(server, client, 21, ctrl_port, b"200 Type set to I\r\n")
    emit(client, server, ctrl_port, 21, b"PASV\r\n")
    emit(server, client, 21, ctrl_port, b"227 Entering Passive Mode\r\n")
    verb = b"STOR " if upload else b"RETR "
    emit(client, server, ctrl_port, 21, verb + filename.encode() + b"\r\n")
    emit(server, client, 21, ctrl_port, b"150 Opening data connection\r\n")

    # --- data channel (PASV): chunk the payload ---
    chunk, sent = 1400, 0
    while sent < data_bytes:
        n = min(chunk, data_bytes - sent)
        if upload:
            emit(client, server, data_cport, data_sport, b"\x00" * n, dt=0.001)
        else:
            emit(server, client, data_sport, data_cport, b"\x00" * n, dt=0.001)
        sent += n

    emit(server, client, 21, ctrl_port, b"226 Transfer complete\r\n")
    emit(client, server, ctrl_port, 21, b"QUIT\r\n")
    return pkts


def write_session(path: str, *args, **kwargs) -> str:
    wrpcap(path, ftp_session(*args, **kwargs))
    return path


# --- self-test scenario matrix ---------------------------------------------

SCENARIOS = [
    # (name, client, server, upload, bytes, v6, malicious?)
    ("benign STOR small  -> public",  "192.168.1.10", "203.0.113.9",  True,   1_024, False, False),
    ("benign STOR 5 MB   -> public",  "192.168.1.10", "203.0.113.9",  True, 5_000_000, False, False),
    ("benign STOR IPv6   -> public",  "2001:db8::10", "2001:db8:aa::9", True,  2_048, True,  False),
    ("benign RETR (dl)   -> public",  "192.168.1.10", "203.0.113.9",  False,  5_000_000, False, False),
    ("benign STOR        -> LAN",     "192.168.1.10", "192.168.1.20",  True,   4_096, False, False),
    ("MALICIOUS STOR     -> C2",      "192.168.1.10", "198.51.100.66", True,   1_500, False, True),
]


def _run_matrix():
    import os, sys, tempfile
    sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "pipeline"))
    from pcap_loader import load_pcap
    from traffic_analysis import detect_exfil, detect_ftp_exfil, _is_private_ip
    from attribution import attribute, init_threatintel_db, _REP_DB
    import sqlite3

    init_threatintel_db()
    # Mark the C2 as known-bad so the "malicious" row has reputation backing.
    try:
        c = sqlite3.connect(os.environ.get("THREATINTEL_DB", _REP_DB))
        c.execute("INSERT OR IGNORE INTO bad_indicators (value, source, note) "
                  "VALUES ('198.51.100.66','harness','synthetic C2')")
        c.commit(); c.close()
    except Exception:
        pass

    tmp = tempfile.mkdtemp()
    print(f"{'scenario':<32}{'STOR?':>6}{'vol?':>6}{'rep?':>6}  flagged")
    print("-" * 72)
    for name, cl, sv, up, nbytes, v6, mal in SCENARIOS:
        p = os.path.join(tmp, name.replace(" ", "_").replace("/", "") + ".pcap")
        write_session(p, cl, sv, upload=up, data_bytes=nbytes, v6=v6)
        conns = load_pcap(p)
        stor = bool(detect_ftp_exfil(conns))
        vol = bool(detect_exfil(conns, min_raw_upload_bytes=200 * 1024))
        rep = any(attribute(c.dst_ip).reputation_hit for c in conns
                  if not _is_private_ip(c.dst_ip))
        flagged = stor or vol or rep
        print(f"{name:<32}{('Y' if stor else '-'):>6}{('Y' if vol else '-'):>6}"
              f"{('Y' if rep else '-'):>6}  {'FLAGGED' if flagged else 'quiet'}"
              f"{'  <-- FALSE POSITIVE' if flagged and not mal else ''}"
              f"{'  <-- true positive' if flagged and mal else ''}")


if __name__ == "__main__":
    _run_matrix()

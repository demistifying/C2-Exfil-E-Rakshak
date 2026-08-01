"""
netmon2pcap.py — convert Microsoft NetMon 2.x capture files (.cap) to libpcap.

Some public benign/sample captures (e.g. the Wireshark SampleCaptures FTPv6
files) ship in Microsoft Network Monitor 2.x format, which scapy cannot read.
This converts them to a standard .pcap so they flow through the pipeline and
`validate.py` like any other capture. No external tools (tshark/editcap) needed.

NetMon 2.x layout used here:
  * 128-byte header: magic "GMBU", ver_minor/major, network type, a 16-byte
    SYSTEMTIME (capture start), then frame-table offset + length.
  * frame table: array of little-endian uint32 offsets, one per frame.
  * each frame record: uint64 ts_delta (microseconds from start), uint32
    orig_len, uint32 incl_len, then `incl_len` bytes of Ethernet frame.

Usage:
  python tools/netmon2pcap.py input.cap [output.pcap]
  python tools/netmon2pcap.py input.cap        # -> input.pcap
"""

from __future__ import annotations
import struct
import sys
import os
from datetime import datetime, timezone, timedelta


def convert(src: str, dst: str) -> int:
    """Convert one NetMon 2.x file to pcap. Returns the frame count written."""
    from scapy.all import Ether, wrpcap  # imported lazily so --help is cheap

    data = open(src, "rb").read()
    if data[:4] != b"GMBU":
        raise ValueError(f"{src}: not a NetMon 2.x capture (bad magic)")

    # SYSTEMTIME at offset 8: year, month, day-of-week, day, hour, min, sec, msec
    st = struct.unpack_from("<8H", data, 8)
    base = datetime(st[0], st[1], st[3], st[4], st[5], st[6], st[7] * 1000,
                    tzinfo=timezone.utc)

    frametableoffset = struct.unpack_from("<I", data, 24)[0]
    frametablelength = struct.unpack_from("<I", data, 28)[0]
    n = frametablelength // 4
    offsets = struct.unpack_from("<%dI" % n, data, frametableoffset)

    pkts = []
    for o in offsets:
        ts_delta = struct.unpack_from("<Q", data, o)[0]
        _orig_len, incl_len = struct.unpack_from("<II", data, o + 8)
        frame = data[o + 16:o + 16 + incl_len]
        try:
            pk = Ether(frame)
        except Exception:
            continue  # skip any frame scapy can't decode rather than abort
        pk.time = (base + timedelta(microseconds=ts_delta)).timestamp()
        pkts.append(pk)

    wrpcap(dst, pkts)
    return len(pkts)


def main() -> int:
    if len(sys.argv) < 2 or sys.argv[1] in ("-h", "--help"):
        print(__doc__)
        return 1
    src = sys.argv[1]
    dst = sys.argv[2] if len(sys.argv) > 2 else os.path.splitext(src)[0] + ".pcap"
    n = convert(src, dst)
    print(f"[netmon2pcap] {n} frames  {src} -> {dst}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

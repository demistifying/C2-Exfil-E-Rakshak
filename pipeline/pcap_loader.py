"""
pcap_loader.py — turns packet data into Connection records.

Two entry points:
  load_pcap(path)       — parse a raw .pcap directly with scapy (works today,
                          no Zeek needed; good for dev and as a cross-check)
  load_zeek_conn(path)  — parse Zeek's conn.log (production path, authoritative)

Both return list[Connection], so everything downstream is source-agnostic.
"""

from __future__ import annotations
from collections import defaultdict
import json
from traffic_analysis import Connection


def load_pcap(path: str) -> list[Connection]:
    from scapy.all import rdpcap, IP, TCP, Raw
    import ipaddress
    packets = rdpcap(path)

    # Helper to check if IP is internal (RFC1918, loopback, link-local)
    _INTERNAL_NETS = [
        ipaddress.ip_network("10.0.0.0/8"),
        ipaddress.ip_network("172.16.0.0/12"),
        ipaddress.ip_network("192.168.0.0/16"),
        ipaddress.ip_network("127.0.0.0/8"),
        ipaddress.ip_network("169.254.0.0/16"),
        ipaddress.ip_network("0.0.0.0/8"),
    ]

    def is_internal(ip: str) -> bool:
        try:
            addr = ipaddress.ip_address(ip)
            return any(addr in net for net in _INTERNAL_NETS)
        except ValueError:
            return False

    # Bidirectional flows. Keyed by (client_ip, client_port, server_ip, server_port)
    # where client_ip is the originator.
    # To identify connection flows from both directions:
    # We maintain a map from canonical key -> (client_ip, client_port, server_ip, server_port)
    canonical_to_flow: dict[tuple, tuple[str, int, str, int]] = {}
    flows: dict[tuple[str, int, str, int], dict] = defaultdict(
        lambda: {"ts": None, "orig_bytes": 0, "resp_bytes": 0,
                 "history": "", "http_method": None, "http_host": None,
                 "http_uri": None, "ftp_upload_cmd": None})

    for pkt in packets:
        if IP not in pkt or TCP not in pkt:
            continue
        ip, tcp = pkt[IP], pkt[TCP]

        # Bidirectional identifier (sorted IPs and ports)
        canonical_key = tuple(sorted([(ip.src, int(tcp.sport)), (ip.dst, int(tcp.dport))]))

        if canonical_key not in canonical_to_flow:
            # Determine originator (client)
            if is_internal(ip.src) and not is_internal(ip.dst):
                client_ip, client_port, server_ip, server_port = ip.src, int(tcp.sport), ip.dst, int(tcp.dport)
            elif is_internal(ip.dst) and not is_internal(ip.src):
                client_ip, client_port, server_ip, server_port = ip.dst, int(tcp.dport), ip.src, int(tcp.sport)
            else:
                # Fallback: assume first packet is from client
                client_ip, client_port, server_ip, server_port = ip.src, int(tcp.sport), ip.dst, int(tcp.dport)
            canonical_to_flow[canonical_key] = (client_ip, client_port, server_ip, server_port)

        flow_key = canonical_to_flow[canonical_key]
        client_ip, client_port, server_ip, server_port = flow_key
        f = flows[flow_key]

        if f["ts"] is None:
            f["ts"] = float(pkt.time)

        payload_len = len(pkt[Raw].load) if Raw in pkt else 0

        # Accumulate bytes depending on direction
        if ip.src == client_ip and int(tcp.sport) == client_port:
            # client -> server (orig_bytes)
            f["orig_bytes"] += payload_len
            # Sniff HTTP method/URI/Host from cleartext payloads in outbound requests
            if Raw in pkt:
                try:
                    head = pkt[Raw].load[:200].decode("latin-1", errors="ignore")
                    for m in ("POST", "GET", "PUT"):
                        if head.startswith(m + " "):
                            f["http_method"] = m
                            f["http_uri"] = head.split(" ")[1]
                            for line in head.split("\r\n"):
                                if line.lower().startswith("host:"):
                                    f["http_host"] = line.split(":", 1)[1].strip()
                    # FTP store commands (control channel, cleartext): an explicit
                    # "upload this file" instruction — a volume-independent exfil
                    # signal. Keep the first one seen on the flow (with filename).
                    if f["ftp_upload_cmd"] is None:
                        for line in head.split("\r\n"):
                            stripped = line.strip()
                            up = stripped.upper()
                            if up.startswith(("STOR ", "STOU ", "APPE ")) or up in ("STOU",):
                                f["ftp_upload_cmd"] = stripped
                                break
                except Exception:
                    pass
        elif ip.src == server_ip and int(tcp.sport) == server_port:
            # server -> client (resp_bytes)
            f["resp_bytes"] += payload_len

    conns: list[Connection] = []
    for (client_ip, client_port, server_ip, server_port), f in flows.items():
        conns.append(Connection(
            ts=f["ts"], src_ip=client_ip, dst_ip=server_ip, dst_port=server_port, proto="tcp",
            orig_bytes=f["orig_bytes"], resp_bytes=f["resp_bytes"],
            history=f["history"], http_method=f["http_method"],
            http_host=f["http_host"], http_uri=f["http_uri"],
            ftp_upload_cmd=f["ftp_upload_cmd"]))
    return conns


def load_zeek_conn(path: str) -> list[Connection]:
    """Parse Zeek conn.log (TSV). Production path — Zeek is authoritative."""
    conns, fields = [], []
    with open(path) as fh:
        for line in fh:
            line = line.rstrip("\n")
            if line.startswith("#fields"):
                fields = line.split("\t")[1:]
                continue
            if line.startswith("#") or not line:
                continue
            vals = line.split("\t")
            row = dict(zip(fields, vals))
            def num(x, cast, default=0):
                try:
                    return cast(x)
                except (ValueError, TypeError):
                    return default
            conns.append(Connection(
                ts=num(row.get("ts"), float, 0.0),
                src_ip=row.get("id.orig_h", ""),
                dst_ip=row.get("id.resp_h", ""),
                dst_port=num(row.get("id.resp_p"), int),
                proto=row.get("proto", "tcp"),
                orig_bytes=num(row.get("orig_bytes"), int),
                resp_bytes=num(row.get("resp_bytes"), int),
                history=row.get("history", "")))
    return conns

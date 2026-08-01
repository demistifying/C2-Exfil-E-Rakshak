"""
test_content_timeline.py — D1 content reconstruction + E3 unified timeline.
"""
import sys, os, hashlib
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "pipeline"))
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "tools"))

from scapy.all import Ether, IP, TCP, Raw, wrpcap
from pipeline.content_recon import reconstruct_outbound_content, _preview
from pipeline.provenance import build_provenance
from pipeline.timeline import build_timeline, render_timeline
from pipeline.correlation import correlate
from pipeline.etw_ingest import parse_event
import etw_scenario_gen as gen


def _pcap_with(tmp_path, src, dst, payload):
    pk = Ether() / IP(src=src, dst=dst) / TCP(sport=5000, dport=80, flags="PA") / Raw(load=payload)
    p = str(tmp_path / "x.pcap"); wrpcap(p, [pk]); return p


class TestContentRecon:
    def test_outbound_reconstructed_with_hash(self, tmp_path):
        payload = b"STOLEN user=david pass=Global786@ host=DESKTOP-WE9H2FM"
        p = _pcap_with(tmp_path, "10.0.0.5", "203.0.113.9", payload)
        arts = reconstruct_outbound_content(p, min_bytes=8)
        assert len(arts) == 1
        a = arts[0]
        assert a.total_bytes == len(payload)
        assert a.sha256 == hashlib.sha256(payload).hexdigest()
        assert "STOLEN user=david" in a.preview
        assert a.is_outbound is True

    def test_inbound_download_not_reconstructed(self, tmp_path):
        # data arriving FROM a public host (dst is our private client) → not exfil
        p = _pcap_with(tmp_path, "203.0.113.9", "10.0.0.5", b"A" * 500)
        assert reconstruct_outbound_content(p, min_bytes=8) == []

    def test_tiny_flow_below_min(self, tmp_path):
        p = _pcap_with(tmp_path, "10.0.0.5", "203.0.113.9", b"hi")
        assert reconstruct_outbound_content(p, min_bytes=64) == []

    def test_preview_sanitises_control_bytes(self):
        assert _preview(b"ok\x00\x01\xff!") == "ok...!"


class TestProvenanceWithContent:
    def test_recovered_content_attached(self):
        acc, n = gen.aligned()
        art_cls = reconstruct_outbound_content.__globals__["Artifact"]
        art = art_cls(ts=1.0, total_bytes=4096, sha256="deadbeef" * 8,
                      dest_ip="198.51.100.7", is_outbound=True,
                      preview="user=david")
        prov = build_provenance(correlate(acc, n, best_match=True), n, [art])
        r = prov[0]
        assert r.recovered_bytes == 4096
        assert "recovered 4096 B" in r.statement()

    def test_no_artifact_no_recovered(self):
        acc, n = gen.aligned()
        r = build_provenance(correlate(acc, n, best_match=True), n, [])[0]
        assert r.recovered_bytes == 0 and "recovered" not in r.statement()


class TestTimeline:
    def _access(self):
        return [parse_event({"timestamp": "2026-02-03T16:13:01+00:00",
                             "data_type": "browser_credentials",
                             "api_call": "CryptUnprotectData"})]

    def test_orders_host_then_network(self):
        net = [{"kind": "exfil", "dst_ip": "198.51.100.7",
                "timestamp": "2026-02-03T16:13:04+00:00",
                "confidence_tier": "strong", "http_uri": "STOR creds.txt"}]
        tl = build_timeline(self._access(), net, mitre_map={"exfil": "T1041"})
        assert len(tl) == 2
        assert tl[0].actor == "host" and tl[1].actor == "network"
        assert tl[0].timestamp < tl[1].timestamp

    def test_mitre_and_phase_annotated(self):
        net = [{"kind": "exfil", "dst_ip": "198.51.100.7",
                "timestamp": "2026-02-03T16:13:04+00:00", "confidence_tier": "strong"}]
        tl = build_timeline(self._access(), net, mitre_map={"exfil": "T1041"})
        host = [e for e in tl if e.actor == "host"][0]
        network = [e for e in tl if e.actor == "network"][0]
        assert host.mitre == "T1555.003" and host.phase == "collection"
        assert network.mitre == "T1041" and network.phase == "exfiltration"

    def test_empty(self):
        assert build_timeline([], []) == []

    def test_render_contains_entries(self):
        net = [{"kind": "exfil", "dst_ip": "198.51.100.7",
                "timestamp": "2026-02-03T16:13:04+00:00", "confidence_tier": "weak"}]
        s = render_timeline(build_timeline(self._access(), net, {"exfil": "T1041"}))
        assert "host" in s and "network" in s and "T1041" in s

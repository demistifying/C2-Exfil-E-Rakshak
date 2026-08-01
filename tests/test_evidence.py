"""
test_evidence.py — case manifest, chain-of-custody, and chain verification.
"""
import sys, os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "pipeline"))

from pipeline.evidence import (build_case_manifest, sha256_file, verify_chain,
                              CaseManifest)
from pipeline.orchestrator import emit_schema_rows


class TestCaseManifest:
    def test_hashes_inputs(self, tmp_path):
        pcap = tmp_path / "e.pcap"; pcap.write_bytes(b"PCAPDATA")
        m = build_case_manifest(pcap=str(pcap))
        assert len(m.inputs) == 1
        assert m.inputs[0].sha256 == sha256_file(str(pcap))
        assert m.inputs[0].role == "pcap"

    def test_case_id_deterministic(self, tmp_path):
        """Same inputs + params → same case_id, regardless of time."""
        pcap = tmp_path / "e.pcap"; pcap.write_bytes(b"SAME")
        a = build_case_manifest(pcap=str(pcap), parameters={"x": 1})
        b = build_case_manifest(pcap=str(pcap), parameters={"x": 1})
        assert a.case_id == b.case_id

    def test_case_id_changes_with_input(self, tmp_path):
        p1 = tmp_path / "a.pcap"; p1.write_bytes(b"AAA")
        p2 = tmp_path / "b.pcap"; p2.write_bytes(b"BBB")
        assert (build_case_manifest(pcap=str(p1)).case_id
                != build_case_manifest(pcap=str(p2)).case_id)

    def test_case_id_changes_with_params(self, tmp_path):
        pcap = tmp_path / "e.pcap"; pcap.write_bytes(b"SAME")
        assert (build_case_manifest(pcap=str(pcap), parameters={"x": 1}).case_id
                != build_case_manifest(pcap=str(pcap), parameters={"x": 2}).case_id)

    def test_records_tool_versions(self, tmp_path):
        pcap = tmp_path / "e.pcap"; pcap.write_bytes(b"X")
        m = build_case_manifest(pcap=str(pcap))
        assert "python" in m.tool_versions and "schema" in m.tool_versions

    def test_zeek_logs_hashed(self, tmp_path):
        (tmp_path / "conn.log").write_text("#fields\tts\n1.0\n")
        (tmp_path / "dns.log").write_text("#fields\tts\n1.0\n")
        m = build_case_manifest(zeek_dir=str(tmp_path))
        assert {r.role for r in m.inputs} == {"zeek_log"}
        assert len(m.inputs) == 2

    def test_manifest_writes_json(self, tmp_path):
        pcap = tmp_path / "e.pcap"; pcap.write_bytes(b"X")
        out = str(tmp_path / "case.json")
        build_case_manifest(pcap=str(pcap)).write(out)
        assert os.path.exists(out)


class TestChainVerification:
    def _rows(self):
        net = [{"kind": "exfil", "dst_ip": "198.51.100.44", "dst_port": 80,
                "timestamp": "2024-10-23T19:15:35+00:00", "confidence": 0.9,
                "reputation_hit": True, "confidence_tier": "confirmed"}]
        return emit_schema_rows(net, [], sample_id="case-test")

    def test_valid_chain_verifies(self):
        ok, idx = verify_chain(self._rows())
        assert ok and idx == -1

    def test_tamper_detected(self):
        rows = self._rows()
        rows[0]["destination_ip"] = "1.2.3.4"
        ok, idx = verify_chain(rows)
        assert not ok and idx == 0

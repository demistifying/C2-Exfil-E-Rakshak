"""
test_zeek_ingest.py — Zeek-primary ingestion + unified data model.

Covers:
  * Zeek log reading in both encodings (TSV and JSON-lines)
  * Multi-log bundle assembly (conn/dns/http/ssl/ftp/smtp/files)
  * to_connections() back-compat bridge (enrichment from transactions)
  * Zeek-path vs pcap-path equivalence for detection
"""
import sys, os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "pipeline"))

import pytest
from pipeline.zeek_ingest import (read_zeek_log, load_zeek_dir, bundle_from_pcap,
                                  load_bundle)
from pipeline.model import AnalysisBundle, Session, HttpTransaction, FtpTransaction
from pipeline.traffic_analysis import detect_ftp_exfil, detect_exfil


CONN_TSV = ("#separator \\x09\n#fields\tts\tuid\tid.orig_h\tid.orig_p\t"
            "id.resp_h\tid.resp_p\tproto\tservice\torig_bytes\tresp_bytes\thistory\n"
            "1.0\tC1\t10.0.0.5\t5000\t203.0.113.9\t21\ttcp\tftp\t250\t800\tShAdDf\n")
FTP_TSV = ("#fields\tts\tuid\tid.orig_h\tid.orig_p\tid.resp_h\tid.resp_p\t"
           "command\targ\treply_code\n"
           "1.1\tC1\t10.0.0.5\t5000\t203.0.113.9\t21\tSTOR\tsecrets.zip\t150\n")
HTTP_JSON = ('{"ts":2.0,"uid":"C2","id.orig_h":"10.0.0.5","id.resp_h":"1.2.3.4",'
             '"id.resp_p":80,"method":"POST","host":"gate.bad","uri":"/gate.php",'
             '"request_body_len":9000}\n')


class TestZeekLogReader:
    def test_tsv(self, tmp_path):
        p = tmp_path / "conn.log"; p.write_text(CONN_TSV)
        rows = read_zeek_log(str(p))
        assert len(rows) == 1
        assert rows[0]["id.resp_h"] == "203.0.113.9"
        assert rows[0]["id.resp_p"] == "21"

    def test_json_lines(self, tmp_path):
        p = tmp_path / "http.log"; p.write_text(HTTP_JSON)
        rows = read_zeek_log(str(p))
        assert rows[0]["method"] == "POST"
        assert rows[0]["request_body_len"] == 9000

    def test_empty_and_dash_normalised(self, tmp_path):
        p = tmp_path / "conn.log"
        p.write_text("#fields\tts\tuid\tservice\n1.0\tC1\t-\n")
        rows = read_zeek_log(str(p))
        assert rows[0]["service"] is None

    def test_missing_file(self, tmp_path):
        assert read_zeek_log(str(tmp_path / "nope.log")) == []


class TestLoadZeekDir:
    def _dir(self, tmp_path):
        (tmp_path / "conn.log").write_text(CONN_TSV)
        (tmp_path / "ftp.log").write_text(FTP_TSV)
        (tmp_path / "http.log").write_text(HTTP_JSON)
        return str(tmp_path)

    def test_bundle_assembly(self, tmp_path):
        b = load_zeek_dir(self._dir(tmp_path))
        assert b.source == "zeek"
        assert len(b.sessions) == 1
        assert len(b.ftp) == 1 and b.ftp[0].is_upload
        assert len(b.http) == 1 and b.http[0].method == "POST"

    def test_zeek_path_detects_ftp_stor(self, tmp_path):
        """The Zeek path must flag the same FTP exfil the pcap path would."""
        b = load_zeek_dir(self._dir(tmp_path))
        verdicts = detect_ftp_exfil(b.to_connections())
        assert any(v.dst_ip == "203.0.113.9" for v in verdicts)


class TestToConnections:
    def test_http_enrichment(self):
        b = AnalysisBundle(source="zeek")
        b.sessions.append(Session(ts=1.0, src_ip="10.0.0.5", src_port=5000,
                                  dst_ip="1.2.3.4", dst_port=80, proto="tcp",
                                  orig_bytes=9000, resp_bytes=100, uid="C2"))
        b.http.append(HttpTransaction(ts=1.0, src_ip="10.0.0.5", dst_ip="1.2.3.4",
                                      dst_port=80, method="POST", host="gate.bad",
                                      uri="/gate.php", uid="C2"))
        c = b.to_connections()[0]
        assert c.http_method == "POST" and c.http_uri == "/gate.php"

    def test_ftp_upload_enrichment(self):
        b = AnalysisBundle(source="zeek")
        b.sessions.append(Session(ts=1.0, src_ip="10.0.0.5", src_port=5000,
                                  dst_ip="203.0.113.9", dst_port=21, uid="C1"))
        b.ftp.append(FtpTransaction(ts=1.0, src_ip="10.0.0.5", dst_ip="203.0.113.9",
                                    command="STOR", arg="secrets.zip", uid="C1"))
        c = b.to_connections()[0]
        assert c.ftp_upload_cmd == "STOR secrets.zip"


class TestPcapFallbackEquivalence:
    SNAKE = os.path.join(os.path.dirname(__file__), "..", "data",
                         "2024-09-17-Snake-KeyLogger-infection-FTP-exfil.pcap",
                         "2024-09-17-Snake-KeyLogger-infection-FTP-exfil.pcap")

    def test_pcap_bundle_reproduces_detection(self):
        if not os.path.exists(self.SNAKE):
            pytest.skip("Snake pcap not present")
        b = bundle_from_pcap(self.SNAKE)
        assert b.source == "pcap"
        verdicts = detect_ftp_exfil(b.to_connections())
        assert any(v.dst_ip == "216.252.233.118" for v in verdicts)

    def test_load_bundle_prefers_zeek(self, tmp_path):
        (tmp_path / "conn.log").write_text(CONN_TSV)
        (tmp_path / "ftp.log").write_text(FTP_TSV)
        b = load_bundle(pcap_path=None, zeek_dir=str(tmp_path))
        assert b.source == "zeek"

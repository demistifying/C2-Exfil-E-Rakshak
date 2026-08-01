"""
test_app_exfil.py — cloud/SaaS and SMTP exfiltration detection.
"""
import sys, os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "pipeline"))

from pipeline.model import TlsTransaction, HttpTransaction, Session, SmtpTransaction
from pipeline.app_exfil import detect_cloud_exfil, detect_smtp_exfil, _match_service


def _sess(src, dst, dport, orig, resp):
    return Session(ts=1.0, src_ip=src, src_port=5000, dst_ip=dst, dst_port=dport,
                   orig_bytes=orig, resp_bytes=resp)


class TestCloudExfil:
    def test_high_risk_service_strong_signal(self):
        tls = [TlsTransaction(ts=1, src_ip="10.0.0.5", dst_ip="149.154.167.220",
                              dst_port=443, server_name="api.telegram.org")]
        f = detect_cloud_exfil(tls, [], [_sess("10.0.0.5", "149.154.167.220", 443, 9000, 200)])
        assert len(f) == 1 and f[0].risk == "high"
        assert f[0].direction == "upload" and f[0].category == "cloud_exfil"

    def test_dual_use_service_flagged_low(self):
        tls = [TlsTransaction(ts=1, src_ip="10.0.0.5", dst_ip="142.250.1.1",
                              dst_port=443, server_name="drive.google.com")]
        f = detect_cloud_exfil(tls, [], [_sess("10.0.0.5", "142.250.1.1", 443, 200, 9000)])
        assert len(f) == 1 and f[0].risk == "dual"
        assert f[0].direction == "download" and f[0].category == "cloud_staging"

    def test_subdomain_matches_service(self):
        assert _match_service("cdn.discordapp.com")[0] == "Discord"

    def test_normal_https_not_flagged(self):
        tls = [TlsTransaction(ts=1, src_ip="10.0.0.5", dst_ip="1.2.3.4",
                              dst_port=443, server_name="www.example.com")]
        assert detect_cloud_exfil(tls, [], []) == []

    def test_http_host_also_matched(self):
        http = [HttpTransaction(ts=1, src_ip="10.0.0.5", dst_ip="1.2.3.4",
                                dst_port=80, method="POST", host="pastebin.com",
                                uri="/api/api_post.php")]
        f = detect_cloud_exfil([], http, [])
        assert len(f) == 1 and f[0].service == "Pastebin"


class TestSmtpExfil:
    def test_smtp_send_flagged(self):
        smtp = [SmtpTransaction(ts=1, src_ip="10.0.0.5", dst_ip="203.0.113.9",
                                mail_from="stealer@x.com", rcpt_to=["drop@evil.com"],
                                subject="PW logs", attachments=["a"])]
        f = detect_smtp_exfil(smtp, [])
        assert len(f) == 1 and f[0].has_attachment
        assert "drop@evil.com" in f[0].rcpt_to

    def test_empty_envelope_ignored(self):
        smtp = [SmtpTransaction(ts=1, src_ip="10.0.0.5", dst_ip="203.0.113.9")]
        assert detect_smtp_exfil(smtp, []) == []

    def test_self_send_detected(self):
        """A mailbox emailing itself (AgentTesla/VIP-Recovery pattern) is flagged
        as self_send — a robust behavioural signal independent of subject text."""
        smtp = [SmtpTransaction(ts=1, src_ip="10.0.0.5", dst_ip="208.91.198.143",
                                mail_from="director@igakuin.com",
                                rcpt_to=["director@igakuin.com"],
                                subject="Pc Name: david.miller | VIP Recovery")]
        f = detect_smtp_exfil(smtp, [])
        assert len(f) == 1 and f[0].self_send is True

    def test_normal_mail_not_self_send(self):
        smtp = [SmtpTransaction(ts=1, src_ip="10.0.0.5", dst_ip="203.0.113.9",
                                mail_from="alice@corp.com", rcpt_to=["bob@partner.com"])]
        f = detect_smtp_exfil(smtp, [])
        assert len(f) == 1 and f[0].self_send is False


class TestSmtpScapyFallback:
    def test_smtp_parsed_from_pcap(self, tmp_path):
        """A plaintext SMTP send in a pcap is parsed by the scapy fallback."""
        from scapy.all import Ether, IP, TCP, Raw, wrpcap
        from zeek_ingest import bundle_from_pcap
        body = (b"MAIL FROM:<stealer@host.com>\r\n"
                b"RCPT TO:<drop@evil.com>\r\n"
                b"DATA\r\nSubject: Passwords\r\n"
                b"Content-Disposition: attachment; filename=logs.txt\r\n")
        pk = Ether() / IP(src="10.0.0.5", dst="203.0.113.9") / TCP(sport=5000, dport=25, flags="PA") / Raw(load=body)
        p = str(tmp_path / "smtp.pcap"); wrpcap(p, [pk])
        b = bundle_from_pcap(p)
        assert len(b.smtp) == 1
        assert b.smtp[0].mail_from == "stealer@host.com"
        assert "drop@evil.com" in b.smtp[0].rcpt_to
        assert b.smtp[0].attachments

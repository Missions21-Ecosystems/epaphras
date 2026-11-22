import gzip
import io
import os
import sys
import unittest
import zipfile
from datetime import datetime
from email.message import EmailMessage
from email.mime.application import MIMEApplication
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from zoneinfo import ZoneInfo

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from dmarcd import analyze, extract, render  # noqa: E402
from dmarcd import mail  # noqa: E402
from dmarcd import __main__ as main_mod  # noqa: E402
from dmarcd.__main__ import build_digest, digest_due, fully_handled, ingest  # noqa: E402
from dmarcd.config import Config  # noqa: E402
from dmarcd.parse import ReportError, parse_report  # noqa: E402
from dmarcd.store import Store  # noqa: E402

FIX = os.path.join(os.path.dirname(__file__), "fixtures")


def fixture(name: str) -> bytes:
    with open(os.path.join(FIX, name), "rb") as fh:
        return fh.read()


def report_xml(records: str, p: str = "none", ns: str = "", org: str = "example.net", rid: str = "r1") -> bytes:
    xmlns = f' xmlns="{ns}"' if ns else ""
    return f"""<?xml version="1.0"?>
<feedback{xmlns}>
  <report_metadata><org_name>{org}</org_name><email>d@{org}</email><report_id>{rid}</report_id>
    <date_range><begin>1795219200</begin><end>1795305599</end></date_range></report_metadata>
  <policy_published><domain>example.org</domain><adkim>r</adkim><aspf>r</aspf><p>{p}</p><pct>100</pct></policy_published>
  {records}
</feedback>""".encode()


def rec(ip, count, dkim, spf, auth="", reason="", disposition="none", env=""):
    reason_xml = f"<reason><type>{reason}</type></reason>" if reason else ""
    env_xml = f"<envelope_from>{env}</envelope_from>" if env else ""
    return f"""<record><row><source_ip>{ip}</source_ip><count>{count}</count>
      <policy_evaluated><disposition>{disposition}</disposition><dkim>{dkim}</dkim><spf>{spf}</spf>{reason_xml}</policy_evaluated></row>
      <identifiers><header_from>example.org</header_from>{env_xml}</identifiers>
      <auth_results>{auth}</auth_results></record>"""


def cfg(**kw) -> Config:
    base = dict(email="dmarc@example.org", password="x", forward_to=["me@example.org"], imap_host="imap.example.org",
                smtp_host="smtp.example.org", from_addr="dmarc@example.org", data_dir="/nonexistent", rdns=False)
    base.update(kw)
    return Config(**base)


class ExtractTests(unittest.TestCase):
    def test_forwarded_zip_attachment(self):
        msg = MIMEMultipart()
        msg.attach(MIMEText("see attached"))
        msg.attach(MIMEApplication(fixture("google.zip"), "zip", Name="google.com!example.zip"))
        payloads, forensic = extract.extract(extract.parse_message(msg.as_bytes()))
        self.assertEqual(len(payloads), 1)
        self.assertTrue(payloads[0].xml.lstrip().startswith(b"<?xml"))
        self.assertTrue(payloads[0].filename.endswith(".xml"))

    def test_direct_single_part_gzip_without_filename(self):
        # Several reporters send the report as the whole message body.
        msg = EmailMessage()
        msg["Subject"] = "Report Domain: example.org"
        msg.set_content(fixture("yahoo.xml.gz"), maintype="application", subtype="gzip")
        payloads, _ = extract.extract(extract.parse_message(msg.as_bytes()))
        self.assertEqual(len(payloads), 1)
        self.assertIsNotNone(payloads[0].xml)
        self.assertEqual(parse_report(payloads[0].xml).org_name, "Yahoo")

    def test_report_nested_in_forwarded_message(self):
        inner = MIMEMultipart()
        inner.attach(MIMEApplication(fixture("outlook.xml.gz"), "gzip", Name="outlook.xml.gz"))
        outer = MIMEMultipart()
        outer.attach(MIMEText("fwd"))
        part = MIMEApplication(b"", "octet-stream")
        from email.mime.message import MIMEMessage
        outer.attach(MIMEMessage(inner))
        del part
        payloads, _ = extract.extract(extract.parse_message(outer.as_bytes()))
        self.assertEqual(len(payloads), 1)
        self.assertIsNotNone(payloads[0].xml)

    def test_plain_xml_and_octet_stream_zip(self):
        buf = io.BytesIO()
        with zipfile.ZipFile(buf, "w") as zf:
            zf.writestr("r.xml", report_xml(rec("192.0.2.1", 1, "pass", "pass")))
        msg = MIMEMultipart()
        msg.attach(MIMEApplication(buf.getvalue(), "octet-stream"))  # no filename at all
        msg.attach(MIMEApplication(report_xml(rec("192.0.2.2", 1, "pass", "pass"), rid="r2"), "xml", Name="r2.xml"))
        payloads, _ = extract.extract(extract.parse_message(msg.as_bytes()))
        self.assertEqual(len([p for p in payloads if p.xml]), 2)

    def test_corrupt_gzip_reported_not_raised(self):
        msg = MIMEMultipart()
        msg.attach(MIMEApplication(b"\x1f\x8bnot really gzip", "gzip", Name="bad.xml.gz"))
        payloads, _ = extract.extract(extract.parse_message(msg.as_bytes()))
        self.assertEqual(len(payloads), 1)
        self.assertIsNone(payloads[0].xml)
        self.assertIn("decompress", payloads[0].error)

    def test_decompression_limit(self):
        old = extract.MAX_XML_BYTES
        extract.MAX_XML_BYTES = 1000
        try:
            with self.assertRaises(ValueError):
                extract.decode_payload(gzip.compress(b"<?xml" + b" " * 5000), "big.xml.gz")
        finally:
            extract.MAX_XML_BYTES = old

    def test_forensic_report(self):
        raw = (b"From: reporter@example.net\r\nSubject: Report\r\nMIME-Version: 1.0\r\n"
               b'Content-Type: multipart/report; report-type=feedback-report; boundary="b"\r\n\r\n'
               b"--b\r\nContent-Type: text/plain\r\n\r\nThis is an authentication failure report\r\n"
               b"--b\r\nContent-Type: message/feedback-report\r\n\r\n"
               b"Feedback-Type: auth-failure\r\nAuth-Failure: dmarc\r\nSource-IP: 203.0.113.9\r\n"
               b"Reported-Domain: example.org\r\n\r\n"
               b"--b\r\nContent-Type: text/rfc822-headers\r\n\r\nFrom: ceo@example.org\r\nSubject: wire money\r\n\r\n"
               b"--b--\r\n")
        msg = raw
        _, forensic = extract.extract(extract.parse_message(msg))
        self.assertEqual(len(forensic), 1)
        self.assertIn("wire money", forensic[0].original_headers)
        self.assertEqual(forensic[0].fields["source-ip"], ["203.0.113.9"])
        f = analyze.forensic_finding(forensic[0].fields)
        self.assertEqual(f.severity, analyze.ACTION)


class ParseTests(unittest.TestCase):
    def test_real_fixtures(self):
        r = parse_report(extract.decode_payload(fixture("google.zip"))[0][1])
        self.assertEqual(r.org_name, "google.com")
        self.assertEqual(r.policy.domain, "example.org")
        self.assertEqual(len(r.records), 13)
        self.assertEqual(r.total, r.passing)

    def test_dmarc2_namespace(self):
        r = parse_report(report_xml(rec("192.0.2.1", 3, "pass", "fail"), ns="urn:ietf:params:xml:ns:dmarc-2.0"))
        self.assertEqual(r.total, 3)
        self.assertEqual(r.records[0].dkim_eval, "pass")

    def test_rejects_dtd(self):
        evil = b'<?xml version="1.0"?><!DOCTYPE x [<!ENTITY a "aaaa">]><feedback>&a;</feedback>'
        with self.assertRaises(ReportError):
            parse_report(evil)

    def test_rejects_non_report(self):
        with self.assertRaises(ReportError):
            parse_report(b"<?xml version='1.0'?><html/>")


class AnalyzeTests(unittest.TestCase):
    def findings(self, xml: bytes, rdns=None):
        return analyze.summarize([parse_report(xml)], rdns or {})[0].findings

    def test_all_pass_on_p_none_suggests_tightening(self):
        reps = [parse_report(extract.decode_payload(fixture(n))[0][1]) for n in ("google.zip", "yahoo.xml.gz", "outlook.xml.gz")]
        ips = {r.source_ip for rep in reps for r in rep.records}
        rdns = {ip: ("x.mxroute.com" if ip.startswith("198.51.100.") else "") for ip in ips}
        s = analyze.summarize(reps, rdns)[0]
        titles = [f.title for f in s.findings]
        self.assertTrue(any("Ready to tighten" in t for t in titles), titles)
        self.assertTrue(any("SPF only" in t for t in titles), titles)  # MXroute unsigned mail
        self.assertFalse(any(f.severity == analyze.ACTION for f in s.findings))
        self.assertFalse(any("different published" in t for t in titles))  # sp/np omitted ≠ different
        brevo = next(src for src in s.sources if src.label == "Brevo")
        self.assertEqual(brevo.passed, brevo.total)

    def test_spoofing_is_action(self):
        fs = self.findings(report_xml(rec("203.0.113.50", 12, "fail", "fail",
                                          "<spf><domain>example.org</domain><result>fail</result></spf>")))
        spoof = [f for f in fs if "Unauthenticated" in f.title]
        self.assertEqual(len(spoof), 1)
        self.assertEqual(spoof[0].severity, analyze.ACTION)
        self.assertTrue(any("Stay on p=none" in f.title or "p=none" in f.title for f in fs))

    def test_provider_without_domain_dkim_is_action(self):
        auth = ("<dkim><domain>mailin.fr</domain><selector>s</selector><result>pass</result></dkim>"
                "<spf><domain>a.d.sender-sib.com</domain><result>pass</result></spf>")
        fs = self.findings(report_xml(rec("203.0.113.9", 6, "fail", "fail", auth)))
        f = next(f for f in fs if "Brevo" in f.title)
        self.assertEqual(f.severity, analyze.ACTION)
        self.assertIn("no DKIM signature for example.org", f.detail)
        self.assertTrue(any("Brevo:" in s for s in f.steps))
        self.assertTrue(any("Stay on p=none" in x.title for x in fs))

    def test_broken_signature_explained(self):
        auth = "<dkim><domain>example.org</domain><selector>k1</selector><result>fail</result></dkim>"
        fs = self.findings(report_xml(rec("198.51.100.7", 2, "fail", "fail", auth)), {"198.51.100.7": "mx.somewhere.example"})
        self.assertTrue(any("k1._domainkey.example.org" in f.detail for f in fs))

    def test_forwarded_is_not_action(self):
        auth = "<spf><domain>lists.example.com</domain><result>pass</result></spf>"
        fs = self.findings(report_xml(rec("192.0.2.80", 3, "fail", "fail", auth, reason="forwarded")))
        f = next(f for f in fs if "Forwarded" in f.title)
        self.assertEqual(f.severity, analyze.INFO)

    def test_quarantined_legit_mail_flagged(self):
        auth = "<spf><domain>bounce.sendgrid.net</domain><result>pass</result></spf>"
        fs = self.findings(report_xml(rec("167.89.0.1", 2, "fail", "fail", auth, disposition="quarantine"), p="quarantine"))
        f = next(f for f in fs if "SendGrid" in f.title)
        self.assertEqual(f.severity, analyze.ACTION)
        self.assertIn("quarantined/rejected", f.detail)

    def test_org_domain(self):
        self.assertEqual(analyze.org_domain("a.b.example.co.uk"), "example.co.uk")
        self.assertTrue(analyze.aligned("mail.example.org", "example.org", "r"))
        self.assertFalse(analyze.aligned("mail.example.org", "example.org", "s"))


class FlowTests(unittest.TestCase):
    def test_ingest_dedupes_and_builds_digest(self):
        store = Store(":memory:")
        msg = MIMEMultipart()
        msg["Subject"] = "Report"
        msg.attach(MIMEApplication(fixture("google.zip"), "zip", Name="g.zip"))
        self.assertIn("reports=1", ingest(store, msg.as_bytes()))
        self.assertIn("dup=1", ingest(store, msg.as_bytes()))
        c = cfg()
        msg_out, ids, text, html = build_digest(c, store)
        self.assertIn("[DMARC] example.org", msg_out["Subject"])
        self.assertIn("Skipped duplicate", text)
        names = [p.get_filename() for p in msg_out.iter_attachments()]
        self.assertEqual(names, ["dmarc-records.csv", "google.com!example.org!1795219200!1795305599.xml"])
        self.assertEqual(msg_out["Auto-Submitted"], "auto-generated")
        store.record_digest(msg_out["Subject"], c.forward_to, *ids)
        self.assertIsNone(build_digest(c, store))

    def test_non_report_mail_ignored(self):
        store = Store(":memory:")
        msg = EmailMessage()
        msg["Subject"] = "hello"
        msg.set_content("just a note")
        self.assertEqual(ingest(store, msg.as_bytes()), "no-report")
        self.assertIsNone(build_digest(cfg(), store))

    def test_digest_time(self):
        store = Store(":memory:")
        tz = ZoneInfo("America/Chicago")
        c = cfg(digest_time="07:00", tz="America/Chicago")
        self.assertFalse(digest_due(c, store, datetime(2026, 11, 22, 6, 59, tzinfo=tz)) and store.last_digest_at())
        store.record_digest("s", ["x"], [], [], [])  # sent "now"
        early = datetime.fromtimestamp(store.last_digest_at(), tz)
        self.assertFalse(digest_due(c, store, early))
        self.assertTrue(digest_due(cfg(), store))  # no DIGEST_TIME = always due

    def test_subject_counts(self):
        s = analyze.summarize([parse_report(report_xml(rec("203.0.113.50", 12, "fail", "fail")))])
        self.assertIn("action item", render.subject(s, []))


class FakeConn:
    def __init__(self):
        self.calls = []

    def uid(self, *args):
        self.calls.append(args)
        return "OK", [b""]

    def expunge(self):
        self.calls.append(("EXPUNGE-ALL",))
        return "OK", [b""]


def fake_box(c, caps=("MOVE", "UIDPLUS")):
    box = object.__new__(mail.Mailbox)
    box.cfg, box.readonly, box.conn = c, False, FakeConn()
    box.can_move, box.can_uid_expunge = "MOVE" in caps, "UIDPLUS" in caps
    return box


class ProcessedActionTests(unittest.TestCase):
    def test_keep_only_marks_read(self):
        box = fake_box(cfg(processed_action="keep"))
        box.done(7)
        self.assertEqual(box.conn.calls, [("STORE", "7", "+FLAGS.SILENT", r"(\Seen)")])

    def test_move(self):
        box = fake_box(cfg(processed_action="move", archive_folder="INBOX.processed"))
        box.done(7)
        self.assertEqual(box.conn.calls[-1], ("MOVE", "7", "INBOX.processed"))

    def test_move_without_move_capability_copies_then_expunges_one(self):
        box = fake_box(cfg(processed_action="move", archive_folder="Archive"), caps=("UIDPLUS",))
        box.done(7)
        self.assertEqual([c[0] for c in box.conn.calls], ["STORE", "COPY", "STORE", "EXPUNGE"])
        self.assertEqual(box.conn.calls[-1], ("EXPUNGE", "7"))

    def test_delete_expunges_only_that_uid(self):
        box = fake_box(cfg(processed_action="delete"))
        box.done(7)
        self.assertEqual(box.conn.calls[1:], [("STORE", "7", "+FLAGS.SILENT", r"(\Deleted)"), ("EXPUNGE", "7")])

    def test_delete_without_uidplus_falls_back(self):
        box = fake_box(cfg(processed_action="delete"), caps=())
        box.done(7)
        self.assertEqual(box.conn.calls[-1], ("EXPUNGE-ALL",))

    def test_capabilities_are_read_after_login(self):
        # Dovecot-style servers list MOVE/UIDPLUS only once logged in.
        class FakeIMAP:
            def __init__(self, *a, **kw):
                self.capabilities = ("IMAP4REV1", "AUTH=PLAIN")

            def login(self, u, p):
                return "OK", [b""]

            def capability(self):
                return "OK", [b"IMAP4rev1 UIDPLUS MOVE IDLE"]

            def select(self, f, readonly=False):
                return "OK", [b"1"]

            def response(self, code):
                return "OK", [b"42"]

        orig = mail.imaplib.IMAP4_SSL
        mail.imaplib.IMAP4_SSL = FakeIMAP
        try:
            box = mail.Mailbox(cfg())
        finally:
            mail.imaplib.IMAP4_SSL = orig
        self.assertTrue(box.can_move)
        self.assertTrue(box.can_uid_expunge)
        self.assertEqual(box.uidvalidity, 42)

    def test_readonly_touches_nothing(self):
        box = fake_box(cfg(processed_action="delete"))
        box.readonly = True
        box.done(7)
        self.assertEqual(box.conn.calls, [])

    def test_config_parsing(self):
        env = {"EMAIL": "a@example.org", "PASSWORD": "x", "FWD_REPORT_EMAIL": "b@example.org", "IMAP_HOST": "h"}
        old = dict(os.environ)
        try:
            os.environ.clear()
            os.environ.update(env)
            self.assertEqual(Config.from_env().processed_action, "keep")
            os.environ["IMAP_ARCHIVE_FOLDER"] = "Done"
            self.assertEqual(Config.from_env().processed_action, "move")  # folder alone implies move
            os.environ["PROCESSED_ACTION"] = "delete"
            c = Config.from_env()
            self.assertEqual((c.processed_action, c.archive_folder), ("delete", ""))
            del os.environ["IMAP_ARCHIVE_FOLDER"]
            os.environ["PROCESSED_ACTION"] = "move"
            with self.assertRaises(SystemExit):
                Config.from_env()
            os.environ["PROCESSED_ACTION"] = "shred"
            with self.assertRaises(SystemExit):
                Config.from_env()
        finally:
            os.environ.clear()
            os.environ.update(old)

    def test_fully_handled(self):
        self.assertTrue(fully_handled("reports=1 dup=0 bad=0 forensic=0"))
        self.assertTrue(fully_handled("reports=0 dup=1 bad=0 forensic=0"))
        self.assertFalse(fully_handled("reports=1 dup=0 bad=1 forensic=0"))
        self.assertFalse(fully_handled("no-report"))

    def test_poll_only_acts_on_messages_whose_reports_were_stored(self):
        good = MIMEMultipart()
        good["Subject"] = "Report"
        good.attach(MIMEApplication(fixture("yahoo.xml.gz"), "gzip", Name="y.xml.gz"))
        bad = MIMEMultipart()
        bad["Subject"] = "Broken"
        bad.attach(MIMEApplication(b"\x1f\x8bjunk", "gzip", Name="b.xml.gz"))
        human = EmailMessage()
        human["Subject"] = "Question about DMARC"
        human["From"] = "someone@example.net"
        human.set_content("hi")
        msgs = {1: good.as_bytes(), 2: bad.as_bytes(), 3: human.as_bytes()}
        done = []

        class Box:
            uidvalidity = 1

            def __init__(self, c, readonly=False):
                pass

            def ensure_folder(self, f):
                pass

            def uids(self):
                return list(msgs)

            def fetch(self, uids):
                return [(u, msgs[u]) for u in uids]

            def done(self, uid):
                done.append(uid)

            def close(self):
                pass

        store = Store(":memory:")
        orig = main_mod.mail.Mailbox
        main_mod.mail.Mailbox = Box
        try:
            main_mod.poll(cfg(processed_action="delete"), store)
            main_mod.poll(cfg(processed_action="delete"), store)  # second pass: nothing new
        finally:
            main_mod.mail.Mailbox = orig
        self.assertEqual(done, [1])
        notes = " ".join(n["text"] for n in store.pending()[2])
        self.assertIn("Could not read attachment", notes)
        self.assertIn("Question about DMARC", notes)


if __name__ == "__main__":
    unittest.main()

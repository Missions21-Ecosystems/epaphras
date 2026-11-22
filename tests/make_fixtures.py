"""Regenerate the test fixtures: synthetic DMARC aggregate reports for
example.org, using only RFC 2606 domains and RFC 5737 documentation IPs.

    python3 tests/make_fixtures.py

The scenarios mirror real-world shapes: a bulk-mail provider that passes on
DKIM only, a mailbox provider that sometimes sends unsigned mail (SPF-only),
and a forwarding filter service.
"""

import gzip
import io
import os
import zipfile

OUT = os.path.join(os.path.dirname(__file__), "fixtures")
DOMAIN = "example.org"
BEGIN, END = 1795219200, 1795305599


def dkim(domain, selector, result="pass"):
    return f"<dkim><domain>{domain}</domain><selector>{selector}</selector><result>{result}</result></dkim>"


def spf(domain, result="pass"):
    return f"<spf><domain>{domain}</domain><result>{result}</result></spf>"


def record(ip, count, dkim_eval, spf_eval, auth, envelope_to=""):
    to = f"<envelope_to>{envelope_to}</envelope_to>" if envelope_to else ""
    return f"""  <record>
    <row>
      <source_ip>{ip}</source_ip>
      <count>{count}</count>
      <policy_evaluated><disposition>none</disposition><dkim>{dkim_eval}</dkim><spf>{spf_eval}</spf></policy_evaluated>
    </row>
    <identifiers>{to}<header_from>{DOMAIN}</header_from></identifiers>
    <auth_results>{"".join(auth)}</auth_results>
  </record>
"""


def report(org, email, report_id, records, policy_extra=""):
    return f"""<?xml version="1.0" encoding="UTF-8"?>
<feedback>
  <version>1.0</version>
  <report_metadata>
    <org_name>{org}</org_name>
    <email>{email}</email>
    <report_id>{report_id}</report_id>
    <date_range><begin>{BEGIN}</begin><end>{END}</end></date_range>
  </report_metadata>
  <policy_published>
    <domain>{DOMAIN}</domain><adkim>r</adkim><aspf>r</aspf><p>none</p>{policy_extra}<pct>100</pct>
  </policy_published>
{"".join(records)}</feedback>
""".encode()


# Bulk-mail provider (Brevo-style): DKIM signs as example.org, SPF uses the
# provider's own bounce domain, so SPF never aligns.
def esp(ip, n, bounce, extra_sig=False, to=""):
    auth = [dkim(DOMAIN, "brevo1")] + ([dkim("mailin.fr", "brevo1")] if extra_sig else []) + [spf(bounce)]
    return record(ip, n, "pass", "fail", auth, to)


# Mailbox provider: normally DKIM selector "x" + aligned SPF.
def mbox(ip, n=1, signed=True):
    auth = ([dkim(DOMAIN, "x")] if signed else []) + [spf(DOMAIN)]
    return record(ip, n, "pass" if signed else "fail", "pass", auth)


google = report("google.com", "noreply-dmarc-support@google.com", "1234567890123456789", [
    esp("203.0.113.25", 4, "a.d.sender-sib.com"),
    esp("203.0.113.26", 4, "b.d.sender-sib.com"),
    # Forwarded through a filtering service: DKIM survives, SPF is theirs.
    record("192.0.2.140", 1, "pass", "fail",
           [dkim("antispam.mailspamprotection.com", "default"), dkim(DOMAIN, "brevo1"), spf("forwarder.example.net")]),
    esp("203.0.113.104", 11, "c.d.sender-sib.com"),
    esp("203.0.113.104", 69, "c.d.sender-sib.com", extra_sig=True),
    mbox("198.51.100.11", signed=False),
    mbox("198.51.100.68"),
    mbox("198.51.100.83"),
    mbox("198.51.100.110"),
    mbox("198.51.100.146", signed=False),
    mbox("198.51.100.148"),
    mbox("198.51.100.200"),
    mbox("198.51.100.227", signed=False),
], "<sp>none</sp><np>none</np>")

yahoo = report("Yahoo", "dmarchelp@yahooinc.example", "1795219200.100000000000000000000000000000000000001", [
    mbox("198.51.100.200"),
    esp("203.0.113.104", 8, "c.d.sender-sib.com", extra_sig=True),
    esp("203.0.113.25", 1, "a.d.sender-sib.com"),
])

outlook = report("Enterprise Outlook", "dmarcreport@microsoft.example", "0123456789abcdef0123456789abcdef", [
    esp("203.0.113.25", 1, "a.d.sender-sib.com", to="example.com"),
    esp("203.0.113.26", 2, "b.d.sender-sib.com", to="example.net"),
    esp("203.0.113.26", 1, "b.d.sender-sib.com", to="example.edu"),
    esp("203.0.113.26", 1, "b.d.sender-sib.com", to="test.example"),
], "<sp>none</sp><fo>0</fo>")


def main():
    os.makedirs(OUT, exist_ok=True)
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
        info = zipfile.ZipInfo(f"google.com!{DOMAIN}!{BEGIN}!{END}.xml", date_time=(2026, 11, 21, 0, 0, 0))
        zf.writestr(info, google)
    files = {
        "google.zip": buf.getvalue(),
        # mtime=0 keeps the output byte-identical between runs.
        "yahoo.xml.gz": gzip.compress(yahoo, mtime=0),
        "outlook.xml.gz": gzip.compress(outlook, mtime=0),
    }
    for name, data in files.items():
        with open(os.path.join(OUT, name), "wb") as fh:
            fh.write(data)
        print("wrote", os.path.join(OUT, name))


if __name__ == "__main__":
    main()

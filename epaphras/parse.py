"""DMARC aggregate report XML (RFC 7489 appendix C, and the DMARCbis 2.0
namespace) into plain dataclasses. Namespaces are ignored."""

from __future__ import annotations

import xml.etree.ElementTree as ET
from dataclasses import dataclass, field


class ReportError(ValueError):
    pass


@dataclass
class AuthResult:
    domain: str
    result: str
    selector: str = ""  # DKIM only
    scope: str = ""  # SPF only (mfrom/helo)


@dataclass
class Record:
    source_ip: str
    count: int
    disposition: str
    dkim_eval: str  # policy_evaluated: aligned DKIM pass?
    spf_eval: str  # policy_evaluated: aligned SPF pass?
    reasons: list[tuple[str, str]]  # (type, comment)
    header_from: str
    envelope_from: str
    envelope_to: str
    dkim: list[AuthResult]
    spf: list[AuthResult]

    @property
    def dmarc_pass(self) -> bool:
        return self.dkim_eval == "pass" or self.spf_eval == "pass"


@dataclass
class Policy:
    domain: str
    adkim: str = "r"
    aspf: str = "r"
    p: str = ""
    sp: str = ""
    np: str = ""
    pct: str = ""
    fo: str = ""


@dataclass
class Report:
    org_name: str
    org_email: str
    report_id: str
    begin: int
    end: int
    policy: Policy
    records: list[Record] = field(default_factory=list)
    errors: list[str] = field(default_factory=list)

    @property
    def total(self) -> int:
        return sum(r.count for r in self.records)

    @property
    def passing(self) -> int:
        return sum(r.count for r in self.records if r.dmarc_pass)


def _strip_ns(root: ET.Element) -> None:
    for el in root.iter():
        if isinstance(el.tag, str) and "}" in el.tag:
            el.tag = el.tag.split("}", 1)[1]


def _t(el: ET.Element | None, path: str, default: str = "") -> str:
    if el is None:
        return default
    found = el.find(path)
    if found is None or found.text is None:
        return default
    return found.text.strip()


def parse_report(xml: bytes) -> Report:
    # ElementTree never fetches external entities; refusing DTDs outright also
    # rules out entity-expansion tricks. Real reports never carry one.
    if b"<!DOCTYPE" in xml[:4096].upper() or b"<!ENTITY" in xml.upper():
        raise ReportError("report contains a DTD; refusing to parse")
    try:
        root = ET.fromstring(xml)
    except ET.ParseError as exc:
        raise ReportError(f"invalid XML: {exc}") from exc
    _strip_ns(root)
    if root.tag != "feedback":
        raise ReportError(f"not a DMARC aggregate report (root <{root.tag}>)")

    meta = root.find("report_metadata")
    pp = root.find("policy_published")
    if meta is None or pp is None:
        raise ReportError("missing report_metadata or policy_published")

    def _int(text: str) -> int:
        try:
            return int(float(text))
        except ValueError:
            return 0

    policy = Policy(
        domain=_t(pp, "domain").lower(),
        adkim=_t(pp, "adkim", "r").lower() or "r",
        aspf=_t(pp, "aspf", "r").lower() or "r",
        p=_t(pp, "p").lower(),
        sp=_t(pp, "sp").lower(),
        np=_t(pp, "np").lower(),
        pct=_t(pp, "pct"),
        fo=_t(pp, "fo"),
    )
    report = Report(
        org_name=_t(meta, "org_name") or "unknown reporter",
        org_email=_t(meta, "email"),
        report_id=_t(meta, "report_id"),
        begin=_int(_t(meta, "date_range/begin", "0")),
        end=_int(_t(meta, "date_range/end", "0")),
        policy=policy,
    )
    for err in meta.findall("error"):
        if err.text:
            report.errors.append(err.text.strip())

    for rec in root.findall("record"):
        row = rec.find("row")
        pe = row.find("policy_evaluated") if row is not None else None
        ident = rec.find("identifiers")
        auth = rec.find("auth_results")
        reasons = []
        if pe is not None:
            for r in pe.findall("reason"):
                reasons.append((_t(r, "type").lower(), _t(r, "comment")))
        dkim = []
        spf = []
        if auth is not None:
            for d in auth.findall("dkim"):
                dkim.append(AuthResult(_t(d, "domain").lower(), _t(d, "result").lower(), selector=_t(d, "selector")))
            for s in auth.findall("spf"):
                spf.append(AuthResult(_t(s, "domain").lower(), _t(s, "result").lower(), scope=_t(s, "scope").lower()))
        report.records.append(
            Record(
                source_ip=_t(row, "source_ip"),
                count=_int(_t(row, "count", "0")),
                disposition=_t(pe, "disposition", "none").lower(),
                dkim_eval=_t(pe, "dkim").lower(),
                spf_eval=_t(pe, "spf").lower(),
                reasons=reasons,
                header_from=_t(ident, "header_from").lower() or policy.domain,
                envelope_from=_t(ident, "envelope_from").lower(),
                envelope_to=_t(ident, "envelope_to").lower(),
                dkim=dkim,
                spf=spf,
            )
        )
    return report

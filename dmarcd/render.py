"""Digest rendering: subject, plain text, HTML (inline styles for mail
clients) and a CSV of every record."""

from __future__ import annotations

import csv
import io
from datetime import datetime, timezone
from html import escape

from .analyze import ACTION, INFO, REVIEW, DomainSummary, Finding
from .plain import BAD, GOOD, summarize_plain

PLAIN_COLORS = {GOOD: ("#067647", "#ecfdf3"), "ok": ("#175cd3", "#eff8ff"), BAD: ("#b42318", "#fef3f2")}
PLAIN_MARK = {GOOD: "✔", "ok": "●", BAD: "!"}

LABELS = {ACTION: "ACTION", REVIEW: "REVIEW", INFO: "FYI"}
COLORS = {ACTION: "#b42318", REVIEW: "#b54708", INFO: "#475467"}
BG = {ACTION: "#fef3f2", REVIEW: "#fffaeb", INFO: "#f2f4f7"}


def _day(ts: int, tz) -> str:
    if not ts:
        return "?"
    return datetime.fromtimestamp(ts, timezone.utc).astimezone(tz).strftime("%b %d, %Y")


def _period(summary: DomainSummary, tz) -> str:
    begins = [r.begin for r in summary.reports if r.begin]
    ends = [r.end for r in summary.reports if r.end]
    if not begins:
        return "unknown period"
    a, b = _day(min(begins), tz), _day(max(ends), tz)
    return a if a == b else f"{a} – {b}"


def _pct(n: int, total: int) -> str:
    return f"{(100.0 * n / total):.0f}%" if total else "–"


def subject(summaries: list[DomainSummary], extra: list[Finding]) -> str:
    findings = [f for s in summaries for f in s.findings] + extra
    actions = sum(1 for f in findings if f.severity == ACTION)
    reviews = sum(1 for f in findings if f.severity == REVIEW)
    domains = ", ".join(s.domain for s in summaries) or "failure reports"
    total = sum(s.total for s in summaries)
    passed = sum(s.passed for s in summaries)
    reports = sum(len(s.reports) for s in summaries)
    head = f"[DMARC] {domains}: "
    if actions:
        head += f"{actions} action item{'s' if actions != 1 else ''}"
    elif reviews:
        head += f"{reviews} item{'s' if reviews != 1 else ''} to review"
    else:
        head += "all good"
    if summaries:
        head += f" — {reports} report{'s' if reports != 1 else ''}, {total} msgs, {_pct(passed, total)} pass"
    return head


def _all_findings(summaries, extra) -> list[Finding]:
    from .analyze import SEVERITY_ORDER

    return sorted([f for s in summaries for f in s.findings] + extra, key=lambda f: SEVERITY_ORDER[f.severity])


def text_body(summaries: list[DomainSummary], extra: list[Finding], notes: list[str], tz) -> str:
    out = io.StringIO()
    w = out.write
    findings = _all_findings(summaries, extra)
    plain = summarize_plain(summaries, extra, tz)
    w("IN SHORT\n========\n\n")
    w(f"{plain.headline}\n\n")
    for p in plain.points:
        w(f"* {p}\n")
    w(f"\nWhat to do: {plain.todo}\n\n\n")
    w("DETAILS FOR WHOEVER MANAGES YOUR EMAIL\n======================================\n\n")
    for s in summaries:
        w(f"{s.domain}  ({_period(s, tz)})\n")
        w(f"  {len(s.reports)} report(s), {s.total} message(s), {s.passed} passed DMARC ({_pct(s.passed, s.total)}), {s.failed} failed\n")
        w(f"  Published policy: {s.policy_line}\n\n")

    acts = [f for f in findings if f.severity != INFO]
    w("WHAT TO DO\n----------\n")
    if not acts:
        w("Nothing needs your attention.\n")
    for i, f in enumerate(findings, 1):
        w(f"\n{i}. [{LABELS[f.severity]}] {f.title}\n")
        w(f"   {f.detail}\n")
        for step in f.steps:
            w(f"   - {step}\n")
    for s in summaries:
        w(f"\nSENDING SOURCES — {s.domain}\n" + "-" * (18 + len(s.domain)) + "\n")
        w(f"{'Source':<26}{'Msgs':>6}{'Pass':>7}{'DKIM':>7}{'SPF':>7}  Disposition / reporters\n")
        for src in s.sources:
            disp = ", ".join(f"{k} {v}" for k, v in src.dispositions.most_common() if k != "none") or "delivered"
            w(f"{src.label[:25]:<26}{src.total:>6}{_pct(src.passed, src.total):>7}{_pct(src.dkim_aligned, src.total):>7}"
              f"{_pct(src.spf_aligned, src.total):>7}  {disp}; {', '.join(sorted(src.reporters))}\n")
            w(f"{'':<4}{', '.join(sorted(src.ips))}" + (f"  ({', '.join(sorted(src.hosts))})" if src.hosts else "") + "\n")
        w(f"\nREPORTS — {s.domain}\n")
        for r in sorted(s.reports, key=lambda r: (r.begin, r.org_name)):
            w(f"  {r.org_name:<24} {_day(r.begin, tz)}  {r.total:>5} msgs  {_pct(r.passing, r.total):>5} pass  id {r.report_id}\n")
    if notes:
        w("\nNOTES\n-----\n")
        for n in notes:
            w(f"- {n}\n")
    w("\nDKIM/SPF columns = share of mail that passed *aligned* with your domain (what DMARC counts).\n"
      "Original report files and a CSV of every record are attached.\n")
    return out.getvalue()


def _finding_html(i: int, f: Finding) -> str:
    steps = "".join(f"<li style='margin:2px 0'>{escape(s)}</li>" for s in f.steps)
    return (
        f"<div style='border-left:4px solid {COLORS[f.severity]};background:{BG[f.severity]};padding:10px 14px;margin:0 0 10px;border-radius:4px'>"
        f"<div style='font-weight:600;color:#101828'>{i}. <span style='color:{COLORS[f.severity]};font-size:12px;letter-spacing:.04em'>"
        f"{LABELS[f.severity]}</span> &nbsp;{escape(f.title)}</div>"
        f"<div style='color:#344054;margin-top:4px;font-size:14px'>{escape(f.detail)}</div>"
        + (f"<ul style='margin:6px 0 0;padding-left:20px;color:#101828;font-size:14px'>{steps}</ul>" if steps else "")
        + "</div>"
    )


def html_body(summaries: list[DomainSummary], extra: list[Finding], notes: list[str], tz) -> str:
    findings = _all_findings(summaries, extra)
    th = "style='text-align:left;padding:6px 8px;border-bottom:2px solid #d0d5dd;font-size:12px;color:#475467'"
    thr = "style='text-align:right;padding:6px 8px;border-bottom:2px solid #d0d5dd;font-size:12px;color:#475467'"
    td = "style='padding:6px 8px;border-bottom:1px solid #eaecf0;vertical-align:top'"
    tdr = "style='padding:6px 8px;border-bottom:1px solid #eaecf0;text-align:right;vertical-align:top;white-space:nowrap'"
    h = ["<!doctype html><html><body style='margin:0;background:#f9fafb'>"
         "<div style='max-width:760px;margin:0 auto;padding:20px 16px;font-family:-apple-system,Segoe UI,Roboto,Helvetica,Arial,sans-serif;color:#101828;font-size:14px;line-height:1.45'>"
         "<h1 style='font-size:20px;margin:0 0 12px'>DMARC report digest</h1>"]
    plain = summarize_plain(summaries, extra, tz)
    fg, bg = PLAIN_COLORS[plain.status]
    h.append(
        f"<div style='background:{bg};border:1px solid {fg}33;border-radius:10px;padding:16px 18px;margin-bottom:18px'>"
        "<div style='font-size:12px;letter-spacing:.06em;text-transform:uppercase;color:#475467;margin-bottom:6px'>In short</div>"
        f"<div style='font-size:18px;font-weight:600;color:{fg};margin-bottom:10px'>"
        f"<span style='display:inline-block;width:24px;height:24px;line-height:24px;text-align:center;border-radius:12px;"
        f"background:{fg};color:#fff;font-size:14px;margin-right:8px;vertical-align:1px'>{PLAIN_MARK[plain.status]}</span>"
        f"{escape(plain.headline)}</div>"
        "<ul style='margin:0 0 10px;padding-left:20px;font-size:15px;line-height:1.5;color:#101828'>"
        + "".join(f"<li style='margin:0 0 6px'>{escape(p)}</li>" for p in plain.points)
        + "</ul>"
        f"<div style='font-size:15px;color:#101828'><b>What to do:</b> {escape(plain.todo)}</div></div>"
        "<div style='font-size:12px;letter-spacing:.06em;text-transform:uppercase;color:#475467;margin:0 0 8px'>"
        "Details for whoever manages your email</div>"
    )
    for s in summaries:
        ok = s.failed == 0
        h.append(
            "<div style='background:#fff;border:1px solid #eaecf0;border-radius:8px;padding:12px 16px;margin-bottom:12px'>"
            f"<div style='font-size:16px;font-weight:600'>{escape(s.domain)} <span style='font-weight:400;color:#667085;font-size:13px'>{escape(_period(s, tz))}</span></div>"
            f"<div style='margin-top:6px'><b style='font-size:22px;color:{'#067647' if ok else '#b42318'}'>{_pct(s.passed, s.total)}</b> passed DMARC"
            f" &nbsp;·&nbsp; {s.total} messages &nbsp;·&nbsp; {s.failed} failed &nbsp;·&nbsp; {len(s.reports)} reports</div>"
            f"<div style='color:#667085;font-size:12px;margin-top:4px'>Published policy: {escape(s.policy_line)}</div></div>"
        )
    h.append("<h2 style='font-size:16px;margin:18px 0 8px'>What to do</h2>")
    if not any(f.severity != INFO for f in findings):
        h.append("<p style='color:#067647;font-weight:600'>Nothing needs your attention.</p>")
    h += [_finding_html(i, f) for i, f in enumerate(findings, 1)]

    for s in summaries:
        h.append(f"<h2 style='font-size:16px;margin:22px 0 8px'>Sending sources — {escape(s.domain)}</h2>"
                 "<table style='border-collapse:collapse;width:100%;background:#fff;font-size:13px'>"
                 f"<tr><th {th}>Source</th><th {thr}>Msgs</th><th {thr}>DMARC</th><th {thr}>DKIM</th><th {thr}>SPF</th><th {th}>Seen by</th></tr>")
        for src in s.sources:
            color = "#067647" if src.failed == 0 else "#b42318"
            where = ", ".join(sorted(src.ips)[:6]) + (" …" if len(src.ips) > 6 else "")
            hosts = ", ".join(sorted(src.hosts)[:3]) + (" …" if len(src.hosts) > 3 else "")
            disp = ", ".join(f"{k} {v}" for k, v in src.dispositions.most_common() if k != "none")
            h.append(
                f"<tr><td {td}><b>{escape(src.label)}</b>"
                f"<div style='color:#667085;font-size:11px'>{escape(where)}{'<br>' + escape(hosts) if hosts else ''}</div></td>"
                f"<td {tdr}>{src.total}</td><td {tdr}><b style='color:{color}'>{_pct(src.passed, src.total)}</b></td>"
                f"<td {tdr}>{_pct(src.dkim_aligned, src.total)}</td><td {tdr}>{_pct(src.spf_aligned, src.total)}</td>"
                f"<td {td}>{escape(', '.join(sorted(src.reporters)))}{'<br><span style=color:#b42318>' + escape(disp) + '</span>' if disp else ''}</td></tr>"
            )
        h.append("</table>")
        h.append(f"<h2 style='font-size:16px;margin:22px 0 8px'>Reports — {escape(s.domain)}</h2>"
                 "<table style='border-collapse:collapse;width:100%;background:#fff;font-size:13px'>"
                 f"<tr><th {th}>Reporter</th><th {th}>Day</th><th {thr}>Msgs</th><th {thr}>Pass</th><th {th}>Report ID</th></tr>")
        for r in sorted(s.reports, key=lambda r: (r.begin, r.org_name)):
            h.append(f"<tr><td {td}>{escape(r.org_name)}</td><td {td}>{escape(_day(r.begin, tz))}</td><td {tdr}>{r.total}</td>"
                     f"<td {tdr}>{_pct(r.passing, r.total)}</td><td style='padding:6px 8px;border-bottom:1px solid #eaecf0;font-size:11px;color:#667085;word-break:break-all'>{escape(r.report_id)}</td></tr>")
        h.append("</table>")
    if notes:
        h.append("<h2 style='font-size:16px;margin:22px 0 8px'>Notes</h2><ul style='padding-left:20px'>"
                 + "".join(f"<li>{escape(n)}</li>" for n in notes) + "</ul>")
    h.append("<p style='color:#667085;font-size:12px;margin-top:22px'>DKIM / SPF columns show the share of mail that passed "
             "<i>aligned</i> with your domain — that is what DMARC counts; a message passes DMARC if either is aligned. "
             "The original report files and a CSV of every record are attached.</p></div></body></html>")
    return "".join(h)


def records_csv(summaries: list[DomainSummary], rdns: dict[str, str]) -> bytes:
    buf = io.StringIO()
    w = csv.writer(buf)
    w.writerow(["domain", "reporter", "report_id", "begin_utc", "end_utc", "source_ip", "rdns", "count", "disposition",
                "dmarc", "dkim_aligned", "spf_aligned", "header_from", "envelope_from", "envelope_to",
                "dkim_results", "spf_results", "reasons"])
    for s in summaries:
        for r in s.reports:
            for rec in r.records:
                w.writerow([
                    s.domain, r.org_name, r.report_id,
                    datetime.fromtimestamp(r.begin, timezone.utc).isoformat() if r.begin else "",
                    datetime.fromtimestamp(r.end, timezone.utc).isoformat() if r.end else "",
                    rec.source_ip, rdns.get(rec.source_ip, ""), rec.count, rec.disposition,
                    "pass" if rec.dmarc_pass else "fail", rec.dkim_eval, rec.spf_eval,
                    rec.header_from, rec.envelope_from, rec.envelope_to,
                    "; ".join(f"{d.domain}/{d.selector}={d.result}" for d in rec.dkim),
                    "; ".join(f"{x.domain}={x.result}" for x in rec.spf),
                    "; ".join(f"{t}: {c}".strip(": ") for t, c in rec.reasons),
                ])
    return buf.getvalue().encode("utf-8")

"""The "in short" section at the top of the digest: a few sentences in plain
language for people who don't manage email systems (directors, owners,
office staff). No jargon: it says whether our email checks out, whether
anyone is pretending to be us, and who, if anyone, needs to do something.

Built from the same analysis as the technical findings, so the two never
disagree; only the wording differs.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timezone

from .analyze import ACTION, REVIEW, DomainSummary, Finding

GOOD, OK, BAD = "good", "ok", "bad"

HEADLINES = {
    GOOD: "All good: email sent in our name is checking out.",
    OK: "Working fine, with a suggested improvement.",
    BAD: "Something needs attention.",
}

# Friendly names for the organisations that send reports.
_REPORTERS = [
    (("google",), "Google"),
    (("outlook", "microsoft", "hotmail"), "Microsoft"),
    (("yahoo", "aol"), "Yahoo"),
    (("apple", "icloud"), "Apple"),
    (("comcast",), "Comcast"),
    (("mail.ru",), "Mail.ru"),
    (("zoho",), "Zoho"),
]


@dataclass
class Plain:
    status: str  # good | ok | bad
    headline: str
    points: list[str]
    todo: str


def _n(count: int, one: str, many: str | None = None) -> str:
    return f"{count:,} {one if count == 1 else (many or one + 's')}"


def _list(items: list[str]) -> str:
    items = list(dict.fromkeys(items))
    if len(items) <= 1:
        return "".join(items)
    return ", ".join(items[:-1]) + " and " + items[-1]


def _reporter(name: str) -> str:
    low = name.lower()
    for keys, friendly in _REPORTERS:
        if any(k in low for k in keys):
            return friendly
    return name


def _senders(sources) -> str:
    """Name known services; describe the rest without IP addresses."""
    names = sorted({src.label for src in sources if src.kind != "unknown"})
    unknown = sum(1 for src in sources if src.kind == "unknown")
    if unknown:
        names.append("a mail server we couldn't identify" if unknown == 1 else f"{unknown} mail servers we couldn't identify")
    return _list(names)


def _dates(s: DomainSummary, tz) -> str:
    begins = [r.begin for r in s.reports if r.begin]
    ends = [r.end for r in s.reports if r.end]
    if not begins:
        return ""
    a = datetime.fromtimestamp(min(begins), timezone.utc).astimezone(tz)
    b = datetime.fromtimestamp(max(ends), timezone.utc).astimezone(tz)
    if a.date() == b.date():
        return f"On {a:%B} {a.day}"
    return f"Between {a:%B} {a.day} and {b:%B} {b.day}"


def _protection(s: DomainSummary) -> str:
    seen = [r.policy.p for r in s.reports if r.policy.p]
    return max(set(seen), key=seen.count) if seen else ""


def _domain_points(s: DomainSummary, tz) -> list[str]:
    d = s.domain
    points: list[str] = []
    who = _list(sorted({_reporter(r.org_name) for r in s.reports}))
    when = _dates(s, tz)
    pct = round(100 * s.passed / s.total) if s.total else 100
    lead = f"{when}, " if when else ""
    if s.failed == 0:
        points.append(f"{lead}{who} checked {_n(s.total, 'email')} sent as @{d}. "
                      f"All of them were confirmed as genuinely from us.")
    else:
        points.append(f"{lead}{who} checked {_n(s.total, 'email')} sent as @{d}. "
                      f"{s.passed:,} ({pct}%) were confirmed as genuinely from us; {s.failed:,} were not.")

    protection = _protection(s)
    enforcing = protection in ("quarantine", "reject")

    def failed(cls: str) -> int:
        return sum(src.failed for src in s.sources if src.failure_class == cls)

    def blocked(cls: str) -> int:
        return sum(src.dispositions.get("quarantine", 0) + src.dispositions.get("reject", 0)
                   for src in s.sources if src.failure_class == cls)

    spoof, ours, other = failed("spoof"), failed("ours"), failed("forwarded") + failed("unrecognised")

    if spoof:
        stopped = blocked("spoof")
        fate = (f"Email providers blocked or sent {'it' if spoof == 1 else 'them'} to spam."
                if stopped >= spoof else
                f"Email providers blocked {stopped:,} of them; the rest were delivered." if stopped else
                f"Because our protection is in \"monitor only\" mode, {'it was' if spoof == 1 else 'they were'} still delivered."
                if not enforcing else
                f"{'It was' if spoof == 1 else 'They were'} still delivered.")
        points.append(f"{_n(spoof, 'email')} from computers we don't recognise pretended to be from @{d}. "
                      f"This is usually someone impersonating us (spam or scam email). {fate}")
    else:
        points.append(f"We found no sign of anyone impersonating @{d}.")

    if ours:
        senders = _senders([src for src in s.sources if src.failure_class == "ours"])
        stopped = blocked("ours")
        fate = (f"Some of it ({stopped:,}) was sent to spam or refused." if stopped else
                "It was still delivered, but this has to be fixed before we turn on stronger protection."
                if not enforcing else "It may have gone to spam.")
        points.append(f"{_n(ours, 'email')} that we really did send (through {senders}) failed the checks, "
                      f"because a setting is missing. {fate}")

    unsigned = sum(src.spf_only for src in s.sources)
    if unsigned:
        senders = _senders([src for src in s.sources if src.spf_only])
        points.append(f"{_n(unsigned, 'email')} we sent through {senders} went out without a security signature. "
                      "They were delivered, but could land in spam if someone forwards them.")

    if other and not spoof and not ours:
        points.append(f"{_n(other, 'forwarded copy', 'forwarded copies')} or mailing-list "
                      f"{'message' if other == 1 else 'messages'} failed the checks. That's normal and nothing to worry about.")

    if protection == "none":
        tail = ("Since everything is checking out, we're ready to turn it on."
                if not s.failed and not unsigned else
                "We should turn it on once the issues above are fixed.")
        points.append("Our protection is set to \"monitor only\": we receive these reports, but email providers "
                      f"aren't told to stop fake email. {tail}")
    elif protection == "quarantine":
        points.append("Our protection is on: email providers are told to send fake email in our name to spam.")
    elif protection == "reject":
        points.append("Our protection is fully on: email providers are told to refuse fake email in our name.")
    return points


def summarize_plain(summaries: list[DomainSummary], extra: list[Finding], tz) -> Plain:
    findings = [f for s in summaries for f in s.findings] + extra
    actions = sum(1 for f in findings if f.severity == ACTION)
    reviews = sum(1 for f in findings if f.severity == REVIEW)
    status = BAD if actions else OK if reviews else GOOD

    points: list[str] = []
    for s in summaries:
        points += _domain_points(s, tz)
    if extra:
        points.append(f"We also received {_n(len(extra), 'alert')} about individual emails that failed the checks.")

    if status == BAD:
        todo = (f"Please forward this email to whoever looks after our email or website settings (IT person, web "
                f"host or consultant). There {'is' if actions == 1 else 'are'} {_n(actions, 'item')} for them "
                "in the details below.")
    elif status == OK:
        todo = ("Nothing urgent. When convenient, pass this to whoever looks after our email settings; the "
                "suggestions for them are in the details below.")
    else:
        todo = "No action needed."
    return Plain(status, HEADLINES[status], points, todo)

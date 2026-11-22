"""Turn parsed aggregate reports into per-source statistics and findings
(the "what do I need to do" part of the digest)."""

from __future__ import annotations

import concurrent.futures
import socket
from collections import Counter, defaultdict
from dataclasses import dataclass, field

from .parse import Record, Report

# Severity order: things to fix, things to look at, background notes.
ACTION, REVIEW, INFO = "action", "review", "info"
SEVERITY_ORDER = {ACTION: 0, REVIEW: 1, INFO: 2}

# (name, kind, domain suffixes). kind: "sender" = a service that sends on our
# behalf; "forwarder" = relays mail others sent (forwarding, filtering).
PROVIDERS: list[tuple[str, str, tuple[str, ...]]] = [
    ("Brevo", "sender", ("sender-sib.com", "sendinblue.com", "brevo.com", "mailin.fr", "brevosend.com")),
    ("MXroute", "sender", ("mxroute.com", "mxrouting.net")),
    ("Google", "sender", ("google.com", "googlemail.com", "1e100.net", "gmail.com")),
    ("Microsoft 365", "sender", ("protection.outlook.com", "outlook.com", "office365.com")),
    ("Amazon SES", "sender", ("amazonses.com",)),
    ("SendGrid", "sender", ("sendgrid.net", "sendgrid.com")),
    ("Mailchimp", "sender", ("mcsv.net", "mcdlv.net", "rsgsv.net", "mandrillapp.com", "mailchimpapp.net")),
    ("Mailgun", "sender", ("mailgun.org", "mailgun.net")),
    ("Postmark", "sender", ("mtasv.net", "postmarkapp.com")),
    ("Zoho", "sender", ("zoho.com", "zohomail.com")),
    ("SiteGround AntiSpam", "forwarder", ("mailspamprotection.com",)),
    ("Proofpoint", "forwarder", ("pphosted.com", "ppe-hosted.com")),
    ("Mimecast", "forwarder", ("mimecast.com",)),
    ("Barracuda", "forwarder", ("barracudanetworks.com", "cudamail.com")),
]

FORWARD_REASONS = {"forwarded", "mailing_list", "trusted_forwarder"}

_MULTI_PART_TLDS = {"co.uk", "org.uk", "ac.uk", "com.au", "net.au", "org.au", "co.nz", "co.za", "com.br", "co.jp"}


def org_domain(domain: str) -> str:
    """Approximate organizational domain (no full public-suffix list)."""
    labels = domain.lower().strip(".").split(".")
    if len(labels) >= 3 and ".".join(labels[-2:]) in _MULTI_PART_TLDS:
        return ".".join(labels[-3:])
    return ".".join(labels[-2:])


def aligned(auth_domain: str, header_from: str, mode: str) -> bool:
    if not auth_domain or not header_from:
        return False
    if mode == "s":
        return auth_domain == header_from
    return org_domain(auth_domain) == org_domain(header_from)


def _match_provider(names: list[str]) -> tuple[str, str] | None:
    for name in names:
        name = name.lower().rstrip(".")
        for label, kind, suffixes in PROVIDERS:
            if any(name == s or name.endswith("." + s) for s in suffixes):
                return label, kind
    return None


def reverse_dns(ips: set[str], timeout: float = 4.0) -> dict[str, str]:
    """Best-effort PTR lookups, in parallel, bounded by timeout overall."""
    out: dict[str, str] = {}

    def lookup(ip: str) -> tuple[str, str]:
        try:
            return ip, socket.gethostbyaddr(ip)[0].lower()
        except (OSError, UnicodeError):
            return ip, ""

    if not ips:
        return out
    pool = concurrent.futures.ThreadPoolExecutor(max_workers=16)
    futures = [pool.submit(lookup, ip) for ip in ips]
    done, _ = concurrent.futures.wait(futures, timeout=timeout)
    for f in done:
        ip, host = f.result()
        out[ip] = host
    pool.shutdown(wait=False, cancel_futures=True)
    return out


@dataclass
class Source:
    key: str
    label: str
    kind: str  # sender | forwarder | unknown
    ips: set[str] = field(default_factory=set)
    hosts: set[str] = field(default_factory=set)
    total: int = 0
    passed: int = 0
    dkim_aligned: int = 0
    spf_aligned: int = 0
    spf_only: int = 0  # passed DMARC on SPF alone
    dkim_only: int = 0  # passed DMARC on DKIM alone
    failed: int = 0
    dispositions: Counter = field(default_factory=Counter)
    reporters: set[str] = field(default_factory=set)
    selectors: set[str] = field(default_factory=set)  # aligned, passing
    envelope_domains: set[str] = field(default_factory=set)
    failures: list[tuple[Record, Report]] = field(default_factory=list)
    # Set by _findings for sources with failures, in plain terms:
    # forwarded | ours | unrecognised | spoof
    failure_class: str = ""
    spf_only_records: list[tuple[Record, Report]] = field(default_factory=list)

    @property
    def pass_pct(self) -> float:
        return 100.0 * self.passed / self.total if self.total else 100.0


@dataclass
class Finding:
    severity: str
    domain: str
    title: str
    detail: str
    steps: list[str] = field(default_factory=list)


@dataclass
class DomainSummary:
    domain: str
    reports: list[Report]
    sources: list[Source]
    findings: list[Finding]
    policies: Counter  # "p=none pct=100 adkim=r aspf=r" -> reports seeing it
    rdns: dict[str, str] = field(default_factory=dict)

    @property
    def policy_line(self) -> str:
        return published_policy(self.reports)

    @property
    def total(self) -> int:
        return sum(s.total for s in self.sources)

    @property
    def passed(self) -> int:
        return sum(s.passed for s in self.sources)

    @property
    def failed(self) -> int:
        return sum(s.failed for s in self.sources)


def _source_for(rec: Record, host: str) -> tuple[str, str, str]:
    """(key, label, kind) for a record's sending source."""
    names = [host] if host else []
    names += [d.domain for d in rec.dkim if d.result == "pass" and not aligned(d.domain, rec.header_from, "r")]
    names += [s.domain for s in rec.spf if s.domain]
    names += [rec.envelope_from] if rec.envelope_from else []
    match = _match_provider(names)
    if match:
        return match[0], match[0], match[1]
    if host:
        od = org_domain(host)
        return od, od, "unknown"
    return rec.source_ip, rec.source_ip, "unknown"


def _policy_key(r: Report) -> str:
    """The parts every reporter includes. sp/np are optional in reports (many
    reporters omit them), so they'd make identical policies look different."""
    p = r.policy
    return f"p={p.p or '?'} pct={p.pct or '100'} adkim={p.adkim} aspf={p.aspf}"


def published_policy(reports: list[Report]) -> str:
    """One readable line for the policy, merging optional tags across reports."""
    if not reports:
        return ""
    base = Counter(_policy_key(r) for r in reports).most_common(1)[0][0]
    p, pct, adkim, aspf = base.split(" ")
    sp = Counter(r.policy.sp for r in reports if r.policy.sp).most_common(1)
    np = Counter(r.policy.np for r in reports if r.policy.np).most_common(1)
    bits = [p] + ([f"sp={sp[0][0]}"] if sp else []) + ([f"np={np[0][0]}"] if np else []) + [pct, adkim, aspf]
    return "; ".join(bits)


def summarize(reports: list[Report], rdns: dict[str, str] | None = None) -> list[DomainSummary]:
    rdns = rdns or {}
    by_domain: dict[str, list[Report]] = defaultdict(list)
    for r in reports:
        by_domain[r.policy.domain or "unknown"].append(r)

    summaries = []
    for domain, reps in sorted(by_domain.items()):
        sources: dict[str, Source] = {}
        for rep in reps:
            for rec in rep.records:
                host = rdns.get(rec.source_ip, "")
                key, label, kind = _source_for(rec, host)
                src = sources.get(key) or sources.setdefault(key, Source(key, label, kind))
                src.ips.add(rec.source_ip)
                if host:
                    src.hosts.add(host)
                src.total += rec.count
                src.reporters.add(rep.org_name)
                src.dispositions[rec.disposition] += rec.count
                if rec.envelope_from:
                    src.envelope_domains.add(rec.envelope_from)
                for s in rec.spf:
                    if s.domain and not aligned(s.domain, rec.header_from, rep.policy.aspf):
                        src.envelope_domains.add(s.domain)
                if rec.dkim_eval == "pass":
                    src.dkim_aligned += rec.count
                    for d in rec.dkim:
                        if d.result == "pass" and aligned(d.domain, rec.header_from, rep.policy.adkim) and d.selector:
                            src.selectors.add(d.selector)
                if rec.spf_eval == "pass":
                    src.spf_aligned += rec.count
                if rec.dmarc_pass:
                    src.passed += rec.count
                    if rec.dkim_eval != "pass":
                        src.spf_only += rec.count
                        src.spf_only_records.append((rec, rep))
                    elif rec.spf_eval != "pass":
                        src.dkim_only += rec.count
                else:
                    src.failed += rec.count
                    src.failures.append((rec, rep))
                if any(t in FORWARD_REASONS for t, _ in rec.reasons) and src.kind == "unknown":
                    src.kind = "forwarder"
        ordered = sorted(sources.values(), key=lambda s: (-s.failed, -s.total))
        policies = Counter(_policy_key(r) for r in reps)
        summary = DomainSummary(domain, reps, ordered, [], policies, rdns)
        summary.findings = _findings(summary)
        summaries.append(summary)
    return summaries


def _describe_where(src: Source, records: list[tuple[Record, Report]] | None = None, rdns: dict[str, str] | None = None) -> str:
    if records is not None:
        ips = sorted({rec.source_ip for rec, _ in records})
        hosts = sorted({(rdns or {}).get(ip, "") for ip in ips} - {""})
    else:
        hosts = sorted(src.hosts)
        ips = sorted(src.ips)
    where = ", ".join(ips[:4]) + (f" (+{len(ips) - 4} more)" if len(ips) > 4 else "")
    if hosts:
        where += " — " + ", ".join(hosts[:3]) + (" …" if len(hosts) > 3 else "")
    return where


def _failure_reasons(src: Source, domain: str) -> tuple[list[str], set[str], bool]:
    """Explain why a source's failing records failed.
    Returns (explanations, other authenticated domains, any-auth-at-all)."""
    notes: list[str] = []
    other_domains: set[str] = set()
    any_auth = False
    broken_sigs: Counter = Counter()
    unsigned = 0
    forwarded = 0
    for rec, rep in src.failures:
        own_dkim = [d for d in rec.dkim if aligned(d.domain, rec.header_from, "r")]
        for d in rec.dkim:
            if d.result == "pass":
                any_auth = True
                if not aligned(d.domain, rec.header_from, rep.policy.adkim):
                    other_domains.add(d.domain)
        for s in rec.spf:
            if s.result == "pass":
                any_auth = True
                if not aligned(s.domain, rec.header_from, rep.policy.aspf):
                    other_domains.add(s.domain)
        if own_dkim and all(d.result != "pass" for d in own_dkim):
            for d in own_dkim:
                broken_sigs[f"{d.selector or '?'}._domainkey.{d.domain} ({d.result})"] += rec.count
        elif not own_dkim:
            unsigned += rec.count
        if any(t in FORWARD_REASONS for t, _ in rec.reasons):
            forwarded += rec.count
    if broken_sigs:
        sigs = ", ".join(f"{k} ×{v}" for k, v in broken_sigs.most_common())
        notes.append(f"A DKIM signature for {domain} was present but did not verify: {sigs}.")
    if unsigned:
        notes.append(f"{unsigned} message(s) carried no DKIM signature for {domain}.")
    if other_domains:
        notes.append("Authenticated only as other domain(s): " + ", ".join(sorted(other_domains)) + " — not aligned with the From: domain.")
    if forwarded:
        notes.append(f"The reporter flagged {forwarded} message(s) as forwarded / mailing list.")
    return notes, other_domains, any_auth


def _findings(s: DomainSummary) -> list[Finding]:
    out: list[Finding] = []
    d = s.domain
    policy_values = {r.policy.p for r in s.reports}
    enforcing = bool(policy_values & {"quarantine", "reject"})
    legit_problems = False
    spoofing = False

    for src in s.sources:
        if not src.failed:
            continue
        blocked = src.dispositions.get("quarantine", 0) + src.dispositions.get("reject", 0)
        fate = (
            f"{blocked} of them were quarantined/rejected by the receiver."
            if blocked
            else "Your policy is p=none, so they were delivered anyway." if not enforcing
            else "The receiver delivered them anyway (local override)."
        )
        reasons, other_domains, any_auth = _failure_reasons(src, d)
        where = _describe_where(src, src.failures, s.rdns)
        reporters = ", ".join(sorted(src.reporters))
        base = f"{src.failed} message(s) with From: @{d} sent from {where} failed DMARC (seen by {reporters}). {fate}"
        detail = base + (" " + " ".join(reasons) if reasons else "")

        fwd = sum(rec.count for rec, _ in src.failures if any(t in FORWARD_REASONS for t, _ in rec.reasons))
        kind = "forwarder" if fwd and fwd == src.failed else src.kind
        if kind == "forwarder":
            src.failure_class = "forwarded"
            out.append(Finding(
                REVIEW if blocked else INFO, d,
                f"Forwarded mail via {src.label} failed DMARC ({src.failed})",
                detail,
                ["Forwarding and filtering services rewrite the envelope (breaking SPF) and sometimes modify the message "
                 "(breaking DKIM). Usually nothing to fix on your side as long as your own DKIM signs every message.",
                 "If the volume is significant and the recipients matter, ask that organisation to enable ARC or to whitelist your domain."],
            ))
        elif kind == "sender":
            src.failure_class = "ours"
            legit_problems = True
            steps = []
            if src.passed:
                steps.append(f"{src.passed} other message(s) from {src.label} passed, so the setup works for some mail — "
                             "find the sending path (another account, alias, form plugin, app) that isn't signing with "
                             f"{d}.")
            steps.append(f"In {src.label}, set up domain authentication for {d} (custom DKIM) and publish the DNS records it gives you.")
            if any("did not verify" in r for r in reasons):
                steps.append("Check that the DKIM public key published in DNS for that selector matches what the provider signs with "
                             "(a rotated or truncated key is the usual cause).")
            if src.label == "Brevo":
                steps.append("Brevo: Settings → Senders, Domains & Dedicated IPs → Domains → authenticate the domain.")
            out.append(Finding(ACTION if not src.passed or src.failed >= 5 or blocked else REVIEW, d,
                               f"{src.label} sent {src.failed} message(s) that failed DMARC", detail, steps))
        elif any_auth:
            src.failure_class = "unrecognised"
            out.append(Finding(
                REVIEW, d,
                f"Unrecognised source {src.label} failed DMARC ({src.failed})",
                detail,
                [f"If this is a service you use, configure it to sign with DKIM for {d} (and/or add it to your SPF record).",
                 "If it authenticated as another organisation's domain, it is most likely a forward, mailing list or "
                 "auto-reply, and can be ignored."],
            ))
            if not other_domains:
                legit_problems = True
        else:
            src.failure_class = "spoof"
            spoofing = True
            out.append(Finding(
                ACTION if not enforcing or src.failed >= 10 else REVIEW, d,
                f"Unauthenticated mail claiming to be {d} from {src.label} ({src.failed})",
                detail + " Neither SPF nor DKIM passed for any domain.",
                [f"If you don't recognise {where}: this is spoofing of {d}. "
                 + ("Moving to p=quarantine (then p=reject) is what stops it." if not enforcing else "Your policy is already acting on it."),
                 f"If it IS yours (a server, printer, web form, CRM): add it to the SPF record for {d} and turn on DKIM signing there."],
            ))

    for src in s.sources:
        if not src.spf_only:
            continue
        partial = src.dkim_aligned > 0
        hint = (f" Other messages from {src.label} were DKIM-signed (selector {', '.join(sorted(src.selectors))}), "
                "so signing is configured — some messages are leaving by a path that doesn't sign."
                if partial else "")
        out.append(Finding(
            REVIEW if partial else ACTION, d,
            f"{src.label}: {src.spf_only} message(s) passed on SPF only (no DKIM)",
            f"{src.spf_only} message(s) from {_describe_where(src, src.spf_only_records, s.rdns)} passed DMARC only because SPF aligned; "
            f"they carried no valid DKIM signature for {d}.{hint} SPF breaks as soon as a message is forwarded, so "
            "these will fail at recipients who forward their mail.",
            [f"Enable DKIM signing for {d} in {src.label}" + (" for every sending account/alias." if partial else "."),
             "Check DKIM status again in the next reports."],
        ))

    dkim_only = [src for src in s.sources if src.dkim_only]
    if dkim_only:
        parts = []
        for src in dkim_only:
            env = ", ".join(sorted(e for e in src.envelope_domains if not aligned(e, d, "r"))[:3])
            parts.append(f"{src.label} ({src.dkim_only} msg" + (f", bounce domain {env}" if env else "") + ")")
        out.append(Finding(
            INFO, d, "SPF not aligned for some senders — DMARC passed on DKIM",
            "These sources use their own bounce (Return-Path) domain, so SPF passes for them but not for "
            f"{d}: " + "; ".join(parts) + ". DMARC only needs one of SPF/DKIM aligned, so this is fine.",
            ["Optional: if the provider offers a custom return-path / bounce domain (e.g. bounce." + d + "), setting it up "
             "gives you a second aligned check."],
        ))

    # Policy advice.
    pcts = {r.policy.pct for r in s.reports if r.policy.pct}
    if "none" in policy_values:
        if not legit_problems and not s.failed:
            out.append(Finding(
                REVIEW, d, "Ready to tighten policy: everything passed",
                f"All {s.total} reported message(s) passed DMARC while the policy is p=none (monitor only), "
                "which gives no protection against spoofing.",
                [f"After a couple of weeks of clean reports, change _dmarc.{d} to p=quarantine; pct=25, then raise pct to 100, then p=reject."],
            ))
        elif not legit_problems:
            out.append(Finding(
                REVIEW, d, "Policy is p=none (monitor only)",
                f"Your legitimate senders pass, but {s.failed} message(s) failed and were delivered because the policy "
                "doesn't ask receivers to act." + (" Some of that looks like spoofing." if spoofing else ""),
                [f"Once the remaining items are understood, move _dmarc.{d} to p=quarantine (pct=25 first)."],
            ))
        else:
            out.append(Finding(
                INFO, d, "Stay on p=none for now",
                "Some of your own senders are failing DMARC; tightening the policy now would send that mail to spam.",
                ["Fix the action items above first, then plan the move to p=quarantine."],
            ))
    if pcts - {"100"}:
        out.append(Finding(INFO, d, f"Policy applies to only {', '.join(sorted(pcts - {'100'}))}% of failing mail",
                           "pct below 100 means receivers apply your policy to only a sample of failing messages.",
                           ["Raise pct to 100 when you are confident in the results."]))
    if enforcing and any(r.policy.sp == "none" for r in s.reports):
        out.append(Finding(REVIEW, d, "Subdomains are not protected (sp=none)",
                           f"The main domain is enforced but sp=none lets anyone spoof <anything>.{d}.",
                           ["Remove sp=none (subdomains then inherit p) unless a subdomain really needs it."]))
    if len(s.policies) > 1:
        seen = "; ".join(f"{k} ({v} report(s))" for k, v in s.policies.most_common())
        out.append(Finding(INFO, d, "Receivers saw different published policies",
                           f"Policies seen: {seen}. Normal right after a DNS change; otherwise check for "
                           "duplicate or conflicting _dmarc TXT records.", []))
    for rep in s.reports:
        for err in rep.errors:
            out.append(Finding(INFO, d, f"{rep.org_name} reported an error", err, []))

    out.sort(key=lambda f: SEVERITY_ORDER[f.severity])
    return out


def forensic_finding(fields: dict[str, list[str]]) -> Finding:
    get = lambda k: ", ".join(fields.get(k, [])) or "?"  # noqa: E731
    domain = get("reported-domain")
    return Finding(
        ACTION, domain,
        f"Failure report: message from {get('source-ip')} failed {get('auth-failure')}",
        f"A receiver sent a forensic (failure) report for a single message. Reported domain: {domain}; "
        f"source IP: {get('source-ip')}; envelope from: {get('original-mail-from')}; arrival: {get('arrival-date')}; "
        f"DKIM domain/selector: {get('dkim-domain')}/{get('dkim-selector')}; delivery result: {get('delivery-result')}.",
        ["If the source is yours, fix its SPF/DKIM. If not, it's spoofing — see the policy advice."],
    )

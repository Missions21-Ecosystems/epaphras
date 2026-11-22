"""dmarcd: poll a mailbox for DMARC reports, email a readable digest.

    python -m dmarcd                 run forever (poll every POLL_INTERVAL_SECONDS)
    python -m dmarcd --once          one poll, then send the digest if one is due
    python -m dmarcd --once --now    ...and send it now even if DIGEST_TIME isn't reached
    python -m dmarcd --dry-run       read the mailbox read-only, write the digest to
                                     DATA_DIR/preview/ instead of sending; changes nothing
    python -m dmarcd --resend        rebuild the last digest from stored reports and send it
                                     again (e.g. after an upgrade); changes no state
    python -m dmarcd --file a.xml.gz b.zip       digest from local files (no mailbox) and
                                     send it; add --dry-run to only preview it
"""

from __future__ import annotations

import argparse
import json
import logging
import os
import signal
import sys
import time
from datetime import datetime, timedelta
from email.header import decode_header, make_header
from zoneinfo import ZoneInfo, ZoneInfoNotFoundError

from . import analyze, extract, mail, render
from .config import Config, load_dotenv
from .parse import ReportError, parse_report
from .store import Store

log = logging.getLogger("dmarcd")
_stop = False


def _header(msg, name: str) -> str:
    raw = msg.get(name, "")
    try:
        return str(make_header(decode_header(raw))).replace("\n", " ").replace("\r", "")
    except (UnicodeError, LookupError, ValueError):
        return str(raw)


def fully_handled(outcome: str) -> bool:
    """True when every report in the message was read and stored (or was a
    known duplicate), so the message itself is no longer needed."""
    return outcome != "no-report" and " bad=0 " in f" {outcome} "


def ingest(store: Store, raw: bytes, label: str = "") -> str:
    """Store whatever reports a message holds. Returns a short outcome."""
    msg = extract.parse_message(raw)
    subject = _header(msg, "Subject") or label
    payloads, forensic = extract.extract(msg)
    return store_payloads(store, payloads, forensic, subject)


def ingest_file(store: Store, path: str) -> str:
    """A saved .eml, or a bare report file (.xml/.xml.gz/.zip)."""
    with open(path, "rb") as fh:
        data = fh.read()
    name = os.path.basename(path)
    if path.lower().endswith(".eml"):
        return ingest(store, data, name)
    try:
        found = extract.decode_payload(data, name)
    except Exception as exc:  # noqa: BLE001 - report any unreadable file
        return store_payloads(store, [extract.Payload(name, data, None, str(exc))], [], name)
    payloads = [extract.Payload(n or name, data, x) for n, x in found] or [extract.Payload(name, data, None, "not a gzip/zip/XML file")]
    return store_payloads(store, payloads, [], name)


def store_payloads(store: Store, payloads, forensic, subject: str) -> str:
    added = dup = bad = 0
    for p in payloads:
        if p.xml is None:
            bad += 1
            store.add_note(f"Could not read attachment {p.filename!r} in “{subject}”: {p.error}")
            continue
        try:
            rep = parse_report(p.xml)
        except ReportError as exc:
            bad += 1
            store.add_note(f"Could not parse {p.filename!r} in “{subject}”: {exc}")
            continue
        if store.add_report(rep.org_name, rep.report_id, rep.policy.domain, rep.begin, rep.end, p.filename, p.raw, p.xml):
            added += 1
        else:
            dup += 1
            store.add_note(f"Skipped duplicate report {rep.report_id} from {rep.org_name} ({p.filename}).")
    for f in forensic:
        store.add_forensic(subject, f.fields, f.original_headers)
    if not payloads and not forensic:
        return "no-report"
    return f"reports={added} dup={dup} bad={bad} forensic={len(forensic)}"


def poll(cfg: Config, store: Store, readonly: bool = False) -> int:
    box = mail.Mailbox(cfg, readonly=readonly)
    try:
        if cfg.processed_action == "move":
            box.ensure_folder(cfg.archive_folder)
        seen = store.seen(cfg.imap_folder, box.uidvalidity)
        new = [u for u in box.uids() if u not in seen]
        if new:
            log.info("%d new message(s) in %s", len(new), cfg.imap_folder)
        cleaned: list[str] = []
        for uid, raw in box.fetch(new):
            msg = extract.parse_message(raw)
            outcome = ingest(store, raw, f"uid {uid}")
            store.mark_message(cfg.imap_folder, box.uidvalidity, uid, msg.get("Message-ID", ""),
                               _header(msg, "From"), _header(msg, "Subject"), outcome)
            store.commit()  # per message, so a crash never re-processes or loses one
            log.info("uid %s from %s: %s", uid, _header(msg, "From"), outcome)
            if fully_handled(outcome):
                box.done(uid)
            elif outcome == "no-report" and cfg.inbox_cleanup:
                box.delete(uid)
                cleaned.append(f"“{_header(msg, 'Subject') or '(no subject)'}” from {_header(msg, 'From') or '?'}")
                log.info("uid %s deleted (INBOX_CLEANUP: no DMARC report)", uid)
            else:
                # Not ours to tidy away: a human message, or a report we
                # couldn't read. Leave it unread where it is.
                if outcome == "no-report":
                    store.add_note(f"Left in {cfg.imap_folder} (no DMARC report in it): "
                                   f"“{_header(msg, 'Subject')}” from {_header(msg, 'From')}.")
                    store.commit()
                log.info("uid %s left in place, unread", uid)
        if cleaned:
            shown = "; ".join(cleaned[:10]) + (f"; and {len(cleaned) - 10} more" if len(cleaned) > 10 else "")
            store.add_note(f"INBOX_CLEANUP deleted {len(cleaned)} message(s) from {cfg.imap_folder} that had no "
                           f"DMARC report: {shown}.")
            store.commit()
        return len(new)
    finally:
        box.close()


def _tz(cfg: Config):
    try:
        return ZoneInfo(cfg.tz)
    except (ZoneInfoNotFoundError, ValueError):
        log.warning("unknown TZ %r, using UTC", cfg.tz)
        return ZoneInfo("UTC")


def digest_due(cfg: Config, store: Store, now: datetime | None = None) -> bool:
    if not cfg.digest_time:
        return True
    tz = _tz(cfg)
    now = now or datetime.now(tz)
    hh, mm = (int(x) for x in cfg.digest_time.split(":"))
    slot = now.replace(hour=hh, minute=mm, second=0, microsecond=0)
    if now < slot:
        slot -= timedelta(days=1)
    return store.last_digest_at() < slot.timestamp()


def build_digest(cfg: Config, store: Store, items=None):
    """(EmailMessage, ids, text, html) for everything not yet sent (or for
    the given (reports, forensic, notes) rows), or None."""
    reports_rows, forensic_rows, note_rows = items if items is not None else store.pending()
    if not reports_rows and not forensic_rows:
        return None  # notes alone (e.g. only duplicates) aren't worth an email
    reports = []
    notes = [n["text"] for n in note_rows]
    for row in reports_rows:
        try:
            reports.append(parse_report(row["xml"]))
        except ReportError as exc:  # stored, so it parsed once; be defensive anyway
            notes.append(f"Report {row['report_id']} could not be re-read: {exc}")
    ips = {rec.source_ip for r in reports for rec in r.records}
    rdns = analyze.reverse_dns(ips) if cfg.rdns else {}
    summaries = analyze.summarize(reports, rdns)
    extra = [analyze.forensic_finding(json.loads(f["fields"])) for f in forensic_rows]
    tz = _tz(cfg)
    subject = render.subject(summaries, extra)
    text = render.text_body(summaries, extra, notes, tz)
    html = render.html_body(summaries, extra, notes, tz)
    attachments = []
    if cfg.attach_csv and reports:
        attachments.append(("dmarc-records.csv", render.records_csv(summaries, rdns), "text/csv"))
    if cfg.attach_originals:
        used = set()
        for row in reports_rows:
            name = row["filename"] or f"report-{row['id']}"
            if name in used:
                name = f"{row['id']}-{name}"
            used.add(name)
            data = row["raw"] or row["xml"]
            ctype = ("application/gzip" if data[:2] == b"\x1f\x8b" else
                     "application/zip" if data[:4] == b"PK\x03\x04" else "application/xml")
            attachments.append((name, data, ctype))
    msg = mail.build_message(cfg, subject, text, html, attachments)
    ids = ([r["id"] for r in reports_rows], [f["id"] for f in forensic_rows], [n["id"] for n in note_rows])
    return msg, ids, text, html


def send_digest(cfg: Config, store: Store, dry_run: bool = False) -> bool:
    built = build_digest(cfg, store)
    if not built:
        return False
    msg, ids, text, html = built
    if dry_run:
        out = os.path.join(cfg.data_dir, "preview")
        os.makedirs(out, exist_ok=True)
        for name, body in (("digest.txt", text), ("digest.html", html)):
            with open(os.path.join(out, name), "w", encoding="utf-8") as fh:
                fh.write(body)
        with open(os.path.join(out, "digest.eml"), "wb") as fh:
            fh.write(msg.as_bytes())
        log.info("dry run: wrote %s/digest.{txt,html,eml} — subject: %s", out, msg["Subject"])
        return True
    mail.send(cfg, msg)
    store.record_digest(msg["Subject"], cfg.forward_to, *ids)
    log.info("sent digest to %s: %s", ", ".join(cfg.forward_to), msg["Subject"])
    return True


def cycle(cfg: Config, store: Store, force_send: bool = False) -> None:
    try:
        poll(cfg, store)
    except Exception:  # network, auth, server hiccups: log and retry next cycle
        log.exception("poll failed")
    try:
        if force_send or digest_due(cfg, store):
            send_digest(cfg, store)
    except Exception:
        log.exception("sending digest failed; will retry next cycle")


def _on_signal(signum, _frame):
    global _stop
    _stop = True
    log.info("signal %s: stopping after this step", signum)


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(prog="dmarcd", description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--env", default=".env", help="env file to load when not under Compose (default .env)")
    ap.add_argument("--once", action="store_true", help="run one cycle and exit")
    ap.add_argument("--now", action="store_true", help="with --once: send the digest regardless of DIGEST_TIME")
    ap.add_argument("--dry-run", action="store_true", help="read-only; write the digest to DATA_DIR/preview/")
    ap.add_argument("--resend", action="store_true",
                    help="rebuild the most recent digest from stored reports (current layout) and send it again; "
                         "changes no state (combine with --dry-run to only preview)")
    ap.add_argument("--file", nargs="*", default=[], help="build a digest from local report files instead of the mailbox")
    args = ap.parse_args(argv)

    load_dotenv(args.env)
    if args.file and args.dry_run:
        os.environ.setdefault("EMAIL", "dry-run@example.invalid")
        os.environ.setdefault("PASSWORD", "-")
        os.environ.setdefault("FWD_REPORT_EMAIL", "dry-run@example.invalid")
        os.environ.setdefault("IMAP_HOST", "-")
    cfg = Config.from_env()
    logging.basicConfig(level=getattr(logging, cfg.log_level, logging.INFO),
                        format="%(asctime)s %(levelname)s %(name)s: %(message)s", stream=sys.stdout)
    os.makedirs(cfg.data_dir, exist_ok=True)

    if (args.dry_run and not args.resend) or args.file:
        store = Store(":memory:")  # never touches real state
        for path in args.file:
            log.info("%s: %s", path, ingest_file(store, path))
        if not args.file:
            poll(cfg, store, readonly=True)
        store.commit()
        if not send_digest(cfg, store, dry_run=args.dry_run):
            log.info("nothing to report")
        return 0

    store = Store(cfg.db_path)
    if args.resend:
        built = build_digest(cfg, store, store.last_digest_items())
        if not built:
            log.info("no digest has been sent yet; nothing to resend")
            return 1
        msg, _ids, text, html = built
        if args.dry_run:
            out = os.path.join(cfg.data_dir, "preview")
            os.makedirs(out, exist_ok=True)
            for name, body in (("digest.txt", text), ("digest.html", html)):
                with open(os.path.join(out, name), "w", encoding="utf-8") as fh:
                    fh.write(body)
            log.info("resend dry run: wrote %s/digest.{txt,html} — %s", out, msg["Subject"])
        else:
            mail.send(cfg, msg)
            log.info("resent last digest to %s: %s", ", ".join(cfg.forward_to), msg["Subject"])
        return 0
    if args.once:
        cycle(cfg, store, force_send=args.now)
        return 0

    signal.signal(signal.SIGTERM, _on_signal)
    signal.signal(signal.SIGINT, _on_signal)
    log.info("watching %s@%s/%s every %ss (processed mail: %s); digests to %s%s", cfg.imap_user, cfg.imap_host,
             cfg.imap_folder, cfg.poll_interval,
             {"keep": "kept", "move": f"moved to {cfg.archive_folder}", "delete": "deleted"}[cfg.processed_action], ", ".join(cfg.forward_to), f" daily at {cfg.digest_time} {cfg.tz}" if cfg.digest_time else "")
    while not _stop:
        cycle(cfg, store)
        deadline = time.monotonic() + cfg.poll_interval
        while not _stop and time.monotonic() < deadline:
            time.sleep(min(5, deadline - time.monotonic()))
    return 0


if __name__ == "__main__":
    sys.exit(main())

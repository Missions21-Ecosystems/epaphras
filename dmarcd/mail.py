"""IMAP fetching and SMTP sending."""

from __future__ import annotations

import imaplib
import logging
import re
import smtplib
import ssl
from email.message import EmailMessage
from email.utils import formataddr, formatdate, make_msgid
from typing import Iterator

from .config import Config

log = logging.getLogger(__name__)


class Mailbox:
    """One IMAP session on the report folder."""

    def __init__(self, cfg: Config, readonly: bool = False):
        self.cfg = cfg
        self.readonly = readonly
        ctx = ssl.create_default_context()
        if cfg.imap_security == "ssl":
            self.conn = imaplib.IMAP4_SSL(cfg.imap_host, cfg.imap_port, ssl_context=ctx, timeout=60)
        else:
            self.conn = imaplib.IMAP4(cfg.imap_host, cfg.imap_port, timeout=60)
            self.conn.starttls(ssl_context=ctx)
        self.conn.login(cfg.imap_user, cfg.password)
        typ, _ = self.conn.select(_quote(cfg.imap_folder), readonly=readonly)
        if typ != "OK":
            raise RuntimeError(f"cannot open folder {cfg.imap_folder!r}")
        typ, data = self.conn.response("UIDVALIDITY")
        self.uidvalidity = int(data[0]) if data and data[0] else 0
        caps = self.conn.capabilities
        self.can_move = "MOVE" in caps

    def uids(self) -> list[int]:
        typ, data = self.conn.uid("SEARCH", None, "ALL")
        if typ != "OK":
            raise RuntimeError("UID SEARCH failed")
        return [int(u) for u in data[0].split()] if data and data[0] else []

    def fetch(self, uids: list[int]) -> Iterator[tuple[int, bytes]]:
        for uid in uids:
            typ, data = self.conn.uid("FETCH", str(uid), "(BODY.PEEK[])")
            if typ != "OK":
                log.warning("fetch of uid %s failed", uid)
                continue
            for item in data:
                if isinstance(item, tuple) and len(item) == 2:
                    yield uid, item[1]
                    break

    def done(self, uid: int) -> None:
        """Mark handled: \\Seen, and move to the archive folder if configured."""
        if self.readonly:
            return
        self.conn.uid("STORE", str(uid), "+FLAGS.SILENT", r"(\Seen)")
        folder = self.cfg.archive_folder
        if not folder:
            return
        if self.can_move:
            typ, data = self.conn.uid("MOVE", str(uid), _quote(folder))
        else:
            typ, data = self.conn.uid("COPY", str(uid), _quote(folder))
            if typ == "OK":
                self.conn.uid("STORE", str(uid), "+FLAGS.SILENT", r"(\Deleted)")
                self.conn.expunge()
        if typ != "OK":
            log.warning("could not move uid %s to %s: %s", uid, folder, data)

    def ensure_folder(self, folder: str) -> None:
        if self.readonly or not folder:
            return
        typ, data = self.conn.list(pattern=_quote(folder))
        if typ == "OK" and data and data[0]:
            return
        typ, data = self.conn.create(_quote(folder))
        if typ == "OK":
            self.conn.subscribe(_quote(folder))
            log.info("created folder %s", folder)
        else:
            log.warning("could not create folder %s: %s", folder, data)

    def close(self) -> None:
        try:
            self.conn.logout()
        except (imaplib.IMAP4.error, OSError):
            pass


def _quote(name: str) -> str:
    return '"' + name.replace("\\", "\\\\").replace('"', '\\"') + '"' if re.search(r'[\s"\\]', name) else name


def build_message(cfg: Config, subject: str, text: str, html: str, attachments: list[tuple[str, bytes, str]]) -> EmailMessage:
    msg = EmailMessage()
    msg["Subject"] = subject
    msg["From"] = formataddr((cfg.from_name, cfg.from_addr))
    msg["To"] = ", ".join(cfg.forward_to)
    msg["Date"] = formatdate(localtime=False)
    msg["Message-ID"] = make_msgid(domain=cfg.from_addr.rpartition("@")[2] or None)
    # Stops vacation responders and other automation replying to the digest.
    msg["Auto-Submitted"] = "auto-generated"
    msg["X-Auto-Response-Suppress"] = "All"
    msg.set_content(text)
    msg.add_alternative(html, subtype="html")
    for name, data, ctype in attachments:
        maintype, _, subtype = ctype.partition("/")
        msg.add_attachment(data, maintype=maintype, subtype=subtype, filename=name)
    return msg


def send(cfg: Config, msg: EmailMessage) -> None:
    ctx = ssl.create_default_context()
    if cfg.smtp_security == "ssl":
        server = smtplib.SMTP_SSL(cfg.smtp_host, cfg.smtp_port, context=ctx, timeout=60)
    else:
        server = smtplib.SMTP(cfg.smtp_host, cfg.smtp_port, timeout=60)
    try:
        server.ehlo()
        if cfg.smtp_security == "starttls":
            server.starttls(context=ctx)
            server.ehlo()
        if cfg.smtp_user:
            server.login(cfg.smtp_user, cfg.smtp_password)
        server.send_message(msg, from_addr=cfg.from_addr, to_addrs=cfg.forward_to)
    finally:
        try:
            server.quit()
        except (smtplib.SMTPException, OSError):
            pass

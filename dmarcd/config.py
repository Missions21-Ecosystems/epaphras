"""Settings. Everything comes from environment variables (Compose passes the
.env file through; outside Compose, --env loads it). See example.env for the
full, documented list. Nothing provider-specific is hard-coded."""

from __future__ import annotations

import os
from dataclasses import dataclass


def _env(name: str, default: str = "") -> str:
    return os.environ.get(name, default).strip()


def _int(name: str, default: int) -> int:
    raw = _env(name)
    try:
        return int(raw) if raw else default
    except ValueError:
        raise SystemExit(f"{name} must be a number, got {raw!r}")


def _bool(name: str, default: bool) -> bool:
    raw = _env(name).lower()
    if not raw:
        return default
    return raw not in ("0", "false", "no", "off")


def _list(name: str) -> list[str]:
    return [a.strip() for a in _env(name).split(",") if a.strip()]


def load_dotenv(path: str) -> None:
    """Minimal .env loader for running outside Compose. Real env wins."""
    if not os.path.exists(path):
        return
    with open(path, encoding="utf-8") as fh:
        for line in fh:
            line = line.strip()
            if not line or line.startswith("#") or "=" not in line:
                continue
            key, _, value = line.partition("=")
            key = key.strip()
            if key.startswith("export "):
                key = key[7:].strip()
            value = value.strip()
            if len(value) >= 2 and value[0] == value[-1] and value[0] in "'\"":
                value = value[1:-1]
            os.environ.setdefault(key, value)


@dataclass
class Config:
    # Mailbox that receives the reports (rua=mailto:...).
    email: str
    password: str
    forward_to: list[str]

    imap_host: str
    imap_port: int = 993
    imap_security: str = "ssl"  # ssl | starttls
    imap_user: str = ""
    imap_folder: str = "INBOX"
    # After a message's reports are stored: keep (mark read), move (to
    # archive_folder) or delete. Messages without a readable report are
    # never moved or deleted.
    processed_action: str = "keep"
    archive_folder: str = ""

    smtp_host: str = ""
    smtp_port: int = 465
    smtp_security: str = "ssl"  # ssl | starttls | none
    smtp_user: str = ""
    smtp_password: str = ""
    from_addr: str = ""
    from_name: str = "DMARC Reports"

    poll_interval: int = 900
    digest_time: str = ""  # "HH:MM" in tz = one digest a day; "" = after each poll with news
    tz: str = "UTC"

    data_dir: str = "/data"
    rdns: bool = True
    attach_originals: bool = True
    attach_csv: bool = True
    log_level: str = "INFO"

    @property
    def db_path(self) -> str:
        return os.path.join(self.data_dir, "dmarc.sqlite")

    @classmethod
    def from_env(cls) -> "Config":
        email = _env("EMAIL")
        password = _env("PASSWORD")
        fwd = _list("FWD_REPORT_EMAIL")
        imap_host = _env("IMAP_HOST")
        missing = [n for n, v in (("EMAIL", email), ("PASSWORD", password),
                                  ("FWD_REPORT_EMAIL", fwd), ("IMAP_HOST", imap_host)) if not v]
        if missing:
            raise SystemExit(f"missing required settings: {', '.join(missing)} (see example.env)")
        imap_security = _env("IMAP_SECURITY", "ssl").lower()
        smtp_security = _env("SMTP_SECURITY", "ssl").lower()
        if imap_security not in ("ssl", "starttls"):
            raise SystemExit("IMAP_SECURITY must be ssl or starttls")
        if smtp_security not in ("ssl", "starttls", "none"):
            raise SystemExit("SMTP_SECURITY must be ssl, starttls or none")
        archive_folder = _env("IMAP_ARCHIVE_FOLDER")
        action = _env("PROCESSED_ACTION").lower() or ("move" if archive_folder else "keep")
        if action not in ("keep", "move", "delete"):
            raise SystemExit("PROCESSED_ACTION must be keep, move or delete")
        if action == "move" and not archive_folder:
            raise SystemExit("PROCESSED_ACTION=move needs IMAP_ARCHIVE_FOLDER")
        digest_time = _env("DIGEST_TIME")
        if digest_time:
            hh, _, mm = digest_time.partition(":")
            if not (hh.isdigit() and mm.isdigit() and int(hh) < 24 and int(mm) < 60):
                raise SystemExit("DIGEST_TIME must be HH:MM (24h) or empty")
        return cls(
            email=email,
            password=password,
            forward_to=fwd,
            imap_host=imap_host,
            imap_port=_int("IMAP_PORT", 993 if imap_security == "ssl" else 143),
            imap_security=imap_security,
            imap_user=_env("IMAP_USER", email),
            imap_folder=_env("IMAP_FOLDER", "INBOX"),
            processed_action=action,
            archive_folder=archive_folder if action == "move" else "",
            smtp_host=_env("SMTP_HOST", imap_host),
            smtp_port=_int("SMTP_PORT", {"ssl": 465, "starttls": 587, "none": 25}[smtp_security]),
            smtp_security=smtp_security,
            smtp_user=_env("SMTP_USER", email),
            smtp_password=_env("SMTP_PASSWORD", password),
            from_addr=_env("FROM_EMAIL", email),
            from_name=_env("FROM_NAME", "DMARC Reports"),
            poll_interval=max(60, _int("POLL_INTERVAL_SECONDS", 900)),
            digest_time=digest_time,
            tz=_env("TZ", "UTC"),
            data_dir=_env("DATA_DIR", "/data"),
            rdns=_bool("RDNS", True),
            attach_originals=_bool("ATTACH_ORIGINALS", True),
            attach_csv=_bool("ATTACH_CSV", True),
            log_level=_env("LOG_LEVEL", "INFO").upper(),
        )

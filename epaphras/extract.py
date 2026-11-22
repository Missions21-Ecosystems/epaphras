"""Pull DMARC report payloads out of an email message.

Reporters send aggregate reports as .xml.gz, .zip or plain .xml, either as an
attachment or as the whole (single-part) message body, sometimes without a
filename. Forwarded copies nest them inside message/rfc822 parts. We walk
every leaf part and sniff the bytes rather than trusting names or types.

Forensic (failure, "ruf") reports arrive as multipart/report with a
message/feedback-report part; those are returned separately.
"""

from __future__ import annotations

import email
import email.policy
import gzip
import io
import zipfile
from dataclasses import dataclass
from email.message import Message

MAX_XML_BYTES = 50 * 1024 * 1024  # decompressed cap per report (zip bombs)
MAX_ZIP_MEMBERS = 20

GZIP_MAGIC = b"\x1f\x8b"
ZIP_MAGIC = b"PK\x03\x04"


@dataclass
class Payload:
    filename: str  # what the sender called it (or a synthesized name)
    raw: bytes  # bytes exactly as attached (for re-attaching)
    xml: bytes | None  # decompressed XML, None if extraction failed
    error: str = ""


@dataclass
class ForensicReport:
    fields: dict[str, list[str]]
    original_headers: str


def parse_message(raw: bytes) -> Message:
    return email.message_from_bytes(raw, policy=email.policy.compat32)


def _read_limited(stream, limit: int) -> bytes:
    data = stream.read(limit + 1)
    if len(data) > limit:
        raise ValueError(f"decompressed report exceeds {limit // (1024 * 1024)} MB")
    return data


def _looks_like_xml(data: bytes) -> bool:
    head = data.lstrip(b"\xef\xbb\xbf \t\r\n")[:200].lower()
    return head.startswith(b"<?xml") or head.startswith(b"<feedback")


def decode_payload(data: bytes, filename: str = "") -> list[tuple[str, bytes]]:
    """Return [(name, xml_bytes)] for every report found in data. Raises
    ValueError when data is a recognised container that can't be read."""
    if data.startswith(GZIP_MAGIC):
        with gzip.GzipFile(fileobj=io.BytesIO(data)) as gz:
            inner = _read_limited(gz, MAX_XML_BYTES)
        name = filename[:-3] if filename.lower().endswith(".gz") else filename
        return decode_payload(inner, name) if (inner.startswith(ZIP_MAGIC) or inner.startswith(GZIP_MAGIC)) else [(name, inner)]
    if data.startswith(ZIP_MAGIC):
        out: list[tuple[str, bytes]] = []
        with zipfile.ZipFile(io.BytesIO(data)) as zf:
            members = [i for i in zf.infolist() if not i.is_dir()]
            if len(members) > MAX_ZIP_MEMBERS:
                raise ValueError(f"zip has {len(members)} members")
            for info in members:
                if info.file_size > MAX_XML_BYTES:
                    raise ValueError(f"{info.filename} is too large")
                with zf.open(info) as fh:
                    out.extend(decode_payload(_read_limited(fh, MAX_XML_BYTES), info.filename))
        return out
    if _looks_like_xml(data):
        return [(filename, data)]
    return []


_REPORT_EXTS = (".xml", ".xml.gz", ".gz", ".zip", ".xml.zip")
_REPORT_TYPES = {
    "application/gzip", "application/x-gzip", "application/zip",
    "application/x-zip-compressed", "application/x-zip", "application/xml",
    "text/xml", "application/octet-stream",
}


def extract(msg: Message) -> tuple[list[Payload], list[ForensicReport]]:
    payloads: list[Payload] = []
    forensic: list[ForensicReport] = []
    for part in msg.walk():
        ctype = part.get_content_type()
        if ctype == "message/feedback-report":
            forensic.append(_forensic(msg, part))
            continue
        if part.is_multipart() or ctype.startswith("message/"):
            continue
        filename = part.get_filename() or ""
        if ctype in ("text/plain", "text/html") and not filename:
            continue  # message body text, not an attachment
        candidate = filename.lower().endswith(_REPORT_EXTS) or ctype in _REPORT_TYPES
        if not candidate:
            continue
        data = part.get_payload(decode=True) or b""
        if not data:
            continue
        name = filename or f"report{len(payloads) + 1}"
        try:
            found = decode_payload(data, name)
        except (OSError, EOFError, zipfile.BadZipFile, ValueError) as exc:
            payloads.append(Payload(name, data, None, f"could not decompress: {exc}"))
            continue
        if not found and filename.lower().endswith(_REPORT_EXTS):
            payloads.append(Payload(name, data, None, "not a gzip/zip/XML file"))
        for inner_name, xml in found:
            payloads.append(Payload(inner_name or name, data, xml))
    return payloads, forensic


def _forensic(msg: Message, part: Message) -> ForensicReport:
    # The feedback-report body is a header block ("Key: value" lines). The
    # parser may hand it back as sub-message(s) whose headers are the fields.
    fields: dict[str, list[str]] = {}
    body = part.get_payload()
    if isinstance(body, list):
        for sub in body:
            for k, v in sub.items():
                fields.setdefault(k.strip().lower(), []).append(str(v).strip())
    else:
        raw = part.get_payload(decode=True)
        text = raw.decode("utf-8", "replace") if raw else str(body)
        for line in text.splitlines():
            if ":" in line and not line.startswith((" ", "\t")):
                k, _, v = line.partition(":")
                fields.setdefault(k.strip().lower(), []).append(v.strip())
    original = ""
    for p in msg.walk():
        if p.get_content_type() in ("message/rfc822", "text/rfc822-headers") and p is not part:
            payload = p.get_payload()
            if isinstance(payload, list) and payload:
                original = "\n".join(f"{k}: {v}" for k, v in payload[0].items())
            else:
                raw = p.get_payload(decode=True) or b""
                original = raw.decode("utf-8", "replace").split("\n\n", 1)[0]
            break
    return ForensicReport(fields, original[:4000])

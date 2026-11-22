# Changelog

## 0.4.0 — 2026-11-22

- `INBOX_CLEANUP=1` treats the mailbox as a no-reply, report-only inbox:
  messages containing no DMARC report (bounces, auto-replies, spam, people
  writing in) are permanently deleted. Messages with an unreadable report are
  still kept. Each poll adds one note to the next digest listing what was
  deleted. Default off.

## 0.3.0 — 2026-11-22

- Digest opens with an "In short" section for non-technical readers: a
  plain-language status, a few jargon-free sentences (is our email checking
  out, is anyone impersonating us, is any of our own mail failing, how strong
  is protection) and who needs to act. Built from the same analysis as the
  technical findings (`dmarcd/plain.py`), so the two always agree.

## 0.2.0 — 2026-11-22

- `PROCESSED_ACTION=keep|move|delete` decides what happens to a report email
  once its reports are saved (default `keep`; setting only
  `IMAP_ARCHIVE_FOLDER` still means `move`). Deletion expunges just that
  message (UID EXPUNGE).
- Messages without a DMARC report, or whose report can't be read, are no
  longer marked read or moved: they stay unread in place and the next digest
  lists them.
- Fix: IMAP capabilities are re-read after login. Servers that announce
  MOVE/UIDPLUS only to logged-in clients (e.g. Dovecot) were treated as
  lacking them, which made moves fall back to COPY + folder-wide EXPUNGE.
- README notes that no AI is involved in reading reports or writing digests.

## 0.1.0 — 2026-11-22

- First release: IMAP polling, report extraction (.xml.gz/.zip/.xml,
  attachments, single-part bodies, forwards), DMARC 1.0/2.0 parsing,
  per-source analysis with ranked findings, HTML + text digest with CSV and
  original attachments, Docker Compose deployment, MIT license.

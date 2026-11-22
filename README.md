# dmarcd

A small service that watches the mailbox your DMARC aggregate reports go to,
reads the reports (`.xml.gz`, `.zip` or `.xml`), and emails you a readable
digest that says what, if anything, you need to fix.

Python 3.10+ standard library only — no third-party dependencies.

**No AI.** dmarcd does not use AI or language models to read your reports or
write the digest. Reports are parsed as XML, and every finding and
recommendation comes from fixed, readable rules in
[dmarcd/analyze.py](dmarcd/analyze.py). The same reports (and reverse-DNS
answers) always produce the same digest, and your report data never leaves
your machine — the only outbound connections are to your own mail server and
reverse-DNS lookups of the sending IPs (turn those off with `RDNS=0`).

## What the digest contains

- **Headline per domain**: messages seen, % passing DMARC, failures, the policy
  receivers saw.
- **What to do**: findings ranked ACTION / REVIEW / FYI, each with an
  explanation and concrete steps. For example:
  - a known sending service (Brevo, SendGrid, Mailchimp, Google, Microsoft 365,
    MXroute, …) whose mail fails DMARC because it isn't signing with your
    domain's DKIM;
  - mail that passes only on SPF (no DKIM) — it will fail once forwarded;
  - a DKIM signature for your domain that fails to verify (wrong/rotated key);
  - unauthenticated mail claiming to be from your domain (spoofing, or a
    sender you forgot to authorise);
  - forwarded / mailing-list mail (usually nothing to do);
  - mail quarantined or rejected by receivers;
  - policy advice: when it's safe to move from `p=none` to `quarantine` and
    `reject`, `pct` below 100, unprotected subdomains.
- **Sending sources**: each source (grouped by provider, using reverse DNS and
  the authenticated domains) with DMARC / aligned-DKIM / aligned-SPF rates.
- **Reports** received, duplicates skipped, files that couldn't be read.
- Attachments: a CSV of every record and the original report files.

Forensic (failure, `ruf`) reports are recognised and listed as action items.

## How it works

1. Every `POLL_INTERVAL_SECONDS` it logs in over IMAP and reads messages it
   hasn't handled yet (tracked by UID in SQLite, so read/unread state in your
   mail client doesn't matter).
2. Report files are found by content (gzip/zip/XML magic bytes), whether they
   are attachments, the whole body of the message (common for reports sent
   directly by receivers), or inside a forwarded message.
3. Reports are stored once, keyed by reporter + report ID — reporters that
   resend the same report don't produce duplicates.
4. Handled messages are marked read and, if `IMAP_ARCHIVE_FOLDER` is set,
   moved there.
5. A digest of everything not yet sent goes out after each check that found
   reports, or once a day at `DIGEST_TIME`. If sending fails, it's retried on
   the next check; nothing is lost.

## Quick start (Docker)

```sh
cp example.env .env      # fill in mailbox, IMAP host and recipient
make preview             # read-only: writes data/preview/digest.html, sends nothing
make up                  # start the service
make logs
```

All settings are environment variables, documented in
[example.env](example.env).

Without Docker:

```sh
pip install .            # or just run from the checkout
dmarcd --env .env        # runs forever; DATA_DIR defaults to /data, set it e.g. DATA_DIR=./data
```

## Commands

| | |
|---|---|
| `dmarcd` | run forever |
| `dmarcd --once` | one check, then send the digest if one is due |
| `dmarcd --once --now` | one check and send the digest now, ignoring `DIGEST_TIME` |
| `dmarcd --dry-run` | read the mailbox read-only and write the digest to `DATA_DIR/preview/` — marks nothing, sends nothing, uses no saved state |
| `dmarcd --file a.xml.gz b.zip c.eml` | build a digest from local files and send it (`--dry-run` to only preview) |

`make test` runs the unit tests (`python3 tests/make_fixtures.py` regenerates the fixtures); `make mailpit-test` delivers a digest built
from the test fixtures to a local Mailpit on `localhost:1025`.

## Setting up the reporting address

Point your DMARC record's `rua` at the mailbox:

```
_dmarc.example.org.  TXT  "v=DMARC1; p=none; rua=mailto:dmarc@example.org"
```

If the mailbox is on a **different domain** from the one being reported on,
that domain must authorise it (RFC 7489 §7.1), e.g. for reports about
`other.com` sent to `dmarc@example.org`:

```
other.com._report._dmarc.example.org.  TXT  "v=DMARC1"
```

## Security notes

- The mailbox password lives in `.env` (never committed; see `.gitignore`).
- XML with a DTD/entities is refused; decompressed size and zip member counts
  are capped.
- The digest carries `Auto-Submitted: auto-generated` so auto-responders don't
  reply to it.

## State

`DATA_DIR/dmarc.sqlite` holds handled message UIDs, the stored reports (raw and
XML), and the digests sent. Deleting it makes the service treat everything in
the folder as new.

## License

MIT — see [LICENSE](LICENSE). Test fixtures are synthetic (`tests/make_fixtures.py`), using only reserved example domains and documentation IP ranges.

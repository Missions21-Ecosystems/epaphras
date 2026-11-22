"""SQLite state: which mailbox messages were handled, the reports pulled out of
them (deduplicated by reporter + report id), and what has been sent."""

from __future__ import annotations

import json
import sqlite3
import time

SCHEMA = """
CREATE TABLE IF NOT EXISTS messages (
    folder TEXT NOT NULL, uidvalidity INTEGER NOT NULL, uid INTEGER NOT NULL,
    message_id TEXT, sender TEXT, subject TEXT, processed_at INTEGER NOT NULL, outcome TEXT NOT NULL,
    PRIMARY KEY (folder, uidvalidity, uid)
);
CREATE TABLE IF NOT EXISTS reports (
    id INTEGER PRIMARY KEY,
    org_name TEXT NOT NULL, report_id TEXT NOT NULL, domain TEXT NOT NULL,
    begin_ts INTEGER, end_ts INTEGER, received_at INTEGER NOT NULL,
    filename TEXT, raw BLOB, xml BLOB NOT NULL,
    digest_id INTEGER,
    UNIQUE (org_name, report_id, domain)
);
CREATE TABLE IF NOT EXISTS forensic (
    id INTEGER PRIMARY KEY, received_at INTEGER NOT NULL, subject TEXT,
    fields TEXT NOT NULL, original TEXT, digest_id INTEGER
);
-- Things worth a line in the next digest: duplicates, unreadable files.
CREATE TABLE IF NOT EXISTS notes (
    id INTEGER PRIMARY KEY, received_at INTEGER NOT NULL, text TEXT NOT NULL, digest_id INTEGER
);
CREATE TABLE IF NOT EXISTS digests (
    id INTEGER PRIMARY KEY, sent_at INTEGER NOT NULL, subject TEXT, recipients TEXT
);
"""


class Store:
    def __init__(self, path: str):
        self.db = sqlite3.connect(path)
        self.db.row_factory = sqlite3.Row
        self.db.executescript(SCHEMA)
        self.db.commit()

    def seen(self, folder: str, uidvalidity: int) -> set[int]:
        rows = self.db.execute("SELECT uid FROM messages WHERE folder=? AND uidvalidity=?", (folder, uidvalidity))
        return {r["uid"] for r in rows}

    def mark_message(self, folder, uidvalidity, uid, message_id, sender, subject, outcome) -> None:
        self.db.execute(
            "INSERT OR REPLACE INTO messages VALUES (?,?,?,?,?,?,?,?)",
            (folder, uidvalidity, uid, message_id, sender, subject, int(time.time()), outcome),
        )

    def add_report(self, org_name, report_id, domain, begin, end, filename, raw, xml) -> bool:
        """False if this report was already stored (resent / duplicated)."""
        cur = self.db.execute(
            "INSERT OR IGNORE INTO reports (org_name, report_id, domain, begin_ts, end_ts, received_at, filename, raw, xml)"
            " VALUES (?,?,?,?,?,?,?,?,?)",
            (org_name, report_id, domain, begin, end, int(time.time()), filename, raw, xml),
        )
        return cur.rowcount == 1

    def add_forensic(self, subject: str, fields: dict, original: str) -> None:
        self.db.execute("INSERT INTO forensic (received_at, subject, fields, original) VALUES (?,?,?,?)",
                        (int(time.time()), subject, json.dumps(fields), original))

    def add_note(self, text: str) -> None:
        self.db.execute("INSERT INTO notes (received_at, text) VALUES (?,?)", (int(time.time()), text))

    def commit(self) -> None:
        self.db.commit()

    def pending(self):
        reports = self.db.execute("SELECT * FROM reports WHERE digest_id IS NULL ORDER BY begin_ts").fetchall()
        forensic = self.db.execute("SELECT * FROM forensic WHERE digest_id IS NULL ORDER BY id").fetchall()
        notes = self.db.execute("SELECT * FROM notes WHERE digest_id IS NULL ORDER BY id").fetchall()
        return reports, forensic, notes

    def record_digest(self, subject: str, recipients: list[str], report_ids, forensic_ids, note_ids) -> int:
        cur = self.db.execute("INSERT INTO digests (sent_at, subject, recipients) VALUES (?,?,?)",
                              (int(time.time()), subject, ",".join(recipients)))
        did = cur.lastrowid
        for table, ids in (("reports", report_ids), ("forensic", forensic_ids), ("notes", note_ids)):
            self.db.executemany(f"UPDATE {table} SET digest_id=? WHERE id=?", [(did, i) for i in ids])
        self.db.commit()
        return did

    def last_digest_items(self):
        """(reports, forensic, notes) included in the most recent digest."""
        row = self.db.execute("SELECT MAX(id) AS id FROM digests").fetchone()
        if not row["id"]:
            return [], [], []
        did = row["id"]
        return tuple(self.db.execute(f"SELECT * FROM {t} WHERE digest_id=? ORDER BY id", (did,)).fetchall()
                     for t in ("reports", "forensic", "notes"))

    def last_digest_at(self) -> int:
        row = self.db.execute("SELECT MAX(sent_at) AS t FROM digests").fetchone()
        return row["t"] or 0

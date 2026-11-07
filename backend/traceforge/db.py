"""Small, transactional SQLite persistence layer."""
from contextlib import contextmanager
from datetime import datetime, timezone
import os
from pathlib import Path
import sqlite3


def now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def data_dir() -> Path:
    return Path(os.environ.get("TRACEFORGE_DATA_DIR", ".traceforge")).resolve()


@contextmanager
def database():
    root = data_dir()
    root.mkdir(parents=True, exist_ok=True)
    connection = sqlite3.connect(root / "traceforge.sqlite3", timeout=30)
    connection.row_factory = sqlite3.Row
    connection.execute("PRAGMA foreign_keys=ON")
    try:
        yield connection
        connection.commit()
    except BaseException:
        connection.rollback()
        raise
    finally:
        connection.close()


def initialize() -> None:
    with database() as db:
        db.execute("PRAGMA journal_mode=WAL")
        db.executescript("""
        CREATE TABLE IF NOT EXISTS cases (
            id TEXT PRIMARY KEY,
            name TEXT NOT NULL,
            description TEXT NOT NULL DEFAULT '',
            created_at TEXT NOT NULL
        );
        CREATE TABLE IF NOT EXISTS evidence (
            id TEXT PRIMARY KEY,
            case_id TEXT NOT NULL REFERENCES cases(id) ON DELETE CASCADE,
            filename TEXT NOT NULL,
            sha256 TEXT NOT NULL,
            size_bytes INTEGER NOT NULL,
            uploaded_at TEXT NOT NULL,
            status TEXT NOT NULL,
            event_count INTEGER NOT NULL DEFAULT 0,
            error TEXT NOT NULL DEFAULT ''
        );
        CREATE TABLE IF NOT EXISTS events (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            case_id TEXT NOT NULL REFERENCES cases(id) ON DELETE CASCADE,
            evidence_id TEXT NOT NULL REFERENCES evidence(id) ON DELETE CASCADE,
            timestamp TEXT,
            event_id INTEGER,
            record_id TEXT,
            host TEXT,
            channel TEXT,
            provider TEXT,
            account TEXT,
            summary TEXT NOT NULL,
            data_json TEXT NOT NULL,
            raw_xml TEXT NOT NULL
        );
        CREATE INDEX IF NOT EXISTS ix_events_case_timestamp ON events(case_id, timestamp);
        CREATE INDEX IF NOT EXISTS ix_events_case_event_id ON events(case_id, event_id);
        CREATE INDEX IF NOT EXISTS ix_events_evidence ON events(evidence_id);
        CREATE TABLE IF NOT EXISTS findings (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            case_id TEXT NOT NULL REFERENCES cases(id) ON DELETE CASCADE,
            evidence_id TEXT NOT NULL REFERENCES evidence(id) ON DELETE CASCADE,
            event_row_id INTEGER NOT NULL REFERENCES events(id) ON DELETE CASCADE,
            rule_id TEXT NOT NULL,
            title TEXT NOT NULL,
            severity TEXT NOT NULL,
            explanation TEXT NOT NULL,
            created_at TEXT NOT NULL
        );
        CREATE INDEX IF NOT EXISTS ix_findings_case ON findings(case_id);
        CREATE TABLE IF NOT EXISTS hunts (
            id TEXT PRIMARY KEY,
            case_id TEXT NOT NULL REFERENCES cases(id) ON DELETE CASCADE,
            created_at TEXT NOT NULL,
            status TEXT NOT NULL,
            output_json TEXT NOT NULL,
            stderr TEXT NOT NULL
        );
        """)

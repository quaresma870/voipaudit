"""
Optional SQLite-backed scan history — `scan --db PATH` persists each
target's run and findings, matching the sibling secureaudit/
redteam-toolkit/loganalyzer repos' own SQLite-backed history pattern.

Deliberately separate from core/audit_log.py's hash-chained,
tamper-evident log: that log exists to prove exactly what actions were
taken and when (an integrity record), while this is a plain, mutable,
queryable history of findings meant to be browsed (via the `dashboard`
command) — two different jobs, not a redundant second copy of the same
one. Entirely opt-in: without --db, nothing is written here at all.
"""

from __future__ import annotations

import json
import sqlite3
from datetime import datetime

_SCHEMA = """
CREATE TABLE IF NOT EXISTS runs (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    engagement_id TEXT NOT NULL,
    client TEXT NOT NULL,
    target TEXT NOT NULL,
    modules TEXT NOT NULL,
    transport TEXT NOT NULL,
    started_at TEXT NOT NULL,
    finished_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS findings (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    run_id INTEGER NOT NULL REFERENCES runs(id),
    module TEXT NOT NULL,
    title TEXT NOT NULL,
    severity TEXT NOT NULL,
    category TEXT NOT NULL,
    target TEXT NOT NULL,
    description TEXT NOT NULL,
    evidence TEXT NOT NULL,
    remediation TEXT NOT NULL,
    extra TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_findings_run_id ON findings(run_id);
"""


def init_db(db_path: str) -> sqlite3.Connection:
    """Opens (creating if needed) the scan-history database and
    ensures its schema exists — idempotent, safe to call on every
    `scan --db` invocation regardless of whether the file is new."""
    conn = sqlite3.connect(db_path)
    conn.executescript(_SCHEMA)
    conn.commit()
    return conn


def record_run(
    conn: sqlite3.Connection,
    *,
    engagement_id: str,
    client: str,
    target: str,
    modules: list[str],
    transport: str,
    started_at: datetime,
    finished_at: datetime,
    findings: list,
) -> int:
    """Persists one target's run and its findings. One call per
    target per `scan` invocation — a run always corresponds to exactly
    one target, matching how findings are already grouped for the
    terminal report (reports/terminal.py's print_results, called once
    per target)."""
    cur = conn.execute(
        "INSERT INTO runs (engagement_id, client, target, modules, transport, started_at, finished_at) "
        "VALUES (?, ?, ?, ?, ?, ?, ?)",
        (
            engagement_id, client, target, ",".join(modules), transport,
            started_at.isoformat(), finished_at.isoformat(),
        ),
    )
    run_id = cur.lastrowid
    for f in findings:
        conn.execute(
            "INSERT INTO findings (run_id, module, title, severity, category, target, description, "
            "evidence, remediation, extra) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
            (
                run_id, f.module, f.title, f.severity.value, f.category.value, f.target,
                f.description, f.evidence, f.remediation, json.dumps(f.extra),
            ),
        )
    conn.commit()
    return run_id

"""
Tests for core/db.py — the optional SQLite-backed scan history
persisted by `scan --db`.
"""

from __future__ import annotations

import datetime
import sqlite3

from voipaudit.core.db import init_db, record_run
from voipaudit.core.models import Finding, FindingCategory, Severity


def _finding(**overrides) -> Finding:
    defaults = dict(
        module="pbx_fingerprint",
        title="Asterisk detected",
        severity=Severity.INFO,
        category=FindingCategory.RECON,
        target="127.0.0.1:5060",
        description="desc",
        evidence="Server: Asterisk PBX 18.9.0",
        remediation="",
        extra={},
    )
    defaults.update(overrides)
    return Finding(**defaults)


class TestInitDb:
    def test_creates_schema_idempotently(self, tmp_path):
        db_path = str(tmp_path / "history.db")
        conn1 = init_db(db_path)
        conn1.close()
        # Calling again on the same (now-existing) file must not raise
        # or wipe anything -- schema creation is idempotent.
        conn2 = init_db(db_path)
        tables = {
            row[0] for row in conn2.execute("SELECT name FROM sqlite_master WHERE type='table'")
        }
        assert {"runs", "findings"} <= tables
        conn2.close()


class TestRecordRun:
    def test_persists_run_and_findings(self, tmp_path):
        conn = init_db(str(tmp_path / "history.db"))
        now = datetime.datetime.now(datetime.UTC)
        run_id = record_run(
            conn, engagement_id="eng-1", client="Acme Corp", target="127.0.0.1:5060",
            modules=["pbx_fingerprint", "transport_security"], transport="tcp",
            started_at=now, finished_at=now, findings=[_finding()],
        )
        assert run_id == 1

        run_row = conn.execute("SELECT * FROM runs WHERE id = ?", (run_id,)).fetchone()
        assert run_row[1] == "eng-1"  # engagement_id
        assert run_row[2] == "Acme Corp"  # client
        assert run_row[4] == "pbx_fingerprint,transport_security"  # modules
        assert run_row[5] == "tcp"  # transport

        finding_rows = conn.execute("SELECT * FROM findings WHERE run_id = ?", (run_id,)).fetchall()
        assert len(finding_rows) == 1
        assert finding_rows[0][2] == "pbx_fingerprint"  # module
        assert finding_rows[0][4] == "INFO"  # severity

    def test_multiple_runs_get_independent_findings(self, tmp_path):
        conn = init_db(str(tmp_path / "history.db"))
        now = datetime.datetime.now(datetime.UTC)
        run_a = record_run(
            conn, engagement_id="eng-a", client="A", target="127.0.0.1:5060",
            modules=["pbx_fingerprint"], transport="udp", started_at=now, finished_at=now,
            findings=[_finding(module="pbx_fingerprint")],
        )
        run_b = record_run(
            conn, engagement_id="eng-b", client="B", target="127.0.0.1:5061",
            modules=["srtp_check"], transport="udp", started_at=now, finished_at=now,
            findings=[_finding(module="srtp_check"), _finding(module="srtp_check")],
        )
        assert run_a != run_b
        findings_a = conn.execute("SELECT * FROM findings WHERE run_id = ?", (run_a,)).fetchall()
        findings_b = conn.execute("SELECT * FROM findings WHERE run_id = ?", (run_b,)).fetchall()
        assert len(findings_a) == 1
        assert len(findings_b) == 2

    def test_run_with_no_findings_persists_cleanly(self, tmp_path):
        conn = init_db(str(tmp_path / "history.db"))
        now = datetime.datetime.now(datetime.UTC)
        run_id = record_run(
            conn, engagement_id="eng-1", client="Acme", target="127.0.0.1:5060",
            modules=["pbx_fingerprint"], transport="udp", started_at=now, finished_at=now,
            findings=[],
        )
        rows = conn.execute("SELECT * FROM findings WHERE run_id = ?", (run_id,)).fetchall()
        assert rows == []

    def test_extra_dict_round_trips_as_json(self, tmp_path):
        import json

        conn = init_db(str(tmp_path / "history.db"))
        now = datetime.datetime.now(datetime.UTC)
        run_id = record_run(
            conn, engagement_id="eng-1", client="Acme", target="127.0.0.1:5060",
            modules=["m"], transport="udp", started_at=now, finished_at=now,
            findings=[_finding(extra={"foo": "bar", "count": 3})],
        )
        row = conn.execute("SELECT extra FROM findings WHERE run_id = ?", (run_id,)).fetchone()
        assert json.loads(row[0]) == {"foo": "bar", "count": 3}

    def test_reopening_existing_db_preserves_prior_data(self, tmp_path):
        db_path = str(tmp_path / "history.db")
        now = datetime.datetime.now(datetime.UTC)
        conn1 = init_db(db_path)
        record_run(
            conn1, engagement_id="eng-1", client="Acme", target="127.0.0.1:5060",
            modules=["m"], transport="udp", started_at=now, finished_at=now, findings=[_finding()],
        )
        conn1.close()

        conn2 = init_db(db_path)
        rows = conn2.execute("SELECT * FROM runs").fetchall()
        assert len(rows) == 1
        conn2.close()

    def test_direct_sqlite_read_matches_record_run_output(self, tmp_path):
        """Confirms the persisted file is a genuine, plain SQLite
        database readable by any standard client, not something that
        depends on this module's own connection object."""
        db_path = str(tmp_path / "history.db")
        conn = init_db(db_path)
        now = datetime.datetime.now(datetime.UTC)
        record_run(
            conn, engagement_id="eng-1", client="Acme", target="127.0.0.1:5060",
            modules=["m"], transport="udp", started_at=now, finished_at=now, findings=[_finding()],
        )
        conn.close()

        fresh = sqlite3.connect(db_path)
        count = fresh.execute("SELECT COUNT(*) FROM findings").fetchone()[0]
        assert count == 1
        fresh.close()

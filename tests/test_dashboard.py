"""
Tests for voipaudit/dashboard/app.py — the read-only web dashboard for
browsing `scan --db` history. Tested via FastAPI's real TestClient
(a real ASGI request/response cycle, not a mock of the framework)
against a real SQLite database populated through core/db.py.
"""

from __future__ import annotations

import datetime

import pytest

pytest.importorskip("fastapi", reason="dashboard tests require the optional 'dashboard' extra")

from fastapi.testclient import TestClient  # noqa: E402

from voipaudit.core.db import init_db, record_run  # noqa: E402
from voipaudit.core.models import Finding, FindingCategory, Severity  # noqa: E402
from voipaudit.dashboard.app import create_app  # noqa: E402


def _finding(**overrides) -> Finding:
    defaults = dict(
        module="pbx_fingerprint",
        title="Asterisk detected",
        severity=Severity.INFO,
        category=FindingCategory.RECON,
        target="127.0.0.1:5060",
        description="desc",
        evidence="evidence text",
        remediation="remediation text",
        extra={},
    )
    defaults.update(overrides)
    return Finding(**defaults)


def _seed_db(db_path: str, findings: list[Finding], **run_overrides) -> int:
    conn = init_db(db_path)
    now = datetime.datetime.now(datetime.UTC)
    defaults = dict(
        engagement_id="test-eng", client="Test Client", target="127.0.0.1:5060",
        modules=["pbx_fingerprint"], transport="udp", started_at=now, finished_at=now,
    )
    defaults.update(run_overrides)
    run_id = record_run(conn, findings=findings, **defaults)
    conn.close()
    return run_id


class TestDashboardIndex:
    def test_empty_db_shows_no_runs_message(self, tmp_path):
        db_path = str(tmp_path / "history.db")
        init_db(db_path).close()
        client = TestClient(create_app(db_path))

        resp = client.get("/")
        assert resp.status_code == 200
        assert "No runs yet" in resp.text

    def test_lists_runs_with_engagement_and_target(self, tmp_path):
        db_path = str(tmp_path / "history.db")
        _seed_db(db_path, [_finding()], engagement_id="acme-eng-2026", target="10.0.0.5:5061")
        client = TestClient(create_app(db_path))

        resp = client.get("/")
        assert resp.status_code == 200
        assert "acme-eng-2026" in resp.text
        assert "10.0.0.5:5061" in resp.text

    def test_severity_counts_shown(self, tmp_path):
        db_path = str(tmp_path / "history.db")
        _seed_db(db_path, [_finding(severity=Severity.CRITICAL), _finding(severity=Severity.CRITICAL),
                            _finding(severity=Severity.INFO)])
        client = TestClient(create_app(db_path))

        resp = client.get("/")
        assert "2 CRITICAL" in resp.text
        assert "1 INFO" in resp.text


class TestDashboardRunDetail:
    def test_shows_findings_for_run(self, tmp_path):
        db_path = str(tmp_path / "history.db")
        _seed_db(db_path, [_finding(title="A distinctive finding title")])
        client = TestClient(create_app(db_path))

        resp = client.get("/runs/1")
        assert resp.status_code == 200
        assert "A distinctive finding title" in resp.text

    def test_missing_run_returns_404(self, tmp_path):
        db_path = str(tmp_path / "history.db")
        init_db(db_path).close()
        client = TestClient(create_app(db_path))

        resp = client.get("/runs/999")
        assert resp.status_code == 404

    def test_html_in_finding_content_is_escaped_not_injected(self, tmp_path):
        """Finding text can embed target-controlled data (a hostile
        PBX's own Server/From header content, echoed back by
        pbx_fingerprint/caller_id_spoofing) -- must never be rendered
        as raw HTML. A real, not hypothetical, stored-XSS check."""
        db_path = str(tmp_path / "history.db")
        _seed_db(db_path, [_finding(
            title="<script>alert('title')</script>",
            description="<img src=x onerror=alert('desc')>",
            evidence="<b>bold evidence</b>",
        )])
        client = TestClient(create_app(db_path))

        resp = client.get("/runs/1")
        assert resp.status_code == 200
        assert "<script>alert" not in resp.text
        assert "<img src=x onerror" not in resp.text
        assert "<b>bold evidence</b>" not in resp.text
        assert "&lt;script&gt;" in resp.text
        assert "&lt;img src=x onerror" in resp.text

    def test_findings_ordered_by_severity(self, tmp_path):
        db_path = str(tmp_path / "history.db")
        _seed_db(db_path, [
            _finding(title="the-info-one", severity=Severity.INFO),
            _finding(title="the-critical-one", severity=Severity.CRITICAL),
            _finding(title="the-medium-one", severity=Severity.MEDIUM),
        ])
        client = TestClient(create_app(db_path))

        resp = client.get("/runs/1")
        critical_idx = resp.text.index("the-critical-one")
        medium_idx = resp.text.index("the-medium-one")
        info_idx = resp.text.index("the-info-one")
        assert critical_idx < medium_idx < info_idx


class TestDashboardJsonApi:
    def test_api_runs_lists_runs(self, tmp_path):
        db_path = str(tmp_path / "history.db")
        _seed_db(db_path, [_finding()], engagement_id="json-eng")
        client = TestClient(create_app(db_path))

        resp = client.get("/api/runs")
        assert resp.status_code == 200
        data = resp.json()
        assert len(data) == 1
        assert data[0]["engagement_id"] == "json-eng"

    def test_api_run_findings_returns_parsed_extra(self, tmp_path):
        db_path = str(tmp_path / "history.db")
        _seed_db(db_path, [_finding(extra={"nested": {"a": 1}})])
        client = TestClient(create_app(db_path))

        resp = client.get("/api/runs/1/findings")
        assert resp.status_code == 200
        data = resp.json()
        assert len(data) == 1
        assert data[0]["extra"] == {"nested": {"a": 1}}

    def test_api_run_findings_missing_run_returns_404(self, tmp_path):
        db_path = str(tmp_path / "history.db")
        init_db(db_path).close()
        client = TestClient(create_app(db_path))

        resp = client.get("/api/runs/999/findings")
        assert resp.status_code == 404


class TestDashboardIsReadOnly:
    def test_no_post_put_delete_routes_exist(self, tmp_path):
        """Confirms this is genuinely GET-only -- an attempt to mutate
        via any other HTTP method must be rejected by the framework
        itself (405/404), not silently accepted."""
        db_path = str(tmp_path / "history.db")
        _seed_db(db_path, [_finding()])
        client = TestClient(create_app(db_path))

        assert client.post("/runs/1").status_code in (404, 405)
        assert client.delete("/runs/1").status_code in (404, 405)
        assert client.put("/api/runs/1/findings").status_code in (404, 405)

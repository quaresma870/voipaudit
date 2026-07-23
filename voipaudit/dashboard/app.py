"""
Read-only web dashboard for browsing `scan --db`-persisted history
(core/db.py). Optional: pip install voipaudit[dashboard].

Deliberately GET-only — no route here ever inserts, updates, or
deletes anything — and defaults to binding 127.0.0.1 only (see the
`dashboard` CLI command): this serves potentially sensitive engagement
findings with NO authentication of its own, the same "operator's own
trusted machine" assumption the rest of this toolkit already makes for
authorization.yml and the audit log, not a hardened multi-user service.

HTML is rendered through a Jinja2 Environment with autoescape=True
(inline string templates, not FastAPI's file-based Jinja2Templates —
avoids needing package-data/MANIFEST changes for separate .html files,
keeping this a single small, auditable module). Autoescaping is
mandatory here, not a style choice: finding titles/descriptions/
evidence can embed target-controlled data (e.g. a hostile PBX's own
Server or From header content, echoed back into a finding by
pbx_fingerprint or caller_id_spoofing) — a stored-XSS vector if ever
rendered unescaped.
"""

from __future__ import annotations

import json
import sqlite3

from jinja2 import Environment

_env = Environment(autoescape=True)

_BASE_STYLE = """
body { font-family: system-ui, sans-serif; margin: 2em; color: #222; }
table { border-collapse: collapse; width: 100%; margin-top: 1em; }
th, td { border: 1px solid #ccc; padding: 6px 10px; text-align: left; vertical-align: top; }
th { background: #f0f0f0; }
a { color: #06c; }
.sev-CRITICAL { color: #a00; font-weight: bold; }
.sev-HIGH { color: #c00; font-weight: bold; }
.sev-MEDIUM { color: #a60; }
.sev-LOW { color: #069; }
.sev-INFO { color: #666; }
.badge { display: inline-block; padding: 2px 8px; border-radius: 8px; margin-right: 4px;
         font-size: 0.85em; background: #eee; }
"""

_INDEX_TEMPLATE = _env.from_string("""
<!doctype html>
<html>
<head><title>voipaudit dashboard</title><style>{{ style }}</style></head>
<body>
<h1>voipaudit — scan history</h1>
<p>Read-only. {{ runs|length }} run(s) recorded.</p>
{% if not runs %}
<p><em>No runs yet — use <code>scan --db PATH</code> to start recording history.</em></p>
{% else %}
<table>
<tr><th>ID</th><th>Engagement</th><th>Client</th><th>Target</th><th>Transport</th>
    <th>Started</th><th>Findings</th></tr>
{% for run in runs %}
<tr>
  <td><a href="/runs/{{ run.id }}">{{ run.id }}</a></td>
  <td>{{ run.engagement_id }}</td>
  <td>{{ run.client }}</td>
  <td>{{ run.target }}</td>
  <td>{{ run.transport }}</td>
  <td>{{ run.started_at }}</td>
  <td>
    {% for sev, count in run.severity_counts.items() %}
      <span class="badge sev-{{ sev }}">{{ count }} {{ sev }}</span>
    {% endfor %}
  </td>
</tr>
{% endfor %}
</table>
{% endif %}
</body>
</html>
""")

_RUN_DETAIL_TEMPLATE = _env.from_string("""
<!doctype html>
<html>
<head><title>voipaudit — run {{ run.id }}</title><style>{{ style }}</style></head>
<body>
<p><a href="/">&larr; all runs</a></p>
<h1>Run {{ run.id }} — {{ run.target }}</h1>
<p>Engagement: {{ run.engagement_id }} ({{ run.client }}) &mdash;
   modules: {{ run.modules }} &mdash; transport: {{ run.transport }}</p>
<p>Started: {{ run.started_at }} &mdash; Finished: {{ run.finished_at }}</p>
{% if not findings %}
<p><em>No findings for this run.</em></p>
{% else %}
<table>
<tr><th>Severity</th><th>Module</th><th>Title</th><th>Description</th><th>Evidence</th><th>Remediation</th></tr>
{% for f in findings %}
<tr>
  <td class="sev-{{ f.severity }}">{{ f.severity }}</td>
  <td>{{ f.module }}</td>
  <td>{{ f.title }}</td>
  <td>{{ f.description }}</td>
  <td>{{ f.evidence }}</td>
  <td>{{ f.remediation }}</td>
</tr>
{% endfor %}
</table>
{% endif %}
</body>
</html>
""")

_SEVERITY_ORDER = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]


def create_app(db_path: str):
    """Builds the FastAPI app. Imported lazily by the `dashboard` CLI
    command (and by tests) rather than at module import time, so the
    optional 'dashboard' extra is only ever required by code paths
    that actually use it."""
    from fastapi import FastAPI, HTTPException
    from fastapi.responses import HTMLResponse

    app = FastAPI(title="voipaudit dashboard")

    def _connect() -> sqlite3.Connection:
        conn = sqlite3.connect(db_path)
        conn.row_factory = sqlite3.Row
        return conn

    def _severity_counts(conn: sqlite3.Connection, run_id: int) -> dict[str, int]:
        rows = conn.execute(
            "SELECT severity, COUNT(*) AS c FROM findings WHERE run_id = ? GROUP BY severity", (run_id,),
        ).fetchall()
        counts = {r["severity"]: r["c"] for r in rows}
        return {sev: counts[sev] for sev in _SEVERITY_ORDER if sev in counts}

    @app.get("/", response_class=HTMLResponse)
    def index() -> str:
        conn = _connect()
        try:
            rows = conn.execute("SELECT * FROM runs ORDER BY id DESC").fetchall()
            runs = []
            for row in rows:
                run = dict(row)
                run["severity_counts"] = _severity_counts(conn, run["id"])
                runs.append(run)
        finally:
            conn.close()
        return _INDEX_TEMPLATE.render(runs=runs, style=_BASE_STYLE)

    @app.get("/runs/{run_id}", response_class=HTMLResponse)
    def run_detail(run_id: int) -> str:
        conn = _connect()
        try:
            row = conn.execute("SELECT * FROM runs WHERE id = ?", (run_id,)).fetchone()
            if row is None:
                raise HTTPException(status_code=404, detail="Run not found")
            run = dict(row)
            finding_rows = conn.execute(
                "SELECT * FROM findings WHERE run_id = ? ORDER BY "
                "CASE severity "
                "WHEN 'CRITICAL' THEN 0 WHEN 'HIGH' THEN 1 WHEN 'MEDIUM' THEN 2 "
                "WHEN 'LOW' THEN 3 ELSE 4 END",
                (run_id,),
            ).fetchall()
            findings = [dict(r) for r in finding_rows]
        finally:
            conn.close()
        return _RUN_DETAIL_TEMPLATE.render(run=run, findings=findings, style=_BASE_STYLE)

    @app.get("/api/runs")
    def api_runs() -> list[dict]:
        conn = _connect()
        try:
            rows = conn.execute("SELECT * FROM runs ORDER BY id DESC").fetchall()
            return [dict(r) for r in rows]
        finally:
            conn.close()

    @app.get("/api/runs/{run_id}/findings")
    def api_run_findings(run_id: int) -> list[dict]:
        conn = _connect()
        try:
            row = conn.execute("SELECT id FROM runs WHERE id = ?", (run_id,)).fetchone()
            if row is None:
                raise HTTPException(status_code=404, detail="Run not found")
            rows = conn.execute("SELECT * FROM findings WHERE run_id = ?", (run_id,)).fetchall()
            findings = []
            for r in rows:
                d = dict(r)
                d["extra"] = json.loads(d["extra"])
                findings.append(d)
            return findings
        finally:
            conn.close()

    return app

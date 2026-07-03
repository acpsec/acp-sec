"""Report file writer.

Verbatim port of dashboard/serve.py ``_save_report`` (+ ``_report_path``).
Persists a completed scan as ``<reports_dir>/{agent_id}.json`` so the
leaderboard click handler can load the full breakdown via GET /api/report.
Best-effort — never raises. Reports dir is injected (get_reports_dir) so tests
never touch the real dashboard/reports.
"""

from __future__ import annotations

import json
from pathlib import Path

from acpsec_api.leaderboard_store import leaderboard_key


def write_report(reports_dir: Path, scan: dict) -> None:
    """Persist the full scan result as ``<reports_dir>/{agent_id}.json``."""
    name = (scan.get("agent_name") or scan.get("x_username") or "").strip()
    if not name:
        return
    key = leaderboard_key(scan.get("x_username") or name)
    if not key:
        return
    try:
        reports_dir.mkdir(parents=True, exist_ok=True)  # matches Flask _report_path
        (reports_dir / f"{key}.json").write_text(json.dumps(scan, indent=2, default=str))
    except OSError:
        pass

"""Report file writer.

Persists a completed scan as ``<reports_dir>/{agent_id}.json`` so the
leaderboard click handler can load the full breakdown via GET /api/report.
``agent_id`` is the leaderboard entry id returned by ``LeaderboardStore.upsert``
(derived from the scanned host — never from client-supplied names). Atomic and
best-effort — never raises. Reports dir is injected (get_reports_dir) so tests
never touch the real data/reports.
"""

from __future__ import annotations

import json
import re
from pathlib import Path

from acpsec_api.utils import atomic_write_text

_SAFE_ID = re.compile(r"[a-z0-9_]+")


def write_report(reports_dir: Path, agent_id: str, scan: dict) -> None:
    """Persist ``scan`` as ``<reports_dir>/{agent_id}.json``."""
    if not _SAFE_ID.fullmatch(agent_id or ""):
        return
    try:
        reports_dir.mkdir(parents=True, exist_ok=True)
        atomic_write_text(reports_dir / f"{agent_id}.json", json.dumps(scan, indent=2, default=str))
    except OSError:
        pass

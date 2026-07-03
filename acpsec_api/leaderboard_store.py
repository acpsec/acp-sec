"""Leaderboard persistence + banding.

Standalone port of the leaderboard helpers in ``dashboard/serve.py`` (copied,
not imported). ``LeaderboardStore`` mirrors ``_load_leaderboard`` /
``_save_leaderboard``; the 6-band tier table mirrors ``_LEADERBOARD_BANDS`` /
``_tier_for_score``.

NOTE: ``tier_for_score`` / ``LEADERBOARD_BANDS`` are used by the scanner-side
upsert (Task 2.5) — the GET /api/leaderboard endpoint reflects the stored
``tier`` field and does not recompute it. They live here so 2.5 can reuse them.
"""

from __future__ import annotations

import json
from pathlib import Path

# Default path = the SAME file Flask uses, so cutover reads pre-existing data.
# leaderboard_store.py → <repo>/acpsec_api/... → <repo>/dashboard/leaderboard.json
_DEFAULT_LEADERBOARD_FILE = (
    Path(__file__).resolve().parent.parent / "dashboard" / "leaderboard.json"
)

# Six-band tier scheme (distinct from the 5-band score verdicts in scoring.py).
LEADERBOARD_BANDS = [
    (90, "EXEMPLARY"),
    (70, "SECURE"),
    (50, "HARDENED"),
    (30, "VULNERABLE"),
    (10, "CRITICAL"),
    (0,  "COMPROMISED"),
]


def tier_for_score(score: float) -> str:
    """Return the band name for a 0-100 score (six-band scheme)."""
    for threshold, band in LEADERBOARD_BANDS:
        if score >= threshold:
            return band
    return "COMPROMISED"


class LeaderboardStore:
    """JSON-file persistence for the leaderboard (load/save, never raises)."""

    def __init__(self, path: Path | str | None = None) -> None:
        self.path = Path(path) if path is not None else _DEFAULT_LEADERBOARD_FILE

    def load(self) -> dict:
        """Load leaderboard.json (seed + runtime upserts). Never raises."""
        try:
            return json.loads(self.path.read_text())
        except (OSError, ValueError):
            return {"updated": "", "checks_per_scan": 38, "agents": []}

    def save(self, board: dict) -> None:
        """Persist leaderboard.json (best-effort; ignores read-only FS)."""
        try:
            self.path.parent.mkdir(parents=True, exist_ok=True)
            self.path.write_text(json.dumps(board, indent=2))
        except OSError:
            pass

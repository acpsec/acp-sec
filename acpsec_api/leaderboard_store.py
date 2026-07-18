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
import re
from datetime import datetime, timezone
from pathlib import Path

# Default path: <repo>/acpsec_api/leaderboard_store.py → <repo>/data/leaderboard.json
_DEFAULT_LEADERBOARD_FILE = (
    Path(__file__).resolve().parent.parent / "data" / "leaderboard.json"
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


def leaderboard_key(name: str) -> str:
    """Stable id for an agent: lowercase, strip @, keep [a-z0-9_].

    Copied from dashboard/serve.py ``_leaderboard_key``.
    """
    key = (name or "").strip().lstrip("@").lower()
    return re.sub(r"[^a-z0-9_]", "", key.replace(" ", "_")) or "unknown"


def limited_tiebreaker_bonus(token, acp_registered: bool, base_mcp: bool) -> float:
    """Extra points for limited-scan agents based on observable public signals.

    Copied from dashboard/serve.py ``_limited_tiebreaker_bonus``.
    """
    bonus = 0.0
    if token:
        bonus += 1.0
    if acp_registered:
        bonus += 1.0
    if base_mcp:
        bonus += 0.5
    return bonus


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

    def upsert(self, scan: dict) -> None:
        """Add or update an agent in the leaderboard from a completed scan.

        Verbatim port of dashboard/serve.py ``_upsert_leaderboard_entry``.
        ``scan`` is the dashboard-wire-format data object returned by the
        scanner engine. Movement is derived later (GET /api/leaderboard) from
        the ``previous_score`` stashed here.
        """
        name = (scan.get("agent_name") or "").strip()
        if not name:
            return
        key = leaderboard_key(scan.get("x_username") or name)

        score = scan.get("score_pct")
        if score is None:
            score = scan.get("final_score") or 0
        score = round(float(score))

        controls = scan.get("controls") or []
        critical_fails = scan.get("critical_fails")
        if critical_fails is None:
            critical_fails = sum(
                1 for c in controls
                if str(c.get("severity", "")).upper() == "CRITICAL"
                and str(c.get("status", "")).lower() == "fail"
            )

        board = self.load()
        agents = board.setdefault("agents", [])
        existing = next((a for a in agents if a.get("id") == key), None)
        today = datetime.now(timezone.utc).strftime("%Y-%m-%d")

        # v0.4.1 — extract ticker from scan token block, if present
        token_block = scan.get("token") or {}
        detected_ticker = token_block.get("ticker") if token_block.get("has_token") else None

        is_limited = bool(scan.get("limited_scan", False))

        if existing:
            effective_token = detected_ticker or existing.get("token")
            if is_limited:
                score += limited_tiebreaker_bonus(
                    token=effective_token,
                    acp_registered=bool(scan.get("acp_registered", existing.get("acp_registered", False))),
                    base_mcp=bool(existing.get("base_mcp", False)),
                )
            existing["previous_score"] = existing.get("score", score)
            existing["score"]          = score
            existing["tier"]           = tier_for_score(score)
            existing["critical_fails"] = int(critical_fails)
            existing["limited_scan"]   = is_limited
            existing["last_scan_date"] = today
            if scan.get("x_username"):
                existing["x_handle"] = scan["x_username"]
            # Overwrite token only when scan found one and existing is blank.
            if detected_ticker and not existing.get("token"):
                existing["token"] = detected_ticker
        else:
            if is_limited:
                score += limited_tiebreaker_bonus(
                    token=detected_ticker,
                    acp_registered=bool(scan.get("acp_registered", False)),
                    base_mcp=False,
                )
            agents.append({
                "id":             key,
                "name":           name,
                "x_handle":       scan.get("x_username") or key,
                "score":          score,
                "tier":           tier_for_score(score),
                "critical_fails": int(critical_fails),
                "category":       "general",
                "token":          detected_ticker,   # v0.4.1 — from scan token block
                "base_mcp":       False,
                "limited_scan":   is_limited,
                # v0.4.0 fields
                "wallet_address": scan.get("wallet_address"),
                "acp_registered": bool(scan.get("acp_registered", False)),
                "custodial":      scan.get("custodial", "unknown"),
                "fund_transfer":  bool(scan.get("fund_transfer", False)),
                "evaluator":      bool(scan.get("evaluator", False)),
                "job_types":      list(scan.get("job_types", []) or []),
                "last_scan_date": today,
                "previous_score": score,   # first sighting → no movement
            })

        board["updated"] = today
        self.save(board)

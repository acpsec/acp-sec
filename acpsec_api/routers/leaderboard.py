"""Leaderboard router (Task 2.4).

Contract-identical port of the leaderboard read/auth handlers in
dashboard/serve.py:
    GET  /api/leaderboard          open; sorted board with movement + rank
    GET  /api/report/{agent_id}    read-only full-scan report from REPORTS_DIR
    POST /api/leaderboard/auth     password check → in-memory session cookie

Scanner-side writes (_upsert_leaderboard_entry / _save_report) are Task 2.5 —
NOT ported here.
"""

from __future__ import annotations

import json
import os
import re
from pathlib import Path
from typing import Any

from fastapi import APIRouter, Depends, Request
from fastapi.responses import JSONResponse

from acpsec_api.deps import get_lb_sessions, get_leaderboard_store, get_reports_dir
from acpsec_api.leaderboard_store import LeaderboardStore
from acpsec_api.sessions import (
    LB_SESSION_COOKIE,
    LB_SESSION_MAX_AGE,
    LbSessions,
    cookie_samesite,
    cookie_secure,
)

router = APIRouter()


@router.get("/api/leaderboard")
def get_leaderboard(
    store: LeaderboardStore = Depends(get_leaderboard_store),
) -> dict[str, Any]:
    """Return the leaderboard sorted by score descending.

    Each agent carries a derived `movement` field: 'up' | 'down' | 'same'
    based on score vs previous_score.

    INTENTIONAL PARITY DEVIATION: Flask 500s on agents with null scores
    (unhandled ``None > None`` TypeError). FastAPI handles this defensively by
    coercing null scores to 0. The deviation is deliberate: a crash is not a
    contract. See test_leaderboard_null_scores_handled.
    """
    board = store.load()
    agents = list(board.get("agents", []))

    for a in agents:
        # Defensive coercion (see docstring): null score/previous_score → 0.
        cur = a.get("score") or 0
        prev = a.get("previous_score")
        prev = cur if prev is None else prev
        if cur > prev:
            a["movement"] = "up"
        elif cur < prev:
            a["movement"] = "down"
        else:
            a["movement"] = "same"
        a["movement_delta"] = round(cur - prev)

    agents.sort(key=lambda a: a.get("score") or 0, reverse=True)
    for i, a in enumerate(agents, 1):
        a["rank"] = i

    return {
        "ok": True,
        "updated": board.get("updated", ""),
        "checks_per_scan": board.get("checks_per_scan", 38),
        "count": len(agents),
        "agents": agents,
    }


@router.post("/api/leaderboard/auth")
async def leaderboard_auth(
    request: Request, sessions: LbSessions = Depends(get_lb_sessions)
) -> Any:
    """Validate the leaderboard password and issue a session cookie."""
    password = os.environ.get("LEADERBOARD_PASSWORD", "")
    if not password:
        # No password set — leaderboard is open
        return {"ok": True, "token": "open"}

    try:
        body = await request.json()
    except (ValueError, TypeError):
        body = {}
    if not isinstance(body, dict):
        body = {}
    if body.get("password") != password:
        return JSONResponse({"ok": False, "error": "Incorrect password"}, status_code=401)

    token = sessions.create()
    resp = JSONResponse({"ok": True})
    # Task 2.8: cross-origin cookie flags (SameSite=None; Secure by default),
    # env-overridable for local dev. See acpsec_api.sessions.cookie_* helpers.
    resp.set_cookie(
        LB_SESSION_COOKIE,
        token,
        max_age=LB_SESSION_MAX_AGE,
        httponly=True,
        samesite=cookie_samesite(),
        secure=cookie_secure(),
        path="/",
    )
    return resp


@router.get("/api/report/{agent_id}")
def get_report(
    agent_id: str, reports_dir: Path = Depends(get_reports_dir)
) -> Any:
    """Return the full scan breakdown for a leaderboard agent (read-only).

    Reports live in data/reports/{agent_id}.json — written scanner-side.
    404 with a friendly message when no report exists.
    """
    # Normalise: strip @ and lowercase, same as _leaderboard_key()
    safe_id = re.sub(r"[^a-z0-9_]", "", (agent_id or "").lower().replace("-", "_"))
    if not safe_id:
        return JSONResponse({"ok": False, "error": "invalid agent id"}, status_code=400)

    reports_dir.mkdir(parents=True, exist_ok=True)  # matches Flask _report_path
    path = reports_dir / f"{safe_id}.json"
    if not path.exists():
        return JSONResponse(
            {
                "ok": False,
                "error": "report_not_found",
                "message": (
                    "Full report not available for this agent. "
                    "Re-scan it from the Scanner page for a detailed breakdown."
                ),
                "scan_url": "/scanner",
            },
            status_code=404,
        )

    try:
        data = json.loads(path.read_text())
        return {"ok": True, "data": data}
    except (OSError, ValueError) as exc:
        return JSONResponse({"ok": False, "error": str(exc)}, status_code=500)

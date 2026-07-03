"""Leaderboard auth sessions.

Standalone port of the in-memory session store in ``dashboard/serve.py``
(``_lb_sessions`` dict + cookie constants). Tokens are ``lb_<urlsafe>`` with a
7-day expiry. Purely in-memory — no file or external store, matching Flask.
"""

from __future__ import annotations

import secrets
from datetime import datetime, timedelta, timezone

# Cookie / session constants — matched to Flask (dashboard/serve.py).
LB_SESSION_COOKIE = "lb_session"
LB_SESSION_DAYS = 7
LB_SESSION_MAX_AGE = LB_SESSION_DAYS * 86400  # 604800


class LbSessions:
    """In-memory token → expiry map for leaderboard auth."""

    def __init__(self) -> None:
        self._sessions: dict[str, datetime] = {}

    def create(self) -> str:
        """Mint a new session token and record its expiry."""
        token = "lb_" + secrets.token_urlsafe(24)
        expiry = datetime.now(timezone.utc) + timedelta(days=LB_SESSION_DAYS)
        self._sessions[token] = expiry
        return token

    def valid(self, token: str) -> bool:
        """Return True if the token maps to a live (unexpired) session."""
        expiry = self._sessions.get(token or "")
        return bool(expiry and datetime.now(timezone.utc) < expiry)

"""Leaderboard auth sessions.

Standalone port of the in-memory session store in ``dashboard/serve.py``
(``_lb_sessions`` dict + cookie constants). Tokens are ``lb_<urlsafe>`` with a
7-day expiry. Purely in-memory — no file or external store, matching Flask.
"""

from __future__ import annotations

import os
import secrets
import threading
from collections.abc import Callable
from datetime import datetime, timedelta, timezone

# Cookie / session constants — matched to Flask (dashboard/serve.py).
LB_SESSION_COOKIE = "lb_session"
LB_SESSION_DAYS = 7
LB_SESSION_MAX_AGE = LB_SESSION_DAYS * 86400  # 604800

# Task 2.8 — cross-origin cookie flags (INTENTIONAL parity break from Flask).
# The frontend (Vercel) and API (Railway) are separate origins, so the session
# cookie must ride cross-origin requests: SameSite=None; Secure. Both are read
# at REQUEST time (not import) so tests / local dev can flip them per-request.
#
# Local-dev override (plain http://localhost can't set Secure cookies):
#   ACPSEC_COOKIE_SAMESITE=lax  ACPSEC_COOKIE_SECURE=false
_FALSEY = {"false", "0", "no", "off", ""}


def cookie_samesite() -> str:
    """SameSite flag for lb_session — default 'none' (cross-origin production)."""
    return os.environ.get("ACPSEC_COOKIE_SAMESITE", "none").strip().lower() or "none"


def cookie_secure() -> bool:
    """Secure flag for lb_session — default True (SameSite=None requires it)."""
    return os.environ.get("ACPSEC_COOKIE_SECURE", "true").strip().lower() not in _FALSEY


class LbSessions:
    """In-memory token → expiry map for leaderboard auth (bounded, thread-safe).

    Expired sessions are pruned whenever one is created, and beyond
    ``max_sessions`` the oldest are dropped, so the map cannot grow without
    bound. ``clock`` is injectable for tests.
    """

    def __init__(
        self,
        max_sessions: int = 10_000,
        clock: Callable[[], datetime] | None = None,
    ) -> None:
        self.max_sessions = max_sessions
        self._clock = clock or (lambda: datetime.now(timezone.utc))
        self._lock = threading.Lock()
        self._sessions: dict[str, datetime] = {}  # insertion order = oldest first

    def __len__(self) -> int:
        with self._lock:
            return len(self._sessions)

    def create(self) -> str:
        """Mint a new session token and record its expiry."""
        token = "lb_" + secrets.token_urlsafe(24)
        now = self._clock()
        with self._lock:
            for expired in [t for t, exp in self._sessions.items() if exp <= now]:
                del self._sessions[expired]
            self._sessions[token] = now + timedelta(days=LB_SESSION_DAYS)
            while len(self._sessions) > self.max_sessions:
                del self._sessions[next(iter(self._sessions))]
        return token

    def valid(self, token: str) -> bool:
        """Return True if the token maps to a live (unexpired) session."""
        with self._lock:
            expiry = self._sessions.get(token or "")
        return bool(expiry and self._clock() < expiry)

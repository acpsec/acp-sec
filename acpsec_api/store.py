"""Per-visitor dashboard score slots.

Backs the dashboard's "server session score" (GET/POST/DELETE /api/score):
one slot per visitor, bound to a server-minted session id that travels in an
HttpOnly cookie (see ``acpsec_api.routers.score``). There is no shared slot, so
a visitor can only ever read, replace or clear their own score.

In memory and bounded: at most ``max_sessions`` slots (least recently used
evicted first), each expiring ``ttl_seconds`` after its last write. Nothing is
written to disk. This replaces the Flask-parity model of one process-wide score
written through to data/score_store.json.

Thread-safe: the score routes may run in the threadpool concurrently.
"""

from __future__ import annotations

import secrets
import threading
import time
from collections import OrderedDict
from collections.abc import Callable
from typing import Any

SESSION_TTL_SECONDS = 86400  # one day — also the cookie Max-Age
MAX_SESSIONS = 1000


class SessionScoreStore:
    """session id → score dict, LRU- and TTL-bounded."""

    def __init__(
        self,
        max_sessions: int = MAX_SESSIONS,
        ttl_seconds: float = SESSION_TTL_SECONDS,
        clock: Callable[[], float] | None = None,
    ) -> None:
        self.max_sessions = max_sessions
        self.ttl_seconds = ttl_seconds
        self._clock = clock or time.monotonic
        self._lock = threading.Lock()
        # sid -> [expires_at, data]; ordered oldest → most recently written
        self._slots: OrderedDict[str, list[Any]] = OrderedDict()

    def new_session(self) -> str:
        """Mint an empty slot and return its (unguessable) id."""
        sid = secrets.token_urlsafe(24)
        with self._lock:
            self._slots[sid] = [self._clock() + self.ttl_seconds, None]
            while len(self._slots) > self.max_sessions:
                self._slots.popitem(last=False)
        return sid

    def has(self, sid: str | None) -> bool:
        with self._lock:
            return self._live(sid) is not None

    def get(self, sid: str | None) -> dict[str, Any] | None:
        with self._lock:
            slot = self._live(sid)
            return slot[1] if slot else None

    def set(self, sid: str | None, data: dict[str, Any]) -> bool:
        """Write ``sid``'s slot. False if the id was never minted (or expired)."""
        with self._lock:
            slot = self._live(sid)
            if slot is None:
                return False
            slot[0] = self._clock() + self.ttl_seconds
            slot[1] = data
            self._slots.move_to_end(sid)  # type: ignore[arg-type]
            return True

    def clear(self, sid: str | None) -> None:
        with self._lock:
            slot = self._live(sid)
            if slot is not None:
                slot[1] = None

    def __len__(self) -> int:
        with self._lock:
            return len(self._slots)

    def _live(self, sid: str | None) -> list[Any] | None:
        """The slot for ``sid`` if it exists and has not expired (lock held)."""
        if not sid:
            return None
        slot = self._slots.get(sid)
        if slot is None:
            return None
        if slot[0] <= self._clock():
            del self._slots[sid]
            return None
        return slot

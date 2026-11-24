"""Per-client rate limiting for the scanner and on-chain endpoints.

In-memory sliding windows — the API runs as a single uvicorn process, so one
process-wide table is the whole picture (a restart simply resets it). Each
endpoint has its own bucket (``LIMITS``) with a per-client allowance plus a
global ceiling across all clients. Denied requests are not counted, so a
client that keeps hammering does not extend its own lockout. The dependency is
declared AFTER the scanner gate, so requests the gate rejects (401) never
consume anyone's allowance.

CLIENT IDENTITY. On Railway every request arrives through Railway's edge
proxy: the TCP peer (``request.client``) is the proxy, shared by all callers,
and uvicorn's own proxy-header support stays off (it only trusts
``FORWARDED_ALLOW_IPS``, default 127.0.0.1). Railway's edge sets
``X-Real-IP`` to the caller's address (documented "for identifying client's
remote IP"), so that is the key on Railway. ``X-Forwarded-For`` is never read:
it is not among the headers Railway documents setting, so whatever a client
puts there can reach the app unchanged. IPv6 callers are grouped by /64 (one
subscriber's allocation), so address rotation inside it does not help.
Outside Railway (local dev, tests) no proxy header is trusted at all — the
TCP peer is the client. Each bucket's global ceiling bounds total load
independently of client keying (defence in depth).
"""

from __future__ import annotations

import ipaddress
import math
import os
import threading
import time
from collections import OrderedDict, deque
from collections.abc import Callable
from dataclasses import dataclass

from fastapi import Request
from fastapi.responses import JSONResponse

RATE_LIMITED_ERROR = "rate limit exceeded — retry later"


@dataclass(frozen=True)
class RateLimit:
    per_client: int     # requests per window from one client
    global_limit: int   # requests per window from everyone together
    window: float       # seconds


# A scan is ~30 outbound fetches and up to 45 s of work; /bulk is up to 10 scans.
# B20: the frontend fires /api/b20/scan once per form submit (a mutation, never
# retried), each scan is dozens of RPC calls against the shared provider quota;
# /api/b20/preflight is not used by the frontend at all (integrations only) and
# costs a handful of eth_calls — hence a looser per-client allowance.
LIMITS = {
    "scanner_lookup": RateLimit(per_client=20, global_limit=120, window=60),
    "scanner_scan": RateLimit(per_client=10, global_limit=60, window=60),
    "scanner_bulk": RateLimit(per_client=2, global_limit=6, window=600),
    "onchain_check": RateLimit(per_client=20, global_limit=120, window=60),
    "b20_scan": RateLimit(per_client=10, global_limit=60, window=60),
    "b20_preflight": RateLimit(per_client=30, global_limit=300, window=60),
    "leaderboard_auth": RateLimit(per_client=10, global_limit=100, window=60),
}


def _now() -> float:
    return time.monotonic()


class SlidingWindowLimiter:
    """Sliding-window log: per-client and global, bounded client table."""

    def __init__(
        self,
        per_client: int,
        global_limit: int,
        window: float,
        *,
        max_clients: int = 10_000,
        clock: Callable[[], float] | None = None,
    ) -> None:
        self.per_client = per_client
        self.global_limit = global_limit
        self.window = window
        self.max_clients = max_clients
        self._clock = clock
        self._lock = threading.Lock()
        self._clients: OrderedDict[str, deque[float]] = OrderedDict()
        self._global: deque[float] = deque()

    def hit(self, key: str) -> float | None:
        """Count a request from ``key``: None if allowed, else seconds to wait."""
        now = (self._clock or _now)()
        cutoff = now - self.window
        with self._lock:
            _prune(self._global, cutoff)
            hits = self._clients.get(key)
            if hits is None:
                hits = self._clients[key] = deque()
            else:
                self._clients.move_to_end(key)
                _prune(hits, cutoff)
            if len(hits) >= self.per_client:
                return hits[0] + self.window - now
            if len(self._global) >= self.global_limit:
                return self._global[0] + self.window - now
            hits.append(now)
            self._global.append(now)
            while len(self._clients) > self.max_clients:
                self._clients.popitem(last=False)  # least recently seen
            return None

    def tracked_clients(self) -> int:
        with self._lock:
            return len(self._clients)


def _prune(hits: deque[float], cutoff: float) -> None:
    while hits and hits[0] <= cutoff:
        hits.popleft()


def _parse_ip(text: str) -> ipaddress.IPv4Address | ipaddress.IPv6Address | None:
    try:
        return ipaddress.ip_address((text or "").strip())
    except ValueError:
        return None


def _key_for(ip: ipaddress.IPv4Address | ipaddress.IPv6Address) -> str:
    if ip.version == 6:
        if ip.ipv4_mapped is not None:
            return str(ip.ipv4_mapped)
        return str(ipaddress.ip_network(f"{ip}/64", strict=False))
    return str(ip)


def client_key(request: Request) -> str:
    """Rate-limit identity of the caller (see module docstring)."""
    if os.environ.get("RAILWAY_ENVIRONMENT_NAME", "").strip():
        ip = _parse_ip(request.headers.get("x-real-ip", ""))
        if ip is not None:
            return _key_for(ip)
    peer = request.client.host if request.client else ""
    ip = _parse_ip(peer)
    if ip is not None:
        return _key_for(ip)
    return peer or "unknown"


_limiters: dict[str, SlidingWindowLimiter] = {}
_limiters_lock = threading.Lock()


def _limiter(bucket: str) -> SlidingWindowLimiter:
    with _limiters_lock:
        lim = _limiters.get(bucket)
        if lim is None:
            spec = LIMITS[bucket]
            lim = _limiters[bucket] = SlidingWindowLimiter(
                spec.per_client, spec.global_limit, spec.window
            )
        return lim


def reset_rate_limits() -> None:
    """Forget every window (tests)."""
    with _limiters_lock:
        _limiters.clear()


class RateLimited(Exception):
    """Raised by a ``rate_limited`` dependency; rendered as a flat 429."""

    def __init__(self, retry_after: float) -> None:
        super().__init__(retry_after)
        self.retry_after = max(1, math.ceil(retry_after))


def rate_limited(bucket: str) -> Callable[[Request], object]:
    """FastAPI dependency factory: count the request against ``bucket``."""
    if bucket not in LIMITS:
        raise KeyError(bucket)

    async def _dependency(request: Request) -> None:
        retry_after = _limiter(bucket).hit(client_key(request))
        if retry_after is not None:
            raise RateLimited(retry_after)

    return _dependency


def rate_limited_handler(request: Request, exc: RateLimited) -> JSONResponse:
    """Render RateLimited as a flat 429 (same shape as the gate's errors)."""
    return JSONResponse(
        {"ok": False, "error": RATE_LIMITED_ERROR},
        status_code=429,
        headers={"Retry-After": str(exc.retry_after)},
    )

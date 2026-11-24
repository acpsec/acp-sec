"""Concurrency caps for blocking outbound work.

Handlers that do blocking network I/O — the scan engine, the Nitter lookup,
on-chain and B20 RPC — run it in the threadpool, never on the event loop, and
hold a slot of a per-kind cap while they do. A request that finds every slot
of its kind taken gets a flat 503 + Retry-After instead of queueing behind
them. The caps together stay far below anyio's 40 threadpool workers, so cheap
endpoints keep answering (and /api/health is async — it needs no worker).
"""

from __future__ import annotations

import threading
from collections.abc import Iterator
from contextlib import contextmanager

from fastapi import Request
from fastapi.responses import JSONResponse

SERVER_BUSY_ERROR = "server busy — retry shortly"
RETRY_AFTER_SECONDS = 5

# "scan" covers /api/scanner/scan and /bulk (a batch holds one slot throughout).
SLOT_LIMITS = {"scan": 3, "lookup": 4, "onchain": 4, "b20": 4}
_slots = {kind: threading.BoundedSemaphore(n) for kind, n in SLOT_LIMITS.items()}


class ServerBusy(Exception):
    """Every slot of a kind is taken; rendered as a flat 503."""


@contextmanager
def slot(kind: str) -> Iterator[None]:
    """Hold one ``kind`` slot for the block, or raise ServerBusy at once."""
    sem = _slots[kind]
    if not sem.acquire(blocking=False):
        raise ServerBusy(kind)
    try:
        yield
    finally:
        sem.release()


def server_busy_handler(request: Request, exc: ServerBusy) -> JSONResponse:
    """Render ServerBusy as a flat 503 (same shape as the gate's errors)."""
    return JSONResponse(
        {"ok": False, "error": SERVER_BUSY_ERROR},
        status_code=503,
        headers={"Retry-After": str(RETRY_AFTER_SECONDS)},
    )

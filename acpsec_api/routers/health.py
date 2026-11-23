"""Health router — GET /api/health.

Contract-identical port of the Flask liveness probe in dashboard/serve.py.
Used by Railway healthchecks and uptime monitors.

Response (status 200):
    {ok, service, acpsec_available, scanner_protected, leaderboard_configured}

The `*_configured` booleans report whether a required prod secret is present
(never the value) so an env-precondition smoke check can catch a missing var.
Same idiom as `scanner_protected`, which uses the gate's own predicate
(`scanner_token()`) so it is true only when the scanner gate actually enforces.
"""

from __future__ import annotations

import os

from fastapi import APIRouter

from acpsec_api.availability import ACPSEC_AVAILABLE
from acpsec_api.scanner_auth import scanner_token

router = APIRouter()


@router.get("/api/health")
def health() -> dict[str, object]:
    """Lightweight liveness probe — used by Railway healthchecks and uptime monitors."""
    return {
        "ok": True,
        "service": "acp-sec-dashboard",
        "acpsec_available": bool(ACPSEC_AVAILABLE),
        "scanner_protected": bool(scanner_token()),
        "leaderboard_configured": bool(os.environ.get("LEADERBOARD_PASSWORD")),
    }

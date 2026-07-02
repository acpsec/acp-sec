"""Health router — GET /api/health.

Contract-identical port of the Flask liveness probe in dashboard/serve.py.
Used by Railway healthchecks and uptime monitors.

Response (status 200):
    {ok, service, acpsec_available, scanner_protected}
"""

from __future__ import annotations

import os

from fastapi import APIRouter

router = APIRouter()

# acpsec package availability — mirror the Flask import probe: True iff the
# scoring/model/catalogue modules import cleanly, False otherwise. Resolved
# once at import time so the check is a cheap flag, not a per-request import.
try:
    from acpsec.scorer import ScoringEngine  # noqa: F401
    from acpsec.models import CheckStatus  # noqa: F401
    from acpsec.catalogue import get_check_catalogue  # noqa: F401

    ACPSEC_AVAILABLE = True
except ImportError:
    ACPSEC_AVAILABLE = False


@router.get("/api/health")
def health() -> dict[str, object]:
    """Lightweight liveness probe — used by Railway healthchecks and uptime monitors."""
    return {
        "ok": True,
        "service": "acp-sec-dashboard",
        "acpsec_available": bool(ACPSEC_AVAILABLE),
        "scanner_protected": bool(os.environ.get("SCANNER_TOKEN")),
    }

"""Score router — READ side (Task 2.3a).

Contract-identical port of the read/clear/catalogue handlers in
dashboard/serve.py:
    GET    /api/score     current score (memory → disk → null)
    DELETE /api/score     clear in-memory cache + persisted file
    GET    /api/controls  check/control metadata for the scoring editor

POST /api/score and POST /api/score/manual are Task 2.3b — NOT here.
"""

from __future__ import annotations

from typing import Any

from fastapi import APIRouter, Depends

from acpsec_api.deps import get_score_store
from acpsec_api.fallback_catalogue import ASF_CONTROLS_DEFAULT, FALLBACK_CHECKS
from acpsec_api.store import ScoreStore

# acpsec catalogue availability — same try/except probe Flask uses. When the
# package is present it is the single source of truth for the check list.
try:
    from acpsec.catalogue import get_check_catalogue

    ACPSEC_AVAILABLE = True
except ImportError:
    ACPSEC_AVAILABLE = False

router = APIRouter()


@router.get("/api/score")
def get_score(store: ScoreStore = Depends(get_score_store)) -> dict[str, Any]:
    """Return the current score: memory cache → disk → null."""
    data = store.get()
    if data is None:
        return {"ok": False, "data": None}
    return {"ok": True, "data": data}


@router.delete("/api/score")
def clear_score(store: ScoreStore = Depends(get_score_store)) -> dict[str, Any]:
    """Clear in-memory cache and remove the persisted file."""
    store.clear()
    return {"ok": True}


@router.get("/api/controls")
def get_controls() -> dict[str, Any]:
    """Return check/control metadata for the scoring editor.

    Sourced from acpsec.catalogue when the package is installed (single source
    of truth); falls back to the static copy only when it is unavailable.
    """
    if ACPSEC_AVAILABLE:
        checks = get_check_catalogue()
        source = "acpsec"
    else:
        checks = FALLBACK_CHECKS
        source = "static-fallback"

    return {
        "source": source,
        "acpsec_available": ACPSEC_AVAILABLE,
        "checks": checks,
        "asf_controls": ASF_CONTROLS_DEFAULT,
    }

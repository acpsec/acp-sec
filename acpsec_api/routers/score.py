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

from fastapi import APIRouter, Depends, Request
from fastapi.responses import JSONResponse

from acpsec_api.deps import get_score_store
from acpsec_api.fallback_catalogue import ASF_CONTROLS_DEFAULT, FALLBACK_CHECKS
from acpsec_api.scoring import auto_normalise, compute_manual_score
from acpsec_api.store import ScoreStore

# acpsec catalogue availability — same try/except probe Flask uses. When the
# package is present it is the single source of truth for the check list.
try:
    from acpsec.catalogue import get_check_catalogue

    ACPSEC_AVAILABLE = True
except ImportError:
    ACPSEC_AVAILABLE = False

router = APIRouter()


def _is_json_request(request: Request) -> bool:
    """Mirror Flask/Werkzeug ``request.is_json``: mimetype is JSON."""
    mimetype = request.headers.get("content-type", "").split(";")[0].strip().lower()
    return mimetype == "application/json" or mimetype.endswith("+json")


@router.get("/api/score")
def get_score(store: ScoreStore = Depends(get_score_store)) -> dict[str, Any]:
    """Return the current score: memory cache → disk → null."""
    data = store.get()
    if data is None:
        return {"ok": False, "data": None}
    return {"ok": True, "data": data}


@router.post("/api/score")
async def post_score(
    request: Request, store: ScoreStore = Depends(get_score_store)
) -> Any:
    """Accept acpsec or native ASF JSON, normalise, cache, and persist."""
    if not _is_json_request(request):
        return JSONResponse(
            {"error": "Content-Type must be application/json"}, status_code=415
        )
    try:
        payload = await request.json()
        normalised = auto_normalise(payload)
        store.set(normalised)
        return {"ok": True, "data": normalised}
    except (ValueError, KeyError) as exc:
        return JSONResponse({"error": str(exc)}, status_code=400)


@router.post("/api/score/manual")
async def post_score_manual(
    request: Request, store: ScoreStore = Depends(get_score_store)
) -> Any:
    """Accept manually entered control scores and compute aggregate band/verdict.

    CRITICAL-severity controls with status='fail' incur an additional penalty
    (via acpsec.scorer when available, or a local fallback otherwise).
    """
    if not _is_json_request(request):
        return JSONResponse(
            {"error": "Content-Type must be application/json"}, status_code=415
        )
    payload = await request.json()
    if not payload.get("controls"):
        return JSONResponse(
            {"error": "'controls' list is required and must be non-empty"},
            status_code=422,
        )
    normalised = compute_manual_score(payload)
    store.set(normalised)
    return {"ok": True, "data": normalised}


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

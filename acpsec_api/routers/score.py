"""Score router.

    GET    /api/score         the caller's own score (or {ok: false, data: null})
    POST   /api/score         normalise an acpsec/ASF payload into the caller's slot
    POST   /api/score/manual  compute a score from manual controls into the caller's slot
    DELETE /api/score         clear the caller's own slot
    GET    /api/controls      check/control metadata for the scoring editor

Per-visitor (deliberate deviation from the Flask original's single global
slot): each visitor's score lives in its own slot of ``SessionScoreStore``,
bound to a server-minted HttpOnly ``score_session`` cookie (same SameSite /
Secure policy as ``lb_session``). A cookie value the server did not mint is
never adopted — the caller simply gets a fresh session. GET and DELETE never
mint one. Response bodies are unchanged.
"""

from __future__ import annotations

from typing import Any

from fastapi import APIRouter, Depends, Request
from fastapi.responses import JSONResponse

from acpsec_api.availability import ACPSEC_AVAILABLE
from acpsec_api.deps import get_score_store
from acpsec_api.fallback_catalogue import ASF_CONTROLS_DEFAULT, FALLBACK_CHECKS
from acpsec_api.scoring import auto_normalise, compute_manual_score
from acpsec_api.sessions import cookie_samesite, cookie_secure
from acpsec_api.store import SESSION_TTL_SECONDS, SessionScoreStore
from acpsec_api.utils import is_json_request

# When acpsec is present it is the single source of truth for the check list.
if ACPSEC_AVAILABLE:
    from acpsec.catalogue import get_check_catalogue

router = APIRouter()

SCORE_SESSION_COOKIE = "score_session"


def _save_for_visitor(
    request: Request, store: SessionScoreStore, data: dict[str, Any]
) -> JSONResponse:
    """Store ``data`` in the caller's own slot, minting a session if needed."""
    resp = JSONResponse({"ok": True, "data": data})
    sid = request.cookies.get(SCORE_SESSION_COOKIE)
    if not (sid and store.set(sid, data)):
        sid = store.new_session()
        store.set(sid, data)
        resp.set_cookie(
            SCORE_SESSION_COOKIE,
            sid,
            max_age=SESSION_TTL_SECONDS,
            httponly=True,
            samesite=cookie_samesite(),
            secure=cookie_secure(),
            path="/",
        )
    return resp


@router.get("/api/score")
def get_score(
    request: Request, store: SessionScoreStore = Depends(get_score_store)
) -> dict[str, Any]:
    """Return the caller's own score, or the empty-state body."""
    data = store.get(request.cookies.get(SCORE_SESSION_COOKIE))
    if data is None:
        return {"ok": False, "data": None}
    return {"ok": True, "data": data}


@router.post("/api/score")
async def post_score(
    request: Request, store: SessionScoreStore = Depends(get_score_store)
) -> Any:
    """Accept acpsec or native ASF JSON, normalise it into the caller's slot."""
    if not is_json_request(request):
        return JSONResponse(
            {"error": "Content-Type must be application/json"}, status_code=415
        )
    try:
        payload = await request.json()
        normalised = auto_normalise(payload)
    except (ValueError, KeyError) as exc:
        return JSONResponse({"error": str(exc)}, status_code=400)
    return _save_for_visitor(request, store, normalised)


@router.post("/api/score/manual")
async def post_score_manual(
    request: Request, store: SessionScoreStore = Depends(get_score_store)
) -> Any:
    """Accept manually entered control scores and compute aggregate band/verdict.

    CRITICAL-severity controls with status='fail' incur an additional penalty
    (via acpsec.scorer when available, or a local fallback otherwise).
    """
    if not is_json_request(request):
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
    return _save_for_visitor(request, store, normalised)


@router.delete("/api/score")
def clear_score(
    request: Request, store: SessionScoreStore = Depends(get_score_store)
) -> dict[str, Any]:
    """Clear the caller's own slot (no-op without a session)."""
    store.clear(request.cookies.get(SCORE_SESSION_COOKIE))
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

"""Scanner router (Task 2.5a).

Contract-identical port of POST /api/scanner/lookup from dashboard/serve.py.
Gated by the reusable ``require_scanner_access`` dependency (SSRF protection).

/api/scanner/scan and /api/scanner/bulk are Task 2.5b — NOT here.
"""

from __future__ import annotations

from typing import Any, Callable, Optional

from fastapi import APIRouter, Depends, Request
from fastapi.responses import JSONResponse

from acpsec_api.deps import get_profile_scraper
from acpsec_api.scanner_auth import require_scanner_access

router = APIRouter()


def _is_json_request(request: Request) -> bool:
    """Mirror Flask/Werkzeug ``request.is_json`` (see routers/score.py)."""
    mimetype = request.headers.get("content-type", "").split(";")[0].strip().lower()
    return mimetype == "application/json" or mimetype.endswith("+json")


@router.post("/api/scanner/lookup")
async def scanner_lookup(
    request: Request,
    _gate: None = Depends(require_scanner_access),
    scraper: Optional[Callable[[str], dict]] = Depends(get_profile_scraper),
) -> Any:
    """Scrape basic X/Twitter profile info via Nitter.

    Request body: { "username": "@agentname" }
    Returns: { ok, data: { username, display_name, bio, website, avatar_url, ... } }
    """
    if not _is_json_request(request):
        return JSONResponse(
            {"error": "Content-Type must be application/json"}, status_code=415
        )
    payload = await request.json()
    username = (payload.get("username") or "").strip()
    if not username:
        return JSONResponse({"error": "'username' is required"}, status_code=422)

    if scraper is None:
        return JSONResponse({"error": "scanner module not available"}, status_code=503)

    result = scraper(username)
    return {"ok": True, "data": result}

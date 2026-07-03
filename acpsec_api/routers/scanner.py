"""Scanner router.

Contract-identical ports from dashboard/serve.py, gated by the reusable
``require_scanner_access`` dependency (SSRF protection):
    - POST /api/scanner/lookup  (2.5a)  — Nitter profile scrape
    - POST /api/scanner/scan    (2.5b-i) — heuristic scan + leaderboard/report writes

/api/scanner/bulk is Task 2.5b-ii — NOT here.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Callable, Optional

from fastapi import APIRouter, Depends, Request
from fastapi.responses import JSONResponse

from acpsec_api.deps import (
    get_leaderboard_store,
    get_profile_scraper,
    get_reports_dir,
    get_scan_store_path,
    get_scanner_engine,
)
from acpsec_api.leaderboard_store import LeaderboardStore
from acpsec_api.reports import write_report
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


@router.post("/api/scanner/scan")
async def scanner_scan(
    request: Request,
    _gate: None = Depends(require_scanner_access),
    engine: Optional[Any] = Depends(get_scanner_engine),
    lb_store: LeaderboardStore = Depends(get_leaderboard_store),
    reports_dir: Path = Depends(get_reports_dir),
    scan_store_path: Path = Depends(get_scan_store_path),
) -> Any:
    """Heuristic website security analysis mapped to acpsec checks.

    Request body: { url, agent_name?, username?, scan_mode?, scraped?, x_bio? }
    Returns: { ok, data: <dashboard wire format> } or { ok: false, error }.
    On success, writes the last scan, upserts the leaderboard, and saves the
    full report — all best-effort (a store failure never breaks the scan).
    """
    if not _is_json_request(request):
        return JSONResponse(
            {"error": "Content-Type must be application/json"}, status_code=415
        )
    payload    = await request.json()
    url        = (payload.get("url") or "").strip()
    agent_name = (payload.get("agent_name") or "").strip()
    username   = (payload.get("username")   or "").strip()
    scan_mode  = (payload.get("scan_mode")  or "root").strip().lower()
    # `scraped` is True only when the X profile was successfully fetched via
    # Nitter — used by the UI to decide whether to render the @handle.
    scraped    = bool(payload.get("scraped", False))

    if scan_mode not in ("root", "exact"):
        scan_mode = "root"

    if not url:
        return JSONResponse({"error": "'url' is required"}, status_code=422)

    if engine is None:
        return JSONResponse({"error": "scanner module not available"}, status_code=503)

    result = engine.analyze_agent(url, agent_name or url, scan_mode=scan_mode)
    if not result["ok"]:
        return JSONResponse(result, status_code=422)

    # Attach the X username only when it came from a verified scrape — prevents
    # stale @handles after the user pivots following a scrape failure.
    result["data"]["x_username"]        = username if scraped else ""
    result["data"]["x_handle_verified"] = scraped
    result["data"]["agent_name"]        = agent_name or result["data"]["agent_name"]

    # v0.4.1 — re-run token extraction with the X bio when we have it from a
    # successful Nitter scrape. The bio often carries the ticker / CA the site omits.
    x_bio = (payload.get("x_bio") or "").strip()
    if scraped and x_bio:
        try:
            token_merged = engine.extract_token_info(
                html=result["data"].get("_body_text_for_token", ""),
                x_bio=x_bio,
            )
            existing = result["data"].get("token") or {}
            # Bio signal wins for ticker/CA if website didn't find any.
            if not existing.get("has_token") and token_merged.get("has_token"):
                result["data"]["token"] = token_merged
            elif token_merged.get("has_token"):
                if not existing.get("ticker") and token_merged.get("ticker"):
                    existing["ticker"] = token_merged["ticker"]
                if not existing.get("contract_address") and token_merged.get("contract_address"):
                    existing["contract_address"] = token_merged["contract_address"]
                existing["has_token"] = True
                existing.setdefault("detected_from", "x_bio")
                result["data"]["token"] = existing
        except Exception:  # noqa: BLE001
            pass

    # Persist last scan (best-effort)
    try:
        scan_store_path.write_text(json.dumps(result["data"], indent=2, default=str))
    except OSError:
        pass

    # Auto-add / update this agent on the public leaderboard (best-effort).
    try:
        lb_store.upsert(result["data"])
    except Exception:  # noqa: BLE001 — leaderboard must never break a scan
        pass

    # Auto-save the full breakdown for GET /api/report/<agent_id> (best-effort).
    try:
        write_report(reports_dir, result["data"])
    except Exception:  # noqa: BLE001
        pass

    return result

"""Scanner router.

Contract-identical ports from dashboard/serve.py, gated by the reusable
``require_scanner_access`` dependency (SSRF protection):
    - POST /api/scanner/lookup  (2.5a)  — Nitter profile scrape
    - POST /api/scanner/scan    (2.5b-i) — heuristic scan + leaderboard/report writes

    - POST /api/scanner/bulk    (2.5b-ii) — batch scan up to 10 X usernames
"""

from __future__ import annotations

import json
import time
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


# Inter-scan throttle for /bulk, matching Flask's downstream rate-limiting.
# Exposed as a module constant so it stays visible; tests patch ``time.sleep``.
BULK_MAX = 10
BULK_SCAN_DELAY_SECONDS = 5

# Derive a plausible website URL from an X username. For purely social-only
# agents this hits the social-media guard in analyze_agent and triggers a
# limited scan — which is correct. Kept verbatim from Flask's bulk handler.
_BULK_URL_TEMPLATE = "https://twitter.com/{username}"


def _persist_leaderboard_and_report(
    lb_store: LeaderboardStore, reports_dir: Path, data: dict
) -> None:
    """Best-effort leaderboard upsert + report write for a successful scan.

    Shared verbatim by /scan and /bulk. Each write is independently guarded —
    a store failure must never break a scan (mirrors the two try blocks in the
    Flask handlers).
    """
    try:
        lb_store.upsert(data)
    except Exception:  # noqa: BLE001 — leaderboard must never break a scan
        pass
    try:
        write_report(reports_dir, data)
    except Exception:  # noqa: BLE001
        pass


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

    # Persist last scan (best-effort) — single-scan only; /bulk does not do this.
    try:
        scan_store_path.write_text(json.dumps(result["data"], indent=2, default=str))
    except OSError:
        pass

    # Auto-add to leaderboard + save the full breakdown (both best-effort).
    _persist_leaderboard_and_report(lb_store, reports_dir, result["data"])

    return result


@router.post("/api/scanner/bulk")
async def scanner_bulk(
    request: Request,
    _gate: None = Depends(require_scanner_access),
    engine: Optional[Any] = Depends(get_scanner_engine),
    lb_store: LeaderboardStore = Depends(get_leaderboard_store),
    reports_dir: Path = Depends(get_reports_dir),
) -> Any:
    """Scan multiple agents by X username, sequentially with rate limiting.

    Request body: { usernames: ["aerodromefi", ...], scan_mode?: "root"|"exact" }
    Returns { ok, count, results[] } where each entry is
    { username, ok, data? | error? } in the same shape as /api/scanner/scan.

    Rate limits: max 10 agents per request; a 5s pause between scans respects
    downstream services. A single agent failing (raise or ok:False) is captured
    per-item and does not abort the batch.
    """
    if not _is_json_request(request):
        return JSONResponse(
            {"error": "Content-Type must be application/json"}, status_code=415
        )
    payload = await request.json() or {}
    usernames = [
        str(u).strip().lstrip("@") for u in (payload.get("usernames") or []) if u
    ]
    scan_mode = (payload.get("scan_mode") or "root").strip().lower()
    if scan_mode not in ("root", "exact"):
        scan_mode = "root"

    if not usernames:
        return JSONResponse(
            {"error": "'usernames' must be a non-empty list"}, status_code=422
        )

    if len(usernames) > BULK_MAX:
        return JSONResponse(
            {
                "error": f"Too many agents — maximum {BULK_MAX} per request, "
                f"got {len(usernames)}",
            },
            status_code=422,
        )

    if engine is None:
        return JSONResponse({"error": "scanner module not available"}, status_code=503)

    results = []
    for i, username in enumerate(usernames):
        if i > 0:
            time.sleep(BULK_SCAN_DELAY_SECONDS)  # throttle between scans

        url = _BULK_URL_TEMPLATE.format(username=username)
        try:
            scan = engine.analyze_agent(url, username, scan_mode=scan_mode)
        except Exception as exc:  # noqa: BLE001
            results.append({"username": username, "ok": False, "error": str(exc)})
            continue

        if scan.get("ok") and scan.get("data"):
            scan["data"]["x_username"] = username
            _persist_leaderboard_and_report(lb_store, reports_dir, scan["data"])
            results.append({"username": username, "ok": True, "data": scan["data"]})
        else:
            results.append({
                "username": username, "ok": False,
                "error": scan.get("error") or "scan failed",
            })

    return {"ok": True, "count": len(results), "results": results}

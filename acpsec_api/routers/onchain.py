"""On-chain router.

Contract-identical port from dashboard/serve.py, gated by the reusable
``require_scanner_access`` dependency (SSRF/RPC-abuse protection):
    - POST /api/onchain/check (2.6) — best-effort Base-mainnet ACP registration

Read-only: hits public Base RPC and returns the result. No state writes. The
checker is injected via ``get_onchain_checker`` so tests can mock it — the suite
never makes a live RPC call.
"""

from __future__ import annotations

import os
from typing import Any, Callable, Optional

from fastapi import APIRouter, Depends, Request
from fastapi.responses import JSONResponse

from acpsec_api.deps import get_onchain_checker
from acpsec_api.scanner_auth import require_scanner_access
from acpsec_api.utils import is_json_request

router = APIRouter()


@router.post("/api/onchain/check")
async def onchain_check(
    request: Request,
    _gate: None = Depends(require_scanner_access),
    checker: Optional[Callable[..., dict]] = Depends(get_onchain_checker),
) -> Any:
    """Best-effort on-chain ACP registration check.

    Request body: { "wallet": "0x…" }
    Returns: { ok, data: { contract, wallet, registered, log_count, ... } }.

    ``registered`` is True (log found), False (no log in the scanned window), or
    None (RPC failed / malformed wallet — inconclusive). The handler does no
    wallet-format validation; the checker validates internally and never raises.
    """
    if not is_json_request(request):
        return JSONResponse(
            {"error": "Content-Type must be application/json"}, status_code=415
        )
    payload = await request.json()
    wallet = (payload.get("wallet") or "").strip()
    if not wallet:
        return JSONResponse(
            {"ok": False, "error": "'wallet' is required"}, status_code=422
        )

    if checker is None:
        return JSONResponse(
            {"ok": False, "error": "acpsec.onchain not available"}, status_code=503
        )

    rpc_url = os.environ.get("BASE_RPC_URL", "").strip() or None
    result = checker(wallet, rpc_url=rpc_url)
    return {"ok": True, "data": result}

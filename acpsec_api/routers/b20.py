"""B20 Trust Score router — ``POST /api/b20/scan`` (Task 7.1b).

Merges the standalone ``acp-sec-b20`` HTTP surface into acpsec_api so the B20
scanner shares a single origin (no second Railway service). The scan logic is a
verbatim port of ``acp_sec_b20.api.scan`` — same validation, same error codes,
same ``ScanResult.to_dict()`` body — with two deliberate changes:

- **GET → POST.** The standalone endpoint was ``GET /scan?address&chain_id``;
  here it is ``POST /api/b20/scan`` with a JSON body, matching acpsec_api's other
  scan endpoints. The *response* body is byte-identical; only the method + input
  location differ (documented in ``docs/b20-endpoint-schema.md``).
- Handler is **sync ``def``** so FastAPI runs it in the threadpool — the scan is
  RPC-bound (blocking urllib), so it must not run on the event loop.

The three ``get_*`` providers are the injection seams: tests override them via
``app.dependency_overrides`` so the suite never touches the network.
"""

from __future__ import annotations

import re
from typing import Callable

from fastapi import APIRouter, Depends
from fastapi.responses import JSONResponse
from pydantic import BaseModel

from acpsec_api.b20.engine import assess
from acpsec_api.b20.reader import B20Unavailable, read_token
from acpsec_api.b20.rpc import RpcClient

router = APIRouter()

SUPPORTED_CHAINS = (8453, 84532)
_ADDRESS_RE = re.compile(r"^0x[0-9a-fA-F]{40}$")


# --- Injectable dependency providers (overridden in tests) ----------------
def get_read_fn() -> Callable:
    return read_token


def get_scorer() -> Callable:
    return assess


def get_rpc_factory() -> Callable:
    return RpcClient


class B20ScanRequest(BaseModel):
    address: str
    chain_id: int


def _error(status: int, error: str, detail: str) -> JSONResponse:
    return JSONResponse(status_code=status, content={"error": error, "detail": detail})


@router.post("/api/b20/scan")
def b20_scan(
    body: B20ScanRequest,
    read_fn=Depends(get_read_fn),
    scorer=Depends(get_scorer),
    rpc_factory=Depends(get_rpc_factory),
):
    address = body.address
    chain_id = body.chain_id

    if not _ADDRESS_RE.match(address or ""):
        return _error(
            400, "invalid_address", f"{address!r} is not a 0x-prefixed 40-hex address."
        )
    if chain_id not in SUPPORTED_CHAINS:
        return _error(
            400,
            "unsupported_chain",
            f"chain_id {chain_id} is not one of {list(SUPPORTED_CHAINS)}.",
        )

    try:
        rpc = rpc_factory(chain_id)
    except Exception as exc:  # noqa: BLE001
        return _error(
            503, "rpc_unreachable", f"cannot initialise RPC for chain {chain_id}: {exc}"
        )

    # Definitive negative (not a B20 token / not initialized / feature off).
    try:
        inputs = read_fn(address, chain_id, rpc=rpc)
    except B20Unavailable as exc:
        return _error(400, "not_b20", str(exc))

    # Entirely unreachable (no response to any call) vs reachable-but-unrated.
    if getattr(rpc, "attempts", 0) > 0 and not getattr(rpc, "any_response", True):
        return _error(
            503, "rpc_unreachable", f"chain {chain_id} RPC returned no response to any call."
        )

    return scorer(inputs).to_dict()

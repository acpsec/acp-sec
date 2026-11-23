"""Gate-level regression tests for every SCANNER_TOKEN-gated endpoint.

The gate is one dependency (``require_scanner_access``) shared by all four
endpoints, so a denial must look identical on each. Every request here is
rejected by the gate before any scraper/engine/RPC dependency resolves — there
are NO network calls in this suite.
"""

from __future__ import annotations

import pytest

from acpsec_api.scanner_auth import SCANNER_DENIED_ERROR

GATED_ENDPOINTS = [
    "/api/scanner/lookup",
    "/api/scanner/scan",
    "/api/scanner/bulk",
    "/api/onchain/check",
]


@pytest.mark.parametrize("path", GATED_ENDPOINTS)
@pytest.mark.parametrize(
    "headers",
    [
        {},
        # Starlette TestClient's default Host is "testserver": Origin == Host
        # used to be a free pass (the removed same-origin shortcut).
        {"Origin": "http://testserver"},
        {"X-Scanner-Token": "wrong"},
    ],
    ids=["no-token", "spoofed-same-origin", "wrong-token"],
)
def test_gated_endpoint_denies(fastapi_client, monkeypatch, path, headers) -> None:
    monkeypatch.setenv("SCANNER_TOKEN", "sekret")
    resp = fastapi_client.post(path, json={}, headers=headers)
    assert resp.status_code == 401
    assert resp.json() == {"ok": False, "error": SCANNER_DENIED_ERROR}

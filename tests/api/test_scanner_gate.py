"""Gate-level regression tests for every SCANNER_TOKEN-gated endpoint.

The gate is one dependency (``require_scanner_access``) shared by all four
endpoints, so a denial must look identical on each. Every request here is
rejected by the gate before any scraper/engine/RPC dependency resolves — there
are NO network calls in this suite (the open-mode tests mock the scraper).
"""

from __future__ import annotations

import pytest

from acpsec_api.scanner_auth import SCANNER_DENIED_ERROR, SCANNER_UNCONFIGURED_ERROR

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


# --- Fail-closed in production --------------------------------------------
# RAILWAY_ENVIRONMENT_NAME is injected by Railway itself, so this guard needs no
# extra variable to arm: a production deploy that lost SCANNER_TOKEN must CLOSE
# the scanner (503), never silently fall back to the open dev mode.

PRODUCTION_NAMES = ["production", "Production", " production "]


@pytest.mark.parametrize("path", GATED_ENDPOINTS)
@pytest.mark.parametrize("token", [None, "", "   "], ids=["unset", "empty", "blank"])
@pytest.mark.parametrize(
    "headers",
    [{}, {"X-Scanner-Token": ""}, {"X-Scanner-Token": "anything"}],
    ids=["no-header", "empty-header", "some-header"],
)
def test_production_without_token_fails_closed(
    fastapi_client, monkeypatch, path, token, headers
) -> None:
    monkeypatch.setenv("RAILWAY_ENVIRONMENT_NAME", "production")
    if token is None:
        monkeypatch.delenv("SCANNER_TOKEN", raising=False)
    else:
        monkeypatch.setenv("SCANNER_TOKEN", token)
    resp = fastapi_client.post(path, json={}, headers=headers)
    assert resp.status_code == 503
    assert resp.json() == {"ok": False, "error": SCANNER_UNCONFIGURED_ERROR}


@pytest.mark.parametrize("env_name", PRODUCTION_NAMES)
def test_production_name_match_is_normalised(fastapi_client, monkeypatch, env_name) -> None:
    # Case/whitespace variants still count as production — err towards closed.
    monkeypatch.setenv("RAILWAY_ENVIRONMENT_NAME", env_name)
    monkeypatch.delenv("SCANNER_TOKEN", raising=False)
    resp = fastapi_client.post("/api/scanner/lookup", json={"username": "agentx"})
    assert resp.status_code == 503


def test_production_with_token_enforces_it(scanner_client, monkeypatch) -> None:
    monkeypatch.setenv("RAILWAY_ENVIRONMENT_NAME", "production")
    monkeypatch.setenv("SCANNER_TOKEN", "sekret")
    client = scanner_client(lambda username: {"username": username})
    denied = client.post("/api/scanner/lookup", json={"username": "agentx"})
    assert denied.status_code == 401
    assert denied.json() == {"ok": False, "error": SCANNER_DENIED_ERROR}
    allowed = client.post(
        "/api/scanner/lookup",
        json={"username": "agentx"},
        headers={"X-Scanner-Token": "sekret"},
    )
    assert allowed.status_code == 200


@pytest.mark.parametrize(
    "env_name", [None, "", "staging", "pr-12"], ids=["unset", "empty", "staging", "pr-env"]
)
def test_outside_production_without_token_stays_open(
    scanner_client, monkeypatch, env_name
) -> None:
    # Local dev (no Railway variables) and non-production Railway environments
    # keep the documented open mode when SCANNER_TOKEN is unset.
    if env_name is None:
        monkeypatch.delenv("RAILWAY_ENVIRONMENT_NAME", raising=False)
    else:
        monkeypatch.setenv("RAILWAY_ENVIRONMENT_NAME", env_name)
    monkeypatch.delenv("SCANNER_TOKEN", raising=False)
    client = scanner_client(lambda username: {"username": username})
    resp = client.post("/api/scanner/lookup", json={"username": "agentx"})
    assert resp.status_code == 200
    assert resp.json() == {"ok": True, "data": {"username": "agentx"}}
